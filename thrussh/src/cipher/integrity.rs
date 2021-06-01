use crate::kex::ComputeKeys;
use crate::Error;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub const NONE: Name = Name("none");
pub const HMAC_SHA2_256: Name = Name("hmac-sha2-256");
pub const HMAC_SHA2_512: Name = Name("hmac-sha2-512");
pub const HMAC_SHA1: Name = Name("hmac-sha1");

pub enum Auth {
    HmacSha256([u8; 32]),
    HmacSha512([u8; 64]),
    HmacSha1([u8; 20]),
}

impl Auth {
    pub fn new_from_name(name: Name, keys: &ComputeKeys) -> Result<Option<Auth>, Error> {
        use std::convert::TryInto;
        Ok(Some(match name {
            NONE => return Ok(None),
            HMAC_SHA2_256 => Auth::HmacSha256(keys.integrity_key(32)?.try_into().unwrap()),
            HMAC_SHA2_512 => Auth::HmacSha512(keys.integrity_key(64)?.try_into().unwrap()),
            HMAC_SHA1 => Auth::HmacSha1(keys.integrity_key(20)?.try_into().unwrap()),
            _ => return Err(Error::NoCommonCipher),
        }))
    }

    pub fn compute(&self, seqn: u32, data: &[u8], tag: &mut [u8]) {
        match self {
            Auth::HmacSha256(key) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
                mac.update(&seqn.to_be_bytes());
                mac.update(data);
                tag.clone_from_slice(&mac.finalize().into_bytes());
            }
            Auth::HmacSha512(key) => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
                mac.update(&seqn.to_be_bytes());
                mac.update(data);
                tag.clone_from_slice(&mac.finalize().into_bytes());
            }
            Auth::HmacSha1(key) => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
                mac.update(&seqn.to_be_bytes());
                mac.update(data);
                tag.clone_from_slice(&mac.finalize().into_bytes());
            }
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            Auth::HmacSha256(_) => 32,
            Auth::HmacSha512(_) => 64,
            Auth::HmacSha1(_) => 20,
        }
    }
}
