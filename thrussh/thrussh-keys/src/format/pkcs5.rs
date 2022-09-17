use super::{decode_rsa, Encryption};
use crate::key;
use crate::Error;
use cipher::{BlockDecryptMut, KeyIvInit};
use digest::Digest;
use md5::Md5;

/// Decode a secret key in the PKCS#5 format, possible deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&[u8]>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut h = Md5::new();
                h.update(pass);
                h.update(&iv[..8]);
                let md5 = h.finalize();
                cbc::Decryptor::<aes::Aes128>::new(&md5, iv.into())
                    .decrypt_padded_vec_mut::<block_padding::Pkcs7>(secret)
                    .map_err(|_| Error::CouldNotReadKey)?
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        decode_rsa(&sec)
    } else {
        Err(Error::KeyIsEncrypted.into())
    }
}
