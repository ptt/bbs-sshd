use crate::Error;
use elliptic_curve::{Curve, FieldBytes, FieldSize, ProjectiveArithmetic};

#[derive(Eq, PartialEq)]
pub enum EcPublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl EcPublicKey {
    pub fn ident(&self) -> &'static str {
        match self {
            Self::P256(_) => "nistp256",
            Self::P384(_) => "nistp384",
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::P256(_) => "ecdsa-sha2-nistp256",
            Self::P384(_) => "ecdsa-sha2-nistp384",
        }
    }

    pub fn from_sec1_bytes(algorithm_name: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        match algorithm_name {
            crate::KEYTYPE_ECDSA_SHA2_NISTP256 => Ok(Self::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)?,
            )),
            crate::KEYTYPE_ECDSA_SHA2_NISTP384 => Ok(Self::P384(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)?,
            )),
            _ => Err(Error::UnsupportedKeyType(algorithm_name.into())),
        }
    }

    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::P384(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    pub fn verify(&self, msg: &[u8], r: &[u8], s: &[u8]) -> Result<(), Error> {
        use ecdsa::signature::Verifier;
        match self {
            Self::P256(key) => key.verify(
                msg,
                &p256::ecdsa::Signature::from_scalars(
                    try_field_bytes_from_mpint::<p256::NistP256>(r)
                        .ok_or(Error::InvalidSignature)?
                        .clone(),
                    try_field_bytes_from_mpint::<p256::NistP256>(s)
                        .ok_or(Error::InvalidSignature)?
                        .clone(),
                )?,
            ),
            Self::P384(key) => key.verify(
                msg,
                &p384::ecdsa::Signature::from_scalars(
                    try_field_bytes_from_mpint::<p384::NistP384>(r)
                        .ok_or(Error::InvalidSignature)?
                        .clone(),
                    try_field_bytes_from_mpint::<p384::NistP384>(s)
                        .ok_or(Error::InvalidSignature)?
                        .clone(),
                )?,
            ),
        }
        .map_err(Error::from)
    }
}

impl std::fmt::Debug for EcPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::P256(_) => write!(f, "P256"),
            Self::P384(_) => write!(f, "P384"),
        }
    }
}

#[derive(Eq, PartialEq)]
pub enum EcPrivateKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl EcPrivateKey {
    pub fn new_from_secret_scalar(key_type: &[u8], scalar: &[u8]) -> Result<Self, Error> {
        match key_type {
            crate::KEYTYPE_ECDSA_SHA2_NISTP256 => {
                Ok(Self::P256(p256::ecdsa::SigningKey::from_bytes(scalar)?))
            }
            crate::KEYTYPE_ECDSA_SHA2_NISTP384 => {
                Ok(Self::P384(p384::ecdsa::SigningKey::from_bytes(scalar)?))
            }
            _ => Err(Error::UnsupportedKeyType(key_type.into())),
        }
    }

    pub fn ident(&self) -> &'static str {
        match self {
            Self::P256(_) => "nistp256",
            Self::P384(_) => "nistp384",
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::P256(_) => "ecdsa-sha2-nistp256",
            Self::P384(_) => "ecdsa-sha2-nistp384",
        }
    }

    pub fn to_public_key(&self) -> EcPublicKey {
        match self {
            Self::P256(key) => EcPublicKey::P256(key.verifying_key()),
            Self::P384(key) => EcPublicKey::P384(key.verifying_key()),
        }
    }

    pub fn try_sign(&self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        use ecdsa::signature::RandomizedSigner;
        match self {
            Self::P256(key) => key
                .try_sign_with_rng(rand::thread_rng(), msg)
                .map(|sig| sig.split_bytes())
                .map(|(r, s)| (r.to_vec(), s.to_vec())),
            Self::P384(key) => key
                .try_sign_with_rng(rand::thread_rng(), msg)
                .map(|sig| sig.split_bytes())
                .map(|(r, s)| (r.to_vec(), s.to_vec())),
        }
        .map_err(Error::from)
    }
}

impl std::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::P256(_) => write!(f, "P256"),
            Self::P384(_) => write!(f, "P384"),
        }
    }
}

pub fn try_field_bytes_from_mpint<C>(b: &[u8]) -> Option<FieldBytes<C>>
where
    C: Curve + ProjectiveArithmetic,
{
    use typenum::Unsigned;
    let size = FieldSize::<C>::to_usize();
    if b.len() == size + 1 && b[0] == 0 {
        Some(FieldBytes::<C>::clone_from_slice(&b[1..]))
    } else if b.len() == size {
        Some(FieldBytes::<C>::clone_from_slice(b))
    } else if b.len() < size {
        let mut fb: FieldBytes<C> = Default::default();
        fb.as_mut_slice()[size - b.len()..].clone_from_slice(b);
        Some(fb)
    } else {
        None
    }
}
