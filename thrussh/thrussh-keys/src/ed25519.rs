use crate::Error;
use ed25519_dalek::{Signer, Verifier};

pub const PUBLICKEY_BYTES: usize = 32;
pub const SECRETKEY_BYTES: usize = 64;
pub const SIGNATURE_BYTES: usize = 64;

/// Ed25519 public key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey(
            ed25519_dalek::PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidKey)?,
        ))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Ed25519 secret key.
pub struct SecretKey(ed25519_dalek::Keypair);

impl SecretKey {
    /// Creates a SecretKey from key pair bytes, first secret key bytes then public key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(SecretKey(
            ed25519_dalek::Keypair::from_bytes(bytes).map_err(|_| Error::InvalidKey)?,
        ))
    }

    pub fn public_as_bytes(&self) -> &[u8; 32] {
        self.0.public.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey(self.0.public.clone())
    }
}

pub struct Signature(pub [u8; SIGNATURE_BYTES]);

/// Generate a key pair.
pub fn keypair() -> SecretKey {
    use rand::RngCore;
    let mut sk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk[..]);
    let secret = ed25519_dalek::SecretKey::from_bytes(&sk[..]).unwrap();
    let public = ed25519_dalek::PublicKey::from(&secret);
    SecretKey(ed25519_dalek::Keypair { public, secret })
}

/// Verify a signature, `sig` could as well be a `Signature`.
pub fn verify_detached(sig: &[u8], m: &[u8], pk: &PublicKey) -> bool {
    if let Ok(sig) = ::ed25519::Signature::from_bytes(sig) {
        pk.0.verify(m, &sig).is_ok()
    } else {
        false
    }
}

/// Sign a message with a secret key.
pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
    Signature(sk.0.sign(m).to_bytes())
}
