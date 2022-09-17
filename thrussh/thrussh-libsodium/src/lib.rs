extern crate libc;
#[macro_use]
extern crate lazy_static;
use libc::c_ulonglong;
use libsodium_sys::*;

lazy_static! {
    static ref SODIUM: i32 = unsafe { sodium_init() };
}

pub mod ed25519 {
    use super::*;
    pub const PUBLICKEY_BYTES: usize = 32;
    pub const SECRETKEY_BYTES: usize = 64;
    pub const SIGNATURE_BYTES: usize = 64;

    /// Ed25519 public key.
    #[derive(Debug, PartialEq, Eq)]
    pub struct PublicKey {
        /// Actual key
        pub key: [u8; PUBLICKEY_BYTES],
    }

    impl PublicKey {
        pub fn new_zeroed() -> Self {
            PublicKey {
                key: [0; PUBLICKEY_BYTES],
            }
        }
    }

    /// Ed25519 secret key.
    #[derive(Clone)]
    pub struct SecretKey {
        /// Actual key
        pub key: [u8; SECRETKEY_BYTES],
    }

    impl SecretKey {
        pub fn new_zeroed() -> Self {
            SecretKey {
                key: [0; SECRETKEY_BYTES],
            }
        }
    }

    pub struct Signature(pub [u8; SIGNATURE_BYTES]);

    /// Generate a key pair.
    pub fn keypair() -> (PublicKey, SecretKey) {
        unsafe {
            lazy_static::initialize(&super::SODIUM);
            let mut pk = PublicKey {
                key: [0; PUBLICKEY_BYTES],
            };
            let mut sk = SecretKey {
                key: [0; SECRETKEY_BYTES],
            };
            crypto_sign_keypair(pk.key.as_mut_ptr(), sk.key.as_mut_ptr());
            (pk, sk)
        }
    }

    /// Verify a signature, `sig` could as well be a `Signature`.
    pub fn verify_detached(sig: &[u8], m: &[u8], pk: &PublicKey) -> bool {
        lazy_static::initialize(&super::SODIUM);
        if sig.len() == SIGNATURE_BYTES {
            unsafe {
                crypto_sign_verify_detached(
                    sig.as_ptr(),
                    m.as_ptr(),
                    m.len() as c_ulonglong,
                    pk.key.as_ptr(),
                ) == 0
            }
        } else {
            false
        }
    }

    /// Sign a message with a secret key.
    pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
        lazy_static::initialize(&super::SODIUM);
        let mut sig = Signature([0; SIGNATURE_BYTES]);
        let mut sig_len = 0;
        unsafe {
            crypto_sign_detached(
                sig.0.as_mut_ptr(),
                &mut sig_len,
                m.as_ptr(),
                m.len() as c_ulonglong,
                sk.key.as_ptr(),
            );
        }
        sig
    }
}

pub mod scalarmult {
    use super::*;
    pub const BYTES: usize = 32;

    #[derive(Debug)]
    pub struct Scalar(pub [u8; BYTES]);
    #[derive(Debug)]
    pub struct GroupElement(pub [u8; BYTES]);

    pub fn scalarmult_base(n: &Scalar) -> GroupElement {
        lazy_static::initialize(&super::SODIUM);
        let mut q = GroupElement([0; BYTES]);
        unsafe {
            crypto_scalarmult_curve25519_base(q.0.as_mut_ptr(), n.0.as_ptr());
        }
        q
    }

    pub fn scalarmult(n: &Scalar, p: &GroupElement) -> GroupElement {
        lazy_static::initialize(&super::SODIUM);
        let mut q = GroupElement([0; BYTES]);
        unsafe {
            crypto_scalarmult_curve25519(q.0.as_mut_ptr(), n.0.as_ptr(), p.0.as_ptr());
        }
        q
    }
}
