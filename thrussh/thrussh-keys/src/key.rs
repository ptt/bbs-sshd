// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::ec;
use crate::encoding::{Encoding, Reader};
pub use crate::signature::*;
use crate::Error;
use cryptovec::CryptoVec;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Name of a public key algorithm.
pub struct Name(pub &'static str);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The name of the Ed25519 algorithm for SSH.
pub const ED25519: Name = Name("ssh-ed25519");
/// The name of the ssh-sha2-512 algorithm for SSH.
pub const RSA_SHA2_512: Name = Name("rsa-sha2-512");
/// The name of the ssh-sha2-256 algorithm for SSH.
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");

pub const SSH_RSA: Name = Name("ssh-rsa");

impl Name {
    /// Base name of the private key file for a key name.
    pub fn identity_file(&self) -> &'static str {
        match *self {
            ED25519 => "id_ed25519",
            RSA_SHA2_512 => "id_rsa",
            RSA_SHA2_256 => "id_rsa",
            _ => unreachable!(),
        }
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// The hash function used for hashing buffers.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// SHA2, 256 bits.
    SHA2_256,
    /// SHA2, 384 bits.
    SHA2_384,
    /// SHA2, 512 bits.
    SHA2_512,
    /// SHA1
    SHA1,
}

impl SignatureHash {
    pub fn name(&self) -> Name {
        match *self {
            SignatureHash::SHA2_256 => RSA_SHA2_256,
            SignatureHash::SHA2_384 => unreachable!(),
            SignatureHash::SHA2_512 => RSA_SHA2_512,
            SignatureHash::SHA1 => SSH_RSA,
        }
    }

    fn to_rsa_hash(&self) -> rsa::hash::Hash {
        use rsa::hash::Hash;
        match *self {
            SignatureHash::SHA2_256 => Hash::SHA2_256,
            SignatureHash::SHA2_384 => Hash::SHA2_384,
            SignatureHash::SHA2_512 => Hash::SHA2_512,
            SignatureHash::SHA1 => Hash::SHA1,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        use digest::Digest;
        match *self {
            SignatureHash::SHA2_256 => sha2::Sha256::new_with_prefix(data).finalize().to_vec(),
            SignatureHash::SHA2_384 => sha2::Sha384::new_with_prefix(data).finalize().to_vec(),
            SignatureHash::SHA2_512 => sha2::Sha512::new_with_prefix(data).finalize().to_vec(),
            SignatureHash::SHA1 => sha1::Sha1::new_with_prefix(data).finalize().to_vec(),
        }
    }
}

/// Public key
#[derive(Eq, PartialEq, Debug)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(crate::ed25519::PublicKey),
    #[doc(hidden)]
    RSA {
        key: rsa::RsaPublicKey,
        hash: SignatureHash,
    },
    #[doc(hidden)]
    Ec { key: ec::EcPublicKey },
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let key_bytes = p.read_string()?;
                if key_algo != b"ssh-ed25519" || key_bytes.len() != crate::ed25519::PUBLICKEY_BYTES
                {
                    return Err(Error::CouldNotReadKey.into());
                }
                let p = crate::ed25519::PublicKey::from_bytes(key_bytes)?;
                Ok(PublicKey::Ed25519(p))
            }
            b"ssh-rsa" | b"rsa-sha2-256" | b"rsa-sha2-512" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                debug!("{:?}", std::str::from_utf8(key_algo));
                if key_algo != b"ssh-rsa"
                    && key_algo != b"rsa-sha2-256"
                    && key_algo != b"rsa-sha2-512"
                {
                    return Err(Error::CouldNotReadKey.into());
                }
                let e = rsa::BigUint::from_bytes_be(p.read_string()?);
                let n = rsa::BigUint::from_bytes_be(p.read_string()?);
                Ok(PublicKey::RSA {
                    key: rsa::RsaPublicKey::new(n, e)?,
                    hash: {
                        if algo == b"rsa-sha2-256" {
                            SignatureHash::SHA2_256
                        } else if algo == b"rsa-sha2-512" {
                            SignatureHash::SHA2_512
                        } else {
                            SignatureHash::SHA1
                        }
                    },
                })
            }
            _ => Err(Error::CouldNotReadKey.into()),
        }
    }

    /// Algorithm name for that key.
    pub fn name(&self) -> &'static str {
        match *self {
            PublicKey::Ed25519(_) => ED25519.0,
            PublicKey::RSA { ref hash, .. } => hash.name().0,
            PublicKey::Ec { ref key } => key.algorithm_name(),
        }
    }

    /// Verify a signature.
    pub fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                crate::ed25519::verify_detached(&sig, buffer, &public)
            }
            &PublicKey::RSA { ref key, ref hash } => {
                use rsa::PublicKey;
                key.verify(
                    rsa::padding::PaddingScheme::PKCS1v15Sign {
                        hash: Some(hash.to_rsa_hash()),
                    },
                    &hash.hash(buffer),
                    sig,
                )
                .is_ok()
            }
            &PublicKey::Ec { ref key, .. } => ec_verify(key, buffer, sig).is_ok(),
        }
    }

    /// Compute the key fingerprint, hashed with sha2-256.
    pub fn fingerprint(&self) -> String {
        use super::PublicKeyBase64;
        use digest::Digest;
        use sha2::Sha256;
        let key = self.public_key_bytes();
        data_encoding::BASE64_NOPAD.encode(&Sha256::digest(&key[..]))
    }

    pub fn set_algorithm(&mut self, algorithm: &[u8]) {
        if let PublicKey::RSA { ref mut hash, .. } = self {
            if algorithm == b"rsa-sha2-512" {
                *hash = SignatureHash::SHA2_512
            } else if algorithm == b"rsa-sha2-256" {
                *hash = SignatureHash::SHA2_256
            } else if algorithm == b"ssh-rsa" {
                *hash = SignatureHash::SHA1
            }
        }
    }
}

impl Verify for PublicKey {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
}

/// Public key exchange algorithms.
pub enum KeyPair {
    Ed25519(crate::ed25519::SecretKey),
    RSA {
        key: rsa::RsaPrivateKey,
        hash: SignatureHash,
    },
    Ec {
        key: ec::EcPrivateKey,
    },
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyPair::Ed25519(ref key) => write!(
                f,
                "Ed25519 {{ public: {:?}, secret: (hidden) }}",
                key.public_as_bytes()
            ),
            KeyPair::RSA { .. } => write!(f, "RSA {{ (hidden) }}"),
            KeyPair::Ec { ref key } => write!(f, "Ec {{ key: {:?} }}", key),
        }
    }
}

impl<'b> crate::encoding::Bytes for &'b KeyPair {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

impl KeyPair {
    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> PublicKey {
        match self {
            &KeyPair::Ed25519(ref key) => PublicKey::Ed25519(key.to_public_key()),
            &KeyPair::RSA { ref key, ref hash } => PublicKey::RSA {
                key: key.to_public_key(),
                hash: hash.clone(),
            },
            &KeyPair::Ec { ref key } => PublicKey::Ec {
                key: key.to_public_key(),
            },
        }
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            KeyPair::RSA { ref hash, .. } => hash.name().0,
            KeyPair::Ec { ref key } => key.algorithm_name(),
        }
    }

    /// Generate a key pair.
    pub fn generate_ed25519() -> Option<Self> {
        Some(KeyPair::Ed25519(crate::ed25519::keypair()))
    }

    pub fn generate_rsa(bits: usize, hash: SignatureHash) -> Option<Self> {
        let key = rsa::RsaPrivateKey::new(&mut crate::key::safe_rng(), bits).ok()?;
        Some(KeyPair::RSA { key, hash })
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(
                crate::ed25519::sign_detached(to_sign.as_ref(), secret).0,
            ))),
            &KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA {
                bytes: rsa_signature(hash, key, to_sign.as_ref())?,
                hash: *hash,
            }),
            &KeyPair::Ec { ref key } => Ok(Signature::Ecdsa {
                bytes: ec_signature(key, to_sign.as_ref())?,
                algorithm_name: key.algorithm_name(),
            }),
        }
    }

    #[doc(hidden)]
    /// This is used by the server to sign the initial DH kex
    /// message. Note: we are not signing the same kind of thing as in
    /// the function below, `add_self_signature`.
    pub fn add_signature<H: AsRef<[u8]>>(
        &self,
        buffer: &mut CryptoVec,
        to_sign: H,
    ) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = crate::ed25519::sign_detached(to_sign.as_ref(), secret);

                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            &KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, to_sign.as_ref())?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            &KeyPair::Ec { ref key } => {
                let signature = ec_signature(key, to_sign.as_ref())?;
                let name = key.algorithm_name().as_bytes();
                buffer.push_u32_be((name.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name);
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    /// This is used by the client for authentication. Note: we are
    /// not signing the same kind of thing as in the above function,
    /// `add_signature`.
    pub fn add_self_signature(&self, buffer: &mut CryptoVec) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = crate::ed25519::sign_detached(&buffer, secret);
                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            &KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, buffer)?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            &KeyPair::Ec { ref key } => {
                let signature = ec_signature(key, buffer)?;
                let name = key.algorithm_name().as_bytes();
                buffer.push_u32_be((name.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name);
                buffer.extend_ssh_string(&signature);
            }
        }
        Ok(())
    }
}

fn rsa_signature(
    hash: &SignatureHash,
    key: &rsa::RsaPrivateKey,
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    key.sign(
        rsa::padding::PaddingScheme::PKCS1v15Sign {
            hash: Some(hash.to_rsa_hash()),
        },
        &hash.hash(b),
    )
    .map_err(Error::from)
}

fn ec_signature(key: &ec::EcPrivateKey, b: &[u8]) -> Result<Vec<u8>, Error> {
    let (r, s) = key.try_sign(b)?;
    let mut buf = Vec::new();
    buf.extend_ssh_mpint(&r);
    buf.extend_ssh_mpint(&s);
    Ok(buf)
}

fn ec_verify(key: &ec::EcPublicKey, b: &[u8], sig: &[u8]) -> Result<(), Error> {
    let mut reader = sig.reader(0);
    key.verify(b, reader.read_mpint()?, reader.read_mpint()?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8]) -> Result<PublicKey, Error> {
    let mut pos = p.reader(0);
    let t = pos.read_string()?;
    if t == crate::KEYTYPE_ED25519 {
        if let Ok(pubkey) = pos.read_string() {
            let p = crate::ed25519::PublicKey::from_bytes(pubkey)?;
            return Ok(PublicKey::Ed25519(p));
        }
    }
    if t == crate::KEYTYPE_RSA {
        let e = rsa::BigUint::from_bytes_be(pos.read_string()?);
        let n = rsa::BigUint::from_bytes_be(pos.read_string()?);
        return Ok(PublicKey::RSA {
            key: rsa::RsaPublicKey::new(n, e)?,
            hash: SignatureHash::SHA2_256,
        });
    }
    if t == crate::KEYTYPE_ECDSA_SHA2_NISTP256 || t == crate::KEYTYPE_ECDSA_SHA2_NISTP384 {
        let ident = pos.read_string()?;
        let q = pos.read_string()?;

        let key = ec::EcPublicKey::from_sec1_bytes(t, q)?;

        if key.ident().as_bytes() != ident {
            return Err(Error::CouldNotReadKey);
        }

        return Ok(PublicKey::Ec { key });
    }
    Err(Error::CouldNotReadKey.into())
}

/// Obtain a cryptographic-safe random number generator.
pub fn safe_rng() -> impl rand::CryptoRng + rand::RngCore {
    rand::thread_rng()
}
