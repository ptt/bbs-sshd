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
use crate::encoding::{Encoding, Reader};
pub use crate::signature::*;
use crate::Error;
use cryptovec::CryptoVec;
use openssl::pkey::{Private, Public};

/// Keys for elliptic curve Ed25519 cryptography.
pub mod ed25519 {
    pub use sodium::ed25519::{keypair, sign_detached, verify_detached, PublicKey, SecretKey};
}

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

    fn to_message_digest(&self) -> openssl::hash::MessageDigest {
        use openssl::hash::MessageDigest;
        match *self {
            SignatureHash::SHA2_256 => MessageDigest::sha256(),
            SignatureHash::SHA2_384 => MessageDigest::sha384(),
            SignatureHash::SHA2_512 => MessageDigest::sha512(),
            SignatureHash::SHA1 => MessageDigest::sha1(),
        }
    }
}

/// Key type of an EC key
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct EcKeyType {
    pub hash: SignatureHash,
    pub ident: &'static str,
}

impl EcKeyType {
    pub fn new_from_name(name: &[u8]) -> Option<EcKeyType> {
        Some(match name {
            crate::KEYTYPE_ECDSA_SHA2_NISTP256 => EcKeyType {
                hash: SignatureHash::SHA2_256,
                ident: &"nistp256",
            },
            crate::KEYTYPE_ECDSA_SHA2_NISTP384 => EcKeyType {
                hash: SignatureHash::SHA2_384,
                ident: &"nistp384",
            },
            crate::KEYTYPE_ECDSA_SHA2_NISTP521 => EcKeyType {
                hash: SignatureHash::SHA2_512,
                ident: &"nistp521",
            },
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match (self.hash, self.ident) {
            (SignatureHash::SHA2_256, "nistp256") => "ecdsa-sha2-nistp256",
            (SignatureHash::SHA2_384, "nistp384") => "ecdsa-sha2-nistp384",
            (SignatureHash::SHA2_512, "nistp521") => "ecdsa-sha2-nistp521",
            _ => unreachable!(),
        }
    }

    pub fn ident(&self) -> &'static str {
        self.ident
    }

    pub fn curve_nid(&self) -> openssl::nid::Nid {
        use openssl::nid::Nid;
        match self.ident {
            "nistp256" => Nid::X9_62_PRIME256V1,
            "nistp384" => Nid::SECP384R1,
            "nistp521" => Nid::SECP521R1,
            _ => unreachable!(),
        }
    }
}

/// Public key
#[derive(Eq, PartialEq, Debug)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(sodium::ed25519::PublicKey),
    #[doc(hidden)]
    RSA {
        key: OpenSSLPKey,
        hash: SignatureHash,
    },
    #[doc(hidden)]
    Ec { key: OpenSSLPKey, typ: EcKeyType },
}

/// A public key from OpenSSL.
pub struct OpenSSLPKey(pub openssl::pkey::PKey<Public>);

use std::cmp::{Eq, PartialEq};
impl PartialEq for OpenSSLPKey {
    fn eq(&self, b: &OpenSSLPKey) -> bool {
        self.0.public_eq(&b.0)
    }
}
impl Eq for OpenSSLPKey {}
impl std::fmt::Debug for OpenSSLPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSLPKey {{ (hidden) }}")
    }
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let key_bytes = p.read_string()?;
                if key_algo != b"ssh-ed25519" || key_bytes.len() != sodium::ed25519::PUBLICKEY_BYTES
                {
                    return Err(Error::CouldNotReadKey.into());
                }
                let mut p = sodium::ed25519::PublicKey {
                    key: [0; sodium::ed25519::PUBLICKEY_BYTES],
                };
                p.key.clone_from_slice(key_bytes);
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
                let key_e = p.read_string()?;
                let key_n = p.read_string()?;
                use openssl::bn::BigNum;
                use openssl::pkey::PKey;
                use openssl::rsa::Rsa;
                Ok(PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                        BigNum::from_slice(key_n)?,
                        BigNum::from_slice(key_e)?,
                    )?)?),
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
            PublicKey::Ec { ref typ, .. } => typ.name(),
        }
    }

    /// Verify a signature.
    pub fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                sodium::ed25519::verify_detached(&sig, buffer, &public)
            }
            &PublicKey::RSA { ref key, ref hash } => {
                use openssl::sign::*;
                let verify = || {
                    let mut verifier = Verifier::new(hash.to_message_digest(), &key.0)?;
                    verifier.update(buffer)?;
                    verifier.verify(&sig)
                };
                verify().unwrap_or(false)
            }
            &PublicKey::Ec { ref key, ref typ } => {
                if let Ok(key) = key.0.ec_key() {
                    ec_verify(&typ.hash, &key, buffer, sig).unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }

    /// Compute the key fingerprint, hashed with sha2-256.
    pub fn fingerprint(&self) -> String {
        use super::PublicKeyBase64;
        let key = self.public_key_bytes();
        data_encoding::BASE64_NOPAD.encode(&openssl::sha::sha256(&key[..]))
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
    Ed25519(sodium::ed25519::SecretKey),
    RSA {
        key: openssl::rsa::Rsa<Private>,
        hash: SignatureHash,
    },
    Ec {
        key: openssl::ec::EcKey<Private>,
        typ: EcKeyType,
    },
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyPair::Ed25519(ref key) => write!(
                f,
                "Ed25519 {{ public: {:?}, secret: (hidden) }}",
                &key.key[32..]
            ),
            KeyPair::RSA { .. } => write!(f, "RSA {{ (hidden) }}"),
            KeyPair::Ec { ref typ, .. } => write!(f, "Ec {{ {} }}", typ.name()),
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
            &KeyPair::Ed25519(ref key) => {
                let mut public = sodium::ed25519::PublicKey { key: [0; 32] };
                public.key.clone_from_slice(&key.key[32..]);
                PublicKey::Ed25519(public)
            }
            &KeyPair::RSA { ref key, ref hash } => {
                use openssl::pkey::PKey;
                use openssl::rsa::Rsa;
                let key = Rsa::from_public_components(
                    key.n().to_owned().unwrap(),
                    key.e().to_owned().unwrap(),
                )
                .unwrap();
                PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(key).unwrap()),
                    hash: hash.clone(),
                }
            }
            &KeyPair::Ec { ref key, ref typ } => {
                use openssl::ec::EcKey;
                use openssl::pkey::PKey;
                PublicKey::Ec {
                    key: OpenSSLPKey(
                        PKey::from_ec_key(
                            EcKey::from_public_key(key.group(), key.public_key()).unwrap(),
                        )
                        .unwrap(),
                    ),
                    typ: typ.clone(),
                }
            }
        }
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            KeyPair::RSA { ref hash, .. } => hash.name().0,
            KeyPair::Ec { ref typ, .. } => typ.name(),
        }
    }

    /// Generate a key pair.
    pub fn generate_ed25519() -> Option<Self> {
        let (public, secret) = sodium::ed25519::keypair();
        assert_eq!(&public.key, &secret.key[32..]);
        Some(KeyPair::Ed25519(secret))
    }

    pub fn generate_rsa(bits: usize, hash: SignatureHash) -> Option<Self> {
        let key = openssl::rsa::Rsa::generate(bits as u32).ok()?;
        Some(KeyPair::RSA { key, hash })
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(
                sodium::ed25519::sign_detached(to_sign.as_ref(), secret).0,
            ))),
            &KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA {
                bytes: rsa_signature(hash, key, to_sign.as_ref())?,
                hash: *hash,
            }),
            &KeyPair::Ec { ref key, ref typ } => Ok(Signature::Ecdsa {
                bytes: ec_signature(&typ.hash, key, to_sign.as_ref())?,
                typ: typ.clone(),
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
                let signature = sodium::ed25519::sign_detached(to_sign.as_ref(), secret);

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
            &KeyPair::Ec { ref key, ref typ } => {
                let signature = ec_signature(&typ.hash, key, to_sign.as_ref())?;
                let name = typ.name().as_bytes();
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
                let signature = sodium::ed25519::sign_detached(&buffer, secret);
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
            &KeyPair::Ec { ref key, ref typ } => {
                let signature = ec_signature(&typ.hash, key, buffer)?;
                let name = typ.name().as_bytes();
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
    key: &openssl::rsa::Rsa<Private>,
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    use openssl::pkey::*;
    use openssl::rsa::*;
    use openssl::sign::Signer;
    let pkey = PKey::from_rsa(Rsa::from_private_components(
        key.n().to_owned()?,
        key.e().to_owned()?,
        key.d().to_owned()?,
        key.p().unwrap().to_owned()?,
        key.q().unwrap().to_owned()?,
        key.dmp1().unwrap().to_owned()?,
        key.dmq1().unwrap().to_owned()?,
        key.iqmp().unwrap().to_owned()?,
    )?)?;
    let mut signer = Signer::new(hash.to_message_digest(), &pkey)?;
    signer.update(b)?;
    Ok(signer.sign_to_vec()?)
}

fn ec_signature(
    hash: &SignatureHash,
    key: &openssl::ec::EcKey<Private>,
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    let data = openssl::hash::hash(hash.to_message_digest(), b)?;
    let sig = openssl::ecdsa::EcdsaSig::sign(&data, key)?;
    let mut buf = Vec::new();
    buf.extend_ssh_mpint(&sig.r().to_vec());
    buf.extend_ssh_mpint(&sig.s().to_vec());
    Ok(buf)
}

fn ec_verify(
    hash: &SignatureHash,
    key: &openssl::ec::EcKey<Public>,
    b: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let data = openssl::hash::hash(hash.to_message_digest(), b)?;
    let mut reader = sig.reader(0);
    let sig = openssl::ecdsa::EcdsaSig::from_private_components(
        openssl::bn::BigNum::from_slice(reader.read_mpint()?)?,
        openssl::bn::BigNum::from_slice(reader.read_mpint()?)?,
    )?;
    Ok(sig.verify(&data, key)?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8]) -> Result<PublicKey, Error> {
    let mut pos = p.reader(0);
    let t = pos.read_string()?;
    if t == crate::KEYTYPE_ED25519 {
        if let Ok(pubkey) = pos.read_string() {
            use sodium::ed25519;
            let mut p = ed25519::PublicKey {
                key: [0; ed25519::PUBLICKEY_BYTES],
            };
            p.key.clone_from_slice(pubkey);
            return Ok(PublicKey::Ed25519(p));
        }
    }
    if t == crate::KEYTYPE_RSA {
        let e = pos.read_string()?;
        let n = pos.read_string()?;
        use openssl::bn::*;
        use openssl::pkey::*;
        use openssl::rsa::*;
        return Ok(PublicKey::RSA {
            key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                BigNum::from_slice(n)?,
                BigNum::from_slice(e)?,
            )?)?),
            hash: SignatureHash::SHA2_256,
        });
    }
    if t == crate::KEYTYPE_ECDSA_SHA2_NISTP256
        || t == crate::KEYTYPE_ECDSA_SHA2_NISTP384
        || t == crate::KEYTYPE_ECDSA_SHA2_NISTP521
    {
        use openssl::bn::*;
        use openssl::ec::*;
        use openssl::pkey::*;

        let typ = EcKeyType::new_from_name(t).unwrap();
        if pos.read_string()? != typ.ident().as_bytes() {
            return Err(Error::CouldNotReadKey.into());
        }

        let q = pos.read_string()?;
        let group = EcGroup::from_curve_name(typ.curve_nid())?;
        let mut cx = BigNumContext::new()?;
        let key = OpenSSLPKey(PKey::from_ec_key(EcKey::from_public_key(
            &group,
            EcPoint::from_bytes(&group, q, &mut cx)?.as_ref(),
        )?)?);
        return Ok(PublicKey::Ec { key, typ });
    }
    Err(Error::CouldNotReadKey.into())
}
