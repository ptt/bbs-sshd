use super::Encryption;
use crate::key;
use crate::key::SignatureHash;
use crate::Error;
use bit_vec::BitVec;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::Rng;
use std;
use std::borrow::Cow;
use yasna;
use yasna::BERReaderSeq;

const PBES2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 13];
const PBKDF2: &'static [u64] = &[1, 2, 840, 113549, 1, 5, 12];
const HMAC_SHA256: &'static [u64] = &[1, 2, 840, 113549, 2, 9];
const AES256CBC: &'static [u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const ED25519: &'static [u64] = &[1, 3, 101, 112];
const RSA: &'static [u64] = &[1, 2, 840, 113549, 1, 1, 1];

/// Decode a PKCS#8-encoded private key.
pub fn decode_pkcs8(ciphertext: &[u8], password: Option<&[u8]>) -> Result<key::KeyPair, Error> {
    let secret = if let Some(pass) = password {
        // let mut sec = Vec::new();
        Cow::Owned(yasna::parse_der(&ciphertext, |reader| {
            reader.read_sequence(|reader| {
                // Encryption parameters
                let parameters = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    if oid.components().as_slice() == PBES2 {
                        asn1_read_pbes2(reader)
                    } else {
                        Ok(Err(Error::UnknownAlgorithm(oid)).into())
                    }
                })?;
                // Ciphertext
                let ciphertext = reader.next().read_bytes()?;
                Ok(parameters.map(|p| p.decrypt(pass, &ciphertext)))
            })
        })???)
    } else {
        Cow::Borrowed(ciphertext)
    };
    yasna::parse_der(&secret, |reader| {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u64()?;
            if version == 0 {
                Ok(read_key_v0(reader))
            } else if version == 1 {
                Ok(read_key_v1(reader))
            } else {
                Ok(Err(Error::CouldNotReadKey.into()))
            }
        })
    })?
}

fn asn1_read_pbes2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Algorithms, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        // PBES2 has two components.
        // 1. Key generation algorithm
        let keygen = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == PBKDF2 {
                asn1_read_pbkdf2(reader)
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        // 2. Encryption algorithm.
        let algorithm = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == AES256CBC {
                asn1_read_aes256cbc(reader)
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        Ok(keygen.and_then(|keygen| algorithm.map(|algo| Algorithms::Pbes2(keygen, algo))))
    })
}

fn asn1_read_pbkdf2(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<KeyDerivation, Error>, yasna::ASN1Error> {
    reader.next().read_sequence(|reader| {
        let salt = reader.next().read_bytes()?;
        let rounds = reader.next().read_u64()?;
        let digest = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if oid.components().as_slice() == HMAC_SHA256 {
                reader.next().read_null()?;
                Ok(Ok(pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>))
            } else {
                Ok(Err(Error::UnknownAlgorithm(oid)))
            }
        })?;
        Ok(digest.map(|digest| KeyDerivation::Pbkdf2 {
            salt,
            rounds,
            digest,
        }))
    })
}

fn asn1_read_aes256cbc(
    reader: &mut yasna::BERReaderSeq,
) -> Result<Result<Encryption, Error>, yasna::ASN1Error> {
    let iv = reader.next().read_bytes()?;
    let mut i = [0; 16];
    i.clone_from_slice(&iv);
    Ok(Ok(Encryption::Aes256Cbc(i)))
}

fn write_key_v1(writer: &mut yasna::DERWriterSeq, secret: &crate::ed25519::SecretKey) {
    writer.next().write_u32(1);
    // write OID
    writer.next().write_sequence(|writer| {
        writer
            .next()
            .write_oid(&ObjectIdentifier::from_slice(ED25519));
    });
    let seed = yasna::construct_der(|writer| writer.write_bytes(&secret.to_bytes()));
    writer.next().write_bytes(&seed);
    writer
        .next()
        .write_tagged(yasna::Tag::context(1), |writer| {
            let public = secret.public_as_bytes().as_slice();
            writer.write_bitvec(&BitVec::from_bytes(public))
        })
}

fn read_key_v1(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader
        .next()
        .read_sequence(|reader| reader.next().read_oid())?;
    if oid.components().as_slice() == ED25519 {
        use crate::ed25519::{PublicKey, SecretKey};
        let secret = {
            let s = yasna::parse_der(&reader.next().read_bytes()?, |reader| reader.read_bytes())?;
            SecretKey::from_bytes(&s)?
        };
        let _public = {
            let public = reader
                .next()
                .read_tagged(yasna::Tag::context(1), |reader| reader.read_bitvec())?
                .to_bytes();
            PublicKey::from_bytes(&public)?
        };
        Ok(key::KeyPair::Ed25519(secret))
    } else {
        Err(Error::CouldNotReadKey.into())
    }
}

fn write_key_v0(writer: &mut yasna::DERWriterSeq, key: &rsa::RsaPrivateKey) {
    writer.next().write_u32(0);
    // write OID
    writer.next().write_sequence(|writer| {
        writer.next().write_oid(&ObjectIdentifier::from_slice(RSA));
        writer.next().write_null()
    });
    let bytes = yasna::construct_der(|writer| {
        use rsa::PublicKeyParts;
        writer.write_sequence(|writer| {
            use num_bigint::BigUint;
            use num_integer::Integer;
            use num_traits::identities::One;

            let primes = key.primes();
            let (p, q) = (&primes[0], &primes[1]);
            let one = &rsa::BigUint::one();
            let dmp1 = key.d().mod_floor(&(p.clone() - one)); // d mod p-1
            let dmq1 = key.d().mod_floor(&(q.clone() - one)); // d mod q-1
            let iqmp = key.crt_coefficient().unwrap();

            writer.next().write_u32(0);
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.n().to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.e().to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&key.d().to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&p.to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&q.to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&dmp1.to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&dmq1.to_bytes_be()));
            writer
                .next()
                .write_biguint(&BigUint::from_bytes_be(&iqmp.to_bytes_be()));
        })
    });
    writer.next().write_bytes(&bytes);
}

fn read_key_v0(reader: &mut BERReaderSeq) -> Result<key::KeyPair, Error> {
    let oid = reader.next().read_sequence(|reader| {
        let oid = reader.next().read_oid()?;
        reader.next().read_null()?;
        Ok(oid)
    })?;
    if oid.components().as_slice() == RSA {
        let seq = &reader.next().read_bytes()?;
        let rsa: Result<rsa::RsaPrivateKey, Error> = yasna::parse_der(seq, |reader| {
            reader.read_sequence(|reader| {
                let version = reader.next().read_u32()?;
                if version != 0 {
                    return Ok(Err(Error::CouldNotReadKey.into()));
                }
                let mut read_key = || -> Result<rsa::RsaPrivateKey, Error> {
                    let (n, e, d, p, q, _dmp1, _dmq1, _iqmp) = (
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                        rsa::BigUint::from_bytes_be(&reader.next().read_biguint()?.to_bytes_be()),
                    );
                    let mut key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]);
                    key.validate()?;
                    key.precompute()?;
                    // TODO: Check dmp1, dmq1, iqmp
                    Ok(key)
                };
                Ok(read_key())
            })
        })?;
        Ok(key::KeyPair::RSA {
            key: rsa?,
            hash: SignatureHash::SHA2_256,
        })
    } else {
        Err(Error::CouldNotReadKey.into())
    }
}

#[test]
fn test_read_write_pkcs8() {
    let secret = crate::ed25519::keypair();
    let key = key::KeyPair::Ed25519(secret);
    let password = b"blabla";
    let ciphertext = encode_pkcs8_encrypted(password, 100, &key).unwrap();
    let key = decode_pkcs8(&ciphertext, Some(password)).unwrap();
    match key {
        key::KeyPair::Ed25519 { .. } => println!("Ed25519"),
        key::KeyPair::RSA { .. } => println!("RSA"),
        key::KeyPair::Ec { ref key } => println!("EC {{ {} }}", key.algorithm_name()),
    }
}

use yasna::models::ObjectIdentifier;
/// Encode a password-protected PKCS#8-encoded private key.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &key::KeyPair,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0; 64];
    crate::key::safe_rng().fill(&mut salt);
    let mut iv = [0; 16];
    crate::key::safe_rng().fill(&mut iv);
    let mut dkey = [0; 32]; // AES256-CBC
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, &salt, rounds, &mut dkey);

    let plaintext = encode_pkcs8(key);
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(&dkey.into(), &iv.into())
        .encrypt_padded_vec_mut::<block_padding::Pkcs7>(&plaintext);

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // Encryption parameters
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(PBES2));
                asn1_write_pbes2(writer.next(), rounds as u64, &salt, &iv)
            });
            // Ciphertext
            writer.next().write_bytes(&ciphertext[..])
        })
    }))
}

/// Encode a Decode a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &key::KeyPair) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| match *key {
            key::KeyPair::Ed25519(ref secret) => write_key_v1(writer, secret),
            key::KeyPair::RSA { ref key, .. } => write_key_v0(writer, key),
            key::KeyPair::Ec { .. } => unimplemented!(),
        })
    })
}

fn asn1_write_pbes2(writer: yasna::DERWriter, rounds: u64, salt: &[u8], iv: &[u8]) {
    writer.write_sequence(|writer| {
        // 1. Key generation algorithm
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(PBKDF2));
            asn1_write_pbkdf2(writer.next(), rounds, salt)
        });
        // 2. Encryption algorithm.
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(AES256CBC));
            writer.next().write_bytes(iv)
        });
    })
}

fn asn1_write_pbkdf2(writer: yasna::DERWriter, rounds: u64, salt: &[u8]) {
    writer.write_sequence(|writer| {
        writer.next().write_bytes(salt);
        writer.next().write_u64(rounds);
        writer.next().write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(HMAC_SHA256));
            writer.next().write_null()
        })
    })
}

enum Algorithms {
    Pbes2(KeyDerivation, Encryption),
}

impl Algorithms {
    fn decrypt(&self, password: &[u8], cipher: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithms::Pbes2(ref der, ref enc) => {
                let mut key = enc.key();
                der.derive(password, &mut key)?;
                let out = enc.decrypt(&key, cipher)?;
                Ok(out)
            }
        }
    }
}

impl KeyDerivation {
    fn derive(&self, password: &[u8], key: &mut [u8]) -> Result<(), Error> {
        match *self {
            KeyDerivation::Pbkdf2 {
                ref salt,
                rounds,
                digest,
            } => digest(password, salt, rounds as u32, key),
        }
        Ok(())
    }
}

enum Key {
    K128([u8; 16]),
    K256([u8; 32]),
}

impl std::ops::Deref for Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            Key::K128(ref k) => k,
            Key::K256(ref k) => k,
        }
    }
}

impl std::ops::DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        match *self {
            Key::K128(ref mut k) => k,
            Key::K256(ref mut k) => k,
        }
    }
}

impl Encryption {
    fn key(&self) -> Key {
        match *self {
            Encryption::Aes128Cbc(_) => Key::K128([0; 16]),
            Encryption::Aes256Cbc(_) => Key::K256([0; 32]),
        }
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_impl(key, ciphertext)
            .ok_or(Error::CouldNotReadKey)
    }

    fn decrypt_impl(&self, key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        match *self {
            Encryption::Aes128Cbc(ref iv) => {
                cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                    .ok()?
                    .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
                    .ok()
            }
            Encryption::Aes256Cbc(ref iv) => {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .ok()?
                    .decrypt_padded_vec_mut::<block_padding::Pkcs7>(ciphertext)
                    .ok()
            }
        }
    }
}

type KdfFn = fn(password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8]);

enum KeyDerivation {
    Pbkdf2 {
        salt: Vec<u8>,
        rounds: u64,
        digest: KdfFn,
    },
}
