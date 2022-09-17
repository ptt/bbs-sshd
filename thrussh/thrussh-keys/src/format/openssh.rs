use crate::bcrypt_pbkdf;
use crate::encoding::Reader;
use crate::key;
use crate::Error;
use cryptovec::CryptoVec;
use openssl::bn::BigNum;
use openssl::symm::{Cipher, Crypter, Mode};
use rsa::{BigUint, RsaPrivateKey};

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&[u8]>) -> Result<key::KeyPair, Error> {
    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = secret.reader(15);

        let ciphername = position.read_string()?;
        let kdfname = position.read_string()?;
        let kdfoptions = position.read_string()?;

        let nkeys = position.read_u32()?;

        // Read all public keys
        for _ in 0..nkeys {
            position.read_string()?;
        }

        // Read all secret keys
        let secret_ = position.read_string()?;
        let secret = decrypt_secret_key(ciphername, kdfname, kdfoptions, password, secret_)?;
        let mut position = secret.reader(0);
        let _check0 = position.read_u32()?;
        let _check1 = position.read_u32()?;
        for _ in 0..nkeys {
            let key_type = position.read_string()?;
            if key_type == crate::KEYTYPE_ED25519 {
                let pubkey = position.read_string()?;
                let seckey = position.read_string()?;
                let _comment = position.read_string()?;
                assert_eq!(pubkey, &seckey[32..]);
                use key::ed25519::*;
                let mut secret = SecretKey::new_zeroed();
                secret.key.clone_from_slice(seckey);
                return Ok(key::KeyPair::Ed25519(secret));
            } else if key_type == crate::KEYTYPE_RSA {
                let n = BigUint::from_bytes_be(position.read_string()?);
                let e = BigUint::from_bytes_be(position.read_string()?);
                let d = BigUint::from_bytes_be(position.read_string()?);
                let iqmp = BigUint::from_bytes_be(position.read_string()?);
                let p = BigUint::from_bytes_be(position.read_string()?);
                let q = BigUint::from_bytes_be(position.read_string()?);

                let mut key = RsaPrivateKey::from_components(n, e, d, vec![p, q]);
                key.validate()?;
                key.precompute()?;

                let computed_iqmp = key.crt_coefficient().unwrap();
                if computed_iqmp != iqmp {
                    return Err(rsa::errors::Error::InvalidCoefficient.into());
                }

                return Ok(key::KeyPair::RSA {
                    key,
                    hash: key::SignatureHash::SHA2_512,
                });
            } else if key_type == crate::KEYTYPE_ECDSA_SHA2_NISTP256
                || key_type == crate::KEYTYPE_ECDSA_SHA2_NISTP384
                || key_type == crate::KEYTYPE_ECDSA_SHA2_NISTP521
            {
                let ident = position.read_string()?;
                let pubkey = position.read_string()?;
                let seckey = position.read_string()?;
                let _comment = position.read_string()?;

                let typ = crate::key::EcKeyType::new_from_name(key_type).unwrap();
                if typ.ident().as_bytes() != ident {
                    return Err(Error::CouldNotReadKey.into());
                }

                use openssl::ec::*;
                use openssl::pkey::Private;
                let group = EcGroup::from_curve_name(typ.curve_nid())?;
                let mut cx = openssl::bn::BigNumContext::new()?;
                let point = EcPoint::from_bytes(&group, pubkey, &mut cx)?;
                let private = BigNum::from_slice(seckey)?;
                let key = openssl::ec::EcKey::<Private>::from_private_components(
                    &group, &private, &point,
                )?;
                return Ok(key::KeyPair::Ec { key, typ });
            } else {
                return Err(Error::UnsupportedKeyType(key_type.to_vec()).into());
            }
        }
        Err(Error::CouldNotReadKey.into())
    } else {
        Err(Error::CouldNotReadKey.into())
    }
}

fn decrypt_secret_key(
    ciphername: &[u8],
    kdfname: &[u8],
    kdfoptions: &[u8],
    password: Option<&[u8]>,
    secret_key: &[u8],
) -> Result<Vec<u8>, Error> {
    if kdfname == b"none" {
        if password.is_none() {
            Ok(secret_key.to_vec())
        } else {
            Err(Error::CouldNotReadKey.into())
        }
    } else if let Some(password) = password {
        let mut key = CryptoVec::new();
        let cipher = match ciphername {
            b"aes128-cbc" => {
                key.resize(16 + 16);
                Cipher::aes_128_cbc()
            }
            b"aes128-ctr" => {
                key.resize(16 + 16);
                Cipher::aes_128_ctr()
            }
            b"aes256-cbc" => {
                key.resize(16 + 32);
                Cipher::aes_256_cbc()
            }
            b"aes256-ctr" => {
                key.resize(16 + 32);
                Cipher::aes_256_ctr()
            }
            _ => return Err(Error::CouldNotReadKey.into()),
        };

        match kdfname {
            b"bcrypt" => {
                let mut kdfopts = kdfoptions.reader(0);
                let salt = kdfopts.read_string()?;
                let rounds = kdfopts.read_u32()?;
                bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut key);
            }
            _kdfname => {
                return Err(Error::CouldNotReadKey.into());
            }
        };
        let iv = &key[32..];
        let key = &key[..32];
        let mut c = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))?;
        c.pad(false);
        let mut dec = vec![0; secret_key.len() + 32];
        let n = c.update(&secret_key, &mut dec)?;
        let n = n + c.finalize(&mut dec[n..])?;
        dec.truncate(n);
        Ok(dec)
    } else {
        Err(Error::KeyIsEncrypted.into())
    }
}
