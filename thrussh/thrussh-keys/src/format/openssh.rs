use crate::bcrypt_pbkdf;
use crate::ec;
use crate::encoding::Reader;
use crate::key;
use crate::Error;
use cryptovec::CryptoVec;
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
            {
                let ident = position.read_string()?;
                let pubkey = position.read_string()?;
                let seckey = position.read_string()?;
                let _comment = position.read_string()?;

                let key = ec::EcPrivateKey::new_from_secret_scalar(key_type, seckey)?;

                if ident != key.ident().as_bytes() {
                    return Err(Error::CouldNotReadKey);
                }

                let pubkey = ec::EcPublicKey::from_sec1_bytes(key_type, pubkey)?;
                if pubkey.to_sec1_bytes() != key.to_public_key().to_sec1_bytes() {
                    return Err(Error::CouldNotReadKey);
                }

                return Ok(key::KeyPair::Ec { key });
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
        match ciphername {
            b"aes128-cbc" => cbc_decrypt(
                kdf_init::<cbc::Decryptor<aes::Aes128>>(kdfname, kdfoptions, password)?,
                secret_key,
            ),
            b"aes128-ctr" => ctr_decrypt(
                kdf_init::<ctr::Ctr128BE<aes::Aes128>>(kdfname, kdfoptions, password)?,
                secret_key,
            ),
            b"aes256-cbc" => cbc_decrypt(
                kdf_init::<cbc::Decryptor<aes::Aes256>>(kdfname, kdfoptions, password)?,
                secret_key,
            ),
            b"aes256-ctr" => ctr_decrypt(
                kdf_init::<ctr::Ctr128BE<aes::Aes256>>(kdfname, kdfoptions, password)?,
                secret_key,
            ),
            _ => return Err(Error::CouldNotReadKey.into()),
        }
    } else {
        Err(Error::KeyIsEncrypted.into())
    }
}

fn kdf_init<C>(kdfname: &[u8], kdfoptions: &[u8], password: &[u8]) -> Result<C, Error>
where
    C: cipher::KeyIvInit,
{
    let key_len = C::key_size();
    let iv_len = C::iv_size();

    let mut key = CryptoVec::new();
    key.resize(key_len + iv_len);
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

    let (key, iv) = key.split_at(key_len);
    Ok(C::new(key.into(), iv.into()))
}

fn cbc_decrypt<C>(decryptor: C, secret_key: &[u8]) -> Result<Vec<u8>, Error>
where
    C: cipher::BlockDecryptMut,
{
    decryptor
        .decrypt_padded_vec_mut::<block_padding::NoPadding>(secret_key)
        .map_err(|_| Error::CouldNotReadKey)
}

fn ctr_decrypt<C>(mut stream_cipher: C, secret_key: &[u8]) -> Result<Vec<u8>, Error>
where
    C: cipher::StreamCipher,
{
    let mut buf = secret_key.to_vec();
    stream_cipher.apply_keystream(&mut buf);
    Ok(buf)
}
