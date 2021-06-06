use openssl::{error::ErrorStack, pkey::Private, rsa::Rsa};
use thrussh_keys::key::{
    ed25519, KeyPair, Name, SignatureHash, ED25519, RSA_SHA2_256, RSA_SHA2_512, SSH_RSA,
};

#[derive(Debug)]
pub(crate) enum Error {
    SSHKeys(ssh_keys::Error),
    OpenSSL(openssl::error::ErrorStack),
    NoKeys,
}

impl From<ssh_keys::Error> for Error {
    fn from(e: ssh_keys::Error) -> Self {
        Error::SSHKeys(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSSL(e)
    }
}

fn make_rsa_key(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    iqmp: &[u8],
    p: &[u8],
    q: &[u8],
) -> Result<Rsa<Private>, ErrorStack> {
    use openssl::bn::{BigNum, BigNumContext};
    let d = BigNum::from_slice(d)?;
    let p = BigNum::from_slice(p)?;
    let q = BigNum::from_slice(q)?;
    let builder = openssl::rsa::RsaPrivateKeyBuilder::new(
        BigNum::from_slice(n)?,
        BigNum::from_slice(e)?,
        d.to_owned()?,
    )?
    .set_factors(p.to_owned()?, q.to_owned()?)?;

    let mut p1 = p;
    let mut q1 = q;
    let mut dmp1 = BigNum::new()?;
    let mut dmq1 = BigNum::new()?;
    let mut cx = BigNumContext::new()?;
    p1.sub_word(1)?;
    q1.sub_word(1)?;
    dmp1.nnmod(&d, &p1, &mut cx)?;
    dmq1.nnmod(&d, &q1, &mut cx)?;

    Ok(builder
        .set_crt_params(dmp1, dmq1, BigNum::from_slice(iqmp)?)?
        .build())
}

pub(crate) fn convert_key<'a, 'b, 'c>(
    ssh_key: &'a str,
    keys: &'b mut Vec<KeyPair>,
    key_algos: &'c mut Vec<Name>,
) -> Result<(), Error> {
    let key = ssh_keys::openssh::parse_private_key(ssh_key)
        .map_err(Error::from)?
        .into_iter()
        .next();
    match key {
        Some(ssh_keys::PrivateKey::Rsa {
            ref n,
            ref e,
            ref d,
            ref iqmp,
            ref p,
            ref q,
        }) => {
            let key = make_rsa_key(n, e, d, iqmp, p, q).map_err(Error::from)?;

            keys.push(KeyPair::RSA {
                key: key.clone(),
                hash: SignatureHash::SHA1,
            });
            key_algos.push(SSH_RSA);

            keys.push(KeyPair::RSA {
                key: key.clone(),
                hash: SignatureHash::SHA2_512,
            });
            key_algos.push(RSA_SHA2_512);

            keys.push(KeyPair::RSA {
                key,
                hash: SignatureHash::SHA2_256,
            });
            key_algos.push(RSA_SHA2_256);
        }
        Some(ssh_keys::PrivateKey::Ed25519(key)) => {
            keys.push(KeyPair::Ed25519(ed25519::SecretKey { key }));
            key_algos.push(ED25519);
        }
        None => return Err(Error::NoKeys),
    }
    Ok(())
}
