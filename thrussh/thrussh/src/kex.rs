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
use crate::session::Exchange;
use crate::{cipher, cipher::integrity};
use cryptovec::CryptoVec;
use openssl;
use openssl::hash::{DigestBytes, MessageDigest};
use std::cell::RefCell;
use thrussh_keys::encoding::Encoding;
use thrussh_keys::key::{KeyPair, PublicKey};

#[derive(Debug)]
pub enum Algorithms {
    Ecdh(ecdh::Algorithm),
    Dh(dh::Algorithm),
}

impl Algorithms {
    pub fn new(name: Name) -> Result<Self, crate::Error> {
        Ok(match name {
            CURVE25519 => Algorithms::Ecdh(ecdh::Algorithm::new_curve25519()?),
            DH_GROUP14_SHA1 => Algorithms::Dh(dh::Algorithm::new_group14_sha1()?),
            DH_GROUP14_SHA256 => Algorithms::Dh(dh::Algorithm::new_group14_sha256()?),
            _ => return Err(crate::Error::NoCommonKexAlgo),
        })
    }

    pub fn server_dh(
        &self,
        exchange: &Exchange,
        key: &KeyPair,
        payload: &[u8],
        reply: &mut CryptoVec,
    ) -> Result<Output, crate::Error> {
        match self {
            Algorithms::Ecdh(algo) => algo.server_dh(exchange, key, payload, reply),
            Algorithms::Dh(algo) => algo.server_dh(exchange, key, payload, reply),
        }
    }

    pub fn client_dh_init(&mut self, msg: &mut CryptoVec) -> Result<(), crate::Error> {
        match self {
            Algorithms::Ecdh(algo) => algo.client_dh_init(msg),
            Algorithms::Dh(_algo) => unimplemented!(),
        }
    }

    pub fn client_dh(
        &self,
        exchange: &Exchange,
        key: &PublicKey,
        payload: &[u8],
    ) -> Result<Output, crate::Error> {
        match self {
            Algorithms::Ecdh(algo) => algo.client_dh(exchange, key, payload),
            Algorithms::Dh(_algo) => unimplemented!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");
pub const DH_GROUP14_SHA1: Name = Name("diffie-hellman-group14-sha1");
pub const DH_GROUP14_SHA256: Name = Name("diffie-hellman-group14-sha256");

thread_local! {
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

pub struct Output {
    pub shared_secret: CryptoVec,
    pub exchange_hash: DigestBytes,
    pub digest: MessageDigest,
}

impl Output {
    pub fn keys<'a>(
        &'a self,
        session_id: &'a DigestBytes,
        is_client_to_server: bool,
    ) -> ComputeKeys<'a> {
        ComputeKeys {
            digest: self.digest.clone(),
            shared_secret: &self.shared_secret,
            session_id,
            exchange_hash: &self.exchange_hash,
            c_iv_enc_int: Self::c_tuple(is_client_to_server),
        }
    }

    pub fn make_cipher(
        &self,
        session_id: &DigestBytes,
        is_server: bool,
        cipher: cipher::Name,
        mac: Option<integrity::Name>,
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        // https://tools.ietf.org/html/rfc4253#section-7.2
        let local_to_remote =
            cipher::make_sealing_cipher(cipher, mac, &self.keys(session_id, !is_server))?;
        let remote_to_local =
            cipher::make_opening_cipher(cipher, mac, &self.keys(session_id, is_server))?;
        Ok(super::cipher::CipherPair {
            local_to_remote,
            remote_to_local,
        })
    }

    fn c_tuple(is_client_to_server: bool) -> (u8, u8, u8) {
        if is_client_to_server {
            (b'A', b'C', b'E')
        } else {
            (b'B', b'D', b'F')
        }
    }
}

pub mod ecdh {
    use crate::key::PubKey;
    use crate::session::Exchange;
    use crate::{key, msg};
    use cryptovec::CryptoVec;
    use openssl::hash::{hash, DigestBytes, MessageDigest};
    use openssl::rand::rand_bytes;
    use sodium::scalarmult::*;
    use thrussh_keys::encoding::{Encoding, Reader};
    use thrussh_keys::key::{KeyPair, PublicKey};

    // We used to support curve "NIST P-256" here, but the security of
    // that curve is controversial, see
    // http://safecurves.cr.yp.to/rigid.html

    pub struct Algorithm {
        local_pubkey: Option<GroupElement>,
        local_secret: Option<Scalar>,
        digest: MessageDigest,
    }

    impl std::fmt::Debug for Algorithm {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "ecdh::Algorithm {{ local_pubkey: {:?}, local_secret: [hidden], digest: {} }}",
                self.local_pubkey,
                self.digest.type_().short_name().unwrap_or("err"),
            )
        }
    }

    impl Algorithm {
        pub fn new_curve25519() -> Result<Self, crate::Error> {
            Ok(Algorithm {
                local_pubkey: None,
                local_secret: None,
                digest: MessageDigest::sha256(),
            })
        }

        pub fn server_dh(
            &self,
            exchange: &Exchange,
            key: &KeyPair,
            payload: &[u8],
            reply: &mut CryptoVec,
        ) -> Result<super::Output, crate::Error> {
            let mut r = payload.reader(0);
            super::check_packet_type(r.read_byte()?, msg::KEX_ECDH_INIT)?;

            let mut client_pubkey = GroupElement([0; 32]);
            super::checked_clone(&mut client_pubkey.0, r.read_string()?)?;
            debug!("client_pubkey: {:?}", client_pubkey);

            let mut server_secret = Scalar([0; 32]);
            rand_bytes(&mut server_secret.0)?;
            let server_pubkey = scalarmult_base(&server_secret);
            let shared_secret = scalarmult(&server_secret, &client_pubkey);
            let exchange_hash = self.compute_exchange_hash(
                key,
                exchange,
                &client_pubkey,
                &server_pubkey,
                &shared_secret,
            )?;

            // fill exchange.
            reply.clear();
            reply.push(msg::KEX_ECDH_REPLY);
            key.push_to(reply);
            reply.extend_ssh_string(&server_pubkey.0);
            key.add_signature(reply, &exchange_hash)?;

            Ok(super::Output {
                shared_secret: shared_secret.0.to_vec().into(),
                exchange_hash,
                digest: self.digest,
            })
        }

        pub fn client_dh_init(&mut self, msg: &mut CryptoVec) -> Result<(), crate::Error> {
            let mut client_secret = Scalar([0; 32]);
            rand_bytes(&mut client_secret.0)?;
            let client_pubkey = scalarmult_base(&client_secret);

            // fill exchange.
            msg.push(msg::KEX_ECDH_INIT);
            msg.extend_ssh_string(&client_pubkey.0);

            self.local_pubkey.replace(client_pubkey);
            self.local_secret.replace(client_secret);

            Ok(())
        }

        pub fn client_dh(
            &self,
            exchange: &Exchange,
            key: &PublicKey,
            payload: &[u8],
        ) -> Result<super::Output, crate::Error> {
            let mut r = payload.reader(0);
            super::check_packet_type(r.read_byte()?, msg::KEX_ECDH_REPLY)?;

            let mut server_pubkey = GroupElement([0; 32]);
            super::checked_clone(&mut server_pubkey.0, r.read_string()?)?;
            debug!("server_pubkey: {:?}", server_pubkey);
            let signature = r.read_string()?;

            let shared_secret = scalarmult(self.local_secret.as_ref().unwrap(), &server_pubkey);
            let exchange_hash = self.compute_exchange_hash(
                key,
                exchange,
                self.local_pubkey.as_ref().unwrap(),
                &server_pubkey,
                &shared_secret,
            )?;

            let signature = {
                let mut sig_reader = signature.reader(0);
                let sig_type = sig_reader.read_string()?;
                debug!("sig_type: {:?}", sig_type);
                sig_reader.read_string()?
            };
            use thrussh_keys::key::Verify;
            debug!("signature: {:?}", signature);
            if !key.verify_server_auth(&exchange_hash.to_vec(), signature) {
                debug!("wrong server sig");
                return Err(crate::Error::WrongServerSig.into());
            }

            Ok(super::Output {
                shared_secret: shared_secret.0.to_vec().into(),
                exchange_hash,
                digest: self.digest,
            })
        }

        fn compute_exchange_hash<K: key::PubKey>(
            &self,
            key: &K,
            exchange: &Exchange,
            client_pubkey: &GroupElement,
            server_pubkey: &GroupElement,
            shared_secret: &GroupElement,
        ) -> Result<DigestBytes, crate::Error> {
            super::BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                // Computing the exchange hash, RFC 4253 Sec. 8.
                buffer.clear();
                buffer.extend_ssh_string(&exchange.client_id);
                buffer.extend_ssh_string(&exchange.server_id);
                buffer.extend_ssh_string(&exchange.client_kex_init);
                buffer.extend_ssh_string(&exchange.server_kex_init);
                key.push_to(&mut buffer);
                buffer.extend_ssh_string(&client_pubkey.0);
                buffer.extend_ssh_string(&server_pubkey.0);
                buffer.extend_ssh_mpint(&shared_secret.0);
                Ok(hash(self.digest.clone(), &buffer)?)
            })
        }
    }
}

pub mod dh {
    use crate::key::PubKey;
    use crate::session::Exchange;
    use crate::{key, msg};
    use cryptovec::CryptoVec;
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::hash::{hash, DigestBytes, MessageDigest};
    use thrussh_keys::encoding::{Encoding, Reader};
    use thrussh_keys::key::KeyPair;

    pub struct Algorithm {
        p: BigNum,
        g: BigNum,
        digest: MessageDigest,
    }

    impl std::fmt::Debug for Algorithm {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "dh::Algorithm {{ p: [omitted], g: [omitted], digest: {} }}",
                self.digest.type_().short_name().unwrap_or("err"),
            )
        }
    }

    impl Algorithm {
        pub fn new_group14_sha1() -> Result<Self, crate::Error> {
            Ok(Algorithm {
                p: BigNum::get_rfc3526_prime_2048()?,
                g: BigNum::from_u32(2)?,
                digest: MessageDigest::sha1(),
            })
        }

        pub fn new_group14_sha256() -> Result<Self, crate::Error> {
            Ok(Algorithm {
                p: BigNum::get_rfc3526_prime_2048()?,
                g: BigNum::from_u32(2)?,
                digest: MessageDigest::sha256(),
            })
        }

        pub fn server_dh(
            &self,
            exchange: &Exchange,
            key: &KeyPair,
            payload: &[u8],
            reply: &mut CryptoVec,
        ) -> Result<super::Output, crate::Error> {
            let mut r = payload.reader(0);
            super::check_packet_type(r.read_byte()?, msg::KEXDH_INIT)?;

            let client_pubkey = BigNum::from_slice(r.read_mpint()?)?;

            let mut cx = BigNumContext::new()?;

            // S generates a random number y (0 < y < q)
            // q = p-1 for prime p
            let mut q = self.p.to_owned()?;
            q.sub_word(1)?;
            let mut y = BigNum::new()?;
            q.rand_range(&mut y)?;

            // S computes server_pubkey = f = g^y mod p
            let mut server_pubkey = BigNum::new()?;
            server_pubkey.mod_exp(&self.g, &y, &self.p, &mut cx)?;

            // S computes shared_secret = K = e^y mod p
            let mut shared_secret = BigNum::new()?;
            shared_secret.mod_exp(&client_pubkey, &y, &self.p, &mut cx)?;

            let exchange_hash = self.compute_exchange_hash(
                key,
                exchange,
                &client_pubkey,
                &server_pubkey,
                &shared_secret,
            )?;

            // Generate a reply per RFC 4253 Sec 8.
            reply.clear();
            reply.push(msg::KEXDH_REPLY);
            key.push_to(reply);
            reply.extend_ssh_mpint(&server_pubkey.to_vec());
            key.add_signature(reply, exchange_hash)?;

            Ok(super::Output {
                exchange_hash,
                shared_secret: shared_secret.to_vec().into(),
                digest: self.digest.clone(),
            })
        }

        fn compute_exchange_hash<K: key::PubKey>(
            &self,
            key: &K,
            exchange: &Exchange,
            client_pubkey: &BigNum,
            server_pubkey: &BigNum,
            shared_secret: &BigNum,
        ) -> Result<DigestBytes, crate::Error> {
            super::BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                // Computing the exchange hash, RFC 4253 Sec. 8.
                buffer.clear();
                buffer.extend_ssh_string(&exchange.client_id);
                buffer.extend_ssh_string(&exchange.server_id);
                buffer.extend_ssh_string(&exchange.client_kex_init);
                buffer.extend_ssh_string(&exchange.server_kex_init);
                key.push_to(&mut buffer);
                buffer.extend_ssh_mpint(&client_pubkey.to_vec());
                buffer.extend_ssh_mpint(&server_pubkey.to_vec());
                buffer.extend_ssh_mpint(&shared_secret.to_vec());
                Ok(hash(self.digest.clone(), &buffer)?)
            })
        }
    }
}

pub struct ComputeKeys<'a> {
    digest: MessageDigest,
    shared_secret: &'a [u8],
    session_id: &'a DigestBytes,
    exchange_hash: &'a DigestBytes,
    c_iv_enc_int: (u8, u8, u8),
}

impl ComputeKeys<'_> {
    pub fn iv<const N: usize>(&self) -> Result<[u8; N], crate::Error> {
        self.compute_keys::<N>(self.c_iv_enc_int.0)
    }

    pub fn encryption_key<const N: usize>(&self) -> Result<[u8; N], crate::Error> {
        self.compute_keys::<N>(self.c_iv_enc_int.1)
    }

    pub fn integrity_key<const N: usize>(&self) -> Result<[u8; N], crate::Error> {
        self.compute_keys::<N>(self.c_iv_enc_int.2)
    }

    fn compute_keys<const N: usize>(&self, c: u8) -> Result<[u8; N], crate::Error> {
        let mut out = [0; N];
        let mut n = 0;
        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            buffer.extend_ssh_mpint(&self.shared_secret);
            buffer.extend(self.exchange_hash);
            buffer.push(c);
            buffer.extend(self.session_id);
            use openssl::hash::*;
            n += Self::truncated_copy(&mut out, &hash(self.digest.clone(), &buffer)?);

            while n < out.len() {
                // extend.
                buffer.clear();
                buffer.extend_ssh_mpint(&self.shared_secret);
                buffer.extend(self.exchange_hash);
                buffer.extend(&out[..n]);
                n += Self::truncated_copy(&mut out[n..], &hash(self.digest.clone(), &buffer)?);
            }
            Ok(out)
        })
    }

    fn truncated_copy(dst: &mut [u8], src: &[u8]) -> usize {
        let n = std::cmp::min(dst.len(), src.len());
        dst[..n].copy_from_slice(&src[..n]);
        n
    }
}

#[must_use]
fn check_packet_type(received: u8, expected: u8) -> Result<(), crate::Error> {
    if received != expected {
        Err(crate::Error::Inconsistent)
    } else {
        Ok(())
    }
}

#[must_use]
fn checked_clone(dst: &mut [u8], src: &[u8]) -> Result<(), crate::Error> {
    if dst.len() != src.len() {
        Err(crate::Error::Inconsistent)
    } else {
        dst.clone_from_slice(src);
        Ok(())
    }
}
