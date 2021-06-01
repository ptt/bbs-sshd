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
use crate::{cipher, cipher::integrity, key, msg};
use byteorder::{BigEndian, ByteOrder};

use crate::session::Exchange;
use cryptovec::CryptoVec;
use openssl;
use sodium;
use std::cell::RefCell;
use thrussh_keys::encoding::Encoding;

#[doc(hidden)]
pub struct Algorithm {
    local_secret: Option<sodium::scalarmult::Scalar>,
    shared_secret: Option<sodium::scalarmult::GroupElement>,
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
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

thread_local! {
    static KEY_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html

impl Algorithm {
    #[doc(hidden)]
    pub fn server_dh(
        _name: Name,
        exchange: &mut Exchange,
        payload: &[u8],
    ) -> Result<Algorithm, crate::Error> {
        debug!("server_dh");

        assert_eq!(payload[0], msg::KEX_ECDH_INIT);
        let mut client_pubkey = GroupElement([0; 32]);
        {
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
            client_pubkey
                .0
                .clone_from_slice(&payload[5..(5 + pubkey_len)])
        };
        debug!("client_pubkey: {:?}", client_pubkey);
        use openssl::rand::*;
        use sodium::scalarmult::*;
        let mut server_secret = Scalar([0; 32]);
        rand_bytes(&mut server_secret.0)?;
        let server_pubkey = scalarmult_base(&server_secret);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        let shared = scalarmult(&server_secret, &client_pubkey);
        Ok(Algorithm {
            local_secret: None,
            shared_secret: Some(shared),
        })
    }

    #[doc(hidden)]
    pub fn client_dh(
        _name: Name,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<Algorithm, crate::Error> {
        use openssl::rand::*;
        use sodium::scalarmult::*;
        let mut client_secret = Scalar([0; 32]);
        rand_bytes(&mut client_secret.0)?;
        let client_pubkey = scalarmult_base(&client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);

        Ok(Algorithm {
            local_secret: Some(client_secret),
            shared_secret: None,
        })
    }

    pub fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = std::mem::replace(&mut self.local_secret, None).unwrap();

        use sodium::scalarmult::*;
        let mut remote_pubkey = GroupElement([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let shared = scalarmult(&local_secret, &remote_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    pub fn compute_exchange_hash<K: key::PubKey>(
        &self,
        key: &K,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<openssl::hash::DigestBytes, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        key.push_to(buffer);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared.0);
        }
        use openssl::hash::*;
        let hash = {
            let mut hasher = Hasher::new(MessageDigest::sha256())?;
            hasher.update(&buffer)?;
            hasher.finish()?
        };
        Ok(hash)
    }

    pub fn compute_keys(
        &self,
        session_id: &openssl::hash::DigestBytes,
        exchange_hash: &openssl::hash::DigestBytes,
        cipher: cipher::Name,
        mac: Option<integrity::Name>,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        // https://tools.ietf.org/html/rfc4253#section-7.2
        let local_to_remote = cipher::make_sealing_cipher(
            cipher,
            mac,
            &ComputeKeys {
                shared_secret: self.shared_secret.as_ref(),
                session_id: &session_id,
                exchange_hash: &exchange_hash,
                c_iv_enc_int: c_local_to_remote(is_server),
            },
        )?;
        let remote_to_local = cipher::make_opening_cipher(
            cipher,
            mac,
            &ComputeKeys {
                shared_secret: self.shared_secret.as_ref(),
                session_id: &session_id,
                exchange_hash: &exchange_hash,
                c_iv_enc_int: c_remote_to_local(is_server),
            },
        )?;
        Ok(super::cipher::CipherPair {
            local_to_remote,
            remote_to_local,
        })
    }
}

fn c_local_to_remote(is_server: bool) -> (u8, u8, u8) {
    c_remote_to_local(!is_server)
}

fn c_remote_to_local(is_server: bool) -> (u8, u8, u8) {
    if is_server {
        (b'A', b'C', b'E')
    } else {
        (b'B', b'D', b'F')
    }
}

pub struct ComputeKeys<'a> {
    shared_secret: Option<&'a sodium::scalarmult::GroupElement>,
    session_id: &'a openssl::hash::DigestBytes,
    exchange_hash: &'a openssl::hash::DigestBytes,
    c_iv_enc_int: (u8, u8, u8),
}

impl ComputeKeys<'_> {
    pub fn iv(&self, len: usize) -> Result<Vec<u8>, crate::Error> {
        self.compute_keys(self.c_iv_enc_int.0, len)
    }

    pub fn encryption_key(&self, len: usize) -> Result<Vec<u8>, crate::Error> {
        self.compute_keys(self.c_iv_enc_int.1, len)
    }

    pub fn integrity_key(&self, len: usize) -> Result<Vec<u8>, crate::Error> {
        self.compute_keys(self.c_iv_enc_int.2, len)
    }

    fn compute_keys(&self, c: u8, len: usize) -> Result<Vec<u8>, crate::Error> {
        KEY_BUF.with(|key| {
            let mut key = key.borrow_mut();
            key.clear();
            BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                buffer.clear();

                if let Some(ref shared) = self.shared_secret {
                    buffer.extend_ssh_mpint(&shared.0);
                }

                buffer.extend(self.exchange_hash);
                buffer.push(c);
                buffer.extend(self.session_id);
                use openssl::hash::*;
                let hash = {
                    let mut hasher = Hasher::new(MessageDigest::sha256())?;
                    hasher.update(&buffer)?;
                    hasher.finish()?
                };
                key.extend(&hash);

                while key.len() < len {
                    // extend.
                    buffer.clear();
                    if let Some(ref shared) = self.shared_secret {
                        buffer.extend_ssh_mpint(&shared.0);
                    }
                    buffer.extend(self.exchange_hash);
                    buffer.extend(&key);
                    let hash = {
                        let mut hasher = Hasher::new(MessageDigest::sha256())?;
                        hasher.update(&buffer)?;
                        hasher.finish()?
                    };
                    key.extend(&hash);
                }
                Ok(key[..len].to_vec())
            })
        })
    }
}
