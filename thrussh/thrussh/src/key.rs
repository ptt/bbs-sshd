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
use cryptovec::CryptoVec;
use thrussh_keys::ec;
use thrussh_keys::encoding::*;
use thrussh_keys::key::*;

#[doc(hidden)]
pub trait PubKey {
    fn push_to(&self, buffer: &mut CryptoVec);
}

impl PubKey for PublicKey {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            &PublicKey::Ed25519(ref public) => {
                let key = public.as_bytes().as_slice();
                buffer.push_u32_be((ED25519.0.len() + key.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(key);
            }
            &PublicKey::RSA { ref key, .. } => {
                use rsa::PublicKeyParts;
                let e = key.e().to_bytes_be();
                let n = key.n().to_bytes_be();
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
            &PublicKey::Ec { ref key } => {
                write_ec_public_key(buffer, key);
            }
        }
    }
}

impl PubKey for KeyPair {
    fn push_to(&self, buffer: &mut CryptoVec) {
        match self {
            &KeyPair::Ed25519(ref key) => {
                let public = key.public_as_bytes().as_slice();
                buffer.push_u32_be((ED25519.0.len() + public.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(public);
            }
            &KeyPair::RSA { ref key, .. } => {
                use rsa::PublicKeyParts;
                let e = key.e().to_bytes_be();
                let n = key.n().to_bytes_be();
                buffer.push_u32_be((4 + SSH_RSA.0.len() + mpint_len(&n) + mpint_len(&e)) as u32);
                buffer.extend_ssh_string(SSH_RSA.0.as_bytes());
                buffer.extend_ssh_mpint(&e);
                buffer.extend_ssh_mpint(&n);
            }
            &KeyPair::Ec { ref key } => {
                write_ec_public_key(buffer, &key.to_public_key());
            }
        }
    }
}

pub fn write_ec_public_key(buf: &mut CryptoVec, key: &ec::EcPublicKey) {
    let name = key.algorithm_name().as_bytes();
    let ident = key.ident().as_bytes();
    let q = key.to_sec1_bytes();

    buf.push_u32_be((name.len() + ident.len() + q.len() + 12) as u32);
    buf.extend_ssh_string(name);
    buf.extend_ssh_string(ident);
    buf.extend_ssh_string(&q);
}
