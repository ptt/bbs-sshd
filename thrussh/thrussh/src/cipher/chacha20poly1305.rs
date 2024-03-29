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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use crate::kex::ComputeKeys;
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use chacha20::*;

pub struct OpeningKey {
    k1: Key,
    k2: Key,
}
pub struct SealingKey {
    k1: Key,
    k2: Key,
}

const TAG_LEN: usize = 16;

pub const NAME: super::Name = super::Name("chacha20-poly1305@openssh.com");

pub fn make_sealing_cipher(keys: &ComputeKeys) -> Result<super::SealingCipher, Error> {
    let k = keys.encryption_key::<{ KEY_BYTES * 2 }>()?;
    let mut k1 = Key([0; KEY_BYTES]);
    let mut k2 = Key([0; KEY_BYTES]);
    k1.0.clone_from_slice(&k[KEY_BYTES..]);
    k2.0.clone_from_slice(&k[..KEY_BYTES]);
    Ok(super::SealingCipher::Chacha20Poly1305(SealingKey {
        k1,
        k2,
    }))
}

pub fn make_opening_cipher(keys: &ComputeKeys) -> Result<super::OpeningCipher, Error> {
    let k = keys.encryption_key::<{ KEY_BYTES * 2 }>()?;
    let mut k1 = Key([0; KEY_BYTES]);
    let mut k2 = Key([0; KEY_BYTES]);
    k1.0.clone_from_slice(&k[KEY_BYTES..]);
    k2.0.clone_from_slice(&k[..KEY_BYTES]);
    Ok(super::OpeningCipher::Chacha20Poly1305(OpeningKey {
        k1,
        k2,
    }))
}

fn make_counter(sequence_number: u32) -> Nonce {
    let mut nonce = Nonce([0; NONCE_BYTES]);
    let i0 = NONCE_BYTES - 4;
    BigEndian::write_u32(&mut nonce.0[i0..], sequence_number);
    nonce
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        let nonce = make_counter(sequence_number);
        chacha20_xor(&mut encrypted_packet_length, &nonce, &self.k1);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = make_counter(sequence_number);
        {
            let mut poly_key = poly1305::Key([0; 32]);
            chacha20_xor(&mut poly_key.0, &nonce, &self.k2);
            // let mut tag_ = Tag([0; 16]);
            // tag_.0.clone_from_slice(tag);
            if !poly1305::poly1305_verify(&tag, ciphertext_in_plaintext_out, &poly_key) {
                return Err(Error::PacketAuth);
            }
        }
        chacha20_xor_ic(&mut ciphertext_in_plaintext_out[4..], &nonce, 1, &self.k2);
        Ok(&ciphertext_in_plaintext_out[4..])
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// Append an encrypted packet with contents `packet_content` at the end of `buffer`.
    fn seal(
        &self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        let mut nonce = make_counter(sequence_number);
        {
            let (a, b) = plaintext_in_ciphertext_out.split_at_mut(4);
            chacha20_xor(a, &nonce, &self.k1);
            chacha20_xor_ic(b, &nonce, 1, &self.k2);
        }
        nonce.0[0] = 0;
        let mut poly_key = poly1305::Key([0; 32]);
        chacha20_xor(&mut poly_key.0, &nonce, &self.k2);
        let tag = poly1305::poly1305_auth(plaintext_in_ciphertext_out, &poly_key);
        tag_out.clone_from_slice(&tag.0);
    }
}

mod chacha20 {
    use chacha::{ChaCha, KeyStream, SeekableKeyStream};

    pub const NONCE_BYTES: usize = 8;
    pub const KEY_BYTES: usize = 32;
    const BLOCK_SIZE: u64 = 64;
    pub struct Nonce(pub [u8; NONCE_BYTES]);
    pub struct Key(pub [u8; KEY_BYTES]);

    pub fn chacha20_xor(c: &mut [u8], n: &Nonce, k: &Key) {
        ChaCha::new_chacha20(&k.0, &n.0).xor_read(c).unwrap();
    }

    pub fn chacha20_xor_ic(c: &mut [u8], n: &Nonce, ic: u64, k: &Key) {
        let mut s = ChaCha::new_chacha20(&k.0, &n.0);
        s.seek_to(ic * BLOCK_SIZE).unwrap();
        s.xor_read(c).unwrap();
    }
}

pub mod poly1305 {
    use poly1305::Poly1305;
    use subtle::ConstantTimeEq;
    use universal_hash::KeyInit;

    pub const KEY_BYTES: usize = 32;
    pub const TAG_BYTES: usize = 16;
    pub struct Key(pub [u8; KEY_BYTES]);
    pub struct Tag(pub [u8; TAG_BYTES]);

    pub fn poly1305_auth(m: &[u8], key: &Key) -> Tag {
        Tag(Poly1305::new(&key.0.into()).compute_unpadded(m).into())
    }

    pub fn poly1305_verify(tag: &[u8], m: &[u8], key: &Key) -> bool {
        tag.len() == TAG_BYTES
            && Poly1305::new(&key.0.into())
                .compute_unpadded(m)
                .ct_eq(tag.into())
                .unwrap_u8()
                == 1
    }
}
