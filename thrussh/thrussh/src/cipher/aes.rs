use super::integrity::Auth;
use super::Name;
use crate::kex::ComputeKeys;
use crate::Error;
use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, Aes256};
use std::sync::Mutex;

pub const AES128_CTR_NAME: Name = Name("aes128-ctr");
pub const AES256_CTR_NAME: Name = Name("aes256-ctr");

pub enum Cipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl Cipher {
    fn new_from_name(name: Name, keys: &ComputeKeys) -> Result<Self, Error> {
        use aes::cipher::KeyInit;
        match name {
            AES128_CTR_NAME => Ok(Cipher::Aes128(Aes128::new(&keys.encryption_key()?.into()))),
            AES256_CTR_NAME => Ok(Cipher::Aes256(Aes256::new(&keys.encryption_key()?.into()))),
            _ => Err(Error::NoCommonCipher),
        }
    }

    fn encrypt(&self, block: &mut [u8]) {
        use aes::cipher::BlockEncrypt;
        let arr = GenericArray::from_mut_slice(block);
        match self {
            Cipher::Aes128(c) => c.encrypt_block(arr),
            Cipher::Aes256(c) => c.encrypt_block(arr),
        }
    }
}

pub struct CounterState {
    cipher: Cipher,
    counter: Mutex<u128>,
    auth: Option<Auth>,
}

impl CounterState {
    pub fn new_from_name(
        name: Name,
        keys: &ComputeKeys,
        auth: Option<Auth>,
    ) -> Result<Self, Error> {
        let counter = u128::from_be_bytes(keys.iv()?);
        Ok(CounterState {
            cipher: Cipher::new_from_name(name, keys)?,
            counter: Mutex::new(counter),
            auth,
        })
    }
}

impl super::OpeningKey for CounterState {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        let mut scratch = self.counter.lock().unwrap().to_be_bytes();
        self.cipher.encrypt(&mut scratch);
        xor(&mut encrypted_packet_length, &scratch[..4]);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        self.auth.as_ref().map(Auth::tag_len).unwrap_or(0)
    }

    fn open<'a>(
        &self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        debug!(
            "open: seq {}, data {} bytes, and tag {} bytes",
            sequence_number,
            ciphertext_in_plaintext_out.len(),
            tag.len(),
        );
        let mut counter = self.counter.lock().unwrap();
        for block in ciphertext_in_plaintext_out.chunks_mut(BLOCK_LEN) {
            let mut scratch = counter.to_be_bytes();
            *counter += 1;
            self.cipher.encrypt(&mut scratch);
            xor(block, &scratch);
        }
        if let Some(auth) = &self.auth {
            let mut expect_tag = vec![0; auth.tag_len()];
            auth.compute(
                sequence_number,
                ciphertext_in_plaintext_out,
                &mut expect_tag,
            );
            if tag != expect_tag {
                return Err(Error::PacketAuth);
            }
        }
        Ok(&ciphertext_in_plaintext_out[4..])
    }
}

impl super::SealingKey for CounterState {
    fn padding_length(&self, payload: &[u8]) -> usize {
        assert!(super::MINIMUM_PACKET_LEN >= BLOCK_LEN);
        let total = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + payload.len();
        let last_block = total & (BLOCK_LEN - 1);
        // RFC 4523 Sec. 6, There MUST be at least four bytes of padding.
        let pad = BLOCK_LEN - last_block;
        if pad < 4 {
            BLOCK_LEN + pad
        } else {
            pad
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
        self.auth.as_ref().map(Auth::tag_len).unwrap_or(0)
    }

    fn seal(
        &self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        debug!(
            "seal: seq {}, data {} bytes, and tag {} bytes",
            sequence_number,
            plaintext_in_ciphertext_out.len(),
            tag_out.len(),
        );
        if let Some(auth) = &self.auth {
            auth.compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        }
        let mut counter = self.counter.lock().unwrap();
        for block in plaintext_in_ciphertext_out.chunks_mut(BLOCK_LEN) {
            let mut scratch = counter.to_be_bytes();
            *counter += 1;
            self.cipher.encrypt(&mut scratch);
            xor(block, &scratch);
        }
    }
}

fn xor(dst: &mut [u8], src: &[u8]) {
    dst.iter_mut().zip(src.iter()).for_each(|(d, s)| *d ^= s);
}

pub const BLOCK_LEN: usize = 16;
