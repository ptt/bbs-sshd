use super::*;
use crate::cipher::CipherPair;
use crate::negotiation::Select;
use crate::{kex, msg, negotiation};
use std::cell::RefCell;

thread_local! {
    static HASH_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl KexInit {
    pub fn server_parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if buf[0] == msg::KEXINIT {
            let algo = {
                // read algorithms from packet.
                self.exchange.client_kex_init.extend(buf);
                super::negotiation::Server::read_kex(buf, &config.preferred)?
            };
            if !self.sent {
                self.server_write(config, cipher, write_buffer)?
            }
            let mut key = 0;
            while key < config.keys.len() && config.keys[key].name() != algo.key.as_ref() {
                key += 1
            }
            let next_kex = if key < config.keys.len() {
                Kex::KexDh(KexDh {
                    exchange: self.exchange,
                    key: key,
                    names: algo,
                    session_id: self.session_id,
                })
            } else {
                return Err(Error::UnknownKey.into());
            };

            Ok(next_kex)
        } else {
            Ok(Kex::KexInit(self))
        }
    }

    pub fn server_write(
        &mut self,
        config: &Config,
        cipher: &CipherPair,
        write_buffer: &mut SSHBuffer,
    ) -> Result<(), Error> {
        self.exchange.server_kex_init.clear();
        negotiation::write_kex(&config.preferred, &mut self.exchange.server_kex_init)?;
        debug!("server kex init: {:?}", &self.exchange.server_kex_init[..]);
        self.sent = true;
        cipher.write(&self.exchange.server_kex_init, write_buffer);
        Ok(())
    }
}

impl KexDh {
    pub fn parse(
        mut self,
        config: &Config,
        cipher: &CipherPair,
        buf: &[u8],
        write_buffer: &mut SSHBuffer,
    ) -> Result<Kex, Error> {
        if self.names.ignore_guessed {
            // If we need to ignore this packet.
            self.names.ignore_guessed = false;
            Ok(Kex::KexDh(self))
        } else {
            let kex = kex::Algorithms::new(self.names.kex)?;

            let output = HASH_BUF.with(|reply| -> Result<kex::Output, Error> {
                let mut reply = reply.borrow_mut();
                let output =
                    kex.server_dh(&self.exchange, &config.keys[self.key], buf, &mut reply)?;
                cipher.write(&reply, write_buffer);
                cipher.write(&[msg::NEWKEYS], write_buffer);
                Ok(output)
            })?;

            if self.session_id.is_none() {
                self.session_id.replace(output.exchange_hash.clone());
            }

            let cipher = output.make_cipher(
                self.session_id.as_ref().unwrap(),
                true,
                self.names.cipher,
                self.names.mac,
            )?;

            Ok(Kex::NewKeys(crate::session::NewKeys {
                exchange: self.exchange,
                names: self.names,
                key: self.key,
                cipher,
                session_id: self.session_id.unwrap(),
                received: false,
                sent: false,
            }))
        }
    }
}
