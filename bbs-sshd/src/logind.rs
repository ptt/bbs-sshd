use bytes::BytesMut;
use std::net::SocketAddr;

pub struct ConnData {
    pub addr: SocketAddr,
    pub encoding: u32,
    pub lport: u16,
    pub flags: u32,
    /// The client (client_code in pttbbs include/daemons.h): client_code()
    /// of the SSH identification string, 0 if none.
    pub client_code: u32,
}

impl ConnData {
    pub const CONV_NORMAL: u32 = 0;
    pub const CONV_UTF8: u32 = 1;

    pub const CONN_FLAG_SECURE: u32 = 1;
    /// From bbs-sshd (CONN_FLAG_SSH in pttbbs include/daemons.h): tells logind
    /// the login came in over SSH.
    pub const CONN_FLAG_SSH: u32 = 1 << 2;

    pub fn serialize(&self) -> Option<Vec<u8>> {
        use bytes::BufMut;
        let mut conn_data = BytesMut::with_capacity(40);
        // u32: cb
        // u32: encoding
        // u32: ip_len
        // s16: ip
        // u16: rport
        // u16: lport
        // u32: flags
        // u32: client_code (logind before it takes only the 36 bytes above)

        let cb = conn_data.capacity() as u32;
        conn_data.put_u32_le(cb);
        conn_data.put_u32_le(self.encoding);
        match self.addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip().octets();
                conn_data.put_u32_le(ip.len() as u32);
                conn_data.put_slice(&ip);
                conn_data.put_slice(&[0; 12]);
            }
            SocketAddr::V6(v6) => {
                let ip = v6.ip().octets();
                conn_data.put_u32_le(ip.len() as u32);
                conn_data.put_slice(&ip);
            }
        };
        conn_data.put_u16_le(self.addr.port());
        conn_data.put_u16_le(self.lport);
        conn_data.put_u32_le(self.flags);
        conn_data.put_u32_le(self.client_code);
        assert_eq!(40, conn_data.len());
        Some(conn_data.to_vec())
    }
}

pub fn encoding_name(encoding: u32) -> &'static str {
    match encoding {
        ConnData::CONV_NORMAL => "big5",
        ConnData::CONV_UTF8 => "utf8",
        _ => "unknown",
    }
}

/// The program name of an SSH identification string ("SSH-2.0-" then the
/// software version, up to the first "_", "-" or space, at most 32 bytes),
/// e.g. "PuTTY" of "SSH-2.0-PuTTY_Release_0.70", "BePTT" of
/// "SSH-2.0-BePTT_Android_7.2.9.1070209002". None if there is none.
pub fn program_name(sshid: &[u8]) -> Option<&[u8]> {
    let rest = sshid.strip_prefix(b"SSH-")?;
    let rest = &rest[rest.iter().position(|&c| c == b'-')? + 1..];
    let end = rest
        .iter()
        .position(|&c| matches!(c, b'_' | b'-' | b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(rest.len());
    let name = &rest[..end.min(32)];
    (!name.is_empty()).then_some(name)
}

/// The client code logind takes for an SSH connection: CRC-32 (IEEE, as
/// wsproxy computes for the program name of a User-Agent) of the program name
/// of the SSH identification string, 0 if none.
pub fn client_code(sshid: &[u8]) -> u32 {
    program_name(sshid).map_or(0, crc32)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_names() {
        for (id, want) in [
            (&b"SSH-2.0-PuTTY_Release_0.70"[..], Some(&b"PuTTY"[..])),
            (b"SSH-2.0-SwiftNIOSSH_1.0", Some(b"SwiftNIOSSH")),
            (b"SSH-2.0-BePTT_Android_7.2.9.1070209002", Some(b"BePTT")),
            (b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", Some(b"OpenSSH")),
            (b"SSH-2.0-JSCH-0.1.54", Some(b"JSCH")),
            (b"SSH-1.99-Go", Some(b"Go")),
            (b"SSH-2.0-", None),
            (b"SSH-2.0-_x", None),
            (b"garbage", None),
        ] {
            assert_eq!(program_name(id), want, "{:?}", String::from_utf8_lossy(id));
        }
    }

    #[test]
    fn client_codes() {
        // zlib.crc32 (what wsproxy and the activity service compute).
        assert_eq!(client_code(b"SSH-2.0-PuTTY_Release_0.70"), 0x0505_9f14);
        assert_eq!(client_code(b"SSH-2.0-BePTT_Android_7.2.9"), 0x3684_d808);
        assert_eq!(client_code(b"SSH-2.0-OpenSSH_9.6"), 0x294d_f8fe);
        assert_eq!(client_code(b"nope"), 0);
    }
}
