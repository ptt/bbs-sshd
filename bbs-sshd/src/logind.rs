use bytes::BytesMut;
use std::net::SocketAddr;

pub struct ConnData {
    pub addr: SocketAddr,
    pub encoding: u32,
    pub lport: u16,
    pub flags: u32,
}

impl ConnData {
    pub const CONV_NORMAL: u32 = 0;
    pub const CONV_UTF8: u32 = 1;

    pub const CONN_FLAG_SECURE: u32 = 1;

    pub fn serialize(&self) -> Option<Vec<u8>> {
        use bytes::BufMut;
        let mut conn_data = BytesMut::with_capacity(36);
        // u32: cb
        // u32: encoding
        // u32: ip_len
        // s16: ip
        // u16: rport
        // u16: lport
        // u32: flags

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
        assert_eq!(36, conn_data.len());
        Some(conn_data.to_vec())
    }
}

pub fn encoding_name(encoding: u32) -> &'static str {
    match encoding {
        ConnData::CONV_NORMAL => &"big5",
        ConnData::CONV_UTF8 => &"utf8",
        _ => &"unknown",
    }
}
