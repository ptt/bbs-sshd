use crate::logind;
use crate::telnet;
use futures::FutureExt;
use log::{debug, warn};
use std::borrow::Cow;
use std::cmp;
use std::future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use thrussh::server;
use thrussh::server::{Auth, Handle, Session};
use thrussh::ChannelId;
use tokio::net::UnixStream;

struct TelnetHandler {
    ssh: Handle,
    channel: ChannelId,
}

impl TelnetHandler {
    fn new(handle: Handle, channel: ChannelId) -> Self {
        TelnetHandler {
            ssh: handle,
            channel,
        }
    }

    async fn send_data(
        mut self,
        remote: telnet::Remote,
        data: thrussh::CryptoVec,
    ) -> io::Result<(Self, telnet::Remote)> {
        match self.ssh.data(self.channel, data).await {
            Ok(_) => Ok((self, remote)),
            Err(e) => {
                debug!("send_data: error {:?}", e);
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
    }

    async fn send_eof(mut self, remote: telnet::Remote) -> io::Result<(Self, telnet::Remote)> {
        _ = self.ssh.eof(self.channel).await;
        _ = self.ssh.close(self.channel).await;
        Ok((self, remote))
    }
}

impl telnet::Handler for TelnetHandler {
    type FutureUnit =
        Pin<Box<dyn future::Future<Output = io::Result<(Self, telnet::Remote)>> + Send>>;

    fn unit(self, remote: telnet::Remote) -> Self::FutureUnit {
        future::ready(Ok((self, remote))).boxed()
    }

    fn command(self, remote: telnet::Remote, cmd: u8, opt: Option<u8>) -> Self::FutureUnit {
        debug!("telnet command {} opt {:?}", cmd, opt);
        self.unit(remote)
    }

    fn data(self, remote: telnet::Remote, data: &[u8]) -> Self::FutureUnit {
        self.send_data(remote, data.to_vec().into()).boxed()
    }

    fn eof(self, remote: telnet::Remote) -> Self::FutureUnit {
        self.send_eof(remote).boxed()
    }
}

pub(crate) struct Handler {
    addr: SocketAddr,
    encoding: u32,
    telnet: Option<telnet::Telnet>,
    channel: Option<ChannelId>,
}

impl Drop for Handler {
    fn drop(&mut self) {
        debug!("[client {}] dropping handler", self.addr);
        if let Some(telnet) = &self.telnet {
            tokio::spawn(Self::upstream_shutdown_write(telnet.remote().clone()));
        }
    }
}

impl Handler {
    pub fn new(client_addr: SocketAddr) -> Self {
        Handler {
            addr: client_addr,
            encoding: logind::ConnData::CONV_NORMAL,
            telnet: None,
            channel: None,
        }
    }

    async fn send_to_conn(conn: &UnixStream, data: Vec<u8>) -> io::Result<()> {
        let mut sent = 0;
        while sent < data.len() {
            conn.writable().await?;
            match conn.try_write(&data[sent..]) {
                Ok(n) => sent += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };
        }
        Ok(())
    }

    async fn start_conn(
        mut self,
        session: Session,
        channel: ChannelId,
    ) -> Result<(Self, Session), thrussh::Error> {
        let conn = UnixStream::connect(&"/home/bbs/run/logind.connfwd.sock").await?;

        let conn_data = logind::ConnData {
            addr: self.addr,
            encoding: self.encoding,
        };
        Self::send_to_conn(&conn, conn_data.serialize().unwrap()).await?;

        let (read_half, write_half) = conn.into_split();

        self.telnet = Some(telnet::Telnet::new(1024));
        tokio::spawn(self.telnet.as_mut().unwrap().run_stream(
            read_half,
            write_half,
            TelnetHandler::new(session.handle(), channel),
        ));

        Ok((self, session))
    }

    async fn send_window_size(
        self,
        session: Session,
        cols: u32,
        rows: u32,
    ) -> Result<(Self, Session), thrussh::Error> {
        if let Some(telnet) = &self.telnet {
            let cols = cmp::min(cmp::max(cols, u16::MIN as u32), u16::MAX as u32) as u16;
            let rows = cmp::min(cmp::max(rows, u16::MIN as u32), u16::MAX as u32) as u16;
            let mut neg = [0; 4];
            neg[..2].copy_from_slice(&cols.to_be_bytes());
            neg[2..].copy_from_slice(&rows.to_be_bytes());
            telnet
                .remote()
                .subnegotiate(telnet::NAWS, neg.into())
                .await?
        }
        Ok((self, session))
    }

    async fn send_data(
        self,
        session: Session,
        remote: telnet::Remote,
        data: Vec<u8>,
    ) -> Result<(Self, Session), thrussh::Error> {
        match remote.data(data).await {
            Ok(_) => Ok((self, session)),
            Err(e) => Err(e.into()),
        }
    }

    async fn client_eof(self, session: Session) -> Result<(Self, Session), thrussh::Error> {
        debug!("[client {}] client eof", self.addr);
        if let Some(telnet) = &self.telnet {
            telnet.remote().shutdown_write().await?;
        }
        Ok((self, session))
    }

    async fn upstream_shutdown_write(remote: telnet::Remote) -> io::Result<()> {
        remote.shutdown_write().await
    }

    fn check_channel(&self, channel: ChannelId) -> bool {
        self.channel.is_some() && self.channel.unwrap() == channel
    }

    fn wrong_channel() -> <Self as server::Handler>::FutureUnit {
        future::ready(Err(thrussh::Error::WrongChannel)).boxed()
    }
}

impl server::Handler for Handler {
    type Error = thrussh::Error;
    type FutureAuth = future::Ready<Result<(Self, Auth), Self::Error>>;
    type FutureBool = future::Ready<Result<(Self, Session, bool), Self::Error>>;
    type FutureUnit =
        Pin<Box<dyn future::Future<Output = Result<(Self, Session), Self::Error>> + Send>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        future::ready(Ok((self, auth)))
    }

    fn finished_bool(self, b: bool, session: Session) -> Self::FutureBool {
        future::ready(Ok((self, session, b)))
    }

    fn finished(self, session: Session) -> Self::FutureUnit {
        future::ready(Ok((self, session))).boxed()
    }

    fn auth_none(mut self, user: &str) -> Self::FutureAuth {
        debug!("[client {}] auth_none: {}", self.addr, user);
        match user {
            "bbs" => self.encoding = logind::ConnData::CONV_NORMAL,
            "bbsu" => self.encoding = logind::ConnData::CONV_UTF8,
            _ => return future::ready(Ok((self, Auth::Reject))),
        }
        future::ready(Ok((self, Auth::Accept)))
    }

    fn auth_keyboard_interactive(
        self,
        user: &str,
        submethods: &str,
        response: Option<thrussh::server::Response<'_>>,
    ) -> Self::FutureAuth {
        // If we reach here, the user is neither "bbs" nor "bbsu".
        debug!(
            "[client {}] auth_keyboard_interactive: user {}, submethods {}, response {:?}",
            self.addr, user, submethods, response
        );
        if response.is_none() {
            future::ready(Ok((
                self,
                Auth::Partial {
                    name: Cow::from("(BBS SSH Only)"),
                    instructions: Cow::from(
                        "Please use user \"bbs\" for Big5 or \"bbsu\" for UTF-8.",
                    ),
                    prompts: Cow::from(vec![(
                        Cow::from(format!("User {} is not recognized.\n", user)),
                        true,
                    )]),
                },
            )))
        } else {
            future::ready(Ok((self, Auth::Reject)))
        }
    }

    fn channel_open_session(
        mut self,
        channel: ChannelId,
        mut session: Session,
    ) -> Self::FutureUnit {
        if self.channel.is_some() {
            warn!(
                "[client {}] channel_open_session: there is already an existing channel",
                self.addr
            );
            session.channel_failure(channel);
            self.finished(session)
        } else {
            debug!("[client {}] channel_open_session: opened", self.addr);
            session.channel_success(channel);
            self.channel = Some(channel);
            self.start_conn(session, channel).boxed()
        }
    }

    fn pty_request(
        self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(thrussh::Pty, u32)],
        session: Session,
    ) -> Self::FutureUnit {
        debug!(
            "[client {}] pty_request: term {}, {} cols {} rows, pix w {} h {}, modes: {:?}",
            self.addr, term, col_width, row_height, pix_width, pix_height, modes
        );
        if !self.check_channel(channel) {
            return Self::wrong_channel();
        }
        self.send_window_size(session, col_width, row_height)
            .boxed()
    }

    fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Self::FutureUnit {
        debug!(
            "[client {}] window_change_request: {} cols {} rows, pix w {} h {}",
            self.addr, col_width, row_height, pix_width, pix_height
        );
        if !self.check_channel(channel) {
            return Self::wrong_channel();
        }
        self.send_window_size(session, col_width, row_height)
            .boxed()
    }

    fn data(self, channel: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        if !self.check_channel(channel) {
            return Self::wrong_channel();
        }
        if let Some(telnet) = &self.telnet {
            let remote = telnet.remote().clone();
            self.send_data(session, remote, data.into()).boxed()
        } else {
            self.finished(session)
        }
    }

    fn channel_eof(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        if !self.check_channel(channel) {
            return Self::wrong_channel();
        }
        self.client_eof(session).boxed()
    }

    fn channel_close(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        self.channel_eof(channel, session)
    }
}
