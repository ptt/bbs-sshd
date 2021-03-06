use crate::logind;
use crate::telnet;
use futures::FutureExt;
use log::{debug, info, trace, warn};
use std::borrow::Cow;
use std::cmp;
use std::future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use thrussh::server;
use thrussh::server::{Auth, Handle, Session};
use thrussh::{ChannelId, CryptoVec};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug)]
struct WindowSize {
    pub cols: u16,
    pub rows: u16,
}

impl WindowSize {
    pub fn new() -> Self {
        WindowSize { cols: 80, rows: 24 }
    }
}

struct TelnetHandler {
    tx: mpsc::Sender<CryptoVec>,
}

impl TelnetHandler {
    fn new(tx: mpsc::Sender<CryptoVec>) -> Self {
        TelnetHandler { tx }
    }

    async fn send_data(
        self,
        remote: telnet::Remote,
        data: CryptoVec,
    ) -> io::Result<(Self, telnet::Remote)> {
        match self.tx.send(data).await {
            Ok(_) => Ok((self, remote)),
            Err(_) => Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        }
    }
}

impl telnet::Handler for TelnetHandler {
    type FutureUnit =
        Pin<Box<dyn future::Future<Output = io::Result<(Self, telnet::Remote)>> + Send>>;

    fn unit(self, remote: telnet::Remote) -> Self::FutureUnit {
        future::ready(Ok((self, remote))).boxed()
    }

    fn command(self, remote: telnet::Remote, cmd: u8, opt: Option<u8>) -> Self::FutureUnit {
        trace!("telnet command {} opt {:?}", cmd, opt);
        self.unit(remote)
    }

    fn subnegotiation(self, remote: telnet::Remote, data: &[u8]) -> Self::FutureUnit {
        trace!("telnet subnegotiation data {:?}", data);
        self.unit(remote)
    }

    fn data(self, remote: telnet::Remote, data: &[u8]) -> Self::FutureUnit {
        self.send_data(remote, CryptoVec::from_slice(data)).boxed()
    }
}

async fn ssh_writer(
    mut rx: mpsc::Receiver<CryptoVec>,
    mut ssh: Handle,
    channel: ChannelId,
) -> io::Result<()> {
    while let Some(data) = rx.recv().await {
        if let Err(e) = ssh.data(channel, data).await {
            trace!("send_data: error {:?}", e);
            return Err(io::Error::from(io::ErrorKind::ConnectionReset));
        }
    }
    let _ = ssh.eof(channel).await;
    let _ = ssh.close(channel).await;
    Ok(())
}

pub(crate) struct Handler {
    addr: SocketAddr,
    encoding: u32,
    lport: u16,
    window_size: WindowSize,
    logind_path: Arc<PathBuf>,
    telnet: Option<telnet::Telnet>,
    channel: Option<ChannelId>,
    auth_attempts: u16,
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
    pub fn new(client_addr: SocketAddr, lport: u16, logind_path: Arc<PathBuf>) -> Self {
        Handler {
            addr: client_addr,
            encoding: logind::ConnData::CONV_NORMAL,
            lport,
            window_size: WindowSize::new(),
            logind_path,
            telnet: None,
            channel: None,
            auth_attempts: 0,
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
        if self.telnet.is_some() {
            warn!(
                "[client {}] Ignored client request to start another connection",
                self.addr
            );
            return Ok((self, session));
        }
        info!("[client {}] Opened a connection to logind", self.addr);

        let conn = UnixStream::connect(self.logind_path.as_ref()).await?;

        let conn_data = logind::ConnData {
            addr: self.addr,
            encoding: self.encoding,
            lport: self.lport,
            flags: logind::ConnData::CONN_FLAG_SECURE,
        };
        Self::send_to_conn(&conn, conn_data.serialize().unwrap()).await?;

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(ssh_writer(rx, session.handle(), channel));

        let (read_half, write_half) = conn.into_split();

        self.telnet = Some(telnet::Telnet::new(1024));
        self.telnet
            .as_mut()
            .unwrap()
            .start(read_half, write_half, TelnetHandler::new(tx));

        let ws = self.window_size;
        self.send_window_size(session, ws.cols as u32, ws.rows as u32)
            .await
    }

    async fn send_window_size(
        mut self,
        session: Session,
        cols: u32,
        rows: u32,
    ) -> Result<(Self, Session), thrussh::Error> {
        let cols = cmp::min(cmp::max(cols, u16::MIN as u32), u16::MAX as u32) as u16;
        let rows = cmp::min(cmp::max(rows, u16::MIN as u32), u16::MAX as u32) as u16;
        self.window_size = WindowSize { cols, rows };
        if let Some(telnet) = &self.telnet {
            let mut neg = [0; 4];
            neg[..2].copy_from_slice(&cols.to_be_bytes());
            neg[2..].copy_from_slice(&rows.to_be_bytes());
            telnet
                .remote()
                .subnegotiate(telnet::byte::NAWS, neg.into())
                .await?;
            debug!("Sent new window size: {:?}", self.window_size);
        } else {
            debug!("Recorded new window size: {:?}", self.window_size);
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
        self.channel == Some(channel)
    }

    fn wrong_channel() -> <Self as server::Handler>::FutureUnit {
        future::ready(Err(thrussh::Error::WrongChannel)).boxed()
    }

    fn auth_reject(mut self) -> <Self as server::Handler>::FutureAuth {
        self.auth_attempts += 1;
        if self.auth_attempts < 5 {
            future::ready(Ok((self, Auth::Reject)))
        } else {
            future::ready(Err(thrussh::Error::Disconnect))
        }
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
            _ => return self.auth_reject(),
        }
        future::ready(Ok((self, Auth::Accept)))
    }

    fn auth_password(mut self, user: &str, _password: &str) -> Self::FutureAuth {
        debug!("[client {}] auth_password: {}", self.addr, user);
        match user {
            "bbs" => self.encoding = logind::ConnData::CONV_NORMAL,
            "bbsu" => self.encoding = logind::ConnData::CONV_UTF8,
            _ => return self.auth_reject(),
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
            info!("[client {}] Rejected auth: user {}", self.addr, user);
            self.auth_reject()
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
            session.close(channel);
            self.finished(session)
        } else {
            debug!("[client {}] channel_open_session: opened", self.addr);
            info!(
                "[client {}] Session opened: encoding {}",
                self.addr,
                logind::encoding_name(self.encoding)
            );
            self.channel = Some(channel);
            self.finished(session)
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
        mut session: Session,
    ) -> Self::FutureUnit {
        info!(
            "[client {}] pty_request: term {}, {} cols {} rows",
            self.addr, term, col_width, row_height,
        );
        debug!(
            "[client {}] pty_request: pix w {} h {}, modes: {:?}",
            self.addr, pix_width, pix_height, modes
        );
        if !self.check_channel(channel) {
            session.channel_failure(channel);
            return Self::wrong_channel();
        }
        session.channel_success(channel);
        self.send_window_size(session, col_width, row_height)
            .boxed()
    }

    fn shell_request(self, channel: ChannelId, mut session: Session) -> Self::FutureUnit {
        debug!("[client {}] shell_request", self.addr);
        if !self.check_channel(channel) {
            session.channel_failure(channel);
            return Self::wrong_channel();
        }
        session.channel_success(channel);
        self.start_conn(session, channel).boxed()
    }

    fn exec_request(
        self,
        channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Self::FutureUnit {
        debug!(
            "[client {}] exec_request: data = {}",
            self.addr,
            String::from_utf8_lossy(data)
        );
        session.channel_failure(channel);
        if !self.check_channel(channel) {
            return Self::wrong_channel();
        }
        warn!("[client {}] exec_request: Rejected", self.addr);
        session.close(channel);
        self.finished(session)
    }

    fn window_change_request(
        self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        mut session: Session,
    ) -> Self::FutureUnit {
        debug!(
            "[client {}] window_change_request: {} cols {} rows, pix w {} h {}",
            self.addr, col_width, row_height, pix_width, pix_height
        );
        if !self.check_channel(channel) {
            session.channel_failure(channel);
            return Self::wrong_channel();
        }
        session.channel_success(channel);
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
