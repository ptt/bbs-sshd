use bbs_common::daemon::{Accept, Stream};
use bbs_common::logind;
use bbs_common::socket_linux;
use bbs_common::telnet::{self, WindowSize};
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use russh::server;
use russh::server::{Auth, Handle, Msg, Session};
use russh::{Channel, ChannelId};
use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

struct TelnetHandler {
    tx: mpsc::Sender<Bytes>,
}

impl TelnetHandler {
    fn new(tx: mpsc::Sender<Bytes>) -> Self {
        TelnetHandler { tx }
    }

    async fn send_data(&mut self, _remote: &telnet::Remote, data: Bytes) -> io::Result<()> {
        match self.tx.send(data).await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }
}

impl telnet::Handler for TelnetHandler {
    async fn command(
        &mut self,
        _remote: &telnet::Remote,
        cmd: u8,
        opt: Option<u8>,
    ) -> io::Result<()> {
        trace!("telnet command {} opt {:?}", cmd, opt);
        Ok(())
    }

    async fn subnegotiation(&mut self, _remote: &telnet::Remote, data: &[u8]) -> io::Result<()> {
        trace!("telnet subnegotiation data {:?}", data);
        Ok(())
    }

    async fn data(&mut self, remote: &telnet::Remote, data: &[u8]) -> io::Result<()> {
        self.send_data(remote, Bytes::copy_from_slice(data)).await
    }
}

async fn ssh_writer(
    mut rx: mpsc::Receiver<Bytes>,
    ssh: Handle,
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

pub struct Handler {
    addr: SocketAddr,
    encoding: u32,
    lport: u16,
    window_size: WindowSize,
    term: String,
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
            window_size: WindowSize::initial(),
            term: String::new(),
            logind_path,
            telnet: None,
            channel: None,
            auth_attempts: 0,
        }
    }

    async fn start_conn(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        if self.telnet.is_some() {
            warn!(
                "[client {}] Ignored client request to start another connection",
                self.addr
            );
            return Ok(());
        }
        info!("[client {}] Opened a connection to logind", self.addr);
        // What the client is, to tell programs apart later (logs only): its
        // SSH identification string (e.g. "SSH-2.0-PuTTY_Release_0.81"), the
        // terminal type and size it asked for, and the user (encoding).
        info!(
            "[client {}] Client: id {:?} code {:08x} term {:?} size {}x{} user {}",
            self.addr,
            String::from_utf8_lossy(session.remote_sshid()),
            logind::client_code(session.remote_sshid()),
            self.term,
            self.window_size.cols,
            self.window_size.rows,
            logind::encoding_name(self.encoding)
        );

        let conn = UnixStream::connect(self.logind_path.as_ref()).await?;

        let conn_data = logind::ConnData {
            addr: self.addr,
            encoding: self.encoding,
            lport: self.lport,
            flags: logind::ConnData::CONN_FLAG_SECURE | logind::ConnData::CONN_FLAG_SSH,
            client_code: logind::client_code(session.remote_sshid()),
        };
        logind::send_to_conn(&conn, &conn_data.serialize().unwrap()).await?;

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
        &mut self,
        _session: &mut Session,
        cols: u32,
        rows: u32,
    ) -> Result<(), russh::Error> {
        self.window_size = WindowSize::new(cols, rows);
        if let Some(telnet) = &self.telnet {
            telnet
                .remote()
                .subnegotiate(telnet::byte::NAWS, self.window_size.naws_payload())
                .await?;
            debug!("Sent new window size: {:?}", self.window_size);
        } else {
            debug!("Recorded new window size: {:?}", self.window_size);
        }
        Ok(())
    }

    async fn send_data(
        &mut self,
        _session: &mut Session,
        remote: telnet::Remote,
        data: Vec<u8>,
    ) -> Result<(), russh::Error> {
        match remote.data(data).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn client_eof(&mut self, _session: &mut Session) -> Result<(), russh::Error> {
        debug!("[client {}] client eof", self.addr);
        if let Some(telnet) = &self.telnet {
            telnet.remote().shutdown_write().await?;
        }
        Ok(())
    }

    async fn upstream_shutdown_write(remote: telnet::Remote) -> io::Result<()> {
        remote.shutdown_write().await
    }

    /// Returns `russh::Error::WrongChannel` unless `channel` is the one channel
    /// this handler serves.
    fn check_channel(&self, channel: ChannelId) -> Result<(), russh::Error> {
        if self.channel == Some(channel) {
            Ok(())
        } else {
            Err(russh::Error::WrongChannel)
        }
    }

    /// `check_channel` plus the `channel_success` / `channel_failure` reply
    /// expected for a channel request.
    fn check_channel_request(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<(), russh::Error> {
        if self.check_channel(channel).is_err() {
            session.channel_failure(channel)?;
            return Err(russh::Error::WrongChannel);
        }
        session.channel_success(channel)?;
        Ok(())
    }

    fn auth_reject(&mut self) -> Result<Auth, russh::Error> {
        self.auth_attempts += 1;
        if self.auth_attempts < 5 {
            let mut method_set = russh::MethodSet::empty();
            method_set.push(russh::MethodKind::PublicKey);
            method_set.push(russh::MethodKind::KeyboardInteractive);
            method_set.push(russh::MethodKind::Password);
            Ok(Auth::Reject {
                proceed_with_methods: Some(method_set),
                partial_success: false,
            })
        } else {
            Err(russh::Error::Disconnect)
        }
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        debug!("[client {}] auth_none: {}", self.addr, user);
        match user {
            "bbs" => self.encoding = logind::ConnData::CONV_NORMAL,
            "bbsu" => self.encoding = logind::ConnData::CONV_UTF8,
            _ => return self.auth_reject(),
        }
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        debug!("[client {}] auth_password: {}", self.addr, user);
        match user {
            "bbs" => self.encoding = logind::ConnData::CONV_NORMAL,
            "bbsu" => self.encoding = logind::ConnData::CONV_UTF8,
            _ => return self.auth_reject(),
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        debug!("[client {}] auth_publickey_offered: {}", self.addr, user);
        self.auth_reject()
    }

    async fn auth_keyboard_interactive<'a>(
        &mut self,
        user: &str,
        submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        // If we reach here, the user is neither "bbs" nor "bbsu".
        debug!(
            "[client {}] auth_keyboard_interactive: user {}, submethods {}",
            self.addr, user, submethods
        );
        if response.is_none() {
            Ok(Auth::Partial {
                name: Cow::from("(BBS SSH Only)"),
                instructions: Cow::from("Please use user \"bbs\" for Big5 or \"bbsu\" for UTF-8."),
                prompts: Cow::from(vec![(
                    Cow::from(format!("User {} is not recognized.\n", user)),
                    true,
                )]),
            })
        } else {
            info!("[client {}] Rejected auth: user {}", self.addr, user);
            self.auth_reject()
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channel.is_some() {
            warn!(
                "[client {}] channel_open_session: there is already an existing channel",
                self.addr
            );
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            Ok(())
        } else {
            debug!("[client {}] channel_open_session: opened", self.addr);
            info!(
                "[client {}] Session opened: encoding {}",
                self.addr,
                logind::encoding_name(self.encoding)
            );
            self.channel = Some(channel.id());
            reply.accept().await;
            Ok(())
        }
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(
            "[client {}] pty_request: term {}, {} cols {} rows",
            self.addr, term, col_width, row_height,
        );
        self.term = term.chars().take(64).collect();
        debug!(
            "[client {}] pty_request: pix w {} h {}, modes: {:?}",
            self.addr, pix_width, pix_height, modes
        );
        self.check_channel_request(session, channel)?;
        self.send_window_size(session, col_width, row_height).await
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("[client {}] shell_request", self.addr);
        self.check_channel_request(session, channel)?;
        self.start_conn(session, channel).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(
            "[client {}] exec_request: data = {}",
            self.addr,
            String::from_utf8_lossy(data)
        );
        // exec is always rejected, so reply failure before checking the channel.
        session.channel_failure(channel)?;
        self.check_channel(channel)?;
        warn!("[client {}] exec_request: Rejected", self.addr);
        session.close(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(
            "[client {}] window_change_request: {} cols {} rows, pix w {} h {}",
            self.addr, col_width, row_height, pix_width, pix_height
        );
        self.check_channel_request(session, channel)?;
        self.send_window_size(session, col_width, row_height).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.check_channel(channel)?;
        if let Some(telnet) = &self.telnet {
            let remote = telnet.remote().clone();
            self.send_data(session, remote, data.into()).await
        } else {
            Ok(())
        }
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.check_channel(channel)?;
        self.client_eof(session).await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_eof(channel, session).await
    }
}

async fn run_forwarding<S>(
    config: Arc<russh::server::Config>,
    stream: S,
    handler: Handler,
) -> Result<(), russh::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    russh::server::run_stream(config, stream, handler)
        .await?
        .await
}

/// One [`russh`] session per accepted connection.
#[derive(Clone)]
pub struct Sshd {
    config: Arc<russh::server::Config>,
}

impl Sshd {
    pub fn new(config: Arc<russh::server::Config>) -> Self {
        Self { config }
    }
}

impl Accept for Sshd {
    async fn accept(
        self,
        stream: Stream,
        client_addr: SocketAddr,
        lport: u16,
        logind_path: Arc<PathBuf>,
    ) {
        let handler = Handler::new(client_addr, lport, logind_path);
        let result = match stream {
            Stream::Tcp(stream) => {
                let stream = socket_linux::set_client_conn_options(stream)
                    .expect("unable to set socket options");
                run_forwarding(self.config, stream, handler).await
            }
            // A unix socket has no TCP options to set.
            Stream::Unix(stream) => run_forwarding(self.config, stream, handler).await,
        };
        if let Err(e) = result {
            error!("[client {client_addr}] SSH session ended: {e}");
        }
    }
}

/// Name of the SSH service, used in the process title and logs.
pub const DAEMON: &str = "bbs-sshd";
