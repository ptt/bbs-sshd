use crate::async_telnet;
use crate::logind;
use futures::FutureExt;
use std::borrow::Cow;
use std::cmp;
use std::future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use telnet::TelnetEvent;
use thrussh::server;
use thrussh::server::{Auth, Handle, Session};
use thrussh::ChannelId;
use tokio::net::UnixStream;

pub(crate) struct Handler {
    addr: SocketAddr,
    encoding: u32,
    telnet: Option<Arc<async_telnet::Telnet>>,
    channel: Option<ChannelId>,
}

impl Drop for Handler {
    fn drop(&mut self) {
        println!("drop!");
        if let Some(telnet) = &self.telnet {
            telnet.shutdown_write();
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

    async fn forward_telnet_to_client(
        telnet: Arc<async_telnet::Telnet>,
        mut handle: Handle,
        channel: ChannelId,
    ) {
        loop {
            match telnet.read().await {
                Ok(TelnetEvent::Data(data)) => {
                    if handle.data(channel, data.to_vec().into()).await.is_err() {
                        println!("connection abort");
                        break;
                    }
                }
                Ok(TelnetEvent::Error(msg)) => {
                    println!("telnet eof: {}", msg);
                    break;
                }
                Ok(event) => println!("telnet event: {:?}", event),
                Err(err) => {
                    println!("read error: {:?}", err);
                    break;
                }
            }
        }
        let _ = handle.eof(channel).await;
        let _ = handle.close(channel).await;
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

        let telnet = Arc::new(async_telnet::Telnet::new(conn, 1024));
        self.telnet = Some(telnet.clone());
        tokio::spawn(Self::forward_telnet_to_client(
            telnet.clone(),
            session.handle(),
            channel,
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
                .subnegotiate(telnet::TelnetOption::NAWS, &neg)
                .await?
        }
        Ok((self, session))
    }

    async fn send_client_data(self, session: Session) -> Result<(Self, Session), thrussh::Error> {
        if let Some(telnet) = &self.telnet {
            telnet.flush_write().await?;
        }
        Ok((self, session))
    }

    async fn client_eof(self, session: Session) -> Result<(Self, Session), thrussh::Error> {
        println!("client_eof");
        if let Some(telnet) = &self.telnet {
            telnet.shutdown_write();
        }
        Ok((self, session))
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
        println!("auth_none: {}", user);
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
        _submethods: &str,
        response: Option<thrussh::server::Response<'_>>,
    ) -> Self::FutureAuth {
        // If we reach here, the user is neither "bbs" nor "bbsu".
        println!(
            "auth_keyboard_interactive: {}, response {:?}",
            user, response
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
            println!("channel_open_session: failed");
            session.channel_failure(channel);
            self.finished(session)
        } else {
            println!("channel_open_session: success");
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
        println!(
            "pty_request: term {}, {} cols {} rows, pix w {} h {}, modes: {:?}",
            term, col_width, row_height, pix_width, pix_height, modes
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
        println!(
            "window_change_request: {} cols {} rows, pix w {} h {}",
            col_width, row_height, pix_width, pix_height
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
        match &self.telnet {
            Some(telnet) => match telnet.write(data) {
                Ok(_) => self.send_client_data(session).boxed(),
                Err(e) => future::ready(Err(e.into())).boxed(),
            },
            None => self.finished(session),
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
