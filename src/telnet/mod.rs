pub mod byte;
mod process;
use byte::{IAC, SB, SE};
use futures::Future;
use log::{debug, trace};
use process::Processor;
use std::io;
use std::io::{IoSlice, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

pub trait Handler: Sized {
    type FutureUnit: Future<Output = Result<(Self, Remote)>> + Send;

    fn unit(self, remote: Remote) -> Self::FutureUnit;

    #[allow(unused_variables)]
    fn data(self, remote: Remote, data: &[u8]) -> Self::FutureUnit {
        self.unit(remote)
    }

    #[allow(unused_variables)]
    fn command(self, remote: Remote, cmd: u8, opt: Option<u8>) -> Self::FutureUnit {
        self.unit(remote)
    }

    #[allow(unused_variables)]
    fn subnegotiation(self, remote: Remote, data: &[u8]) -> Self::FutureUnit {
        self.unit(remote)
    }

    #[allow(unused_variables)]
    fn eof(self, remote: Remote) -> Self::FutureUnit {
        self.unit(remote)
    }
}

pub enum Action {
    Data(Vec<u8>),
    Subnegotiate(u8, Vec<u8>),
    ShutdownWrite,
}

#[derive(Clone)]
pub struct Remote {
    sender: Sender<Action>,
}

impl Remote {
    pub async fn data(&self, data: Vec<u8>) -> Result<()> {
        trace!("Remote: data: {} bytes", data.len());
        self.sender
            .send(Action::Data(data))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }

    pub async fn subnegotiate(&self, cmd: u8, data: Vec<u8>) -> Result<()> {
        trace!("Remote: subnegotiate: cmd {} data {:?}", cmd, data);
        self.sender
            .send(Action::Subnegotiate(cmd, data))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }

    pub async fn shutdown_write(&self) -> Result<()> {
        debug!("Remote: shutdown_write");
        self.sender
            .send(Action::ShutdownWrite)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }
}

fn escape_iov<'a>(data: &'a [u8], skip_single: bool) -> Option<Vec<IoSlice<'a>>> {
    let mut iov: Option<Vec<IoSlice<'_>>> = None;
    let mut last = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == IAC {
            iov.get_or_insert_default()
                .push(IoSlice::new(&data[last..=i]));
            last = i;
        }
    }
    if iov.is_some() || !skip_single {
        iov.get_or_insert_default()
            .push(IoSlice::new(&data[last..]));
    }
    iov
}

async fn escape_send<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<usize> {
    if let Some(iov) = escape_iov(data, true) {
        stream.write_vectored(&iov).await
    } else {
        stream.write(&data).await
    }
}

async fn send_subnegotiate<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cmd: u8,
    data: &[u8],
) -> Result<usize> {
    let mut iov = Vec::new();
    let begin = vec![IAC, SB, cmd];
    iov.push(IoSlice::new(&begin));
    iov.extend_from_slice(&escape_iov(data, false).unwrap());
    iov.push(IoSlice::new(&[IAC, SE]));
    stream.write_vectored(&iov).await
}

pub(crate) struct Telnet {
    buf_size: usize,
    _remote: Remote,
    receiver: Option<Receiver<Action>>,
}

impl Telnet {
    pub fn new(buf_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let remote = Remote { sender };
        Telnet {
            buf_size,
            _remote: remote,
            receiver: Some(receiver),
        }
    }

    pub fn start<
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        H: Handler + Send + 'static,
    >(
        &mut self,
        read_half: R,
        write_half: W,
        handler: H,
    ) {
        tokio::spawn(run_processor(
            read_half,
            self.buf_size,
            Processor::new(),
            handler,
            self._remote.clone(),
        ));
        tokio::spawn(run_writer(write_half, self.receiver.take().unwrap()));
    }

    pub fn remote(&self) -> &Remote {
        &self._remote
    }
}

async fn run_processor<R: AsyncRead + Unpin, H: Handler>(
    mut read_half: R,
    buf_size: usize,
    mut processor: Processor,
    mut handler: H,
    mut remote: Remote,
) -> Result<()> {
    let mut buf = Vec::new();
    buf.resize(buf_size, 0);

    loop {
        match read_half.read(&mut buf).await {
            Ok(n) => {
                let (handler_, remote_) = processor.process(&buf[..n], handler, remote).await?;
                handler = handler_;
                remote = remote_;
                if n == 0 {
                    break;
                }
            }
            Err(e) => {
                debug!("run_processor: read error: {:?}", e);
                return Err(e);
            }
        }
    }
    Ok(())
}

async fn run_writer<W: AsyncWrite + Unpin>(
    mut write_half: W,
    mut receiver: Receiver<Action>,
) -> Result<()> {
    loop {
        match receiver.recv().await {
            Some(Action::Data(data)) => {
                escape_send(&mut write_half, &data).await?;
            }
            Some(Action::Subnegotiate(cmd, data)) => {
                send_subnegotiate(&mut write_half, cmd, &data).await?;
            }
            Some(Action::ShutdownWrite) => break,
            None => break,
        }
    }
    Ok(())
}
