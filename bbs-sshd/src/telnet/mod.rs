pub mod byte;
mod process;
use async_trait::async_trait;
use byte::{IAC, SB, SE};
use log::{debug, trace};
use process::Processor;
use std::io;
use std::io::{IoSlice, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

#[async_trait]
pub trait Handler: Sized {
    #[allow(unused_variables)]
    async fn data(&mut self, remote: &Remote, data: &[u8]) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    async fn command(&mut self, remote: &Remote, cmd: u8, opt: Option<u8>) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    async fn subnegotiation(&mut self, remote: &Remote, data: &[u8]) -> Result<()> {
        Ok(())
    }

    #[allow(unused_variables)]
    async fn eof(&mut self, remote: &Remote) -> Result<()> {
        Ok(())
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

fn escape_iov(data: &[u8], skip_single: bool) -> Option<Vec<IoSlice<'_>>> {
    let mut iov: Option<Vec<IoSlice<'_>>> = None;
    let mut last = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == IAC {
            iov.get_or_insert_with(Default::default)
                .push(IoSlice::new(&data[last..=i]));
            last = i;
        }
    }
    if iov.is_some() || !skip_single {
        iov.get_or_insert_with(Default::default)
            .push(IoSlice::new(&data[last..]));
    }
    iov
}

async fn escape_send<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<usize> {
    if let Some(iov) = escape_iov(data, true) {
        stream.write_vectored(&iov).await
    } else {
        stream.write(data).await
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
    remote: Remote,
    receiver: Option<Receiver<Action>>,
}

impl Telnet {
    pub fn new(buf_size: usize) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        Telnet {
            buf_size,
            remote: Remote { sender },
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
            self.remote.clone(),
        ));
        tokio::spawn(run_writer(write_half, self.receiver.take().unwrap()));
    }

    pub fn remote(&self) -> &Remote {
        &self.remote
    }
}

async fn run_processor<R: AsyncRead + Unpin, H: Handler + Send>(
    mut read_half: R,
    buf_size: usize,
    mut processor: Processor,
    mut handler: H,
    remote: Remote,
) -> Result<()> {
    let mut buf = vec![0; buf_size];
    loop {
        match read_half.read(&mut buf).await {
            Ok(n) => {
                processor.process(&buf[..n], &mut handler, &remote).await?;
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
