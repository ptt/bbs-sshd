use futures::Future;
use log::debug;
use std::assert;
use std::io;
use std::io::{IoSlice, Result};
use std::ops::Range;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

pub const IAC: u8 = 255;
pub const SE: u8 = 240;
pub const SB: u8 = 250;
pub const NAWS: u8 = 31;

pub(crate) trait Handler: Sized {
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
    fn subnegotiation(self, remote: Remote, subnegotiation: &[u8]) -> Self::FutureUnit {
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
        self.sender
            .send(Action::Data(data))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }

    pub async fn subnegotiate(&self, cmd: u8, data: Vec<u8>) -> Result<()> {
        self.sender
            .send(Action::Subnegotiate(cmd, data))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }

    pub async fn shutdown_write(&self) -> Result<()> {
        debug!("shutdown_write");
        self.sender
            .send(Action::ShutdownWrite)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionReset))
    }
}

#[derive(Debug)]
struct Queued {
    start: usize,
    queued: usize,
}

impl Queued {
    fn new() -> Self {
        Queued {
            start: 0,
            queued: 0,
        }
    }

    fn queue(&mut self) {
        self.queued += 1;
    }

    fn skip(&mut self) {
        assert_eq!(self.queued, 0);
        self.start += 1;
    }

    fn flush(&mut self) -> Range<usize> {
        let r = self.start..self.start + self.queued;
        self.start += self.queued;
        self.queued = 0;
        r
    }

    fn current(&self) -> usize {
        self.start + self.queued
    }

    fn has_queued(&self) -> bool {
        self.queued > 0
    }

    fn reset(&mut self) {
        self.start = 0;
        self.queued = 0;
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Normal,
    Iac,
    IacOpt,
    SubNeg,
    SubNegIac,
}

enum ProcEvent {
    Queue,
    Flush,
    Processed,
    Command(u8, Option<u8>),
    Subnegotiation(Vec<u8>),
    Error,
}

struct Processor {
    state: State,
    queued: Queued,
    cmd: u8,
    sub_neg: Option<Vec<u8>>,
}

impl Processor {
    fn new() -> Self {
        Processor {
            state: State::Normal,
            queued: Queued::new(),
            cmd: 0,
            sub_neg: None,
        }
    }

    async fn process<H: Handler>(
        &mut self,
        data: &[u8],
        mut handler: H,
        mut remote: Remote,
    ) -> Result<(H, Remote)> {
        if data.len() == 0 {
            debug!("process: eof");
            if self.state != State::Normal {
                return Err(io::Error::from(io::ErrorKind::ConnectionReset));
            } else {
                return handler.eof(remote).await;
            }
        }
        self.queued.reset();
        while self.queued.current() < data.len() {
            let b = data[self.queued.current()];
            let event = match self.state {
                State::Normal => self.normal(b),
                State::Iac => self.iac(b),
                State::IacOpt => self.iac_opt(b),
                State::SubNeg => self.sub_neg(b),
                State::SubNegIac => self.sub_neg_iac(b),
            };
            match event {
                ProcEvent::Queue => self.queued.queue(),
                ProcEvent::Flush => {
                    (handler, remote) = handler.data(remote, &data[self.queued.flush()]).await?;
                }
                ProcEvent::Processed => self.queued.skip(),
                ProcEvent::Command(cmd, opt) => {
                    self.queued.skip();
                    (handler, remote) = handler.command(remote, cmd, opt).await?;
                }
                ProcEvent::Subnegotiation(sub_neg) => {
                    self.queued.skip();
                    (handler, remote) = handler.subnegotiation(remote, &sub_neg).await?;
                }
                ProcEvent::Error => return Err(io::Error::from(io::ErrorKind::ConnectionReset)),
            }
        }
        let rest = self.queued.flush();
        if !rest.is_empty() {
            (handler, remote) = handler.data(remote, &data[rest]).await?;
        }
        Ok((handler, remote))
    }

    fn normal(&mut self, b: u8) -> ProcEvent {
        if b == IAC {
            if !self.change_state(State::Iac) {
                ProcEvent::Flush
            } else {
                ProcEvent::Processed
            }
        } else {
            ProcEvent::Queue
        }
    }

    fn iac(&mut self, b: u8) -> ProcEvent {
        match b {
            IAC => {
                assert!(self.change_state(State::Normal));
                ProcEvent::Queue
            }
            241..=249 => {
                assert!(self.change_state(State::Normal));
                ProcEvent::Command(b, None)
            }
            251..=254 => {
                self.cmd = b;
                assert!(self.change_state(State::IacOpt));
                ProcEvent::Processed
            }
            SB => {
                assert!(self.change_state(State::SubNeg));
                self.sub_neg.replace(Vec::new());
                ProcEvent::Processed
            }
            _ => ProcEvent::Error,
        }
    }

    fn iac_opt(&mut self, b: u8) -> ProcEvent {
        assert!(self.change_state(State::Normal));
        ProcEvent::Command(self.cmd, Some(b))
    }

    fn sub_neg(&mut self, b: u8) -> ProcEvent {
        if b == IAC {
            assert!(self.change_state(State::SubNegIac));
        } else {
            self.sub_neg.as_mut().unwrap().push(b);
        }
        ProcEvent::Processed
    }

    fn sub_neg_iac(&mut self, b: u8) -> ProcEvent {
        match b {
            IAC => {
                assert!(self.change_state(State::SubNeg));
                self.sub_neg.as_mut().unwrap().push(b);
                ProcEvent::Processed
            }
            SE => {
                assert!(self.change_state(State::Normal));
                ProcEvent::Subnegotiation(self.sub_neg.take().unwrap())
            }
            _ => ProcEvent::Error,
        }
    }

    fn change_state(&mut self, state: State) -> bool {
        if self.queued.has_queued() {
            debug!(
                "telnet state: (queued {:?}) {:?} -> {:?}",
                self.queued, self.state, state
            );
            return false;
        }
        debug!("telnet state: {:?} -> {:?}", self.state, state);
        self.state = state;
        return true;
    }
}

fn escape_iov<'a, 'b>(data: &'a [u8], iov: &'b mut Vec<IoSlice<'a>>, skip_single: bool) -> bool {
    let mut last = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == IAC {
            iov.push(IoSlice::new(&data[last..=i]));
            last = i;
        }
    }
    if iov.len() > 0 || !skip_single {
        iov.push(IoSlice::new(&data[last..]));
        true
    } else {
        false
    }
}

async fn escape_send<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<usize> {
    let mut iov = Vec::new();
    if escape_iov(data, &mut iov, true) {
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
    _ = escape_iov(data, &mut iov, false);
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

    pub fn run_stream<
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        H: Handler + Send + 'static,
    >(
        &mut self,
        read_half: R,
        write_half: W,
        handler: H,
    ) -> impl Future<Output = Result<()>> {
        run_stream(
            self.buf_size,
            self._remote.clone(),
            self.receiver.take().unwrap(),
            read_half,
            write_half,
            handler,
        )
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
                (handler, remote) = processor.process(&buf[..n], handler, remote).await?;
                if n == 0 {
                    break;
                }
            }
            Err(e) => {
                debug!("stream.read error: {:?}", e);
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

async fn run_stream<
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    H: Handler + Send + 'static,
>(
    buf_size: usize,
    remote: Remote,
    receiver: Receiver<Action>,
    read_half: R,
    write_half: W,
    handler: H,
) -> Result<()> {
    debug!("run_stream started");
    tokio::spawn(run_processor(
        read_half,
        buf_size,
        Processor::new(),
        handler,
        remote,
    ));
    tokio::spawn(run_writer(write_half, receiver));
    Ok(())
}
