use super::byte::{IAC, SB, SE};
use super::{Handler, Remote};
use log::trace;
use std::io;
use std::io::Result;
use std::ops::Range;

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

#[derive(Debug)]
enum ProcEvent {
    Queue,
    Flush,
    Processed,
    Command(u8, Option<u8>),
    Subnegotiation(Vec<u8>),
    Error,
}

pub(crate) struct Processor {
    state: State,
    queued: Queued,
    cmd: u8,
    sub_neg: Option<Vec<u8>>,
}

impl Processor {
    pub fn new() -> Self {
        Processor {
            state: State::Normal,
            queued: Queued::new(),
            cmd: 0,
            sub_neg: None,
        }
    }

    pub async fn process<H: Handler + Send>(
        &mut self,
        data: &[u8],
        handler: &mut H,
        remote: &Remote,
    ) -> Result<()> {
        if data.is_empty() {
            trace!("process: eof");
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
                    handler.data(remote, &data[self.queued.flush()]).await?;
                }
                ProcEvent::Processed => self.queued.skip(),
                ProcEvent::Command(cmd, opt) => {
                    self.queued.skip();
                    handler.command(remote, cmd, opt).await?;
                }
                ProcEvent::Subnegotiation(data) => {
                    self.queued.skip();
                    handler.subnegotiation(remote, &data).await?;
                }
                ProcEvent::Error => return Err(io::Error::from(io::ErrorKind::ConnectionReset)),
            }
        }
        let rest = self.queued.flush();
        if !rest.is_empty() {
            handler.data(remote, &data[rest]).await?;
        }
        Ok(())
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
            return false;
        }
        trace!("telnet state: {:?} -> {:?}", self.state, state);
        self.state = state;
        true
    }
}
