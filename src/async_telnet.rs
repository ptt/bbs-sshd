use std::cell::Cell;
use std::io::Result;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use telnet::NegotiationAction;
use telnet::TelnetEvent;
use telnet::TelnetOption;
use tokio::net::unix::OwnedReadHalf;
use tokio::net::unix::OwnedWriteHalf;

#[derive(Clone)]
struct Conn {
    read_half: Arc<OwnedReadHalf>,
    write_buf: Arc<Mutex<Cell<Vec<u8>>>>,
}

impl std::io::Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.read_half.as_ref().as_ref().try_read(buf)
    }
}

impl std::io::Write for Conn {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.write_buf
            .lock()
            .unwrap()
            .get_mut()
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl telnet::Stream for Conn {
    fn set_nonblocking(&self, _nonblocking: bool) -> Result<()> {
        Ok(())
    }

    fn set_read_timeout(&self, _dur: Option<Duration>) -> Result<()> {
        Ok(())
    }
}

pub struct Telnet {
    read_half: Arc<OwnedReadHalf>,
    write_half: Mutex<Option<Arc<OwnedWriteHalf>>>,
    write_buf: Arc<Mutex<Cell<Vec<u8>>>>,
    telnet: Mutex<telnet::Telnet>,
}

unsafe impl std::marker::Send for Telnet {}
unsafe impl std::marker::Sync for Telnet {}

impl Telnet {
    pub fn new(conn: tokio::net::UnixStream, buf_size: usize) -> Self {
        let write_buf = Arc::new(Mutex::new(Cell::new(Vec::new())));
        let (read_half, write_half) = conn.into_split();
        let read_half = Arc::new(read_half);
        let write_half = Mutex::new(Some(Arc::new(write_half)));
        let stream = Box::new(Conn {
            read_half: read_half.clone(),
            write_buf: write_buf.clone(),
        });
        Telnet {
            read_half,
            write_half,
            write_buf,
            telnet: Mutex::new(telnet::Telnet::from_stream(stream, buf_size)),
        }
    }

    pub async fn read(&self) -> Result<TelnetEvent> {
        loop {
            match self.telnet.lock().unwrap().read_nonblocking() {
                Ok(TelnetEvent::NoData) => (),
                other => return other,
            }
            self.read_half.as_ref().as_ref().readable().await?;
        }
    }

    pub fn write(&self, data: &[u8]) -> Result<usize> {
        Ok(self.telnet.lock().unwrap().write(data)?)
    }

    pub async fn flush_write(&self) -> Result<()> {
        let data = self.write_buf.lock().unwrap().take();
        let w = self.write_half.lock().unwrap().as_ref().cloned().unwrap();
        let mut sent = 0;
        while sent < data.len() {
            match w.as_ref().as_ref().try_write(&data[sent..]) {
                Ok(n) => sent += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    w.as_ref().as_ref().writable().await?;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn shutdown_write(&self) {
        self.write_half.lock().unwrap().take();
    }

    #[allow(dead_code)]
    pub async fn negotiate(&self, action: NegotiationAction, opt: TelnetOption) -> Result<()> {
        self.telnet.lock().unwrap().negotiate(action, opt);
        self.flush_write().await?;
        Ok(())
    }

    pub async fn subnegotiate(&self, opt: TelnetOption, data: &[u8]) -> Result<()> {
        self.telnet.lock().unwrap().subnegotiate(opt, data);
        self.flush_write().await?;
        Ok(())
    }
}
