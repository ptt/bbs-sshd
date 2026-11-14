//! Daemon plumbing shared by the binaries in this crate: privilege handling,
//! daemonization, logging, socket binding, and the accept/drain loop.

use crate::config::DaemonConfig;
use crate::socket_linux;
use log::{error, info};
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};
use tokio::net::{TcpListener, TcpStream, UnixListener as TokioUnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio::task::JoinSet;

/// What a server does with one accepted connection: gets the accepted stream,
/// the client address, the local port, and the `logind` socket path to forward
/// the connection to.
///
/// The stream is the whole connection, so a server that serves it on one half
/// keeps the other half to end the connection once the session is over.
///
/// `accept` takes the acceptor by value, so the future owns its state and is
/// `'static`: the loop just clones the acceptor and spawns the future.
///
/// It must never panic and is responsible for logging its own failures, since
/// the accept loop ignores its result.
pub trait Accept: Clone + Send + Sync + 'static {
    fn accept(
        self,
        stream: Stream,
        client_addr: SocketAddr,
        lport: u16,
        logind_path: Arc<PathBuf>,
    ) -> impl Future<Output = ()> + Send;
}

/// A socket to accept clients on: a TCP address, or a unix socket path, as
/// written in the `bind` config list.
pub enum Listener {
    Tcp(std::net::TcpListener),
    Unix(UnixListener),
}

/// A connection accepted from a [`Listener`].
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    /// Split the connection in halves, so the session served by the read half
    /// leaves a write half free to stop sending once it is over.
    ///
    /// Each half keeps the socket alive, so what the session has already handed
    /// to the client is not dropped with the session.
    pub fn into_split(self) -> (Half, Half) {
        match self {
            Stream::Tcp(stream) => {
                let (read, write) = stream.into_split();
                (Half::TcpRead(read), Half::TcpWrite(write))
            }
            Stream::Unix(stream) => {
                let (read, write) = stream.into_split();
                (Half::UnixRead(read), Half::UnixWrite(write))
            }
        }
    }
}

/// One half of a [`Stream`].
///
/// A half reads and writes the socket of the connection it came from, so a
/// session on the read half can still answer the handshake, and the write half
/// can stop sending.
pub enum Half {
    TcpRead(TcpReadHalf),
    TcpWrite(TcpWriteHalf),
    UnixRead(UnixReadHalf),
    UnixWrite(UnixWriteHalf),
}

impl Half {
    /// Stop sending, so the peer sees EOF and reads whatever is already on its
    /// way to it.
    ///
    /// Closing a unix socket drops the frames the peer has not read, while a
    /// TCP connection lets them through, and a handshake rejection is one.
    pub async fn shutdown_write(mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = self.shutdown().await;
    }
}

impl AsyncRead for Half {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Half::TcpRead(half) => Pin::new(half).poll_read(cx, buf),
            Half::TcpWrite(half) => poll_shared_read(half.as_ref(), cx, buf),
            Half::UnixRead(half) => Pin::new(half).poll_read(cx, buf),
            Half::UnixWrite(half) => poll_shared_read(half.as_ref(), cx, buf),
        }
    }
}

impl AsyncWrite for Half {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Half::TcpRead(half) => poll_shared_write(half.as_ref(), cx, buf),
            Half::TcpWrite(half) => Pin::new(half).poll_write(cx, buf),
            Half::UnixRead(half) => poll_shared_write(half.as_ref(), cx, buf),
            Half::UnixWrite(half) => Pin::new(half).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Half::TcpRead(half) => poll_shared_write_vectored(half.as_ref(), cx, bufs),
            Half::TcpWrite(half) => Pin::new(half).poll_write_vectored(cx, bufs),
            Half::UnixRead(half) => poll_shared_write_vectored(half.as_ref(), cx, bufs),
            Half::UnixWrite(half) => Pin::new(half).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Nothing of ours is buffered, and a socket queues no write of its own.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Half::TcpRead(half) => shutdown_write(half.as_ref()),
            Half::TcpWrite(half) => Pin::new(half).poll_shutdown(cx),
            Half::UnixRead(half) => shutdown_write(half.as_ref()),
            Half::UnixWrite(half) => Pin::new(half).poll_shutdown(cx),
        }
    }
}

/// The shared-handle methods that both tokio socket types have, which a half
/// uses for the direction of the socket it does not own.
trait SharedSocket {
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn try_write(&self, buf: &[u8]) -> io::Result<usize>;
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl SharedSocket for TcpStream {
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_read(buf)
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_read_ready(cx)
    }

    fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        self.try_write(buf)
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_ready(cx)
    }
}

impl SharedSocket for UnixStream {
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_read(buf)
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_read_ready(cx)
    }

    fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        self.try_write(buf)
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_ready(cx)
    }
}

/// Read into `buf` from a socket that is shared with the other half.
fn poll_shared_read<S: SharedSocket>(
    stream: &S,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    loop {
        match stream.try_read(buf.filled_mut()) {
            // A read of zero bytes is the end of the stream.
            Ok(0) => return Poll::Ready(Ok(())),
            Ok(read) => {
                buf.advance(read);
                return Poll::Ready(Ok(()));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match stream.poll_read_ready(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            },
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
}

/// Write `buf` to a socket that is shared with the other half, picking up where
/// a partial write left off.
fn poll_shared_write<S: SharedSocket>(
    stream: &S,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    let mut left = buf;
    let mut written = 0usize;
    loop {
        match stream.try_write(left) {
            // A write of zero bytes is a socket that took no more.
            Ok(0) => return stopped(written, Poll::Ready(Ok(written))),
            Ok(wrote) => {
                written += wrote;
                left = &left[wrote..];
                if left.is_empty() {
                    return Poll::Ready(Ok(written));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => match stream.poll_write_ready(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return stopped(written, Poll::Ready(Err(e))),
                Poll::Pending => return stopped(written, Poll::Pending),
            },
            Err(e) => return stopped(written, Poll::Ready(Err(e))),
        }
    }
}

/// Write `bufs` to a socket that is shared with the other half.
fn poll_shared_write_vectored<S: SharedSocket>(
    stream: &S,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>> {
    // A slice cannot be picked up in mid-slice in stable Rust, so every slice
    // goes out on its own.
    let mut written = 0usize;
    for buf in bufs {
        match poll_shared_write(stream, cx, buf) {
            Poll::Ready(Ok(wrote)) => written += wrote,
            stop => return stopped(written, stop),
        }
    }
    Poll::Ready(Ok(written))
}

/// The outcome of a write that stopped with `written` bytes gone out: a caller
/// that wrote nothing keeps the reason to stop for, and a caller that wrote
/// something takes the bytes.
fn stopped(written: usize, stop: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
    if written == 0 {
        stop
    } else {
        Poll::Ready(Ok(written))
    }
}

/// Stop sending on a socket shared with the other half, so the peer sees EOF
/// once it has read everything already on its way.
fn shutdown_write<S: AsRawFd>(stream: &S) -> Poll<io::Result<()>> {
    let rc = unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_WR) };
    if rc == 0 {
        Poll::Ready(Ok(()))
    } else {
        Poll::Ready(Err(io::Error::last_os_error()))
    }
}

/// What a unix peer looks like to `logind`: no address and no port, so the
/// client address has to come out of the request.
pub const NO_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Prefix of a unix entry in the `bind` list, whose clients have no address of
/// their own.
pub const UNIX_PREFIX: &str = "unix:";
/// Prefix of a unix abstract namespace name, which has no socket file.
const ABSTRACT_PREFIX: &str = "@";
/// Backlog of every listening socket.
const BACKLOG: i32 = 10;

/// A `bind` entry, parsed.
#[derive(Debug)]
enum Bind {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// Parse one `bind` entry: a TCP address, `unix:<path>`, or `unix:@<name>` for
/// the abstract namespace.
fn parse_bind(entry: &str) -> std::io::Result<Bind> {
    let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
    if let Some(rest) = entry.strip_prefix(UNIX_PREFIX) {
        if rest.is_empty() {
            return Err(invalid(format!("bind entry {entry:?} has no unix path")));
        }
        // An abstract name stands for a NUL byte and the name, and has no
        // socket file behind it.
        if let Some(name) = rest.strip_prefix(ABSTRACT_PREFIX) {
            if name.is_empty() {
                return Err(invalid(format!(
                    "bind entry {entry:?} has no abstract name"
                )));
            }
            return Ok(Bind::Unix(PathBuf::from(format!("\0{name}"))));
        }
        return Ok(Bind::Unix(PathBuf::from(rest)));
    }
    SocketAddr::from_str(entry)
        .map(Bind::Tcp)
        .map_err(|e| invalid(format!("unable to parse bind address {entry:?}: {e}")))
}

fn bind_socket(entry: &str) -> Listener {
    let bind = parse_bind(entry).expect("invalid bind entry");
    match bind {
        Bind::Tcp(addr) => {
            Listener::Tcp(socket_linux::new_listener(addr, BACKLOG).expect("unable to bind"))
        }
        Bind::Unix(path) => Listener::Unix(
            socket_linux::new_unix_listener(&path, BACKLOG)
                .unwrap_or_else(|e| panic!("unable to bind {}: {e}", path.display())),
        ),
    }
}

/// What [`startup`] prepared for the binary to serve.
pub struct Prepared {
    pub listeners: Vec<Listener>,
    pub logind_paths: Vec<Arc<PathBuf>>,
}

struct Logger {
    under: Mutex<syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>>,
    name: String,
    also_stderr: bool,
}

impl Logger {
    fn new(
        under: syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>,
        name: String,
        also_stderr: bool,
    ) -> Self {
        Logger {
            under: Mutex::new(under),
            name,
            also_stderr,
        }
    }
}

/// Connect to syslog (`/dev/log`) with `name` as the ident.
fn open_syslog(
    name: &str,
) -> syslog::Result<syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>> {
    syslog::unix(syslog::Formatter3164 {
        facility: syslog::Facility::LOG_LOCAL0,
        hostname: None,
        process: name.into(),
        pid: std::process::id(),
    })
}

/// Send `message` to syslog at `level`.
fn send(
    under: &mut syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>,
    level: log::Level,
    message: &str,
) -> syslog::Result<()> {
    match level {
        log::Level::Error => under.err(message),
        log::Level::Warn => under.warning(message),
        log::Level::Info => under.info(message),
        log::Level::Debug => under.debug(message),
        log::Level::Trace => under.debug(message),
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level().to_level_filter() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        use time::format_description::well_known::Rfc3339;

        if self.enabled(record.metadata()) {
            let mut under = self.under.lock().unwrap();
            let message = format!("{} ({}) {}", record.level(), record.target(), record.args());
            if self.also_stderr {
                eprintln!(
                    "{} {}",
                    time::OffsetDateTime::now_utc()
                        // Truncate to seconds.
                        .replace_microsecond(0)
                        .unwrap()
                        .format(&Rfc3339)
                        .unwrap(),
                    message
                );
            }
            // A restarted syslogd makes a new /dev/log, and the old connection
            // fails from then on: connect again and retry the line once.
            if send(&mut under, record.level(), &message).is_err() {
                let Ok(fresh) = open_syslog(&self.name) else {
                    return;
                };
                *under = fresh;
                let _ = send(&mut under, record.level(), &message);
            }
        }
    }

    fn flush(&self) {}
}

fn daemonize() {
    // Closing fds is known to be problematic.
    match fork::daemon(/* nochdir */ false, /* noclose */ true) {
        Ok(fork::Fork::Child) => (),
        Ok(fork::Fork::Parent(_)) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error daemonizing: {}", e);
            std::process::exit(1);
        }
    }
}

fn write_pid_file(cfg: &DaemonConfig) {
    if let Some(pid_file) = &cfg.pid_file {
        std::fs::write(pid_file, std::process::id().to_string()).expect("failed to write pid file");
    }
}

fn drop_privileges(cfg: &DaemonConfig) {
    use nix::unistd::{Gid, Uid, setgid, setuid};
    if let Some(gid) = cfg.gid {
        setgid(Gid::from_raw(gid)).expect("failed to set gid");
    }
    if let Some(uid) = cfg.uid {
        setuid(Uid::from_raw(uid)).expect("failed to set uid");
    }
}

fn bind_sockets(cfg: &DaemonConfig) -> Vec<Listener> {
    cfg.bind.iter().map(|addr| bind_socket(addr)).collect()
}

/// Prepare the process for serving: apply resource limits, bind sockets, drop
/// privileges, daemonize, write the PID file, and start logging to syslog with
/// `name` as the ident.
///
/// `foreground` keeps the process in view of the caller that started it: it
/// stays put and writes no PID file, and log lines go to stderr as well.
///
/// Logging is not initialized before this returns, so binaries must not log
/// from `main`.
pub fn startup(cfg: &DaemonConfig, name: &str, foreground: bool) -> Prepared {
    if let Some(nofile) = cfg.nofile {
        rlimit::setrlimit(rlimit::Resource::NOFILE, nofile as u64, nofile as u64)
            .expect("unable to set nofile limit");
    }

    let listeners = bind_sockets(cfg);

    drop_privileges(cfg);
    if !foreground {
        daemonize();
        write_pid_file(cfg);
    }

    let logger = open_syslog(name).expect("unable to start logging");
    log::set_boxed_logger(Box::new(Logger::new(logger, name.into(), foreground))).unwrap();
    log::set_max_level(cfg.log_level.unwrap_or(log::LevelFilter::Info));

    let logind_paths: Vec<Arc<PathBuf>> = cfg
        .logind_paths
        .iter()
        .map(|p| Arc::new(PathBuf::from(p)))
        .collect();
    if logind_paths.is_empty() {
        error!("logind_paths is empty");
        std::process::exit(1);
    }

    Prepared {
        listeners,
        logind_paths,
    }
}

/// Build the tokio runtime for this daemon: a single threaded one unless
/// `workers` asks for more.
pub fn build_runtime(workers: Option<usize>) -> tokio::runtime::Runtime {
    match workers.unwrap_or(0) {
        0 => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        n => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(n)
            .build(),
    }
    .unwrap()
}

/// Accept on every listener until SIGINT/SIGTERM, then drain: stop accepting
/// and wait for all clients to disconnect.
pub async fn serve<A: Accept>(
    name: &str,
    listeners: Vec<Listener>,
    logind_paths: Vec<Arc<PathBuf>>,
    accept: A,
) {
    let (tx, _rx) = broadcast::channel(1);

    proctitle::set_title(format!("{name}: run"));

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    let mut join_set = JoinSet::new();
    for (idx, listener) in listeners.into_iter().enumerate() {
        join_set.spawn(run_one_server(
            listener,
            RoundRobin::new(logind_paths.clone(), idx),
            tx.subscribe(),
            accept.clone(),
        ));
    }

    tokio::select! {
        biased;
        _ = sigint.recv() => (),
        _ = sigterm.recv() => (),
    }
    info!("Signal caught, draining clients");
    proctitle::set_title(format!("{name}: drain"));
    drop(tx);

    while join_set.join_next().await.is_some() {}
    info!("{name} stopped");
}

async fn run_one_server<A: Accept>(
    listener: Listener,
    mut logind_paths: RoundRobin<Arc<PathBuf>>,
    mut stop: broadcast::Receiver<()>,
    accept: A,
) {
    let server = Server::start(listener).expect("unable to start listening");

    let mut join_set = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.recv() => break,
            accepted = server.accept() => {
                let (stream, client_addr, lport) = accepted.expect("unable to accept connection");
                let logind_path = logind_paths.next().clone();
                join_set.spawn(accept.clone().accept(stream, client_addr, lport, logind_path));
            }
        }
    }
    drop(server);
    while join_set.join_next().await.is_some() {}
}

/// A tokio listener, ready to accept, with the local port of a TCP socket.
enum Server {
    Tcp(TcpListener, u16),
    Unix(TokioUnixListener),
}

impl Server {
    fn start(listener: Listener) -> std::io::Result<Self> {
        match listener {
            Listener::Tcp(listener) => {
                let listener = TcpListener::from_std(listener)
                    .expect("unable to convert TcpListener into tokio");
                let lport = listener
                    .local_addr()
                    .expect("unable to retrieve local address")
                    .port();
                Ok(Server::Tcp(listener, lport))
            }
            Listener::Unix(listener) => Ok(Server::Unix(
                TokioUnixListener::from_std(listener)
                    .expect("unable to convert UnixListener into tokio"),
            )),
        }
    }

    /// The next client, its address, and the local port to report to `logind`.
    async fn accept(&self) -> std::io::Result<(Stream, SocketAddr, u16)> {
        match self {
            Server::Tcp(listener, lport) => {
                let (stream, client_addr) = listener.accept().await?;
                Ok((Stream::Tcp(stream), client_addr, *lport))
            }
            // A unix peer has no address, and this listener has no port.
            Server::Unix(listener) => {
                let (stream, _peer) = listener.accept().await?;
                Ok((Stream::Unix(stream), NO_PEER, 0))
            }
        }
    }
}

/// Round-robin picker over `logind` sockets, starting at `offset` so that
/// several listeners do not all start at the same entry.
struct RoundRobin<T> {
    items: Vec<T>,
    offset: usize,
}

impl<T> RoundRobin<T> {
    fn new(items: Vec<T>, offset: usize) -> Self {
        let offset = offset % items.len();
        Self { items, offset }
    }

    fn next(&mut self) -> &T {
        let item = &self.items[self.offset];
        self.offset += 1;
        if self.offset == self.items.len() {
            self.offset = 0;
        }
        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix_path(entry: &str) -> PathBuf {
        let Bind::Unix(path) = parse_bind(entry).expect("a unix bind entry") else {
            panic!("{entry:?} is not a unix bind entry")
        };
        path
    }

    #[test]
    fn parses_tcp_binds() {
        let Bind::Tcp(addr) = parse_bind("127.0.0.1:2022").expect("a tcp bind entry") else {
            panic!("not a tcp bind entry")
        };
        assert_eq!(addr, SocketAddr::from(([127, 0, 0, 1], 2022)));

        let Bind::Tcp(addr) = parse_bind("[::]:2022").expect("a tcp bind entry") else {
            panic!("not a tcp bind entry")
        };
        assert_eq!(addr.port(), 2022);
    }

    #[test]
    fn parses_unix_binds() {
        assert_eq!(
            unix_path("unix:/run/bbs/wsd.sock"),
            PathBuf::from("/run/bbs/wsd.sock")
        );
        // An abstract name has no socket file, so it starts with a NUL byte.
        assert_eq!(unix_path("unix:@bbs"), PathBuf::from("\0bbs"));
    }

    #[test]
    fn rejects_useless_binds() {
        // A unix path needs the `unix:` prefix, and an abstract name needs a
        // name behind `@`.
        for entry in [
            "",
            "nonsense",
            "127.0.0.1",
            "/run/bbs/wsd.sock",
            "unix:",
            "unix:@",
        ] {
            assert_eq!(
                parse_bind(entry)
                    .expect_err("{entry:?} is not a bind entry")
                    .kind(),
                std::io::ErrorKind::InvalidInput,
                "{entry:?} should be rejected"
            );
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bbs-common-{}-{}-{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("cannot create the temp dir");
        dir
    }

    #[tokio::test]
    async fn accepts_a_tcp_client() {
        // Port 0 is the port the operating system picks for us.
        let Listener::Tcp(listener) = bind_socket("127.0.0.1:0") else {
            panic!("a tcp entry is a tcp listener")
        };
        let port = listener
            .local_addr()
            .expect("cannot read the address")
            .port();
        let server = Server::start(Listener::Tcp(listener)).expect("cannot start listening");

        let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("cannot connect");
        let (stream, peer, lport) = server.accept().await.expect("no client connected");
        assert!(matches!(stream, Stream::Tcp(_)));
        assert_eq!(lport, port);
        assert_eq!(peer.ip().to_string(), "127.0.0.1");

        drop(conn);
        drop(server);
    }

    #[tokio::test]
    async fn accepts_a_unix_client() {
        let dir = temp_dir("accept");
        let path = dir.join("wsd.sock");
        let entry = format!("unix:{}", path.display());
        let Listener::Unix(listener) = bind_socket(&entry) else {
            panic!("{entry:?} is a unix bind entry")
        };
        let server = Server::start(Listener::Unix(listener)).expect("cannot start listening");

        let conn = tokio::net::UnixStream::connect(&path)
            .await
            .expect("cannot connect");
        let (stream, peer, lport) = server.accept().await.expect("no client connected");
        assert!(matches!(stream, Stream::Unix(_)));
        // A unix peer has no address, and this listener has no port.
        assert_eq!(peer, NO_PEER);
        assert_eq!(lport, 0);

        drop(conn);
        drop(server);
        std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
    }

    #[tokio::test]
    async fn accepts_an_abstract_client() {
        let name = format!("@bbs-common-accept-{}", std::process::id());
        let Listener::Unix(listener) = bind_socket(&format!("unix:{name}")) else {
            panic!("an abstract entry is a unix listener")
        };
        let server = Server::start(Listener::Unix(listener)).expect("cannot start listening");

        // The address behind the `@` spelling is a NUL byte and the name.
        let path = PathBuf::from(format!("\0{}", &name[1..]));
        let conn = tokio::net::UnixStream::connect(&path)
            .await
            .expect("cannot connect an abstract name");
        let (stream, _, _) = server.accept().await.expect("no client connected");
        assert!(matches!(stream, Stream::Unix(_)));

        drop(conn);
        drop(server);
    }
}
