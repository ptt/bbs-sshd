//! Daemon plumbing shared by the binaries in this crate: privilege handling,
//! daemonization, logging, socket binding, and the accept/drain loop.

use crate::config::DaemonConfig;
use crate::socket_linux;
use log::{error, info};
use std::future::Future;
use std::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UnixListener as TokioUnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time::sleep;

/// What a server does with one accepted connection: gets the socket it came in
/// on and the `logind` socket path to forward the connection to, by the kind of
/// socket the client arrived over.
///
/// Both methods default to logging the connection away and dropping the socket,
/// for a daemon that has nothing to serve one kind of client with.
///
/// It is responsible for logging its own failures; the accept loop ignores its result.
pub trait Accept: Clone + Send + Sync + 'static {
    /// Serve one TCP client.
    fn accept_tcp(
        self,
        stream: TcpStream,
        peer: SocketAddr,
        lport: u16,
        logind_path: Arc<PathBuf>,
    ) -> impl Future<Output = ()> + Send {
        let _ = (stream, peer, lport, logind_path);
        error!("nothing to serve a TCP client with: closing the connection");
        std::future::ready(())
    }

    /// Serve one unix client.
    fn accept_unix(
        self,
        stream: UnixStream,
        logind_path: Arc<PathBuf>,
    ) -> impl Future<Output = ()> + Send {
        let _ = (stream, logind_path);
        error!("nothing to serve a unix client with: closing the connection");
        std::future::ready(())
    }
}

/// A socket to accept clients on: a TCP address, or a unix socket path, as
/// written in the `bind` config list.
pub enum Listener {
    Tcp(std::net::TcpListener),
    Unix(UnixListener),
}

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
    // One loop serves both kinds: `Server::accept` takes the next client of
    // the kind its listener is, and `Accepted::serve` answers it with the
    // `Accept` method for that kind. Accepts that fail in a row are waited
    // out; one that works ends the run of them.
    let mut misses = 0;
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stop.recv() => break,
            accepted = server.accept(&mut logind_paths) => accepted,
        };
        match accepted {
            Ok(accepted) => {
                misses = 0;
                join_set.spawn(accepted.serve(accept.clone()));
            }
            Err(e) => {
                // A client that came in and went away before the accept landed.
                if e.kind() == std::io::ErrorKind::ConnectionAborted {
                    info!("a client went away before it was accepted: {e}");
                    continue;
                }
                misses += 1;
                let delay = backoff_delay(misses);
                error!("unable to accept a client, {misses} in a row, waiting {delay:?}: {e}");
                if backoff(misses, &mut stop).await {
                    break;
                }
            }
        }
    }
    // Dropping `server` stops accepting for this listener, and this waits out
    // the clients that are still connected.
    while join_set.join_next().await.is_some() {}
}

/// The wait an accept loop starts with after a failed accept, and the most its
/// run of failures grows it to.
const BACKOFF_FIRST: Duration = Duration::from_millis(50);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The wait before the accept that follows `misses` accepts that failed in a
/// row: the first wait, doubled per failure, capped.
fn backoff_delay(misses: u32) -> Duration {
    (BACKOFF_FIRST * (1u32 << misses.saturating_sub(1).min(10))).min(BACKOFF_MAX)
}

/// Wait out the delay `misses` failures in a row asks for, and report `stop`
/// as ending the wait early, which is what ends the accept loop.
async fn backoff(misses: u32, stop: &mut broadcast::Receiver<()>) -> bool {
    tokio::select! {
        biased;
        _ = stop.recv() => true,
        _ = sleep(backoff_delay(misses)) => false,
    }
}

/// A tokio listener, ready to accept, with the local port of a TCP socket.
enum Server {
    Tcp(TcpListener, u16),
    Unix(TokioUnixListener),
}

/// One accepted client, by the kind of socket it arrived over.
enum Accepted {
    Tcp {
        stream: TcpStream,
        peer: SocketAddr,
        lport: u16,
        logind_path: Arc<PathBuf>,
    },
    Unix {
        stream: UnixStream,
        logind_path: Arc<PathBuf>,
    },
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

    /// The next client of this listener's own kind. A client that arrives
    /// takes the next `logind` path, a failed accept takes none.
    async fn accept(
        &self,
        logind_paths: &mut RoundRobin<Arc<PathBuf>>,
    ) -> std::io::Result<Accepted> {
        match self {
            Server::Tcp(listener, lport) => {
                let (stream, peer) = listener.accept().await?;
                Ok(Accepted::Tcp {
                    stream,
                    peer,
                    lport: *lport,
                    logind_path: logind_paths.next().clone(),
                })
            }
            Server::Unix(listener) => {
                let (stream, _peer) = listener.accept().await?;
                Ok(Accepted::Unix {
                    stream,
                    logind_path: logind_paths.next().clone(),
                })
            }
        }
    }
}

impl Accepted {
    /// Serve this client with the `Accept` method that fits the kind it came
    /// over, as one task to spawn.
    async fn serve<A: Accept>(self, accept: A) {
        match self {
            Accepted::Tcp {
                stream,
                peer,
                lport,
                logind_path,
            } => accept.accept_tcp(stream, peer, lport, logind_path).await,
            Accepted::Unix {
                stream,
                logind_path,
            } => accept.accept_unix(stream, logind_path).await,
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
        let Server::Tcp(server, lport) =
            Server::start(Listener::Tcp(listener)).expect("cannot start listening")
        else {
            panic!("a tcp listener starts a tcp server")
        };

        let conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("cannot connect");
        let (stream, peer) = server.accept().await.expect("no client connected");
        // A TCP client comes with the address of the peer and the port of this
        // listener.
        assert_eq!(lport, port);
        assert_eq!(peer.ip().to_string(), "127.0.0.1");

        drop(stream);
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
        let Server::Unix(server) =
            Server::start(Listener::Unix(listener)).expect("cannot start listening")
        else {
            panic!("a unix listener starts a unix server")
        };

        let conn = tokio::net::UnixStream::connect(&path)
            .await
            .expect("cannot connect");
        let (stream, _peer) = server.accept().await.expect("no client connected");
        // A unix connection names no `ip:port` and no listener port, which is
        // what a server has to report a client by.

        drop(stream);
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
        let Server::Unix(server) =
            Server::start(Listener::Unix(listener)).expect("cannot start listening")
        else {
            panic!("a unix listener starts a unix server")
        };

        // The address behind the `@` spelling is a NUL byte and the name.
        let path = PathBuf::from(format!("\0{}", &name[1..]));
        let conn = tokio::net::UnixStream::connect(&path)
            .await
            .expect("cannot connect an abstract name");
        let (stream, _peer) = server.accept().await.expect("no client connected");

        drop(stream);
        drop(conn);
        drop(server);
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        // The first failure waits the least, every one after it in a row
        // doubles that, and the run stops growing at the cap.
        assert_eq!(backoff_delay(1), BACKOFF_FIRST);
        assert_eq!(backoff_delay(2), BACKOFF_FIRST * 2);
        assert_eq!(backoff_delay(7), BACKOFF_FIRST * 64);
        assert_eq!(backoff_delay(10), BACKOFF_FIRST * 512);
        assert_eq!(backoff_delay(11), BACKOFF_MAX);
        assert_eq!(backoff_delay(u32::MAX), BACKOFF_MAX);
    }
}
