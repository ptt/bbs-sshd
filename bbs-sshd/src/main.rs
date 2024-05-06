mod config;
mod handler;
mod logind;
mod socket_linux;
mod telnet;
use log::{error, info};
use russh_keys::key::KeyPair;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use syslog::{Facility, Formatter3164, LoggerBackend};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

const FLAG_NO_DEAMON: &str = "no_daemon";
const FLAG_CONFIG_FILE: &str = "config_file";

struct Logger {
    under: Mutex<syslog::Logger<LoggerBackend, Formatter3164>>,
    also_stderr: bool,
}

impl Logger {
    fn new(under: syslog::Logger<LoggerBackend, Formatter3164>, also_stderr: bool) -> Self {
        Logger {
            under: Mutex::new(under),
            also_stderr,
        }
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
            let _ = match record.level() {
                log::Level::Error => under.err(message),
                log::Level::Warn => under.warning(message),
                log::Level::Info => under.info(message),
                log::Level::Debug => under.debug(message),
                log::Level::Trace => under.debug(message),
            };
        }
    }

    fn flush(&self) {}
}

fn daemonize() {
    // Closing fds is known to be problematic.
    match fork::daemon(/* nochdir */ false, /* noclose */ true) {
        Ok(fork::Fork::Child) => return,
        Ok(fork::Fork::Parent(_)) => std::process::exit(0),
        Err(e) => {
            error!("Error daemonizing: {}", e);
            std::process::exit(1);
        }
    }
}

fn write_pid_file(cfg: &config::Config) {
    if let Some(pid_file) = &cfg.pid_file {
        std::fs::write(pid_file, std::process::id().to_string()).expect("failed to write pid file");
    }
}

fn drop_privileges(cfg: &config::Config) {
    use nix::unistd::{setgid, setuid, Gid, Uid};
    if let Some(gid) = cfg.gid {
        setgid(Gid::from_raw(gid)).expect("failed to set gid");
    }
    if let Some(uid) = cfg.uid {
        setuid(Uid::from_raw(uid)).expect("failed to set uid");
    }
}

fn load_host_keys(
    cfg: &config::Config,
    keys: &mut Vec<KeyPair>,
    key_algos: &mut Vec<russh_keys::key::Name>,
) {
    for path in &cfg.host_keys {
        let key = russh_keys::load_secret_key(path, None).expect("failed to load key");
        use russh_keys::key::*;
        match key {
            KeyPair::RSA { key, .. } => {
                keys.push(KeyPair::RSA {
                    key: key.clone(),
                    hash: SignatureHash::SHA2_512,
                });
                key_algos.push(RSA_SHA2_512);

                keys.push(KeyPair::RSA {
                    key: key.clone(),
                    hash: SignatureHash::SHA2_256,
                });
                key_algos.push(RSA_SHA2_256);

                keys.push(KeyPair::RSA {
                    key: key.clone(),
                    hash: SignatureHash::SHA1,
                });
                key_algos.push(SSH_RSA);
            }
            KeyPair::Ed25519(key) => {
                keys.push(KeyPair::Ed25519(key));
                key_algos.push(ED25519);
            }
            KeyPair::EC { key } => {
                let key = KeyPair::EC { key };
                key_algos.push(russh_keys::key::Name(key.name()));
                keys.push(key);
            }
        }
    }
}

fn make_ssh_config(cfg: &config::Config) -> russh::server::Config {
    let mut sshcfg = russh::server::Config::default();
    sshcfg.server_id = russh::SshId::Standard("SSH-2.0-bbs-sshd".to_string());
    sshcfg.auth_rejection_time = Duration::ZERO;
    sshcfg.inactivity_timeout = None;

    let mut key_algos = Vec::new();
    load_host_keys(cfg, &mut sshcfg.keys, &mut key_algos);
    sshcfg.preferred.key = key_algos.leak();
    sshcfg.preferred.compression = &["none"];

    // Per RFC 4252 Sec. 7, "publickey" method is required. However, we are not going to accept it.
    // "keyboard-interactive" is used for printing out error messages about bad user names.
    sshcfg.methods = russh::MethodSet::PUBLICKEY
        | russh::MethodSet::KEYBOARD_INTERACTIVE
        | russh::MethodSet::PASSWORD;
    if false {
        // debug rekey
        sshcfg.limits.rekey_time_limit = Duration::from_secs(10);
        sshcfg.limits.rekey_write_limit = 16384;
    }

    sshcfg
}

fn bind_ports(cfg: &config::Config) -> Vec<std::net::TcpListener> {
    cfg.bind
        .iter()
        .map(|addr| {
            socket_linux::new_listener(
                SocketAddr::from_str(addr).expect("unable to parse bind address"),
                10,
            )
            .expect("unable to create listener socket")
        })
        .collect()
}

fn main() {
    use clap::{Arg, Command};
    let matches = Command::new("BBS SSH Daemon")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Specialized SSH daemon to bridge ssh client to logind.")
        .arg(
            Arg::new(FLAG_CONFIG_FILE)
                .short('f')
                .help("Config file path")
                .takes_value(true)
                .value_name("FILE")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_NO_DEAMON)
                .short('D')
                .help("Do not daemonize; PID file will not be written"),
        )
        .after_help(
            "SIGNALS:\n\
            \x20   SIGINT, SIGTERM - Graceful shutdown.\n\
            \x20       Stop listening and wait all clients to disconnect",
        )
        .get_matches();

    let cfg: config::Config = toml::from_str(
        &std::fs::read_to_string(matches.value_of(FLAG_CONFIG_FILE).unwrap())
            .expect("failed to read config file"),
    )
    .expect("failed to parse config file");

    let sshcfg = make_ssh_config(&cfg);

    if let Some(nofile) = cfg.nofile {
        rlimit::setrlimit(rlimit::Resource::NOFILE, nofile as u64, nofile as u64)
            .expect("unable to set nofile limit");
    }

    let listeners = bind_ports(&cfg);

    drop_privileges(&cfg);
    let foreground = matches.is_present(FLAG_NO_DEAMON);
    if !foreground {
        daemonize();
        write_pid_file(&cfg);
    }

    let logger = syslog::unix(Formatter3164 {
        facility: Facility::LOG_LOCAL0,
        hostname: None,
        process: "bbs-sshd".into(),
        pid: std::process::id(),
    })
    .expect("unable to start logging");
    log::set_boxed_logger(Box::new(Logger::new(logger, foreground))).unwrap();
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

    match cfg.workers.unwrap_or(0) {
        0 => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        n => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(n)
            .build(),
    }
    .unwrap()
    .block_on(async move { run(sshcfg, listeners, logind_paths).await });
}

async fn run(
    config: russh::server::Config,
    listeners: Vec<std::net::TcpListener>,
    logind_paths: Vec<Arc<PathBuf>>,
) {
    let (tx, mut rx) = mpsc::channel(1);
    let config = Arc::new(config);

    proctitle::set_title("bbs-sshd: run");
    let servers: Vec<_> = listeners
        .into_iter()
        .enumerate()
        .map(move |(idx, listener)| {
            tokio::spawn(run_one_server(
                config.clone(),
                listener,
                PathPicker::new(logind_paths.clone(), idx),
                tx.clone(),
            ))
        })
        .collect();

    for handle in servers.into_iter() {
        let _ = handle.await;
    }
    info!("Signal caught, draining clients");
    proctitle::set_title("bbs-sshd: drain");
    let _ = rx.recv().await;
    info!("bbs-sshd stopped");
}

async fn run_one_server(
    config: Arc<russh::server::Config>,
    listener: std::net::TcpListener,
    mut logind_paths: PathPicker,
    alive: mpsc::Sender<()>,
) {
    let _ = alive;
    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("unable to convert TcpListener into tokio");
    let lport = match listener
        .local_addr()
        .expect("unable to retrieve local address")
    {
        SocketAddr::V4(v4) => v4.port(),
        SocketAddr::V6(v6) => v6.port(),
    };

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    loop {
        tokio::select! {
            biased;
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            accepted = listener.accept() => {
                let (stream, client_addr) = accepted.expect("unable to accept connection");
                spawn_forwarding(
                    config.clone(),
                    stream,
                    handler::Handler::new(client_addr, lport, logind_paths.next()),
                    alive.clone(),
                );
            }
        }
    }
}

fn spawn_forwarding(
    config: Arc<russh::server::Config>,
    stream: tokio::net::TcpStream,
    handler: handler::Handler,
    alive: mpsc::Sender<()>,
) {
    let stream =
        socket_linux::set_client_conn_options(stream).expect("unable to set socket options");

    use futures::FutureExt;
    tokio::spawn(
        russh::server::run_stream(config, stream, handler).map(move |_| {
            let _ = alive;
        }),
    );
}

struct PathPicker {
    paths: Vec<Arc<PathBuf>>,
    offset: usize,
}

impl PathPicker {
    pub fn new(paths: Vec<Arc<PathBuf>>, offset: usize) -> Self {
        let offset = offset % paths.len();
        PathPicker { paths, offset }
    }

    pub fn next(&mut self) -> Arc<PathBuf> {
        let path = self.paths[self.offset].clone();
        self.offset += 1;
        if self.offset == self.paths.len() {
            self.offset = 0;
        }
        path
    }
}
