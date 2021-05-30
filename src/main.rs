#![feature(destructuring_assignment)]
mod config;
mod handler;
mod host_keys;
mod logind;
mod socket_linux;
mod telnet;
use clap::{App, Arg};
use log::{error, info};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use syslog::{Facility, Formatter3164, LoggerBackend};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

struct Logger {
    under: Arc<Mutex<syslog::Logger<LoggerBackend, Formatter3164>>>,
}

impl Logger {
    fn new(under: syslog::Logger<LoggerBackend, Formatter3164>) -> Self {
        Logger {
            under: Arc::new(Mutex::new(under)),
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut under = self.under.lock().unwrap();
            let message = format!("{} ({}) {}", record.level(), record.target(), record.args());
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

fn make_ssh_config(cfg: &config::Config) -> thrussh::server::Config {
    let mut sshcfg = thrussh::server::Config::default();
    sshcfg.server_id = "SSH-2.0-bbs-sshd".to_string();
    sshcfg.auth_rejection_time = Duration::ZERO;
    sshcfg.connection_timeout = None;

    let mut key_algos = Vec::new();
    for path in &cfg.host_keys {
        let pem = std::fs::read_to_string(path).expect("failed to read key");
        host_keys::convert_key(&pem, &mut sshcfg.keys, &mut key_algos)
            .expect("failed to parse key");
    }
    sshcfg.preferred.key = key_algos.leak();

    // Per RFC 4252 Sec. 7, "publickey" method is required. However, we are not going to accept it.
    // "keyboard-interactive" is used for printing out error messages about bad user names.
    sshcfg.methods = thrussh::MethodSet::PUBLICKEY | thrussh::MethodSet::KEYBOARD_INTERACTIVE;
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
    let matches = App::new("BBS SSH Daemon")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Specialized SSH daemon to bridge ssh client to logind.")
        .arg(
            Arg::with_name("config_file")
                .short("f")
                .help("Config file path")
                .takes_value(true)
                .value_name("FILE")
                .required(true),
        )
        .arg(
            Arg::with_name("no_daemon")
                .short("D")
                .help("Do not daemonize; PID file will not be written"),
        )
        .after_help(
            "SIGNALS:\n\
            \x20   SIGINT, SIGTERM - Graceful shutdown.\n\
            \x20       Stop listening and wait all clients to disconnect",
        )
        .get_matches();

    let cfg: config::Config = toml::from_str(
        &std::fs::read_to_string(matches.value_of("config_file").unwrap())
            .expect("failed to read config file"),
    )
    .expect("failed to parse config file");

    let sshcfg = make_ssh_config(&cfg);
    let listeners = bind_ports(&cfg);

    drop_privileges(&cfg);
    if !matches.is_present("no_daemon") {
        daemonize();
        write_pid_file(&cfg);
    }

    let logger = syslog::unix(Formatter3164 {
        facility: Facility::LOG_LOCAL0,
        hostname: None,
        process: "bbs-sshd".into(),
        pid: std::process::id() as i32,
    })
    .expect("unable to start logging");
    log::set_boxed_logger(Box::new(Logger::new(logger))).unwrap();
    log::set_max_level(log::LevelFilter::Info);

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
    .block_on(async move { run(sshcfg, listeners).await });
}

async fn run(config: thrussh::server::Config, listeners: Vec<std::net::TcpListener>) {
    let (tx, mut rx) = mpsc::channel(1);
    let config = Arc::new(config);

    let servers: Vec<_> = listeners
        .into_iter()
        .map(move |listener| tokio::spawn(run_one_server(config.clone(), listener, tx.clone())))
        .collect();

    for handle in servers.into_iter() {
        let _ = handle.await;
    }
    info!("Signal caught, draining clients");
    let _ = rx.recv().await;
    info!("bbs-sshd stopped");
}

async fn run_one_server(
    config: Arc<thrussh::server::Config>,
    listener: std::net::TcpListener,
    alive: mpsc::Sender<()>,
) {
    let _ = alive;
    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("unable to convert TcpListener into tokio");

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    loop {
        tokio::select! {
            biased;
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            accepted = listener.accept() => {
                let (stream, client_addr) = accepted.expect("unable to accept connection");

                let stream =
                    socket_linux::set_client_conn_options(stream)
                    .expect("unable to set socket options");
                tokio::spawn(run_forward(
                    config.clone(),
                    stream,
                    handler::Handler::new(client_addr),
                    alive.clone(),
                ));
            }
        }
    }
}

async fn run_forward(
    config: Arc<thrussh::server::Config>,
    stream: tokio::net::TcpStream,
    handler: handler::Handler,
    alive: mpsc::Sender<()>,
) {
    let _ = alive;
    let _ = thrussh::server::run_stream(config.clone(), stream, handler).await;
}
