#![feature(destructuring_assignment)]
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

fn drop_privileges() {
    use nix::unistd::{setgid, setuid, Gid, Uid};
    setgid(Gid::from_raw(99)).expect("failed to set gid");
    setuid(Uid::from_raw(9999)).expect("failed to set uid");
}

fn main() {
    let matches = App::new("BBS SSH Daemon")
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Specialized SSH daemon to bridge ssh client to logind.")
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

    let logger = syslog::unix(Formatter3164 {
        facility: Facility::LOG_LOCAL0,
        hostname: None,
        process: "bbs-sshd".into(),
        pid: std::process::id() as i32,
    })
    .expect("unable to start logging");
    log::set_boxed_logger(Box::new(Logger::new(logger))).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let mut config = thrussh::server::Config::default();
    config.server_id = "SSH-2.0-bbs-sshd".to_string();
    config.auth_rejection_time = Duration::ZERO;
    config.connection_timeout = None;

    let mut key_algos = Vec::new();
    for path in [
        "/home/robert/ssh_host_key_ed25519",
        "/home/robert/ssh_host_key_rsa",
    ] {
        let pem = std::fs::read_to_string(path).expect("failed to read key");
        host_keys::convert_key(&pem, &mut config.keys, &mut key_algos)
            .expect("failed to parse key");
    }
    config.preferred.key = key_algos.leak();

    // Per RFC 4252 Sec. 7, "publickey" method is required. However, we are not going to accept it.
    // "keyboard-interactive" is used for printing out error messages about bad user names.
    config.methods = thrussh::MethodSet::PUBLICKEY | thrussh::MethodSet::KEYBOARD_INTERACTIVE;
    if false {
        // debug rekey
        config.limits.rekey_time_limit = Duration::from_secs(10);
        config.limits.rekey_write_limit = 16384;
    }

    let listener = socket_linux::new_listener(
        SocketAddr::from_str("0.0.0.0:2222").expect("unable to parse bind address"),
        10,
    )
    .expect("unable to create listener socket");

    drop_privileges();
    if !matches.is_present("no_daemon") {
        daemonize();
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move { run(config, listener).await })
}

async fn run(config: thrussh::server::Config, listener: std::net::TcpListener) {
    let listener = tokio::net::TcpListener::from_std(listener)
        .expect("unable to convert TcpListener into tokio");
    let config = Arc::new(config);

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    let mut client_handles = Vec::new();
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
                client_handles.push(tokio::spawn(thrussh::server::run_stream(
                    config.clone(),
                    stream,
                    handler::Handler::new(client_addr),
                )));
            }
        }
    }
    std::mem::drop(listener);
    info!("Signal caught, draining clients");
    for handle in client_handles.into_iter() {
        let _ = handle.await;
    }
    info!("bbs-sshd stopped");
}
