#![feature(destructuring_assignment)]
mod handler;
mod host_keys;
mod logind;
mod socket_linux;
mod telnet;
use log::info;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() {
    env_logger::init();

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
    let config = Arc::new(config);

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    let listener = socket_linux::new_listener(
        SocketAddr::from_str("0.0.0.0:2222").expect("unable to parse bind address"),
        10,
    )
    .expect("unable to create listener socket");

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
}
