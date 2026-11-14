use bbs_common::{config::load, daemon};
use bbs_sshd::{config, handler};
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;

fn make_ssh_config(cfg: &config::SshConfig) -> russh::server::Config {
    let mut sshcfg = russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-bbs-sshd".into()),
        auth_rejection_time: Duration::ZERO,
        inactivity_timeout: None,
        ..Default::default()
    };

    sshcfg.keys = cfg
        .host_keys
        .iter()
        .map(|path| russh::keys::load_secret_key(path, None).expect("failed to load key"))
        .collect();
    sshcfg.preferred.key = sshcfg
        .keys
        .iter()
        .map(|key| key.algorithm())
        .collect::<Vec<_>>()
        .into();
    sshcfg.preferred.compression = std::borrow::Cow::from(&[russh::compression::NONE]);

    // Per RFC 4252 Sec. 7, "publickey" method is required. However, we are not going to accept it.
    // "keyboard-interactive" is used for printing out error messages about bad user names.
    sshcfg.methods.push(russh::MethodKind::PublicKey);
    sshcfg.methods.push(russh::MethodKind::KeyboardInteractive);
    sshcfg.methods.push(russh::MethodKind::Password);
    if false {
        // debug rekey
        sshcfg.limits.rekey_time_limit = Duration::from_secs(10);
        sshcfg.limits.rekey_write_limit = 16384;
    }

    sshcfg
}

#[derive(Parser, Debug)]
#[command(
    name = "BBS SSH Daemon",
    version,
    author,
    about = "Specialized SSH daemon to bridge ssh client to logind.",
    long_about = None,
    after_help = "SIGNALS:\n\
        \x20   SIGINT, SIGTERM - Graceful shutdown.\n\
        \x20       Stop listening and wait all clients to disconnect",
)]
struct Args {
    /// Config file path
    #[arg(long, short = 'f')]
    config_file: String,

    /// Do not daemonize; PID file will not be written
    #[arg(short = 'D', default_value_t = false)]
    no_daemon: bool,
}

fn main() {
    let args = Args::parse();

    let cfg = load::<config::SshConfig>(&args.config_file);
    let sshcfg = Arc::new(make_ssh_config(&cfg));
    let prepared = daemon::startup(&cfg.daemon, handler::DAEMON, args.no_daemon);

    daemon::build_runtime(cfg.daemon.workers).block_on(daemon::serve(
        handler::DAEMON,
        prepared.listeners,
        prepared.logind_paths,
        handler::Sshd::new(sshcfg),
    ));
}
