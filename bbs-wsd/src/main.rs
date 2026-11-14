use bbs_common::{config::load, daemon};
use bbs_wsd::{config, ws};
use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "BBS WebSocket Daemon",
    version,
    author,
    about = "Specialized WebSocket server to bridge web clients to logind.",
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

    let cfg = load::<config::WsdConfig>(&args.config_file);

    let params = Arc::new(ws::Params::new(&cfg).expect("invalid WebSocket settings in config"));
    let prepared = daemon::startup(&cfg.daemon, ws::DAEMON, args.no_daemon);

    daemon::build_runtime(cfg.daemon.workers).block_on(daemon::serve(
        ws::DAEMON,
        prepared.listeners,
        prepared.logind_paths,
        ws::Wsd::new(params),
    ));
}
