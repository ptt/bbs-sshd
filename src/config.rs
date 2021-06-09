use log::LevelFilter;
use serde_derive::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Config {
    // List of addresses to bind.
    pub bind: Vec<String>,
    // List of host key files to load.
    pub host_keys: Vec<String>,
    // UID for the server to run as.
    pub uid: Option<u32>,
    // GID for the server to run as.
    pub gid: Option<u32>,
    // Number of worker threads to start.
    pub workers: Option<usize>,
    // Number of file descriptors limit to set.
    pub nofile: Option<usize>,
    // PID file to write to.
    pub pid_file: Option<String>,
    // Log level. Valid values: OFF, ERROR, WARN, INFO, DEBUG, TRACE.
    // TRACE is not available in release builds.
    pub log_level: Option<LevelFilter>,
    // Path to logind socket.
    pub logind_path: String,
}
