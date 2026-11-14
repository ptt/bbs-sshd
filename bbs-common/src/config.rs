use log::LevelFilter;
use serde::de::DeserializeOwned;
use serde_derive::Deserialize;

/// Settings shared by every daemon.
#[derive(Deserialize, Default)]
pub struct DaemonConfig {
    // List of addresses to bind: a TCP address, `unix:/path/to/sock`, or
    // `unix:@name` for a unix abstract namespace socket.
    pub bind: Vec<String>,
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
    // List of path to logind socket.
    pub logind_paths: Vec<String>,
}

/// Read and parse a TOML config file of the given type.
pub fn load<T: DeserializeOwned>(path: &str) -> T {
    toml::from_str(&std::fs::read_to_string(path).expect("failed to read config file"))
        .expect("failed to parse config file")
}
