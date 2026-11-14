use bbs_common::config::DaemonConfig;
use serde_derive::Deserialize;

/// Configuration of `bbs-sshd`.
#[derive(Deserialize)]
pub struct SshConfig {
    #[serde(flatten)]
    pub daemon: DaemonConfig,
    // List of host key files to load.
    pub host_keys: Vec<String>,
}
