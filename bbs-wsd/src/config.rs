use bbs_common::config::DaemonConfig;
use serde_derive::Deserialize;

/// Configuration of `bbs-wsd`.
#[derive(Deserialize)]
pub struct WsdConfig {
    #[serde(flatten)]
    pub daemon: DaemonConfig,
    // WebSocket endpoint path.
    pub path: Option<String>,
    // Header that tells whether the session came in a secured channel.
    #[serde(default = "default_secure_header")]
    pub secure_header: String,
    // Header that carries the client address as `ip:port` (an IPv6 address in
    // brackets).
    #[serde(default = "default_ip_header")]
    pub ip_header: String,
    // Header that carries the server local port the client connected to.
    #[serde(default = "default_lport_header")]
    pub lport_header: String,
}

/// The `secure_header` name used when the config sets none.
pub const DEFAULT_SECURE_HEADER: &str = "X-BBS-Secure";

/// The `ip_header` name used when the config sets none.
pub const DEFAULT_IP_HEADER: &str = "X-BBS-Client-IP";

/// The `lport_header` name used when the config sets none.
pub const DEFAULT_LPORT_HEADER: &str = "X-BBS-Local-Port";

/// Default for `secure_header`.
pub fn default_secure_header() -> String {
    DEFAULT_SECURE_HEADER.to_string()
}

/// Default for `ip_header`.
pub fn default_ip_header() -> String {
    DEFAULT_IP_HEADER.to_string()
}

/// Default for `lport_header`.
pub fn default_lport_header() -> String {
    DEFAULT_LPORT_HEADER.to_string()
}
