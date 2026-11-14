use bbs_common::config::DaemonConfig;
use serde_derive::Deserialize;

/// Configuration of `bbs-wsd`.
#[derive(Deserialize)]
pub struct WsdConfig {
    #[serde(flatten)]
    pub daemon: DaemonConfig,
    // WebSocket endpoint path (default: "/bbs"). Requests to any other path,
    // e.g. a load balancer health check, are answered with 404.
    pub path: Option<String>,
    // Header that tells whether the session came in over TLS, so a login is
    // reported to `logind` as encrypted: `1` for a secure session and `0` for
    // a plain one. A request whose header is missing, or names neither `0` nor
    // `1`, is refused.
    //
    // An empty string disables the header, and every session is insecure then.
    // (default: "X-BBS-Secure")
    #[serde(default = "default_secure_header")]
    pub secure_header: String,
    // Header that carries the client address as `ip:port` (an IPv6 address in
    // brackets): the first value of the header that is an `ip:port` names the
    // client, and in a comma-separated list the first `ip:port` is the client.
    // A bare address names no client. Nothing else names the client, so a
    // connection whose header names no `ip:port` is refused.
    //
    // An empty string disables the header, and clients are named by their TCP
    // peer address then, which a unix socket connection has none of, so a
    // `bind` entry of a unix socket needs a header name here.
    // (default: "X-BBS-Client-IP")
    #[serde(default = "default_ip_header")]
    pub ip_header: String,
}

/// The `secure_header` name used when the config sets none.
pub const DEFAULT_SECURE_HEADER: &str = "X-BBS-Secure";

/// The `ip_header` name used when the config sets none.
pub const DEFAULT_IP_HEADER: &str = "X-BBS-Client-IP";

/// Default for `secure_header`.
pub fn default_secure_header() -> String {
    DEFAULT_SECURE_HEADER.to_string()
}

/// Default for `ip_header`.
pub fn default_ip_header() -> String {
    DEFAULT_IP_HEADER.to_string()
}
