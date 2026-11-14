//! Shared parts of the BBS front-end daemons.
//!
//! Both `bbs-sshd` and `bbs-wsd` bridge their clients to `logind` over its
//! telnet `connfwd` Unix socket, and share everything but the client protocol:
//!
//! * [`daemon`]  - process setup (syslog, PID file, privileges) and the accept
//!   loop; a server implements `daemon::Accept` to handle one connection.
//! * [`logind`]  - the `connfwd` handshake and `logind` output stream.
//! * [`telnet`]  - the telnet protocol spoken towards `logind`.
//! * [`socket_linux`] - TCP socket options and unix socket binding.
//! * [`config`]  - the settings shared by every daemon.

pub mod config;
pub mod daemon;
pub mod logind;
pub mod socket_linux;
pub mod telnet;
