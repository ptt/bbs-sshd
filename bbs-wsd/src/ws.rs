//! WebSocket front-end: forwards each client connection to `logind`, passing
//! the telnet byte stream between the two as it is, in WebSocket messages
//! towards the client.
//!
//! # Client protocol
//!
//! * Each message carries a chunk of the raw telnet byte stream, passed
//!   verbatim: a binary frame goes to `logind` as it is, and `logind` output
//!   comes back as a binary frame as it is. Nothing is framed as telnet on
//!   either side, so telnet commands and subnegotiations reach the client as
//!   bytes.
//! * Text frames are dropped: keystrokes arrive as binary frames, so text
//!   carries nothing, including the old JSON control messages.
//! * A close frame, or the connection going away, makes the `logind` side see
//!   EOF.
//! * The subprotocol is negotiated from `Sec-WebSocket-Protocol`. Only "telnet"
//!   is supported. If request does not negotiate, telnet is assumed.
//! * The client address reported to `logind` is the `ip:port` named by the
//!   configured `ip_header` (default `X-BBS-Client-IP`): the first of its
//!   values that is an address with a port behind it (an IPv6 address in
//!   brackets), the first of a comma-separated list. Nothing else names the
//!   client, so a request the header names no `ip:port` in is refused with 500
//!   and logged, and so is a unix connection with `ip_header` set to an empty
//!   string, which disables the header and leaves a unix peer with no address
//!   of its own.
//! * The client program named by `User-Agent` is reported to `logind` as
//!   `client_code`, the CRC-32 of the name in front of the first `/`,
//!   white-space or `(`, compatible with `wsproxy`; a client that sends no
//!   `User-Agent` is 0.
//! * A login is reported to `logind` as coming over a WebSocket
//!   (`CONN_FLAG_WEBSOCKET`), plus `CONN_FLAG_SECURE` when the configured
//!   `secure_header` (default `X-BBS-Secure`) says `1`, and alone when it says
//!   `0`. The header disabled by an empty name leaves every session insecure,
//!   and a request whose header is missing, or names neither `0` nor `1`, is
//!   refused with 500.

use crate::config::WsdConfig;
use bbs_common::daemon::{Accept, Half, Stream, UNIX_PREFIX};
use bbs_common::logind;
use bbs_common::socket_linux;
use bytes::Bytes;
use futures::sink::SinkExt;
use futures::stream::{SplitSink, SplitStream, StreamExt};
use log::{debug, error, info, trace};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::http;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::http::header::{
    AsHeaderName, HeaderName, HeaderValue, SEC_WEBSOCKET_PROTOCOL, SERVER, USER_AGENT,
};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config};

/// The WebSocket endpoint path requested by clients that we do not serve.
const DEFAULT_PATH: &str = "/bbs";
/// The subprotocol token asking for chunks of the raw telnet byte stream.
const PROTOCOL_TELNET: &str = "telnet";
/// What a session the client asked for no subprotocol of is logged as.
const NO_SUBPROTOCOL: &str = "none";
/// Why a unix connection with `ip_header` disabled has no client to report.
pub const NO_IP_HEADER: &str = "ip_header is disabled and a unix peer has no address";

/// The client half of a session: reads what the client sends.
type WsReader = SplitStream<WebSocketStream<Half>>;
/// The write half of a session: sends `logind` output to the client.
type WsSink = SplitSink<WebSocketStream<Half>, Message>;

/// Settings of the WebSocket front-end, shared by all connections.
#[derive(Clone, Debug)]
pub struct Params {
    pub path: Arc<str>,
    /// Header carrying the client address, or none when the config disables it
    /// with an empty name, which leaves a TCP peer address to name the client
    /// by.
    pub ip_header: Option<HeaderName>,
    /// Header carrying whether the session came in over TLS, `1` for secure and
    /// `0` for plain, or none when the config disables it with an empty name,
    /// which leaves every session insecure.
    pub secure_header: Option<HeaderName>,
}

impl Params {
    pub fn new(cfg: &WsdConfig) -> io::Result<Self> {
        // A unix peer has no address of its own to name the client by, so
        // there the header cannot be disabled.
        if cfg.ip_header.is_empty() && cfg.daemon.bind.iter().any(|e| is_unix_bind(e)) {
            return Err(invalid("ip_header is required for a unix socket"));
        }
        Ok(Params {
            path: Arc::from(cfg.path.as_deref().unwrap_or(DEFAULT_PATH)),
            ip_header: header_name(&cfg.ip_header)?,
            secure_header: header_name(&cfg.secure_header)?,
        })
    }
}

/// Whether a `bind` entry is a unix socket, whose clients have no address.
fn is_unix_bind(entry: &str) -> bool {
    entry.starts_with(UNIX_PREFIX)
}

/// A configured header name; an empty name disables the header.
fn header_name(name: &str) -> io::Result<Option<HeaderName>> {
    if name.is_empty() {
        return Ok(None);
    }
    HeaderName::from_str(name)
        .map(Some)
        .map_err(|e| invalid(format!("invalid header name {name:?}: {e}")))
}

/// A config setting that cannot be used.
fn invalid(reason: impl Into<Box<dyn Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Session parameters negotiated during the handshake.
#[derive(Clone)]
struct Handshake {
    /// What `logind` is told to transcode as: the telnet byte stream goes
    /// through as it is, so this is always the plain encoding.
    encoding: u32,
    /// The subprotocol the client asked for and the handshake echoes back, or
    /// none when the client asked for no subprotocol.
    protocol: Option<&'static str>,
    remote: SocketAddr,
    /// How `logind` is told the session came in: over a WebSocket, and over
    /// TLS as well when the secure header said so.
    flags: u32,
    /// The `User-Agent` the client sent, empty if it sent none.
    agent: String,
    /// What the client is, named by that `User-Agent` (see `logind::agent_code`).
    client_code: u32,
}

/// Serve one WebSocket client until it goes away, forwarding it to `logind`.
pub async fn serve_one(
    stream: Stream,
    peer: SocketAddr,
    lport: u16,
    logind_path: Arc<PathBuf>,
    params: Arc<Params>,
) {
    // A unix connection has no peer address to name the client, and no TCP
    // options to set.
    let (stream, peer, unix) = match stream {
        Stream::Tcp(stream) => {
            let stream = socket_linux::set_client_conn_options(stream)
                .expect("unable to set socket options");
            // The TCP peer is the client when the header names none.
            let peer = stream.peer_addr().unwrap_or(peer);
            (Stream::Tcp(stream), peer, false)
        }
        stream @ Stream::Unix(_) => (stream, peer, true),
    };
    // The session runs on the read half, so the write half stays free to hand
    // the client EOF once the session is over.
    let (session, write) = stream.into_split();
    let result = forwarding(session, peer, unix, lport, &logind_path, params).await;
    write.shutdown_write().await;
    if let Err(e) = result {
        info!("[client {peer}] WebSocket session ended: {e}");
    }
}

async fn forwarding(
    stream: Half,
    peer: SocketAddr,
    unix: bool,
    lport: u16,
    logind_path: &Path,
    params: Arc<Params>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut handshake: Option<Handshake> = None;
    // A rejected handshake leaves its answer on the way to the client, and the
    // write half that `serve_one` kept is what lets the client read it.
    let ws = accept_hdr_async_with_config(
        stream,
        WsCallback {
            out: &mut handshake,
            peer,
            unix,
            params,
        },
        Some(ws_config()),
    )
    .await?;
    let handshake = handshake.expect("the handshake callback always yields a handshake");
    // What the client is, to tell programs apart later (logs only): the
    // `User-Agent` it sent, which is what `client_code` names it by, and the
    // subprotocol it settled on.
    info!(
        "[client {}] Client: protocol {} encoding {} code {:08x} agent {:?}",
        handshake.remote,
        handshake.protocol.unwrap_or(NO_SUBPROTOCOL),
        logind::encoding_name(handshake.encoding),
        handshake.client_code,
        handshake.agent,
    );

    let (sink, mut ws_reader) = ws.split();

    let conn = UnixStream::connect(logind_path).await?;
    let conn_data = logind::ConnData {
        addr: handshake.remote,
        encoding: handshake.encoding,
        lport,
        flags: handshake.flags,
        client_code: handshake.client_code,
    };
    logind::send_to_conn(&conn, &conn_data.serialize().unwrap()).await?;
    info!(
        "[client {}] Opened a WebSocket connection to logind {} (encoding {})",
        handshake.remote,
        logind_path.display(),
        logind::encoding_name(handshake.encoding)
    );

    let (logind_reader, mut logind_writer) = conn.into_split();
    // Both directions pass bytes as they are: `logind` output goes out in a
    // binary frame per read, and a client frame goes to `logind` as it is.
    tokio::spawn(logind_to_client(logind_reader, sink));
    let result = client_to_logind(&mut ws_reader, &mut logind_writer).await;
    // Let `logind` see EOF once the client is gone.
    let _ = logind_writer.shutdown().await;
    drain_client(&mut ws_reader).await;
    result
}

/// A client that is done has this long to close its side of the connection.
const CLOSE_GRACE: Duration = Duration::from_secs(30);

/// Read whatever the client sends once the session is over, until it closes its
/// side of the connection.
///
/// Closing a unix socket drops the frames the client has not read, while a TCP
/// connection lets them through, so the session has to stay open until the
/// client has taken everything.
async fn drain_client(ws: &mut WsReader) {
    let _ = tokio::time::timeout(CLOSE_GRACE, async { while ws.next().await.is_some() {} }).await;
}

/// Handshake callback: negotiates the session and stores it in `out`.
struct WsCallback<'a> {
    out: &'a mut Option<Handshake>,
    peer: SocketAddr,
    /// Whether the connection came in on a unix socket, which has no peer
    /// address to name the client.
    unix: bool,
    params: Arc<Params>,
}

impl Callback for WsCallback<'_> {
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> StdResult<Response, ErrorResponse> {
        match handshake(request, self.peer, self.unix, &self.params) {
            Ok(handshake) => {
                // The subprotocol to echo back is known before the handshake is
                // handed over to the session.
                let protocol = handshake.protocol;
                *self.out = Some(handshake);
                Ok(with_server(match protocol {
                    Some(protocol) => with_protocol(response, protocol),
                    None => response,
                }))
            }
            Err((status, reason)) => Err(reject(status, &reason)),
        }
    }
}

/// Negotiate the session from the handshake request.
fn handshake(
    req: &Request,
    peer: SocketAddr,
    unix: bool,
    params: &Params,
) -> Result<Handshake, (StatusCode, String)> {
    if req.uri().path() != params.path.as_ref() {
        return Err((StatusCode::NOT_FOUND, "no such path".to_string()));
    }

    // An offer of no subprotocol is served as it stands; `telnet` is the only
    // token served, echoed back verbatim, so it is normalised to a 'static
    // constant. Offers of nothing but other tokens are refused here, before the
    // upgrade.
    let protocol = match requested_protocol(req) {
        Ok(protocol) => protocol,
        Err(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown protocol {other}; use {PROTOCOL_TELNET}"),
            ));
        }
    };

    let remote =
        client_addr(req, params, peer, unix).map_err(|(_, reason)| refused(peer, reason))?;
    let secure = secure_flag(req, params).map_err(|(_, reason)| refused(peer, reason))?;
    let agent = agent(req);
    Ok(Handshake {
        // The telnet byte stream is handed over untranscoded, whatever the
        // subprotocol is.
        encoding: logind::ConnData::CONV_NORMAL,
        protocol,
        remote,
        flags: logind::ConnData::CONN_FLAG_WEBSOCKET
            | if secure {
                logind::ConnData::CONN_FLAG_SECURE
            } else {
                0
            },
        client_code: logind::agent_code(&agent),
        agent,
    })
}

/// A request that cannot be served is a misconfiguration, a proxy that sends
/// no client address or says nothing about TLS, so the session never starts and
/// the reason goes to the log, with the answer that goes to the client.
fn refused(peer: SocketAddr, reason: String) -> (StatusCode, String) {
    error!("[client {peer}] {reason}: refusing the connection");
    server_error(reason)
}

/// Whether the session came in over TLS, as the configured `secure_header`
/// says: `1` is secure and `0` is plain. The header disabled by an empty name
/// leaves every session insecure, and a request whose header is missing, or
/// names neither `0` nor `1`, is refused.
fn secure_flag(req: &Request, params: &Params) -> Result<bool, (StatusCode, String)> {
    // The config disabled the header, so nothing is encrypted.
    let Some(header) = params.secure_header.as_ref() else {
        return Ok(false);
    };
    let name = header.as_str();
    match header_value(req, header) {
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(other) => Err(server_error(format!("{name} names {other}, not 0 or 1"))),
        None => Err(server_error(format!("{name} is missing"))),
    }
}

/// The `User-Agent` the client sent, empty if it sent none.
fn agent(req: &Request) -> String {
    header_value(req, &USER_AGENT)
        .unwrap_or_default()
        .to_string()
}

/// The subprotocol to serve, picked from the `Sec-WebSocket-Protocol` offers.
///
/// A client that offers no token, e.g. `new WebSocket(url)`, is served without
/// a subprotocol being echoed back; so is a client whose offers are all empty.
/// `telnet` is the only token served, and it is served wherever it appears
/// among the offers. Offers of nothing but other tokens are refused, naming the
/// first offer.
fn requested_protocol(req: &Request) -> Result<Option<&'static str>, &str> {
    let mut offers = header_values(req, SEC_WEBSOCKET_PROTOCOL);
    let mut first = None;
    for offer in offers.by_ref() {
        if offer.is_empty() {
            continue;
        }
        if offer == PROTOCOL_TELNET {
            return Ok(Some(PROTOCOL_TELNET));
        }
        first = first.or(Some(offer));
    }
    match first {
        Some(other) => Err(other),
        None => Ok(None),
    }
}

/// The first value of a header, if it is set and names something.
fn header_value<'a>(req: &'a Request, name: &'a HeaderName) -> Option<&'a str> {
    header_values(req, name).find(|value| !value.is_empty())
}

/// All values of a header, split on commas.
fn header_values<K: AsHeaderName>(req: &Request, name: K) -> impl Iterator<Item = &str> {
    req.headers()
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim))
}

/// The client address to report to `logind`, named by the configured
/// `ip_header`: the first of its values that is an `ip:port` (an IPv6 address
/// in brackets), the first of a comma-separated list. Nothing else names the
/// client, so a request whose header names no `ip:port` is refused, as is one
/// whose header names nothing at all; a unix connection with the header
/// disabled has no peer address of its own, so it is refused too.
fn client_addr(
    req: &Request,
    params: &Params,
    peer: SocketAddr,
    unix: bool,
) -> Result<SocketAddr, (StatusCode, String)> {
    // The config disabled the header, so the TCP peer address names the client.
    let Some(header) = params.ip_header.as_ref() else {
        return match unix {
            false => Ok(peer),
            true => Err(server_error(NO_IP_HEADER.to_string())),
        };
    };
    let name = header.as_str();
    // A client address is an address with a port of its own behind it, so a
    // bare address, and anything else of no use, names no client.
    for value in header_values(req, header).filter(|value| !value.is_empty()) {
        if let Ok(addr) = SocketAddr::from_str(value) {
            return Ok(addr);
        }
    }
    Err(server_error(if header_value(req, header).is_some() {
        format!("{name} names no ip:port")
    } else {
        format!("{name} is missing")
    }))
}

/// A request that cannot be served, with what to tell the client about it.
fn server_error(reason: String) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, reason)
}

fn with_protocol(mut resp: Response, protocol: &'static str) -> Response {
    resp.headers_mut()
        .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(protocol));
    resp
}

/// Every answer says which daemon sent it.
fn with_server<T>(mut resp: http::Response<T>) -> http::Response<T> {
    resp.headers_mut()
        .insert(SERVER, HeaderValue::from_static(DAEMON));
    resp
}

fn reject(status: StatusCode, reason: &str) -> ErrorResponse {
    let mut resp = ErrorResponse::new(Some(reason.to_string()));
    *resp.status_mut() = status;
    with_server(resp)
}
fn ws_config() -> WebSocketConfig {
    // A terminal session has many small messages, so write them out eagerly.
    WebSocketConfig::default()
        .read_buffer_size(4 * 1024)
        .write_buffer_size(0)
        .max_message_size(Some(1 << 20))
        .max_frame_size(Some(64 * 1024))
}

/// How much of the `logind` byte stream is read at a time, one frame per read.
const LOGIND_READ: usize = 4 * 1024;

/// Send everything `logind` has to say to the client, then close the session.
async fn logind_to_client(mut logind: OwnedReadHalf, mut ws: WsSink) -> io::Result<()> {
    let mut buf = vec![0; LOGIND_READ];
    loop {
        let read = logind.read(&mut buf).await?;
        // `logind` has said the last of it, so the session is over.
        if read == 0 {
            break;
        }
        if ws
            .send(Message::Binary(Bytes::copy_from_slice(&buf[..read])))
            .await
            .is_err()
        {
            trace!("logind_to_client: send error");
            return Err(io::ErrorKind::ConnectionReset.into());
        }
    }
    let _ = ws.close().await;
    Ok(())
}

/// Forward client messages to `logind` as they are, until the client goes away.
async fn client_to_logind(
    ws: &mut WsReader,
    logind: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    while let Some(msg) = ws.next().await {
        match msg? {
            Message::Binary(data) => logind.write_all(&data).await?,
            Message::Text(text) => trace!("Dropping text frame: {text}"),
            Message::Close(frame) => {
                debug!("Client closed the session: {frame:?}");
                break;
            }
            Message::Ping(payload) => trace!("Client ping {} bytes", payload.len()),
            Message::Pong(payload) => trace!("Client pong {} bytes", payload.len()),
            Message::Frame(frame) => trace!("Client frame {frame:?}"),
        }
    }
    Ok(())
}

/// Name of the WebSocket service, used in the process title and logs.
pub const DAEMON: &str = "bbs-wsd";

/// One forwarded `logind` session per accepted connection.
#[derive(Clone)]
pub struct Wsd {
    params: Arc<Params>,
}

impl Wsd {
    pub fn new(params: Arc<Params>) -> Self {
        Self { params }
    }
}

impl Accept for Wsd {
    async fn accept(self, stream: Stream, peer: SocketAddr, lport: u16, logind_path: Arc<PathBuf>) {
        serve_one(stream, peer, lport, logind_path, self.params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_IP_HEADER, DEFAULT_SECURE_HEADER, default_ip_header, default_secure_header,
    };
    use bbs_common::config::DaemonConfig;

    fn config() -> WsdConfig {
        WsdConfig {
            daemon: DaemonConfig::default(),
            path: Some("/ws".to_string()),
            secure_header: default_secure_header(),
            ip_header: default_ip_header(),
        }
    }

    /// Settings of a config with `path`, `ip_header` and `secure_header` as
    /// given.
    fn settings(ip_header: &str, secure_header: &str) -> Params {
        Params::new(&WsdConfig {
            path: Some("/bbs".to_string()),
            ip_header: ip_header.to_string(),
            secure_header: secure_header.to_string(),
            ..config()
        })
        .expect("usable config")
    }

    /// A request refused for, with what the client is told about it.
    fn refused<T>(reason: &str) -> Result<T, (StatusCode, String)> {
        Err((StatusCode::INTERNAL_SERVER_ERROR, reason.to_string()))
    }

    #[test]
    fn params_use_the_config_settings() {
        let params = Params::new(&config()).expect("usable config");
        assert_eq!(params.path.as_ref(), "/ws");
        assert_eq!(
            params.ip_header,
            Some(HeaderName::from_static("x-bbs-client-ip"))
        );
        assert_eq!(
            params.secure_header,
            Some(HeaderName::from_static("x-bbs-secure"))
        );
    }

    #[test]
    fn params_fill_in_the_defaults() {
        let mut cfg = config();
        cfg.path = None;
        let params = Params::new(&cfg).expect("usable config");
        assert_eq!(params.path.as_ref(), DEFAULT_PATH);
        assert_eq!(
            params.ip_header,
            Some(HeaderName::from_str(DEFAULT_IP_HEADER).expect("the default is a header name"))
        );
        assert_eq!(
            params.secure_header,
            Some(
                HeaderName::from_str(DEFAULT_SECURE_HEADER).expect("the default is a header name")
            )
        );
    }

    #[test]
    fn header_names_are_validated() {
        let mut cfg = config();
        cfg.ip_header = "Content Type".to_string();
        Params::new(&cfg).expect_err("a space is not a header name");
        cfg.ip_header = default_ip_header();
        cfg.secure_header = "Secure?".to_string();
        Params::new(&cfg).expect_err("a question mark is not a header name");

        // An empty name disables a header. The client address header, which a
        // TCP socket can do: its peer address names the client then. And the
        // secure header, which leaves every session insecure.
        cfg.secure_header = String::new();
        cfg.ip_header = String::new();
        let params = Params::new(&cfg).expect("usable config");
        assert_eq!(params.ip_header, None);
        assert_eq!(params.secure_header, None);

        // A unix peer has no address of its own to name the client by, so
        // there the client address header cannot be disabled, while a disabled
        // secure header serves it.
        cfg.daemon.bind = vec!["unix:/run/bbs/wsd.sock".to_string()];
        Params::new(&cfg).expect_err("a unix socket cannot do with a disabled address header");
        cfg.ip_header = default_ip_header();
        Params::new(&cfg).expect("a unix socket with a disabled secure header");
    }

    /// A handshake request with the given extra headers.
    fn request(headers: &[(&'static str, &'static str)]) -> Request {
        let mut builder = Request::builder().method("GET").uri("/bbs");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("usable request")
    }

    #[test]
    fn client_addresses_come_from_the_header() {
        let params = settings(DEFAULT_IP_HEADER, DEFAULT_SECURE_HEADER);
        let peer = SocketAddr::from(([127, 0, 0, 1], 8081));
        let client = |addr: &str| addr.parse::<SocketAddr>().expect("an ip:port");
        // The header of the config names the client and nothing else does, so
        // a request it names no client in is refused, over TCP as well as over
        // unix. A client address is an `ip:port`, so a bare address names no
        // client, and so does a value that is no address at all.
        for (headers, unix, want) in [
            (
                &[("x-bbs-client-ip", "203.0.113.7:4321")][..],
                false,
                Ok(client("203.0.113.7:4321")),
            ),
            (
                &[("x-bbs-client-ip", "203.0.113.7:4321")][..],
                true,
                Ok(client("203.0.113.7:4321")),
            ),
            (
                &[("x-bbs-client-ip", "[2001:db8::1]:4321")][..],
                true,
                Ok(client("[2001:db8::1]:4321")),
            ),
            (
                &[("x-bbs-client-ip", "203.0.113.7")][..],
                false,
                refused("x-bbs-client-ip names no ip:port"),
            ),
            (
                &[("x-bbs-client-ip", "203.0.113.7")][..],
                true,
                refused("x-bbs-client-ip names no ip:port"),
            ),
            (
                &[("x-bbs-client-ip", "2001:db8::1")][..],
                false,
                refused("x-bbs-client-ip names no ip:port"),
            ),
            // In a chain the leftmost `ip:port` is the client, and a value that
            // names none is passed over for the next value of the header.
            (
                &[("x-bbs-client-ip", "203.0.113.7:4321, 192.0.2.1")][..],
                true,
                Ok(client("203.0.113.7:4321")),
            ),
            (
                &[("x-bbs-client-ip", "unknown, 192.0.2.1:4321")][..],
                false,
                Ok(client("192.0.2.1:4321")),
            ),
            (
                &[("x-bbs-client-ip", "203.0.113.7, 192.0.2.1")][..],
                false,
                refused("x-bbs-client-ip names no ip:port"),
            ),
            // A header that is not the configured one names no client, and so
            // does the peer address of a TCP connection. A header that names
            // nothing at all is as good as one that is not there.
            (
                &[("x-real-ip", "203.0.113.7")][..],
                false,
                refused("x-bbs-client-ip is missing"),
            ),
            (&[][..], false, refused("x-bbs-client-ip is missing")),
            (&[][..], true, refused("x-bbs-client-ip is missing")),
            (
                &[("x-bbs-client-ip", "")][..],
                false,
                refused("x-bbs-client-ip is missing"),
            ),
            (
                &[("x-bbs-client-ip", "unknown")][..],
                false,
                refused("x-bbs-client-ip names no ip:port"),
            ),
            (
                &[("x-bbs-client-ip", "unknown")][..],
                true,
                refused("x-bbs-client-ip names no ip:port"),
            ),
        ] {
            assert_eq!(
                client_addr(&request(headers), &params, peer, unix),
                want,
                "{headers:?} over {}",
                if unix { "unix" } else { "TCP" }
            );
        }
    }

    #[test]
    fn a_disabled_header_leaves_the_tcp_peer_to_name_the_client() {
        let params = settings("", DEFAULT_SECURE_HEADER);
        let peer = SocketAddr::from(([127, 0, 0, 1], 8081));
        // The header is disabled, so no header names a client: the TCP peer
        // address does, and a unix peer has no address of its own.
        assert_eq!(
            client_addr(
                &request(&[("x-bbs-client-ip", "203.0.113.7:4321")]),
                &params,
                peer,
                false
            ),
            Ok(peer),
        );
        assert_eq!(
            client_addr(&request(&[]), &params, peer, true),
            refused(NO_IP_HEADER)
        );
    }

    #[test]
    fn security_comes_from_the_secure_header() {
        let params = settings(DEFAULT_IP_HEADER, DEFAULT_SECURE_HEADER);
        // `1` is a session over TLS and `0` is a plain one, and a request that
        // names neither, in a header that is there at all, is refused.
        for (headers, want) in [
            (&[("x-bbs-secure", "1")][..], Ok(true)),
            (&[("x-bbs-secure", "0")][..], Ok(false)),
            (&[("x-bbs-secure", " 1 ")][..], Ok(true)),
            (&[("x-bbs-secure", "1, 0")][..], Ok(true)),
            (
                &[("x-bbs-secure", "yes")][..],
                refused("x-bbs-secure names yes, not 0 or 1"),
            ),
            (
                &[("x-bbs-secure", "2")][..],
                refused("x-bbs-secure names 2, not 0 or 1"),
            ),
            (
                &[("x-bbs-secure", "")][..],
                refused("x-bbs-secure is missing"),
            ),
            (&[("x-secure", "1")][..], refused("x-bbs-secure is missing")),
            (&[][..], refused("x-bbs-secure is missing")),
        ] {
            assert_eq!(secure_flag(&request(headers), &params), want, "{headers:?}");
        }
        // The header disabled leaves every session insecure, whatever the
        // request sends, and nothing of the request is read for it.
        let plain = settings(DEFAULT_IP_HEADER, "");
        assert_eq!(secure_flag(&request(&[]), &plain), Ok(false));
        assert_eq!(
            secure_flag(&request(&[("x-bbs-secure", "yes")]), &plain),
            Ok(false)
        );
    }

    #[test]
    fn negotiates_the_subprotocol() {
        // No offer at all, or offers of nothing, mean no subprotocol to echo
        // back. `telnet` is served from anywhere among the offers, in as many
        // headers as the client spread them over. Offers of nothing but other
        // tokens are refused, naming the first offer.
        for (offers, want) in [
            (&[][..], Ok(None)),
            (&[("sec-websocket-protocol", "")][..], Ok(None)),
            (
                &[("sec-websocket-protocol", "telnet")][..],
                Ok(Some(PROTOCOL_TELNET)),
            ),
            (&[("sec-websocket-protocol", "bbs")][..], Err("bbs")),
            (&[("sec-websocket-protocol", "bbs, bbsu")][..], Err("bbs")),
            (
                &[("sec-websocket-protocol", "bbs, telnet")][..],
                Ok(Some(PROTOCOL_TELNET)),
            ),
            (
                &[
                    ("sec-websocket-protocol", "bbs"),
                    ("sec-websocket-protocol", "telnet"),
                ][..],
                Ok(Some(PROTOCOL_TELNET)),
            ),
            (
                &[("sec-websocket-protocol", ", telnet,")][..],
                Ok(Some(PROTOCOL_TELNET)),
            ),
        ] {
            assert_eq!(requested_protocol(&request(offers)), want, "{offers:?}");
        }
    }
}
