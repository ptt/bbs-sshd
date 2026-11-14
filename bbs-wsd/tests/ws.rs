//! End-to-end tests for the WebSocket front-end against a stand-in `logind`.

use bbs_common::daemon::{NO_PEER, Stream};
use bbs_common::logind;
use bbs_common::socket_linux;
use bbs_common::telnet::byte::{IAC, NAWS, SB};
use bbs_wsd::ws;
use futures::sink::SinkExt;
use futures::stream::{Stream as WsStream, StreamExt};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::{
    HeaderName, HeaderValue, SEC_WEBSOCKET_PROTOCOL, SERVER,
};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{client_async, connect_async};

/// A stand-in for logind: reads the `connfwd` header, writes some screen
/// output, then echoes everything it reads until the writer side is shut down.
async fn fake_logind(path: PathBuf) -> (Vec<u8>, Vec<u8>) {
    let listener = UnixListener::bind(&path).expect("cannot bind the logind socket");
    let (conn, _) = listener.accept().await.expect("no logind client");
    drop(listener);
    let (mut rd, mut wr) = conn.into_split();

    // logind takes the 36 bytes it has always read, plus the client code that
    // goes out after them.
    let mut header = vec![0; 40];
    rd.read_exact(&mut header).await.expect("short header");
    wr.write_all(b"screen output\r\n")
        .await
        .expect("cannot write");

    let mut echoed = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = rd.read(&mut buf).await.expect("logind read failed");
        if n == 0 {
            break;
        }
        echoed.extend_from_slice(&buf[..n]);
        wr.write_all(&buf[..n]).await.expect("cannot echo");
    }
    (header, echoed)
}

/// A name no other test run of this tag collides with.
fn unique(tag: &str) -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bbs-wsd-{}", unique(tag)));
    std::fs::create_dir_all(&dir).expect("cannot create the temp dir");
    dir
}

/// A unique abstract namespace name, which has no socket file to clean up. A
/// `unix:@<name>` config entry stands for this: a NUL byte and the name.
fn abstract_name(tag: &str) -> PathBuf {
    PathBuf::from(format!("\0bbs-wsd-{}", unique(tag)))
}

/// A server socket bound at `path`, ready for a client to connect to.
fn unix_listener(path: &Path) -> UnixListener {
    UnixListener::from_std(
        socket_linux::new_unix_listener(path, 10).expect("cannot bind the server socket"),
    )
    .expect("cannot serve the unix socket")
}

/// Settings with the default header names, so a request has to name the client
/// address and whether the session came in over TLS.
fn params(path: &str) -> Arc<ws::Params> {
    params_with(path, Some("x-bbs-client-ip"), Some("x-bbs-secure"))
}

/// Settings with both headers disabled, so a TCP peer address names the client
/// and every session is insecure.
fn params_plain(path: &str) -> Arc<ws::Params> {
    params_with(path, None, None)
}

/// Settings with the client address under `ip_header` and the secure header
/// disabled.
fn params_ip_only(path: &str, ip_header: &'static str) -> Arc<ws::Params> {
    params_with(path, Some(ip_header), None)
}

fn params_with(
    path: &str,
    ip_header: Option<&'static str>,
    secure_header: Option<&'static str>,
) -> Arc<ws::Params> {
    Arc::new(ws::Params {
        path: Arc::from(path),
        ip_header: ip_header.map(HeaderName::from_static),
        secure_header: secure_header.map(HeaderName::from_static),
    })
}

/// A telnet NAWS subnegotiation, which this front-end never sends, as it
/// passes bytes only.
fn has_naws(data: &[u8]) -> bool {
    data.windows(3).any(|w| w == [IAC, SB, NAWS])
}

/// A handshake request with the given extra headers.
fn request(url: &str, headers: &[(&'static str, &'static str)]) -> Request {
    let mut request = url.into_client_request().unwrap();
    for (name, value) in headers {
        request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    request
}

/// Take binary frames until they add up to `want`.
///
/// `logind` output reaches the client in chunks, one per read of its socket,
/// so what one exchange sends can come back as more than one frame.
async fn collect<S>(ws: &mut S, want: &[u8]) -> Vec<u8>
where
    S: WsStream<Item = Result<Message, WsError>> + Unpin,
{
    let mut got = Vec::new();
    while !got.windows(want.len()).any(|w| w == want) {
        match ws.next().await.expect("no message").expect("read failed") {
            Message::Binary(data) => got.extend_from_slice(data.as_ref()),
            other => panic!("unexpected frame {other:?}"),
        }
    }
    got
}

/// Drain the client side of a session and check that it ends with a close frame.
async fn drain<S>(ws: &mut S)
where
    S: WsStream<Item = Result<Message, WsError>> + Unpin,
{
    while let Some(msg) = ws.next().await {
        match msg.expect("client read failed") {
            Message::Close(_) => break,
            Message::Binary(_) | Message::Text(_) => (),
            other => panic!("unexpected trailing frame {other:?}"),
        }
    }
}

#[tokio::test]
async fn forwards_a_session() {
    let dir = temp_dir("session");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    let (mut ws, response) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("sec-websocket-protocol", "bbs, telnet"),
            ("x-bbs-client-ip", "203.0.113.7:1234"),
            ("x-bbs-secure", "1"),
            ("user-agent", AGENT_FIREFOX),
        ],
    ))
    .await
    .expect("handshake failed");
    assert_eq!(response.status(), 101);
    // `telnet` is served from a list of offers, and echoed back.
    assert_eq!(response.headers()[SEC_WEBSOCKET_PROTOCOL], "telnet");
    // The answer names the daemon that sent it.
    assert_eq!(response.headers()[SERVER], ws::DAEMON);

    // Screen output from logind arrives as a binary frame, a chunk of the raw
    // telnet byte stream.
    match ws.next().await.expect("no output").expect("read failed") {
        Message::Binary(data) => assert_eq!(data.as_ref(), b"screen output\r\n"),
        other => panic!("unexpected frame {other:?}"),
    }

    // Keyboard input goes to logind and comes back echoed.
    ws.send(Message::binary(b"ls\r".to_vec()))
        .await
        .expect("cannot send");
    match ws.next().await.expect("no echo").expect("read failed") {
        Message::Binary(data) => assert_eq!(data.as_ref(), b"ls\r"),
        other => panic!("unexpected frame {other:?}"),
    }

    // A text frame is dropped, even when it looks like JSON.
    ws.send(Message::text(RESIZE_JSON))
        .await
        .expect("cannot send");

    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, echoed) = logind.await.expect("logind did not finish");

    // The connfwd header: cb, encoding, ip_len, ip, rport, lport, flags,
    // client_code.
    assert_eq!(header.len(), 40);
    assert_eq!(&header[0..4], &40u32.to_le_bytes());
    assert_eq!(&header[4..8], &logind::ConnData::CONV_NORMAL.to_le_bytes());
    assert_eq!(&header[8..12], &4u32.to_le_bytes());
    assert_eq!(&header[12..16], &[203, 0, 113, 7]);
    assert_eq!(&header[16..28], &[0; 12]);
    assert_eq!(&header[28..30], &1234u16.to_le_bytes());
    assert_eq!(&header[30..32], &lport.to_le_bytes());
    assert_eq!(
        &header[32..36],
        &(logind::ConnData::CONN_FLAG_WEBSOCKET | logind::ConnData::CONN_FLAG_SECURE).to_le_bytes()
    );
    assert_eq!(
        &header[36..40],
        &logind::agent_code(AGENT_FIREFOX).to_le_bytes()
    );

    // No window size is announced to logind at all.
    assert!(!has_naws(&echoed), "unexpected NAWS in {echoed:?}");
    assert!(
        !echoed
            .windows(RESIZE_JSON.len())
            .any(|w| w == RESIZE_JSON.as_bytes()),
        "a dropped text frame reached logind in {echoed:?}"
    );
    assert!(echoed.windows(3).any(|w| w == b"ls\r"));

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

/// A browser `User-Agent`, to name the client by for `logind`.
const AGENT_FIREFOX: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) \
    Gecko/20100101 Firefox/119.0";

/// Old JSON control text: text frames are dropped, so this must not reach
/// logind.
const RESIZE_JSON: &str = r#"{"type":"resize","cols":90,"rows":25}"#;

#[tokio::test]
async fn passes_binary_data_verbatim() {
    let dir = temp_dir("verbatim");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    let (mut ws, response) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("x-bbs-client-ip", "203.0.113.7:1234"),
            ("x-bbs-secure", "0"),
        ],
    ))
    .await
    .unwrap();
    // A client that offers no subprotocol is served without one, so there is
    // nothing to echo back.
    assert!(!response.headers().contains_key(SEC_WEBSOCKET_PROTOCOL));
    ws.next().await.expect("no output").expect("read failed");
    // Bytes go out to `logind` as they are, with no telnet framing around
    // them, and what `logind` echoes back comes in as it is.
    ws.send(Message::binary(b"pwd\r".to_vec()))
        .await
        .expect("cannot send");
    assert_eq!(collect(&mut ws, b"pwd\r").await, b"pwd\r");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (_, echoed) = logind.await.expect("logind did not finish");
    assert!(echoed.windows(4).any(|w| w == b"pwd\r"));

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn serves_the_telnet_subprotocol() {
    let dir = temp_dir("telnet");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    // What `new WebSocket(url, "telnet")` asks for.
    let (mut ws, response) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("sec-websocket-protocol", "telnet"),
            ("x-bbs-client-ip", "203.0.113.7:1234"),
            ("x-bbs-secure", "0"),
        ],
    ))
    .await
    .expect("handshake failed");
    assert_eq!(response.status(), 101);
    assert_eq!(response.headers()[SEC_WEBSOCKET_PROTOCOL], "telnet");

    ws.next().await.expect("no output").expect("read failed");
    // A message carries a chunk of the raw telnet byte stream, and it is
    // handed over as it is: the bytes go out to `logind` as they are, and the
    // stream it echoes back comes back in binary frames.
    ws.send(Message::binary(b"pwd\r".to_vec()))
        .await
        .expect("cannot send");
    assert_eq!(collect(&mut ws, b"pwd\r").await, b"pwd\r");

    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, echoed) = logind.await.expect("logind did not finish");
    // The telnet byte stream is reported to logind untranscoded, and the
    // client's bytes reach logind as they are.
    assert_eq!(&header[4..8], &logind::ConnData::CONV_NORMAL.to_le_bytes());
    assert!(echoed.windows(4).any(|w| w == b"pwd\r"));

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn rejects_a_bad_handshake() {
    let dir = temp_dir("reject");
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, peer) = listener.accept().await.unwrap();
            ws::serve_one(
                Stream::Tcp(stream),
                peer,
                lport,
                Arc::new(sock.clone()),
                params("/bbs"),
            )
            .await;
        }
    });

    // A path we do not serve, e.g. a load balancer health check.
    let err = connect_async(request(&format!("ws://127.0.0.1:{lport}/health"), &[]))
        .await
        .expect_err("path should be rejected");
    assert_rejected(&err, 404, "no such path");

    // A subprotocol other than `telnet`, turned down before the upgrade.
    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("sec-websocket-protocol", "nope")],
    ))
    .await
    .expect_err("protocol should be rejected");
    assert_rejected(&err, 400, "unknown protocol nope; use telnet");

    // Offers of nothing but other subprotocols name the first of them.
    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("sec-websocket-protocol", "bbs, bbsu")],
    ))
    .await
    .expect_err("offers should be rejected");
    assert_rejected(&err, 400, "unknown protocol bbs; use telnet");

    server.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn serves_a_unix_socket() {
    let dir = temp_dir("unix");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    // A reverse proxy is expected to reach the server over this socket file.
    let path = dir.join("wsd.sock");
    let listener = unix_listener(&path);
    let server = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Unix(stream),
            NO_PEER,
            0,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let (mut ws, response) = client_async(
        request(
            "ws://localhost/bbs",
            &[
                ("sec-websocket-protocol", "telnet"),
                ("x-bbs-client-ip", "203.0.113.7:1234"),
                ("x-bbs-secure", "1"),
            ],
        ),
        conn,
    )
    .await
    .expect("handshake failed");
    assert_eq!(response.status(), 101);
    assert_eq!(response.headers()[SEC_WEBSOCKET_PROTOCOL], "telnet");

    match ws.next().await.expect("no output").expect("read failed") {
        Message::Binary(data) => assert_eq!(data.as_ref(), b"screen output\r\n"),
        other => panic!("unexpected frame {other:?}"),
    }
    ws.send(Message::binary(b"ls\r".to_vec()))
        .await
        .expect("cannot send");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, echoed) = logind.await.expect("logind did not finish");

    // The client comes from the header: a unix peer has no address and this
    // listener has no port.
    assert_eq!(&header[12..16], &[203, 0, 113, 7]);
    assert_eq!(&header[28..30], &1234u16.to_le_bytes());
    assert_eq!(&header[30..32], &0u16.to_le_bytes());
    // A WebSocket login, flagged as secure by `x-bbs-secure`.
    assert_eq!(
        &header[32..36],
        &(logind::ConnData::CONN_FLAG_WEBSOCKET | logind::ConnData::CONN_FLAG_SECURE).to_le_bytes()
    );
    assert!(echoed.windows(3).any(|w| w == b"ls\r"));

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn rejects_a_unix_client_that_names_no_ip_port() {
    // A unix connection has no peer address of its own, so a request whose
    // client address header names no `ip:port` is answered 500: no header at
    // all, a header that names no address, and a bare address.
    let dir = temp_dir("unix-noaddr");
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let path = dir.join("wsd.sock");
    let listener = unix_listener(&path);
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _peer) = listener.accept().await.unwrap();
            ws::serve_one(
                Stream::Unix(stream),
                NO_PEER,
                0,
                Arc::new(sock.clone()),
                params("/bbs"),
            )
            .await;
        }
    });

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(request("ws://localhost/bbs", &[]), conn)
        .await
        .expect_err("a unix client has to be named");
    assert_rejected(&err, 500, "x-bbs-client-ip is missing");

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(
        request("ws://localhost/bbs", &[("x-bbs-client-ip", "unknown")]),
        conn,
    )
    .await
    .expect_err("a unix client has to be named");
    assert_rejected(&err, 500, "x-bbs-client-ip names no ip:port");

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(
        request("ws://localhost/bbs", &[("x-bbs-client-ip", "192.0.2.1")]),
        conn,
    )
    .await
    .expect_err("a client address needs a port of its own");
    assert_rejected(&err, 500, "x-bbs-client-ip names no ip:port");

    server.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn rejects_a_client_the_header_names_no_address() {
    // The header names the client and nothing else does, so a connection it
    // names no client in is refused: a TCP request with no header of that name
    // goes unserved, whatever its peer address, and a unix connection with the
    // header disabled has no peer address of its own to name the client by.
    let dir = temp_dir("noaddr");
    let logind = Arc::new(dir.join("logind.sock"));
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let tcp = tokio::spawn({
        let logind = logind.clone();
        async move {
            let (stream, peer) = listener.accept().await.unwrap();
            ws::serve_one(Stream::Tcp(stream), peer, lport, logind, params("/bbs")).await;
        }
    });

    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("x-real-ip", "203.0.113.7")],
    ))
    .await
    .expect_err("the header has to name the client");
    assert_rejected(&err, 500, "x-bbs-client-ip is missing");

    let path = dir.join("wsd.sock");
    let listener = unix_listener(&path);
    let unix = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Unix(stream),
            NO_PEER,
            0,
            logind,
            params_plain("/bbs"),
        )
        .await;
    });

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(request("ws://localhost/bbs", &[]), conn)
        .await
        .expect_err("a disabled header names no unix client");
    assert_rejected(&err, 500, ws::NO_IP_HEADER);

    tcp.await.unwrap();
    unix.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn serves_a_tcp_client_by_its_peer_when_the_header_is_disabled() {
    let dir = temp_dir("peer");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params_with("/bbs", None, Some("x-bbs-secure")),
        )
        .await;
        peer
    });

    // A TCP peer names its own client once the header is disabled, and the
    // secure header says the session came in over TLS.
    let (mut ws, response) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("x-forwarded-for", "203.0.113.7"), ("x-bbs-secure", "1")],
    ))
    .await
    .expect("a tcp peer names its own client");
    assert_eq!(response.status(), 101);
    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    let peer = server.await.unwrap();
    let (header, _) = logind.await.expect("logind did not finish");

    // With the header disabled no header is read for a client, not even a
    // proxy header, so logind is told the peer address of the connection.
    let IpAddr::V4(ip) = peer.ip() else {
        panic!("a loopback peer is an IPv4 address")
    };
    assert_eq!(&header[12..16], &ip.octets());
    assert_eq!(&header[28..30], &peer.port().to_le_bytes());
    assert_eq!(
        &header[32..36],
        &(logind::ConnData::CONN_FLAG_WEBSOCKET | logind::ConnData::CONN_FLAG_SECURE).to_le_bytes()
    );

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn serves_a_unix_socket_over_an_abstract_name() {
    let dir = temp_dir("abstract");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    // An abstract name has no socket file, so nothing in `dir` is the server.
    let path = abstract_name("abstract");
    let listener = unix_listener(&path);
    let server = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Unix(stream),
            NO_PEER,
            0,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    let conn = UnixStream::connect(&path)
        .await
        .expect("cannot connect an abstract name");
    let (mut ws, response) = client_async(
        request(
            "ws://localhost/bbs",
            &[("x-bbs-client-ip", "192.0.2.1:4321"), ("x-bbs-secure", "0")],
        ),
        conn,
    )
    .await
    .expect("handshake failed");
    assert_eq!(response.status(), 101);

    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, _) = logind.await.expect("logind did not finish");

    // The header names the client and its port, and the unix listener has no
    // port of its own to report.
    assert_eq!(&header[12..16], &[192, 0, 2, 1]);
    assert_eq!(&header[28..30], &4321u16.to_le_bytes());
    assert_eq!(&header[30..32], &0u16.to_le_bytes());

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn rejects_a_unix_handshake() {
    let dir = temp_dir("unix-reject");
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let path = dir.join("wsd.sock");
    let listener = unix_listener(&path);
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _peer) = listener.accept().await.unwrap();
            ws::serve_one(
                Stream::Unix(stream),
                NO_PEER,
                0,
                Arc::new(sock.clone()),
                params("/bbs"),
            )
            .await;
        }
    });

    // Closing a unix socket drops the answer on its way to the client, so the
    // session has to stop sending only once the client has read it.
    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(request("ws://localhost/health", &[]), conn)
        .await
        .expect_err("path should be rejected");
    assert_rejected(&err, 404, "no such path");

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(
        request("ws://localhost/bbs", &[("sec-websocket-protocol", "nope")]),
        conn,
    )
    .await
    .expect_err("protocol should be rejected");
    assert_rejected(&err, 400, "unknown protocol nope; use telnet");

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let err = client_async(
        request(
            "ws://localhost/bbs",
            &[("sec-websocket-protocol", "bbs, bbsu")],
        ),
        conn,
    )
    .await
    .expect_err("offers should be rejected");
    assert_rejected(&err, 400, "unknown protocol bbs; use telnet");

    server.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn ends_a_session_when_the_client_vanishes() {
    let dir = temp_dir("vanish");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let path = dir.join("wsd.sock");
    let listener = unix_listener(&path);
    let server = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Unix(stream),
            NO_PEER,
            0,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    let conn = UnixStream::connect(&path).await.expect("cannot connect");
    let (mut ws, _) = client_async(
        request(
            "ws://localhost/bbs",
            &[
                ("x-bbs-client-ip", "203.0.113.7:1234"),
                ("x-bbs-secure", "0"),
            ],
        ),
        conn,
    )
    .await
    .expect("handshake failed");
    ws.next().await.expect("no output").expect("read failed");

    // A client that goes away without closing its side leaves nothing to read,
    // so the session ends at once instead of waiting out the closing handshake.
    drop(ws);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the session should end once the client is gone")
        .expect("the server task failed");
    let (header, _) = logind.await.expect("logind did not finish");
    assert_eq!(&header[12..16], &[203, 0, 113, 7]);
    assert_eq!(&header[28..30], &1234u16.to_le_bytes());

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

fn assert_rejected(err: &WsError, code: u16, reason: &str) {
    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), code);
            // The whole answer has to reach the client, not just its head.
            assert_eq!(response.body().as_deref(), Some(reason.as_bytes()));
            // A rejection names the daemon as well.
            assert_eq!(response.headers()[SERVER], ws::DAEMON);
        }
        other => panic!("expected an HTTP {code} rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_client_that_names_no_secure_flag() {
    // The secure header has to say `1` for a session over TLS, or `0` for a
    // plain one, so a request with no header of that name, and one that names
    // anything else, is refused.
    let dir = temp_dir("nosecure");
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            ws::serve_one(
                Stream::Tcp(stream),
                peer,
                lport,
                Arc::new(sock.clone()),
                params("/bbs"),
            )
            .await;
        }
    });

    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("x-bbs-client-ip", "203.0.113.7:1234")],
    ))
    .await
    .expect_err("the secure header has to say 0 or 1");
    assert_rejected(&err, 500, "x-bbs-secure is missing");

    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("x-bbs-client-ip", "203.0.113.7:1234"),
            ("x-bbs-secure", "yes"),
        ],
    ))
    .await
    .expect_err("`yes` is no 0 or 1");
    assert_rejected(&err, 500, "x-bbs-secure names yes, not 0 or 1");

    server.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn ignores_query_strings() {
    let dir = temp_dir("query");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params_plain("/bbs"),
        )
        .await;
    });

    // A query string is just part of the path we match; nothing is read out of
    // it, so these leftovers from the old client protocol change nothing.
    let (mut ws, response) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs?user=bbsu&cols=100&rows=30&ip=203.0.113.7"),
        &[("x-bbs-client-ip", "192.0.2.1")],
    ))
    .await
    .unwrap();
    assert!(!response.headers().contains_key(SEC_WEBSOCKET_PROTOCOL));
    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, echoed) = logind.await.expect("logind did not finish");

    // Both headers are disabled, so the peer address names the client, nothing
    // says the session is secure, and the encoding is the default one.
    assert_eq!(u32::from_le_bytes(header[4..8].try_into().unwrap()), 0);
    assert_eq!(&header[12..16], &[127, 0, 0, 1]);
    assert_eq!(&header[30..32], &lport.to_le_bytes());
    // A WebSocket login, with the secure header disabled, so nothing makes it
    // secure.
    assert_eq!(
        &header[32..36],
        &logind::ConnData::CONN_FLAG_WEBSOCKET.to_le_bytes()
    );
    // A client that names no `User-Agent` is no client code.
    assert_eq!(&header[36..40], &0u32.to_le_bytes());
    assert!(!has_naws(&echoed), "unexpected NAWS in {echoed:?}");

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn honours_the_configured_header() {
    let dir = temp_dir("headers");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params_ip_only("/bbs", "client-ip"),
        )
        .await;
    });

    // Only the configured header is honored, and an address that carries a
    // port of its own is the client as it stands.
    let (mut ws, _) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("x-forwarded-for", "203.0.113.7"),
            ("client-ip", "192.0.2.1:4321"),
            ("x-columns", "132"),
        ],
    ))
    .await
    .unwrap();
    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, echoed) = logind.await.expect("logind did not finish");
    assert_eq!(&header[12..16], &[192, 0, 2, 1]);
    assert_eq!(&header[28..30], &4321u16.to_le_bytes());
    // Nothing about the window size reaches logind, whatever the client sends.
    assert!(!has_naws(&echoed), "unexpected NAWS in {echoed:?}");

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn takes_the_first_address_of_a_list() {
    let dir = temp_dir("ip-order");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    // In a chain of addresses the leftmost one is the client, and an address
    // that names a port of its own is taken whole, so the port of the
    // connection goes unread.
    let (mut ws, _) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("x-bbs-client-ip", "203.0.113.7:1234, 192.0.2.1"),
            ("x-bbs-secure", "0"),
        ],
    ))
    .await
    .unwrap();
    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, _) = logind.await.expect("logind did not finish");
    assert_eq!(&header[12..16], &[203, 0, 113, 7]);
    assert_eq!(&header[28..30], &1234u16.to_le_bytes());
    assert_eq!(&header[30..32], &lport.to_le_bytes());

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn rejects_a_tcp_client_that_names_a_bare_address() {
    let dir = temp_dir("ip-port");
    let sock = dir.join("logind.sock");
    let _listener = UnixListener::bind(&sock).expect("cannot bind the logind socket");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            ws::serve_one(
                Stream::Tcp(stream),
                peer,
                lport,
                Arc::new(sock.clone()),
                params("/bbs"),
            )
            .await;
        }
    });

    // A client address is an `ip:port`, so a bare address names no client, not
    // even with the port of the TCP connection it came in on to go with it.
    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("x-bbs-client-ip", "203.0.113.7")],
    ))
    .await
    .expect_err("a client address needs a port of its own");
    assert_rejected(&err, 500, "x-bbs-client-ip names no ip:port");

    let err = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[("x-bbs-client-ip", "203.0.113.7, 192.0.2.1")],
    ))
    .await
    .expect_err("no address of the chain has a port");
    assert_rejected(&err, 500, "x-bbs-client-ip names no ip:port");

    server.await.unwrap();
    drop(_listener);
    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}

#[tokio::test]
async fn passes_over_a_value_that_is_no_ip_port() {
    let dir = temp_dir("ip-plain");
    let sock = dir.join("logind.sock");
    let logind = tokio::spawn(fake_logind(sock.clone()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lport = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        ws::serve_one(
            Stream::Tcp(stream),
            peer,
            lport,
            Arc::new(sock),
            params("/bbs"),
        )
        .await;
    });

    // A value that names no `ip:port` is passed over for the next value of the
    // header, which names the client with a port of its own.
    let (mut ws, _) = connect_async(request(
        &format!("ws://127.0.0.1:{lport}/bbs"),
        &[
            ("x-bbs-client-ip", "unknown, 192.0.2.1:4321"),
            ("x-bbs-secure", "0"),
        ],
    ))
    .await
    .unwrap();
    ws.next().await.expect("no output").expect("read failed");
    ws.send(Message::Close(None)).await.expect("cannot close");
    drain(&mut ws).await;
    server.await.unwrap();
    let (header, _) = logind.await.expect("logind did not finish");
    assert_eq!(&header[12..16], &[192, 0, 2, 1]);
    assert_eq!(&header[28..30], &4321u16.to_le_bytes());
    assert_eq!(&header[30..32], &lport.to_le_bytes());

    std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
}
