//! Socket creation and socket options for the daemons.

use libc::c_int;
use socket2::{Domain, SockAddr, Socket, TcpKeepalive, Type};
use std::io::Result;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;

pub fn new_listener(addr: SocketAddr, backlog: i32) -> Result<std::net::TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog as c_int)?;
    Ok(sock.into())
}

/// Bind a stream unix socket at `path`, so a reverse proxy can reach the
/// server over a socket file instead of a TCP port. The file is open to every
/// local user, since the proxy runs as a user of its own.
///
/// A socket file left behind by a dead run is replaced; a path that a live
/// listener answers is reported as `AddrInUse`.
pub fn new_unix_listener(path: &Path, backlog: i32) -> Result<UnixListener> {
    let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    sock.set_nonblocking(true)?;
    bind_unix(&sock, path)?;
    if !is_abstract(path) {
        // A fresh socket file takes the mode the umask of this run leaves.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;
    }
    sock.listen(backlog as c_int)?;
    Ok(sock.into())
}

/// True for an abstract namespace name, which is a leading NUL byte and a name
/// and has no socket file behind it.
fn is_abstract(path: &Path) -> bool {
    path.as_os_str().as_bytes().first() == Some(&0)
}

fn bind_unix(sock: &Socket, path: &Path) -> Result<()> {
    let addr = SockAddr::unix(path)?;
    match sock.bind(&addr) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && !listening_on(path) => {
            if !is_abstract(path) {
                std::fs::remove_file(path)?;
            }
            sock.bind(&addr)
        }
        Err(e) => Err(e),
    }
}

/// True when something is accepting on `path`. A leftover socket file from a
/// dead run refuses the connection. Abstract namespace names start with a NUL
/// byte, which the standard library refuses to connect to, so this asks
/// `socket2`, which understands them.
fn listening_on(path: &Path) -> bool {
    let Ok(addr) = SockAddr::unix(path) else {
        return false;
    };
    let Ok(sock) = Socket::new(Domain::UNIX, Type::STREAM, None) else {
        return false;
    };
    sock.connect(&addr).is_ok()
}

/// TCP options for a client connection: no delays, and a long keepalive.
pub fn set_client_conn_options(stream: TcpStream) -> Result<TcpStream> {
    let sock = Socket::from(stream.into_std()?);
    sock.set_tcp_nodelay(true)?;
    sock.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(600)))?;
    TcpStream::from_std(sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bbs-common-{}-{}-{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("cannot create the temp dir");
        dir
    }

    #[test]
    fn binds_a_unix_socket() {
        let dir = temp_dir("unix-bind");
        let path = dir.join("wsd.sock");

        let listener = new_unix_listener(&path, 10).expect("cannot bind");
        assert!(path.exists());
        // A proxy runs as its own user, so the socket file is open to it.
        assert_eq!(
            path.metadata()
                .expect("cannot read the socket file")
                .permissions()
                .mode()
                & 0o777,
            0o777
        );
        // A client reaches the socket file and is accepted.
        UnixStream::connect(&path).expect("cannot connect");
        listener
            .accept()
            .expect("no client connected")
            .0
            .shutdown(std::net::Shutdown::Write)
            .expect("cannot stop writing");
        // A live listener answers the probe, so rebinding has to fail.
        new_unix_listener(&path, 10).expect_err("the path is in use");

        drop(listener);
        // The file stays behind, and nothing listens on it any more.
        let listener = new_unix_listener(&path, 10).expect("cannot rebind over a stale file");
        drop(listener);
        std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
    }

    #[test]
    fn binds_an_abstract_socket() {
        // An abstract namespace name is a NUL byte and a name: it has no socket
        // file, so only socket2 can talk to it.
        let path = PathBuf::from(format!("\0bbs-wsd-test-{}", std::process::id()));
        assert!(is_abstract(&path));
        let sock = Socket::new(Domain::UNIX, Type::STREAM, None).expect("cannot open a socket");
        sock.set_nonblocking(true)
            .expect("cannot make the socket nonblocking");
        bind_unix(&sock, &path).expect("cannot bind an abstract socket");
        sock.listen(10).expect("cannot listen");
        assert_eq!(
            sock.local_addr()
                .expect("cannot read the address")
                .as_abstract_namespace(),
            // The bytes start after the leading NUL byte.
            Some(&path.as_os_str().as_bytes()[1..])
        );

        let addr = SockAddr::unix(&path).expect("cannot name an abstract socket");
        Socket::new(Domain::UNIX, Type::STREAM, None)
            .expect("cannot open a socket")
            .connect(&addr)
            .expect("cannot connect an abstract socket");

        // A live listener answers the name, so a second bind reports the
        // conflict instead of removing a file that is not there.
        assert!(listening_on(&path));
        let again = Socket::new(Domain::UNIX, Type::STREAM, None).expect("cannot open a socket");
        assert_eq!(
            bind_unix(&again, &path)
                .expect_err("an abstract name in use stays in use")
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        assert!(
            std::fs::remove_file(&path)
                .expect_err("an abstract name has no file")
                .kind()
                == std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn rejects_a_path_that_is_too_long() {
        let dir = temp_dir("unix-long");
        let path = dir.join("x".repeat(200));
        std::fs::create_dir_all(&path).expect("cannot make a directory");

        let e = new_unix_listener(&path.join("sock"), 10).expect_err("the path is too long");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(&dir).expect("cannot remove the temp dir");
    }
}
