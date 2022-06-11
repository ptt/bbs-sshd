use libc::c_int;
use socket2::{Domain, Socket, TcpKeepalive, Type};
use std::io::Result;
use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::time::Duration;
use tokio::net::TcpStream;

pub fn new_listener(addr: SocketAddr, backlog: i32) -> Result<std::net::TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog as c_int)?;

    let fd = sock.into_raw_fd();
    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

pub fn set_client_conn_options(stream: TcpStream) -> Result<TcpStream> {
    let fd = stream.into_std()?.into_raw_fd();
    let sock = unsafe { Socket::from_raw_fd(fd) };
    sock.set_nodelay(true)?;
    sock.set_tcp_keepalive(&TcpKeepalive::new().with_time(Duration::from_secs(600)))?;
    let fd = sock.into_raw_fd();
    TcpStream::from_std(unsafe { std::net::TcpStream::from_raw_fd(fd) })
}
