use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Duration;

use socket2::Socket;

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: Duration,
    send_interval: Duration,
) -> std::io::Result<()> {
    let raw_fd = tcp_stream.as_raw_fd();
    let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
    if idle_time.is_zero() && send_interval.is_zero() {
        socket2_socket.set_keepalive(false)?;
    } else {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(idle_time)
            .with_interval(send_interval);
        socket2_socket.set_keepalive(true)?;
        socket2_socket.set_tcp_keepalive(&keepalive)?;
    }
    Ok(())
}
