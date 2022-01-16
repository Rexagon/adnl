use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

pub fn make_udp_socket(port: u16) -> Result<UdpSocket, SocketError> {
    let udp_socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
        .map_err(SocketError::BindFailed)?;
    udp_socket
        .set_nonblocking(true)
        .map_err(SocketError::ConfigurationFailed)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = udp_socket.as_raw_fd();
        maximise_recv_buffer(fd)?;
        set_reuse_port(fd, true)?;
    }

    UdpSocket::from_std(udp_socket).map_err(SocketError::InvalidSocket)
}

#[cfg(unix)]
fn set_reuse_port(socket: libc::c_int, reuse: bool) -> Result<(), SocketError> {
    unsafe {
        setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            reuse as libc::c_int,
        )
    }
}

#[cfg(unix)]
fn maximise_recv_buffer(socket: libc::c_int) -> Result<(), SocketError> {
    const MAX_UDP_RECV_BUFFER_SIZE: usize = 1 << 24;

    unsafe {
        let current_size: libc::c_int = getsockopt(socket, libc::SOL_SOCKET, libc::SO_RCVBUF)?;

        let mut min = current_size;
        let mut max = MAX_UDP_RECV_BUFFER_SIZE as libc::c_int;
        while min <= max {
            let avg = min + (max - min) / 2;
            match setsockopt(socket, libc::SOL_SOCKET, libc::SO_RCVBUF, avg) {
                Ok(_) => {
                    min = avg + 1;
                }
                Err(_) => {
                    max = avg - 1;
                }
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
unsafe fn getsockopt<T>(
    socket: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
) -> Result<T, SocketError>
where
    T: Copy,
{
    let mut slot: T = std::mem::zeroed();
    let mut len = std::mem::size_of::<T>() as libc::socklen_t;
    cvt(libc::getsockopt(
        socket,
        level,
        optname,
        &mut slot as *mut _ as *mut _,
        &mut len,
    ))?;
    debug_assert_eq!(len as usize, std::mem::size_of::<T>());
    Ok(slot)
}

#[cfg(unix)]
unsafe fn setsockopt<T>(
    socket: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: T,
) -> Result<(), SocketError>
where
    T: Copy,
{
    let value = &value as *const T as *const libc::c_void;
    cvt(libc::setsockopt(
        socket,
        level,
        name,
        value,
        std::mem::size_of::<T>() as libc::socklen_t,
    ))?;
    Ok(())
}

#[cfg(unix)]
fn cvt(res: libc::c_int) -> Result<(), SocketError> {
    if res == -1 {
        Err(SocketError::ConfigurationFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SocketError {
    #[error("failed to bind UDP port")]
    BindFailed(#[source] std::io::Error),
    #[error("failed to configure udp socket")]
    ConfigurationFailed(#[source] std::io::Error),
    #[error("failed to convert std::net::UdpSocket to tokio::net::UdpSocket")]
    InvalidSocket(#[source] std::io::Error),
}
