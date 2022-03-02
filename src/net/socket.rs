use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::net::UdpSocket;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SocketBuilder {
    V4,
    V6,
}

impl SocketBuilder {
    pub fn build(self, port: u16) -> Result<UdpSocket, SocketBuilderError> {
        let addr = match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };

        let udp_socket =
            std::net::UdpSocket::bind((addr, port)).map_err(SocketBuilderError::BindFailed)?;

        udp_socket
            .set_nonblocking(true)
            .map_err(SocketBuilderError::ConfigurationFailed)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;

            let fd = udp_socket.as_raw_fd();
            maximise_recv_buffer(fd)?;
            set_reuse_port(fd, true)?;
        }

        UdpSocket::from_std(udp_socket).map_err(SocketBuilderError::InvalidSocket)
    }
}

impl From<SocketBuilder> for IpAddr {
    fn from(ty: SocketBuilder) -> Self {
        match ty {
            SocketBuilder::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketBuilder::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

#[cfg(unix)]
fn set_reuse_port(socket: libc::c_int, reuse: bool) -> Result<(), SocketBuilderError> {
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
fn maximise_recv_buffer(socket: libc::c_int) -> Result<(), SocketBuilderError> {
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
) -> Result<T, SocketBuilderError>
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
) -> Result<(), SocketBuilderError>
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
fn cvt(res: libc::c_int) -> Result<(), SocketBuilderError> {
    if res == -1 {
        Err(SocketBuilderError::ConfigurationFailed(
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SocketBuilderError {
    #[error("failed to bind UDP port")]
    BindFailed(#[source] std::io::Error),
    #[error("failed to configure udp socket")]
    ConfigurationFailed(#[source] std::io::Error),
    #[error("failed to convert std::net::UdpSocket to tokio::net::UdpSocket")]
    InvalidSocket(#[source] std::io::Error),
}
