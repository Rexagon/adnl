use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::proto;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum AdnlAddress {
    Udp(u32, u16),
    Udp6([u8; 16], u16),
}

impl AdnlAddress {
    #[inline(always)]
    pub fn from_tl(tl: proto::Address<'_>) -> Option<Self> {
        match tl {
            proto::Address::Udp { ip, port } => Some(Self::Udp(ip, port.try_into().ok()?)),
            proto::Address::Udp6 { ip, port } => Some(Self::Udp6(*ip, port.try_into().ok()?)),
            proto::Address::Tunnel { .. } => None,
        }
    }

    #[inline(always)]
    pub fn new(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => {
                let ip = u32::from_be_bytes(addr.ip().octets());
                Self::Udp(ip, addr.port())
            }
            SocketAddr::V6(addr) => Self::Udp6(addr.ip().octets(), addr.port()),
        }
    }

    #[inline(always)]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Udp(ip, _) => IpAddr::V4(From::from(*ip)),
            Self::Udp6(ip, _) => IpAddr::V6(From::from(*ip)),
        }
    }

    #[inline(always)]
    pub fn port(&self) -> u16 {
        match self {
            Self::Udp(_, port) => *port,
            Self::Udp6(_, port) => *port,
        }
    }

    #[inline(always)]
    pub fn as_tl(&'_ self) -> proto::Address<'_> {
        match self {
            &Self::Udp(ip, port) => proto::Address::Udp {
                ip,
                port: port as u32,
            },
            Self::Udp6(ip, port) => proto::Address::Udp6 {
                ip,
                port: *port as u32,
            },
        }
    }
}

impl std::fmt::Display for AdnlAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Udp(ip, port) => f.write_fmt(format_args!(
                "{}.{}.{}.{}:{}",
                (ip >> 24) as u8,
                (ip >> 16) as u8,
                (ip >> 8) as u8,
                *ip as u8,
                port
            )),

            // TODO: optimize
            Self::Udp6(ip, port) => SocketAddrV6::new(From::from(*ip), *port, 0, 0).fmt(f),
        }
    }
}

impl From<SocketAddr> for AdnlAddress {
    #[inline(always)]
    fn from(addr: SocketAddr) -> Self {
        Self::new(addr)
    }
}

impl From<AdnlAddress> for SocketAddr {
    fn from(addr: AdnlAddress) -> Self {
        match addr {
            AdnlAddress::Udp(ip, port) => SocketAddr::V4(SocketAddrV4::new(ip.into(), port)),
            AdnlAddress::Udp6(ip, port) => SocketAddr::V6(SocketAddrV6::new(ip.into(), port, 0, 0)),
        }
    }
}

pub fn parse_address_list(
    now: u32,
    list: proto::AddressList<'_>,
) -> Result<AdnlAddress, AddressListError> {
    let address = list
        .address
        .and_then(AdnlAddress::from_tl)
        .ok_or(AddressListError::ListIsEmpty)?;

    if list.version > now || list.reinit_date > now {
        return Err(AddressListError::TooNewVersion);
    }

    if (1..now).contains(&list.expire_at) {
        return Err(AddressListError::Expired);
    }

    Ok(address)
}

#[derive(thiserror::Error, Debug)]
pub enum AddressListError {
    #[error("address list is empty")]
    ListIsEmpty,
    #[error("address list version is too new")]
    TooNewVersion,
    #[error("address list is expired")]
    Expired,
}
