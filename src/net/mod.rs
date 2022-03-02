use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use tl_proto::TlWrite;
use tokio::net::UdpSocket;

pub use self::address::*;
pub use self::socket::*;

mod address;
mod socket;

pub trait Decoder {
    type Item;
    type Error: std::fmt::Debug;

    fn decode(&self, src: &mut BytesMut) -> Result<Self::Item, Self::Error>;
}

pub struct UdpSender {
    socket: Arc<UdpSocket>,
    rw: BytesMut,
}

impl UdpSender {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            rw: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
        }
    }

    #[inline(always)]
    pub fn acquire_buffer(&mut self) -> UdpSenderBuffer {
        UdpSenderBuffer(&mut self.rw)
    }

    pub async fn flush(&self, to: SocketAddr) -> Result<(), std::io::Error> {
        self.socket.send_to(&self.rw, to).await?;
        Ok(())
    }
}

pub struct UdpSenderBuffer<'a>(&'a mut BytesMut);

impl UdpSenderBuffer<'_> {
    #[inline(always)]
    pub fn write<T: TlWrite>(self, data: T) {
        self.0.clear();
        data.write_to(self.0);
    }
}

pub struct UdpReceiver<C> {
    socket: Arc<UdpSocket>,
    decoder: C,
    rd: BytesMut,
}

impl<C> UdpReceiver<C>
where
    C: Decoder,
{
    pub fn new(socket: Arc<UdpSocket>, decoder: C) -> Self {
        Self {
            socket,
            decoder,
            rd: BytesMut::with_capacity(RECV_BUFFER_CHUNK_SIZE),
        }
    }

    pub async fn recv(&mut self) -> Result<C::Item, std::io::Error> {
        if self.rd.remaining() < RECV_BUFFER_SIZE {
            // Create new bytes instance
            self.rd = BytesMut::with_capacity(RECV_BUFFER_CHUNK_SIZE);
        } else {
            // Clear existing bytes instance
            self.rd.clear();
        }

        loop {
            // SAFETY: Convert `&mut [MaybeUninit<u8>]` to `&mut [u8]` because we will be
            // writing to it via `poll_recv_from` and therefore initializing the memory.
            let mut buf = unsafe {
                &mut *(self.rd.chunk_mut() as *mut _ as *mut [MaybeUninit<u8>] as *mut [u8])
            };
            if buf.len() > RECV_BUFFER_SIZE {
                buf = &mut buf[..RECV_BUFFER_SIZE];
            }

            let len = self.socket.recv(buf).await?;
            if len == 0 {
                continue;
            }

            // SAFETY: `len` bytes were definitely initialized by `recv` method
            unsafe { self.rd.advance_mut(len) };

            if let Ok(item) = self.decoder.decode(&mut self.rd) {
                return Ok(item);
            }
        }
    }
}

const RECV_BUFFER_CHUNK_SIZE: usize = 64 * 1024;
const RECV_BUFFER_SIZE: usize = 2 * 1024;

const INITIAL_WR_CAPACITY: usize = 8 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_prefix_stays_valid() {
        let mut bytes = BytesMut::with_capacity(4);
        bytes.put_u32(0x11223344);

        let prefix = bytes.split_to(2);

        assert_eq!(prefix.as_ref(), &[0x11, 0x22]);
        assert_eq!(bytes.as_ref(), &[0x33, 0x44]);

        bytes.clear();
        bytes.put_u32(0x55667788);

        assert_eq!(prefix.as_ref(), &[0x11, 0x22]);
        assert_eq!(bytes.as_ref(), &[0x55, 0x66, 0x77, 0x88]);
    }
}
