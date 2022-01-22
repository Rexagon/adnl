use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

pub trait Encoder<Item> {
    fn encode(&mut self, item: Item, dst: &mut BytesMut);
}

pub trait Decoder {
    type Item;
    type Error: std::fmt::Debug;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, Self::Error>;
}

pub struct UdpFramed<C> {
    socket: UdpSocket,
    codec: C,
    rd: BytesMut,
    wr: BytesMut,
    out_addr: SocketAddr,
    flushed: bool,
    is_readable: bool,
}

impl<C> UdpFramed<C> {
    pub fn new(socket: UdpSocket, codec: C) -> Self {
        Self {
            socket,
            codec,
            rd: BytesMut::with_capacity(INITIAL_RD_CAPACITY),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            flushed: true,
            is_readable: false,
        }
    }
}

impl<C> Unpin for UdpFramed<C> {}

impl<C> Stream for UdpFramed<C>
where
    C: Decoder,
{
    type Item = Result<C::Item, NetworkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        pin.rd.reserve(INITIAL_RD_CAPACITY);

        loop {
            if pin.is_readable {
                match pin.codec.decode(&mut pin.rd) {
                    Ok(frame) => return Poll::Ready(Some(Ok(frame))),
                    Err(e) => {
                        log::debug!("got invalid packet: {:?}", e);
                    }
                }

                pin.is_readable = false;
                pin.rd.clear();
            }

            unsafe {
                // Convert `&mut [MaybeUninit<u8>]` to `&mut [u8]` because we will be
                // writing to it via `poll_recv_from` and therefore initializing the memory.
                let buf = &mut *(pin.rd.chunk_mut() as *mut _ as *mut [MaybeUninit<u8>]);

                let mut read = ReadBuf::uninit(buf);
                futures::ready!(pin.socket.poll_recv_from(cx, &mut read))
                    .map_err(NetworkError::PacketReceiveError)?;

                pin.rd.advance_mut(read.filled().len());
            }

            pin.is_readable = true;
        }
    }
}

impl<I, C> Sink<(I, SocketAddr)> for UdpFramed<C>
where
    C: Encoder<I>,
{
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (I, SocketAddr)) -> Result<(), Self::Error> {
        let (frame, out_addr) = item;

        let pin = self.get_mut();

        pin.codec.encode(frame, &mut pin.wr);
        pin.out_addr = out_addr;
        pin.flushed = false;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref socket,
            ref mut out_addr,
            ref mut wr,
            ..
        } = *self;

        let n = futures::ready!(socket.poll_send_to(cx, wr, *out_addr))
            .map_err(NetworkError::PacketSendError)?;

        let wrote_all = n == self.wr.len();
        self.wr.clear();
        self.flushed = true;

        let res = if wrote_all {
            Ok(())
        } else {
            Err(NetworkError::PartialSend)
        };

        Poll::Ready(res)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        futures::ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

const INITIAL_RD_CAPACITY: usize = 64 * 1024;
const INITIAL_WR_CAPACITY: usize = 8 * 1024;

#[derive(thiserror::Error, Debug)]
pub enum NetworkError {
    #[error("failed to write entire datagram to socket")]
    PartialSend,
    #[error("failed to receive datagram")]
    PacketReceiveError(#[source] std::io::Error),
    #[error("failed to send datagram")]
    PacketSendError(#[source] std::io::Error),
}

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
