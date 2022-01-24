pub mod channel;
pub mod codec;
pub mod keys;
pub mod net;
pub mod peer;
pub mod proto;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::socket::SocketBuilder;
    use crate::net::UdpFramed;
    use futures::StreamExt;

    #[test]
    fn test_codec() {
        let codec = codec::Codec::default();
        let socket = SocketBuilder::V4.build(30303).unwrap();

        let framed = UdpFramed::new(socket, codec).split();
    }
}
