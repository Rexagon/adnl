use aes::cipher::StreamCipher;
use bytes::{Buf, Bytes, BytesMut};
use rustc_hash::FxHashMap;
use sha2::Digest;
use tl_proto::*;

use crate::channel::*;
use crate::keys::*;
use crate::proto;
use crate::utils::*;

pub use self::address::*;

pub mod address;
pub mod framed;
pub mod socket;

pub struct Codec {
    keys: FxHashMap<NodeId, ed25519::KeyPair>,
    channels: FxHashMap<ChannelId, Channel>,
}

#[derive(Copy, Clone)]
struct PacketToSend<'a> {
    contents: &'a proto::PacketContents<'a>,
    encoder: PacketEncoder<'a>,
}

impl<'a> framed::Encoder<PacketToSend<'a>> for Codec {
    fn encode(&mut self, item: PacketToSend<'a>, dst: &mut BytesMut) {
        match item.encoder {
            PacketEncoder::Handshake(handshake) => handshake.encode(item.contents, dst),
            PacketEncoder::Channel(channel) => channel.encoder(item.contents, dst),
        }
    }
}

impl framed::Decoder for Codec {
    type Item = Bytes;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, CodecError> {
        let (local_id, peer_id) = match HandshakeDecoder(&self.keys).decode(src)? {
            Some(local_id) => (local_id, None),
            None => {
                let channel = ChannelDecoder(&self.channels).decode(src)?;
                channel.set_ready();
                channel.reset_drop_timeout();
                (channel.local_id(), Some(channel.peer_id()))
            }
        };

        todo!()
    }
}

#[derive(Copy, Clone)]
pub enum PacketEncoder<'a> {
    Handshake(HandshakeEncoder<'a>),
    Channel(ChannelEncoder<'a>),
}

#[derive(Copy, Clone)]
pub struct HandshakeEncoder<'a> {
    peer_id_short: &'a NodeId,
    peer_public_key: &'a ed25519::PublicKey,
}

impl HandshakeEncoder<'_> {
    pub fn encode<T: TlWrite>(self, packet: &T, buffer: &mut BytesMut) {
        let temp_secret_key = ed25519::SecretKey::generate().expand();
        let temp_public_key = ed25519::PublicKey::from(&temp_secret_key);
        let shared_secret = temp_secret_key.compute_shared_secret(self.peer_public_key);

        let (checksum, len) = PacketHasher::hash(packet);

        buffer.reserve(len + 96);
        buffer.extend_from_slice(self.peer_id_short.as_bytes());
        buffer.extend_from_slice(temp_public_key.as_bytes());
        buffer.extend_from_slice(&checksum);
        packet.write_to(buffer);

        build_packet_cipher(&shared_secret, &checksum).apply_keystream(&mut buffer[96..]);
    }
}

#[derive(Copy, Clone)]
pub struct HandshakeDecoder<'a>(&'a FxHashMap<NodeId, ed25519::KeyPair>);

impl<'a> HandshakeDecoder<'a> {
    pub fn decode(self, buffer: &mut BytesMut) -> Result<Option<&'a NodeId>, HandshakeError> {
        if buffer.len() < 96 {
            return Err(HandshakeError::PacketTooSmall);
        }

        let peer_id_short = &buffer[..32];
        let temp_public_key =
            match ed25519::PublicKey::from_bytes(buffer[32..64].try_into().unwrap()) {
                Some(public_key) => public_key,
                None => return Err(HandshakeError::InvalidPublicKey),
            };

        for (local_peer_id_short, key) in self.0 {
            if local_peer_id_short == peer_id_short {
                let shared_secret = key.secret_key.compute_shared_secret(&temp_public_key);

                let checksum: [u8; 32] = buffer[64..96].try_into().unwrap();
                build_packet_cipher(&shared_secret, &checksum).apply_keystream(&mut buffer[96..]);

                if !sha2::Sha256::digest(&buffer[96..]).as_slice().eq(&checksum) {
                    return Err(HandshakeError::InvalidChecksum);
                }

                buffer.advance(96);
                return Ok(Some(local_peer_id_short));
            }
        }

        Ok(None)
    }
}

#[derive(Copy, Clone)]
pub struct ChannelEncoder<'a>(&'a Channel);

impl ChannelEncoder<'_> {
    pub fn encoder<T: TlWrite>(self, packet: &T, buffer: &mut BytesMut) {
        let (checksum, len) = PacketHasher::hash(packet);

        buffer.reserve(len + 64);
        buffer.extend_from_slice(&self.0.outgoing().id);
        buffer.extend_from_slice(&checksum);
        packet.write_to(buffer);

        build_packet_cipher(&self.0.outgoing().secret, &checksum)
            .apply_keystream(&mut buffer[64..]);
    }
}

#[derive(Copy, Clone)]
pub struct ChannelDecoder<'a>(&'a FxHashMap<ChannelId, Channel>);

impl<'a> ChannelDecoder<'a> {
    pub fn decode(self, buffer: &mut BytesMut) -> Result<&'a Channel, ChannelError> {
        if buffer.len() < 64 {
            return Err(ChannelError::PacketTooSmall);
        }

        let channel_id = &buffer[..32];
        let channel = self
            .0
            .get(channel_id)
            .ok_or(ChannelError::ChannelNotFound)?;

        let checksum: [u8; 32] = buffer[32..64].try_into().unwrap();
        let data = &mut buffer[64..];

        build_packet_cipher(&channel.incoming().secret, &checksum).apply_keystream(data);

        if sha2::Sha256::digest(data).as_slice() != checksum {
            return Err(ChannelError::InvalidChecksum);
        }

        buffer.advance(64);
        Ok(channel)
    }
}

fn build_packet_cipher(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> aes::Aes256Ctr {
    use aes::cipher::NewCipher;

    let mut aes_key_bytes: [u8; 32] = *shared_secret;
    aes_key_bytes[16..32].copy_from_slice(&checksum[16..32]);
    let mut aes_ctr_bytes: [u8; 16] = checksum[..16].try_into().unwrap();
    aes_ctr_bytes[4..16].copy_from_slice(&shared_secret[20..32]);

    aes::Aes256Ctr::new(
        &generic_array::GenericArray::from(aes_key_bytes),
        &generic_array::GenericArray::from(aes_ctr_bytes),
    )
}

#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    #[error("invalid handshake packet")]
    InvalidHandshakePacket(#[from] HandshakeError),
    #[error("invalid channel packet")]
    InvalidChannelPacket(#[from] ChannelError),
}

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("handshake packet too small")]
    PacketTooSmall,
    #[error("invalid public key in handshake packet")]
    InvalidPublicKey,
    #[error("bad handshake packet checksum")]
    InvalidChecksum,
}

#[derive(thiserror::Error, Debug)]
pub enum ChannelError {
    #[error("channel packet too small")]
    PacketTooSmall,
    #[error("channel not found")]
    ChannelNotFound,
    #[error("bad channel packet checksum")]
    InvalidChecksum,
}
