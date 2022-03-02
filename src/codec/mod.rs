use std::hash::BuildHasherDefault;
use std::sync::Arc;

use aes::cipher::StreamCipher;
use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use everscale_crypto::ed25519;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use tl_proto::*;

use crate::channel::*;
use crate::node_id::*;
use crate::peer::*;
use crate::{net, proto};

pub struct CodecState {
    pub options: CodecOptions,
    /// Initialization timestamp
    pub reinit_date: u32,
    /// Maps local keys to remote peers
    pub connections: RwLock<FxHashMap<NodeId, ConnectionsEntry>>,
    /// Channels between local and remote peers
    pub channels_by_id: FxDashMap<ChannelId, Arc<Channel>>,
}

impl CodecState {
    pub fn get_peer(&self, local_id: &NodeId, peer_id: &NodeId) -> Result<Arc<Peer>, CodecError> {
        let connections = self.connections.read();

        let entry = connections
            .get(local_id)
            .ok_or(CodecError::LocalPeerNotFound)?;

        let entry = entry.peers.get(peer_id).ok_or(CodecError::PeerNotFound)?;

        Ok(entry.value().clone())
    }

    pub fn update_peer(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
        public_key: &ed25519::PublicKey,
        address: net::Address,
    ) -> Result<Arc<Peer>, CodecError> {
        use dashmap::mapref::entry::Entry;

        let connections = self.connections.read();

        let entry = connections
            .get(local_id)
            .ok_or(CodecError::LocalPeerNotFound)?;

        let peer = match entry.peers.entry(*peer_id) {
            Entry::Occupied(entry) => {
                let peer = entry.get().clone();

                // Drop entry lock before address update to prevent locks overlap
                drop(entry);

                peer.set_address(address);
                peer
            }
            Entry::Vacant(entry) => entry
                .insert(Arc::new(Peer::new(address, *public_key, self.reinit_date)))
                .clone(),
        };

        Ok(peer)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CodecOptions {
    pub clock_tolerance_sec: u32,
}

impl Default for CodecOptions {
    fn default() -> Self {
        Self {
            clock_tolerance_sec: 60,
        }
    }
}

pub struct ConnectionsEntry {
    /// Local key
    pub key: ed25519::KeyPair,
    /// Remote peers
    pub peers: FxDashMap<NodeId, Arc<Peer>>,
    /// Peer channels
    pub channels_by_peers: FxDashMap<NodeId, Arc<Channel>>,
}

#[derive(Copy, Clone)]
struct PacketToSend<'a> {
    contents: &'a proto::OutgoingPacketContents<'a>,
    encoder: PacketEncoder<'a>,
}

// impl<'a> Encoder<PacketToSend<'a>> for Codec {
//     fn encode(&mut self, item: PacketToSend<'a>, dst: &mut BytesMut) {
//         match item.encoder {
//             PacketEncoder::Handshake(handshake) => handshake.encode(item.contents, dst),
//             PacketEncoder::Channel(channel) => channel.encoder(item.contents, dst),
//         }
//     }
// }

// impl net::Decoder for Codec {
//     type Item = DecodedPacket;
//     type Error = CodecError;
//
//     fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, CodecError> {
//         match HandshakeDecoder(&self.keys).decode(src)? {
//             Some(packet) => Ok(packet),
//             None => ChannelDecoder(&self.channels_by_id).decode(src),
//         }
//     }
// }

pub struct DecodedPacket {
    pub data: Bytes,
    pub local_id: NodeId,
    pub peer_id: Option<NodeId>,
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
        let temp_secret_key = ed25519::SecretKey::generate(&mut rand::thread_rng()).expand();
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
    pub fn decode(self, buffer: &mut BytesMut) -> Result<Option<DecodedPacket>, HandshakeError> {
        if buffer.len() < 96 {
            return Err(HandshakeError::PacketTooSmall);
        }

        let target_id = &buffer[..32];
        let temp_public_key =
            match ed25519::PublicKey::from_bytes(buffer[32..64].try_into().unwrap()) {
                Some(public_key) => public_key,
                None => return Err(HandshakeError::InvalidPublicKey),
            };

        for (local_id, key) in self.0 {
            if local_id == target_id {
                let shared_secret = key.secret_key.compute_shared_secret(&temp_public_key);

                let checksum: [u8; 32] = buffer[64..96].try_into().unwrap();
                build_packet_cipher(&shared_secret, &checksum).apply_keystream(&mut buffer[96..]);

                if !sha2::Sha256::digest(&buffer[96..]).as_slice().eq(&checksum) {
                    return Err(HandshakeError::InvalidChecksum);
                }

                buffer.advance(96);

                return Ok(Some(DecodedPacket {
                    data: buffer.split().freeze(),
                    local_id: *local_id,
                    peer_id: None,
                }));
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
pub struct ChannelDecoder<'a>(&'a FxHashMap<ChannelId, Arc<Channel>>);

impl<'a> ChannelDecoder<'a> {
    pub fn decode(self, buffer: &mut BytesMut) -> Result<DecodedPacket, ChannelError> {
        if buffer.len() < 64 {
            return Err(ChannelError::PacketTooSmall);
        }

        let channel_id = &buffer[..32];
        let channel = self
            .0
            .get(channel_id)
            .ok_or(ChannelError::ChannelNotFound)?
            .as_ref();

        let checksum: [u8; 32] = buffer[32..64].try_into().unwrap();
        let data = &mut buffer[64..];

        build_packet_cipher(&channel.incoming().secret, &checksum).apply_keystream(data);

        if sha2::Sha256::digest(data).as_slice() != checksum {
            return Err(ChannelError::InvalidChecksum);
        }

        buffer.advance(64);

        channel.set_ready();
        channel.reset_drop_timeout();

        Ok(DecodedPacket {
            data: buffer.split().freeze(),
            local_id: *channel.local_id(),
            peer_id: Some(*channel.peer_id()),
        })
    }
}

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

fn build_packet_cipher(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> Aes256Ctr {
    use aes::cipher::KeyIvInit;

    let mut aes_key_bytes: [u8; 32] = *shared_secret;
    aes_key_bytes[16..32].copy_from_slice(&checksum[16..32]);
    let mut aes_ctr_bytes: [u8; 16] = checksum[..16].try_into().unwrap();
    aes_ctr_bytes[4..16].copy_from_slice(&shared_secret[20..32]);

    Aes256Ctr::new(
        &generic_array::GenericArray::from(aes_key_bytes),
        &generic_array::GenericArray::from(aes_ctr_bytes),
    )
}

#[derive(Default)]
struct PacketHasher {
    len: usize,
    h: Sha256,
}

impl PacketHasher {
    #[inline(always)]
    fn hash<T: TlWrite>(packet: &T) -> ([u8; 32], usize) {
        let mut hasher = Self::default();
        packet.write_to(&mut hasher);
        (hasher.h.finalize().into(), hasher.len)
    }
}

impl TlPacket for PacketHasher {
    const TARGET: TlTarget = TlTarget::Hasher;

    #[inline(always)]
    fn write_u32(&mut self, data: u32) {
        self.len += 4;
        self.h.update(&data.to_le_bytes());
    }

    #[inline(always)]
    fn write_i32(&mut self, data: i32) {
        self.len += 4;
        self.h.update(&data.to_le_bytes());
    }

    #[inline(always)]
    fn write_u64(&mut self, data: u64) {
        self.len += 8;
        self.h.update(&data.to_le_bytes());
    }

    #[inline(always)]
    fn write_i64(&mut self, data: i64) {
        self.len += 8;
        self.h.update(&data.to_le_bytes());
    }

    #[inline(always)]
    fn write_raw_slice(&mut self, data: &[u8]) {
        self.len += data.len();
        self.h.update(data);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    #[error("invalid handshake packet")]
    InvalidHandshakePacket(#[from] HandshakeError),
    #[error("invalid channel packet")]
    InvalidChannelPacket(#[from] ChannelError),
    #[error("local peer not found")]
    LocalPeerNotFound,
    #[error("peer not found")]
    PeerNotFound,
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

type FxDashMap<K, V> = DashMap<K, V, BuildHasherDefault<rustc_hash::FxHasher>>;
