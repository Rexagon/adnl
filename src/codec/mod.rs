use std::sync::Arc;

use aes::cipher::StreamCipher;
use bytes::{Buf, Bytes, BytesMut};
use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};
use tl_proto::*;

use crate::channel::*;
use crate::keys::*;
use crate::net::address::*;
use crate::net::{Decoder, Encoder};
use crate::peer::*;
use crate::proto;

pub struct CodecOptions {
    pub clock_tolerance_sec: u32,
    pub packet_history_enabled: bool,
}

impl Default for CodecOptions {
    fn default() -> Self {
        Self {
            clock_tolerance_sec: 60,
            packet_history_enabled: false,
        }
    }
}

#[derive(Default)]
pub struct Codec {
    options: CodecOptions,
    keys: FxHashMap<NodeId, ed25519::KeyPair>,
    peers: FxHashMap<NodeId, LocalPeerConnections>,
    channels_by_id: FxHashMap<ChannelId, Arc<Channel>>,
}

impl Codec {
    fn process_packet(
        &mut self,
        now: u32,
        packet: proto::IncomingPacketContents<'_>,
        local_id: &NodeId,
        source: PacketSource,
    ) -> Result<Option<NodeId>, ValidationError> {
        let (from_channel, peer_id) = match (source, packet.from, packet.from_short) {
            // Packet from channel
            (PacketSource::Channel(peer_id), None, None) => (true, peer_id),
            // Invalid packet from channel
            (PacketSource::Channel(_), _, _) => {
                return Err(ValidationError::ExplicitSourceForChannel)
            }
            // Handshake packet with `from` field
            (PacketSource::Handshake, Some(public_key), from_short) => {
                let public_key = ed25519::PublicKey::from_tl(public_key)
                    .ok_or(ValidationError::InvalidPeerPublicKey)?;
                let peer_id = NodeId::from(public_key);

                if matches!(from_short, Some(id) if peer_id.as_bytes() != id) {
                    return Err(ValidationError::PeerIdMismatch);
                }

                if let Some(list) = packet.address {
                    let ip_address = parse_address_list(now, list)?;
                    // TODO: add peer
                }

                (false, peer_id)
            }
            // Handshake packet with only `from_short` field
            (PacketSource::Handshake, None, Some(peer_id)) => (false, NodeId::new(*peer_id)),
            // Strange packet without and peer info
            (PacketSource::Handshake, None, None) => {
                return Err(ValidationError::NoPeerDataInPacket)
            }
        };

        let connections = match self.peers.get_mut(local_id) {
            Some(peers) => peers,
            None => self.peers.entry(*local_id).or_default(),
        };
        let peer = if from_channel {
            if connections.channels_by_peers.contains_key(&peer_id) {
                connections.peers.get_mut(&peer_id)
            } else {
                return Err(ValidationError::PeerChannelNotFound);
            }
        } else {
            connections.peers.get_mut(&peer_id)
        }
        .ok_or(ValidationError::PeerNotFound)?;

        if let Some((peer_reinit_date, local_reinit_date)) = packet.reinit_dates {
            if local_reinit_date != 0 {
                match local_reinit_date.cmp(&peer.incoming_state().reinit_date) {
                    std::cmp::Ordering::Equal => { /* do nothing */ }
                    std::cmp::Ordering::Greater => {
                        return Err(ValidationError::LocalReinitDateTooNew)
                    }
                    std::cmp::Ordering::Less => {
                        // TODO: send message with NOP
                        return Err(ValidationError::LocalReinitDateTooOld);
                    }
                }
            }

            match peer_reinit_date.cmp(&peer.outgoing_state().reinit_date) {
                std::cmp::Ordering::Equal => { /* do nothing */ }
                std::cmp::Ordering::Greater => {
                    if peer.outgoing_state().reinit_date > now + self.options.clock_tolerance_sec {
                        return Err(ValidationError::PeerReinitDateTooNew);
                    }
                    peer.outgoing_state_mut().reinit_date = peer_reinit_date;
                    // TODO: reset packet history
                }
                std::cmp::Ordering::Less => return Err(ValidationError::PeerReinitDateTooOld),
            }
        }

        if let Some(confirm_seqno) = packet.confirm_seqno {
            // TODO: check sender history seqno
        }

        Ok(Some(peer_id))
    }
}

#[derive(Default)]
struct LocalPeerConnections {
    peers: FxHashMap<NodeId, Peer>,
    channels_by_peers: FxHashMap<NodeId, Arc<Channel>>,
}

#[derive(Copy, Clone)]
struct PacketToSend<'a> {
    contents: &'a proto::OutgoingPacketContents<'a>,
    encoder: PacketEncoder<'a>,
}

impl<'a> Encoder<PacketToSend<'a>> for Codec {
    fn encode(&mut self, item: PacketToSend<'a>, dst: &mut BytesMut) {
        match item.encoder {
            PacketEncoder::Handshake(handshake) => handshake.encode(item.contents, dst),
            PacketEncoder::Channel(channel) => channel.encoder(item.contents, dst),
        }
    }
}

impl Decoder for Codec {
    type Item = Bytes;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, CodecError> {
        let (local_id, peer_id) = match HandshakeDecoder(&self.keys).decode(src)? {
            Some(local_id) => (local_id, None),
            None => {
                let channel = ChannelDecoder(&self.channels_by_id).decode(src)?;
                channel.set_ready();
                channel.reset_drop_timeout();
                (channel.local_id(), Some(channel.peer_id()))
            }
        };

        let packet = tl_proto::deserialize::<proto::IncomingPacketContents>(src);

        todo!()
    }
}

#[derive(Copy, Clone)]
enum PacketSource {
    Handshake,
    Channel(NodeId),
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
pub struct ChannelDecoder<'a>(&'a FxHashMap<ChannelId, Arc<Channel>>);

impl<'a> ChannelDecoder<'a> {
    pub fn decode(self, buffer: &mut BytesMut) -> Result<&'a Channel, ChannelError> {
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
    #[error("invalid packet")]
    InvalidPacket(ValidationError),
    #[error("invalid handshake packet")]
    InvalidHandshakePacket(#[from] HandshakeError),
    #[error("invalid channel packet")]
    InvalidChannelPacket(#[from] ChannelError),
}

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("explicit source public key inside channel packet")]
    ExplicitSourceForChannel,
    #[error("invalid peer public key")]
    InvalidPeerPublicKey,
    #[error("invalid address list")]
    InvalidAddressList(#[from] AddressListError),
    #[error("peer id mismatch (from / from_short)")]
    PeerIdMismatch,
    #[error("no peer data in packet")]
    NoPeerDataInPacket,
    #[error("peer channel not found")]
    PeerChannelNotFound,
    #[error("peer not found")]
    PeerNotFound,
    #[error("local reinit date is too new")]
    LocalReinitDateTooNew,
    #[error("local reinit date is too old")]
    LocalReinitDateTooOld,
    #[error("peer reinit date is too old")]
    PeerReinitDateTooOld,
    #[error("peer reinit date is too new")]
    PeerReinitDateTooNew,
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
