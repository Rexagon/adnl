use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use everscale_crypto::ed25519;
use sha2::{Digest, Sha256};
use tl_proto::HashWrapper;

use crate::node_id::*;

pub type ChannelId = [u8; 32];

pub struct Channel {
    ready: AtomicBool,
    incoming: ChannelSide,
    outgoing: ChannelSide,
    local_id: NodeId,
    peer_id: NodeId,
    peer_channel_public_key: [u8; 32],
    peer_channel_date: u32,
    drop: AtomicI32,
}

impl Channel {
    pub fn new(
        local_id: NodeId,
        peer_id: NodeId,
        channel_key: &ed25519::KeyPair,
        peer_channel_date: u32,
        context: AdnlChannelCreationContext,
    ) -> Self {
        let shared_secret = channel_key
            .secret_key
            .compute_shared_secret(&channel_key.public_key);
        let mut reversed_secret = shared_secret;
        reversed_secret.reverse();

        let (in_secret, out_secret) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (shared_secret, reversed_secret),
            std::cmp::Ordering::Equal => (shared_secret, shared_secret),
            std::cmp::Ordering::Greater => (reversed_secret, shared_secret),
        };

        Self {
            ready: AtomicBool::new(context == AdnlChannelCreationContext::ConfirmChannel),
            incoming: ChannelSide::from_secret(in_secret),
            outgoing: ChannelSide::from_secret(out_secret),
            local_id,
            peer_id,
            peer_channel_public_key: channel_key.public_key.to_bytes(),
            peer_channel_date,
            drop: Default::default(),
        }
    }

    #[inline(always)]
    pub fn incoming(&self) -> &ChannelSide {
        &self.incoming
    }

    #[inline(always)]
    pub fn outgoing(&self) -> &ChannelSide {
        &self.outgoing
    }

    #[inline(always)]
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    #[inline(always)]
    pub fn peer_id(&self) -> &NodeId {
        &self.peer_id
    }

    #[inline(always)]
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    #[inline(always)]
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    #[inline(always)]
    pub fn reset_drop_timeout(&self) {
        self.drop.store(0, Ordering::Release);
    }

    #[inline(always)]
    pub fn key(&self) -> &[u8; 32] {
        &self.peer_channel_public_key
    }

    #[inline(always)]
    pub fn peer_date(&self) -> u32 {
        self.peer_channel_date
    }

    #[inline(always)]
    pub fn is_still_valid(&self, time: u32) -> bool {
        self.peer_channel_date >= time
    }
}

pub struct ChannelSide {
    pub id: ChannelId,
    pub secret: [u8; 32],
}

impl ChannelSide {
    #[inline(always)]
    fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            id: compute_channel_id(&secret),
            secret,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AdnlChannelCreationContext {
    CreateChannel,
    ConfirmChannel,
}

impl std::fmt::Display for AdnlChannelCreationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateChannel => f.write_str("creation"),
            Self::ConfirmChannel => f.write_str("confirmation"),
        }
    }
}

#[inline(always)]
fn compute_channel_id(key: &[u8; 32]) -> ChannelId {
    let mut h = Sha256::new();
    HashWrapper(everscale_crypto::tl::PublicKey::Aes { key }).update_hasher(&mut h);
    h.finalize().into()
}
