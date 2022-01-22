use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use sha2::{Digest, Sha256};
use tl_proto::HashWrapper;

use crate::keys::ed25519;
use crate::node_id::*;
use crate::proto;

pub type AdnlChannelId = [u8; 32];

pub struct AdnlChannel {
    ready: AtomicBool,
    incoming: AdnlChannelSide,
    outgoing: AdnlChannelSide,
    local_id: AdnlNodeIdShort,
    peer_id: AdnlNodeIdShort,
    peer_channel_date: u32,
    drop: AtomicI32,
}

impl AdnlChannel {
    pub fn new(
        local_id: AdnlNodeIdShort,
        peer_id: AdnlNodeIdShort,
        channel_key: &ed25519::ExpandedSecretKey,
        other_public_key: &ed25519::PublicKey,
        peer_channel_date: u32,
        context: AdnlChannelCreationContext,
    ) -> Self {
        let shared_secret = channel_key.compute_shared_secret(other_public_key);
        let mut reversed_secret = shared_secret;
        reversed_secret.reverse();

        let (in_secret, out_secret) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (shared_secret, reversed_secret),
            std::cmp::Ordering::Equal => (shared_secret, shared_secret),
            std::cmp::Ordering::Greater => (reversed_secret, shared_secret),
        };

        Self {
            ready: AtomicBool::new(context == AdnlChannelCreationContext::ConfirmChannel),
            incoming: AdnlChannelSide::from_secret(in_secret),
            outgoing: AdnlChannelSide::from_secret(out_secret),
            local_id,
            peer_id,
            peer_channel_date,
            drop: Default::default(),
        }
    }

    #[inline(always)]
    pub fn incoming(&self) -> &AdnlChannelSide {
        &self.incoming
    }

    #[inline(always)]
    pub fn outgoing(&self) -> &AdnlChannelSide {
        &self.outgoing
    }

    #[inline(always)]
    pub fn local_id(&self) -> &AdnlNodeIdShort {
        &self.local_id
    }

    #[inline(always)]
    pub fn peer_id(&self) -> &AdnlNodeIdShort {
        &self.peer_id
    }

    #[inline(always)]
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    #[inline(always)]
    pub fn reset_drop_timeout(&self) {
        self.drop.store(0, Ordering::Release);
    }
}

pub struct AdnlChannelSide {
    pub id: AdnlChannelId,
    pub secret: [u8; 32],
}

impl AdnlChannelSide {
    #[inline(always)]
    fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            id: compute_channel_id(&secret),
            secret,
        }
    }
}

pub struct AdnlChannelKey {
    public_key: ed25519::PublicKey,
    private_key: ed25519::ExpandedSecretKey,
}

impl AdnlChannelKey {
    pub fn generate() -> Self {
        let private_key = ed25519::SecretKey::generate().expand();
        let public_key = ed25519::PublicKey::from(&private_key);

        Self {
            public_key,
            private_key,
        }
    }

    #[inline(always)]
    pub fn public_key(&self) -> &ed25519::PublicKey {
        &self.public_key
    }

    #[inline(always)]
    pub fn private_key(&self) -> &ed25519::ExpandedSecretKey {
        &self.private_key
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
fn compute_channel_id(key: &[u8; 32]) -> AdnlChannelId {
    let mut h = Sha256::new();
    HashWrapper(proto::PublicKey::Aes { key }).update_hasher(&mut h);
    h.finalize().into()
}
