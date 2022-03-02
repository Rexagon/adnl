use std::sync::atomic::{AtomicU32, Ordering};

use everscale_crypto::ed25519;
use parking_lot::RwLock;

use crate::net::*;

pub struct Peer {
    public_key: ed25519::PublicKey,
    address: RwLock<Address>,
    channel_key: ed25519::KeyPair,
    local_state: PeerState,
    target_state: PeerState,
}

impl Peer {
    pub fn new(address: Address, public_key: ed25519::PublicKey, reinit_date: u32) -> Self {
        Self {
            public_key,
            address: RwLock::new(address),
            channel_key: ed25519::KeyPair::generate(&mut rand::thread_rng()),
            local_state: PeerState {
                reinit_date: AtomicU32::new(reinit_date),
            },
            target_state: Default::default(),
        }
    }

    #[inline(always)]
    pub fn public_key(&self) -> &ed25519::PublicKey {
        &self.public_key
    }

    #[inline(always)]
    pub fn address(&self) -> Address {
        *self.address.read()
    }

    pub fn set_address(&self, address: Address) {
        *self.address.write() = address;
    }

    #[inline(always)]
    pub fn channel_key(&self) -> &ed25519::KeyPair {
        &self.channel_key
    }

    #[inline(always)]
    pub fn local_state(&self) -> &PeerState {
        &self.local_state
    }

    #[inline(always)]
    pub fn target_state(&self) -> &PeerState {
        &self.target_state
    }

    #[inline(always)]
    pub fn outgoing_state_mut(&mut self) -> &mut PeerState {
        &mut self.target_state
    }

    pub fn reset(&mut self) {
        self.channel_key = ed25519::KeyPair::generate(&mut rand::thread_rng());
        self.target_state = Default::default();
    }
}

#[derive(Default)]
pub struct PeerState {
    reinit_date: AtomicU32,
}

impl PeerState {
    pub fn reinit_date(&self) -> u32 {
        self.reinit_date.load(Ordering::Acquire)
    }

    pub fn set_reinit_date(&self, reinit_date: u32) {
        self.reinit_date.store(reinit_date, Ordering::Release)
    }
}
