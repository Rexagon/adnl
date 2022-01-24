use crate::keys::*;
use crate::net::address::*;

pub struct Peer {
    public_key: ed25519::PublicKey,
    ip: Address,
    channel_key: ed25519::KeyPair,
    incoming_state: PeerState,
    outgoing_state: PeerState,
}

impl Peer {
    pub fn new(ip: Address, public_key: ed25519::PublicKey, reinit_date: u32) -> Self {
        Self {
            public_key,
            ip,
            channel_key: ed25519::KeyPair::generate(),
            incoming_state: PeerState { reinit_date },
            outgoing_state: Default::default(),
        }
    }

    #[inline(always)]
    pub fn public_key(&self) -> &ed25519::PublicKey {
        &self.public_key
    }

    #[inline(always)]
    pub fn ip(&self) -> &Address {
        &self.ip
    }

    #[inline(always)]
    pub fn channel_key(&self) -> &ed25519::KeyPair {
        &self.channel_key
    }

    #[inline(always)]
    pub fn incoming_state(&self) -> &PeerState {
        &self.incoming_state
    }

    #[inline(always)]
    pub fn incoming_state_mut(&mut self) -> &mut PeerState {
        &mut self.incoming_state
    }

    #[inline(always)]
    pub fn outgoing_state(&self) -> &PeerState {
        &self.outgoing_state
    }

    #[inline(always)]
    pub fn outgoing_state_mut(&mut self) -> &mut PeerState {
        &mut self.outgoing_state
    }

    pub fn reset(&mut self) {
        self.channel_key = ed25519::KeyPair::generate();
        self.outgoing_state = Default::default();
    }
}

#[derive(Default)]
pub struct PeerState {
    pub reinit_date: u32,
}
