use std::sync::Arc;

use everscale_crypto::ed25519;

use crate::codec;
use crate::net;
use crate::node_id::*;
use crate::proto;

pub struct Receiver {
    state: Arc<codec::CodecState>,
}

impl Receiver {
    pub async fn process_packet(
        &self,
        now: u32,
        decoded: codec::DecodedPacket,
    ) -> Result<(), ValidationError> {
        let packet = tl_proto::deserialize::<proto::IncomingPacketContents>(&decoded.data)
            .map_err(ValidationError::InvalidPacketContents)?;

        let peer = match (decoded.peer_id, packet.from, packet.from_short) {
            // Packet from channel
            (Some(peer_id), None, None) => self.state.get_peer(&decoded.local_id, &peer_id)?,
            // Invalid packet from channel
            (Some(_), _, _) => return Err(ValidationError::ExplicitSourceForChannel),
            // Handshake packet with `from` field
            (None, Some(public_key), from_short) => {
                let public_key = ed25519::PublicKey::from_tl(public_key)
                    .ok_or(ValidationError::InvalidPeerPublicKey)?;
                let peer_id = NodeId::from(public_key);

                if matches!(from_short, Some(id) if peer_id.as_bytes() != id) {
                    return Err(ValidationError::PeerIdMismatch);
                }

                if let Some(list) = packet.address {
                    let address = net::parse_address_list(now, list)?;
                    self.state
                        .update_peer(&decoded.local_id, &peer_id, &public_key, address)?
                } else {
                    self.state.get_peer(&decoded.local_id, &peer_id)?
                }
            }
            // Handshake packet with only `from_short` field
            (None, None, Some(peer_id)) => self
                .state
                .get_peer(&decoded.local_id, &NodeId::new(*peer_id))?,
            // Strange packet without any peer info
            (None, None, None) => return Err(ValidationError::NoPeerDataInPacket),
        };

        // Peer
        if let Some(proto::ReinitDates {
            local: peer_reinit_date,
            target: local_reinit_date,
        }) = packet.reinit_dates
        {
            let expected_local_reinit_date =
                local_reinit_date.cmp(&peer.local_state().reinit_date());

            if expected_local_reinit_date == std::cmp::Ordering::Greater {
                return Err(ValidationError::ExpectedLocalReinitDateTooNew);
            }

            if peer_reinit_date > now + self.state.options.clock_tolerance_sec {
                return Err(ValidationError::PeerReinitDateTooNew);
            }

            let known_peer_reinit_date = peer.target_state().reinit_date();
            match peer_reinit_date.cmp(&known_peer_reinit_date) {
                std::cmp::Ordering::Equal => { /* do nothing */ }
                // Peer was updated with newer reinit date
                std::cmp::Ordering::Greater => {
                    peer.target_state().set_reinit_date(peer_reinit_date)
                    // TODO: reset packet history
                }
                // We already know about newer peer instance
                std::cmp::Ordering::Less => return Err(ValidationError::PeerReinitDateTooOld),
            }

            if local_reinit_date != 0 && expected_local_reinit_date == std::cmp::Ordering::Less {
                return Err(ValidationError::ExpectedLocalReinitDateTooOld);
            }
        }

        if let Some(_confirm_seqno) = packet.confirm_seqno {
            // TODO: check sender history seqno
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("invalid packet contents")]
    InvalidPacketContents(#[from] tl_proto::TlError),
    #[error("explicit source public key inside channel packet")]
    ExplicitSourceForChannel,
    #[error("invalid peer public key")]
    InvalidPeerPublicKey,
    #[error("invalid address list")]
    InvalidAddressList(#[from] net::AddressListError),
    #[error("peer id mismatch (from / from_short)")]
    PeerIdMismatch,
    #[error("no peer data in packet")]
    NoPeerDataInPacket,
    #[error("codec error")]
    CodecError(#[from] codec::CodecError),
    #[error("local reinit date is too new")]
    ExpectedLocalReinitDateTooNew,
    #[error("local reinit date is too old")]
    ExpectedLocalReinitDateTooOld,
    #[error("peer reinit date is too old")]
    PeerReinitDateTooOld,
    #[error("peer reinit date is too new")]
    PeerReinitDateTooNew,
}
