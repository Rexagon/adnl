use sha2::Digest;
use smallvec::SmallVec;
use std::sync::Arc;
use tl_proto::TlWrite;

use crate::codec;
use crate::net;
use crate::node_id::*;
use crate::proto;

pub struct Sender {
    state: Arc<codec::CodecState>,
}

impl Sender {
    pub async fn send_message(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
        message: proto::Message<'_>,
    ) -> Result<(), SenderError> {
        const MAX_ADNL_MESSAGE_SIZE: usize = 1024;

        const MSG_CREATE_CHANNEL_SIZE: usize = 4 + 4 + 32;
        const MSG_CONFIRM_CHANNEL_SIZE: usize = 4 + 4 + 32 + 32;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Shouldn't fail")
            .as_secs() as u32;

        let encoder = self.state.get_packet_encoder(local_id, peer_id)?;
        let (control_message_len, control_message) = match &encoder.data {
            codec::PacketEncoderData::Handshake(_) => {
                log::debug!("Create channel {:?} -> {:?}", local_id, peer_id);

                let message = proto::Message::CreateChannel {
                    key: encoder.peer.channel_key().public_key.as_bytes(),
                    date: now,
                };
                (MSG_CREATE_CHANNEL_SIZE, Some(message))
            }
            codec::PacketEncoderData::Channel(channel) if channel.ready() => (0, None),
            codec::PacketEncoderData::Channel(channel) => {
                log::debug!("Confirm channel {:?} -> {:?}", local_id, peer_id);

                let message = proto::Message::ConfirmChannel {
                    key: channel.key(),
                    peer_key: encoder.peer.channel_key().public_key.as_bytes(),
                    date: channel.peer_date(), // TODO: research date field
                };
                (MSG_CONFIRM_CHANNEL_SIZE, Some(message))
            }
        };

        let original_message_len = message.max_size_hint();

        let size = match &message {
            proto::Message::Answer { .. }
            | proto::Message::ConfirmChannel { .. }
            | proto::Message::Custom { .. }
            | proto::Message::Nop
            | proto::Message::Query { .. } => control_message_len + original_message_len,
            _ => return Err(SenderError::UnexpectedMessageType),
        };

        if size <= MAX_ADNL_MESSAGE_SIZE {
            // TODO: serialize whole packet

            let mut messages = SmallVec::<[proto::Message; 2]>::new();

            let message = match control_message {
                Some(additional_message) => {
                    messages.push(additional_message);
                    messages.push(message);
                }
                None => messages.push(message),
            };

            // TODO: send
        } else {
            fn build_part_message<'a>(
                data: &'a [u8],
                hash: &'a [u8; 32],
                max_size: usize,
                offset: &mut usize,
            ) -> Option<proto::Message<'a>> {
                let current_offset = *offset;

                let len = std::cmp::min(data.len(), current_offset + max_size);
                // NOTE: `current_offset >= data.len()` will not eliminate useless bounds check
                if current_offset >= len {
                    return None;
                }

                let result = proto::Message::Part {
                    hash,
                    total_size: data.len() as u32,
                    offset: current_offset as u32,
                    data: &data[current_offset..len],
                };

                *offset += len;
                Some(result)
            }

            let mut serialized_len = 0;

            let mut data = Vec::with_capacity(original_message_len);
            message.write_to(&mut data);
            let hash: [u8; 32] = sha2::Sha256::digest(&data).into();

            let mut offset = 0;
            if let Some(control_message) = control_message {
                let len = std::cmp::min(data.len(), MAX_ADNL_MESSAGE_SIZE - control_message_len);
                *offset += len;

                let message = proto::Message::Part {
                    hash: &hash,
                    total_size: data.len() as u32,
                    offset: 0,
                    data: &data[..len],
                };

                // TODO: send packet
            }

            while let Some(message) =
                build_part_message(&data, &hash, MAX_ADNL_MESSAGE_SIZE, &mut offset)
            {
                // TODO
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SenderError {
    #[error("codec error")]
    CodecError(#[from] codec::CodecError),
    #[error("unexpected message type")]
    UnexpectedMessageType,
}

#[inline(always)]
fn bytes_max_size_hint(mut len: usize) -> usize {
    if len < 254 {
        len += 1;
    } else {
        len += 4;
    }

    let remainder = len % 4;
    if remainder != 0 {
        len += 4 - remainder;
    }

    len
}
