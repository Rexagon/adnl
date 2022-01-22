use sha2::{Digest, Sha256};
use tl_proto::*;

#[derive(Default)]
pub struct PacketHasher {
    len: usize,
    h: Sha256,
}

impl PacketHasher {
    #[inline(always)]
    pub fn hash<T: TlWrite>(packet: &T) -> ([u8; 32], usize) {
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
