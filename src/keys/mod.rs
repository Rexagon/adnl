use sha2::{Digest, Sha256};

pub mod ed25519;
// TODO: Add AES

#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct NodeId([u8; 32]);

impl NodeId {
    #[inline(always)]
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<ed25519::PublicKey> for NodeId {
    fn from(public_key: ed25519::PublicKey) -> Self {
        let mut h = Sha256::new();
        tl_proto::HashWrapper(public_key.as_tl()).update_hasher(&mut h);
        Self(h.finalize().into())
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(&self.0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl AsRef<[u8; 32]> for NodeId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq<[u8]> for NodeId {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}
