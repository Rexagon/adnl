use sha2::{Digest, Sha256};
use tl_proto::TlWrite;

use crate::keys::ed25519;
use crate::proto;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct AdnlNodeIdFull(ed25519::PublicKey);

impl AdnlNodeIdFull {
    #[inline(always)]
    pub fn from_tl(tl: proto::PublicKey<'_>) -> Option<Self> {
        match tl {
            proto::PublicKey::Ed25519 { key } => ed25519::PublicKey::from_bytes(*key).map(Self),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn new(public_key: ed25519::PublicKey) -> Self {
        Self(public_key)
    }

    #[inline(always)]
    pub fn public_key(&self) -> &ed25519::PublicKey {
        &self.0
    }

    #[inline(always)]
    pub fn as_tl(&'_ self) -> proto::PublicKey<'_> {
        proto::PublicKey::Ed25519 {
            key: self.0.as_bytes(),
        }
    }

    pub fn compute_short_id(&self) -> AdnlNodeIdShort {
        let mut h = Sha256::new();
        tl_proto::HashWrapper(self.as_tl()).update_hasher(&mut h);
        AdnlNodeIdShort(h.finalize().into())
    }
}

impl From<ed25519::PublicKey> for AdnlNodeIdFull {
    fn from(public_key: ed25519::PublicKey) -> Self {
        Self(public_key)
    }
}

impl ToString for AdnlNodeIdFull {
    fn to_string(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct AdnlNodeIdShort([u8; 32]);

impl AdnlNodeIdShort {
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

impl std::fmt::Debug for AdnlNodeIdShort {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(&self.0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl AsRef<[u8; 32]> for AdnlNodeIdShort {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ed25519::PublicKey {
    #[inline(always)]
    pub fn compute_node_ids(&self) -> (AdnlNodeIdFull, AdnlNodeIdShort) {
        let full_id = AdnlNodeIdFull::new(*self);
        let short_id = full_id.compute_short_id();
        (full_id, short_id)
    }
}

pub struct StoredAdnlNodeKey {
    short_id: AdnlNodeIdShort,
    full_id: AdnlNodeIdFull,
    private_key: ed25519::ExpandedSecretKey,
}

impl StoredAdnlNodeKey {
    pub fn from_parts(
        short_id: AdnlNodeIdShort,
        full_id: AdnlNodeIdFull,
        private_key: &ed25519::SecretKey,
    ) -> Self {
        Self {
            short_id,
            full_id,
            private_key: ed25519::ExpandedSecretKey::from(private_key),
        }
    }

    #[inline(always)]
    pub fn short_id(&self) -> &AdnlNodeIdShort {
        &self.short_id
    }

    #[inline(always)]
    pub fn full_id(&self) -> &AdnlNodeIdFull {
        &self.full_id
    }

    #[inline(always)]
    pub fn private_key_nonce(&self) -> &[u8; 32] {
        self.private_key.nonce()
    }

    #[inline(always)]
    pub fn sign<T: TlWrite>(&self, data: T) -> [u8; 64] {
        self.private_key.sign(data, &self.full_id.0)
    }
}
