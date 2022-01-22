use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek_ng::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek_ng::scalar::Scalar;
use rand::Rng;
use sha2::{Digest, Sha512};
use tl_proto::*;

use crate::proto;

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub secret_key: ExpandedSecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    #[inline(always)]
    pub fn generate() -> Self {
        Self::from(&SecretKey::generate())
    }

    #[inline(always)]
    pub fn sign<T: TlWrite>(&self, data: T) -> [u8; 64] {
        self.secret_key.sign(data, &self.public_key)
    }
}

impl From<ExpandedSecretKey> for KeyPair {
    fn from(secret_key: ExpandedSecretKey) -> Self {
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

impl From<&'_ SecretKey> for KeyPair {
    fn from(secret_key: &SecretKey) -> Self {
        let secret_key = secret_key.expand();
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey(CompressedEdwardsY, EdwardsPoint);

impl PublicKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let compressed = CompressedEdwardsY(bytes);
        let point = compressed.decompress()?;
        Some(PublicKey(compressed, -point))
    }

    #[inline(always)]
    pub fn from_tl(tl: proto::PublicKey<'_>) -> Option<Self> {
        match tl {
            proto::PublicKey::Ed25519 { key } => Self::from_bytes(*key),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn as_tl(&'_ self) -> proto::PublicKey<'_> {
        proto::PublicKey::Ed25519 {
            key: self.0.as_bytes(),
        }
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0 .0
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0 .0
    }

    pub fn verify<T: TlWrite>(&self, message: T, signature: &[u8; 64]) -> bool {
        let target_r = CompressedEdwardsY(signature[..32].try_into().unwrap());
        let s = match check_scalar(signature[32..].try_into().unwrap()) {
            Some(s) => s,
            None => return false,
        };

        let mut h = Sha512::new();
        h.update(target_r.as_bytes());
        h.update(&self.0 .0);
        HashWrapper(message).update_hasher(&mut h);

        let k = Scalar::from_hash(h);
        let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.1, &s);

        r.compress() == target_r
    }

    #[inline(always)]
    fn from_scalar(bits: [u8; 32]) -> PublicKey {
        let point = &clamp_scalar(bits) * &ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();
        Self(compressed, -point)
    }
}

impl From<&'_ SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(&secret_key.0);
        let hash: [u8; 64] = h.finalize().into();
        Self::from_scalar(hash[..32].try_into().unwrap())
    }
}

impl From<&'_ ExpandedSecretKey> for PublicKey {
    fn from(expanded_secret_key: &ExpandedSecretKey) -> Self {
        Self::from_scalar(expanded_secret_key.key.to_bytes())
    }
}

impl AsRef<[u8; 32]> for PublicKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl PartialEq for PublicKey {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.0 .0.eq(&other.0 .0)
    }
}

impl Eq for PublicKey {}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(&self.0 .0, &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

#[derive(Copy, Clone)]
pub struct ExpandedSecretKey {
    key: Scalar,
    nonce: [u8; 32],
}

impl ExpandedSecretKey {
    #[inline(always)]
    pub fn nonce(&'_ self) -> &'_ [u8; 32] {
        &self.nonce
    }

    #[allow(non_snake_case)]
    pub fn sign<T: TlWrite>(&self, message: T, public_key: &PublicKey) -> [u8; 64] {
        let message = HashWrapper(message);

        let mut h = Sha512::new();
        h.update(&self.nonce);
        message.update_hasher(&mut h);

        let r = Scalar::from_hash(h);
        let R = (&r * &ED25519_BASEPOINT_TABLE).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        message.update_hasher(&mut h);

        let k = Scalar::from_hash(h);
        let s = (k * self.key) + r;

        let mut result = [0u8; 64];
        result[..32].copy_from_slice(R.as_bytes().as_slice());
        result[32..].copy_from_slice(s.as_bytes().as_slice());
        result
    }

    #[inline(always)]
    pub fn compute_shared_secret(&self, other_public_key: &PublicKey) -> [u8; 32] {
        let point = (-other_public_key.1).to_montgomery();
        (clamp_scalar(self.key.to_bytes()) * point).to_bytes()
    }
}

impl From<&'_ SecretKey> for ExpandedSecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(&secret_key.0);
        let hash: [u8; 64] = h.finalize().into();

        let mut lower: [u8; 32] = hash[..32].try_into().unwrap();
        let nonce: [u8; 32] = hash[32..].try_into().unwrap();

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        Self {
            key: Scalar::from_bits(lower),
            nonce,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0
    }

    pub fn generate() -> Self {
        Self(rand::thread_rng().gen())
    }

    #[inline(always)]
    pub fn expand(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from(self)
    }
}

#[inline(always)]
fn clamp_scalar(mut bits: [u8; 32]) -> Scalar {
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}

#[inline(always)]
fn check_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    if bytes[31] & 0xf0 == 0 {
        Some(Scalar::from_bits(bytes))
    } else {
        Scalar::from_canonical_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_signature() {
        let secret = SecretKey::from_bytes([
            99, 87, 207, 105, 199, 108, 51, 89, 172, 108, 232, 48, 240, 147, 49, 155, 145, 60, 66,
            55, 98, 149, 119, 0, 251, 19, 132, 69, 151, 132, 184, 53,
        ]);

        let pubkey = PublicKey::from(&secret);
        assert_eq!(
            pubkey.to_bytes(),
            [
                75, 54, 96, 93, 16, 21, 8, 159, 230, 42, 68, 148, 54, 18, 251, 196, 205, 254, 252,
                114, 76, 87, 204, 218, 132, 26, 196, 181, 191, 188, 115, 123
            ]
        );
        println!("{:?}", pubkey);

        let data = b"hello world";

        let extended = ExpandedSecretKey::from(&secret);
        let signature = extended.sign(data, &pubkey);
        assert_eq!(
            signature,
            [
                76, 51, 131, 27, 77, 188, 20, 26, 229, 121, 93, 100, 10, 166, 183, 121, 12, 48, 17,
                239, 115, 184, 50, 162, 103, 228, 3, 136, 213, 165, 246, 113, 220, 84, 255, 136,
                251, 141, 229, 52, 236, 249, 135, 182, 242, 198, 171, 1, 194, 148, 164, 8, 131,
                253, 205, 112, 112, 145, 6, 225, 71, 78, 138, 1
            ]
        );

        assert!(pubkey.verify(data, &signature))
    }

    #[test]
    fn verify_with_different_key() {
        let first = SecretKey::generate();
        let first_pubkey = PublicKey::from(&first);

        let second = SecretKey::generate();
        let second_pubkey = PublicKey::from(&second);

        let data = b"hello world";

        let extended = ExpandedSecretKey::from(&first);
        let signature = extended.sign(data, &first_pubkey);

        assert!(!second_pubkey.verify(&data, &signature))
    }

    #[test]
    fn same_shared_secret() {
        let first = ExpandedSecretKey::from(&SecretKey::generate());
        let first_pubkey = PublicKey::from(&first);

        let second = ExpandedSecretKey::from(&SecretKey::generate());
        let second_pubkey = PublicKey::from(&second);

        let first_shared_key = first.compute_shared_secret(&second_pubkey);
        let second_shared_key = second.compute_shared_secret(&first_pubkey);

        assert_eq!(first_shared_key, second_shared_key);
    }
}
