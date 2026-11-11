//! WireGuard key handling for WARP identities.
//!
//! Key types come from `boringtun::x25519` (a re-export of x25519-dalek) so that
//! the same `StaticSecret` we generate/load is the one handed to `Tunn`.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

/// Generate a fresh WireGuard private key. x25519-dalek clamps the scalar when it
/// is used for Diffie-Hellman, so the stored representation interoperates with the
/// clamped keys produced by warp-plus / wgcf.
pub fn generate_private_key() -> StaticSecret {
    StaticSecret::random_from_rng(OsRng)
}

/// Derive the public key from a private key.
pub fn public_from_private(sk: &StaticSecret) -> PublicKey {
    PublicKey::from(sk)
}

/// Encode a 32-byte key as standard base64 (the form used by the WARP API and
/// wgcf-identity.json).
pub fn encode_key_b64(bytes: &[u8; 32]) -> String {
    B64.encode(bytes)
}

/// Decode a base64 key into raw 32 bytes.
pub fn decode_key_b64(s: &str) -> Result<[u8; 32]> {
    let v = B64
        .decode(s.trim())
        .map_err(|e| anyhow!("invalid base64 key: {e}"))?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key should be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

/// Reconstruct a `StaticSecret` from a base64 private key.
pub fn static_secret_from_b64(s: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_key_b64(s)?))
}

/// Reconstruct a `PublicKey` from a base64 public key.
pub fn public_from_b64(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_key_b64(s)?))
}
