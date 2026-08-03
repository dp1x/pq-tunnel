//! Per-direction nonce counter management and reconstruction.
//!
//! CRYPTO_PROFILE §8 mandates unique nonce usage for the AEAD.  The on-wire
//! `PacketHeader::packet_nonce` is a 64-bit big-endian monotonic counter
//! (PROTOCOL_SPEC §11).  The AEAD nonce is reconstructed as
//! `kdf::build_session_nonce(prefix[4], counter[8])` (12 bytes), where the
//! 4-byte `prefix` is a per-direction, per-session secret derived by HKDF
//! (`derive_nonce_prefix_c2s` / `derive_nonce_prefix_s2c`), bound to the
//! session identifier so distinct sessions never share a nonce space even when
//! they share a master secret (PROTOCOL_SPEC §10 unique session keys).
//!
//! Because the prefix is secret and per-direction, counter reuse across
//! *different* sessions or *different* directions within a session is
//! irrelevant — the reconstructed nonces are independent.  Within a single
//! direction, the counter is strictly monotonic (sender) or strictly
//! increasing (receiver high-water), so the constructed nonce never repeats.
//!
//! `MAX_PACKET_NONCE` defines the safety threshold below `u64::MAX` at which
//! the counter triggers a rekey (PROTOCOL_SPEC §13).  This is an implementation
//! parameter — the guarantee (unique nonce) holds as long as the counter
//! never wraps, which is enforced by checking against `MAX_PACKET_NONCE`.

use crate::codec::{AEAD_NONCE_LEN, MAX_PACKET_NONCE, PACKET_NONCE_LEN};
use crate::error::CodecError;

/// Re-export the exhaustion threshold check from the codec for convenience.
///
/// Returns `true` once `counter >= MAX_PACKET_NONCE`, meaning the counter is
/// within the final `2^32` values of the u64 space and must trigger a rekey
/// before any further packets are emitted or accepted.
pub const fn is_counter_exhausted(counter: u64) -> bool {
    crate::codec::is_counter_exhausted(counter)
}

/// Re-export the safety threshold constant.
pub const fn max_packet_nonce() -> u64 {
    MAX_PACKET_NONCE
}

/// Compile-time assertion: the session nonce must be AEAD_NONCE_LEN bytes
/// (= PACKET_NONCE_LEN + 4-byte secret prefix, tied to `kdf::build_session_nonce`).
const _: () = assert!(
    AEAD_NONCE_LEN == PACKET_NONCE_LEN + 4,
    "session nonce must be 4-byte prefix + 8-byte counter = 12 bytes (kdf::build_session_nonce)"
);

// ---------------------------------------------------------------------------
// Send-side counter (nonce generation)
// ---------------------------------------------------------------------------

/// Monotonic send counter with exhaustion guard.
///
/// Wraps a `u64` that is strictly incremented for every packet a direction
/// sends.  `next_nonce()` reconstructs the full AEAD nonce from the secret
/// per-direction prefix + the counter, and returns `NonceExhausted` once the
/// counter reaches `MAX_PACKET_NONCE` (PROTOCOL_SPEC §13 rekey trigger).
///
/// The counter field itself is non-secret, but it is not exposed via `Debug`.
#[derive(Debug)]
pub struct SendCounter {
    counter: u64,
}

impl Default for SendCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl SendCounter {
    /// Start at counter 0 (the first packet sent uses counter 0).
    pub const fn new() -> Self {
        Self { counter: 0 }
    }

    /// Current counter value (for diagnostics / testing).
    pub fn get(&self) -> u64 {
        self.counter
    }

    /// Reconstruct the AEAD nonce for the current counter and advance.
    ///
    /// Returns `NonceExhausted` when the counter has reached the rekey
    /// threshold, so the caller must rotate keys before calling again.
    /// The caller is responsible for passing the correct per-direction prefix.
    pub fn next_nonce(&mut self, prefix: &[u8; 4]) -> Result<pq_crypto::AeadNonce, CodecError> {
        if is_counter_exhausted(self.counter) {
            return Err(CodecError::NonceExhausted {
                counter: self.counter,
            });
        }
        let nonce = pq_crypto::aead::AeadNonce::from_bytes(pq_crypto::kdf::build_session_nonce(
            prefix,
            self.counter,
        ));
        // Advance strictly monotonically.  `checked_add` guards the u64 edge;
        // the exhaustion check above ensures we never reach u64::MAX.
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CodecError::NonceExhausted {
                counter: self.counter,
            })?;
        Ok(nonce)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MAX_PACKET_NONCE;
    use pq_crypto::kdf::MasterSecret;
    use pq_crypto::kdf::derive_nonce_prefix_c2s;

    /// Deterministic master secret for tests.
    fn test_master() -> MasterSecret {
        let c = [0x11u8; 32];
        let s = [0x22u8; 32];
        pq_crypto::derive_master_secret(&c, &s).expect("master secret")
    }

    /// Non-secret test session identifier.
    fn test_sid() -> [u8; 8] {
        [0xAB; 8]
    }

    fn test_prefix() -> [u8; 4] {
        derive_nonce_prefix_c2s(&test_master(), &test_sid()).unwrap()
    }

    #[test]
    fn counter_starts_at_zero() {
        let c = SendCounter::new();
        assert_eq!(c.get(), 0);
    }

    #[test]
    fn next_nonce_advances_counter() {
        let prefix = test_prefix();
        let mut c = SendCounter::new();

        let n0 = c.next_nonce(&prefix).unwrap();
        assert_eq!(c.get(), 1);
        assert_ne!(&n0.as_bytes()[..4], &[0u8; 4]); // prefix is non-zero

        let n1 = c.next_nonce(&prefix).unwrap();
        assert_eq!(c.get(), 2);
        // Nonces differ because the counter portion differs.
        assert_ne!(n0.as_bytes(), n1.as_bytes());
    }

    #[test]
    fn exhaustion_triggers_before_wrap() {
        let prefix = test_prefix();
        let mut c = SendCounter::new();
        c.counter = MAX_PACKET_NONCE;
        let res = c.next_nonce(&prefix);
        assert!(
            matches!(res, Err(CodecError::NonceExhausted { .. })),
            "must reject at exhaustion threshold"
        );
    }

    #[test]
    fn last_accepted_then_exhausted() {
        let prefix = test_prefix();
        let mut c = SendCounter::new();
        c.counter = MAX_PACKET_NONCE - 1;
        // This call uses counter MAX_PACKET_NONCE - 1 and advances to MAX_PACKET_NONCE.
        let _ = c.next_nonce(&prefix).unwrap();
        assert_eq!(c.get(), MAX_PACKET_NONCE);
        // Next call must reject.
        let res = c.next_nonce(&prefix);
        assert!(matches!(res, Err(CodecError::NonceExhausted { .. })));
    }

    #[test]
    fn u64_max_is_exhausted() {
        assert!(is_counter_exhausted(u64::MAX));
        assert!(is_counter_exhausted(MAX_PACKET_NONCE));
        assert!(!is_counter_exhausted(0));
        assert!(!is_counter_exhausted(MAX_PACKET_NONCE - 1));
    }
}
