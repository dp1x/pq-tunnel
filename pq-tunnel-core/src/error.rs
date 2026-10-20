/// Errors raised by the packet codec (`pq_tunnel_core::codec`) and the AEAD
/// envelope (`pq_tunnel_core::envelope`).
///
/// Every variant represents a packet that is malformed or violates the protocol and
/// must be rejected (PROTOCOL_SPEC §14 — reject invalid packets, never fall back to
/// insecure behaviour).  On the receive path, per-packet failures are collapsed so
/// that an attacker observes no distinguishable semantics (no replay-vs-tamper-vs-
/// direction distinction leaks via error handling — see the envelope "Failure is
/// rejection" docs).  Callers translate these into a silent drop.
///
/// # The one distinction that is *not* collapsed
///
/// [`CodecError::DecryptionFailed`] means **the AEAD tag did not verify**.  Every
/// other per-packet rejection — a replayed counter, invalid inner framing, a
/// direction mismatch, a wrong version byte — is reported as
/// [`CodecError::Rejected`].
///
/// The distinction is **local only**: the rejected packet is dropped identically
/// in both cases (no reply, no error datagram, no on-wire signal), so the
/// "uniform rejection" property of the wire is preserved.  It exists solely so
/// the data-path failure gate can apply the D24 accounting rule — *a token is
/// consumed only when an AEAD decrypt actually fails*.  Charging a token for a
/// replayed-but-authentic packet would let an off-path attacker who captures
/// copies of the victim's traffic drain the victim's failure budget and get its
/// legitimate traffic dropped for a whole window (D24 violation).
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("truncated or oversized field `{field}`: needed {min} bytes, got {got}")]
    Truncated {
        field: &'static str,
        min: usize,
        got: usize,
    },

    /// Caller supplied a field of the wrong exact size (e.g. payload must be
    /// `PAYLOAD_LEN` bytes).  Distinct from `Truncated`, which is reserved for
    /// undersized *parser* input.
    #[error("field `{field}` wrong size: expected {expected}, got {got}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("unsupported protocol version: expected {expected}, found {found}")]
    InvalidVersion { expected: u8, found: u8 },

    #[error("invalid message type byte: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("invalid direction byte: 0x{0:02x}")]
    InvalidDirection(u8),

    /// Rekey rotation trigger: the per-direction nonce counter reached the safety
    /// threshold (CRYPTO_PROFILE §8).  The `counter` field is retained for the
    /// in-process `Session` layer to log/diagnostics via `tracing::debug!`; the
    /// Display impl intentionally does **not** render it, so the value never
    /// appears in error strings that could be logged or surfaced externally
    /// (minimal-disclosure; the counter is non-secret but we do not advertise it).
    #[error("packet nonce counter exhausted: rekey required")]
    NonceExhausted { counter: u64 },

    /// Rekey validation rejected: a rotation trigger fired, but the offered
    /// rekey proof did not validate against the peer's long-term identity
    /// commitment (PROTOCOL_SPEC §13, §16).  The inner string carries only a
    /// fixed, non-sensitive discriminator ("bad_proof" | "mismatched_peer")
    /// so no key material or internal state leaks through the error value;
    /// full detail lives in `tracing::debug!`.  Treated as a silent reject.
    #[error("rekey rejected: {reason}")]
    RekeyRejected { reason: &'static str },

    /// Uniform "drop this packet" result for an **AEAD tag mismatch**
    /// (tamper/corruption).  Carries no internal state so that no side channel
    /// can distinguish failure reasons (PROTOCOL_SPEC §14).  Operators debug via
    /// `tracing::debug!` at the call site, never via the returned value.
    ///
    /// This is the **only** per-packet rejection that may consume a data-path
    /// failure-gate token (D24: a token is consumed only when an AEAD decrypt
    /// actually fails).  Every other rejection is [`CodecError::Rejected`].
    #[error("packet rejected: decryption/validation failed")]
    DecryptionFailed,

    /// The packet was rejected **without an AEAD failure**.
    ///
    /// Covers every per-packet rejection that is decided *after* the AEAD tag
    /// verified (a replayed counter, invalid inner framing, a direction that
    /// does not match the receiver's role) as well as the ones decided on the
    /// cleartext header before any AEAD work (a wrong version byte).
    ///
    /// Wire behaviour is identical to [`CodecError::DecryptionFailed`]: the
    /// packet is dropped silently, no reply is emitted, nothing distinguishes
    /// the two on the wire.  The distinction is local, and exists only so the
    /// data-path failure gate can charge a token **only** for a genuine AEAD
    /// failure (D24).  See the module docs.
    #[error("packet rejected: not an AEAD failure")]
    Rejected,

    /// Wraps a `pq_crypto` failure (KDF/key-setup errors).  These are fatal/local —
    /// not per-packet peer input — so the structured error is preserved for logging.
    #[error("crypto: {0}")]
    Crypto(#[from] pq_crypto::CryptoError),
}
