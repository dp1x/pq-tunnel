use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] pq_crypto::CryptoError),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Handshake timeout")]
    HandshakeTimeout,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors raised by the packet codec (`pq_tunnel_core::codec`) and the AEAD
/// envelope (`pq_tunnel_core::envelope`).
///
/// Every variant represents a packet that is malformed or violates the protocol and
/// must be rejected (PROTOCOL_SPEC §14 — reject invalid packets, never fall back to
/// insecure behaviour).  On the receive path, `Envelope::decrypt`-level failures are
/// collapsed to [`CodecError::DecryptionFailed`] so that an attacker observes no
/// distinguishable semantics (no replay-vs-tamper-vs-direction distinction leaks via
/// error handling — see the envelope "Failure is rejection" docs).  Callers
/// translate these into a silent drop.
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

    /// Uniform "drop this packet" result for every per-packet decryption failure:
    /// replay, AEAD tag mismatch (tamper/corruption), version mismatch, wrong
    /// direction, or malformed inner framing.  Carries no internal state so that no
    /// side channel can distinguish failure reasons (PROTOCOL_SPEC §14).  Operators
    /// debug via `tracing::debug!` at the call site, never via the returned value.
    #[error("packet rejected: decryption/validation failed")]
    DecryptionFailed,

    /// Wraps a `pq_crypto` failure (KDF/key-setup errors).  These are fatal/local —
    /// not per-packet peer input — so the structured error is preserved for logging.
    #[error("crypto: {0}")]
    Crypto(#[from] pq_crypto::CryptoError),
}
