//! v2 handshake — mutual-ephemeral hybrid ML-KEM-768 + X25519 establishment.
//!
//! Implements DESIGN_DECISIONS D12–D15 over the uniform 1280-byte codec
//! datagram framing (DESIGN_DECISIONS D13).  (The pre-v2 QUIC handshake that
//! this module replaced was removed with the legacy transport.)
//!
//! # Wire model (D13)
//!
//! ```text
//! M1 ClientHello:  VERSION(1) ‖ SID(8) ‖ eph_pk_c(1184) ‖ x_c(32) ‖ client_sig(3309)
//!                  = 4534 bytes → 4 fragments
//! M2 ServerHello:  VERSION(1) ‖ SID(8) ‖ eph_pk_s(1184) ‖ x_s(32) ‖ ct2(1088)
//!                  ‖ server_sig(3309) = 5622 bytes → 5 fragments
//! M3 ClientConfirm: VERSION(1) ‖ SID(8) ‖ ct3(1088) ‖ client_finished(16)
//!                  = 1113 bytes → 1 fragment
//! ```
//!
//! Every fragment travels as exactly one 1280-byte `WirePacket`:
//!
//! ```text
//! VERSION(1) ‖ SID(8) ‖ hs_type(1) ‖ frag_idx(1) ‖ frag_total(1) ‖ body(≤1268) ‖ zero padding
//! ```
//!
//! `hs_type` is byte-disjoint from the codec `MessageType` (0x00–0x03), so a
//! receiver can dispatch a datagram unambiguously:
//!
//! **Dispatch rule (pinned):** byte 9 of a datagram selects the path.
//! `0x10`/`0x20`/`0x30` → handshake fragment; anything else → data path
//! (`PacketHeader` + envelope).  A data packet's byte 9 is the most-significant
//! byte of the packet nonce counter; it can only enter 0x10–0x30 after 2^60
//! packets in one direction (≈35,000 years at 1 Gbps) — unreachable in a
//! session lifetime, and even then the fragment path rejects it structurally
//! (`frag_total` is pinned per `hs_type`, so a data packet can never be
//! interpreted as a valid fragment; it is silently dropped — fail secure).
//!
//! # Transcript and signatures (D13)
//!
//! One canonical transcript, domain string `HANDSHAKE_DOMAIN` prepended once,
//! signature/MAC slots zero-filled in the hashed forms, fragment headers and
//! padding excluded:
//!
//! ```text
//! TH1 = SHA256(dom ‖ M1_z)                    (client signature over the zero-sig form)
//! TH2 = SHA256(dom ‖ M1_s ‖ M2_z)             (server signature; full M2 coverage)
//! TH3 = SHA256(dom ‖ M1_z ‖ M2_z ‖ M3_z)      (bound into master + Finished MAC)
//! ```
//!
//! ML-DSA signs the 32-byte SHA-256 digest, never the raw transcript.
//!
//! # Key schedule (D13/D14/D15)
//!
//! ```text
//! master        = HKDF(ikm = ssA ‖ ssB ‖ dh_cs, salt = [0;32],
//!                      info = "pq-tunnel-master-v2" ‖ VERSION ‖ SID ‖ TH3)
//! finished_key  = HKDF(master, salt = [0;32],
//!                      info = "pq-tunnel-finished-v1" ‖ VERSION ‖ SID)
//! client_finished = HMAC-SHA256(finished_key, TH3)[..16]
//! ```
//!
//! Verification order on both sides: version/sid checks → decode →
//! signature verify → KEM (D13: never KEM before signature).
//!
//! # Failure and DoS posture (D12/D13/D15)
//!
//! - Every peer-input failure is a silent drop with zero state mutation; no
//!   error datagrams are ever emitted.  Local/transport failures propagate.
//! - The server allocates a pending entry only on a validated fragment 0 of an
//!   M1, never before; the table is bounded (`ServerConfig::max_pending`) and
//!   TTL-evicted; M1 fragments are rate-limited per source.
//! - A forged or raced M3 is silently dropped **without** consuming the
//!   client's retransmit budget, resetting backoff, or touching the cached M2 —
//!   the entry stays `AwaitM3` (D15).
//! - The server verifies the client signature against the entire pinned roster
//!   with no early exit (uniform verification count; D12).
//! - Client retransmission is byte-identical (deterministic fragmentation) with
//!   jittered exponential backoff and bounded budgets; the server answers a
//!   duplicate M1 with the cached, byte-identical M2.
//!
//! # Scope of the drivers
//!
//! `client_handshake_v2` / `server_handshake_v2` run one handshake per
//! invocation: the client returns ready after M3 is emitted (1 RTT; server
//! confirmation is implicit — D15, with liveness enforcement owned by the
//! session layer); the server returns the outcome only after the M3 Finished
//! MAC verifies (1.5 RTT).  A multi-session manager (Phase 6) drives one
//! `ServerHandshake` per source.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use pq_crypto::kdf::{
    MasterSecret, compute_client_finished, derive_finished_key, derive_master_secret_v2,
};
use pq_crypto::{
    ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
    MlDsaKeypair, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext, MlKemKeypair, MlKemPublicKey,
    MlKemSecretKey, X25519Keypair, X25519PublicKey, decapsulate, encapsulate, verify,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::codec::{PACKET_SIZE, PROTOCOL_VERSION, SESSION_ID_LEN, VERSION_LEN, WirePacket};
use crate::error::CodecError;
use crate::udp::UdpTransport;

// ---------------------------------------------------------------------------
// Wire constants (D13)
// ---------------------------------------------------------------------------

/// Handshake message type: ClientHello fragment header byte.
pub const HS_TYPE_CLIENT_HELLO: u8 = 0x10;
/// Handshake message type: ServerHello fragment header byte.
pub const HS_TYPE_SERVER_HELLO: u8 = 0x20;
/// Handshake message type: ClientConfirm fragment header byte.
pub const HS_TYPE_CLIENT_CONFIRM: u8 = 0x30;

/// Fragment header length: `VERSION(1) ‖ SID(8) ‖ hs_type(1) ‖ frag_idx(1) ‖ frag_total(1)`.
pub const HS_FRAG_HEADER_LEN: usize = VERSION_LEN + SESSION_ID_LEN + 3;
/// Maximum body bytes per fragment datagram (`1280 − 12`).
pub const HS_FRAG_BODY_MAX: usize = PACKET_SIZE - HS_FRAG_HEADER_LEN;

/// X25519 public key size on the wire.
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
/// Finished MAC length in M3.
pub const FINISHED_MAC_LEN: usize = 16;

/// M1 ClientHello body length: 4534 bytes.
pub const M1_BODY_LEN: usize = VERSION_LEN
    + SESSION_ID_LEN
    + ML_KEM_768_PUBLIC_KEY_BYTES
    + X25519_PUBLIC_KEY_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;
/// M2 ServerHello body length: 5622 bytes.
pub const M2_BODY_LEN: usize = VERSION_LEN
    + SESSION_ID_LEN
    + ML_KEM_768_PUBLIC_KEY_BYTES
    + X25519_PUBLIC_KEY_BYTES
    + ML_KEM_768_CIPHERTEXT_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;
/// M3 ClientConfirm body length: 1113 bytes.
pub const M3_BODY_LEN: usize =
    VERSION_LEN + SESSION_ID_LEN + ML_KEM_768_CIPHERTEXT_BYTES + FINISHED_MAC_LEN;

/// Fragment counts (pinned by the message sizes above).
pub const M1_FRAG_COUNT: u8 = 4;
/// Fragment counts (pinned by the message sizes above).
pub const M2_FRAG_COUNT: u8 = 5;
/// Fragment counts (pinned by the message sizes above).
pub const M3_FRAG_COUNT: u8 = 1;

/// Canonical transcript domain string (D13).
pub const HANDSHAKE_DOMAIN: &[u8] = b"pq-tunnel-v1";

// Message sizes must partition into exactly the pinned fragment counts.
const _: () = assert!(
    M1_BODY_LEN > (M1_FRAG_COUNT as usize - 1) * HS_FRAG_BODY_MAX
        && M1_BODY_LEN <= M1_FRAG_COUNT as usize * HS_FRAG_BODY_MAX,
    "M1 must need exactly 4 fragments"
);
const _: () = assert!(
    M2_BODY_LEN > (M2_FRAG_COUNT as usize - 1) * HS_FRAG_BODY_MAX
        && M2_BODY_LEN <= M2_FRAG_COUNT as usize * HS_FRAG_BODY_MAX,
    "M2 must need exactly 5 fragments"
);
const _: () = assert!(
    M3_BODY_LEN <= M3_FRAG_COUNT as usize * HS_FRAG_BODY_MAX,
    "M3 must fit in 1 fragment"
);
const _: () = assert!(
    M1_BODY_LEN == 4534 && M2_BODY_LEN == 5622 && M3_BODY_LEN == 1113,
    "D13 message sizes are pinned"
);
const _: () = assert!(
    crate::codec::MessageType::Close.as_u8() < HS_TYPE_CLIENT_HELLO,
    "hs_type must be byte-disjoint from codec MessageType (0x00-0x03)"
);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by the v2 handshake.
///
/// Peer-input failures (malformed fragments, failed verification, forged
/// Finished) are **silent drops** — they surface as `ServerEvent::None` /
/// `ClientEvent::None`, never as errors, and never as emitted datagrams
/// (D12/D13: no error oracle, no amplification).  This enum covers local
/// failures only.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeV2Error {
    /// Transport-level failure (socket error etc.).  Fatal for the handshake.
    #[error("transport: {0}")]
    Transport(String),
    /// A datagram was rejected at the transport layer (wrong size) — skip and
    /// continue; not fatal.  Drivers MUST treat this as a silent drop.
    #[error("datagram rejected by transport (skipped)")]
    DatagramRejected,
    /// Packet codec failure.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// Local cryptographic failure (key generation, derivation).  Fatal.
    #[error("crypto: {0}")]
    Crypto(#[from] pq_crypto::CryptoError),
    /// The retransmit budget was exhausted before the peer's expected message
    /// arrived.
    #[error("handshake timeout")]
    Timeout,
    /// Invalid local configuration (e.g. version mismatch).  Fail closed.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// Result of a completed v2 handshake: the session master plus the verified
/// peer identity.
///
/// Secret-bearing: the `master` is zeroized on drop.  `peer_identity` is the
/// *pinned* peer key that authenticated the exchange (the client's configured
/// server key, or the server's matched roster key) — identity keys are never
/// transmitted on the wire (D12).
#[derive(Clone)]
pub struct HandshakeOutcome {
    /// Session master secret (D14; zeroized on drop, never retained for rekey).
    pub master: MasterSecret,
    /// The client-chosen, server-echoed session identifier (D13).
    pub session_id: [u8; SESSION_ID_LEN],
    /// The verified peer's identity public key (never on the wire).
    pub peer_identity: MlDsaPublicKey,
    /// Wall-clock duration of the establishment phase.
    pub handshake_duration: Duration,
}

impl fmt::Debug for HandshakeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeOutcome")
            .field("session_id", &self.session_id)
            .field("peer_identity", &"<redacted>")
            .field("handshake_duration", &self.handshake_duration)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Fragment framing
// ---------------------------------------------------------------------------

/// Expected fragment count for a handshake message type (pinned, D13).
pub fn expected_frag_count(hs_type: u8) -> Option<u8> {
    match hs_type {
        HS_TYPE_CLIENT_HELLO => Some(M1_FRAG_COUNT),
        HS_TYPE_SERVER_HELLO => Some(M2_FRAG_COUNT),
        HS_TYPE_CLIENT_CONFIRM => Some(M3_FRAG_COUNT),
        _ => None,
    }
}

/// Full message body length for a handshake message type (pinned, D13).
pub fn message_body_len(hs_type: u8) -> Option<usize> {
    match hs_type {
        HS_TYPE_CLIENT_HELLO => Some(M1_BODY_LEN),
        HS_TYPE_SERVER_HELLO => Some(M2_BODY_LEN),
        HS_TYPE_CLIENT_CONFIRM => Some(M3_BODY_LEN),
        _ => None,
    }
}

/// Dispatch: is this datagram a handshake fragment rather than a data packet?
///
/// Pinned rule: byte 9 (`VERSION_LEN + SESSION_ID_LEN`) selects the path.
/// `0x10`/`0x20`/`0x30` → handshake; anything else → data path.  See the
/// module docs for the (unreachable-in-practice) data-counter caveat.
pub fn is_handshake_fragment(pkt: &WirePacket) -> bool {
    matches!(
        pkt.as_bytes()[VERSION_LEN + SESSION_ID_LEN],
        HS_TYPE_CLIENT_HELLO | HS_TYPE_SERVER_HELLO | HS_TYPE_CLIENT_CONFIRM
    )
}

/// A parsed handshake fragment (header + body slice of the message).
///
/// Structural validation is strict (D13): version equality, known `hs_type`,
/// `frag_total` equal to the pinned count for the type, `frag_idx <
/// frag_total`, and a body length computed from the pinned message size — so
/// an arbitrary datagram can never be interpreted as a valid fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFragment {
    /// Must equal [`PROTOCOL_VERSION`] (validated on decode).
    pub version: u8,
    /// Session identifier (client-chosen, echoed by the server).
    pub sid: [u8; SESSION_ID_LEN],
    /// One of [`HS_TYPE_CLIENT_HELLO`], [`HS_TYPE_SERVER_HELLO`],
    /// [`HS_TYPE_CLIENT_CONFIRM`].
    pub hs_type: u8,
    /// Zero-based fragment index.
    pub frag_idx: u8,
    /// Total fragment count (pinned per type).
    pub frag_total: u8,
    /// This fragment's slice of the message body.
    pub body: Vec<u8>,
}

impl HandshakeFragment {
    /// Strictly parse and validate a fragment from a 1280-byte datagram.
    ///
    /// Any malformed structure returns `Err`; callers MUST drop silently.
    pub fn from_datagram(pkt: &WirePacket) -> Result<Self, CodecError> {
        let bytes = pkt.as_bytes();
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&bytes[VERSION_LEN..VERSION_LEN + SESSION_ID_LEN]);
        let hs_type = bytes[VERSION_LEN + SESSION_ID_LEN];
        let frag_idx = bytes[VERSION_LEN + SESSION_ID_LEN + 1];
        let frag_total = bytes[VERSION_LEN + SESSION_ID_LEN + 2];

        let expected =
            expected_frag_count(hs_type).ok_or(CodecError::InvalidMessageType(hs_type))?;
        if frag_total != expected {
            return Err(CodecError::Truncated {
                field: "frag_total",
                min: expected as usize,
                got: frag_total as usize,
            });
        }
        if frag_idx >= frag_total {
            return Err(CodecError::Truncated {
                field: "frag_idx",
                min: frag_total as usize,
                got: frag_idx as usize,
            });
        }
        let msg_len = message_body_len(hs_type).expect("hs_type validated above");
        let start = frag_idx as usize * HS_FRAG_BODY_MAX;
        let body_len = (msg_len - start).min(HS_FRAG_BODY_MAX);
        // Compile-time asserts guarantee start < msg_len for frag_idx < frag_total,
        // so body_len > 0 and start + body_len <= msg_len <= HS_FRAG_BODY_MAX * total.
        let body = bytes[HS_FRAG_HEADER_LEN..HS_FRAG_HEADER_LEN + body_len].to_vec();
        Ok(Self {
            version,
            sid,
            hs_type,
            frag_idx,
            frag_total,
            body,
        })
    }
}

/// Deterministically fragment a full handshake message into 1280-byte
/// datagrams (zero-padded to `PACKET_SIZE`).
///
/// Deterministic ⇒ retransmits are byte-identical (D13 client-driven
/// retransmission).  `hs_type` must be one of the pinned types.
pub fn fragment_message(
    hs_type: u8,
    version: u8,
    sid: [u8; SESSION_ID_LEN],
    message: &[u8],
) -> Result<Vec<WirePacket>, CodecError> {
    let total = expected_frag_count(hs_type).ok_or(CodecError::InvalidMessageType(hs_type))?;
    let msg_len = message_body_len(hs_type).expect("hs_type validated above");
    if message.len() != msg_len {
        return Err(CodecError::WrongLength {
            field: "handshake message",
            expected: msg_len,
            got: message.len(),
        });
    }
    let mut out = Vec::with_capacity(total as usize);
    for idx in 0..total {
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = version;
        dg[VERSION_LEN..VERSION_LEN + SESSION_ID_LEN].copy_from_slice(&sid);
        dg[VERSION_LEN + SESSION_ID_LEN] = hs_type;
        dg[VERSION_LEN + SESSION_ID_LEN + 1] = idx;
        dg[VERSION_LEN + SESSION_ID_LEN + 2] = total;
        let start = idx as usize * HS_FRAG_BODY_MAX;
        let end = (start + HS_FRAG_BODY_MAX).min(message.len());
        dg[HS_FRAG_HEADER_LEN..HS_FRAG_HEADER_LEN + (end - start)]
            .copy_from_slice(&message[start..end]);
        out.push(WirePacket::from_bytes(&dg).expect("1280-byte buffer always parses"));
    }
    Ok(out)
}

/// Result of feeding one fragment into a `FragmentAssembler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentResult {
    /// No state change (duplicate, inconsistent, or already complete).
    Ignored,
    /// New data accepted; the message is not yet complete.
    Advanced,
    /// The message became complete on this fragment.
    Completed,
}

/// Order-independent fragment reassembly for one handshake message.
///
/// Allocates its (bounded, ≤5622-byte) buffer at construction — callers MUST
/// create one only on a validated fragment 0 arrival (D13 DoS pin), and purge
/// on failure.
#[derive(Debug)]
pub struct FragmentAssembler {
    hs_type: u8,
    total: u8,
    received: [bool; M2_FRAG_COUNT as usize],
    buffer: Vec<u8>,
    complete: bool,
}

impl FragmentAssembler {
    /// Create an assembler for a message type; `None` for an unknown type.
    pub fn new(hs_type: u8) -> Option<Self> {
        let total = expected_frag_count(hs_type)?;
        let msg_len = message_body_len(hs_type)?;
        Some(Self {
            hs_type,
            total,
            received: [false; M2_FRAG_COUNT as usize],
            buffer: vec![0u8; msg_len],
            complete: false,
        })
    }

    /// Add a fragment; see [`FragmentResult`].
    ///
    /// Duplicate fragments are ignored (no state change).  Structurally
    /// inconsistent fragments are ignored defensively (the caller's
    /// `HandshakeFragment` parse already enforces the pinned structure).
    pub fn add_fragment(&mut self, frag: &HandshakeFragment) -> FragmentResult {
        if self.complete || frag.hs_type != self.hs_type || frag.frag_total != self.total {
            return FragmentResult::Ignored;
        }
        let idx = frag.frag_idx as usize;
        if idx >= self.total as usize || self.received[idx] {
            return FragmentResult::Ignored;
        }
        let start = idx * HS_FRAG_BODY_MAX;
        let end = start + frag.body.len();
        if end > self.buffer.len() {
            return FragmentResult::Ignored;
        }
        self.received[idx] = true;
        self.buffer[start..end].copy_from_slice(&frag.body);
        // Completion is judged over `total` slots only: the backing array is
        // sized for the largest message (M2), so shorter messages must not be
        // blocked by never-received trailing slots.
        if self.received[..self.total as usize].iter().all(|&r| r) {
            self.complete = true;
            FragmentResult::Completed
        } else {
            FragmentResult::Advanced
        }
    }

    /// The fully assembled message, once complete.
    pub fn message(&self) -> Option<&[u8]> {
        self.complete.then_some(self.buffer.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Message codec (D13 layouts)
// ---------------------------------------------------------------------------

/// Encode an M1 ClientHello body; `sig = None` zero-fills the signature slot
/// (the pre-sign canonical form used to compute TH1).
fn encode_m1(
    version: u8,
    sid: [u8; SESSION_ID_LEN],
    eph_pk_c: &MlKemPublicKey,
    x_c: &[u8; X25519_PUBLIC_KEY_BYTES],
    sig: Option<&MlDsaSignature>,
) -> [u8; M1_BODY_LEN] {
    let mut out = [0u8; M1_BODY_LEN];
    out[0] = version;
    out[VERSION_LEN..VERSION_LEN + SESSION_ID_LEN].copy_from_slice(&sid);
    let pk = eph_pk_c.to_bytes();
    out[9..9 + ML_KEM_768_PUBLIC_KEY_BYTES].copy_from_slice(&pk);
    out[9 + ML_KEM_768_PUBLIC_KEY_BYTES..9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32].copy_from_slice(x_c);
    if let Some(s) = sig {
        out[M1_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..].copy_from_slice(&s.encode());
    }
    out
}

/// M1 ClientHello (D13): `VERSION(1) ‖ SID(8) ‖ eph_pk_c(1184) ‖ x_c(32) ‖ client_sig(3309)`.
#[derive(Clone)]
pub struct ClientHello {
    pub version: u8,
    pub sid: [u8; SESSION_ID_LEN],
    pub eph_pk_c: MlKemPublicKey,
    pub x_c: [u8; X25519_PUBLIC_KEY_BYTES],
    pub client_sig: MlDsaSignature,
}

impl ClientHello {
    pub fn encode(&self) -> [u8; M1_BODY_LEN] {
        encode_m1(
            self.version,
            self.sid,
            &self.eph_pk_c,
            &self.x_c,
            Some(&self.client_sig),
        )
    }

    /// Strict decode; rejects wrong length and wrong version (D13 strict
    /// equality — the version byte is the full profile selector).
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != M1_BODY_LEN {
            return Err(CodecError::Truncated {
                field: "ClientHello",
                min: M1_BODY_LEN,
                got: data.len(),
            });
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&data[1..9]);
        let eph_pk_c = MlKemPublicKey::from_bytes(&data[9..9 + ML_KEM_768_PUBLIC_KEY_BYTES])?;
        let mut x_c = [0u8; X25519_PUBLIC_KEY_BYTES];
        x_c.copy_from_slice(
            &data[9 + ML_KEM_768_PUBLIC_KEY_BYTES..M1_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES],
        );
        let client_sig =
            MlDsaSignature::from_bytes(&data[M1_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..])?;
        Ok(Self {
            version,
            sid,
            eph_pk_c,
            x_c,
            client_sig,
        })
    }
}

/// Encode an M2 ServerHello body; `sig = None` zero-fills the signature slot
/// (the canonical form used to compute TH2 before signing).
fn encode_m2(
    version: u8,
    sid: [u8; SESSION_ID_LEN],
    eph_pk_s: &MlKemPublicKey,
    x_s: &[u8; X25519_PUBLIC_KEY_BYTES],
    ct2: &MlKemCiphertext,
    sig: Option<&MlDsaSignature>,
) -> [u8; M2_BODY_LEN] {
    let mut out = [0u8; M2_BODY_LEN];
    out[0] = version;
    out[VERSION_LEN..VERSION_LEN + SESSION_ID_LEN].copy_from_slice(&sid);
    let pk = eph_pk_s.to_bytes();
    out[9..9 + ML_KEM_768_PUBLIC_KEY_BYTES].copy_from_slice(&pk);
    out[9 + ML_KEM_768_PUBLIC_KEY_BYTES..9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32].copy_from_slice(x_s);
    let ct = ct2.to_bytes();
    out[9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32
        ..9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32 + ML_KEM_768_CIPHERTEXT_BYTES]
        .copy_from_slice(&ct);
    if let Some(s) = sig {
        out[M2_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..].copy_from_slice(&s.encode());
    }
    out
}

/// M2 ServerHello (D13): `VERSION(1) ‖ SID(8) ‖ eph_pk_s(1184) ‖ x_s(32) ‖ ct2(1088) ‖ server_sig(3309)`.
#[derive(Clone)]
pub struct ServerHello {
    pub version: u8,
    pub sid: [u8; SESSION_ID_LEN],
    pub eph_pk_s: MlKemPublicKey,
    pub x_s: [u8; X25519_PUBLIC_KEY_BYTES],
    pub ct2: MlKemCiphertext,
    pub server_sig: MlDsaSignature,
}

impl ServerHello {
    pub fn encode(&self) -> [u8; M2_BODY_LEN] {
        encode_m2(
            self.version,
            self.sid,
            &self.eph_pk_s,
            &self.x_s,
            &self.ct2,
            Some(&self.server_sig),
        )
    }

    /// Strict decode; rejects wrong length and wrong version.
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != M2_BODY_LEN {
            return Err(CodecError::Truncated {
                field: "ServerHello",
                min: M2_BODY_LEN,
                got: data.len(),
            });
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&data[1..9]);
        let eph_pk_s = MlKemPublicKey::from_bytes(&data[9..9 + ML_KEM_768_PUBLIC_KEY_BYTES])?;
        let mut x_s = [0u8; X25519_PUBLIC_KEY_BYTES];
        x_s.copy_from_slice(
            &data[9 + ML_KEM_768_PUBLIC_KEY_BYTES..9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32],
        );
        let ct2 = MlKemCiphertext::from_bytes(
            &data[9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32
                ..9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32 + ML_KEM_768_CIPHERTEXT_BYTES],
        )?;
        let server_sig =
            MlDsaSignature::from_bytes(&data[M2_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..])?;
        Ok(Self {
            version,
            sid,
            eph_pk_s,
            x_s,
            ct2,
            server_sig,
        })
    }
}

/// Encode an M3 ClientConfirm body; `finished = None` zero-fills the MAC slot
/// (the canonical form used to compute TH3 before the MAC).
fn encode_m3(
    version: u8,
    sid: [u8; SESSION_ID_LEN],
    ct3: &MlKemCiphertext,
    finished: Option<&[u8; FINISHED_MAC_LEN]>,
) -> [u8; M3_BODY_LEN] {
    let mut out = [0u8; M3_BODY_LEN];
    out[0] = version;
    out[VERSION_LEN..VERSION_LEN + SESSION_ID_LEN].copy_from_slice(&sid);
    let ct = ct3.to_bytes();
    out[9..9 + ML_KEM_768_CIPHERTEXT_BYTES].copy_from_slice(&ct);
    if let Some(m) = finished {
        out[M3_BODY_LEN - FINISHED_MAC_LEN..].copy_from_slice(m);
    }
    out
}

/// M3 ClientConfirm (D13/D15): `VERSION(1) ‖ SID(8) ‖ ct3(1088) ‖ client_finished(16)`.
#[derive(Clone)]
pub struct ClientConfirm {
    pub version: u8,
    pub sid: [u8; SESSION_ID_LEN],
    pub ct3: MlKemCiphertext,
    pub client_finished: [u8; FINISHED_MAC_LEN],
}

impl ClientConfirm {
    pub fn encode(&self) -> [u8; M3_BODY_LEN] {
        encode_m3(
            self.version,
            self.sid,
            &self.ct3,
            Some(&self.client_finished),
        )
    }

    /// Strict decode; rejects wrong length and wrong version.
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != M3_BODY_LEN {
            return Err(CodecError::Truncated {
                field: "ClientConfirm",
                min: M3_BODY_LEN,
                got: data.len(),
            });
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                found: version,
            });
        }
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&data[1..9]);
        let ct3 = MlKemCiphertext::from_bytes(&data[9..9 + ML_KEM_768_CIPHERTEXT_BYTES])?;
        let mut client_finished = [0u8; FINISHED_MAC_LEN];
        client_finished.copy_from_slice(&data[M3_BODY_LEN - FINISHED_MAC_LEN..]);
        Ok(Self {
            version,
            sid,
            ct3,
            client_finished,
        })
    }
}

// ---------------------------------------------------------------------------
// Canonical transcript (D13)
// ---------------------------------------------------------------------------

/// Canonical form of a message for hashing: the full message bytes with the
/// signature (M1/M2) or Finished MAC (M3) slot zero-filled (D13: padding
/// excluded, signature slots zero-filled, fragment headers never hashed).
fn canonical_zerofill(hs_type: u8, message: &[u8]) -> Option<Vec<u8>> {
    let slot = match hs_type {
        HS_TYPE_CLIENT_HELLO | HS_TYPE_SERVER_HELLO => ML_DSA_65_SIGNATURE_BYTES,
        HS_TYPE_CLIENT_CONFIRM => FINISHED_MAC_LEN,
        _ => return None,
    };
    let len = message_body_len(hs_type)?;
    if message.len() != len {
        return None;
    }
    let mut out = message.to_vec();
    for b in &mut out[len - slot..] {
        *b = 0;
    }
    Some(out)
}

fn hash_with_domain(parts: &[Vec<u8>]) -> [u8; 32] {
    let mut t = pq_crypto::Transcript::new_with_initial(HANDSHAKE_DOMAIN);
    for p in parts {
        t.update(p);
    }
    t.into_bytes()
}

/// `TH1 = SHA256(dom ‖ M1_z)` — the digest the client signs (D13).
///
/// `M1_z` is the ClientHello with the signature slot zero-filled, so this
/// accepts either the pre-sign or the full message.
pub fn th1_from_m1(m1: &[u8]) -> Option<[u8; 32]> {
    let canon = canonical_zerofill(HS_TYPE_CLIENT_HELLO, m1)?;
    Some(hash_with_domain(&[canon]))
}

/// `TH2 = SHA256(dom ‖ M1_s ‖ M2_z)` — the digest the server signs (D13).
///
/// `M1_s` is the full M1 *with* the client signature; `M2_z` is the M2 with
/// the signature slot zero-filled.  Full M2 coverage is mandatory.
pub fn th2_from_m1_m2(m1_s: &[u8], m2: &[u8]) -> Option<[u8; 32]> {
    if m1_s.len() != M1_BODY_LEN {
        return None;
    }
    let m2_z = canonical_zerofill(HS_TYPE_SERVER_HELLO, m2)?;
    Some(hash_with_domain(&[m1_s.to_vec(), m2_z]))
}

/// `TH3 = SHA256(dom ‖ M1_z ‖ M2_z ‖ M3_z)` — bound into the master
/// derivation and the Finished MAC (D13/D15).
pub fn th3_from_m1_m2_m3(m1: &[u8], m2: &[u8], m3: &[u8]) -> Option<[u8; 32]> {
    let m1_z = canonical_zerofill(HS_TYPE_CLIENT_HELLO, m1)?;
    let m2_z = canonical_zerofill(HS_TYPE_SERVER_HELLO, m2)?;
    let m3_z = canonical_zerofill(HS_TYPE_CLIENT_CONFIRM, m3)?;
    Some(hash_with_domain(&[m1_z, m2_z, m3_z]))
}

/// Derive the session master from the three ephemeral shared secrets
/// (D13/D14); the ikm staging is zeroized inside `pq_crypto::kdf`.
fn derive_master(
    ss_a: &[u8; 32],
    ss_b: &[u8; 32],
    dh_cs: &[u8; 32],
    version: u8,
    sid: &[u8; SESSION_ID_LEN],
    th3: &[u8; 32],
) -> Result<MasterSecret, HandshakeV2Error> {
    Ok(derive_master_secret_v2(
        ss_a, ss_b, dh_cs, version, sid, th3,
    )?)
}

// ---------------------------------------------------------------------------
// Transport abstraction
// ---------------------------------------------------------------------------

/// Transport contract for the handshake drivers.
///
/// Implemented by [`UdpTransport`] (one 1280-byte datagram per packet).  The
/// v1 drivers are per-handshake: the client talks to `ClientConfig::server_addr`,
/// the server replies to each datagram's source.  A wrong-size datagram MUST be
/// surfaced as [`HandshakeV2Error::DatagramRejected`] so drivers can skip
/// background noise without aborting.
///
/// NOTE: The async-trait style here is intentional — the driver layer awaits
/// these methods directly and the current transports happen to yield `Send`
/// futures. The `async_fn_in_trait` lint (a rustc builtin that clippy also
/// reports) is allowed rather than suppressing the design; if auto-trait
/// bounds or object safety become a requirement, revisit how to express them
/// before the 1.0 API freeze.
#[allow(async_fn_in_trait)]
pub trait HandshakeTransport {
    /// Send one fixed-size packet to `peer`.
    async fn send_to(
        &mut self,
        packet: &WirePacket,
        peer: SocketAddr,
    ) -> Result<(), HandshakeV2Error>;
    /// Receive one fixed-size packet plus its source.
    async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error>;
}

impl HandshakeTransport for UdpTransport {
    async fn send_to(
        &mut self,
        packet: &WirePacket,
        peer: SocketAddr,
    ) -> Result<(), HandshakeV2Error> {
        UdpTransport::send_to(self, packet, peer)
            .await
            .map_err(|e| HandshakeV2Error::Transport(e.to_string()))
    }

    async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error> {
        match UdpTransport::recv(self).await {
            Ok(v) => Ok(v),
            Err(crate::udp::UdpError::WrongSize { .. }) => Err(HandshakeV2Error::DatagramRejected),
            Err(e) => Err(HandshakeV2Error::Transport(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn jittered(base: Duration) -> Duration {
    // ±20% uniform jitter: base * (0.8..=1.2)
    let nanos = base.as_nanos();
    let factor = 80 + (getrandom::u64().unwrap_or(0) % 40) as u128;
    Duration::from_nanos((nanos * factor / 100).try_into().unwrap_or(u64::MAX))
}

fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    // Exponential backoff, capped at 32× base.
    let shift = attempt.min(5);
    jittered(base.saturating_mul(1u32 << shift))
}

pub(crate) fn random_sid() -> Result<[u8; SESSION_ID_LEN], HandshakeV2Error> {
    let mut sid = [0u8; SESSION_ID_LEN];
    getrandom::fill(&mut sid).map_err(|e| {
        HandshakeV2Error::Crypto(pq_crypto::CryptoError::InvalidInput(format!(
            "getrandom: {e}"
        )))
    })?;
    Ok(sid)
}

fn validate_version(version: u8) -> Result<(), HandshakeV2Error> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(HandshakeV2Error::InvalidConfig(format!(
            "version {version} unsupported (expected {PROTOCOL_VERSION})"
        )))
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client handshake configuration (D12/D13).
///
/// `identity` is the client's static ML-DSA-65 identity key; `server_identity`
/// is the server's key pinned out of band.  Identity keys never appear on the
/// wire.
#[derive(Clone)]
pub struct ClientConfig {
    /// Protocol version; must equal [`PROTOCOL_VERSION`] (strict, no
    /// negotiation — D13).
    pub version: u8,
    /// The server endpoint datagrams are sent to.
    pub server_addr: SocketAddr,
    /// This client's static identity key.
    pub identity: MlDsaKeypair,
    /// The server's pinned identity public key.
    pub server_identity: MlDsaPublicKey,
    /// Base retransmit delay for M1 (jittered, exponential backoff).
    pub m1_retransmit_base: Duration,
    /// Maximum M1 retransmissions before giving up.
    pub m1_max_attempts: u32,
    /// Maximum M3 retransmissions after the first send.
    pub m3_max_attempts: u32,
}

impl ClientConfig {
    /// Construct with protocol defaults (timing parameters are tunable — D7).
    pub fn new(
        server_addr: SocketAddr,
        identity: MlDsaKeypair,
        server_identity: MlDsaPublicKey,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            server_addr,
            identity,
            server_identity,
            m1_retransmit_base: Duration::from_millis(250),
            m1_max_attempts: 8,
            m3_max_attempts: 8,
        }
    }
}

/// Event produced by the client state machine: datagrams to emit, or
/// completion.
#[derive(Debug)]
pub enum ClientEvent {
    /// Emit these datagrams (byte-identical retransmit or the M3).
    Emit(Vec<WirePacket>),
    /// Handshake complete: the client is ready (1 RTT; server confirmation is
    /// implicit — D15; liveness enforcement is the session layer's job).
    Complete(HandshakeOutcome),
    /// Nothing to do — silent drop, no state change.
    None,
}

enum ClientState {
    AwaitM2 {
        assembler: FragmentAssembler,
        attempts: u32,
        next_delay: Duration,
    },
    M3Sent {
        m3_frags: Vec<WirePacket>,
        attempts: u32,
        next_delay: Duration,
        outcome: HandshakeOutcome,
    },
}

/// Client-side handshake state machine.
///
/// Pure with respect to I/O: `handle_datagram`/`on_timer` only compute and
/// return events; the driver performs the actual sends.  This makes the
/// receive path directly fuzzable.
pub struct ClientHandshake {
    cfg: ClientConfig,
    sid: [u8; SESSION_ID_LEN],
    kp_mlkem: MlKemKeypair,
    kp_x: X25519Keypair,
    m1: ClientHello,
    m1_frags: Vec<WirePacket>,
    state: ClientState,
}

impl ClientHandshake {
    /// Build the client side with an explicit session identifier (injectable
    /// for tests; production callers use `client_handshake_v2`, which draws a
    /// CSPRNG sid).
    pub fn new(cfg: &ClientConfig, sid: [u8; SESSION_ID_LEN]) -> Result<Self, HandshakeV2Error> {
        validate_version(cfg.version)?;
        let kp_mlkem = MlKemKeypair::generate()?;
        let kp_x = X25519Keypair::generate();
        let x_c = kp_x.public.to_bytes();

        let pre_sign = encode_m1(cfg.version, sid, &kp_mlkem.public, &x_c, None);
        let th1_d = th1_from_m1(&pre_sign).expect("fixed-length M1");
        let client_sig = cfg.identity.sign(&th1_d)?;

        let m1 = ClientHello {
            version: cfg.version,
            sid,
            eph_pk_c: kp_mlkem.public.clone(),
            x_c,
            client_sig,
        };
        let m1_frags = fragment_message(HS_TYPE_CLIENT_HELLO, cfg.version, sid, &m1.encode())?;
        let assembler =
            FragmentAssembler::new(HS_TYPE_SERVER_HELLO).expect("known hs_type (M2 assembler)");
        Ok(Self {
            cfg: cfg.clone(),
            sid,
            kp_mlkem,
            kp_x,
            m1,
            m1_frags,
            state: ClientState::AwaitM2 {
                assembler,
                attempts: 0,
                next_delay: jittered(cfg.m1_retransmit_base),
            },
        })
    }

    /// The M1 fragment datagrams (cached for byte-identical retransmission).
    pub fn m1_frags(&self) -> &[WirePacket] {
        &self.m1_frags
    }

    /// The M3 fragment datagrams once the client has reached `M3Sent`.
    pub fn m3_frags(&self) -> &[WirePacket] {
        match &self.state {
            ClientState::M3Sent { m3_frags, .. } => m3_frags,
            ClientState::AwaitM2 { .. } => &[],
        }
    }

    /// Current retransmit delay (for the driver's timer).
    pub fn next_delay(&self) -> Duration {
        match &self.state {
            ClientState::AwaitM2 { next_delay, .. } | ClientState::M3Sent { next_delay, .. } => {
                *next_delay
            }
        }
    }

    /// The client-chosen session identifier.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.sid
    }

    /// Process one received datagram (silent drop on anything irrelevant).
    pub fn handle_datagram(&mut self, pkt: &WirePacket) -> Result<ClientEvent, HandshakeV2Error> {
        if pkt.as_bytes()[VERSION_LEN + SESSION_ID_LEN] != HS_TYPE_SERVER_HELLO {
            // Data packets, foreign M1/M3 fragments, junk — silent (D13).
            return Ok(ClientEvent::None);
        }
        let frag = match HandshakeFragment::from_datagram(pkt) {
            Ok(f) => f,
            Err(_) => return Ok(ClientEvent::None),
        };
        if frag.sid != self.sid {
            return Ok(ClientEvent::None);
        }
        match &mut self.state {
            ClientState::AwaitM2 { assembler, .. } => {
                if assembler.add_fragment(&frag) != FragmentResult::Completed {
                    return Ok(ClientEvent::None);
                }
                let m2_bytes = assembler.message().expect("complete").to_vec();
                self.on_complete_m2(m2_bytes)
            }
            ClientState::M3Sent { .. } => Ok(ClientEvent::None),
        }
    }

    /// Retransmit timer tick (byte-identical retransmission with jittered
    /// exponential backoff and bounded budgets — D13).
    pub fn on_timer(&mut self) -> Result<ClientEvent, HandshakeV2Error> {
        match &mut self.state {
            ClientState::AwaitM2 {
                attempts,
                next_delay,
                ..
            } => {
                if *attempts >= self.cfg.m1_max_attempts {
                    return Err(HandshakeV2Error::Timeout);
                }
                *attempts += 1;
                *next_delay = backoff_delay(self.cfg.m1_retransmit_base, *attempts);
                Ok(ClientEvent::Emit(self.m1_frags.clone()))
            }
            ClientState::M3Sent {
                attempts,
                next_delay,
                m3_frags,
                outcome,
            } => {
                if *attempts >= self.cfg.m3_max_attempts {
                    // M3 budget exhausted: the client is ready (1 RTT); any
                    // mis-keying is caught by the session layer's liveness
                    // timeout (D15).
                    return Ok(ClientEvent::Complete(outcome.clone()));
                }
                *attempts += 1;
                *next_delay = backoff_delay(self.cfg.m1_retransmit_base, *attempts);
                Ok(ClientEvent::Emit(m3_frags.clone()))
            }
        }
    }

    fn reset_m2_assembler(&mut self) {
        if let ClientState::AwaitM2 { assembler, .. } = &mut self.state {
            *assembler =
                FragmentAssembler::new(HS_TYPE_SERVER_HELLO).expect("known hs_type (M2 assembler)");
        }
    }

    fn on_complete_m2(&mut self, m2_bytes: Vec<u8>) -> Result<ClientEvent, HandshakeV2Error> {
        let m2 = match ServerHello::decode(&m2_bytes) {
            Ok(m) => m,
            Err(_) => {
                // Corrupt M2: silent; allow a later (byte-identical) resend.
                self.reset_m2_assembler();
                return Ok(ClientEvent::None);
            }
        };
        if m2.sid != self.sid || m2.version != self.cfg.version {
            self.reset_m2_assembler();
            return Ok(ClientEvent::None);
        }
        let th2_d = th2_from_m1_m2(&self.m1.encode(), &m2_bytes).expect("fixed lengths");
        let ok = verify(&self.cfg.server_identity, &th2_d, &m2.server_sig)?;
        if !ok {
            // Signature failure is silent (D12) — no KEM work, no state change.
            self.reset_m2_assembler();
            return Ok(ClientEvent::None);
        }

        // KEM only after the server signature verifies (D13 order).
        let ss_a_ss = decapsulate(&self.kp_mlkem.secret, &m2.ct2)?;
        let (ss_b_ss, ct3) = encapsulate(&m2.eph_pk_s)?;
        let mut ss_a_b = ss_a_ss.as_bytes();
        let mut ss_b_b = ss_b_ss.as_bytes();
        let x_pk = X25519PublicKey::from(m2.x_s);
        let mut dh_cs = self.kp_x.diffie_hellman(&x_pk);

        let m3_z = encode_m3(self.cfg.version, self.sid, &ct3, None);
        let th3_d =
            th3_from_m1_m2_m3(&self.m1.encode(), &m2_bytes, &m3_z).expect("fixed message lengths");
        let master = derive_master(
            &ss_a_b,
            &ss_b_b,
            &dh_cs,
            self.cfg.version,
            &self.sid,
            &th3_d,
        )?;
        // Ephemeral share copies are zeroized after master derivation (D14).
        ss_a_b.zeroize();
        ss_b_b.zeroize();
        dh_cs.zeroize();

        let mut finished_key = derive_finished_key(&master, self.cfg.version, &self.sid)?;
        let finished = compute_client_finished(&finished_key, &th3_d);
        finished_key.zeroize();

        let m3 = ClientConfirm {
            version: self.cfg.version,
            sid: self.sid,
            ct3,
            client_finished: finished,
        };
        let m3_frags = fragment_message(
            HS_TYPE_CLIENT_CONFIRM,
            self.cfg.version,
            self.sid,
            &m3.encode(),
        )?;
        let outcome = HandshakeOutcome {
            master,
            session_id: self.sid,
            peer_identity: self.cfg.server_identity.clone(),
            handshake_duration: Duration::ZERO,
        };
        self.state = ClientState::M3Sent {
            attempts: 0,
            next_delay: jittered(self.cfg.m1_retransmit_base),
            m3_frags,
            outcome,
        };
        match &self.state {
            ClientState::M3Sent { m3_frags, .. } => Ok(ClientEvent::Emit(m3_frags.clone())),
            _ => unreachable!(),
        }
    }
}

/// Run the client side of the handshake over a transport.
///
/// Draws a CSPRNG sid, sends M1 (retransmitting byte-identically with jittered
/// backoff until M2 arrives or the budget is exhausted), then sends M3 and
/// returns the outcome (client ready at 1 RTT — D13; implicit server
/// confirmation + liveness is the session layer's responsibility — D15).
pub async fn client_handshake_v2<T: HandshakeTransport>(
    transport: &mut T,
    cfg: &ClientConfig,
) -> Result<HandshakeOutcome, HandshakeV2Error> {
    validate_version(cfg.version)?;
    let sid = random_sid()?;
    let mut h = ClientHandshake::new(cfg, sid)?;
    let started = Instant::now();
    for frag in &h.m1_frags {
        transport.send_to(frag, cfg.server_addr).await?;
    }
    loop {
        let delay = h.next_delay();
        tokio::select! {
            r = transport.recv() => {
                match r {
                    Err(HandshakeV2Error::DatagramRejected) => continue,
                    Err(e) => return Err(e),
                    Ok((pkt, _from)) => match h.handle_datagram(&pkt)? {
                        ClientEvent::Emit(frags) => {
                            for f in &frags { transport.send_to(f, cfg.server_addr).await?; }
                        }
                        ClientEvent::Complete(mut out) => {
                            out.handshake_duration = started.elapsed();
                            return Ok(out);
                        }
                        ClientEvent::None => {}
                    },
                }
            }
            _ = tokio::time::sleep(delay) => match h.on_timer()? {
                ClientEvent::Emit(frags) => {
                    for f in &frags { transport.send_to(f, cfg.server_addr).await?; }
                }
                ClientEvent::Complete(mut out) => {
                    out.handshake_duration = started.elapsed();
                    return Ok(out);
                }
                ClientEvent::None => {}
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Server handshake configuration (D12/D13).
#[derive(Clone)]
pub struct ServerConfig {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub version: u8,
    /// The server's static ML-DSA-65 identity key.
    pub identity: MlDsaKeypair,
    /// Pinned client identity public keys, provisioned out of band.  The
    /// client signature is verified against the entire roster with no early
    /// exit (D12); an empty roster fails closed.
    pub roster: Vec<MlDsaPublicKey>,
    /// Upper bound on concurrently pending handshakes (D13 DoS posture).
    pub max_pending: usize,
    /// Pending-entry lifetime before silent eviction (D13).
    pub pending_ttl: Duration,
    /// M1 fragment burst allowance per source per `rate_limit_window`.
    pub rate_limit_burst: u32,
    /// Rate-limit window for M1 fragments.
    pub rate_limit_window: Duration,
}

impl ServerConfig {
    /// Construct with protocol defaults (DoS parameters are tunable — D7).
    pub fn new(identity: MlDsaKeypair, roster: Vec<MlDsaPublicKey>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            identity,
            roster,
            max_pending: 64,
            pending_ttl: Duration::from_secs(30),
            rate_limit_burst: 16,
            rate_limit_window: Duration::from_secs(10),
        }
    }
}

/// Event produced by the server state machine.
#[derive(Debug)]
pub enum ServerEvent {
    /// Emit these datagrams to `peer` (M2 or a cached-M2 resend).
    Emit(Vec<WirePacket>, SocketAddr),
    /// Handshake complete: the M3 Finished MAC verified (1.5 RTT — D13).
    Complete(HandshakeOutcome),
    /// Nothing to do — silent drop, no state change.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingState {
    AwaitM1,
    AwaitM3,
}

/// Per-sid server-side handshake state.
///
/// Holds the ephemeral secrets (`ss_a`, `dh_cs`) across the M2→M3 gap; they
/// are zeroized when the entry drops (D14).  `m1_body`/`m2_cache` are the raw
/// message bytes (public material) used for the TH3 canonical form and the
/// byte-identical M2 resend.
struct PendingSession {
    source: SocketAddr,
    state: PendingState,
    assembler: Option<FragmentAssembler>,
    m1_body: Option<Vec<u8>>,
    m2_cache: Option<Vec<u8>>,
    last_seen: Instant,
    started: Instant,
    ss_a: [u8; 32],
    dh_cs: [u8; 32],
    sk_s: Option<MlKemSecretKey>,
    verified_client: Option<MlDsaPublicKey>,
}

impl PendingSession {
    fn new(source: SocketAddr, now: Instant, assembler: FragmentAssembler) -> Self {
        Self {
            source,
            state: PendingState::AwaitM1,
            assembler: Some(assembler),
            m1_body: None,
            m2_cache: None,
            last_seen: now,
            started: now,
            ss_a: [0u8; 32],
            dh_cs: [0u8; 32],
            sk_s: None,
            verified_client: None,
        }
    }
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        // Ephemeral handshake secrets must not outlive the pending entry
        // (CRYPTO_PROFILE §12, IMPLEMENTATION_GUIDE §6, D14).
        self.ss_a.zeroize();
        self.dh_cs.zeroize();
    }
}

struct RateBucket {
    tokens: u32,
    last_refill: Instant,
}

/// Absolute cap on per-source rate buckets: a spoofed-source flood must not
/// grow the table unboundedly (the window-based prune alone is evadable by
/// keeping buckets fresh).  At the cap, the stalest bucket is evicted.
const MAX_RATE_BUCKETS: usize = 4096;

/// Server-side handshake state machine (one per source in v1).
///
/// Pure with respect to I/O: `handle_datagram` only computes and returns
/// events; the driver performs the actual sends.  This makes the receive path
/// directly fuzzable.
pub struct ServerHandshake {
    cfg: ServerConfig,
    pending: HashMap<[u8; SESSION_ID_LEN], PendingSession>,
    rate_buckets: HashMap<SocketAddr, RateBucket>,
}

impl ServerHandshake {
    /// Create a server handshake state machine.  Configuration is validated
    /// by `server_handshake_v2` (empty roster / bad version fail closed).
    pub fn new(cfg: &ServerConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            pending: HashMap::new(),
            rate_buckets: HashMap::new(),
        }
    }

    /// Number of pending handshake entries (diagnostics).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Process one received datagram.  Any peer-input failure is a silent
    /// drop (`ServerEvent::None`) with no state mutation (D12/D13/D15).
    pub fn handle_datagram(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ServerEvent, HandshakeV2Error> {
        match pkt.as_bytes()[VERSION_LEN + SESSION_ID_LEN] {
            HS_TYPE_CLIENT_HELLO => self.on_m1_fragment(pkt, from),
            HS_TYPE_CLIENT_CONFIRM => self.on_m3_fragment(pkt, from),
            // Data packets / junk: the data path handles byte-9 ∉ {0x10,0x20,0x30}.
            _ => Ok(ServerEvent::None),
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        self.pending
            .retain(|_, e| now.duration_since(e.last_seen) < self.cfg.pending_ttl);
    }

    fn rate_ok(&mut self, from: SocketAddr) -> bool {
        let now = Instant::now();
        if self.rate_buckets.len() > 32 {
            // Bound the bucket table (per-source in v1; prune stale entries).
            self.rate_buckets
                .retain(|_, b| now.duration_since(b.last_refill) < self.cfg.rate_limit_window);
        }
        if self.rate_buckets.len() >= MAX_RATE_BUCKETS {
            // Hard cap: evict the stalest bucket so spoofed sources cannot
            // grow the table without bound, regardless of freshness.
            if let Some(stale) = self
                .rate_buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| *k)
            {
                self.rate_buckets.remove(&stale);
            }
        }
        let bucket = self.rate_buckets.entry(from).or_insert_with(|| RateBucket {
            tokens: self.cfg.rate_limit_burst,
            last_refill: now,
        });
        if now.duration_since(bucket.last_refill) >= self.cfg.rate_limit_window {
            bucket.tokens = self.cfg.rate_limit_burst;
            bucket.last_refill = now;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    fn on_m1_fragment(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ServerEvent, HandshakeV2Error> {
        let frag = match HandshakeFragment::from_datagram(pkt) {
            Ok(f) => f,
            Err(_) => return Ok(ServerEvent::None),
        };
        self.evict_expired(Instant::now());
        let sid = frag.sid;

        if self.pending.contains_key(&sid) {
            let entry = self.pending.get_mut(&sid).expect("checked");
            if entry.source != from {
                // sid collision across sources → reject the newcomer (D13).
                return Ok(ServerEvent::None);
            }
            let entry_state = entry.state;
            match entry_state {
                PendingState::AwaitM1 => {
                    let asm = entry.assembler.as_mut().expect("AwaitM1 has assembler");
                    match asm.add_fragment(&frag) {
                        FragmentResult::Completed => {
                            let m1_bytes = asm.message().expect("complete").to_vec();
                            // Expensive work (roster verify + KEM) is per-source
                            // budgeted like every other allocation (D13 DoS pin).
                            if !self.rate_ok(from) {
                                return Ok(ServerEvent::None);
                            }
                            self.complete_m1(sid, m1_bytes, from)
                        }
                        // Only state-advancing fragments extend the TTL; a
                        // duplicate flood cannot keep an entry alive.
                        FragmentResult::Advanced => {
                            entry.last_seen = Instant::now();
                            Ok(ServerEvent::None)
                        }
                        FragmentResult::Ignored => Ok(ServerEvent::None),
                    }
                }
                PendingState::AwaitM3 => {
                    if frag.frag_idx != 0 {
                        return Ok(ServerEvent::None);
                    }
                    let body = entry
                        .m2_cache
                        .as_ref()
                        .expect("AwaitM3 has M2 cache")
                        .clone();
                    let src = entry.source;
                    // Duplicate M1 → resend the cached M2 byte-identical (D13).
                    // Gated to fragment 0 so one retransmit burst yields ONE
                    // resend (no per-fragment 4×5 self-amplification), and
                    // per-source budgeted like everything else.
                    if !self.rate_ok(from) {
                        return Ok(ServerEvent::None);
                    }
                    let frags =
                        fragment_message(HS_TYPE_SERVER_HELLO, self.cfg.version, sid, &body)?;
                    Ok(ServerEvent::Emit(frags, src))
                }
            }
        } else {
            // New sid: no allocation before a validated fragment 0 (D13 pin),
            // and the allocation is per-source budgeted.
            if frag.frag_idx != 0 || !self.rate_ok(from) {
                return Ok(ServerEvent::None);
            }
            if self.pending.len() >= self.cfg.max_pending {
                return Ok(ServerEvent::None);
            }
            let now = Instant::now();
            let mut asm = match FragmentAssembler::new(HS_TYPE_CLIENT_HELLO) {
                Some(a) => a,
                None => return Ok(ServerEvent::None),
            };
            // M1 requires 4 fragments, so fragment 0 alone can never complete.
            asm.add_fragment(&frag);
            self.pending
                .insert(sid, PendingSession::new(from, now, asm));
            Ok(ServerEvent::None)
        }
    }

    /// Handle a fully assembled, verified M1: authenticate against the roster
    /// (uniform iteration, no early exit), then KEM and emit M2 (D12/D13).
    fn complete_m1(
        &mut self,
        sid: [u8; SESSION_ID_LEN],
        m1_bytes: Vec<u8>,
        from: SocketAddr,
    ) -> Result<ServerEvent, HandshakeV2Error> {
        let m1 = match ClientHello::decode(&m1_bytes) {
            Ok(m) => m,
            Err(_) => {
                self.pending.remove(&sid);
                return Ok(ServerEvent::None);
            }
        };
        if m1.version != self.cfg.version || m1.sid != sid {
            self.pending.remove(&sid);
            return Ok(ServerEvent::None);
        }
        let th1_d = th1_from_m1(&m1_bytes).expect("fixed-length M1");
        let mut authed = false;
        let mut matched: Option<MlDsaPublicKey> = None;
        for pk in &self.cfg.roster {
            let ok = verify(pk, &th1_d, &m1.client_sig)?;
            authed |= ok; // bitwise: uniform verification count (D12)
            if ok {
                matched = Some(pk.clone());
            }
        }
        if !authed {
            // Unknown client: hard, silent rejection — no M2, no state (D12).
            self.pending.remove(&sid);
            return Ok(ServerEvent::None);
        }

        // KEM only after the client signature verifies (D13 order).
        let ml_kp = MlKemKeypair::generate()?;
        let x_kp = X25519Keypair::generate();
        let x_s = x_kp.public.to_bytes();
        let (ss_a_ss, ct2) = encapsulate(&m1.eph_pk_c)?;
        let mut ss_a_b = ss_a_ss.as_bytes();
        let x_pk = X25519PublicKey::from(m1.x_c);
        let mut dh_cs = x_kp.diffie_hellman(&x_pk);

        let m2_z = encode_m2(self.cfg.version, sid, &ml_kp.public, &x_s, &ct2, None);
        let th2_d = th2_from_m1_m2(&m1_bytes, &m2_z).expect("fixed lengths");
        let server_sig = self.cfg.identity.sign(&th2_d)?;

        let m2 = ServerHello {
            version: self.cfg.version,
            sid,
            eph_pk_s: ml_kp.public,
            x_s,
            ct2,
            server_sig,
        };
        let m2_bytes = m2.encode();
        let frags = fragment_message(HS_TYPE_SERVER_HELLO, self.cfg.version, sid, &m2_bytes)?;

        let mut entry = self.pending.remove(&sid).expect("entry exists");
        entry.state = PendingState::AwaitM3;
        entry.m1_body = Some(m1_bytes);
        entry.m2_cache = Some(m2_bytes.to_vec());
        entry.ss_a = ss_a_b;
        entry.dh_cs = dh_cs;
        entry.sk_s = Some(ml_kp.secret);
        entry.verified_client = matched;
        entry.assembler = None;
        entry.last_seen = Instant::now();
        self.pending.insert(sid, entry);
        // The entry holds its own copies; wipe the ephemeral local copies now
        // that the secret material has been transferred (D14).
        ss_a_b.zeroize();
        dh_cs.zeroize();
        Ok(ServerEvent::Emit(frags, from))
    }

    fn on_m3_fragment(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ServerEvent, HandshakeV2Error> {
        let frag = match HandshakeFragment::from_datagram(pkt) {
            Ok(f) => f,
            Err(_) => return Ok(ServerEvent::None),
        };
        self.evict_expired(Instant::now());
        let sid = frag.sid;

        // D13 DoS posture: the M3 path burns asymmetric work (decapsulation,
        // HKDF, HMAC) before the MAC comparison can fail; gate per source
        // exactly like the M1 path so a forged-M3 flood costs the attacker's
        // own budget, not the server's CPU.  Gating happens before the entry
        // lookup so a spoofed-source flood cannot even reach the map.
        if !self.rate_ok(from) {
            return Ok(ServerEvent::None);
        }

        let entry = match self.pending.get_mut(&sid) {
            Some(e) => e,
            None => return Ok(ServerEvent::None), // unknown sid → silent
        };
        if entry.source != from || entry.state != PendingState::AwaitM3 {
            return Ok(ServerEvent::None);
        }
        let m3 = match ClientConfirm::decode(&frag.body) {
            Ok(m) => m,
            Err(_) => return Ok(ServerEvent::None),
        };
        if m3.version != self.cfg.version || m3.sid != sid {
            return Ok(ServerEvent::None);
        }

        let sk_s = match entry.sk_s.as_ref() {
            Some(s) => s,
            None => return Ok(ServerEvent::None),
        };
        let ss_b_ss = decapsulate(sk_s, &m3.ct3)?;
        let mut ss_b_b = ss_b_ss.as_bytes();

        let m1_body = entry.m1_body.as_ref().expect("set in AwaitM3");
        let m2_body = entry.m2_cache.as_ref().expect("set in AwaitM3");
        let th3_d = th3_from_m1_m2_m3(m1_body, m2_body, &frag.body).expect("fixed lengths");
        let master = derive_master(&entry.ss_a, &ss_b_b, &entry.dh_cs, m3.version, &sid, &th3_d)?;
        ss_b_b.zeroize();

        let mut finished_key = derive_finished_key(&master, m3.version, &sid)?;
        let expected = compute_client_finished(&finished_key, &th3_d);
        finished_key.zeroize();

        if !bool::from(expected.ct_eq(&m3.client_finished)) {
            // Forged/raced M3: silent drop with NO state mutation — the entry
            // stays AwaitM3, the M2 cache stays intact, the client's
            // retransmit budget/backoff are untouched (D15 pin).
            return Ok(ServerEvent::None);
        }

        let peer_identity = entry.verified_client.clone().expect("set at M2");
        let duration = entry.started.elapsed();
        self.pending.remove(&sid);
        Ok(ServerEvent::Complete(HandshakeOutcome {
            master,
            session_id: sid,
            peer_identity,
            handshake_duration: duration,
        }))
    }
}

/// Run the server side of the handshake over a transport (one source per
/// invocation in v1; a session manager drives one instance per source).
///
/// Returns only after the M3 Finished MAC verifies (1.5 RTT — D13).  Wrong-
/// size datagrams are skipped; transport errors are fatal.
pub async fn server_handshake_v2<T: HandshakeTransport>(
    transport: &mut T,
    cfg: &ServerConfig,
) -> Result<HandshakeOutcome, HandshakeV2Error> {
    validate_version(cfg.version)?;
    if cfg.roster.is_empty() {
        return Err(HandshakeV2Error::InvalidConfig(
            "roster must not be empty (fail closed)".into(),
        ));
    }
    let mut srv = ServerHandshake::new(cfg);
    loop {
        let (pkt, from) = match transport.recv().await {
            Err(HandshakeV2Error::DatagramRejected) => continue,
            r => r?,
        };
        match srv.handle_datagram(&pkt, from)? {
            ServerEvent::Emit(frags, peer) => {
                for f in &frags {
                    transport.send_to(f, peer).await?;
                }
            }
            ServerEvent::Complete(out) => return Ok(out),
            ServerEvent::None => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::net::{IpAddr, Ipv4Addr};

    pub(crate) const CLIENT_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);
    pub(crate) const SERVER_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002);
    pub(crate) const OTHER_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40003);

    // -- helpers (pub(crate): shared with the session-manager tests) -------------

    pub(crate) fn test_ids() -> (MlDsaKeypair, MlDsaKeypair) {
        (
            MlDsaKeypair::generate().expect("client keygen"),
            MlDsaKeypair::generate().expect("server keygen"),
        )
    }

    pub(crate) fn test_configs() -> (ClientConfig, ServerConfig) {
        let (client_id, server_id) = test_ids();
        let cc = ClientConfig::new(SERVER_ADDR, client_id.clone(), server_id.public.clone());
        let sc = ServerConfig::new(server_id, vec![client_id.public]);
        (cc, sc)
    }

    /// A structurally valid M1 fragment-0 datagram (body garbage is fine:
    /// allocation does not decode the body).
    pub(crate) fn m1_frag0_datagram(sid: [u8; SESSION_ID_LEN]) -> WirePacket {
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = PROTOCOL_VERSION;
        dg[1..9].copy_from_slice(&sid);
        dg[9] = HS_TYPE_CLIENT_HELLO;
        dg[10] = 0;
        dg[11] = M1_FRAG_COUNT;
        WirePacket::from_bytes(&dg).expect("1280-byte buffer parses")
    }

    /// A datagram with an arbitrary byte-9 (dispatch pin test helper).
    pub(crate) fn datagram_with_type(hs_type: u8, sid: [u8; SESSION_ID_LEN]) -> WirePacket {
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = PROTOCOL_VERSION;
        dg[1..9].copy_from_slice(&sid);
        dg[9] = hs_type;
        WirePacket::from_bytes(&dg).expect("1280-byte buffer parses")
    }

    fn encode_real_m1(cc: &ClientConfig, sid: [u8; SESSION_ID_LEN]) -> [u8; M1_BODY_LEN] {
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let x_c = x.public.to_bytes();
        let pre_sign = encode_m1(cc.version, sid, &kp.public, &x_c, None);
        let th1_d = th1_from_m1(&pre_sign).expect("fixed-length M1");
        let sig = cc.identity.sign(&th1_d).expect("sign");
        encode_m1(cc.version, sid, &kp.public, &x_c, Some(&sig))
    }

    fn encode_real_m2(sc: &ServerConfig, sid: [u8; SESSION_ID_LEN]) -> [u8; M2_BODY_LEN] {
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let x_s = x.public.to_bytes();
        let peer_pk = MlKemKeypair::generate().expect("keygen");
        let (_, ct2) = encapsulate(&peer_pk.public).expect("encaps");
        let m2_z = encode_m2(sc.version, sid, &kp.public, &x_s, &ct2, None);
        let th2_d = th2_from_m1_m2(&encode_real_m1_for_th2(sc, sid), &m2_z).expect("fixed");
        let sig = sc.identity.sign(&th2_d).expect("sign");
        encode_m2(sc.version, sid, &kp.public, &x_s, &ct2, Some(&sig))
    }

    // Minimal M1 for TH2 derivation (any fixed-length bytes).
    fn encode_real_m1_for_th2(sc: &ServerConfig, sid: [u8; SESSION_ID_LEN]) -> [u8; M1_BODY_LEN] {
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let x_c = x.public.to_bytes();
        let sig = sc.identity.sign(&[0u8; 32]).expect("sign");
        encode_m1(sc.version, sid, &kp.public, &x_c, Some(&sig))
    }

    fn manual_sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(HANDSHAKE_DOMAIN);
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    /// Drive a full exchange at the state-machine level.  Returns the client
    /// and server outcomes (masters must be equal).
    fn run_exchange(
        cc: &ClientConfig,
        sc: &ServerConfig,
        sid: [u8; SESSION_ID_LEN],
    ) -> (HandshakeOutcome, HandshakeOutcome) {
        let mut client = ClientHandshake::new(cc, sid).expect("client");
        let mut server = ServerHandshake::new(sc);

        let mut m2_frags = Vec::new();
        for f in client.m1_frags() {
            if let ServerEvent::Emit(frags, peer) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                assert_eq!(peer, CLIENT_ADDR, "M2 goes back to the source");
                m2_frags = frags;
            }
        }
        assert_eq!(m2_frags.len(), M2_FRAG_COUNT as usize, "full M2 emitted");
        assert_eq!(server.pending_len(), 1, "pending entry held across M1→M2");

        let mut m3_frags = Vec::new();
        for f in &m2_frags {
            if let ClientEvent::Emit(frags) = client.handle_datagram(f).expect("cli") {
                m3_frags = frags;
            }
        }
        assert_eq!(
            m3_frags.len(),
            M3_FRAG_COUNT as usize,
            "client emits M3 once"
        );

        let mut server_outcome = None;
        for f in &m3_frags {
            if let ServerEvent::Complete(out) = server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                server_outcome = Some(out);
            }
        }
        let server_outcome = server_outcome.expect("server completes at M3");
        assert_eq!(
            server.pending_len(),
            0,
            "pending entry removed on completion"
        );

        let mut client_outcome = None;
        for _ in 0..=cc.m3_max_attempts {
            if let ClientEvent::Complete(out) = client.on_timer().expect("cli") {
                client_outcome = Some(out);
                break;
            }
        }
        let client_outcome = client_outcome.expect("client completes after M3 budget");
        (client_outcome, server_outcome)
    }

    /// Drive the exchange to the point where the server awaits M3; returns the
    /// client machine (in M3Sent), the server machine, and the M2 fragments.
    fn reach_await_m3(
        cc: &ClientConfig,
        sc: &ServerConfig,
        sid: [u8; SESSION_ID_LEN],
    ) -> (
        ClientHandshake,
        ServerHandshake,
        Vec<WirePacket>,
        Vec<WirePacket>,
    ) {
        let mut client = ClientHandshake::new(cc, sid).expect("client");
        let mut server = ServerHandshake::new(sc);
        let mut m2_frags = Vec::new();
        for f in client.m1_frags() {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                m2_frags = frags;
            }
        }
        assert_eq!(m2_frags.len(), M2_FRAG_COUNT as usize);
        let mut m3_frags = Vec::new();
        for f in &m2_frags {
            if let ClientEvent::Emit(frags) = client.handle_datagram(f).expect("cli") {
                m3_frags = frags;
            }
        }
        assert_eq!(m3_frags.len(), M3_FRAG_COUNT as usize);
        (client, server, m2_frags, m3_frags)
    }

    // -- fragment framing -----------------------------------------------------

    #[test]
    fn fragment_roundtrip_all_types() {
        let (cc, sc) = test_configs();
        let sid = [7u8; SESSION_ID_LEN];

        let m1 = encode_real_m1(&cc, sid);
        let frags = fragment_message(HS_TYPE_CLIENT_HELLO, cc.version, sid, &m1).expect("frag");
        assert_eq!(frags.len(), M1_FRAG_COUNT as usize);
        let mut asm = FragmentAssembler::new(HS_TYPE_CLIENT_HELLO).expect("asm");
        for f in &frags {
            let frag = HandshakeFragment::from_datagram(f).expect("parse");
            asm.add_fragment(&frag);
        }
        assert_eq!(asm.message().expect("complete"), m1.as_slice());

        let m2 = encode_real_m2(&sc, sid);
        let frags = fragment_message(HS_TYPE_SERVER_HELLO, sc.version, sid, &m2).expect("frag");
        assert_eq!(frags.len(), M2_FRAG_COUNT as usize);
        let mut asm = FragmentAssembler::new(HS_TYPE_SERVER_HELLO).expect("asm");
        for f in &frags {
            let frag = HandshakeFragment::from_datagram(f).expect("parse");
            asm.add_fragment(&frag);
        }
        assert_eq!(asm.message().expect("complete"), m2.as_slice());

        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, Some(&[0xAB; FINISHED_MAC_LEN]));
        let frags = fragment_message(HS_TYPE_CLIENT_CONFIRM, cc.version, sid, &m3).expect("frag");
        assert_eq!(frags.len(), M3_FRAG_COUNT as usize);
        let mut asm = FragmentAssembler::new(HS_TYPE_CLIENT_CONFIRM).expect("asm");
        for f in &frags {
            let frag = HandshakeFragment::from_datagram(f).expect("parse");
            asm.add_fragment(&frag);
        }
        assert_eq!(asm.message().expect("complete"), m3.as_slice());
    }

    #[test]
    fn from_datagram_strict_rejects() {
        let sid = [1u8; SESSION_ID_LEN];

        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = PROTOCOL_VERSION;
        dg[1..9].copy_from_slice(&sid);
        dg[9] = HS_TYPE_CLIENT_HELLO;
        dg[11] = M1_FRAG_COUNT;

        // Wrong version byte.
        let mut bad = dg;
        bad[0] = PROTOCOL_VERSION + 1;
        assert!(
            HandshakeFragment::from_datagram(&WirePacket::from_bytes(&bad).expect("1280")).is_err()
        );

        // Unknown hs_type.
        let mut bad = dg;
        bad[9] = 0x40;
        assert!(
            HandshakeFragment::from_datagram(&WirePacket::from_bytes(&bad).expect("1280")).is_err()
        );

        // frag_total mismatch.
        let mut bad = dg;
        bad[11] = M1_FRAG_COUNT - 1;
        assert!(
            HandshakeFragment::from_datagram(&WirePacket::from_bytes(&bad).expect("1280")).is_err()
        );

        // frag_idx >= frag_total.
        let mut bad = dg;
        bad[10] = M1_FRAG_COUNT;
        assert!(
            HandshakeFragment::from_datagram(&WirePacket::from_bytes(&bad).expect("1280")).is_err()
        );

        // Valid shape parses.
        let frag = HandshakeFragment::from_datagram(&WirePacket::from_bytes(&dg).expect("1280"))
            .expect("valid fragment parses");
        assert_eq!(frag.hs_type, HS_TYPE_CLIENT_HELLO);
        assert_eq!(frag.frag_idx, 0);
        assert_eq!(frag.frag_total, M1_FRAG_COUNT);
    }

    #[test]
    fn is_handshake_fragment_dispatch() {
        let sid = [2u8; SESSION_ID_LEN];
        for hs_type in [
            HS_TYPE_CLIENT_HELLO,
            HS_TYPE_SERVER_HELLO,
            HS_TYPE_CLIENT_CONFIRM,
        ] {
            assert!(
                is_handshake_fragment(&datagram_with_type(hs_type, sid)),
                "0x{hs_type:02x} must route to the handshake path"
            );
        }
        for hs_type in [0x00u8, 0x01, 0x02, 0x03, 0x0F, 0x11, 0x2F, 0x40, 0xFF] {
            assert!(
                !is_handshake_fragment(&datagram_with_type(hs_type, sid)),
                "0x{hs_type:02x} must route to the data path"
            );
        }
    }

    #[test]
    fn assembler_order_independent_with_duplicates() {
        let (_, sc) = test_configs();
        let sid = [3u8; SESSION_ID_LEN];
        let m2 = encode_real_m2(&sc, sid);
        let frags = fragment_message(HS_TYPE_SERVER_HELLO, sc.version, sid, &m2).expect("frag");
        let parsed: Vec<HandshakeFragment> = frags
            .iter()
            .map(|f| HandshakeFragment::from_datagram(f).expect("parse"))
            .collect();

        let mut asm = FragmentAssembler::new(HS_TYPE_SERVER_HELLO).expect("asm");
        for idx in [2usize, 0, 1, 1, 3, 4, 2] {
            // Duplicates and out-of-order must not disturb the result.
            asm.add_fragment(&parsed[idx]);
        }
        assert_eq!(asm.message().expect("complete"), m2.as_slice());
    }

    #[test]
    fn assembler_incomplete_never_completes() {
        let (_, sc) = test_configs();
        let sid = [4u8; SESSION_ID_LEN];
        let m2 = encode_real_m2(&sc, sid);
        let frags = fragment_message(HS_TYPE_SERVER_HELLO, sc.version, sid, &m2).expect("frag");
        let parsed: Vec<HandshakeFragment> = frags
            .iter()
            .map(|f| HandshakeFragment::from_datagram(f).expect("parse"))
            .collect();
        let mut asm = FragmentAssembler::new(HS_TYPE_SERVER_HELLO).expect("asm");
        for f in &parsed[..M2_FRAG_COUNT as usize - 1] {
            asm.add_fragment(f);
        }
        assert!(
            asm.message().is_none(),
            "incomplete assembly stays incomplete"
        );
    }

    #[test]
    fn fragment_message_rejects_wrong_length() {
        let sid = [5u8; SESSION_ID_LEN];
        let err = fragment_message(HS_TYPE_CLIENT_HELLO, PROTOCOL_VERSION, sid, &[0u8; 100])
            .expect_err("wrong length rejected");
        assert!(matches!(err, CodecError::WrongLength { .. }));
    }

    // -- message codecs -------------------------------------------------------

    #[test]
    fn message_codecs_roundtrip() {
        let (cc, sc) = test_configs();
        let sid = [6u8; SESSION_ID_LEN];

        let m1_bytes = encode_real_m1(&cc, sid);
        let m1 = ClientHello::decode(&m1_bytes).expect("decode");
        assert_eq!(m1.encode().as_slice(), m1_bytes.as_slice());

        let m2_bytes = encode_real_m2(&sc, sid);
        let m2 = ServerHello::decode(&m2_bytes).expect("decode");
        assert_eq!(m2.encode().as_slice(), m2_bytes.as_slice());

        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3_bytes = encode_m3(cc.version, sid, &ct3, Some(&[0xCD; FINISHED_MAC_LEN]));
        let m3 = ClientConfirm::decode(&m3_bytes).expect("decode");
        assert_eq!(m3.encode().as_slice(), m3_bytes.as_slice());
    }

    #[test]
    fn codecs_reject_bad_version_and_length() {
        let (cc, _) = test_configs();
        let sid = [8u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);

        assert!(
            ClientHello::decode(&m1[..m1.len() - 1]).is_err(),
            "truncated"
        );
        let mut wrong = m1;
        wrong[0] = PROTOCOL_VERSION + 1;
        assert!(ClientHello::decode(&wrong).is_err(), "wrong version");

        // A full-length, correct-version body always decodes: the KEM key
        // section has no invalid encodings at this layer (length-validated).
        let ok = ClientHello::decode(&m1).expect("full valid M1 decodes");
        assert_eq!(ok.version, PROTOCOL_VERSION);
    }

    // -- canonical transcript -------------------------------------------------

    #[test]
    fn th1_zero_and_signed_forms_agree() {
        let (cc, _) = test_configs();
        let sid = [9u8; SESSION_ID_LEN];
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let x_c = x.public.to_bytes();
        let pre_sign = encode_m1(cc.version, sid, &kp.public, &x_c, None);
        let th1_d = th1_from_m1(&pre_sign).expect("pre-sign form");
        let sig = cc.identity.sign(&th1_d).expect("sign");
        let full = encode_m1(cc.version, sid, &kp.public, &x_c, Some(&sig));
        assert_eq!(
            th1_from_m1(&full).expect("signed form"),
            th1_d,
            "TH1 must not depend on the signature slot content"
        );
    }

    #[test]
    fn th2_zero_and_signed_forms_agree() {
        let (cc, sc) = test_configs();
        let sid = [10u8; SESSION_ID_LEN];
        let m1_s = encode_real_m1(&cc, sid);
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let x_s = x.public.to_bytes();
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct2) = encapsulate(&peer.public).expect("encaps");
        let m2_z = encode_m2(sc.version, sid, &kp.public, &x_s, &ct2, None);
        let th2_d = th2_from_m1_m2(&m1_s, &m2_z).expect("zero form");
        let sig = sc.identity.sign(&th2_d).expect("sign");
        let m2_full = encode_m2(sc.version, sid, &kp.public, &x_s, &ct2, Some(&sig));
        assert_eq!(
            th2_from_m1_m2(&m1_s, &m2_full).expect("signed form"),
            th2_d,
            "TH2 must not depend on the signature slot content"
        );
    }

    #[test]
    fn th3_zero_mac_and_real_forms_agree() {
        let (cc, sc) = test_configs();
        let sid = [11u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3_z = encode_m3(cc.version, sid, &ct3, None);
        let th3_d = th3_from_m1_m2_m3(&m1, &m2, &m3_z).expect("zero form");
        let m3_full = encode_m3(cc.version, sid, &ct3, Some(&[0xEE; FINISHED_MAC_LEN]));
        assert_eq!(
            th3_from_m1_m2_m3(&m1, &m2, &m3_full).expect("real form"),
            th3_d,
            "TH3 must not depend on the Finished MAC content"
        );
    }

    #[test]
    fn transcripts_match_independent_sha256() {
        let (cc, sc) = test_configs();
        let sid = [12u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);

        // Canonical forms: signature/MAC slots zero-filled (D13).
        let mut m1_z = m1.to_vec();
        for b in &mut m1_z[M1_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..] {
            *b = 0;
        }
        let mut m2_z = m2.to_vec();
        for b in &mut m2_z[M2_BODY_LEN - ML_DSA_65_SIGNATURE_BYTES..] {
            *b = 0;
        }

        assert_eq!(
            th1_from_m1(&m1).expect("th1"),
            manual_sha256(&[&m1_z]),
            "TH1 must equal SHA256(dom ‖ M1_z)"
        );

        assert_eq!(
            th2_from_m1_m2(&m1, &m2).expect("th2"),
            manual_sha256(&[&m1, &m2_z]),
            "TH2 must equal SHA256(dom ‖ M1_s ‖ M2_z)"
        );

        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, Some(&[0x11; FINISHED_MAC_LEN]));
        let mut m3_z = m3.to_vec();
        for b in &mut m3_z[M3_BODY_LEN - FINISHED_MAC_LEN..] {
            *b = 0;
        }
        assert_eq!(
            th3_from_m1_m2_m3(&m1, &m2, &m3).expect("th3"),
            manual_sha256(&[&m1_z, &m2_z, &m3_z]),
            "TH3 must equal SHA256(dom ‖ M1_z ‖ M2_z ‖ M3_z)"
        );
    }

    #[test]
    fn th3_binds_all_messages() {
        let (cc, sc) = test_configs();
        let sid = [13u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, None);
        let base = th3_from_m1_m2_m3(&m1, &m2, &m3).expect("th3");

        let mut m1_b = m1;
        m1_b[9] ^= 1;
        assert_ne!(th3_from_m1_m2_m3(&m1_b, &m2, &m3).expect("th3"), base);

        let mut m2_b = m2;
        m2_b[1000] ^= 1;
        assert_ne!(th3_from_m1_m2_m3(&m1, &m2_b, &m3).expect("th3"), base);

        let mut m3_b = m3;
        m3_b[50] ^= 1;
        assert_ne!(th3_from_m1_m2_m3(&m1, &m2, &m3_b).expect("th3"), base);

        let mut sid_b = sid;
        sid_b[0] ^= 1;
        let m1_s = encode_real_m1(&cc, sid_b);
        assert_ne!(th3_from_m1_m2_m3(&m1_s, &m2, &m3).expect("th3"), base);
    }

    // -- timing helpers -------------------------------------------------------

    #[test]
    fn jitter_within_20_percent() {
        for base_ms in [100u64, 250, 1000, 8000] {
            let base = Duration::from_millis(base_ms);
            for _ in 0..64 {
                let d = jittered(base);
                let lo = base.saturating_mul(8) / 10;
                let hi = base.saturating_mul(12) / 10;
                assert!(d >= lo && d <= hi, "jitter must stay within ±20%");
            }
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        let base = Duration::from_millis(250);
        let cap = base.saturating_mul(32).saturating_mul(12) / 10; // 32x base, then ±20% jitter
        for attempt in 0..20u32 {
            let d = backoff_delay(base, attempt);
            let upper = base
                .saturating_mul(1u32 << attempt.min(5))
                .saturating_mul(12)
                / 10;
            assert!(
                d <= upper,
                "backoff must never exceed the 32x cap with jitter"
            );
            assert!(d <= cap, "backoff capped at 32x base");
        }
        assert!(
            backoff_delay(base, 8) >= backoff_delay(base, 0) / 4,
            "monotonic in aggregate"
        );
    }

    // -- client state machine -------------------------------------------------

    #[test]
    fn client_ignores_non_m2_datagrams_without_state_change() {
        let (cc, _) = test_configs();
        let sid = [14u8; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).expect("client");
        let delay_before = client.next_delay();

        for f in client.m1_frags().to_vec() {
            assert!(matches!(
                client.handle_datagram(&f).expect("cli"),
                ClientEvent::None
            ));
        }
        for hs_type in [
            0x00u8,
            0x03,
            HS_TYPE_CLIENT_HELLO,
            HS_TYPE_CLIENT_CONFIRM,
            0xFF,
        ] {
            assert!(matches!(
                client
                    .handle_datagram(&datagram_with_type(hs_type, sid))
                    .expect("cli"),
                ClientEvent::None
            ));
        }
        assert_eq!(
            client.next_delay(),
            delay_before,
            "irrelevant datagrams must not touch the timer state"
        );
    }

    #[test]
    fn client_ignores_wrong_sid() {
        let (cc, sc) = test_configs();
        let sid_a = [15u8; SESSION_ID_LEN];
        let sid_b = [16u8; SESSION_ID_LEN];
        let (_, _, m2_frags, _) = reach_await_m3(&cc, &sc, sid_a);
        let mut client = ClientHandshake::new(&cc, sid_b).expect("client");
        for f in &m2_frags {
            assert!(matches!(
                client.handle_datagram(f).expect("cli"),
                ClientEvent::None
            ));
        }
        // A later M1 (our own) is still the current expected message: the
        // foreign M2 must not have advanced the machine.
        assert!(matches!(
            client.on_timer().expect("cli"),
            ClientEvent::Emit(_)
        ));
    }

    #[test]
    fn client_recovers_from_corrupt_m2() {
        let (cc, sc) = test_configs();
        let sid = [17u8; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).expect("client");
        let mut server = ServerHandshake::new(&sc);

        let mut m2_frags = Vec::new();
        for f in client.m1_frags() {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                m2_frags = frags;
            }
        }

        // Corrupt the M2 signature slot in the last fragment: the signature
        // occupies the final 3309 bytes of the 5622-byte body, so its last
        // byte sits at body offset 5621, i.e. datagram offset
        // 12 + (5621 − 4·1268) = 561 within the final fragment.
        let mut dg = *m2_frags[4].as_bytes();
        let sig_last = HS_FRAG_HEADER_LEN
            + (M2_BODY_LEN - 1 - (M2_FRAG_COUNT as usize - 1) * HS_FRAG_BODY_MAX);
        dg[sig_last] ^= 0xFF;
        let corrupted = WirePacket::from_bytes(&dg).expect("1280");

        // The full (corrupted) M2 assembles; the failed verification must be a
        // silent None that resets the assembler (D12).
        for f in &m2_frags[..4] {
            assert!(matches!(
                client.handle_datagram(f).expect("cli"),
                ClientEvent::None
            ));
        }
        assert!(matches!(
            client.handle_datagram(&corrupted).expect("cli"),
            ClientEvent::None
        ));

        // The pristine (byte-identical) M2 resend must now succeed — proving
        // the assembler was reset and no state was poisoned (D12/D13).
        let mut got_m3 = false;
        for f in &m2_frags {
            if let ClientEvent::Emit(frags) = client.handle_datagram(f).expect("cli") {
                assert_eq!(frags.len(), M3_FRAG_COUNT as usize);
                got_m3 = true;
            }
        }
        assert!(got_m3, "clean M2 must complete the client handshake");
    }

    #[test]
    fn client_m1_timeout_after_budget() {
        let (cc, _) = test_configs();
        let sid = [18u8; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).expect("client");
        for _ in 0..cc.m1_max_attempts {
            assert!(matches!(
                client.on_timer().expect("cli"),
                ClientEvent::Emit(_)
            ));
        }
        assert!(
            matches!(client.on_timer(), Err(HandshakeV2Error::Timeout)),
            "M1 budget exhausted → Timeout"
        );
    }

    #[test]
    fn client_m3_retransmits_byte_identical_then_completes() {
        let (cc, sc) = test_configs();
        let sid = [19u8; SESSION_ID_LEN];
        let (mut client, _, _, m3_frags) = reach_await_m3(&cc, &sc, sid);

        let mut completed = false;
        for _ in 0..=cc.m3_max_attempts {
            match client.on_timer().expect("cli") {
                ClientEvent::Emit(frags) => {
                    assert_eq!(frags.len(), m3_frags.len());
                    for (a, b) in frags.iter().zip(&m3_frags) {
                        assert_eq!(
                            a.as_bytes(),
                            b.as_bytes(),
                            "M3 retransmits must be byte-identical (D13)"
                        );
                    }
                }
                ClientEvent::Complete(out) => {
                    assert_eq!(out.session_id, sid);
                    completed = true;
                    break;
                }
                ClientEvent::None => panic!("unexpected"),
            }
        }
        assert!(completed, "M3 budget exhaustion completes the client (D15)");
    }

    // -- server state machine -------------------------------------------------

    #[test]
    fn server_completes_and_masters_agree() {
        let (cc, sc) = test_configs();
        let sid = [20u8; SESSION_ID_LEN];
        let (client_out, server_out) = run_exchange(&cc, &sc, sid);

        assert_eq!(
            client_out.master.as_bytes(),
            server_out.master.as_bytes(),
            "client and server must derive the identical session master"
        );
        assert_eq!(client_out.session_id, server_out.session_id);
        assert_eq!(
            client_out.peer_identity.encode(),
            sc.identity.public.encode(),
            "client pins the server identity"
        );
        assert_eq!(
            server_out.peer_identity.encode(),
            cc.identity.public.encode(),
            "server pins the matched roster identity"
        );
        assert!(
            server_out.handshake_duration > Duration::ZERO,
            "server records the establishment duration"
        );
    }

    #[test]
    fn server_silent_on_junk_no_state_no_amplification() {
        let (_, sc) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        let mut seen_events = 0;
        for i in 0..100u16 {
            let mut sid = [0u8; SESSION_ID_LEN];
            sid[..2].copy_from_slice(&i.to_be_bytes());
            let hs_type = (i % 9) as u8 * 16; // {0x00,0x10,0x20,...,0x80,0xF0}
            let mut pkt = datagram_with_type(hs_type, sid);
            if i % 3 == 0 {
                pkt = WirePacket::from_bytes(&[0u8; PACKET_SIZE]).expect("1280");
            }
            match server.handle_datagram(&pkt, OTHER_ADDR).expect("srv") {
                ServerEvent::None => {}
                _ => seen_events += 1,
            }
        }
        assert_eq!(seen_events, 0, "junk must never elicit a response");
        assert_eq!(server.pending_len(), 0, "junk must never allocate state");
    }

    #[test]
    fn server_no_allocation_on_nonzero_first_fragment() {
        let (_, sc) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        let sid = [21u8; SESSION_ID_LEN];
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = PROTOCOL_VERSION;
        dg[1..9].copy_from_slice(&sid);
        dg[9] = HS_TYPE_CLIENT_HELLO;
        dg[10] = 1; // frag_idx != 0
        dg[11] = M1_FRAG_COUNT;
        let pkt = WirePacket::from_bytes(&dg).expect("1280");
        assert!(matches!(
            server.handle_datagram(&pkt, CLIENT_ADDR).expect("srv"),
            ServerEvent::None
        ));
        assert_eq!(
            server.pending_len(),
            0,
            "no allocation before a valid frag 0"
        );
    }

    #[test]
    fn server_rate_limits_m1_per_source() {
        let (_, mut sc) = test_configs();
        sc.rate_limit_burst = 2;
        let mut server = ServerHandshake::new(&sc);
        for i in 0..3u8 {
            let sid = [22u8 + i; SESSION_ID_LEN];
            server
                .handle_datagram(&m1_frag0_datagram(sid), CLIENT_ADDR)
                .expect("srv");
        }
        assert_eq!(
            server.pending_len(),
            2,
            "third M1 from the same source is dropped"
        );
        // A different source has its own bucket.
        let sid = [25u8; SESSION_ID_LEN];
        server
            .handle_datagram(&m1_frag0_datagram(sid), OTHER_ADDR)
            .expect("srv");
        assert_eq!(server.pending_len(), 3, "rate limit is per-source");
    }

    #[test]
    fn server_max_pending_cap() {
        let (_, mut sc) = test_configs();
        sc.max_pending = 2;
        let mut server = ServerHandshake::new(&sc);
        for i in 0..3u8 {
            let sid = [30u8 + i; SESSION_ID_LEN];
            server
                .handle_datagram(&m1_frag0_datagram(sid), CLIENT_ADDR)
                .expect("srv");
        }
        assert_eq!(server.pending_len(), 2, "pending capped at max_pending");
    }

    #[test]
    fn server_m2_resend_byte_identical() {
        let (cc, sc) = test_configs();
        let sid = [33u8; SESSION_ID_LEN];
        let (_, mut server, m2_frags, _) = reach_await_m3(&cc, &sc, sid);

        // Re-send the full M1 after AwaitM3: the server must resend the cached
        // M2 byte-identical (D13 client-driven retransmission).
        let mut resend = Vec::new();
        let client = ClientHandshake::new(&cc, sid).expect("client");
        for f in client.m1_frags() {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                resend = frags;
            }
        }
        assert_eq!(resend.len(), m2_frags.len());
        for (a, b) in resend.iter().zip(&m2_frags) {
            assert_eq!(
                a.as_bytes(),
                b.as_bytes(),
                "cached M2 resend must be byte-identical"
            );
        }
    }

    #[test]
    fn server_m2_resend_once_per_burst() {
        let (cc, sc) = test_configs();
        let sid = [39u8; SESSION_ID_LEN];
        let (_, mut server, m2_frags, _) = reach_await_m3(&cc, &sc, sid);
        let m1 = ClientHandshake::new(&cc, sid)
            .expect("client")
            .m1_frags()
            .to_vec();

        // One full retransmit burst must yield exactly ONE M2 resend (only
        // fragment 0 is the trigger; no per-fragment 4x5 self-amplification).
        let mut resends = 0;
        for f in &m1 {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                resends += 1;
                assert_eq!(frags.len(), m2_frags.len(), "resend is the full M2");
            }
        }
        assert_eq!(resends, 1, "one M2 resend per retransmit burst");

        // A second burst must trigger another resend (client-driven
        // retransmission stays functional).
        for f in &m1 {
            if let ServerEvent::Emit(..) = server.handle_datagram(f, CLIENT_ADDR).expect("srv") {
                resends += 1;
            }
        }
        assert_eq!(resends, 2, "each retransmit burst resends the M2 once");
    }

    #[test]
    fn server_m3_flood_is_rate_limited() {
        // Budget: 2 tokens for the M1 (allocation + verify), leaving 2 for
        // forged M3s before the gate closes.
        let (cc, mut sc) = test_configs();
        sc.rate_limit_burst = 4;
        let sid = [40u8; SESSION_ID_LEN];
        let (_, mut server, _, m3_frags) = reach_await_m3(&cc, &sc, sid);

        // Forge an M3: same body, corrupted Finished MAC.
        let mut dg = *m3_frags[0].as_bytes();
        let mac_start = HS_FRAG_HEADER_LEN + M3_BODY_LEN - FINISHED_MAC_LEN;
        for b in &mut dg[mac_start..mac_start + FINISHED_MAC_LEN] {
            *b = 0xAA;
        }
        let forged = WirePacket::from_bytes(&dg).expect("1280");

        // First two forged M3s burn the remaining per-source budget; the
        // third is dropped before any asymmetric work.
        for _ in 0..3 {
            assert!(matches!(
                server.handle_datagram(&forged, CLIENT_ADDR).expect("srv"),
                ServerEvent::None
            ));
        }
        assert_eq!(
            server.pending_len(),
            1,
            "entry survives the forged-M3 flood"
        );

        // The genuine M3 is also gated while the budget is exhausted — the
        // flood must not let the real M3 ride in on a shared budget.
        let mut completed = false;
        for f in &m3_frags {
            if let ServerEvent::Complete(_) = server.handle_datagram(f, CLIENT_ADDR).expect("srv") {
                completed = true;
            }
        }
        assert!(!completed, "genuine M3 is rate-gated like everything else");
        assert_eq!(
            server.pending_len(),
            1,
            "no completion while the budget is exhausted"
        );
    }

    #[test]
    fn server_ttl_eviction_duplicates_do_not_extend() {
        let (_, mut sc) = test_configs();
        sc.pending_ttl = Duration::from_secs(30);
        let mut server = ServerHandshake::new(&sc);
        let sid = [42u8; SESSION_ID_LEN];
        server
            .handle_datagram(&m1_frag0_datagram(sid), CLIENT_ADDR)
            .expect("srv");
        assert_eq!(server.pending_len(), 1);

        // A duplicate-fragment flood must not refresh the entry's TTL.
        let dup = m1_frag0_datagram(sid);
        for _ in 0..50 {
            server.handle_datagram(&dup, CLIENT_ADDR).expect("srv");
        }
        let now = Instant::now();
        server.evict_expired(now + sc.pending_ttl);
        assert_eq!(
            server.pending_len(),
            0,
            "duplicates must not extend the TTL (F5)"
        );
    }

    #[test]
    fn server_ttl_eviction_advancing_fragments_extend() {
        let (_, mut sc) = test_configs();
        sc.pending_ttl = Duration::from_secs(30);
        let mut server = ServerHandshake::new(&sc);
        let sid = [43u8; SESSION_ID_LEN];
        server
            .handle_datagram(&m1_frag0_datagram(sid), CLIENT_ADDR)
            .expect("srv");

        // A NEW fragment (frag 1) advances the assembly and refreshes the TTL.
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = PROTOCOL_VERSION;
        dg[1..9].copy_from_slice(&sid);
        dg[9] = HS_TYPE_CLIENT_HELLO;
        dg[10] = 1;
        dg[11] = M1_FRAG_COUNT;
        let frag1 = WirePacket::from_bytes(&dg).expect("1280");
        server.handle_datagram(&frag1, CLIENT_ADDR).expect("srv");

        let now = Instant::now();
        // 25s after the last advance: still alive (TTL 30s).
        server.evict_expired(now + sc.pending_ttl - Duration::from_secs(5));
        assert_eq!(
            server.pending_len(),
            1,
            "advancing fragments refresh the TTL"
        );
        // Just past the TTL after the last advance: evicted.
        server.evict_expired(now + sc.pending_ttl + Duration::from_secs(1));
        assert_eq!(
            server.pending_len(),
            0,
            "entry expires TTL after its last advance"
        );
    }

    #[test]
    fn server_rate_bucket_table_is_capped() {
        let (_, sc) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        for i in 0..(MAX_RATE_BUCKETS + 10) as u16 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)),
                40000 + (i % 1000),
            );
            let sid = (i as u8).wrapping_add(60);
            server
                .handle_datagram(&m1_frag0_datagram([sid; SESSION_ID_LEN]), addr)
                .expect("srv");
        }
        assert!(
            server.rate_buckets.len() <= MAX_RATE_BUCKETS,
            "spoofed sources must not grow the bucket table without bound"
        );
    }

    #[test]
    fn server_rejects_unknown_client() {
        let (_, sc) = test_configs();
        let sid = [34u8; SESSION_ID_LEN];
        let (cc, _) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        let client = ClientHandshake::new(&cc, sid).expect("client");
        for f in client.m1_frags() {
            assert!(matches!(
                server.handle_datagram(f, CLIENT_ADDR).expect("srv"),
                ServerEvent::None
            ));
        }
        assert_eq!(
            server.pending_len(),
            0,
            "unknown client: entry removed, no M2, no state"
        );
    }

    #[test]
    fn server_sid_collision_across_sources() {
        let (cc, sc) = test_configs();
        let sid = [35u8; SESSION_ID_LEN];
        let mut server = ServerHandshake::new(&sc);
        let client = ClientHandshake::new(&cc, sid).expect("client");
        for f in client.m1_frags() {
            server.handle_datagram(f, CLIENT_ADDR).expect("srv");
        }
        assert_eq!(server.pending_len(), 1);
        // Same sid from a different source: rejected, entry untouched.
        let f = client.m1_frags()[0].clone();
        assert!(matches!(
            server.handle_datagram(&f, OTHER_ADDR).expect("srv"),
            ServerEvent::None
        ));
        assert_eq!(
            server.pending_len(),
            1,
            "colliding source must not displace the entry"
        );
    }

    #[test]
    fn server_forged_m3_silent_keeps_entry_then_completes() {
        let (cc, sc) = test_configs();
        let sid = [36u8; SESSION_ID_LEN];
        let (_, mut server, _, m3_frags) = reach_await_m3(&cc, &sc, sid);

        // Forge an M3: same body, corrupted Finished MAC.
        let mut dg = *m3_frags[0].as_bytes();
        let mac_start = HS_FRAG_HEADER_LEN + M3_BODY_LEN - FINISHED_MAC_LEN;
        for b in &mut dg[mac_start..mac_start + FINISHED_MAC_LEN] {
            *b = 0xAA;
        }
        let forged = WirePacket::from_bytes(&dg).expect("1280");
        assert!(matches!(
            server.handle_datagram(&forged, CLIENT_ADDR).expect("srv"),
            ServerEvent::None
        ));
        assert_eq!(
            server.pending_len(),
            1,
            "forged M3 must not consume the entry (D15)"
        );

        // The genuine M3 must still complete — the failed attempt poisoned
        // nothing and consumed no budget.
        let mut completed = false;
        for f in &m3_frags {
            if let ServerEvent::Complete(_) = server.handle_datagram(f, CLIENT_ADDR).expect("srv") {
                completed = true;
            }
        }
        assert!(completed, "genuine M3 completes after a forged one");
        assert_eq!(server.pending_len(), 0);
    }

    #[test]
    fn server_m3_unknown_sid_and_wrong_source_silent() {
        let (cc, sc) = test_configs();
        let sid = [37u8; SESSION_ID_LEN];
        let (_, mut server, _, m3_frags) = reach_await_m3(&cc, &sc, sid);

        // Unknown sid.
        let unknown_sid = [38u8; SESSION_ID_LEN];
        let kp = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&kp.public).expect("encaps");
        let m3_unknown = encode_m3(
            cc.version,
            unknown_sid,
            &ct3,
            Some(&[0u8; FINISHED_MAC_LEN]),
        );
        let frags = fragment_message(HS_TYPE_CLIENT_CONFIRM, cc.version, unknown_sid, &m3_unknown)
            .expect("frag");
        for f in &frags {
            assert!(matches!(
                server.handle_datagram(f, CLIENT_ADDR).expect("srv"),
                ServerEvent::None
            ));
        }
        assert_eq!(server.pending_len(), 1);

        // Wrong source.
        for f in &m3_frags {
            assert!(matches!(
                server.handle_datagram(f, OTHER_ADDR).expect("srv"),
                ServerEvent::None
            ));
        }
        assert_eq!(server.pending_len(), 1, "wrong-source M3 must not complete");
    }

    // -- in-memory transport for driver tests (pub(crate): shared) ------------

    pub(crate) struct MemoryTransport {
        pub(crate) local: SocketAddr,
        pub(crate) tx: tokio::sync::mpsc::UnboundedSender<(WirePacket, SocketAddr)>,
        pub(crate) rx: tokio::sync::mpsc::UnboundedReceiver<(WirePacket, SocketAddr)>,
    }

    impl HandshakeTransport for MemoryTransport {
        async fn send_to(
            &mut self,
            packet: &WirePacket,
            _peer: SocketAddr,
        ) -> Result<(), HandshakeV2Error> {
            self.tx
                .send((packet.clone(), self.local))
                .map_err(|e| HandshakeV2Error::Transport(e.to_string()))
        }

        async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| HandshakeV2Error::Transport("channel closed".into()))
        }
    }

    pub(crate) struct LossyTransport {
        pub(crate) inner: MemoryTransport,
        pub(crate) drop_budget: usize,
    }

    impl HandshakeTransport for LossyTransport {
        async fn send_to(
            &mut self,
            packet: &WirePacket,
            peer: SocketAddr,
        ) -> Result<(), HandshakeV2Error> {
            if self.drop_budget > 0 {
                self.drop_budget -= 1;
                return Ok(()); // simulate datagram loss
            }
            self.inner.send_to(packet, peer).await
        }

        async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error> {
            self.inner.recv().await
        }
    }

    /// Wire up a client transport and a server transport so that each one's
    /// sends land in the other's receive queue.
    pub(crate) fn wired_transports() -> (
        MemoryTransport,
        MemoryTransport,
        tokio::sync::mpsc::UnboundedSender<(WirePacket, SocketAddr)>,
    ) {
        let (srv_tx, cli_rx) = tokio::sync::mpsc::unbounded_channel();
        let (cli_tx, srv_rx) = tokio::sync::mpsc::unbounded_channel();
        let client_t = MemoryTransport {
            local: CLIENT_ADDR,
            tx: cli_tx,
            rx: cli_rx,
        };
        let server_t = MemoryTransport {
            local: SERVER_ADDR,
            tx: srv_tx.clone(),
            rx: srv_rx,
        };
        (client_t, server_t, srv_tx)
    }

    // -- drivers --------------------------------------------------------------

    #[tokio::test]
    async fn client_and_server_drivers_agree() {
        let (client_id, server_id) = test_ids();
        let mut cc = ClientConfig::new(SERVER_ADDR, client_id, server_id.public.clone());
        // Complete on the first timer tick after M3 (avoids the ~4s budget
        // sweep; the exchange itself takes microseconds).
        cc.m3_max_attempts = 0;
        let sc = ServerConfig::new(server_id, vec![cc.identity.public.clone()]);

        let (mut client_t, mut server_t, _guard) = wired_transports();
        let srv = tokio::spawn(async move { server_handshake_v2(&mut server_t, &sc).await });
        let cli = tokio::spawn(async move { client_handshake_v2(&mut client_t, &cc).await });

        let (srv_res, cli_res) = tokio::join!(srv, cli);
        let server_out = srv_res.expect("join").expect("server completes");
        let client_out = cli_res.expect("join").expect("client completes");

        assert_eq!(
            client_out.master.as_bytes(),
            server_out.master.as_bytes(),
            "drivers must agree on the session master"
        );
        assert_eq!(client_out.session_id, server_out.session_id);
        assert!(client_out.handshake_duration > Duration::ZERO);
        assert!(server_out.handshake_duration > Duration::ZERO);
    }

    #[tokio::test]
    async fn client_retransmits_after_loss() {
        let (client_id, server_id) = test_ids();
        let mut cc = ClientConfig::new(SERVER_ADDR, client_id, server_id.public.clone());
        cc.m3_max_attempts = 0;
        let sc = ServerConfig::new(server_id, vec![cc.identity.public.clone()]);

        let (client_t, mut server_t, _guard) = wired_transports();
        let mut lossy = LossyTransport {
            inner: client_t,
            drop_budget: 4, // drop the whole initial M1 burst
        };
        let srv = tokio::spawn(async move { server_handshake_v2(&mut server_t, &sc).await });
        let cli = tokio::spawn(async move { client_handshake_v2(&mut lossy, &cc).await });

        let (srv_res, cli_res) = tokio::join!(srv, cli);
        let server_out = srv_res.expect("join").expect("server completes");
        let client_out = cli_res.expect("join").expect("client completes");
        assert_eq!(
            client_out.master.as_bytes(),
            server_out.master.as_bytes(),
            "retransmitted M1 must still converge"
        );
    }

    #[tokio::test]
    async fn server_empty_roster_fails_closed() {
        let (_, server_id) = test_ids();
        let sc = ServerConfig::new(server_id, vec![]);
        let (client_t, mut server_t, _guard) = wired_transports();
        let srv = tokio::spawn(async move { server_handshake_v2(&mut server_t, &sc).await });
        let cli = tokio::spawn(async move {
            // Give the server a moment; it must fail closed before any I/O.
            tokio::time::sleep(Duration::from_millis(50)).await;
            client_t
        });
        let (srv_res, _) = tokio::join!(srv, cli);
        assert!(matches!(
            srv_res.expect("join"),
            Err(HandshakeV2Error::InvalidConfig(_))
        ));
    }
}
