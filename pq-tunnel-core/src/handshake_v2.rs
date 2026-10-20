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

use std::collections::{HashMap, VecDeque};
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
    /// A peer reset surfaced by the transport (ICMP port-unreachable —
    /// Windows WSAECONNRESET / ECONNREFUSED).  *Informational* in UDP: the
    /// peer or its port vanished.  Session-local — drivers MUST NOT treat it
    /// as fatal to a multi-session manager; the vanished session is reaped
    /// by the normal idle-eviction path (M9B).
    #[error("transport reset by peer")]
    TransportReset,
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
            // ICMP port-unreachable: the peer's port vanished.  Distinct from
            // a transport fault so drivers can recover (M9B).
            Err(e) if e.is_recoverable_reset() => Err(HandshakeV2Error::TransportReset),
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
            // M3 budget must stay strictly inside the session manager's
            // default handshake_timeout (30s): 4 attempts with ±20% jitter
            // cap at ~9.3s worst case, so a default-configured client always
            // establishes before the deadline (the earlier 8-attempt default
            // budgeted ~31.75-38s — past the deadline, so the client could
            // never become ready against a passive server).
            m3_max_attempts: 4,
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
        // Fail secure on a non-contributory X25519 exchange: a low-order peer
        // key makes `dh_cs` all-zero and would let the peer dictate the DH
        // leg's contribution to the hybrid master (RFC 7748 §6.1). Silent drop
        // with no state mutation, like any other M2 verification failure (D12).
        let mut dh_cs = match self.kp_x.diffie_hellman(&x_pk) {
            Some(dh) => dh,
            None => {
                self.reset_m2_assembler();
                return Ok(ClientEvent::None);
            }
        };

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
    /// exit (D12); an empty roster fails closed, and the roster size is
    /// bounded by [`ServerConfig::max_roster_size`].
    pub roster: Vec<MlDsaPublicKey>,
    /// Maximum number of client keys the roster may hold.
    ///
    /// A D7 *resource* bound, not a security guarantee: the server verifies
    /// the client signature against **every** roster entry (D12, uniform
    /// verification count, no early exit), so a completing M1 costs
    /// `roster.len()` ML-DSA-65 verifications.  The bound turns an
    /// unbounded pre-authentication work amplifier into a finite one; it is
    /// operator-overridable, so a deployment that genuinely needs more keys
    /// can raise it (at the cost of proportionally more CPU per handshake).
    pub max_roster_size: usize,
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
    /// Default maximum roster size.
    ///
    /// # Why 64
    ///
    /// The bound exists because the D12 verification loop is uniform and has
    /// no early exit, so a completing M1 costs `roster.len()` ML-DSA-65
    /// verifications.  Measured on the reference host
    /// (`docs/performance/I-benchmark-methodology.md` §4.1, §6.3):
    ///
    /// | roster | D12 loop p50 | server-side handshake p50 |
    /// |---:|---:|---:|
    /// | 1 | 56.7 us | 0.84 ms |
    /// | 64 | 3.41 ms | 4.38 ms |
    /// | 256 | 13.7 ms | 15.1 ms |
    /// | 1024 | 56.3 ms | 57.3 ms |
    ///
    /// 64 keeps the worst-case completing M1 at **3.41 ms** of measured
    /// verification work — the same order as D16's "~2.5 ms CPU per side"
    /// claim (1.36x for the verification loop, 1.75x for the whole server
    /// handshake at 4.38 ms) — instead of the unbounded figure.  It is also the
    /// value already used by the two other capacity constants of the DoS
    /// posture (`max_sessions` = 64, `max_pending` = 64), and it is 64x the
    /// production roster of the 1:1 deployment model (D28: one client per
    /// server, so the deployed roster is 1).
    ///
    /// The number is a *policy* default, not a derived requirement: the
    /// security-relevant property is that a finite, enforced, operator-
    /// overridable bound exists on every entry point.  Deployments that
    /// genuinely need more keys raise it with
    /// [`ServerConfig::with_roster_limit`].
    pub const DEFAULT_MAX_ROSTER_SIZE: usize = 64;

    /// Construct with protocol defaults (DoS parameters are tunable — D7).
    ///
    /// **Fail closed on an over-limit roster.**  A roster larger than
    /// [`ServerConfig::DEFAULT_MAX_ROSTER_SIZE`] is *not* adopted: the
    /// returned configuration carries an empty roster, which every consumer
    /// rejects (`ServerSessionManager::new`, `server_handshake_v2`).  The
    /// roster is never silently truncated — it is either adopted whole or
    /// not at all, because a partial roster would silently revoke clients.
    ///
    /// Use [`ServerConfig::with_roster_limit`] to raise the limit for a
    /// deployment that needs more keys.
    pub fn new(identity: MlDsaKeypair, roster: Vec<MlDsaPublicKey>) -> Self {
        Self::with_roster_limit(identity, roster, Self::DEFAULT_MAX_ROSTER_SIZE)
    }

    /// Construct with an explicit roster-size limit (operator-overridable).
    ///
    /// The same fail-closed rule as [`ServerConfig::new`]: a roster larger
    /// than `max_roster_size` is not adopted, and the configuration is left
    /// with an empty roster.
    pub fn with_roster_limit(
        identity: MlDsaKeypair,
        roster: Vec<MlDsaPublicKey>,
        max_roster_size: usize,
    ) -> Self {
        let mut cfg = Self {
            version: PROTOCOL_VERSION,
            identity,
            roster: Vec::new(),
            max_roster_size,
            max_pending: 64,
            pending_ttl: Duration::from_secs(30),
            rate_limit_burst: 16,
            rate_limit_window: Duration::from_secs(10),
        };
        if roster.len() <= max_roster_size {
            cfg.roster = roster;
        }
        cfg
    }

    /// Validate this configuration (fail closed).
    ///
    /// Checks the protocol version, that the roster is non-empty (D12: an
    /// empty roster would silently revoke every client) and that it is not
    /// larger than [`ServerConfig::max_roster_size`].
    pub fn validate(&self) -> Result<(), HandshakeV2Error> {
        if self.version != PROTOCOL_VERSION {
            return Err(HandshakeV2Error::InvalidConfig(format!(
                "version {} unsupported (expected {PROTOCOL_VERSION})",
                self.version
            )));
        }
        if self.roster.is_empty() {
            return Err(HandshakeV2Error::InvalidConfig(
                "roster must not be empty (fail closed)".into(),
            ));
        }
        if self.roster.len() > self.max_roster_size {
            return Err(HandshakeV2Error::InvalidConfig(format!(
                "roster of {} keys exceeds the configured maximum of {}",
                self.roster.len(),
                self.max_roster_size
            )));
        }
        Ok(())
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
/// keeping buckets fresh).  At the cap, the oldest-inserted bucket is evicted
/// (O(1), from the insertion-order queue) and the table never exceeds the
/// cap.
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
    /// Insertion order of `rate_buckets`' keys.
    ///
    /// Invariant: `rate_order` holds exactly the keys of `rate_buckets`,
    /// each once, so `rate_order.len() == rate_buckets.len()`.  The
    /// cap-eviction victim is the front of this queue, so eviction is O(1)
    /// instead of a scan for the least-recently-refilled bucket.  The
    /// window prune removes the same keys from both.
    ///
    /// This is the same shape as the data-path failure gate
    /// (`session_manager::FailGate`): one insertion-order queue, one
    /// invariant, no second ordering to keep consistent.
    rate_order: VecDeque<SocketAddr>,
    /// When the window prune last ran (D29: amortized to at most one pass per
    /// `rate_limit_window`, so a spoofed-source flood cannot buy a per-packet
    /// O(n) scan by holding buckets fresh).
    last_rate_prune: Instant,
    /// Test instrumentation: the number of rate-bucket table entries visited
    /// by an operation that is not a plain hash lookup (cap evictions and
    /// prune passes).  The packet path must never move this counter for a
    /// source that is already tracked.
    #[cfg(test)]
    rate_table_visits: u64,
}

impl ServerHandshake {
    /// Create a server handshake state machine.  Configuration is validated
    /// by `server_handshake_v2` (empty roster / bad version fail closed).
    ///
    /// **Fail closed on an over-limit roster.**  If the configuration's
    /// roster is larger than `max_roster_size` (only reachable through a
    /// struct-literal construction that bypasses [`ServerConfig::new`]), the
    /// machine adopts an *empty* roster: the D12 uniform-verification loop
    /// must verify against the whole roster or against none of it, and a
    /// truncated roster would silently revoke clients.  An empty roster
    /// rejects every client, which is the safe direction.
    pub fn new(cfg: &ServerConfig) -> Self {
        let mut cfg = cfg.clone();
        if cfg.roster.len() > cfg.max_roster_size {
            cfg.roster = Vec::new();
        }
        Self {
            cfg,
            pending: HashMap::new(),
            rate_buckets: HashMap::new(),
            rate_order: VecDeque::new(),
            last_rate_prune: Instant::now(),
            #[cfg(test)]
            rate_table_visits: 0,
        }
    }

    /// Number of pending handshake entries (diagnostics).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Replace the client roster in place (D27).
    ///
    /// Parse-then-swap: the caller validates the whole roster before it gets
    /// here, so `set_roster` either adopts the new roster wholesale or leaves
    /// the machine untouched. An empty roster is rejected (fail closed — an
    /// empty roster would silently revoke every client), matching
    /// [`ServerConfig::new`]'s fail-closed contract.
    ///
    /// A roster larger than [`ServerConfig::max_roster_size`] is rejected for
    /// the same reason and with the same effect: the hot-swap path is a
    /// roster entry point like any other, and it must not be a way around
    /// the bound. The roster is never truncated — the previous roster stays
    /// in force.
    ///
    /// Membership is re-verified at M3 (`on_m3_fragment`), so a handshake that
    /// authenticated against a since-revoked key cannot complete after the
    /// swap. Established sessions are untouched: revocation stops *future*
    /// establishment, it does not tear down live sessions (D27 §5).
    pub fn set_roster(&mut self, roster: Vec<MlDsaPublicKey>) -> Result<(), HandshakeV2Error> {
        if roster.is_empty() {
            return Err(HandshakeV2Error::InvalidConfig(
                "roster must not be empty (fail closed)".into(),
            ));
        }
        if roster.len() > self.cfg.max_roster_size {
            return Err(HandshakeV2Error::InvalidConfig(format!(
                "roster of {} keys exceeds the configured maximum of {}",
                roster.len(),
                self.cfg.max_roster_size
            )));
        }
        self.cfg.roster = roster;
        Ok(())
    }

    /// Number of client keys currently on the roster (diagnostics).
    pub fn roster_len(&self) -> usize {
        self.cfg.roster.len()
    }

    /// `true` if `pk` is on the current roster.
    ///
    /// The post-swap membership check for a pending handshake; not a
    /// constant-time operation and not used on any authentication path.
    pub fn roster_contains(&self, pk: &MlDsaPublicKey) -> bool {
        self.cfg.roster.iter().any(|k| k.encode() == pk.encode())
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
        // D29: the window prune is amortized to at most one pass per
        // `rate_limit_window` instead of running on every packet once the
        // table exceeds 32 entries.  The prune is a *memory cleanup*, not a
        // correctness requirement: a bucket older than the window refills to
        // a full burst on its next touch (below), so a stale entry costs
        // memory, never correctness.  Holding buckets fresh therefore no
        // longer buys a per-packet O(n) scan, and the cap below remains the
        // real memory bound.
        if self.rate_buckets.len() > 32
            && (now.duration_since(self.last_rate_prune) >= self.cfg.rate_limit_window
                || now.duration_since(self.last_rate_prune) < Duration::from_nanos(1))
        {
            self.last_rate_prune = now;
            self.rate_buckets
                .retain(|_, b| now.duration_since(b.last_refill) < self.cfg.rate_limit_window);
            // Keep `rate_order` in lockstep with `rate_buckets`: the swept
            // keys are gone from the table, so they are gone from the queue.
            {
                let buckets = &self.rate_buckets;
                self.rate_order.retain(|k| buckets.contains_key(k));
            }
            #[cfg(test)]
            {
                self.rate_table_visits += (self.rate_buckets.len() + self.rate_order.len()) as u64;
            }
        }
        // An already-tracked source: charge its own budget.  This is the hot
        // path and it is O(1) — one hash lookup, no eviction, no insert and
        // no scan of the table.  (Before the fix, the cap eviction ran on
        // *every* call once the table was at the cap, so a repeat source's
        // packet evicted a *different* source's bucket — resetting that
        // source's token budget — and paid an O(n) `min_by_key` scan for it.)
        if let Some(bucket) = self.rate_buckets.get_mut(&from) {
            if now.duration_since(bucket.last_refill) >= self.cfg.rate_limit_window {
                bucket.tokens = self.cfg.rate_limit_burst;
                bucket.last_refill = now;
            }
            if bucket.tokens == 0 {
                return false;
            }
            bucket.tokens -= 1;
            return true;
        }
        // A new source: make room first.  The victim is the oldest-*inserted*
        // tracked source (the front of `rate_order`), so the eviction is
        // O(1) — one queue pop and one map removal, no scan.  The victim is
        // never the source being inserted (that one is not tracked yet).
        //
        // The victim policy is the same one the data-path failure gate uses
        // (D24): under table pressure *any* eviction policy allows a budget
        // reset, and the least-recently-refilled bucket is precisely the one
        // a table-filling attacker would keep fresh — so oldest-inserted is
        // no weaker and costs one pop instead of a scan.
        while self.rate_buckets.len() >= MAX_RATE_BUCKETS {
            match self.rate_order.pop_front() {
                Some(victim) => {
                    self.rate_buckets.remove(&victim);
                    #[cfg(test)]
                    {
                        self.rate_table_visits += 1;
                    }
                }
                // Unreachable while the `rate_order`/`rate_buckets` invariant
                // holds.
                None => break,
            }
        }
        let mut bucket = RateBucket {
            tokens: self.cfg.rate_limit_burst,
            last_refill: now,
        };
        // The admit/refuse decision is taken on the *pre-decrement* budget,
        // exactly as the pre-refactor path did.
        let allowed = bucket.tokens > 0;
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
        }
        self.rate_buckets.insert(from, bucket);
        self.rate_order.push_back(from);
        allowed
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
            // Snapshot the entry fields this arm needs: no `self.pending` borrow
            // may be live across `rate_ok`, which takes `&mut self`.
            let (entry_source, entry_state) = {
                let entry = self.pending.get(&sid).expect("checked");
                (entry.source, entry.state)
            };
            if entry_source != from {
                // sid collision across sources → reject the newcomer (D13).
                return Ok(ServerEvent::None);
            }
            match entry_state {
                PendingState::AwaitM1 => {
                    // Feed the fragment (it advances the assembler) in its own
                    // scoped borrow.
                    let frag_result = {
                        let entry = self.pending.get_mut(&sid).expect("checked");
                        let asm = entry.assembler.as_mut().expect("AwaitM1 has assembler");
                        asm.add_fragment(&frag)
                    };
                    match frag_result {
                        FragmentResult::Completed => {
                            // Expensive work (roster verify + KEM) is per-source
                            // budgeted like every other allocation (D13 DoS pin).
                            // The gate runs BEFORE the ~5.6 KiB reassembly copy so
                            // a refused source never pays for it; the copy is pure
                            // local work, so ordering it after the gate changes
                            // neither token accounting nor the success path.
                            if !self.rate_ok(from) {
                                return Ok(ServerEvent::None);
                            }
                            let m1_bytes = {
                                let entry = self.pending.get(&sid).expect("checked");
                                let asm = entry.assembler.as_ref().expect("AwaitM1 has assembler");
                                asm.message().expect("complete").to_vec()
                            };
                            self.complete_m1(sid, m1_bytes, from)
                        }
                        // Only state-advancing fragments extend the TTL; a
                        // duplicate flood cannot keep an entry alive.
                        FragmentResult::Advanced => {
                            let entry = self.pending.get_mut(&sid).expect("checked");
                            entry.last_seen = Instant::now();
                            Ok(ServerEvent::None)
                        }
                        FragmentResult::Ignored => Ok(ServerEvent::None),
                    }
                }
                PendingState::AwaitM3 => {
                    let (body, src) = {
                        let entry = self.pending.get(&sid).expect("checked");
                        let body = entry
                            .m2_cache
                            .as_ref()
                            .expect("AwaitM3 has M2 cache")
                            .clone();
                        (body, entry.source)
                    };
                    if frag.frag_idx != 0 {
                        return Ok(ServerEvent::None);
                    }
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
        // Fail secure on a non-contributory X25519 exchange: a low-order
        // client key makes `dh_cs` all-zero and would let the client dictate
        // the DH leg's contribution to the hybrid master (RFC 7748 §6.1).
        // Silent drop with no M2 and no session state, like every other M1
        // failure (D12) — never an error, never an amplification.
        let mut dh_cs = match x_kp.diffie_hellman(&x_pk) {
            Some(dh) => dh,
            None => {
                self.pending.remove(&sid);
                return Ok(ServerEvent::None);
            }
        };

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

        // D27 revocation re-check: membership is re-verified at the LAST
        // moment before a session comes into existence.  `complete_m1`
        // authenticated against the roster as it stood then; a swap between M1
        // and M3 must not be able to mint a session.  Fail closed: drop the
        // pending entry (zeroizing its key material on drop) and return no
        // outcome, so the client never gets a session and simply retries into
        // its handshake budget.
        if !self.roster_contains(&peer_identity) {
            self.pending.remove(&sid);
            return Ok(ServerEvent::None);
        }

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
    cfg.validate()?;
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

    /// D24 — exact per-source token accounting, observed through the gate.
    ///
    /// A full 4-fragment M1 costs exactly **2** tokens: one at fragment 0
    /// (pending-entry ALLOCATION) and one at the completing fragment (the gate
    /// that precedes the expensive crypto: roster verify + KEM).  Fragments 1-2
    /// return `FragmentResult::Advanced` and are free — they memcpy into an
    /// already-allocated buffer, performing no allocation and no crypto.  M3
    /// costs 1 more, so M1 + M3 = 3.
    ///
    /// Proven deterministically with `rate_limit_burst = 3`: with a full M1+M3
    /// costing 3, a *second* full M1 from the same source is refused outright
    /// (its fragment 0 cannot even allocate), whereas a budget of 4 would let
    /// the second M1 allocate.  `pending_len` is the discriminator and needs no
    /// wall clock.
    #[test]
    fn d24_full_m1_costs_two_tokens_and_m3_one_more() {
        let (cc, mut sc) = test_configs();
        sc.rate_limit_burst = 3; // exactly M1 (2) + M3 (1)

        // First handshake.  `reach_await_m3` stops *before* delivering M3, so
        // at this point exactly the M1's 2 tokens are spent and 1 remains.
        let sid = [41u8; SESSION_ID_LEN];
        let (_, mut server, _, m3_frags) = reach_await_m3(&cc, &sc, sid);
        assert_eq!(server.pending_len(), 1, "first handshake held its entry");

        // The remaining single token is exactly the M3's cost: the genuine M3
        // is accepted and completes the handshake.
        assert!(
            matches!(
                server
                    .handle_datagram(&m3_frags[0], CLIENT_ADDR)
                    .expect("srv"),
                ServerEvent::Complete(_)
            ),
            "M1 (2) + M3 (1) exactly exhausts a 3-token budget"
        );
        assert_eq!(
            server.pending_len(),
            0,
            "entry consumed by the completed M3"
        );

        // Budget now empty: a second full M1 from the same source is refused
        // outright — its fragment 0 cannot even allocate a pending entry.  If
        // the M1 had cost fewer than 2 tokens this entry would exist.
        let sid2 = [42u8; SESSION_ID_LEN];
        let client2 = ClientHandshake::new(&cc, sid2).expect("client");
        let mut m2 = Vec::new();
        for f in client2.m1_frags() {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                m2 = frags;
            }
        }
        assert!(
            m2.is_empty(),
            "an exhausted budget must refuse the second M1 outright"
        );
        assert_eq!(
            server.pending_len(),
            0,
            "the second M1 must not allocate a pending entry (frag 0 is gated)"
        );
    }

    /// D24 — the completion charge is charged at the completing fragment, not
    /// at allocation, and pure-reassembly fragments are free.  With a budget of
    /// exactly 2 (one allocation + one completion), a full M1 emits its M2 and
    /// spends everything.
    #[test]
    fn d24_reassembly_fragments_are_free_but_completion_is_charged() {
        let (cc, mut sc) = test_configs();
        sc.rate_limit_burst = 2;
        let mut server = ServerHandshake::new(&sc);
        let sid = [43u8; SESSION_ID_LEN];

        let client = ClientHandshake::new(&cc, sid).expect("client");
        let m1 = client.m1_frags().to_vec();
        assert_eq!(m1.len(), M1_FRAG_COUNT as usize, "M1 is 4 fragments");

        // Fragment 0: charged (allocation), 1 token left.
        server.handle_datagram(&m1[0], CLIENT_ADDR).expect("srv");
        assert_eq!(server.pending_len(), 1, "frag 0 allocated the entry");

        // Fragments 1 and 2: `Advanced`, no charge — they advance the entry.
        for (i, f) in m1.iter().enumerate().take(3).skip(1) {
            assert!(
                matches!(
                    server.handle_datagram(f, CLIENT_ADDR).expect("srv"),
                    ServerEvent::None
                ),
                "reassembly fragment {i} emits nothing"
            );
        }
        assert_eq!(
            server.pending_len(),
            1,
            "reassembly fragments are free and keep the entry"
        );

        // Fragment 3 completes the M1: charged (expensive crypto gate) and the
        // budget is now exactly empty — the M2 is still emitted.
        let mut m2 = Vec::new();
        if let ServerEvent::Emit(frags, _) =
            server.handle_datagram(&m1[3], CLIENT_ADDR).expect("srv")
        {
            m2 = frags;
        }
        assert_eq!(m2.len(), M2_FRAG_COUNT as usize, "full M2 emitted");

        // Budget empty: a second M1's fragment 0 cannot allocate.
        let sid2 = [44u8; SESSION_ID_LEN];
        let client2 = ClientHandshake::new(&cc, sid2).expect("client");
        server
            .handle_datagram(&client2.m1_frags()[0], CLIENT_ADDR)
            .expect("srv");
        assert_eq!(
            server.pending_len(),
            1,
            "an exhausted 2-token budget refuses a second M1 at frag 0"
        );
    }

    /// An invalid M1 is still rejected correctly after the reordered gate: the
    /// `rate_ok` decision now precedes the ~5.6 KiB reassembly copy, but the
    /// failure semantics (no M2, no session state, silent drop) are unchanged.
    #[test]
    fn d24_invalid_m1_is_still_rejected_after_the_reorder() {
        let (cc, mut sc) = test_configs();
        sc.rate_limit_burst = 16;
        let mut server = ServerHandshake::new(&sc);
        let sid = [45u8; SESSION_ID_LEN];

        // Reassemble a structurally valid M1, then corrupt a signature byte in
        // the final fragment so roster verification fails in `complete_m1`.
        let client = ClientHandshake::new(&cc, sid).expect("client");
        let m1 = client.m1_frags().to_vec();
        let mut dg = *m1[3].as_bytes();
        let pos = HS_FRAG_HEADER_LEN + 4; // inside the ClientHello signature
        dg[pos] ^= 0xFF;
        let corrupt = WirePacket::from_bytes(&dg).expect("1280");

        for (i, f) in m1.iter().enumerate() {
            let pkt = if i == 3 { &corrupt } else { f };
            assert!(
                matches!(
                    server.handle_datagram(pkt, CLIENT_ADDR).expect("srv"),
                    ServerEvent::None
                ),
                "an unverifiable M1 must be a silent drop"
            );
        }
        assert_eq!(
            server.pending_len(),
            0,
            "invalid M1: no session state, no M2 (D12)"
        );
    }

    /// Valid M1 retransmission semantics are unchanged by the reorder: a
    /// duplicate M1 after M2 resends the cached M2 byte-identical, once per
    /// burst.  This is the D13 client-driven retransmission contract and the
    /// reason the completion arm cannot change what it charges or returns.
    #[test]
    fn d24_valid_m1_retransmission_is_unchanged() {
        let (cc, sc) = test_configs();
        let sid = [46u8; SESSION_ID_LEN];
        let (_, mut server, m2_frags, _) = reach_await_m3(&cc, &sc, sid);
        assert_eq!(m2_frags.len(), M2_FRAG_COUNT as usize);

        let client = ClientHandshake::new(&cc, sid).expect("client");
        let m1 = client.m1_frags().to_vec();

        // One retransmit burst yields exactly ONE byte-identical M2 resend.
        let mut resends: Vec<Vec<WirePacket>> = Vec::new();
        for f in &m1 {
            if let ServerEvent::Emit(frags, _) =
                server.handle_datagram(f, CLIENT_ADDR).expect("srv")
            {
                resends.push(frags);
            }
        }
        assert_eq!(resends.len(), 1, "one M2 resend per retransmit burst");
        assert_eq!(resends[0].len(), m2_frags.len(), "resend is the full M2");
        for (a, b) in resends[0].iter().zip(&m2_frags) {
            assert_eq!(
                a.as_bytes(),
                b.as_bytes(),
                "cached M2 resend must be byte-identical"
            );
        }
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

    /// D29: the window prune must be amortized, not per-packet.
    ///
    /// Before the fix, `rate_ok` ran a `retain` scan over the whole bucket
    /// table on *every* packet once the table exceeded 32 entries. An
    /// unauthenticated attacker who grew the table past 32 (one source
    /// address with many ports — the same amplification D24 removed from the
    /// data path) and kept it there could buy an O(n) scan per packet: on
    /// this host, measured at 65 µs/pkt at the 4096 cap versus 1.6 µs/pkt on
    /// a small table.
    ///
    /// The invariant is asserted structurally, not by timing: with the
    /// prune window satisfied, a flood of packets from many fresh sources
    /// must not run more than one prune pass. `prune_passes` counts the
    /// actual scans.
    #[test]
    fn rate_ok_prune_is_amortized_not_per_packet() {
        let (_, mut sc) = test_configs();
        sc.rate_limit_window = Duration::from_secs(10);
        let mut server = ServerHandshake::new(&sc);
        server.last_rate_prune = Instant::now() - sc.rate_limit_window - Duration::from_secs(1);

        // Count prune passes by observing the table shrink. Grow it above 32
        // with fresh buckets, all within one window (so a prune keeps them).
        for i in 0..100u64 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 3, (i >> 8) as u8, i as u8)),
                40000 + (i % 1000) as u16,
            );
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&i.to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), addr)
                .expect("srv");
        }
        assert!(
            server.rate_buckets.len() > 32,
            "table must exceed 32 for the prune to be reachable, got {}",
            server.rate_buckets.len()
        );

        // First packet after the window runs exactly one prune (which keeps
        // the fresh buckets). Record the prune timestamp.
        let first_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 55555);
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&9999u64.to_be_bytes());
        server
            .handle_datagram(&m1_frag0_datagram(sid), first_src)
            .expect("srv");
        let after_first = server.last_rate_prune;

        // Now flood from many more fresh sources, all inside the same window.
        // Each of these must be refused a prune pass (window not elapsed), so
        // `last_rate_prune` is unchanged and the table is NOT rescanned.
        let len_before = server.rate_buckets.len();
        for i in 0..500u64 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 4, (i >> 8) as u8, i as u8)),
                30000 + (i % 2000) as u16,
            );
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&(i + 20_000).to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), addr)
                .expect("srv");
        }
        assert_eq!(
            server.last_rate_prune, after_first,
            "no packet inside the window may trigger another prune pass"
        );
        assert_eq!(
            server.rate_buckets.len(),
            len_before + 500,
            "inside the window every fresh source is retained (no prune ran)"
        );
    }

    /// D29: the amortized prune must still actually reclaim memory.  After a
    /// window elapses with no traffic, the next packet runs one prune and
    /// stale buckets are gone — the cap remains the backstop, but the
    /// periodic prune is not defeated by the amortization.
    #[test]
    fn rate_ok_prune_still_reclaims_after_window() {
        let (_, mut sc) = test_configs();
        sc.rate_limit_window = Duration::from_millis(50);
        let mut server = ServerHandshake::new(&sc);

        for i in 0..100u64 {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 5, (i >> 8) as u8, i as u8)),
                40000 + (i % 1000) as u16,
            );
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&i.to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), addr)
                .expect("srv");
        }
        assert!(server.rate_buckets.len() > 32);

        // Rewind the prune clock and age every bucket past the window.
        std::thread::sleep(sc.rate_limit_window + Duration::from_millis(10));
        for b in server.rate_buckets.values_mut() {
            b.last_refill = Instant::now() - sc.rate_limit_window - Duration::from_secs(1);
        }
        server.last_rate_prune = Instant::now() - sc.rate_limit_window - Duration::from_secs(1);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 6, 6, 6)), 51000);
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&4242u64.to_be_bytes());
        server
            .handle_datagram(&m1_frag0_datagram(sid), src)
            .expect("srv");
        assert_eq!(
            server.rate_buckets.len(),
            1,
            "one prune after the window must reclaim every stale bucket"
        );
        assert_eq!(
            server.rate_order.len(),
            server.rate_buckets.len(),
            "the insertion-order queue must stay in lockstep with the table"
        );
    }

    // -----------------------------------------------------------------------
    // Rate-bucket cap eviction: O(1), and never on behalf of a tracked source
    // -----------------------------------------------------------------------

    /// Fill the rate-bucket table to its cap with `n` distinct sources and
    /// return the source addresses in insertion order.
    fn fill_rate_table(server: &mut ServerHandshake, n: usize) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(n);
        for i in 0..n {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, (i >> 8) as u8, i as u8, 7)),
                40000 + (i % 1000) as u16,
            );
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&(i as u64).to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), addr)
                .expect("srv");
            addrs.push(addr);
        }
        addrs
    }

    /// The hot path must be O(1): a packet from a source that is *already*
    /// tracked must not visit a single table entry.
    ///
    /// Before the fix, the cap eviction ran on every call once the table was
    /// at the cap: it scanned the whole table for the least-recently-refilled
    /// bucket (`min_by_key`) and removed one — even when the arriving source
    /// was already in the table, i.e. a repeat source's packet evicted a
    /// *different* source's bucket and reset that source's token budget.
    ///
    /// The invariant is asserted structurally (a visit counter), never by
    /// timing.
    #[test]
    fn rate_ok_hot_path_visits_no_table_entry() {
        let (_, sc) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        let addrs = fill_rate_table(&mut server, MAX_RATE_BUCKETS);
        assert_eq!(server.rate_buckets.len(), MAX_RATE_BUCKETS);
        let visits_before = server.rate_table_visits;

        // 200 further packets, all from one already-tracked source.
        for i in 0..200u64 {
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&(100_000u64 + i).to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), addrs[0])
                .expect("srv");
        }

        assert_eq!(
            server.rate_table_visits, visits_before,
            "a packet from a tracked source must not visit the table at all"
        );
        assert_eq!(
            server.rate_buckets.len(),
            MAX_RATE_BUCKETS,
            "a tracked source's packet must not evict anybody"
        );
        assert_eq!(
            server.rate_order.len(),
            server.rate_buckets.len(),
            "the insertion-order queue must stay in lockstep with the table"
        );
    }

    /// A repeat source must be charged its own budget and must not evict —
    /// let alone reset the budget of — any *other* source.
    ///
    /// The pre-fix code evicted the *stalest* bucket on every call at the
    /// cap, so a tracked source's packet could hand a different source a
    /// fresh token budget.  This test is set up so that the oldest-inserted
    /// source is also the stalest: under the pre-fix policy that source
    /// would have been evicted by a packet from a *different* tracked source,
    /// so the assertion is not vacuous.
    #[test]
    fn rate_ok_tracked_source_does_not_reset_another_sources_budget() {
        let (_, mut sc) = test_configs();
        sc.rate_limit_burst = 4;
        sc.rate_limit_window = Duration::from_secs(600);
        let mut server = ServerHandshake::new(&sc);
        let addrs = fill_rate_table(&mut server, MAX_RATE_BUCKETS);

        // Spend the whole budget of the *oldest* inserted source.
        let oldest = addrs[0];
        for i in 0..4u64 {
            let mut sid = [0u8; SESSION_ID_LEN];
            sid.copy_from_slice(&(200_000u64 + i).to_be_bytes());
            server
                .handle_datagram(&m1_frag0_datagram(sid), oldest)
                .expect("srv");
        }
        assert_eq!(server.rate_buckets[&oldest].tokens, 0);

        // A packet from a *different*, already-tracked source must neither
        // evict the exhausted source nor hand it a fresh budget.
        server
            .handle_datagram(&m1_frag0_datagram([9u8; SESSION_ID_LEN]), addrs[5])
            .expect("srv");
        assert!(
            server.rate_buckets.contains_key(&oldest),
            "a tracked source's packet must not evict another source"
        );
        assert_eq!(
            server.rate_buckets[&oldest].tokens, 0,
            "another source's packet must not reset an exhausted source's budget"
        );
    }

    /// The cap eviction is O(1) and takes the *oldest-inserted* source.
    ///
    /// The victim policy matches the data-path failure gate (D24): under
    /// table pressure any eviction policy allows a budget reset, and the
    /// least-recently-refilled bucket is the one a table-filling attacker
    /// keeps fresh, so oldest-inserted is no weaker — and it costs one pop
    /// instead of a scan.
    #[test]
    fn rate_ok_cap_eviction_is_o1_and_takes_the_oldest_inserted_source() {
        let (_, sc) = test_configs();
        let mut server = ServerHandshake::new(&sc);
        let addrs = fill_rate_table(&mut server, MAX_RATE_BUCKETS);
        let visits_before = server.rate_table_visits;

        // One more distinct source pushes the table past the cap.
        let newcomer = SocketAddr::new(Ipv4Addr::new(10, 99, 99, 99).into(), 45000);
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&300_000u64.to_be_bytes());
        server
            .handle_datagram(&m1_frag0_datagram(sid), newcomer)
            .expect("srv");

        assert_eq!(
            server.rate_buckets.len(),
            MAX_RATE_BUCKETS,
            "the table must never exceed the cap"
        );
        assert_eq!(
            server.rate_table_visits - visits_before,
            1,
            "the eviction must visit exactly one table entry"
        );
        assert!(
            !server.rate_buckets.contains_key(&addrs[0]),
            "the oldest-inserted source is the victim"
        );
        for a in &addrs[1..] {
            assert!(
                server.rate_buckets.contains_key(a),
                "no other source may be evicted"
            );
        }
        assert_eq!(
            server.rate_order.len(),
            server.rate_buckets.len(),
            "the insertion-order queue must stay in lockstep with the table"
        );
    }

    /// The window prune is a *memory cleanup*, not a correctness requirement:
    /// a bucket the prune removes and a bucket it keeps behave identically
    /// on the source's next touch (both refill to a full burst), so skipping
    /// or performing the prune can never change an accept/reject decision.
    ///
    /// The two cases are compared directly: the same source, with the same
    /// aged-out bucket, is charged once on a server where the prune ran and
    /// once on a server where it did not.  The resulting budget must be
    /// identical.
    #[test]
    fn rate_ok_prune_is_decision_preserving() {
        const BURST: u32 = 8;

        /// One server: `prune` decides whether the window prune runs.
        fn budget_after_one_stale_touch(prune: bool) -> u32 {
            let (_, mut sc) = test_configs();
            sc.rate_limit_burst = BURST;
            sc.rate_limit_window = Duration::from_millis(50);
            let mut server = ServerHandshake::new(&sc);

            // 40 tracked sources, so the prune is reachable (it only runs
            // above 32 entries).
            let addrs = fill_rate_table(&mut server, 40);
            let subject = addrs[0];

            // Age every bucket past the window.
            let aged = Instant::now() - sc.rate_limit_window - Duration::from_secs(1);
            for b in server.rate_buckets.values_mut() {
                b.last_refill = aged;
            }
            if prune {
                // Rewind the prune clock so the next packet runs one pass.
                server.last_rate_prune = aged;
                server
                    .handle_datagram(&m1_frag0_datagram([77u8; SESSION_ID_LEN]), addrs[39])
                    .expect("srv");
                assert!(
                    !server.rate_buckets.contains_key(&subject),
                    "the prune must have reclaimed the stale bucket"
                );
            } else {
                assert!(
                    server.rate_buckets.contains_key(&subject),
                    "without a prune the stale bucket must survive"
                );
            }

            // The subject's next touch: same decision, same budget.
            server
                .handle_datagram(&m1_frag0_datagram([78u8; SESSION_ID_LEN]), subject)
                .expect("srv");
            server.rate_buckets[&subject].tokens
        }

        let pruned = budget_after_one_stale_touch(true);
        let kept = budget_after_one_stale_touch(false);
        assert_eq!(
            pruned, kept,
            "the prune must not change the budget a source is left with"
        );
        assert_eq!(
            pruned,
            BURST - 1,
            "a stale source is refilled to a full burst and then charged once"
        );
    }

    // -----------------------------------------------------------------------
    // Roster-size bound (D12 uniform verification => the bound is a work bound)
    // -----------------------------------------------------------------------
    /// `n` distinct ML-DSA-65 public keys.
    fn roster_of(n: usize) -> Vec<MlDsaPublicKey> {
        (0..n)
            .map(|_| MlDsaKeypair::generate().expect("keygen").public_key())
            .collect()
    }

    /// The default roster limit is **64** — written out, not derived from the
    /// constant, so a change to the constant fails this test.
    #[test]
    fn roster_limit_default_is_64() {
        assert_eq!(ServerConfig::DEFAULT_MAX_ROSTER_SIZE, 64);
    }

    /// A roster of exactly the limit is accepted, and the hot-swap path
    /// accepts it too.
    #[test]
    fn roster_at_the_limit_is_accepted() {
        let (client_id, server_id) = test_ids();
        let roster = roster_of(64);
        let sc = ServerConfig::new(server_id, roster.clone());
        assert_eq!(
            sc.roster.len(),
            64,
            "a roster of exactly the limit must be adopted whole"
        );
        assert!(sc.validate().is_ok());

        let mut server = ServerHandshake::new(&sc);
        assert_eq!(server.roster_len(), 64);
        server
            .set_roster(roster)
            .expect("a roster of exactly the limit must be accepted by the hot-swap path");
        assert_eq!(server.roster_len(), 64);
        let _ = client_id;
    }

    /// One key over the limit fails closed, and the hot-swap path leaves the
    /// previous roster in force (no truncation, no partial adoption).
    #[test]
    fn roster_one_over_the_limit_fails_closed() {
        let (_, server_id) = test_ids();
        let roster = roster_of(65);
        let sc = ServerConfig::new(server_id, roster.clone());
        assert!(
            sc.roster.is_empty(),
            "an over-limit roster must not be adopted"
        );
        assert!(sc.validate().is_err(), "validation must fail closed");

        // The hot-swap path rejects it and keeps the old roster in force.
        let mut server = ServerHandshake::new(&sc);
        let good = roster_of(1);
        server
            .set_roster(good.clone())
            .expect("a roster within the limit is accepted");
        assert!(
            server.set_roster(roster).is_err(),
            "an over-limit roster must be rejected by the hot-swap path"
        );
        assert_eq!(
            server.roster_len(),
            1,
            "a rejected swap must leave the previous roster in force"
        );
    }

    /// The limit is a `ServerConfig` field, so an operator can raise it (and
    /// lower it).  A raised limit adopts the whole roster; a lowered limit
    /// fails closed.
    #[test]
    fn roster_limit_is_operator_overridable() {
        let (_, server_id) = test_ids();
        let roster = roster_of(65);

        let raised = ServerConfig::with_roster_limit(server_id.clone(), roster.clone(), 128);
        assert_eq!(
            raised.roster.len(),
            65,
            "a raised limit must adopt the whole roster"
        );
        assert!(raised.validate().is_ok());

        let lowered = ServerConfig::with_roster_limit(server_id, roster, 1);
        assert!(
            lowered.roster.is_empty(),
            "a lowered limit must fail closed, not truncate"
        );
        assert!(lowered.validate().is_err());
    }

    /// A handshake machine built from an over-limit configuration must never
    /// verify against more than the limit allows.  The D12 uniform loop
    /// verifies against the *whole* roster or against none of it, so the
    /// fail-closed direction is an empty roster (every client is rejected),
    /// never a truncated one.
    #[test]
    fn handshake_machine_fails_closed_on_an_over_limit_roster() {
        let (_, server_id) = test_ids();
        let mut sc = ServerConfig::new(server_id, roster_of(65));
        // Bypass the constructor's fail-closed rule to model a struct-literal
        // configuration that skipped it.
        sc.roster = roster_of(65);
        let server = ServerHandshake::new(&sc);
        assert_eq!(
            server.roster_len(),
            0,
            "an over-limit configuration must yield a machine that trusts nobody"
        );
    }

    /// The standalone server driver rejects an over-limit roster before it
    /// touches the network.
    #[tokio::test]
    async fn server_rejects_an_over_limit_roster() {
        let (_, server_id) = test_ids();
        // Build a configuration whose roster exceeds its own limit, bypassing
        // the constructor's fail-closed adoption rule.
        let mut sc = ServerConfig::with_roster_limit(server_id, roster_of(1), 64);
        sc.roster = roster_of(65);
        let (client_t, mut server_t, _guard) = wired_transports();
        let srv = tokio::spawn(async move { server_handshake_v2(&mut server_t, &sc).await });
        let cli = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            client_t
        });
        let (srv_res, _) = tokio::join!(srv, cli);
        assert!(matches!(
            srv_res.expect("join"),
            Err(HandshakeV2Error::InvalidConfig(_))
        ));
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

    // -----------------------------------------------------------------------
    // Non-contributory X25519 / low-order key substitution (RFC 7748 §6.1)
    // -----------------------------------------------------------------------
    //
    // Two distinct properties are proved here:
    //
    // 1. `TH1` covers the client's X25519 key and `TH2` covers the server's,
    //    so the ML-DSA signatures make key substitution *detectable*. This is
    //    the primary defence and it already exists.
    // 2. The contributory check is defence in depth for the case where a
    //    legitimate roster member (or a future protocol revision) does supply
    //    a low-order key: it must abort rather than contribute zero entropy.

    /// The server's X25519 key is inside `M2`, and `M2` is inside `TH2` under
    /// the server's ML-DSA signature. Replacing it must break verification.
    #[test]
    fn th2_binds_the_servers_x25519_key() {
        let (cc, sc) = test_configs();
        let sid = [60u8; SESSION_ID_LEN];
        let m1_s = encode_real_m1(&cc, sid);

        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct2) = encapsulate(&peer.public).expect("encaps");

        let m2_z = encode_m2(
            sc.version,
            sid,
            &kp.public,
            &x.public.to_bytes(),
            &ct2,
            None,
        );
        let th2 = th2_from_m1_m2(&m1_s, &m2_z).expect("fixed");

        // Same M2 with the X25519 key replaced by the low-order u=0 point.
        let mut m2_forged = m2_z;
        let x_off = 9 + ML_KEM_768_PUBLIC_KEY_BYTES;
        for b in &mut m2_forged[x_off..x_off + 32] {
            *b = 0;
        }
        let th2_forged = th2_from_m1_m2(&m1_s, &m2_forged).expect("fixed");
        assert_ne!(
            th2, th2_forged,
            "TH2 must bind the server's X25519 public key (D13 full-M2 coverage)"
        );

        // And the server's signature over the pristine TH2 must not verify
        // against the tampered transcript.
        let server_sig = sc.identity.sign(&th2).expect("sign");
        assert!(
            !verify(&sc.identity.public, &th2_forged, &server_sig).expect("verify"),
            "an X25519 substitution must break the ML-DSA signature check"
        );
    }

    /// `TH1` covers the client's X25519 key: the client's own signature over
    /// the pristine `TH1` must not verify against a tampered `TH1`.
    #[test]
    fn th1_binds_the_clients_x25519_key() {
        let (cc, _) = test_configs();
        let sid = [61u8; SESSION_ID_LEN];
        let kp = MlKemKeypair::generate().expect("keygen");
        let x = X25519Keypair::generate();
        let pre_sign = encode_m1(cc.version, sid, &kp.public, &x.public.to_bytes(), None);
        let th1 = th1_from_m1(&pre_sign).expect("fixed");
        let client_sig = cc.identity.sign(&th1).expect("sign");

        let mut m1_forged = pre_sign;
        let x_off = 9 + ML_KEM_768_PUBLIC_KEY_BYTES;
        for b in &mut m1_forged[x_off..x_off + 32] {
            *b = 0;
        }
        let th1_forged = th1_from_m1(&m1_forged).expect("fixed");
        assert_ne!(th1, th1_forged, "TH1 must bind the client's X25519 key");
        assert!(
            !verify(&cc.identity.public, &th1_forged, &client_sig).expect("verify"),
            "an X25519 substitution must break the client's signature check"
        );
    }

    /// Defence in depth: if a roster member really does present a low-order
    /// X25519 key, the server must abort instead of deriving a master whose
    /// DH leg is all-zero.
    #[test]
    fn server_rejects_non_contributory_client_x25519_key() {
        let (cc, sc) = test_configs();
        let sid = [62u8; SESSION_ID_LEN];

        // A well-formed, correctly signed M1 whose X25519 key is the low-order
        // u=0 point.
        let kp = MlKemKeypair::generate().expect("keygen");
        let x_c = [0u8; 32];
        let pre_sign = encode_m1(cc.version, sid, &kp.public, &x_c, None);
        let th1 = th1_from_m1(&pre_sign).expect("fixed");
        let sig = cc.identity.sign(&th1).expect("sign");
        let m1 = encode_m1(cc.version, sid, &kp.public, &x_c, Some(&sig));

        let frags = fragment_message(HS_TYPE_CLIENT_HELLO, cc.version, sid, &m1).expect("frag");
        let mut server = ServerHandshake::new(&sc);
        let mut emitted = 0;
        for f in &frags {
            if let ServerEvent::Emit(..) = server.handle_datagram(f, CLIENT_ADDR).expect("srv") {
                emitted += 1;
            }
        }
        assert_eq!(emitted, 0, "a low-order X25519 key must elicit no M2 (D12)");
        assert_eq!(
            server.pending_len(),
            0,
            "a low-order X25519 key must leave no session state (D12)"
        );
    }

    /// The mirror case on the client side: a signed M2 carrying a low-order
    /// server X25519 key must not produce an M3 or a master.
    #[test]
    fn client_rejects_non_contributory_server_x25519_key() {
        let (cc, sc) = test_configs();
        let sid = [63u8; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).expect("client");

        // Build a real M2 from the server, but with the X25519 key zeroed
        // before it is signed — i.e. a genuinely non-contributory exchange the
        // client would otherwise accept.
        let kp = MlKemKeypair::generate().expect("keygen");
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct2) = encapsulate(&peer.public).expect("encaps");
        let m2_z = encode_m2(sc.version, sid, &kp.public, &[0u8; 32], &ct2, None);
        let th2 = th2_from_m1_m2(&client.m1.encode(), &m2_z).expect("fixed");
        let sig = sc.identity.sign(&th2).expect("sign");
        let m2 = encode_m2(sc.version, sid, &kp.public, &[0u8; 32], &ct2, Some(&sig));
        let m2_frags = fragment_message(HS_TYPE_SERVER_HELLO, sc.version, sid, &m2).expect("frag");

        for f in &m2_frags {
            assert!(
                matches!(client.handle_datagram(f), Ok(ClientEvent::None)),
                "a low-order server X25519 key must yield no M3 (silent drop, D12)"
            );
        }
        assert!(
            client.m3_frags().is_empty(),
            "no M3 may be emitted for a non-contributory exchange"
        );
        // The client is still awaiting M2 and can retry.
        assert!(matches!(client.on_timer(), Ok(ClientEvent::Emit(_))));
    }

    // -----------------------------------------------------------------------
    // Key-schedule binding through TH3 (Item 2)
    // -----------------------------------------------------------------------
    //
    // `derive_master_secret_v2` does **not** take the ML-KEM ciphertexts or the
    // ephemeral public keys as direct inputs. They are bound transitively via
    // `TH3`, which `info` carries. These tests prove each of those fields
    // actually reaches the master secret; without them, a ciphertext swap that
    // preserved the three shared secrets would go unnoticed.

    /// `TH3` over fixed-length placeholders — isolates the transcript function
    /// from message construction so a single field can be perturbed.
    fn th3_digest(m1: &[u8], m2: &[u8], m3: &[u8]) -> [u8; 32] {
        th3_from_m1_m2_m3(m1, m2, m3).expect("fixed-length messages")
    }

    /// `TH3` must bind the client's ML-KEM encapsulation key. It is the first
    /// field of M1 after version/sid, so it sits closest to the message header.
    #[test]
    fn th3_binds_the_client_kem_public_key() {
        let (cc, sc) = test_configs();
        let sid = [70u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, None);

        let mut m1_alt = m1;
        m1_alt[9] ^= 0x01; // first byte of eph_pk_c
        assert_ne!(
            th3_digest(&m1_alt, &m2, &m3),
            th3_digest(&m1, &m2, &m3),
            "TH3 must bind the client ML-KEM encapsulation key"
        );
    }

    /// `TH3` must bind **both** ML-KEM ciphertexts: `ct2` (M2) and `ct3` (M3).
    /// Swapping either must change the digest, at both ends of the ciphertext.
    #[test]
    fn th3_binds_both_kem_ciphertexts() {
        let (cc, sc) = test_configs();
        let sid = [71u8; SESSION_ID_LEN];

        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, None);

        let base = th3_digest(&m1, &m2, &m3);

        // ct2 lives at M2 offset 9 + 1184 + 32.
        let ct2_off = 9 + ML_KEM_768_PUBLIC_KEY_BYTES + 32;
        let mut m2_alt = m2;
        m2_alt[ct2_off] ^= 0x01;
        assert_ne!(
            th3_digest(&m1, &m2_alt, &m3),
            base,
            "TH3 must bind ct2 (the server's KEM ciphertext)"
        );

        let mut m3_alt = m3;
        m3_alt[9] ^= 0x01;
        assert_ne!(
            th3_digest(&m1, &m2, &m3_alt),
            base,
            "TH3 must bind ct3 (the client's KEM ciphertext)"
        );

        let mut m3_tail = m3;
        m3_tail[9 + ML_KEM_768_CIPHERTEXT_BYTES - 1] ^= 0x01;
        assert_ne!(
            th3_digest(&m1, &m2, &m3_tail),
            base,
            "the whole ct3 must be covered, not just a prefix"
        );
    }

    /// `TH3` must bind the server's ML-KEM encapsulation key and X25519 key
    /// (both in M2), so a MITM cannot re-frame the server's ephemeral offer.
    #[test]
    fn th3_binds_both_server_ephemeral_keys() {
        let (cc, sc) = test_configs();
        let sid = [72u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, None);
        let base = th3_digest(&m1, &m2, &m3);

        let x_off = 9 + ML_KEM_768_PUBLIC_KEY_BYTES;
        let mut m2_x = m2;
        m2_x[x_off + 31] ^= 0x01; // last byte of x_s
        assert_ne!(
            th3_digest(&m1, &m2_x, &m3),
            base,
            "TH3 must bind the server X25519 key"
        );

        let mut m2_pk = m2;
        m2_pk[9 + ML_KEM_768_PUBLIC_KEY_BYTES - 1] ^= 0x01; // last byte of eph_pk_s
        assert_ne!(
            th3_digest(&m1, &m2_pk, &m3),
            base,
            "TH3 must bind the server ML-KEM encapsulation key"
        );
    }

    /// End-to-end: the master secret must differ when *only* the ML-KEM
    /// ciphertexts differ, with all three shared secrets held constant. This
    /// is the property that makes a ciphertext swap detectable, and it is the
    /// one the direct `derive_master_secret_v2` binding cannot show on its own.
    #[test]
    fn master_secret_changes_when_only_the_ciphertext_changes() {
        let (_, ct3_a) =
            encapsulate(&MlKemKeypair::generate().expect("keygen").public).expect("encaps");
        let (_, ct3_b) =
            encapsulate(&MlKemKeypair::generate().expect("keygen").public).expect("encaps");

        let (cc, sc) = test_configs();
        let sid = [73u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);
        let m2 = encode_real_m2(&sc, sid);
        let m3_a = encode_m3(cc.version, sid, &ct3_a, None);
        let m3_b = encode_m3(cc.version, sid, &ct3_b, None);

        let th3_a = th3_digest(&m1, &m2, &m3_a);
        let th3_b = th3_digest(&m1, &m2, &m3_b);
        assert_ne!(th3_a, th3_b, "distinct ct3 must yield distinct TH3");

        let (ss_a, ss_b, dh) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let master_a = pq_crypto::kdf::derive_master_secret_v2(
            &ss_a,
            &ss_b,
            &dh,
            PROTOCOL_VERSION,
            &sid,
            &th3_a,
        )
        .expect("master");
        let master_b = pq_crypto::kdf::derive_master_secret_v2(
            &ss_a,
            &ss_b,
            &dh,
            PROTOCOL_VERSION,
            &sid,
            &th3_b,
        )
        .expect("master");
        assert_ne!(
            master_a.as_bytes(),
            master_b.as_bytes(),
            "the ciphertext swap must change the session master"
        );
    }

    /// The contributory guard must not perturb a normal exchange: both sides
    /// still derive the identical master.
    #[test]
    fn contributory_check_does_not_perturb_a_valid_exchange() {
        let (cc, sc) = test_configs();
        let sid = [74u8; SESSION_ID_LEN];
        let (client_out, server_out) = run_exchange(&cc, &sc, sid);
        assert_eq!(
            client_out.master.as_bytes(),
            server_out.master.as_bytes(),
            "the contributory check must not perturb derivation"
        );
    }

    // -----------------------------------------------------------------------
    // Message-codec length boundaries (Item 4)
    // -----------------------------------------------------------------------
    //
    // Self-consistency/regression tests, NOT external anchors.

    /// `ClientHello::decode` accepts exactly M1_BODY_LEN and rejects len-1 and
    /// len+1 before any field is read.
    #[test]
    fn client_hello_decode_length_boundaries() {
        let (cc, _) = test_configs();
        let sid = [80u8; SESSION_ID_LEN];
        let m1 = encode_real_m1(&cc, sid);

        assert!(matches!(
            ClientHello::decode(&m1[..M1_BODY_LEN - 1]),
            Err(CodecError::Truncated { .. })
        ));
        assert!(ClientHello::decode(&m1).is_ok(), "exact length must decode");
        let mut longer = m1.to_vec();
        longer.push(0);
        assert!(matches!(
            ClientHello::decode(&longer),
            Err(CodecError::Truncated { .. })
        ));
        assert!(ClientHello::decode(&[]).is_err());
    }

    /// `ServerHello::decode` accepts exactly M2_BODY_LEN and rejects len±1.
    #[test]
    fn server_hello_decode_length_boundaries() {
        let (_, sc) = test_configs();
        let sid = [81u8; SESSION_ID_LEN];
        let m2 = encode_real_m2(&sc, sid);

        assert!(matches!(
            ServerHello::decode(&m2[..M2_BODY_LEN - 1]),
            Err(CodecError::Truncated { .. })
        ));
        assert!(ServerHello::decode(&m2).is_ok(), "exact length must decode");
        let mut longer = m2.to_vec();
        longer.push(0);
        assert!(matches!(
            ServerHello::decode(&longer),
            Err(CodecError::Truncated { .. })
        ));
        assert!(ServerHello::decode(&[]).is_err());
    }

    /// `ClientConfirm::decode` accepts exactly M3_BODY_LEN and rejects len±1.
    #[test]
    fn client_confirm_decode_length_boundaries() {
        let (cc, _) = test_configs();
        let sid = [82u8; SESSION_ID_LEN];
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        let m3 = encode_m3(cc.version, sid, &ct3, Some(&[0x5Au8; FINISHED_MAC_LEN]));

        assert!(matches!(
            ClientConfirm::decode(&m3[..M3_BODY_LEN - 1]),
            Err(CodecError::Truncated { .. })
        ));
        assert!(
            ClientConfirm::decode(&m3).is_ok(),
            "exact length must decode"
        );
        let mut longer = m3.to_vec();
        longer.push(0);
        assert!(matches!(
            ClientConfirm::decode(&longer),
            Err(CodecError::Truncated { .. })
        ));
        assert!(ClientConfirm::decode(&[]).is_err());
    }

    /// All three message codecs must reject every length in a window around
    /// their exact size, and must never panic doing so.
    #[test]
    fn message_codecs_never_panic_across_the_length_window() {
        let (cc, sc) = test_configs();
        let sid = [83u8; SESSION_ID_LEN];
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        let bodies: Vec<Vec<u8>> = vec![
            encode_real_m1(&cc, sid).to_vec(),
            encode_real_m2(&sc, sid).to_vec(),
            encode_m3(cc.version, sid, &ct3, None).to_vec(),
        ];

        for body in &bodies {
            let n = body.len();
            for len in 0..=(n + 2) {
                let slice = &body[..len.min(n)];
                let _ = ClientHello::decode(slice);
                let _ = ServerHello::decode(slice);
                let _ = ClientConfirm::decode(slice);
            }
            // One byte past the end is still a must-not-panic case.
            let mut over = body.clone();
            over.push(0);
            let _ = ClientHello::decode(&over);
            let _ = ServerHello::decode(&over);
            let _ = ClientConfirm::decode(&over);
        }
    }

    /// `HandshakeFragment::from_datagram` operates on a fixed-size `WirePacket`,
    /// so its inputs are always in bounds. What must be pinned is the *body*
    /// slice it produces at the last fragment index for each message type: the
    /// final fragment is shorter than `HS_FRAG_BODY_MAX`, and an off-by-one
    /// there would truncate or over-read the message.
    #[test]
    fn fragment_body_length_is_exact_for_every_index_and_type() {
        let (cc, sc) = test_configs();
        let sid = [84u8; SESSION_ID_LEN];

        let mut messages: Vec<(u8, Vec<u8>)> = vec![
            (HS_TYPE_CLIENT_HELLO, encode_real_m1(&cc, sid).to_vec()),
            (HS_TYPE_SERVER_HELLO, encode_real_m2(&sc, sid).to_vec()),
        ];
        let peer = MlKemKeypair::generate().expect("keygen");
        let (_, ct3) = encapsulate(&peer.public).expect("encaps");
        messages.push((
            HS_TYPE_CLIENT_CONFIRM,
            encode_m3(cc.version, sid, &ct3, None).to_vec(),
        ));

        for (hs_type, message) in messages {
            let frags = fragment_message(hs_type, cc.version, sid, &message).expect("fragment");
            let total = expected_frag_count(hs_type).expect("known type");
            assert_eq!(frags.len(), total as usize);

            let mut covered = 0usize;
            for (idx, frag) in frags.iter().enumerate() {
                let parsed = HandshakeFragment::from_datagram(frag).expect("parse");
                assert_eq!(parsed.frag_idx, idx as u8);
                assert_eq!(parsed.frag_total, total);
                assert!(
                    !parsed.body.is_empty(),
                    "every fragment must carry a non-empty body slice"
                );
                assert!(
                    parsed.body.len() <= HS_FRAG_BODY_MAX,
                    "no fragment may exceed the body capacity"
                );
                // The slices must tile the message exactly, with no gap and no
                // overlap, and together reconstruct it byte for byte.
                let start = idx * HS_FRAG_BODY_MAX;
                assert_eq!(
                    parsed.body.len(),
                    (message.len() - start).min(HS_FRAG_BODY_MAX)
                );
                assert_eq!(&message[start..start + parsed.body.len()], &parsed.body[..]);
                covered += parsed.body.len();
            }
            assert_eq!(
                covered,
                message.len(),
                "fragments must cover the message exactly for hs_type 0x{hs_type:02x}"
            );
        }
    }
}
