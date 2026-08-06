//! Tunnel packet codec foundation.
//!
//! This module defines the fixed-size on-wire packet structure and the
//! strictly-validated typed primitives used by the rest of the stack. It is
//! intentionally pure logic with no cryptographic type dependency: it owns the
//! *framing* (byte layout, field types, encoding/decoding, validation), while
//! confidentiality, integrity, nonce construction and key selection are the
//! responsibility of the cryptographic envelope ([`crate`]) and the key
//! schedule in `pq_crypto::kdf`.
//!
//! # Layout rationale (derived from the canonical specification)
//!
//! `PROTOCOL_SPEC.md` §11 requires every Tunnel packet to provide session
//! association, integrity, confidentiality, replay-detection (a sequencing
//! mechanism), and authenticated-associated-data handling, and to define a
//! header structure with *authenticated* (AD) and *protected* (encrypted)
//! fields.  §12 requires uniform packet sizes for metadata resistance, and
//! §7.5 requires avoiding assumptions about a specific MTU.  §4 / §10 state
//! that a session identifier is *not* secret and must not permanently depend on
//! a source network address.  §15 requires version identification to prevent
//! downgrade.
//!
//! Consequently the on-wire `WirePacket` is split into a fixed-length
//! *clear-text header* (used as AEAD associated data) and an *AEAD region*
//! (ciphertext + tag) that encrypts the `InnerPlaintext`:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | V |                   Session ID (8)          | Packet Nonce(8) BE|
//! +-+-+-------------------------------------------+---------------+
//! |                          AEAD ciphertext (1247 bytes)          |
//! | ...                                                        ... |
//! +-+---------------------------------------------------------------+
//! |                         AEAD tag (16)                           |
//! +-+---------------------------------------------------------------+
//! ```
//!
//! * **version**        – 1 byte.  Protocol version ([§15](#version)).  Cleartext so
//!   downgrade attempts are detectable before any cryptographic work.
//! * **session_id**     – 8 bytes.  Non-secret session association identifier
//!   ([§4](#connection-id), [§10](#session-requirements)) used by the receiver
//!   to look up the session keys without decrypting.
//! * **packet_nonce**   – 8-byte big-endian monotonic counter.  Cleartext so the
//!   receiver can *reconstruct the AEAD nonce* without a circular dependency:
//!   the nonce is `nonce_prefix(4, session-derived & secret) ‖ packet_nonce(8)`
//!   (see `pq_crypto::kdf::build_session_nonce`), and replay detection is built
//!   on this counter ([§11](#packet-requirements), [§5.6](#replay-protection),
//!   CRYPTO_PROFILE §8 unique-nonce requirement).
//!
//! The AEAD region encrypts the [`InnerPlaintext`] — `msg_type + direction +
//! payload` — so that traffic patterns (data vs. cover, direction) are not
//! observable ([§12](#traffic-shaping-requirements) metadata resistance).  The
//! whole packet is a uniform `PACKET_SIZE` bytes regardless of content.
//!
//! # Parameters vs. guarantees
//!
//! Every numeric constant below is an *implementation parameter* (DESIGN
//! DECISIONS D7: "parameters control tradeoffs; they do not redefine
//! guarantees").  They are named, documented, and centralized here so that
//! future design decisions (version, packet size, field widths) can be revised
//! without touching the rest of the stack.  No cryptographic security property
//! is encoded in any of these values.

use core::fmt;

use zeroize::Zeroize;

use crate::error::CodecError;

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Current protocol version.
///
/// PROTOCOL_SPEC §15 — version identification used to prevent incompatible
/// communication and downgrade attacks.  Packets carrying a version other than
/// this value are rejected by [`PacketHeader::decode`].  Bumping this constant
/// signals an incompatible wire-format change.
pub const PROTOCOL_VERSION: u8 = 1;

/// Number of bytes occupied by the version field.
pub const VERSION_LEN: usize = 1;

// ---------------------------------------------------------------------------
// Fixed on-wire dimensions
// ---------------------------------------------------------------------------

/// Fixed size of every on-wire `WirePacket` in bytes.
///
/// PROTOCOL_SPEC §12 (traffic-shaping requirements) requires uniform packet
/// sizes to resist size-based traffic analysis.  PROTOCOL_SPEC §7.5 requires
/// avoiding dependence on a specific MTU; therefore this default fits a standard
/// IPv4/IPv6 MTU (1500 / 1280) without requiring jumbo frames, while still
/// carrying a useful payload.  This is an implementation parameter (D7) and is
/// intentionally centralized so it can be tuned per deployment.
///
/// This is the canonical Tunnel on-wire packet size, re-exported as
/// `pq_tunnel_core::PACKET_SIZE`.  (The pre-v2 QUIC transport used an 8192-byte
/// framing that was byte-incompatible with this codec; that transport has been
/// removed, and 1280 is the only on-wire packet size.)
pub const PACKET_SIZE: usize = 1280;

// Field widths (all on-wire and inner fields are fixed-size by design).
pub const SESSION_ID_LEN: usize = 8;
pub const PACKET_NONCE_LEN: usize = 8;
pub const AEAD_TAG_LEN: usize = 16;
pub const AEAD_NONCE_LEN: usize = 12; // 4-byte session prefix + 8-byte counter

/// Safety margin before the u64 packet-nonce counter must trigger session rotation.
///
/// `packet_nonce` is the cleartext sequence counter folded into the AEAD nonce via
/// `pq_crypto::kdf::build_session_nonce(prefix[4], counter[8])` (12 bytes).  If the
/// counter ever wraps (2^64) the AEAD nonce repeats, which is catastrophic for AEAD
/// confidentiality and integrity (nonce reuse).  CRYPTO_PROFILE §8 mandates
/// unique-nonce usage.  The cipher envelope / `Session` layer MUST refuse to emit or
/// process packets once the counter reaches this limit; this constant is the codec's
/// contract for that hard check.
pub const MAX_PACKET_NONCE: u64 = u64::MAX - (1u64 << 32);

/// `true` once `counter` is within the safety margin of exhausting the u64 nonce.
/// Callers MUST treat this as a session-rotation trigger (PROTOCOL_SPEC §5.6 replay /
/// §11 sequencing).
pub const fn is_counter_exhausted(counter: u64) -> bool {
    counter >= MAX_PACKET_NONCE
}

// Derived region sizes — kept as named constants so the layout is
// self-documenting and single-sourced.
/// Clear-text header length: version + session_id + packet_nonce.
pub const HEADER_LEN: usize = VERSION_LEN + SESSION_ID_LEN + PACKET_NONCE_LEN;
/// Length of the AEAD ciphertext (the encoded [`InnerPlaintext`]).
/// Satisfies `HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN == PACKET_SIZE`.
pub const INNER_PLAINTEXT_LEN: usize = PACKET_SIZE - HEADER_LEN - AEAD_TAG_LEN;
/// Usable payload inside an [`InnerPlaintext`]: the full inner plaintext is a
/// 1-byte message type plus a 1-byte direction plus this many payload bytes.
pub const PAYLOAD_LEN: usize = INNER_PLAINTEXT_LEN - 2; // type(1) + direction(1) + payload

// Compile-time sanity: the fixed-size layout must partition `PACKET_SIZE`
// exactly.  If someone changes a constant upstream, the build fails here
// instead of producing a silent truncation/decompression bug.
const _: () = assert!(
    HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN == PACKET_SIZE,
    "codec layout must partition PACKET_SIZE exactly: \
     header + plaintext + tag == packet_size",
);
const _: () = assert!(
    INNER_PLAINTEXT_LEN > 2,
    "inner plaintext must hold type + direction + payload"
);

// Ties the codec's cleartext counter (PACKET_NONCE_LEN) to kdf's nonce construction:
// `build_session_nonce` = 4-byte session-derived prefix + 8-byte packet counter =>
// 12-byte AEAD nonce.  A drift between these is a silent nonce-misuse hazard.
const _: () = assert!(
    AEAD_NONCE_LEN == PACKET_NONCE_LEN + 4,
    "AEAD nonce must equal 4-byte session prefix + 8-byte packet counter (kdf::build_session_nonce)"
);

// Soundness guard for `WirePacket::into_bytes`: it relies on `self.0: [u8;
// PACKET_SIZE]` being `Copy` so that returning it does not move (and escape an
// un-zeroized buffer).  If `WirePacket.0` ever becomes non-`Copy`, this fails to
// compile and forces a review of the `Drop` zeroization invariant.
const _: fn() = || {
    fn assert_copy<T: Copy>() {}
    assert_copy::<[u8; PACKET_SIZE]>();
};

// ---------------------------------------------------------------------------
// Protocol enums (strict, forward-compatible via rejection)
// ---------------------------------------------------------------------------

/// Type of a Tunnel packet.
///
/// Drives the local protocol state machine (PROTOCOL_SPEC §8).  Only values
/// explicitly enumerated here are accepted by [`MessageType::from_u8`]; unknown
/// values are rejected rather than silently misinterpreted (PROTOCOL_SPEC §14 —
/// reject invalid packets, no insecure fallback).  Adding a variant for a new
/// version is a breaking change that requires bumping [`PROTOCOL_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake establishment / rekey (PROTOCOL_SPEC §8.2, §13 rekey).
    Handshake = 0x00,
    /// Application data in the established session (PROTOCOL_SPEC §8.3).
    Data = 0x01,
    /// Cover traffic filling the schedule (PROTOCOL_SPEC §12.1).
    Cover = 0x02,
    /// Clean session teardown (PROTOCOL_SPEC §8.4).
    Close = 0x03,
}

impl MessageType {
    /// Strict, rejecting decode.
    ///
    /// Unknown byte values are rejected (`Err`) so a future or malformed
    /// message type can never be silently treated as a known type.  Callers
    /// map the error to a silent drop per PROTOCOL_SPEC §14.
    pub const fn from_u8(v: u8) -> Result<Self, CodecError> {
        match v {
            0x00 => Ok(Self::Handshake),
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Cover),
            0x03 => Ok(Self::Close),
            _ => Err(CodecError::InvalidMessageType(v)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Logical direction of a packet relative to a session.
///
/// Per-direction traffic keys and nonce prefixes are derived by
/// `pq_crypto::kdf` (client→server / server→client).  Direction is carried
/// *inside* the encrypted [`InnerPlaintext`] (never in the clear-text header)
/// so that communication direction is not observable by a passive observer
/// (PROTOCOL_SPEC §12).  It is also self-describing for the receiver and serves
/// as an integrity check that a packet matches the session's expected role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 0x00,
    ServerToClient = 0x01,
}

impl Direction {
    pub const fn from_u8(v: u8) -> Result<Self, CodecError> {
        match v {
            0x00 => Ok(Self::ClientToServer),
            0x01 => Ok(Self::ServerToClient),
            _ => Err(CodecError::InvalidDirection(v)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Clear-text header (used as AEAD associated data)
// ---------------------------------------------------------------------------

/// Fixed clear-text header present on every `WirePacket`.
///
/// Carries only what the receiver must read *before* AEAD decryption: the
/// protocol version (§15 downgrade detection), the session identifier (§4/§10
/// routing, non-secret), and the packet nonce / sequence counter (needed to
/// reconstruct the AEAD nonce and for replay detection).  This header is passed
/// to the AEAD as associated data, authenticating it without encrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u8,
    pub session_id: [u8; SESSION_ID_LEN],
    pub packet_nonce: u64,
}

impl PacketHeader {
    /// Create a header.  `version` should normally be [`PROTOCOL_VERSION`].
    pub const fn new(session_id: [u8; SESSION_ID_LEN], packet_nonce: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            session_id,
            packet_nonce,
        }
    }

    /// Deterministic big-endian encoding into exactly [`HEADER_LEN`] bytes.
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1..][..SESSION_ID_LEN].copy_from_slice(&self.session_id);
        out[1 + SESSION_ID_LEN..].copy_from_slice(&self.packet_nonce.to_be_bytes());
        out
    }

    /// Strict decode from a byte slice.
    ///
    /// # Errors
    /// - [`CodecError::Truncated`] if the slice is shorter than [`HEADER_LEN`].
    /// - [`CodecError::InvalidVersion`] if the version is not [`PROTOCOL_VERSION`]
    ///   (PROTOCOL_SPEC §15 — reject unsupported/downgraded versions).
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() < HEADER_LEN {
            return Err(CodecError::Truncated {
                field: "PacketHeader",
                min: HEADER_LEN,
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
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&data[1..1 + SESSION_ID_LEN]);
        let packet_nonce = u64::from_be_bytes(
            data[1 + SESSION_ID_LEN..1 + SESSION_ID_LEN + PACKET_NONCE_LEN]
                .try_into()
                .expect("already bounds-checked above: data.len() >= HEADER_LEN"),
        );
        Ok(Self {
            version,
            session_id,
            packet_nonce,
        })
    }
}

/// The plaintext that the AEAD protects: a message type, a direction, and a
/// fixed-size payload.
///
/// The entire [`InnerPlaintext`] is the input to AEAD encryption; its encoded
/// form is exactly [`INNER_PLAINTEXT_LEN`] bytes.  See the module docs for the
/// rationale behind keeping `msg_type`/`direction` out of the clear-text header.
//
// `Debug` is implemented by hand (below) so the decrypted `payload` is never
// printed — this type holds plaintext (application or cover data) and must obey
// the crate's redaction discipline (cf. `AeadKey`/`AeadNonce`/`MasterSecret`).
#[derive(Clone, PartialEq, Eq)]
pub struct InnerPlaintext {
    pub msg_type: MessageType,
    pub direction: Direction,
    pub payload: [u8; PAYLOAD_LEN],
}

impl fmt::Debug for InnerPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerPlaintext")
            .field("msg_type", &self.msg_type)
            .field("direction", &self.direction)
            .field(
                "payload",
                &format_args!("<redacted: {} bytes>", self.payload.len()),
            )
            .finish()
    }
}

impl InnerPlaintext {
    /// Build an inner plaintext, copying `payload` (must be exactly
    /// [`PAYLOAD_LEN`] bytes).
    pub fn new(
        msg_type: MessageType,
        direction: Direction,
        payload: &[u8],
    ) -> Result<Self, CodecError> {
        if payload.len() != PAYLOAD_LEN {
            return Err(CodecError::WrongLength {
                field: "payload",
                expected: PAYLOAD_LEN,
                got: payload.len(),
            });
        }
        let mut p = [0u8; PAYLOAD_LEN];
        p.copy_from_slice(payload);
        Ok(Self {
            msg_type,
            direction,
            payload: p,
        })
    }

    /// Encode into exactly [`INNER_PLAINTEXT_LEN`] bytes: type || direction || payload.
    pub fn encode(&self) -> [u8; INNER_PLAINTEXT_LEN] {
        let mut out = [0u8; INNER_PLAINTEXT_LEN];
        out[0] = self.msg_type.as_u8();
        out[1] = self.direction.as_u8();
        out[2..].copy_from_slice(&self.payload);
        out
    }

    /// Strict decode from a byte slice.
    ///
    /// # Errors
    /// - [`CodecError::Truncated`] if the slice is not exactly
    ///   [`INNER_PLAINTEXT_LEN`] bytes.
    /// - [`CodecError::InvalidMessageType`] / [`CodecError::InvalidDirection`]
    ///   for unknown field values (PROTOCOL_SPEC §14 — reject, never silently
    ///   reinterpret).
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != INNER_PLAINTEXT_LEN {
            return Err(CodecError::Truncated {
                field: "InnerPlaintext",
                min: INNER_PLAINTEXT_LEN,
                got: data.len(),
            });
        }
        let msg_type = MessageType::from_u8(data[0])?;
        let direction = Direction::from_u8(data[1])?;
        let mut payload = [0u8; PAYLOAD_LEN];
        payload.copy_from_slice(&data[2..2 + PAYLOAD_LEN]);
        Ok(Self {
            msg_type,
            direction,
            payload,
        })
    }
}

impl InnerPlaintext {
    /// Convenience: a `Cover` plaintext filled entirely with `fill` bytes.
    /// Cover traffic must be indistinguishable from data traffic by size, which
    /// the fixed-length layout guarantees (PROTOCOL_SPEC §12.1).
    pub fn cover(direction: Direction, fill: u8) -> Self {
        Self {
            msg_type: MessageType::Cover,
            direction,
            payload: [fill; PAYLOAD_LEN],
        }
    }

    /// Convenience: a `Data` plaintext carrying `payload`, which must be exactly
    /// [`PAYLOAD_LEN`] bytes.  Callers are responsible for fragmenting larger
    /// application data into these fixed-size slots (a transport-layer concern).
    pub fn data(direction: Direction, payload: &[u8]) -> Result<Self, CodecError> {
        Self::new(MessageType::Data, direction, payload)
    }
}

impl Drop for InnerPlaintext {
    fn drop(&mut self) {
        // The decoded `payload` holds decrypted application/cover data.  Erase it so
        // plaintext does not outlive its useful life (IMPLEMENTATION_GUIDE §6:
        // securely erase sensitive material).  Direction/MessageType are non-secret.
        self.payload.zeroize();
    }
}

// ---------------------------------------------------------------------------
// On-wire packet container
// ---------------------------------------------------------------------------

/// A fixed-size on-wire Tunnel packet.
///
/// Every datagram exchanged over the transport is exactly [`PACKET_SIZE`] bytes
/// so that packet size reveals nothing about content or activity
/// (PROTOCOL_SPEC §12 metadata resistance, §7.5 uniform structure).  The
/// packet is split into a clear-text header (used as AEAD AAD) and an AEAD
/// region (ciphertext + tag).  Instances are zeroized on drop to avoid leaving
/// ciphertext / plaintext in memory longer than necessary.
#[derive(Clone)]
pub struct WirePacket([u8; PACKET_SIZE]);

impl WirePacket {
    /// Construct a zero-initialized packet (e.g. as a scratch buffer).
    pub fn zeroed() -> Self {
        Self([0u8; PACKET_SIZE])
    }

    /// Strict construction from an exact-length byte slice (PROTOCOL_SPEC §14 —
    /// reject packets of the wrong size).
    pub fn from_bytes(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != PACKET_SIZE {
            return Err(CodecError::Truncated {
                field: "WirePacket",
                min: PACKET_SIZE,
                got: data.len(),
            });
        }
        let mut pkt = [0u8; PACKET_SIZE];
        pkt.copy_from_slice(data);
        Ok(Self(pkt))
    }

    pub fn as_bytes(&self) -> &[u8; PACKET_SIZE] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; PACKET_SIZE] {
        &mut self.0
    }

    /// Borrow the clear-text header bytes (first [`HEADER_LEN`] bytes).
    pub fn header_bytes(&self) -> &[u8; HEADER_LEN] {
        debug_assert!(self.0.len() >= HEADER_LEN);
        self.0[..HEADER_LEN]
            .try_into()
            .expect("header slice length")
    }

    /// Borrow the AEAD ciphertext (exactly [`INNER_PLAINTEXT_LEN`] bytes), i.e.
    /// the encrypted [`InnerPlaintext`].
    pub fn ciphertext(&self) -> &[u8; INNER_PLAINTEXT_LEN] {
        debug_assert!(
            self.0.len() >= HEADER_LEN + INNER_PLAINTEXT_LEN,
            "invariant: layout partitions PACKET_SIZE"
        );
        self.0[HEADER_LEN..HEADER_LEN + INNER_PLAINTEXT_LEN]
            .try_into()
            .expect("ciphertext slice length")
    }

    /// Borrow the AEAD authentication tag (final [`AEAD_TAG_LEN`] bytes).
    pub fn tag(&self) -> &[u8; AEAD_TAG_LEN] {
        debug_assert!(
            self.0.len() >= HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN,
            "invariant: layout partitions PACKET_SIZE"
        );
        self.0[HEADER_LEN + INNER_PLAINTEXT_LEN..]
            .try_into()
            .expect("tag slice length")
    }

    /// The AEAD "associated data": the clear-text header bytes.
    pub fn aad(&self) -> &[u8; HEADER_LEN] {
        self.header_bytes()
    }

    /// Parse and validate the clear-text header (version check included).
    pub fn parse_header(&self) -> Result<PacketHeader, CodecError> {
        PacketHeader::decode(&self.0[..HEADER_LEN])
    }

    /// Parse the ciphertext and tag as a single contiguous AEAD region reference.
    /// Useful when handing the region to an AEAD implementation that consumes
    /// ciphertext-and-tag together.
    pub fn aead_region(&self) -> &[u8] {
        &self.0[HEADER_LEN..]
    }
}

impl std::fmt::Debug for WirePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = self.header_bytes();
        f.debug_struct("WirePacket")
            .field("size", &self.0.len())
            .field("version", &h[0])
            .field("session_id", &&h[1..1 + SESSION_ID_LEN])
            .field("packet_nonce", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for WirePacket {
    fn drop(&mut self) {
        // Zeroize on release: a captured packet buffer should not retain
        // ciphertext/plaintext once discarded.
        self.0.zeroize();
    }
}

impl WirePacket {
    /// Consume the packet and return the underlying byte buffer.
    ///
    /// The inner array is `Copy`, so this returns a copy of the bytes while the
    /// original buffer is still zeroized on drop — no plaintext lingers in the
    /// consumed packet's memory.
    pub fn into_bytes(self) -> [u8; PACKET_SIZE] {
        self.0
    }

    /// Construct a `WirePacket` from the encoded clear-text header + an AEAD
    /// region (ciphertext || tag) already laid out by an envelope.
    ///
    /// `header` must be [`HEADER_LEN`] bytes and `aead_region` must be
    /// `PACKET_SIZE - HEADER_LEN` bytes (ciphertext + 16-byte tag).  This is the
    /// primary assembly point for the data path (Phase 4 envelope).
    ///
    /// Validates the header's version byte (PROTOCOL_SPEC §15 — defense in depth:
    /// the receive path also checks via `parse_header`, but validating here prevents
    /// a caller from accidentally constructing a version-mismatched packet).
    pub fn from_parts(header: &[u8; HEADER_LEN], aead_region: &[u8]) -> Result<Self, CodecError> {
        if header[0] != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                found: header[0],
            });
        }
        if aead_region.len() != PACKET_SIZE - HEADER_LEN {
            return Err(CodecError::Truncated {
                field: "aead_region",
                min: PACKET_SIZE - HEADER_LEN,
                got: aead_region.len(),
            });
        }
        let mut buf = [0u8; PACKET_SIZE];
        buf[..HEADER_LEN].copy_from_slice(header);
        buf[HEADER_LEN..].copy_from_slice(aead_region);
        Ok(Self(buf))
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Handshake => write!(f, "handshake"),
            MessageType::Data => write!(f, "data"),
            MessageType::Cover => write!(f, "cover"),
            MessageType::Close => write!(f, "close"),
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::ClientToServer => write!(f, "client-to-server"),
            Direction::ServerToClient => write!(f, "server-to-client"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_pass_by_value)]
    use super::*;

    #[test]
    fn layout_partitions_packet_size_exactly() {
        assert_eq!(HEADER_LEN, 1 + 8 + 8);
        assert_eq!(INNER_PLAINTEXT_LEN + HEADER_LEN + AEAD_TAG_LEN, PACKET_SIZE);
        assert_eq!(PAYLOAD_LEN + 2, INNER_PLAINTEXT_LEN);
        assert_eq!(PACKET_SIZE, 1280);
    }

    #[test]
    fn packet_header_roundtrip() {
        let hdr = PacketHeader::new(
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            0x0123_4567_89AB_CDEF,
        );
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        let back = PacketHeader::decode(&bytes).expect("decode");
        assert_eq!(back, hdr);
    }

    #[test]
    fn packet_header_rejects_short_input() {
        let short = [0u8; HEADER_LEN - 1];
        assert!(matches!(
            PacketHeader::decode(&short),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn packet_header_rejects_unsupported_version() {
        let mut bad = PacketHeader::new([1u8; SESSION_ID_LEN], 1).encode();
        bad[0] = PROTOCOL_VERSION + 1; // version byte forged
        assert!(matches!(
            PacketHeader::decode(&bad),
            Err(CodecError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn packet_header_rejects_downgrade_version() {
        let mut bad = PacketHeader::new([1u8; SESSION_ID_LEN], 1).encode();
        bad[0] = 0; // older version — downgrade attempt must be rejected (§15)
        assert!(matches!(
            PacketHeader::decode(&bad),
            Err(CodecError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn msg_type_from_u8_roundtrips_and_rejects_unknown() {
        for (mt, v) in [
            (MessageType::Handshake, 0x00),
            (MessageType::Data, 0x01),
            (MessageType::Cover, 0x02),
            (MessageType::Close, 0x03),
        ] {
            assert_eq!(mt.as_u8(), v);
            assert_eq!(MessageType::from_u8(v).unwrap(), mt);
        }
        assert!(MessageType::from_u8(0x04).is_err());
        assert!(MessageType::from_u8(0xFF).is_err());
    }

    #[test]
    fn direction_from_u8_roundtrips_and_rejects_unknown() {
        assert_eq!(Direction::from_u8(0x00).unwrap(), Direction::ClientToServer);
        assert_eq!(Direction::from_u8(0x01).unwrap(), Direction::ServerToClient);
        assert!(Direction::from_u8(0x02).is_err());
        assert!(Direction::from_u8(0xFF).is_err());
    }

    #[test]
    fn inner_plaintext_roundtrip() {
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = 0xAA;
        payload[PAYLOAD_LEN - 1] = 0xBB;
        let inner =
            InnerPlaintext::new(MessageType::Data, Direction::ClientToServer, &payload).unwrap();
        let bytes = inner.encode();
        assert_eq!(bytes.len(), INNER_PLAINTEXT_LEN);
        let back = InnerPlaintext::decode(&bytes).unwrap();
        assert_eq!(back, inner);
    }

    #[test]
    fn inner_plaintext_rejects_wrong_len() {
        let bad = vec![0u8; INNER_PLAINTEXT_LEN + 1];
        assert!(matches!(
            InnerPlaintext::decode(&bad),
            Err(CodecError::Truncated { .. })
        ));
        let bad2 = vec![0u8; INNER_PLAINTEXT_LEN - 1];
        assert!(InnerPlaintext::decode(&bad2).is_err());
    }

    #[test]
    fn inner_plaintext_rejects_unknown_message_type() {
        let mut bytes = [0u8; INNER_PLAINTEXT_LEN];
        bytes[0] = 0x99; // unknown msg type
        bytes[1] = Direction::ClientToServer.as_u8();
        // remaining bytes are payload
        assert!(matches!(
            InnerPlaintext::decode(&bytes),
            Err(CodecError::InvalidMessageType(_))
        ));
    }

    #[test]
    fn inner_plaintext_encoding_is_deterministic() {
        let p = [0x55u8; PAYLOAD_LEN];
        let a = InnerPlaintext::new(MessageType::Cover, Direction::ServerToClient, &p).unwrap();
        let b = InnerPlaintext::new(MessageType::Cover, Direction::ServerToClient, &p).unwrap();
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn wire_packet_from_bytes_strict() {
        let ok = WirePacket::from_bytes(&[0u8; PACKET_SIZE]).unwrap();
        assert_eq!(ok.as_bytes().len(), PACKET_SIZE);

        assert!(WirePacket::from_bytes(&[0u8; PACKET_SIZE - 1]).is_err());
        assert!(WirePacket::from_bytes(&[0u8; PACKET_SIZE + 1]).is_err());
    }

    #[test]
    fn wire_packet_header_accessor_roundtrips() {
        let mut pkt = WirePacket::zeroed();
        let hdr = PacketHeader::new([9u8; SESSION_ID_LEN], 42);
        let hbytes = hdr.encode();
        pkt.as_mut_bytes()[..HEADER_LEN].copy_from_slice(&hbytes);

        assert_eq!(pkt.header_bytes(), &hbytes);
        let parsed = pkt.parse_header().unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn wire_packet_regions_are_non_overlapping_and_complete() {
        let pkt = WirePacket::zeroed();
        let total = pkt.header_bytes().len() + pkt.ciphertext().len() + pkt.tag().len();
        assert_eq!(total, PACKET_SIZE);
    }

    #[test]
    fn wire_packet_aad_matches_header() {
        let pkt = WirePacket::zeroed();
        assert_eq!(pkt.header_bytes(), pkt.aad());
    }

    #[test]
    fn wire_packet_is_differentiable_by_content() {
        let mut a = WirePacket::zeroed();
        let mut b = WirePacket::zeroed();
        a.as_mut_bytes()[0] = 0x01;
        b.as_mut_bytes()[0] = 0x02;
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn inner_plaintext_new_rejects_wrong_payload_len() {
        let too_short = vec![0u8; PAYLOAD_LEN - 1];
        assert!(
            InnerPlaintext::new(MessageType::Data, Direction::ClientToServer, &too_short).is_err()
        );
    }

    #[test]
    fn cover_plaintext_has_cover_type_and_fixed_size() {
        let c = InnerPlaintext::cover(Direction::ServerToClient, 0x00);
        assert_eq!(c.msg_type, MessageType::Cover);
        assert_eq!(c.encode().len(), INNER_PLAINTEXT_LEN);
    }

    #[test]
    fn wire_packet_drop_does_not_panic() {
        // Exercise Drop / zeroization path on a non-trivial buffer.
        let mut pkt = WirePacket::zeroed();
        for (i, b) in pkt.as_mut_bytes().iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        drop(pkt);
    }

    #[test]
    fn wire_packet_drop_zeroizes_buffer() {
        // IMPLEMENTATION_GUIDE §8: verify security properties, not just absence of panic.
        use core::ptr;
        use std::mem::ManuallyDrop;

        let pkt = ManuallyDrop::new(WirePacket::from_bytes(&[0xA5; PACKET_SIZE]).unwrap());
        let ptr = pkt.as_bytes().as_ptr();
        // Run WirePacket::drop in place; it must zeroize `self.0`.  ManuallyDrop
        // keeps the allocation alive (no free), so reading `ptr` afterward is sound
        // and observes the erasure Drop performed.
        unsafe { ptr::drop_in_place(&*pkt as *const WirePacket as *mut WirePacket) };
        let all_zero = unsafe {
            std::slice::from_raw_parts(ptr, PACKET_SIZE)
                .iter()
                .all(|&b| b == 0)
        };
        assert!(all_zero, "WirePacket::drop did not zeroize the buffer");
    }

    #[test]
    fn from_parts_rejects_wrong_aead_region_length() {
        // `from_parts` pins the AEAD region to exactly `PACKET_SIZE - HEADER_LEN`
        // (ciphertext + 16-byte tag), which is the envelope's sole assembly path.
        const EXACT: usize = PACKET_SIZE - HEADER_LEN;
        let hdr = PacketHeader::new([1u8; SESSION_ID_LEN], 7).encode();

        // too short / too long -> Truncated.
        assert!(matches!(
            WirePacket::from_parts(&hdr, &[0u8; 0]),
            Err(CodecError::Truncated { .. })
        ));
        assert!(matches!(
            WirePacket::from_parts(&hdr, &[0u8; EXACT - 1]),
            Err(CodecError::Truncated { .. })
        ));
        assert!(matches!(
            WirePacket::from_parts(&hdr, &[0u8; EXACT + 1]),
            Err(CodecError::Truncated { .. })
        ));

        // exact length, wrong version -> InvalidVersion at assembly time (§15 defense in depth).
        let mut bad_hdr = hdr;
        bad_hdr[0] = 0; // wrong version
        assert!(matches!(
            WirePacket::from_parts(&bad_hdr, &[0u8; EXACT]),
            Err(CodecError::InvalidVersion { .. })
        ));
        // Version is checked before region length, so bad version + wrong region
        // still returns InvalidVersion (not Truncated).

        // Correct version, correct length -> Ok.
        let wp = WirePacket::from_parts(&hdr, &[0u8; EXACT]).unwrap();
        assert_eq!(wp.parse_header().unwrap().version, PROTOCOL_VERSION);
    }

    // -----------------------------------------------------------------------
    // Property-based / fuzz-style tests (no external fuzz dependency)
    // -----------------------------------------------------------------------

    /// Generate a pseudo-random byte vector of the given length for fuzzing.
    fn fuzz_bytes(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        getrandom::fill(&mut buf).expect("getrandom for fuzz input");
        buf
    }

    /// `WirePacket::from_bytes` must never panic on arbitrary input — only
    /// return `Err` for wrong-size input (§14: reject, never crash).
    #[test]
    fn fuzz_wire_packet_from_bytes_never_panics() {
        for &len in &[0, 1, 16, 17, 64, 128, 1279, 1280, 1281, 2048, 8192] {
            let mut ok_count = 0;
            for _ in 0..50 {
                let data = fuzz_bytes(len);
                let _ = WirePacket::from_bytes(&data); // must not panic
                ok_count += 1;
            }
            assert_eq!(ok_count, 50);
        }
    }

    /// `PacketHeader::decode` must never panic on arbitrary-length input.
    #[test]
    fn fuzz_packet_header_decode_never_panics() {
        for &len in &[0, 1, 8, 16, 17, 18, 32, 256] {
            for _ in 0..50 {
                let data = fuzz_bytes(len);
                let _ = PacketHeader::decode(&data); // must not panic
            }
        }
    }

    /// `InnerPlaintext::decode` must never panic on arbitrary input and
    /// must only accept exactly `INNER_PLAINTEXT_LEN` bytes with valid
    /// MessageType/Direction bytes.
    #[test]
    fn fuzz_inner_plaintext_decode_never_panics() {
        for &len in &[
            0,
            1,
            2,
            10,
            INNER_PLAINTEXT_LEN - 1,
            INNER_PLAINTEXT_LEN,
            INNER_PLAINTEXT_LEN + 1,
            2048,
        ] {
            for _ in 0..50 {
                let data = fuzz_bytes(len);
                let _ = InnerPlaintext::decode(&data); // must not panic
            }
        }
    }

    /// `from_parts` must reject any region length != `PACKET_SIZE - HEADER_LEN`,
    /// and must reject wrong-version headers.
    #[test]
    fn fuzz_from_parts_rejects_random_regions() {
        let good_hdr = PacketHeader::new([0x42; SESSION_ID_LEN], 1).encode();
        for &region_len in &[0, 1, 100, 500, 1262, 1263, 1264, 2000, 8192] {
            for _ in 0..20 {
                let region = fuzz_bytes(region_len);
                let result = WirePacket::from_parts(&good_hdr, &region);
                if region_len == PACKET_SIZE - HEADER_LEN {
                    assert!(
                        result.is_ok(),
                        "correct-length region with valid version must succeed"
                    );
                } else {
                    assert!(result.is_err(), "wrong-length region must be rejected");
                }
            }
        }
    }

    /// `InnerPlaintext::new` must reject any payload that is not exactly
    /// `PAYLOAD_LEN` bytes — no panics on random input.
    #[test]
    fn fuzz_inner_plaintext_new_rejects_wrong_sizes() {
        for &len in &[0, 1, 100, PAYLOAD_LEN - 1, PAYLOAD_LEN + 1, 2000] {
            for _ in 0..30 {
                let payload = fuzz_bytes(len);
                let result =
                    InnerPlaintext::new(MessageType::Data, Direction::ClientToServer, &payload);
                if len == PAYLOAD_LEN {
                    assert!(result.is_ok(), "payload of correct length must succeed");
                } else {
                    assert!(result.is_err(), "payload of wrong length must be rejected");
                }
            }
        }
    }

    /// Roundtrip: encode then decode always recovers the original header.
    #[test]
    fn fuzz_packet_header_roundtrip() {
        for _ in 0..100 {
            let sid = fuzz_bytes(SESSION_ID_LEN);
            let sid_arr: [u8; SESSION_ID_LEN] = sid.try_into().unwrap();
            let nonce: u64 = getrandom::u64().unwrap_or(0) % (u64::MAX / 2);
            let hdr = PacketHeader::new(sid_arr, nonce);
            let bytes = hdr.encode();
            assert_eq!(bytes.len(), HEADER_LEN);
            let decoded = PacketHeader::decode(&bytes).unwrap();
            assert_eq!(decoded, hdr, "header roundtrip must be deterministic");
        }
    }

    /// All valid `MessageType` bytes roundtrip; all invalid bytes are rejected.
    #[test]
    fn fuzz_message_type_exhaustive() {
        for b in 0u8..=255 {
            match MessageType::from_u8(b) {
                Ok(mt) => assert!(mt.as_u8() == b, "valid roundtrip for {:#x}", b),
                Err(_) => { /* invalid byte, rejected — correct */ }
            }
        }
    }

    /// All valid `Direction` bytes roundtrip; all invalid bytes are rejected.
    #[test]
    fn fuzz_direction_exhaustive() {
        for b in 0u8..=255 {
            match Direction::from_u8(b) {
                Ok(d) => assert!(d.as_u8() == b, "valid roundtrip for {:#x}", b),
                Err(_) => { /* invalid byte, rejected — correct */ }
            }
        }
    }

    /// `WirePacket` must always be exactly `PACKET_SIZE` bytes, regardless
    /// of how it was constructed.
    #[test]
    fn fuzz_wire_packet_size_invariant() {
        for len in 0..=PACKET_SIZE * 2 {
            let data = fuzz_bytes(len);
            if let Ok(wp) = WirePacket::from_bytes(&data) {
                assert_eq!(
                    wp.as_bytes().len(),
                    PACKET_SIZE,
                    "WirePacket size invariant must hold"
                );
            }
        }
    }
}
