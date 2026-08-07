//! AEAD packet envelope — cryptographic binding over the codec framing.
//!
//! This module is the security-critical glue between the pure framing of
//! [`crate::codec`] and the cryptographic primitives of `pq_crypto` (key schedule in
//! `kdf`, authenticated encryption in `aead`).  It owns the per-session cipher state
//! (keys, nonce prefixes, sequence counters) and exposes the two operations the
//! transport relies on:
//!
//! * [`CipherSession::encrypt`] — turn an application/cover payload into an
//!   authenticated, fixed-size [`WirePacket`] (header plaintext + AEAD
//!   ciphertext-and-tag).
//! * [`CipherSession::decrypt`] — validate the header, defeat replay, reconstruct the
//!   AEAD nonce, and recover the inner plaintext only if every check passes.
//!
//! # Where the cryptography lives (and where it does not)
//!
//! The codec owns **framing** (byte layout, field types, validation); `pq_crypto`
//! owns **crypto** (AEAD, key derivation).  This module owns the **binding**: it is
//! the only place that decides which key and which nonce to feed to `pq_crypto::aead`
//! for a given direction, and it is the only place that maintains the per-direction
//! sequence counters that make nonce reuse impossible (CRYPTO_PROFILE §8).
//!
//! # Nonce uniqueness & replay (the central invariant)
//!
//! Each direction derives a 4-byte secret nonce prefix via
//! `kdf::derive_nonce_prefix_c2s` / `derive_nonce_prefix_s2c`.  The on-wire
//! `PacketHeader::packet_nonce` is a 64-bit big-endian counter; the AEAD nonce is
//! reconstructed as `kdf::build_session_nonce(prefix, counter)` (4 + 8 = 12 bytes,
//! matching `AEAD_NONCE_BYTES`).  Because the prefix is secret and per-session and
//! the counter is never reused for a given direction, the 4-byte counter space is
//! effectively protected by the prefix — counter reuse across *different* sessions
//! is irrelevant, and within a session the envelope never repeats a counter
//! (sender is strictly monotonic; receiver is strictly monotonic per direction,
//! rejecting any packet whose counter has already been seen or falls outside
//! the sliding window — i.e. any counter whose bit in the `ReplayWindow`
//! bitmap is set or that is more than `WINDOW_BITS` below the high-water mark).
//!
//! PROTOCOL_SPEC §5.6 (replay) and §11 (sequencing) are enforced here with a
//! strict high-water replay guard.  Out-of-order tolerance (a sliding receive
//! window) is intentionally deferred to Phase 7; for now the envelope trades a
//! little availability under path reordering for a simpler, lower-state replay
//! defense (HNDL/metadata resistance first).
//!
//! # Failure is rejection (and is intentionally not constant-time)
//!
//! On the receive path every per-packet failure — wrong version (§15), replay,
//! AEAD tag mismatch (tamper/corruption), wrong direction (§12), or unknown inner
//! framing (§14) — collapses to the single [`CodecError::DecryptionFailed`]
//! variant.  Callers MUST treat any `Err` as "silently drop the packet"
//! (PROTOCOL_SPEC §14: reject invalid packets, no insecure fallback, **no
//! observable distinction** between failure reasons on the wire — no
//! `format!`-carrying counters/directions escape in the returned error; operators
//! debug via `tracing::debug!` locally).
//!
//! Two deliberate, cheap *pre-filters* run before AEAD: the version byte
//! (`PacketHeader::parse_header`, §15 downgrade detection) and the replay
//! high-water check (§5.6).  These are NOT constant-time, but they are safe by
//! threat model: the attacker is the network (active per THREAT_MODEL §4.3, who
//! can modify/inject/replay packets), but the version/counter are AAD-authenticated,
//! so neither pre-filter accepts a forged packet (a forged counter still must pass
//! AEAD).  **`NonceExhausted` is intentionally checked *after* AEAD** (§13) so that
//! only an authentically decrypted packet at the exhaustion threshold triggers
//! rekey — a pre-AEAD exhaustion check would let an attacker forge high-counter
//! packets to spuriously trigger rekey DoS.  `NonceExhausted` is a separate,
//! non-per-packet signal and is intentionally *not* collapsed to
//! `DecryptionFailed`.

use pq_crypto::aead::{AeadKey, AeadNonce, decrypt as aead_decrypt, encrypt as aead_encrypt};
use pq_crypto::kdf::{
    MasterSecret, build_session_nonce, derive_client_to_server_key, derive_nonce_prefix_c2s,
    derive_nonce_prefix_s2c, derive_server_to_client_key,
};
use zeroize::Zeroize;

use crate::codec::{
    self, AEAD_NONCE_LEN, AEAD_TAG_LEN, Direction, INNER_PLAINTEXT_LEN, InnerPlaintext,
    MessageType, PAYLOAD_LEN, PacketHeader, SESSION_ID_LEN, WirePacket,
};
use crate::error::CodecError;
use crate::replay::ReplayWindow;

// Ties the envelope's AEAD constants to `pq_crypto`'s real ChaCha20-Poly1305
// parameters.  A drift here would compile green but silently break packet
// assembly (ciphertext length mismatch surfaced late as a `Truncated` from
// `WirePacket::from_parts`).  Failing at compile time is safer.
const _: () = assert!(
    AEAD_TAG_LEN == pq_crypto::aead::AEAD_TAG_BYTES,
    "codec AEAD_TAG_LEN must equal pq_crypto's AEAD_TAG_BYTES (ChaCha20-Poly1305)"
);
const _: () = assert!(
    AEAD_NONCE_LEN == pq_crypto::aead::AEAD_NONCE_BYTES,
    "codec AEAD_NONCE_LEN must equal pq_crypto's AEAD_NONCE_BYTES (ChaCha20-Poly1305)"
);

/// Endpoint role, which selects the send/receive direction and the per-direction
/// key/nonce-prefix pair.  PROTOCOL_SPEC §8 state machine: the role is fixed at
/// session establishment and never changes.  (In-place rekeying is not provided
/// in this version — see `WireSession` docs; the `session_id` binding in the
/// key schedule already guarantees per-session key uniqueness, §10.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    /// Direction this role *sends* (and therefore encrypts under).
    fn send_direction(self) -> Direction {
        match self {
            Role::Client => Direction::ClientToServer,
            Role::Server => Direction::ServerToClient,
        }
    }

    /// Direction this role *receives* (and therefore decrypts).
    fn recv_direction(self) -> Direction {
        match self {
            Role::Client => Direction::ServerToClient,
            Role::Server => Direction::ClientToServer,
        }
    }
}

/// Per-session cryptographic state for the steady-state data plane.
///
/// Constructed from a [`MasterSecret`] (post-handshake) via the `pq_crypto::kdf`
/// key schedule.  Holds both directions' keys and nonce prefixes plus the
/// monotonically-increasing send counter and the receive replay high-water mark.
/// Secret fields are erased on `Drop`.
pub struct CipherSession {
    role: Role,
    session_id: [u8; SESSION_ID_LEN],
    key_c2s: AeadKey,
    key_s2c: AeadKey,
    prefix_c2s: [u8; 4],
    prefix_s2c: [u8; 4],
    /// Next counter to use when *sending*.  Strictly monotonic; never reused.
    send_counter: u64,
    /// Sliding-window replay guard (1024-bit bitmap, PROTOCOL_SPEC §5.6).
    /// Tracks seen counters to reject replays while tolerating out-of-order
    /// delivery within the window.  Replaces the old strict high-water-only
    /// approach that rejected all out-of-order packets.
    replay: ReplayWindow,
}

impl core::fmt::Debug for CipherSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CipherSession")
            .field("role", &self.role)
            .field("session_id", &self.session_id)
            .field("send_counter", &self.send_counter)
            .field("recv_highest", &self.replay.highest())
            .finish_non_exhaustive()
    }
}

// `AeadKey` self-erases on drop via its own `Drop`, so we only need to scrub the
// nonce prefixes (secret, per-session) here.  `session_id`, counters, and `role`
// are non-secret routing/state.
impl Drop for CipherSession {
    fn drop(&mut self) {
        self.prefix_c2s.zeroize();
        self.prefix_s2c.zeroize();
    }
}

impl CipherSession {
    /// Derive a fresh cipher session from a master secret and session identifier.
    ///
    /// All keys/prefixes come from `master` via distinct HKDF labels, so a
    /// compromise of one direction does not directly yield the other
    /// (PROTOCOL_SPEC §4 key separation).  The `master` itself is borrowed and not
    /// retained; its caller is responsible for erasing it.
    ///
    /// **Session uniqueness (§10):** the `session_id` is bound into every
    /// derivation, so the derived keys and nonce prefixes are *per-session*, not
    /// merely per-master.  Two sessions sharing a master (e.g. the client and
    /// server ends of one connection) derive independent per-direction keying
    /// material, and a fresh session with a new `session_id` (or a new `master`)
    /// cannot overlap the previous session's AEAD nonce space even though the
    /// send counter restarts at 0 (CRYPTO_PROFILE §8).  Re-creating the *same*
    /// session (same master + same `session_id`) with a reset counter would
    /// repeat the exact key/nonce pair and is forbidden.
    pub fn new(
        role: Role,
        master: &MasterSecret,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<Self, CodecError> {
        let key_c2s = derive_client_to_server_key(master, &session_id)?;
        let key_s2c = derive_server_to_client_key(master, &session_id)?;
        let prefix_c2s = derive_nonce_prefix_c2s(master, &session_id)?;
        let prefix_s2c = derive_nonce_prefix_s2c(master, &session_id)?;
        Ok(Self {
            role,
            session_id,
            key_c2s: AeadKey::from_bytes(key_c2s),
            key_s2c: AeadKey::from_bytes(key_s2c),
            prefix_c2s,
            prefix_s2c,
            send_counter: 0,
            replay: ReplayWindow::new(),
        })
    }

    /// The (non-secret) session identifier this cipher session is bound to.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Current send counter (for diagnostics / replay testing only).
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Highest accepted receive counter, or `None` if no packets have been
    /// received.  Non-secret (counter values are part of the cleartext header).
    pub fn recv_highest(&self) -> Option<u64> {
        self.replay.highest()
    }

    fn send_key(&self) -> &AeadKey {
        match self.role {
            Role::Client => &self.key_c2s,
            Role::Server => &self.key_s2c,
        }
    }

    fn send_prefix(&self) -> &[u8; 4] {
        match self.role {
            Role::Client => &self.prefix_c2s,
            Role::Server => &self.prefix_s2c,
        }
    }

    fn recv_key(&self) -> &AeadKey {
        match self.role {
            Role::Client => &self.key_s2c,
            Role::Server => &self.key_c2s,
        }
    }

    fn recv_prefix(&self) -> &[u8; 4] {
        match self.role {
            Role::Client => &self.prefix_s2c,
            Role::Server => &self.prefix_c2s,
        }
    }

    /// Encrypt a fixed-size payload into an authenticated [`WirePacket`].
    ///
    /// `payload` must be exactly [`PAYLOAD_LEN`] bytes (the codec's fixed slot);
    /// larger application data is fragmented by the transport layer.  The AEAD nonce
    /// is reconstructed from the session prefix + the current send counter, so the
    /// counter is never reused for a direction (CRYPTO_PROFILE §8).  Returns
    /// [`CodecError::NonceExhausted`] when the counter reaches the rotation
    /// threshold (PROTOCOL_SPEC §13 rekey).
    pub fn encrypt(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<WirePacket, CodecError> {
        if payload.len() != PAYLOAD_LEN {
            return Err(CodecError::WrongLength {
                field: "payload",
                expected: PAYLOAD_LEN,
                got: payload.len(),
            });
        }
        if codec::is_counter_exhausted(self.send_counter) {
            return Err(CodecError::NonceExhausted {
                counter: self.send_counter,
            });
        }

        let inner = InnerPlaintext::new(msg_type, self.role.send_direction(), payload)?;
        let header = PacketHeader::new(self.session_id, self.send_counter);
        let aad = header.encode(); // [u8; HEADER_LEN], used as AEAD AAD (authenticated only)
        let nonce =
            AeadNonce::from_bytes(build_session_nonce(self.send_prefix(), self.send_counter));

        let mut ciphertext = aead_encrypt(self.send_key(), &nonce, &inner.encode(), &aad)?;
        debug_assert_eq!(
            ciphertext.len(),
            INNER_PLAINTEXT_LEN + AEAD_TAG_LEN,
            "AEAD ciphertext must be plaintext + tag (codec layout invariant)"
        );

        let packet = WirePacket::from_parts(&aad, &ciphertext)?;
        // `from_parts` copied the ciphertext into the zeroizing `WirePacket`; wipe the
        // transient heap buffer so ciphertext/tag don't linger (IMPLEMENTATION_GUIDE §6).
        ciphertext.zeroize();
        // Advance strictly-monotonically.  `checked_add` guards the u64 edge; the
        // `is_counter_exhausted` check above ensures we never reach u64::MAX.
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(CodecError::NonceExhausted {
                counter: self.send_counter,
            })?;
        Ok(packet)
    }

    /// Decrypt and validate a [`WirePacket`] back into its [`InnerPlaintext`].
    ///
    /// Performs, in order: version validation (§15), replay rejection (§5.6/§11),
    /// AEAD decryption with a nonce reconstructed from the header counter (§4 key
    /// separation + CRYPTO_PROFILE §8), nonce-exhaustion rekey trigger (§13,
    /// checked post-AEAD to prevent forged-counter DoS), and direction validation
    /// (the packet's encrypted `Direction` must match this role's receive
    /// direction).  Any failure returns `Err`; callers MUST drop the packet silently (§14).
    pub fn decrypt(&mut self, packet: &WirePacket) -> Result<InnerPlaintext, CodecError> {
        // §15: version pre-filter (cheap; also AAD-authenticated so a tampered
        // version fails AEAD too).  Collapsed to the generic per-packet result so
        // no failure-type distinction leaks (§14).
        let header = packet.parse_header().map_err(|e| {
            tracing::debug!(err=%e, "decrypt: header rejected");
            CodecError::DecryptionFailed
        })?;
        let counter = header.packet_nonce;

        let nonce = AeadNonce::from_bytes(build_session_nonce(self.recv_prefix(), counter));
        let aad = packet.header_bytes(); // &[u8; HEADER_LEN], the authenticated header
        let mut plaintext = match aead_decrypt(self.recv_key(), &nonce, packet.aead_region(), aad) {
            Ok(pt) => pt,
            Err(e) => {
                tracing::debug!(err=%e, "decrypt: AEAD failed");
                return Err(CodecError::DecryptionFailed);
            }
        };

        // §13 / CRYPTO_PROFILE §8: rekey trigger.  Checked AFTER AEAD so that only
        // an authentically decrypted packet at the exhaustion threshold triggers
        // rekey.  This prevents an active attacker from forging high-counter
        // packets (which would bypass AEAD if checked pre-AEAD) to trigger
        // spurious KEM/key-derivation work — a DoS amplification vector
        // (PROTOCOL_SPEC §5.7: fail securely).  The reconstructed nonce
        // (recv_prefix || MAX_PACKET_NONCE) is safe: the sender never emits a
        // packet at or above this counter, so nonce reuse is impossible.
        // The plaintext was already recovered by AEAD; scrub it before returning
        // so a rejected-but-authentic packet does not leak its payload on the
        // heap (IMPLEMENTATION_GUIDE §6).
        if codec::is_counter_exhausted(counter) {
            plaintext.zeroize();
            return Err(CodecError::NonceExhausted { counter });
        }

        // §5.6 replay: accept this counter in the sliding window.  Checked AFTER
        // AEAD so that only authenticated packets update the replay state — a
        // forged counter still fails AEAD above and never reaches `accept`.
        // The sliding window (1024-bit, per DIRECTION) tolerates out-of-order
        // delivery within the window while rejecting replays (PROTOCOL_SPEC §5.6).
        // Scrub the recovered plaintext (replay is a replayed *authentic* packet).
        if let Err(e) = self.replay.accept(counter) {
            tracing::debug!(counter, recv_highest=?self.replay.highest(), "decrypt: replay rejected");
            plaintext.zeroize();
            return Err(e);
        }

        if plaintext.len() != INNER_PLAINTEXT_LEN {
            // AEAD succeeded but produced an unexpected length — unreachable given
            // the fixed AEAD plaintext size pinned by `from_parts`, but reject
            // uniformly (§14) rather than trust it.
            tracing::debug!(
                pt_len = plaintext.len(),
                "decrypt: unexpected plaintext length"
            );
            plaintext.zeroize();
            return Err(CodecError::DecryptionFailed);
        }
        let inner = match InnerPlaintext::decode(&plaintext) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!(err=%e, "decrypt: inner framing rejected");
                plaintext.zeroize();
                return Err(CodecError::DecryptionFailed);
            }
        };
        // AEAD returned a heap `Vec<u8>`; `Vec::drop` does NOT zeroize
        // (IMPLEMENTATION_GUIDE §6).  Scrub it now that the plaintext has been copied
        // into `inner` (whose own Drop wipes `payload`).
        plaintext.zeroize();

        if inner.direction != self.role.recv_direction() {
            tracing::debug!(expected=?self.role.recv_direction(), got=?inner.direction, "decrypt: direction mismatch");
            return Err(CodecError::DecryptionFailed);
        }

        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{HEADER_LEN, MAX_PACKET_NONCE, PROTOCOL_VERSION, WirePacket};
    use crate::error::CodecError;

    /// Build a deterministic-but-nonzero master secret for deterministic tests.
    fn test_master() -> MasterSecret {
        let c = [0x11u8; 32];
        let s = [0x22u8; 32];
        // derive_master_secret is real HKDF; deterministic for fixed inputs.
        // We replicate its inputs here so tests don't depend on random KEM output.
        pq_crypto::derive_master_secret(&c, &s).expect("master secret derivation in test")
    }

    fn test_sid() -> [u8; SESSION_ID_LEN] {
        [0xAB; SESSION_ID_LEN]
    }

    #[test]
    fn encrypt_decrypt_roundtrip_same_role_pair() {
        let master = test_master();
        let sid = test_sid();
        let mut client = CipherSession::new(Role::Client, &master, sid).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, sid).unwrap();

        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = 0x42;
        payload[PAYLOAD_LEN - 1] = 0x99;

        let pkt = client
            .encrypt(MessageType::Data, &payload)
            .expect("encrypt");
        assert_eq!(pkt.as_bytes().len(), crate::PACKET_SIZE);
        assert_eq!(pkt.parse_header().unwrap().packet_nonce, 0);

        let inner = server.decrypt(&pkt).expect("decrypt");
        assert_eq!(inner.msg_type, MessageType::Data);
        assert_eq!(inner.direction, Direction::ClientToServer);
        assert_eq!(inner.payload, payload);
        assert_eq!(server.recv_highest(), Some(0));
    }

    #[test]
    fn send_counter_advances_monotonically() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        for i in 0..5u64 {
            let pkt = client
                .encrypt(MessageType::Data, &[i as u8; PAYLOAD_LEN])
                .unwrap();
            assert_eq!(pkt.parse_header().unwrap().packet_nonce, i);
            server.decrypt(&pkt).expect("decrypt");
        }
        assert_eq!(client.send_counter(), 5);
        assert_eq!(server.recv_highest(), Some(4));
    }

    #[test]
    fn replay_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0xAA; PAYLOAD_LEN])
            .unwrap();
        server.decrypt(&pkt).expect("first decrypt");
        // Same packet again -> replay -> rejected (§5.6).
        let second = server.decrypt(&pkt);
        assert!(
            matches!(second, Err(CodecError::DecryptionFailed)),
            "replay must be rejected"
        );
    }

    #[test]
    fn rollback_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let p1 = client
            .encrypt(MessageType::Data, &[1u8; PAYLOAD_LEN])
            .unwrap(); // counter 0
        let p2 = client
            .encrypt(MessageType::Data, &[2u8; PAYLOAD_LEN])
            .unwrap(); // counter 1

        // Out-of-order: counter 1 arrives before counter 0.  Sliding window
        // accepts it (within window, not yet seen).
        server.decrypt(&p2).expect("decrypt counter 1");

        // Counter 0 arrives — within the window, not yet seen, passes AEAD → accepted.
        // (Unlike the old high-water-only guard, the sliding window tolerates
        // out-of-order delivery per PROTOCOL_SPEC §5.6.)
        server.decrypt(&p1).expect("decrypt counter 0 out-of-order");

        // Replay: counter 0 again — already in the window bitmap → rejected.
        let replay = server.decrypt(&p1);
        assert!(
            matches!(replay, Err(CodecError::DecryptionFailed)),
            "replay must be rejected"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        // Flip a byte inside the AEAD ciphertext region (after header).
        let mut mangled = *pkt.as_bytes();
        mangled[HEADER_LEN] ^= 0xFF;
        let bad = WirePacket::from_bytes(&mangled).unwrap();
        let res = server.decrypt(&bad);
        assert!(res.is_err(), "tampered ciphertext must fail AEAD");
    }

    #[test]
    fn tampered_version_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();

        let mut bytes = *pkt.as_bytes();
        bytes[0] = PROTOCOL_VERSION + 1; // version byte forged
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        // parse_header checks version BEFORE AEAD, so rejection is immediate.
        assert!(matches!(
            bad.parse_header(),
            Err(CodecError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn direction_mismatch_rejected() {
        // A client-role session only ever sends/receives its role's directions.
        // Decrypting a client→server packet on a *client* session (which expects
        // server→client) must fail the direction check.
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut other_client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let res = other_client.decrypt(&pkt);
        assert!(
            matches!(res, Err(CodecError::DecryptionFailed)),
            "direction mismatch must be rejected"
        );
    }

    #[test]
    fn nonce_exhaustion_triggers_on_threshold() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        // Fast-forward the send counter to the exhaustion threshold.
        client.send_counter = MAX_PACKET_NONCE;
        let res = client.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]);
        assert!(
            matches!(res, Err(CodecError::NonceExhausted { .. })),
            "encrypt at threshold must signal rekey"
        );
    }

    #[test]
    fn cover_traffic_roundtrips_indistinguishably_sized() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Cover, &[0u8; PAYLOAD_LEN])
            .unwrap();
        assert_eq!(pkt.as_bytes().len(), crate::PACKET_SIZE); // same size as Data
        let inner = server.decrypt(&pkt).expect("decrypt cover");
        assert_eq!(inner.msg_type, MessageType::Cover);
    }

    #[test]
    fn cipher_session_zeroizes_on_drop() {
        // Smoke-test the Drop: constructing and dropping must not panic and must
        // not retain observable nonce prefixes (we only assert no-panic + that the
        // type implements Drop with zeroization; memory-inspection is covered by the
        // WirePacket zeroize test in the codec module).
        let master = test_master();
        let mut s = CipherSession::new(Role::Server, &master, test_sid()).unwrap();
        let _ = s.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        drop(s);
    }

    #[test]
    fn payload_length_mismatch_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let too_short = vec![0u8; PAYLOAD_LEN - 1];
        assert!(client.encrypt(MessageType::Data, &too_short).is_err());
    }

    #[test]
    fn reverse_duplex_roundtrip() {
        // Server→client direction (s2c). Half the traffic directions were previously
        // only exercised via rejection; this positively verifies the s2c key/prefix
        // and Direction::ServerToClient mapping.
        let master = test_master();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();

        let pkt = server
            .encrypt(MessageType::Data, &[0x33; PAYLOAD_LEN])
            .expect("s2c encrypt");
        assert_eq!(pkt.as_bytes().len(), crate::PACKET_SIZE);
        let inner = client.decrypt(&pkt).expect("c2s decrypt of s2c packet");
        assert_eq!(inner.direction, Direction::ServerToClient);
        assert_eq!(inner.msg_type, MessageType::Data);
        assert_eq!(inner.payload, [0x33u8; PAYLOAD_LEN]);
    }

    #[test]
    fn nonce_exhaustion_boundary_last_accepted_then_rejects() {
        // MAX_PACKET_NONCE - 1 is the last accepted counter; encrypting it rolls
        // send_counter to MAX_PACKET_NONCE, and the *next* encrypt must reject
        // (PROTOCOL_SPEC §13 rekey, CRYPTO_PROFILE §8).
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        client.send_counter = MAX_PACKET_NONCE - 1;
        let _pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .expect("last-accepted encrypt");
        assert_eq!(client.send_counter(), MAX_PACKET_NONCE);
        let next = client.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]);
        assert!(
            matches!(
                next,
                Err(CodecError::NonceExhausted {
                    counter: MAX_PACKET_NONCE
                })
            ),
            "next encrypt after boundary must signal rekey"
        );
    }

    #[test]
    fn u64_max_is_counter_exhausted() {
        // u64::MAX is past the threshold -> must be treated as exhausted so a
        // receiver can never reconstruct a nonce at the wrap boundary.
        assert!(crate::codec::is_counter_exhausted(u64::MAX));
        assert!(crate::codec::is_counter_exhausted(MAX_PACKET_NONCE));
        assert!(!crate::codec::is_counter_exhausted(0));
    }

    #[test]
    fn tamper_aead_tag_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();
        let mut bytes = *client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap()
            .as_bytes();
        // Flip a byte in the 16-byte AEAD tag (tail of the packet).
        bytes[crate::PACKET_SIZE - 1] ^= 0x01;
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(server.decrypt(&bad).is_err(), "tampered tag must fail AEAD");
    }

    #[test]
    fn tamper_session_id_aad_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();
        let mut bytes = *client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap()
            .as_bytes();
        // session_id is bytes [1..9] (within the 17-byte AAD); flipping it must break
        // the AEAD tag (PROTOCOL_SPEC §12: header fields are authenticated as AAD).
        bytes[3] ^= 0x01;
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(
            server.decrypt(&bad).is_err(),
            "tampered session_id (AAD) must fail AEAD"
        );
    }

    #[test]
    fn tamper_packet_counter_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();
        let mut bytes = *client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap()
            .as_bytes();
        // packet_nonce occupies header bytes [9..17]; flipping it changes the
        // reconstructed AEAD nonce AND the AAD -> AEAD must fail (CRYPTO_PROFILE §8).
        bytes[10] ^= 0x01;
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(
            server.decrypt(&bad).is_err(),
            "tampered packet_nonce must fail AEAD"
        );
    }

    #[test]
    fn version_byte_is_aad_covered() {
        // The version byte is the cheap §15 downgrade pre-filter via `parse_header`,
        // but it must ALSO be AEAD-authenticated (it lives in the AAD).  Prove the
        // AEAD catches a flipped version even if the pre-filter were bypassed:
        let key = pq_crypto::aead::AeadKey::from_bytes([0xABu8; 32]);
        let nonce = pq_crypto::aead::AeadNonce::from_bytes([0u8; 12]);
        let pt = [0u8; INNER_PLAINTEXT_LEN];
        let mut aad = PacketHeader::new(test_sid(), 7).encode(); // version = PROTOCOL_VERSION
        let ct = pq_crypto::aead::encrypt(&key, &nonce, &pt, &aad).unwrap();
        aad[0] = PROTOCOL_VERSION + 1; // flip version within the AAD
        assert!(
            pq_crypto::aead::decrypt(&key, &nonce, &ct, &aad).is_err(),
            "version byte is part of the AAD; flipping it must break AEAD verification"
        );
    }

    #[test]
    fn cross_master_decryption_fails() {
        // Key separation (§4): a packet encrypted under master A must not decrypt
        // under master B's derived keys.
        let a = pq_crypto::derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let b = pq_crypto::derive_master_secret(&[0x33u8; 32], &[0x44u8; 32]).unwrap();
        let mut enc = CipherSession::new(Role::Client, &a, test_sid()).unwrap();
        let mut dec = CipherSession::new(Role::Server, &b, test_sid()).unwrap();
        let pkt = enc.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(
            matches!(dec.decrypt(&pkt), Err(CodecError::DecryptionFailed)),
            "cross-master packet must be rejected at AEAD"
        );
    }

    #[test]
    fn replay_rejects_backward_after_forward_jump() {
        // Accept a forward jump (0..5), then reject an earlier counter (2).
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let mut saved_two: Option<WirePacket> = None;
        for i in 0u64..5 {
            let pkt = client
                .encrypt(MessageType::Data, &[(i as u8); PAYLOAD_LEN])
                .unwrap();
            if i == 2 {
                saved_two = Some(pkt.clone());
            }
            server.decrypt(&pkt).expect("forward accept");
        }
        assert_eq!(client.send_counter(), 5);
        assert_eq!(server.recv_highest(), Some(4));
        // counter 2 is now below the high-water and was already seen -> replay rejected.
        let two = saved_two.unwrap();
        assert!(
            matches!(server.decrypt(&two), Err(CodecError::DecryptionFailed)),
            "out-of-order lower counter must be rejected"
        );
        // The next in-order counter (5) is still accepted.
        let p5 = client
            .encrypt(MessageType::Data, &[5u8; PAYLOAD_LEN])
            .unwrap();
        server.decrypt(&p5).expect("next in-order must succeed");
    }

    #[test]
    fn cipher_session_zeroizes_nonce_prefixes() {
        // Memory-inspection for the secret nonce prefixes (closes the gap vs. the
        // WirePacket zeroize test).  Same-module test can read private fields.
        use std::mem::ManuallyDrop;

        let master = test_master();
        let sid = test_sid();
        let server = ManuallyDrop::new(CipherSession::new(Role::Server, &master, sid).unwrap());
        // Capture secret prefixes before drop (Copy).  Per-direction prefixes must
        // differ (proven by distinct HKDF labels; kdf.rs tests confirm).
        let before_c2s = server.prefix_c2s;
        let before_s2c = server.prefix_s2c;
        assert_ne!(
            before_c2s, before_s2c,
            "per-direction nonce prefixes must differ"
        );

        // Run CipherSession::drop in place (zeroizes prefixes).  ManuallyDrop keeps
        // the allocation alive, so reading the fields afterward is sound and shows
        // the erasure Drop performed.
        unsafe { std::ptr::drop_in_place(&*server as *const CipherSession as *mut CipherSession) };
        assert_eq!(
            server.prefix_c2s, [0u8; 4],
            "prefix_c2s must be zeroized on drop"
        );
        assert_eq!(
            server.prefix_s2c, [0u8; 4],
            "prefix_s2c must be zeroized on drop"
        );
    }

    // -----------------------------------------------------------------------
    // Property-based / fuzz-style tests (no external fuzz dependency)
    // -----------------------------------------------------------------------

    /// `decrypt` must never panic on random valid-size packets — it should
    /// always return `Ok` or `Err(CodecError::*)` without crashing (§14:
    /// reject invalid packets, never panic).
    #[allow(clippy::manual_is_multiple_of)] // is_multiple_of is stable >= 1.87; workspace MSRV is 1.85
    #[test]
    fn fuzz_decrypt_never_panics() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let mut payload = [0u8; PAYLOAD_LEN];
        // Generate a few valid packets to mix into the fuzz corpus.
        let mut valid_packets: Vec<WirePacket> = Vec::new();
        for i in 0..10u64 {
            payload[0] = i as u8;
            let pkt = client.encrypt(MessageType::Data, &payload).unwrap();
            valid_packets.push(pkt.clone());
            server.decrypt(&pkt).expect("valid packet must decrypt");
        }

        // Feed 200 random packets + some old valid ones (replays) to decrypt.
        for _ in 0..200 {
            let mut bytes = [0u8; crate::PACKET_SIZE];
            getrandom::fill(&mut bytes).expect("getrandom");

            // Occasionally use a real encrypted packet to exercise the accept path.
            if getrandom::u32().unwrap_or(0) % 3 == 0 {
                let idx = getrandom::u32().unwrap_or(0) as usize % valid_packets.len();
                let _ = server.decrypt(&valid_packets[idx]);
            } else {
                let pkt = WirePacket::from_bytes(&bytes).unwrap();
                let _ = server.decrypt(&pkt); // must not panic, must return Err
            }
        }
    }

    /// `decrypt` must collapse ALL failure types to `DecryptionFailed` except
    /// `NonceExhausted` (rekey trigger).  No error variant other than these
    /// two should ever escape.
    #[test]
    fn fuzz_decrypt_error_uniformity() {
        let master = test_master();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        for _ in 0..200 {
            let mut bytes = [0u8; crate::PACKET_SIZE];
            getrandom::fill(&mut bytes).expect("getrandom");
            if let Ok(pkt) = WirePacket::from_bytes(&bytes) {
                match server.decrypt(&pkt) {
                    Ok(_) => {}
                    Err(e) => {
                        // Must be DecryptionFailed, NonceExhausted, or InvalidVersion
                        // (InvalidVersion is collapsed to DecryptionFailed by the version
                        // pre-filter, so it should not appear here).
                        assert!(
                            matches!(
                                e,
                                CodecError::DecryptionFailed | CodecError::NonceExhausted { .. }
                            ),
                            "unexpected error variant from decrypt: {:?}",
                            e
                        );
                    }
                }
            }
        }
    }

    /// Tampered version byte must be rejected (§15 downgrade detection).
    #[test]
    fn negative_tampered_version_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        // Tamper with the version byte.
        let mut bytes = *pkt.as_bytes();
        bytes[0] = 0; // version 0 (should be 1)
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(
            matches!(server.decrypt(&bad), Err(CodecError::DecryptionFailed)),
            "tampered version must be rejected (collapsed to DecryptionFailed)"
        );
    }

    /// Tampered AEAD tag must be rejected.
    #[test]
    fn negative_tampered_tag_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let mut bytes = *pkt.as_bytes();
        // Flip a byte in the tag (last 16 bytes).
        bytes[crate::PACKET_SIZE - 1] ^= 0x01;
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(server.decrypt(&bad).is_err(), "tampered tag must fail AEAD");
    }

    /// Tampered session_id (AAD) must be rejected.
    #[test]
    fn negative_tampered_session_id_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let mut bytes = *pkt.as_bytes();
        bytes[3] ^= 0x01; // session_id byte
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(
            server.decrypt(&bad).is_err(),
            "tampered session_id (AAD) must fail AEAD"
        );
    }

    /// Tampered packet_nonce must be rejected (it's part of the nonce AND AAD).
    #[test]
    fn negative_tampered_counter_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = CipherSession::new(Role::Server, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let mut bytes = *pkt.as_bytes();
        bytes[10] ^= 0x01; // packet_nonce byte
        let bad = WirePacket::from_bytes(&bytes).unwrap();
        assert!(
            server.decrypt(&bad).is_err(),
            "tampered counter must fail AEAD"
        );
    }

    /// Oversized packet (extra bytes) must be rejected by `from_bytes`.
    #[test]
    fn negative_oversized_packet_rejected() {
        let mut big = [0u8; crate::PACKET_SIZE + 1];
        getrandom::fill(&mut big).expect("getrandom");
        assert!(
            WirePacket::from_bytes(&big).is_err(),
            "oversized packet must be rejected"
        );
    }

    /// Undersized packet must be rejected.
    #[test]
    fn negative_undersized_packet_rejected() {
        let short = [0u8; crate::PACKET_SIZE - 1];
        assert!(
            WirePacket::from_bytes(&short).is_err(),
            "undersized packet must be rejected"
        );
    }

    /// Direction-flipped packet (client encrypts c2s, server tries to decrypt
    /// on its own role — which expects s2c) must be rejected.
    #[test]
    fn negative_direction_mismatch_rejected() {
        let master = test_master();
        let mut client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut other_client = CipherSession::new(Role::Client, &master, test_sid()).unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        assert!(
            matches!(
                other_client.decrypt(&pkt),
                Err(CodecError::DecryptionFailed)
            ),
            "direction mismatch must be rejected"
        );
    }
}
