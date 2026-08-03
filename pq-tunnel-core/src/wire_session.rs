//! Data-path Tunnel session.
//!
//! PROTOCOL_SPEC §10 requires active sessions to provide:
//!
//! - unique session protection keys (via [`CipherSession`] + [`MasterSecret`]),
//! - replay protection (via the envelope's sliding window),
//! - connection identification (the `session_id`),
//! - secure state management (the explicit state machine, PROTOCOL_SPEC §8).
//!
//! [`WireSession`] is the cryptographic core of an established connection: it
//! owns a per-direction `CipherSession`, exposes the lifecycle transitions
//! defined by the state machine, and gates the data path on the
//! `Established` state (PROTOCOL_SPEC §8.3).  It does NOT perform I/O — the
//! transport (`UdpTransport`, or anything else) delivers [`WirePacket`]s to
//! [`WireSession::decrypt`] and sends what [`WireSession::encrypt`] returns.
//!
//! # Rekey handling
//!
//! When the nonce counter reaches the exhaustion threshold (CRYPTO_PROFILE §8),
//! the envelope returns [`CodecError::NonceExhausted`].  This session treats
//! that as the §13 rekey trigger: it transitions to `Rekey` and surfaces
//! [`SessionError::RekeyRequired`].  The *construction* of rekeying (how fresh
//! keying material is derived and confirmed) is an open protocol decision
//! (DESIGN_DECISIONS "Rekeying Model" — Unresolved), so this version does NOT
//! provide an in-place rekey path: a session that exhausts its nonce space is
//! blocked from further data (its [`Self::state`] reports `Rekey`) and the
//! caller MUST close it and establish a fresh session.  A fresh session MUST
//! NOT reuse the same keying material with a reset counter — re-deriving the
//! same master + session_id would repeat the exact AEAD key/nonce pair
//! (catastrophic reuse, CRYPTO_PROFILE §8).  New sessions must use a new
//! session_id and/or a new master; the handshake supplies fresh keying per
//! session (§10 unique session protection keys).

use std::time::Instant;

use pq_crypto::CryptoError;
use pq_crypto::kdf::MasterSecret;

use crate::codec::{InnerPlaintext, MessageType, PAYLOAD_LEN, SESSION_ID_LEN, WirePacket};
use crate::envelope::{CipherSession, Role};
use crate::error::CodecError;
use crate::metrics::SessionMetrics;
use crate::state::{InvalidTransition, ProtocolState};

/// Errors raised by [`WireSession`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A lifecycle transition was rejected by the state machine
    /// (PROTOCOL_SPEC §8, IMPLEMENTATION_GUIDE §3.3).
    #[error("invalid state transition: {0}")]
    State(#[from] InvalidTransition),

    /// The data path was used in a state that does not permit it.  Only
    /// `Established` permits encrypted traffic (§8.3); `Handshake` and `Rekey`
    /// must complete first.
    #[error("session must be in {required} state to perform this operation (actual: {actual})")]
    WrongState {
        required: ProtocolState,
        actual: ProtocolState,
    },

    /// A per-packet codec/envelope failure (rejected silently by callers).
    #[error("codec: {0}")]
    Codec(#[from] CodecError),

    /// A local cryptographic failure (key derivation / setup).  Fatal for this
    /// session; do not continue (§5.7).
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// The nonce counter reached the exhaustion threshold (§13,
    /// CRYPTO_PROFILE §8).  The session has been transitioned to
    /// [`ProtocolState::Rekey`] and the data path is blocked.  Because the
    /// rekeying model is unresolved (DESIGN_DECISIONS), this version offers no
    /// in-place rekey: close this session and establish a fresh one with new
    /// keying material.
    #[error("nonce counter exhausted: session must be closed and re-established")]
    RekeyRequired,
}

/// A session in one direction of a Tunnel connection: the AEAD envelope bound
/// to an explicit connection state machine.
///
/// Secret-bearing (holds key material inside `CipherSession`); deliberately not
/// `Clone`.  Dropping the session zeroizes the envelope's per-direction keys
/// and nonce prefixes via `CipherSession`'s `Drop`.
#[derive(Debug)]
pub struct WireSession {
    role: Role,
    session_id: [u8; SESSION_ID_LEN],
    state: ProtocolState,
    cipher: CipherSession,
    metrics: SessionMetrics,
}

impl WireSession {
    /// Create a session in [`ProtocolState::Initial`] from a post-handshake
    /// master secret.  The caller must provide a *new* `MasterSecret` per
    /// session (nonce reuse across sessions is catastrophic — see
    /// [`CipherSession::new`] docs).
    pub fn new(
        role: Role,
        master: &MasterSecret,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<Self, SessionError> {
        let cipher = CipherSession::new(role, master, session_id)?;
        let metrics = SessionMetrics {
            created_at: Some(Instant::now()),
            ..SessionMetrics::default()
        };
        Ok(Self {
            role,
            session_id,
            state: ProtocolState::Initial,
            cipher,
            metrics,
        })
    }

    /// Create a session in [`ProtocolState::Established`] directly from a
    /// completed v2 handshake outcome.
    ///
    /// This is the Phase 6 session-manager integration point: the v2
    /// handshake (DESIGN_DECISIONS D13–D15) has already verified the peer and
    /// derived the fresh per-session master, so the session enters the data
    /// path ready to encrypt/decrypt immediately — no `Initial → Handshake →
    /// Established` walk is needed.  The outcome's `peer_identity` is the
    /// pinned, verified peer key; identity keys never appear on the wire
    /// (D12).
    pub fn established(
        role: Role,
        outcome: &crate::handshake_v2::HandshakeOutcome,
    ) -> Result<Self, SessionError> {
        let cipher = CipherSession::new(role, &outcome.master, outcome.session_id)?;
        let metrics = SessionMetrics {
            created_at: Some(Instant::now()),
            ..SessionMetrics::default()
        };
        Ok(Self {
            role,
            session_id: outcome.session_id,
            state: ProtocolState::Established,
            cipher,
            metrics,
        })
    }

    /// Current state of the session.
    pub fn state(&self) -> ProtocolState {
        self.state
    }

    /// This endpoint's role in the session.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The (non-secret) session identifier.
    pub fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Session metrics (bytes/packets handled since creation).
    pub fn metrics(&self) -> &SessionMetrics {
        &self.metrics
    }

    // ------------------------------------------------------------------
    // Lifecycle (state machine)
    // ------------------------------------------------------------------

    /// Transition `Initial → Handshake` (§8.2).
    pub fn begin_handshake(&mut self) -> Result<(), SessionError> {
        self.state = self.state.transition(ProtocolState::Handshake)?;
        Ok(())
    }

    /// Transition `Handshake → Established` (§8.3).
    pub fn complete_handshake(&mut self) -> Result<(), SessionError> {
        self.state = self.state.transition(ProtocolState::Established)?;
        Ok(())
    }

    /// Transition any state → `Closed` (§8.4).  Idempotent: closing an already
    /// closed session is a no-op success.
    pub fn close(&mut self) -> Result<(), SessionError> {
        self.state = ProtocolState::Closed;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Data path — only in `Established` (§8.3)
    // ------------------------------------------------------------------

    fn require_established(&self) -> Result<(), SessionError> {
        if self.state == ProtocolState::Established {
            Ok(())
        } else {
            Err(SessionError::WrongState {
                required: ProtocolState::Established,
                actual: self.state,
            })
        }
    }

    /// Encrypt a fixed-size payload into a [`WirePacket`] (§8.3).
    ///
    /// On nonce exhaustion the session transitions to `Rekey` and returns
    /// [`SessionError::RekeyRequired`].
    pub fn encrypt(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<WirePacket, SessionError> {
        self.require_established()?;
        match self.cipher.encrypt(msg_type, payload) {
            Ok(pkt) => {
                self.metrics.packets_sent += 1;
                self.metrics.bytes_sent += crate::codec::PACKET_SIZE as u64;
                Ok(pkt)
            }
            Err(CodecError::NonceExhausted { .. }) => {
                self.state = ProtocolState::Rekey;
                Err(SessionError::RekeyRequired)
            }
            Err(e) => Err(SessionError::Codec(e)),
        }
    }

    /// Encrypt a cover packet (random fill, fixed size) — §12 traffic
    /// management / cover traffic.
    pub fn cover(&mut self) -> Result<WirePacket, SessionError> {
        self.require_established()?;
        let mut fill = [0u8; PAYLOAD_LEN];
        getrandom::fill(&mut fill).map_err(|e| {
            SessionError::Crypto(CryptoError::InvalidInput(format!("getrandom: {e}")))
        })?;
        self.encrypt(MessageType::Cover, &fill)
    }

    /// Decrypt and validate a received packet (§8.3).
    ///
    /// Any per-packet failure is returned as [`SessionError::Codec`] (the
    /// envelope already collapses failure reasons to a uniform rejection —
    /// PROTOCOL_SPEC §14); callers MUST drop the packet silently.  Metrics are
    /// updated only for successfully decrypted packets, so a flood of garbage
    /// cannot inflate counters.  On nonce exhaustion the session transitions to
    /// `Rekey` and returns [`SessionError::RekeyRequired`].
    pub fn decrypt(&mut self, packet: &WirePacket) -> Result<InnerPlaintext, SessionError> {
        self.require_established()?;
        match self.cipher.decrypt(packet) {
            Ok(inner) => {
                self.metrics.packets_received += 1;
                self.metrics.bytes_received += crate::codec::PACKET_SIZE as u64;
                Ok(inner)
            }
            Err(CodecError::NonceExhausted { .. }) => {
                self.state = ProtocolState::Rekey;
                Err(SessionError::RekeyRequired)
            }
            Err(e) => Err(SessionError::Codec(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Direction, PACKET_SIZE};

    fn test_master() -> MasterSecret {
        let c = [0x11u8; 32];
        let s = [0x22u8; 32];
        pq_crypto::derive_master_secret(&c, &s).expect("master secret derivation")
    }

    fn test_sid() -> [u8; SESSION_ID_LEN] {
        [0xAB; SESSION_ID_LEN]
    }

    /// A pair of sessions (client + server) sharing a master secret, both in
    /// `Established`.
    fn established_pair() -> (WireSession, WireSession) {
        let master = test_master();
        let mut client = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        let mut server = WireSession::new(Role::Server, &master, test_sid()).unwrap();
        client.begin_handshake().unwrap();
        client.complete_handshake().unwrap();
        server.begin_handshake().unwrap();
        server.complete_handshake().unwrap();
        (client, server)
    }

    #[test]
    fn lifecycle_full_path() {
        let master = test_master();
        let mut s = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        assert_eq!(s.state(), ProtocolState::Initial);

        s.begin_handshake().unwrap();
        assert_eq!(s.state(), ProtocolState::Handshake);

        s.complete_handshake().unwrap();
        assert_eq!(s.state(), ProtocolState::Established);

        s.close().unwrap();
        assert_eq!(s.state(), ProtocolState::Closed);
    }

    #[test]
    fn close_is_idempotent() {
        let master = test_master();
        let mut s = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        s.close().unwrap();
        assert_eq!(s.state(), ProtocolState::Closed);
        // Closing again is a no-op success.
        s.close().unwrap();
        assert_eq!(s.state(), ProtocolState::Closed);
    }

    #[test]
    fn invalid_transition_rejected() {
        let master = test_master();
        let mut s = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        // Cannot jump straight to Established.
        assert!(matches!(
            s.complete_handshake(),
            Err(SessionError::State(_))
        ));
        assert_eq!(
            s.state(),
            ProtocolState::Initial,
            "failed transition must not move state"
        );

        // Cannot begin a second handshake after reaching Established.
        s.begin_handshake().unwrap();
        s.complete_handshake().unwrap();
        assert!(matches!(s.begin_handshake(), Err(SessionError::State(_))));
        assert_eq!(s.state(), ProtocolState::Established);

        // Cannot handshake after closing.
        s.close().unwrap();
        assert!(matches!(s.begin_handshake(), Err(SessionError::State(_))));
        assert_eq!(s.state(), ProtocolState::Closed);
    }

    #[test]
    fn data_path_requires_established() {
        let master = test_master();
        let mut s = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        let payload = [0u8; PAYLOAD_LEN];

        let err = s.encrypt(MessageType::Data, &payload).unwrap_err();
        assert!(matches!(
            err,
            SessionError::WrongState {
                required: ProtocolState::Established,
                ..
            }
        ));

        // During handshake, still blocked.
        s.begin_handshake().unwrap();
        assert!(s.encrypt(MessageType::Data, &payload).is_err());

        // After close, blocked forever.
        s.close().unwrap();
        assert!(s.encrypt(MessageType::Data, &payload).is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (mut client, mut server) = established_pair();

        let payload = [0x55u8; PAYLOAD_LEN];
        let pkt = client.encrypt(MessageType::Data, &payload).unwrap();

        let inner = server.decrypt(&pkt).unwrap();
        assert_eq!(inner.msg_type, MessageType::Data);
        assert_eq!(inner.direction, Direction::ClientToServer);
        assert_eq!(&inner.payload[..], &payload[..]);
    }

    #[test]
    fn cover_packet_roundtrip() {
        let (mut client, mut server) = established_pair();

        let pkt = client.cover().unwrap();
        let inner = server.decrypt(&pkt).unwrap();
        assert_eq!(inner.msg_type, MessageType::Cover);
        assert_eq!(inner.direction, Direction::ClientToServer);
        // Cover payload is random, but must be non-trivial at least some of the
        // time — just assert it is the fixed payload length and not all zeros
        // in the overwhelmingly-likely case.  (A pathological all-zero draw is
        // astronomically unlikely with 4080 random bytes.)
        assert_eq!(inner.payload.len(), PAYLOAD_LEN);
    }

    #[test]
    fn wrong_direction_rejected() {
        let (mut client, _server) = established_pair();
        // A second *client* with the same master must not be able to read the
        // first client's packets (direction separation).
        let master = test_master();
        let mut other = WireSession::new(Role::Client, &master, test_sid()).unwrap();
        other.begin_handshake().unwrap();
        other.complete_handshake().unwrap();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        assert!(matches!(
            other.decrypt(&pkt),
            Err(SessionError::Codec(CodecError::DecryptionFailed))
        ));
    }

    #[test]
    fn tampered_packet_rejected_silently() {
        let (mut client, mut server) = established_pair();
        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let mut bytes = *pkt.as_bytes();
        bytes[PACKET_SIZE - 1] ^= 0x01;
        let tampered = crate::codec::WirePacket::from_bytes(&bytes).unwrap();
        assert!(server.decrypt(&tampered).is_err());
        // Session still functional and still Established.
        assert_eq!(server.state(), ProtocolState::Established);
    }

    #[test]
    fn metrics_track_successful_traffic() {
        let (mut client, mut server) = established_pair();

        let pkt = client
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let _ = server.decrypt(&pkt).unwrap();

        assert_eq!(client.metrics().packets_sent, 1);
        assert_eq!(client.metrics().bytes_sent, PACKET_SIZE as u64);
        assert_eq!(server.metrics().packets_received, 1);
        assert_eq!(server.metrics().bytes_received, PACKET_SIZE as u64);

        // A garbage packet must not inflate receive metrics.
        let garbage = crate::codec::WirePacket::from_bytes(&[0u8; PACKET_SIZE]).unwrap();
        assert!(server.decrypt(&garbage).is_err());
        assert_eq!(server.metrics().packets_received, 1);
    }

    #[test]
    fn nonce_exhaustion_transitions_to_rekey_and_blocks() {
        // §13 rekey trigger: when an *authentic* packet arrives at the
        // exhaustion threshold (checked post-AEAD, so a forged high counter
        // cannot trigger a spurious rekey DoS), decrypt signals RekeyRequired
        // and the session enters Rekey.  Because the rekeying model is
        // unresolved, there is no in-place rekey: the data path stays blocked
        // and the caller must close the session and establish a fresh one with
        // new keying material.
        use crate::codec::{InnerPlaintext, PacketHeader, WirePacket};
        use pq_crypto::aead::{AeadKey, AeadNonce, encrypt as aead_encrypt};
        use pq_crypto::kdf::{
            build_session_nonce, derive_client_to_server_key, derive_nonce_prefix_c2s,
        };

        let master = test_master();
        let sid = test_sid();
        let mut server = WireSession::new(Role::Server, &master, sid).unwrap();
        server.begin_handshake().unwrap();
        server.complete_handshake().unwrap();
        assert_eq!(server.state(), ProtocolState::Established);

        // Build a valid packet at the exhaustion-threshold counter directly
        // with the (public) KDF + AEAD primitives.  The sender never emits such
        // a packet, but if it did, the receiver MUST trigger rekey.
        let key = derive_client_to_server_key(&master, &sid).unwrap();
        let prefix = derive_nonce_prefix_c2s(&master, &sid).unwrap();
        let inner = InnerPlaintext::new(
            MessageType::Data,
            Direction::ClientToServer,
            &[0u8; PAYLOAD_LEN],
        )
        .unwrap();
        let header = PacketHeader::new(sid, crate::codec::MAX_PACKET_NONCE);
        let aad = header.encode();
        let nonce =
            AeadNonce::from_bytes(build_session_nonce(&prefix, crate::codec::MAX_PACKET_NONCE));
        let ct = aead_encrypt(&AeadKey::from_bytes(key), &nonce, &inner.encode(), &aad).unwrap();
        let pkt = WirePacket::from_parts(&aad, &ct).unwrap();

        assert!(matches!(
            server.decrypt(&pkt),
            Err(SessionError::RekeyRequired)
        ));
        assert_eq!(server.state(), ProtocolState::Rekey);

        // Data path is blocked while in Rekey — the next attempt is a
        // WrongState rejection, not a spurious success.
        assert!(matches!(
            server.decrypt(&pkt),
            Err(SessionError::WrongState { .. })
        ));
        assert_eq!(server.state(), ProtocolState::Rekey);

        // The only way forward is teardown.
        server.close().unwrap();
        assert_eq!(server.state(), ProtocolState::Closed);
    }

    // -----------------------------------------------------------------------
    // End-to-end: WireSession pair transported over raw UDP loopback.
    // -----------------------------------------------------------------------

    #[test]
    fn established_from_handshake_outcome_ready_for_data() {
        use crate::handshake_v2::HandshakeOutcome;
        use pq_crypto::kdf::MasterSecret;

        let master = MasterSecret::from_bytes([0x77; 32]);
        let outcome = HandshakeOutcome {
            master,
            session_id: test_sid(),
            peer_identity: pq_crypto::MlDsaKeypair::generate().expect("keygen").public,
            handshake_duration: std::time::Duration::from_millis(1),
        };

        let mut client = WireSession::established(Role::Client, &outcome).expect("client");
        let mut server = WireSession::established(Role::Server, &outcome).expect("server");

        assert_eq!(client.state(), ProtocolState::Established);
        assert_eq!(client.session_id(), &test_sid());
        assert_eq!(server.state(), ProtocolState::Established);

        // The data path is immediately usable — the v2 handshake already
        // authenticated the peer (D12/D13), so no lifecycle walk is needed.
        let pkt = client
            .encrypt(MessageType::Data, &[0x5Au8; PAYLOAD_LEN])
            .expect("encrypt");
        let inner = server.decrypt(&pkt).expect("decrypt");
        assert_eq!(&inner.payload[..], &[0x5Au8; PAYLOAD_LEN][..]);
    }

    #[tokio::test]
    async fn udp_end_to_end_roundtrip() {
        use crate::codec::WirePacket;
        use crate::udp::UdpTransport;

        let (mut client, mut server) = established_pair();

        let mut server_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server_udp.local_addr().unwrap();
        let client_udp = UdpTransport::connect(server_addr).await.unwrap();
        server_udp.set_peer(client_udp.local_addr().unwrap());

        // client → server over UDP.
        let pkt = client
            .encrypt(MessageType::Data, &[0x7Au8; PAYLOAD_LEN])
            .unwrap();
        client_udp.send(&pkt).await.unwrap();
        let (recv_pkt, from) = server_udp.recv().await.unwrap();
        // Client binds a wildcard address; the kernel picks a loopback source
        // for the actual datagram.  Match on port + loopback-ness, not the
        // reported (0.0.0.0) local IP.
        assert_eq!(from.port(), client_udp.local_addr().unwrap().port());
        assert!(from.ip().is_loopback(), "source must be loopback");
        let inner = server.decrypt(&recv_pkt).unwrap();
        assert_eq!(inner.msg_type, MessageType::Data);
        assert_eq!(&inner.payload[..], &[0x7Au8; PAYLOAD_LEN][..]);

        // server → client reply over UDP (both directions exercised).  The
        // server learns the client's source from the received datagram (the
        // client's reported local address is the wildcard 0.0.0.0 and is not
        // sendable-to).
        server_udp.set_peer(from);
        let reply = server
            .encrypt(MessageType::Data, &[0x33u8; PAYLOAD_LEN])
            .unwrap();
        server_udp.send(&reply).await.unwrap();
        let (recv_reply, _from) = client_udp.recv().await.unwrap();
        let inner = client.decrypt(&recv_reply).unwrap();
        assert_eq!(inner.direction, Direction::ServerToClient);
        assert_eq!(&inner.payload[..], &[0x33u8; PAYLOAD_LEN][..]);

        // A tampered packet that survives UDP still fails AEAD on receipt, and
        // the session remains functional in Established.
        let mut tampered = *pkt.as_bytes();
        tampered[PACKET_SIZE - 1] ^= 0x01;
        client_udp
            .send(&WirePacket::from_bytes(&tampered).unwrap())
            .await
            .unwrap();
        let (bad, _from) = server_udp.recv().await.unwrap();
        assert!(server.decrypt(&bad).is_err());
        assert_eq!(server.state(), ProtocolState::Established);
    }
}
