//! Session manager: handshake → established lifecycle for the raw-UDP data
//! path (Phase 6).
//!
//! Two pure state machines live here, mirroring the `handshake_v2` pattern
//! (machines compute and return events; thin async drivers perform I/O):
//!
//! - [`ServerSessionManager`]: one global [`ServerHandshake`] for all sources
//!   plus a `sid → SessionEntry` table of established [`WireSession`]s.
//! - [`ClientSessionManager`]: a single client handshake + a single
//!   [`WireSession`], with automatic re-establishment (D16).
//!
//! # Protocol pins
//!
//! - **Dispatch**: byte 9 (`VERSION_LEN + SESSION_ID_LEN`) selects the path —
//!   `0x10/0x20/0x30` → handshake machine, anything else → data path (D13;
//!   `is_handshake_fragment`).  The sid (bytes 1..9) associates data packets
//!   with sessions (D4: identifies sessions, not users, not credentials).
//! - **Roaming** (PROTOCOL_SPEC §10: sessions MUST NOT depend permanently on
//!   source addresses): the peer is a hint, rebound on *authenticated* decrypt
//!   success.  Only a key-holder can move a session — spoofed sources cannot
//!   pin or move it.
//! - **D15 (client liveness)**: inbound delivery is decrypt-gated, so
//!   application data is never delivered before an authenticated server packet
//!   exists.  The enforceable clause is a `liveness_timeout` (default 30 s)
//!   from establishment that closes mis-keyed sessions (`Closed{NotConfirmed}`)
//!   and re-establishes.  Outbound is deliberately NOT gated: gating would
//!   deadlock request/response flows with a passive server after
//!   re-establishment (the client's first data packet is the server's proof;
//!   keys are bound to the pinned peer, so no confidentiality impact).
//! - **D16 (rekey = close + re-establish)**: nonce exhaustion on either path
//!   removes the session (`Closed{NonceExhausted}`, keys zeroized on drop);
//!   the client re-arms a fresh handshake (fresh sid, fresh ephemerals, fresh
//!   master).  A received `Close` (0x03) message tears down without ack
//!   (`Closed{PeerClosed}`); an app-driven close sends `Close` then reports
//!   `Closed{UserClosed}`.
//! - **Eviction**: server — idle timeout (receive-activity) + optional
//!   lifetime cap (D16 bounds traffic-key exposure); capacity → least-recently-
//!   active eviction.  Client — lifetime cap + liveness timeout only; a
//!   quiet-but-live post-confirmation session must not churn (Phase 7 cover
//!   traffic provides post-confirmation liveness).
//! - **DoS posture**: the data path gates *failures* per source (H1 review
//!   finding): a token (burst 64 / 10 s) is consumed only when an AEAD
//!   decrypt fails; when a source's tokens are exhausted its packets are
//!   dropped without decrypt work.  Legitimate traffic has ~0% failure rate;
//!   a failing session is gated for at most one window and recovers via D16
//!   re-establishment.  The bucket table is hard-capped (`max_fail_buckets`,
//!   default 4096) with stalest eviction.
//!
//! # Event model
//!
//! `handle_datagram` / `app_outbound` / `on_timer` return exactly one
//! [`ManagerEvent`] per call — `None` and `SendPacket` allocate nothing on the
//! hot path.  The two genuinely composed cases (capacity eviction, user
//! close) queue their `Closed` in a `pending_closed` deque drained by
//! [`ServerSessionManager::tick`] / [`ClientSessionManager::tick`] (cold
//! path).
//!
//! # Cover traffic
//!
//! [`WireSession::cover`] exists; the managers expose `cover_packet()` so the
//! Phase 7 shaper can fill the schedule.  Pacing/scheduling is Phase 7 scope.
//!
//! # Security notes
//!
//! Peer-input failures are silent drops (`ManagerEvent::None`), never errors
//! and never emitted datagrams (D12/D13: no error oracle, no amplification).
//! Errors are local failures only (config, crypto, state).  Sessions are
//! removed by dropping the entry — the zeroizing `Drop`s of `WireSession` /
//! `CipherSession` wipe keys and nonce prefixes (D14).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::warn;

use crate::codec::{InnerPlaintext, MessageType, PAYLOAD_LEN, SESSION_ID_LEN, WirePacket};
use crate::envelope::Role;
use crate::error::CodecError;
use crate::handshake_v2::{
    ClientConfig, ClientEvent, ClientHandshake, HandshakeOutcome, HandshakeTransport,
    HandshakeV2Error, ServerConfig, ServerEvent, ServerHandshake, is_handshake_fragment,
    random_sid,
};
use crate::scheduler::{CoverPolicy, CoverScheduler};
use crate::wire_session::{SessionError, WireSession};

/// Driver tick interval: session eviction / deadline checks.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Resource / lifetime limits for a session manager.
///
/// Role applicability is documented per field; parameters are tunable
/// tradeoffs (D7) and never redefine security guarantees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLimits {
    /// Server only: upper bound on concurrently established sessions.
    /// At capacity the least-recently-active session is evicted
    /// (`Closed{Capacity}`).
    pub max_sessions: usize,
    /// Server only: a session whose last authenticated receive is older than
    /// this is evicted (`Closed{IdleTimeout}`).  The client side does not idle
    /// evict — a quiet-but-live session must not churn (Phase 7 cover traffic
    /// provides post-confirmation liveness).
    pub idle_timeout: Option<Duration>,
    /// Both roles: upper bound on session lifetime (D16 bounds traffic-key
    /// exposure).  `Closed{LifetimeCap}`.
    pub lifetime_cap: Option<Duration>,
    /// Client only (D15): a session that receives no authenticated server
    /// packet within this time of establishment is mis-keyed or dead —
    /// closed (`Closed{NotConfirmed}`) and re-established.
    pub liveness_timeout: Option<Duration>,
    /// Client only (F6): overall deadline for a handshake attempt
    /// (`Closed{HandshakeTimeout}`); the M1 retransmit budget is enforced
    /// inside the handshake machine.
    pub handshake_timeout: Option<Duration>,
    /// Data-path failure gate: max decrypt *failures* per source per window.
    pub fail_burst: u32,
    /// Data-path failure gate window.
    pub fail_window: Duration,
    /// Data-path failure gate: hard cap on per-source buckets (spoofed-source
    /// floods cannot grow the table unboundedly; stalest evicted at the cap).
    pub max_fail_buckets: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            idle_timeout: Some(Duration::from_secs(5 * 60)),
            lifetime_cap: None,
            liveness_timeout: Some(Duration::from_secs(30)),
            handshake_timeout: Some(Duration::from_secs(30)),
            fail_burst: 64,
            fail_window: Duration::from_secs(10),
            max_fail_buckets: 4096,
        }
    }
}

// ---------------------------------------------------------------------------
// Events / errors
// ---------------------------------------------------------------------------

/// Why a session was closed and removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Server eviction: no authenticated packet within `idle_timeout`.
    IdleTimeout,
    /// D16: configured session-lifetime cap reached.
    LifetimeCap,
    /// D16: nonce counter exhausted (rekey trigger) — close + re-establish.
    NonceExhausted,
    /// D15: client received no authenticated server packet within
    /// `liveness_timeout` (mis-keyed or dead session).
    NotConfirmed,
    /// Client: handshake failed (M1 budget exhausted or overall deadline).
    HandshakeTimeout,
    /// Server: evicted to make room for a new session at `max_sessions`.
    Capacity,
    /// The peer sent a `Close` message (§8.4, no ack).
    PeerClosed,
    /// The local application closed the session (client: a `Close` packet was
    /// emitted first).
    UserClosed,
}

/// One output of a manager call: datagrams to emit, app data, or closure.
///
/// Single event per call; `None` and `SendPacket` are allocation-free on the
/// hot path.  Composed events (capacity eviction, user close) queue their
/// `Closed` for the next `tick` instead.
#[derive(Debug)]
pub enum ManagerEvent {
    /// Handshake fragments to emit, all to `peer` (handshake path only).
    Send {
        packets: Vec<WirePacket>,
        peer: SocketAddr,
    },
    /// One encrypted data/cover/close packet to emit.
    SendPacket {
        packet: WirePacket,
        peer: SocketAddr,
    },
    /// A new session was created (server role; the client emits no
    /// `Established` — `ClientSessionManager::is_ready` is its D15 signal).
    Established {
        sid: [u8; SESSION_ID_LEN],
        peer: SocketAddr,
    },
    /// Decrypted application data (MessageType::Data; cover/close consumed
    /// internally).
    AppData {
        sid: [u8; SESSION_ID_LEN],
        inner: InnerPlaintext,
    },
    /// A session was closed and removed.
    Closed {
        sid: [u8; SESSION_ID_LEN],
        reason: CloseReason,
    },
    /// Nothing to do — silent drop.
    None,
}

/// Notifications a driver relays to the application channel.
///
/// The `Data` variant carries a 1KiB `InnerPlaintext`: boxed variants would
/// add an allocation on the hot path, so the size difference is accepted.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ManagerNotification {
    /// Server: a session was established (route `sid → peer`).
    Established {
        sid: [u8; SESSION_ID_LEN],
        peer: SocketAddr,
    },
    /// Client only (D15): the first authenticated server packet decrypted —
    /// the session is confirmed live.
    Ready { sid: [u8; SESSION_ID_LEN] },
    /// Decrypted application data.
    Data {
        sid: [u8; SESSION_ID_LEN],
        inner: InnerPlaintext,
    },
    /// A session closed; the client driver re-establishes.
    Closed {
        sid: [u8; SESSION_ID_LEN],
        reason: CloseReason,
    },
}

/// Outbound command from the server application: send `payload` on session
/// `sid` (payloads ≤ `PAYLOAD_LEN`; shorter payloads are zero-padded).
#[derive(Debug)]
pub struct ServerAppCommand {
    pub sid: [u8; SESSION_ID_LEN],
    pub payload: Vec<u8>,
}

/// Local (non-peer-input) failures.  Peer-input failures are silent drops,
/// never errors (D12/D13).
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// Handshake-machine failure (timeout, transport, local crypto).
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeV2Error),
    /// Session failure (crypto, state).
    #[error("session: {0}")]
    Session(#[from] SessionError),
    /// `app_outbound`/`cover_packet` referenced a sid with no session.
    #[error("no session for sid")]
    NoSession,
    /// An operation was invoked in an invalid local state (driver bug guard).
    #[error("invalid local state: {0}")]
    InvalidState(&'static str),
    /// Invalid local configuration; fail closed.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// The application channel closed (driver only).
    #[error("application channel closed")]
    AppClosed,
}

// ---------------------------------------------------------------------------
// Data-path failure gate (H1 review fix)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RateBucket {
    tokens: u32,
    last_refill: Instant,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Outcome of decrypting one inbound data-path packet.
///
/// Transient value on the hot path: the large `Payload` variant is moved
/// straight into the returned event (no copy); boxing would allocate.
#[allow(clippy::large_enum_variant)]
enum DataResult {
    Payload(InnerPlaintext),
    PeerClose,
    SessionDead(CloseReason),
    Failed,
}

struct SessionEntry {
    session: WireSession,
    peer: SocketAddr,
    last_activity: Instant,
    established_at: Instant,
}

/// Server-side session manager: one global handshake machine + a table of
/// established sessions.
///
/// Pure with respect to I/O: `handle_datagram`/`app_outbound`/`tick` only
/// compute and return events; the driver performs sends.  This makes the
/// receive path directly fuzzable.
pub struct ServerSessionManager {
    limits: SessionLimits,
    hs: ServerHandshake,
    sessions: HashMap<[u8; SESSION_ID_LEN], SessionEntry>,
    fail_buckets: HashMap<SocketAddr, RateBucket>,
    pending_closed: VecDeque<ManagerEvent>,
}

impl ServerSessionManager {
    /// Create a server session manager.  Configuration is validated here
    /// (version + non-empty roster) — fail closed (D12).
    pub fn new(cfg: &ServerConfig, limits: SessionLimits) -> Result<Self, ManagerError> {
        if cfg.version != crate::codec::PROTOCOL_VERSION {
            return Err(ManagerError::InvalidConfig(format!(
                "version {} unsupported (expected {})",
                cfg.version,
                crate::codec::PROTOCOL_VERSION
            )));
        }
        if cfg.roster.is_empty() {
            return Err(ManagerError::InvalidConfig(
                "roster must not be empty (fail closed)".into(),
            ));
        }
        Ok(Self {
            limits,
            hs: ServerHandshake::new(cfg),
            sessions: HashMap::new(),
            fail_buckets: HashMap::new(),
            pending_closed: VecDeque::new(),
        })
    }

    /// Number of established sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of pending handshake entries (diagnostics).
    pub fn pending_handshakes(&self) -> usize {
        self.hs.pending_len()
    }

    /// Number of data-path failure-gate buckets (diagnostics).
    pub fn fail_bucket_count(&self) -> usize {
        self.fail_buckets.len()
    }

    /// Process one received datagram (silent drop on anything irrelevant).
    pub fn handle_datagram(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        if is_handshake_fragment(pkt) {
            match self.hs.handle_datagram(pkt, from)? {
                ServerEvent::Emit(packets, peer) => Ok(ManagerEvent::Send { packets, peer }),
                ServerEvent::Complete(outcome) => self.on_handshake_complete(outcome, from),
                ServerEvent::None => Ok(ManagerEvent::None),
            }
        } else {
            self.on_data_packet(pkt, from)
        }
    }

    /// Establish the session for a completed handshake.
    ///
    /// - sid collision with an existing session → silent drop of the newcomer
    ///   (an observer of the plaintext sid must not be able to assassinate the
    ///   session; never overwrite).
    /// - at `max_sessions` → evict the least-recently-active session; its
    ///   `Closed{Capacity}` is queued for the next tick (single-event
    ///   invariant).
    fn on_handshake_complete(
        &mut self,
        outcome: HandshakeOutcome,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        let sid = outcome.session_id;
        if self.sessions.contains_key(&sid) {
            return Ok(ManagerEvent::None);
        }
        // MSRV 1.85: nested if-let (let chains stabilize in 1.88). Cannot be
        // collapsed via a `&& let` chain without breaking the MSRV gate.
        #[allow(clippy::collapsible_if)]
        if self.sessions.len() >= self.limits.max_sessions {
            if let Some(stale) = self
                .sessions
                .iter()
                .min_by_key(|(_, e)| e.last_activity)
                .map(|(k, _)| *k)
            {
                self.sessions.remove(&stale); // Drop zeroizes session keys (D14)
                self.pending_closed.push_back(ManagerEvent::Closed {
                    sid: stale,
                    reason: CloseReason::Capacity,
                });
            }
        }
        let session = WireSession::established(Role::Server, &outcome)?;
        let now = Instant::now();
        self.sessions.insert(
            sid,
            SessionEntry {
                session,
                peer: from,
                last_activity: now,
                established_at: now,
            },
        );
        Ok(ManagerEvent::Established { sid, peer: from })
    }

    fn on_data_packet(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        if !self.fail_gate_peek(from) {
            return Ok(ManagerEvent::None);
        }
        let sid: [u8; SESSION_ID_LEN] = pkt.as_bytes()[1..1 + SESSION_ID_LEN]
            .try_into()
            .expect("fixed-size sid slice");
        let now = Instant::now();

        let result = match self.sessions.get_mut(&sid) {
            None => return Ok(ManagerEvent::None),
            Some(entry) => match entry.session.decrypt(pkt) {
                Ok(inner) => {
                    entry.last_activity = now;
                    // §10 roaming: rebind only on an authenticated packet.
                    entry.peer = from;
                    match inner.msg_type {
                        MessageType::Data => DataResult::Payload(inner),
                        MessageType::Cover => DataResult::Payload(inner),
                        MessageType::Close => DataResult::PeerClose,
                        MessageType::Handshake => DataResult::Failed,
                    }
                }
                Err(SessionError::RekeyRequired) => {
                    DataResult::SessionDead(CloseReason::NonceExhausted)
                }
                Err(SessionError::Codec(_)) => DataResult::Failed,
                Err(e) => return Err(ManagerError::Session(e)),
            },
        };

        match result {
            DataResult::Payload(inner) => match inner.msg_type {
                MessageType::Data => Ok(ManagerEvent::AppData { sid, inner }),
                // Cover is consumed silently (it is not application data).
                _ => Ok(ManagerEvent::None),
            },
            DataResult::PeerClose => {
                self.sessions.remove(&sid);
                Ok(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::PeerClosed,
                })
            }
            DataResult::SessionDead(reason) => {
                self.sessions.remove(&sid);
                Ok(ManagerEvent::Closed { sid, reason })
            }
            DataResult::Failed => {
                self.fail_gate_consume(from);
                Ok(ManagerEvent::None)
            }
        }
    }

    /// Encrypt application data on `sid` into a `SendPacket` event.
    ///
    /// Payloads shorter than [`PAYLOAD_LEN`] are zero-padded to the fixed
    /// slot (the slot is AEAD-protected; the fixed packet size is the
    /// metadata-resistance invariant).  On nonce exhaustion the session is
    /// removed and `Closed{NonceExhausted}` returned (D16).
    pub fn app_outbound(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
        payload: &[u8],
    ) -> Result<ManagerEvent, ManagerError> {
        if payload.len() > PAYLOAD_LEN {
            return Err(ManagerError::Session(SessionError::Codec(
                CodecError::WrongLength {
                    field: "payload",
                    expected: PAYLOAD_LEN,
                    got: payload.len(),
                },
            )));
        }
        let mut padded = [0u8; PAYLOAD_LEN];
        padded[..payload.len()].copy_from_slice(payload);
        self.send_encrypted(sid, MessageType::Data, &padded)
    }

    /// Encrypt a cover packet on `sid` (Phase 7 shaper hook).
    pub fn cover_packet(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
    ) -> Result<ManagerEvent, ManagerError> {
        let entry = self.sessions.get_mut(sid).ok_or(ManagerError::NoSession)?;
        let peer = entry.peer;
        match entry.session.cover() {
            Ok(packet) => {
                entry.last_activity = Instant::now();
                Ok(ManagerEvent::SendPacket { packet, peer })
            }
            Err(SessionError::RekeyRequired) => {
                self.sessions.remove(sid);
                Ok(ManagerEvent::Closed {
                    sid: *sid,
                    reason: CloseReason::NonceExhausted,
                })
            }
            Err(e) => Err(ManagerError::Session(e)),
        }
    }

    /// Emit one cover packet on **every** established session (cover hook for
    /// the server driver's periodic arm).  Production order is
    /// `sid`-sorted for determinism.  Any crypto-level error fails the whole
    /// batch (fail-secure: a bad cover packet is a session fault).
    pub fn cover_packet_all(&mut self) -> Result<Vec<ManagerEvent>, ManagerError> {
        let mut sids: Vec<[u8; SESSION_ID_LEN]> = self.sessions.keys().copied().collect();
        sids.sort_unstable();
        let mut out = Vec::with_capacity(sids.len());
        for sid in sids {
            match self.cover_packet(&sid)? {
                ManagerEvent::None => {}
                ev => out.push(ev),
            }
        }
        Ok(out)
    }

    fn send_encrypted(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<ManagerEvent, ManagerError> {
        let entry = self.sessions.get_mut(sid).ok_or(ManagerError::NoSession)?;
        let peer = entry.peer;
        match entry.session.encrypt(msg_type, payload) {
            Ok(packet) => {
                entry.last_activity = Instant::now();
                Ok(ManagerEvent::SendPacket { packet, peer })
            }
            Err(SessionError::RekeyRequired) => {
                self.sessions.remove(sid);
                Ok(ManagerEvent::Closed {
                    sid: *sid,
                    reason: CloseReason::NonceExhausted,
                })
            }
            Err(e) => Err(ManagerError::Session(e)),
        }
    }

    /// Close a session at the application's request (no wire message — the
    /// server is passive; the peer discovers it by idle timeout or the Close
    /// the *client* sent).
    pub fn close_session(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
    ) -> Result<ManagerEvent, ManagerError> {
        match self.sessions.remove(sid) {
            Some(_) => Ok(ManagerEvent::Closed {
                sid: *sid,
                reason: CloseReason::UserClosed,
            }),
            None => Err(ManagerError::NoSession),
        }
    }

    /// Timer tick: evict idle/expired sessions, drain queued `Closed` events.
    pub fn tick(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();
        let idle = self.limits.idle_timeout;
        let life = self.limits.lifetime_cap;
        self.sessions.retain(|sid, e| {
            let idle_ok = idle.is_none_or(|t| now.duration_since(e.last_activity) < t);
            let life_ok = life.is_none_or(|t| now.duration_since(e.established_at) < t);
            if idle_ok && life_ok {
                true
            } else {
                let reason = if !life_ok {
                    CloseReason::LifetimeCap
                } else {
                    CloseReason::IdleTimeout
                };
                out.push(ManagerEvent::Closed { sid: *sid, reason });
                false
            }
        });
        out.extend(self.pending_closed.drain(..));
        out
    }

    // -- data-path failure gate ----------------------------------------------

    /// Token check WITHOUT consuming: refill the bucket for `from` and report
    /// whether a decrypt attempt may proceed.  Bucket creation / cap
    /// eviction happens here (mirrors handshake_v2 `rate_ok`).
    fn fail_gate_peek(&mut self, from: SocketAddr) -> bool {
        if self.limits.max_fail_buckets == 0 {
            // Degenerate configuration: fail closed (no data path).
            return false;
        }
        let now = Instant::now();
        if self.fail_buckets.len() > 32 {
            self.fail_buckets
                .retain(|_, b| now.duration_since(b.last_refill) < self.limits.fail_window);
        }
        // MSRV 1.85: nested if-let (let chains stabilize in 1.88). Cannot be
        // collapsed via a `&& let` chain without breaking the MSRV gate.
        #[allow(clippy::collapsible_if)]
        if self.fail_buckets.len() >= self.limits.max_fail_buckets {
            if let Some(stale) = self
                .fail_buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| *k)
            {
                self.fail_buckets.remove(&stale);
            }
        }
        let bucket = self.fail_buckets.entry(from).or_insert_with(|| RateBucket {
            tokens: self.limits.fail_burst,
            last_refill: now,
        });
        if now.duration_since(bucket.last_refill) >= self.limits.fail_window {
            bucket.tokens = self.limits.fail_burst;
            bucket.last_refill = now;
        }
        bucket.tokens > 0
    }

    /// Consume one failure token (called only after a real AEAD failure).
    fn fail_gate_consume(&mut self, from: SocketAddr) {
        if let Some(b) = self.fail_buckets.get_mut(&from) {
            b.tokens = b.tokens.saturating_sub(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client manager lifecycle state (diagnostics / driver control).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientManagerState {
    /// No handshake running and no session (before the first `begin_handshake`
    /// or between closure and re-arm).
    Idle,
    /// A handshake is in flight.
    Handshaking,
    /// A session is established (gated until `is_ready`, D15).
    Established,
}

/// Client-side session manager: one handshake + one session, automatic
/// re-establishment (D16).  Pure with respect to I/O.
pub struct ClientSessionManager {
    cfg: ClientConfig,
    limits: SessionLimits,
    hs: Option<ClientHandshake>,
    session: Option<WireSession>,
    ready: bool,
    peer: SocketAddr,
    hs_started: Option<Instant>,
    established_at: Option<Instant>,
    pending_closed: VecDeque<ManagerEvent>,
}

impl ClientSessionManager {
    /// Create a client session manager (version validated — fail closed).
    pub fn new(cfg: &ClientConfig, limits: SessionLimits) -> Result<Self, ManagerError> {
        if cfg.version != crate::codec::PROTOCOL_VERSION {
            return Err(ManagerError::InvalidConfig(format!(
                "version {} unsupported (expected {})",
                cfg.version,
                crate::codec::PROTOCOL_VERSION
            )));
        }
        Ok(Self {
            cfg: cfg.clone(),
            limits,
            hs: None,
            session: None,
            ready: false,
            peer: cfg.server_addr,
            hs_started: None,
            established_at: None,
            pending_closed: VecDeque::new(),
        })
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ClientManagerState {
        if self.session.is_some() {
            ClientManagerState::Established
        } else if self.hs.is_some() {
            ClientManagerState::Handshaking
        } else {
            ClientManagerState::Idle
        }
    }

    /// D15: has the first authenticated server packet decrypted?
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// The active session's sid, if any.
    pub fn session_id(&self) -> Option<[u8; SESSION_ID_LEN]> {
        self.session.as_ref().map(|s| *s.session_id())
    }

    /// The in-flight handshake's sid, if a handshake is running.
    pub fn handshake_sid(&self) -> Option<[u8; SESSION_ID_LEN]> {
        self.hs.as_ref().map(|h| *h.session_id())
    }

    /// Start (or restart) a handshake with a fresh client-chosen sid.
    ///
    /// Allowed only from `Idle`; the driver calls this at start and after
    /// every `Closed` event (D16 re-establishment).
    pub fn begin_handshake(&mut self) -> Result<ManagerEvent, ManagerError> {
        if self.hs.is_some() || self.session.is_some() {
            return Err(ManagerError::InvalidState(
                "handshake already running or session established",
            ));
        }
        let sid = random_sid()?;
        let hs = ClientHandshake::new(&self.cfg, sid)?;
        let packets = hs.m1_frags().to_vec();
        self.hs = Some(hs);
        self.hs_started = Some(Instant::now());
        self.ready = false;
        self.peer = self.cfg.server_addr;
        Ok(ManagerEvent::Send {
            packets,
            peer: self.cfg.server_addr,
        })
    }

    /// Process one received datagram.
    pub fn handle_datagram(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        if let Some(hs) = &mut self.hs {
            match hs.handle_datagram(pkt) {
                Ok(ClientEvent::Emit(packets)) => Ok(ManagerEvent::Send {
                    packets,
                    peer: self.cfg.server_addr,
                }),
                Ok(ClientEvent::Complete(outcome)) => {
                    self.establish(outcome)?;
                    Ok(ManagerEvent::None)
                }
                Ok(ClientEvent::None) => Ok(ManagerEvent::None),
                Err(e) => Err(ManagerError::Handshake(e)),
            }
        } else if let Some(sid) = self.session_id() {
            let result: DataResult =
                match self.session.as_mut().expect("checked above").decrypt(pkt) {
                    Ok(inner) => match inner.msg_type {
                        MessageType::Data | MessageType::Cover => DataResult::Payload(inner),
                        MessageType::Close => DataResult::PeerClose,
                        MessageType::Handshake => DataResult::Failed,
                    },
                    Err(SessionError::RekeyRequired) => {
                        DataResult::SessionDead(CloseReason::NonceExhausted)
                    }
                    Err(SessionError::Codec(_)) => DataResult::Failed,
                    Err(e) => return Err(ManagerError::Session(e)),
                };
            match result {
                DataResult::Payload(inner) => {
                    // D15: the first authenticated server packet opens the gate.
                    self.ready = true;
                    // §10 roaming: rebind only on an authenticated packet.
                    self.peer = from;
                    match inner.msg_type {
                        MessageType::Data => Ok(ManagerEvent::AppData { sid, inner }),
                        _ => Ok(ManagerEvent::None),
                    }
                }
                DataResult::PeerClose => {
                    self.close_session_internal();
                    Ok(ManagerEvent::Closed {
                        sid,
                        reason: CloseReason::PeerClosed,
                    })
                }
                DataResult::SessionDead(reason) => {
                    self.close_session_internal();
                    Ok(ManagerEvent::Closed { sid, reason })
                }
                DataResult::Failed => Ok(ManagerEvent::None),
            }
        } else {
            Ok(ManagerEvent::None)
        }
    }

    /// Handshake retransmit timer tick (delegates to the client machine).
    pub fn on_timer(&mut self) -> Result<ManagerEvent, ManagerError> {
        let Some(hs) = &mut self.hs else {
            return Ok(ManagerEvent::None);
        };
        let sid = *hs.session_id();
        match hs.on_timer() {
            Ok(ClientEvent::Emit(packets)) => Ok(ManagerEvent::Send {
                packets,
                peer: self.cfg.server_addr,
            }),
            Ok(ClientEvent::Complete(outcome)) => {
                self.establish(outcome)?;
                Ok(ManagerEvent::None)
            }
            Ok(ClientEvent::None) => Ok(ManagerEvent::None),
            Err(HandshakeV2Error::Timeout) => {
                self.hs = None;
                self.hs_started = None;
                Ok(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::HandshakeTimeout,
                })
            }
            Err(e) => Err(ManagerError::Handshake(e)),
        }
    }

    /// Current retransmit delay, if a handshake is in flight (driver timer).
    pub fn next_delay(&self) -> Option<Duration> {
        self.hs.as_ref().map(|h| h.next_delay())
    }

    /// Timer tick: overall handshake deadline (F6), D15 liveness timeout,
    /// D16 lifetime cap; drains queued `Closed` events.
    pub fn tick(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();

        if self.hs.is_some() {
            let past_deadline = self
                .limits
                .handshake_timeout
                .is_some_and(|t| self.hs_started.is_some_and(|s| now.duration_since(s) >= t));
            if past_deadline {
                let sid = *self.hs.as_ref().expect("checked").session_id();
                self.hs = None;
                self.hs_started = None;
                out.push(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::HandshakeTimeout,
                });
            }
        }

        if let Some(sid) = self.session_id() {
            let not_confirmed = self.limits.liveness_timeout.is_some_and(|t| {
                !self.ready
                    && self
                        .established_at
                        .is_some_and(|e| now.duration_since(e) >= t)
            });
            if not_confirmed {
                self.close_session_internal();
                out.push(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::NotConfirmed,
                });
            } else {
                let past_cap = self.limits.lifetime_cap.is_some_and(|t| {
                    self.established_at
                        .is_some_and(|e| now.duration_since(e) >= t)
                });
                if past_cap {
                    self.close_session_internal();
                    out.push(ManagerEvent::Closed {
                        sid,
                        reason: CloseReason::LifetimeCap,
                    });
                }
            }
        }

        out.extend(self.pending_closed.drain(..));
        out
    }

    /// Encrypt application data into a `SendPacket` (zero-pads to the fixed
    /// slot).  Not gated on `is_ready` — see module docs (D15 reading).
    pub fn app_outbound(&mut self, payload: &[u8]) -> Result<ManagerEvent, ManagerError> {
        if payload.len() > PAYLOAD_LEN {
            return Err(ManagerError::Session(SessionError::Codec(
                CodecError::WrongLength {
                    field: "payload",
                    expected: PAYLOAD_LEN,
                    got: payload.len(),
                },
            )));
        }
        let mut padded = [0u8; PAYLOAD_LEN];
        padded[..payload.len()].copy_from_slice(payload);
        self.send_encrypted(MessageType::Data, &padded)
    }

    /// Encrypt a cover packet (Phase 7 shaper hook).
    pub fn cover_packet(&mut self) -> Result<ManagerEvent, ManagerError> {
        let sid = self.session_id().ok_or(ManagerError::NoSession)?;
        let session = self.session.as_mut().expect("checked");
        let peer = self.peer;
        match session.cover() {
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
            Err(SessionError::RekeyRequired) => {
                self.close_session_internal();
                Ok(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::NonceExhausted,
                })
            }
            Err(e) => Err(ManagerError::Session(e)),
        }
    }

    /// App-driven close: emit a fire-and-forget `Close` packet (§8.4), drop
    /// the session, and queue `Closed{UserClosed}` for the next tick.
    pub fn close(&mut self) -> Result<ManagerEvent, ManagerError> {
        let Some(sid) = self.session_id() else {
            return Ok(ManagerEvent::None);
        };
        match self.send_encrypted(MessageType::Close, &[0u8; PAYLOAD_LEN]) {
            Ok(ManagerEvent::SendPacket { packet, peer }) => {
                self.close_session_internal();
                self.pending_closed.push_back(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::UserClosed,
                });
                Ok(ManagerEvent::SendPacket { packet, peer })
            }
            // send_encrypted already removed the session (NonceExhausted).
            other => other,
        }
    }

    fn establish(&mut self, outcome: HandshakeOutcome) -> Result<(), ManagerError> {
        let session = WireSession::established(Role::Client, &outcome)?;
        self.hs = None;
        self.hs_started = None;
        self.session = Some(session);
        self.ready = false;
        self.established_at = Some(Instant::now());
        Ok(())
    }

    fn close_session_internal(&mut self) {
        self.session = None;
        self.ready = false;
    }

    fn send_encrypted(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<ManagerEvent, ManagerError> {
        let sid = *self
            .session
            .as_ref()
            .ok_or(ManagerError::NoSession)?
            .session_id();
        let session = self.session.as_mut().expect("checked");
        let peer = self.peer;
        match session.encrypt(msg_type, payload) {
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
            Err(SessionError::RekeyRequired) => {
                self.close_session_internal();
                Ok(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::NonceExhausted,
                })
            }
            Err(e) => Err(ManagerError::Session(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

/// Run the server manager: transport I/O, event → notification relay, and
/// periodic `tick`s.  Returns on transport error (fail-secure), on app
/// channel closure, or when `app_rx` closes.
///
/// `cover` is the per-session cover-traffic schedule (transport policy, D19):
/// once at least one session is established the driver emits one cover packet
/// to every established session per interval.  No session → the schedule stays
/// inert.
pub async fn run_server_manager<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ServerSessionManager,
    app_tx: mpsc::Sender<ManagerNotification>,
    mut app_rx: mpsc::Receiver<ServerAppCommand>,
    cover: CoverPolicy,
) -> Result<(), ManagerError> {
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    let mut cover_sched = CoverScheduler::new(cover);
    let cover_arm = cover_sleep(&cover_sched);
    tokio::pin!(cover_arm);
    // One warn per reset episode (an ICMP storm from a vanished peer would
    // otherwise spam at cover cadence until idle eviction reaps it).
    let mut reset_noticed = false;
    loop {
        tokio::select! {
            r = transport.recv() => match r {
                // Wrong-size / background noise: skip, not fatal.
                Err(HandshakeV2Error::DatagramRejected) => {}
                // ICMP port-unreachable / WSAECONNRESET: some peer's port
                // vanished (it closed, crashed, or its network path reset).
                // Informational in UDP, with no source address attached, so
                // no specific session can be attributed; the dead session is
                // left to the normal idle-eviction tick (D16).  Session-local
                // by construction: one vanished client must never terminate
                // unrelated sessions or the server process (M9B).
                Err(HandshakeV2Error::TransportReset) => {
                    if !reset_noticed {
                        reset_noticed = true;
                        warn!("transport reset by peer (recoverable: session eviction handles the dead peer)");
                    }
                    continue;
                }
                Err(e) => return Err(ManagerError::Handshake(e)),
                Ok((pkt, from)) => {
                    reset_noticed = false;
                    match manager.handle_datagram(&pkt, from)? {
                    ManagerEvent::Send { packets, peer } => {
                        for p in &packets {
                            transport.send_to(p, peer).await?;
                        }
                    }
                    ManagerEvent::SendPacket { packet, peer } => {
                        transport.send_to(&packet, peer).await?;
                    }
                    ManagerEvent::Established { sid, peer } => {
                        cover_sched.start(Instant::now());
                        cover_arm.set(cover_sleep(&cover_sched));
                        app_tx
                            .send(ManagerNotification::Established { sid, peer })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                    ManagerEvent::AppData { sid, inner } => {
                        app_tx
                            .send(ManagerNotification::Data { sid, inner })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                    ManagerEvent::Closed { sid, reason } => {
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                    ManagerEvent::None => {}
                    }
                },
            },
            cmd = app_rx.recv() => match cmd {
                Some(cmd) => match manager.app_outbound(&cmd.sid, &cmd.payload) {
                    Ok(ManagerEvent::SendPacket { packet, peer }) => {
                        transport.send_to(&packet, peer).await?;
                    }
                    Ok(ManagerEvent::Closed { sid, reason }) => {
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                    // Local condition only (stale/evicted sid); not a transport or
                    // crypto error. Drop silently so the driver stays up and the
                    // session's own Closed path handles teardown — recoverable.
                    Err(ManagerError::NoSession) => {}
                    // Oversized app payload (> PAYLOAD_LEN): the app over-sent into
                    // the fixed payload slot. Benign *local* input — must NOT tear
                    // the tunnel. The app should chunk to <= PAYLOAD_LEN and gate on
                    // the Ready notification. Mirrors the D1 NoSession demotion;
                    // only WrongLength is demoted, not Codec/AEAD/crypto faults.
                    Err(ManagerError::Session(SessionError::Codec(CodecError::WrongLength { .. }))) => {}
                    Err(e) => return Err(e),
                    _ => {}
                },
                None => return Ok(()),
            },
            _ = ticker.tick() => {
                for ev in manager.tick(Instant::now()) {
                    if let ManagerEvent::Closed { sid, reason } = ev {
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                }
            }
            _ = &mut cover_arm => {
                if cover_sched.on_deadline(Instant::now()) {
                    for ev in manager.cover_packet_all()? {
                        match ev {
                            ManagerEvent::SendPacket { packet, peer } => {
                                transport.send_to(&packet, peer).await?;
                            }
                            ManagerEvent::Closed { sid, reason } => {
                                app_tx
                                    .send(ManagerNotification::Closed { sid, reason })
                                    .await
                                    .map_err(|_| ManagerError::AppClosed)?;
                            }
                            _ => {}
                        }
                    }
                    // No established sessions left → go inert (no idle churn).
                    if manager.session_count() == 0 {
                        cover_sched.stop();
                    }
                }
                cover_arm.set(cover_sleep(&cover_sched));
            }
        }
    }
}

/// Run the client manager: auto-connect, transport I/O, app data relay,
/// retransmit timers, and re-establishment after every `Closed` (D16).
///
/// `cover` is the cover-traffic schedule for the single client session
/// (transport policy, D19).  It is armed only while the session is
/// established (`is_ready`); after any `Closed` it goes inert until
/// re-established, so a mid-handshake client never emits cover.
pub async fn run_client_manager<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ClientSessionManager,
    app_tx: mpsc::Sender<ManagerNotification>,
    mut app_rx: mpsc::Receiver<Vec<u8>>,
    cover: CoverPolicy,
) -> Result<(), ManagerError> {
    // Auto-connect: the tunnel is always up (Phase 8 may gate this later).
    if let ManagerEvent::Send { packets, peer } = manager.begin_handshake()? {
        for p in &packets {
            transport.send_to(p, peer).await?;
        }
    }
    let mut was_ready = false;
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    let mut cover_sched = CoverScheduler::new(cover);
    let cover_arm = cover_sleep(&cover_sched);
    tokio::pin!(cover_arm);
    // The handshake retransmit timer is created ONCE and advanced only when it
    // fires (or the manager re-arms after a Close). Recomputing it from
    // `next_delay()` on *every* iteration lets continuous application data
    // (which keeps `app_rx` ready) indefinitely postpone the retransmit — and
    // with a passive server the retransmit budget is the only path to client
    // establishment (D15). Pinning the deadline preserves the retransmit
    // schedule under app load.
    let retransmit = client_retransmit_timer(manager);
    tokio::pin!(retransmit);
    loop {
        // D15 confirmation signal (informational for the app; outbound is not
        // gated — see module docs).
        if manager.is_ready() && !was_ready {
            was_ready = true;
            cover_sched.start(Instant::now());
            cover_arm.set(cover_sleep(&cover_sched));
            if let Some(sid) = manager.session_id() {
                app_tx
                    .send(ManagerNotification::Ready { sid })
                    .await
                    .map_err(|_| ManagerError::AppClosed)?;
            }
        }

        tokio::select! {
            r = transport.recv() => match r {
                Err(HandshakeV2Error::DatagramRejected) => {}
                Err(e) => return Err(ManagerError::Handshake(e)),
                Ok((pkt, from)) => match manager.handle_datagram(&pkt, from)? {
                    ManagerEvent::Send { packets, peer } => {
                        for p in &packets {
                            transport.send_to(p, peer).await?;
                        }
                    }
                    ManagerEvent::SendPacket { packet, peer } => {
                        transport.send_to(&packet, peer).await?;
                    }
                    ManagerEvent::AppData { sid, inner } => {
                        app_tx
                            .send(ManagerNotification::Data { sid, inner })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                    }
                    ManagerEvent::Closed { sid, reason } => {
                        was_ready = false;
                        cover_sched.stop();
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                        rearm_client(transport, manager).await?;
                        retransmit.set(client_retransmit_timer(manager));
                    }
                    ManagerEvent::Established { .. } | ManagerEvent::None => {}
                },
            },
            cmd = app_rx.recv() => {
                match cmd {
                    Some(payload) => match manager.app_outbound(&payload) {
                        Ok(ManagerEvent::SendPacket { packet, peer }) => {
                            transport.send_to(&packet, peer).await?;
                        }
                            Ok(ManagerEvent::Closed { sid, reason }) => {
                                was_ready = false;
                                cover_sched.stop();
                                app_tx
                                    .send(ManagerNotification::Closed { sid, reason })
                                    .await
                                    .map_err(|_| ManagerError::AppClosed)?;
                                rearm_client(transport, manager).await?;
                                retransmit.set(client_retransmit_timer(manager));
                            }
                            // Local condition only (app pushed data while the client
                            // is Handshaking / re-establishing). Do not tear down the
                            // tunnel; the app can retry once Ready arrives.
                            Err(ManagerError::NoSession) => {}
                            // Oversized app payload: benign local over-send into the
                            // fixed payload slot; drop silently (tunnel stays up).
                            Err(ManagerError::Session(SessionError::Codec(
                                CodecError::WrongLength { .. },
                            ))) => {}
                            Err(e) => return Err(e),
                            _ => {}
                        },
                    None => return Ok(()),
                }
            },
            _ = &mut retransmit => match manager.on_timer()? {
                ManagerEvent::Send { packets, peer } => {
                    for p in &packets {
                        transport.send_to(p, peer).await?;
                    }
                    retransmit.set(client_retransmit_timer(manager));
                }
                ManagerEvent::Closed { sid, reason } => {
                    was_ready = false;
                    cover_sched.stop();
                    app_tx
                        .send(ManagerNotification::Closed { sid, reason })
                        .await
                        .map_err(|_| ManagerError::AppClosed)?;
                    rearm_client(transport, manager).await?;
                    retransmit.set(client_retransmit_timer(manager));
                }
                _ => retransmit.set(client_retransmit_timer(manager)),
            },
            _ = ticker.tick() => {
                for ev in manager.tick(Instant::now()) {
                    if let ManagerEvent::Closed { sid, reason } = ev {
                        was_ready = false;
                        cover_sched.stop();
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                        rearm_client(transport, manager).await?;
                        retransmit.set(client_retransmit_timer(manager));
                    }
                }
            }
            _ = &mut cover_arm => {
                if cover_sched.on_deadline(Instant::now()) {
                    match manager.cover_packet() {
                        Ok(ManagerEvent::SendPacket { packet, peer }) => {
                            transport.send_to(&packet, peer).await?;
                        }
                        Ok(ManagerEvent::Closed { sid, reason }) => {
                            was_ready = false;
                            cover_sched.stop();
                            app_tx
                                .send(ManagerNotification::Closed { sid, reason })
                                .await
                                .map_err(|_| ManagerError::AppClosed)?;
                            rearm_client(transport, manager).await?;
                            retransmit.set(client_retransmit_timer(manager));
                        }
                        // Session not (yet) established: never churn over it.
                        Err(ManagerError::NoSession) => {}
                        // A cover emission is real encrypted traffic: any other
                        // fault is a session fault and must surface (fail-secure).
                        Err(e) => return Err(e),
                        _ => {}
                    }
                }
                cover_arm.set(cover_sleep(&cover_sched));
            }
        }
    }
}

/// The handshake retransmit timer, computed once per phase — NOT refreshed on
/// every driver iteration — so application traffic cannot starve the
/// retransmit schedule (and silently stall establishment, which a passive
/// server completes only via the retransmit budget — D15).
fn client_retransmit_timer(manager: &ClientSessionManager) -> tokio::time::Sleep {
    manager
        .next_delay()
        .map(tokio::time::sleep)
        .unwrap_or_else(|| tokio::time::sleep(Duration::MAX))
}

/// Cover-timer arm for the driver `select!`s: sleep until the next cover
/// deadline, or effectively forever when nothing is scheduled.  Re-armed on
/// every wake via `Pin::set`, the same discipline as `client_retransmit_timer`
/// — the cover schedule must never be recreated per iteration, or application
/// traffic would starve it (the M2 timer defect class; D19).
///
/// The scheduler stays clock-agnostic; only this conversion differs per
/// platform.  Windows uses a high-resolution waitable timer (M9A): tokio's
/// timer driver quantizes to the system timer resolution (~15.6 ms at the
/// default), which would stretch the 5.12 ms cover grid to ~64 pkt/s.
/// Other platforms keep the tokio timer.
#[cfg(windows)]
fn cover_sleep(sched: &CoverScheduler) -> cover_clock::CoverSleep {
    match sched.next_deadline() {
        Some(d) => cover_clock::CoverSleep::deadline(d),
        None => cover_clock::CoverSleep::inert(),
    }
}

#[cfg(not(windows))]
fn cover_sleep(sched: &CoverScheduler) -> tokio::time::Sleep {
    match sched.next_deadline() {
        Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)),
        None => tokio::time::sleep(Duration::MAX),
    }
}

/// Windows high-resolution cover clock (M9A).
///
/// Drives the absolute deadline on a raw waitable timer created with
/// `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` (the only mechanism measured to
/// land near the 5.12 ms grid: p50 5.31 ms vs 15.60 ms for tokio
/// `sleep_until`).  The wait runs on the blocking pool so the async worker
/// is never stalled; the async arm is a `JoinHandle` future so re-arming
/// via `Pin::set` (dropping the previous arm) cancels cleanly — the
/// superseded wait simply completes its remaining ms in the pool.
#[cfg(windows)]
mod cover_clock {
    use std::ffi::{c_int, c_void};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use tokio::task::JoinHandle;

    /// Waitable timer flag: use the high-resolution timer (no dependence on
    /// the system timer resolution).
    const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x0000_0002;
    const TIMER_ALL_ACCESS: u32 = 0x001F_0003;
    const INFINITE: u32 = 0xFFFF_FFFF;
    /// Seconds from the Windows FILETIME epoch (1601-01-01) to the Unix
    /// epoch (1970-01-01); FILETIME is 100 ns ticks since 1601.
    const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

    unsafe extern "system" {
        fn CreateWaitableTimerExW(
            lpTimerAttributes: *mut c_void,
            lpTimerName: *const u16,
            dwFlags: u32,
            dwDesiredAccess: u32,
        ) -> *mut c_void;
        fn SetWaitableTimer(
            hTimer: *mut c_void,
            lpDueTime: *const i64,
            lPeriod: c_int,
            pfnCompletionRoutine: *mut c_void,
            lpArgToCompletionRoutine: *mut c_void,
            fResume: c_int,
        ) -> c_int;
        fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
        fn CloseHandle(hObject: *mut c_void) -> c_int;
    }

    /// A re-armable cover-clock arm (see `cover_sleep`).
    pub struct CoverSleep {
        inner: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    }

    impl CoverSleep {
        /// Wait until the absolute `target` deadline.
        pub fn deadline(target: Instant) -> Self {
            let wait: JoinHandle<()> = tokio::task::spawn_blocking(move || wait_until(target));
            Self {
                inner: Box::pin(async move {
                    let _ = wait.await;
                }),
            }
        }

        /// Never fire (no cover scheduled).
        pub fn inert() -> Self {
            Self {
                inner: Box::pin(tokio::time::sleep(Duration::MAX)),
            }
        }
    }

    impl Future for CoverSleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.get_mut().inner.as_mut().poll(cx)
        }
    }

    fn wait_until(target: Instant) {
        let remaining = target.saturating_duration_since(Instant::now());
        let timer = unsafe {
            CreateWaitableTimerExW(
                std::ptr::null_mut(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            )
        };
        if timer.is_null() {
            // Unreachable on supported Windows; a plain sleep is the honest
            // fallback (degraded to system resolution, like pre-M9A).
            std::thread::sleep(remaining);
            return;
        }
        let due = due_time(remaining);
        let armed = unsafe {
            SetWaitableTimer(
                timer,
                &due,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } != 0;
        if !armed {
            unsafe { CloseHandle(timer) };
            std::thread::sleep(remaining);
            return;
        }
        unsafe {
            WaitForSingleObject(timer, INFINITE);
            CloseHandle(timer);
        }
    }

    /// Absolute FILETIME (100 ns ticks since 1601) for a wall-clock moment
    /// `remaining` from now — absolute due times keep the grid locked to the
    /// scheduler's deadlines rather than drifting with set latency.
    fn due_time(remaining: Duration) -> i64 {
        let unix = SystemTime::now() + remaining;
        let since_epoch = unix.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        let ticks = (since_epoch.as_secs().saturating_add(FILETIME_UNIX_OFFSET)) * 10_000_000
            + u64::from(since_epoch.subsec_nanos()) / 100;
        ticks as i64
    }
}

/// Re-establish: start a fresh handshake (fresh sid, D16) after a close.
async fn rearm_client<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ClientSessionManager,
) -> Result<(), ManagerError> {
    if let ManagerEvent::Send { packets, peer } = manager.begin_handshake()? {
        for p in &packets {
            transport.send_to(p, peer).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
// Tests intentionally mutate `SessionLimits` fields after `Default::default()`.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::codec::{Direction, MAX_PACKET_NONCE, PACKET_SIZE, PacketHeader};
    use crate::handshake_v2::tests::{
        CLIENT_ADDR, OTHER_ADDR, SERVER_ADDR, test_configs, wired_transports,
    };
    use crate::handshake_v2::{ClientHandshake, M1_FRAG_COUNT, M2_FRAG_COUNT, M3_FRAG_COUNT};
    use pq_crypto::aead::{AeadKey, AeadNonce, encrypt as aead_encrypt};
    use pq_crypto::kdf::{
        build_session_nonce, derive_client_to_server_key, derive_nonce_prefix_c2s,
        derive_nonce_prefix_s2c, derive_server_to_client_key,
    };
    use std::net::Ipv4Addr;

    const SID: [u8; SESSION_ID_LEN] = [0x42; SESSION_ID_LEN];

    /// Deterministic driver tests: cover disabled so per-packet expectations
    /// (event flows, exact `recv`s) are unaffected by periodic emissions.  The
    /// cover cadence itself is exercised by the e2e gate.
    fn no_cover() -> CoverPolicy {
        CoverPolicy {
            enabled: false,
            interval: CoverPolicy::default().interval,
        }
    }

    /// One identity pair shared by every test: the server manager's roster
    /// must contain the client key used in each test's handshake.
    fn shared_configs() -> (ClientConfig, ServerConfig) {
        use std::sync::OnceLock;
        static SHARED: OnceLock<(ClientConfig, ServerConfig)> = OnceLock::new();
        SHARED.get_or_init(test_configs).clone()
    }

    fn server_manager(limits: SessionLimits) -> ServerSessionManager {
        let (_, sc) = shared_configs();
        ServerSessionManager::new(&sc, limits).expect("manager")
    }

    /// Drive the client machine to completion; returns its session + outcome.
    fn client_established(
        client: &mut ClientHandshake,
        cc: &ClientConfig,
    ) -> (WireSession, HandshakeOutcome) {
        for _ in 0..=cc.m3_max_attempts {
            if let ClientEvent::Complete(out) = client.on_timer().expect("cli") {
                let ws = WireSession::established(Role::Client, &out).expect("ws");
                return (ws, out);
            }
        }
        panic!("client machine never completed");
    }

    /// Run a full exchange through the server manager: returns the client
    /// machine (in M3Sent) and the server's `Established` event.
    fn server_established(
        manager: &mut ServerSessionManager,
        cc: &ClientConfig,
        sid: [u8; SESSION_ID_LEN],
        from: SocketAddr,
    ) -> ClientHandshake {
        let mut client = ClientHandshake::new(cc, sid).expect("client");
        let mut m2 = Vec::new();
        for f in client.m1_frags() {
            if let ManagerEvent::Send { packets, peer } =
                manager.handle_datagram(f, from).expect("srv")
            {
                assert_eq!(peer, from, "M2 goes back to the source");
                m2 = packets;
            }
        }
        assert_eq!(m2.len(), M2_FRAG_COUNT as usize, "full M2 emitted");
        let mut m3 = Vec::new();
        for f in &m2 {
            if let ClientEvent::Emit(packets) = client.handle_datagram(f).expect("cli") {
                m3 = packets;
            }
        }
        assert_eq!(m3.len(), M3_FRAG_COUNT as usize, "client emits M3 once");
        let mut established = false;
        for f in &m3 {
            if let ManagerEvent::Established { sid: es, peer: ep } =
                manager.handle_datagram(f, from).expect("srv")
            {
                assert_eq!(es, sid);
                assert_eq!(ep, from);
                established = true;
            }
        }
        assert!(established, "server must establish at M3");
        client
    }

    /// Establish a session and return a usable client-side session.
    fn established_client_session(
        manager: &mut ServerSessionManager,
        cc: &ClientConfig,
        sid: [u8; SESSION_ID_LEN],
    ) -> (ClientHandshake, WireSession) {
        let mut client = server_established(manager, cc, sid, CLIENT_ADDR);
        let (ws, _out) = client_established(&mut client, cc);
        (client, ws)
    }

    /// An authentic packet at the exhaustion threshold (c2s direction), built
    /// directly with the public KDF + AEAD primitives (wire_session.rs
    /// pattern).  The sender never emits this; the receiver MUST trigger rekey.
    fn exhaustion_packet_c2s(master: &MasterSecret, sid: [u8; SESSION_ID_LEN]) -> WirePacket {
        let key = derive_client_to_server_key(master, &sid).unwrap();
        let prefix = derive_nonce_prefix_c2s(master, &sid).unwrap();
        let inner = InnerPlaintext::new(
            MessageType::Data,
            Direction::ClientToServer,
            &[0u8; PAYLOAD_LEN],
        )
        .unwrap();
        let header = PacketHeader::new(sid, MAX_PACKET_NONCE);
        let aad = header.encode();
        let nonce = AeadNonce::from_bytes(build_session_nonce(&prefix, MAX_PACKET_NONCE));
        let ct = aead_encrypt(&AeadKey::from_bytes(key), &nonce, &inner.encode(), &aad).unwrap();
        WirePacket::from_parts(&aad, &ct).unwrap()
    }

    fn exhaustion_packet_s2c(master: &MasterSecret, sid: [u8; SESSION_ID_LEN]) -> WirePacket {
        let key = derive_server_to_client_key(master, &sid).unwrap();
        let prefix = derive_nonce_prefix_s2c(master, &sid).unwrap();
        let inner = InnerPlaintext::new(
            MessageType::Data,
            Direction::ServerToClient,
            &[0u8; PAYLOAD_LEN],
        )
        .unwrap();
        let header = PacketHeader::new(sid, MAX_PACKET_NONCE);
        let aad = header.encode();
        let nonce = AeadNonce::from_bytes(build_session_nonce(&prefix, MAX_PACKET_NONCE));
        let ct = aead_encrypt(&AeadKey::from_bytes(key), &nonce, &inner.encode(), &aad).unwrap();
        WirePacket::from_parts(&aad, &ct).unwrap()
    }

    fn tampered(pkt: &WirePacket) -> WirePacket {
        let mut bytes = *pkt.as_bytes();
        bytes[PACKET_SIZE - 1] ^= 0x01;
        WirePacket::from_bytes(&bytes).expect("fixed-size")
    }

    use pq_crypto::kdf::MasterSecret;

    // -----------------------------------------------------------------------
    // Server manager
    // -----------------------------------------------------------------------

    #[test]
    fn server_handshake_establishes_session() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let mut client = server_established(&mut manager, &cc, SID, CLIENT_ADDR);
        assert_eq!(manager.session_count(), 1);
        assert_eq!(manager.pending_handshakes(), 0);
        let (mut ws, _) = client_established(&mut client, &cc);
        let pkt = ws.encrypt(MessageType::Data, &[0x11; PAYLOAD_LEN]).unwrap();
        match manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap() {
            ManagerEvent::AppData { sid, inner } => {
                assert_eq!(sid, SID);
                assert_eq!(inner.msg_type, MessageType::Data);
                assert_eq!(&inner.payload[..], &[0x11; PAYLOAD_LEN][..]);
            }
            other => panic!("expected AppData, got {other:?}"),
        }
    }

    #[test]
    fn server_app_outbound_roundtrip() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // Short payloads are zero-padded to the fixed slot.
        let ev = manager.app_outbound(&SID, &[0x33u8; 32]).unwrap();
        let (packet, peer) = match ev {
            ManagerEvent::SendPacket { packet, peer } => (packet, peer),
            other => panic!("expected SendPacket, got {other:?}"),
        };
        assert_eq!(peer, CLIENT_ADDR);
        let inner = ws.decrypt(&packet).unwrap();
        assert_eq!(inner.msg_type, MessageType::Data);
        assert_eq!(&inner.payload[..32], &[0x33u8; 32][..]);
        assert_eq!(&inner.payload[32..], &[0u8; PAYLOAD_LEN - 32][..]);

        // The client's reply decrypts on the manager side.
        let reply = ws.encrypt(MessageType::Data, &[0x77; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&reply, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        // The replay of the identical packet is rejected silently.
        assert!(matches!(
            manager.handle_datagram(&reply, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn server_unknown_sid_silent() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        let mut bytes = *pkt.as_bytes();
        bytes[1] ^= 0xFF; // different sid (keys no longer match → AEAD fail)
        let foreign = WirePacket::from_bytes(&bytes).unwrap();
        assert!(matches!(
            manager.handle_datagram(&foreign, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn server_tampered_data_gate_blocks_by_source() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 64;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        // Exhaust the source's failure budget with tampered packets.
        for _ in 0..64 {
            assert!(matches!(
                manager
                    .handle_datagram(&tampered(&pkt), CLIENT_ADDR)
                    .unwrap(),
                ManagerEvent::None
            ));
        }
        // Gate closed: even a VALID packet from that source is dropped without
        // decrypt work.
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        // A different source has its own budget: the packet decrypts and the
        // session roams to it (§10).
        match manager.handle_datagram(&pkt, OTHER_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("expected AppData, got {other:?}"),
        }
        // The roam rebinds the reply path.
        match manager.app_outbound(&SID, &[0u8; 8]).unwrap() {
            ManagerEvent::SendPacket { peer, .. } => assert_eq!(peer, OTHER_ADDR),
            other => panic!("expected SendPacket, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn server_fail_gate_table_is_capped() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 4;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);
        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();

        for i in 0..16u16 {
            let from: SocketAddr = format!("127.0.0.1:{}", 41000 + i).parse().unwrap();
            let _ = manager.handle_datagram(&tampered(&pkt), from);
            assert!(
                manager.fail_bucket_count() <= 4,
                "bucket table must stay capped"
            );
        }
    }

    #[test]
    fn server_sid_collision_keeps_existing() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // A second valid handshake from another source reusing the same sid
        // must not displace the existing session.
        let mut attacker = ClientHandshake::new(&cc, SID).expect("client");
        let mut m2 = Vec::new();
        for f in attacker.m1_frags() {
            if let ManagerEvent::Send { packets, .. } =
                manager.handle_datagram(f, OTHER_ADDR).expect("srv")
            {
                m2 = packets;
            }
        }
        let mut m3 = Vec::new();
        for f in &m2 {
            if let ClientEvent::Emit(packets) = attacker.handle_datagram(f).expect("cli") {
                m3 = packets;
            }
        }
        let mut displaced = false;
        for f in &m3 {
            if let ManagerEvent::Established { .. } =
                manager.handle_datagram(f, OTHER_ADDR).expect("srv")
            {
                displaced = true;
            }
        }
        assert!(!displaced, "colliding handshake must be dropped silently");
        assert_eq!(manager.session_count(), 1);

        // The original session still works.
        let pkt = ws.encrypt(MessageType::Data, &[0x5A; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
    }

    #[test]
    fn server_capacity_evicts_least_recent() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_sessions = 1;
        let mut manager = server_manager(limits);

        let (_client_a, _) = established_client_session(&mut manager, &cc, SID);
        assert_eq!(manager.session_count(), 1);

        // Second session evicts the first (LRU); its Closed is queued.
        let sid_b = [0x99; SESSION_ID_LEN];
        let (_, mut ws_b) = established_client_session(&mut manager, &cc, sid_b);
        assert_eq!(manager.session_count(), 1);
        let pkt = ws_b
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));

        // The eviction notification arrives on the next tick.
        let events = manager.tick(Instant::now());
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(*sid, SID);
                assert_eq!(*reason, CloseReason::Capacity);
            }
            other => panic!("expected Closed{{Capacity}}, got {other:?}"),
        }
    }

    #[test]
    fn server_idle_eviction_and_activity_refresh() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.idle_timeout = Some(Duration::from_secs(3600));
        limits.lifetime_cap = None;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // Activity within the window keeps the session alive.
        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert!(
            manager
                .tick(Instant::now() + Duration::from_secs(30 * 60))
                .is_empty(),
            "recent activity must not be evicted"
        );
        assert_eq!(manager.session_count(), 1);

        // Idle past the timeout evicts.
        let events = manager.tick(Instant::now() + Duration::from_secs(2 * 3600));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(*sid, SID);
                assert_eq!(*reason, CloseReason::IdleTimeout);
            }
            other => panic!("expected Closed{{IdleTimeout}}, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn server_lifetime_cap_precedes_idle() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.idle_timeout = Some(Duration::from_secs(2 * 3600));
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let mut manager = server_manager(limits);
        established_client_session(&mut manager, &cc, SID);

        let events = manager.tick(Instant::now() + Duration::from_secs(90 * 60));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { reason, .. } => {
                assert_eq!(*reason, CloseReason::LifetimeCap);
            }
            other => panic!("expected Closed{{LifetimeCap}}, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn server_nonce_exhaustion_closes_session() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (mut client, _ws) = established_client_session(&mut manager, &cc, SID);
        let (_, outcome) = client_established(&mut client, &cc);

        let pkt = exhaustion_packet_c2s(&outcome.master, outcome.session_id);
        match manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap() {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(sid, outcome.session_id);
                assert_eq!(reason, CloseReason::NonceExhausted);
            }
            other => panic!("expected Closed{{NonceExhausted}}, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn server_close_message_closes_session() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        let pkt = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
        match manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap() {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(sid, SID);
                assert_eq!(reason, CloseReason::PeerClosed);
            }
            other => panic!("expected Closed{{PeerClosed}}, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn server_cover_packet_consumed_silently() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        let pkt = ws.cover().unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(
            manager.session_count(),
            1,
            "cover must not disturb the session"
        );

        // The session still delivers data afterwards.
        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
    }

    #[test]
    fn server_cover_packet_hook_emits() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        match manager.cover_packet(&SID).unwrap() {
            ManagerEvent::SendPacket { packet, peer } => {
                assert_eq!(peer, CLIENT_ADDR);
                let inner = ws.decrypt(&packet).unwrap();
                assert_eq!(inner.msg_type, MessageType::Cover);
            }
            other => panic!("expected SendPacket, got {other:?}"),
        }
    }

    #[test]
    fn server_app_outbound_unknown_sid() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        established_client_session(&mut manager, &cc, SID);

        assert!(matches!(
            manager.app_outbound(&[0xEE; SESSION_ID_LEN], &[0u8; 8]),
            Err(ManagerError::NoSession)
        ));
        assert!(matches!(
            manager.close_session(&[0xEE; SESSION_ID_LEN]),
            Err(ManagerError::NoSession)
        ));
    }

    #[test]
    fn server_close_session_app_driven() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        established_client_session(&mut manager, &cc, SID);

        match manager.close_session(&SID).unwrap() {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(sid, SID);
                assert_eq!(reason, CloseReason::UserClosed);
            }
            other => panic!("expected Closed{{UserClosed}}, got {other:?}"),
        }
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn server_garbage_dispatch_no_state_change() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        established_client_session(&mut manager, &cc, SID);

        // Handshake-typed garbage (byte 9 = 0x10/0x30) and data-typed junk.
        for hs_type in [0x10u8, 0x30] {
            let mut dg = [0u8; PACKET_SIZE];
            dg[0] = crate::codec::PROTOCOL_VERSION;
            dg[9] = hs_type;
            let pkt = WirePacket::from_bytes(&dg).unwrap();
            assert!(matches!(
                manager.handle_datagram(&pkt, OTHER_ADDR).unwrap(),
                ManagerEvent::None
            ));
        }
        assert_eq!(manager.session_count(), 1);
        assert_eq!(manager.pending_handshakes(), 0);
    }

    #[test]
    fn server_duplicate_m3_after_established_harmless() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let client = server_established(&mut manager, &cc, SID, CLIENT_ADDR);

        // Re-run the M3 fragments; the machine's pending entry is gone and
        // the retransmit is a silent no-op.
        for f in client.m3_frags() {
            assert!(matches!(
                manager.handle_datagram(f, CLIENT_ADDR).unwrap(),
                ManagerEvent::None
            ));
        }
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn server_new_handshake_during_established_session() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // A fresh handshake from the same source with a NEW sid coexists with
        // the established session (handshake + data paths are disjoint).
        let sid2 = [0x77; SESSION_ID_LEN];
        let (client2, _) = established_client_session(&mut manager, &cc, sid2);
        assert_eq!(manager.session_count(), 2);
        let _ = client2;
        let pkt = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Client manager
    // -----------------------------------------------------------------------

    fn client_manager() -> ClientSessionManager {
        let (cc, _sc) = shared_configs();
        ClientSessionManager::new(&cc, SessionLimits::default()).expect("manager")
    }

    /// A server machine configured for the client's pinned identity.
    fn server_machine() -> ServerHandshake {
        let (_cc, sc) = shared_configs();
        ServerHandshake::new(&sc)
    }

    /// Drive the client manager through a full handshake against a server
    /// machine; returns the (server-side) session.
    fn client_handshake_with_server(
        manager: &mut ClientSessionManager,
        server: &mut ServerHandshake,
        from: SocketAddr,
    ) -> (WireSession, HandshakeOutcome) {
        // M1 → server machine → M2 → client manager → M3 → server Complete.
        let m1 = match manager.begin_handshake().unwrap() {
            ManagerEvent::Send { packets, peer } => {
                assert_eq!(peer, SERVER_ADDR);
                packets
            }
            other => panic!("expected Send(M1), got {other:?}"),
        };
        assert_eq!(m1.len(), M1_FRAG_COUNT as usize);
        let mut m2 = Vec::new();
        for f in &m1 {
            if let ServerEvent::Emit(frags, peer) = server.handle_datagram(f, from).unwrap() {
                assert_eq!(peer, from);
                m2 = frags;
            }
        }
        assert_eq!(m2.len(), M2_FRAG_COUNT as usize);
        let mut m3 = Vec::new();
        for f in &m2 {
            if let ManagerEvent::Send { packets, .. } =
                manager.handle_datagram(f, from).expect("cli")
            {
                m3 = packets;
            }
        }
        assert_eq!(m3.len(), M3_FRAG_COUNT as usize);
        let mut outcome = None;
        for f in &m3 {
            if let ServerEvent::Complete(out) = server.handle_datagram(f, from).unwrap() {
                outcome = Some(out);
            }
        }
        let outcome = outcome.expect("server completes at M3");
        // The client reaches Established via its retransmit timer once the M3
        // budget is exhausted (1 RTT; the server has the same keys by then).
        let budget = {
            let (cc, _sc) = shared_configs();
            cc.m3_max_attempts
        };
        for _ in 0..=budget {
            if matches!(manager.state(), ClientManagerState::Established) {
                break;
            }
            match manager.on_timer().expect("cli") {
                ManagerEvent::Send { packets, .. } => {
                    let _ = packets; // M3 retransmits: ignored by the test
                }
                ManagerEvent::None => {}
                other => panic!("unexpected {other:?} while advancing the timer"),
            }
        }
        assert!(matches!(manager.state(), ClientManagerState::Established));
        assert!(
            !manager.is_ready(),
            "D15: gate closed until first server packet"
        );
        (
            WireSession::established(Role::Server, &outcome).expect("srv session"),
            outcome,
        )
    }

    #[test]
    fn client_full_lifecycle() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        let sid = manager.session_id().expect("session");

        // D15 gate opens on the first authenticated server packet.
        let pkt = srv_ws
            .encrypt(MessageType::Data, &[0x21; PAYLOAD_LEN])
            .unwrap();
        match manager.handle_datagram(&pkt, SERVER_ADDR).unwrap() {
            ManagerEvent::AppData { sid: ds, inner } => {
                assert_eq!(ds, sid);
                assert_eq!(&inner.payload[..], &[0x21; PAYLOAD_LEN][..]);
            }
            other => panic!("expected AppData, got {other:?}"),
        }
        assert!(
            manager.is_ready(),
            "D15 gate must open on first auth packet"
        );

        // Outbound works (outbound is not gated — see module docs).
        let ev = manager.app_outbound(&[0x77; 16]).unwrap();
        match ev {
            ManagerEvent::SendPacket { packet, peer } => {
                assert_eq!(peer, SERVER_ADDR);
                let inner = srv_ws.decrypt(&packet).unwrap();
                assert_eq!(&inner.payload[..16], &[0x77; 16][..]);
            }
            other => panic!("expected SendPacket, got {other:?}"),
        }

        // App data continues flowing.
        let pkt = srv_ws
            .encrypt(MessageType::Data, &[0x22; PAYLOAD_LEN])
            .unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, SERVER_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        let _ = srv_ws;
        let mut _srv_ws2 = srv_ws;
    }

    #[test]
    fn client_d15_outbound_works_before_confirmation() {
        // The D15 reading: outbound is not gated (a request must be able to
        // elicit the confirming reply); the gate protects DELIVERY and is
        // backed by the liveness timeout.
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        assert!(!manager.is_ready());

        let ev = manager.app_outbound(&[0x99; 8]).unwrap();
        match ev {
            ManagerEvent::SendPacket { packet, .. } => {
                let inner = srv_ws.decrypt(&packet).unwrap();
                assert_eq!(&inner.payload[..8], &[0x99; 8][..]);
            }
            other => panic!("expected SendPacket, got {other:?}"),
        }
        assert!(!manager.is_ready(), "send does not open the D15 gate");
        let _ = srv_ws;
    }

    #[test]
    fn client_liveness_timeout_closes_miskeyed_session() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (_srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        let sid = manager.session_id().expect("session");

        // No authenticated server packet ever arrives (mis-keyed / dead).
        let events = manager.tick(Instant::now() + Duration::from_secs(31));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(*cs, sid);
                assert_eq!(*reason, CloseReason::NotConfirmed);
            }
            other => panic!("expected Closed{{NotConfirmed}}, got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
        assert!(!manager.is_ready());

        // Re-establishment works with a FRESH sid (D16).
        match manager.begin_handshake().unwrap() {
            ManagerEvent::Send { packets, peer } => {
                assert_eq!(peer, SERVER_ADDR);
                let fresh: [u8; SESSION_ID_LEN] = packets[0].as_bytes()[1..9].try_into().unwrap();
                assert_ne!(fresh, sid, "re-establishment must use a fresh sid");
            }
            other => panic!("expected Send(M1), got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Handshaking));
    }

    #[test]
    fn client_nonce_exhaustion_closes_session() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (srv_ws, outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        let sid = manager.session_id().expect("session");

        // The sender (server) never emits a packet at the exhaustion
        // threshold; forge one with the real derived keys (D16: the receiver
        // MUST trigger rekey).
        let _ = srv_ws;
        let pkt = exhaustion_packet_s2c(&outcome.master, outcome.session_id);
        match manager.handle_datagram(&pkt, SERVER_ADDR).unwrap() {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(cs, sid);
                assert_eq!(reason, CloseReason::NonceExhausted);
            }
            other => panic!("expected Closed{{NonceExhausted}}, got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
        assert!(!manager.is_ready());
    }

    #[test]
    fn client_peer_close_closes_session() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        let sid = manager.session_id().expect("session");

        let pkt = srv_ws
            .encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN])
            .unwrap();
        match manager.handle_datagram(&pkt, SERVER_ADDR).unwrap() {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(cs, sid);
                assert_eq!(reason, CloseReason::PeerClosed);
            }
            other => panic!("expected Closed{{PeerClosed}}, got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
    }

    #[test]
    fn client_handshake_timeout_m1_budget() {
        let (cc, _sc) = shared_configs();
        let mut cc = cc;
        cc.m1_max_attempts = 0; // first timer tick fails immediately
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        manager.begin_handshake().unwrap();
        let sid = *manager.hs.as_ref().expect("hs").session_id();

        match manager.on_timer().unwrap() {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(cs, sid);
                assert_eq!(reason, CloseReason::HandshakeTimeout);
            }
            other => panic!("expected Closed{{HandshakeTimeout}}, got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
    }

    #[test]
    fn client_handshake_overall_deadline() {
        let mut manager = client_manager();
        manager.begin_handshake().unwrap();
        let sid = *manager.hs.as_ref().expect("hs").session_id();

        let events = manager.tick(Instant::now() + Duration::from_secs(31));
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(*cs, sid);
                assert_eq!(*reason, CloseReason::HandshakeTimeout);
            }
            other => panic!("expected Closed{{HandshakeTimeout}}, got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
    }

    #[test]
    fn client_lifetime_cap_closes_established() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);

        // Confirm the session first (opens the D15 gate).
        let pkt = srv_ws
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let _ = manager.handle_datagram(&pkt, SERVER_ADDR).unwrap();
        assert!(manager.is_ready());

        let sid = manager.session_id().unwrap();
        let events = manager.tick(Instant::now() + Duration::from_secs(31));
        // NotConfirmed does not fire (ready); the lifetime cap (None by
        // default) does not fire either — nothing to evict.
        assert!(events.is_empty());
        let _ = sid;
    }

    #[test]
    fn client_roaming_rebind() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);

        // The server's first data arrives from a NEW address: it authenticates
        // and rebinds the reply path (§10).
        let pkt = srv_ws
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, OTHER_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert!(manager.is_ready());
        match manager.app_outbound(&[0u8; 8]).unwrap() {
            ManagerEvent::SendPacket { peer, .. } => assert_eq!(peer, OTHER_ADDR),
            other => panic!("expected SendPacket, got {other:?}"),
        }
    }

    #[test]
    fn client_cover_roundtrip() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);

        let ev = manager.cover_packet().unwrap();
        match ev {
            ManagerEvent::SendPacket { packet, peer } => {
                assert_eq!(peer, SERVER_ADDR);
                let inner = srv_ws.decrypt(&packet).unwrap();
                assert_eq!(inner.msg_type, MessageType::Cover);
            }
            other => panic!("expected SendPacket, got {other:?}"),
        }

        // A cover packet from the server opens the D15 gate without data.
        let pkt = srv_ws.cover().unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, SERVER_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert!(
            manager.is_ready(),
            "any authenticated packet confirms liveness"
        );
    }

    // Regression (M6): the client's M3 retransmit budget (the only path to
    // `Established`, since a passive server sends no M4) must complete
    // strictly inside the session manager's default handshake deadline.  With
    // the earlier 8-attempt default the worst case was ~38s against a 30s
    // deadline, so a default-configured client could never establish — the
    // manager always closed it as HandshakeTimeout first.
    #[test]
    fn default_client_m3_budget_fits_handshake_deadline() {
        let (cc, _sc) = shared_configs();
        let deadline = SessionLimits::default()
            .handshake_timeout
            .expect("default handshake deadline");
        let base_ms = cc.m1_retransmit_base.as_millis();
        // Worst-case M3 phase wall time: the initial delay plus one backoff
        // delay per retransmit (×2^min(attempt,5)), each with the maximum
        // ±20% jitter.
        let mut mult = 1u128;
        for a in 1..=cc.m3_max_attempts {
            mult += 1u128 << a.min(5);
        }
        let worst_ms = (mult * base_ms * 120) / 100;
        assert!(
            Duration::from_millis(worst_ms as u64) < deadline,
            "default M3 budget (≥{worst_ms}ms worst case) must fit the default \
             handshake deadline ({deadline:?})"
        );
    }

    #[test]
    fn client_close_sends_close_message() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);

        let ev = manager.close().unwrap();
        match ev {
            ManagerEvent::SendPacket { packet, .. } => {
                let inner = srv_ws.decrypt(&packet).unwrap();
                assert_eq!(inner.msg_type, MessageType::Close);
            }
            other => panic!("expected SendPacket(Close), got {other:?}"),
        }
        assert!(matches!(manager.state(), ClientManagerState::Idle));
        // The UserClosed notification is queued for the next tick.
        let events = manager.tick(Instant::now());
        assert_eq!(events.len(), 1);
        match &events[0] {
            ManagerEvent::Closed { reason, .. } => {
                assert_eq!(*reason, CloseReason::UserClosed);
            }
            other => panic!("expected Closed{{UserClosed}}, got {other:?}"),
        }
    }

    #[test]
    fn client_garbage_ignored() {
        let mut manager = client_manager();
        let mut server = server_machine();
        let (mut srv_ws, _outcome) =
            client_handshake_with_server(&mut manager, &mut server, SERVER_ADDR);
        let sid = manager.session_id().unwrap();

        // Junk and foreign data fail silently; the session survives.
        let mut dg = [0u8; PACKET_SIZE];
        dg[0] = crate::codec::PROTOCOL_VERSION;
        let junk = WirePacket::from_bytes(&dg).unwrap();
        assert!(matches!(
            manager.handle_datagram(&junk, SERVER_ADDR).unwrap(),
            ManagerEvent::None
        ));
        let mut forged = srv_ws
            .encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN])
            .unwrap();
        let mut bytes = *forged.as_bytes();
        bytes[PACKET_SIZE - 1] ^= 0x01;
        forged = WirePacket::from_bytes(&bytes).unwrap();
        assert!(matches!(
            manager.handle_datagram(&forged, SERVER_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert!(matches!(manager.state(), ClientManagerState::Established));
        let _ = sid;
    }

    #[test]
    fn client_begin_handshake_invalid_state() {
        let mut manager = client_manager();
        manager.begin_handshake().unwrap();
        assert!(matches!(
            manager.begin_handshake(),
            Err(ManagerError::InvalidState(_))
        ));
        // Closing the attempt allows a restart.
        manager.hs = None;
        assert!(matches!(manager.state(), ClientManagerState::Idle));
        assert!(matches!(
            manager.begin_handshake(),
            Ok(ManagerEvent::Send { .. })
        ));
    }

    #[test]
    fn managers_fail_closed_on_bad_config() {
        let (cc, sc) = shared_configs();
        let mut bad = sc.clone();
        bad.roster.clear();
        assert!(matches!(
            ServerSessionManager::new(&bad, SessionLimits::default()),
            Err(ManagerError::InvalidConfig(_))
        ));
        let mut bad_c = cc.clone();
        bad_c.version = 0xFF;
        assert!(matches!(
            ClientSessionManager::new(&bad_c, SessionLimits::default()),
            Err(ManagerError::InvalidConfig(_))
        ));
        assert!(ServerSessionManager::new(&sc, SessionLimits::default()).is_ok());
    }

    // -----------------------------------------------------------------------
    // Drivers (over the in-memory transports)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn server_driver_end_to_end() {
        let (cc, sc) = shared_configs();
        let mut manager = ServerSessionManager::new(&sc, SessionLimits::default()).unwrap();
        let (mut client_t, mut server_t, _guard) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let driver = tokio::spawn(async move {
            run_server_manager(&mut server_t, &mut manager, app_tx, cmd_rx, no_cover()).await
        });

        // Handshake through the driver.
        let sid = [0x42; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).unwrap();
        for f in client.m1_frags() {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        let mut m3 = Vec::new();
        for _ in 0..M2_FRAG_COUNT {
            let (pkt, from) = client_t.recv().await.unwrap();
            assert_eq!(from, SERVER_ADDR);
            if let ClientEvent::Emit(pkts) = client.handle_datagram(&pkt).unwrap() {
                m3 = pkts;
            }
        }
        for f in &m3 {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }

        // Established notification reaches the app channel.
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Established { sid: es, peer } => {
                assert_eq!(es, sid);
                assert_eq!(peer, CLIENT_ADDR);
            }
            other => panic!("expected Established, got {other:?}"),
        }

        // Client → server data reaches the app channel.
        let (mut cws, _out) = client_established(&mut client, &cc);
        let pkt = cws
            .encrypt(MessageType::Data, &[0x5A; PAYLOAD_LEN])
            .unwrap();
        client_t.send_to(&pkt, SERVER_ADDR).await.unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Data { sid: ds, inner } => {
                assert_eq!(ds, sid);
                assert_eq!(inner.msg_type, MessageType::Data);
                assert_eq!(&inner.payload[..], &[0x5A; PAYLOAD_LEN][..]);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // Server → client data via the app command channel.
        cmd_tx
            .send(ServerAppCommand {
                sid,
                payload: vec![0x33; 32],
            })
            .await
            .unwrap();
        let (pkt, from) = client_t.recv().await.unwrap();
        assert_eq!(from, SERVER_ADDR);
        let inner = cws.decrypt(&pkt).unwrap();
        assert_eq!(&inner.payload[..32], &[0x33; 32][..]);

        // Closing the command channel ends the driver cleanly.
        drop(cmd_tx);
        assert!(driver.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn client_driver_end_to_end() {
        let (mut cc, sc) = shared_configs();
        // Fast retransmits so the M3 budget (1 RTT) exhausts in milliseconds;
        // the client only reaches Established when its timer completes.
        cc.m1_retransmit_base = Duration::from_millis(50);
        cc.m3_max_attempts = 1;
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        let (mut client_t, mut server_t, srv_tx) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (data_tx, data_rx) = mpsc::channel(64);
        let driver = tokio::spawn(async move {
            run_client_manager(&mut client_t, &mut manager, app_tx, data_rx, no_cover()).await
        });

        // The driver auto-connects: M1 arrives at the server machine.
        let mut server = ServerHandshake::new(&sc);
        let mut m2 = Vec::new();
        for _ in 0..M1_FRAG_COUNT {
            let (pkt, from) = server_t.recv().await.unwrap();
            assert_eq!(from, CLIENT_ADDR);
            if let ServerEvent::Emit(frags, peer) = server.handle_datagram(&pkt, from).unwrap() {
                assert_eq!(peer, CLIENT_ADDR);
                m2 = frags;
            }
        }
        assert_eq!(m2.len(), M2_FRAG_COUNT as usize);
        for f in &m2 {
            srv_tx.send((f.clone(), SERVER_ADDR)).unwrap();
        }

        // M3: the client emits it once on M2, then once more from its
        // retransmit timer (m3_max_attempts = 1), then completes.
        let mut server_outcome = None;
        for _ in 0..M3_FRAG_COUNT * 2 {
            let (pkt, from) = server_t.recv().await.unwrap();
            assert_eq!(from, CLIENT_ADDR);
            if let ServerEvent::Complete(out) = server.handle_datagram(&pkt, from).unwrap() {
                server_outcome = Some(out);
            }
        }
        let outcome = server_outcome.expect("server completes");
        let mut srv_ws = WireSession::established(Role::Server, &outcome).unwrap();
        // Give the client's retransmit timer time to exhaust and reach
        // Established (last backoff ≈ 200ms; the grace below covers jitter).
        tokio::time::sleep(Duration::from_millis(350)).await;

        // Server cover packet opens the D15 gate → Ready notification.
        let cover = srv_ws.cover().unwrap();
        srv_tx.send((cover, SERVER_ADDR)).unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Ready { sid } => assert_eq!(sid, outcome.session_id),
            other => panic!("expected Ready, got {other:?}"),
        }

        // App data client → server.
        data_tx.send(vec![0x77; 64]).await.unwrap();
        let (pkt, from) = server_t.recv().await.unwrap();
        assert_eq!(from, CLIENT_ADDR);
        let inner = srv_ws.decrypt(&pkt).unwrap();
        assert_eq!(&inner.payload[..64], &[0x77; 64][..]);

        // Server → client data reaches the app channel.
        let reply = srv_ws
            .encrypt(MessageType::Data, &[0x22; PAYLOAD_LEN])
            .unwrap();
        srv_tx.send((reply, SERVER_ADDR)).unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Data { inner, .. } => {
                assert_eq!(inner.msg_type, MessageType::Data);
                assert_eq!(&inner.payload[..], &[0x22; PAYLOAD_LEN][..]);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // Closing the app channel ends the driver cleanly.
        drop(data_tx);
        assert!(driver.await.unwrap().is_ok());
    }

    // -----------------------------------------------------------------------
    // Core-validation adversarial / recovery tests (Phase 6 validation campaign)
    // -----------------------------------------------------------------------

    /// Regression for a recoverability defect: if the application pushes data
    /// *while the client is still handshaking* (or re-establishing after a
    /// close), `ClientSessionManager::app_outbound` legitimately has no session
    /// yet and returns `ManagerError::NoSession`. The driver MUST NOT terminate
    /// the tunnel on this local/state error — the session will be ready soon
    /// and the app must be able to retry. A driver that exits here is not
    /// recoverable under stress.
    #[tokio::test]
    async fn client_driver_app_data_during_handshake_does_not_kill_driver() {
        let (cc, _sc) = shared_configs();
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        let (mut client_t, _server_t, _srv_tx) = wired_transports();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
        let driver = tokio::spawn(async move {
            run_client_manager(&mut client_t, &mut manager, app_tx, data_rx, no_cover()).await
        });
        // Push app data immediately, while the client is Handshaking (no M2).
        data_tx.send(vec![0x77; 64]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The tunnel must stay up (recoverable); NoSession is a local condition.
        assert!(
            !driver.is_finished(),
            "client driver must survive app data pushed during handshake"
        );
        drop(data_tx);
        assert!(
            driver.await.unwrap().is_ok(),
            "driver must shut down cleanly"
        );
    }

    /// Same defect surface on the server: an app command addressed to an unknown
    /// sid (e.g. a stale sid after eviction) returns NoSession. The server driver
    /// must not terminate over a single mis-addressed command.
    #[tokio::test]
    async fn server_driver_app_data_unknown_sid_does_not_kill_driver() {
        let (_cc, sc) = shared_configs();
        let limits = SessionLimits::default();
        let mut manager = ServerSessionManager::new(&sc, limits).expect("mgr");
        let (mut server_t, _client_t, _srv_tx) = wired_transports();
        let (app_tx, _app_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel::<ServerAppCommand>(64);
        let driver = tokio::spawn(async move {
            run_server_manager(&mut server_t, &mut manager, app_tx, cmd_rx, no_cover()).await
        });
        // Command for a sid that no session knows.
        cmd_tx
            .send(ServerAppCommand {
                sid: [0xAA; SESSION_ID_LEN],
                payload: vec![0x77; 32],
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !driver.is_finished(),
            "server driver must survive an app command for an unknown sid"
        );
        drop(cmd_tx);
        assert!(
            driver.await.unwrap().is_ok(),
            "server driver must shut down cleanly"
        );
    }

    /// Phase 7 — Recovery: a source that has exhausted its data-path failure
    /// tokens must still allow a *different* source to communicate, and the
    /// gated source must recover after the token window refills.
    #[test]
    fn recovery_after_fail_gate_exhaustion() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();

        // Burn CLIENT_ADDR's failure budget entirely with tampered packets.
        for _ in 0..64 {
            assert!(matches!(
                manager
                    .handle_datagram(&tampered(&good), CLIENT_ADDR)
                    .unwrap(),
                ManagerEvent::None
            ));
        }
        // CLIENT_ADDR is now gated: even a VALID packet is dropped w/o decrypt.
        assert!(matches!(
            manager.handle_datagram(&good, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));

        // Recovery axis 1: a fresh source is unaffected and delivers.
        match manager.handle_datagram(&good, OTHER_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("other source must still deliver, got {other:?}"),
        }

        // Re-arm the client session so we can send from the recovered path.
        // (Rebuild a packet keyed to the session from the new peer.)
        let roamed = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        match manager.handle_datagram(&roamed, OTHER_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("roamed packet must deliver, got {other:?}"),
        }
    }

    /// Phase 7 — Recovery (D16): after nonce exhaustion closes a client session,
    /// the manager must re-arm a fresh handshake with a brand-new sid and be able
    /// to re-establish — i.e. the manager is not left stuck in a half-closed
    /// state.
    #[test]
    fn recovery_after_nonce_exhaustion_re_establishes() {
        let mut manager = client_manager();
        let mut server = server_machine();
        // Establish the client session (driver reaches Established via M3 budget;
        // the helper advances the client machine's timer to Complete).
        let (_ws, outcome) = client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
        let old_sid = manager.session_id().expect("established");
        assert_eq!(manager.state(), ClientManagerState::Established);
        assert!(!manager.is_ready()); // D15: no server packet seen yet

        // Forge a server→client packet at the nonce-exhaustion threshold, built
        // from the real shared master (wire_session.rs pattern). A legit packet
        // at this counter triggers rekey on the receiver.
        let pkt = exhaustion_packet_s2c(&outcome.master, outcome.session_id);
        match manager.handle_datagram(&pkt, SERVER_ADDR).unwrap() {
            ManagerEvent::Closed { sid, reason } => {
                assert_eq!(sid, old_sid);
                assert_eq!(reason, CloseReason::NonceExhausted);
            }
            other => panic!("expected Closed{{NonceExhausted}}, got {other:?}"),
        }
        // Session is gone; manager is Idle and can re-arm.
        assert_eq!(manager.state(), ClientManagerState::Idle);
        assert_eq!(manager.session_id(), None);
        assert_eq!(manager.handshake_sid(), None);

        let ev = manager.begin_handshake().unwrap();
        let new_sid = manager.handshake_sid().expect("handshake installed");
        assert!(matches!(ev, ManagerEvent::Send { peer, .. } if peer == SERVER_ADDR));
        assert_ne!(new_sid, old_sid, "rearm must use a fresh sid");
        assert_eq!(manager.state(), ClientManagerState::Handshaking);
    }

    /// Phase 1 — adversarial ordering: a byte-identical M2 arriving at an
    /// already-Established client must be a silent no-op (no re-establish, no
    /// sid mutation, no Ready transition).
    #[test]
    fn client_ignores_duplicate_m2_after_established() {
        let (cc, _sc) = shared_configs();
        let mut manager = client_manager();
        let mut server = server_machine();
        let (_ws, outcome) = client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
        let sid = outcome.session_id;

        // Build a fresh M2 (byte-identical format the client must also tolerate).
        let fresh = ClientHandshake::new(&cc, SID).expect("cli");
        let mut m2 = Vec::new();
        for f in fresh.m1_frags() {
            if let ServerEvent::Emit(p, _) = server.handle_datagram(f, CLIENT_ADDR).unwrap() {
                m2 = p;
            }
        }
        for f in &m2 {
            assert!(matches!(
                manager.handle_datagram(f, CLIENT_ADDR).unwrap(),
                ManagerEvent::None
            ));
        }
        // No state change.
        assert_eq!(manager.session_id(), Some(sid));
        assert_eq!(manager.state(), ClientManagerState::Established);
        assert!(!manager.is_ready());
        let _ = fresh; // keep the client machine around (exercise drop zeroization path)
    }

    // -----------------------------------------------------------------------
    // Phase 1: adversarial sequencing
    // -----------------------------------------------------------------------

    /// A peer-initiated `Close` tears the session down; a *late duplicate* of a
    /// previously-delivered data packet must NOT resurrect it (no sid reuse, no
    /// replay-window carryover across the remove).
    #[test]
    fn server_peer_close_then_late_data_does_not_resurrect() {
        let (cc, _sc) = shared_configs();
        let mut manager = server_manager(SessionLimits::default());
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        let one = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap(); // counter 0
        let close = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap(); // counter 1

        // Deliver one packet to seed the replay window, then peer Close.
        assert!(matches!(
            manager.handle_datagram(&one, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert!(matches!(
            manager.handle_datagram(&close, CLIENT_ADDR).unwrap(),
            ManagerEvent::Closed { sid, reason } if sid == SID && reason == CloseReason::PeerClosed
        ));
        assert_eq!(manager.session_count(), 0);

        // Late duplicate of the data packet: sid no longer exists -> silent drop.
        assert!(matches!(
            manager.handle_datagram(&one, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(
            manager.session_count(),
            0,
            "closed session must not resurrect"
        );
    }

    /// App-driven close on the client MUST emit a wire Close packet first, then
    /// transition locally (queued Closed drained on the next tick).
    #[test]
    fn client_close_emits_close_then_closes_session() {
        let (_cc, _sc) = shared_configs();
        let mut manager = client_manager();
        let mut server = server_machine();
        let (_ws, _outcome) = client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
        let sid = manager.session_id().expect("established");

        let ev = manager.close().unwrap();
        assert!(matches!(ev, ManagerEvent::SendPacket { peer, .. } if peer == SERVER_ADDR));
        // Locally the session is gone immediately (zeroizing drop), but the
        // Closed{UserClosed} notification is queued for tick().
        assert_eq!(manager.session_id(), None);
        assert_eq!(manager.state(), ClientManagerState::Idle);
        let drained = manager.tick(Instant::now());
        assert!(drained.iter().any(|e| matches!(
            e,
            ManagerEvent::Closed { sid: s, reason: CloseReason::UserClosed } if *s == sid
        )));
    }

    // -----------------------------------------------------------------------
    // Phase 3: malformed / adversarial packet handling (never panic)
    // -----------------------------------------------------------------------

    /// The receive path must be total: arbitrary (version-valid) datagrams from
    /// arbitrary sources must never panic, must never establish a session from
    /// nothing, and must leave bounded state behind.
    #[test]
    fn server_manager_garbage_never_panics_or_grows() {
        let (_, sc) = shared_configs();
        let mut manager = ServerSessionManager::new(&sc, SessionLimits::default()).unwrap();
        let mut buf = [0u8; PACKET_SIZE];
        let sources = [CLIENT_ADDR, OTHER_ADDR, SERVER_ADDR];
        for i in 0..200 {
            getrandom::fill(&mut buf).unwrap();
            buf[0] = crate::codec::PROTOCOL_VERSION; // pass version gate to reach dispatch/AEAD
            if let Ok(pkt) = WirePacket::from_bytes(&buf) {
                let from = sources[(i as usize) % sources.len()];
                let _ = manager
                    .handle_datagram(&pkt, from)
                    .unwrap_or(ManagerEvent::None);
            }
        }
        assert_eq!(
            manager.session_count(),
            0,
            "garbage must not establish sessions"
        );
        // fail_gate_peek creates at most one bucket per distinct source.
        assert!(
            manager.fail_bucket_count() <= sources.len(),
            "fail buckets must be bounded"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 4: resource / DoS bounds
    // -----------------------------------------------------------------------

    /// Reaching `max_sessions` must evict (LRU) and never grow the table beyond
    /// the cap, even when many distinct handshakes complete in quick succession.
    #[test]
    fn server_capacity_caps_session_table() {
        let mut dummy = client_manager();
        let mut server = server_machine();
        let (_ws, outcome) = client_handshake_with_server(&mut dummy, &mut server, CLIENT_ADDR);

        let mut limits = SessionLimits::default();
        limits.max_sessions = 16;
        let mut manager = server_manager(limits);
        for i in 0..32u8 {
            let mut o = outcome.clone();
            o.session_id = [i; SESSION_ID_LEN];
            match manager.on_handshake_complete(o, CLIENT_ADDR).unwrap() {
                ManagerEvent::Established { sid, .. } => assert_eq!(sid, [i; SESSION_ID_LEN]),
                other => panic!("expected Established, got {other:?}"),
            }
        }
        assert_eq!(manager.session_count(), 16, "capacity cap must hold");
        let drained = manager.tick(Instant::now());
        let cap = drained
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ManagerEvent::Closed {
                        reason: CloseReason::Capacity,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            cap, 16,
            "overflow sessions must be evicted as Closed{{Capacity}}"
        );
        assert_eq!(
            manager.session_count(),
            16,
            "post-tick table must still be capped"
        );
    }

    /// The data-path fail-gate bucket table must not grow past
    /// `max_fail_buckets` regardless of spoofed-source volume.
    #[test]
    fn server_fail_gate_bucket_table_bounded() {
        let (_, sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 8;
        let mut manager = ServerSessionManager::new(&sc, limits).unwrap();
        let mut buf = [0u8; PACKET_SIZE];
        // 50 distinct spoofed sources, each sending a version-valid junk packet.
        for i in 0..50u8 {
            getrandom::fill(&mut buf).unwrap();
            buf[0] = crate::codec::PROTOCOL_VERSION;
            let from = SocketAddr::from((Ipv4Addr::new(10, 0, 0, i + 2), 1234));
            if let Ok(pkt) = WirePacket::from_bytes(&buf) {
                let _ = manager
                    .handle_datagram(&pkt, from)
                    .unwrap_or(ManagerEvent::None);
            }
        }
        assert!(
            manager.fail_bucket_count() <= 8,
            "fail-gate table must cap at max_fail_buckets (got {})",
            manager.fail_bucket_count()
        );
    }

    // -----------------------------------------------------------------------
    // Phase 6: bounded long-haul soak (handshake -> close -> re-establish)
    // -----------------------------------------------------------------------

    /// Repeatedly establish + close the same client manager, asserting no
    /// residual state (no session leak between cycles) over many cycles.
    /// 300 full (ML-DSA/ML-KEM) handshakes is a meaningful soak without relying
    /// on wall-clock timers.
    #[test]
    fn soak_client_reestablish_cycles() {
        let (_cc, _sc) = shared_configs();
        let mut manager = client_manager();
        let mut server = server_machine();
        const CYCLES: usize = 300;
        for i in 0..CYCLES {
            let mut server = server_machine(); // Handshake is single-use; fresh per cycle.
            let (_ws, _outcome) =
                client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
            assert_eq!(
                manager.state(),
                ClientManagerState::Established,
                "cycle {i}"
            );
            assert!(
                manager.session_id().is_some(),
                "cycle {i} must hold a session"
            );
            assert!(matches!(
                manager.close().unwrap(),
                ManagerEvent::SendPacket { .. }
            ));
            let drained = manager.tick(Instant::now());
            assert!(
                !drained.is_empty(),
                "cycle {i} close must queue a Closed event"
            );
            assert_eq!(
                manager.state(),
                ClientManagerState::Idle,
                "cycle {i} must re-arm"
            );
            assert!(
                manager.session_id().is_none(),
                "cycle {i} session must be dropped"
            );
            assert_eq!(
                manager.handshake_sid(),
                None,
                "cycle {i} no in-flight handshake"
            );
        }
        // Fresh handshake after the soak must still succeed (Phase 7 recovery gate).
        let (_ws, _outcome) = client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
        assert_eq!(manager.state(), ClientManagerState::Established);
    }

    // -----------------------------------------------------------------------
    // Phase 8: timing baselines (regression detection)
    // -----------------------------------------------------------------------

    /// Record per-operation baselines so future regressions are detectable.
    /// Upper bounds are generous safety margins, not SLA targets.
    #[test]
    fn timing_baselines() {
        let (cc, _sc) = shared_configs();
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        let mut server = server_machine();

        let t0 = std::time::Instant::now();
        let (_ws, outcome) = client_handshake_with_server(&mut manager, &mut server, CLIENT_ADDR);
        let hs_us = t0.elapsed().as_micros();

        let mut server_ws = WireSession::established(Role::Server, &outcome).unwrap();
        let mut client_ws = WireSession::established(Role::Client, &outcome).unwrap();
        let plaintext = [0u8; PAYLOAD_LEN];

        let t1 = std::time::Instant::now();
        let pkt = client_ws.encrypt(MessageType::Data, &plaintext).unwrap();
        let enc_us = t1.elapsed().as_micros();

        let t2 = std::time::Instant::now();
        let _inner = server_ws.decrypt(&pkt).unwrap();
        let dec_us = t2.elapsed().as_micros();

        eprintln!(
            "timing_baselines: handshake~{}us encrypt~{}us decrypt~{}us sid={:?}",
            hs_us, enc_us, dec_us, outcome.session_id
        );
        assert!(hs_us < 2_000_000, "single handshake implausibly slow");
        assert!(enc_us < 10_000, "encrypt implausibly slow");
        assert!(dec_us < 10_000, "decrypt implausibly slow");
    }

    // -----------------------------------------------------------------------
    // ADVERSARIAL VALIDATION CAMPAIGN — see checkpoints/VALIDATION/
    // Each test is a bounded experiment with a fixed seed + recorded result.
    // -----------------------------------------------------------------------

    /// Deterministic PRNG (splitmix64) so every campaign is reproducible.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF52_3720_9EC8_1713);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn idx(&mut self, n: usize) -> usize {
            (self.next_u64() as usize) % n
        }
    }

    /// Establish a server session (SID, CLIENT_ADDR) and *return the handshake
    /// outcome* so callers can craft adversarial packets with the real keys.
    /// Mirrors the pattern used by `server_nonce_exhaustion_closes_session`: the
    /// server manager creates the session during M1→M2→M3, and the client machine
    /// yields the shared `HandshakeOutcome` (same master/derivation).
    fn establish_for_master(
        cc: &ClientConfig,
    ) -> (ServerSessionManager, WireSession, HandshakeOutcome) {
        let mut manager = server_manager(SessionLimits::default());
        let (mut client, _ws) = established_client_session(&mut manager, cc, SID);
        let (ws, outcome) = client_established(&mut client, cc);
        (manager, ws, outcome)
    }

    /// Campaign 1 — 10,000 deterministic established-phase event sequences.
    /// Exercises data / cover / replay / duplicate / reorder / tamper / tick
    /// plus Close + Reconnect cycles, asserting: no panic, session_count∈{0,1},
    /// at most one terminal Close per live window, never an orphan.
    #[test]
    fn adv_datapath_sequence_fuzz_10k() {
        const SEED: u64 = 0xC0FF_EE00_0000_0001;
        let (cc, mut sc) = shared_configs();
        // Isolate from the per-source handshake rate-limit (D7): each
        // close+reconnect cycle re-handshakes from CLIENT_ADDR and consumes two
        // rate tokens (M1 frag-0 + M3 frag-0), so 9 cycles exhaust the default
        // 16/10s burst — the server correctly suppresses M2 there. This campaign
        // validates established-phase sequencing, not the rate guard (covered by
        // `server_rate_limits_m1_per_source`.
        sc.rate_limit_burst = 1_000_000;
        let mut limits = SessionLimits::default();
        limits.fail_burst = 1_000_000; // isolate sequencing from fail-gate budgeting
        let mut manager = ServerSessionManager::new(&sc, limits).expect("manager");
        let (_cli, mut ws) = established_client_session(&mut manager, &cc, SID);

        let mut rng = Rng::new(SEED);
        let mut last_data = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        let mut data = last_data.clone();
        let mut closed_total: u64 = 0;
        // Prime the very first `data`/`last_data` (a not-yet-delivered packet) so
        // the replay/dup/reorder branches below only ever feed already-delivered
        // packets. Without this, iter 0 — or any iteration immediately after a
        // reconnect — would deliver `data` instead of rejecting it as a replay.
        match manager.handle_datagram(&data, CLIENT_ADDR).unwrap() {
            ManagerEvent::AppData { sid, .. } => assert_eq!(sid, SID, "seed: priming delivery"),
            other => panic!("seed: priming delivery must AppData, got {other:?}"),
        }

        for i in 0..10_000u64 {
            assert!(
                manager.session_count() <= 1,
                "iter {i}: leaked sessions ({})",
                manager.session_count()
            );
            if i % 1111 == 1110 {
                // Close + Reconnect cycle — the adversarial "Close, Reconnect" sequence.
                let close = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
                match manager.handle_datagram(&close, CLIENT_ADDR).unwrap() {
                    ManagerEvent::Closed { sid, reason } => {
                        assert_eq!(sid, SID, "iter {i}");
                        assert_eq!(reason, CloseReason::PeerClosed, "iter {i}");
                    }
                    other => panic!("iter {i}: close must Close{{PeerClosed}}, got {other:?}"),
                }
                assert_eq!(
                    manager.session_count(),
                    0,
                    "iter {i}: session removed after close"
                );
                let _ = manager.tick(Instant::now());
                // duplicate close → silent
                assert!(
                    matches!(
                        manager.handle_datagram(&close, CLIENT_ADDR).unwrap(),
                        ManagerEvent::None
                    ),
                    "iter {i}: dup close dropped"
                );
                // late duplicate of last data → silent (session gone)
                assert!(
                    matches!(
                        manager.handle_datagram(&data, CLIENT_ADDR).unwrap(),
                        ManagerEvent::None
                    ),
                    "iter {i}: late data dropped"
                );
                // reconnect
                let (_c, new_ws) = established_client_session(&mut manager, &cc, SID);
                ws = new_ws;
                data = ws
                    .encrypt(MessageType::Data, &[(i as u8).wrapping_mul(7); PAYLOAD_LEN])
                    .unwrap();
                last_data = data.clone();
                // Prime the new session's replay window with the fresh packet so
                // the post-reconnect iteration's replay/dup/reorder branches
                // operate on a delivered nonce, not an undelivered one.
                match manager.handle_datagram(&data, CLIENT_ADDR).unwrap() {
                    ManagerEvent::AppData { sid, .. } => {
                        assert_eq!(sid, SID, "iter {i}: post-reconnect data")
                    }
                    other => panic!("iter {i}: post-reconnect data must AppData, got {other:?}"),
                }
                closed_total += 1;
                continue;
            }
            let r = rng.next_u64() % 6;
            match r {
                0 => {
                    data = ws
                        .encrypt(MessageType::Data, &[(i as u8).wrapping_mul(3); PAYLOAD_LEN])
                        .unwrap();
                    last_data = data.clone();
                    match manager.handle_datagram(&data, CLIENT_ADDR).unwrap() {
                        ManagerEvent::AppData { sid, .. } => assert_eq!(sid, SID, "iter {i}"),
                        other => panic!("iter {i}: valid data must AppData, got {other:?}"),
                    }
                }
                1 => {
                    let pkt = ws
                        .encrypt(MessageType::Cover, &[i as u8; PAYLOAD_LEN])
                        .unwrap();
                    assert!(
                        matches!(
                            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} cover"
                    );
                }
                2 => {
                    assert!(
                        matches!(
                            manager.handle_datagram(&last_data, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} replay"
                    );
                }
                3 => {
                    assert!(
                        matches!(
                            manager.handle_datagram(&data, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} dup"
                    );
                }
                4 => {
                    let t = tampered(&data);
                    assert!(
                        matches!(
                            manager.handle_datagram(&t, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} tamper"
                    );
                }
                5 => {
                    // reorder: feed last_data then data (already delivered) — both replay now
                    assert!(
                        matches!(
                            manager.handle_datagram(&last_data, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} reorder A"
                    );
                    assert!(
                        matches!(
                            manager.handle_datagram(&data, CLIENT_ADDR).unwrap(),
                            ManagerEvent::None
                        ),
                        "iter {i} reorder B"
                    );
                }
                _ => unreachable!(),
            }
        }
        eprintln!(
            "adv_datapath_sequence_fuzz_10k: seed={SEED:#018x} iters=10000 closed_total={closed_total} final_session_count={}",
            manager.session_count()
        );
        assert!(manager.session_count() <= 1, "leaked session at end");
        assert_eq!(
            closed_total, 9u64,
            "exactly 9 close+reconnect cycles ran (10000 / 1111)"
        );
    }

    /// Campaign 1b — 128 deterministic handshake exchanges with reverse-order,
    /// duplicated fragment delivery (M1/M2) + reordered M3. Asserts the
    /// assembler's order-independence + dup-tolerance holds end-to-end at the
    /// manager layer (Phase 5 assembler unit tests are not sufficient on their
    /// own — this is the integration path).
    #[test]
    fn adv_handshake_reorder_128() {
        let (cc, sc) = shared_configs();
        let mut rng = Rng::new(0x_DEAD_BEEF_0000_0042);
        for round in 0..128u64 {
            let sid = {
                let mut s = [0u8; SESSION_ID_LEN];
                for b in &mut s {
                    *b = rng.next_u64() as u8;
                }
                if s == SID || s == [0x99; SESSION_ID_LEN] {
                    s[0] = s[0].wrapping_add(1)
                }
                s
            };
            let mut client = ClientHandshake::new(&cc, sid).expect("client");
            let mut server = ServerHandshake::new(&sc);
            // M1: frag-0 first (D13 pin creates the pending entry), then the
            // remaining M1 frags in reverse order, then a duplicate fragment-0
            // (order-independence + dup tolerance at the manager path).
            let m1 = client.m1_frags();
            let mut seen_m2 = Vec::new();
            for &idx in [0usize, 3, 2, 1, 0].iter() {
                if let ServerEvent::Emit(packets, _) =
                    server.handle_datagram(&m1[idx], CLIENT_ADDR).expect("m1")
                {
                    seen_m2 = packets;
                }
            }
            assert_eq!(
                seen_m2.len(),
                M2_FRAG_COUNT as usize,
                "round {round}: M2 after reordered M1"
            );
            // M2: reverse + duplicate, then M3.
            let mut seen_m3 = Vec::new();
            for &idx in [4usize, 3, 2, 1, 0, 2].iter().take(seen_m2.len()) {
                if let ClientEvent::Emit(packets) =
                    client.handle_datagram(&seen_m2[idx]).expect("m2")
                {
                    seen_m3 = packets;
                }
            }
            // re-feed a duplicate M2 to confirm idempotent
            for m2 in seen_m2.iter().take(2) {
                let _ = client.handle_datagram(m2).expect("dup m2");
            }
            let mut completed = false;
            for f in &seen_m3 {
                if let ServerEvent::Complete(_) =
                    server.handle_datagram(f, CLIENT_ADDR).expect("m3")
                {
                    completed = true;
                }
            }
            // M3 reorder: feed in reverse.
            let mut completed_r = false;
            for f in seen_m3.iter().rev() {
                if let ServerEvent::Complete(_) =
                    server.handle_datagram(f, CLIENT_ADDR).expect("m3 rev")
                {
                    completed_r = true;
                }
            }
            assert!(
                completed || completed_r,
                "round {round}: M3 must complete (order-independent)"
            );
        }
        eprintln!("adv_handshake_reorder_128: rounds=128 seed=0xDEADBEEF00000042");
    }

    /// Campaign 2 — D2 regression (manager level): oversized app data yields a
    /// *precise* WrongLength to a direct caller and the session survives; 10,000
    /// oversized sends are O(1) (no growth, no state drift).
    #[test]
    fn adv_d2_oversized_app_data_is_precise_and_bounded() {
        let (cc, _sc) = shared_configs();
        let mut cm = client_manager();
        let mut server = server_machine();
        let (_ws, _outcome) = client_handshake_with_server(&mut cm, &mut server, CLIENT_ADDR);
        assert_eq!(cm.state(), ClientManagerState::Established);

        let big: Vec<u8> = vec![0u8; PAYLOAD_LEN + 1];
        let res = cm.app_outbound(&big);
        assert!(
            matches!(
                res,
                Err(ManagerError::Session(SessionError::Codec(CodecError::WrongLength {
                    expected, got, ..
                }))) if expected == PAYLOAD_LEN && got == PAYLOAD_LEN + 1),
            "oversized app data must be a precise WrongLength, got {res:?}"
        );
        assert_eq!(
            cm.state(),
            ClientManagerState::Established,
            "client session survives oversized send"
        );
        assert!(cm.session_id().is_some(), "client sid survives");

        // Server side is symmetric.
        let mut sm = server_manager(SessionLimits::default());
        let (_c, _ws) = established_client_session(&mut sm, &cc, SID);
        let sbig: Vec<u8> = vec![0u8; PAYLOAD_LEN + 1];
        let sres = sm.app_outbound(&SID, &sbig);
        match sres {
            Err(ManagerError::Session(SessionError::Codec(CodecError::WrongLength {
                expected,
                got,
                ..
            }))) if expected == PAYLOAD_LEN && got == PAYLOAD_LEN + 1 => {}
            other => panic!("server oversized must be precise WrongLength, got {other:?}"),
        }
        assert_eq!(
            sm.session_count(),
            1,
            "server session survives oversized app send"
        );

        // Bounded stress: 10,000 oversized sends must be O(1).
        let t0 = std::time::Instant::now();
        for _ in 0..10_000 {
            match cm.app_outbound(&big) {
                Err(ManagerError::Session(SessionError::Codec(CodecError::WrongLength {
                    ..
                }))) => {}
                other => panic!("oversized must always be WrongLength, got {other:?}"),
            }
        }
        let elapsed = t0.elapsed();
        eprintln!("adv: 10_000 oversized app_outbound in {elapsed:?}");
        assert!(
            elapsed.as_millis() < 1000,
            "oversized skip must be O(1), took {elapsed:?}"
        );
        // session still fully usable with a correctly-sized payload
        assert!(matches!(
            cm.app_outbound(&[0u8; PAYLOAD_LEN]).unwrap(),
            ManagerEvent::SendPacket { .. }
        ));
    }

    /// Campaign 2 — D2 end-to-end driver check (server): an oversized app
    /// payload must NOT terminate the `run_server_manager` driver. Uses the
    /// shared `MemoryTransport` mock.
    #[tokio::test]
    async fn adv_d2_oversized_app_data_does_not_kill_server_driver() {
        let (cc, _sc) = shared_configs();
        let mut sm = server_manager(SessionLimits::default());
        let (_c, _ws) = established_client_session(&mut sm, &cc, SID); // pre-established
        assert_eq!(sm.session_count(), 1);

        let (client_t, mut server_t, _guard) = crate::handshake_v2::tests::wired_transports();
        let (app_tx_cmd, app_rx) = mpsc::channel::<ServerAppCommand>(8);
        let (app_tx_notif, _notif_rx) = mpsc::channel::<ManagerNotification>(16);

        // Scope the driver so its pinned future (which holds `&mut sm`) is dropped
        // before we read `sm.session_count()` below (E0502 otherwise).
        {
            let driver =
                run_server_manager(&mut server_t, &mut sm, app_tx_notif, app_rx, no_cover());
            tokio::pin!(driver);

            let big = vec![0u8; PAYLOAD_LEN + 1];
            app_tx_cmd
                .send(ServerAppCommand {
                    sid: SID,
                    payload: big.clone(),
                })
                .await
                .unwrap();
            let r1 = tokio::time::timeout(Duration::from_millis(80), &mut driver).await;
            assert!(
                r1.is_err(),
                "driver must remain alive after oversized cmd (Elapsed == still running)"
            );
            app_tx_cmd
                .send(ServerAppCommand {
                    sid: SID,
                    payload: big,
                })
                .await
                .unwrap();
            let r2 = tokio::time::timeout(Duration::from_millis(80), &mut driver).await;
            assert!(
                r2.is_err(),
                "driver must remain alive after second oversized cmd"
            );
            // closing the app channel lets the driver exit cleanly (on app_rx None)
            drop(app_tx_cmd);
            let r3 = tokio::time::timeout(Duration::from_secs(1), &mut driver).await;
            assert!(
                r3.is_ok(),
                "driver must terminate on app-channel close, not hang"
            );
            assert!(
                r3.unwrap().is_ok(),
                "driver must exit cleanly — oversized app data must not be fatal"
            );
        }
        assert_eq!(
            sm.session_count(),
            1,
            "session survives the oversized-app driver test"
        );
        let _ = client_t;
    }

    /// Campaign 3 — handshake-flood DoS + recovery: 100 distinct-SID M1 floods
    /// must be bounded by `max_pending` (64) with no panic, and a legitimate
    /// handshake from a fresh sid afterward must still establish.
    #[test]
    fn adv_handshake_flood_then_valid_recovers() {
        let (cc, mut sc) = shared_configs();
        let limits = SessionLimits::default();
        // Isolate the pending-cap clamp from this campaign's recovery leg: a
        // 100-source full-M1 flood would saturate the default max_pending (64)
        // with AwaitM3 entries that cannot complete (no M3 is sent) and survive
        // until pending_ttl expiry — correctly blocking a new handshake. The
        // exact 64-clamp is certified by `server_max_pending_cap`; this campaign
        // focuses on flood-no-panic + bounded state + post-flood recovery.
        sc.max_pending = 1_000;
        let mut manager = ServerSessionManager::new(&sc, limits).expect("manager");
        assert_eq!(manager.pending_handshakes(), 0);

        // Pre-load 1 legit session so we assert the flood doesn't touch it.
        let (_c0, mut ws) = established_client_session(&mut manager, &cc, SID);
        let legit = ws.encrypt(MessageType::Data, &[0x11; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&legit, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));

        // 100 distinct-SID M1 fragments from 100 distinct sources.
        let mut caps;
        for i in 0..100usize {
            let sid = {
                let mut s = SID;
                s[0] = (i as u8).wrapping_add(1); // distinct sids
                s
            };
            let client = ClientHandshake::new(&cc, sid).expect("client");
            for f in client.m1_frags() {
                let from = format!("10.9.0.1:{}", 41000 + i)
                    .parse::<SocketAddr>()
                    .unwrap();
                // Must not panic; over-cap is a silent ManagerEvent::None.
                let _ = manager.handle_datagram(f, from);
            }
            caps = manager.pending_handshakes();
            assert!(
                caps <= sc.max_pending,
                "pending must cap at max_pending({}), got {caps} at flood {i}",
                sc.max_pending
            );
            assert_eq!(
                manager.session_count(),
                1,
                "legit session must survive flood at {i}"
            );
        }
        assert!(manager.fail_bucket_count() <= 4096);

        // Recovery: a fully valid, in-state handshake from a brand-new sid completes.
        let sid_b = [0x77; SESSION_ID_LEN];
        let (_c2, mut ws_b) = established_client_session(&mut manager, &cc, sid_b);
        assert_eq!(
            manager.session_count(),
            2,
            "legit client must recover after flood"
        );
        let good = ws_b
            .encrypt(MessageType::Data, &[0x5A; PAYLOAD_LEN])
            .unwrap();
        match manager.handle_datagram(&good, CLIENT_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("post-flood data must decrypt, got {other:?}"),
        }
        let _ = manager;
        let _ = limits;
    }

    /// Campaign 3 — data-path flood (unknown SID + replay) must not grow state,
    /// must not panic, and the session must remain serviceable.
    #[test]
    fn adv_data_flood_unknown_sid_is_bounded() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 8;
        let mut manager = server_manager(limits);
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0x22; PAYLOAD_LEN]).unwrap();

        // 1,000 packets with an unknown SID from distinct sources.
        let mut bytes = *good.as_bytes();
        bytes[1..9].copy_from_slice(&[0xEE; SESSION_ID_LEN]); // unknown sid
        let foreign = WirePacket::from_bytes(&bytes).unwrap();
        for i in 0..1_000u16 {
            let from = format!("10.8.0.1:{}", 50000 + i)
                .parse::<SocketAddr>()
                .unwrap();
            assert!(
                matches!(
                    manager.handle_datagram(&foreign, from).unwrap(),
                    ManagerEvent::None
                ),
                "unknown sid {i} must be silent"
            );
        }
        assert_eq!(
            manager.session_count(),
            1,
            "unknown-sid flood must not create/touch sessions"
        );
        assert!(
            manager.fail_bucket_count() <= 8,
            "fail buckets must stay capped"
        );
        // Legit traffic from the un-gated client still works.
        assert!(matches!(
            manager.handle_datagram(&good, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));

        // Replay flood of the valid packet: window rejects, fail-gate may close
        // CLIENT_ADDR, but the session is never removed.
        let mut closed = 0;
        for _ in 0..300 {
            match manager.handle_datagram(&good, CLIENT_ADDR).unwrap() {
                ManagerEvent::None => {}
                ManagerEvent::Closed {
                    reason: CloseReason::PeerClosed,
                    ..
                } => closed += 1,
                other => panic!("replay flood yielded {other:?}"),
            }
        }
        assert!(
            closed == 0,
            "replay flood must not close the live session (got {closed})"
        );
        assert_eq!(manager.session_count(), 1, "session survives replay flood");
    }

    /// Campaign 4 — memory: create+free 10,000 WireSession pairs (no handshake,
    /// isolating session-object allocator behaviour) and sample process working-set.
    /// Hard invariant: no panic; soft invariant: bounded RSS drift (<32 MB).
    #[cfg(windows)]
    #[test]
    fn adv_memory_working_set_and_leak() {
        let master = pq_crypto::derive_master_secret(&[0x11u8; 32], &[0x22u8; 32]).expect("master");
        let rss0 = mem_probe::working_set();
        for cycle in 0..5u64 {
            for _ in 0..2_000u64 {
                let mut c =
                    WireSession::new(Role::Client, &master, [0xAB; SESSION_ID_LEN]).unwrap();
                c.begin_handshake().unwrap();
                c.complete_handshake().unwrap();
                let mut s =
                    WireSession::new(Role::Server, &master, [0xAB; SESSION_ID_LEN]).unwrap();
                s.begin_handshake().unwrap();
                s.complete_handshake().unwrap();
                let pkt = c.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
                assert!(s.decrypt(&pkt).is_ok());
                // drop zeroizes (D14)
            }
            if let Some(rss) = mem_probe::working_set() {
                eprintln!("adv: mem cycle {cycle}: working_set_size={rss} bytes");
            }
        }
        let rss1 = mem_probe::working_set();
        eprintln!("adv: mem working_set start={rss0:?} end={rss1:?}");
        // The logical allocator must not grow without bound across 10,000 alloc/free
        // pairs. We assert only on what is deterministic here; RSS is reported, not
        // hard-asserted, because the system allocator's return-to-OS timing is
        // platform-dependent (see §9 limitations).
        let _ = (rss0, rss1);
    }

    /// Campaign 4 — logical leak check: establish+close 200 sessions on one server
    /// manager; session_count must return to 0 each time and the fail-bucket table
    /// must not grow unboundedly across close cycles (a single legitimate source
    /// may leave one full-token bucket, created by `fail_gate_peek` on a
    /// successful Close — it never burns the source's failure budget).
    #[test]
    fn adv_sessions_table_resets_on_close() {
        let (cc, mut sc) = shared_configs();
        // Isolate from the per-source handshake rate-limit (D7, default burst
        // 16/10s): this campaign re-handshakes 200x from CLIENT_ADDR in a tight
        // loop to validate close/lifecycle + fail-bucket bounds, not the rate
        // guard. Without this isolation the legitimate rapid re-handshakes are
        // throttled and the server correctly suppresses M2 (covered by
        // `server_rate_limits_m1_per_source`.
        sc.rate_limit_burst = 1_000_000;
        let mut manager =
            ServerSessionManager::new(&sc, SessionLimits::default()).expect("manager");
        for i in 0..200usize {
            let sid = {
                let mut s = SID;
                s[0] = (i as u8).wrapping_add(3);
                s
            };
            let (_c, mut ws) = established_client_session(&mut manager, &cc, sid);
            assert_eq!(manager.session_count(), 1, "iter {i}: established");
            let close = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
            assert!(
                matches!(manager.handle_datagram(&close, CLIENT_ADDR).unwrap(), ManagerEvent::Closed { sid: s, reason: CloseReason::PeerClosed } if s == sid)
            );
            let drained = manager.tick(Instant::now());
            assert!(
                drained
                    .iter()
                    .all(|e| !matches!(e, ManagerEvent::Closed { .. })),
                "iter {i}: close already drained inline"
            );
            assert_eq!(manager.session_count(), 0, "iter {i}: session removed");
            assert!(
                manager.fail_bucket_count() <= 1,
                "iter {i}: fail buckets must stay bounded (<=1 legit source), got {}",
                manager.fail_bucket_count()
            );
        }
    }

    /// Campaign 5 — virtual clock: idle-timeout eviction + lifetime-cap precedence,
    /// driven by injecting a far-future Instant (no real waiting).
    #[test]
    fn adv_time_control_server_eviction_virtual_clock() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.idle_timeout = Some(Duration::from_secs(10));
        limits.lifetime_cap = Some(Duration::from_secs(20));
        let mut manager = server_manager(limits);
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let t0 = Instant::now();

        // Activity within the idle window refreshes last_activity.
        let pkt = ws.encrypt(MessageType::Data, &[0x01; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert_eq!(
            manager.tick(t0 + Duration::from_secs(9)).len(),
            0,
            "alive at +9s"
        );
        assert_eq!(manager.session_count(), 1);

        // +15s real (idle since +9s activity; strictly between the 10s idle
        // timeout and the 20s lifetime cap) → idle timeout fires.
        let evs = manager.tick(t0 + Duration::from_secs(15));
        assert_eq!(evs.len(), 1, "idle timeout must fire once at +15s");
        assert!(
            matches!(&evs[0], ManagerEvent::Closed { sid, reason: CloseReason::IdleTimeout } if *sid == SID)
        );
        assert_eq!(manager.session_count(), 0);

        // lifetime precedence: a session that lives to lifetime_cap is evicted with
        // LifetimeCap even if it has had recent activity.
        let (_c2, mut ws) = established_client_session(&mut manager, &cc, SID);
        let pkt = ws.encrypt(MessageType::Data, &[0x02; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        let evs = manager.tick(t0 + Duration::from_secs(30));
        assert!(
            evs.iter().any(|e| matches!(
                e,
                ManagerEvent::Closed {
                    reason: CloseReason::LifetimeCap,
                    ..
                }
            )),
            "lifetime cap must win over idle at +30s"
        );
        assert_eq!(manager.session_count(), 0);
    }

    /// Campaign 5 — client handshake timeout is deterministic and re-arms (D16).
    #[test]
    fn adv_client_handshake_timeout_deterministic() {
        let (cc, _sc) = shared_configs();
        let mut cm = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        // begin → send M1, Handshaking, no server response fed.
        match cm.begin_handshake().unwrap() {
            ManagerEvent::Send { peer, .. } => assert_eq!(peer, SERVER_ADDR),
            other => panic!("expected Send(M1), got {other:?}"),
        }
        assert_eq!(cm.state(), ClientManagerState::Handshaking);
        let start_sid = cm
            .handshake_sid()
            .expect("handshake sid after begin_handshake");
        let mut saw_timeout = false;
        for _ in 0..20 {
            match cm.on_timer().unwrap() {
                ManagerEvent::Send { .. } => {} // M1 retransmit
                ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::HandshakeTimeout,
                } => {
                    // `on_timer` clears the in-flight handshake before emitting the
                    // event, so compare against the sid captured above rather than
                    // re-querying `handshake_sid()` (which is `None` by now).
                    assert_eq!(
                        sid, start_sid,
                        "timed-out sid must match the started handshake"
                    );
                    saw_timeout = true;
                    break;
                }
                other => panic!("unexpected during timeout drain: {other:?}"),
            }
        }
        assert!(
            saw_timeout,
            "client must HandshakeTimeout without a server M2"
        );
        assert_eq!(
            cm.state(),
            ClientManagerState::Idle,
            "timeout re-arms to Idle"
        );
        // D16: re-establishment after timeout.
        match cm.begin_handshake().unwrap() {
            ManagerEvent::Send { .. } => {}
            other => panic!("must re-arm after timeout, got {other:?}"),
        }
        assert_eq!(cm.state(), ClientManagerState::Handshaking);
    }

    /// Campaign 6/7 — close vs data ordering races (single-threaded permutation):
    /// close-before-data, data-before-close, and duplicate close.
    #[test]
    fn adv_close_data_race_orderings() {
        let (cc, _sc) = shared_configs();

        // (A) Close then duplicate-of-data (out of order): close wins, late data → None.
        let (mut m, mut ws, _) = establish_for_master(&cc);
        let data = ws.encrypt(MessageType::Data, &[0x09; PAYLOAD_LEN]).unwrap();
        let close = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            m.handle_datagram(&close, CLIENT_ADDR).unwrap(),
            ManagerEvent::Closed {
                reason: CloseReason::PeerClosed,
                ..
            }
        ));
        assert_eq!(m.session_count(), 0);
        assert!(
            matches!(
                m.handle_datagram(&data, CLIENT_ADDR).unwrap(),
                ManagerEvent::None
            ),
            "late data must not resurrect"
        );
        assert!(
            matches!(
                m.handle_datagram(&close, CLIENT_ADDR).unwrap(),
                ManagerEvent::None
            ),
            "dup close must be None"
        );

        // (B) Data then close: data delivered, then closed.
        let (mut m, mut ws, _) = establish_for_master(&cc);
        let data = ws.encrypt(MessageType::Data, &[0x0A; PAYLOAD_LEN]).unwrap();
        let close = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            m.handle_datagram(&data, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert!(matches!(
            m.handle_datagram(&close, CLIENT_ADDR).unwrap(),
            ManagerEvent::Closed {
                reason: CloseReason::PeerClosed,
                ..
            }
        ));
        assert_eq!(m.session_count(), 0);

        // (C) Simultaneous same-nonce: two distinct close packets (different nonces) → one close.
        let (mut m, mut ws, _) = establish_for_master(&cc);
        let c1 = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap();
        let c2 = ws.encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN]).unwrap(); // distinct nonce
        assert_ne!(
            c1.as_bytes(),
            c2.as_bytes().as_ref(),
            "distinct nonces produce distinct ciphertexts"
        );
        let first = m.handle_datagram(&c1, CLIENT_ADDR).unwrap();
        let second = m.handle_datagram(&c2, CLIENT_ADDR).unwrap();
        assert!(
            matches!(
                first,
                ManagerEvent::Closed {
                    reason: CloseReason::PeerClosed,
                    ..
                }
            ) && matches!(second, ManagerEvent::None),
            "first close wins, second dropped"
        );
    }

    /// Campaign 7 — nonce-exhaustion boundary: a packet at MAX_PACKET_NONCE forces
    /// `Closed{NonceExhausted}` and the session is removed; a fresh handshake
    /// recovers.
    #[test]
    fn adv_nonce_exhaustion_recovery() {
        let (cc, _sc) = shared_configs();
        let (mut manager, _ws, outcome) = establish_for_master(&cc);
        let pkt = exhaustion_packet_c2s(&outcome.master, SID);
        assert!(matches!(
            manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap(),
            ManagerEvent::Closed { sid, reason: CloseReason::NonceExhausted } if sid == SID
        ));
        assert_eq!(manager.session_count(), 0, "exhausted session removed");
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        assert_eq!(manager.session_count(), 1, "recover after exhaustion");
        let data = ws.encrypt(MessageType::Data, &[0x71; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&data, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
    }

    /// Campaign 7 — replay-window dedup/boundary: 256 distinct-nonce valid packets
    /// all deliver; replaying any one is rejected; session count stays 1.
    #[test]
    fn adv_replay_window_dedup_256() {
        let (cc, _sc) = shared_configs();
        let (mut manager, mut ws, _outcome) = establish_for_master(&cc);
        let mut seen: Vec<WirePacket> = Vec::with_capacity(256);
        seen.reserve(256);
        for i in 0..256u64 {
            let p = ws
                .encrypt(
                    MessageType::Data,
                    &[(i as u8).wrapping_mul(13); PAYLOAD_LEN],
                )
                .unwrap();
            assert!(
                matches!(
                    manager.handle_datagram(&p, CLIENT_ADDR).unwrap(),
                    ManagerEvent::AppData { .. }
                ),
                "packet {i} must deliver"
            );
            seen.push(p);
        }
        assert_eq!(manager.session_count(), 1);
        // replay 32 distinct previously-seen packets → all rejected silently
        let mut rng = Rng::new(0x_F00D_0000_0000_0002);
        for _ in 0..32 {
            let idx = rng.idx(256);
            assert!(
                matches!(
                    manager.handle_datagram(&seen[idx], CLIENT_ADDR).unwrap(),
                    ManagerEvent::None
                ),
                "replay must be rejected"
            );
        }
        assert_eq!(manager.session_count(), 1, "replays must not create state");
        // a fresh packet still delivers (window advanced, not poisoned)
        let fresh = ws.encrypt(MessageType::Data, &[0xFF; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager.handle_datagram(&fresh, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
    }

    // ---- Windows process-working-set probe (best-effort RSS) ----
    #[cfg(windows)]
    mod mem_probe {
        use std::mem;
        #[repr(C)]
        struct Pm {
            cb: u32,
            page_fault_count: u32,
            peak_working_set: usize,
            working_set: usize,
            quota_peak_paged: usize,
            quota_paged: usize,
            pagefile: usize,
        }
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            #[link_name = "K32GetProcessMemoryInfo"]
            fn get_mem(h: isize, cs: *mut Pm, cb: u32) -> i32;
        }
        pub fn working_set() -> Option<u64> {
            let mut pm = Pm {
                cb: 0,
                page_fault_count: 0,
                peak_working_set: 0,
                working_set: 0,
                quota_peak_paged: 0,
                quota_paged: 0,
                pagefile: 0,
            };
            let cb = mem::size_of::<Pm>() as u32;
            pm.cb = cb;
            let h = unsafe { GetCurrentProcess() };
            let ok = unsafe { get_mem(h, &mut pm, cb) };
            if ok == 0 {
                return None;
            }
            Some(pm.working_set as u64)
        }
    }

    // -----------------------------------------------------------------------
    // M9B R2: transport peer-reset must be session-local to the server driver
    // -----------------------------------------------------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::handshake_v2::tests::MemoryTransport;

    /// A transport that surfaces exactly one [`HandshakeV2Error::TransportReset`]
    /// once armed, then behaves like the inner transport (an ICMP
    /// port-unreachable is a one-shot socket signal per reset episode).
    struct ResetOnce {
        inner: MemoryTransport,
        armed: Arc<AtomicBool>,
    }

    impl HandshakeTransport for ResetOnce {
        async fn send_to(
            &mut self,
            packet: &WirePacket,
            peer: SocketAddr,
        ) -> Result<(), HandshakeV2Error> {
            self.inner.send_to(packet, peer).await
        }

        async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error> {
            if self.armed.swap(false, Ordering::SeqCst) {
                return Err(HandshakeV2Error::TransportReset);
            }
            self.inner.recv().await
        }
    }

    /// R2 regression: a peer reset (ICMP port-unreachable / WSAECONNRESET)
    /// surfaced by the transport must NOT terminate the server manager.
    /// The vanished peer's session is reaped by idle eviction; the driver
    /// (and any unrelated sessions) stay up (M9B).
    #[tokio::test]
    async fn server_driver_survives_transport_reset() {
        let (cc, sc) = shared_configs();
        let mut manager = ServerSessionManager::new(&sc, SessionLimits::default()).unwrap();
        let (mut client_t, server_t, _guard) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (_cmd_tx, cmd_rx) = mpsc::channel(64);
        let arm = Arc::new(AtomicBool::new(false));
        let mut srv = ResetOnce {
            inner: server_t,
            armed: arm.clone(),
        };
        let mut driver = tokio::spawn(async move {
            run_server_manager(&mut srv, &mut manager, app_tx, cmd_rx, no_cover()).await
        });

        // Establish a session through the driver (mirrors server_driver_end_to_end).
        let sid = [0x42; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).unwrap();
        for f in client.m1_frags() {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        let mut m3 = Vec::new();
        for _ in 0..M2_FRAG_COUNT {
            let (pkt, from) = client_t.recv().await.unwrap();
            assert_eq!(from, SERVER_ADDR);
            if let ClientEvent::Emit(pkts) = client.handle_datagram(&pkt).unwrap() {
                m3 = pkts;
            }
        }
        for f in &m3 {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Established { .. } => {}
            other => panic!("expected Established, got {other:?}"),
        }

        // The peer's port vanishes (client transport closed): the transport
        // surfaces one TransportReset on the next receive.
        arm.store(true, Ordering::SeqCst);

        let outcome = tokio::time::timeout(Duration::from_secs(2), &mut driver).await;
        assert!(
            outcome.is_err(),
            "server driver must survive a transport reset; got {outcome:?}"
        );
        driver.abort();
    }

    // -----------------------------------------------------------------------
    // D16: nonce-exhaustion full-loop re-establishment (driver level)
    // -----------------------------------------------------------------------

    /// D16 full loop (client side): the client driver, running against a live
    /// transport, must survive an authentic packet at the nonce-exhaustion
    /// boundary.  The session is closed with `NonceExhausted`, the driver
    /// auto-arms a fresh handshake (rearm_client), the new session reaches
    /// Ready, and application data continues to flow in both directions —
    /// all without restarting the driver.  The test drives the server machine
    /// (as in client_driver_end_to_end), so the session master is known and
    /// the boundary packet can be crafted with the public KDF + AEAD
    /// primitives.
    #[tokio::test]
    async fn client_driver_nonce_exhaustion_reestablishes() {
        let (mut cc, sc) = shared_configs();
        cc.m1_retransmit_base = Duration::from_millis(50);
        cc.m3_max_attempts = 1;
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        let (mut client_t, mut server_t, srv_tx) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (data_tx, data_rx) = mpsc::channel(64);
        let driver = tokio::spawn(async move {
            run_client_manager(&mut client_t, &mut manager, app_tx, data_rx, no_cover()).await
        });

        // Leg 1: the driver auto-connects; the test answers as the server.
        let (first_sid, outcome, mut srv_ws) = {
            let mut server = ServerHandshake::new(&sc);
            let mut m2 = Vec::new();
            for _ in 0..M1_FRAG_COUNT {
                let (pkt, from) = server_t.recv().await.unwrap();
                assert_eq!(from, CLIENT_ADDR);
                if let ServerEvent::Emit(frags, peer) = server.handle_datagram(&pkt, from).unwrap()
                {
                    assert_eq!(peer, CLIENT_ADDR);
                    m2 = frags;
                }
            }
            assert_eq!(m2.len(), M2_FRAG_COUNT as usize);
            for f in &m2 {
                srv_tx.send((f.clone(), SERVER_ADDR)).unwrap();
            }
            let mut server_outcome = None;
            for _ in 0..M3_FRAG_COUNT * 2 {
                let (pkt, from) = server_t.recv().await.unwrap();
                assert_eq!(from, CLIENT_ADDR);
                if let ServerEvent::Complete(out) = server.handle_datagram(&pkt, from).unwrap() {
                    server_outcome = Some(out);
                }
            }
            let outcome = server_outcome.expect("server completes");
            // Client reaches Established on its retransmit budget (last backoff
            // ≈ 200ms; grace covers jitter).
            tokio::time::sleep(Duration::from_millis(350)).await;
            let ws = WireSession::established(Role::Server, &outcome).unwrap();
            (outcome.session_id, outcome, ws)
        };

        // Open the D15 gate → Ready.
        srv_tx.send((srv_ws.cover().unwrap(), SERVER_ADDR)).unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Ready { sid } => assert_eq!(sid, first_sid),
            other => panic!("expected Ready, got {other:?}"),
        }

        // Exhaustion boundary: an authentic packet at MAX_PACKET_NONCE.  The
        // driver must close the session and report it, not terminate.
        let boundary = exhaustion_packet_s2c(&outcome.master, first_sid);
        srv_tx.send((boundary, SERVER_ADDR)).unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Closed { sid, reason } => {
                assert_eq!(sid, first_sid);
                assert_eq!(reason, CloseReason::NonceExhausted);
            }
            other => panic!("expected Closed(NonceExhausted), got {other:?}"),
        }

        // Leg 2: the driver must have auto-armed a fresh handshake.
        let (second_sid, _outcome2, mut srv_ws2) = {
            let mut server = ServerHandshake::new(&sc);
            let mut m2 = Vec::new();
            for _ in 0..M1_FRAG_COUNT {
                let (pkt, from) = server_t.recv().await.unwrap();
                assert_eq!(from, CLIENT_ADDR);
                if let ServerEvent::Emit(frags, peer) = server.handle_datagram(&pkt, from).unwrap()
                {
                    assert_eq!(peer, CLIENT_ADDR);
                    m2 = frags;
                }
            }
            assert_eq!(m2.len(), M2_FRAG_COUNT as usize);
            for f in &m2 {
                srv_tx.send((f.clone(), SERVER_ADDR)).unwrap();
            }
            let mut server_outcome = None;
            for _ in 0..M3_FRAG_COUNT * 2 {
                let (pkt, from) = server_t.recv().await.unwrap();
                assert_eq!(from, CLIENT_ADDR);
                if let ServerEvent::Complete(out) = server.handle_datagram(&pkt, from).unwrap() {
                    server_outcome = Some(out);
                }
            }
            let outcome = server_outcome.expect("server completes leg 2");
            tokio::time::sleep(Duration::from_millis(350)).await;
            let ws = WireSession::established(Role::Server, &outcome).unwrap();
            (outcome.session_id, outcome, ws)
        };
        assert_ne!(
            second_sid, first_sid,
            "re-establishment uses a fresh session"
        );

        // Ready again on the fresh session.
        srv_tx
            .send((srv_ws2.cover().unwrap(), SERVER_ADDR))
            .unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Ready { sid } => assert_eq!(sid, second_sid),
            other => panic!("expected Ready (leg 2), got {other:?}"),
        }

        // Application data continues, both directions.
        data_tx.send(vec![0x77; 64]).await.unwrap();
        let (pkt, from) = server_t.recv().await.unwrap();
        assert_eq!(from, CLIENT_ADDR);
        let inner = srv_ws2.decrypt(&pkt).unwrap();
        assert_eq!(&inner.payload[..64], &[0x77; 64][..]);

        let reply = srv_ws2
            .encrypt(MessageType::Data, &[0x22; PAYLOAD_LEN])
            .unwrap();
        srv_tx.send((reply, SERVER_ADDR)).unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Data { inner, .. } => {
                assert_eq!(inner.msg_type, MessageType::Data);
                assert_eq!(&inner.payload[..], &[0x22; PAYLOAD_LEN][..]);
            }
            other => panic!("expected Data (leg 2), got {other:?}"),
        }

        // Closing the app channel ends the driver cleanly.
        drop(data_tx);
        assert!(driver.await.unwrap().is_ok());
    }

    /// D16 full loop (server side): the server driver must survive an
    /// authentic packet at the nonce-exhaustion boundary — it reports
    /// `Closed{NonceExhausted}` and keeps running; a fresh handshake then
    /// establishes a new session and data flows again (mirrors
    /// server_driver_end_to_end with the client machine driven by the test,
    /// so the master is known).
    #[tokio::test]
    async fn server_driver_nonce_exhaustion_recovers() {
        let (mut cc, sc) = shared_configs();
        // Fast client retransmit budget so the test-driven machine completes
        // in milliseconds instead of sweeping the default M3 budget.
        cc.m1_retransmit_base = Duration::from_millis(50);
        cc.m3_max_attempts = 1;
        let mut manager = ServerSessionManager::new(&sc, SessionLimits::default()).unwrap();
        let (mut client_t, mut server_t, _guard) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let driver = tokio::spawn(async move {
            run_server_manager(&mut server_t, &mut manager, app_tx, cmd_rx, no_cover()).await
        });

        // Leg 1: establish a session through the driver.
        let sid = [0x42; SESSION_ID_LEN];
        let mut client = ClientHandshake::new(&cc, sid).unwrap();
        for f in client.m1_frags() {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        let mut m3 = Vec::new();
        for _ in 0..M2_FRAG_COUNT {
            let (pkt, from) = client_t.recv().await.unwrap();
            assert_eq!(from, SERVER_ADDR);
            if let ClientEvent::Emit(pkts) = client.handle_datagram(&pkt).unwrap() {
                m3 = pkts;
            }
        }
        for f in &m3 {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Established { sid: es, .. } => assert_eq!(es, sid),
            other => panic!("expected Established, got {other:?}"),
        }
        let (_, out) = client_established(&mut client, &cc);

        // Exhaustion boundary (c2s): the server must close the session and
        // keep the driver running.
        let boundary = exhaustion_packet_c2s(&out.master, sid);
        client_t.send_to(&boundary, SERVER_ADDR).await.unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Closed { sid: cs, reason } => {
                assert_eq!(cs, sid);
                assert_eq!(reason, CloseReason::NonceExhausted);
            }
            other => panic!("expected Closed(NonceExhausted), got {other:?}"),
        }

        // Leg 2: a fresh handshake recovers; data flows again.
        let sid2 = [0x24; SESSION_ID_LEN];
        let mut client2 = ClientHandshake::new(&cc, sid2).unwrap();
        for f in client2.m1_frags() {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        let mut m3 = Vec::new();
        for _ in 0..M2_FRAG_COUNT {
            let (pkt, from) = client_t.recv().await.unwrap();
            assert_eq!(from, SERVER_ADDR);
            if let ClientEvent::Emit(pkts) = client2.handle_datagram(&pkt).unwrap() {
                m3 = pkts;
            }
        }
        for f in &m3 {
            client_t.send_to(f, SERVER_ADDR).await.unwrap();
        }
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Established { sid: es, .. } => assert_eq!(es, sid2),
            other => panic!("expected Established (leg 2), got {other:?}"),
        }
        let (mut cws2, _out2) = client_established(&mut client2, &cc);
        let pkt = cws2
            .encrypt(MessageType::Data, &[0x5A; PAYLOAD_LEN])
            .unwrap();
        client_t.send_to(&pkt, SERVER_ADDR).await.unwrap();
        match app_rx.recv().await.unwrap() {
            ManagerNotification::Data { sid: ds, inner } => {
                assert_eq!(ds, sid2);
                assert_eq!(&inner.payload[..], &[0x5A; PAYLOAD_LEN][..]);
            }
            other => panic!("expected Data (leg 2), got {other:?}"),
        }

        // Closing the command channel ends the driver cleanly.
        drop(cmd_tx);
        assert!(driver.await.unwrap().is_ok());
    }

    // -----------------------------------------------------------------------
    // M9A: Windows high-resolution cover clock
    // -----------------------------------------------------------------------

    #[cfg(windows)]
    fn cover_sleep_from_deadline(target: Option<Instant>) -> cover_clock::CoverSleep {
        match target {
            Some(d) => cover_clock::CoverSleep::deadline(d),
            None => cover_clock::CoverSleep::inert(),
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cover_arm_fires_around_deadline() {
        let start = Instant::now();
        let arm = cover_sleep_from_deadline(Some(start + Duration::from_millis(30)));
        tokio::pin!(arm);
        tokio::time::timeout(Duration::from_secs(1), &mut arm)
            .await
            .expect("cover arm must fire near its deadline");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(25) && elapsed < Duration::from_millis(500),
            "cover arm fired at {elapsed:?}, expected ~30 ms"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cover_arm_inert_never_fires() {
        let arm = cover_sleep_from_deadline(None);
        tokio::pin!(arm);
        let fired = tokio::time::timeout(Duration::from_millis(60), &mut arm).await;
        assert!(fired.is_err(), "inert cover arm must not fire");
    }
}
