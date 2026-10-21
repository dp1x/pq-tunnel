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
//!   re-establishment.  D24 pins the lookup-first ordering: a datagram whose
//!   sid names no live session is dropped *before* the gate, so it allocates
//!   and touches no bucket.  The source key is the full `SocketAddr` (port
//!   included), so one address is up to 65,535 distinct keys.
//! - **Fail-gate resource bound (D24, corrected)**: the bucket table is
//!   bounded by `max_fail_buckets` (default 4096) and by *nothing else* — in
//!   particular **not** by the live-session population.  The sid is cleartext
//!   in every packet header, so a party that observes one packet learns a
//!   live sid and can then mint one bucket per source port: the table can be
//!   driven to its cap from a single live session.  The cap is the *memory*
//!   bound; the *work* bound is separate and is what the packet path now
//!   respects: the packet path is O(1) (hash lookups only, no table scan),
//!   cap eviction is O(1), and the expiry sweep runs at most once per
//!   `fail_window` from the driver's 1 Hz tick — never from a datagram
//!   handler.  See [`FailGate`].
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

use std::collections::{HashMap, HashSet, VecDeque};
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
use pq_crypto::MlDsaPublicKey;

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
    /// Server only: a session whose last **authenticated receive** is older
    /// than this is evicted (`Closed{IdleTimeout}`).  Outbound traffic — the
    /// server's own cover emissions and application replies — deliberately
    /// does **not** refresh it: an idle timeout that the endpoint keeps
    /// refreshing itself is not an idle timeout, and with cover enabled (the
    /// default) it would mean abandoned sessions are never reaped (D31 §5).
    ///
    /// It MUST be strictly greater than [`Self::liveness_probe_interval`],
    /// otherwise a live-but-quiet client would be evicted before its probe
    /// arrives.  The invariant is validated at construction (fail closed).
    pub idle_timeout: Option<Duration>,
    /// Both roles: upper bound on session lifetime (D16 bounds traffic-key
    /// exposure).  `Closed{LifetimeCap}`.  `None` means unbounded.
    ///
    /// The clock starts when the session is *prepared* (the client: the
    /// moment the M3 is transmitted; the server: the moment the M3's Finished
    /// MAC verifies), so the two endpoints' clocks differ by ≈1 RTT rather
    /// than by the whole M3 retransmission budget.  The `Close` message is
    /// what makes the semantics exact — the two clocks are never assumed to
    /// agree (D31 §6).
    pub lifetime_cap: Option<Duration>,
    /// Client only (D15): the **confirmation** deadline.  A prepared session
    /// that receives no authenticated server packet within this time of the
    /// M3 transmission is closed (`Closed{NotConfirmed}`) and re-established.
    ///
    /// This is the *only* deadline on the unconfirmed path.  The M3
    /// retransmission budget is a retransmission *policy* underneath it, not
    /// a competing deadline: with both armed, the budget (≈7.75 s) always
    /// fires first and the probe period is dead code (D31 §5).
    pub confirm_timeout: Option<Duration>,
    /// Both roles: the interval between liveness probes.
    ///
    /// A probe is an in-session control message (sub-type `0x01`) that the
    /// client sends to the server; the server answers with an ack
    /// (sub-type `0x02`).  The probe is what keeps a live-but-quiet session
    /// alive on the server (whose idle timeout only counts *authenticated
    /// receives*) and what gives the client post-confirmation peer-loss
    /// detection.  It **replaces** a cover slot, so the D19 cover grid's rate
    /// is invariant (D31 §5).
    pub liveness_probe_interval: Duration,
    /// Client only: the number of **consecutive unanswered** liveness rounds
    /// after which the peer is declared dead (`Closed{PeerUnresponsive}`).
    ///
    /// A single missed round is never fatal — UDP loss must not kill a
    /// healthy session (D31 §8) — so the decision is made on N consecutive
    /// rounds, not on one timeout.
    pub liveness_rounds: u32,
    /// Client only (F6): overall deadline for a handshake attempt
    /// (`Closed{HandshakeTimeout}`); the M1 retransmit budget is enforced
    /// inside the handshake machine.
    pub handshake_timeout: Option<Duration>,
    /// Data-path failure gate: max decrypt *failures* per source per window.
    ///
    /// A token is consumed **only** when an AEAD decrypt actually fails
    /// (D24).  A successful decrypt, a replayed-but-authentic packet, and an
    /// in-session control message all consume nothing.
    pub fail_burst: u32,
    /// Data-path failure gate window.
    pub fail_window: Duration,
    /// Data-path failure gate: hard cap on per-source buckets (spoofed-source
    /// floods cannot grow the table unboundedly; stalest evicted at the cap).
    pub max_fail_buckets: usize,
    /// Pacing interval for the **session slot**: the shortest interval at
    /// which the endpoint may emit one queued application payload or one
    /// liveness probe.
    ///
    /// The session slot is the unit that keeps the observable packet rate
    /// invariant (D19/D22): a queued payload is flushed *through* the slot
    /// rather than as a burst, and a liveness probe *replaces* a cover
    /// packet instead of adding to it.
    pub slot_interval: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            idle_timeout: Some(Duration::from_secs(5 * 60)),
            lifetime_cap: None,
            confirm_timeout: Some(Duration::from_secs(30)),
            liveness_probe_interval: Duration::from_secs(5),
            liveness_rounds: 3,
            handshake_timeout: Some(Duration::from_secs(30)),
            fail_burst: 64,
            fail_window: Duration::from_secs(10),
            max_fail_buckets: 4096,
            slot_interval: Duration::from_millis(5),
        }
    }
}

impl SessionLimits {
    /// Validate the cross-field invariants.  Fail closed: an invalid
    /// configuration is rejected at construction, never silently repaired.
    ///
    /// * `idle_timeout` must be strictly greater than
    ///   `liveness_probe_interval` — otherwise the server evicts a live
    ///   client before its probe arrives, and the client re-establishes in a
    ///   loop.
    /// * `liveness_rounds` must be at least 1.
    /// * `slot_interval` must be non-zero.
    pub fn validate(&self) -> Result<(), ManagerError> {
        // MSRV 1.85: no let-chains (stabilized in 1.88), so the guards are
        // expressed with `match` rather than a nested `if let`.
        match self.idle_timeout {
            Some(idle) if idle <= self.liveness_probe_interval => {
                return Err(ManagerError::InvalidConfig(format!(
                    "idle_timeout ({idle:?}) must be strictly greater than \
                     liveness_probe_interval ({:?})",
                    self.liveness_probe_interval
                )));
            }
            _ => {}
        }
        if self.liveness_rounds == 0 {
            return Err(ManagerError::InvalidConfig(
                "liveness_rounds must be at least 1".into(),
            ));
        }
        if self.slot_interval.is_zero() {
            return Err(ManagerError::InvalidConfig(
                "slot_interval must be non-zero".into(),
            ));
        }
        Ok(())
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
    /// D15: the client received no authenticated server packet within
    /// `confirm_timeout` (mis-keyed or dead session).
    NotConfirmed,
    /// D31: the peer stopped answering liveness probes — `liveness_rounds`
    /// consecutive rounds went unanswered.  Distinct from
    /// [`CloseReason::NotConfirmed`], which is the *pre*-confirmation
    /// failure: this one fires on a session that was confirmed and then
    /// went silent.
    PeerUnresponsive,
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
    /// Datagrams to emit, all to `peer`.
    ///
    /// Carries handshake fragments (M1 retransmits, the M3) and — on the
    /// client — the in-session liveness probe that rides along with an M3
    /// retransmission.  The probe is a *data-path* packet, so it travels in
    /// the same burst as the handshake fragment it accompanies; the burst is
    /// part of the establishment phase, which is inherently off-grid.
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
    /// The bounded outbound queue dropped one or more application payloads
    /// (overflow, or per-entry TTL expiry).  `dropped` is the **cumulative**
    /// count since the manager was created; it never decreases.
    OutboundDropped { dropped: u64 },
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
    /// The bounded outbound queue dropped one or more application payloads.
    ///
    /// `dropped` is the cumulative number of dropped payloads since the
    /// manager was created.  The application learns that its data was *not*
    /// delivered — the previous behaviour (a silent `Err(NoSession)`) lost
    /// the data with no signal at all (D31 §7).
    OutboundDropped { dropped: u64 },
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
// Data-path failure gate (H1 review fix; D24)
// ---------------------------------------------------------------------------

/// Per-source failure budget.
///
/// `tokens` is the remaining budget; `last_refill` is the instant of the last
/// window refill (bucket creation counts as a refill).  A bucket older than
/// `fail_window` is *logically* expired: the peek path treats it as absent
/// and the consume path refills it to a full burst.  Expiry is therefore a
/// property of the accounting, not of the table's physical contents.
#[derive(Debug)]
struct RateBucket {
    tokens: u32,
    last_refill: Instant,
}

/// Per-source data-path failure gate (D24).
///
/// # Bound
///
/// The table holds at most `max_fail_buckets` entries — a hard cap, enforced
/// before every insert — and **not** one entry per live session.  The sid is
/// cleartext in every packet header, so a party that observes a single packet
/// learns a live sid and can then drive one bucket per source port; the
/// table can be driven to its cap from a single live session.  The live
/// session population is *not* a bound on this table, and `max_sessions` is
/// not a bound on it either.
///
/// # Work
///
/// The packet path is O(1): [`FailGate::peek`] is one hash lookup and
/// [`FailGate::consume`] is one hash lookup plus at most one insert and one
/// O(1) cap eviction.  No packet path scans the table.  The only scans are
/// off the packet path:
///
/// - [`FailGate::sweep`] reclaims expired buckets.  It runs at most once per
///   `fail_window` (the driver calls it from its 1 Hz tick), so its cost is
///   bounded by `max_fail_buckets` bucket visits per `fail_window`,
///   independent of the packet rate.
/// - the cap eviction pops one key from `order` — O(1), no scan.
#[derive(Debug)]
struct FailGate {
    /// Tracked sources and their remaining failure budget.
    buckets: HashMap<SocketAddr, RateBucket>,
    /// Insertion order of `buckets`' keys.  The cap-eviction victim is the
    /// front of this queue, so eviction is O(1) instead of a scan for the
    /// least-recently-refilled bucket.
    ///
    /// Invariant: `order` holds exactly the keys of `buckets`, each once, so
    /// `order.len() == buckets.len()`.  The sweep restores the invariant
    /// after removing expired buckets; the eviction path removes from both.
    order: VecDeque<SocketAddr>,
    /// When the expiry sweep last ran (amortisation clock).
    last_sweep: Instant,
    /// Test instrumentation: the number of fail-gate table entries visited by
    /// an operation that is not a plain hash lookup (cap evictions and sweep
    /// passes).  The packet path must never move this counter.
    #[cfg(test)]
    table_visits: u64,
    /// Test instrumentation: the number of expiry sweeps performed.
    #[cfg(test)]
    sweeps: u64,
}

impl FailGate {
    fn new(now: Instant) -> Self {
        Self {
            buckets: HashMap::new(),
            order: VecDeque::new(),
            last_sweep: now,
            #[cfg(test)]
            table_visits: 0,
            #[cfg(test)]
            sweeps: 0,
        }
    }

    /// Number of tracked sources (diagnostic).
    fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Token check WITHOUT consuming, and WITHOUT allocating: report whether a
    /// decrypt attempt for a *known* session may proceed.  A source with no
    /// bucket — or with an expired one — has spent nothing yet, so a full
    /// burst is assumed and no state is created (D24 lookup-first: buckets are
    /// only materialised by a real failure).
    fn peek(&self, from: SocketAddr, now: Instant, limits: &SessionLimits) -> bool {
        if limits.max_fail_buckets == 0 {
            // Degenerate configuration: fail closed (no data path).
            return false;
        }
        match self.buckets.get(&from) {
            // No bucket → nothing consumed, so nothing to gate on.
            None => true,
            Some(b) => {
                if now.duration_since(b.last_refill) >= limits.fail_window {
                    // Window elapsed: the bucket refills to a full burst on the
                    // next real failure (see `consume`).
                    return true;
                }
                b.tokens > 0
            }
        }
    }

    /// Consume one failure token (called only after a real AEAD failure).
    ///
    /// This is the only writer of the fail-gate table.  It performs no scan:
    /// the cap is enforced by evicting the oldest-inserted tracked source
    /// (O(1) — the front of `order`), and expiry is handled by the off-path
    /// sweep.
    fn consume(&mut self, from: SocketAddr, now: Instant, limits: &SessionLimits) {
        if limits.max_fail_buckets == 0 {
            // Degenerate configuration: fail closed (no data path).
            return;
        }
        // Already tracked: charge the existing budget.  No eviction, no
        // insert, no scan — the common case on the failure path.
        if let Some(bucket) = self.buckets.get_mut(&from) {
            if now.duration_since(bucket.last_refill) >= limits.fail_window {
                bucket.tokens = limits.fail_burst;
                bucket.last_refill = now;
            }
            bucket.tokens = bucket.tokens.saturating_sub(1);
            return;
        }
        // A new source: make room first.  O(1) per eviction — `order` holds
        // exactly the map's keys, so the front is a victim.  The victim is the
        // *oldest-inserted* tracked source; it is never the source being
        // inserted (that one is not tracked yet).
        while self.buckets.len() >= limits.max_fail_buckets {
            match self.order.pop_front() {
                Some(victim) => {
                    self.buckets.remove(&victim);
                    #[cfg(test)]
                    {
                        self.table_visits += 1;
                    }
                }
                // Unreachable while the `order`/`buckets` invariant holds.
                None => break,
            }
        }
        self.buckets.insert(
            from,
            RateBucket {
                tokens: limits.fail_burst.saturating_sub(1),
                last_refill: now,
            },
        );
        self.order.push_back(from);
        debug_assert_eq!(self.buckets.len(), self.order.len());
    }

    /// Reclaim expired buckets.  Runs from the driver's 1 Hz tick, never from
    /// a datagram handler, and at most once per `fail_window`, so its cost is
    /// bounded by `max_fail_buckets` bucket visits per window regardless of
    /// the packet rate.
    ///
    /// Expiry is a *logical* property of the accounting — an expired bucket
    /// is treated as absent by `peek` and refilled by `consume` — so skipping
    /// a sweep never changes an accept/reject decision; it only leaves the
    /// entry in the map for longer.
    fn sweep(&mut self, now: Instant, limits: &SessionLimits) {
        if self.buckets.is_empty() {
            return;
        }
        if now.duration_since(self.last_sweep) < limits.fail_window {
            return;
        }
        self.last_sweep = now;
        #[cfg(test)]
        let map_visits = self.buckets.len() as u64;
        #[cfg(test)]
        let order_visits = self.order.len() as u64;
        let window = limits.fail_window;
        self.buckets
            .retain(|_, b| now.duration_since(b.last_refill) < window);
        // Keep `order` in lockstep with `buckets`: the swept keys are gone.
        let buckets = &self.buckets;
        self.order.retain(|k| buckets.contains_key(k));
        #[cfg(test)]
        {
            self.table_visits += map_visits + order_visits;
            self.sweeps += 1;
        }
    }
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
    /// An in-session control message (liveness probe / ack).  Consumed
    /// internally: never relayed to the application, never charged to the
    /// failure gate.
    Control(InnerPlaintext),
    PeerClose,
    SessionDead(CloseReason),
    /// The AEAD tag did not verify — the *only* outcome that may consume a
    /// failure-gate token (D24).
    Failed,
    /// The packet was rejected for a reason that is **not** an AEAD failure
    /// (a replayed-but-authentic packet, invalid inner framing, a direction
    /// mismatch, a wrong version byte).  No token is consumed (D24): the
    /// rejection says nothing about the key being wrong, and charging it
    /// would let an off-path attacker drain a victim's budget with replayed
    /// copies of its own traffic.
    Rejected,
}

/// In-session control sub-types carried in `payload[0]` of a
/// [`MessageType::Handshake`] message.
///
/// `MessageType::Handshake` (0x00) already exists in the protocol's type
/// space; giving it a meaning is a **semantic extension of an existing
/// authenticated type**, not a new type and not a framing change.  No new
/// wire bytes are introduced: the message rides the ordinary encrypted
/// session slot (D31 §5).
pub mod control {
    /// Liveness probe: "are you there?".  The peer answers with
    /// [`ACK`](super::control::ACK).
    pub const PROBE: u8 = 0x01;
    /// Liveness acknowledgement: "yes".  A probe that is answered also
    /// *confirms* the key agreement (D15).
    pub const ACK: u8 = 0x02;
}

/// A session that has been closed locally but whose `Close` notification is
/// still being retransmitted to the peer.
///
/// The session object is retained (bounded, ≤ `CLOSE_RETRANSMIT_TOTAL`
/// seconds) purely so the remaining `Close` packets can be encrypted with
/// the same session keys.  It is **not** in the session table, so it cannot
/// serve data, and it is dropped — zeroizing its keys (D14) — once the
/// retransmission budget is spent.
struct PendingClose {
    session: WireSession,
    peer: SocketAddr,
    /// Retransmissions still to send.
    attempts_left: u32,
    /// When the next retransmission is due.
    next_at: Instant,
}

/// Total number of `Close` packets emitted for one teardown: the first one
/// plus `CLOSE_RETRANSMIT_TOTAL - 1` retransmissions.
///
/// A fire-and-forget `Close` over UDP can be lost, which would strand the
/// peer for a whole lifetime-cap period; the retransmissions make the
/// convergence reliable without unbounded traffic (D31 §6).
const CLOSE_RETRANSMIT_TOTAL: u32 = 3;
/// Base delay between `Close` retransmissions (jittered exponential backoff).
const CLOSE_RETRANSMIT_BASE: Duration = Duration::from_secs(1);

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
    fail_gate: FailGate,
    pending_closed: VecDeque<ManagerEvent>,
    /// Sessions whose `Close` notification is still being retransmitted.
    pending_closes: Vec<PendingClose>,
}

impl ServerSessionManager {
    /// Create a server session manager.  Configuration is validated here
    /// (version + non-empty roster + roster-size limit) — fail closed (D12).
    pub fn new(cfg: &ServerConfig, limits: SessionLimits) -> Result<Self, ManagerError> {
        // `ServerConfig::validate` is the single fail-closed validator
        // (version, non-empty roster, roster-size limit).  Calling it here
        // closes the struct-literal construction path: a config built by
        // hand with an over-limit roster is rejected with a precise error
        // instead of silently yielding a machine that trusts nobody.
        cfg.validate().map_err(|e| match e {
            HandshakeV2Error::InvalidConfig(msg) => ManagerError::InvalidConfig(msg),
            other => ManagerError::Handshake(other),
        })?;
        // Cross-field limit invariants (fail closed — see `SessionLimits`).
        limits.validate()?;
        Ok(Self {
            limits,
            hs: ServerHandshake::new(cfg),
            sessions: HashMap::new(),
            fail_gate: FailGate::new(Instant::now()),
            pending_closed: VecDeque::new(),
            pending_closes: Vec::new(),
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

    /// Replace the client roster without restarting (D27).
    ///
    /// Atomic and fail-closed: an empty roster is rejected and the existing
    /// roster is left in force.  Pending handshakes authenticated against the
    /// old roster are re-checked at M3 and will not complete if their key was
    /// revoked in the meantime.  Established sessions are deliberately NOT
    /// torn down — revocation gates future establishment (D27 §5).
    pub fn set_roster(&mut self, roster: Vec<MlDsaPublicKey>) -> Result<(), ManagerError> {
        self.hs.set_roster(roster).map_err(ManagerError::from)
    }

    /// Number of client keys on the current roster (diagnostics).
    pub fn roster_len(&self) -> usize {
        self.hs.roster_len()
    }

    /// Number of data-path failure-gate buckets (diagnostics).
    ///
    /// Bounded by `max_fail_buckets`, not by the live-session population: a
    /// party that learns a live sid (the sid is cleartext on the wire) can
    /// drive one bucket per source port.
    pub fn fail_bucket_count(&self) -> usize {
        self.fail_gate.len()
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
        let sid: [u8; SESSION_ID_LEN] = pkt.as_bytes()[1..1 + SESSION_ID_LEN]
            .try_into()
            .expect("fixed-size sid slice");
        // D24 lookup-first: the sid is resolved BEFORE the failure gate.  A
        // datagram naming an unowned sid performs no decryption and burns no
        // budget, so charging it is meaningless work that only inflates
        // attacker-controlled state (one bucket per distinct source, up to
        // 65,535 from a single IP by varying the port).
        if !self.sessions.contains_key(&sid) {
            return Ok(ManagerEvent::None);
        }
        let now = Instant::now();
        if !self.fail_gate.peek(from, now, &self.limits) {
            return Ok(ManagerEvent::None);
        }

        let result: DataResult = match self.sessions.get_mut(&sid) {
            None => return Ok(ManagerEvent::None),
            Some(entry) => match entry.session.decrypt(pkt) {
                Ok(inner) => {
                    // B4: `last_activity` tracks **authenticated receives
                    // only**.  The server's own cover emissions and
                    // application replies must NOT refresh it: an idle
                    // timeout that the endpoint refreshes itself is not an
                    // idle timeout, and with cover enabled (the default) it
                    // would mean abandoned sessions are never reaped.
                    entry.last_activity = now;
                    // §10 roaming: rebind only on an authenticated packet.
                    entry.peer = from;
                    match inner.msg_type {
                        MessageType::Data => DataResult::Payload(inner),
                        MessageType::Cover => DataResult::Payload(inner),
                        MessageType::TunData => DataResult::Payload(inner),
                        MessageType::Close => DataResult::PeerClose,
                        // In-session control message: consumed internally,
                        // never relayed to the application, and never charged
                        // to the failure gate (it decrypted successfully).
                        MessageType::Handshake => DataResult::Control(inner),
                    }
                }
                Err(SessionError::RekeyRequired) => {
                    DataResult::SessionDead(CloseReason::NonceExhausted)
                }
                // B9: a replayed-but-authentic packet (and every other
                // non-AEAD rejection) must NOT consume a failure-gate
                // token: the tag verified, so the rejection says nothing
                // about the key being wrong (D24).
                Err(SessionError::Codec(CodecError::Rejected)) => DataResult::Rejected,
                // A genuine AEAD failure is the only thing that spends a
                // token (D24).
                Err(SessionError::Codec(CodecError::DecryptionFailed)) => DataResult::Failed,
                Err(SessionError::Codec(CodecError::NonceExhausted { .. })) => {
                    DataResult::SessionDead(CloseReason::NonceExhausted)
                }
                Err(SessionError::Codec(_)) => DataResult::Failed,
                Err(e) => return Err(ManagerError::Session(e)),
            },
        };

        match result {
            DataResult::Payload(inner) => match inner.msg_type {
                MessageType::Data => Ok(ManagerEvent::AppData { sid, inner }),
                MessageType::TunData => Ok(ManagerEvent::AppData { sid, inner }),
                // Cover is consumed silently (it is not application data).
                _ => Ok(ManagerEvent::None),
            },
            DataResult::Control(inner) => self.on_control_message(sid, inner),
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
                self.fail_gate.consume(from, now, &self.limits);
                Ok(ManagerEvent::None)
            }
            // Not an AEAD failure: no token is consumed (D24).
            DataResult::Rejected => Ok(ManagerEvent::None),
        }
    }

    /// Handle an in-session control message (liveness probe / ack).
    ///
    /// The message is consumed entirely inside the session layer: it is never
    /// relayed to the application and it never touches the failure gate.  A
    /// probe is answered with an ack; an ack and every unknown sub-type are
    /// ignored (no state change, no charge).
    fn on_control_message(
        &mut self,
        sid: [u8; SESSION_ID_LEN],
        inner: InnerPlaintext,
    ) -> Result<ManagerEvent, ManagerError> {
        match inner.payload[0] {
            control::PROBE => {
                // Answer the probe so the client can confirm the key
                // agreement (D15).  The ack is encrypted with the same
                // session keys, so it is itself an authenticated packet.
                let result = {
                    let Some(entry) = self.sessions.get_mut(&sid) else {
                        // The session vanished between the decrypt and here
                        // (a concurrent teardown): a silent drop, never an
                        // error — a peer-input condition must not take the
                        // server down.
                        return Ok(ManagerEvent::None);
                    };
                    let peer = entry.peer;
                    let mut payload = [0u8; PAYLOAD_LEN];
                    payload[0] = control::ACK;
                    entry
                        .session
                        .encrypt(MessageType::Handshake, &payload)
                        .map(|packet| (packet, peer))
                };
                match result {
                    Ok((packet, peer)) => Ok(ManagerEvent::SendPacket { packet, peer }),
                    Err(SessionError::RekeyRequired) => {
                        self.sessions.remove(&sid);
                        Ok(ManagerEvent::Closed {
                            sid,
                            reason: CloseReason::NonceExhausted,
                        })
                    }
                    Err(e) => Err(ManagerError::Session(e)),
                }
            }
            // An ack needs no answer; every other sub-type is unknown and is
            // ignored without any state change and without touching the
            // failure gate.
            _ => Ok(ManagerEvent::None),
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

    /// Encrypt one overlay record on `sid` as `MessageType::TunData`.
    ///
    /// The payload must be exactly one [`PAYLOAD_LEN`] slot (overlay header +
    /// fragment).  This is the transport contract for the system-wide TUN
    /// data plane (D33): callers fragment the inner IP packet first via
    /// `dataplane::fragment_ip_packet` and send one slot per record.
    pub fn tun_outbound(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
        payload: &[u8],
    ) -> Result<ManagerEvent, ManagerError> {
        if payload.len() != PAYLOAD_LEN {
            return Err(ManagerError::Session(SessionError::Codec(
                CodecError::WrongLength {
                    field: "payload",
                    expected: PAYLOAD_LEN,
                    got: payload.len(),
                },
            )));
        }
        let mut slot = [0u8; PAYLOAD_LEN];
        slot.copy_from_slice(payload);
        self.send_encrypted(sid, MessageType::TunData, &slot)
    }
    ///
    /// B4: a cover emission is **outbound** traffic and deliberately does
    /// *not* refresh `last_activity`.  The idle timeout counts authenticated
    /// *receives* only — an endpoint that keeps its own session alive by
    /// talking to itself never reaps an abandoned session, and with cover
    /// enabled (the default) that means the session table grows without
    /// bound.
    pub fn cover_packet(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
    ) -> Result<ManagerEvent, ManagerError> {
        let entry = self.sessions.get_mut(sid).ok_or(ManagerError::NoSession)?;
        let peer = entry.peer;
        match entry.session.cover() {
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
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
            // B4: outbound traffic does not refresh `last_activity` (see
            // `cover_packet`).
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
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

    /// Close a session at the application's request.
    ///
    /// B7: an encrypted `Close` is emitted to the peer **before** the session
    /// is dropped, so the peer learns about the closure immediately instead
    /// of discovering it by idle timeout (or, on the client, by using a dead
    /// session for another 24 h).  The `Close` is retransmitted a bounded
    /// number of times (see [`PendingClose`]).  The `Closed{UserClosed}`
    /// notification is queued for the next tick (single-event invariant).
    pub fn close_session(
        &mut self,
        sid: &[u8; SESSION_ID_LEN],
    ) -> Result<ManagerEvent, ManagerError> {
        let entry = self.sessions.remove(sid).ok_or(ManagerError::NoSession)?;
        self.pending_closed.push_back(ManagerEvent::Closed {
            sid: *sid,
            reason: CloseReason::UserClosed,
        });
        Ok(self.begin_close(*sid, entry, Instant::now()))
    }

    /// Encrypt the first `Close` packet for a session that is being torn
    /// down, and schedule the retransmissions.
    ///
    /// The session is moved into `pending_closes`; it is dropped (keys
    /// zeroized, D14) once the retransmission budget is spent.
    fn begin_close(
        &mut self,
        _sid: [u8; SESSION_ID_LEN],
        entry: SessionEntry,
        now: Instant,
    ) -> ManagerEvent {
        let SessionEntry {
            mut session, peer, ..
        } = entry;
        let payload = [0u8; PAYLOAD_LEN];
        // The `Close` payload is all zeros; the message *type* is what
        // carries the meaning (§8.4).
        let packet = match session.encrypt(MessageType::Close, &payload) {
            Ok(packet) => packet,
            Err(_) => {
                // The session cannot encrypt any more (nonce exhausted): the
                // peer will discover the closure by timeout.  Fail securely —
                // never emit a malformed packet.
                return ManagerEvent::None;
            }
        };
        self.pending_closes.push(PendingClose {
            session,
            peer,
            attempts_left: CLOSE_RETRANSMIT_TOTAL - 1,
            next_at: now + CLOSE_RETRANSMIT_BASE,
        });
        ManagerEvent::SendPacket { packet, peer }
    }

    /// Timer tick: evict idle/expired sessions, drain queued `Closed` events.
    pub fn tick(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();
        let idle = self.limits.idle_timeout;
        let life = self.limits.lifetime_cap;
        // Collect the expiring sids first: the session must still be alive
        // when its `Close` is encrypted (B7).
        let expired: Vec<([u8; SESSION_ID_LEN], CloseReason)> = self
            .sessions
            .iter()
            .filter_map(|(sid, e)| {
                let idle_ok = idle.is_none_or(|t| now.duration_since(e.last_activity) < t);
                let life_ok = life.is_none_or(|t| now.duration_since(e.established_at) < t);
                if idle_ok && life_ok {
                    None
                } else {
                    let reason = if !life_ok {
                        CloseReason::LifetimeCap
                    } else {
                        CloseReason::IdleTimeout
                    };
                    Some((*sid, reason))
                }
            })
            .collect();
        for (sid, reason) in expired {
            if let Some(entry) = self.sessions.remove(&sid) {
                // B7: the peer is told before the session disappears.
                let close = self.begin_close(sid, entry, now);
                if !matches!(close, ManagerEvent::None) {
                    out.push(close);
                }
            }
            out.push(ManagerEvent::Closed { sid, reason });
        }
        out.extend(self.pending_closed.drain(..));
        out.extend(self.retransmit_closes(now));
        // Off-path fail-gate housekeeping: reclaim expired buckets.  This runs
        // at most once per `fail_window` and never on the packet path, so the
        // table's reclamation cost is independent of the packet rate (D24).
        self.fail_gate.sweep(now, &self.limits);
        out
    }

    /// Retransmit the pending `Close` packets whose backoff has elapsed.
    ///
    /// A `Close` that is never received strands the peer: on the client that
    /// means using a dead session for another lifetime-cap period.  The
    /// retransmissions are bounded (3 packets, 1 s / 2 s backoff) and the
    /// session is dropped — keys zeroized (D14) — once they are spent.
    fn retransmit_closes(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();
        let payload = [0u8; PAYLOAD_LEN];

        for pc in self.pending_closes.iter_mut() {
            if pc.attempts_left == 0 || now < pc.next_at {
                continue;
            }
            pc.attempts_left -= 1;
            pc.next_at = now + CLOSE_RETRANSMIT_BASE * 2;
            match pc.session.encrypt(MessageType::Close, &payload) {
                Ok(packet) => out.push(ManagerEvent::SendPacket {
                    packet,
                    peer: pc.peer,
                }),
                Err(_) => {
                    // The session can no longer encrypt: stop retrying.
                    pc.attempts_left = 0;
                }
            }
        }
        // Drop the sessions whose retransmission budget is spent.  The drop
        // zeroizes the session keys (D14).
        self.pending_closes
            .retain(|pc| pc.attempts_left > 0 && now < pc.next_at);
        out
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
    /// A handshake is in flight: the M1 was sent, the M2 is awaited.  No
    /// session exists yet.
    Handshaking,
    /// The session is **prepared but unconfirmed**: the M3 was transmitted, so
    /// the peer is *authenticated* (its ML-DSA-65 signature over TH2 was
    /// verified while the M2 was assembled) and the shared key material
    /// exists — but the key agreement is **not yet confirmed**, because no
    /// authenticated server packet has decrypted yet (D15).
    ///
    /// The distinction from [`ClientManagerState::Established`] is *key
    /// confirmation*, **not** authentication: the peer is already known to be
    /// genuine in this state.  Inbound application data is still gated (D15).
    Unconfirmed,
    /// The session is established **and confirmed**: an authenticated server
    /// packet has decrypted, so the D15 gate is open.
    Established,
}

/// One application payload buffered while the client has no session.
struct QueuedPayload {
    payload: Vec<u8>,
    queued_at: Instant,
}

/// Maximum number of application payloads buffered while no session exists.
///
/// The queue is explicitly bounded: an unbounded buffer would turn a stalled
/// tunnel into a memory exhaustion vector (D31 §7).
const OUTBOUND_QUEUE_CAP: usize = 64;
/// Maximum age of a buffered application payload.
///
/// A stale datagram must not be injected into the tunnel long after the
/// application sent it: the peer would answer a request whose context is
/// long gone (D31 §7).
const OUTBOUND_QUEUE_TTL: Duration = Duration::from_secs(2);
/// Number of session identifiers remembered for the non-reuse invariant.
const SID_HISTORY_CAP: usize = 64;
/// Number of torn-down session identifiers remembered (B12 guard).
///
/// The set is bounded like every other growing structure in this manager: it
/// grows by one 8-byte entry per teardown, and a teardown loop (a peer that
/// keeps vanishing) would otherwise grow it without bound.  The bound is far
/// above the number of teardowns a healthy deployment performs in a lifetime
/// (one per 24 h rotation), so the guard keeps its meaning in practice.
const RETIRED_SID_CAP: usize = 1024;

/// Client-side session manager: one handshake + one session, automatic
/// re-establishment (D16).  Pure with respect to I/O.
///
/// # The one-live-object invariant (D31 §2)
///
/// The manager never holds the handshake machine **and** a session at the
/// same time.  The machine exists only while the M2 is awaited; the moment
/// the M3 is emitted the manager drops it and takes ownership of
///
/// * the cached M3 fragments (for retransmission),
/// * the derived outcome (the session is created from it, **unconfirmed**),
/// * the M3 retransmission budget, and
/// * the prepared session.
///
/// This is what makes `begin_handshake()` safe to call after *every* teardown
/// path: the manager is either holding a handshake or holding a session,
/// never both, so the "handshake already running or session established"
/// guard can never be tripped by a legitimate transition.
pub struct ClientSessionManager {
    cfg: ClientConfig,
    limits: SessionLimits,
    /// The handshake machine — present **only** while `Handshaking`.
    hs: Option<ClientHandshake>,
    /// The prepared / established session — present only once the M3 was
    /// emitted.
    session: Option<WireSession>,
    /// D15 gate: has an authenticated server packet decrypted?
    ready: bool,
    peer: SocketAddr,
    /// When the current handshake attempt started (F6 deadline).
    hs_started: Option<Instant>,
    /// When the M3 was emitted: the origin of the session's lifetime clock
    /// and of the confirmation deadline.
    prepared_at: Option<Instant>,
    /// Cached M3 fragments, for byte-identical retransmission.
    m3_frags: Vec<WirePacket>,
    /// M3 retransmissions already made.
    m3_attempts: u32,
    /// The M3 retransmission budget is spent (a *policy* boundary, not a
    /// deadline — the confirmation deadline is the only deadline).
    m3_exhausted: bool,
    /// The next liveness-probe deadline.
    next_probe_at: Option<Instant>,
    /// Consecutive liveness rounds the peer failed to answer.
    rounds_unanswered: u32,
    /// When the last session slot was used (slot pacing).
    last_slot_at: Option<Instant>,
    /// Application payloads awaiting a session (bounded, TTL'd).
    out_queue: VecDeque<QueuedPayload>,
    /// Cumulative count of dropped application payloads.
    dropped_outbound: u64,
    /// When the last drop was logged (log rate limiting).
    last_drop_log: Option<Instant>,
    /// Every session identifier this manager has drawn (non-reuse, D13).
    used_sids: HashSet<[u8; SESSION_ID_LEN]>,
    /// Insertion order of `used_sids`, for the bounded history.
    used_order: VecDeque<[u8; SESSION_ID_LEN]>,
    /// Session identifiers whose session was torn down.  No later event may
    /// create a session for one of these (B12).
    retired_sids: HashSet<[u8; SESSION_ID_LEN]>,
    /// Insertion order of `retired_sids`, so the set can be bounded.
    retired_order: VecDeque<[u8; SESSION_ID_LEN]>,
    /// A teardown happened and no handshake is running: the driver must
    /// re-arm (D16).
    rearm_requested: bool,
    pending_closed: VecDeque<ManagerEvent>,
    /// Sessions whose `Close` notification is still being retransmitted.
    pending_closes: Vec<PendingClose>,
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
        // Cross-field limit invariants (fail closed — see `SessionLimits`).
        limits.validate()?;
        Ok(Self {
            cfg: cfg.clone(),
            limits,
            hs: None,
            session: None,
            ready: false,
            peer: cfg.server_addr,
            hs_started: None,
            prepared_at: None,
            m3_frags: Vec::new(),
            m3_attempts: 0,
            m3_exhausted: false,
            next_probe_at: None,
            rounds_unanswered: 0,
            last_slot_at: None,
            out_queue: VecDeque::new(),
            dropped_outbound: 0,
            last_drop_log: None,
            used_sids: HashSet::new(),
            used_order: VecDeque::new(),
            retired_sids: HashSet::new(),
            retired_order: VecDeque::new(),
            rearm_requested: false,
            pending_closed: VecDeque::new(),
            pending_closes: Vec::new(),
        })
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ClientManagerState {
        if self.session.is_some() {
            if self.ready {
                ClientManagerState::Established
            } else {
                ClientManagerState::Unconfirmed
            }
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

    /// The number of application payloads dropped since the manager was
    /// created (queue overflow + TTL expiry).
    pub fn outbound_dropped(&self) -> u64 {
        self.dropped_outbound
    }

    /// The number of application payloads currently buffered.
    pub fn outbound_queued(&self) -> usize {
        self.out_queue.len()
    }

    /// A teardown happened and no handshake is running: the driver must
    /// re-arm with a fresh handshake (D16).
    ///
    /// The driver calls this from its periodic tick as a backstop, so a
    /// transient failure in the immediate re-arm cannot leave the tunnel
    /// permanently down (D31 §2, B13).
    pub fn needs_rearm(&self) -> bool {
        self.rearm_requested && self.hs.is_none() && self.session.is_none()
    }

    /// Start (or restart) a handshake with a fresh client-chosen sid.
    ///
    /// Allowed only from `Idle`; the driver calls this at start and after
    /// every `Closed` event (D16 re-establishment).
    ///
    /// The sid is drawn from the CSPRNG and is guaranteed **never to have been
    /// used within the remembered window** (the last [`SID_HISTORY_CAP`]
    /// draws): a 64-bit collision is improbable, but its effect is not
    /// transient — the server silently drops a newcomer whose sid already
    /// names a live session, so the client would never establish (D31 §2,
    /// B15).  Independently of that window, a sid that ever *hosted* a session
    /// is refused outright by [`Self::on_m3_sent`], so a session is never
    /// recreated under a sid that already carried one.
    pub fn begin_handshake(&mut self) -> Result<ManagerEvent, ManagerError> {
        if self.hs.is_some() || self.session.is_some() {
            return Err(ManagerError::InvalidState(
                "handshake already running or session established",
            ));
        }
        let sid = self.fresh_sid()?;
        let hs = ClientHandshake::new(&self.cfg, sid)?;
        let packets = hs.m1_frags().to_vec();
        self.hs = Some(hs);
        self.hs_started = Some(Instant::now());
        self.ready = false;
        self.peer = self.cfg.server_addr;
        self.rearm_requested = false;
        Ok(ManagerEvent::Send {
            packets,
            peer: self.cfg.server_addr,
        })
    }

    /// Draw a session identifier this manager has never used.
    fn fresh_sid(&mut self) -> Result<[u8; SESSION_ID_LEN], ManagerError> {
        for _ in 0..8 {
            let sid = random_sid().map_err(ManagerError::Handshake)?;
            if self.used_sids.contains(&sid) {
                continue;
            }
            self.used_sids.insert(sid);
            self.used_order.push_back(sid);
            // Bounded history: the oldest identifiers are forgotten, so the
            // guarantee is "never reused *within the remembered window*".
            // With 64 remembered 64-bit identifiers the collision
            // probability of a redraw is 64/2^64 ≈ 2^-58 per draw.
            while self.used_order.len() > SID_HISTORY_CAP {
                if let Some(old) = self.used_order.pop_front() {
                    self.used_sids.remove(&old);
                }
            }
            return Ok(sid);
        }
        Err(ManagerError::InvalidState(
            "could not draw a fresh session identifier",
        ))
    }

    /// Process one received datagram.
    pub fn handle_datagram(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        if is_handshake_fragment(pkt) {
            // Handshake fragments reach the handshake machine **only while the
            // M2 is awaited**.  Once the M3 has been emitted the machine is
            // gone, so a late or duplicated M2 fragment is stale and dropped
            // (D31 §3).
            let peer = self.cfg.server_addr;
            let Some(hs) = self.hs.as_mut() else {
                return Ok(ManagerEvent::None);
            };
            match hs.handle_datagram(pkt)? {
                ClientEvent::Emit(packets) => Ok(ManagerEvent::Send { packets, peer }),
                ClientEvent::M3Sent { packets, outcome } => self.on_m3_sent(packets, outcome),
                ClientEvent::None => Ok(ManagerEvent::None),
            }
        } else {
            self.on_data_packet(pkt, from)
        }
    }

    /// The M3 was emitted: prepare the session and start the confirmation
    /// window.
    ///
    /// The session is created **once**, here, in an *unconfirmed* state.
    /// Creating it is safe: the master comes from an M2 whose server
    /// signature the client verified, so only the genuine server can decrypt
    /// what the client sends; and the server verifies the Finished MAC
    /// before committing the session, so a forged M3 cannot make the server
    /// commit (D31 §2).
    ///
    /// The session is **adopted, never recreated**: if one already exists the
    /// outcome is refused, because recreating it would reset the send
    /// counter and install a fresh replay window under a live sid (B12).
    fn on_m3_sent(
        &mut self,
        packets: Vec<WirePacket>,
        outcome: HandshakeOutcome,
    ) -> Result<ManagerEvent, ManagerError> {
        if self.session.is_some() {
            // Refuse: never swap the key material under a live sid.
            //
            // Unreachable under the one-live-object invariant (the manager
            // holds the handshake machine only *before* the M3, and the
            // session only *after* it), but the machine is retired here
            // anyway: leaving it in place would stall the client for the
            // whole M3 budget with no session to work with.
            warn!("refusing a second M3 outcome: the manager already holds a session");
            self.hs = None;
            self.hs_started = None;
            self.rearm_requested = true;
            return Ok(ManagerEvent::None);
        }
        // A sid whose session was torn down must never come back to life
        // (B12): a late event must not resurrect it with a fresh replay
        // window and a reset counter.
        if self.retired_sids.contains(&outcome.session_id) {
            return Ok(ManagerEvent::None);
        }
        let now = Instant::now();
        let session = WireSession::established(Role::Client, &outcome)?;
        self.session = Some(session);
        // The handshake machine is dropped here: from now on the manager
        // owns the M3 fragments, the outcome, the retransmission budget and
        // the prepared session — never the machine *and* a session at once.
        self.hs = None;
        self.hs_started = None;
        self.ready = false;
        self.prepared_at = Some(now);
        self.m3_frags = packets.clone();
        self.m3_attempts = 0;
        self.m3_exhausted = false;
        self.rounds_unanswered = 0;
        // The first *periodic* probe is due one interval from now: the
        // probe that rides along with the M3 burst below is the immediate
        // one.
        self.next_probe_at = Some(now + self.limits.liveness_probe_interval);

        // The M3 burst carries a liveness probe so the client can be
        // confirmed in ≈1 RTT instead of waiting out the retransmission
        // budget.  A probe that races ahead of the server's processing of
        // the M3 is dropped by the server (it has no session for that sid
        // yet) — which is exactly why the probe is repeated on every M3
        // retransmission and then periodically.
        let mut burst = packets;
        if let Some(probe) = self.build_probe() {
            burst.push(probe);
        }
        Ok(ManagerEvent::Send {
            packets: burst,
            peer: self.cfg.server_addr,
        })
    }

    /// Build an in-session liveness probe packet.
    fn build_probe(&mut self) -> Option<WirePacket> {
        let session = self.session.as_mut()?;
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = control::PROBE;
        session.encrypt(MessageType::Handshake, &payload).ok()
    }

    /// Process one inbound data-path packet.
    fn on_data_packet(
        &mut self,
        pkt: &WirePacket,
        from: SocketAddr,
    ) -> Result<ManagerEvent, ManagerError> {
        let Some(session) = self.session.as_ref() else {
            eprintln!("client on_data: no session");
            return Ok(ManagerEvent::None);
        };
        // B11: the sid is compared against the session's sid **before** the
        // decrypt.  A packet for an unknown sid must cost no AEAD work —
        // otherwise the previous session's cover traffic (195 pkt/s) would
        // cost a full AEAD attempt each, forever.
        let sid: [u8; SESSION_ID_LEN] = pkt.as_bytes()[1..1 + SESSION_ID_LEN]
            .try_into()
            .expect("fixed-size sid slice");
        if sid != *session.session_id() {
            eprintln!("client on_data: sid mismatch");
            return Ok(ManagerEvent::None);
        }
        let session = self.session.as_mut().expect("checked");
        let result: DataResult = match session.decrypt(pkt) {
            Ok(inner) => DataResult::Payload(inner),
            Err(SessionError::RekeyRequired) => {
                DataResult::SessionDead(CloseReason::NonceExhausted)
            }
            Err(SessionError::Codec(CodecError::Rejected)) => { eprintln!("client on_data: rejected"); DataResult::Rejected }
            Err(SessionError::Codec(CodecError::DecryptionFailed)) => { eprintln!("client on_data: decryption failed"); DataResult::Failed },
            Err(SessionError::Codec(CodecError::NonceExhausted { .. })) => {
                DataResult::SessionDead(CloseReason::NonceExhausted)
            }
            Err(SessionError::Codec(_)) => DataResult::Failed,
            Err(e) => return Err(ManagerError::Session(e)),
        };
        match result {
            DataResult::Payload(inner) => {
                // D15: the first authenticated server packet opens the gate.
                // A cover packet and an in-session control ack are
                // authenticated server packets too, so they confirm as well.
                self.ready = true;
                // The peer answered: the liveness round counter resets.
                self.rounds_unanswered = 0;
                // §10 roaming: rebind only on an authenticated packet.
                self.peer = from;
                eprintln!("client on_data: msg_type {:?}", inner.msg_type);
                match inner.msg_type {
                    // Cover is consumed silently (it is not application data).
                    MessageType::Close => {
                        // The peer told us it is closing: no `Close` in reply
                        // (it already knows), and the teardown is graceful.
                        self.teardown(CloseReason::PeerClosed, Instant::now(), false);
                        Ok(ManagerEvent::Closed {
                            sid,
                            reason: CloseReason::PeerClosed,
                        })
                    }
                    // In-session control message: consumed internally, never
                    // relayed, never charged.  The client is the *prober* in
                    // this version, so an ack needs no answer and a probe is
                    // ignored (no state change).
                    MessageType::Handshake => Ok(ManagerEvent::None),
                    _ => Ok(ManagerEvent::None),
                }
            }
            DataResult::SessionDead(reason) => {
                self.teardown(reason, Instant::now(), true);
                Ok(ManagerEvent::Closed { sid, reason })
            }
            // The client has no per-source failure gate (it has exactly one
            // peer), so both rejection classes are silent drops.
            DataResult::Failed | DataResult::Rejected => Ok(ManagerEvent::None),
            DataResult::Control(_) | DataResult::PeerClose => Ok(ManagerEvent::None),
        }
    }

    /// Handshake retransmit timer tick.
    ///
    /// Two regimes, one timer:
    ///
    /// * `Handshaking` — the machine retransmits the M1; when its budget is
    ///   spent the attempt fails explicitly (`Closed{HandshakeTimeout}`).
    /// * `Unconfirmed` — the manager retransmits the M3 (byte-identically)
    ///   under the *retransmission policy*, never as a deadline.  When the
    ///   budget is spent the retransmissions stop, but the session is kept:
    ///   the confirmation deadline (D15) is the only deadline on this path.
    pub fn on_timer(&mut self) -> Result<ManagerEvent, ManagerError> {
        if self.hs.is_some() {
            let peer = self.cfg.server_addr;
            let sid = *self.hs.as_ref().expect("checked").session_id();
            // The machine is borrowed only for the call; the borrow ends
            // before the match, so the arms can take `&mut self`.
            let event = {
                let hs = self.hs.as_mut().expect("checked");
                hs.on_timer()
            };
            return match event {
                Ok(ClientEvent::Emit(packets)) => Ok(ManagerEvent::Send { packets, peer }),
                Ok(ClientEvent::M3Sent { packets, outcome }) => {
                    // Unreachable under the one-live-object invariant (the
                    // machine is dropped the moment the M3 is emitted, so it
                    // can never be in `M3Sent` here).  It is *handled* rather
                    // than discarded: dropping the outcome would leave the
                    // client without a session for the whole M3 budget.
                    self.on_m3_sent(packets, outcome)
                }
                Ok(ClientEvent::None) => Ok(ManagerEvent::None),
                Err(HandshakeV2Error::Timeout) => {
                    // The M1 budget is spent: an explicit failure.
                    self.hs = None;
                    self.hs_started = None;
                    self.rearm_requested = true;
                    Ok(ManagerEvent::Closed {
                        sid,
                        reason: CloseReason::HandshakeTimeout,
                    })
                }
                Err(e) => Err(ManagerError::Handshake(e)),
            };
        }
        // Unconfirmed: retransmit the M3 (with a probe) while the budget
        // lasts.
        if self.session.is_none() || self.ready || self.m3_exhausted {
            return Ok(ManagerEvent::None);
        }
        if self.m3_attempts >= self.cfg.m3_max_attempts {
            // The budget is spent.  This is a *policy* boundary, not a
            // deadline: the session stays prepared and the client keeps
            // probing until the confirmation deadline fires.
            self.m3_exhausted = true;
            return Ok(ManagerEvent::None);
        }
        self.m3_attempts += 1;
        let mut packets = self.m3_frags.clone();
        if let Some(probe) = self.build_probe() {
            packets.push(probe);
        }
        Ok(ManagerEvent::Send {
            packets,
            peer: self.cfg.server_addr,
        })
    }

    /// Current retransmit delay, if a handshake or an M3 retransmission is
    /// pending (driver timer).
    pub fn next_delay(&self) -> Option<Duration> {
        if let Some(hs) = &self.hs {
            return Some(hs.next_delay());
        }
        if self.session.is_some() && !self.ready && !self.m3_exhausted {
            return Some(self.m3_delay());
        }
        None
    }

    /// The M3 retransmission delay: the jittered backoff the machine would
    /// have used.
    fn m3_delay(&self) -> Duration {
        crate::handshake_v2::backoff_delay(self.cfg.m1_retransmit_base, self.m3_attempts)
    }

    /// When the next **session slot** is due, if any.
    ///
    /// The session slot is the unit that keeps the observable packet rate
    /// invariant: a queued application payload is flushed *through* the slot
    /// (never as a burst) and a liveness probe *replaces* a cover packet
    /// (never adds to it).
    pub fn next_slot_delay(&self) -> Option<Duration> {
        self.session.as_ref()?;
        let now = Instant::now();
        let pace = self
            .last_slot_at
            .map(|l| l + self.limits.slot_interval)
            .unwrap_or(now);
        let mut next: Option<Instant> = None;
        if !self.out_queue.is_empty() {
            next = Some(pace);
        }
        if let Some(probe) = self.next_probe_at {
            let due = probe.max(pace);
            next = Some(next.map_or(due, |n| n.min(due)));
        }
        next.map(|n| n.saturating_duration_since(now))
    }

    /// Take the next session-slot payload, if one is due.
    ///
    /// Priority: a buffered application payload first (so the application's
    /// data is not starved by the heartbeat), then a due liveness probe.
    /// Nothing else: the caller emits cover traffic in that case, so the
    /// slot's packet rate is unchanged.
    pub fn take_slot(&mut self, now: Instant) -> Option<ManagerEvent> {
        self.session.as_ref()?;
        // Pacing: at most one slot packet per `slot_interval`.
        match self.last_slot_at {
            Some(last) if now.duration_since(last) < self.limits.slot_interval => return None,
            _ => {}
        }
        if let Some(ev) = self.take_queued_payload(now) {
            self.last_slot_at = Some(now);
            return Some(ev);
        }
        if let Some(ev) = self.take_probe(now) {
            self.last_slot_at = Some(now);
            return Some(ev);
        }
        None
    }

    /// Pop the oldest buffered application payload and encrypt it.
    fn take_queued_payload(&mut self, now: Instant) -> Option<ManagerEvent> {
        self.expire_queued(now);
        let queued = self.out_queue.pop_front()?;
        let mut padded = [0u8; PAYLOAD_LEN];
        let n = queued.payload.len().min(PAYLOAD_LEN);
        padded[..n].copy_from_slice(&queued.payload[..n]);
        // A local failure here is a session fault (e.g. nonce exhaustion),
        // which `send_encrypted` already turns into a `Closed` event.
        match self.send_encrypted(MessageType::Data, &padded) {
            Ok(ev) => Some(ev),
            Err(ManagerError::Session(e)) => {
                // Fail securely: the payload cannot be encrypted, so it is
                // lost — but the session fault is surfaced, never swallowed.
                warn!("outbound flush failed: {e}");
                Some(ManagerEvent::None)
            }
            Err(e) => {
                warn!("outbound flush failed: {e}");
                Some(ManagerEvent::None)
            }
        }
    }

    /// Build a liveness probe if one is due.
    fn take_probe(&mut self, now: Instant) -> Option<ManagerEvent> {
        let due = self.next_probe_at?;
        if now < due {
            return None;
        }
        // The deadline is advanced **unconditionally**, before the probe is
        // built: if the local session cannot encrypt (a session fault), the
        // slot must not spin at the poll rate waiting for a probe that will
        // never be built.
        self.next_probe_at = Some(now + self.limits.liveness_probe_interval);
        let packet = self.build_probe()?;
        // Only a *confirmed* session counts liveness rounds: before the
        // confirmation the single confirmation deadline governs.
        if self.ready {
            self.rounds_unanswered = self.rounds_unanswered.saturating_add(1);
        }
        let peer = self.peer;
        Some(ManagerEvent::SendPacket { packet, peer })
    }

    /// Whether the **confirmation** deadline (D15) has elapsed.
    ///
    /// Pre-confirmation only: a confirmed session is governed by the
    /// liveness rounds, not by this deadline.
    fn confirm_deadline_passed(&self, now: Instant) -> bool {
        if self.ready {
            return false;
        }
        match self.prepared_at {
            Some(prepared_at) => self
                .limits
                .confirm_timeout
                .is_some_and(|t| now.duration_since(prepared_at) >= t),
            None => false,
        }
    }

    /// Timer tick: the handshake deadline (F6), the confirmation deadline
    /// (D15), the post-confirmation liveness decision, the session lifetime
    /// cap (D16), the outbound queue's TTL, and the queued `Close`
    /// retransmissions.
    pub fn tick(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();

        // 1. The overall handshake deadline (F6).
        if self.hs.is_some() {
            let past_deadline = self
                .limits
                .handshake_timeout
                .is_some_and(|t| self.hs_started.is_some_and(|s| now.duration_since(s) >= t));
            if past_deadline {
                let sid = *self.hs.as_ref().expect("checked").session_id();
                self.hs = None;
                self.hs_started = None;
                self.rearm_requested = true;
                out.push(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::HandshakeTimeout,
                });
            }
        }

        // 2. The lifetime cap (D16).  The clock starts when the M3 was
        //    emitted, so the two endpoints' clocks differ by ≈1 RTT; the
        //    `Close` message is what makes the semantics exact.
        if let Some(prepared_at) = self.prepared_at {
            let past_cap = self
                .limits
                .lifetime_cap
                .is_some_and(|t| now.duration_since(prepared_at) >= t);
            // The session is taken from the manager by `teardown`, so the
            // identifier is read *before* the teardown.  A missing session is
            // not a panic: an inconsistent local state must fail securely
            // (skip the event), never abort the driver (AGENTS.md, "Invalid
            // state -> do not guess").
            if past_cap {
                self.close_now(CloseReason::LifetimeCap, now, &mut out);
            }
        }

        // 3. The confirmation deadline (D15) — the *only* deadline on the
        //    unconfirmed path.
        if self.confirm_deadline_passed(now) {
            // The peer is told, so the server does not accumulate an
            // orphan session for a client that never came up.
            self.close_now(CloseReason::NotConfirmed, now, &mut out);
        }

        // 4. The post-confirmation liveness decision: N *consecutive*
        //    unanswered rounds.  A single missed round is never fatal.
        if self.ready && self.rounds_unanswered >= self.limits.liveness_rounds {
            self.close_now(CloseReason::PeerUnresponsive, now, &mut out);
        }

        // 5. The outbound queue's per-entry TTL.
        if self.expire_queued(now) > 0 {
            out.push(ManagerEvent::OutboundDropped {
                dropped: self.dropped_outbound,
            });
        }

        out.extend(self.pending_closed.drain(..));
        out.extend(self.retransmit_closes(now));
        out
    }

    /// Encrypt application data into a `SendPacket` (zero-pads to the fixed
    /// slot).  Not gated on `is_ready` — see the module docs (D15 reading).
    ///
    /// When no session exists yet the payload is **buffered** in the bounded
    /// outbound queue instead of being silently dropped: the application
    /// asked for it, and losing it with no signal was a data-loss bug
    /// (D31 §7, B10).
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
        if self.session.is_none() {
            return self.enqueue(padded.to_vec());
        }
        self.send_encrypted(MessageType::Data, &padded)
    }

    /// Encrypt one overlay record as `MessageType::TunData` (client side).
    ///
    /// Requires an established session; when none exists the packet is
    /// dropped (the TUN read loop gates on `is_ready`).  The payload must
    /// be exactly one [`PAYLOAD_LEN`] slot.
    pub fn tun_outbound(&mut self, payload: &[u8]) -> Result<ManagerEvent, ManagerError> {
        if payload.len() != PAYLOAD_LEN {
            return Err(ManagerError::Session(SessionError::Codec(
                CodecError::WrongLength {
                    field: "payload",
                    expected: PAYLOAD_LEN,
                    got: payload.len(),
                },
            )));
        }
        if self.session.is_none() {
            return Ok(ManagerEvent::None);
        }
        let mut slot = [0u8; PAYLOAD_LEN];
        slot.copy_from_slice(payload);
        self.send_encrypted(MessageType::TunData, &slot)
    }

    /// Buffer an application payload for a session that does not exist yet.
    ///
    /// Overflow policy: **drop-newest**.  The oldest request is the one the
    /// application is still waiting for, so it is never the one discarded.
    fn enqueue(&mut self, payload: Vec<u8>) -> Result<ManagerEvent, ManagerError> {
        if self.out_queue.len() >= OUTBOUND_QUEUE_CAP {
            self.dropped_outbound = self.dropped_outbound.saturating_add(1);
            self.log_drop();
            return Ok(ManagerEvent::OutboundDropped {
                dropped: self.dropped_outbound,
            });
        }
        self.out_queue.push_back(QueuedPayload {
            payload,
            queued_at: Instant::now(),
        });
        Ok(ManagerEvent::None)
    }

    /// Drop the buffered payloads whose TTL has elapsed; returns how many
    /// were dropped.
    fn expire_queued(&mut self, now: Instant) -> u64 {
        let before = self.out_queue.len();
        self.out_queue
            .retain(|q| now.duration_since(q.queued_at) < OUTBOUND_QUEUE_TTL);
        let dropped = (before - self.out_queue.len()) as u64;
        if dropped > 0 {
            self.dropped_outbound = self.dropped_outbound.saturating_add(dropped);
            self.log_drop();
        }
        dropped
    }

    /// Log the drop counter, rate-limited: a stalled tunnel would otherwise
    /// log once per dropped payload.
    fn log_drop(&mut self) {
        let now = Instant::now();
        match self.last_drop_log {
            Some(last) if now.duration_since(last) < Duration::from_secs(1) => return,
            _ => {}
        }
        self.last_drop_log = Some(now);
        warn!(
            "outbound queue dropped application payloads (cumulative {})",
            self.dropped_outbound
        );
    }

    /// Encrypt a cover packet (Phase 7 shaper hook).
    pub fn cover_packet(&mut self) -> Result<ManagerEvent, ManagerError> {
        let sid = self.session_id().ok_or(ManagerError::NoSession)?;
        let session = self.session.as_mut().expect("checked");
        let peer = self.peer;
        match session.cover() {
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
            Err(SessionError::RekeyRequired) => {
                self.teardown(CloseReason::NonceExhausted, Instant::now(), true);
                Ok(ManagerEvent::Closed {
                    sid,
                    reason: CloseReason::NonceExhausted,
                })
            }
            Err(e) => Err(ManagerError::Session(e)),
        }
    }

    /// App-driven close: emit an encrypted `Close` packet (§8.4), drop the
    /// session, and queue `Closed{UserClosed}` for the next tick.
    ///
    /// The `Close` is retransmitted a bounded number of times: a
    /// fire-and-forget `Close` over UDP can be lost, which would leave the
    /// peer using a dead session.
    pub fn close(&mut self) -> Result<ManagerEvent, ManagerError> {
        let Some(sid) = self.session_id() else {
            return Ok(ManagerEvent::None);
        };
        let now = Instant::now();
        let close = self.teardown(CloseReason::UserClosed, now, true);
        self.pending_closed.push_back(ManagerEvent::Closed {
            sid,
            reason: CloseReason::UserClosed,
        });
        Ok(close.unwrap_or(ManagerEvent::None))
    }

    /// Tear the session down and report the closure to the driver.
    ///
    /// The identifier is read **before** the teardown, because the teardown
    /// takes the session out of the manager.  An inconsistent local state (a
    /// session that has already been torn down) is **not** a panic: the event
    /// is skipped and the driver continues (fail securely — AGENTS.md, "Invalid
    /// state -> do not guess").  A panic here would abort the driver and take
    /// the whole tunnel down.
    fn close_now(&mut self, reason: CloseReason, now: Instant, out: &mut Vec<ManagerEvent>) {
        let Some(sid) = self.session_id() else {
            return;
        };
        if let Some(ev) = self.teardown(reason, now, true) {
            out.push(ev);
        }
        out.push(ManagerEvent::Closed { sid, reason });
    }

    /// Retire a session identifier: no later event may create a session for
    /// it (B12).
    ///
    /// The set is bounded (`RETIRED_SID_CAP`), oldest-first, so a teardown
    /// loop cannot grow it without limit.  The eviction is safe because a
    /// retired sid can only be re-drawn after `SID_HISTORY_CAP` further
    /// handshakes, and the bound is far larger than that window.
    fn retire_sid(&mut self, sid: [u8; SESSION_ID_LEN]) {
        if !self.retired_sids.insert(sid) {
            return;
        }
        self.retired_order.push_back(sid);
        while self.retired_order.len() > RETIRED_SID_CAP {
            if let Some(old) = self.retired_order.pop_front() {
                self.retired_sids.remove(&old);
            }
        }
    }

    /// Tear the session down.
    ///
    /// The session is dropped (its keys zeroized on drop, D14) and its sid is
    /// retired: no later event may create a session for it (B12).  When
    /// `send_close` is set, an encrypted `Close` is emitted and its
    /// retransmissions are scheduled — the `Close` is the convergence
    /// mechanism for a teardown, so the peer is never left with a session it
    /// believes is alive (B7).
    fn teardown(
        &mut self,
        _reason: CloseReason,
        now: Instant,
        send_close: bool,
    ) -> Option<ManagerEvent> {
        let mut session = self.session.take()?;
        let sid = *session.session_id();
        self.ready = false;
        self.prepared_at = None;
        self.m3_frags.clear();
        self.m3_attempts = 0;
        self.m3_exhausted = true;
        self.next_probe_at = None;
        self.rounds_unanswered = 0;
        self.rearm_requested = true;
        self.retire_sid(sid);
        if !send_close {
            return None;
        }
        let payload = [0u8; PAYLOAD_LEN];
        let packet = session.encrypt(MessageType::Close, &payload).ok()?;
        let peer = self.peer;
        self.pending_closes.push(PendingClose {
            session,
            peer,
            attempts_left: CLOSE_RETRANSMIT_TOTAL - 1,
            next_at: now + CLOSE_RETRANSMIT_BASE,
        });
        Some(ManagerEvent::SendPacket { packet, peer })
    }

    /// Retransmit the pending `Close` packets whose backoff has elapsed.
    fn retransmit_closes(&mut self, now: Instant) -> Vec<ManagerEvent> {
        let mut out = Vec::new();
        let payload = [0u8; PAYLOAD_LEN];
        for pc in self.pending_closes.iter_mut() {
            if pc.attempts_left == 0 || now < pc.next_at {
                continue;
            }
            pc.attempts_left -= 1;
            pc.next_at = now + CLOSE_RETRANSMIT_BASE * 2;
            match pc.session.encrypt(MessageType::Close, &payload) {
                Ok(packet) => out.push(ManagerEvent::SendPacket {
                    packet,
                    peer: pc.peer,
                }),
                Err(_) => {
                    // The session can no longer encrypt: stop retrying.
                    pc.attempts_left = 0;
                }
            }
        }
        // Drop the sessions whose retransmission budget is spent.  The drop
        // zeroizes the session keys (D14).
        self.pending_closes
            .retain(|pc| pc.attempts_left > 0 && now < pc.next_at);
        out
    }

    fn send_encrypted(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<ManagerEvent, ManagerError> {
        let Some(session) = self.session.as_mut() else {
            return Err(ManagerError::NoSession);
        };
        let sid = *session.session_id();
        let peer = self.peer;
        match session.encrypt(msg_type, payload) {
            Ok(packet) => Ok(ManagerEvent::SendPacket { packet, peer }),
            Err(SessionError::RekeyRequired) => {
                self.teardown(CloseReason::NonceExhausted, Instant::now(), true);
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
                    ManagerEvent::OutboundDropped { .. } => {}
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
    // The session-slot arm carries the liveness probe and the outbound queue
    // flush while the cover schedule is not running (D31 §5).
    let slot_arm = client_slot_timer(manager, false);
    tokio::pin!(slot_arm);
    // The handshake retransmit timer is created ONCE and advanced only when it
    // fires (or the manager re-arms after a Close). Recomputing it from
    // `next_delay()` on *every* iteration lets continuous application data
    // (which keeps `app_rx` ready) indefinitely postpone the retransmit — and
    // with a passive server the retransmit budget is the only path to client
    // establishment (D15). Pinning the deadline preserves the retransmit
    // schedule under app load.
    let retransmit = client_retransmit_timer(manager);
    tokio::pin!(retransmit);
    // One warn per reset episode (an ICMP storm from a vanished peer would
    // otherwise spam at cover cadence until idle eviction reaps it).
    let mut reset_noticed = false;
    loop {
        // D15 confirmation signal (informational for the app; outbound is not
        // gated — see module docs).
        if manager.is_ready() && !was_ready {
            was_ready = true;
            cover_sched.start(Instant::now());
            cover_arm.set(cover_sleep(&cover_sched));
            // If the cover schedule is running, the cover arm owns the
            // session slot: the slot arm goes inert so a liveness probe
            // *replaces* a cover packet instead of adding to the observable
            // grid.  With cover disabled the cover arm never fires, so the
            // slot arm must stay live — otherwise the probe would stop.
            slot_arm.set(client_slot_timer(
                manager,
                cover_sched.next_deadline().is_some(),
            ));
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
                // ICMP port-unreachable / WSAECONNRESET: the server's port
                // vanished (it closed, crashed, or its network path reset).
                // Informational in UDP, with no source address attached; the
                // session itself is left to the manager's own timeout/retry
                // path (handshake retransmits, or the D16 re-establishment).
                // Local-transport error only: it must never tear down the
                // tunnel (M9B).
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
                    // The M1 retransmit deadline is stale the moment the M3
                    // is emitted, so the M3 schedule must be re-based on the
                    // transition.  It is re-armed **once**, at the
                    // transition — never on every datagram, or a busy peer
                    // would postpone the M3 retransmit indefinitely (the
                    // same defect class the pinned M1 timer exists to
                    // avoid).
                    let was_unconfirmed = manager.state() == ClientManagerState::Unconfirmed;
                    match manager.handle_datagram(&pkt, from)? {
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
                        cover_arm.set(cover_sleep(&cover_sched));
                        slot_arm.set(client_slot_timer(manager, false));
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                        rearm_client(transport, manager).await?;
                        retransmit.set(client_retransmit_timer(manager));
                    }
                    ManagerEvent::Established { .. } | ManagerEvent::None => {}
                    ManagerEvent::OutboundDropped { .. } => {}
                    }
                    // The M3 was just emitted: the M1 retransmit deadline is
                    // stale, so the M3 schedule is re-based on *now*.  The
                    // timer is re-armed **once**, at the transition — never on
                    // every datagram, or a busy peer would postpone the M3
                    // retransmit indefinitely (the defect class the pinned
                    // M1 timer exists to avoid).
                    if !was_unconfirmed && manager.state() == ClientManagerState::Unconfirmed {
                        retransmit.set(client_retransmit_timer(manager));
                    }
                    // The session may have just been prepared (the M3 was
                    // emitted): re-arm the session-slot arm so the periodic
                    // liveness probe starts flowing.  The delay is recomputed
                    // from the current time, so this cannot starve the arm.
                    slot_arm.set(client_slot_timer(manager, cover_sched.next_deadline().is_some()));
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
                                cover_arm.set(cover_sleep(&cover_sched));
                                slot_arm.set(client_slot_timer(manager, false));
                                app_tx
                                    .send(ManagerNotification::Closed { sid, reason })
                                    .await
                                    .map_err(|_| ManagerError::AppClosed)?;
                                rearm_client(transport, manager).await?;
                                retransmit.set(client_retransmit_timer(manager));
                            }
                            // The payload was buffered (no session yet) or
                            // was dropped by the bounded queue: the
                            // application is told, so the data is never lost
                            // silently (D31 §7, B10).
                            Ok(ManagerEvent::OutboundDropped { dropped }) => {
                                app_tx
                                    .send(ManagerNotification::OutboundDropped { dropped })
                                    .await
                                    .map_err(|_| ManagerError::AppClosed)?;
                            }
                        Ok(_) => {
                            // The payload may have been buffered: re-arm the
                            // session-slot arm so the flush starts flowing.
                            slot_arm.set(client_slot_timer(
                                manager,
                                cover_sched.next_deadline().is_some(),
                            ));
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
                    cover_arm.set(cover_sleep(&cover_sched));
                    slot_arm.set(client_slot_timer(manager, false));
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
                    match ev {
                        ManagerEvent::SendPacket { packet, peer } => {
                            transport.send_to(&packet, peer).await?;
                        }
                        ManagerEvent::Closed { sid, reason } => {
                            was_ready = false;
                            cover_sched.stop();
                            cover_arm.set(cover_sleep(&cover_sched));
                            slot_arm.set(client_slot_timer(manager, false));
                            app_tx
                                .send(ManagerNotification::Closed { sid, reason })
                                .await
                                .map_err(|_| ManagerError::AppClosed)?;
                            rearm_client(transport, manager).await?;
                            retransmit.set(client_retransmit_timer(manager));
                        }
                        ManagerEvent::OutboundDropped { dropped } => {
                            app_tx
                                .send(ManagerNotification::OutboundDropped { dropped })
                                .await
                                .map_err(|_| ManagerError::AppClosed)?;
                        }
                        _ => {}
                    }
                }
                // Backstop: a teardown that left the manager idle (a failed
                // re-arm, say) must not leave the tunnel down forever
                // (D31 §2, B13).
                if manager.needs_rearm() {
                    rearm_client(transport, manager).await?;
                    retransmit.set(client_retransmit_timer(manager));
                }
            }
            _ = &mut slot_arm => {
                // The cover schedule is not running: this arm owns the
                // session slot, so the liveness probe and the outbound queue
                // flush still flow.
                // NB: the body uses a match, never an if-let: tokio's select
                // macro parses an if at the top of an arm as its
                // precondition clause, so an if-let inside an arm body is a
                // macro syntax error.
                match manager.take_slot(Instant::now()) {
                    Some(ManagerEvent::SendPacket { packet, peer }) => {
                        transport.send_to(&packet, peer).await?;
                    }
                    Some(ManagerEvent::Closed { sid, reason }) => {
                        was_ready = false;
                        cover_sched.stop();
                        cover_arm.set(cover_sleep(&cover_sched));
                        slot_arm.set(client_slot_timer(manager, false));
                        app_tx
                            .send(ManagerNotification::Closed { sid, reason })
                            .await
                            .map_err(|_| ManagerError::AppClosed)?;
                        rearm_client(transport, manager).await?;
                        retransmit.set(client_retransmit_timer(manager));
                    }
                    _ => {}
                }
                slot_arm.set(client_slot_timer(manager, cover_sched.next_deadline().is_some()));
            }
            _ = &mut cover_arm => {
                if cover_sched.on_deadline(Instant::now()) {
                    // One packet per slot: a buffered application payload or
                    // a due liveness probe *replaces* this cover packet, so
                    // the observable grid rate is unchanged (D19/D22).
                    let ev = match manager.take_slot(Instant::now()) {
                        Some(ev) => Some(ev),
                        None => match manager.cover_packet() {
                            Ok(ev) => Some(ev),
                            // Session not (yet) established: never churn over it.
                            Err(ManagerError::NoSession) => None,
                            // A cover emission is real encrypted traffic: any other
                            // fault is a session fault and must surface (fail-secure).
                            Err(e) => return Err(e),
                        },
                    };
                    match ev {
                        Some(ManagerEvent::SendPacket { packet, peer }) => {
                            transport.send_to(&packet, peer).await?;
                        }
                        Some(ManagerEvent::Closed { sid, reason }) => {
                            was_ready = false;
                            cover_sched.stop();
                            cover_arm.set(cover_sleep(&cover_sched));
                            slot_arm.set(client_slot_timer(manager, false));
                            app_tx
                                .send(ManagerNotification::Closed { sid, reason })
                                .await
                                .map_err(|_| ManagerError::AppClosed)?;
                            rearm_client(transport, manager).await?;
                            retransmit.set(client_retransmit_timer(manager));
                        }
                        _ => {}
                    }
                }
                cover_arm.set(cover_sleep(&cover_sched));
            },
        }
    }
}

/// The session-slot arm: when the cover schedule owns the slot (cover
/// enabled and the session confirmed), this arm is inert so a liveness probe
/// *replaces* a cover packet instead of adding to the observable grid.
fn client_slot_timer(manager: &ClientSessionManager, cover_owns_slot: bool) -> tokio::time::Sleep {
    if cover_owns_slot {
        return tokio::time::sleep(Duration::MAX);
    }
    manager
        .next_slot_delay()
        .map(tokio::time::sleep)
        .unwrap_or_else(|| tokio::time::sleep(Duration::MAX))
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
///
/// A failed re-arm is **never** fatal to the tunnel: the manager's own
/// `needs_rearm()` backstop retries on the next tick, so a transient
/// refusal cannot leave the tunnel down (D31 §2, B13).  The old code
/// propagated the error with `?`, which made the whole client process exit
/// and the tunnel stay down.
async fn rearm_client<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ClientSessionManager,
) -> Result<(), ManagerError> {
    match manager.begin_handshake() {
        Ok(ManagerEvent::Send { packets, peer }) => {
            for p in &packets {
                transport.send_to(p, peer).await?;
            }
        }
        Ok(_) => {}
        Err(ManagerError::InvalidState(_)) => {
            // The manager still holds a handshake or a session: the re-arm
            // is not needed yet.  The tick backstop will try again.
        }
        Err(e) => {
            // The re-arm failed for any other reason (a local CSPRNG fault,
            // for instance).  It must **never** kill the driver: the tunnel
            // staying up with a retrying handshake is strictly better than
            // the process exiting and the tunnel going down (B13).  The
            // `needs_rearm()` backstop retries on the next tick.
            warn!("client re-arm failed, will retry on the next tick: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
// Tests intentionally mutate `SessionLimits` fields after `Default::default()`.
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::codec::{Direction, MAX_PACKET_NONCE, PACKET_SIZE, PacketHeader, VERSION_LEN};
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

    /// The `Closed` events in a tick result.
    ///
    /// A tick may also carry `SendPacket` events: when a session is evicted
    /// (lifetime cap, idle timeout) the endpoint sends an encrypted `Close`
    /// to the peer **before** dropping the session, so the peer converges
    /// without relying on synchronised clocks (D31 §6, B7).
    fn closed_events(events: &[ManagerEvent]) -> Vec<([u8; SESSION_ID_LEN], CloseReason)> {
        events
            .iter()
            .filter_map(|e| match e {
                ManagerEvent::Closed { sid, reason } => Some((*sid, *reason)),
                _ => None,
            })
            .collect()
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
    ///
    /// The client machine's success signal is the M3 emission: the derived
    /// outcome is available from the machine once the M3 was sent (D31 §2).
    fn client_established(
        client: &mut ClientHandshake,
        _cc: &ClientConfig,
    ) -> (WireSession, HandshakeOutcome) {
        let out = client.outcome().expect("the M3 was emitted").clone();
        let ws = WireSession::established(Role::Client, &out).expect("ws");
        (ws, out)
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
            if let ClientEvent::M3Sent { packets, .. } = client.handle_datagram(f).expect("cli") {
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
            if let ClientEvent::M3Sent { packets, .. } = attacker.handle_datagram(f).expect("cli") {
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

        // Idle past the timeout evicts (and tells the peer with a `Close`).
        let events = manager.tick(Instant::now() + Duration::from_secs(2 * 3600));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].0, SID);
        assert_eq!(closes[0].1, CloseReason::IdleTimeout);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ManagerEvent::SendPacket { .. })),
            "the eviction must tell the peer with an encrypted Close (D31 §6)"
        );
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
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].1, CloseReason::LifetimeCap);
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

        // D31 §6 (B7): the app-driven close tells the peer with an encrypted
        // `Close` before the session disappears, so the peer does not keep
        // using a dead session until its idle timeout.
        match manager.close_session(&SID).unwrap() {
            ManagerEvent::SendPacket { packet, peer } => {
                assert_eq!(peer, CLIENT_ADDR);
                assert_eq!(packet.parse_header().unwrap().session_id, SID);
            }
            other => panic!("expected SendPacket(Close), got {other:?}"),
        }
        // The `Closed{UserClosed}` notification is queued for the next tick
        // (single-event invariant).
        let closes = closed_events(&manager.tick(Instant::now()));
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].0, SID);
        assert_eq!(closes[0].1, CloseReason::UserClosed);
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
        let mut burst = Vec::new();
        for f in &m2 {
            if let ManagerEvent::Send { packets, .. } =
                manager.handle_datagram(f, from).expect("cli")
            {
                burst = packets;
            }
        }
        // The M3 burst carries the M3 fragment *and* the in-session liveness
        // probe (D31 §5): only the handshake fragment goes to the server
        // machine.
        let m3: Vec<WirePacket> = burst
            .iter()
            .filter(|p| is_handshake_fragment(p))
            .cloned()
            .collect();
        assert_eq!(m3.len(), M3_FRAG_COUNT as usize);
        let mut outcome = None;
        for f in &m3 {
            if let ServerEvent::Complete(out) = server.handle_datagram(f, from).unwrap() {
                outcome = Some(out);
            }
        }
        let outcome = outcome.expect("server completes at M3");
        // The client is `Unconfirmed`: the M3 was emitted, so the session
        // exists and the peer is *authenticated* (its signature over TH2 was
        // verified), but the key agreement is not yet confirmed — no
        // authenticated server packet has decrypted yet (D15).
        assert!(matches!(manager.state(), ClientManagerState::Unconfirmed));
        assert!(
            !manager.is_ready(),
            "D15: gate closed until the first authenticated server packet"
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
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        let (cs, reason) = closes[0];
        assert_eq!(cs, sid);
        assert_eq!(reason, CloseReason::NotConfirmed);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ManagerEvent::SendPacket { .. })),
            "the teardown must tell the peer with an encrypted Close (D31 §6)"
        );
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
        assert!(matches!(manager.state(), ClientManagerState::Unconfirmed));
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
            if let ClientEvent::M3Sent { packets: pkts, .. } = client.handle_datagram(&pkt).unwrap()
            {
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

        // App data client → server.  The client also emits liveness probes
        // and M3 retransmissions, so skip everything that is not
        // application data (D31 §5).
        data_tx.send(vec![0x77; 64]).await.unwrap();
        let inner = loop {
            let (pkt, from) = server_t.recv().await.unwrap();
            assert_eq!(from, CLIENT_ADDR);
            match srv_ws.decrypt(&pkt) {
                Ok(inner) if inner.msg_type == MessageType::Data => break inner,
                _ => {}
            }
        };
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
        assert_eq!(manager.state(), ClientManagerState::Unconfirmed);
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
        assert_eq!(manager.state(), ClientManagerState::Unconfirmed);
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
        // D24: junk naming an unowned sid performs no decryption, so it
        // allocates no fail bucket at all.
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "garbage must not allocate fail buckets"
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

    /// D24: a datagram whose sid names no live session must not allocate or
    /// touch a fail-gate bucket, so spoofed-source junk volume cannot populate
    /// the table at all.  `max_fail_buckets` (8 here) is no longer the binding
    /// constraint on this path — the bucket count is exactly zero.
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
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "unknown-sid junk must allocate no fail bucket (got {})",
            manager.fail_bucket_count()
        );
    }

    // -----------------------------------------------------------------------
    // Session-accounting invariant: server Established/Closed pairing
    // -----------------------------------------------------------------------

    /// Mirrors the server driver's `ManagerEvent` → `ManagerNotification`
    /// relay (run_server_manager): `Established`/`Closed` are relayed in the
    /// order produced, `tick()` output is appended as it comes, everything
    /// else is silent.  Session accounting in the forwarding app is an
    /// add/sub pair over this stream, so it is only correct while the two
    /// events are strictly paired — every `Closed` preceded by exactly one
    /// `Established` for the same sid, and every `Established` eventually
    /// matched by exactly one `Closed`.
    #[derive(Default)]
    struct NotificationRelay {
        /// Sids announced `Established` to the app and not yet retired by a
        /// `Closed`, in announcement order.  The forwarding app's session
        /// counter is `Established - Closed`, so it stays correct exactly while
        /// a `Closed` never arrives for a sid outside this set.
        live: Vec<[u8; SESSION_ID_LEN]>,
        /// Every `Established` seen, so the test can assert full pairing.
        established: Vec<[u8; SESSION_ID_LEN]>,
        /// Every `Closed` seen, in order.
        closed: Vec<[u8; SESSION_ID_LEN]>,
    }

    impl NotificationRelay {
        /// Feed one `ManagerEvent` exactly as the driver relays it.
        fn event(&mut self, ev: ManagerEvent) {
            match ev {
                ManagerEvent::Established { sid, .. } => {
                    assert!(
                        !self.live.contains(&sid),
                        "Established twice without a Closed for {sid:02x?}"
                    );
                    self.live.push(sid);
                    self.established.push(sid);
                }
                ManagerEvent::Closed { sid, .. } => {
                    // A Closed for a sid that was never announced to the app
                    // would underflow any Established-minus-Closed counter.
                    let pos =
                        self.live.iter().position(|s| *s == sid).unwrap_or_else(|| {
                            panic!("Closed for never-established sid {sid:02x?}")
                        });
                    self.live.remove(pos);
                    self.closed.push(sid);
                }
                _ => {}
            }
        }

        fn tick(&mut self, events: Vec<ManagerEvent>) {
            for ev in events {
                self.event(ev);
            }
        }
    }

    /// The driver relays `Established` in the same `handle_datagram` call that
    /// returns `Closed{Capacity}` to `pending_closed`; the queued `Closed` is
    /// drained by the next `tick`.  Ordering is therefore preserved and every
    /// evicted sid was announced — the accounting add/sub pair stays balanced.
    #[test]
    fn server_capacity_eviction_is_paired_after_established() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_sessions = 2;
        let mut manager = server_manager(limits);
        let mut relay = NotificationRelay::default();

        let mut live: Vec<([u8; SESSION_ID_LEN], WireSession)> = Vec::new();
        // 3 iterations is the ceiling: the server's per-source DoS limiter
        // (`rate_limit_burst` = 16 per window) charges exactly 2 tokens for one
        // full 4-fragment M1 (fragment 0 allocation + completion) and 1 for the
        // M3, so three handshakes cost 9 of 16 tokens.  A 4th would still fit;
        // the loop is bounded by what the pairing assertion below needs (one
        // eviction at `max_sessions` = 2), not by the budget.  That budget is
        // D13's / D24's accounting, not a test artefact.
        for i in 0..3u8 {
            let sid = [i; SESSION_ID_LEN];
            let mut client = ClientHandshake::new(&cc, sid).unwrap();
            let mut m2 = Vec::new();
            for f in client.m1_frags() {
                if let ManagerEvent::Send { packets, .. } =
                    manager.handle_datagram(f, CLIENT_ADDR).unwrap()
                {
                    m2 = packets;
                }
            }
            assert_eq!(m2.len(), M2_FRAG_COUNT as usize, "full M2 emitted");
            let mut m3 = Vec::new();
            for f in &m2 {
                if let ClientEvent::M3Sent { packets: pkts, .. } =
                    client.handle_datagram(f).unwrap()
                {
                    m3 = pkts;
                }
            }
            for f in &m3 {
                // Relay EVERY event the driver would relay, in the same order.
                relay.event(manager.handle_datagram(f, CLIENT_ADDR).unwrap());
            }
            let (ws, _out) = client_established(&mut client, &cc);
            live.push((sid, ws));
        }
        // Drain the capacity `Closed` events queued during the last handshake,
        // exactly as the driver does (receive path, then `tick`).
        relay.tick(manager.tick(Instant::now()));

        assert_eq!(manager.session_count(), 2);
        assert_eq!(relay.live.len(), 2, "relay must track the live table");
        assert!(
            !relay.closed.is_empty(),
            "capacity evictions must be reported"
        );
        assert_eq!(
            relay.established.len() - relay.closed.len(),
            relay.live.len(),
            "Established minus Closed must equal the live sessions"
        );
    }

    /// Full server lifecycle sweep: every close path (capacity eviction, idle
    /// and lifetime eviction, peer Close, nonce exhaustion, app-driven close)
    /// must emit exactly one `Closed` per `Established` — none before, none
    /// after, none twice.
    #[test]
    fn server_lifecycle_events_are_strictly_paired() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_sessions = 2;
        limits.idle_timeout = Some(Duration::from_secs(3600));
        limits.lifetime_cap = Some(Duration::from_secs(7200));
        let mut manager = server_manager(limits);
        let mut relay = NotificationRelay::default();

        // 1. Peer Close.
        let sid_a = [0x01; SESSION_ID_LEN];
        let (_c_a, mut ws_a) = established_client_session(&mut manager, &cc, sid_a);
        relay.event(ManagerEvent::Established {
            sid: sid_a,
            peer: CLIENT_ADDR,
        });
        let pkt = ws_a
            .encrypt(MessageType::Close, &[0u8; PAYLOAD_LEN])
            .unwrap();
        relay.event(manager.handle_datagram(&pkt, CLIENT_ADDR).unwrap());

        // 2. Idle + lifetime eviction of a second session.
        let sid_b = [0x02; SESSION_ID_LEN];
        established_client_session(&mut manager, &cc, sid_b);
        relay.event(ManagerEvent::Established {
            sid: sid_b,
            peer: CLIENT_ADDR,
        });
        relay.tick(manager.tick(Instant::now() + Duration::from_secs(7200)));

        // 3. Capacity eviction: a third handshake at max_sessions=2 evicts
        //    the least-recently-active survivor, queued for the next tick.
        let sid_c = [0x03; SESSION_ID_LEN];
        established_client_session(&mut manager, &cc, sid_c);
        relay.event(ManagerEvent::Established {
            sid: sid_c,
            peer: CLIENT_ADDR,
        });
        relay.tick(manager.tick(Instant::now() + Duration::from_secs(7200)));

        // 4. App-driven close of the survivor.
        let sid_d = [0x04; SESSION_ID_LEN];
        let (mut client_d, _ws_d) = established_client_session(&mut manager, &cc, sid_d);
        relay.event(ManagerEvent::Established {
            sid: sid_d,
            peer: CLIENT_ADDR,
        });
        let _ = client_established(&mut client_d, &cc);
        relay.event(manager.close_session(&sid_d).unwrap());

        // 5. Nonce exhaustion (D16) via an authentic boundary packet.  The
        //    boundary packet must be built from the master that established
        //    THIS sid, so the handshake outcome is driven directly here rather
        //    than via `established_client_session` (which discards it).
        let sid_e = [0x05; SESSION_ID_LEN];
        let mut client_e = server_established(&mut manager, &cc, sid_e, CLIENT_ADDR);
        let (_ws_e, out_e) = client_established(&mut client_e, &cc);
        relay.event(ManagerEvent::Established {
            sid: sid_e,
            peer: CLIENT_ADDR,
        });
        let boundary = exhaustion_packet_c2s(&out_e.master, sid_e);
        relay.event(manager.handle_datagram(&boundary, CLIENT_ADDR).unwrap());

        // Table is empty again.
        assert_eq!(manager.session_count(), 0);
        relay.tick(manager.tick(Instant::now()));
        assert!(relay.live.is_empty(), "no session may remain live");
        assert_eq!(
            relay.closed.len(),
            relay.established.len(),
            "every Established must be matched by exactly one Closed"
        );
        for sid in &relay.established {
            assert_eq!(
                relay.closed.iter().filter(|c| *c == sid).count(),
                1,
                "sid {sid:02x?} must be closed exactly once"
            );
        }
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
                ClientManagerState::Unconfirmed,
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
        assert_eq!(manager.state(), ClientManagerState::Unconfirmed);
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
                if let ClientEvent::M3Sent { packets, .. } =
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
        assert_eq!(cm.state(), ClientManagerState::Unconfirmed);

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
            ClientManagerState::Unconfirmed,
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
            manager.fail_bucket_count() == 0,
            "unknown-sid flood must allocate no fail bucket (got {})",
            manager.fail_bucket_count()
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
    /// must not grow across close cycles.  Under D24 lookup-first, a fully
    /// legitimate establish→Close cycle performs no decryption failure at all,
    /// so it leaves *zero* buckets — the table is only ever materialised by a
    /// real AEAD failure.
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
            assert_eq!(
                manager.fail_bucket_count(),
                0,
                "iter {i}: a legitimate lifecycle must allocate no fail bucket"
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
        let closes = closed_events(&evs);
        assert_eq!(closes.len(), 1, "idle timeout must fire once at +15s");
        assert_eq!(closes[0].0, SID);
        assert_eq!(closes[0].1, CloseReason::IdleTimeout);
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

    // -----------------------------------------------------------------------
    // D24 — data-path failure gate: what is counted, and what is bounded
    // -----------------------------------------------------------------------

    /// Build a version-valid data-path datagram naming `sid`, addressed to
    /// reach the data path (byte 9 ∉ {0x10,0x20,0x30}) with no AEAD
    /// relationship to any session.
    fn d24_data_packet(sid: [u8; SESSION_ID_LEN]) -> WirePacket {
        let mut bytes = [0u8; PACKET_SIZE];
        bytes[0] = crate::codec::PROTOCOL_VERSION;
        bytes[1..1 + SESSION_ID_LEN].copy_from_slice(&sid);
        bytes[VERSION_LEN + SESSION_ID_LEN] = 0x00; // MessageType::Data
        WirePacket::from_bytes(&bytes).expect("fixed-size")
    }

    /// A datagram naming an unowned sid performs no decryption and must not
    /// allocate a fail-gate bucket — for ANY source, including 4,096 distinct
    /// ports on one IP address (the source key is the full `SocketAddr`, port
    /// included).  Before D24 each such source minted a full-token bucket,
    /// saturating and holding the table indefinitely at ~409 packets/window.
    #[test]
    fn d24_unknown_sid_never_allocates_a_fail_bucket() {
        let (_, sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 4096;
        let mut manager = ServerSessionManager::new(&sc, limits).expect("manager");
        let pkt = d24_data_packet([0xEE; SESSION_ID_LEN]); // no session owns this sid

        // 4096 distinct sources on a single IP, one datagram each: the exact
        // shape that used to fill the table to its cap.
        for port in 0..4096u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 1024 + port));
            assert!(
                matches!(
                    manager.handle_datagram(&pkt, from).unwrap(),
                    ManagerEvent::None
                ),
                "unknown-sid datagram from {from} must be silent"
            );
        }
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "unknown-SID traffic must allocate no fail-gate bucket, got {}",
            manager.fail_bucket_count()
        );
        assert_eq!(manager.session_count(), 0, "and no session state");
    }

    /// The same 4,096-source volume, repeated many times, still allocates
    /// nothing: the invariant is about the miss path, not about a one-shot
    /// table that happens to be empty.
    #[test]
    fn d24_unknown_sid_flood_never_allocates_a_fail_bucket() {
        let (_, sc) = shared_configs();
        let mut manager =
            ServerSessionManager::new(&sc, SessionLimits::default()).expect("manager");
        let pkt = d24_data_packet([0xEE; SESSION_ID_LEN]);
        for round in 0..8u16 {
            for port in 0..512u16 {
                let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 1024 + port));
                let _ = manager.handle_datagram(&pkt, from).unwrap();
            }
            assert_eq!(
                manager.fail_bucket_count(),
                0,
                "round {round}: unknown-SID flood allocated {} buckets",
                manager.fail_bucket_count()
            );
        }
    }

    /// The gate MUST still apply to a KNOWN sid whose AEAD fails — lookup-first
    /// reorders the gate, it does not remove it.  With `fail_burst = 2`, the
    /// first two tampered packets for a live session are decrypted-and-failed
    /// (each consuming one token), and the third is dropped without decrypt:
    /// after exhaustion even a VALID packet from that source yields `None`.
    #[test]
    fn d24_known_sid_aead_failure_is_still_gated() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 2;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();

        // Before any failure the gate must let legitimate traffic through.
        assert!(matches!(
            manager.handle_datagram(&good, CLIENT_ADDR).unwrap(),
            ManagerEvent::AppData { .. }
        ));
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "a success must not allocate a bucket"
        );

        // Two real AEAD failures: each is decrypted-and-rejected and charges a
        // token.  A bucket now exists — the failure path is its only writer.
        for i in 0..2 {
            assert!(matches!(
                manager
                    .handle_datagram(&tampered(&good), CLIENT_ADDR)
                    .unwrap(),
                ManagerEvent::None
            ));
            assert_eq!(
                manager.fail_bucket_count(),
                1,
                "failure {i} must create exactly one bucket"
            );
        }

        // Budget exhausted: a VALID packet is now dropped without decrypt.
        // This is the whole point of the gate and proves it was not ungated.
        let fresh = ws.encrypt(MessageType::Data, &[0x11; PAYLOAD_LEN]).unwrap();
        assert!(
            matches!(
                manager.handle_datagram(&fresh, CLIENT_ADDR).unwrap(),
                ManagerEvent::None
            ),
            "a gated source must be dropped without decrypt even on a valid packet"
        );
        // The session itself survives — the gate is per-source, not a kill.
        assert_eq!(
            manager.session_count(),
            1,
            "gating must not remove the session"
        );
    }

    /// D24 (corrected): the fail-gate table is bounded by
    /// `max_fail_buckets` — **not** by the live-session population.
    ///
    /// Two facts are pinned here:
    ///
    /// 1. *Lookup-first still holds*: traffic naming an unowned sid allocates
    ///    no bucket at all, whatever the source diversity.
    /// 2. *One bucket per failing source*: the table tracks the sources that
    ///    actually failed an AEAD decrypt, not the sessions.
    #[test]
    fn d24_fail_gate_state_is_bounded_by_the_configured_cap() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_sessions = 4;
        limits.max_fail_buckets = 4096;
        let mut manager = server_manager(limits);

        // Four live sessions, each from its own source address.
        let mut sessions = Vec::new();
        for i in 0..4u8 {
            let sid = [i; SESSION_ID_LEN];
            let from = SocketAddr::from((Ipv4Addr::new(203, 0, 113, i), 5000));
            let mut client = server_established(&mut manager, &cc, sid, from);
            let (ws, _out) = client_established(&mut client, &cc);
            sessions.push((ws, from));
        }
        assert_eq!(manager.session_count(), 4, "four sessions established");

        // 2,000 distinct hostile sources, all naming an unknown sid.
        let unknown = d24_data_packet([0xEE; SESSION_ID_LEN]);
        for port in 0..2000u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 9), 1024 + port));
            let _ = manager.handle_datagram(&unknown, from).unwrap();
        }
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "unknown-sid traffic must allocate no fail-gate bucket"
        );

        // Every live session's source now fails AEAD once.
        for (ws, from) in sessions.iter_mut() {
            let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
            assert!(matches!(
                manager.handle_datagram(&tampered(&good), *from).unwrap(),
                ManagerEvent::None
            ));
        }
        assert_eq!(
            manager.fail_bucket_count(),
            sessions.len(),
            "one bucket per failing source ({}), got {}",
            sessions.len(),
            manager.fail_bucket_count()
        );

        // And one more round of hostile churn does not grow it.
        for port in 0..2000u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 1024 + port));
            let _ = manager.handle_datagram(&unknown, from).unwrap();
        }
        assert_eq!(
            manager.fail_bucket_count(),
            sessions.len(),
            "hostile churn must not grow the fail-gate table"
        );
    }

    /// D24 (corrected): ONE live session is enough to drive the fail-gate
    /// table to its cap.
    ///
    /// The sid is cleartext in every packet header, so a party that observes a
    /// single packet learns a live sid and can then present AEAD-failing
    /// traffic from a fresh source port per datagram.  This is the direct
    /// counterexample to the superseded D24 claim that the table was "bounded
    /// by the active session population": the table tracks *failing sources*,
    /// and its bound is `max_fail_buckets`.
    #[test]
    fn d24_one_live_session_can_drive_the_table_to_the_cap() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 64;
        let mut manager = server_manager(limits);
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert_eq!(manager.session_count(), 1, "exactly one live session");

        // 200 distinct source ports, each presenting one AEAD-failing
        // datagram that names that session's sid.
        for port in 0..200u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 30), 1024 + port));
            assert!(matches!(
                manager.handle_datagram(&tampered(&good), from).unwrap(),
                ManagerEvent::None
            ));
        }
        assert_eq!(
            manager.fail_bucket_count(),
            64,
            "one live session is enough to reach the configured cap"
        );
        assert!(
            manager.fail_bucket_count() > manager.session_count(),
            "the table is NOT bounded by the live-session population"
        );
    }

    /// The AEAD-failure hot path performs NO table scan, and the cap
    /// eviction visits exactly ONE table entry (O(1)), not the whole table.
    ///
    /// `FailGate::table_visits` counts every fail-gate table entry visited by
    /// an operation that is not a plain hash lookup (cap evictions and sweep
    /// passes).  The pre-fix path ran a full `retain` on every failing packet
    /// once the table exceeded 32 entries, and a full `min_by_key` on every
    /// insert at the cap.
    ///
    /// The assertion is structural (a counter), not a timing measurement.
    #[test]
    fn d24_repeated_aead_failure_does_no_table_scan() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 64;
        let mut manager = server_manager(limits);
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        let src = |port: u16| SocketAddr::from((Ipv4Addr::new(198, 51, 100, 40), port));

        // Fill the table to its cap.  No eviction is needed yet, so no table
        // entry is visited at all.
        for port in 0..64u16 {
            let _ = manager
                .handle_datagram(&tampered(&good), src(1024 + port))
                .unwrap();
        }
        assert_eq!(manager.fail_bucket_count(), 64, "the table is at the cap");
        assert_eq!(
            manager.fail_gate.table_visits, 0,
            "filling the table must not scan it"
        );

        // One more source: the cap is enforced by sacrificing exactly ONE
        // entry (the oldest-inserted one).  A scan-based eviction would visit
        // all 64.
        let _ = manager
            .handle_datagram(&tampered(&good), src(2048))
            .unwrap();
        assert_eq!(
            manager.fail_gate.table_visits, 1,
            "the cap eviction must visit exactly one table entry"
        );
        assert_eq!(manager.fail_bucket_count(), 64, "the cap still holds");

        // 1,000 further AEAD failures from an already-tracked source.  The
        // source's budget runs out after `fail_burst` of them and the gate
        // then drops its packets before the decrypt; either way the packet
        // path must not visit a single table entry.
        let tracked = src(1024 + 63); // still tracked: it was not the victim
        for _ in 0..1000 {
            let _ = manager.handle_datagram(&tampered(&good), tracked).unwrap();
        }
        assert_eq!(
            manager.fail_gate.table_visits, 1,
            "repeated AEAD failure must not visit a single table entry"
        );
        assert_eq!(
            manager.fail_gate.sweeps, 0,
            "the expiry sweep must never run on the packet path"
        );
        assert_eq!(manager.fail_bucket_count(), 64, "the table did not grow");

        // The sacrificed source (the oldest-inserted one) is re-inserted on
        // its next failure, which costs exactly one further eviction — the
        // documented FIFO victim policy, and still O(1) per packet.
        let _ = manager
            .handle_datagram(&tampered(&good), src(1024))
            .unwrap();
        assert_eq!(
            manager.fail_gate.table_visits, 2,
            "re-inserting an evicted source costs exactly one eviction"
        );
        assert_eq!(manager.fail_bucket_count(), 64, "the cap still holds");
    }

    /// The unknown-sid path touches no fail-gate state at all: no bucket is
    /// allocated and no table entry is visited.
    #[test]
    fn d24_unknown_sid_path_visits_no_fail_gate_entry() {
        let (_, sc) = shared_configs();
        let mut manager =
            ServerSessionManager::new(&sc, SessionLimits::default()).expect("manager");
        let pkt = d24_data_packet([0xEE; SESSION_ID_LEN]);
        for port in 0..1000u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 45), 1024 + port));
            let _ = manager.handle_datagram(&pkt, from).unwrap();
        }
        assert_eq!(manager.fail_bucket_count(), 0, "no bucket allocated");
        assert_eq!(
            manager.fail_gate.table_visits, 0,
            "the unknown-sid path must not visit a fail-gate table entry"
        );
    }

    /// Cap-boundary behaviour is defined and pinned: the table never exceeds
    /// `max_fail_buckets`, and at the cap the *oldest-inserted* tracked
    /// source is sacrificed (its budget is reset).  Nothing about the
    /// session, the wire, or the other sources' budgets changes.
    #[test]
    fn d24_cap_boundary_behaviour_is_defined() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 2;
        limits.max_fail_buckets = 4;
        let mut manager = server_manager(limits.clone());
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        let src = |port: u16| SocketAddr::from((Ipv4Addr::new(198, 51, 100, 70), port));

        // Four distinct failing sources fill the table to its cap.
        for port in 0..4u16 {
            let _ = manager
                .handle_datagram(&tampered(&good), src(1024 + port))
                .unwrap();
        }
        assert_eq!(manager.fail_bucket_count(), 4, "the table is at the cap");

        // The oldest-inserted source exhausts its budget and is gated.
        let oldest = src(1024);
        let _ = manager.handle_datagram(&tampered(&good), oldest).unwrap();
        assert!(
            !manager.fail_gate.peek(oldest, Instant::now(), &limits),
            "the exhausted source is gated"
        );

        // A fifth source arrives: the cap is enforced by sacrificing the
        // oldest-inserted tracked source — O(1), one table entry visited.
        let newcomer = src(2000);
        let _ = manager.handle_datagram(&tampered(&good), newcomer).unwrap();
        assert_eq!(manager.fail_bucket_count(), 4, "the cap still holds");
        assert_eq!(
            manager.fail_gate.table_visits, 1,
            "the eviction visits exactly one table entry"
        );
        assert!(
            manager.fail_gate.peek(oldest, Instant::now(), &limits),
            "the sacrificed source's budget is reset"
        );

        // Sustained churn never grows the table, and the session survives.
        for port in 0..500u16 {
            let _ = manager
                .handle_datagram(&tampered(&good), src(3000 + port))
                .unwrap();
            assert!(
                manager.fail_bucket_count() <= 4,
                "the table stays within the cap"
            );
        }
        assert_eq!(manager.session_count(), 1, "the session survives");
    }

    /// Expiry is a property of the *accounting*: a source that has not failed
    /// for a full `fail_window` gets a fresh budget, whether or not the
    /// physical entry has been reclaimed yet.
    #[test]
    fn d24_expired_budget_is_refreshed_for_the_source() {
        let (_, sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 2;
        let mut manager = ServerSessionManager::new(&sc, limits.clone()).expect("manager");
        let t0 = Instant::now();
        let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 50), 1234));

        // No bucket yet: the gate allows the packet and allocates nothing.
        assert!(manager.fail_gate.peek(from, t0, &limits));
        assert_eq!(manager.fail_bucket_count(), 0, "peek must not allocate");

        // Two real failures exhaust the budget.
        manager.fail_gate.consume(from, t0, &limits);
        manager.fail_gate.consume(from, t0, &limits);
        assert!(
            !manager.fail_gate.peek(from, t0, &limits),
            "the budget is exhausted"
        );

        // One window later the budget is refreshed (logical expiry) and the
        // source is allowed again.
        let t1 = t0 + limits.fail_window;
        assert!(
            manager.fail_gate.peek(from, t1, &limits),
            "an expired budget refills"
        );
        manager.fail_gate.consume(from, t1, &limits);
        assert!(
            manager.fail_gate.peek(from, t1, &limits),
            "a refilled budget has a full burst again"
        );
        manager.fail_gate.consume(from, t1, &limits);
        assert!(
            !manager.fail_gate.peek(from, t1, &limits),
            "the refilled budget is charged again"
        );
    }

    /// Stale entries are physically reclaimed by the off-path sweep, at most
    /// one pass per `fail_window`, on the driver's tick (virtual clock).
    #[test]
    fn d24_expired_buckets_are_reclaimed_by_the_sweep() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.max_fail_buckets = 64;
        let mut manager = server_manager(limits.clone());
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        for port in 0..8u16 {
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 60), 1024 + port));
            let _ = manager.handle_datagram(&tampered(&good), from).unwrap();
        }
        assert_eq!(manager.fail_bucket_count(), 8, "8 failing sources tracked");

        let t0 = Instant::now();
        // A tick inside the window does not reclaim: the sweep is amortized to
        // at most one pass per `fail_window`.
        let _ = manager.tick(t0);
        assert_eq!(manager.fail_bucket_count(), 8, "no sweep inside the window");
        assert_eq!(manager.fail_gate.sweeps, 0, "no sweep pass yet");

        // One window later the next tick reclaims every stale entry.
        let _ = manager.tick(t0 + limits.fail_window + Duration::from_secs(1));
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "stale entries are reclaimed"
        );
        assert_eq!(manager.fail_gate.sweeps, 1, "exactly one sweep pass");

        // And a further tick inside the next window does not sweep again.
        let _ = manager.tick(t0 + limits.fail_window + Duration::from_secs(2));
        assert_eq!(
            manager.fail_gate.sweeps, 1,
            "the sweep is amortized to one pass per window"
        );
        assert_eq!(manager.session_count(), 1, "the session is unaffected");
    }

    /// Per-source accounting (D24): a source that exhausts its budget is
    /// gated, and a different source is not starved by it.  Successes never
    /// consume budget and never allocate a bucket.
    #[test]
    fn d24_per_source_budget_is_not_shared_between_sources() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 2;
        let mut manager = server_manager(limits.clone());
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        let a = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 80), 1024));
        let b = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 81), 1024));

        // Source A fails twice: its budget is exhausted.
        for _ in 0..2 {
            assert!(matches!(
                manager.handle_datagram(&tampered(&good), a).unwrap(),
                ManagerEvent::None
            ));
        }
        assert!(
            !manager.fail_gate.peek(a, Instant::now(), &limits),
            "A is gated"
        );
        assert_eq!(manager.fail_bucket_count(), 1, "only A is tracked");

        // A is dropped without decrypt work — even for a VALID packet.
        assert!(matches!(
            manager.handle_datagram(&good, a).unwrap(),
            ManagerEvent::None
        ));

        // Source B is untouched: its valid packet still decrypts and the
        // session roams to it (§10).  A's exhaustion must not starve B.
        assert!(
            matches!(
                manager.handle_datagram(&good, b).unwrap(),
                ManagerEvent::AppData { .. }
            ),
            "B must not be starved by A"
        );
        assert_eq!(
            manager.fail_bucket_count(),
            1,
            "B's success must not allocate a bucket"
        );
    }

    /// NAT / shared-source fairness (D24): per-source semantics are preserved
    /// deliberately.  Two clients behind ONE source address share a budget,
    /// but consumption is failure-only, so the honest client's successful
    /// traffic can never drain the shared budget or starve it.
    #[test]
    fn d24_shared_source_client_is_not_starved_by_another_client() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 4;
        let mut manager = server_manager(limits);

        // Two sessions, both bound to the SAME source address (one NAT egress).
        let shared = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 40000));
        let sid_a = [0xA1; SESSION_ID_LEN];
        let sid_b = [0xB2; SESSION_ID_LEN];
        let mut ca = server_established(&mut manager, &cc, sid_a, shared);
        let (mut ws_a, _oa) = client_established(&mut ca, &cc);
        let mut cb = server_established(&mut manager, &cc, sid_b, shared);
        let (mut ws_b, _ob) = client_established(&mut cb, &cc);
        assert_eq!(manager.session_count(), 2, "both sessions share one source");

        // Client B generates failures — burning the SHARED budget.
        for i in 0..4u8 {
            let bad = ws_b
                .encrypt(MessageType::Data, &[(i + 1); PAYLOAD_LEN])
                .unwrap();
            assert!(matches!(
                manager.handle_datagram(&tampered(&bad), shared).unwrap(),
                ManagerEvent::None
            ));
        }
        assert_eq!(
            manager.fail_bucket_count(),
            1,
            "both clients share a single bucket"
        );

        // Client A, honest, is still gated (the known consequence of
        // per-source accounting under a shared address).
        let a1 = ws_a
            .encrypt(MessageType::Data, &[0x01; PAYLOAD_LEN])
            .unwrap();
        assert!(matches!(
            manager.handle_datagram(&a1, shared).unwrap(),
            ManagerEvent::None
        ));

        // But client A's *successful* traffic never drains a budget.  This is
        // deterministic and timing-free: A has already been charged nothing,
        // and no amount of honest traffic can push a fresh source below a full
        // burst.  Deliver many successes from a fresh source (session A roams
        // to it on the first authenticated decrypt, §10) and show every one
        // of them is delivered — none is gated, and no bucket is created.
        let solo = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 51), 40000));
        for i in 0..256u16 {
            let good = ws_a
                .encrypt(MessageType::Data, &[(i as u8); PAYLOAD_LEN])
                .unwrap();
            assert!(
                matches!(
                    manager.handle_datagram(&good, solo).unwrap(),
                    ManagerEvent::AppData { .. }
                ),
                "honest packet {i} must deliver: success never consumes budget"
            );
        }
        assert_eq!(
            manager.fail_bucket_count(),
            1,
            "256 successes from a fresh source must create no bucket"
        );
        // Client A has roamed to `solo`, so B's failures now hit a fresh key.
        let _ = &mut ws_b;
    }

    /// Hostile source churn must not consume the legitimate client's budget and
    /// must not grow the fail-gate table.  The legitimate handshake is driven
    /// from a source the hostile traffic never used, and the hostile sids are
    /// distinct, so the only shared budget key is by construction not spent.
    #[test]
    fn d24_hostile_source_churn_does_not_block_a_legitimate_handshake() {
        let (cc, mut sc) = shared_configs();
        sc.rate_limit_burst = 64; // ample for one legit handshake (M1 2 + M3 1)
        sc.max_pending = 8;
        let mut manager =
            ServerSessionManager::new(&sc, SessionLimits::default()).expect("manager");

        // A legitimate session is established first and must remain serviceable.
        let (_c, mut ws) = established_client_session(&mut manager, &cc, SID);
        assert_eq!(manager.session_count(), 1, "legit client established");

        // Hostile churn: partial M1s (fragment 0 only), each with a distinct sid
        // and source, saturating the pending table at `max_pending`.  Each is
        // charged against its OWN source budget, never the legitimate one.
        for i in 0..64u16 {
            let sid = [0xC0u8.wrapping_add(i as u8); SESSION_ID_LEN];
            let client = ClientHandshake::new(&cc, sid).expect("client");
            let frag0 = client.m1_frags()[0].clone();
            let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 1024 + i));
            let _ = manager.handle_datagram(&frag0, from).unwrap();
        }
        assert_eq!(
            manager.pending_handshakes(),
            sc.max_pending,
            "pending table is capped at max_pending"
        );

        // The legitimate client's traffic is untouched: 256 authentic data
        // packets all deliver.  Hostile sources spent their own budgets.
        for i in 0..256u16 {
            let good = ws
                .encrypt(MessageType::Data, &[(i as u8); PAYLOAD_LEN])
                .unwrap();
            assert!(
                matches!(
                    manager.handle_datagram(&good, CLIENT_ADDR).unwrap(),
                    ManagerEvent::AppData { .. }
                ),
                "legit packet {i} must survive hostile source churn"
            );
        }
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "handshake churn and successful data must allocate no fail buckets"
        );
        assert_eq!(manager.session_count(), 1, "the legit session survives");
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
            if let ClientEvent::M3Sent { packets: pkts, .. } = client.handle_datagram(&pkt).unwrap()
            {
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

    // No cover cadence and a single ResetOnce arm would otherwise leave the
    // driver blocked in `recv()` after its one reset — indistinguishable from
    // a torn-down driver at the observation points below, and a race against
    // any transport signal from the preceding test.
    /// Pre-armed one-shot reset. Fires on the first `recv` *of the driver* and
    /// thereafter blocks (like `MemoryTransport` on an idle channel) — so the
    /// only way out of the driver is the app channel closing.
    struct ResetThenIdle {
        inner: MemoryTransport,
    }

    impl HandshakeTransport for ResetThenIdle {
        async fn send_to(
            &mut self,
            packet: &WirePacket,
            peer: SocketAddr,
        ) -> Result<(), HandshakeV2Error> {
            self.inner.send_to(packet, peer).await
        }

        async fn recv(&mut self) -> Result<(WirePacket, SocketAddr), HandshakeV2Error> {
            match self.inner.recv().await {
                // The ICMP signal and the next real packet can be queued
                // together; reset first, so the driver is observed in exactly
                // the state a Windows socket reaches.
                Err(_) | Ok(_) if RESET_ARMED.swap(false, Ordering::SeqCst) => {
                    Err(HandshakeV2Error::TransportReset)
                }
                r => r,
            }
        }
    }

    static RESET_ARMED: AtomicBool = AtomicBool::new(false);

    /// N-2 regression: the same ICMP port-unreachable / WSAECONNRESET signal
    /// reaching the *client* transport must NOT terminate the client manager.
    /// The driver returns Err only if the reset escapes the select!; a driver
    /// that returns stays alive until the app channel closes.  The signal is
    /// delivered before any session exists (a vanished server at start-up),
    /// so it cannot be a side effect of the preceding exchange.
    #[tokio::test]
    async fn client_driver_survives_transport_reset() {
        let (cc, _sc) = shared_configs();
        let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).unwrap();
        let (client_t, _server_t, _guard) = wired_transports();
        let (app_tx, mut app_rx) = mpsc::channel(64);
        let (data_tx, data_rx) = mpsc::channel(64);
        RESET_ARMED.store(true, Ordering::SeqCst);
        let mut cli = ResetThenIdle { inner: client_t };
        let mut driver = tokio::spawn(async move {
            run_client_manager(&mut cli, &mut manager, app_tx, data_rx, no_cover()).await
        });

        // The driver keeps running across the reset.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !driver.is_finished(),
            "client driver terminated on a recoverable transport reset"
        );
        assert!(app_rx.try_recv().is_err(), "no session may be established");

        // The driver is only reachable through its result: it must still be
        // alive after the reset, and its only way out is the app channel
        // closing (Ok) — never the reset itself (Err).
        drop(data_tx);
        let joined = tokio::time::timeout(Duration::from_secs(2), &mut driver)
            .await
            .expect("client driver hung after a transport reset")
            .expect("client driver panicked");
        assert!(
            joined.is_ok(),
            "client driver returned Err on a recoverable transport reset: {joined:?}"
        );
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
            // The client emits its `Close` (and the close retransmissions)
            // and its M3 retransmissions before it re-arms, so skip
            // everything that is not an M1 fragment (D31 §6).
            let mut m1_seen = 0u8;
            while m1_seen < M1_FRAG_COUNT {
                let (pkt, from) = server_t.recv().await.unwrap();
                assert_eq!(from, CLIENT_ADDR);
                if pkt.as_bytes()[crate::codec::VERSION_LEN + SESSION_ID_LEN]
                    != crate::handshake_v2::HS_TYPE_CLIENT_HELLO
                {
                    continue;
                }
                m1_seen += 1;
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

        // Application data continues, both directions.  Skip the liveness
        // probes and the M3 retransmissions the client also emits.
        data_tx.send(vec![0x77; 64]).await.unwrap();
        let inner = loop {
            let (pkt, from) = server_t.recv().await.unwrap();
            assert_eq!(from, CLIENT_ADDR);
            match srv_ws2.decrypt(&pkt) {
                Ok(inner) if inner.msg_type == MessageType::Data => break inner,
                _ => {}
            }
        };
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
            if let ClientEvent::M3Sent { packets: pkts, .. } = client.handle_datagram(&pkt).unwrap()
            {
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
            if let ClientEvent::M3Sent { packets: pkts, .. } =
                client2.handle_datagram(&pkt).unwrap()
            {
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

    // -----------------------------------------------------------------------
    // D31 — the client lifecycle, liveness and the lifetime cap
    // -----------------------------------------------------------------------

    /// A client manager and a server manager, wired through their public
    /// APIs.  `ServerSessionManager` is the *real* peer: it answers the
    /// in-session liveness probe with an ack, so the client's confirmation
    /// path is genuinely exercised.
    fn client_server_pair(limits: SessionLimits) -> (ClientSessionManager, ServerSessionManager) {
        let (cc, sc) = shared_configs();
        (
            ClientSessionManager::new(&cc, limits.clone()).expect("client manager"),
            ServerSessionManager::new(&sc, limits).expect("server manager"),
        )
    }

    /// Start a handshake and return the M1 fragments.
    fn start_handshake(client: &mut ClientSessionManager) -> Vec<WirePacket> {
        match client.begin_handshake().unwrap() {
            ManagerEvent::Send { packets, .. } => packets,
            other => panic!("expected Send(M1), got {other:?}"),
        }
    }

    /// Complete a handshake between the two managers: the M2 the server
    /// answers with, the client's M3 burst and the server's replies (the
    /// ack for the liveness probe).
    fn finish_handshake(
        client: &mut ClientSessionManager,
        server: &mut ServerSessionManager,
        m1: &[WirePacket],
    ) -> (Vec<WirePacket>, Vec<WirePacket>) {
        let mut m2 = Vec::new();
        for f in m1 {
            if let ManagerEvent::Send { packets, .. } =
                server.handle_datagram(f, CLIENT_ADDR).unwrap()
            {
                m2 = packets;
            }
        }
        assert_eq!(
            m2.len(),
            M2_FRAG_COUNT as usize,
            "the server answers the M1"
        );
        let mut burst = Vec::new();
        for f in &m2 {
            if let ManagerEvent::Send { packets, .. } =
                client.handle_datagram(f, SERVER_ADDR).unwrap()
            {
                burst = packets;
            }
        }
        assert_eq!(
            burst.len(),
            M3_FRAG_COUNT as usize + 1,
            "the M3 burst carries the M3 fragment and the liveness probe"
        );
        let mut established = false;
        let mut replies = Vec::new();
        for f in &burst {
            match server.handle_datagram(f, CLIENT_ADDR).unwrap() {
                ManagerEvent::Established { .. } => established = true,
                ManagerEvent::SendPacket { packet, .. } => replies.push(packet),
                _ => {}
            }
        }
        assert!(established, "the server must establish at the M3");
        (burst, replies)
    }

    /// Run one handshake between the two managers.
    ///
    /// Returns the client's M3 burst (the M3 fragment plus the liveness
    /// probe) and the server's replies (the ack for the probe).
    fn handshake_pair(
        client: &mut ClientSessionManager,
        server: &mut ServerSessionManager,
    ) -> (Vec<WirePacket>, Vec<WirePacket>) {
        let m1 = start_handshake(client);
        finish_handshake(client, server, &m1)
    }

    /// D31 §2 (test 1): the session is created at M3 transmission, in the
    /// **unconfirmed** state; the first authenticated server packet confirms
    /// it.
    #[test]
    fn client_m3_sent_yields_unconfirmed_then_established() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, replies) = handshake_pair(&mut client, &mut server);

        // The session exists, but the key agreement is not confirmed: the
        // peer is authenticated (its signature over TH2 was verified) while
        // the client has not yet decrypted an authenticated server packet.
        assert!(client.session_id().is_some(), "the M3 creates the session");
        assert!(matches!(client.state(), ClientManagerState::Unconfirmed));
        assert!(!client.is_ready(), "D15: the gate is still closed");

        // The server answered the probe: that is an authenticated server
        // packet, so it confirms the key agreement and opens the gate.
        assert_eq!(replies.len(), 1, "the server answers the liveness probe");
        match client.handle_datagram(&replies[0], SERVER_ADDR).unwrap() {
            ManagerEvent::None => {}
            other => panic!("the ack is consumed internally, got {other:?}"),
        }
        assert!(client.is_ready(), "the ack opens the D15 gate");
        assert!(matches!(client.state(), ClientManagerState::Established));
    }

    /// D31 §7 (test 2): application data pushed before the session exists is
    /// **buffered**, not lost, and it is delivered once the session is up.
    #[test]
    fn application_data_before_confirmation_is_buffered_not_lost() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        for i in 0..3u8 {
            let ev = client.app_outbound(&[i; 16]).unwrap();
            assert!(
                matches!(ev, ManagerEvent::None),
                "the payload is buffered, not dropped: {ev:?}"
            );
        }
        assert_eq!(client.outbound_queued(), 3);
        assert_eq!(client.outbound_dropped(), 0, "nothing is dropped yet");

        handshake_pair(&mut client, &mut server);

        // The queue is flushed through the session slot, one payload per
        // slot (rate-paced, never a burst).
        let mut now = Instant::now();
        let mut flushed = 0usize;
        for _ in 0..3 {
            now += client.limits.slot_interval;
            match client.take_slot(now) {
                Some(ManagerEvent::SendPacket { packet, .. }) => {
                    match server.handle_datagram(&packet, CLIENT_ADDR).unwrap() {
                        ManagerEvent::AppData { inner, .. } => {
                            assert_eq!(inner.msg_type, MessageType::Data);
                            flushed += 1;
                        }
                        other => panic!("expected AppData, got {other:?}"),
                    }
                }
                other => panic!("expected a flushed payload, got {other:?}"),
            }
        }
        assert_eq!(flushed, 3, "every buffered payload is delivered");
        assert_eq!(client.outbound_queued(), 0);
        assert_eq!(client.outbound_dropped(), 0);
    }

    /// D31 §5 (test 3): a lost, delayed, duplicated or reordered confirmation
    /// is handled without a state change that breaks the lifecycle.
    #[test]
    fn confirmation_lost_delayed_duplicated_and_reordered() {
        // (a) LOST: the client stays unconfirmed until the confirmation
        //     deadline, then fails closed with `NotConfirmed`.
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, _replies) = handshake_pair(&mut client, &mut server);
        assert!(!client.is_ready());
        // The ack never arrives.
        let events = client.tick(Instant::now() + Duration::from_secs(31));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].1, CloseReason::NotConfirmed);
        assert!(matches!(client.state(), ClientManagerState::Idle));

        // (b) DELAYED: the ack arrives after several probe rounds — it still
        //     confirms.
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, replies) = handshake_pair(&mut client, &mut server);
        let mut now = Instant::now();
        for _ in 0..3 {
            now += Duration::from_secs(6);
            let _ = client.take_slot(now); // a probe goes out, unanswered
        }
        client.handle_datagram(&replies[0], SERVER_ADDR).unwrap();
        assert!(client.is_ready(), "the late ack still confirms");

        // (c) DUPLICATED: the same ack twice — the second is a replay and is
        //     rejected silently, with no state change.
        let before = client.state();
        let ev = client.handle_datagram(&replies[0], SERVER_ADDR).unwrap();
        assert!(
            matches!(ev, ManagerEvent::None),
            "a replay is a silent drop"
        );
        assert_eq!(client.state(), before, "a replay changes no state");
        assert!(client.is_ready(), "a replay does not close the gate");

        // (d) REORDERED: a data packet that arrives before the ack confirms
        //     the session just the same.
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, _replies) = handshake_pair(&mut client, &mut server);
        // The server's application data reaches the client before the ack.
        let data = server
            .app_outbound(&client.session_id().expect("sid"), &[0x42; PAYLOAD_LEN])
            .unwrap();
        let ManagerEvent::SendPacket { packet, peer } = data else {
            panic!("expected SendPacket");
        };
        assert_eq!(peer, CLIENT_ADDR);
        match client.handle_datagram(&packet, SERVER_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("expected AppData, got {other:?}"),
        }
        assert!(client.is_ready(), "a data packet confirms too");
    }

    /// D31 §2 (test 4): the M3 retransmission budget is a *policy*, not a
    /// deadline; when it is spent the client never reports success, and the
    /// confirmation deadline produces an explicit `NotConfirmed` with a safe
    /// cleanup and a retry on a **fresh** sid.
    #[test]
    fn m3_budget_exhaustion_is_never_a_success_and_retries_fresh() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, _replies) = handshake_pair(&mut client, &mut server);
        let first_sid = client.session_id().expect("session");

        // Spend the M3 retransmission budget.
        let mut retransmits = 0u32;
        loop {
            match client.on_timer().unwrap() {
                ManagerEvent::Send { .. } => retransmits += 1,
                ManagerEvent::None => break,
                other => panic!("unexpected {other:?}"),
            }
            assert!(retransmits <= 16, "the budget must be bounded");
        }
        assert!(
            retransmits > 0,
            "the M3 must be retransmitted at least once"
        );
        // The budget is spent: the client is still unconfirmed, and the
        // session is still there (the budget is not a deadline).
        assert!(matches!(client.state(), ClientManagerState::Unconfirmed));
        assert!(!client.is_ready());

        // The confirmation deadline is the only deadline: it fires and the
        // client fails closed.
        let events = client.tick(Instant::now() + Duration::from_secs(31));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].1, CloseReason::NotConfirmed);
        assert_eq!(closes[0].0, first_sid);
        // Safe cleanup: the session is gone, the keys are zeroized (D14).
        assert!(client.session_id().is_none());
        assert!(matches!(client.state(), ClientManagerState::Idle));

        // The retry uses a fresh sid: never a reused one (D13, B15).
        match client.begin_handshake().unwrap() {
            ManagerEvent::Send { packets, .. } => {
                let fresh: [u8; SESSION_ID_LEN] = packets[0].as_bytes()[1..9].try_into().unwrap();
                assert_ne!(fresh, first_sid, "the retry must use a fresh sid");
            }
            other => panic!("expected Send(M1), got {other:?}"),
        }
    }

    /// D31 §5 (test 5): with cover disabled, a dead peer is detected within
    /// the liveness bound (N consecutive unanswered rounds) — the client
    /// never sits in a black hole.
    #[test]
    fn dead_peer_is_detected_within_the_liveness_bound() {
        let mut limits = SessionLimits::default();
        limits.liveness_probe_interval = Duration::from_secs(1);
        limits.liveness_rounds = 3;
        let (mut client, mut server) = client_server_pair(limits);
        let (_burst, replies) = handshake_pair(&mut client, &mut server);
        // The session is confirmed: the peer answered the probe.
        client.handle_datagram(&replies[0], SERVER_ADDR).unwrap();
        assert!(client.is_ready());

        // The peer is now dead: no answer ever arrives.
        let mut now = Instant::now();
        for _ in 0..3 {
            now += Duration::from_secs(2);
            let _ = client.take_slot(now); // a probe goes out, unanswered
        }
        // The liveness decision is made on N consecutive unanswered rounds.
        let events = client.tick(now + Duration::from_secs(1));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1, "the dead peer must be detected");
        assert_eq!(closes[0].1, CloseReason::PeerUnresponsive);
        assert!(matches!(client.state(), ClientManagerState::Idle));
        // And the tunnel recovers: a fresh handshake is possible.
        assert!(client.begin_handshake().is_ok());
    }

    /// D31 §6 (test 7): at the lifetime cap the client sends an encrypted
    /// `Close` to the peer and re-establishes; the peer converges (it sees
    /// the `Close` and drops the session).
    #[test]
    fn lifetime_cap_closes_and_both_endpoints_converge() {
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        handshake_pair(&mut client, &mut server);
        let sid = client.session_id().expect("session");

        // The cap fires.
        let events = client.tick(Instant::now() + Duration::from_secs(3600));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].1, CloseReason::LifetimeCap);
        let close_packet = events
            .iter()
            .find_map(|e| match e {
                ManagerEvent::SendPacket { packet, .. } => Some(packet.clone()),
                _ => None,
            })
            .expect("the cap must send an encrypted Close");
        assert!(client.session_id().is_none(), "the session is gone");

        // The peer converges: it decrypts the `Close` and drops the session.
        match server.handle_datagram(&close_packet, CLIENT_ADDR).unwrap() {
            ManagerEvent::Closed { sid: cs, reason } => {
                assert_eq!(cs, sid);
                assert_eq!(reason, CloseReason::PeerClosed);
            }
            other => panic!("expected Closed{{PeerClosed}}, got {other:?}"),
        }
        assert_eq!(server.session_count(), 0, "the peer dropped the session");
    }

    /// D31 §6: the exposure bound is only meaningful if **both** endpoints
    /// enforce the cap.  This is the path that proves it: the client's `Close`
    /// is lost entirely, and the **server's own cap** fires and converges.
    ///
    /// Without this test, "both ends enforce the cap ⇒ the traffic-key
    /// exposure is bounded" is an assertion nobody checks, and a lost `Close`
    /// would silently leave the peer's session alive for a whole cap period.
    #[test]
    fn a_lost_close_is_covered_by_the_peers_own_cap() {
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        handshake_pair(&mut client, &mut server);
        assert_eq!(server.session_count(), 1);

        // The client's cap fires and its `Close` is **lost** (never
        // delivered to the server).
        let events = client.tick(Instant::now() + Duration::from_secs(3600));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0].1, CloseReason::LifetimeCap);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ManagerEvent::SendPacket { .. })),
            "the client must have tried to tell the peer"
        );
        assert_eq!(
            server.session_count(),
            1,
            "the lost Close leaves the peer's session alive — that is the case this test covers"
        );

        // The server's **own** cap fires and converges: it tells the peer and
        // drops the session, so the exposure is bounded even though the
        // client's Close never arrived.
        let server_events = server.tick(Instant::now() + Duration::from_secs(3600));
        let server_closes = closed_events(&server_events);
        assert_eq!(server_closes.len(), 1);
        assert_eq!(server_closes[0].1, CloseReason::LifetimeCap);
        assert!(
            server_events
                .iter()
                .any(|e| matches!(e, ManagerEvent::SendPacket { .. })),
            "the server's own cap must send a Close to the peer"
        );
        assert_eq!(server.session_count(), 0, "the server dropped the session");
    }

    /// D31 §4: the traffic-key exposure bound is `cap + ≈4 s` — the 1 Hz tick
    /// granularity plus the `Close`-retransmission window during which the
    /// session (and therefore its keys) is still held.
    ///
    /// This pins that window: the keys must be **released** once the
    /// retransmission budget is spent.  Without it, a regression that kept
    /// the session alive indefinitely would still pass every other test.
    #[test]
    fn the_session_keys_are_released_after_the_close_retransmission_budget() {
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        handshake_pair(&mut client, &mut server);
        assert!(client.session_id().is_some());

        // The cap fires: the session is torn down, but it is retained for the
        // `Close` retransmissions.
        let events = client.tick(Instant::now() + Duration::from_secs(3600));
        assert_eq!(closed_events(&events).len(), 1);
        assert_eq!(
            client.pending_closes.len(),
            1,
            "the session is retained until its Close is delivered"
        );

        // The retransmission budget is spent: the session (and its keys) is
        // dropped and zeroized (D14).  The budget spans the `Close`
        // retransmission backoff, so the clock is advanced past each step.
        let mut t = Instant::now() + Duration::from_secs(3600);
        for _ in 0..8 {
            t += Duration::from_secs(5);
            let _ = client.tick(t);
            if client.pending_closes.is_empty() {
                break;
            }
        }
        assert!(
            client.pending_closes.is_empty(),
            "the retained session must be dropped once the Close budget is spent, \
             so the traffic keys are released (D31 §4)"
        );
    }

    /// D31 §6 (test 8a): a *lost* `Close` is retried a bounded number of
    /// times, and the peer converges on one of the retransmissions.
    #[test]
    fn lost_close_is_retransmitted_and_the_peer_converges() {
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        handshake_pair(&mut client, &mut server);

        // The cap fires; the first `Close` is "lost" (not delivered).
        let events = client.tick(Instant::now() + Duration::from_secs(3600));
        let mut closes: Vec<WirePacket> = events
            .iter()
            .filter_map(|e| match e {
                ManagerEvent::SendPacket { packet, .. } => Some(packet.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(closes.len(), 1, "the first Close is sent immediately");

        // The retransmissions follow the backoff.
        let mut now = Instant::now() + Duration::from_secs(3600);
        for _ in 0..2 {
            now += Duration::from_secs(1);
            let evs = client.tick(now);
            closes.extend(evs.iter().filter_map(|e| match e {
                ManagerEvent::SendPacket { packet, .. } => Some(packet.clone()),
                _ => None,
            }));
        }
        assert!(
            closes.len() >= 2,
            "the Close must be retransmitted, got {}",
            closes.len()
        );
        // The peer converges on one of them.
        let mut converged = false;
        for c in &closes {
            if let ManagerEvent::Closed { .. } = server.handle_datagram(c, CLIENT_ADDR).unwrap() {
                converged = true;
            }
        }
        assert!(
            converged,
            "the peer must converge on a Close retransmission"
        );
        assert_eq!(server.session_count(), 0);
    }

    /// D31 §5/§6 (test 8b): a lost *confirmation* does not kill a healthy
    /// session — the next probe round re-confirms it.
    #[test]
    fn lost_confirmation_is_recovered_by_the_next_probe_round() {
        let mut limits = SessionLimits::default();
        limits.liveness_probe_interval = Duration::from_secs(1);
        let (mut client, mut server) = client_server_pair(limits);
        let (_burst, replies) = handshake_pair(&mut client, &mut server);
        // The first ack is lost.
        assert!(!client.is_ready());
        // The client probes again; the server answers again.
        let mut now = Instant::now();
        now += Duration::from_secs(2);
        let probe = client.take_slot(now).expect("a probe is due");
        let ManagerEvent::SendPacket { packet, .. } = probe else {
            panic!("expected a probe packet");
        };
        let ack = match server.handle_datagram(&packet, CLIENT_ADDR).unwrap() {
            ManagerEvent::SendPacket { packet, .. } => packet,
            other => panic!("expected the ack, got {other:?}"),
        };
        client.handle_datagram(&ack, SERVER_ADDR).unwrap();
        assert!(client.is_ready(), "the next round confirms the session");
        let _ = replies;
    }

    /// D31 §2 / B2 / B12 (test 9): the client's session exists from the M3
    /// transmission, so the server's first authenticated packet can no longer
    /// be swallowed by the handshake machine (B2 — the baseline hole).  A
    /// replay of an already-accepted packet is rejected, and a late event
    /// can never create a second session for the same sid (B12).
    #[test]
    fn replayed_server_packet_is_rejected_and_nonce_state_is_never_reset() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        handshake_pair(&mut client, &mut server);
        let sid = client.session_id().expect("session");

        // The server's data packet is delivered: the session existed at the
        // M3, so nothing is swallowed (B2 fixed).
        let data = server.app_outbound(&sid, &[0x11; PAYLOAD_LEN]).unwrap();
        let ManagerEvent::SendPacket { packet, .. } = data else {
            panic!("expected SendPacket");
        };
        match client.handle_datagram(&packet, SERVER_ADDR).unwrap() {
            ManagerEvent::AppData { .. } => {}
            other => panic!("expected AppData, got {other:?}"),
        }

        // The replay is rejected: the packet is not delivered twice, and the
        // replay window is not reset by it.
        let ev = client.handle_datagram(&packet, SERVER_ADDR).unwrap();
        assert!(
            matches!(ev, ManagerEvent::None),
            "a replay must be rejected"
        );
        assert!(client.session_id().is_some(), "the session survives");
        assert!(client.is_ready(), "the gate stays open");

        // A late duplicate of the M2 cannot create a second session for the
        // same sid (B12): the handshake machine is gone, so the fragment is
        // stale and dropped.
        assert_eq!(client.session_id(), Some(sid), "the session is unchanged");
        assert!(
            client.handshake_sid().is_none(),
            "the handshake machine is dropped at the M3 (one live object)"
        );
    }

    /// D31 §7 (test 10): the bounded outbound queue drops the **newest**
    /// payload on overflow, counts the drops exactly, expires stale entries,
    /// and survives a re-establishment.
    #[test]
    fn outbound_queue_is_bounded_drops_newest_and_expires() {
        let (mut client, _server) = client_server_pair(SessionLimits::default());
        // Overflow: the queue holds 64 entries; the 65th is dropped.
        for i in 0..64u8 {
            let ev = client.app_outbound(&[i; 8]).unwrap();
            assert!(matches!(ev, ManagerEvent::None));
        }
        assert_eq!(client.outbound_queued(), 64);
        assert_eq!(client.outbound_dropped(), 0);
        let ev = client.app_outbound(&[0xFF; 8]).unwrap();
        match ev {
            ManagerEvent::OutboundDropped { dropped } => assert_eq!(dropped, 1),
            other => panic!("expected OutboundDropped, got {other:?}"),
        }
        assert_eq!(client.outbound_dropped(), 1, "the count is exact");
        assert_eq!(
            client.outbound_queued(),
            64,
            "the newest is dropped, the oldest are kept"
        );

        // Expiry: the per-entry TTL removes the stale entries and counts
        // them.
        let events = client.tick(Instant::now() + Duration::from_secs(3));
        let dropped = events
            .iter()
            .filter_map(|e| match e {
                ManagerEvent::OutboundDropped { dropped } => Some(*dropped),
                _ => None,
            })
            .max()
            .expect("the expiry must be reported");
        assert_eq!(dropped, 65, "64 expired + 1 overflowed");
        assert_eq!(client.outbound_queued(), 0);
        assert_eq!(client.outbound_dropped(), 65);
    }

    /// D31 §5 (test 12): the client is ready in ≈1 RTT, not after the M3
    /// retransmission budget.  The assertion is on *observable state
    /// transitions*, not on wall-clock time.
    #[test]
    fn readiness_is_one_round_trip_not_the_m3_budget() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let (_burst, replies) = handshake_pair(&mut client, &mut server);
        // The session exists at the M3 — no retransmission has happened yet.
        assert!(client.session_id().is_some());
        assert!(!client.is_ready());
        // The very first authenticated server packet (the ack to the probe
        // that rode along with the M3) confirms the session: one round trip.
        client.handle_datagram(&replies[0], SERVER_ADDR).unwrap();
        assert!(client.is_ready());
        // The M3 retransmission budget was never touched: the client did
        // not have to spend it to become ready.
        assert_eq!(client.m3_attempts, 0, "no M3 retransmission was needed");
    }

    /// D24 (test 13): a successfully decrypted in-session control message
    /// consumes **no** failure-gate token, and neither does a replayed
    /// authentic packet.
    #[test]
    fn control_message_and_replay_consume_no_failure_token() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.fail_burst = 2;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // A control probe: decrypted successfully, answered with an ack, and
        // it must not touch the failure gate.
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = control::PROBE;
        let probe = ws.encrypt(MessageType::Handshake, &payload).unwrap();
        match manager.handle_datagram(&probe, CLIENT_ADDR).unwrap() {
            ManagerEvent::SendPacket { packet, .. } => {
                let inner = ws.decrypt(&packet).expect("the ack decrypts");
                assert_eq!(inner.msg_type, MessageType::Handshake);
                assert_eq!(inner.payload[0], control::ACK);
            }
            other => panic!("expected the ack, got {other:?}"),
        }
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "a successful control message must not allocate a failure bucket"
        );

        // A replayed authentic packet: rejected, and it must not touch the
        // failure gate either (D24: only an AEAD failure may).
        assert!(matches!(
            manager.handle_datagram(&probe, CLIENT_ADDR).unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(
            manager.fail_bucket_count(),
            0,
            "a replay must not allocate a failure bucket"
        );

        // A genuine AEAD failure *does* allocate one — the control above is
        // what proves the difference.
        let good = ws.encrypt(MessageType::Data, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(
            manager
                .handle_datagram(&tampered(&good), CLIENT_ADDR)
                .unwrap(),
            ManagerEvent::None
        ));
        assert_eq!(
            manager.fail_bucket_count(),
            1,
            "an AEAD failure is the only thing that spends a token"
        );
    }

    /// B4 (test 14): the server's idle timeout counts **authenticated
    /// receives** only.  The server's own cover traffic and application
    /// replies do not keep a session alive, so a departed peer is reaped;
    /// a live-but-quiet peer (kept alive by the client's liveness probe) is
    /// not.
    #[test]
    fn server_idle_eviction_counts_receives_only() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.idle_timeout = Some(Duration::from_secs(60));
        limits.lifetime_cap = None;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // The server's *own* outbound traffic (cover) must not refresh the
        // idle clock.
        let cover = manager.cover_packet(&SID).unwrap();
        assert!(matches!(cover, ManagerEvent::SendPacket { .. }));
        let app = manager.app_outbound(&SID, &[0u8; PAYLOAD_LEN]).unwrap();
        assert!(matches!(app, ManagerEvent::SendPacket { .. }));

        // The peer is gone: the session is reaped within the idle timeout.
        let events = manager.tick(Instant::now() + Duration::from_secs(61));
        let closes = closed_events(&events);
        assert_eq!(closes.len(), 1, "a departed peer must be reaped");
        assert_eq!(closes[0].1, CloseReason::IdleTimeout);
        assert_eq!(manager.session_count(), 0);
        let _ = &mut ws;
    }

    /// D31 §5: a live-but-quiet peer — one that only sends liveness probes —
    /// is **not** reaped: the probe is an authenticated receive, and the
    /// idle timeout counts authenticated receives.
    #[test]
    fn a_live_but_quiet_peer_is_not_reaped() {
        let (cc, _sc) = shared_configs();
        let mut limits = SessionLimits::default();
        limits.idle_timeout = Some(Duration::from_secs(600));
        limits.lifetime_cap = None;
        let mut manager = server_manager(limits);
        let (_client, mut ws) = established_client_session(&mut manager, &cc, SID);

        // The peer keeps itself alive with probes only.
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[0] = control::PROBE;
        let mut last = Instant::now();
        for _ in 0..5 {
            last += Duration::from_secs(30);
            let probe = ws.encrypt(MessageType::Handshake, &payload).unwrap();
            match manager.handle_datagram(&probe, CLIENT_ADDR).unwrap() {
                ManagerEvent::SendPacket { .. } => {}
                other => panic!("expected the ack, got {other:?}"),
            }
            // The tick between the probes must not evict the session.
            assert!(
                closed_events(&manager.tick(last)).is_empty(),
                "a probe-driven session must not be reaped"
            );
        }
        assert_eq!(manager.session_count(), 1, "the session is still alive");
    }

    /// D31 §4: a **simultaneous close** — both endpoints cap at once, both
    /// send a `Close`, and each receives a `Close` for a session it has
    /// already closed.  That must be a graceful silent drop: not an error,
    /// and not charged to the failure gate.
    #[test]
    fn simultaneous_close_is_graceful() {
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        handshake_pair(&mut client, &mut server);
        let sid = client.session_id().expect("session");

        // Both sides cap at the same moment: each sends a `Close`.
        let client_events = client.tick(Instant::now() + Duration::from_secs(3600));
        let server_events = server.tick(Instant::now() + Duration::from_secs(3600));
        let client_close = client_events
            .iter()
            .find_map(|e| match e {
                ManagerEvent::SendPacket { packet, .. } => Some(packet.clone()),
                _ => None,
            })
            .expect("the client sends a Close");
        let server_close = server_events
            .iter()
            .find_map(|e| match e {
                ManagerEvent::SendPacket { packet, .. } => Some(packet.clone()),
                _ => None,
            })
            .expect("the server sends a Close");

        // The client receives the server's `Close` for a session it has
        // already closed: a graceful, silent drop.
        let ev = client.handle_datagram(&server_close, SERVER_ADDR).unwrap();
        assert!(
            matches!(ev, ManagerEvent::None),
            "a Close for an already-closed session is a silent drop, got {ev:?}"
        );
        // The server receives the client's `Close` likewise.
        let ev = server.handle_datagram(&client_close, CLIENT_ADDR).unwrap();
        assert!(
            matches!(ev, ManagerEvent::None),
            "a Close for an already-closed session is a silent drop, got {ev:?}"
        );
        assert_eq!(server.session_count(), 0);
        assert_eq!(
            server.fail_bucket_count(),
            0,
            "a simultaneous close must not be charged to the failure gate"
        );
        let _ = sid;
    }

    /// B13 (test 15): `begin_handshake()` succeeds after **every** teardown
    /// path, and it always yields a fresh sid.
    #[test]
    fn begin_handshake_succeeds_after_every_teardown_path() {
        let (mut client, mut server) = client_server_pair(SessionLimits::default());
        let mut sids: Vec<[u8; SESSION_ID_LEN]> = Vec::new();

        // Path 1: the confirmation deadline (NotConfirmed).
        handshake_pair(&mut client, &mut server);
        sids.push(client.session_id().expect("session"));
        let events = client.tick(Instant::now() + Duration::from_secs(31));
        assert_eq!(closed_events(&events).len(), 1);
        assert!(client.needs_rearm(), "the manager must ask for a re-arm");
        let m1 = start_handshake(&mut client);
        sids.push(m1[0].as_bytes()[1..9].try_into().unwrap());

        // Path 2: the peer's `Close` (PeerClosed).
        let (_burst, _replies) = finish_handshake(&mut client, &mut server, &m1);
        let sid = client.session_id().expect("session");
        let close = server.close_session(&sid).unwrap();
        let ManagerEvent::SendPacket { packet, .. } = close else {
            panic!("the server must send a Close");
        };
        match client.handle_datagram(&packet, SERVER_ADDR).unwrap() {
            ManagerEvent::Closed { reason, .. } => assert_eq!(reason, CloseReason::PeerClosed),
            other => panic!("expected Closed{{PeerClosed}}, got {other:?}"),
        }
        assert!(client.session_id().is_none(), "the session is gone");
        let m1 = start_handshake(&mut client);
        sids.push(m1[0].as_bytes()[1..9].try_into().unwrap());

        // Path 3: the lifetime cap (LifetimeCap).
        let mut limits = SessionLimits::default();
        limits.lifetime_cap = Some(Duration::from_secs(3600));
        let (mut client, mut server) = client_server_pair(limits);
        let m1 = start_handshake(&mut client);
        finish_handshake(&mut client, &mut server, &m1);
        sids.push(client.session_id().expect("session"));
        let events = client.tick(Instant::now() + Duration::from_secs(3600));
        assert_eq!(closed_events(&events).len(), 1);
        let m1 = start_handshake(&mut client);
        sids.push(m1[0].as_bytes()[1..9].try_into().unwrap());

        // Every sid is distinct: a session identifier is never reused (D13).
        let mut sorted = sids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), sids.len(), "the sids must be distinct");
    }
}
