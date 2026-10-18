//! D27 — revocation and session-lifetime contract tests.
//!
//! These tests pin the semantics fixed by `docs/decisions/D27-revocation-and-session-lifetime.md`:
//!
//! 1. `lifetime_cap` fires and yields `Closed{LifetimeCap}`.
//! 2. `lifetime_cap` takes precedence over `idle_timeout`.
//! 3. A revoked key cannot re-establish (at M1 and at the M3 re-check).
//! 4. An established session survives a roster reload that does not remove it.
//! 5. Roster replacement is atomic: no observer ever sees a partial roster.
//!
//! The lifetime tests drive the core `SessionLimits` machinery directly (the
//! binary exposes no CLI surface for it — D27 §1); the revocation tests drive
//! the real `ServerSessionManager`, so the M1/M2/M3 roster path is genuinely
//! exercised rather than simulated.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pq_crypto::{MlDsaKeypair, MlDsaPublicKey};
use pq_tunnel_core::{
    ClientEvent, ClientHandshake, ClientManagerState, ClientSessionManager, CloseReason,
    HandshakeOutcome, HandshakeV2ClientConfig, HandshakeV2ServerConfig, ManagerEvent, MessageType,
    PAYLOAD_LEN, Role, ServerSessionManager, SessionLimits, WirePacket, WireSession,
};
use pq_tunnel_lib::identity::{self, RosterHandle};

const SID: [u8; 8] = [0x42; 8];

fn client_addr() -> SocketAddr {
    "127.0.0.1:40001".parse().unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:40002".parse().unwrap()
}

/// The client's own static public key, plus both handshake configs.
struct Fixture {
    client_pk: MlDsaPublicKey,
    cc: HandshakeV2ClientConfig,
    sc: HandshakeV2ServerConfig,
}

fn fixture() -> Fixture {
    let client_kp = MlDsaKeypair::generate().expect("client keygen");
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let client_pk = client_kp.public_key();
    let cc = HandshakeV2ClientConfig::new(server_addr(), client_kp, server_kp.public_key());
    let sc = HandshakeV2ServerConfig::new(server_kp, vec![client_pk.clone()]);
    Fixture { client_pk, cc, sc }
}

fn server_mgr(sc: &HandshakeV2ServerConfig, limits: SessionLimits) -> ServerSessionManager {
    ServerSessionManager::new(sc, limits).expect("server session manager init")
}

/// Drive a client machine to `Complete`.  Against a passive server the client
/// converges on `Complete` once its M3 budget is spent (no M4 exists), so a
/// small bounded loop is the deterministic way to reach it.
fn client_established(client: &mut ClientHandshake) -> HandshakeOutcome {
    for _ in 0..16 {
        if let ClientEvent::Complete(outcome) = client.on_timer().expect("client timer") {
            return outcome;
        }
    }
    panic!("client handshake never completed");
}

/// Run M1 and M2 to completion and park the client machine in `M3Sent`.
///
/// Returning *before* the M3 fragments are handed to the server is what lets a
/// test revoke a key inside the handshake window (D27 §4).
fn paused_before_m3(
    mgr: &mut ServerSessionManager,
    cc: &HandshakeV2ClientConfig,
    sid: [u8; 8],
) -> (ClientHandshake, Vec<WirePacket>) {
    let mut client = ClientHandshake::new(cc, sid).expect("client handshake");
    let mut m2: Vec<WirePacket> = Vec::new();
    for f in client.m1_frags() {
        if let ManagerEvent::Send { packets, .. } =
            mgr.handle_datagram(f, client_addr()).expect("srv")
        {
            m2 = packets;
        }
    }
    assert!(!m2.is_empty(), "server must emit M2 once M1 authenticates");
    for f in &m2 {
        client.handle_datagram(f).expect("client accepts M2");
    }
    let m3 = client.m3_frags().to_vec();
    assert!(!m3.is_empty(), "client must be parked in M3Sent");
    (client, m3)
}

/// Full handshake through the manager; returns a usable client-side session.
fn established(
    mgr: &mut ServerSessionManager,
    cc: &HandshakeV2ClientConfig,
    sid: [u8; 8],
) -> (ClientHandshake, WireSession) {
    let (mut client, m3) = paused_before_m3(mgr, cc, sid);
    let mut ok = false;
    for f in &m3 {
        if let ManagerEvent::Established { .. } = mgr.handle_datagram(f, client_addr()).unwrap() {
            ok = true;
        }
    }
    assert!(ok, "server must establish at M3");
    let outcome = client_established(&mut client);
    let ws = WireSession::established(Role::Client, &outcome).expect("client session");
    (client, ws)
}

/// The single `Closed` reason from a `tick`, panicking on anything else.
fn only_close_reason(events: &[ManagerEvent]) -> CloseReason {
    assert_eq!(
        events.len(),
        1,
        "expected exactly one eviction, got {events:?}"
    );
    match &events[0] {
        ManagerEvent::Closed { reason, .. } => *reason,
        other => panic!("expected a Closed event, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. lifetime_cap fires and yields Closed{LifetimeCap}
// ---------------------------------------------------------------------------

/// With no idle bound at all, `lifetime_cap` alone is what evicts the session,
/// and the reported reason is `LifetimeCap`.
///
/// Mirrors `server_lifetime_cap_precedes_idle` in
/// `pq-tunnel-core/src/session_manager.rs`.
#[test]
fn lifetime_cap_fires_and_yields_closed_lifetime_cap() {
    let f = fixture();
    let limits = SessionLimits {
        idle_timeout: None,
        lifetime_cap: Some(Duration::from_secs(3600)),
        ..SessionLimits::default()
    };
    let mut mgr = server_mgr(&f.sc, limits);

    let (_client, _ws) = established(&mut mgr, &f.cc, SID);
    assert_eq!(mgr.session_count(), 1);

    // Just under the cap: still alive.
    assert!(
        mgr.tick(Instant::now() + Duration::from_secs(3500))
            .is_empty(),
        "a session below lifetime_cap must not be evicted"
    );
    assert_eq!(mgr.session_count(), 1);

    // At the cap: evicted.
    let reason = only_close_reason(&mgr.tick(Instant::now() + Duration::from_secs(3600)));
    assert_eq!(
        reason,
        CloseReason::LifetimeCap,
        "expiry must be reported as LifetimeCap"
    );
    assert_eq!(mgr.session_count(), 0, "an evicted session is removed");
}

/// The client role enforces the same cap: at the cap it closes the session so
/// the driver re-establishes under D16 (fresh sid, fresh ephemerals).
///
/// The manager is driven through a genuine server handshake rather than a
/// back door, so the session state under test is the one production builds.
#[test]
fn client_side_lifetime_cap_closes_and_re_arms() {
    let f = fixture();
    let limits = SessionLimits {
        lifetime_cap: Some(Duration::from_secs(60)),
        // The client also carries a liveness timeout (default 30 s, D15). It
        // only applies while a session is unconfirmed, and this session is
        // never confirmed (no server packet ever reaches it), so it is
        // disabled here to isolate the cap as the single bound under test.
        liveness_timeout: None,
        ..SessionLimits::default()
    };
    let mut cm = ClientSessionManager::new(&f.cc, limits).expect("client mgr");
    let mut server = pq_tunnel_core::ServerHandshake::new(&f.sc);

    client_mgr_handshake(&mut cm, &mut server);
    let sid = cm.session_id().expect("client session established");

    assert!(
        cm.tick(Instant::now() + Duration::from_secs(50))
            .iter()
            .all(|e| !matches!(e, ManagerEvent::Closed { .. })),
        "no close before the cap"
    );

    let reason = only_close_reason(&cm.tick(Instant::now() + Duration::from_secs(60)));
    assert_eq!(reason, CloseReason::LifetimeCap);
    assert_eq!(cm.session_id(), None, "the capped session must be gone");
    assert_eq!(cm.state(), ClientManagerState::Idle);

    // Re-establishment is legal from the resulting Idle state — the D16 path a
    // revoked client would drive. It must use a FRESH sid.
    cm.begin_handshake().expect("client re-establishes");
    let new_sid = cm.handshake_sid().expect("a handshake is running");
    assert_ne!(new_sid, sid, "D16 re-establishment must draw a fresh sid");
}

/// Drive a `ClientSessionManager` to `Established` against a `ServerHandshake`
/// machine, moving M1/M2/M3 through the public `handle_datagram` API.
fn client_mgr_handshake(
    cm: &mut ClientSessionManager,
    server: &mut pq_tunnel_core::ServerHandshake,
) {
    let m1 = match cm.begin_handshake().expect("begin_handshake") {
        ManagerEvent::Send { packets, .. } => packets,
        other => panic!("expected Send(M1), got {other:?}"),
    };
    let mut m2 = Vec::new();
    for frag in &m1 {
        if let pq_tunnel_core::ServerEvent::Emit(frags, _) =
            server.handle_datagram(frag, client_addr()).expect("server")
        {
            m2 = frags;
        }
    }
    assert!(
        !m2.is_empty(),
        "server must answer an authenticated M1 with M2"
    );
    for frag in &m2 {
        cm.handle_datagram(frag, client_addr())
            .expect("client accepts M2");
    }
    // The client is now in M3Sent; its session exists once the M3 budget
    // converges (v2 has no M4, so the client completes once it stops
    // retransmitting).
    for _ in 0..16 {
        cm.on_timer().expect("client timer");
        if cm.session_id().is_some() {
            break;
        }
    }
    assert!(
        cm.session_id().is_some(),
        "client must hold a session after the M3 budget converges"
    );
}

// ---------------------------------------------------------------------------
// 2. lifetime_cap precedence over idle_timeout
// ---------------------------------------------------------------------------

/// When both bounds have expired, the reported reason is `LifetimeCap`.
///
/// The precedence is structural in `ServerSessionManager::tick`: the reason is
/// chosen on the life check whenever it fails, so an operator always learns
/// which bound actually fired.
#[test]
fn lifetime_cap_takes_precedence_over_idle_timeout() {
    let f = fixture();
    let limits = SessionLimits {
        idle_timeout: Some(Duration::from_secs(60)),
        lifetime_cap: Some(Duration::from_secs(120)),
        ..SessionLimits::default()
    };
    let mut mgr = server_mgr(&f.sc, limits);

    let (_c, _ws) = established(&mut mgr, &f.cc, SID);
    assert_eq!(mgr.session_count(), 1);

    // Both expired (tick far past either): one event, and it names the cap.
    let reason = only_close_reason(&mgr.tick(Instant::now() + Duration::from_secs(600)));
    assert_eq!(
        reason,
        CloseReason::LifetimeCap,
        "LifetimeCap must win when both bounds are expired"
    );

    // Control: with no cap configured the same expiry is IdleTimeout, proving
    // the reason is driven by the cap check and not merely by the tick time.
    let f2 = fixture();
    let limits = SessionLimits {
        idle_timeout: Some(Duration::from_secs(60)),
        lifetime_cap: None,
        ..SessionLimits::default()
    };
    let mut mgr2 = server_mgr(&f2.sc, limits);
    let (_c2, _ws2) = established(&mut mgr2, &f2.cc, SID);
    let reason2 = only_close_reason(&mgr2.tick(Instant::now() + Duration::from_secs(600)));
    assert_eq!(
        reason2,
        CloseReason::IdleTimeout,
        "with no cap configured the expiry must be IdleTimeout"
    );
}

/// A session that is idle-expired *before* the cap still reports IdleTimeout:
/// precedence is not a blanket "always blame the cap".
#[test]
fn idle_timeout_before_cap_reports_idle_timeout() {
    let f = fixture();
    let limits = SessionLimits {
        idle_timeout: Some(Duration::from_secs(60)),
        lifetime_cap: Some(Duration::from_secs(86400)),
        ..SessionLimits::default()
    };
    let mut mgr = server_mgr(&f.sc, limits);

    let (_c, _ws) = established(&mut mgr, &f.cc, SID);
    let reason = only_close_reason(&mgr.tick(Instant::now() + Duration::from_secs(600)));
    assert_eq!(
        reason,
        CloseReason::IdleTimeout,
        "the idle bound fired first, so that is the reason reported"
    );
}

// ---------------------------------------------------------------------------
// 3. A revoked key cannot re-establish
// ---------------------------------------------------------------------------

/// After the client's key leaves the roster, a *fresh* handshake is refused:
/// M1 never authenticates, so there is no M2 and no session.
#[test]
fn revoked_key_cannot_re_establish() {
    let f = fixture();
    let keep = MlDsaKeypair::generate().expect("unrelated keygen");
    let mut mgr = server_mgr(&f.sc, SessionLimits::default());

    // Revoke the client's key.
    mgr.set_roster(vec![keep.public_key()])
        .expect("roster swap");
    assert_eq!(mgr.roster_len(), 1);

    let mut m2_seen = false;
    let client = ClientHandshake::new(&f.cc, SID).expect("client handshake");
    for frag in client.m1_frags() {
        if let ManagerEvent::Send { .. } = mgr.handle_datagram(frag, client_addr()).unwrap() {
            m2_seen = true;
        }
    }
    assert!(
        !m2_seen,
        "a revoked key must never receive an M2 (fail-closed silent drop)"
    );
    assert_eq!(
        mgr.session_count(),
        0,
        "a revoked key must not create a session"
    );
}

/// Revocation between M1 and M3 is caught by the M3 membership re-check.
///
/// The handshake authenticated at `complete_m1` against the roster as it stood
/// then, but must not *complete* after the swap. This is the window D27 §4
/// closes; without the re-check a revoked key could still obtain a session by
/// having started its handshake before the reload landed.
#[test]
fn midflight_revocation_blocks_m3_completion() {
    let f = fixture();
    let keep = MlDsaKeypair::generate().expect("unrelated keygen");
    let mut mgr = server_mgr(&f.sc, SessionLimits::default());

    // M1 has already authenticated at complete_m1 against the ORIGINAL roster.
    let (_client, m3) = paused_before_m3(&mut mgr, &f.cc, SID);

    // Revoke the client's key while M3 is in flight.
    mgr.set_roster(vec![keep.public_key()])
        .expect("roster swap");

    let mut established_yet = false;
    for frag in &m3 {
        if let ManagerEvent::Established { .. } = mgr.handle_datagram(frag, client_addr()).unwrap()
        {
            established_yet = true;
        }
    }
    assert!(
        !established_yet,
        "M3 must not complete after the key was revoked mid-handshake"
    );
    assert_eq!(mgr.session_count(), 0);
}

/// An empty roster is rejected: revocation can never silently drop every
/// client, and a rejected swap leaves the previous roster in force.
#[test]
fn empty_roster_swap_is_rejected_fail_closed() {
    let f = fixture();
    let mut mgr = server_mgr(&f.sc, SessionLimits::default());
    assert_eq!(mgr.roster_len(), 1);

    assert!(
        mgr.set_roster(Vec::new()).is_err(),
        "an empty roster must be rejected"
    );
    assert_eq!(
        mgr.roster_len(),
        1,
        "a rejected swap must leave the old roster in force"
    );

    // Control: the original key still works, i.e. the rejection was a no-op.
    let (_c, _ws) = established(&mut mgr, &f.cc, SID);
    assert_eq!(mgr.session_count(), 1);
}

/// The revoke → re-establish loop is fail-secure, not fail-open: a revoked
/// client retries, is never served, and the server stays up.
#[test]
fn revoked_client_retry_loop_never_establishes() {
    let f = fixture();
    let keep = MlDsaKeypair::generate().expect("unrelated keygen");
    let mut mgr = server_mgr(&f.sc, SessionLimits::default());
    mgr.set_roster(vec![keep.public_key()])
        .expect("roster swap");

    // Each attempt uses a fresh sid, as D16 re-establishment does.
    for i in 0..3u8 {
        let sid = [0x50 + i; 8];
        let client = ClientHandshake::new(&f.cc, sid).expect("client handshake");
        for frag in client.m1_frags() {
            assert!(
                matches!(
                    mgr.handle_datagram(frag, client_addr()).unwrap(),
                    ManagerEvent::None
                ),
                "revoked retry {i} must produce no M2 at all"
            );
        }
    }
    assert_eq!(mgr.session_count(), 0, "no session, ever");
    assert_eq!(
        mgr.roster_len(),
        1,
        "the roster is untouched by the retries"
    );
}

// ---------------------------------------------------------------------------
// 4. Established sessions and reloads that do not remove them
// ---------------------------------------------------------------------------

/// An established session survives a roster swap that does not remove its key,
/// and keeps carrying data afterwards.
///
/// D27 §5: revocation gates *future* establishment; it does not tear down a
/// live session mid-flight.
#[test]
fn established_session_survives_non_removing_roster_swap() {
    let f = fixture();
    let extra = MlDsaKeypair::generate().expect("extra keygen");
    let mut mgr = server_mgr(&f.sc, SessionLimits::default());

    let (_c, mut ws) = established(&mut mgr, &f.cc, SID);
    assert_eq!(mgr.session_count(), 1);

    // Swap in a roster that ADDS a key and keeps the established client.
    let mut next = vec![f.client_pk.clone()];
    next.push(extra.public_key());
    mgr.set_roster(next).expect("roster swap");
    assert_eq!(mgr.roster_len(), 2);

    // The live session is untouched and still carries application data.
    let pkt = ws.encrypt(MessageType::Data, &[0x2A; PAYLOAD_LEN]).unwrap();
    assert!(
        matches!(
            mgr.handle_datagram(&pkt, client_addr()).unwrap(),
            ManagerEvent::AppData { .. }
        ),
        "an established session must survive a non-removing roster swap"
    );
    assert_eq!(
        mgr.session_count(),
        1,
        "the session survives, one still open"
    );
}

/// Revocation does not tear down an already-established session — it bounds
/// how long that session can keep running, which is `lifetime_cap`'s job.
///
/// This is the D27 §5 decision stated as a test: an established session whose
/// key is revoked mid-flight continues until the (much shorter) cap expires,
/// at which point it closes as `LifetimeCap` rather than `Revoked`.
#[test]
fn revocation_defers_to_lifetime_cap_for_established_sessions() {
    let f = fixture();
    let extra = MlDsaKeypair::generate().expect("extra keygen");
    let limits = SessionLimits {
        idle_timeout: None,
        lifetime_cap: Some(Duration::from_secs(3600)),
        ..SessionLimits::default()
    };
    let mut mgr = server_mgr(&f.sc, limits);

    let (_c, mut ws) = established(&mut mgr, &f.cc, SID);

    // Revoke the established client's key.
    mgr.set_roster(vec![extra.public_key()])
        .expect("roster swap");
    assert_eq!(mgr.roster_len(), 1);

    // The existing session is still live and still delivering.
    let pkt = ws.encrypt(MessageType::Data, &[0x01; PAYLOAD_LEN]).unwrap();
    assert!(
        matches!(
            mgr.handle_datagram(&pkt, client_addr()).unwrap(),
            ManagerEvent::AppData { .. }
        ),
        "revocation must not kill an established session"
    );

    // ... and it is bounded by the cap, which is what closes it.
    let reason = only_close_reason(&mgr.tick(Instant::now() + Duration::from_secs(3600)));
    assert_eq!(reason, CloseReason::LifetimeCap);
    assert_eq!(mgr.session_count(), 0);

    // Re-establishment against the revoked roster now fails closed.
    let client = ClientHandshake::new(&f.cc, [0x60; 8]).expect("client handshake");
    for frag in client.m1_frags() {
        assert!(matches!(
            mgr.handle_datagram(frag, client_addr()).unwrap(),
            ManagerEvent::None
        ));
    }
    assert_eq!(
        mgr.session_count(),
        0,
        "revoked re-establishment fails cleanly"
    );
}

// ---------------------------------------------------------------------------
// 5. Atomic roster replacement
// ---------------------------------------------------------------------------

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pq-tunnel-{}-{}", name, std::process::id()))
}

fn write_roster(path: &Path, keys: &[MlDsaPublicKey]) {
    identity::save_roster(path, keys).expect("save roster");
}

/// A reload is all-or-nothing: a corrupt or empty file leaves the previously
/// published roster in force, and a good file replaces it wholesale.
#[test]
fn roster_reload_is_fail_closed_on_bad_input() {
    let a = MlDsaKeypair::generate().expect("a");
    let b = MlDsaKeypair::generate().expect("b");
    let path = temp_path("roster-reload-failclosed");

    write_roster(&path, &[a.public_key()]);
    let mut handle = RosterHandle::load(&path).expect("load");
    assert_eq!(handle.len(), 1);
    assert_eq!(handle.snapshot()[0].encode(), a.public_key().encode());

    // Empty roster (header only, no keys): rejected, old roster still in force.
    std::fs::write(&path, "PQTI\nversion: 1\ntype: roster\n").expect("write empty");
    assert!(
        handle.reload().is_err(),
        "an empty roster must not be published"
    );
    assert_eq!(handle.len(), 1, "old roster survives the empty reload");
    assert_eq!(handle.snapshot()[0].encode(), a.public_key().encode());

    // Wrong magic: rejected.
    std::fs::write(&path, "NOPE\nversion: 1\ntype: roster\nzz\n").expect("write bad magic");
    assert!(
        handle.reload().is_err(),
        "a bad header must not be published"
    );
    assert_eq!(handle.len(), 1);

    // Truncated key (valid hex, wrong length): rejected as a partial key.
    let short = "ab".repeat(100);
    std::fs::write(&path, format!("PQTI\nversion: 1\ntype: roster\n{short}\n"))
        .expect("write short key");
    assert!(
        handle.reload().is_err(),
        "a half-written key must not be published"
    );
    assert_eq!(handle.len(), 1);

    // Missing file: rejected.
    let _ = std::fs::remove_file(&path);
    assert!(
        handle.reload().is_err(),
        "a missing roster must not be published"
    );
    assert_eq!(handle.len(), 1);

    // Finally a good file: the swap takes effect.
    write_roster(&path, &[a.public_key(), b.public_key()]);
    assert_eq!(handle.reload().expect("reload"), 2);
    assert_eq!(handle.len(), 2);

    let _ = std::fs::remove_file(&path);
}

/// Concurrent readers never observe a partial, empty, or mixed roster.
///
/// `RosterHandle` publishes a fully-built snapshot with a single `Arc` store and
/// hands readers an immutable `Arc` clone, so a reader always sees exactly one
/// complete generation. This hammers the on-disk file between two generations
/// while several threads sample the handle, asserting every sample is one whole
/// generation — never a mix, never empty.
#[test]
fn roster_replacement_is_atomic_under_concurrent_readers() {
    let a = MlDsaKeypair::generate().expect("a");
    let b = MlDsaKeypair::generate().expect("b");
    let enc_a = Arc::new(a.public_key().encode());
    let enc_b = Arc::new(b.public_key().encode());
    let path = temp_path("roster-atomic");

    // Two generations: [A] and [A, B]. Both are complete; neither is a prefix
    // of the other in the "partial roster" sense (they differ in membership).
    write_roster(&path, &[a.public_key()]);
    let mut handle = RosterHandle::load(&path).expect("load");

    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let reader_handle = handle.clone();
        let stop = Arc::clone(&stop);
        let enc_a = Arc::clone(&enc_a);
        let enc_b = Arc::clone(&enc_b);
        readers.push(std::thread::spawn(move || {
            let mut samples = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let snap = reader_handle.snapshot();
                assert!(!snap.is_empty(), "observer saw an empty roster");
                let mut encs: Vec<Vec<u8>> = snap.iter().map(|k| k.encode()).collect();
                encs.sort();
                encs.dedup();
                // Each sample must be exactly one of the two whole generations.
                let is_a = encs.len() == 1 && encs[0] == *enc_a;
                let is_ab = encs.len() == 2 && encs[0] == *enc_a && encs[1] == *enc_b;
                assert!(
                    is_a || is_ab,
                    "observer saw a partial/mixed roster of {} key(s)",
                    encs.len()
                );
                samples += 1;
            }
            samples
        }));
    }

    // Toggle the backing file between the two generations and reload each time.
    let mut reloads = 0usize;
    for i in 0..200 {
        let keys: Vec<MlDsaPublicKey> = if i % 2 == 0 {
            vec![a.public_key(), b.public_key()]
        } else {
            vec![a.public_key()]
        };
        write_roster(&path, &keys);
        let published = handle.reload().expect("reload publishes");
        assert_eq!(published, keys.len(), "publication is the whole file");
        reloads += 1;
    }
    assert_eq!(reloads, 200);

    stop.store(true, Ordering::Relaxed);
    let mut total_samples = 0usize;
    for r in readers {
        total_samples += r.join().expect("reader join");
    }
    assert!(
        total_samples > 0,
        "readers never sampled, so atomicity was not exercised"
    );

    let _ = std::fs::remove_file(&path);
}

/// The snapshot handed to a reader stays valid and immutable across a swap:
/// a reader that already holds an `Arc` keeps seeing its complete generation.
#[test]
fn held_snapshot_survives_a_swap_unchanged() {
    let a = MlDsaKeypair::generate().expect("a");
    let b = MlDsaKeypair::generate().expect("b");
    let path = temp_path("roster-held-snapshot");

    write_roster(&path, &[a.public_key()]);
    let mut handle = RosterHandle::load(&path).expect("load");

    // A reader takes its snapshot before the swap.
    let held = handle.snapshot();
    assert_eq!(held.len(), 1);

    write_roster(&path, &[a.public_key(), b.public_key()]);
    handle.reload().expect("reload");
    assert_eq!(handle.len(), 2);

    // The held snapshot is untouched — still one key, the old generation.
    assert_eq!(held.len(), 1, "a held snapshot is immutable");
    assert_eq!(
        held[0].encode(),
        a.public_key().encode(),
        "a held snapshot keeps its own generation"
    );
    assert_eq!(
        handle.snapshot().len(),
        2,
        "new readers see the new generation"
    );

    let _ = std::fs::remove_file(&path);
}
