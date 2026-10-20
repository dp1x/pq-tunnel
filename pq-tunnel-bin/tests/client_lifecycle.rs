//! D31 — the client lifecycle, liveness and the lifetime cap, at the
//! driver level.
//!
//! These tests exercise the **shipped** driver (`run_client_manager`) rather
//! than the manager in isolation, because the lifecycle bugs D31 closes were
//! driver-level ones:
//!
//! * B3 — the client never detected peer loss, so it sat in an infinite
//!   re-handshake loop with no liveness signal.
//! * B13 — a failed re-arm propagated out of the driver, so the *process*
//!   exited and the tunnel stayed down.
//! * B10 — application data pushed while the client was handshaking was
//!   dropped silently (`Err(NoSession) => {}`).

use std::time::Duration;

use pq_crypto::MlDsaKeypair;
use pq_tunnel_core::{
    ClientSessionManager, CloseReason, CoverPolicy, HandshakeV2ClientConfig,
    HandshakeV2ServerConfig, ManagerNotification, ServerSessionManager, SessionLimits,
    UdpTransport, run_client_manager, run_server_manager,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Cover disabled: the liveness probe is the only traffic the client emits,
/// so a dead peer is detected by the liveness rounds alone (D31 §5).
fn no_cover() -> CoverPolicy {
    CoverPolicy {
        enabled: false,
        interval: CoverPolicy::default().interval,
    }
}

/// A client configuration whose handshake budget is spent quickly, so the
/// test does not have to wait for the production 64 s budget.
fn fast_client_config(server_addr: std::net::SocketAddr) -> HandshakeV2ClientConfig {
    let client_kp = MlDsaKeypair::generate().expect("client keygen");
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let mut cc = HandshakeV2ClientConfig::new(server_addr, client_kp, server_kp.public_key());
    cc.m1_retransmit_base = Duration::from_millis(50);
    cc.m1_max_attempts = 1;
    cc
}

/// The client driver must survive a **dead peer**: it detects the loss,
/// reports it, tears the session down and keeps retrying — and the driver
/// never exits (D31 §8, B3, B13).
///
/// The pre-fix behaviour was an infinite re-handshake loop with no liveness
/// signal at all (B3) and a driver that returned `Err` on a failed re-arm,
/// which killed the whole client process (B13).
#[tokio::test]
async fn client_driver_survives_a_dead_peer() {
    // A socket that never answers: the peer is gone.
    let dead = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    let mut client_udp = UdpTransport::connect(dead_addr).await.expect("connect");

    let cc = fast_client_config(dead_addr);
    let limits = SessionLimits {
        confirm_timeout: Some(Duration::from_secs(2)),
        ..SessionLimits::default()
    };
    let mut manager = ClientSessionManager::new(&cc, limits).expect("manager");
    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (_data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    let driver = tokio::spawn(async move {
        run_client_manager(&mut client_udp, &mut manager, app_tx, data_rx, no_cover()).await
    });

    // The dead peer is detected: the client reports the failure and retries.
    let mut closes = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while closes < 2 && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), app_rx.recv()).await {
            Ok(Some(ManagerNotification::Closed { reason, .. })) => {
                assert!(
                    matches!(
                        reason,
                        CloseReason::NotConfirmed | CloseReason::HandshakeTimeout
                    ),
                    "unexpected close reason: {reason:?}"
                );
                closes += 1;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    assert!(
        closes >= 2,
        "the client must keep detecting the dead peer and retrying (got {closes} closes)"
    );
    assert!(
        !driver.is_finished(),
        "the client driver must never exit because the peer is dead (B13)"
    );
    driver.abort();
}

/// Application data pushed while the client is handshaking must not be lost
/// silently: the driver **buffers** it and delivers it once the session
/// exists (D31 §7, B10).
///
/// Pre-fix, `app_outbound` returned `Err(NoSession)` and the driver matched
/// it with `{}` — the payload was gone with no signal at all.  The pre-fix
/// client also had no session for the whole M3 retransmission budget
/// (≈7.75 s), so *every* payload pushed during the handshake was dropped and
/// the peer never saw one.
///
/// The assertion is therefore end-to-end: the payloads are pushed **before**
/// the driver starts, so they are certainly consumed while the client is
/// still handshaking, and the test asserts that the **server** receives all
/// of them.  A "no drop notification arrived" assertion would not
/// discriminate: the pre-fix code produced exactly the same observable.
#[tokio::test]
async fn client_driver_does_not_lose_application_data() {
    let mut server_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("server bind");
    let server_addr = server_udp.local_addr().expect("addr");

    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let client_kp = MlDsaKeypair::generate().expect("client keygen");
    let sc = HandshakeV2ServerConfig::new(server_kp, vec![client_kp.public_key()]);
    let cc = HandshakeV2ClientConfig::new(server_addr, client_kp, sc.identity.public.clone());

    let mut client_manager =
        ClientSessionManager::new(&cc, SessionLimits::default()).expect("client manager");
    let mut server_manager =
        ServerSessionManager::new(&sc, SessionLimits::default()).expect("server manager");

    let mut client_udp = UdpTransport::connect(server_addr).await.expect("connect");
    let (srv_app_tx, mut srv_app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (_srv_cmd_tx, srv_cmd_rx) = mpsc::channel::<pq_tunnel_core::ServerAppCommand>(64);
    let server_driver = tokio::spawn(async move {
        run_server_manager(
            &mut server_udp,
            &mut server_manager,
            srv_app_tx,
            srv_cmd_rx,
            no_cover(),
        )
        .await
    });

    let (app_tx, _app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    // The payloads are queued **before** the driver starts, so they are
    // certainly consumed while the client is handshaking.
    const PAYLOADS: usize = 4;
    for _ in 0..PAYLOADS {
        data_tx.send(vec![0x77; 32]).await.expect("push");
    }
    let driver = tokio::spawn(async move {
        run_client_manager(
            &mut client_udp,
            &mut client_manager,
            app_tx,
            data_rx,
            no_cover(),
        )
        .await
    });

    // The server must receive every payload: the client's data was buffered,
    // not dropped.
    let mut delivered = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while delivered < PAYLOADS && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), srv_app_rx.recv()).await {
            Ok(Some(ManagerNotification::Data { inner, .. })) => {
                assert_eq!(
                    &inner.payload[..32],
                    &[0x77u8; 32],
                    "the server must receive the payload the application sent"
                );
                delivered += 1;
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert_eq!(
        delivered, PAYLOADS,
        "every payload pushed during the handshake must be delivered, not lost (B10)"
    );
    assert!(
        !driver.is_finished(),
        "the driver must survive application data pushed during the handshake (B10)"
    );
    driver.abort();
    server_driver.abort();
}

/// The bounded outbound queue reports its drops to the application, so a
/// data loss is never silent (D31 §7).
#[tokio::test]
async fn client_driver_reports_outbound_drops() {
    let dead = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    let mut client_udp = UdpTransport::connect(dead_addr).await.expect("connect");

    let cc = fast_client_config(dead_addr);
    let mut manager = ClientSessionManager::new(&cc, SessionLimits::default()).expect("manager");
    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(256);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(1024);
    let driver = tokio::spawn(async move {
        run_client_manager(&mut client_udp, &mut manager, app_tx, data_rx, no_cover()).await
    });

    // Overflow the bounded queue (64 entries) — the drop is reported.
    for _ in 0..200 {
        if data_tx.send(vec![0x77; 32]).await.is_err() {
            break;
        }
    }
    let mut reported = 0u64;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), app_rx.recv()).await {
            Ok(Some(ManagerNotification::OutboundDropped { dropped })) => {
                assert!(dropped > 0);
                reported = reported.max(dropped);
                break;
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(
        reported > 0,
        "the application must be told that its payloads were dropped (D31 §7)"
    );
    assert!(!driver.is_finished(), "the driver must stay up");
    driver.abort();
}

/// D31 §5: with cover disabled, a peer that vanishes is detected by the
/// liveness rounds; the client tears the session down, reports it and
/// re-establishes — and the driver never exits.
///
/// This is the end-to-end version of B3: the pre-fix client had **no**
/// post-confirmation peer-loss detection at all, so a dead peer produced an
/// infinite re-handshake loop with no liveness signal.
#[tokio::test]
async fn client_detects_a_vanished_peer_with_cover_disabled() {
    // The server's address is known only after the bind.
    let mut server_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("server bind");
    let server_addr = server_udp.local_addr().expect("addr");

    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let client_kp = MlDsaKeypair::generate().expect("client keygen");
    let sc = HandshakeV2ServerConfig::new(server_kp, vec![client_kp.public_key()]);
    let cc = HandshakeV2ClientConfig::new(server_addr, client_kp, sc.identity.public.clone());

    // Fast liveness: a probe every second, two unanswered rounds.
    let client_limits = SessionLimits {
        liveness_probe_interval: Duration::from_secs(1),
        liveness_rounds: 2,
        ..SessionLimits::default()
    };
    let mut client_manager = ClientSessionManager::new(&cc, client_limits).expect("client manager");
    let mut server_manager =
        ServerSessionManager::new(&sc, SessionLimits::default()).expect("server manager");

    let mut client_udp = UdpTransport::connect(server_addr).await.expect("connect");
    let (srv_app_tx, _srv_app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (_srv_cmd_tx, srv_cmd_rx) = mpsc::channel::<pq_tunnel_core::ServerAppCommand>(64);
    let server_driver = tokio::spawn(async move {
        run_server_manager(
            &mut server_udp,
            &mut server_manager,
            srv_app_tx,
            srv_cmd_rx,
            no_cover(),
        )
        .await
    });

    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (_data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    let client_driver = tokio::spawn(async move {
        run_client_manager(
            &mut client_udp,
            &mut client_manager,
            app_tx,
            data_rx,
            no_cover(),
        )
        .await
    });

    // The session comes up: the client is confirmed by the ack to its
    // liveness probe (≈1 RTT, not the M3 retransmission budget).
    let mut ready = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !ready && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), app_rx.recv()).await {
            Ok(Some(ManagerNotification::Ready { .. })) => ready = true,
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(ready, "the client must reach Ready against a live server");

    // The peer vanishes.
    server_driver.abort();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The liveness rounds expire: the client reports the dead peer.
    let mut reason = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while reason.is_none() && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), app_rx.recv()).await {
            Ok(Some(ManagerNotification::Closed { reason: r, .. })) => reason = Some(r),
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert_eq!(
        reason,
        Some(CloseReason::PeerUnresponsive),
        "a vanished peer must be detected by the liveness rounds (B3)"
    );
    assert!(
        !client_driver.is_finished(),
        "the client driver must survive the peer's disappearance (B13)"
    );
    client_driver.abort();
}
