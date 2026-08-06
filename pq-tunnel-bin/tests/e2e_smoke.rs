//! M2 E2E smoke gate (D18 application model).
//!
//! Drives the real stack end-to-end on loopback:
//!
//! ```text
//! app ──relay frame──▶ relay │ client manager ──wire──▶ MITM proxy/sniffer ──wire──▶
//! ◀──────────────────── relay ◀─ reply wire ◀── server manager ◀── forwarder ◀── echo
//! ```
//!
//! The MITM proxy sits between the two transports with **no keys** — it relays
//! opaque blobs while retaining a byte-for-byte copy of every datagram. The
//! smoke gate asserts:
//!
//! 1. **Fixed-size envelopes on the wire** — every datagram observed by the
//!    proxy (handshake fragments and data alike) is exactly [`PACKET_SIZE`]
//!    bytes.
//! 2. **No plaintext bypass** — the plaintext marker never appears as a
//!    contiguous substring of any sniffed datagram; it lives only inside AEAD
//!    slots.
//! 3. **Round trip** — an app datagram sent to the relay's recorded
//!    destination comes back via that same destination, byte-identical.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pq_crypto::MlDsaKeypair;
use pq_tunnel_core::{
    ClientSessionManager, CoverPolicy, HandshakeV2ClientConfig, HandshakeV2ServerConfig,
    ManagerNotification, PACKET_SIZE, PAYLOAD_LEN, ServerAppCommand, ServerSessionManager,
    SessionLimits, UdpTransport, run_client_manager, run_server_manager,
};
use pq_tunnel_lib::forward::Forwarder;
use pq_tunnel_lib::relay;
use pq_tunnel_lib::relay::{decode_relay, encode_relay};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Plaintext probe that must never appear on the wire in the clear.
const MARKER: &[u8] = b"PQ-SMOKE-7f3a9c1e2c4d8f6a-marker";

/// Overall deadline for handshake + roundtrip on loopback.
const DEADLINE: Duration = Duration::from_secs(30);

/// Cover cadence interval for the M3 legs (25 ms → ~40 pkt/s/direction).
const COVER_INTERVAL: Duration = Duration::from_millis(25);

/// Idle-observation window for the cadence and no-cover legs.
const OBSERVE: Duration = Duration::from_millis(1300);

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn e2e_smoke_forwarding_roundtrip() {
    // -------------------------------------------------------------------
    // Out-of-band provisioning (D17): server identity + pinned client key.
    // -------------------------------------------------------------------
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let client_kp = MlDsaKeypair::generate().expect("client keygen");

    // -------------------------------------------------------------------
    // Server manager + UDP transport (bound first so its address is known).
    // -------------------------------------------------------------------
    let server_pk = server_kp.public_key();
    let sc = HandshakeV2ServerConfig::new(server_kp, vec![client_kp.public_key()]);
    let mut server_mgr = ServerSessionManager::new(&sc, SessionLimits::default())
        .expect("server session manager init");
    let mut server_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("server bind");
    let server_addr = server_udp.local_addr().unwrap();
    assert!(server_addr.ip().is_loopback(), "smoke must run on loopback");

    // -------------------------------------------------------------------
    // Echo backend: the remote application the tunnel will reach.
    // -------------------------------------------------------------------
    let echo = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("echo bind");
    let echo_addr = echo.local_addr().unwrap();
    assert!(
        echo_addr.is_ipv4(),
        "echo target must be IPv4 in this smoke"
    );
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0u8; PAYLOAD_LEN + 1];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            if echo.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });

    // -------------------------------------------------------------------
    // MITM proxy/sniffer: relays both directions, keeping every datagram.
    // -------------------------------------------------------------------
    let proxy = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("proxy bind");
    let proxy_addr = proxy.local_addr().unwrap();
    let sniffed: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let sniff = sniffed.clone();
    let proxy_task = tokio::spawn(async move {
        // The server's bound address is known from the start, so direction is
        // unambiguous: `from == server_addr` is a server → client datagram
        // (the server answers from its own bound port), anything else is the
        // client → server path (the first such packet records the client).
        let mut client_addr: Option<SocketAddr> = None;
        let mut buf = vec![0u8; PACKET_SIZE + 1];
        while let Ok((n, from)) = proxy.recv_from(&mut buf).await {
            // Keep the datagram even if oversized — the final assertion
            // surfaces envelope-size violations.
            let datagram = buf[..n].to_vec();
            sniff.lock().unwrap().push(datagram.clone());
            let target = if from == server_addr {
                client_addr.expect("server cannot speak before the client")
            } else {
                client_addr = Some(from);
                server_addr
            };
            if proxy.send_to(&datagram, target).await.is_err() {
                break;
            }
        }
    });

    // -------------------------------------------------------------------
    // Client manager + transport, wired through the proxy.
    // -------------------------------------------------------------------
    // Client completes after the first M3 (attempts budget 0): a passive
    // server sends no explicit M4, so waiting on the retransmit budget would
    // delay establishment past any reasonable deadline (the driver converges
    // on `Complete` at `attempts >= m3_max_attempts`).
    let mut cc = HandshakeV2ClientConfig::new(proxy_addr, client_kp, server_pk);
    cc.m3_max_attempts = 0;
    let mut client_mgr = ClientSessionManager::new(&cc, SessionLimits::default())
        .expect("client session manager init");
    let mut client_udp = UdpTransport::connect(proxy_addr)
        .await
        .expect("client transport connect");

    // -------------------------------------------------------------------
    // Server drivers: transport manager + forwarding application.
    // -------------------------------------------------------------------
    let (srv_app_tx, mut srv_app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<ServerAppCommand>(64);
    let policy_here = CoverPolicy::default();
    let server_driver = tokio::spawn(async move {
        run_server_manager(
            &mut server_udp,
            &mut server_mgr,
            srv_app_tx,
            cmd_rx,
            policy_here,
        )
        .await
    });
    let app_task = tokio::spawn(async move {
        let mut forwarder = Forwarder::new(false, cmd_tx);
        while let Some(ntf) = srv_app_rx.recv().await {
            match ntf {
                ManagerNotification::Data { sid, inner } => {
                    forwarder.handle(sid, &inner.payload).await;
                }
                ManagerNotification::Closed { sid, .. } => forwarder.on_session_closed(sid),
                ManagerNotification::Established { .. } | ManagerNotification::Ready { .. } => {}
            }
        }
        forwarder.shutdown();
    });

    // -------------------------------------------------------------------
    // Client drivers: transport manager + the local relay (D18).
    // -------------------------------------------------------------------
    let (app_tx, app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    let client_driver = tokio::spawn(async move {
        run_client_manager(
            &mut client_udp,
            &mut client_mgr,
            app_tx,
            data_rx,
            policy_here,
        )
        .await
    });
    let relay_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("relay bind");
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay_task = tokio::spawn(relay::run(relay_socket, data_tx, app_rx));

    // -------------------------------------------------------------------
    // The application: send a relay-framed probe to the relay; expect the
    // echo reply back through the tunnel.
    // -------------------------------------------------------------------
    let app = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("app bind");
    let frame = encode_relay(echo_addr, MARKER).expect("probe must fit the slot");
    let mut recv_buf = vec![0u8; PAYLOAD_LEN];
    let start = Instant::now();
    let mut got = false;
    while !got {
        if start.elapsed() > DEADLINE {
            panic!("smoke roundtrip timed out after {DEADLINE:?}");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Resend while the client handshakes: outbound data during
                // establishment is dropped (NoSession) — D16 recovers.
                app.send_to(&frame, relay_addr).await.expect("app send");
            }
            r = app.recv_from(&mut recv_buf) => {
                let (n, _from) = r.expect("app recv");
                let (dest, payload) =
                    decode_relay(&recv_buf[..n]).expect("reply must be relay-framed");
                assert_eq!(dest, echo_addr, "reply must be labeled with the recorded dest");
                assert_eq!(payload, MARKER, "roundtrip payload mismatch");
                got = true;
            }
        }
    }

    // -------------------------------------------------------------------
    // Wire assertions (the smoke gate).
    // -------------------------------------------------------------------
    {
        let s = sniffed.lock().unwrap();
        assert!(
            !s.is_empty(),
            "the MITM proxy observed no wire datagrams at all"
        );
        let mut sizes: Vec<usize> = s.iter().map(|d| d.len()).collect();
        sizes.sort_unstable();
        assert!(
            sizes.iter().all(|&n| n == PACKET_SIZE),
            "every wire envelope must be exactly {PACKET_SIZE} bytes; saw sizes {sizes:?}"
        );
        for d in s.iter() {
            assert!(
                !contains_subslice(d, MARKER),
                "plaintext marker leaked onto the wire: {MARKER:?}"
            );
        }
        assert!(
            s.len() >= 3,
            "expected handshake fragments + data roundtrip on the wire, saw {}",
            s.len()
        );
    }

    // -------------------------------------------------------------------
    // Teardown: stop all tasks.
    // -------------------------------------------------------------------
    echo_task.abort();
    proxy_task.abort();
    server_driver.abort();
    app_task.abort();
    client_driver.abort();
    relay_task.abort();
}

// ---------------------------------------------------------------------------
// M3 gate: cover-cadence measurements over the same loopback stack.
// ---------------------------------------------------------------------------

/// One datagram observed by the gate's proxy, tagged by direction and time.
/// Spacing is only ever measured at *protocol* granularity — a coarse upper
/// bound that tolerates OS scheduling jitter (D5).
struct Wire {
    from_server: bool,
    at: Instant,
}

/// A full stack with a direction-and-time-recording proxy.  Tasks are held so
/// the test always tears the network down, even on assertion failure.
struct Gate {
    app: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    echo_addr: SocketAddr,
    timing: Arc<Mutex<Vec<Wire>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gate {
    fn stop(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Build the full stack once (like the smoke above) but record
/// `(direction, time)` per datagram for cadence assertions.
async fn build_gate(policy: CoverPolicy) -> Gate {
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let client_kp = MlDsaKeypair::generate().expect("client keygen");
    let server_pk = server_kp.public_key();

    let sc = HandshakeV2ServerConfig::new(server_kp, vec![client_kp.public_key()]);
    let mut server_mgr = ServerSessionManager::new(&sc, SessionLimits::default())
        .expect("server session manager init");
    let mut server_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("server bind");
    let server_addr = server_udp.local_addr().unwrap();
    assert!(server_addr.ip().is_loopback(), "gate must run on loopback");

    let echo = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("echo bind");
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0u8; PAYLOAD_LEN + 1];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            if echo.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });

    // MITM proxy: relay-wise (opaque) + record (direction, time).
    let timing: Arc<Mutex<Vec<Wire>>> = Arc::new(Mutex::new(Vec::new()));
    let timing_main = timing.clone();
    let proxy = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("proxy bind");
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let mut client_addr: Option<SocketAddr> = None;
        let mut buf = vec![0u8; PACKET_SIZE + 1];
        while let Ok((n, from)) = proxy.recv_from(&mut buf).await {
            let datagram = buf[..n].to_vec();
            let from_server = from == server_addr;
            timing_main.lock().unwrap().push(Wire {
                from_server,
                at: Instant::now(),
            });
            let target = if from_server {
                client_addr.expect("server cannot speak before the client")
            } else {
                client_addr = Some(from);
                server_addr
            };
            if proxy.send_to(&datagram, target).await.is_err() {
                break;
            }
        }
    });

    let mut cc = HandshakeV2ClientConfig::new(proxy_addr, client_kp, server_pk);
    cc.m3_max_attempts = 0;
    let mut client_manager = ClientSessionManager::new(&cc, SessionLimits::default())
        .expect("client session manager init");
    let mut client_udp = UdpTransport::connect(proxy_addr)
        .await
        .expect("client transport connect");

    let (srv_app_tx, mut srv_app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<ServerAppCommand>(64);
    let server_driver = tokio::spawn(async move {
        let _ =
            run_server_manager(&mut server_udp, &mut server_mgr, srv_app_tx, cmd_rx, policy).await;
    });
    let app_task = tokio::spawn(async move {
        let mut forwarder = Forwarder::new(false, cmd_tx);
        while let Some(ntf) = srv_app_rx.recv().await {
            match ntf {
                ManagerNotification::Data { sid, inner } => {
                    forwarder.handle(sid, &inner.payload).await;
                }
                ManagerNotification::Closed { sid, .. } => forwarder.on_session_closed(sid),
                ManagerNotification::Established { .. } | ManagerNotification::Ready { .. } => {}
            }
        }
        forwarder.shutdown();
    });

    let (app_tx, app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    let client_driver = tokio::spawn(async move {
        let _ = run_client_manager(
            &mut client_udp,
            &mut client_manager,
            app_tx,
            data_rx,
            policy,
        )
        .await;
    });
    let relay_socket = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("relay bind");
    let relay_addr = relay_socket.local_addr().unwrap();
    let relay_task = tokio::spawn(async move {
        let _ = relay::run(relay_socket, data_tx, app_rx).await;
    });

    let app = Arc::new(
        UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("app bind"),
    );

    Gate {
        app,
        relay_addr,
        echo_addr,
        timing,
        tasks: vec![
            echo_task,
            proxy_task,
            server_driver,
            app_task,
            client_driver,
            relay_task,
        ],
    }
}

/// Relay a MARKER round trip once (proves the client Established + Ready).
async fn gate_roundtrip(gate: &Gate) {
    let frame = encode_relay(gate.echo_addr, MARKER).expect("probe fits payload slot");
    let mut recv_buf = vec![0u8; PAYLOAD_LEN];
    let start = Instant::now();
    let mut got = false;
    while !got {
        if start.elapsed() > DEADLINE {
            panic!("gate roundtrip timed out after {DEADLINE:?}");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                let _ = gate.app.send_to(&frame, gate.relay_addr).await;
            }
            r = gate.app.recv_from(&mut recv_buf) => {
                let (n, _) = r.expect("app recv");
                let (dest, payload) =
                    decode_relay(&recv_buf[..n]).expect("reply must be relay-framed");
                assert_eq!(dest, gate.echo_addr);
                assert_eq!(payload, MARKER, "roundtrip mismatch");
                got = true;
            }
        }
    }
}

/// Count datagrams of one direction arriving at-or-after `after`.
fn count_in_window(wire: &[Wire], from_server: bool, after: Instant) -> usize {
    wire.iter()
        .filter(|w| w.from_server == from_server && w.at >= after)
        .count()
}

/// Longest gap between consecutive datagrams of a direction at-or-after `after`.
fn max_gap(wire: &[Wire], from_server: bool, after: Instant) -> Option<Duration> {
    let mut times: Vec<Instant> = wire
        .iter()
        .filter(|w| w.from_server == from_server && w.at >= after)
        .map(|w| w.at)
        .collect();
    times.sort_unstable();
    times.windows(2).map(|g| g[1].duration_since(g[0])).max()
}

/// M3 cadence gate: with cover enabled, an *idle* established link maintains a
/// stable wire pattern — protocol-level constant-rate over time (D5), not
/// nanosecond alignment.  Asserts per direction:
///
/// * observed emissions fall in a wide count band (separates "stable pattern"
///   from "only-when-data" (≈0) and from burst doubling (≈2×));
/// * no single inter-packet gap exceeds a coarse bound (no intentional idle
///   hole in the pattern).
///
/// The no-burst-catch-up guarantee (one emission max per missed deadline) is
/// owned by the scheduler's unit tests; this leg pins the aggregate pattern.
#[tokio::test]
async fn e2e_cover_cadence_stable_when_idle() {
    let gate = build_gate(CoverPolicy {
        enabled: true,
        interval: COVER_INTERVAL,
    })
    .await;
    gate_roundtrip(&gate).await;

    // Observe the idle link after establishment.  The roundtrip proves the
    // client is Ready; the watermark skips all handshake/carry-over traffic.
    let after = Instant::now();
    tokio::time::sleep(OBSERVE).await;

    let observed = gate.timing.lock().unwrap();
    let expected = OBSERVE.as_secs_f64() / COVER_INTERVAL.as_secs_f64();
    let lo = (expected * 0.5) as usize;
    let hi = (expected * 2.0) as usize + 1;

    for (label, from_server) in [("client→server", false), ("server→client", true)] {
        let n = count_in_window(&observed, from_server, after);
        assert!(
            (lo..=hi).contains(&n),
            "{label}: idle cover count {n} outside {lo}..={hi} (expected ≈{expected:.0} over {OBSERVE:?}); \
             the link must keep a stable, non-zero, non-bursting wire pattern"
        );
        let gap = max_gap(&observed, from_server, after);
        assert!(
            gap.is_none_or(|g| g <= Duration::from_millis(500)),
            "{label}: the cover pattern went silent (longest gap {gap:?} ≥ 500 ms)"
        );
    }

    gate.stop();
}

/// M3 no-cover gate: `--no-cover` kills *emission only* — the roundtrip still
/// works and the idle data-plane goes quiet (no packets where cover would be).
#[tokio::test]
async fn e2e_no_cover_emits_nothing_when_idle() {
    let gate = build_gate(CoverPolicy {
        enabled: false,
        interval: COVER_INTERVAL,
    })
    .await;
    gate_roundtrip(&gate).await;

    let after = Instant::now();
    tokio::time::sleep(OBSERVE).await;

    let observed = gate.timing.lock().unwrap();
    for (label, from_server) in [("client→server", false), ("server→client", true)] {
        let n = count_in_window(&observed, from_server, after);
        assert!(
            n <= 2,
            "{label}: no-cover policy still emitted {n} packets while idle"
        );
    }

    gate.stop();
}
