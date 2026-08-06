//! Shared E2E test harness (M5.3).
//!
//! Each test binary (`tests/e2e_smoke.rs`, `tests/e2e_adversarial.rs`)
//! recompiles this module independently and uses a different subset of its
//! helpers; allow dead code so per-binary warnings do not depend on which
//! sibling test uses what.
#![allow(dead_code)]
//!
//! The harness builds the full Tunnel stack on loopback:
//!
//! ```text
//! app —relay frame→ relay ─ client manager —wire— MITM proxy/sniffer —wire— relay ─→ server manager —forward→ echo
//! ```
//!
//! The MITM proxy relays opaque datagrams both ways and records every one of
//! them.  It is an **attacker-controlled relay**: tests can order it to inject
//! arbitrary datagrams toward either endpoint (`[ProxyCmd::Send]`), which is
//! exactly the capability a wire-level adversary holding no keys has.  The
//! proxy records direction, timing and full bytes of the legitimate traffic so
//! tests can build replay/tamper samples from real wire captures.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pq_crypto::MlDsaKeypair;
use pq_tunnel_core::{
    ClientSessionManager, CoverPolicy, HandshakeV2ClientConfig, HandshakeV2ServerConfig,
    ManagerNotification, PACKET_SIZE, PAYLOAD_LEN, ServerAppCommand, ServerSessionManager,
    SessionLimits, UdpTransport, WirePacket, is_handshake_fragment, run_client_manager,
    run_server_manager,
};
use pq_tunnel_lib::forward::Forwarder;
use pq_tunnel_lib::relay;
use pq_tunnel_lib::relay::{decode_relay, encode_relay};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Plaintext probe that must never appear on the wire in the clear.
pub const MARKER: &[u8] = b"PQ-SMOKE-7f3a9c1e2c4d8f6a-marker";

/// Overall deadline for handshake + roundtrip on loopback.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// Cover cadence interval for the M3 legs (25 ms ≈ ~40 pkt/s/direction).
pub const COVER_INTERVAL: Duration = Duration::from_millis(25);

/// Idle-observation window for the cadence and no-cover legs.
pub const OBSERVE: Duration = Duration::from_millis(1300);

/// True if `needle` is a contiguous substring of `hay`.
pub fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// One datagram observed by the gate's proxy, tagged by direction, time and
/// full bytes (the bytes let adversarial tests replay/tamper real wire
/// traffic).
pub struct Wire {
    pub from_server: bool,
    pub at: Instant,
    pub data: Vec<u8>,
}

/// A command from the test to the MITM proxy (the attacker's injection channel).
pub enum ProxyCmd {
    /// Inject an arbitrary datagram toward one endpoint. `to_server == true`
    /// sends toward the server (a client-looking datagram), `false` toward the
    /// client (a server-looking datagram). The proxy always carries a peer
    /// address, so both directions are injectable from the wire.
    Send { data: Vec<u8>, to_server: bool },
}

/// A full stack with a direction/bytes-recording, commandable proxy.  Tasks
/// are held so the test always tears the network down, even on assertion
/// failure.
pub struct Gate {
    pub app: Arc<UdpSocket>,
    pub relay_addr: SocketAddr,
    pub echo_addr: SocketAddr,
    pub timing: Arc<Mutex<Vec<Wire>>>,
    pub cmd: mpsc::UnboundedSender<ProxyCmd>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Gate {
    pub fn stop(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }

    /// Order the MITM proxy to send `data` toward the server.
    pub fn inject_to_server(&self, data: Vec<u8>) {
        let _ = self.cmd.send(ProxyCmd::Send {
            data,
            to_server: true,
        });
    }

    /// Order the MITM proxy to send `data` toward the client.
    pub fn inject_to_client(&self, data: Vec<u8>) {
        let _ = self.cmd.send(ProxyCmd::Send {
            data,
            to_server: false,
        });
    }

    /// Snapshot of the wire captures headed toward the server (client→server).
    pub fn captured_to_server(&self) -> Vec<Vec<u8>> {
        self.timing
            .lock()
            .unwrap()
            .iter()
            .filter(|w| !w.from_server)
            .map(|w| w.data.clone())
            .collect()
    }

    /// Snapshot of the wire captures headed toward the client (server→client).
    pub fn captured_to_client(&self) -> Vec<Vec<u8>> {
        self.timing
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.from_server)
            .map(|w| w.data.clone())
            .collect()
    }

    /// A captured client→server datagram whose payload is not a handshake
    /// fragment — i.e. an established-session data packet.  Attacks that
    /// assume an encrypted payload (replay, AEAD tamper) use this.
    pub fn captured_data_to_server(&self) -> Vec<Vec<u8>> {
        self.captured_to_server()
            .into_iter()
            .filter(|d| {
                WirePacket::from_bytes(d)
                    .map(|p| !is_handshake_fragment(&p))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// A captured server→client datagram of the session data plane.
    pub fn captured_data_to_client(&self) -> Vec<Vec<u8>> {
        self.captured_to_client()
            .into_iter()
            .filter(|d| {
                WirePacket::from_bytes(d)
                    .map(|p| !is_handshake_fragment(&p))
                    .unwrap_or(false)
            })
            .collect()
    }
}

/// Build the full stack once, with a direction/time/bytes-recording proxy that
/// also accepts injection commands.
pub async fn build_gate(policy: CoverPolicy) -> Gate {
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

    // MITM proxy: relay-wise (opaque), record (direction, time, bytes), and
    // accept attack commands while relaying.
    let timing: Arc<Mutex<Vec<Wire>>> = Arc::new(Mutex::new(Vec::new()));
    let timing_main = timing.clone();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<ProxyCmd>();
    let proxy = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("proxy bind");
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let mut client_addr: Option<SocketAddr> = None;
        let mut buf = vec![0u8; PACKET_SIZE + 1];
        loop {
            tokio::select! {
                r = proxy.recv_from(&mut buf) => {
                    let (n, from) = match r {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let datagram = buf[..n].to_vec();
                    let from_server = from == server_addr;
                    timing_main
                        .lock()
                        .unwrap()
                        .push(Wire { from_server, at: Instant::now(), data: datagram.clone() });
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
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        ProxyCmd::Send { data, to_server } => {
                            let target = if to_server {
                                server_addr
                            } else {
                                client_addr.expect("no client has spoken yet")
                            };
                            if proxy.send_to(&data, target).await.is_err() {
                                break;
                            }
                        }
                    }
                }
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
    let (cmd_srv_tx, cmd_srv_rx) = mpsc::channel::<ServerAppCommand>(64);
    let server_driver = tokio::spawn(async move {
        let _ = run_server_manager(
            &mut server_udp,
            &mut server_mgr,
            srv_app_tx,
            cmd_srv_rx,
            policy,
        )
        .await;
    });
    let app_task = tokio::spawn(async move {
        let mut forwarder = Forwarder::new(false, cmd_srv_tx);
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
        cmd: cmd_tx,
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
pub async fn gate_roundtrip(gate: &Gate) {
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
pub fn count_in_window(wire: &[Wire], from_server: bool, after: Instant) -> usize {
    wire.iter()
        .filter(|w| w.from_server == from_server && w.at >= after)
        .count()
}

/// Longest gap between consecutive datagrams of a direction at-or-after `after`.
pub fn max_gap(wire: &[Wire], from_server: bool, after: Instant) -> Option<Duration> {
    let mut times: Vec<Instant> = wire
        .iter()
        .filter(|w| w.from_server == from_server && w.at >= after)
        .map(|w| w.at)
        .collect();
    times.sort_unstable();
    times.windows(2).map(|g| g[1].duration_since(g[0])).max()
}
