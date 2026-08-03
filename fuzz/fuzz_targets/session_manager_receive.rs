#![no_main]

//! Fuzz target: session-manager receive paths (server + client).
//!
//! Feeds arbitrary 1280-byte datagrams through `ServerSessionManager` and
//! `ClientSessionManager`, then drives a deterministic M1→M2→M3 exchange so
//! the established-session surface (decrypt, roaming rebind, fail gate,
//! cover, app outbound, Close, eviction, deadlines) is reachable.  Every
//! peer-input path MUST be a silent drop with zero panic risk: garbage
//! dispatch, tampered ciphertexts, forged handshakes and forged session
//! packets all funnel through here (H1/D12/D13/D15/D16).

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::{
    ClientHandshake, ClientSessionManager, HandshakeV2ClientConfig, HandshakeV2ServerConfig,
    ManagerEvent, ServerSessionManager, SessionLimits, WirePacket, PACKET_SIZE, PROTOCOL_VERSION,
    SESSION_ID_LEN,
};

struct Configs {
    client_cfg: HandshakeV2ClientConfig,
    server_cfg: HandshakeV2ServerConfig,
}

static CONFIGS: OnceLock<Configs> = OnceLock::new();

fn configs() -> &'static Configs {
    CONFIGS.get_or_init(|| {
        let client_id = pq_crypto::MlDsaKeypair::generate().expect("client keygen");
        let server_id = pq_crypto::MlDsaKeypair::generate().expect("server keygen");
        let server_addr: SocketAddr = "127.0.0.1:40002".parse().expect("valid addr");
        let client_cfg =
            HandshakeV2ClientConfig::new(server_addr, client_id.clone(), server_id.public.clone());
        let server_cfg = HandshakeV2ServerConfig::new(server_id, vec![client_id.public]);
        Configs {
            client_cfg,
            server_cfg,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let cfg = configs();
    let from: SocketAddr = "127.0.0.1:40001".parse().expect("valid addr");
    let sid = [0x42u8; SESSION_ID_LEN];

    let mut server = match ServerSessionManager::new(&cfg.server_cfg, SessionLimits::default()) {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut client = match ClientSessionManager::new(&cfg.client_cfg, SessionLimits::default()) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Arbitrary datagram into both managers (garbage/forgery paths).
    let mut dg = [0u8; PACKET_SIZE];
    let n = data.len().min(PACKET_SIZE);
    dg[..n].copy_from_slice(&data[..n]);
    if let Ok(pkt) = WirePacket::from_bytes(&dg) {
        let _ = server.handle_datagram(&pkt, from);
        let _ = client.handle_datagram(&pkt, from);
    }

    // Client re-arm path (fresh random sid) — always allowed from Idle.
    let _ = client.begin_handshake();

    // Deterministic exchange: client manager ↔ server manager so both reach
    // their established-session surfaces.
    let Some(csid) = client.handshake_sid() else {
        return;
    };
    let mut hs_client = match ClientHandshake::new(&cfg.client_cfg, csid) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut m2 = Vec::new();
    for f in hs_client.m1_frags() {
        if let Ok(ManagerEvent::Send { packets, .. }) = server.handle_datagram(f, from) {
            m2 = packets;
        }
    }
    let mut m3 = Vec::new();
    for f in &m2 {
        if let Ok(ManagerEvent::Send { packets, .. }) = client.handle_datagram(f, from) {
            m3 = packets;
        }
    }
    for f in &m3 {
        if let Ok(ManagerEvent::Established { .. }) = server.handle_datagram(f, from) {
            // Sessions may be evicted by capacity; nothing to assert.
        }
    }
    // Drive the client machine's timer to completion (no sleeping: pure).
    for _ in 0..=cfg.client_cfg.m3_max_attempts {
        let _ = hs_client.on_timer();
        if let Ok(ManagerEvent::Closed { .. }) = client.on_timer() {
            break;
        }
    }

    // Established-session paths on both sides (silent no-session errors).
    let _ = server.app_outbound(&sid, &data[..data.len().min(64)]);
    let _ = server.cover_packet(&sid);
    let _ = server.close_session(&sid);
    if let Some(sid) = client.session_id() {
        let _ = client.app_outbound(&data[..data.len().min(64)]);
        let _ = client.cover_packet();
        let _ = client.close();
        let _ = server.handle_datagram(&data_fragment(data, sid), from);
    }
    let _ = client.handshake_sid();

    // Timer paths: deadlines, liveness, idle, lifetime, nonce-exhaustion
    // Closed events, and the queued-closed drain.
    let _ = server.tick(Instant::now());
    let _ = client.tick(Instant::now());
    let _ = server.pending_handshakes();
    let _ = server.fail_bucket_count();
    let _ = client.is_ready();
});

/// A `Data`-typed datagram crafted from the input (deep decrypt/replay paths).
fn data_fragment(data: &[u8], sid: [u8; SESSION_ID_LEN]) -> WirePacket {
    let mut dg = [0u8; PACKET_SIZE];
    let n = data.len().min(PACKET_SIZE - 9);
    dg[..n].copy_from_slice(&data[..n]);
    dg[1..9].copy_from_slice(&sid);
    dg[9] = 0x00; // data dispatch (not a handshake fragment)
    dg[0] = PROTOCOL_VERSION;
    WirePacket::from_bytes(&dg).expect("fixed-size buffer parses")
}
