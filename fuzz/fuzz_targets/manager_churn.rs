#![no_main]

//! Fuzz target: scripted manager churn (state-machine sequencing).
//!
//! Unlike `session_manager_receive` (arbitrary datagrams), this target treats
//! the input as a **script**: opcodes drive the managers through arbitrary
//! sequences of app outbound, datagram delivery (garbage + crafted data
//! packets), handshake begin/re-arm, timers, cover, close, session close,
//! and full manager reset — across multiple session ids.
//!
//! It is the deterministic complement to the tokio-level races exercised by
//! the E2E stress suite (B3): pure-logic sequencing bugs (close-then-use,
//! reset-then-use, cross-sid eviction, re-arm while closed, payload window
//! fences) must terminate in a silent no-op or a documented error — never a
//! panic, never an invariant violation. Every path is driven through the
//! public API only; assertions are structural (any `expect`/`unwrap` on a
//! wire-derived value would be a crash artifact).

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Instant;

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::{
    ClientSessionManager, HandshakeV2ClientConfig, HandshakeV2ServerConfig, ManagerEvent,
    PACKET_SIZE, PAYLOAD_LEN, PROTOCOL_VERSION, SESSION_ID_LEN, ServerSessionManager,
    SessionLimits, WirePacket,
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
        let server_addr: SocketAddr = "127.0.0.1:40012".parse().expect("valid addr");
        let client_cfg =
            HandshakeV2ClientConfig::new(server_addr, client_id.clone(), server_id.public.clone());
        let server_cfg = HandshakeV2ServerConfig::new(server_id, vec![client_id.public]);
        Configs {
            client_cfg,
            server_cfg,
        }
    })
}

const N_SIDS: usize = 4;

fn sids() -> [[u8; SESSION_ID_LEN]; N_SIDS] {
    let mut out = [[0u8; SESSION_ID_LEN]; N_SIDS];
    for (i, s) in out.iter_mut().enumerate() {
        s.fill(0x40 + i as u8);
    }
    out
}

/// Take a byte-sliced token from the stream, clamped to what remains.
fn consume<'a>(d: &mut &'a [u8]) -> &'a [u8] {
    let Some(&n0) = d.first() else {
        return &[];
    };
    *d = &d[1..];
    let n = (n0 as usize).min(d.len());
    let (a, b) = d.split_at(n);
    *d = b;
    a
}

/// Craft a `Data`-typed datagram from stream bytes for a given sid: the deep
/// decrypt/replay path into a (possibly live) session.
fn data_fragment(d: &mut &[u8], sid: &[u8; SESSION_ID_LEN]) -> Vec<u8> {
    let b = consume(d);
    let mut dg = vec![0u8; PACKET_SIZE];
    let n = b.len().min(PACKET_SIZE - 9);
    dg[..n].copy_from_slice(&b[..n]);
    dg[1..9].copy_from_slice(sid);
    dg[9] = 0x00; // data dispatch (not a handshake fragment)
    dg[0] = PROTOCOL_VERSION;
    dg
}

fuzz_target!(|data: &[u8]| {
    let cfg = configs();
    let from: SocketAddr = "127.0.0.1:40011".parse().expect("valid addr");
    let sids = sids();

    let mut server = match ServerSessionManager::new(&cfg.server_cfg, SessionLimits::default()) {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut client = match ClientSessionManager::new(&cfg.client_cfg, SessionLimits::default()) {
        Ok(m) => m,
        Err(_) => return,
    };

    let mut d = data;
    let mut ops = 0u32;
    while !d.is_empty() && ops < 512 {
        ops += 1;
        let op = *d.first().expect("nonempty checked");
        d = &d[1..];
        match op {
            // Server app outbound on one of the script sids (no session yet
            // is the ordinary case → silent error).
            0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 => {
                let sid = &sids[(op as usize) % N_SIDS];
                let payload = consume(&mut d);
                let _ = server.app_outbound(sid, payload);
            }
            // Client app outbound: succeeds once a session is live; error
            // otherwise. Payload longer than the slot must be the documented
            // WrongLength error — never a panic.
            0x08 => {
                let payload = {
                    // Build the largest possible stream slice; if the script
                    // requests more than the slot, that is the error path.
                    let b = consume(&mut d);
                    let mut pv = vec![u8::MAX; PAYLOAD_LEN + 2];
                    let n = b.len().min(pv.len());
                    pv[..n].copy_from_slice(&b[..n]);
                    pv
                };
                let _ = client.app_outbound(&payload);
            }
            // Client close: may succeed or be a silent already-closed error.
            0x09 => {
                let _ = client.close();
            }
            // Server close of a script sid.
            0x0A => {
                let sid = &sids[(d.first().copied().unwrap_or(0) as usize) % N_SIDS];
                d = &d[1..];
                let _ = server.close_session(sid);
            }
            // Re-arm the client handshake (always allowed from Idle).
            0x0B => {
                let _ = client.begin_handshake();
            }
            // Server cover / client cover.
            0x0C => {
                let sid = &sids[(d.first().copied().unwrap_or(0) as usize) % N_SIDS];
                d = &d[1..];
                let _ = server.cover_packet(sid);
                let _ = client.cover_packet();
            }
            // Feed arbitrary transport bytes to both managers.
            0x0D => {
                let b = consume(&mut d);
                if !b.is_empty() {
                    let mut dg = [0u8; PACKET_SIZE];
                    let n = b.len().min(PACKET_SIZE);
                    dg[..n].copy_from_slice(&b[..n]);
                    if let Ok(pkt) = WirePacket::from_bytes(&dg) {
                        let _ = server.handle_datagram(&pkt, from);
                        let _ = client.handle_datagram(&pkt, from);
                    }
                }
            }
            // Crafted Data fragment at a live session (deep decrypt/replay).
            0x0E => {
                let sid = &sids[(d.first().copied().unwrap_or(0) as usize) % N_SIDS];
                d = &d[1..];
                let dg = data_fragment(&mut d, sid);
                if let Ok(pkt) = WirePacket::from_bytes(&dg) {
                    let _ = server.handle_datagram(&pkt, from);
                    let _ = client.handle_datagram(&pkt, from);
                }
            }
            // Timer paths: the deadlines/liveness machinery on both sides.
            0x0F => {
                let _ = server.tick(Instant::now());
                let _ = client.tick(Instant::now());
                let _ = client.on_timer();
                let _ = server.pending_handshakes();
                let _ = server.fail_bucket_count();
                let _ = client.is_ready();
            }
            // Deterministic handshake drive client→server (reach established
            // surfaces mid-churn).
            0x10 => {
                let Some(csid) = client.handshake_sid() else {
                    break;
                };
                let hs_client = match pq_tunnel_core::ClientHandshake::new(&cfg.client_cfg, csid)
                {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let mut m2 = Vec::new();
                for f in hs_client.m1_frags() {
                    if let Ok(ManagerEvent::Send { packets, .. }) = server.handle_datagram(f, from)
                    {
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
                        // Sessions may be evicted; nothing to assert.
                    }
                }
            }
            // Fresh managers (full state reset mid-script).
            _ => {
                server = match ServerSessionManager::new(&cfg.server_cfg, SessionLimits::default())
                {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                client = match ClientSessionManager::new(&cfg.client_cfg, SessionLimits::default())
                {
                    Ok(m) => m,
                    Err(_) => continue,
                };
            }
        }
    }

    // Probes at teardown in whatever final state: must all be silent/empty.
    let _ = server.tick(Instant::now());
    let _ = client.tick(Instant::now());
    let _ = client.handshake_sid();
    let _ = server.pending_handshakes();
    let _ = server.fail_bucket_count();
});