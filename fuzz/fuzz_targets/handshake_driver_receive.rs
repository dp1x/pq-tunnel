#![no_main]

//! Fuzz target: v2 handshake receive paths (client + server state machines).
//!
//! Feeds arbitrary 1280-byte datagrams — and complete fragment sets built
//! from the input — through `ClientHandshake::handle_datagram` and
//! `ServerHandshake::handle_datagram`.  Peer-input failures MUST be silent
//! drops (`ClientEvent::None` / `ServerEvent::None`) with zero panic risk:
//! malformed fragments, garbage ciphertexts, forged signatures and forged
//! Finished MACs all funnel through this code (D12/D13/D15).

use std::net::SocketAddr;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::{
    ClientHandshake, HandshakeV2ClientConfig, HandshakeV2ServerConfig, PACKET_SIZE,
    PROTOCOL_VERSION, SESSION_ID_LEN, ServerHandshake, WirePacket, fragment_message,
    message_body_len,
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
    let sid = [0x42u8; SESSION_ID_LEN];
    let from: SocketAddr = "127.0.0.1:40001".parse().expect("valid addr");

    // Client receive path: fresh machine per input (ephemeral keygen is part
    // of the harness, not the fuzzed surface).
    let mut client = match ClientHandshake::new(&cfg.client_cfg, sid) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Server receive path (cheap to construct).
    let mut server = ServerHandshake::new(&cfg.server_cfg);

    // Arbitrary datagram into both machines.
    let mut dg = [0u8; PACKET_SIZE];
    let n = data.len().min(PACKET_SIZE);
    dg[..n].copy_from_slice(&data[..n]);
    if let Ok(pkt) = WirePacket::from_bytes(&dg) {
        let _ = client.handle_datagram(&pkt);
        let _ = server.handle_datagram(&pkt, from);
    }

    // Complete fragment sets built from the input reach the deep paths:
    // assembler + M1/M2/M3 decode + roster verify + M2→M3 state machine.
    for hs_type in [0x10u8, 0x20, 0x30] {
        if let Some(len) = message_body_len(hs_type) {
            if data.len() >= len {
                if let Ok(frags) = fragment_message(hs_type, PROTOCOL_VERSION, sid, &data[..len]) {
                    for f in &frags {
                        let _ = client.handle_datagram(f);
                        let _ = server.handle_datagram(f, from);
                    }
                }
            }
        }
    }

    // Timer ticks (backoff/retransmit budget paths).
    let _ = client.on_timer();
});
