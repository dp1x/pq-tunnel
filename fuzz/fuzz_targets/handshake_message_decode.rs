#![no_main]

//! Fuzz target: v2 handshake message decoders + canonical transcripts.
//!
//! Feeds arbitrary bytes through the strict `ClientHello` / `ServerHello` /
//! `ClientConfirm` decoders, the TH1/TH2/TH3 canonical-transcript functions,
//! and the fragment framing (parse + deterministic re-fragmentation).  Every
//! entry point must return `Ok`/`Err`/`None` — never panic, never allocate
//! unboundedly (all buffers are pinned by the D13 message sizes).

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::{
    ClientConfirm, ClientHello, HandshakeFragment, ServerHello, WirePacket, fragment_message,
    is_handshake_fragment, message_body_len, th1_from_m1, th2_from_m1_m2, th3_from_m1_m2_m3,
    M1_BODY_LEN, M2_BODY_LEN, M3_BODY_LEN, PACKET_SIZE, PROTOCOL_VERSION, SESSION_ID_LEN,
};

fuzz_target!(|data: &[u8]| {
    // Decoders must never panic on arbitrary input (any length).
    let _ = ClientHello::decode(data);
    let _ = ServerHello::decode(data);
    let _ = ClientConfirm::decode(data);

    // Pinned-length slices exercise the strict length/version checks.
    if data.len() >= M1_BODY_LEN {
        let _ = ClientHello::decode(&data[..M1_BODY_LEN]);
    }
    if data.len() >= M2_BODY_LEN {
        let _ = ServerHello::decode(&data[..M2_BODY_LEN]);
    }
    if data.len() >= M3_BODY_LEN {
        let _ = ClientConfirm::decode(&data[..M3_BODY_LEN]);
    }

    // Canonical transcripts must never panic (fixed-length inputs).
    let _ = th1_from_m1(data);
    let _ = th2_from_m1_m2(data, data);
    let _ = th3_from_m1_m2_m3(data, data, data);

    // Fragment framing: wrap the input in a 1280-byte datagram.
    let mut dg = [0u8; PACKET_SIZE];
    let n = data.len().min(PACKET_SIZE);
    dg[..n].copy_from_slice(&data[..n]);
    if let Ok(pkt) = WirePacket::from_bytes(&dg) {
        let _ = is_handshake_fragment(&pkt);
        let _ = HandshakeFragment::from_datagram(&pkt);
    }

    // Deterministic re-fragmentation of input-content at pinned lengths.
    for hs_type in [0x10u8, 0x20, 0x30] {
        if let Some(len) = message_body_len(hs_type) {
            if data.len() >= len {
                let _ = fragment_message(
                    hs_type,
                    PROTOCOL_VERSION,
                    [0xAAu8; SESSION_ID_LEN],
                    &data[..len],
                );
            }
        }
    }
});
