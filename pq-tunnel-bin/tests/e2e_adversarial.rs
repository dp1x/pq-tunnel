//! M5.3 adversarial E2E gate.
//!
//! Drives the real stack on loopback (harness in [`common`]) and attacks the
//! ESTABLISHED session through the MITM proxy's injection channel.  Every
//! attack must be a **silent drop** (D12/D13: no error oracle, no
//! amplification) and the link must **recover** — a fresh MARKER roundtrip
//! still completes afterwards.
//!
//! Attacks covered here:
//!   - garbage / wrong-size datagrams (length attack, both endpoints);
//!   - forged / tampered handshake fragments (M1/M2/M3) and unknown types;
//!   - protocol-version downgrade on a captured data packet;
//!   - AEAD tamper (bit-flip inside the encrypted region);
//!   - replay of a captured data datagram; and
//!   - reorder + in-window replay proving exactly-once app delivery.
//!
//! All assertions are observed from the app and wire, never from internal state.

mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use pq_tunnel_core::{
    CoverPolicy, HS_TYPE_CLIENT_CONFIRM, HS_TYPE_CLIENT_HELLO, HS_TYPE_SERVER_HELLO, M1_BODY_LEN,
    M2_BODY_LEN, M3_BODY_LEN, PACKET_SIZE, PAYLOAD_LEN, PROTOCOL_VERSION, SESSION_ID_LEN,
    fragment_message,
};
use pq_tunnel_lib::relay::{decode_relay, encode_relay};

use common::{COVER_INTERVAL, Gate, build_gate, gate_roundtrip};

/// Adversarial gates run cover-disabled so the captured wire is exactly the
/// handshake + data plane (no shaper noise muddies the replay/order census).
async fn adversarial_gate() -> Gate {
    build_gate(CoverPolicy {
        enabled: false,
        interval: COVER_INTERVAL,
    })
    .await
}

/// Assert the app receives nothing within a quiet window starting now.
async fn assert_quiet(gate: &Gate, quiet: Duration, what: &str) {
    let mut buf = vec![0u8; PAYLOAD_LEN];
    let end = Instant::now() + quiet;
    while Instant::now() < end {
        let rem = end.saturating_duration_since(Instant::now());
        if let Ok(Ok((n, _))) = tokio::time::timeout(rem, gate.app.recv_from(&mut buf)).await {
            let (_dest, payload) = decode_relay(&buf[..n]).expect("reply must be relay-framed");
            panic!("{what}: app unexpectedly received {payload:?} during the quiet window");
        }
    }
}

/// Drain every relay reply arriving within `window`, returning their payloads.
async fn drain_app(gate: &Gate, window: Duration) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; PAYLOAD_LEN];
    let end = Instant::now() + window;
    while Instant::now() < end {
        let rem = end.saturating_duration_since(Instant::now());
        if let Ok(Ok((n, _))) = tokio::time::timeout(rem, gate.app.recv_from(&mut buf)).await {
            let (dest, payload) = decode_relay(&buf[..n]).expect("reply must be relay-framed");
            assert_eq!(
                dest, gate.echo_addr,
                "reply must be labeled with the echo dest"
            );
            out.push(payload.to_vec());
        }
    }
    out
}

/// New client-to-server (data-plane) datagrams captured since index `before`.
fn new_c2s_data(gate: &Gate, before: usize) -> Vec<Vec<u8>> {
    let all = gate.captured_data_to_server();
    assert!(
        before <= all.len(),
        "capture census shrank (proxy restarted?): before={before} now={}",
        all.len()
    );
    all[before..].to_vec()
}

/// Let in-flight MARKER echoes drain after establishment so every attack
/// window starts from a quiet app socket (the exactly-once census depends on
/// it).
async fn settle_app(gate: &Gate) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = drain_app(gate, Duration::from_millis(200)).await;
}

/// Pinned message body length for a handshake fragment type (D13).
fn body_len_for(hs_type: u8) -> usize {
    match hs_type {
        HS_TYPE_CLIENT_HELLO => M1_BODY_LEN,
        HS_TYPE_SERVER_HELLO => M2_BODY_LEN,
        HS_TYPE_CLIENT_CONFIRM => M3_BODY_LEN,
        _ => panic!("unknown handshake type"),
    }
}

#[tokio::test]
async fn e2e_adversarial_garbage_and_wrong_lengths_dropped() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    let blobs = vec![
        Vec::new(),
        vec![0xAA; 1],
        vec![0x42; 128],
        vec![0xFF; PACKET_SIZE - 1],
        {
            // Right-size but garbage: version byte is not PROTOCOL_VERSION, so
            // it is rejected at the header before ever touching a session.
            let mut v = vec![0u8; PACKET_SIZE];
            for (i, b) in v.iter_mut().enumerate() {
                *b = (i.wrapping_mul(31)) as u8;
            }
            v[0] = PROTOCOL_VERSION + 1;
            v
        },
        vec![0x13; PACKET_SIZE + 1],
        vec![0xBB; PACKET_SIZE + 4],
    ];

    for b in &blobs {
        gate.inject_to_server(b.clone());
        gate.inject_to_client(b.clone());
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // No data-plane corruption visible to the app, then the link recovers.
    assert_quiet(
        &gate,
        Duration::from_millis(300),
        "garbage/wrong-size blobs",
    )
    .await;
    gate_roundtrip(&gate).await;
    gate.stop();
}

#[tokio::test]
async fn e2e_adversarial_forged_handshake_rejected() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    // The established session's sid, taken from a real data-plane packet, so
    // the forgery targets the live session identifier.
    let live = gate.captured_data_to_server();
    assert!(
        !live.is_empty(),
        "expected at least one data packet post-handshake"
    );
    let live_sid: [u8; SESSION_ID_LEN] = live[0][1..1 + SESSION_ID_LEN].try_into().unwrap();
    let bogus_sid = [0xB0; SESSION_ID_LEN];

    // Forged M1 and M3 (client roles) toward the server.
    for sid in [live_sid, bogus_sid] {
        for hs_type in [HS_TYPE_CLIENT_HELLO, HS_TYPE_CLIENT_CONFIRM] {
            let body = vec![0u8; body_len_for(hs_type)];
            let frags = fragment_message(hs_type, PROTOCOL_VERSION, sid, &body)
                .expect("forged fragment framing must build");
            for f in frags {
                gate.inject_to_server(f.into_bytes().to_vec());
            }
        }
    }

    // Forged M2 (server role) toward the client.
    let body = vec![0u8; M2_BODY_LEN];
    let frags = fragment_message(HS_TYPE_SERVER_HELLO, PROTOCOL_VERSION, bogus_sid, &body)
        .expect("forged M2 framing must build");
    for f in frags {
        gate.inject_to_client(f.into_bytes().to_vec());
    }

    // Unknown handshake type (0x40) with a valid-looking header: byte 9 routes
    // it to the handshake path but `expected_frag_count` has no entry, so it
    // must be dropped before any assembler is created.
    let mut unknown = vec![0u8; PACKET_SIZE];
    unknown[0] = PROTOCOL_VERSION;
    unknown[1..1 + SESSION_ID_LEN].copy_from_slice(&bogus_sid);
    unknown[9] = 0x40;
    gate.inject_to_client(unknown);

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_quiet(
        &gate,
        Duration::from_millis(300),
        "forged handshake fragments",
    )
    .await;
    gate_roundtrip(&gate).await; // recovery after the attack
    gate.stop();
}

#[tokio::test]
async fn e2e_adversarial_version_downgrade_rejected() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    let live = gate.captured_data_to_server();
    assert!(!live.is_empty(), "need a live data packet to downgrade");
    let mut downgraded = live[0].clone();
    assert_ne!(
        downgraded[0], 0,
        "the wire's version must be nonzero to downgrade"
    );
    downgraded[0] -= 1; // v1 -> v0 = a downgrade attempt

    gate.inject_to_server(downgraded.clone());
    gate.inject_to_client(downgraded);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_quiet(&gate, Duration::from_millis(300), "version downgrade").await;
    gate_roundtrip(&gate).await;
    gate.stop();
}

#[tokio::test]
async fn e2e_adversarial_aead_tamper_rejected() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    let live = gate.captured_data_to_server();
    assert!(!live.is_empty(), "need a live data packet to tamper");
    // Flip a byte deep inside the AEAD ciphertext (never the clear header) so
    // the only possible outcome is tag/decrypt failure.
    let mut tampered = live[0].clone();
    let flip_pos = PACKET_SIZE / 2;
    tampered[flip_pos] ^= 0x01;
    assert_ne!(tampered, live[0], "tamper must change the ciphertext");

    gate.inject_to_server(tampered);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_quiet(&gate, Duration::from_millis(300), "AEAD tamper").await;
    gate_roundtrip(&gate).await;
    gate.stop();
}

#[tokio::test]
async fn e2e_adversarial_replayed_datagram_rejected() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    let live = gate.captured_data_to_server();
    assert!(!live.is_empty(), "need a captured data packet to replay");
    // Replay the exact datagrams (same sid, same cleartext counter): the
    // sliding window must reject them, so the app sees nothing new.
    for d in live {
        gate.inject_to_server(d);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_quiet(&gate, Duration::from_millis(400), "replayed datagram").await;
    gate_roundtrip(&gate).await;
    gate.stop();
}

#[tokio::test]
async fn e2e_adversarial_reorder_inwindow_replay_exactly_once() {
    let gate = adversarial_gate().await;
    gate_roundtrip(&gate).await;
    settle_app(&gate).await;

    // Distinct probes P1..P4. Record the data-plane watermark, then emit
    // exactly once and collect the echoes.
    let probes: [&[u8]; 4] = [b"adv-p1", b"adv-p2", b"adv-p3", b"adv-p4"];
    let before = gate.captured_data_to_server().len();
    for p in probes {
        let frame = encode_relay(gate.echo_addr, p).expect("probe fits payload slot");
        let _ = gate.app.send_to(&frame, gate.relay_addr).await;
    }

    let got = drain_app(&gate, Duration::from_millis(1500)).await;
    let mut got_set: BTreeSet<Vec<u8>> = got.iter().cloned().collect();
    for p in probes {
        assert!(
            got_set.remove(p),
            "probe {p:?} was not delivered (drain saw {got:?})"
        );
    }
    assert!(
        got_set.is_empty() && got.len() == probes.len(),
        "exactly-once violated: app received {got:?} for probes {probes:?}"
    );

    // The datagrams the wire census says the probes produced.
    let new_c2s = new_c2s_data(&gate, before);
    assert!(
        new_c2s.len() >= probes.len(),
        "expected at least {} client-to-server data packets, saw {}",
        probes.len(),
        new_c2s.len()
    );

    // Reorder + in-window replay: send the captured probe datagrams back in a
    // scrambled order plus a deliberate duplicate. Every one was already
    // accepted, so the window must reject the replayed copies.
    let mut reordered = new_c2s.clone();
    reordered.reverse();
    reordered.push(new_c2s[0].clone());
    for d in &reordered {
        gate.inject_to_server(d.clone());
    }

    let extra = drain_app(&gate, Duration::from_millis(600)).await;
    assert!(
        extra.is_empty(),
        "reordered/in-window replayed datagrams delivered duplicates: {extra:?}"
    );
    gate_roundtrip(&gate).await; // recovery after the reorder wave
    gate.stop();
}
