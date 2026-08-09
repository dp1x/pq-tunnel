//! M7-B3 tokio driver stress: races libFuzzer cannot reach.
//!
//! Three suites against the *real* stack on loopback (harness in [`common`]):
//!
//! 1. **Backpressure flood** — saturates the bounded 64-slot manager
//!    channels (`v2_client.rs`/`v2_server.rs`) with a high-rate app flood;
//!    the link must not deadlock or wedge: replies keep flowing and a fresh
//!    MARKER roundtrip still lands afterwards.
//! 2. **Teardown races** — kills driver tasks *while traffic is in flight*
//!    (UDP datagrams evaporate into the void; no crash, no panic, no hang).
//! 3. **Reconnect storm** — 25 full establish→roundtrip→tear-down cycles,
//!    every join must settle (Cancelled ok, Panic/Hang = fail) and every
//!    generation must reach a working roundtrip.
//!
//! Assertions are observed from the app and from task join results, never
//! from internal manager state (same discipline as `e2e_adversarial`).

mod common;

use std::time::{Duration, Instant};

use pq_tunnel_core::{CoverPolicy, PAYLOAD_LEN};
use pq_tunnel_lib::relay::{decode_relay, encode_relay};

use common::{COVER_INTERVAL, Gate, build_gate, gate_roundtrip};

/// Stress gates use cover-disabled wiring (no shaper noise on the loads).
async fn stress_gate() -> Gate {
    build_gate(CoverPolicy {
        enabled: false,
        interval: COVER_INTERVAL,
    })
    .await
}

/// Join-results by original task index: `(i, Result)` for settled tasks,
/// plus the still-blocked indices at check time.
type Verdict = (Vec<(usize, Result<(), tokio::task::JoinError>)>, Vec<usize>);

/// Join-result verdict: no panics, aborted tasks all settle, and the only
/// tasks allowed to remain blocked are the non-aborted ones (by design —
/// D12/D13 silence, e.g. after the client side dies, echo/proxy/server
/// wait on sockets that stay open).
fn assert_tasks_clean(what: &str, (results, hung): Verdict, aborted: &[usize]) {
    for (i, r) in results.iter() {
        match r {
            Err(e) if e.is_cancelled() => assert!(
                aborted.contains(i),
                "{what}: task[{i}] cancelled although not aborted"
            ),
            Err(e) => panic!("{what}: task[{i}] panicked: {e}"),
            Ok(()) => assert!(
                !aborted.contains(i),
                "{what}: aborted task[{i}] completed Ok (abort ignored?)"
            ),
        }
    }
    // Every aborted task must have settled (be present in `results`); any
    // hung task beyond the non-aborted ones means an aborted task wedged.
    let total = results.len() + hung.len();
    let remain_by_design = total - aborted.len();
    assert!(
        hung.len() <= remain_by_design,
        "{what}: hung tasks {hung:?}; aborted {aborted:?} should all settle"
    );
}

/// Drain relay replies for up to `window`, returning how many arrived.
async fn drain_replies(gate: &Gate, window: Duration) -> usize {
    let mut buf = vec![0u8; PAYLOAD_LEN];
    let mut got = 0usize;
    let end = Instant::now() + window;
    while Instant::now() < end {
        let rem = end.saturating_duration_since(Instant::now());
        match tokio::time::timeout(rem, gate.app.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                let (_dest, payload) = decode_relay(&buf[..n]).expect("app received a relay frame");
                assert_eq!(payload.len(), 32, "reply payloads are exactly 32 bytes");
                got += 1;
            }
            Ok(Err(e)) => panic!("app recv failed: {e}"),
            Err(_) => break, // quiet window passed
        }
    }
    got
}

#[tokio::test]
async fn flood_backpressure_recovers() {
    let gate = stress_gate().await;
    gate_roundtrip(&gate).await; // established + Ready first

    // Flood-rate app traffic toward the echo endpoint. Three bounded
    // 64-slot channels sit in the path (relay→client driver, server
    // driver→forwarder, forwarder→server driver). A wedged queue would
    // stall the drain below. Loopback UDP may drop under load, so the
    // invariant asserted is "service continues", not "every datagram
    // returns".
    const FLOOD: usize = 2048;
    let mut sent = 0usize;
    for i in 0..FLOOD {
        let payload = vec![(i % 251) as u8; 32];
        let frame = encode_relay(gate.echo_addr, &payload).expect("32B probe fits");
        match gate.app.send_to(&frame, gate.relay_addr).await {
            Ok(_) => sent += 1,
            Err(e) => panic!("flood send failed at {i}: {e}"),
        }
    }

    // Everything the app sent gets a chance to return; the channels must
    // not wedge. If drain sees nothing at all, the stack is jammed.
    let drained = tokio::time::timeout(
        Duration::from_secs(60),
        drain_replies(&gate, Duration::from_secs(8)),
    )
    .await
    .expect("drain must complete within its hard deadline");
    assert!(drained > 0, "flood: no reply drained — the path is wedged");
    assert!(
        drained <= sent,
        "flood: more replies ({drained}) than datagrams sent ({sent})"
    );

    // Service continuity: a fresh MARKER roundtrip afterwards.
    gate_roundtrip(&gate).await;
    gate.stop();
}

#[tokio::test]
async fn teardown_races_never_panic() {
    for round in 0..4u32 {
        let mut gate = stress_gate().await;
        gate_roundtrip(&gate).await;

        // In-flight traffic when the tasks are killed.
        let frame = encode_relay(gate.echo_addr, &[0x52u8; 16]).unwrap();
        for _ in 0..64 {
            let _ = gate.app.send_to(&frame, gate.relay_addr).await;
        }

        // Kill the client driver and the relay mid-stream.
        gate.abort_idx(4); // client driver
        gate.abort_idx(5); // relay

        let verdict = gate.await_shutdown(Duration::from_secs(3)).await;
        assert_tasks_clean(&format!("teardown round {round}"), verdict, &[4, 5]);
    }
}

#[tokio::test]
async fn reconnect_storm_cycles() {
    // 25 full generations: fresh stack, handshake + roundtrip, tear down,
    // all tasks settle. Catches descriptor/task leaks and re-arm bugs
    // across generations.
    for i in 0..25u32 {
        let mut gate = stress_gate().await;
        gate_roundtrip(&gate).await;
        gate.stop();
        let verdict = gate.await_shutdown(Duration::from_secs(10)).await;
        assert_tasks_clean(
            &format!("reconnect cycle {i}"),
            verdict,
            &[0, 1, 2, 3, 4, 5], // all were aborted by stop()
        );
    }
}
