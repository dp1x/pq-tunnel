#![no_main]

//! Stateful fuzz target: overlay header decode + sender fragmentation +
//! reassembler feed across a *sequence* of operations.
//!
//! A single `Reassembler` persists across the whole input. The input bytes are
//! interpreted as a stream of operations (feed / expire / clear) so that
//! interleaving, reordering, duplicates, poisoning, expiry, ID reuse and cap
//! exhaustion are all exercised. The target must never panic or allocate
//! without bound; caps are enforced by the reassembler itself.

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::dataplane::{Reassembler, fragment_ip_packet, OverlayHeader};
use pq_tunnel_core::PAYLOAD_LEN;
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    // Overlay header decode on the leading bytes (and any 20-byte window).
    if data.len() >= 20 {
        let _ = OverlayHeader::decode(&data[..20]);
    }
    for off in (0..data.len().saturating_sub(19)).step_by(7) {
        let _ = OverlayHeader::decode(&data[off..off + 20]);
    }

    // Sender-side fragmentation must never panic.
    let _ = fragment_ip_packet(data, 1);

    // Stateful reassembler driver.
    let max_entries = 16usize;
    let max_bytes = 256 * 1024usize;
    let mut r = Reassembler::with_caps(Duration::from_secs(2), max_entries, max_bytes);
    let base = Instant::now();
    let mut cursor = 0usize;
    while cursor < data.len() {
        let op = data[cursor] % 4;
        cursor += 1;
        match op {
            0 => {
                // Feed one slot, consuming up to PAYLOAD_LEN bytes.
                let mut slot = [0u8; PAYLOAD_LEN];
                let end = (cursor + PAYLOAD_LEN).min(data.len());
                let n = end - cursor;
                if n > 0 {
                    slot[..n].copy_from_slice(&data[cursor..end]);
                }
                let now = base; // fixed base keeps deadline logic exercised
                let _ = r.feed(&slot, now);
                cursor = end;
            }
            1 => {
                // Expire with a small delta derived from the next byte.
                let delta = if cursor < data.len() {
                    data[cursor] as u64
                } else {
                    0
                };
                r.expire(base + Duration::from_millis(delta));
                cursor = (cursor + 1).min(data.len());
            }
            2 => {
                r.clear();
            }
            _ => {
                // Re-feed a zeroed slot to exercise duplicate/poison paths.
                let slot = [0u8; PAYLOAD_LEN];
                let _ = r.feed(&slot, base);
            }
        }
        // Invariants: caps are never exceeded.
        assert!(r.entry_count() <= max_entries);
        assert!(r.current_bytes() <= max_bytes);
    }
});