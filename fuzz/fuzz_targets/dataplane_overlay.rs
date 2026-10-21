#![no_main]

//! Stateful fuzz target: overlay header decode + sender fragmentation +
//! reassembler feed across a *sequence* of operations.
//!
//! A single `Reassembler` persists across the whole input. The input bytes are
//! interpreted as a stream of operations (feed / expire / clear) so that
//! interleaving, reordering, duplicates, poisoning, expiry, ID reuse and cap
//! exhaustion are all exercised. Valid multi-fragment sequences are constructed
//! with `fragment_ip_packet` and fed in orders derived from the input, so
//! complete reassembly is reachable rather than only malformed headers.

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::dataplane::{
    Reassembler, fragment_ip_packet, OverlayHeader, FeedOutcome,
};
use pq_tunnel_core::codec::PAYLOAD_LEN;
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

    // Build a few valid inner IP packets (IPv4 and IPv6) whose sizes are
    // derived from the input, then fragment them. These provide real
    // multi-fragment sequences instead of random bytes.
    let mut base_packets: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;
    while cursor + 1 < data.len() && base_packets.len() < 4 {
        let family = data[cursor] & 1;
        cursor += 1;
        let size_seed = data[cursor] as usize;
        cursor += 1;
        if family == 0 {
            let total = 20 + (size_seed % 200) * 6;
            let mut pkt = vec![0u8; total];
            pkt[0] = 0x45;
            let t = total as u16;
            pkt[2] = (t >> 8) as u8;
            pkt[3] = (t & 0xFF) as u8;
            base_packets.push(pkt);
        } else {
            let payload = 8 + (size_seed % 200) * 6;
            let total = 40 + payload;
            let mut pkt = vec![0u8; total];
            pkt[0] = 0x60;
            let p = payload as u16;
            pkt[4] = (p >> 8) as u8;
            pkt[5] = (p & 0xFF) as u8;
            base_packets.push(pkt);
        }
    }

    let mut fragments: Vec<Vec<[u8; PAYLOAD_LEN]>> = Vec::new();
    for (i, pkt) in base_packets.iter().enumerate() {
        if let Ok(slots) = fragment_ip_packet(pkt, (i as u64) + 1) {
            fragments.push(slots);
        }
    }

    // Stateful reassembler driver.
    let max_entries = 16usize;
    let max_bytes = 256 * 1024usize;
    let mut r = Reassembler::with_caps(Duration::from_secs(2), max_entries, max_bytes);
    let base = Instant::now();
    let mut idx = 0usize;
    // Feed complete valid sequences in input-derived orders.
    while idx < data.len() {
        let op = data[idx] % 5;
        idx += 1;
        match op {
            0 => {
                // Feed one fragment from a valid sequence, if any.
                if !fragments.is_empty() {
                    let fi = data.get(idx).copied().unwrap_or(0) as usize % fragments.len();
                    idx = (idx + 1).min(data.len());
                    let slots = &fragments[fi];
                    if !slots.is_empty() {
                        let si = data.get(idx).copied().unwrap_or(0) as usize % slots.len();
                        idx = (idx + 1).min(data.len());
                        let now = base + Duration::from_millis((data.get(idx).copied().unwrap_or(0) as u64) % 5);
                        idx = (idx + 1).min(data.len());
                        let _ = r.feed(&slots[si], now);
                    }
                }
            }
            1 => {
                // Feed all fragments of one valid datagram in reverse order.
                if !fragments.is_empty() {
                    let fi = data.get(idx).copied().unwrap_or(0) as usize % fragments.len();
                    idx = (idx + 1).min(data.len());
                    let now = base;
                    for slot in fragments[fi].iter().rev() {
                        let _ = r.feed(slot, now);
                    }
                }
            }
            2 => {
                // Duplicate/conflict: mutate a fragment's trailing byte.
                if !fragments.is_empty() {
                    let fi = data.get(idx).copied().unwrap_or(0) as usize % fragments.len();
                    idx = (idx + 1).min(data.len());
                    let slots = &fragments[fi];
                    if !slots.is_empty() {
                        let si = data.get(idx).copied().unwrap_or(0) as usize % slots.len();
                        idx = (idx + 1).min(data.len());
                        let mut slot = slots[si];
                        if slot.len() > 20 {
                            slot[20] ^= 0xFF;
                        }
                        let _ = r.feed(&slot, base);
                    }
                }
            }
            3 => {
                let delta = data.get(idx).copied().unwrap_or(0) as u64;
                idx = (idx + 1).min(data.len());
                r.expire(base + Duration::from_millis(delta));
            }
            _ => {
                r.clear();
            }
        }
        // Invariants: caps are never exceeded.
        assert!(r.entry_count() <= max_entries);
        assert!(r.current_bytes() <= max_bytes);

        // Also exercise raw slot feed for malformed inputs.
        if idx < data.len() {
            let mut slot = [0u8; PAYLOAD_LEN];
            let end = (idx + PAYLOAD_LEN).min(data.len());
            let n = end - idx;
            if n > 0 {
                slot[..n].copy_from_slice(&data[idx..end]);
            }
            let now = base;
            let _ = r.feed(&slot, now);
            idx = end;
        }
        assert!(r.entry_count() <= max_entries);
        assert!(r.current_bytes() <= max_bytes);
    }
    r.clear();
    assert_eq!(r.entry_count(), 0);
    assert_eq!(r.current_bytes(), 0);
    // Keep FeedOutcome referenced.
    let _ = FeedOutcome::Pending;
});