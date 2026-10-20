#![no_main]

//! Fuzz target: overlay header decode + reassembler feed + fragmenter.
//!
//! The reassembler must never panic on arbitrary input and must respect its
//! caps (no unbounded allocation).

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::dataplane::{Reassembler, fragment_ip_packet, OverlayHeader};
use pq_tunnel_core::PAYLOAD_LEN;
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 20 {
        let _ = OverlayHeader::decode(&data[..20]);
    }
    let mut slot = [0u8; PAYLOAD_LEN];
    let n = data.len().min(PAYLOAD_LEN);
    slot[..n].copy_from_slice(&data[..n]);
    let mut r = Reassembler::new(Duration::from_secs(2));
    let _ = r.feed(&slot, Instant::now());
    let _ = fragment_ip_packet(data, 1);
});
