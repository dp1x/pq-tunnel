#![no_main]

//! Fuzz target: `WirePacket::from_bytes`.
//!
//! Feeds arbitrary byte sequences to the wire packet decoder.  The decoder
//! must reject invalid input without panicking (§14: reject, never crash).

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::WirePacket;

fuzz_target!(|data: &[u8]| {
    let _ = WirePacket::from_bytes(data);
});
