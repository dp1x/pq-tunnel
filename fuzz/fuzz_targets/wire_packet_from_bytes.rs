#![allow(dead_code)]

//! Fuzz target: `WirePacket::from_bytes`.
//!
//! Feeds arbitrary byte sequences to the wire packet decoder.  The decoder
//! must reject invalid input without panicking (§14: reject, never crash).

use pq_tunnel_core::WirePacket;

#[no_mangle]
pub extern "C" fn rust_fuzzer_test_input(data: &[u8]) -> i32 {
    let _ = WirePacket::from_bytes(data);
    0
}
