#![no_main]

//! Fuzz target: `InnerPlaintext::decode`.
//!
//! Feeds arbitrary byte sequences to the inner plaintext decoder.  The decoder
//! must reject invalid input without panicking.

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::InnerPlaintext;

fuzz_target!(|data: &[u8]| {
    let _ = InnerPlaintext::decode(data);
});
