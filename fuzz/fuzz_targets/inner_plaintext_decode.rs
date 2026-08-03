#![allow(dead_code)]

//! Fuzz target: `InnerPlaintext::decode`.
//!
//! Feeds arbitrary byte sequences to the inner plaintext decoder.  The decoder
//! must reject invalid input without panicking.

use pq_tunnel_core::InnerPlaintext;

#[no_mangle]
pub extern "C" fn rust_fuzzer_test_input(data: &[u8]) -> i32 {
    let _ = InnerPlaintext::decode(data);
    0
}
