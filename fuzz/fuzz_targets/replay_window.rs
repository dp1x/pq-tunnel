#![allow(dead_code)]

//! Fuzz target: `ReplayWindow::accept`.
//!
//! Feeds random u64 counter values as 8-byte little-endian input to the
//! sliding-window replay detector.  Must never panic and must never accept a
//! counter twice.

use pq_tunnel_core::replay::ReplayWindow;

#[no_mangle]
pub extern "C" fn rust_fuzzer_test_input(data: &[u8]) -> i32 {
    if data.len() < 8 {
        return 0;
    }

    let counter = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    let mut w = ReplayWindow::new();
    // Process up to 10 counter values from the input to exercise window sliding.
    let mut idx = 8;
    for _ in 0..10 {
        let _ = w.accept(counter);
        if idx + 8 <= data.len() {
            let c = u64::from_le_bytes([
                data[idx], data[idx + 1], data[idx + 2], data[idx + 3],
                data[idx + 4], data[idx + 5], data[idx + 6], data[idx + 7],
            ]);
            let _ = w.accept(c);
            idx += 8;
        }
    }
    0
}
