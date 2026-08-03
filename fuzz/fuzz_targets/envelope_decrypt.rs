#![allow(dead_code)]

//! Fuzz target: `CipherSession::decrypt`.
//!
//! Feeds arbitrary 1280-byte packets to the AEAD decryption path.  The decrypt
//! function must never panic — it must always return Ok or Err (§14: reject,
//! never crash).  This target uses a deterministic master secret so it can run
//! without a live handshake.

use pq_crypto::derive_master_secret;
use pq_tunnel_core::{CipherSession, Role, SESSION_ID_LEN, PACKET_SIZE};

// Use a static master for fuzzing (deterministic, non-secret).
fn fuzz_master() -> pq_crypto::kdf::MasterSecret {
    let c = [0x11u8; 32];
    let s = [0x22u8; 32];
    derive_master_secret(&c, &s).expect("master secret derivation")
}

#[no_mangle]
pub extern "C" fn rust_fuzzer_test_input(data: &[u8]) -> i32 {
    if data.len() != PACKET_SIZE {
        return 0;
    }

    let master = fuzz_master();
    let sid = [0xABu8; SESSION_ID_LEN];
    let mut server = match CipherSession::new(Role::Server, &master, sid) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Attempt to parse and decrypt. Must never panic.
    if let Ok(pkt) = pq_tunnel_core::WirePacket::from_bytes(data) {
        let _ = server.decrypt(&pkt);
    }
    0
}
