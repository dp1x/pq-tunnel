//! Bench 2 — post-quantum / classical primitive costs.
//!
//! These feed directly into the "full handshake CPU cost" question and into
//! the D16 claim ("~2.5 ms CPU") that `bench_handshake` cross-checks.
//!
//! Every operation is measured on its OWN public API surface exactly as
//! production calls it (`pq_crypto::kem`, `pq_crypto::classical`,
//! `pq_crypto::signature`) — no crate-internal shortcuts — so the numbers are
//! the ones the handshake actually pays.

use pq_crypto::classical::X25519Keypair;
use pq_crypto::kem::{MlKemKeypair, decapsulate, encapsulate};
use pq_crypto::signature::{MlDsaKeypair, verify};

use crate::stats::{Stats, measure};

/// ML-KEM-768 keygen / encaps / decaps.
///
/// `encapsulate` draws fresh OS randomness per call (CRYPTO_PROFILE), so this
/// is the real production cost including the RNG, not a fixed-`m` primitive
/// cost. `decapsulate` is measured over pre-generated ciphertexts: the
/// operation is deterministic, so re-encapsulating inside the loop would
/// measure `encaps` twice.
pub fn ml_kem_768(warmup: usize, iters: usize) -> Vec<Stats> {
    let mut rows = Vec::new();

    rows.push(measure(
        "ML-KEM-768 keygen (MlKemKeypair::generate)",
        "ns",
        warmup,
        iters,
        |_| MlKemKeypair::generate().expect("ml-kem keygen"),
    ));

    // One long-lived keypair: encaps cost is independent of the key.
    let kp = MlKemKeypair::generate().expect("ml-kem keygen");
    rows.push(measure(
        "ML-KEM-768 encaps (encapsulate)",
        "ns",
        warmup,
        iters,
        |_| encapsulate(&kp.public).expect("encaps"),
    ));

    // Pre-generate ciphertexts so decaps does no RNG work.
    let cts: Vec<_> = (0..iters + warmup)
        .map(|_| encapsulate(&kp.public).expect("encaps").1)
        .collect();
    rows.push(measure(
        "ML-KEM-768 decaps (decapsulate)",
        "ns",
        warmup,
        iters,
        |i| decapsulate(&kp.secret, &cts[i]).expect("decaps"),
    ));

    rows
}

/// X25519 keygen and Diffie-Hellman.
pub fn x25519(warmup: usize, iters: usize) -> Vec<Stats> {
    let mut rows = Vec::new();
    rows.push(measure(
        "X25519 keygen (X25519Keypair::generate)",
        "ns",
        warmup,
        iters,
        |_| X25519Keypair::generate(),
    ));
    let a = X25519Keypair::generate();
    let b = X25519Keypair::generate();
    rows.push(measure(
        "X25519 DH (X25519Keypair::diffie_hellman)",
        "ns",
        warmup,
        iters,
        |_| a.diffie_hellman(&b.public),
    ));
    rows
}

/// ML-DSA-65 keygen / sign / verify.
///
/// Signing is deterministic under D13 (`rnd = 0`), so signing the *same*
/// message is representative and avoids RNG variance dominating the
/// distribution. The handshake always signs a fresh 32-byte transcript digest
/// (see `bench_handshake`), which is the same length and shape.
pub fn ml_dsa_65(warmup: usize, iters: usize) -> Vec<Stats> {
    let mut rows = Vec::new();
    rows.push(measure(
        "ML-DSA-65 keygen (MlDsaKeypair::generate)",
        "ns",
        warmup,
        iters,
        |_| MlDsaKeypair::generate().expect("ml-dsa keygen"),
    ));
    let kp = MlDsaKeypair::generate().expect("ml-dsa keygen");
    let msg = [0x5Au8; 32]; // a TH-digest-shaped 32-byte message
    rows.push(measure(
        "ML-DSA-65 sign (32-byte msg)",
        "ns",
        warmup,
        iters,
        |_| kp.sign(&msg).expect("sign"),
    ));
    let sig = kp.sign(&msg).expect("sign");
    rows.push(measure(
        "ML-DSA-65 verify (valid sig)",
        "ns",
        warmup,
        iters,
        |_| verify(&kp.public, &msg, &sig).expect("verify"),
    ));
    rows
}
