//! Bench 1 — ML-DSA-65 verification cost vs roster size (D12).
//!
//! `ServerHandshake::complete_m1` verifies the client signature against the
//! **entire** roster with no early exit (`handshake_v2.rs`):
//!
//! ```ignore
//! for pk in &self.cfg.roster {
//!     let ok = verify(pk, &th1_d, &m1.client_sig)?;
//!     authed |= ok;               // bitwise: uniform verification count (D12)
//!     if ok { matched = Some(pk.clone()); }
//! }
//! ```
//!
//! So the server's authentication cost is `roster_len * cost_of_one_verify`.
//! This module measures BOTH halves so the linear scaling is visible as real
//! numbers rather than an extrapolation:
//!
//! * **per-verify**: `verify()` against a single roster member, timed alone.
//! * **full-loop**: the exact D12 loop shape — verify the same signature
//!   against every key of a roster of size N — timed as one operation.
//!
//! The full-loop figure is the number that matters operationally; the
//! per-verify figure is what makes the linear model checkable.

use pq_crypto::signature::{MlDsaKeypair, MlDsaPublicKey, verify};

use crate::stats::{Stats, measure};

/// Roster sizes required by the methodology.
pub const ROSTER_SIZES: [usize; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// Build a roster of `n` distinct ML-DSA-65 public keys, with the signing
/// keypair of the LAST entry (so `n=1` means the single key authenticates,
/// and larger `n` means the match sits at the end — the worst case for a
/// would-be early-exit implementation, and the only case consistent with D12
/// which mandates uniform verification regardless).
fn build_roster(n: usize) -> (MlDsaKeypair, Vec<MlDsaPublicKey>) {
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        keys.push(MlDsaKeypair::generate().expect("roster keygen"));
    }
    let signer = keys[n - 1].clone();
    let roster = keys.into_iter().map(|k| k.public_key()).collect();
    (signer, roster)
}

/// Single `verify()` call — the per-element cost of the D12 loop.
///
/// Timed at each roster size purely so the per-verify figure is shown at the
/// same points on the x-axis as the loop total; the value is independent of
/// `n` (it must be, and if it is not, that is a cache-residency artefact worth
/// seeing).
pub fn per_verify(warmup: usize, iters: usize) -> (Vec<Stats>, Vec<f64>) {
    let mut rows = Vec::new();
    let mut ns_per_verify = Vec::new();
    for n in ROSTER_SIZES {
        let (signer, roster) = build_roster(n);
        let th = [0x11u8; 32];
        let sig = signer.sign(&th).expect("sign");
        let pk = roster[0].clone();
        let s = measure(
            &format!("verify() single call (roster n={n})"),
            "ns",
            warmup,
            iters,
            |_| verify(&pk, &th, &sig).expect("verify"),
        );
        ns_per_verify.push(s.p50_ns);
        rows.push(s);
    }
    (rows, ns_per_verify)
}

/// The exact D12 loop, timed as one operation: `n` verifications against a
/// roster of `n`, with the signer at the end (no early exit possible).
pub fn full_loop(warmup: usize, iters: usize) -> Vec<Stats> {
    let mut rows = Vec::new();
    for n in ROSTER_SIZES {
        let (signer, roster) = build_roster(n);
        let th = [0x11u8; 32];
        let sig = signer.sign(&th).expect("sign");
        let s = measure(
            &format!("D12 full roster loop (n={n} verifies)"),
            "ns",
            warmup,
            iters,
            |_| {
                // Identical shape to `complete_m1`, including the bitwise OR
                // (no short-circuit) that makes the count uniform.
                let mut authed = false;
                let mut matched: Option<MlDsaPublicKey> = None;
                for pk in &roster {
                    let ok = verify(pk, &th, &sig).expect("verify");
                    authed |= ok;
                    if ok {
                        matched = Some(pk.clone());
                    }
                }
                (authed, matched.is_some())
            },
        );
        rows.push(s);
    }
    rows
}

/// Negative-path cost: what an *unknown* client costs the server, i.e. a
/// signature that matches NO roster entry. D12 rejects it, but only after
/// verifying against all `n` keys. Same loop, `authed` ends false.
pub fn full_loop_unknown_client(warmup: usize, iters: usize) -> Vec<Stats> {
    let mut rows = Vec::new();
    for n in ROSTER_SIZES {
        let (_signer, roster) = build_roster(n);
        let stranger = MlDsaKeypair::generate().expect("stranger keygen");
        let th = [0x11u8; 32];
        let sig = stranger.sign(&th).expect("sign");
        let s = measure(
            &format!("D12 loop, UNKNOWN client (n={n} verifies)"),
            "ns",
            warmup,
            iters,
            |_| {
                let mut authed = false;
                for pk in &roster {
                    authed |= verify(pk, &th, &sig).expect("verify");
                }
                authed
            },
        );
        rows.push(s);
    }
    rows
}
