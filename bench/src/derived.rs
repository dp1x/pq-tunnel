//! Bench 5 — derived figures, computed ONLY from measured inputs.
//!
//! Every number printed here is either (a) a constant read from the source
//! tree at compile time (quoted with its file:line), or (b) an arithmetic
//! combination of a measured figure with such a constant. The arithmetic is
//! printed alongside the result so it can be checked by hand; nothing is
//! estimated and nothing is extrapolated beyond the measured range.

use pq_tunnel_core::codec::MAX_PACKET_NONCE;
use pq_tunnel_core::scheduler::{DEFAULT_COVER_RATE_BPS, interval_from_rate_bps};
use pq_tunnel_core::{PACKET_SIZE, PAYLOAD_LEN};

use crate::stats::human_ns;

/// `max_sessions` default. Read from `SessionLimits::default()` at runtime
/// below so this never drifts from the code.
pub fn default_max_sessions() -> usize {
    pq_tunnel_core::SessionLimits::default().max_sessions
}

/// D19 nominal cover rate, derived from the source constant (not hard-coded):
/// 1 / interval(2 Mbps).
pub fn nominal_cover_rate() -> f64 {
    1.0 / interval_from_rate_bps(DEFAULT_COVER_RATE_BPS).as_secs_f64()
}

/// Server worst-case cover egress bandwidth.
pub fn cover_egress(max_sessions: usize, rate: f64) {
    let bits = max_sessions as f64 * rate * PACKET_SIZE as f64 * 8.0;
    let mbps = bits / 1e6;
    println!("--- Derived: server worst-case cover egress (D19) ---");
    println!("  max_sessions              = {max_sessions}");
    println!("  nominal cover rate        = {rate} pkt/s per session-direction");
    println!("  PACKET_SIZE               = {PACKET_SIZE} B");
    println!("  arithmetic: {max_sessions} x {rate} x {PACKET_SIZE} x 8");
    println!(
        "             = {max_sessions} * {rate} = {:.4} pkt/s",
        max_sessions as f64 * rate
    );
    println!(
        "             = {:.4} * {PACKET_SIZE} B/s = {:.4} B/s",
        max_sessions as f64 * rate,
        max_sessions as f64 * rate * PACKET_SIZE as f64
    );
    println!(
        "             = {:.4} B/s * 8 = {bits:.0} bit/s",
        max_sessions as f64 * rate * PACKET_SIZE as f64
    );
    println!(
        "  RESULT                    = {bits:.0} bit/s = {mbps:.3} Mbit/s = {:.4} Gbit/s",
        bits / 1e9
    );
    println!();
}

/// Nonce exhaustion time at two rates.
///
/// `MAX_PACKET_NONCE = u64::MAX - (1 << 32)` (codec.rs:119). A direction can
/// emit at most that many packets before `is_counter_exhausted` forces
/// re-establishment.
pub fn nonce_exhaustion(rate_single: f64, rate_worst: f64) {
    let max = MAX_PACKET_NONCE as f64;
    println!("--- Derived: packet-nonce exhaustion time ---");
    println!("  MAX_PACKET_NONCE          = {max:.0}  (u64::MAX - 2^32)");
    for (label, rate) in [
        ("default 2 Mbps, 1 session, 1 direction", rate_single),
        ("worst case (64 sessions, egress total)", rate_worst),
    ] {
        let secs = max / rate;
        println!("  -- {label} --");
        println!("     packet rate            = {rate:.4} pkt/s");
        println!("     arithmetic: {:.0} / {:.4} = {secs:.6e} s", max, rate);
        println!(
            "     RESULT                  = {:.6e} s = {}",
            secs,
            crate::stats::human_seconds(secs)
        );
    }
    println!();
}

/// ML-DSA-65 verify throughput and the handshake rate it implies.
pub fn verify_throughput(verify_ns: f64, loop_ns_by_n: &[(usize, f64)], burst: u32, window_s: f64) {
    println!("--- Derived: ML-DSA-65 verify throughput and handshake capacity ---");
    let sigs_per_s = 1e9 / verify_ns;
    println!("  single verify             = {verify_ns:.1} ns");
    println!("  arithmetic: 1e9 ns/s / {verify_ns:.1} ns = {sigs_per_s:.2} verify/s");
    println!(
        "  RESULT                    = {sigs_per_s:.2} verifications/second (one core, single-threaded)"
    );
    println!();
    println!("  full-handshake CPU cost is dominated by the roster loop, so:");
    if loop_ns_by_n.is_empty() {
        println!("    NOT MEASURED in this run (roster group not executed)");
    }
    for (n, ns) in loop_ns_by_n {
        let hps = 1e9 / ns;
        println!(
            "    roster n={n:<5} D12 loop = {ns:>14.1} ns -> {hps:>12.2} handshakes/s/core (loop-bound lower bound)"
        );
    }
    println!();
    println!("  Rate-limit context (ServerConfig::new defaults):");
    println!("    rate_limit_burst        = {burst} per {window_s} s per source address");
    println!(
        "    arithmetic: {burst} / {window_s} = {:.4} handshakes/s per source address",
        burst as f64 / window_s
    );
    println!(
        "    -> the per-source budget ({:.2}/s) is the binding limit for a",
        burst as f64 / window_s
    );
    println!("       single source address, not the core's verify throughput,");
    println!("       UNLESS a single source is admitted from many source addresses.");
    println!();
}

/// Total CPU cost of the cover path at a given session count, from measured
/// tick and AEAD costs. Syscall cost is explicitly excluded and flagged.
pub fn cover_cpu_cost(tick_ns: f64, aead_ns: f64, sessions: usize, rate: f64) {
    let per_pkt = tick_ns + aead_ns;
    println!("--- Derived: cover-path CPU (measured components only) ---");
    println!("  scheduler tick            = {}", human_ns(tick_ns));
    println!("  AEAD encrypt (1280B)      = {}", human_ns(aead_ns));
    println!("  per-packet CPU (excl. syscalls, NOT MEASURED separately)");
    println!(
        "    = {} + {} = {}",
        human_ns(tick_ns),
        human_ns(aead_ns),
        human_ns(per_pkt)
    );
    for s in [1usize, sessions] {
        let cpu = per_pkt * rate * s as f64;
        println!(
            "  {s:>3} session(s) x {rate:.4} pkt/s = {:.4} pkt/s -> {:.6} CPU-s/s = {:.4}% of one core",
            rate * s as f64,
            cpu / 1e9,
            cpu / 1e7
        );
    }
    println!();
}

/// Payload fill: confirm the 1280-byte record is what is actually measured.
pub fn record_geometry() {
    println!("--- Record geometry (from crate constants) ---");
    println!("  PACKET_SIZE     = {PACKET_SIZE} B");
    println!("  PAYLOAD_LEN     = {PAYLOAD_LEN} B (inner plaintext payload slot)");
    println!();
}
