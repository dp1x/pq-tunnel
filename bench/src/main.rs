//! Tunnel performance harness (TRACK I).
//!
//! Measurements only. Every figure printed by this binary is an observation
//! taken during the run; nothing is estimated, modelled or extrapolated.
//!
//! Opt-in by construction: this crate is NOT a member of the main workspace
//! (see `bench/Cargo.toml`), so `cargo test --workspace` never builds or runs
//! it.
//!
//! Usage (from the repo root):
//!
//! ```sh
//! cargo run --release --manifest-path bench/Cargo.toml \
//!     --target x86_64-pc-windows-msvc -- --bench all
//! ```
//!
//! `--bench <name>` selects a group: `prims`, `roster`, `handshake`, `cover`,
//! `cadence`, `derived`, or `all`.
//!
//! `--quick` reduces iteration counts for a smoke run (the published numbers
//! were taken WITHOUT `--quick`; the counts are printed in the banner either
//! way, so a reduced run can never be mistaken for a full one).

mod cover_timer;
mod crypto_prims;
mod derived;
mod handshake;
mod roster_verify;
mod stats;

use std::time::{Duration, Instant};

use stats::{banner, measure, print_table};

/// Iteration budget. Chosen so the dominant cost (roster 1024 => ~1024 ML-DSA
/// verifications per handshake) still finishes in a sensible wall time while
/// every fast operation gets enough samples for a meaningful p99.
#[derive(Debug, Clone, Copy)]
struct Config {
    prims_warmup: usize,
    prims_iters: usize,
    roster_warmup: usize,
    roster_iters: usize,
    hs_warmup: usize,
    hs_iters: usize,
    sched_inner: usize,
    aead_inner: usize,
    sweep_iters: usize,
    sweep_warmup: usize,
    cadence: Duration,
}

const FULL: Config = Config {
    prims_warmup: 200,
    prims_iters: 5_000,
    roster_warmup: 3,
    // Each roster-1024 sample is ~1024 ML-DSA verifies (~92 ms at the
    // measured per-verify cost). 200 samples across all 11 sizes keeps the
    // group to a few minutes while still giving p99 2 observations; the
    // iteration count is printed in the banner and in every table row so a
    // reader can see exactly what backs each percentile.
    roster_iters: 200,
    hs_warmup: 2,
    // Each handshake at roster 1024 costs ~1024 verifies; keep this modest.
    hs_iters: 60,
    // Amortised groups: `iters` samples each timing `inner` calls. The
    // scheduler tick is ~10 us/call on this host (pre-armed, virtual clock),
    // so 10_000 calls x 1000 samples would be ~100 s per row; 1_000 x 200
    // keeps every group inside a minute while still yielding 200 real samples.
    sched_inner: 1_000,
    aead_inner: 1_000,
    // `interval_from_rate_bps` is a handful of integer ops (~below clock
    // resolution); 50k samples is far more than needed for a stable p50.
    sweep_iters: 50_000,
    sweep_warmup: 10_000,
    cadence: Duration::from_secs(30),
};

const QUICK: Config = Config {
    prims_warmup: 20,
    prims_iters: 200,
    roster_warmup: 1,
    roster_iters: 10,
    hs_warmup: 1,
    hs_iters: 5,
    sched_inner: 100,
    aead_inner: 100,
    sweep_iters: 1_000,
    sweep_warmup: 100,
    cadence: Duration::from_secs(3),
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut which = "all".to_string();
    let mut quick = false;
    let mut repeats = 1usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bench" => {
                which = args.get(i + 1).cloned().unwrap_or_else(|| "all".into());
                i += 2;
            }
            "--repeats" => {
                repeats = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(1);
                i += 2;
            }
            "--quick" => {
                quick = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    let cfg = if quick { QUICK } else { FULL };
    banner();
    println!("bench group       : {which}");
    println!(
        "iteration counts  : prims warmup={} iters={} | roster warmup={} iters={} | handshake warmup={} iters={}",
        cfg.prims_warmup,
        cfg.prims_iters,
        cfg.roster_warmup,
        cfg.roster_iters,
        cfg.hs_warmup,
        cfg.hs_iters
    );
    println!(
        "amortisation      : scheduler tick x{} calls/sample | AEAD x{} calls/sample",
        cfg.sched_inner, cfg.aead_inner
    );
    println!("cadence window    : {:?}", cfg.cadence);
    println!("repeats           : {repeats}");
    println!(
        "mode              : {}",
        if quick {
            "QUICK (smoke — NOT publishable)"
        } else {
            "FULL"
        }
    );
    println!();

    if repeats > 1 {
        println!(
            "NOTE: --repeats {repeats} — run-to-run repeatability. Each block below is an\n\
             INDEPENDENT full pass of the same group; compare the 'p50' column\n\
             across blocks. Variance here is machine noise (this host is shared),\n\
             not a change in the code under test.\n"
        );
    }

    for pass in 0..repeats {
        if repeats > 1 {
            println!(
                "################################################################################"
            );
            println!("# PASS {} of {}", pass + 1, repeats);
            println!(
                "################################################################################"
            );
        }
        run_group(&which, &cfg, quick, pass == repeats - 1);
    }
}

/// Run the selected bench group. `last_pass` controls whether the derived
/// block runs (its values come from this pass's measurements).
fn run_group(which: &str, cfg: &Config, _quick: bool, last_pass: bool) {
    let run_all = which == "all";
    let wall = Instant::now();
    let mut results = Results::default();

    if run_all || which == "prims" {
        let prims = crypto_prims::ml_kem_768(cfg.prims_warmup, cfg.prims_iters);
        print_table(
            "Bench 2a: ML-KEM-768 (FIPS 203, crate ml-kem 0.3.2)",
            &prims,
        );
        let x = crypto_prims::x25519(cfg.prims_warmup, cfg.prims_iters);
        print_table("Bench 2b: X25519 (x25519-dalek 3.0.0-rc.1)", &x);
        let d = crypto_prims::ml_dsa_65(cfg.prims_warmup, cfg.prims_iters);
        print_table("Bench 2c: ML-DSA-65 (FIPS 204, crate ml-dsa 0.1.1)", &d);
        results.verify_ns = d
            .iter()
            .find(|s| s.label.contains("verify"))
            .map(|s| s.p50_ns);
        results.sign_ns = d
            .iter()
            .find(|s| s.label.contains("sign ("))
            .map(|s| s.p50_ns);
        results.kem_keygen_ns = prims.first().map(|s| s.p50_ns);
        results.kem_encaps_ns = prims.get(1).map(|s| s.p50_ns);
        results.kem_decaps_ns = prims.get(2).map(|s| s.p50_ns);
    }

    if run_all || which == "roster" {
        let (per, ns_per_verify) =
            roster_verify::per_verify(cfg.roster_warmup, cfg.prims_iters / 10 + 10);
        print_table(
            "Bench 1a: single ML-DSA-65 verify (the per-element cost)",
            &per,
        );
        let full = roster_verify::full_loop(cfg.roster_warmup, cfg.roster_iters);
        print_table(
            "Bench 1b: D12 full roster loop (uniform verification, no early exit)",
            &full,
        );
        let unknown =
            roster_verify::full_loop_unknown_client(cfg.roster_warmup, cfg.roster_iters / 4 + 1);
        print_table(
            "Bench 1c: D12 loop, UNKNOWN client (no match; full cost then reject)",
            &unknown,
        );

        println!("--- Bench 1: roster scaling summary (p50 ns) ---");
        println!(
            "{:>6} {:>16} {:>16} {:>16} {:>14}",
            "roster", "ns/verify", "loop_p50_ns", "unknown_p50_ns", "verify/s"
        );
        for (i, n) in roster_verify::ROSTER_SIZES.iter().enumerate() {
            println!(
                "{n:>6} {:>16.1} {:>16.1} {:>16.1} {:>14.2}",
                ns_per_verify[i],
                full[i].p50_ns,
                unknown[i].p50_ns,
                1e9 / ns_per_verify[i]
            );
        }
        println!();
        results.roster_loop = full
            .iter()
            .zip(roster_verify::ROSTER_SIZES)
            .map(|(s, n)| (n, s.p50_ns))
            .collect();
    }

    if run_all || which == "handshake" {
        let (total, c1, s2, c3, s3) = handshake::full_handshake(cfg.hs_warmup, cfg.hs_iters);
        print_table(
            "Bench 3a: full handshake CPU, client + server, in-process",
            &total,
        );
        let mut phases: Vec<stats::Stats> = Vec::new();
        phases.extend(c1);
        phases.extend(s2);
        phases.extend(c3);
        phases.extend(s3);
        print_table("Bench 3b: handshake phase breakdown (p50)", &phases);
        results.hs_total = total.iter().map(|s| s.p50_ns).collect();
        results.hs_labels = total.iter().map(|s| s.label.clone()).collect();

        // Server-side CPU only — the figure that bounds handshake capacity,
        // since the client's cost is the client's problem.
        let totals = handshake::handshake_totals(cfg.hs_warmup, cfg.hs_iters, &[1, 8, 64, 256]);
        let mut rows: Vec<stats::Stats> = Vec::new();
        let mut srv_rows: Vec<stats::Stats> = Vec::new();
        for (_, all, srv) in &totals {
            rows.push(all.clone());
            srv_rows.push(srv.clone());
        }
        print_table(
            "Bench 3c: handshake TOTAL (both sides), roster 1/8/64/256",
            &rows,
        );
        print_table(
            "Bench 3d: handshake SERVER-side CPU only, roster 1/8/64/256",
            &srv_rows,
        );
        for (n, all, srv) in &totals {
            println!(
                "  roster n={n:<4} total p50 = {:>14.1} ns | server p50 = {:>14.1} ns | server handshakes/s/core = {:>10.2}",
                all.p50_ns,
                srv.p50_ns,
                1e9 / srv.p50_ns
            );
        }
        println!();
        results.hs_server = srv_rows.iter().map(|s| s.p50_ns).collect();
        results.hs_server_labels = srv_rows.iter().map(|s| s.label.clone()).collect();
    }

    if run_all || which == "cover" {
        // Calibrate the clock itself: on this host `Instant::now()` is the
        // dominant term for sub-microsecond operations, so it is measured as
        // a first-class row rather than silently inflating every small figure.
        let clock = measure(
            "calibration: Instant::now() round-trip",
            "ns",
            cfg.prims_warmup,
            cfg.prims_iters / 10 + 10,
            |_| Instant::now().elapsed().as_nanos() as usize,
        );
        print_table("Bench 4a-0: clock calibration floor", &[clock]);
        let tick_iters = cfg.prims_iters / 50 + 10;
        let tick =
            cover_timer::scheduler_tick(cfg.prims_warmup / 10 + 5, tick_iters, cfg.sched_inner);
        let tick_steady = cover_timer::scheduler_tick_steady(
            cfg.prims_warmup / 10 + 5,
            tick_iters,
            cfg.sched_inner,
        );
        let tick_ctl = cover_timer::scheduler_tick_control(
            cfg.prims_warmup / 10 + 5,
            tick_iters,
            cfg.sched_inner,
        );
        print_table(
            "Bench 4a: cover scheduler tick cost (virtual time) + control",
            &[tick.clone(), tick_steady.clone(), tick_ctl.clone()],
        );
        // Marginal cost = steady-state tick minus the identical clock-only loop.
        println!(
            "  marginal scheduler cost (steady - control) p50 = {:.1} ns per tick",
            tick_steady.p50_ns - tick_ctl.p50_ns
        );
        println!();
        let sweep = cover_timer::interval_sweep(cfg.sweep_warmup, cfg.sweep_iters);
        print_table("Bench 4b: interval_from_rate_bps cost sweep", &sweep);
        let aead =
            cover_timer::aead_1280(cfg.prims_warmup, cfg.prims_iters / 10 + 10, cfg.aead_inner);
        print_table(
            "Bench 4c: AEAD / record encrypt cost (1280-byte record)",
            &aead,
        );
        results.tick_ns = Some(tick.p50_ns);
        results.aead_ns = aead.last().map(|s| s.p50_ns);
        derived::record_geometry();
    }

    if run_all || which == "cadence" {
        println!("--- Bench 4d: Windows cover-clock wake cadence (D23/M9A) ---");
        let (hrt, ctl, hrt_rate, ctl_rate, hrt_n, ctl_n) = cover_timer::cover_cadence(cfg.cadence);
        print_table("Bench 4d: cover wake latency", &[hrt.clone(), ctl.clone()]);
        let nominal = derived::nominal_cover_rate();
        println!(
            "  HR-resolution timer achieved = {hrt_rate:.4} pkt/s over {hrt_n} wakes ({:.2}% of nominal {nominal:.4})",
            hrt_rate / nominal * 100.0
        );
        println!(
            "  thread::sleep control        = {ctl_rate:.4} pkt/s over {ctl_n} wakes ({:.2}% of nominal)",
            ctl_rate / nominal * 100.0
        );
        println!(
            "  D23 recorded reference       = p50 5.31 ms, ~93.5% of nominal (182.6 pkt/s over 30 s)"
        );
        println!();
        results.hrt_p50_ns = Some(hrt.p50_ns);
    }

    if (run_all || which == "derived") && last_pass {
        println!(
            "================================================================================"
        );
        println!("DERIVED FIGURES (arithmetic on measured values + source constants only)");
        println!(
            "================================================================================"
        );
        let rate = derived::nominal_cover_rate();
        let max_sessions = derived::default_max_sessions();
        derived::cover_egress(max_sessions, rate);
        derived::nonce_exhaustion(rate, rate * max_sessions as f64);
        if let Some(v) = results.verify_ns {
            let burst = 16u32;
            let window = 10.0f64;
            let loop_ref: Vec<(usize, f64)> = if results.roster_loop.is_empty() {
                // Only valid when the roster group ran; otherwise leave empty
                // rather than substituting a modelled number for a measured one.
                Vec::new()
            } else {
                results.roster_loop.clone()
            };
            derived::verify_throughput(v, &loop_ref, burst, window);
        }
        if let (Some(t), Some(a)) = (results.tick_ns, results.aead_ns) {
            derived::cover_cpu_cost(t, a, max_sessions, rate);
        }
    }

    println!("================================================================================");
    println!("PASS WALL TIME: {:?}", wall.elapsed());
    println!("================================================================================");
    if last_pass {
        println!("not measured by this harness (see docs/performance/I-benchmark-methodology.md):");
        println!("  - syscall cost per cover packet (sendto + timer arm + wake)");
        println!("  - loopback end-to-end handshake wall time including transport");
        println!("  - multi-core scaling (single-threaded only)");
    }
}

#[derive(Default)]
struct Results {
    verify_ns: Option<f64>,
    sign_ns: Option<f64>,
    kem_keygen_ns: Option<f64>,
    kem_encaps_ns: Option<f64>,
    kem_decaps_ns: Option<f64>,
    tick_ns: Option<f64>,
    aead_ns: Option<f64>,
    hrt_p50_ns: Option<f64>,
    roster_loop: Vec<(usize, f64)>,
    hs_total: Vec<f64>,
    hs_labels: Vec<String>,
    hs_server: Vec<f64>,
    hs_server_labels: Vec<String>,
}

fn print_help() {
    eprintln!(
        "\
Tunnel performance harness (TRACK I) — measurements only

USAGE:
  cargo run --release --manifest-path bench/Cargo.toml \\
      --target x86_64-pc-windows-msvc -- [OPTIONS]

OPTIONS:
  --bench <GROUP>   prims | roster | handshake | cover | cadence | derived | all
                    (default: all)
  --repeats <N>     run the group N times and print each pass, for run-to-run
                    repeatability on a shared/noisy host (default: 1)
  --quick           reduced iteration counts — SMOKE ONLY, not publishable
  -h, --help        this message

This crate is deliberately NOT a workspace member, so `cargo test --workspace`
never builds or runs it."
    );
}
