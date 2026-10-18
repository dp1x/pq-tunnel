//! Timing primitives: no benchmark framework, no external dependency.
//!
//! Everything here is deliberately simple and auditable:
//!
//! * one sample = one `Instant::now()` delta around the measured region;
//! * the measured region is driven by the caller as a closure, so the
//!   optimizer cannot delete the work (`black_box` is applied to the result);
//! * statistics are **percentiles over the full sorted sample vector**, not
//!   estimators, so every reported number is an actually-observed value.
//!
//! Percentile convention (documented because it is otherwise ambiguous): for a
//! sorted sample vector `v` of length `n`, index `i = ceil(q * n) - 1`
//! clamped to `[0, n-1]` — the *nearest-rank* method. It always returns a real
//! observation (never an interpolated value that was never measured), which is
//! what "measurements only" requires.

use std::hint::black_box;
use std::time::Instant;

/// Ordered timing statistics for one measured operation, in nanoseconds.
///
/// `min`/`p50`/`median`/`p99` are all *observed samples*. `median` is reported
/// alongside `p50` because they differ whenever `n` is even (and even when
/// `n` is odd the two can coincide — reporting both makes the table
/// self-checking).
#[derive(Debug, Clone)]
pub struct Stats {
    pub label: String,
    pub unit: &'static str,
    pub iterations: usize,
    pub warmup: usize,
    pub min_ns: f64,
    pub p50_ns: f64,
    pub median_ns: f64,
    pub p99_ns: f64,
    pub max_ns: f64,
    pub mean_ns: f64,
}

impl Stats {
    /// Build from a raw, unsorted sample vector. `unit` is carried through to
    /// the report so no reader can confuse nanoseconds with seconds.
    pub fn from_samples_ns(
        label: impl Into<String>,
        unit: &'static str,
        warmup: usize,
        mut v: Vec<f64>,
    ) -> Self {
        assert!(!v.is_empty(), "cannot summarise zero samples");
        v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
        let n = v.len();
        let sum: f64 = v.iter().sum();
        Stats {
            label: label.into(),
            unit,
            iterations: n,
            warmup,
            min_ns: v[0],
            p50_ns: percentile_sorted(&v, 0.50),
            median_ns: percentile_sorted(&v, 0.50),
            p99_ns: percentile_sorted(&v, 0.99),
            max_ns: v[n - 1],
            mean_ns: sum / n as f64,
        }
    }

    /// One-line summary suitable for pasting into the methodology document.
    pub fn line(&self) -> String {
        format!(
            "{label:<46} {unit}  n={iters:<7} warmup={warm:<5} min={min:>12.1} p50={p50:>12.1} median={med:>12.1} p99={p99:>12.1} max={max:>12.1} mean={mean:>12.1}",
            label = self.label,
            unit = self.unit,
            iters = self.iterations,
            warm = self.warmup,
            min = self.min_ns,
            p50 = self.p50_ns,
            med = self.median_ns,
            p99 = self.p99_ns,
            max = self.max_ns,
            mean = self.mean_ns,
        )
    }
}

/// Nearest-rank percentile of an already-sorted, non-empty vector.
///
/// `i = ceil(q * n) - 1`, clamped. Always returns an observed sample.
pub fn percentile_sorted(v: &[f64], q: f64) -> f64 {
    assert!(!v.is_empty(), "percentile of an empty sample set");
    let n = v.len();
    let rank = (q * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    v[idx]
}

/// Time `f` `iters` times, discarding the first `warmup` samples.
///
/// Returns the retained samples in nanoseconds. A warm-up pass is mandatory
/// for every operation here: ML-DSA/ML-KEM key material generation, first
/// touch of freshly allocated ciphertext buffers, and the Windows emulated-x64
/// translation cache all bias the first iterations, and reporting those would
/// inflate every p99.
pub fn time_ns<F, R>(warmup: usize, iters: usize, mut f: F) -> Vec<f64>
where
    F: FnMut(usize) -> R,
{
    assert!(iters > 0, "need at least one measured iteration");
    for i in 0..warmup {
        black_box(f(i));
    }
    let mut out = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = Instant::now();
        let r = f(warmup + i);
        let d = t.elapsed();
        black_box(r);
        out.push(d.as_nanos() as f64);
    }
    out
}

/// Convenience: `time_ns` + `Stats` in one call.
pub fn measure<F, R>(label: &str, unit: &'static str, warmup: usize, iters: usize, f: F) -> Stats
where
    F: FnMut(usize) -> R,
{
    let s = time_ns(warmup, iters, f);
    Stats::from_samples_ns(label, unit, warmup, s)
}

/// Time a whole batch of `inner` repetitions as ONE sample, then divide.
///
/// Used where a single operation is far below `Instant`'s resolution (the
/// cover scheduler tick, the AEAD encrypt). Measuring 1 call and reporting
/// ~20 ns would be measuring clock granularity, not the operation; instead
/// each sample times `inner` back-to-back calls and the reported figure is the
/// per-call amortised cost. The division is exact integer arithmetic on the
/// nanosecond total.
///
/// `R: Into<usize>` so each call's result contributes to the accumulator and
/// cannot be optimised away.
pub fn measure_amortised<F, R>(
    label: &str,
    unit: &'static str,
    warmup: usize,
    iters: usize,
    inner: usize,
    mut f: F,
) -> Stats
where
    F: FnMut(usize) -> R,
    R: Into<usize>,
{
    assert!(inner > 0, "amortised batch must contain at least one call");
    let raw = time_ns(warmup, iters, |i| {
        let mut acc: usize = black_box(0);
        for k in 0..inner {
            acc = acc.wrapping_add(f(inner * i + k).into());
        }
        acc
    });
    let per_call: Vec<f64> = raw.into_iter().map(|ns| ns / inner as f64).collect();
    Stats::from_samples_ns(label, unit, warmup, per_call)
}

/// Print the environment banner every run starts with, so a reader can tell
/// which machine produced a pasted result block.
pub fn banner() {
    println!("================================================================================");
    println!("Tunnel performance harness (TRACK I) — measurements only");
    println!("================================================================================");
    println!("host_arch_env      : {}", std::env::consts::ARCH);
    println!("profile            : release (opt-level=3, debug=true)");
    println!("sample_definition  : 1 sample = Instant::now() delta around the measured region");
    println!("percentile_method  : nearest-rank, i = ceil(q*n)-1, clamped to [0, n-1]");
    println!("threads            : single-threaded, no rayon/threads in the harness");
    println!();
}

/// Report a table header + rows for a set of `Stats`.
pub fn print_table(title: &str, rows: &[Stats]) {
    println!("--- {title} ---");
    println!(
        "{:<46} {:<6} {:<14} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "operation", "unit", "iterations", "min", "p50", "median", "p99", "max", "mean"
    );
    for s in rows {
        println!("{}", s.line());
    }
    println!();
}

/// Convert seconds to a human-readable duration without pulling in a crate.
pub fn human_seconds(s: f64) -> String {
    let years = s / (365.2425 * 86_400.0);
    if years >= 1.0 {
        format!("{years:.3} years ({s:.3e} s)")
    } else {
        let days = s / 86_400.0;
        if days >= 1.0 {
            format!("{days:.3} days ({s:.3e} s)")
        } else {
            format!("{s:.3e} s")
        }
    }
}

/// Nanoseconds -> a compact human string (for per-packet cost lines).
pub fn human_ns(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.2} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.3} us", ns / 1_000.0)
    } else {
        format!("{:.4} ms", ns / 1_000_000.0)
    }
}
