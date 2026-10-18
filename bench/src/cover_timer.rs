//! Bench 4 — cover-traffic overhead.
//!
//! Three distinct costs, in increasing order of "real overhead":
//!
//! 1. `CoverScheduler::on_deadline` — the pure policy tick (`scheduler.rs`),
//!    tokio-free, measured in virtual time. This is the *floor* paid ~195x/s
//!    per session per direction.
//! 2. AEAD encrypt of one 1280-byte record — `CipherSession::encrypt`
//!    (`envelope.rs`), the crypto the tick immediately triggers.
//! 3. The **driver loop** — where the timer is actually armed. On Windows
//!    `cover_sleep` drives a `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`
//!    waitable timer on the blocking pool (D23/M9A). That is a real
//!    `WaitForSingleObject` round-trip, so it is measured for real here by
//!    replicating the exact timer creation/arm/wait sequence, over 30 s, at the
//!    D19 nominal 5.12 ms grid.
//!
//! (1) and (2) are measured with an amortised batch because a single
//! operation is near `Instant`'s resolution; the reported figure is per-call.
//! (3) is wall-clock per wake — no amortisation, it is the quantity D23 records.

use std::ffi::{c_int, c_void};
use std::time::{Duration, Instant};

use pq_crypto::aead::{AeadKey, AeadNonce, encrypt as aead_encrypt};
use pq_crypto::kdf::MasterSecret;
use pq_tunnel_core::scheduler::{
    CoverPolicy, CoverScheduler, DEFAULT_COVER_RATE_BPS, interval_from_rate_bps,
};
use pq_tunnel_core::{CipherSession, MessageType, PAYLOAD_LEN, Role, SESSION_ID_LEN};

use crate::stats::{Stats, measure, measure_amortised, percentile_sorted};

/// Per-tick cost of `CoverScheduler::on_deadline` on the D19 default grid.
///
/// The scheduler is pure, so the loop runs in VIRTUAL time: a monotonic
/// synthetic clock advances exactly one interval per tick, which is the
/// steady-state the driver drives (it always wakes at or after the deadline).
/// Using a synthetic clock rather than `Instant::now()` matters — otherwise
/// the benchmark would be measuring the OS clock read, which is tens of
/// nanoseconds and would swamp the ~few-nanosecond tick.
///
/// Amortised over `inner` calls because one tick is below `Instant`'s
/// resolution; the reported figure is per-call.
pub fn scheduler_tick(warmup: usize, iters: usize, inner: usize) -> Stats {
    measure_amortised(
        "CoverScheduler::on_deadline (emitting tick)",
        "ns",
        warmup,
        iters,
        inner,
        |_| {
            // One scheduler advanced through its own deadlines, which is the
            // driver's actual access pattern (start once, tick forever).
            // Constructing a scheduler per sample would measure `new`+`start`.
            let policy = CoverPolicy::default();
            let mut s = CoverScheduler::new(policy);
            let t0 = Instant::now();
            s.start(t0);
            let mut now = t0;
            let mut emitted = 0usize;
            // `inner` consecutive due-ticks in virtual time.
            for _ in 0..inner {
                now += policy.interval;
                if s.on_deadline(now) {
                    emitted += 1;
                }
            }
            emitted
        },
    )
}

/// The same tick, but on a scheduler that is already scheduled and driven by a
/// reused instance — isolates the steady-state tick from the one-time
/// `new`+`start` cost that amortisation above folds in.
pub fn scheduler_tick_steady(warmup: usize, iters: usize, inner: usize) -> Stats {
    let policy = CoverPolicy::default();
    let mut s = CoverScheduler::new(policy);
    let t0 = Instant::now();
    s.start(t0);
    let mut now = t0;
    measure_amortised(
        "CoverScheduler::on_deadline (steady, pre-armed)",
        "ns",
        warmup,
        iters,
        inner,
        |_| {
            let mut emitted = 0usize;
            for _ in 0..inner {
                now += policy.interval;
                if s.on_deadline(now) {
                    emitted += 1;
                }
            }
            emitted
        },
    )
}

/// CONTROL for [`scheduler_tick_steady`]: the identical virtual-clock loop
/// with the scheduler call REMOVED.
///
/// The tick loop advances a synthetic `Instant` by one interval per call,
/// which under x64 emulation on an ARM64 host may itself be a large fraction
/// of the measured figure. This control measures the clock arithmetic alone,
/// so the difference between the two rows is the scheduler's marginal cost.
/// Without it, "scheduler tick = N ns" would be uninterpretable.
pub fn scheduler_tick_control(warmup: usize, iters: usize, inner: usize) -> Stats {
    let policy = CoverPolicy::default();
    measure_amortised(
        "CONTROL: virtual Instant advance only (no scheduler)",
        "ns",
        warmup,
        iters,
        inner,
        |_| {
            let t0 = Instant::now();
            let mut now = t0;
            for _ in 0..inner {
                now += policy.interval;
                std::hint::black_box(&now);
            }
            // Collapse the synthetic clock into a `usize` so the batch has a
            // value to accumulate and the loop cannot be optimised away.
            now.duration_since(t0).as_nanos() as usize
        },
    )
}

/// `interval_from_rate_bps` across a sweep — this is exact integer math and
/// is measured (not asserted) so the sweep table is backed by real output.
///
/// NOTE ON WHAT THIS MEASURES: a single call is a handful of integer ops and
/// sits below this host's `Instant` resolution, so the reported figure is
/// dominated by the two clock reads that bracket it (~250 ns each on
/// Windows). The p50 here is therefore a *floor* on the call, not its true
/// cost; the returned `Duration` values in the labels are the substantive
/// output of this sweep and are exact by construction.
pub fn interval_sweep(warmup: usize, iters: usize) -> Vec<Stats> {
    let rates: [u64; 12] = [
        1_000,
        64_000,
        100_000,
        1_000_000,
        2_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        1_000_000_000_000,
        1_000_000_000_000_000,
        1_000_000_000_000_000_000,
        u64::MAX,
    ];
    let mut rows = Vec::new();
    for r in rates {
        let d = interval_from_rate_bps(r);
        let s = measure(
            &format!("interval_from_rate_bps({r}) -> {d:?}"),
            "ns",
            warmup,
            iters,
            |_| interval_from_rate_bps(r),
        );
        rows.push(s);
    }
    rows
}

/// AEAD cost of one full 1280-byte record — the exact production path
/// (`CipherSession::encrypt`: build nonce, AEAD-seal the inner plaintext with
/// the header as AAD, frame to `PACKET_SIZE`).
pub fn aead_1280(warmup: usize, iters: usize, inner: usize) -> Vec<Stats> {
    let mut rows = Vec::new();

    // Raw `pq_crypto::aead::encrypt` on the inner plaintext, for reference.
    let key = AeadKey::from_bytes([0x11u8; 32]);
    let nonce = AeadNonce::from_bytes([0x22u8; 12]);
    let pt = vec![0u8; pq_tunnel_core::INNER_PLAINTEXT_LEN];
    let aad = [0u8; pq_tunnel_core::HEADER_LEN];
    rows.push(measure_amortised(
        "aead::encrypt (raw ChaCha20Poly1305, inner+tag)",
        "ns",
        warmup,
        iters,
        inner,
        |_| {
            aead_encrypt(&key, &nonce, &pt, &aad)
                .expect("aead encrypt")
                .len()
        },
    ));

    // The real session-level encrypt: nonce build + AEAD + framing, i.e. what
    // the data path pays per packet (cover or not).
    rows.push(session_encrypt_amortised(warmup, iters, inner));
    rows
}

/// Per-call cost of `CipherSession::encrypt` (the production packet path).
pub fn session_encrypt_amortised(warmup: usize, iters: usize, inner: usize) -> Stats {
    // Build a client-role session. The session id only has to be a valid
    // length; the derived keys are whatever HKDF produces.
    let mut sess = build_session();
    let payload = vec![0u8; PAYLOAD_LEN];
    measure_amortised(
        "CipherSession::encrypt (full 1280B record)",
        "ns",
        warmup,
        iters,
        inner,
        |_| {
            let pkt = sess
                .encrypt(MessageType::Data, &payload)
                .expect("session encrypt");
            pkt.as_bytes().len()
        },
    )
}

/// Helper: construct a `CipherSession` for the encrypt benchmark.
///
/// `CipherSession::new` derives keys from a master secret via HKDF; the
/// `MasterSecret` constructor is in `pq_crypto::kdf`, which the bench already
/// depends on. Any error here is a harness bug, hence the `expect`.
fn build_session() -> CipherSession {
    let master = MasterSecret::from_bytes([9u8; 32]);
    CipherSession::new(Role::Client, &master, [7u8; SESSION_ID_LEN])
        .expect("build CipherSession for benchmark")
}

// ---------------------------------------------------------------------------
// Windows high-resolution cover clock (D23/M9A)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod hrt {
    use super::*;

    const CREATE_WAITABLE_TIMER_HIGH_RESOLUTION: u32 = 0x0000_0002;
    const TIMER_ALL_ACCESS: u32 = 0x001F_0003;
    const INFINITE: u32 = 0xFFFF_FFFF;
    /// 100ns ticks between Windows FILETIME epoch (1601-01-01) and Unix epoch.
    const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

    unsafe extern "system" {
        fn CreateWaitableTimerExW(
            lp_timer_attributes: *mut c_void,
            lp_timer_name: *const u16,
            dw_flags: u32,
            dw_desired_access: u32,
        ) -> *mut c_void;
        fn SetWaitableTimer(
            h_timer: *mut c_void,
            lp_due_time: *const i64,
            l_period: c_int,
            pfn_completion_routine: *mut c_void,
            lp_arg_to_completion_routine: *mut c_void,
            f_resume: c_int,
        ) -> c_int;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
        fn CloseHandle(h_object: *mut c_void) -> c_int;
        fn GetLastError() -> u32;
    }

    /// The measured latency of one `cover_sleep`-equivalent wake: arm the
    /// high-resolution waitable timer to the deadline, block on it, and return
    /// the realised latency (actual wake - deadline).
    ///
    /// This replicates production `cover_clock::wait_until`
    /// (`session_manager.rs:1509`) exactly, including the relative due-time
    /// form it uses: `due_time(remaining)` computes ticks-from-now, NOT a
    /// negative absolute FILETIME. Sign convention matters — a negative
    /// `lpDueTime` is interpreted as an absolute time, so passing a negated
    /// relative value arms the timer for a moment in 1601 and it never fires.
    ///
    /// The production code creates a NEW timer per `CoverSleep::deadline`
    /// (a fresh `CreateWaitableTimerExW` each re-arm via `Pin::set` drops the
    /// old arm and spawns a new blocking task), so this replicates that
    /// too: create, arm, wait, close. Any residual overshoot is the per-tick
    /// wakeup skew D23 attributes the ~5.5 ms steady-state wire cadence to.
    pub fn wake_latency_series(duration: Duration) -> Vec<f64> {
        let interval = interval_from_rate_bps(DEFAULT_COVER_RATE_BPS);
        let mut latencies = Vec::new();
        let start = Instant::now();
        let mut armed_at = Instant::now();

        while start.elapsed() < duration {
            let target = armed_at + interval;
            let remaining = target.saturating_duration_since(Instant::now());
            let due = due_time(remaining);

            unsafe {
                let h = CreateWaitableTimerExW(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                    TIMER_ALL_ACCESS,
                );
                if h.is_null() {
                    panic!(
                        "CreateWaitableTimerExW failed, GetLastError={}",
                        GetLastError()
                    );
                }
                let ok =
                    SetWaitableTimer(h, &due, 0, std::ptr::null_mut(), std::ptr::null_mut(), 0);
                assert_ne!(
                    ok,
                    0,
                    "SetWaitableTimer failed, GetLastError={}",
                    GetLastError()
                );
                WaitForSingleObject(h, INFINITE);
                CloseHandle(h);
            }
            let woke = Instant::now();
            latencies.push((woke - target).as_nanos() as f64);
            armed_at = woke; // production re-arms from now (D19 pure-periodic)
        }
        latencies
    }

    /// Relative due-time in 100 ns ticks, matching production
    /// `cover_clock::due_time` (`session_manager.rs:1551`) byte for byte in
    /// arithmetic: seconds since the Unix epoch plus the FILETIME offset,
    /// scaled by 10^7 ticks/s, plus the sub-second part in 100 ns units.
    fn due_time(remaining: Duration) -> i64 {
        let unix = std::time::SystemTime::now() + remaining;
        let since_epoch = unix
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let ticks = (since_epoch.as_secs().saturating_add(FILETIME_UNIX_OFFSET)) * 10_000_000
            + u64::from(since_epoch.subsec_nanos()) / 100;
        ticks as i64
    }

    /// Control: the tokio-timer-free baseline is `Sleep`-free, so the honest
    /// control for this host is a plain `thread::sleep` to the same deadline,
    /// which is what the non-Windows code path effectively relies on.
    pub fn thread_sleep_latency_series(duration: Duration, interval: Duration) -> Vec<f64> {
        let mut latencies = Vec::new();
        let start = Instant::now();
        let mut armed_at = Instant::now();
        while start.elapsed() < duration {
            let target = armed_at + interval;
            std::thread::sleep(target.saturating_duration_since(Instant::now()));
            latencies.push((Instant::now() - target).as_nanos() as f64);
            armed_at = Instant::now();
        }
        latencies
    }
}

/// Summarise a latency series into the same `Stats` shape used everywhere else.
pub fn series_stats(label: &str, mut v: Vec<f64>) -> Stats {
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = v.len();
    let mean = v.iter().sum::<f64>() / n as f64;
    Stats {
        label: label.to_string(),
        unit: "ns",
        iterations: n,
        warmup: 0,
        min_ns: v[0],
        p50_ns: percentile_sorted(&v, 0.50),
        median_ns: percentile_sorted(&v, 0.50),
        p99_ns: percentile_sorted(&v, 0.99),
        max_ns: v[n - 1],
        mean_ns: mean,
    }
}

/// Run the cover-clock cadence measurement for `duration` on both the
/// high-resolution waitable timer and the `thread::sleep` control, and report
/// achieved packet rate alongside the latency distribution.
#[cfg(windows)]
pub fn cover_cadence(duration: Duration) -> (Stats, Stats, f64, f64, usize, usize) {
    let hrt = hrt::wake_latency_series(duration);
    let ctl =
        hrt::thread_sleep_latency_series(duration, interval_from_rate_bps(DEFAULT_COVER_RATE_BPS));
    let hrt_stats = series_stats(
        "cover wake latency (CREATE_WAITABLE_TIMER_HIGH_RESOLUTION)",
        hrt,
    );
    let ctl_stats = series_stats("cover wake latency (thread::sleep control)", ctl);
    // D23 achieved-rate: nominal is 195.3125 pkt/s; the achieved rate is
    // (wakes / wall_seconds).
    let wall = duration.as_secs_f64();
    let nominal = 1.0 / interval_from_rate_bps(DEFAULT_COVER_RATE_BPS).as_secs_f64();
    let hrt_n = hrt_stats.iterations;
    let ctl_n = ctl_stats.iterations;
    let hrt_rate = hrt_n as f64 / wall;
    let ctl_rate = ctl_n as f64 / wall;
    println!(
        "  nominal interval = {:?} ({:.4} ms), nominal rate = {:.4} pkt/s",
        interval_from_rate_bps(DEFAULT_COVER_RATE_BPS),
        interval_from_rate_bps(DEFAULT_COVER_RATE_BPS).as_secs_f64() * 1e3,
        nominal
    );
    (hrt_stats, ctl_stats, hrt_rate, ctl_rate, hrt_n, ctl_n)
}

#[cfg(not(windows))]
pub fn cover_cadence(duration: Duration) -> (Stats, Stats, f64, f64, usize, usize) {
    let _ = duration;
    println!("  NOT MEASURED: high-resolution waitable timer is Windows-only");
    (
        series_stats("cover wake latency (NOT MEASURED)", vec![0.0]),
        series_stats("control (NOT MEASURED)", vec![0.0]),
        0.0,
        0.0,
        0,
        0,
    )
}
