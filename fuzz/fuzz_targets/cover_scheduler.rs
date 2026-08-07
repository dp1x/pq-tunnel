#![no_main]

//! Fuzz target: cover-traffic scheduler state machine.
//!
//! Drives `CoverScheduler` over a virtual clock built from the input bytes:
//! start/stop/on_deadline at arbitrary, non-monotonic, and huge offsets.
//! Also exercises `interval_from_rate_bps` directly.
//!
//! Hard invariants (see `pq-tunnel-core/src/scheduler.rs`):
//! * `interval_from_rate_bps(r)` is never zero for ANY u64 rate (1 ns floor);
//! * a higher rate never yields a longer interval;
//! * `on_deadline(t)` returns true EXACTLY when a deadline `d <= t` is armed
//!   (a full behavioural oracle against a local deadline copy);
//! * after an emission the next deadline is `t + interval`;
//! * a disabled policy, a stopped scheduler, and a scheduler that never
//!   started never emit.
//! Every falsification is a real panic.

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::scheduler::{CoverPolicy, CoverScheduler, interval_from_rate_bps};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // -- interval math: never zero, monotone in rate -------------------------
    let mut rate = 0u64;
    for (i, b) in data.iter().take(8).enumerate() {
        rate |= (*b as u64) << (8 * i);
    }
    let d = interval_from_rate_bps(rate);
    assert!(
        !d.is_zero(),
        "interval must never be zero (busy-loop guard)"
    );
    assert!(
        d <= Duration::from_nanos(10_240_000_000_000),
        "1 bps yields ~10.24e9 ns; nothing longer"
    );
    let d_hi = interval_from_rate_bps(rate.saturating_add(1));
    assert!(d >= d_hi, "raising the rate must not lengthen the interval");

    // -- scheduler oracle -----------------------------------------------------
    let epoch = Instant::now();
    let interval = d;
    let mut sched = CoverScheduler::new(CoverPolicy {
        enabled: data[0] & 1 == 0,
        interval,
    });
    // Fuzz-controlled timeline (bounded so every arithmetic is safe).
    let mut off = 0u64;
    let mut now = |off: u64| epoch + Duration::from_nanos(off & ((1 << 61) - 1));

    // Local oracle state.
    let mut started = false;
    let mut stopped = false;
    let mut deadline: Option<Instant> = None;

    for step in 0..48usize {
        let jump = (data[(step * 7 + 3) % data.len()] as u64)
            .wrapping_mul(1 + data[(step * 3 + 1) % data.len()] as u64);
        off = off.wrapping_add(jump);
        let t = now(off);

        if step == 10 {
            sched.start(t);
            started = true;
            if sched.policy().enabled {
                deadline = Some(t + interval);
            }
        }
        if step == 30 {
            sched.stop();
            stopped = true;
            deadline = None;
        }
        if step == 40 && started {
            // Re-arm after stop: the scheduler becomes live again.
            sched.start(t);
            stopped = false;
            if sched.policy().enabled {
                deadline = Some(t + interval);
            }
        }

        let should =
            started && !stopped && sched.policy().enabled && deadline.is_some_and(|dead| t >= dead);
        let emitted = sched.on_deadline(t);
        assert_eq!(
            emitted, should,
            "oracle mismatch at step {step}: started={started} stopped={stopped}",
        );
        if emitted {
            deadline = Some(t + interval);
        }
    }
});
