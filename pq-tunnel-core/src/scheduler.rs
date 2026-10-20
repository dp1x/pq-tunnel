//! Cover-traffic scheduling (Phase 7 / M3).
//!
//! Cover traffic is a **transport behaviour**, not a handshake property: it
//! exists to shape the observable wire pattern of an *established* session
//! (PROTOCOL_SPEC §12.1: fixed shaping, cover enabled by default).  It is
//! intentionally kept out of `ClientConfig`/`ServerConfig`, so it can never
//! become protocol-negotiated state.
//!
//! Layering (D19):
//!
//! * `core` owns the *policy and timing logic* — this module is pure,
//!   `tokio`-free, and unit-testable in virtual time.
//! * the binary drivers (and the manager driver loops they feed) own *async
//!   execution* — they pin a `tokio` sleep on the next deadline computed here.
//!
//! Shaping semantics (D5: pure-periodic; D6: constant-rate, fixed default):
//!
//! * the policy is **fixed** by default — `Fixed`, enabled, 2 Mbps.  Adaptive
//!   modes are future, user-selected policies; they are **never** a default
//!   and are **not** implemented here.
//! * pacing is *pure-periodic with jitter tolerance*: the scheduler tracks a
//!   monotonic deadline and, when that deadline passes, yields **at most one**
//!   emission, rescheduling from "now".  A long OS stall therefore produces a
//!   single catch-up packet — never a buffered burst, which would itself be a
//!   traffic fingerprint.
//!
//! The D5/D6 invariant is protocol-level constant rate over time — a stable,
//! observable pattern — not wall-clock/nanosecond alignment.

use std::time::Duration;
use std::time::Instant;

use crate::codec::PACKET_SIZE;

/// Default fixed cover rate (PROTOCOL_SPEC §12.1 / D6): 2 Mbps for v0.2.0.
pub const DEFAULT_COVER_RATE_BPS: u64 = 2_000_000;

/// Minimum cover emission interval, in nanoseconds.
///
/// # Derivation
///
/// A cover packet is not free: every emission costs one scheduler tick, one
/// full 1280-byte record encryption, and the driver's timer/wake/send
/// syscalls.  Measured on the reference host
/// (`docs/performance/I-benchmark-methodology.md` §7.1, §7.3, §7.5):
///
/// | component | p50 |
/// |---|---:|
/// | `CoverScheduler::on_deadline` (emitting tick) | 11 109 ns |
/// | `CipherSession::encrypt` (full 1280 B record) | 10 653 ns |
/// | **per-cover-packet CPU (excludes syscalls)** | **21 762 ns** |
///
/// A cover interval *shorter than the time it takes to produce one cover
/// packet* is unachievable by construction: the driver is asked to begin
/// emission N+1 before emission N could have finished, so the schedule
/// degenerates into a back-to-back spin whose real rate is set by the OS
/// wake path rather than by the operator's setting.  The floor is therefore
/// the measured per-packet cost, and it is a **lower** bound on the true
/// cost (the timer create/arm/wait/close and the `sendto` are excluded from
/// the measurement).
///
/// **What the floor does and does not guarantee.** It removes the
/// pathological 1 ns interval and it **bounds the rate the operator may
/// request**; the CLI rejects anything above it with a named error rather
/// than silently clamping. It does **not** guarantee that the requested rate
/// is achievable on any given host: the measurement excludes the syscalls,
/// so the true per-packet cost is higher than the floor. On the reference
/// host the measured minimum `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` wake
/// latency is 15 200 ns (§7.4), which puts that host's achievable period at
/// roughly 37 us (about 276 Mbps) — below the ceiling the floor admits. The
/// floor is a **lower bound on cost and an upper bound on the requested
/// rate**, not a promise of throughput.
///
/// Cross-check on the same host: the floor is above the timer's own
/// achievable re-arm period.
///
/// The D19 default is unaffected: 2 Mbps is a 5.12 ms interval, 235x the
/// floor.
pub const MIN_COVER_INTERVAL_NANOS: u64 = 21_762;

/// The highest cover rate whose interval is not shorter than
/// [`MIN_COVER_INTERVAL_NANOS`].
///
/// `PACKET_SIZE * 8` bits per packet at `MIN_COVER_INTERVAL_NANOS` ns per
/// packet.  Integer division floors, so the value is exactly the largest
/// rate the floor admits.
pub const MAX_COVER_RATE_BPS: u64 =
    PACKET_SIZE as u64 * 8 * 1_000_000_000 / MIN_COVER_INTERVAL_NANOS;

/// Cover emission schedule chosen by the operator.
///
/// This is a transport/driver policy parameter.  In particular it does NOT
/// belong to handshake configuration: nothing here is placed on the wire, and
/// future protocol versions must not negotiate it either (D19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverPolicy {
    /// Emit cover packets at all.  Disabling is a visible, documented
    /// reduction of metadata resistance (never a silent default).
    pub enabled: bool,
    /// Per-session, pure-periodic emission interval.
    pub interval: Duration,
}

impl Default for CoverPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: interval_from_rate_bps(DEFAULT_COVER_RATE_BPS),
        }
    }
}

/// Convert a bitrate to the per-`PACKET_SIZE` emission interval.
///
/// Exact integer math (no float multiplication in the timed path):
/// `interval_ns = PACKET_SIZE_bits * 1_000_000_000 / rate_bps`.
/// Rate guards: a pathological `rate_bps = 0` is clamped to 1 bps, and the
/// result is clamped into `[MIN_COVER_INTERVAL_NANOS, ..]` — the exact math
/// saturates to 0 ns for rates above ~10 Tbps (a zero interval would turn
/// the driver's `sleep_until(now)` into a busy loop), and an interval
/// shorter than the time it takes to produce one cover packet is not
/// schedulable at all (see [`MIN_COVER_INTERVAL_NANOS`] for the derivation).
/// The clamp only affects rates that would already saturate the scheduling
/// arithmetic; sane rates are exact — the D19 default (2 Mbps) is exactly
/// 5.12 ms.
pub fn interval_from_rate_bps(rate_bps: u64) -> Duration {
    let bits_per_packet = PACKET_SIZE as u64 * 8;
    let nanos = bits_per_packet
        .saturating_mul(1_000_000_000)
        .saturating_div(rate_bps.max(1));
    Duration::from_nanos(nanos.max(MIN_COVER_INTERVAL_NANOS))
}

/// A pure-periodic cover schedule for one direction of one session.
///
/// This is deliberately clock-agnostic (uses `Instant` as an abstract
/// timeline) and has no `tokio` dependency; the driver converts its deadline
/// into a platform cover-timer arm (high-resolution waitable timer on
/// Windows, tokio elsewhere — M9A).
#[derive(Debug, Clone)]
pub struct CoverScheduler {
    policy: CoverPolicy,
    /// Next emission deadline, or `None` when not scheduled (e.g. before the
    /// session is established, or after it closed).
    next: Option<Instant>,
}

impl CoverScheduler {
    /// A scheduler for `policy`.  It starts unscheduled: it does not emit
    /// until [`CoverScheduler::start`] is called on establishment.
    pub fn new(policy: CoverPolicy) -> Self {
        Self { policy, next: None }
    }

    pub fn policy(&self) -> CoverPolicy {
        self.policy
    }

    /// Begin scheduling as of `now`.  Idempotent: on the first call the
    /// deadline is one interval in the future (no click immediately at
    /// establishment).
    pub fn start(&mut self, now: Instant) {
        if self.next.is_none() && self.policy.enabled {
            self.next = Some(now + self.policy.interval);
        }
    }

    /// Stop scheduling (e.g. the session closed).  The arm is then inert.
    pub fn stop(&mut self) {
        self.next = None;
    }

    /// Whether a deadline is armed and, if so, which one.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.next
    }

    /// Invoked by the driver's when the deadline `Instant` arrives.
    ///
    /// Returns `true` when exactly one emission is due and reschedules the
    /// next deadline from `now`.  Guarantees:
    ///
    /// * at most one `true` per call;
    /// * a heavily-delayed wakeup yields a single catch-up emission, then the
    ///   schedule resets to `now + interval` (no burst accumulation, no clock
    ///   catch-up);
    /// * a disabled policy (or an un-scheduled scheduler) never emits and is a
    ///   no-op.
    pub fn on_deadline(&mut self, now: Instant) -> bool {
        if !self.policy.enabled {
            self.next = None;
            return false;
        }
        match self.next {
            None => false,
            Some(due) if now >= due => {
                self.next = Some(now + self.policy.interval);
                true
            }
            Some(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed `now` timeline for determinism: every test manufactures instants
    /// from a single origin so assertions are virtual-time, not wall-clock.
    fn origin() -> Instant {
        Instant::now()
    }

    #[test]
    fn default_is_fixed_enabled_two_mbps() {
        let p = CoverPolicy::default();
        assert!(p.enabled, "cover must default to enabled (D6)");
        assert_eq!(p.interval, interval_from_rate_bps(DEFAULT_COVER_RATE_BPS),);
        // 1280 B packet == 10_240 bits; 2 Mbps -> 5.12 ms exactly.
        assert_eq!(p.interval, Duration::from_nanos(5_120_000));
    }

    #[test]
    fn interval_math_is_exact() {
        assert_eq!(
            interval_from_rate_bps(2_000_000),
            Duration::from_nanos(5_120_000)
        );
        assert_eq!(
            interval_from_rate_bps(1_000_000),
            Duration::from_nanos(10_240_000)
        );
    }

    #[test]
    fn starts_unscheduled_and_primes_one_interval_out() {
        let now = origin();
        let interval = CoverPolicy::default().interval;
        let mut s = CoverScheduler::new(CoverPolicy::default());
        assert_eq!(s.next_deadline(), None, "not scheduled before start");
        s.start(now);
        s.start(now); // idempotent
        let d = s.next_deadline().unwrap();
        assert_eq!(d, now + interval);
        // First deadline fires: emits, reschedules from now.
        assert!(s.on_deadline(now + interval));
        assert_eq!(s.next_deadline().unwrap(), now + 2 * interval);
    }

    #[test]
    fn emits_exactly_once_per_interval() {
        let sched_default = CoverPolicy::default();
        let interval = sched_default.interval;

        let now = origin();
        let mut s = CoverScheduler::new(sched_default);
        s.start(now);

        // Between deadlines: nothing.
        assert!(!s.on_deadline(now + interval / 2));
        // At the deadline: one emission.
        assert!(s.on_deadline(now + interval));
        assert_eq!(s.next_deadline().unwrap(), now + 2 * interval);
        // Immediately after: nothing.
        assert!(!s.on_deadline(now + interval + Duration::from_nanos(1)));
    }

    #[test]
    fn no_burst_accumulation_after_long_stall() {
        let sched_default = CoverPolicy::default();
        let interval = sched_default.interval;
        let now = origin();
        let mut s = CoverScheduler::new(sched_default);
        s.start(now);
        // A stalled driver wakes up 10 intervals late.
        let stalled = now + interval * 10;
        // A single catch-up emission ...
        assert!(
            s.on_deadline(stalled),
            "a missed deadline must emit exactly once"
        );
        // ... then the schedule restarts from now, not from the old track:
        assert_eq!(s.next_deadline().unwrap(), stalled + interval);
        // No further spurious bursts back-to-back.
        assert!(!s.on_deadline(stalled + Duration::from_nanos(1)));
    }

    #[test]
    fn disabled_policy_never_emits() {
        let p = CoverPolicy {
            enabled: false,
            interval: Duration::from_millis(1),
        };
        let now = origin();
        let mut s = CoverScheduler::new(p);
        s.start(now);
        assert_eq!(s.next_deadline(), None, "disabled never schedules");
        assert!(!s.on_deadline(now + Duration::from_secs(3600)));
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn stop_makes_the_arm_inert() {
        let now = origin();
        let mut s = CoverScheduler::new(CoverPolicy::default());
        s.start(now);
        s.stop();
        assert_eq!(s.next_deadline(), None);
        assert!(!s.on_deadline(now + Duration::from_secs(1)));
    }

    #[test]
    fn zero_rate_is_clamped_not_panicking() {
        // A 0 bps request clamps to 1 bps: enormous but well-defined interval.
        let d = interval_from_rate_bps(0);
        assert!(!d.is_zero());
    }

    /// The derived floor is **21 762 ns**, written out so a change to the
    /// constant fails this test rather than silently re-basing it.
    #[test]
    fn min_cover_interval_is_21762_nanos() {
        assert_eq!(MIN_COVER_INTERVAL_NANOS, 21_762);
    }

    /// No rate may produce an interval shorter than the derived floor: the
    /// 1 ns clamp that used to be reachable (and that turned the driver's
    /// `sleep_until` into a hot re-arm loop) is gone.
    #[test]
    fn interval_never_goes_below_the_derived_floor() {
        for rate in [
            0u64,
            1,
            1_000,
            1_000_000,
            2_000_000,
            MAX_COVER_RATE_BPS,
            MAX_COVER_RATE_BPS + 1,
            1_000_000_000_000,
            1_000_000_000_000_000,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let d = interval_from_rate_bps(rate);
            assert!(
                d >= Duration::from_nanos(MIN_COVER_INTERVAL_NANOS),
                "rate {rate} must not yield an interval below the derived floor, got {d:?}"
            );
        }
        assert_eq!(
            interval_from_rate_bps(u64::MAX),
            Duration::from_nanos(MIN_COVER_INTERVAL_NANOS),
            "the fastest possible rate lands exactly on the floor"
        );
    }

    /// `MAX_COVER_RATE_BPS` is exactly the largest rate the floor admits:
    /// one bit/s more would produce an interval one nanosecond short.
    #[test]
    fn max_cover_rate_bps_is_exactly_the_floor_boundary() {
        let packet_bits = PACKET_SIZE as u64 * 8 * 1_000_000_000;
        assert!(
            MAX_COVER_RATE_BPS * MIN_COVER_INTERVAL_NANOS <= packet_bits,
            "the max rate must not ask for an interval shorter than the floor"
        );
        assert!(
            (MAX_COVER_RATE_BPS + 1) * MIN_COVER_INTERVAL_NANOS > packet_bits,
            "one bit/s more must exceed the floor"
        );
        // The value itself, written out (not derived from the constant).
        assert_eq!(MAX_COVER_RATE_BPS, 470_544_986);
    }

    /// The D19 default is untouched by the floor: 2 Mbps is still exactly
    /// 5.12 ms, 235x the floor.
    #[test]
    fn default_rate_is_unaffected_by_the_floor() {
        assert_eq!(
            interval_from_rate_bps(DEFAULT_COVER_RATE_BPS),
            Duration::from_nanos(5_120_000)
        );
        assert_eq!(MIN_COVER_INTERVAL_NANOS * 235, 5_114_070);
    }

    #[test]
    fn absurd_rate_is_clamped_to_nonzero_interval() {
        // The exact integer math saturates to 0 ns for huge rates; the
        // derived floor keeps the driver's sleep_until from busy-looping.
        assert!(!interval_from_rate_bps(u64::MAX).is_zero());
        // Monotonicity: a higher rate never yields a longer interval
        // (quotients of positive integers are non-increasing in the rate).
        let pairs = [
            (1u64, 2u64),
            (2, 4),
            (1_000, 1_000_000),
            (1_000_000, 1_000_000_000),
            (1_000_000_000, u64::MAX),
            (u64::MAX / 2, u64::MAX),
        ];
        for (lo, hi) in pairs {
            assert!(
                interval_from_rate_bps(lo) >= interval_from_rate_bps(hi),
                "rate {lo} must not give a shorter interval than rate {hi}"
            );
        }
    }
}
