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
/// result is clamped to a nonzero interval (the exact math saturates to 0 ns
/// for rates above ~10 Tbps — a zero interval would turn the driver's
/// `sleep_until(now)` into a busy loop).  The clamp only affects rates that
/// would already saturate the scheduling arithmetic; sane rates are exact.
pub fn interval_from_rate_bps(rate_bps: u64) -> Duration {
    let bits_per_packet = PACKET_SIZE as u64 * 8;
    let nanos = bits_per_packet
        .saturating_mul(1_000_000_000)
        .saturating_div(rate_bps.max(1));
    Duration::from_nanos(nanos.max(1))
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

    #[test]
    fn absurd_rate_is_clamped_to_nonzero_interval() {
        // The exact integer math saturates to 0 ns for huge rates; the 1 ns
        // floor keeps the driver's sleep_until from busy-looping.
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
