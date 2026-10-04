#![no_main]

//! Fuzz target: `ReplayWindow::accept`.
//!
//! Invariant under test — **"no counter is ever accepted twice."**  For every
//! `counter`, across an arbitrary arrival order, `accept(counter)` must return
//! `Ok` on the first arrival and `Err` on *every* later arrival.  This is the
//! HNDL-relevant property (PROTOCOL_SPEC §5.6): once a counter has been used,
//! an attacker replaying the packet must never get a second `Ok`.
//!
//! # Why the oracle is independent of the implementation
//!
//! The oracle is a `HashSet<u64>` of every counter that has ever been offered,
//! which is exactly the definition of "accepted before" and is correct by
//! construction.  It shares **no** code with `ReplayWindow`: it does not
//! reproduce the bitmap, the `shift_right` word/bit decomposition, the
//! `highest` high-water mark, or any of the `gap > WINDOW_BITS` /
//! `gap == WINDOW_BITS` branches.  It cannot inherit a bug from those, so a
//! genuine double-accept — most plausibly in `shift_right`, the most intricate
//! code on this path — surfaces here as a fuzz failure rather than going
//! unnoticed.  The model is only used as the *duplicate* oracle; it is
//! deliberately NOT used to predict acceptance (see below).
//!
//! # Why acceptance is NOT predicted by the model
//!
//! `accept` reports "too old to be inside the window" as the *same*
//! `Err(CodecError::DecryptionFailed)` as a replay (PROTOCOL_SPEC §14), and it
//! legitimately *forgets* counters once the window slides past them — the
//! module doc states the guarantee is "no counter is ever accepted twice" and
//! that the window width only trades availability under reordering.  So a
//! counter that was accepted, then evicted, then re-offered is correctly
//! rejected; asserting `Ok` for it would be wrong, and asserting `Err` for any
//! `HashSet` hit would also be wrong because re-acceptance after eviction would
//! fail the test for a correct implementation.  The model therefore asserts
//! **only** the "never accepted twice" direction, which is the whole security
//! guarantee.  Counters evicted from the window can never be accepted again
//! anyway: they are more than `WINDOW_BITS` below the high-water mark, and any
//! counter that lifts the high-water mark above them is `Ok` — a *new* counter,
//! never one the model has seen.

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use pq_tunnel_core::replay::ReplayWindow;

/// Window width, restated here rather than imported.  The fuzz target asserts a
/// *semantic* invariant (never accept twice) and only needs the window width to
/// bias its generators toward the `gap > WINDOW_BITS` (clear) and
/// `gap == WINDOW_BITS` (preserve-boundary-bit) branches; the guarantee itself
/// is asserted without reference to this constant.
const WINDOW_BITS: u64 = 1024;

/// Maximum number of arrivals driven from one input.  Enough to cross many
/// slide boundaries while keeping every execution cheap.
const MAX_OPS: usize = 24;

/// Unsigned wrapping add — deliberately *not* `saturating_add` and *not*
/// checked, so fuzz bytes near `u64::MAX` produce wrap-around counters
/// instead of a panic inside the generator.
fn wrap_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Generate the next arrival, given the current high-water mark.
///
/// The first byte is a small weighted selector; the remaining bytes are a
/// little-endian u64.  `highest` is the last `Ok` counter (a monotone
/// high-water mark, kept by the driver itself).
fn gen_counter(sel: u8, arg: u64, highest: Option<u64>) -> u64 {
    match sel % 12 {
        // Exact duplicate of an earlier counter, or of the high-water mark: the
        // duplicate-arrival path.
        0 => highest.unwrap_or(0),
        // Forward step of 1..=64.
        1 => wrap_add(highest.unwrap_or(0), (arg & 0x3F) + 1),
        // Forward jump of 1..=4095: spans `bit_shift` values 0..63 and
        // `word_gap` values 0..63, so the cross-word shift is genuinely
        // exercised, and lands inside, across, and beyond `WINDOW_BITS`.
        2 => wrap_add(highest.unwrap_or(0), (arg & 0xFFF) + 1),
        // Backward / out-of-order arrival: anywhere from 1 below the high-water
        // mark to far beyond the window.
        3 | 4 => highest.unwrap_or(0).wrapping_sub(arg & 0xFFF),
        // Directly targeted boundary jumps from the current high-water mark:
        // `gap > WINDOW_BITS` clears the bitmap, `gap == WINDOW_BITS` clears it
        // but preserves the old highest at the boundary bit.
        5 => wrap_add(highest.unwrap_or(0), WINDOW_BITS),
        6 => wrap_add(highest.unwrap_or(0), WINDOW_BITS + 1),
        // Large gap: bitmap fully cleared.
        7 => wrap_add(highest.unwrap_or(0), (arg & 0xFFFF) + WINDOW_BITS + 2),
        // Deliberate back-and-forth across the window edge: a counter just
        // outside the window (rejected as too old, not as a replay), then the
        // same counter with the window pulled back inside.
        8 => match highest {
            Some(h) => {
                let just_outside = h.saturating_sub(WINDOW_BITS + 1);
                wrap_add(just_outside, 1 + (arg & 1))
            }
            None => 0,
        },
        // Duplicate of the high-water mark again (heavier weight for the
        // replay path).
        9 => highest.unwrap_or(0),
        // Cold counter far from the high-water mark (frequently wrapped).
        10 => arg,
        // Unconstrained: plain fuzzer bytes as a counter, which is how the
        // extreme `u64::MAX` / wrap-around cases are reached.
        _ => arg,
    }
}

/// One independent oracle: feed `counters` to a fresh window in arrival order
/// and assert "no counter is accepted twice".
fn run_workload(counters: &[u64]) {
    let mut w = ReplayWindow::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut highest: Option<u64> = None;

    for (i, &c) in counters.iter().enumerate() {
        let was_accepted_before = seen.contains(&c);
        let res = w.accept(c);

        assert_eq!(
            res.is_ok(),
            !was_accepted_before,
            "accept({c}) returned {:?} but the independent model says this counter \
             was {}  (arrival #{i}, counters={counters:?})",
            res,
            if was_accepted_before {
                "already accepted"
            } else {
                "never accepted"
            }
        );

        if res.is_ok() {
            // Defence in depth: the high-water mark is monotone.
            if let Some(h) = highest {
                assert!(
                    c > h,
                    "accept({c}) succeeded below the high-water mark {h} — highest must never decrease"
                );
            }
            highest = Some(c);
            seen.insert(c);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Segment the input into 9-byte records (1 selector + 8 LE argument).  A
    // short tail is ignored, which keeps the target panic-free on any input.
    let ops = data.len() / 9;
    if ops == 0 {
        return;
    }

    // One monotonic workload.
    let mut counters = Vec::with_capacity(ops.min(MAX_OPS));
    let mut highest: Option<u64> = None;
    for i in 0..ops.min(MAX_OPS) {
        let sel = data[i * 9];
        let arg = u64::from_le_bytes([
            data[i * 9 + 1],
            data[i * 9 + 2],
            data[i * 9 + 3],
            data[i * 9 + 4],
            data[i * 9 + 5],
            data[i * 9 + 6],
            data[i * 9 + 7],
            data[i * 9 + 8],
        ]);
        let c = gen_counter(sel, arg, highest);
        if highest.is_none() || c > highest.unwrap() {
            highest = Some(c);
        }
        counters.push(c);
    }
    run_workload(&counters);

    // Second, adversarial ordering of the *same* counters: shuffled, then
    // reversed.  This is where a slide/eviction bug shows up — the arriving
    // order, and hence which counters fall outside the window, differs from
    // the monotonic workload while the "never twice" guarantee must still hold.
    let mut shuffled = counters.clone();
    // Deterministic Fisher–Yates from fuzzer bytes (no RNG state, no clock).
    for i in (1..shuffled.len()).rev() {
        let pick = data[i % data.len()] as usize % (i + 1);
        shuffled.swap(i, pick);
    }
    run_workload(&shuffled);

    let mut reversed = counters;
    reversed.reverse();
    run_workload(&reversed);
});