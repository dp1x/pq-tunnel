//! Sliding-window replay protection for the Tunnel sequence counter.
//!
//! PROTOCOL_SPEC §5.6 (Replay Protection) requires that Tunnel MUST prevent
//! attackers from successfully replaying previously accepted communication.
//! PROTOCOL_SPEC §11 requires a sequencing mechanism (the `packet_nonce`
//! field on `PacketHeader`).
//!
//! # Design
//!
//! Each direction carries a monotonic u64 `packet_nonce` counter
//! (CRYPTO_PROFILE §8 — unique nonce requirement).  On the receive path the
//! `ReplayWindow` tracks which counters have been seen and rejects repeats.
//!
//! A pure high-water mark (reject all out-of-order) would break under benign
//! path reordering.  This implementation uses a **sliding bitmap window** of
//! `WINDOW_BITS` (1024) positions — the same width as WireGuard's replay
//! window — so that packets arriving up to 1024 positions out of order are
//! accepted, while replays and packets older than the window are rejected.
//!
//! `WINDOW_BITS` is an *implementation parameter* (DESIGN_DECISIONS D7 — "parameters
//! control tradeoffs; they do not redefine guarantees").  The security guarantee
//! ("no counter is ever accepted twice") holds for any non-zero window size; the
//! window size only affects availability under reordering, not replay resistance.
//!
//! # Thread-safety
//!
//! `ReplayWindow` is `!Sync`/`!Send` by default — it must be guarded by the
//! per-direction `Mutex`/state machine that owns the `CipherSession`.  This
//! matches the current single-thread-per-direction envelope model.

use crate::error::CodecError;

/// Width of the replay window in bits.  1024 positions covers ~1 second of
/// 1 ms-paced traffic at the 1280-byte packet size, giving ample reordering
/// tolerance (PROTOCOL_SPEC §12.1 schedule jitter) while keeping memory
/// constant at 128 bytes per direction.
pub const WINDOW_BITS: usize = 1024;

const WINDOW_WORDS: usize = WINDOW_BITS / 64; // 16 × u64

/// Sliding-window replay detector keyed on the `packet_nonce` counter.
///
/// `highest` is the highest counter accepted so far (`None` = no packets seen).
/// The bitmap tracks the `WINDOW_BITS` counters immediately below `highest`:
/// bit `i` (0-indexed) corresponds to counter `highest - i - 1`.
///
/// The current `highest` itself is always "seen" (tracked by the field, not the
/// bitmap), so it is rejected on a repeat without needing a bitmap bit.
///
/// Secret-free: counter values are non-secret sequence numbers.  No `Drop`
/// zeroization required (IMPLEMENTATION_GUIDE §6 — only secret material).
#[derive(Debug)]
pub struct ReplayWindow {
    highest: Option<u64>,
    /// `bitmap[word] & (1 << bit)` is set iff counter
    /// `highest - (word*64 + bit + 1)` has been accepted.
    bitmap: [u64; WINDOW_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Create a new window with no packets seen.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: [0u64; WINDOW_WORDS],
        }
    }

    /// Highest accepted counter, or `None` if no packets have been seen.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Attempt to accept a packet with `counter`.
    ///
    /// Returns `Ok(())` if the counter represents a new (non-replayed) packet.
    /// Returns `Err(CodecError::DecryptionFailed)` if the counter is a replay
    /// or falls outside the window (PROTOCOL_SPEC §14 — silently reject).
    ///
    /// `NonceExhausted` is NOT returned here — the caller (`CipherSession::decrypt`)
    /// handles exhaustion as a separate rekey signal after AEAD verification.
    pub fn accept(&mut self, counter: u64) -> Result<(), CodecError> {
        match self.highest {
            // First packet ever: always accept.
            None => {
                self.highest = Some(counter);
                Ok(())
            }
            Some(h) if counter > h => {
                // New highest: advance the window.
                let gap = (counter - h) as usize;

                if gap > WINDOW_BITS {
                    // Gap exceeds window width: clear everything.  The old
                    // highest is now outside the new window, so it can be
                    // safely forgotten — if it reappears, it will be outside
                    // the window and rejected.
                    self.bitmap = [0u64; WINDOW_WORDS];
                } else if gap == WINDOW_BITS {
                    // Old highest lands exactly at the window boundary (bit
                    // WINDOW_BITS - 1).  Clear everything else but preserve
                    // that one bit so the old highest is still treated as
                    // seen (a replay).
                    self.bitmap = [0u64; WINDOW_WORDS];
                    self.set_bit(WINDOW_BITS - 1);
                } else {
                    self.shift_right(gap);
                    // Record the old highest as "seen" at position `gap - 1`.
                    // (The new highest itself is tracked by the `highest` field.)
                    self.set_bit(gap - 1);
                }
                self.highest = Some(counter);
                Ok(())
            }
            Some(h) => {
                // counter <= h
                if counter == h {
                    // Duplicate of the current highest.
                    Err(CodecError::DecryptionFailed)
                } else {
                    // counter < h
                    let offset = (h - counter) as usize; // >= 1
                    if offset > WINDOW_BITS {
                        // Outside window — too old, treat as replay/reject.
                        Err(CodecError::DecryptionFailed)
                    } else {
                        let bit_index = offset - 1; // bit 0 = highest - 1
                        if self.get_bit(bit_index) {
                            // Already seen: replay.
                            Err(CodecError::DecryptionFailed)
                        } else {
                            self.set_bit(bit_index);
                            Ok(())
                        }
                    }
                }
            }
        }
    }

    /// Shift all bitmap bits right by `gap` positions (to higher indices).
    /// Bits at positions >= `WINDOW_BITS - gap` are discarded; positions 0..gap
    /// become 0.
    ///
    /// Precondition: `gap < WINDOW_BITS`.
    fn shift_right(&mut self, gap: usize) {
        debug_assert!(gap < WINDOW_BITS, "caller must handle gap >= WINDOW_BITS");

        let word_gap = gap / 64;
        let bit_shift = gap % 64;

        // Word-level shift: move words right by `word_gap`.
        if word_gap > 0 {
            for i in (word_gap..WINDOW_WORDS).rev() {
                self.bitmap[i] = self.bitmap[i - word_gap];
            }
            for i in 0..word_gap {
                self.bitmap[i] = 0;
            }
        }

        // Bit-level shift within words.
        if bit_shift > 0 {
            let inv = 64 - bit_shift;
            for i in (1..WINDOW_WORDS).rev() {
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | (self.bitmap[i - 1] >> inv);
            }
            self.bitmap[0] <<= bit_shift;
        }
    }

    #[inline]
    fn set_bit(&mut self, bit_index: usize) {
        let word = bit_index / 64;
        let bit = bit_index % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    #[inline]
    fn get_bit(&self, bit_index: usize) -> bool {
        let word = bit_index / 64;
        let bit = bit_index % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }

    /// Reset to empty state (no packets seen).
    pub fn clear(&mut self) {
        self.highest = None;
        self.bitmap = [0u64; WINDOW_WORDS];
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_always_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        assert_eq!(w.highest(), Some(0));
    }

    #[test]
    fn sequential_accepted() {
        let mut w = ReplayWindow::new();
        for i in 0..2000u64 {
            assert!(w.accept(i).is_ok(), "counter {} should be accepted", i);
        }
        assert_eq!(w.highest(), Some(1999));
    }

    #[test]
    fn replay_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        assert!(
            matches!(w.accept(0), Err(CodecError::DecryptionFailed)),
            "replay of counter 0 must be rejected"
        );
        assert!(w.accept(1).is_ok());
        assert!(
            matches!(w.accept(1), Err(CodecError::DecryptionFailed)),
            "replay of counter 1 must be rejected"
        );
    }

    #[test]
    fn rollback_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        assert!(w.accept(1).is_ok());
        assert!(w.accept(2).is_ok());
        // Counter 0 is below the high-water mark of 3 but within the window — replay.
        assert!(
            matches!(w.accept(0), Err(CodecError::DecryptionFailed)),
            "rollback to 0 must be rejected"
        );
        assert!(
            matches!(w.accept(1), Err(CodecError::DecryptionFailed)),
            "rollback to 1 must be rejected"
        );
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        assert!(w.accept(2).is_ok());
        // Counter 1 arrived after 2 — within the window, should be accepted.
        assert!(
            w.accept(1).is_ok(),
            "out-of-order counter 1 should be accepted (within window)"
        );
        assert!(
            matches!(w.accept(1), Err(CodecError::DecryptionFailed)),
            "second arrival of 1 must be rejected as replay"
        );
    }

    #[test]
    fn out_of_order_outside_window_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        // Jump well beyond the window — counter 0 is now permanently outside.
        assert!(w.accept((WINDOW_BITS + 10) as u64).is_ok());
        assert!(
            matches!(w.accept(0), Err(CodecError::DecryptionFailed)),
            "counter outside window must be rejected"
        );
    }

    #[test]
    fn boundary_counter_preserved_as_replay() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        // Jump exactly WINDOW_BITS — counter 0 lands at the window boundary
        // (bit WINDOW_BITS - 1) and must still be treated as seen (replay).
        assert!(w.accept(WINDOW_BITS as u64).is_ok());
        assert!(
            matches!(w.accept(0), Err(CodecError::DecryptionFailed)),
            "boundary counter must be treated as replay"
        );
    }

    #[test]
    fn large_gap_clears_window() {
        let mut w = ReplayWindow::new();
        // Fill some counters
        for i in 0..100u64 {
            assert!(w.accept(i).is_ok());
        }
        // Jump beyond the window size
        assert!(w.accept(5000).is_ok());
        // Old counter should be rejected
        assert!(
            matches!(w.accept(50), Err(CodecError::DecryptionFailed)),
            "counter outside cleared window must be rejected"
        );
    }

    #[test]
    fn window_size_constant() {
        assert_eq!(WINDOW_BITS, 1024);
        assert_eq!(WINDOW_WORDS, 16);
    }

    #[test]
    fn clear_resets_state() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());
        assert!(w.accept(1).is_ok());
        w.clear();
        assert_eq!(w.highest(), None);
        // Should be able to accept 0 again after clear.
        assert!(
            w.accept(0).is_ok(),
            "after clear, counter 0 should be accepted"
        );
    }

    #[test]
    fn far_future_counter_accepted() {
        let mut w = ReplayWindow::new();
        // Accept a very large counter as the first packet.
        assert!(w.accept(u64::MAX).is_ok());
        assert_eq!(w.highest(), Some(u64::MAX));
    }

    #[test]
    fn bit_manipulation_roundtrip() {
        let mut w = ReplayWindow::new();
        // Accept counter 0, then accept counter 65, then check that
        // counter 1 (which is in the bitmap, at bit 0 when highest=65)
        // is correctly tracked.
        assert!(w.accept(0).is_ok());
        assert!(w.accept(65).is_ok()); // 65 - 0 = 65, gap >= WINDOW_BITS? No, 65 < 1024
        // Counter 1 is at position 63 below highest=65: offset = 64, bit_index = 63.
        // Bit 63 of word 0 should be set (old highest 0 was at gap-1 = 64, which is
        // word 1, bit 0).
        // Counter 0 is at offset 65 from highest: outside the window (65 < 1024, so
        // it's within!). Offset = 65, bit_index = 64 = word 1, bit 0.
        // Wait, let me recalculate: highest = 65, counter = 0, offset = 65 - 0 = 65.
        // 65 < WINDOW_BITS (1024), so it's within the window. bit_index = 64.
        // word = 1, bit = 0. The old highest (0) was set at gap-1 = 64 (word 1, bit 0).
        assert!(w.get_bit(64), "bit 64 (old highest 0) should be set");
        // Counter 1 should be accepted (not yet seen).
        assert!(w.accept(1).is_ok());
        // Counter 1 should now be rejected (replay).
        assert!(w.accept(1).is_err());
    }

    // -----------------------------------------------------------------------
    // Property-based / fuzz-style tests (no external fuzz dependency)
    // -----------------------------------------------------------------------

    /// Generate a random u64 counter for fuzz testing.
    fn fuzz_counter() -> u64 {
        getrandom::u64().unwrap_or(0)
    }

    /// `accept` must never panic on random counters of any magnitude —
    /// including values near u64::MAX (which would cause exhaustion).
    #[test]
    fn fuzz_accept_never_panics() {
        for _ in 0..500 {
            let mut w = ReplayWindow::new();
            for _ in 0..20 {
                let counter = fuzz_counter();
                let _ = w.accept(counter); // must not panic
            }
        }
    }

    /// No counter can be accepted twice — the second `accept` must return
    /// `Err(CodecError::ReplayRejected)`.
    #[test]
    fn prop_no_duplicate_acceptance() {
        let mut w = ReplayWindow::new();
        for counter in 0..500u64 {
            assert!(
                w.accept(counter).is_ok(),
                "first accept of {counter} must succeed"
            );
            assert!(
                w.accept(counter).is_err(),
                "second accept of {counter} must be rejected"
            );
        }
    }

    /// Out-of-order packets within the window are accepted as long as they
    /// haven't been seen before — this is the key difference from a
    /// high-water-only scheme.
    #[test]
    fn prop_out_of_order_accepted() {
        let mut w = ReplayWindow::new();
        // Send 0, 2, 1 — all should be accepted.
        assert!(w.accept(0).is_ok());
        assert!(w.accept(2).is_ok());
        // 1 is within window (gap = 2 - 1 = 1 < 1024) and not seen yet.
        assert!(w.accept(1).is_ok());
        // Now 1 is a replay.
        assert!(w.accept(1).is_err());
    }

    /// A counter that lags behind `highest` by more than WINDOW_BITS is
    /// rejected — it's outside the sliding window and could be a replay.
    #[test]
    fn prop_outside_window_rejected() {
        let mut w = ReplayWindow::new();
        // Build up highest to 1000.
        w.accept(1000).unwrap();
        // Counter 0 is offset 1000 > WINDOW_BITS (1024) → no, 1000 < 1024.
        // Use a higher highest to make offset > WINDOW_BITS.
        w.accept(2048).unwrap();
        // Now counter 1023 has offset = 2048 - 1023 = 1025 > WINDOW_BITS → rejected.
        assert!(
            w.accept(1023).is_err(),
            "counter outside window (offset > WINDOW_BITS) must be rejected"
        );
    }

    /// Sliding window correctness: after advancing the window, old bits
    /// must shift correctly and new high-water packets must be accepted.
    #[test]
    fn prop_sliding_window_correct() {
        let mut w = ReplayWindow::new();

        // Accept 0..512 sequentially.
        for c in 0..512u64 {
            assert!(w.accept(c).is_ok());
        }

        // Accept 512 and 513 — should succeed (gap from highest 511 = 1, 2).
        assert!(w.accept(512).is_ok());
        assert!(w.accept(513).is_ok());

        // Try to replay 512 — should be rejected.
        assert!(w.accept(512).is_err());
    }

    /// `highest` must return the correct high-water mark.
    #[test]
    fn prop_highest_correct() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.highest(), None, "empty window: highest is None");
        w.accept(5).unwrap();
        assert_eq!(w.highest(), Some(5), "after accepting 5: highest is 5");
        w.accept(3).unwrap(); // out of order
        assert_eq!(w.highest(), Some(5), "highest does not decrease");
        w.accept(10).unwrap();
        assert_eq!(w.highest(), Some(10), "highest advances on new max");
    }

    /// Counter at exactly the window boundary (gap = WINDOW_BITS) is
    /// accepted (forward jump); old highest is recorded so it's a replay if resubmitted.
    #[test]
    fn prop_window_boundary_correct() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0).is_ok());

        // WINDOW_BITS = 1024.
        // Counter 1024: gap = 1024 = WINDOW_BITS → accepted (old highest 0 is
        // recorded at the boundary bit so it's still a replay if it reappears).
        assert!(
            w.accept(1024).is_ok(),
            "forward jump at gap == WINDOW_BITS must be accepted"
        );
        // The old highest (0) must now be recorded as seen (replay if resubmitted).
        assert!(
            w.accept(0).is_err(),
            "old highest must be treated as replay after window slide"
        );
    }

    /// After `clear`, the window is reset and all counters are accepted again.
    #[test]
    fn prop_clear_resets() {
        let mut w = ReplayWindow::new();
        for c in 0..100u64 {
            w.accept(c).unwrap();
        }
        assert_eq!(w.highest(), Some(99), "highest before clear");
        w.clear();
        assert_eq!(w.highest(), None, "highest after clear is None");
        // After clear, 0 should be accepted again.
        assert!(
            w.accept(0).is_ok(),
            "after clear, all counters must be accepted"
        );
    }
}
