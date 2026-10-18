//! Shared wire-slot utilities for the v2 (datagram-plane) drivers.
//!
//! The data plane carries fixed-size zero-padded payload slots (`PAYLOAD_LEN`
//! bytes each); the slot itself carries no length.  Every consumer — the
//! client's slot → TUN write, the server's echo slot → slot relay — must
//! recover the real IP packet length from the packet's own header.

/// Recover the real IP packet length from a zero-padded payload slot.
///
/// Returns the packet's length in bytes, or `0` when the buffer does not start
/// with a plausible IP packet (version 4/6, sane length within the slot) — the
/// caller drops in that case (fail-safe; never write garbage to a tun).
pub fn ip_packet_len(payload: &[u8]) -> usize {
    if payload.len() < 20 {
        return 0;
    }
    match payload[0] >> 4 {
        // IPv4: total-length field (bytes 2..4, big-endian); includes the header.
        4 => {
            let total = u16::from_be_bytes([payload[2], payload[3]]) as usize;
            if total < 20 || total > payload.len() {
                0
            } else {
                total
            }
        }
        // IPv6: payload-length field (bytes 4..6, big-endian) + 40-byte header.
        6 => {
            let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            let total = 40usize.saturating_add(payload_len);
            if total < 40 || total > payload.len() {
                0
            } else {
                total
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_tunnel_core::PAYLOAD_LEN;

    #[test]
    fn ipv4_length_from_zero_padded_slot() {
        let mut slot = [0u8; PAYLOAD_LEN];
        // Version 4, IHL 5 (20-byte header), total length 40 (bytes 2..3).
        slot[0] = 0x45;
        slot[2] = 0x00;
        slot[3] = 0x28;
        assert_eq!(ip_packet_len(&slot), 40);
    }

    #[test]
    fn ipv6_length_from_zero_padded_slot() {
        let mut slot = [0u8; PAYLOAD_LEN];
        // Version 6, payload length 64 (bytes 4..5) → 40 + 64 = 104.
        slot[0] = 0x60;
        slot[4] = 0x00;
        slot[5] = 0x40;
        assert_eq!(ip_packet_len(&slot), 104);
    }

    #[test]
    fn non_ip_garbage_dropped() {
        let slot = [0u8; PAYLOAD_LEN];
        assert_eq!(ip_packet_len(&slot), 0, "version 0 must fail");
        let mut v9 = [0u8; PAYLOAD_LEN];
        v9[0] = 0x90;
        assert_eq!(ip_packet_len(&v9), 0, "version 9 must fail");
    }

    #[test]
    fn malformed_lengths_dropped() {
        // IPv4 total length smaller than the header → invalid.
        let mut small = [0u8; PAYLOAD_LEN];
        small[0] = 0x45;
        assert_eq!(ip_packet_len(&small), 0, "total < 20 must fail");

        // IPv4 total length exceeding the slot → invalid (can't write what
        // we don't have).
        let mut over = [0u8; PAYLOAD_LEN];
        over[0] = 0x45;
        over[2] = 0xFF;
        over[3] = 0xFF;
        assert_eq!(ip_packet_len(&over), 0, "total > slot must fail");
    }

    // -----------------------------------------------------------------------
    // Boundary / robustness audit (Item 4)
    // -----------------------------------------------------------------------
    //
    // Self-consistency/regression tests, NOT external anchors.

    /// The exact lower edge: an IPv4 packet whose total length equals the
    /// minimum (20, a bare header) must be accepted; 19 must be rejected.
    #[test]
    fn ipv4_minimum_length_boundary() {
        let mut slot = [0u8; PAYLOAD_LEN];
        slot[0] = 0x45;
        slot[2] = 0x00;
        slot[3] = 20;
        assert_eq!(ip_packet_len(&slot), 20, "a 20-byte IPv4 header is valid");

        let mut short = slot;
        short[3] = 19;
        assert_eq!(ip_packet_len(&short), 0, "total 19 must be rejected");
    }

    /// The exact upper edge: total length equal to the slot must be accepted;
    /// one more must be rejected. This is the off-by-one that matters most, since
    /// the slot is zero-padded and the field is attacker-supplied on the far
    /// side of the tunnel.
    #[test]
    fn ipv4_slot_length_boundary() {
        let mut slot = vec![0u8; PAYLOAD_LEN];
        slot[0] = 0x45;
        let total = (PAYLOAD_LEN as u16).to_be_bytes();
        slot[2] = total[0];
        slot[3] = total[1];
        assert_eq!(ip_packet_len(&slot), PAYLOAD_LEN, "a full slot is valid");

        let over = PAYLOAD_LEN + 1;
        if over <= u16::MAX as usize {
            let total = (over as u16).to_be_bytes();
            slot[2] = total[0];
            slot[3] = total[1];
            assert_eq!(
                ip_packet_len(&slot),
                0,
                "one byte past the slot must be rejected, not truncated"
            );
        }
    }

    /// IPv6 minimum: a 40-byte header with a zero payload length is valid.
    #[test]
    fn ipv6_minimum_length_boundary() {
        let mut slot = [0u8; PAYLOAD_LEN];
        slot[0] = 0x60;
        // payload length field stays zero -> total 40.
        assert_eq!(
            ip_packet_len(&slot),
            40,
            "a bare 40-byte IPv6 header is valid"
        );
    }

    /// IPv6 slot boundary: 40 + payload_len == PAYLOAD_LEN is the last valid
    /// value; one more must be rejected.
    #[test]
    fn ipv6_slot_length_boundary() {
        let mut slot = vec![0u8; PAYLOAD_LEN];
        slot[0] = 0x60;
        let payload_len = PAYLOAD_LEN - 40;
        let f = (payload_len as u16).to_be_bytes();
        slot[4] = f[0];
        slot[5] = f[1];
        assert_eq!(
            ip_packet_len(&slot),
            PAYLOAD_LEN,
            "a full-slot IPv6 is valid"
        );

        slot[5] = f[1].wrapping_add(1);
        assert_eq!(
            ip_packet_len(&slot),
            0,
            "one byte past the slot must be rejected"
        );
    }

    /// Robustness finding (Item 4): the version nibble is read from byte 0,
    /// but the function only guards `len >= 20` — an IPv4 minimum. An IPv6
    /// header is 40 bytes, and bytes 4..6 (the IPv6 payload-length field) are
    /// therefore read from a buffer that may be shorter than an IPv6 header.
    ///
    /// The read is in bounds (20 >= 6) so there is no panic and no memory-safety
    /// issue; but a 20..=39-byte buffer whose first nibble is 6 yields a length
    /// computed from bytes that are not an IPv6 payload-length field at all.
    /// Those bytes are attacker-controlled (the relay forwards an arbitrary
    /// framed datagram), so the function can return a length derived from
    /// garbage.
    ///
    /// This is a robustness/correctness defect, not a memory-safety one, and it
    /// is *fail-safe in the direction that matters*: `total > payload.len()`
    /// still rejects, so nothing longer than the buffer is ever reported. The
    /// test documents the current behaviour so the day someone adds a
    /// version-dependent minimum-length check, this pins what changed.
    #[test]
    fn ipv6_branch_reads_a_short_buffer_without_panicking() {
        for len in 20..40usize {
            let mut slot = vec![0u8; len];
            slot[0] = 0x60;
            // Claim a payload length that would exceed the short buffer.
            slot[4] = 0xFF;
            slot[5] = 0xFF;
            let got = ip_packet_len(&slot);
            assert!(
                got == 0 || got <= len,
                "a {len}-byte buffer must never report a length beyond itself (got {got})"
            );
            // In practice an oversized claim is rejected outright.
            assert_eq!(got, 0, "an over-long claim in a short buffer is rejected");
        }
    }

    /// Any buffer shorter than 20 bytes must be rejected outright, including at
    /// len-1 and len boundaries.
    #[test]
    fn sub_minimum_lengths_are_rejected() {
        for len in 0..20usize {
            // Both version nibbles that would otherwise enter a branch.
            for version in [0x4u8, 0x6] {
                let mut slot = vec![0u8; len];
                if len > 0 {
                    slot[0] = version << 4;
                }
                assert_eq!(
                    ip_packet_len(&slot),
                    0,
                    "{len} bytes with version {version} must be rejected"
                );
            }
        }
        assert_eq!(ip_packet_len(&[0u8; PAYLOAD_LEN][..19]), 0);
        assert_eq!(ip_packet_len(&[]), 0, "the empty slice must be rejected");
    }

    /// Every length in the whole slot range must be handled without a panic,
    /// for every version nibble that enters a branch.
    #[test]
    fn never_panics_across_lengths_and_versions() {
        for len in 0..=(PAYLOAD_LEN + 8) {
            for version in [0u8, 4, 6, 0xF] {
                let mut slot = vec![0x5Au8; len];
                if len > 0 {
                    slot[0] = version << 4;
                }
                let got = ip_packet_len(&slot);
                assert!(
                    got == 0 || (got <= len && got >= 20),
                    "len={len} version={version} produced {got}"
                );
            }
        }
    }
}
