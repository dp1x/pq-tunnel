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
}
