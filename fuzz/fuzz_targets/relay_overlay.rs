#![no_main]

//! Fuzz target: application-layer relay overlay (D18) + slot packet length.
//!
//! The relay header family/address/port/len lives inside the encrypted
//! fixed-size payload slot; the overlay codec (`relay.rs`) and the slot
//! length parser (`packet_len.rs`) must be strict and panic-free.
//!
//! Hard invariants (contract of `pq-tunnel-bin`):
//! * `decode_relay` never panics on any byte input;
//! * on success the datagram is an exact slice of the input, its length
//!   equals the declared `len` field, and it fits the family's slot capacity;
//! * canonical re-encode re-decodes to the same destination and datagram;
//! * `encode_relay` mirrors `TooLarge` exactly at the family capacity edge;
//! * `ip_packet_len` never panics, and any positive return is ≤ the input
//!   length and consistent with the version's length fields.
//! Every falsification is a real panic.

use libfuzzer_sys::fuzz_target;
use pq_tunnel_lib::packet_len::ip_packet_len;
use pq_tunnel_lib::relay::{
    FAMILY_IPV4, FAMILY_IPV6, HDR_LEN_V4, HDR_LEN_V6, MAX_DATAGRAM_V4, MAX_DATAGRAM_V6, RelayError,
    decode_relay, encode_relay,
};
use std::net::SocketAddr;

fuzz_target!(|data: &[u8]| {
    // -- decode: panic-free, and round-trip for canonical frames --------------
    if let Ok((dest, datagram)) = decode_relay(data) {
        let hdr = match dest {
            SocketAddr::V4(_) => HDR_LEN_V4,
            SocketAddr::V6(_) => HDR_LEN_V6,
        };
        // The declared length field must equal the surfaced datagram length.
        let declared = u16::from_be_bytes([data[hdr - 2], data[hdr - 1]]) as usize;
        assert_eq!(declared, datagram.len(), "declared len must match slice");
        assert!(datagram.len() <= data.len() - hdr, "slice must fit input");
        let max = match dest {
            SocketAddr::V4(_) => MAX_DATAGRAM_V4,
            SocketAddr::V6(_) => MAX_DATAGRAM_V6,
        };
        assert!(datagram.len() <= max, "decoded datagram must fit the slot");
        // Canonical re-encode round-trips exactly.
        let frame = encode_relay(dest, datagram).expect("canonical re-encode fits");
        assert_eq!(frame.len(), hdr + datagram.len());
        let (dest2, datagram2) = decode_relay(&frame).expect("canonical frame decodes");
        assert_eq!(dest2, dest);
        assert_eq!(datagram2, datagram);
    }

    // -- encode boundary: TooLarge exactly at max+1 for each family -----------
    let v4: SocketAddr = "192.0.2.1:1".parse().expect("static addr");
    let v6: SocketAddr = "[2001:db8::1]:1".parse().expect("static addr");
    for (addr, max) in [(v4, MAX_DATAGRAM_V4), (v6, MAX_DATAGRAM_V6)] {
        let n = data.len().min(max + 1);
        match encode_relay(addr, &data[..n]) {
            Ok(frame) => {
                assert!(n <= max, "TooLarge must fire at max+1");
                let (dest, payload) = decode_relay(&frame).expect("own frame decodes");
                assert_eq!(dest, addr);
                assert_eq!(payload, &data[..n]);
            }
            Err(RelayError::TooLarge { max: m, got }) => {
                assert!(n > m, "TooLarge only beyond capacity");
                assert_eq!(got, n);
            }
            Err(other) => panic!("unexpected encode error: {other:?}"),
        }
    }
    // Header-only edge: a frame claiming len == max must be accepted whole.
    if let Ok((dest, datagram)) = decode_relay(data) {
        let _ = encode_relay(dest, datagram).is_ok(); // always true (checked above)
    }

    // -- ip_packet_len over arbitrary slots ------------------------------------
    let len = ip_packet_len(data);
    if len > 0 {
        assert!(len <= data.len(), "reported length cannot exceed the slot");
        let version = data[0] >> 4;
        if version == 4 {
            let total = u16::from_be_bytes([data[2], data[3]]) as usize;
            assert_eq!(total, len, "IPv4 total-length field must agree");
            assert!(len >= 20, "IPv4 header is at least 20 bytes");
        } else {
            assert!(version == 6, "only v4/v6 may report a length");
            let plen = u16::from_be_bytes([data[4], data[5]]) as usize;
            assert_eq!(len, 40 + plen, "IPv6 length = 40 + payload-length");
        }
    }

    // -- family-tag statics -----------------------------------------------------
    assert!(FAMILY_IPV4 != FAMILY_IPV6);
    assert!(HDR_LEN_V4 < HDR_LEN_V6);
});
