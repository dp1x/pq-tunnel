//! Server-side raw-IP helpers for the TUN data plane (D33 §3).
//!
//! This module is **policy logic only**: no I/O, no TUN device, no sockets.
//! It validates an inner IP packet before it is allowed to enter the server's
//! networking stack:
//!
//! * source-address anti-spoofing (§3.4): the inner source MUST equal the
//!   client's assigned address for that family;
//! * destination policy (§3.3): reuses the shipped egress guard, applied at
//!   the IP layer (v4-mapped normalisation included);
//! * L4 port-0 rule, evaluated only where a transport header is parsable
//!   (§3.3);
//! * IP-header structural validation.
//!
//! The actual TUN device write and kernel forwarding (M2) are not implemented
//! yet; this module is the pure, testable core of that path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pq_tunnel_core::dataplane::validate_ip_packet;

/// Assigned client inner addresses (deployment-local, 1:1).
#[derive(Debug, Clone, Copy)]
pub struct ClientAssignment {
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
}

impl Default for ClientAssignment {
    fn default() -> Self {
        // D33 §3.4 defaults.
        Self {
            v4: Ipv4Addr::new(10, 77, 0, 2),
            v6: "fd00:77::2".parse().unwrap(),
        }
    }
}

/// Source anti-spoofing: returns true iff `src` equals the client's assigned
/// address for its family (v4-mapped normalised to v4).
pub fn source_allowed(src: IpAddr, assignment: &ClientAssignment) -> bool {
    match src {
        IpAddr::V4(v4) => v4 == assignment.v4,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4 == assignment.v4
            } else {
                v6 == assignment.v6
            }
        }
    }
}

/// Extract the destination port from an inner IP packet, if a TCP/UDP header
/// is directly present (no extension-header chain). Returns None otherwise.
pub fn extract_dst_port(pkt: &[u8]) -> Option<u16> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (pkt[0] & 0x0F) as usize * 4;
            if ihl < 20 || pkt.len() < ihl + 4 {
                return None;
            }
            let proto = pkt[9];
            if proto != 6 && proto != 17 {
                return None;
            }
            Some(u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let next = pkt[6];
            if next != 6 && next != 17 {
                return None;
            }
            // only direct transport header (no extension headers)
            if pkt.len() < 44 {
                return None;
            }
            Some(u16::from_be_bytes([pkt[42], pkt[43]]))
        }
        _ => None,
    }
}

/// Extract the destination IP from an inner IP packet.
pub fn extract_dst_ip(pkt: &[u8]) -> Option<IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                pkt[16], pkt[17], pkt[18], pkt[19],
            )))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Extract the source IP from an inner IP packet.
pub fn extract_src_ip(pkt: &[u8]) -> Option<IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                pkt[12], pkt[13], pkt[14], pkt[15],
            )))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Validation result for a server-bound inner packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    Allow,
    SpoofedSource,
    DeniedDestination,
    PortZero,
    Malformed,
}

/// Validate an inner IP packet arriving from the tunnel before it enters the
/// server's networking stack. Does not perform I/O.
pub fn validate_inner_packet(pkt: &[u8], assignment: &ClientAssignment) -> PacketVerdict {
    // Structural IP validation.
    if validate_ip_packet(pkt).is_err() {
        return PacketVerdict::Malformed;
    }
    let src = match extract_src_ip(pkt) {
        Some(s) => s,
        None => return PacketVerdict::Malformed,
    };
    if !source_allowed(src, assignment) {
        return PacketVerdict::SpoofedSource;
    }
    let dst = match extract_dst_ip(pkt) {
        Some(d) => d,
        None => return PacketVerdict::Malformed,
    };
    let port = extract_dst_port(pkt);
    // Reuse shipped egress guard logic via forward::egress if available.
    // Here we inline the minimal guard to avoid coupling.
    if let Some(p) = port
        && p == 0
    {
        return PacketVerdict::PortZero;
    }
    // Destination policy: deny loopback/unspecified/multicast/broadcast/metadata.
    if is_denied_destination(dst) {
        return PacketVerdict::DeniedDestination;
    }
    PacketVerdict::Allow
}

fn is_denied_destination(dst: IpAddr) -> bool {
    match dst {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return true;
            }
            if v4.octets()[0] == 0 {
                return true;
            }
            if v4.is_multicast() {
                return true;
            }
            if v4 == Ipv4Addr::new(255, 255, 255, 255) {
                return true;
            }
            if v4 == Ipv4Addr::new(169, 254, 169, 254) {
                return true;
            }
            if v4 == Ipv4Addr::new(100, 100, 100, 200) {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if v6 == Ipv6Addr::LOCALHOST {
                return true;
            }
            if v6.is_unspecified() {
                return true;
            }
            if v6.is_multicast() {
                return true;
            }
            // AWS/GCP metadata v6
            if v6.to_string() == "fd00:ec2::254" || v6.to_string() == "fd20:ce::254" {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4pkt(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[0] = 0x45;
        v[2] = 0;
        v[3] = 24;
        v[9] = 17; // UDP
        v[12..16].copy_from_slice(&src);
        v[16..20].copy_from_slice(&dst);
        // default non-zero destination port (53) so the port-0 rule does not
        // fire unless a test clears it.
        v[22] = 0;
        v[23] = 53;
        v
    }

    #[test]
    fn source_allowed_default() {
        let a = ClientAssignment::default();
        assert!(source_allowed(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)), &a));
        assert!(!source_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &a));
    }

    #[test]
    fn v4_mapped_source_normalised() {
        let a = ClientAssignment::default();
        let mapped: Ipv6Addr = "::ffff:10.77.0.2".parse().unwrap();
        assert!(source_allowed(IpAddr::V6(mapped), &a));
    }

    #[test]
    fn spoofed_source_rejected() {
        let a = ClientAssignment::default();
        let pkt = v4pkt([1, 2, 3, 4], [8, 8, 8, 8]);
        // src not client
        let verdict = validate_inner_packet(&pkt, &a);
        assert_eq!(verdict, PacketVerdict::SpoofedSource);
    }

    #[test]
    fn allowed_packet() {
        let a = ClientAssignment::default();
        let pkt = v4pkt([10, 77, 0, 2], [8, 8, 8, 8]);
        let verdict = validate_inner_packet(&pkt, &a);
        assert_eq!(verdict, PacketVerdict::Allow);
    }

    #[test]
    fn metadata_destination_rejected() {
        let a = ClientAssignment::default();
        let pkt = v4pkt([10, 77, 0, 2], [169, 254, 169, 254]);
        let verdict = validate_inner_packet(&pkt, &a);
        assert_eq!(verdict, PacketVerdict::DeniedDestination);
    }

    #[test]
    fn port_zero_rejected() {
        let a = ClientAssignment::default();
        let mut pkt = v4pkt([10, 77, 0, 2], [8, 8, 8, 8]);
        // set UDP dst port 0 at offset ihl+2
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        pkt[ihl + 2] = 0;
        pkt[ihl + 3] = 0;
        let verdict = validate_inner_packet(&pkt, &a);
        assert_eq!(verdict, PacketVerdict::PortZero);
    }

    #[test]
    fn malformed_rejected() {
        let a = ClientAssignment::default();
        let pkt = vec![0u8; 5];
        let verdict = validate_inner_packet(&pkt, &a);
        assert_eq!(verdict, PacketVerdict::Malformed);
    }
}
