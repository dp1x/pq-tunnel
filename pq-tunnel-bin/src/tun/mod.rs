//! System-wide TUN data plane (D33) — client and server drivers.
//!
//! This module wires the portable OS TUN device to the authenticated session
//! manager using the overlay codec in `pq_tunnel_core::dataplane`. It is the
//! implementation of Wave 4 tracks B (client) and C (server).
//!
//! Platform-specific device creation and address/route/DNS/firewall setup live
//! in [`crate::os_net`]; this module only depends on the portable
//! [`TunDevice`] trait and the overlay helpers.

use pq_tunnel_core::dataplane::validate_ip_packet;

pub mod client;
pub mod device;
pub mod os_net;
pub mod server;

/// Portable TUN device handle.
pub trait TunDevice: Send {
    fn read_packet(&mut self) -> std::io::Result<Vec<u8>>;
    fn write_packet(&mut self, pkt: &[u8]) -> std::io::Result<usize>;
    fn mtu(&self) -> u16;
    fn close(&mut self);
}

/// Inner MTU mandated by D33 (RFC 8200 §5 floor).
pub const INNER_MTU: u16 = 1280;
/// Reassembly deadline (D33 §4.3).
pub const REASSEMBLY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// Client-assigned inner addresses (D33 §3.4).
pub const CLIENT_V4: (std::net::Ipv4Addr, u8) = (std::net::Ipv4Addr::new(10, 77, 0, 2), 32);
pub const CLIENT_V6: &str = "fd00:77::2";
pub const SERVER_V4: (std::net::Ipv4Addr, u8) = (std::net::Ipv4Addr::new(10, 77, 0, 1), 32);
pub const SERVER_V6: &str = "fd00:77::1";

/// Drop link-local / NDP packets at the tunnel boundary (D33 §2.8.1).
pub fn is_boundary_dropped(pkt: &[u8]) -> bool {
    if pkt.is_empty() {
        return true;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return true;
            }
            let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            if src.is_link_local() || dst.is_link_local() {
                return true;
            }
            // IPv4 multicast / broadcast
            if src.is_multicast() || dst.is_multicast() || dst == std::net::Ipv4Addr::BROADCAST {
                return true;
            }
            false
        }
        6 => {
            if pkt.len() < 40 {
                return true;
            }
            let mut sb = [0u8; 16];
            sb.copy_from_slice(&pkt[8..24]);
            let mut db = [0u8; 16];
            db.copy_from_slice(&pkt[24..40]);
            let src = std::net::Ipv6Addr::from(sb);
            let dst = std::net::Ipv6Addr::from(db);
            // link-local fe80::/10
            if (sb[0] == 0xfe && (sb[1] & 0xc0) == 0x80)
                || (db[0] == 0xfe && (db[1] & 0xc0) == 0x80)
            {
                return true;
            }
            // NDP message types (ICMPv6 type in next header chain; check first next-header = 58 and type)
            // Drop ICMPv6 NDP types 133-137, 143-147 at the boundary.
            let nh = pkt[6];
            if nh == 58 && pkt.len() >= 41 {
                let icmp_type = pkt[40];
                if (133..=137).contains(&icmp_type) || (143..=147).contains(&icmp_type) {
                    return true;
                }
            }
            if src.is_multicast() || dst.is_multicast() {
                return true;
            }
            let _ = (src, dst);
            false
        }
        _ => true,
    }
}

/// Validate inner IP packet length consistency (sender side).
pub fn validate_inner(pkt: &[u8]) -> bool {
    validate_ip_packet(pkt).is_ok()
}
