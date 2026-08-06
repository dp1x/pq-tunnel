//! Client-side UDP relay and the shared relay-message framing (D18).
//!
//! The relay message format is an **application-layer** framing that lives
//! *inside* the encrypted, fixed-size tunnel slot (`PAYLOAD_LEN` bytes) — it
//! never appears on the wire:
//!
//! ```text
//! family(1) ‖ address(4|16) ‖ port(2) ‖ len(2) ‖ datagram(len)
//! ```
//!
//! * `family`: `0x04` IPv4 (9-byte header) / `0x06` IPv6 (21-byte header).
//! * `len` is the datagram length: the slot is zero-padded by the session
//!   layer, and UDP datagrams may legitimately contain trailing zero bytes,
//!   so the length is explicit, never inferred from padding.
//!
//! The client relay binds one application-facing UDP socket and acts as a
//! destination NAT: applications send relay-framed datagrams to it (the
//! destination lives in the header), the client records
//! `destination → app endpoint` and feeds the framed message into the tunnel;
//! replies arrive back through the tunnel framed with the same destination
//! and are returned to the last app endpoint that spoke to that destination
//! (last-writer-wins — a documented D18 tradeoff).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pq_tunnel_core::{ManagerNotification, PAYLOAD_LEN};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

/// Relay message family tag for IPv4.
pub const FAMILY_IPV4: u8 = 0x04;
/// Relay message family tag for IPv6.
pub const FAMILY_IPV6: u8 = 0x06;

/// Relay header length for IPv4: family(1) + addr(4) + port(2) + len(2).
pub const HDR_LEN_V4: usize = 9;
/// Relay header length for IPv6: family(1) + addr(16) + port(2) + len(2).
pub const HDR_LEN_V6: usize = 21;

/// Maximum relayed UDP datagram size (IPv4): one payload slot minus header.
pub const MAX_DATAGRAM_V4: usize = PAYLOAD_LEN - HDR_LEN_V4;
/// Maximum relayed UDP datagram size (IPv6): one payload slot minus header.
pub const MAX_DATAGRAM_V6: usize = PAYLOAD_LEN - HDR_LEN_V6;

/// Idle lifetime of a recorded `(destination → app endpoint)` binding.
const MAP_TTL: Duration = Duration::from_secs(60);
/// Maximum number of recorded bindings (bounded; oldest evicted).
const MAP_MAX: usize = 256;

/// A recorded `destination → local app endpoint` binding with its last use.
type Bindings = HashMap<SocketAddr, (SocketAddr, Instant)>;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay message truncated at {0} bytes")]
    Truncated(usize),
    #[error("unknown relay family tag {0:#04x}")]
    BadFamily(u8),
    #[error("datagram too large: {got} bytes (max {max})")]
    TooLarge { max: usize, got: usize },
}

/// Encode a relay message: destination header + datagram payload.
///
/// Fails if `payload` exceeds the per-family slot capacity.
pub fn encode_relay(dest: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, RelayError> {
    let (family, addr_bytes, max) = match dest {
        SocketAddr::V4(a) => (FAMILY_IPV4, a.ip().octets().to_vec(), MAX_DATAGRAM_V4),
        SocketAddr::V6(a) => (FAMILY_IPV6, a.ip().octets().to_vec(), MAX_DATAGRAM_V6),
    };
    if payload.len() > max {
        return Err(RelayError::TooLarge {
            max,
            got: payload.len(),
        });
    }

    let mut out = Vec::with_capacity(HDR_LEN_V6 + payload.len());
    out.push(family);
    out.extend_from_slice(&addr_bytes);
    out.extend_from_slice(&dest.port().to_be_bytes());
    let len = u16::try_from(payload.len()).expect("payload fits in u16 by construction");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Strictly decode a relay message into the destination and the datagram.
///
/// Returns an error for an unknown family, a truncated header, or a declared
/// length past the end of the buffer. Bytes after the declared datagram (slot
/// padding) are ignored.
pub fn decode_relay(msg: &[u8]) -> Result<(SocketAddr, &[u8]), RelayError> {
    let family = *msg.first().ok_or(RelayError::Truncated(0))?;
    let (addr, hdr_len) = match family {
        FAMILY_IPV4 => {
            if msg.len() < HDR_LEN_V4 {
                return Err(RelayError::Truncated(msg.len()));
            }
            let octets = [msg[1], msg[2], msg[3], msg[4]];
            let port = u16::from_be_bytes([msg[5], msg[6]]);
            (SocketAddr::from((octets, port)), HDR_LEN_V4)
        }
        FAMILY_IPV6 => {
            if msg.len() < HDR_LEN_V6 {
                return Err(RelayError::Truncated(msg.len()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[1..17]);
            let port = u16::from_be_bytes([msg[17], msg[18]]);
            (
                SocketAddr::from((std::net::Ipv6Addr::from(octets), port)),
                HDR_LEN_V6,
            )
        }
        other => return Err(RelayError::BadFamily(other)),
    };

    let len = u16::from_be_bytes([msg[hdr_len - 2], msg[hdr_len - 1]]) as usize;
    if msg.len() < hdr_len + len {
        return Err(RelayError::Truncated(msg.len()));
    }
    Ok((addr, &msg[hdr_len..hdr_len + len]))
}

/// Run the client relay end-to-end: the app→tunnel task (records bindings,
/// forwards framed datagrams into the tunnel) and the tunnel→app task
/// (routes framed replies back to the right app endpoint).
///
/// Returns when `app_rx` closes (the tunnel session layer is down).
pub async fn run(
    socket: UdpSocket,
    data_tx: mpsc::Sender<Vec<u8>>,
    app_rx: mpsc::Receiver<ManagerNotification>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = Arc::new(socket);
    let bindings = Arc::new(Mutex::new(Bindings::new()));

    let s1 = socket.clone();
    let b1 = bindings.clone();
    let app_to_tunnel = tokio::spawn(async move {
        app_to_tunnel_loop(s1, b1, data_tx).await;
    });

    let s2 = socket.clone();
    let b2 = bindings.clone();
    let tunnel_to_app = tokio::spawn(async move {
        tunnel_to_app_loop(s2, b2, app_rx).await;
    });

    let (a, b) = tokio::join!(app_to_tunnel, tunnel_to_app);
    if let Err(join) = a {
        return Err(format!("relay app→tunnel task panicked: {join}").into());
    }
    if let Err(join) = b {
        return Err(format!("relay tunnel→app task panicked: {join}").into());
    }
    Ok(())
}

/// App socket → tunnel: relay-framed datagrams from any app endpoint are
/// validated, recorded (`destination → source`), and passed to the manager.
async fn app_to_tunnel_loop(
    socket: Arc<UdpSocket>,
    bindings: Arc<Mutex<Bindings>>,
    data_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; PAYLOAD_LEN];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                match decode_relay(&buf[..n]) {
                    Ok((dest, _)) => {
                        let now = Instant::now();
                        {
                            let mut b = bindings.lock().await;
                            b.insert(dest, (src, now));
                            prune_bindings(&mut b, now);
                        }
                    }
                    Err(e) => {
                        warn!("dropping malformed relay datagram from {src}: {e}");
                        continue;
                    }
                }
                if data_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!("relay socket error: {e}");
                break;
            }
        }
    }
}

/// Tunnel → app: framed replies are routed to the last app endpoint that
/// spoke to the reply's destination (the remote server's bound source matches
/// the destination header it labels replies with).
async fn tunnel_to_app_loop(
    socket: Arc<UdpSocket>,
    bindings: Arc<Mutex<Bindings>>,
    mut app_rx: mpsc::Receiver<ManagerNotification>,
) {
    loop {
        match app_rx.recv().await {
            None => break,
            Some(ManagerNotification::Data { inner, .. }) => {
                match decode_relay(&inner.payload) {
                    Ok((dest, datagram)) => {
                        let src = {
                            let mut b = bindings.lock().await;
                            prune_bindings(&mut b, Instant::now());
                            b.get(&dest).map(|(s, _)| *s)
                        };
                        // Trim to the exact framed message (the slot is
                        // zero-padded; the app expects a bare relay frame).
                        let frame = match encode_relay(dest, datagram) {
                            Ok(f) => f,
                            Err(e) => {
                                warn!("cannot re-frame relay reply: {e}");
                                continue;
                            }
                        };
                        match src {
                            Some(src) => {
                                if let Err(e) = socket.send_to(&frame, src).await {
                                    warn!("relay reply to {src} failed: {e}");
                                }
                            }
                            None => {
                                warn!("no app endpoint recorded for reply dest {dest}; dropping")
                            }
                        }
                    }
                    Err(e) => warn!("dropping malformed relay reply: {e}"),
                }
            }
            Some(ManagerNotification::Closed { sid, reason }) => {
                // D16: the manager re-arms in the background; bindings persist.
                warn!("Session closed ({reason:?}) sid={sid:02x?}; re-establishing");
            }
            Some(ManagerNotification::Established { .. }) => {
                // Server-only notification; not emitted on the client path.
            }
            Some(ManagerNotification::Ready { .. }) => {
                // D15: the session is confirmed live; nothing to do here.
            }
        }
    }
}

fn prune_bindings(b: &mut Bindings, now: Instant) {
    // TTL sweep is unconditional (run on every frame) so `MAP_TTL` is a real
    // bound, not one that only applies once the map has already grown past
    // `MAP_MAX`.
    let mut expired: Vec<SocketAddr> = Vec::new();
    for (k, (_, last)) in b.iter() {
        if now.duration_since(*last) > MAP_TTL {
            expired.push(*k);
        }
    }
    for k in &expired {
        b.remove(k);
    }
    if b.len() <= MAP_MAX {
        return;
    }
    // Still over cap: evict by oldest last-use until under the cap.
    while b.len() > MAP_MAX {
        let eldest = b.iter().min_by(|a, c| a.1.1.cmp(&c.1.1)).map(|(k, _)| *k);
        if let Some(k) = eldest {
            b.remove(&k);
        } else {
            break;
        }
    }
}

/// Enforce that a relay message fits `range` and re-encode constraints used by
/// the server forwarder at build time (compile-time sanity).
const _: () = {
    assert!(PAYLOAD_LEN > HDR_LEN_V6, "relay header must fit the slot");
    let _ = MAX_DATAGRAM_V4;
    let _ = MAX_DATAGRAM_V6;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let dest = "192.0.2.7:5353".parse::<SocketAddr>().unwrap();
        let payload: Vec<u8> = (0..=200).collect();
        let msg = encode_relay(dest, &payload).unwrap();
        assert_eq!(msg.len(), HDR_LEN_V4 + payload.len());
        let (got_dest, got_payload) = decode_relay(&msg).unwrap();
        assert_eq!(got_dest, dest);
        assert_eq!(got_payload, payload);
    }

    #[test]
    fn v6_roundtrip() {
        let dest = "[2001:db8::99]:443".parse::<SocketAddr>().unwrap();
        let msg = encode_relay(dest, b"hi").unwrap();
        assert_eq!(msg.len(), HDR_LEN_V6 + 2);
        let (got_dest, got_payload) = decode_relay(&msg).unwrap();
        assert_eq!(got_dest, dest);
        assert_eq!(got_payload, b"hi");
    }

    #[test]
    fn assume_len_wins_over_padding_zeros() {
        // A datagram that itself ends in zero bytes must be preserved exactly;
        // padding after `len` must not be surfaced as data.
        let dest = "127.0.0.1:9".parse().unwrap();
        let payload = vec![0xAA, 0x00, 0x00];
        let msg = encode_relay(dest, &payload).unwrap();
        let mut padded = msg.clone();
        padded.extend_from_slice(&[0u8; 20]); // simulate slot padding
        let (_, decoded) = decode_relay(&padded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn truncated_rejected() {
        assert!(decode_relay(b"").is_err());
        assert!(decode_relay(&[FAMILY_IPV4, 0x01]).is_err());
        let dest = "127.0.0.1:9".parse().unwrap();
        let msg = encode_relay(dest, &[1, 2, 3]).unwrap();
        // Header alone declares len=3 but carries no payload bytes.
        let bad = msg[..HDR_LEN_V4].to_vec();
        assert!(decode_relay(&bad).is_err());
    }

    #[test]
    fn bad_family_rejected() {
        assert!(matches!(
            decode_relay(&[0x01, 1, 2, 3, 4, 0, 9, 0, 2]),
            Err(RelayError::BadFamily(_))
        ));
    }

    #[test]
    fn too_large_rejected_v4() {
        let dest = "192.0.2.1:1".parse().unwrap();
        assert!(matches!(
            encode_relay(dest, &vec![0u8; MAX_DATAGRAM_V4 + 1]),
            Err(RelayError::TooLarge { .. })
        ));
    }
}
