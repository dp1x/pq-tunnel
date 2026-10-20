//! Server TUN driver (D33 §3).

use std::io::{Read, Write};
use std::net::SocketAddr;

use pq_tunnel_core::{HandshakeV2ServerConfig, ServerSessionManager, SessionLimits, UdpTransport};

use crate::tun::device;
use crate::tun::{REASSEMBLY_DEADLINE, is_boundary_dropped, validate_inner};
use crate::tun_policy::{ClientAssignment, PacketVerdict, validate_inner_packet};

pub async fn run(
    listen: SocketAddr,
    identity_path: Option<&std::path::Path>,
    roster_path: Option<&std::path::Path>,
    _cover_mbps: u64,
    _no_cover: bool,
    lifetime_cap_secs: u64,
    max_roster_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = identity_path
        .map(crate::identity::load_identity)
        .transpose()?
        .ok_or("server TUN requires --identity")?;
    let roster = roster_path.map(crate::identity::load_roster).transpose()?;
    let roster = roster.unwrap_or_default();
    let cfg = HandshakeV2ServerConfig::with_roster_limit(keypair, roster, max_roster_size);
    let limits = SessionLimits {
        lifetime_cap: crate::lifetime_cap_from_secs(lifetime_cap_secs),
        ..SessionLimits::default()
    };
    let mut manager = ServerSessionManager::new(&cfg, limits)
        .map_err(|e| format!("server session manager init: {e}"))?;
    let udp = UdpTransport::bind(listen)
        .await
        .map_err(|e| format!("UDP bind {listen}: {e}"))?;

    let dev = device::open_tun("pqtun0")
        .await
        .map_err(|e| format!("TUN open: {e}"))?;
    let dev_arc = std::sync::Arc::new(std::sync::Mutex::new(dev));

    enable_forwarding();

    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let dev_read = dev_arc.clone();
    tokio::task::spawn_blocking(move || {
        loop {
            let pkt = {
                let mut d = dev_read.lock().unwrap();
                let mut buf = vec![0u8; 65535];
                match d.read(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        buf
                    }
                    Err(_) => break,
                }
            };
            if tun_tx.blocking_send(pkt).is_err() {
                break;
            }
        }
    });

    let assignment = ClientAssignment::default();
    let mut reasm = pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE);
    let mut current_sid: Option<[u8; 8]> = None;

    loop {
        tokio::select! {
            res = udp.recv() => {
                match res {
                    Ok((pkt, peer)) => {
                        match manager.handle_datagram(&pkt, peer) {
                            Ok(pq_tunnel_core::ManagerEvent::Send { packets, peer: p }) => {
                                for pp in packets { let _ = udp.send_to(&pp, p).await; }
                            }
                            Ok(pq_tunnel_core::ManagerEvent::SendPacket { packet, peer: p }) => {
                                let _ = udp.send_to(&packet, p).await;
                            }
                            Ok(pq_tunnel_core::ManagerEvent::AppData { sid, inner }) => {
                                current_sid = Some(sid);
                                if inner.msg_type == pq_tunnel_core::codec::MessageType::TunData {
                                    let slot: [u8; pq_tunnel_core::codec::PAYLOAD_LEN] = inner.payload;
                                    if let pq_tunnel_core::dataplane::FeedOutcome::Complete(ipkt) = reasm.feed(&slot, std::time::Instant::now())
                                        && validate_inner_packet(&ipkt, &assignment) == PacketVerdict::Allow {
                                        let devw = dev_arc.clone();
                                        let p = ipkt.clone();
                                        let _ = tokio::task::spawn_blocking(move || {
                                            let mut d = devw.lock().unwrap();
                                            let _ = d.write(&p);
                                        }).await;
                                    }
                                }
                            }
                            Ok(pq_tunnel_core::ManagerEvent::Closed { .. }) => {
                                reasm.clear();
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
            Some(pkt) = tun_rx.recv() => {
                if is_boundary_dropped(&pkt) { continue; }
                if !validate_inner(&pkt) { continue; }
                if let Some(sid) = current_sid {
                    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                    let id = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Ok(slots) = pq_tunnel_core::dataplane::fragment_ip_packet(&pkt, id) {
                        for slot in slots {
                            if let Ok(pq_tunnel_core::ManagerEvent::SendPacket { packet, peer: p }) = manager.tun_outbound(&sid, &slot) {
                                let _ = udp.send_to(&packet, p).await;
                            }
                        }
                    }
                }
            }
            else => break,
        }
    }

    Ok(())
}

fn enable_forwarding() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg("sysctl -w net.ipv4.ip_forward=1")
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("powershell")
            .arg("-c")
            .arg("Set-NetIPInterface -Forwarding Enabled")
            .status();
    }
}
