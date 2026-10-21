//! Server TUN driver (D33 §3).

use std::io::{Read, Write};
use std::net::SocketAddr;

use pq_tunnel_core::{HandshakeV2ServerConfig, ServerSessionManager, SessionLimits, UdpTransport};

use crate::tun::device;
use crate::tun::{REASSEMBLY_DEADLINE, is_boundary_dropped, validate_inner};
use crate::tun_policy::{ClientAssignment, PacketVerdict, validate_inner_packet};

#[allow(unreachable_code)]
pub async fn run(
    listen: SocketAddr,
    identity_path: Option<&std::path::Path>,
    roster_path: Option<&std::path::Path>,
    cover_mbps: u64,
    no_cover: bool,
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
        max_sessions: 1,
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
    let (mut tun_reader, mut tun_writer) = dev.split();

    enable_networking()?;

    let cover = crate::cover_policy_from_args(no_cover, cover_mbps)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let assignment = ClientAssignment::default();
    let mut reasms: std::collections::HashMap<[u8; 8], pq_tunnel_core::dataplane::Reassembler> =
        std::collections::HashMap::new();
    let mut current_sid: Option<[u8; 8]> = None;
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));

    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    tokio::task::spawn_blocking(move || {
        loop {
            let mut buf = vec![0u8; 65535];
            match tun_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    buf.truncate(n);
                    if tun_tx.blocking_send(buf).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            r = udp.recv() => match r {
                Err(_) => {}
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
                                let reasm = reasms
                                    .entry(sid)
                                    .or_insert_with(|| pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE));
                                match reasm.feed(&slot, std::time::Instant::now()) {
                                    pq_tunnel_core::dataplane::FeedOutcome::Complete(ipkt)
                                        if validate_inner_packet(&ipkt, &assignment) == PacketVerdict::Allow =>
                                    {
                                        let _ = tun_writer.write(&ipkt);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(pq_tunnel_core::ManagerEvent::Established { sid, .. }) => {
                            reasms
                                .entry(sid)
                                .or_insert_with(|| pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE));
                            current_sid = Some(sid);
                        }
                        Ok(pq_tunnel_core::ManagerEvent::Closed { sid, .. }) => {
                            if let Some(r) = reasms.get_mut(&sid) {
                                r.clear();
                            }
                            reasms.remove(&sid);
                            current_sid = None;
                        }
                        Ok(pq_tunnel_core::ManagerEvent::OutboundDropped { .. }) => {}
                        _ => {}
                    }
                }
            },
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
            _ = ticker.tick() => {
                for ev in manager.tick(std::time::Instant::now()) {
                    match ev {
                        pq_tunnel_core::ManagerEvent::Send { packets, peer } => {
                            for p in packets { let _ = udp.send_to(&p, peer).await; }
                        }
                        pq_tunnel_core::ManagerEvent::SendPacket { packet, peer } => {
                            let _ = udp.send_to(&packet, peer).await;
                        }
                        pq_tunnel_core::ManagerEvent::Closed { sid, .. } => {
                            if let Some(r) = reasms.get_mut(&sid) {
                                r.clear();
                            }
                            reasms.remove(&sid);
                            current_sid = None;
                        }
                        pq_tunnel_core::ManagerEvent::Established { sid, .. } => {
                            reasms
                                .entry(sid)
                                .or_insert_with(|| pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE));
                            current_sid = Some(sid);
                        }
                        _ => {}
                    }
                }
                // cover
                let _ = cover;
                if let Ok(evs) = manager.cover_packet_all() {
                    for ev in evs {
                        if let pq_tunnel_core::ManagerEvent::SendPacket { packet, peer } = ev {
                            let _ = udp.send_to(&packet, peer).await;
                        }
                    }
                }
            }
            else => break,
        }
    }

    Ok(())
}

fn enable_networking() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let cmds =
            crate::tun::os_net::linux_server_install("pqtun0", "10.77.0.1/32", "fd00:77::1/128");
        crate::tun::os_net::run_commands(&cmds)
            .map_err(|e| format!("server TUN address setup failed: {e}"))?;
        let cmds = crate::tun::os_net::linux_enable_forwarding();
        crate::tun::os_net::run_commands(&cmds)
            .map_err(|e| format!("IP forwarding setup failed: {e}"))?;
        let cmds = crate::tun::os_net::linux_nat_install("10.77.0.0/24");
        crate::tun::os_net::run_commands(&cmds).map_err(|e| format!("NAT setup failed: {e}"))?;
        let cmds = crate::tun::os_net::linux_nat_install_ipv6("fd00:77::/64");
        crate::tun::os_net::run_commands(&cmds)
            .map_err(|e| format!("IPv6 NAT setup failed: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("server TUN networking is only implemented for Linux; refusing to start".into())
    }
}
