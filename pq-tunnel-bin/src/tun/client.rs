//! Client TUN driver (D33 §2).

use std::io::{Read, Write};
use std::net::SocketAddr;

use pq_tunnel_core::{ClientSessionManager, HandshakeV2ClientConfig, SessionLimits, UdpTransport};
use tokio::sync::mpsc;

use crate::identity;
use crate::tun::device;
use crate::tun::{REASSEMBLY_DEADLINE, is_boundary_dropped, validate_inner};

#[allow(unreachable_code)]
pub async fn run(
    remote: SocketAddr,
    identity_path: &std::path::Path,
    server_key_path: &std::path::Path,
    lifetime_cap_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = identity::load_identity(identity_path)?;
    let server_key = identity::load_public_key(server_key_path)?;

    let cfg = HandshakeV2ClientConfig::new(remote, keypair, server_key);
    let limits = SessionLimits {
        lifetime_cap: crate::lifetime_cap_from_secs(lifetime_cap_secs),
        ..SessionLimits::default()
    };
    let mut manager = ClientSessionManager::new(&cfg, limits)
        .map_err(|e| format!("client session manager init failed: {e}"))?;
    let udp = UdpTransport::connect(remote)
        .await
        .map_err(|e| format!("UDP connect to {remote} failed: {e}"))?;

    let dev = device::open_tun("pqtun0")
        .await
        .map_err(|e| format!("TUN open failed: {e}"))?;
    let (mut tun_reader, mut tun_writer) = dev.split();

    install_networking(remote)?;

    // Handshake.
    if let pq_tunnel_core::ManagerEvent::Send { packets, peer } = manager.begin_handshake()? {
        for p in &packets {
            udp.send_to(p, peer).await?;
        }
    }

    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
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

    let mut reasm = pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE);
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));

    loop {
        tokio::select! {
            r = udp.recv() => match r {
                Err(_) => {}
                Ok((pkt, from)) => {
                    match manager.handle_datagram(&pkt, from) {
                        Ok(pq_tunnel_core::ManagerEvent::Send { packets, peer }) => {
                            for p in packets { let _ = udp.send_to(&p, peer).await; }
                        }
                        Ok(pq_tunnel_core::ManagerEvent::SendPacket { packet, peer }) => {
                            let _ = udp.send_to(&packet, peer).await;
                        }
                        Ok(pq_tunnel_core::ManagerEvent::AppData { inner, .. }) => {
                            eprintln!("client: AppData msg_type {:?}", inner.msg_type);
                            if inner.msg_type == pq_tunnel_core::codec::MessageType::TunData {
                                let slot: [u8; pq_tunnel_core::codec::PAYLOAD_LEN] = inner.payload;
                                match reasm.feed(&slot, std::time::Instant::now()) {
                                    pq_tunnel_core::dataplane::FeedOutcome::Complete(pkt) => {
                                        eprintln!("client: reassembled {} bytes", pkt.len());
                                        if is_boundary_dropped(&pkt) {
                                            eprintln!("client: boundary dropped");
                                        } else if !validate_inner(&pkt) {
                                            eprintln!("client: invalid inner");
                                        } else {
                                            eprintln!("client: TUN write {} bytes", pkt.len());
                                            let _ = tun_writer.write(&pkt);
                                        }
                                    }
                                    other => {
                                        eprintln!("client: feed outcome {:?}", other);
                                    }
                                }
                            }
                        }
                        Ok(pq_tunnel_core::ManagerEvent::Closed { .. }) => {
                            reasm.clear();
                            eprintln!("client: closed");
                        }
                        Ok(other) => {
                            eprintln!("client: manager event {:?}", other);
                        }
                        Err(e) => {
                            eprintln!("client: handle_datagram error {:?}", e);
                        }
                    }
                }
            },
            Some(pkt) = tun_rx.recv() => {
                eprintln!("client: TUN read {} bytes", pkt.len());
                if is_boundary_dropped(&pkt) { continue; }
                if !validate_inner(&pkt) { continue; }
                static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                let id = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(slots) = pq_tunnel_core::dataplane::fragment_ip_packet(&pkt, id) {
                    for slot in slots {
                        match manager.tun_outbound(&slot) {
                            Ok(pq_tunnel_core::ManagerEvent::SendPacket { packet, peer }) => {
                                let _ = udp.send_to(&packet, peer).await;
                            }
                            Ok(pq_tunnel_core::ManagerEvent::OutboundDropped { .. }) => {}
                            _ => {}
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
                        pq_tunnel_core::ManagerEvent::Closed { .. } => {
                            reasm.clear();
                        }
                        _ => {}
                    }
                }
                // cover
                if let Ok(pq_tunnel_core::ManagerEvent::SendPacket { packet, peer }) = manager.cover_packet() {
                    let _ = udp.send_to(&packet, peer).await;
                }
            }
            else => break,
        }
    }

    uninstall_networking(remote);
    Ok(())
}

fn install_networking(remote: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let (phys_iface, gateway) =
            super::os_net::discover_physical_route(&remote.ip().to_string())
                .map_err(|e| format!("route discovery failed: {e}"))?;
        let (server_v4, server_v6) = match remote.ip() {
            std::net::IpAddr::V4(v) => (v.to_string(), String::new()),
            std::net::IpAddr::V6(v) => (String::new(), v.to_string()),
        };
        let (gw_v4, gw_v6) = if remote.ip().is_ipv4() {
            (gateway, None)
        } else {
            (None, gateway)
        };
        let cmds = super::os_net::linux_install_routes_with_gateway(
            &server_v4,
            &server_v6,
            "pqtun0",
            &phys_iface,
            gw_v4.as_deref(),
            gw_v6.as_deref(),
        );
        super::os_net::run_commands(&cmds).map_err(|e| format!("route command failed: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = remote;
        Err("TUN networking setup is only implemented for Linux; refusing to start".into())
    }
}

fn uninstall_networking(remote: SocketAddr) {
    #[cfg(target_os = "linux")]
    {
        let (server_v4, server_v6) = match remote.ip() {
            std::net::IpAddr::V4(v) => (v.to_string(), String::new()),
            std::net::IpAddr::V6(v) => (String::new(), v.to_string()),
        };
        let cmds = super::os_net::linux_teardown_routes("pqtun0", &server_v4, &server_v6);
        for c in cmds {
            let _ = super::os_net::run_command(&c);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = remote;
    }
}
