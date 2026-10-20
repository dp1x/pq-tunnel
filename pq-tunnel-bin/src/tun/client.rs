//! Client TUN driver (D33 §2).

use std::io::{Read, Write};
use std::net::SocketAddr;

use pq_tunnel_core::{
    ClientSessionManager, CoverPolicy, HandshakeV2ClientConfig, ManagerNotification, SessionLimits,
    UdpTransport, run_client_manager,
};
use tokio::sync::mpsc;
use tracing::info;

use crate::identity;
use crate::tun::device;
use crate::tun::{REASSEMBLY_DEADLINE, is_boundary_dropped, os_net, validate_inner};

pub async fn run(
    remote: SocketAddr,
    identity_path: &std::path::Path,
    server_key_path: &std::path::Path,
    cover: CoverPolicy,
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
    let mut udp = UdpTransport::connect(remote)
        .await
        .map_err(|e| format!("UDP connect to {remote} failed: {e}"))?;

    let dev = device::open_tun("pqtun0")
        .await
        .map_err(|e| format!("TUN open failed: {e}"))?;

    install_networking(remote)?;

    let dev_arc = std::sync::Arc::new(std::sync::Mutex::new(dev));

    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);
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

    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(256);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);

    let _driver = tokio::spawn(async move {
        run_client_manager(&mut udp, &mut manager, app_tx, data_rx, cover).await
    });

    let mut reasm = pq_tunnel_core::dataplane::Reassembler::new(REASSEMBLY_DEADLINE);

    loop {
        tokio::select! {
            Some(notif) = app_rx.recv() => {
                match notif {
                    ManagerNotification::Data { inner, .. } => {
                        if inner.msg_type == pq_tunnel_core::codec::MessageType::TunData {
                            let slot: [u8; pq_tunnel_core::codec::PAYLOAD_LEN] = inner.payload;
                            match reasm.feed(&slot, std::time::Instant::now()) {
                                pq_tunnel_core::dataplane::FeedOutcome::Complete(pkt)
                                    if !is_boundary_dropped(&pkt) && validate_inner(&pkt) =>
                                {
                                    let devw = dev_arc.clone();
                                    let p = pkt.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let mut d = devw.lock().unwrap();
                                        let _ = d.write(&p);
                                    })
                                    .await;
                                }
                                _ => {}
                            }
                        }
                    }
                    ManagerNotification::Ready { .. } => { info!("TUN session ready"); }
                    ManagerNotification::Closed { .. } => { reasm.clear(); }
                    _ => {}
                }
            }
            Some(pkt) = tun_rx.recv() => {
                if is_boundary_dropped(&pkt) { continue; }
                if !validate_inner(&pkt) { continue; }
                static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                let id = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(slots) = pq_tunnel_core::dataplane::fragment_ip_packet(&pkt, id) {
                    for slot in slots {
                        let _ = data_tx.send(slot.to_vec()).await;
                    }
                }
            }
            else => break,
        }
    }

    let _ = _driver.await;
    uninstall_networking(remote);
    Ok(())
}

fn install_networking(remote: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let server_ip = remote.ip().to_string();
    let cmds = os_net::linux_install_routes(&server_ip, &server_ip, "pqtun0", "eth0");
    for c in &cmds {
        let _ = std::process::Command::new("sh").arg("-c").arg(c).status();
    }
    Ok(())
}

fn uninstall_networking(remote: SocketAddr) {
    let server_ip = remote.ip().to_string();
    let cmds = os_net::linux_teardown_routes("pqtun0", &server_ip, &server_ip);
    for c in &cmds {
        let _ = std::process::Command::new("sh").arg("-c").arg(c).status();
    }
}
