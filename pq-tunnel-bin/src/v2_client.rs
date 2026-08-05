//! v2 (datagram-plane) client driver wiring.
//!
//! Owns the UDP transport, the [`ClientSessionManager`], and the two channel
//! legs that connect them to the tun device:
//!
//! * TUN read → outbound app channel (zero-padded by the manager into the
//!   fixed `PAYLOAD_LEN` slot).
//! * Inbound [`ManagerNotification::Data`] → TUN write.  The slot is
//!   zero-padded, so the real IP packet length is recovered from the IP
//!   header (IPv4 total-length / IPv6 payload-length) before writing.
//!
//! The driver task returned by [`run_client_manager`] owns retransmit timers,
//! liveness, and automatic re-establishment (D16): a [`ManagerNotification::Closed`]
//! does not end the client — the loop keeps the tunnel up while the manager
//! re-arms.  Manager and task errors are surfaced, never swallowed.

use std::net::IpAddr;

use pq_tunnel_core::{
    ClientSessionManager, HandshakeV2ClientConfig, InnerPlaintext, ManagerNotification,
    PAYLOAD_LEN, SessionLimits, UdpTransport, run_client_manager,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::Args;
use crate::identity;
use crate::packet_len::ip_packet_len;

/// Run the v2 client to completion: provision identities, establish the UDP
/// transport + session manager, and pump traffic between the tun and the
/// manager via the two channel legs.
pub async fn run(
    tun_ip: IpAddr,
    tun_mask: IpAddr,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity_path = args
        .identity
        .as_deref()
        .ok_or("v2 client requires --identity (client identity seed file)")?;
    let server_key_path = args
        .server_key
        .as_deref()
        .ok_or("v2 client requires --server-key (pinned server public key)")?;

    // Provision (fail closed): a missing/malformed identity or pinned key
    // aborts before any socket is opened.
    let keypair = identity::load_identity(identity_path)?;
    let server_key = identity::load_public_key(server_key_path)?;

    let cfg = HandshakeV2ClientConfig::new(args.remote, keypair, server_key);
    let mut manager = ClientSessionManager::new(&cfg, SessionLimits::default())
        .map_err(|e| format!("client session manager init failed: {e}"))?;
    let mut udp = UdpTransport::connect(args.remote)
        .await
        .map_err(|e| format!("UDP connect to {} failed: {e}", args.remote))?;

    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

    // The manager driver owns all transport I/O, retransmit timers, and D16
    // re-establishment.  It exits only on a transport/manager error or when
    // the app channel closes.
    let driver =
        tokio::spawn(
            async move { run_client_manager(&mut udp, &mut manager, app_tx, data_rx).await },
        );

    // The data plane carries fixed slots; the tun MTU must not exceed one
    // payload so a single tun read always fits.
    let tun_mtu = args.mtu.min(u16::try_from(PAYLOAD_LEN).unwrap_or(u16::MAX));
    let tun = pq_tun::TunDevice::create("pq-tun", tun_ip, tun_mask, tun_mtu)
        .map_err(|e| format!("TUN creation failed: {e}"))?;
    let (mut reader, mut writer) = tun.split();
    info!("Tunnel established. {} is up.", args.tun_addr);

    // TUN → manager outbound channel.
    let forwarder = tokio::spawn(async move {
        let mut buf = vec![0u8; PAYLOAD_LEN];
        loop {
            match reader.read_packet(&mut buf).await {
                Ok(n) => {
                    // Driver gone (channel closed) → stop forwarding.
                    if data_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("TUN read error: {e}");
                    break;
                }
            }
        }
    });

    // Inbound notifications → TUN.
    loop {
        match app_rx.recv().await {
            // App channel closed: the driver has ended (error or shutdown).
            None => break,
            Some(ManagerNotification::Ready { sid }) => {
                info!("Session confirmed (D15), sid={sid:02x?}");
            }
            Some(ManagerNotification::Data { inner, .. }) => {
                forward_inner(&mut writer, &inner).await?;
            }
            Some(ManagerNotification::Closed { sid, reason }) => {
                warn!("Session closed ({reason:?}) sid={sid:02x?}; re-establishing");
                // D16: the manager re-arms in the background; the tunnel stays up.
            }
            Some(ManagerNotification::Established { .. }) => {
                // Server-only notification; not emitted on the client path.
            }
        }
    }

    // Shutdown: stop the TUN forwarder (drops `data_tx`), which lets the
    // manager driver observe app-channel closure and return.
    forwarder.abort();
    match driver.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("client manager driver failed: {e}").into()),
        Err(join) => Err(format!("client manager task panicked: {join}").into()),
    }
}

async fn forward_inner(
    writer: &mut pq_tun::TunWriter,
    inner: &InnerPlaintext,
) -> Result<(), Box<dyn std::error::Error>> {
    let len = ip_packet_len(&inner.payload);
    if len == 0 {
        // Not an IP packet in the slot (or malformed length): drop, fail-safe.
        warn!("dropping non-IP payload (len=0)");
        return Ok(());
    }
    if let Err(e) = writer.write_packet(&inner.payload[..len]).await {
        // TUN write failure: the interface is gone; stop the client.
        return Err(format!("TUN write failed: {e}").into());
    }
    Ok(())
}
