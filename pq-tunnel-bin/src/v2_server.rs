//! v2 (datagram-plane) server driver wiring.
//!
//! Owns the UDP transport, the [`ServerSessionManager`], and the two channel
//! legs that connect them to the application:
//!
//! * Inbound [`ManagerNotification`]s (handshake events, decrypted data,
//!   closures) → application.
//! * Outbound [`ServerAppCommand`]s (application data keyed by `sid`) →
//!   manager → encrypted packets back to the session's peer.
//!
//! The application is a byte-echo relay, mirroring the v1 server's `run_data_loop`
//! semantics: every decrypted `Data` payload is trimmed to its real IP packet
//! length (the wire slot is zero-padded) and sent back to the *same session*.
//! Cover traffic is consumed silently by the manager and never reaches the app.
//!
//! The driver task returned by [`run_server_manager`] owns transport I/O and
//! periodic `tick`s (idle eviction, lifetime cap, D16).  It exits only on a
//! transport/manager error or when the app channel closes.  Manager and task
//! errors are surfaced, never swallowed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pq_tunnel_core::{
    HandshakeV2ServerConfig, ManagerNotification, ServerAppCommand, ServerSessionManager,
    SessionLimits, UdpTransport, run_server_manager,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::ServerArgs;
use crate::identity;
use crate::packet_len::ip_packet_len;

/// Run the v2 server to completion: provision identity + roster (fail closed),
/// bind the UDP transport, and echo app data back to its own session.
pub async fn run(args: &ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let identity_path = args
        .identity
        .as_deref()
        .ok_or("v2 server requires --identity (server identity seed file)")?;
    let roster_path = args
        .roster
        .as_deref()
        .ok_or("v2 server requires --roster (client public-key roster file)")?;

    // Provision (fail closed): a missing/malformed identity or an empty roster
    // aborts before any socket is opened (D12).
    let keypair = identity::load_identity(identity_path)?;
    let roster = identity::load_roster(roster_path)?;

    let cfg = HandshakeV2ServerConfig::new(keypair, roster);
    let mut manager = ServerSessionManager::new(&cfg, SessionLimits::default())
        .map_err(|e| format!("server session manager init failed: {e}"))?;
    let mut udp = UdpTransport::bind(args.listen)
        .await
        .map_err(|e| format!("UDP bind on {} failed: {e}", args.listen))?;

    tracing::info!("Listening on {}...", args.listen);
    let local = udp
        .local_addr()
        .map_err(|e| format!("failed to read UDP bound address: {e}"))?;
    info!("v2 server bound to {local}");

    let (app_tx, mut app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (cmd_tx, cmd_rx) = mpsc::channel::<ServerAppCommand>(64);

    // Session-count diagnostics (the manager itself is owned by the driver
    // task): total handshakes and currently established sessions.
    let total_handshakes = Arc::new(AtomicU64::new(0));
    let active_sessions = Arc::new(AtomicU64::new(0));

    let stats_total = total_handshakes.clone();
    let stats_active = active_sessions.clone();
    let stats_interval = args.stats_interval;
    let stats_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(stats_interval));
        loop {
            interval.tick().await;
            tracing::info!(
                "STATS: handshakes={} sessions={}",
                stats_total.load(Ordering::Relaxed),
                stats_active.load(Ordering::Relaxed)
            );
        }
    });

    let driver =
        tokio::spawn(
            async move { run_server_manager(&mut udp, &mut manager, app_tx, cmd_rx).await },
        );

    // Echo application: relay every decrypted Data payload back to the same
    // sid.  The driver's notification channel closing (transport/app error or
    // shutdown) ends this loop.
    let echo_total = total_handshakes.clone();
    let echo_active = active_sessions.clone();
    let echo_handle = tokio::spawn(async move {
        loop {
            match app_rx.recv().await {
                // App channel closed: the driver has ended (error or shutdown).
                None => break,
                Some(ManagerNotification::Data { sid, inner }) => {
                    let len = ip_packet_len(&inner.payload);
                    if len == 0 {
                        // Not an IP packet in the slot (or malformed length):
                        // drop, fail-safe — never relay garbage.
                        warn!("dropping non-IP payload (len=0) sid={sid:02x?}");
                        continue;
                    }
                    // Echo the real IP packet to the same session.
                    if cmd_tx
                        .send(ServerAppCommand {
                            sid,
                            payload: inner.payload[..len].to_vec(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Some(ManagerNotification::Established { sid, peer }) => {
                    echo_total.fetch_add(1, Ordering::Relaxed);
                    echo_active.fetch_add(1, Ordering::Relaxed);
                    info!("Session established (D13) sid={sid:02x?} peer={peer}");
                }
                Some(ManagerNotification::Closed { sid, reason }) => {
                    echo_active.fetch_sub(1, Ordering::Relaxed);
                    warn!("Session closed ({reason:?}) sid={sid:02x?}");
                    // Server is passive: the manager already removed the
                    // session; nothing to re-arm.
                }
                Some(ManagerNotification::Ready { .. }) => {
                    // Client-only notification; not emitted on the server path.
                }
            }
        }
    });

    // Both tasks wind down together: the driver drops app_tx on exit (error or
    // app-channel close) which unblocks the echo loop; the echo loop dropping
    // cmd_tx closes the driver's command channel.  Drive both to completion so
    // manager errors and task panics are propagated, not swallowed.
    let (echo_result, driver_result) = tokio::join!(echo_handle, driver);
    stats_handle.abort();

    match driver_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("server manager driver failed: {e}").into()),
        Err(join) => return Err(format!("server manager task panicked: {join}").into()),
    }
    match echo_result {
        Ok(()) => {}
        Err(join) => return Err(format!("echo app task panicked: {join}").into()),
    }

    info!("Server shutting down (app channel closed).");
    Ok(())
}
