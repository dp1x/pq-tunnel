//! v2 (datagram-plane) server driver wiring.
//!
//! Owns the UDP transport, the [`ServerSessionManager`], and two channel legs:
//!
//! * Inbound [`ManagerNotification`]s (handshake events, decrypted data,
//!   closures) → the forwarding application.
//! * Outbound [`ServerAppCommand`]s (forwarded replies keyed by `sid`) →
//!   manager → encrypted packets back to the session's peer.
//!
//! The application is a **forwarding backend** (D18): each decrypted relay
//! message is dispatched to the real destination through a per-
//! `(session, destination)` connected UDP socket; replies are relabeled and
//! returned to the same session.  Cover traffic is consumed silently by the
//! manager and never reaches the app.  `--echo` (opt-in) returns the framed
//! datagram to the same session, preserving the v1-era diagnostics loop.
//!
//! The driver task returned by [`run_server_manager`] owns transport I/O and
//! periodic `tick`s (idle eviction, lifetime cap, D16).  It exits only on a
//! transport/manager error or when both [] command channels close.  Manager
//! and task errors are surfaced, never swallowed.

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
use crate::forward::Forwarder;
use crate::identity;

/// Run the v2 server to completion: provision identity + roster (fail closed),
/// bind the UDP transport, and run the forwarding backend (or echo, opt-in).
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

    // Forwarding application: dispatch every decrypted relay message to its
    // real destination; replies return through the manager as commands for the
    // same sid.  The driver's notification channel closing (transport/app
    // error or shutdown) ends this loop.
    let echo = args.echo;
    let fwd_total = total_handshakes.clone();
    let fwd_active = active_sessions.clone();
    let app_task = tokio::spawn(async move {
        let mut forwarder = Forwarder::new(echo, cmd_tx);
        loop {
            match app_rx.recv().await {
                // App channel closed: the driver has ended (error or shutdown).
                None => break,
                Some(ManagerNotification::Data { sid, inner }) => {
                    forwarder.handle(sid, &inner.payload).await;
                }
                Some(ManagerNotification::Established { sid, peer }) => {
                    fwd_total.fetch_add(1, Ordering::Relaxed);
                    fwd_active.fetch_add(1, Ordering::Relaxed);
                    info!("Session established (D13) sid={sid:02x?} peer={peer}");
                }
                Some(ManagerNotification::Closed { sid, reason }) => {
                    fwd_active.fetch_sub(1, Ordering::Relaxed);
                    warn!("Session closed ({reason:?}) sid={sid:02x?}");
                    forwarder.on_session_closed(sid);
                }
                Some(ManagerNotification::Ready { .. }) => {
                    // Client-only notification; not emitted on the server path.
                }
            }
        }
        // Drop the forwarder's reader tasks + command sender: the manager
        // driver observes the (now-empty) command channel and returns.
        forwarder.shutdown();
    });

    // Both tasks wind down together: the driver drops app_tx on exit (error or
    // app-channel close) which unblocks the app loop; the app loop dropping
    // cmd_tx closes the driver's command channel.  Drive both to completion so
    // manager errors and task panics are propagated, not swallowed.
    let (app_result, driver_result) = tokio::join!(app_task, driver);
    stats_handle.abort();

    match driver_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("server manager driver failed: {e}").into()),
        Err(join) => return Err(format!("server manager task panicked: {join}").into()),
    }
    match app_result {
        Ok(()) => {}
        Err(join) => return Err(format!("forward app task panicked: {join}").into()),
    }

    info!("Server shutting down (app channel closed).");
    Ok(())
}
