//! v2 (datagram-plane) client driver wiring.
//!
//! Owns the UDP transport, the [`ClientSessionManager`], and the relay that
//! connects them to local applications (D18):
//!
//! * The **relay socket** (`--relay-listen`) is the application-facing
//!   endpoint: relay-framed datagrams (destination in the header) arrive from
//!   any local app, are recorded `destination → app endpoint`, and are passed
//!   to the manager, which zero-pads them into the fixed `PAYLOAD_LEN` slot.
//! * Inbound [`ManagerNotification::Data`] (framed replies) are routed back to
//!   the app endpoint that last spoke to the reply's destination
//!   (last-writer-wins; D18).
//!
//! The driver task returned by [`run_client_manager`] owns retransmit timers,
//! liveness, and automatic re-establishment (D16): a [`ManagerNotification::Closed`]
//! does not end the client — the loop keeps the relay up while the manager
//! re-arms.  Manager and task errors are surfaced, never swallowed.

use pq_tunnel_core::{
    ClientSessionManager, HandshakeV2ClientConfig, ManagerNotification, SessionLimits,
    UdpTransport, run_client_manager,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

use crate::ClientArgs;
use crate::identity;
use crate::relay;

/// Run the v2 client to completion: provision identities, establish the UDP
/// transport + session manager, and pump traffic between the relay socket and
/// the manager via the two channel legs.
pub async fn run(args: &ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
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
    let cover = crate::cover_policy_from_args(args.no_cover, args.cover_mbps)?;
    let mut manager = ClientSessionManager::new(&cfg, SessionLimits::default())
        .map_err(|e| format!("client session manager init failed: {e}"))?;
    let mut udp = UdpTransport::connect(args.remote)
        .await
        .map_err(|e| format!("UDP connect to {} failed: {e}", args.remote))?;

    let (app_tx, app_rx) = mpsc::channel::<ManagerNotification>(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

    // The manager driver owns all transport I/O, retransmit timers, and D16
    // re-establishment.  It exits only on a transport/manager error or when
    // the app channel closes.
    let driver = tokio::spawn(async move {
        run_client_manager(&mut udp, &mut manager, app_tx, data_rx, cover).await
    });

    // The relay is the application endpoint: local apps send relay-framed
    // datagrams here; the relay records destinations and forwards into the
    // tunnel, and routes framed replies back to the right app endpoint.
    let relay_socket = UdpSocket::bind(args.relay_listen)
        .await
        .map_err(|e| format!("relay bind on {} failed: {e}", args.relay_listen))?;
    let local = relay_socket
        .local_addr()
        .map_err(|e| format!("failed to read relay bound address: {e}"))?;
    // Fail closed on non-loopback relay binds: the relay records unauthenticated
    // `destination → app endpoint` bindings (last-writer-wins) and would
    // otherwise act as an open relay / reply-splice for anyone able to reach the
    // socket.  Loopback-only keeps the app-facing surface local by construction
    // (D18; revisit with an explicit opt-in if a LAN relay is ever wanted).
    if !local.ip().is_loopback() {
        return Err(format!(
            "refusing to bind the relay on non-loopback address {local}: \
             relay bindings are unauthenticated and must stay local"
        )
        .into());
    }
    info!("Relay listening on {local} (destination header is app-facing, D18)");

    // The relay returns when the manager channel closes (driver ended).  It
    // holds `data_tx`, so dropping it after return lets the driver observe
    // channel closure too; await it for a clean error report.
    relay::run(relay_socket, data_tx, app_rx)
        .await
        .map_err(|e| format!("relay failed: {e}"))?;

    match driver.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("client manager driver failed: {e}").into()),
        Err(join) => Err(format!("client manager task panicked: {join}").into()),
    }
}
