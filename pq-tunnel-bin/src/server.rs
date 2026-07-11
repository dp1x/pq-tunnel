use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use pq_tunnel_core::{TunnelConfig, listen};

#[derive(Parser, Debug)]
#[command(name = "pq-tunnel-server", about = "Post-quantum QUIC tunnel server")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    #[arg(short, long, default_value = "10.0.0.2/24")]
    tun_addr: String,
    #[arg(long, default_value = "1400")]
    mtu: u16,
    #[arg(long, default_value = "10")]
    handshake_timeout: u64,
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "5")]
    stats_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let identity = pq_crypto::HybridIdentity::generate()
        .map_err(|e| format!("key generation failed: {}", e))?;

    let config = TunnelConfig {
        identity: identity.clone(),
        listen_addr: Some(args.listen),
        remote_addr: None,
        mtu: args.mtu,
        handshake_timeout: Duration::from_secs(args.handshake_timeout),
        keepalive_interval: Duration::from_secs(15),
    };

    tracing::info!("Listening on {}...", args.listen);
    let listener = listen(config).await?;
    let endpoint = listener.endpoint.as_ref().expect("no endpoint").clone();

    let total_handshakes = Arc::new(AtomicU64::new(0));

    let stats_hs = total_handshakes.clone();
    let stats_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(args.stats_interval)).await;
            let hs = stats_hs.load(Ordering::Relaxed);
            tracing::info!("STATS: handshakes={}", hs);
        }
    });

    let server_id = identity;
    let accept_handle = tokio::spawn(async move {
        loop {
            match endpoint.accept().await {
                Some(connecting) => {
                    let id = server_id.clone();
                    let ths = total_handshakes.clone();
                    tokio::spawn(async move {
                        match connecting.await {
                            Ok(conn) => {
                                let (mut send, mut recv) = match conn.accept_bi().await {
                                    Ok(s) => s,
                                    Err(e) => { tracing::debug!("accept_bi failed: {}", e); return; }
                                };
                                match pq_tunnel_core::server_handshake(&id, &mut send, &mut recv).await {
                                    Ok(result) => {
                                        ths.fetch_add(1, Ordering::Relaxed);
                                        tracing::info!("Handshake complete: {}ms", result.handshake_duration_ms);
                                        run_data_loop(send, recv).await;
                                    }
                                    Err(e) => { tracing::warn!("Handshake failed: {}", e); }
                                }
                            }
                            Err(e) => { tracing::debug!("Connection failed: {}", e); }
                        }
                    });
                }
                None => { tracing::info!("Endpoint closed"); break; }
            }
        }
    });

    tokio::select! { _ = accept_handle => {}, _ = stats_handle => {} }
    tracing::info!("Server shutting down.");
    Ok(())
}

async fn run_data_loop(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    use pq_tunnel_core::handshake::{send_data_packet, recv_data_packet};

    loop {
        match recv_data_packet(&mut recv).await {
            Ok(data) => {
                if send_data_packet(&mut send, &data).await.is_err() { break; }
            }
            Err(_) => break,
        }
    }
}
