use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use pq_tunnel_core::{TunnelConfig, connect};

#[allow(dead_code)] // server-side + provisioning APIs consume the rest
mod identity;
mod packet_len;
mod v2_client;

#[derive(Parser, Debug)]
#[command(name = "pq-tunnel-client", about = "Post-quantum tunnel client")]
struct Args {
    #[arg(short, long)]
    remote: SocketAddr,
    #[arg(short, long, default_value = "10.0.0.1/24")]
    tun_addr: String,
    #[arg(long, default_value = "1400")]
    mtu: u16,
    #[arg(long, default_value = "10")]
    handshake_timeout: u64,
    #[arg(long, default_value_t, value_enum)]
    transport: TransportKind,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    server_key: Option<PathBuf>,
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(long)]
    flood: bool,
    #[arg(long, default_value = "8191")]
    packet_size: usize,
    #[arg(long, default_value = "1000")]
    rate: u64,
    #[arg(long, default_value = "10")]
    duration: u64,
    #[arg(long)]
    flatline: bool,
    #[arg(long)]
    cover: bool,
}

#[derive(ValueEnum, Default, Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    #[default]
    V2,
    Quic,
}

fn parse_tun_addr(s: &str) -> Result<(std::net::IpAddr, std::net::IpAddr), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err("expected IP/CIDR format".into());
    }
    let ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let mask = match ip {
        std::net::IpAddr::V4(_) => {
            let m = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let b = m.to_be_bytes();
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        std::net::IpAddr::V6(_) => {
            let m = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let b = m.to_be_bytes();
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
        }
    };
    Ok((ip, mask))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    match args.transport {
        TransportKind::V2 => run_v2(&args).await,
        TransportKind::Quic => run_quic(&args).await,
    }
}

/// Datagram-plane client driver (default transport). Fail-closed identity
/// provisioning, pinned server key, UDP + client session manager.
async fn run_v2(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.flood || args.flatline || args.cover {
        tracing::error!("flood/cover/flatline are v1 (QUIC) modes; use --transport quic");
        return Err("v1-only flags cannot be combined with --transport v2".into());
    }

    let (tun_ip, tun_mask) = parse_tun_addr(&args.tun_addr)?;
    v2_client::run(tun_ip, tun_mask, args).await
}

/// v1 (QUIC) runtime: handshake over QUIC then flood/cover/tunnel modes.
async fn run_quic(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let identity = pq_crypto::HybridIdentity::generate()
        .map_err(|e| format!("key generation failed: {}", e))?;
    let (tun_ip, tun_mask) = parse_tun_addr(&args.tun_addr)?;

    let config = TunnelConfig {
        identity,
        listen_addr: None,
        remote_addr: Some(args.remote),
        mtu: args.mtu,
        handshake_timeout: Duration::from_secs(args.handshake_timeout),
        keepalive_interval: Duration::from_secs(15),
    };

    tracing::info!("Connecting to {}...", args.remote);
    let _t0 = Instant::now();
    let session = connect(config).await?;
    tracing::info!(
        "Connected! handshake={:?}ms",
        session.stats().handshake_duration_ms
    );

    if args.flood {
        run_flood_mode(&args, session).await?;
    } else if args.cover {
        run_cover_mode(&args, session).await?;
    } else {
        run_tunnel_mode(&args, session, tun_ip, tun_mask).await?;
    }
    Ok(())
}

async fn run_flood_mode(
    args: &Args,
    session: pq_tunnel_core::Session,
) -> Result<(), Box<dyn std::error::Error>> {
    use pq_tunnel_core::handshake::{
        PACKET_SIZE, recv_data_packet, send_data_packet, send_dummy_packet,
    };

    let mut send = session.take_send().ok_or("no send stream")?;
    let mut recv = session.take_recv().ok_or("no recv stream")?;
    let packet_size = args.packet_size.min(PACKET_SIZE - 1);
    let rate = args.rate;
    let duration = args.duration;

    tracing::info!(
        "FLOOD MODE: packet_size={}bytes, rate={}pps, duration={}s, flatline={}",
        PACKET_SIZE,
        rate,
        duration,
        args.flatline
    );

    let mut buf = vec![0u8; packet_size];
    getrandom::fill(&mut buf[..16]).expect("rand");

    let start = Instant::now();
    let mut next = start;
    let interval = Duration::from_nanos(1_000_000_000 / rate);
    let mut sent = 0u64;
    let mut recv_count = 0u64;

    while start.elapsed() < Duration::from_secs(duration) {
        let mut pkt = vec![0u8; packet_size];
        pkt[..16].copy_from_slice(&buf[..16]);
        if args.flatline {
            pkt = vec![0u8; packet_size];
            pkt[..16].copy_from_slice(&buf[..16]);
        }

        match send_data_packet(&mut send, &pkt).await {
            Ok(()) => {
                sent += 1;
                if sent <= 3 {
                    tracing::debug!("sent packet {}", sent);
                }
            }
            Err(e) => {
                tracing::warn!("send error #{}: {}", sent + 1, e);
                break;
            }
        }

        match recv_data_packet(&mut recv).await {
            Ok(_) => {
                recv_count += 1;
                if recv_count <= 3 {
                    tracing::debug!("recv packet {}", recv_count);
                }
            }
            Err(e) => {
                if sent <= 3 {
                    tracing::debug!("recv error: {}", e);
                }
            }
        }

        next += interval;
        let now = Instant::now();
        if next > now {
            let mut jb = [0u8; 1];
            let _ = getrandom::fill(&mut jb);
            tokio::time::sleep((next - now) + Duration::from_nanos((jb[0] as u64) * 100_000)).await;
        }
    }

    let expected = rate * duration;
    let throughput_mbps =
        (sent as f64 * PACKET_SIZE as f64 * 8.0) / (duration as f64 * 1_000_000.0);
    tracing::info!(
        "FLOOD COMPLETE: sent={}, recv={}, throughput={:.2} Mbps",
        sent,
        recv_count,
        throughput_mbps
    );

    if args.flatline {
        let ratio = sent as f64 / expected as f64;
        if ratio > 0.95 && ratio < 1.05 {
            tracing::info!("FLAT-LINE: PASS");
        } else {
            tracing::warn!("FLAT-LINE: FAIL (ratio={:.4})", ratio);
        }
    }

    let _ = send_dummy_packet(&mut send).await;
    Ok(())
}

async fn run_cover_mode(
    args: &Args,
    session: pq_tunnel_core::Session,
) -> Result<(), Box<dyn std::error::Error>> {
    use pq_tunnel_core::handshake::{
        PACKET_SIZE, recv_data_packet, send_data_packet, send_dummy_packet,
    };

    let mut send = session.take_send().ok_or("no send stream")?;
    let mut recv = session.take_recv().ok_or("no recv stream")?;
    let packet_size = args.packet_size.min(PACKET_SIZE - 1);
    let rate = args.rate;
    let duration = args.duration;

    tracing::info!(
        "COVER MODE: packet_size={}bytes, rate={}pps, duration={}s",
        PACKET_SIZE,
        rate,
        duration
    );

    let mut buf = vec![0u8; packet_size];
    getrandom::fill(&mut buf[..16]).expect("rand");

    let start = Instant::now();
    let mut next_send = start;
    let send_interval = Duration::from_nanos(1_000_000_000 / rate);
    let mut sent = 0u64;
    let mut recv_count = 0u64;

    while start.elapsed() < Duration::from_secs(duration) {
        if Instant::now() >= next_send {
            let mut pkt = vec![0u8; packet_size];
            pkt[..16].copy_from_slice(&buf[..16]);
            if send_data_packet(&mut send, &pkt).await.is_ok() {
                sent += 1;
            }
            let mut jb = [0u8; 1];
            let _ = getrandom::fill(&mut jb);
            next_send += send_interval + Duration::from_nanos((jb[0] as u64) * 100_000);
        }

        if recv_data_packet(&mut recv).await.is_ok() {
            recv_count += 1;
        }
        tokio::task::yield_now().await;
    }

    let throughput_mbps =
        (sent as f64 * PACKET_SIZE as f64 * 8.0) / (duration as f64 * 1_000_000.0);
    tracing::info!(
        "COVER COMPLETE: sent={}, recv={}, throughput={:.2} Mbps",
        sent,
        recv_count,
        throughput_mbps
    );

    if sent > 0 && recv_count > 0 {
        tracing::info!("COVER: PASS");
    } else {
        tracing::warn!("COVER: FAIL");
    }

    let _ = send_dummy_packet(&mut send).await;
    Ok(())
}

async fn run_tunnel_mode(
    args: &Args,
    session: pq_tunnel_core::Session,
    tun_ip: std::net::IpAddr,
    tun_mask: std::net::IpAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    use pq_tunnel_core::handshake::{recv_data_packet, send_cover_packet, send_data_packet};

    let tun = pq_tun::TunDevice::create("pq-tun", tun_ip, tun_mask, args.mtu)
        .map_err(|e| format!("TUN creation failed: {}", e))?;
    let (mut reader, mut writer) = tun.split();
    let conn = session.connection();

    let (mut send1, _recv1) = conn.open_bi().await?;
    let (_send2, mut recv2) = conn.open_bi().await?;

    tracing::info!("Tunnel established. TUN interface {} is up.", args.tun_addr);

    let cover_rate = 100u64;
    let cover_interval = Duration::from_nanos(1_000_000_000 / cover_rate);

    let tun_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut next_cover = Instant::now();
        loop {
            match reader.read_packet(&mut buf).await {
                Ok(0) => {
                    if Instant::now() >= next_cover {
                        let _ = send_cover_packet(&mut send1).await;
                        next_cover += cover_interval;
                    }
                    continue;
                }
                Ok(n) => {
                    if send_data_packet(&mut send1, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("TUN read error: {}", e);
                    break;
                }
            }
        }
    });

    let quic_to_tun = tokio::spawn(async move {
        loop {
            match recv_data_packet(&mut recv2).await {
                Ok(data) => {
                    if writer.write_packet(&data).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    });

    tokio::select! { _ = tun_to_quic => {}, _ = quic_to_tun => {} }
    tracing::info!("Tunnel closed.");
    Ok(())
}
