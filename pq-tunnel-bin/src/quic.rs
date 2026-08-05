//! Legacy v1 (QUIC/TLS) runtimes.
//!
//! Transitional bootstrap/development paths from the pre-v2 era. The v1
//! transport performs **no server-certificate validation** and its handshake
//! authenticates nothing against a pinned roster (self-generated ephemeral
//! identities). It is **not** part of the v2 security model and is scheduled
//! for removal; reachable only via `--transport quic`.

use std::time::{Duration, Instant};

use pq_tunnel_core::{TunnelConfig, connect, listen};

use crate::{ClientArgs, ServerArgs};

/// v1 (QUIC) server: listen, accept, handshake, echo each connection's data
/// stream back. Kept behind `--transport quic`.
pub async fn run_server(args: &ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

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
    let stats_interval = args.stats_interval;
    let stats_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(stats_interval)).await;
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
                                    Err(e) => {
                                        tracing::debug!("accept_bi failed: {}", e);
                                        return;
                                    }
                                };
                                match pq_tunnel_core::server_handshake(&id, &mut send, &mut recv)
                                    .await
                                {
                                    Ok(result) => {
                                        ths.fetch_add(1, Ordering::Relaxed);
                                        tracing::info!(
                                            "Handshake complete: {}ms",
                                            result.handshake_duration_ms
                                        );
                                        run_data_loop(send, recv).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!("Handshake failed: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Connection failed: {}", e);
                            }
                        }
                    });
                }
                None => {
                    tracing::info!("Endpoint closed");
                    break;
                }
            }
        }
    });

    tokio::select! { _ = accept_handle => {}, _ = stats_handle => {} }
    tracing::info!("Server shutting down.");
    Ok(())
}

async fn run_data_loop(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    use pq_tunnel_core::handshake::{recv_data_packet, send_data_packet};

    while let Ok(data) = recv_data_packet(&mut recv).await {
        if send_data_packet(&mut send, &data).await.is_err() {
            break;
        }
    }
}

/// v1 (QUIC) client: handshake over QUIC then flood/cover/tunnel modes.
pub async fn run_client(
    args: &ClientArgs,
    tun_ip: std::net::IpAddr,
    tun_mask: std::net::IpAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = pq_crypto::HybridIdentity::generate()
        .map_err(|e| format!("key generation failed: {}", e))?;

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
        run_flood_mode(args, session).await?;
    } else if args.cover {
        run_cover_mode(args, session).await?;
    } else {
        run_tunnel_mode(args, session, tun_ip, tun_mask).await?;
    }
    Ok(())
}

async fn run_flood_mode(
    args: &ClientArgs,
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
    args: &ClientArgs,
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
    args: &ClientArgs,
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
        while let Ok(data) = recv_data_packet(&mut recv2).await {
            if writer.write_packet(&data).await.is_err() {
                break;
            }
        }
    });

    tokio::select! { _ = tun_to_quic => {}, _ = quic_to_tun => {} }
    tracing::info!("Tunnel closed.");
    Ok(())
}
