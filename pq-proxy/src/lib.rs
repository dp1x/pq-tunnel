pub mod error;
pub mod socks5;

use crate::error::ProxyError;
use pq_tunnel_core::{TunnelConfig, connect};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct PqProxy {
    config: TunnelConfig,
    listen_addr: SocketAddr,
}

impl PqProxy {
    pub fn new(config: TunnelConfig, listen_addr: SocketAddr) -> Self {
        PqProxy { config, listen_addr }
    }

    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        tracing::info!("PQ-Proxy listening on {}", self.listen_addr);

        loop {
            let (client, addr) = listener.accept().await?;
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(client, addr, config).await {
                    tracing::debug!("client {} error: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    mut client: TcpStream,
    addr: SocketAddr,
    config: TunnelConfig,
) -> Result<(), ProxyError> {
    let mut buf = [0u8; 256];
    let n = client.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 {
        return Err(ProxyError::InvalidRequest("not SOCKS5".into()));
    }

    let nmethods = buf[1] as usize;
    let methods = &buf[2..2 + nmethods];
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Err(ProxyError::HandshakeFailed("no acceptable methods".into()));
    }

    client.write_all(&[0x05, 0x00]).await?;

    let n = client.read(&mut buf).await?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
        return Err(ProxyError::InvalidRequest("not CONNECT".into()));
    }

    let atyp = buf[3];
    let (host, port) = match atyp {
        0x01 => {
            if n < 7 { return Err(ProxyError::InvalidRequest("short IPv4".into())); }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            let len = buf[4] as usize;
            if n < 5 + len + 2 { return Err(ProxyError::InvalidRequest("short domain".into())); }
            let host = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[6 + len]]);
            (host, port)
        }
        0x06 => {
            if n < 19 { return Err(ProxyError::InvalidRequest("short IPv6".into())); }
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[4..20]).unwrap());
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (ip.to_string(), port)
        }
        _ => return Err(ProxyError::InvalidRequest("unsupported atyp".into())),
    };

    let target = format!("{}:{}", host, port);
    tracing::info!("proxy {} -> {}", addr, target);

    let session = connect(config).await
        .map_err(|e| ProxyError::Tunnel(format!("connect failed: {}", e)))?;

    let conn = session.connection().clone();
    let conn2 = conn.clone();

    let reply = match atyp {
        0x01 => vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        0x03 => {
            let mut r = vec![0x05, 0x00, 0x00, 0x03, host.len() as u8];
            r.extend_from_slice(host.as_bytes());
            r.extend_from_slice(&port.to_be_bytes());
            r
        }
        0x06 => {
            let mut r = vec![0x05, 0x00, 0x00, 0x06];
            r.extend_from_slice(&std::net::Ipv6Addr::UNSPECIFIED.octets());
            r.extend_from_slice(&port.to_be_bytes());
            r
        }
        _ => unreachable!(),
    };
    client.write_all(&reply).await?;

    let (mut client_read, mut client_write) = client.into_split();

    let tunnel_to_client = tokio::spawn(async move {
        let _buf = vec![0u8; 8192];
        loop {
            match conn.read_datagram().await {
                Ok(data) => {
                    if client_write.write_all(&data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    let client_to_tunnel = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = bytes::Bytes::from(buf[..n].to_vec());
                    if conn2.send_datagram(data).is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    tokio::select! {
        _ = tunnel_to_client => {},
        _ = client_to_tunnel => {},
    }

    Ok(())
}
