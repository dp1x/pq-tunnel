use std::time::Duration;

use pq_crypto::HybridIdentity;

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub identity: HybridIdentity,
    pub listen_addr: Option<std::net::SocketAddr>,
    pub remote_addr: Option<std::net::SocketAddr>,
    pub mtu: u16,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            identity: HybridIdentity::generate().expect("key generation must not fail"),
            listen_addr: None,
            remote_addr: None,
            mtu: 1400,
            handshake_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(15),
        }
    }
}
