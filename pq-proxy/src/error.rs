use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Tunnel error: {0}")]
    Tunnel(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("SOCKS5 handshake failed: {0}")]
    HandshakeFailed(String),
}
