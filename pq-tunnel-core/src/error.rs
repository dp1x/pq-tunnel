use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] pq_crypto::CryptoError),

    #[error("QUIC error: {0}")]
    Quic(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Handshake timeout")]
    HandshakeTimeout,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}