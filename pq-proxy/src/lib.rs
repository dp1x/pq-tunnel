//! pq-proxy — Optional SOCKS5/HTTP proxy layer.
//!
//! Depends on pq-tunnel-core (NOT directly on pq-crypto).

pub mod error;
pub mod http_connect;
pub mod socks5;

pub use error::ProxyError;
