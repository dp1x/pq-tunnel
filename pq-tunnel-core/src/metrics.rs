use std::time::Instant;

#[derive(Debug, Default)]
pub struct SessionMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub handshake_duration_ms: Option<u64>,
    pub created_at: Option<Instant>,
}