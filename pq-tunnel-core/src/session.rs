use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::TunnelConfig;
use crate::metrics::SessionMetrics;

const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(60);
const ROTATION_FUTURE_LIMIT: Duration = Duration::from_secs(120);

pub struct Session {
    pub config: TunnelConfig,
    pub shared_secret: [u8; 32],
    connection: Arc<Connection>,
    pub send: Arc<Mutex<Option<SendStream>>>,
    pub recv: Arc<Mutex<Option<RecvStream>>>,
    pub metrics: SessionMetrics,
    key_rotations: Arc<Mutex<Vec<Instant>>>,
    created_at: Instant,
}

impl Session {
    pub fn needs_key_rotation(&self) -> bool {
        let rotations = self.key_rotations.lock().unwrap_or_else(|e| e.into_inner());
        match rotations.last() {
            Some(last) => self.created_at.elapsed() - last.elapsed() > ROTATION_FUTURE_LIMIT,
            None => self.created_at.elapsed() > KEY_ROTATION_INTERVAL,
        }
    }

    pub fn record_key_rotation(&self) {
        let mut rotations = self.key_rotations.lock().unwrap_or_else(|e| e.into_inner());
        rotations.push(Instant::now());
    }

    pub fn new(
        config: TunnelConfig,
        connection: Connection,
        shared_secret: [u8; 32],
        handshake_duration_ms: u64,
    ) -> Self {
        Session {
            config,
            shared_secret,
            connection: Arc::new(connection),
            send: Arc::new(Mutex::new(None)),
            recv: Arc::new(Mutex::new(None)),
            metrics: SessionMetrics {
                handshake_duration_ms: Some(handshake_duration_ms),
                created_at: Some(Instant::now()),
                ..Default::default()
            },
            key_rotations: Arc::new(Mutex::new(Vec::new())),
            created_at: Instant::now(),
        }
    }

    pub fn new_with_streams(
        config: TunnelConfig,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        shared_secret: [u8; 32],
        handshake_duration_ms: u64,
    ) -> Self {
        Session {
            config,
            shared_secret,
            connection: Arc::new(connection),
            send: Arc::new(Mutex::new(Some(send))),
            recv: Arc::new(Mutex::new(Some(recv))),
            metrics: SessionMetrics {
                handshake_duration_ms: Some(handshake_duration_ms),
                created_at: Some(Instant::now()),
                ..Default::default()
            },
            key_rotations: Arc::new(Mutex::new(Vec::new())),
            created_at: Instant::now(),
        }
    }

    pub fn stats(&self) -> &SessionMetrics {
        &self.metrics
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn take_send(&self) -> Option<SendStream> {
        self.send.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    pub fn take_recv(&self) -> Option<RecvStream> {
        self.recv.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

pub struct Listener {
    pub config: TunnelConfig,
    pub endpoint: Option<Endpoint>,
}

impl Drop for Session {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
    }
}

impl Listener {
    pub fn new(config: TunnelConfig) -> Self {
        Listener {
            config,
            endpoint: None,
        }
    }
}
