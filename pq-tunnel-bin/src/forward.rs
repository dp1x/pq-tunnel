//! Server-side forwarding backend (D18).
//!
//! A relay message arriving through the tunnel is decoded to `(dest, datagram)`
//! (the framing lives *inside* the encrypted payload slot — it never appears on
//! the wire).  The forwarder shells out to the internet through per-
//! `(session, destination)` connected UDP sockets:
//!
//! * a connected socket's bound source port *is* `dest.port`, so reply
//!   datagrams emerge from the exact address the client relay recorded;
//! * replies are re-labeled with a relay header for `dest` and fed back into
//!   the manager as a [`ServerAppCommand`] for the same `sid`.
//!
//! `echo` mode (opt-in diagnostics, D18) skips the sockets entirely and returns
//! the framed datagram to the same `sid` — preserving the v1-era echo loop.
//!
//! # Resource caps (fail-secure eviction)
//!
//! The pool is capped per session and globally; idle sockets are TTL-pruned.
//! On cap exhaustion the *oldest* entry is dropped and its reader task aborted
//! (`ForwardError` would turn a DoS into a tunnel teardown; eviction is the
//! documented tradeoff).  Evicted destinations lose their in-flight binding —
//! a later datagram lazily re-creates the socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pq_tunnel_core::ServerAppCommand;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::warn;

use crate::relay::{MAX_DATAGRAM_V6, decode_relay, encode_relay};

/// Idle lifetime of a pooled (session, destination) socket.
pub const IDLE_TTL: Duration = Duration::from_secs(60);
/// Cap on pooled sockets per session.
pub const PER_SESSION_CAP: usize = 128;
/// Global cap on pooled sockets across all sessions.
pub const GLOBAL_CAP: usize = 512;

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("{kind}: {source}")]
    Io {
        kind: &'static str,
        source: std::io::Error,
    },
}

/// One pooled forward socket: a handle for sends + the reader task that
/// relabels and returns replies, plus the last time it was used.
struct ForwardEntry {
    socket: Arc<UdpSocket>,
    reader: tokio::task::JoinHandle<()>,
    last_use: Instant,
}

/// The forwarding backend: session/destination socket pool + optional echo.
pub struct Forwarder {
    echo: bool,
    sockets: HashMap<([u8; 8], SocketAddr), ForwardEntry>,
    commands: mpsc::Sender<ServerAppCommand>,
}

impl Forwarder {
    /// Create the backend.  `false` full forwarding; if `echo` is set, data is
    /// answered from the *same* session without an outbound socket.
    pub fn new(echo: bool, commands: mpsc::Sender<ServerAppCommand>) -> Self {
        Self {
            echo,
            sockets: HashMap::new(),
            commands,
        }
    }

    /// Handle one decrypted application datagram (a relay-framed message
    /// inside its fixed `PAYLOAD_LEN` slot, zero-padded).
    pub async fn handle(&mut self, sid: [u8; 8], slot: &[u8]) {
        // Idle reaping on every datagram (not just on insert) so `IDLE_TTL` is
        // a real bound, not an opportunistic one: a session that opens sockets
        // and then goes quiet releases its descriptors on the first subsequent
        // frame with no dependence on new-insertion pressure.
        self.prune_idle(Instant::now());
        let (dest, datagram) = match decode_relay(slot) {
            Ok(x) => x,
            Err(_) => {
                // Unknown family/truncated: drop, fail-closed (D18: unknown
                // families never routed).
                return;
            }
        };

        if self.echo
            && let Ok(reply) = encode_relay(dest, datagram)
            && self
                .commands
                .send(ServerAppCommand {
                    sid,
                    payload: reply,
                })
                .await
                .is_err()
        {
            // App channel gone; the driver is winding down.
            return;
        }
        if self.echo {
            return;
        }

        // Forward: ensure the (session, destination) socket exists.
        let key = (sid, dest);
        if !self.sockets.contains_key(&key) {
            self.prune_and_insert(key).await;
        }
        {
            let entry = match self.sockets.get_mut(&key) {
                Some(e) => e,
                None => return, // pool cap evicted it mid-flight; next datagram retries
            };
            entry.last_use = Instant::now();
            if let Err(e) = entry.socket.send(datagram).await {
                warn!("forward send to {dest} (sid={sid:02x?}) failed: {e}");
            }
        }
    }

    /// A session closed: drop all of its sockets (reads end, tasks abort).
    pub fn on_session_closed(&mut self, sid: [u8; 8]) {
        let sids: Vec<([u8; 8], SocketAddr)> = self
            .sockets
            .keys()
            .filter(|(s, _)| *s == sid)
            .copied()
            .collect();
        for key in sids {
            self.drop_entry(key);
        }
    }

    // -----------------------------------------------------------------------
    // Pool maintenance
    // -----------------------------------------------------------------------

    /// Lazily bind + connect a forward socket for `key`, spawn its reply
    /// reader, then enforce the pool caps (evicting the oldest on exhaustion).
    async fn prune_and_insert(&mut self, key: ([u8; 8], SocketAddr)) {
        self.prune_idle(Instant::now());
        let (sid, dest) = key;

        if self.sockets.len() >= GLOBAL_CAP
            && let Some((older, _)) = self.oldest()
        {
            self.drop_entry(older);
        }
        // Per-session cap: drop that session's oldest.
        let mut sid_entries = self
            .sockets
            .keys()
            .filter(|(s, _)| *s == sid)
            .copied()
            .collect::<Vec<_>>();
        while sid_entries.len() >= PER_SESSION_CAP {
            let oldest_sid = sid_entries
                .iter()
                .min_by_key(|k| self.sockets[k].last_use)
                .copied();
            match oldest_sid {
                Some(k) => self.drop_entry(k),
                None => break,
            }
            sid_entries = self
                .sockets
                .keys()
                .filter(|(s, _)| *s == sid)
                .copied()
                .collect::<Vec<_>>();
        }

        // Bind an unconnected local socket, then connect to the destination:
        // `send` leaves the source port, which the client's recorded
        // `(dest → app endpoint)` binding matches for replies.
        let bind: SocketAddr = if dest.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(sock) => Arc::new(sock),
            Err(e) => {
                warn!("forward bind on {bind} failed: {e}");
                return;
            }
        };
        if let Err(e) = sock.connect(dest).await {
            warn!("forward connect to {dest} failed: {e}");
            return;
        }
        let reader = {
            let reader_sock = sock.clone();
            let cmd = self.commands.clone();
            tokio::spawn(reply_reader(reader_sock, sid, dest, cmd))
        };
        self.sockets.insert(
            key,
            ForwardEntry {
                socket: sock,
                reader,
                last_use: Instant::now(),
            },
        );
    }

    fn prune_idle(&mut self, now: Instant) {
        let stale: Vec<([u8; 8], SocketAddr)> = self
            .sockets
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_use) > IDLE_TTL)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            self.drop_entry(key);
        }
    }

    fn oldest(&self) -> Option<(([u8; 8], SocketAddr), Instant)> {
        self.sockets
            .iter()
            .min_by_key(|(_, e)| e.last_use)
            .map(|(k, e)| (*k, e.last_use))
    }

    fn drop_entry(&mut self, key: ([u8; 8], SocketAddr)) {
        if let Some(entry) = self.sockets.remove(&key) {
            entry.reader.abort();
        }
    }

    /// Abort every reader (tunnel shutdown) so the remaining `commands`
    /// clones drop and the driver observes channel closure.
    pub fn shutdown(&mut self) {
        for key in self.sockets.keys().copied().collect::<Vec<_>>() {
            self.drop_entry(key);
        }
    }
}

/// Reply reader: datagrams received on a (session, destination) forward socket
/// are re-labeled for the destination and returned to the manager.
async fn reply_reader(
    socket: Arc<UdpSocket>,
    sid: [u8; 8],
    dest: SocketAddr,
    commands: mpsc::Sender<ServerAppCommand>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_V6];
    loop {
        match socket.recv_from(&mut buf).await {
            Err(e) => {
                warn!("forward reply read from {dest} failed: {e}");
                // Socket failure is terminal for the entry; the next datagram
                // lazily re-creates it.
                return;
            }
            Ok((n, _from)) => {
                let payload = match encode_relay(dest, &buf[..n]) {
                    Ok(p) => p,
                    Err(_) => continue, // cannot happen; reader buf <= MAX
                };
                if commands
                    .send(ServerAppCommand { sid, payload })
                    .await
                    .is_err()
                {
                    return; // manager gone
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time caps sanity (avoids the "constant value" lint).
    const _: () = {
        assert!(PER_SESSION_CAP > 0);
        assert!(GLOBAL_CAP >= PER_SESSION_CAP);
    };
}
