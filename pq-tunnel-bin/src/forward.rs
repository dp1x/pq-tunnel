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
//!
//! # Egress guard (server-side destination policy)
//!
//! The relay destination is chosen by the *client*, so at the server it is
//! untrusted input: a roster-authenticated client can ask the forwarding
//! backend to emit a datagram from the server host to any address it names.
//! Unfiltered, that is a server-side request forgery (SSRF) into the server's
//! own network — the tunnel becomes a probe for services bound to the server's
//! loopback and for the cloud metadata plane.
//!
//! [`egress`] holds the deny policy.  It is a pure function of the
//! destination (no I/O, no DNS, no state) and is evaluated **before any
//! socket is created**, so a denied destination never reaches the network and
//! never produces a client-visible reply: the frame is dropped exactly like an
//! unroutable one.  The policy denies only exact unsafe hosts and
//! well-known special-purpose ranges — RFC1918, ULA and CGNAT stay reachable
//! so private-network and VPN routing keeps working.
//!
//! Denials are observable to the operator through a bounded, non-sensitive
//! counter (one per rule, plus one for forward-path failures), never through
//! per-destination logging, which would turn the server's logs into a
//! transcript of the client's attempts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pq_tunnel_core::ServerAppCommand;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::warn;

use self::egress::{EgressGuard, EgressPolicy, EgressStats};
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
    /// Egress policy counters (see [`egress`]).  Shared so an operator-facing
    /// surface can poll them without holding the `Forwarder`.
    guard: Arc<EgressGuard>,
    /// The destination policy applied to every relayed destination.
    policy: EgressPolicy,
}

impl Forwarder {
    /// Create the backend.  `false` full forwarding; if `echo` is set, data is
    /// answered from the *same* session without an outbound socket.
    ///
    /// The backend applies [`EgressPolicy::DenyUnsafe`]: destinations that
    /// would let a client pivot into the server's own network are refused
    /// before any socket is created.  Use [`Forwarder::new_with_policy`] only
    /// for a test or diagnostic fixture that must reach a loopback address.
    pub fn new(echo: bool, commands: mpsc::Sender<ServerAppCommand>) -> Self {
        Self::new_with_policy(echo, commands, EgressPolicy::DenyUnsafe)
    }

    /// Create the backend with an explicit destination policy.
    ///
    /// [`EgressPolicy::AllowLoopback`] re-opens the server-side SSRF path and
    /// is for test/diagnostic use only.
    pub fn new_with_policy(
        echo: bool,
        commands: mpsc::Sender<ServerAppCommand>,
        policy: EgressPolicy,
    ) -> Self {
        Self {
            echo,
            sockets: HashMap::new(),
            commands,
            guard: Arc::new(EgressGuard::default()),
            policy,
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

        // Egress guard: the destination is client-chosen, so it is checked
        // *before* any socket exists.  A denied destination produces no
        // outbound datagram and no client-visible signal — the frame is
        // dropped exactly like an unroutable one — and is only observable to
        // the operator through the bounded per-rule counter.
        if let Some(rule) = egress::deny_reason(&dest, self.policy) {
            let count = self.guard.record_denial(rule);
            if egress::should_log(count) {
                warn!("egress denied: rule={} count={count}", rule.as_str());
            }
            return;
        }

        // MSRV 1.85: nested if-let (let chains stabilize in 1.88). Cannot be
        // collapsed via a `&& let` chain without breaking the MSRV gate.
        #[allow(clippy::collapsible_if)]
        if self.echo {
            if let Ok(reply) = encode_relay(dest, datagram) {
                if self
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
            }
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
            // The send error is moved out of the pool borrow so the failure
            // can be recorded against the guard (which needs `&self`).
            let sent = entry.socket.send(datagram).await;
            if let Err(e) = sent {
                self.record_failure("send", &e);
            }
        }
    }

    /// A snapshot of the egress counters (bounded, non-sensitive).
    pub fn egress_stats(&self) -> EgressStats {
        self.guard.snapshot()
    }

    /// A shared handle to the egress guard, so an operator-facing surface can
    /// poll the counters without holding the `Forwarder`.
    pub fn egress_guard(&self) -> Arc<EgressGuard> {
        self.guard.clone()
    }

    /// Record a forward-path failure.  The failure is counted and logged at a
    /// bounded rate (see [`egress::should_log`]); the log line deliberately
    /// carries **no client-chosen destination**, so a client can neither
    /// flood the server's logs nor turn them into a transcript of its own
    /// attempts.
    fn record_failure(&self, kind: &'static str, e: &std::io::Error) {
        let count = self.guard.record_failure();
        if egress::should_log(count) {
            warn!("forward {kind} failed (failure #{count}): {e}");
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

        // MSRV 1.85: nested if-let (let chains stabilize in 1.88). Cannot be
        // collapsed via a `&& let` chain without breaking the MSRV gate.
        #[allow(clippy::collapsible_if)]
        if self.sockets.len() >= GLOBAL_CAP {
            if let Some((older, _)) = self.oldest() {
                self.drop_entry(older);
            }
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
                self.record_failure("bind", &e);
                return;
            }
        };
        if let Err(e) = sock.connect(dest).await {
            self.record_failure("connect", &e);
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

/// Egress policy for the forwarding backend: the destinations the server
/// refuses to emit a datagram to.
///
/// The policy is a *pure* function of the destination address and port — no
/// I/O, no state, no DNS.  It lives here (and not in `relay::decode_relay`)
/// because the relay framing codec is shared with the client and must stay
/// symmetric: a policy input in a framing function would make the codec
/// asymmetric with `encode_relay` and would make the client drop traffic the
/// server would accept.
pub mod egress {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The destination policy a forwarder applies.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum EgressPolicy {
        /// The production policy: refuse the destinations that would let a
        /// client pivot into the server's own network (loopback, unspecified,
        /// multicast, limited broadcast, cloud metadata) and destinations
        /// that carry no port.  This is the default for every deployed
        /// forwarder.
        #[default]
        DenyUnsafe,
        /// Allow loopback destinations; every other deny rule still applies.
        ///
        /// **Test/diagnostic use only.**  It re-opens the server-side SSRF
        /// path — a client can again reach services bound to the server's
        /// loopback — and must not be used in a deployment.  It exists
        /// because the end-to-end harness exercises the relay mechanics with
        /// a loopback echo fixture as the destination.
        AllowLoopback,
    }

    /// Why a destination is refused.  One unit variant per rule: the enum
    /// carries no client-chosen data, so a counter keyed by it can never
    /// become an information leak.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DenyRule {
        /// Destination port 0 — not a port.  The OS accepts it on some
        /// platforms (measured on Windows: `connect` and `send` both
        /// succeed), so the tunnel refuses it itself.
        PortZero,
        /// IPv4 loopback, `127.0.0.0/8`.
        V4Loopback,
        /// IPv6 loopback, `::1/128`.
        V6Loopback,
        /// IPv4 "this network" / unspecified range, `0.0.0.0/8`.
        V4Unspecified,
        /// IPv6 unspecified address, `::/128`.
        V6Unspecified,
        /// IPv4 multicast, `224.0.0.0/4`.
        V4Multicast,
        /// IPv6 multicast, `ff00::/8`.
        V6Multicast,
        /// IPv4 limited broadcast, `255.255.255.255/32`.
        V4Broadcast,
        /// Cloud metadata service `169.254.169.254` (AWS / GCP / Azure IMDS).
        MetadataImdsV4,
        /// Cloud metadata service `100.100.100.200` (Alibaba ECS IMDS).
        MetadataAlibabaV4,
        /// Cloud metadata service `fd00:ec2::254` (AWS IMDS over IPv6).
        MetadataAwsV6,
        /// Cloud metadata service `fd20:ce::254` (GCP metadata over IPv6).
        MetadataGcpV6,
    }

    impl DenyRule {
        /// Number of rules — the size of the fixed counter array.
        pub const COUNT: usize = 12;

        /// Stable, machine-greppable name (logs and metrics).
        pub fn as_str(self) -> &'static str {
            match self {
                Self::PortZero => "port_zero",
                Self::V4Loopback => "v4_loopback",
                Self::V6Loopback => "v6_loopback",
                Self::V4Unspecified => "v4_unspecified",
                Self::V6Unspecified => "v6_unspecified",
                Self::V4Multicast => "v4_multicast",
                Self::V6Multicast => "v6_multicast",
                Self::V4Broadcast => "v4_broadcast",
                Self::MetadataImdsV4 => "metadata_imds_v4",
                Self::MetadataAlibabaV4 => "metadata_alibaba_v4",
                Self::MetadataAwsV6 => "metadata_aws_v6",
                Self::MetadataGcpV6 => "metadata_gcp_v6",
            }
        }

        /// Index of this rule in the fixed counter array.
        fn index(self) -> usize {
            match self {
                Self::PortZero => 0,
                Self::V4Loopback => 1,
                Self::V6Loopback => 2,
                Self::V4Unspecified => 3,
                Self::V6Unspecified => 4,
                Self::V4Multicast => 5,
                Self::V6Multicast => 6,
                Self::V4Broadcast => 7,
                Self::MetadataImdsV4 => 8,
                Self::MetadataAlibabaV4 => 9,
                Self::MetadataAwsV6 => 10,
                Self::MetadataGcpV6 => 11,
            }
        }
    }

    /// The deny policy: `Some(rule)` when the destination must not be
    /// contacted, `None` when it may be.
    ///
    /// Order matters:
    ///
    /// 1. the port (a destination with no port is not a destination at all);
    /// 2. the exact cloud-metadata hosts — they live *inside* ranges that are
    ///    otherwise allowed (`169.254.169.254` is link-local, `100.100.100.200`
    ///    is inside CGNAT `100.64.0.0/10`), so an exact-host rule must be
    ///    evaluated before any range rule, and the containing ranges must
    ///    stay reachable;
    /// 3. the special-purpose ranges (loopback, unspecified, multicast,
    ///    limited broadcast);
    /// 4. everything else is allowed — RFC1918, ULA and CGNAT included, so
    ///    private-network and VPN routing keeps working.
    ///
    /// `policy` selects the rule set; [`EgressPolicy::DenyUnsafe`] is the
    /// production policy.
    pub fn deny_reason(dest: &SocketAddr, policy: EgressPolicy) -> Option<DenyRule> {
        if dest.port() == 0 {
            return Some(DenyRule::PortZero);
        }
        match dest.ip() {
            IpAddr::V4(v4) => deny_ipv4(v4, policy),
            IpAddr::V6(v6) => deny_ipv6(v6, policy),
        }
    }

    /// IPv4 rules.  Only exact unsafe hosts and special-purpose ranges are
    /// refused; the private and shared address space is not.
    fn deny_ipv4(v4: Ipv4Addr, policy: EgressPolicy) -> Option<DenyRule> {
        // Exact metadata hosts first (see `deny_reason`).
        if v4 == Ipv4Addr::new(169, 254, 169, 254) {
            return Some(DenyRule::MetadataImdsV4);
        }
        if v4 == Ipv4Addr::new(100, 100, 100, 200) {
            return Some(DenyRule::MetadataAlibabaV4);
        }
        if v4.is_loopback() && policy == EgressPolicy::DenyUnsafe {
            return Some(DenyRule::V4Loopback);
        }
        if v4.octets()[0] == 0 {
            // 0.0.0.0/8: "this network" / unspecified (RFC 1122).
            return Some(DenyRule::V4Unspecified);
        }
        if v4.is_multicast() {
            return Some(DenyRule::V4Multicast);
        }
        if v4.is_broadcast() {
            return Some(DenyRule::V4Broadcast);
        }
        None
    }

    /// IPv6 rules, including the normalisation of IPv4-embedded forms.
    fn deny_ipv6(v6: Ipv6Addr, policy: EgressPolicy) -> Option<DenyRule> {
        // Exact metadata hosts first (see `deny_reason`).
        if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
            return Some(DenyRule::MetadataAwsV6);
        }
        if v6 == Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254) {
            return Some(DenyRule::MetadataGcpV6);
        }
        // Native IPv6 rules.
        if v6.is_loopback() {
            if policy == EgressPolicy::DenyUnsafe {
                return Some(DenyRule::V6Loopback);
            }
            // `::1` is the IPv6 loopback (RFC 4291 §2.5.3); it is allowed
            // under the test-only policy and is not reinterpreted as the
            // deprecated IPv4-compatible form below.
            return None;
        }
        if v6.is_unspecified() {
            return Some(DenyRule::V6Unspecified);
        }
        if v6.is_multicast() {
            return Some(DenyRule::V6Multicast);
        }
        // IPv4-embedded forms are normalised to IPv4 *before* the IPv4 rules
        // run, so `::ffff:127.0.0.1` cannot be used to reach the IPv4
        // loopback behind the IPv4 rules.
        if let Some(v4) = embedded_ipv4(v6) {
            return deny_ipv4(v4, policy);
        }
        None
    }

    /// The IPv4 address embedded in an IPv6 address, if any.
    ///
    /// Two forms are normalised:
    ///
    /// * IPv4-mapped, `::ffff:0:0/96` (RFC 4291 §2.5.2) — the form a
    ///   dual-stack socket accepts for an IPv4 peer;
    /// * IPv4-compatible, `::0:0/96` (RFC 4291 §2.5.1, deprecated but still
    ///   accepted by some stacks).
    ///
    /// Both are collapsed to the embedded IPv4 address so that the IPv4 rules
    /// cannot be bypassed by re-encoding the same host in another family.
    fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return Some(v4);
        }
        let s = v6.segments();
        if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
            let hi = s[6];
            let lo = s[7];
            return Some(Ipv4Addr::new(
                (hi >> 8) as u8,
                hi as u8,
                (lo >> 8) as u8,
                lo as u8,
            ));
        }
        None
    }

    /// Bounded, non-sensitive observability for the egress policy.
    ///
    /// One saturating counter per deny rule plus one for forward-path
    /// failures.  The counters live in a fixed-size array of atomics: the
    /// memory they occupy is a compile-time constant (no growth, no
    /// allocation, no per-destination key), so the guard cannot be turned into
    /// a memory denial-of-service, and the values saturate at `u64::MAX` so
    /// they can never wrap and hide activity.  No destination is ever
    /// recorded: a counter says *how many* requests hit a rule, never *which*
    /// one.
    #[derive(Debug)]
    pub struct EgressGuard {
        denials: [AtomicU64; DenyRule::COUNT],
        failures: AtomicU64,
    }

    impl Default for EgressGuard {
        fn default() -> Self {
            Self {
                denials: [const { AtomicU64::new(0) }; DenyRule::COUNT],
                failures: AtomicU64::new(0),
            }
        }
    }

    impl EgressGuard {
        /// A guard with all counters at zero.
        pub fn new() -> Self {
            Self::default()
        }

        /// Record one denial; returns the new count for that rule.
        pub fn record_denial(&self, rule: DenyRule) -> u64 {
            bump(&self.denials[rule.index()])
        }

        /// Record one forward-path failure; returns the new count.
        pub fn record_failure(&self) -> u64 {
            bump(&self.failures)
        }

        /// A snapshot of the counters.
        pub fn snapshot(&self) -> EgressStats {
            EgressStats {
                denials: std::array::from_fn(|i| self.denials[i].load(Ordering::Relaxed)),
                failures: self.failures.load(Ordering::Relaxed),
            }
        }
    }

    /// A snapshot of the guard's counters.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct EgressStats {
        /// Denials per rule, indexed by the rule's own index.
        pub denials: [u64; DenyRule::COUNT],
        /// Forward-path failures (bind / connect / send).
        pub failures: u64,
    }

    impl EgressStats {
        /// Denials recorded for one rule.
        pub fn denials(&self, rule: DenyRule) -> u64 {
            self.denials[rule.index()]
        }

        /// Denials recorded across all rules.
        pub fn total_denials(&self) -> u64 {
            self.denials.iter().sum()
        }
    }

    /// Whether a counter value should be logged: the first hit and then every
    /// power of two.  That bounds the log stream to at most 64 lines per
    /// counter over the lifetime of the process, while a persistent problem
    /// keeps surfacing (the reporting rate halves each time it fires).
    pub fn should_log(count: u64) -> bool {
        count.is_power_of_two()
    }

    /// Saturating atomic increment: the counter never wraps.  A compare-and-
    /// swap loop rather than `fetch_update` (deprecated in newer toolchains
    /// and unnecessary here) keeps this MSRV-clean on 1.85.
    fn bump(counter: &AtomicU64) -> u64 {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(1);
            match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn v4(addr: &str, port: u16) -> SocketAddr {
            format!("{addr}:{port}")
                .parse()
                .expect("valid IPv4 destination")
        }

        fn v6(addr: &str, port: u16) -> SocketAddr {
            format!("[{addr}]:{port}")
                .parse()
                .expect("valid IPv6 destination")
        }

        /// The production policy, applied by every deployed forwarder.
        fn deny(dest: &SocketAddr) -> Option<DenyRule> {
            deny_reason(dest, EgressPolicy::DenyUnsafe)
        }

        /// Every rule has a trigger, and the rule reported is the one the
        /// address belongs to.
        #[test]
        fn every_deny_rule_denies_its_own_example() {
            let cases: &[(DenyRule, SocketAddr)] = &[
                (DenyRule::PortZero, v4("203.0.113.9", 0)),
                (DenyRule::V4Loopback, v4("127.0.0.1", 9)),
                (DenyRule::V4Loopback, v4("127.255.255.254", 9)),
                (DenyRule::V4Loopback, v4("127.1.2.3", 9)),
                (DenyRule::V6Loopback, v6("::1", 9)),
                (DenyRule::V4Unspecified, v4("0.0.0.0", 9)),
                (DenyRule::V4Unspecified, v4("0.0.0.1", 9)),
                (DenyRule::V4Unspecified, v4("0.255.255.255", 9)),
                (DenyRule::V6Unspecified, v6("::", 9)),
                (DenyRule::V4Multicast, v4("224.0.0.1", 9)),
                (DenyRule::V4Multicast, v4("239.255.255.255", 9)),
                (DenyRule::V6Multicast, v6("ff02::1", 9)),
                (DenyRule::V6Multicast, v6("ff00::", 9)),
                (DenyRule::V4Broadcast, v4("255.255.255.255", 9)),
                (DenyRule::MetadataImdsV4, v4("169.254.169.254", 80)),
                (DenyRule::MetadataAlibabaV4, v4("100.100.100.200", 80)),
                (DenyRule::MetadataAwsV6, v6("fd00:ec2::254", 80)),
                (DenyRule::MetadataGcpV6, v6("fd20:ce::254", 80)),
            ];
            for (rule, dest) in cases {
                assert_eq!(deny(dest), Some(*rule), "{dest} must be denied as {rule:?}");
            }
        }

        /// Every rule has its own counter slot: a rule can never share a
        /// counter with another rule (which would blur the operator's view)
        /// and none can fall outside the fixed array.
        #[test]
        fn rule_counters_are_unique_and_in_range() {
            let all = [
                DenyRule::PortZero,
                DenyRule::V4Loopback,
                DenyRule::V6Loopback,
                DenyRule::V4Unspecified,
                DenyRule::V6Unspecified,
                DenyRule::V4Multicast,
                DenyRule::V6Multicast,
                DenyRule::V4Broadcast,
                DenyRule::MetadataImdsV4,
                DenyRule::MetadataAlibabaV4,
                DenyRule::MetadataAwsV6,
                DenyRule::MetadataGcpV6,
            ];
            assert_eq!(all.len(), DenyRule::COUNT, "COUNT must match the rules");
            let mut seen = [false; DenyRule::COUNT];
            for rule in all {
                let idx = rule.index();
                assert!(idx < DenyRule::COUNT, "{rule:?} index out of range");
                assert!(!seen[idx], "{rule:?} shares a counter slot");
                seen[idx] = true;
            }
        }

        /// The allow boundary: private networks, ULA, CGNAT, ordinary public
        /// addresses and ordinary ports all stay reachable, so legitimate
        /// private-network and VPN routing keeps working.
        #[test]
        fn private_and_public_destinations_are_allowed() {
            for dest in [
                v4("10.0.0.1", 443),
                v4("172.16.0.1", 443),
                v4("172.31.255.254", 443),
                v4("192.168.1.1", 443),
                v4("100.64.0.1", 443),
                v4("8.8.8.8", 53),
                v4("203.0.113.7", 1234),
                v6("fd00::1", 443),
                v6("2001:db8::1", 443),
                v6("2606:4700:4700::1111", 53),
            ] {
                assert_eq!(deny(&dest), None, "{dest} must be allowed");
            }
        }

        /// The address *adjacent* to a denied metadata host is not itself
        /// denied: only the exact hosts are refused, never their containing
        /// ranges (link-local, CGNAT, ULA).
        #[test]
        fn adjacent_metadata_addresses_are_allowed() {
            for dest in [
                v4("169.254.169.253", 80),
                v4("169.254.169.255", 80),
                v4("100.100.100.199", 80),
                v4("100.100.100.201", 80),
                v6("fd00:ec2::253", 80),
                v6("fd00:ec2::255", 80),
                v6("fd20:ce::253", 80),
                v6("fd20:ce::255", 80),
            ] {
                assert_eq!(deny(&dest), None, "{dest} must be allowed");
            }
        }

        /// The address family is normalised *before* the IPv4 rules run, so
        /// an alternate encoding of the same host cannot bypass a deny.
        #[test]
        fn ipv4_embedded_forms_are_normalised() {
            // IPv4-mapped (::ffff:0:0/96).
            assert_eq!(deny(&v6("::ffff:127.0.0.1", 9)), Some(DenyRule::V4Loopback));
            assert_eq!(
                deny(&v6("::ffff:0.0.0.0", 9)),
                Some(DenyRule::V4Unspecified)
            );
            assert_eq!(
                deny(&v6("::ffff:169.254.169.254", 80)),
                Some(DenyRule::MetadataImdsV4)
            );
            assert_eq!(
                deny(&v6("::ffff:100.100.100.200", 80)),
                Some(DenyRule::MetadataAlibabaV4)
            );
            assert_eq!(
                deny(&v6("::ffff:224.0.0.1", 9)),
                Some(DenyRule::V4Multicast)
            );
            assert_eq!(
                deny(&v6("::ffff:255.255.255.255", 9)),
                Some(DenyRule::V4Broadcast)
            );
            // IPv4-compatible (::0:0/96, deprecated).
            assert_eq!(deny(&v6("::127.0.0.1", 9)), Some(DenyRule::V4Loopback));
            assert_eq!(
                deny(&v6("::169.254.169.254", 80)),
                Some(DenyRule::MetadataImdsV4)
            );
            // A mapped *allowed* host stays allowed: normalisation must not
            // over-block.
            assert_eq!(deny(&v6("::ffff:10.0.0.1", 443)), None);
            assert_eq!(deny(&v6("::ffff:8.8.8.8", 53)), None);
        }

        /// Port boundaries: 0 is refused (the OS accepts it on some hosts),
        /// 1 and the maximum port are ordinary destinations.
        #[test]
        fn port_boundaries() {
            assert_eq!(deny(&v4("203.0.113.9", 0)), Some(DenyRule::PortZero));
            assert_eq!(deny(&v6("2001:db8::1", 0)), Some(DenyRule::PortZero));
            assert_eq!(deny(&v4("203.0.113.9", 1)), None);
            assert_eq!(deny(&v4("203.0.113.9", u16::MAX)), None);
            assert_eq!(deny(&v6("2001:db8::1", u16::MAX)), None);
        }

        /// The test-only policy re-opens loopback and nothing else: the
        /// metadata, multicast, broadcast, unspecified and port-0 rules stay
        /// in force.
        #[test]
        fn allow_loopback_policy_only_relaxes_loopback() {
            let relax = |dest: &SocketAddr| deny_reason(dest, EgressPolicy::AllowLoopback);
            assert_eq!(relax(&v4("127.0.0.1", 9)), None);
            assert_eq!(relax(&v6("::1", 9)), None);
            assert_eq!(relax(&v6("::ffff:127.0.0.1", 9)), None);
            // Every other rule still applies.
            assert_eq!(
                relax(&v4("169.254.169.254", 80)),
                Some(DenyRule::MetadataImdsV4)
            );
            assert_eq!(
                relax(&v4("100.100.100.200", 80)),
                Some(DenyRule::MetadataAlibabaV4)
            );
            assert_eq!(
                relax(&v6("fd00:ec2::254", 80)),
                Some(DenyRule::MetadataAwsV6)
            );
            assert_eq!(
                relax(&v6("fd20:ce::254", 80)),
                Some(DenyRule::MetadataGcpV6)
            );
            assert_eq!(relax(&v4("224.0.0.1", 9)), Some(DenyRule::V4Multicast));
            assert_eq!(
                relax(&v4("255.255.255.255", 9)),
                Some(DenyRule::V4Broadcast)
            );
            assert_eq!(relax(&v4("0.0.0.0", 9)), Some(DenyRule::V4Unspecified));
            assert_eq!(relax(&v6("::", 9)), Some(DenyRule::V6Unspecified));
            assert_eq!(relax(&v4("203.0.113.9", 0)), Some(DenyRule::PortZero));
        }

        /// The counters are per rule, bounded in memory, and saturating: they
        /// cannot wrap into a smaller number and hide activity.
        #[test]
        fn counters_are_per_rule_bounded_and_saturating() {
            let guard = EgressGuard::default();
            for _ in 0..5 {
                guard.record_denial(DenyRule::V4Loopback);
            }
            guard.record_denial(DenyRule::MetadataImdsV4);
            guard.record_failure();

            let stats = guard.snapshot();
            assert_eq!(stats.denials(DenyRule::V4Loopback), 5);
            assert_eq!(stats.denials(DenyRule::MetadataImdsV4), 1);
            assert_eq!(stats.denials(DenyRule::V6Loopback), 0);
            assert_eq!(stats.total_denials(), 6);
            assert_eq!(stats.failures, 1);

            // Bounded memory: the guard is a fixed-size struct, so no amount
            // of traffic can make it grow.
            assert!(
                std::mem::size_of::<EgressGuard>() <= 128,
                "the guard must stay a fixed-size struct"
            );

            // Saturating: the counter never wraps.
            guard.denials[DenyRule::V4Loopback.index()].store(u64::MAX, Ordering::Relaxed);
            assert_eq!(guard.record_denial(DenyRule::V4Loopback), u64::MAX);
            assert_eq!(guard.snapshot().denials(DenyRule::V4Loopback), u64::MAX);
        }

        /// The log stream is bounded: the first hit and then every power of
        /// two, i.e. at most 64 lines per counter for the whole process
        /// lifetime.
        #[test]
        fn log_sampling_is_bounded() {
            assert!(should_log(1));
            assert!(should_log(2));
            assert!(should_log(4));
            assert!(should_log(1 << 63));
            assert!(!should_log(0));
            assert!(!should_log(3));
            assert!(!should_log(u64::MAX));
            let lines = (0..64).filter(|i| should_log(1u64 << i)).count();
            assert_eq!(lines, 64, "at most 64 log lines per counter");
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
    use crate::relay::encode_relay;
    use std::time::Duration;

    /// Compile-time caps sanity (avoids the "constant value" lint).
    const _: () = {
        assert!(PER_SESSION_CAP > 0);
        assert!(GLOBAL_CAP >= PER_SESSION_CAP);
    };

    /// A denied destination must not produce an outbound datagram: the frame
    /// is dropped before a socket exists, so nothing reaches the server's own
    /// loopback and the client gets no reply.
    #[tokio::test]
    async fn denied_destination_creates_no_socket_and_sends_nothing() {
        // A local listener stands in for a service bound to the server's
        // loopback — exactly what the guard must keep out of reach.
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let loopback = listener.local_addr().unwrap();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ServerAppCommand>(8);
        let mut fwd = Forwarder::new(false, cmd_tx);

        let frame = encode_relay(loopback, b"ssrf-probe").unwrap();
        fwd.handle([0xAA; 8], &frame).await;

        // No socket was created for the denied destination.
        assert!(
            fwd.sockets.is_empty(),
            "a denied destination must not create a pooled socket"
        );

        // Nothing was emitted towards the loopback listener.
        let mut buf = [0u8; 64];
        let received =
            tokio::time::timeout(Duration::from_millis(300), listener.recv_from(&mut buf)).await;
        assert!(
            received.is_err(),
            "a denied destination must produce no outbound datagram"
        );

        // The denial is observable to the operator through the bounded
        // counter — and only through it.
        let stats = fwd.egress_stats();
        assert_eq!(stats.denials(egress::DenyRule::V4Loopback), 1);
        assert_eq!(stats.total_denials(), 1);
        assert_eq!(stats.failures, 0, "a denial is not a forward failure");

        // The client sees nothing: no reply, so the denial is not a
        // client-visible signal.
        assert!(
            cmd_rx.try_recv().is_err(),
            "a denial must not produce a client-visible reply"
        );
    }

    /// A destination with port 0 is refused before any socket is created (the
    /// OS accepts a port-0 destination on some hosts, so the tunnel refuses
    /// it itself).
    #[tokio::test]
    async fn port_zero_destination_creates_no_socket() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<ServerAppCommand>(8);
        let mut fwd = Forwarder::new(false, cmd_tx);

        let frame = encode_relay("203.0.113.9:0".parse().unwrap(), b"probe").unwrap();
        fwd.handle([0xBB; 8], &frame).await;

        assert!(fwd.sockets.is_empty(), "port 0 must not create a socket");
        let stats = fwd.egress_stats();
        assert_eq!(stats.denials(egress::DenyRule::PortZero), 1);
    }

    /// A denied destination is silent in echo mode too: the client cannot use
    /// the echo path to probe which destinations are refused.
    #[tokio::test]
    async fn denied_destination_is_silent_in_echo_mode() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ServerAppCommand>(8);
        let mut fwd = Forwarder::new(true, cmd_tx);

        let denied = encode_relay("127.0.0.1:9".parse().unwrap(), b"probe").unwrap();
        fwd.handle([0xCC; 8], &denied).await;
        assert!(
            cmd_rx.try_recv().is_err(),
            "a denied destination must not be echoed back"
        );

        // Control: an allowed destination is echoed (the diagnostic path
        // itself is unchanged).
        let allowed = encode_relay("203.0.113.9:9".parse().unwrap(), b"probe").unwrap();
        fwd.handle([0xCC; 8], &allowed).await;
        assert!(
            cmd_rx.try_recv().is_ok(),
            "an allowed destination is still echoed in echo mode"
        );
    }

    /// Positive control: an allowed destination *does* create a pooled socket
    /// and the datagram is emitted.  This is what the denied case above
    /// contrasts with — without the guard the loopback datagram would have
    /// been delivered.
    #[tokio::test]
    async fn allowed_destination_reaches_the_destination() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let loopback = listener.local_addr().unwrap();

        let (cmd_tx, _cmd_rx) = mpsc::channel::<ServerAppCommand>(8);
        let mut fwd =
            Forwarder::new_with_policy(false, cmd_tx, egress::EgressPolicy::AllowLoopback);

        let frame = encode_relay(loopback, b"probe").unwrap();
        fwd.handle([0xEE; 8], &frame).await;

        assert_eq!(fwd.sockets.len(), 1, "an allowed destination is pooled");
        let mut buf = [0u8; 64];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .expect("the datagram must reach the destination")
            .expect("destination read");
        assert_eq!(&buf[..n], b"probe");
        assert_eq!(fwd.egress_stats().total_denials(), 0);
    }

    /// The counters are shared through the guard handle, so an operator-facing
    /// surface can poll them without holding the forwarder.
    #[tokio::test]
    async fn egress_guard_handle_reports_the_same_counters() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<ServerAppCommand>(8);
        let mut fwd = Forwarder::new(false, cmd_tx);
        let guard = fwd.egress_guard();

        let frame = encode_relay("169.254.169.254:80".parse().unwrap(), b"probe").unwrap();
        fwd.handle([0xDD; 8], &frame).await;

        assert_eq!(
            guard.snapshot().denials(egress::DenyRule::MetadataImdsV4),
            1
        );
        assert_eq!(guard.snapshot().total_denials(), 1);
    }
}
