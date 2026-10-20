# Changelog

All notable changes to Tunnel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tunnel is in **pre-release** status. `v0.1.0-alpha` was tagged as an early
snapshot (2026-08-04); this changelog documents `v0.2.0-alpha`, the first
release with the full documented decision set. Nothing here represents a
stable 1.0 release.

## [Unreleased]

### Security

- **The client session lifecycle is corrected.**  The client no longer waits
  out the M3 retransmission budget (6.25-9.22 s) before it has a session: the
  session is created at the M3 transmission, in an *unconfirmed* state, and
  confirmed by the first authenticated server packet that decrypts (D15).
  The peer is authenticated at the M2 (D12); what the confirmation gate
  covers is *key agreement*, not identity.  Consequences: the tunnel comes up
  in approximately one RTT instead of 6-9 s, application data pushed during
  establishment is buffered (bounded, TTL'd, drop-newest, reported to the
  application) instead of being dropped silently, and the client can no
  longer end up in an endless re-handshake loop with no liveness signal.
  See `docs/design/D31-client-lifecycle-and-liveness.md`.
- **Post-confirmation peer-loss detection now exists** and works with
  `--no-cover`.  A session that was confirmed and then went silent is closed
  (`Closed{PeerUnresponsive}`) after N consecutive unanswered liveness
  rounds, and the client re-establishes with a fresh sid, fresh ephemerals
  and a fresh master.  Liveness uses the **already-reserved**
  `MessageType::Handshake` (0x00) as an in-session control message: no new
  message type, no new framing, and no change to the AAD, the nonce
  construction, the key schedule, the transcript or the replay window.
- **The server reaps abandoned sessions again.**  The server's idle clock
  tracked the server's *own outbound* traffic, so with cover enabled (the
  default) it never evicted anything and the session table grew without
  bound.  It now tracks authenticated *receives* only, so a departed peer's
  session is reaped after `idle_timeout` and a live-but-quiet peer is kept
  alive by its liveness probe.
- **The data-path failure gate now matches D24 literally.**  A token is spent
  only when an AEAD decrypt *actually fails*.  A successfully decrypted
  in-session control message and a replayed-but-authentic packet no longer
  spend one: the old behaviour let an off-path attacker who captured traffic
  drain a victim's budget and get its legitimate traffic dropped for a whole
  `fail_window` at about 6 packets/s of attacker effort.  The distinction is
  **local only** -- the wire behaviour (silent drop, no reply, no error
  datagram) is unchanged, so PROTOCOL_SPEC §14's "no observable distinction"
  property is preserved.
- **A session-lifetime cap is enforced by default.**  `--lifetime-cap-secs`
  (default 86400 = 24 h, `0` = unbounded) on both the client and the server.
  When the cap fires the endpoint sends an encrypted `Close` to the peer
  before dropping the session, so the two endpoints converge on the intended
  lifetime semantics without relying on synchronised clocks.  The `Close` is
  retransmitted a bounded number of times, because a fire-and-forget `Close`
  over UDP can be lost.  The core `SessionLimits::default().lifetime_cap`
  stays `None`, so library users are unaffected.
- The server's UDP forwarding backend now applies an **egress guard**: it
  refuses destination port 0, IPv4/IPv6 loopback (including IPv4-embedded and
  IPv4-mapped representations), unspecified addresses, multicast, limited
  broadcast, and the exact cloud metadata endpoints `169.254.169.254`,
  `100.100.100.200`, `fd00:ec2::254` and `fd20:ce::254`.  RFC1918, ULA,
  CGNAT, link-local and port 53 remain reachable by design — blocking them
  would break legitimate private-network and VPN routing.  Denials are silent
  to the client and counted per rule (bounded, destination-free) for the
  operator.  This protects the **current UDP relay path only**; a future
  raw-IP/TUN forwarding path needs its own policy.
- The data-path failure gate no longer performs a linear table scan on every
  AEAD failure.  The table is bounded by `max_fail_buckets` and nothing else
  (the session id is cleartext on the wire, so the table is *not* bounded by
  the active session population); cap eviction is now O(1) and the expiry
  sweep runs at most once per `fail_window` from the 1 Hz tick.  Per-source
  token accounting is unchanged.
- The handshake source rate limiter is O(1) on the hot path: a tracked source
  no longer triggers a table scan or evicts another source's budget.  The
  roster size is now bounded (default 64, `--max-roster-size`); an
  over-limit roster is rejected, never truncated.
- `--cover-mbps` is bounded to a schedulable rate (default ceiling 470 Mbps)
  and now fails closed with a named error instead of wrapping silently in a
  release build.  The D19 default (2 Mbps, 5.12 ms) is unchanged.

### Changed

- **Eviction victim policy for the two rate tables changed** from
  least-recently-refilled to oldest-inserted.  The aggregate admission rate is
  unchanged (both policies reset the victim's budget and neither bounds the
  number of distinct sources), but *which* source is sacrificed differs.  This
  is a deliberate change, not an optimisation.
- The SHA-256 known-answer test now asserts exactly one digest (the canonical
  FIPS 180-4 / RFC 6234 value).  The previous test accepted a second value
  and described the canonical one as a platform bug; the implementation was
  always correct, the *test* was wrong.

### Fixed

- The handshake source rate limiter no longer charges a source's budget for an
  M3 that names a sid with no live pending entry: the entry is resolved
  first, then the rate gate applies (the data path's lookup-first
  ordering).  A retransmitted M3 for an already-consumed session is now
  free.
- The server's pending-handshake entry no longer expires while the client is
  actively retransmitting its M1: the cached-M2 resend refreshes the entry's
  last-seen instant.
- The client compares the session id **before** the AEAD decrypt, so a
  datagram naming another session costs no decrypt work.  The server already
  did this.
- The client now compares the session id before the decrypt on **both** roles
  and never re-creates a session for a live or previously retired session
  id: the send counter and the replay window are never reset under a
  session id that already carried a session.
- A failed client re-arm no longer terminates the client driver.  The
  re-arm is retried from the periodic tick instead.
- The project documentation no longer claims a 192-bit ChaCha20-Poly1305
  nonce (the construction uses the RFC 8439 96-bit nonce), no longer cites
  an unreachable commit for the D16 driver E2E, and no longer mis-states the
  1280-byte record as fitting a 1280-byte-MTU path (it is a UDP payload; the
  outer packet is 1308/1328 bytes).

### Documentation

- `docs/design/D31-client-lifecycle-and-liveness.md` — the client
  lifecycle, the liveness mechanism, the lifetime-cap semantics, the
  bounded outbound queue, and the compatibility analysis.
- `docs/design/D32-runtime-revocation.md` and the D27 amendment — the
  runtime roster-reload design, and the verified findings that runtime reload
  was never wired into the shipped server, that the shipped
  roster-atomicity test is vacuous with respect to the swap, and that the
  roster handle's clone is pinned to a stale generation.
- `docs/design/D33-corrected-tun-architecture.md` and the D30 amendment —
  the corrected system-wide TUN/IP data plane, with the byte and MTU
  arithmetic re-derived from the code, and the corrections to D30's
  claims.  **Research only**: no TUN code was written.
- `THREAT_MODEL.md` §13.7 — the establishment window now collapses to about
  one RTT, the M3 budget is no longer a deadline and therefore no longer an
  establishment fingerprint, the liveness probe period is the new periodic
  observable, and the server's session reaping is observable again.  The
  §13.6 lab campaign has **not** been re-run.

### Added (M10)

- Establishment-window measurement campaign recorded in THREAT_MODEL
  §13.6: the client establishment window (default config p50 7.78 s,
  p90-p10 1.42 s) and M3-budget distinguishability are accepted residual
  leakage under D22 (disposition C); the retransmit backoff schedule is
  empirically verified; session linkability remains undetermined
  (single-identity dataset, no claim made).  Documentation only — no
  protocol, code, or config change.

## [0.2.0-alpha] - 2026-08-12

First release of the v2 data plane under the accepted D18–D21 decision set:
UDP relay client + forwarding backend, fixed-rate cover traffic, pre-v2
QUIC/TLS removed, and external known-answer anchoring. Wire format and API
are not stable before 1.0.

### Added (M1 — M5)

- `pq-tunnel` unified CLI with `keygen`/`server`/`client` subcommands and
  PQTI identity provisioning (`keygen` refuses to overwrite key files without
  `--force` and refuses two outputs pointing at the same path).
- UDP relay client + forwarding server over the v2 handshake/data plane
  (M2), including the fixed-rate cover-traffic scheduler (M3).
- External known-answer vectors: RFC 8439 ChaCha20-Poly1305, RFC 5869
  HKDF-SHA256, RFC 7748 X25519, Wycheproof ML-KEM-768 and ML-DSA-65.
- Modern `fuzz_target!` harness for all 10 cargo-fuzz targets (replacing the
  legacy exported-harness style).
- Adversarial end-to-end tunnel test suite (garbage, forged handshake,
  version downgrade, AEAD tamper, replay, reordering) asserting silent drops
  and healthy post-attack round trips.

### Removed (M4)

- Legacy QUIC/TLS transport and `pq-tun` crate removed from the workspace.

### Changed (M5 — M6)

- Validation counts and design-decision record refreshed for the current
  workspace state (330 tests; D19–D21 resolved).
- Workspace is clippy-clean under `-- -D warnings`; CI enforces fmt, clippy,
  tests, fuzz build + smoke on Windows, Linux, and MSRV 1.85.

### Fixed (M6)

- Default client config could never establish against a passive server: the
  M3 retransmit budget (8 attempts ≈ 31.75–38s worst case incl. jitter)
  exceeded the session manager's default `handshake_timeout` (30s), so the
  manager always closed the handshake first. `m3_max_attempts` default
  changed 8 → 4 (≈9.3s worst case) and a regression test now asserts the
  budget fits the deadline.

### Added (M9)

- **Windows high-resolution cover clock (M9A)**: `cover_sleep` on Windows
  drives the D19 grid deadline on a raw waitable timer created with
  `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` instead of the tokio timer driver
  (which quantizes to the system timer resolution ≈15.6 ms, stretching the
  5.12 ms grid to ~64 pkt/s). The scheduler stays clock-agnostic;
  non-Windows platforms keep the tokio arm. Measured steady-state cadence:
  ~182 pkt/s (93.5% of nominal), period p50 5.5 ms / p99 6.0 ms, uniform,
  no fallback runs (see THREAT_MODEL §13.5 — no material privacy impact).
- **Recoverable transport-reset isolation (M9B)**: ICMP port-unreachable
  (Windows `WSAECONNRESET` / connection-refused) is classified as
  `is_recoverable_reset()` and surfaces as `HandshakeV2Error::TransportReset`.
  The relay socket (R1) and the server driver (R2) treat it as session-local
  `continue` with one throttled warn per episode: one dead client can no
  longer kill unrelated sessions or the server; the vanished session is
  reaped by idle eviction.

### Added (M7–M8)

- Adversarial validation campaign: ~6.9M fuzz input units across 7 targets
  (2 × 1M + 594,738 + 597,681 + 207,895 + 105,350), zero product defects.
  Two fuzz-harness-only panics fixed; no protocol or implementation defects
  found. LSan green across the 9-target matrix; MSan/UBSan remain
  toolchain-blocked (rust-src missing). See THREAT_MODEL §13.1–13.3.
- RQ2 claim-vs-adversary analysis: mathematical bounds on the cover-floor
  design (Lemma 1 deterministic grid; Lemma 2 additive leak λ·W ≥ 1 — no
  cover-rate mitigation; Lemma 3 cleartext counters make the leak
  integer-exact; Lemma 4 session count = N per tick). Decision D22:
  metadata target is **reduction, not traffic-flow anonymity** — activity,
  volume, session count, and lifecycle events remain observable residuals.
  Absorbing-emission redesign rejected for v1. See THREAT_MODEL §13.4.

### Tested (release gate)

- **D16 nonce-exhaustion full-loop driver E2E**: a running driver is hit by
  an authentic packet at `MAX_PACKET_NONCE` — the client driver closes the
  session with `Closed{NonceExhausted}`, auto-arms a fresh handshake, reaches
  Ready on the new session, and continues carrying application data in both
  directions; the server driver closes, survives, and accepts a fresh
  handshake. Closes the THREAT_MODEL §13.2 full-loop validation gap.

### Known limitations (pre-release)

- No independent implementation exists yet; interoperability is unverified.
- Cover traffic defaults to a fixed 2 Mbps pure-periodic schedule (adaptive
  shaping is future work).
- On Windows the cover grid lands at ~93.5% of the nominal rate (per-tick
  wakeup skew; measured non-material against THREAT_MODEL §13.4).
- The client emits no cover during connection establishment (D13 M3
  retransmit budget sweep, ≈9.3s worst case); establishment-phase metadata
  is the subject of milestone M10.
- Rekeying is close-and-re-establish.
- Fuzz execution is unavailable on Windows/VBS hosts (targets compile;
  execution requires an ASan-capable host).
- API and wire format are not stable before 1.0.
