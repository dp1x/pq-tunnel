# Changelog

All notable changes to Tunnel are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Tunnel is in **pre-release** status: no release has been tagged yet. Nothing in
this changelog represents a published release; treat every entry as work in
progress toward 1.0.

## [Unreleased]

### Added (M1 — M5)

- `pq-tunnel` unified CLI with `keygen`/`server`/`client` subcommands and
  PQTI identity provisioning (`keygen` refuses to overwrite key files without
  `--force` and refuses two outputs pointing at the same path).
- UDP relay client + forwarding server over the v2 handshake/data plane
  (M2), including the fixed-rate cover-traffic scheduler (M3).
- External known-answer vectors: RFC 8439 ChaCha20-Poly1305, RFC 5869
  HKDF-SHA256, RFC 7748 X25519, Wycheproof ML-KEM-768 and ML-DSA-65.
- Modern `fuzz_target!` harness for all 7 cargo-fuzz targets (replacing the
  legacy exported-harness style).
- Adversarial end-to-end tunnel test suite (garbage, forged handshake,
  version downgrade, AEAD tamper, replay, reordering) asserting silent drops
  and healthy post-attack round trips.

### Removed (M4)

- Legacy QUIC/TLS transport and `pq-tun` crate removed from the workspace.

### Changed (M5 — M6)

- Validation counts and design-decision record refreshed for the current
  workspace state (316 tests; D19–D21 resolved).
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
