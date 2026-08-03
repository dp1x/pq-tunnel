# Tunnel

Tunnel is a post-quantum, metadata-resistant secure networking protocol and
reference implementation. It is designed to keep traffic confidential against
**harvest-now-decrypt-later** adversaries (including future quantum
computers) while limiting the information leaked by traffic patterns
(metadata resistance).

This is the **first public release (v0.1.0)**. It ships the Phase-6
validated `pq-tunnel-core` data plane: a 1.5-RTT, mutual-authentication,
hybrid (ML-KEM-768 + X25519) handshake, fixed 1280-byte wire datagrams,
AEAD envelope with a 64-bit replay window, per-direction nonce accounting,
and a single-event-per-call session manager with DoS-rate limiting and
fail-secure semantics.

> **Status:** The v2 data plane is implemented and tested
> (`cargo test --workspace`: 265 tests pass). The legacy QUIC/TCP transport
> in `pq-tunnel-bin` is transitional and is being retired by the v2 path in
> Phase 6+; it is **not** the security-relevant code path.

---

## Why Tunnel

Most encrypted tunnels only hide message *contents*. Tunnel additionally
treats **metadata** — timing, packet sizes, traffic volume, session
behaviour, directionality — as a first-class security concern, and requires
**post-quantum** key establishment so captured traffic stays confidential
against future cryptanalytic advances.

Core principles (see [PROJECT_CHARTER.md](PROJECT_CHARTER.md)):

1. **HNDL resistance** — captured traffic must remain protected against
   future attackers.
2. **Metadata resistance** — traffic patterns must not leak identity or
   communication graph.
3. **Secure by default** — parameters control tradeoffs; they never silently
   redefine security guarantees.
4. **Fail securely** — a security failure closes the session; it never
   degrades to an insecure mode.

## Project layout

```
```
.
├── Cargo.toml              # workspace manifest + shared metadata
├── Cargo.lock              # pinned, reproducible dependency set
├── LICENSE-APACHE          # Apache-2.0 license
├── .cargo/                 # local build config (gitignored; see .cargo/config.toml.example)
├── build.ps1               # local convenience build wrapper (portable)
├── pq-crypto/              # PQ primitives: ML-KEM, ML-DSA, X25519, KDF/AEAD
├── pq-tunnel-core/         # protocol core: session manager, handshake v2, envelope, codec
├── pq-tun/                 # TUN/TAP device integration
├── pq-proxy/               # SOCKS5 proxy
├── pq-tunnel-bin/          # client/server binaries (transitional QUIC path)
└── fuzz/                   # cargo-fuzz targets (never-panic contract) 
```

Design and security documentation:

- [PROJECT_CHARTER.md](PROJECT_CHARTER.md) — why Tunnel exists.
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversaries and assets.
- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) — protocol requirements & architecture.
- [CRYPTO_PROFILE.md](CRYPTO_PROFILE.md) — cryptographic requirements & profile.
- [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) — accepted/rejected design choices.
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) — engineering guidance.

**Validation (v0.1.0):** 265 unit tests pass (`cargo test --workspace`),
adversarial design-review campaigns (cryptography, protocol, security) were
completed and their findings fixed, and the cargo-fuzz targets compile
(continuous fuzz execution requires an ASan-capable host; see Fuzzing below).
Detailed validation logs are kept private (not part of the public release).

## Build

Tunnel is a Rust workspace. The canonical build/test target is
`x86_64-pc-windows-msvc` (the default host `aarch64-pc-windows-msvc` cannot
compile the `aws-lc-sys` dependency from `rustls`). On a non-macOS/ARM64
host you may drop the `--target` flag.

```sh
# check + test the whole workspace
cargo test --workspace --target x86_64-pc-windows-msvc

# per-crate
cargo test -p pq-crypto       --target x86_64-pc-windows-msvc
cargo test -p pq-tunnel-core  --target x86_64-pc-windows-msvc
```

Or, on Windows, the bundled helper:

```powershell
.\build.ps1 test            # pq-crypto
.\build.ps1 test pq-tunnel-core
```

### Fuzzing

```sh
cargo +nightly fuzz build --fuzz-dir fuzz --target x86_64-pc-windows-msvc
cargo +nightly fuzz run <target> --fuzz-dir fuzz --target x86_64-pc-windows-msvc
# targets: wire_packet_from_bytes, inner_plaintext_decode, envelope_decrypt,
#          replay_window, handshake_message_decode, handshake_driver_receive,
#          session_manager_receive
```

The `cargo-fuzz` ASan runtime is not supported on this Windows host under VBS;
fuzz **execution** should be run on a Linux host. The targets still compile
and define the never-panic contract.

## Tests

- `pq-crypto`: 51 unit tests
- `pq-tunnel-core`: 214 unit tests (incl. session-manager & handshake-v2 tests)
- `pq-proxy`, `pq-tun`, `pq-tunnel-bin`: 0 unit tests (library/bin build verified)
- 7 `cargo-fuzz` targets are defined; they compile under the fuzz harness
  (execution requires an ASan-capable host — see Fuzzing above).

```sh
cargo fmt --check
cargo clippy --all-targets --target x86_64-pc-windows-msvc
cargo test --workspace --target x86_64-pc-windows-msvc
```

## Security

Tunnel is a security project; responsible disclosure is welcome.

- **Do not** open a public GitHub issue for a security vulnerability.
- Email the maintainers at **security@tunnel.email** (or open a private
  security advisory on GitHub) with a description, reproduction, and impact
  assessment. You will receive an acknowledgment within 48 hours.
- Proposed fixes are coordinated before any public disclosure.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model and
[PROJECT_CHARTER.md](PROJECT_CHARTER.md) for the security principles.

### Known issues / limitations (v0.1.0)

- The v2 handshake is validated at the unit/campaign level; **interoperability
  with other implementations is not yet verified** (no independent
  implementation exists yet).
- The transitional v1 QUIC/TLS path (`pq-tunnel-bin` binaries and the legacy
  `pq-tunnel-core` modules) performs **no server-certificate validation** (a
  `SkipServerVerification` verifier). It is a legacy bootstrap/development
  path and is **not** part of the v2 security model — the v2 raw-UDP data
  plane with mutual ML-DSA authentication is the security-relevant path.
  Do not deploy the v1 binaries against untrusted networks.
- The cover-traffic *scheduler* (Phase-7 fixed-rate pacing) is not implemented;
  only the `cover_packet` hooks exist (see [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md)).
- Rekeying is close-and-re-establish (no in-place key rotation).
- Fuzz execution is unavailable on Windows/VBS hosts (see Build above), and 4
  legacy fuzz targets still use the pre-cargo-fuzz-0.13 harness style.
- v0.1.0 is **not** API- or wire-stable; expect breaking changes before 1.0.

## Future work

- Phase 7: cover-traffic scheduler + pacing (metadata resistance at scale).
- Interoperability testing against a second implementation.
- crates.io publishing of library crates (`pq-crypto`, `pq-tunnel-core`,
  `pq-tun`, `pq-proxy`).

## Contributing

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for engineering
guidance. All submissions must pass `cargo fmt --check`,
`cargo clippy --all-targets`, and `cargo test --workspace` on
`x86_64-pc-windows-msvc`.

## License

Tunnel is licensed under Apache-2.0:

- [LICENSE-APACHE](LICENSE-APACHE) (Apache-2.0)

Apache-2.0 was chosen for permissive use plus its patent-grant clause, the
common norm for security/network infrastructure projects. Unless you
explicitly state otherwise, any contribution intentionally submitted for
inclusion is licensed under Apache-2.0. See each file's SPDX header where
present.
