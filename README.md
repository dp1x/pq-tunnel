# Tunnel

Tunnel is a post-quantum, metadata-resistant secure networking protocol and
reference implementation. It is designed to keep traffic confidential against
**harvest-now-decrypt-later** adversaries (including future quantum
computers) while limiting the information leaked by traffic patterns
(metadata resistance).

This is the **first public release (v0.1.0-alpha)**. It ships the
validated `pq-tunnel-core` data plane: a 1.5-RTT, mutual-authentication,
hybrid (ML-KEM-768 + X25519) handshake, fixed 1280-byte wire datagrams,
AEAD envelope with a sliding 1024-bit replay window over a 64-bit sequence
counter, per-direction nonce accounting, and a single-event-per-call session
manager with DoS-rate limiting and fail-secure semantics.

> **Status:** The v2 data plane is implemented and tested
> (`cargo test --workspace`: 296 tests pass). The v0.2.0-alpha CLI
> (`pq-tunnel` with `keygen`/`server`/`client` subcommands) is under
> construction: identity provisioning (`keygen`) is complete, the v2 server and
> client paths run, and the legacy QUIC/TLS transport is transitional and will
> be retired; it is **not** the security-relevant code path.

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
├── Cargo.toml              # workspace manifest + shared metadata
├── Cargo.lock              # pinned, reproducible dependency set
├── LICENSE-APACHE          # Apache-2.0 license
├── .cargo/                 # local build config (gitignored; see .cargo/config.toml.example)
├── build.ps1               # local convenience build wrapper (portable)
├── pq-crypto/              # PQ primitives: ML-KEM, ML-DSA, X25519, KDF/AEAD
├── pq-tunnel-core/         # protocol core: session manager, handshake v2, envelope, codec
├── pq-tun/                 # TUN/TAP device integration
├── pq-proxy/               # SOCKS5 proxy
├── pq-tunnel-bin/          # single pq-tunnel binary (keygen/server/client)
└── fuzz/                   # cargo-fuzz targets (never-panic contract)
```

Design and security documentation:

- [PROJECT_CHARTER.md](PROJECT_CHARTER.md) — why Tunnel exists.
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversaries and assets.
- [PROTOCOL_SPEC.md](PROTOCOL_SPEC.md) — protocol requirements & architecture.
- [CRYPTO_PROFILE.md](CRYPTO_PROFILE.md) — cryptographic requirements & profile.
- [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) — accepted/rejected design choices.
- [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) — engineering guidance.

**Validation (v0.2.0-alpha in progress):** 296 unit tests pass
(`cargo test --workspace`),
adversarial design-review campaigns (cryptography, protocol, security) were
completed and their findings fixed, and the modern-harness cargo-fuzz targets
compile (continuous fuzz execution requires an ASan-capable host; see Fuzzing
below).
Detailed validation logs are kept private (not part of the public release).

## Usage

Identity provisioning is the first step; keys are generated on a trusted
machine and distributed out of band (the secret seed never leaves it):

```sh
# server: identity + public key, and the public key appended to a roster
pq-tunnel keygen --identity server-id.pqti \
                 --public-key server-pub.pqti \
                 --append-roster roster.pqti

# a separate client identity, plus the server's public key pinned client-side
pq-tunnel keygen --identity client-id.pqti --public-key server-pub.pqti
```

Never overwrite a key file without `--force`, and never point two outputs at
the same path (keygen refuses both). Serving is roster-authenticated:

```sh
pq-tunnel server --listen 0.0.0.0:4433 \          # v2 UDP (default)
                 --identity server-id.pqti \
                 --roster roster.pqti

pq-tunnel client --remote 192.0.2.1:4433 \        # v2 UDP (default)
                 --identity client-id.pqti \
                 --server-key server-pub.pqti --tun-addr 10.0.0.1/24
```

The v2 client is TUN-based and root/admin privileged (a local UDP relay is on
the roadmap). `--transport quic` selects the transitional v1 path — see Known
issues.

## Build

Tunnel is a Rust workspace. The canonical build/test target is
`x86_64-pc-windows-msvc` (the default host `aarch64-pc-windows-msvc` cannot
compile the `aws-lc-sys` dependency from `rustls`). On an aarch64 Windows
host, select the x86_64 **toolchain** as well as the target:
`cargo +stable-x86_64-pc-windows-msvc test --workspace --target
x86_64-pc-windows-msvc`. On a non-macOS/ARM host you may drop the `--target`
flag.

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
fuzz **execution** should be run on a Linux host. 3 of the 7 targets use the
modern nightly harness (`fuzz_target!`) and compile under it; the other 4 still
export the legacy `rust_fuzzer_test_input` symbol and are pending harness
migration. All targets define the never-panic contract.

## Tests

- `pq-crypto`: 53 unit tests
- `pq-tunnel-core`: 214 unit tests (incl. session-manager & handshake-v2 tests)
- `pq-tunnel-bin`: 29 unit tests (identity provisioning, keygen, CIDR parsing,
  packet length) — single `pq-tunnel` binary with `keygen`/`server`/`client`
  subcommands
- `pq-proxy`, `pq-tun`: 0 unit tests (library build verified)
- 7 `cargo-fuzz` targets are defined; the 3 modern (`fuzz_target!`) targets
  compile under the fuzz harness (execution requires an ASan-capable host —
  see Fuzzing above).

```sh
cargo fmt --check
cargo clippy --all-targets --target x86_64-pc-windows-msvc
cargo test --workspace --target x86_64-pc-windows-msvc
```

## Security

Tunnel is a security project; responsible disclosure is welcome.

- **Do not** open a public GitHub issue for a security vulnerability.
- Open a **private security advisory** on GitHub with a description,
  reproduction, and impact assessment.
- Proposed fixes are coordinated before any public disclosure.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model and
[PROJECT_CHARTER.md](PROJECT_CHARTER.md) for the security principles.

### Known issues / limitations (v0.2.0-alpha in progress)

- The v2 handshake is validated at the unit/campaign level; **interoperability
  with other implementations is not yet verified** (no independent
  implementation exists yet).
- The transitional v1 QUIC/TLS path (the `pq-tunnel --transport quic` legacy
  paths and the corresponding `pq-tunnel-core` modules) performs **no
  server-certificate validation** (a `SkipServerVerification` verifier). It is
  a legacy bootstrap/development path and is **not** part of the v2 security
  model — the v2 raw-UDP data plane with mutual ML-DSA authentication is the
  security-relevant path.
  Do not deploy the v1 binaries against untrusted networks.
- The cover-traffic *scheduler* (fixed-rate pacing) is not implemented;
  only the `cover_packet` hooks exist (see [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md)).
- Rekeying is close-and-re-establish (no in-place key rotation).
- Fuzz execution is unavailable on Windows/VBS hosts (see Build above), and 4
  legacy fuzz targets still use the pre-cargo-fuzz-0.13 harness style.
- v0.1.0-alpha is **not** API- or wire-stable; expect breaking changes before 1.0.

## Future work

- Cover-traffic scheduler + pacing (metadata resistance at scale).
- Interoperability testing against a second implementation.
- crates.io publishing of library crates (`pq-crypto`, `pq-tunnel-core`,
  `pq-tun`, `pq-proxy`).

## Contributing

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for engineering
guidance. All submissions must pass `cargo fmt --check` and
`cargo test --workspace` on `x86_64-pc-windows-msvc`; `cargo clippy
--all-targets` must add **no new warnings** (the legacy `HybridIdentity`
paths carry tracked deprecation warnings scheduled for removal with the v1
transport).

## License

Tunnel is licensed under Apache-2.0:

- [LICENSE-APACHE](LICENSE-APACHE) (Apache-2.0)

Apache-2.0 was chosen for permissive use plus its patent-grant clause, the
common norm for security/network infrastructure projects. Unless you
explicitly state otherwise, any contribution intentionally submitted for
inclusion is licensed under Apache-2.0. See each file's SPDX header where
present.
