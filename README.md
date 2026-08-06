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
> (`cargo test --workspace`). The v0.2.0-alpha CLI (`pq-tunnel` with
> `keygen`/`server`/`client` subcommands) provides identity provisioning
> (`keygen`), a roster-authenticated v2 server with a forwarding backend, a v2
> client exposing a local UDP relay, and a fixed-rate cover-traffic scheduler.
> The pre-v2 QUIC/TLS transport has been removed.

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
├── pq-proxy/               # SOCKS5 proxy (parked, out of the workspace — v2 rewrite pending)
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

**Validation (v0.2.0-alpha in progress):** 315 tests pass
(`cargo test --workspace`), including external known-answer vectors (RFC 8439
ChaCha20-Poly1305, RFC 5869 HKDF-SHA256, RFC 7748 X25519, Wycheproof ML-KEM-768
and ML-DSA-65 — D21) and adversarial end-to-end cases (garbage, forged
handshake, version downgrade, AEAD tamper, replay, reordering) that assert a
silent drop plus a healthy post-attack round trip.
Adversarial design-review campaigns (cryptography, protocol, security) were
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
                 --server-key server-pub.pqti
```

The v2 client exposes a local UDP relay on `127.0.0.1:51821` (loopback-only)
that forwards application datagrams into the tunnel; the server is a
forwarding backend by default (D18).

## Build

Tunnel is a Rust workspace. The canonical build/test target is
`x86_64-pc-windows-msvc` (the development host is aarch64 Windows; the
`--target` flag pins the tested toolchain). On an aarch64 Windows host, select
the x86_64 **toolchain** as well as the target:
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
fuzz **execution** should be run on a Linux host. All 7 targets use the modern
nightly harness (`fuzz_target!`) and compile under it. All targets define the
never-panic contract.

## Tests

- `pq-crypto`: 61 unit tests (incl. external known-answer vectors, D21)
- `pq-tunnel-core`: 215 unit tests (incl. session-manager & handshake-v2 tests)
- `pq-tunnel-bin`: 30 unit tests + 9 E2E integration tests (identity
  provisioning, keygen, CIDR parsing, packet length) — single `pq-tunnel`
  binary with `keygen`/`server`/`client` subcommands; the E2E suite covers the
  smoke gate (3) and the adversarial tunnel cases (6)
- `pq-proxy`: parked (v1 SOCKS5-over-QUIC, excluded from the workspace; v2
  rewrite planned — see D20); `pq-tun`: removed in M4
- 7 `cargo-fuzz` targets are defined; all use the modern `fuzz_target!`
  harness and compile under the fuzz harness (execution requires an
  ASan-capable host — see Fuzzing above).

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

- The v2 handshake is validated at the unit/campaign level and by the
  adversarial E2E suite; **interoperability
  with other implementations is not yet verified** (no independent
  implementation exists yet).
- Cover traffic defaults to a fixed 2 Mbps pure-periodic schedule; an
  operator-chosen adaptive shaper is future work (see
  [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) D19).
- Rekeying is close-and-re-establish (no in-place key rotation).
- Fuzz execution is unavailable on Windows/VBS hosts (see Build above); all 7
  fuzz targets use the modern `fuzz_target!` harness.
- v0.1.0-alpha is **not** API- or wire-stable; expect breaking changes before 1.0.

## Future work

- Adaptive cover-traffic shaper (user-selected policy; never a default).
- Interoperability testing against a second implementation.
- crates.io publishing of library crates (`pq-crypto`, `pq-tunnel-core`).

## Contributing

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for engineering
guidance. All submissions must pass `cargo fmt --check` and
`cargo test --workspace` on `x86_64-pc-windows-msvc`; `cargo clippy
--all-targets` must add **no new warnings**.

## License

Tunnel is licensed under Apache-2.0:

- [LICENSE-APACHE](LICENSE-APACHE) (Apache-2.0)

Apache-2.0 was chosen for permissive use plus its patent-grant clause, the
common norm for security/network infrastructure projects. Unless you
explicitly state otherwise, any contribution intentionally submitted for
inclusion is licensed under Apache-2.0. See each file's SPDX header where
present.
