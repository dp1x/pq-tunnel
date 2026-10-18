# `bench/` — Tunnel performance harness (TRACK I)

Opt-in, measurement-only performance harness for Tunnel v0.2.0-alpha.

**This crate is NOT a member of the main workspace.** It is its own workspace
root (same pattern as `fuzz/`), so `cargo test --workspace`, `cargo clippy
--workspace` and CI are completely unaffected — they never build or run it.

There are **no additional dependencies**: `pq-crypto`, `pq-tunnel-core` and
`std` only. No `criterion`.

## Why measurements only

Every figure this harness prints is an observation taken during the run. Nothing
is estimated, modelled or extrapolated. Sub-microsecond operations are reported
against a measured control loop so that clock-read overhead is not mistaken for
work done, and anything that genuinely cannot be measured on the host is
reported as **NOT MEASURED** with the reason.

## Build and run

The x86_64 target is **mandatory** — the ARM64 host cannot compile `aws-lc-sys`
(see AGENTS.md). On an ARM64 host the resulting binary runs under the Windows
x64 emulation layer; see §1.1 of the methodology for what that does and does not
invalidate.

```sh
cd C:\Users\Dhane\dev\tunnel

cargo build --release --manifest-path bench/Cargo.toml --target x86_64-pc-windows-msvc

# Full run (~2 min on an otherwise-idle host)
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench all
```

### Options

| Flag | Meaning |
|---|---|
| `--bench <GROUP>` | `prims`, `roster`, `handshake`, `cover`, `cadence`, `derived`, or `all` (default `all`) |
| `--repeats <N>` | run the group N times and print each pass — run-to-run repeatability on a noisy/shared host |
| `--quick` | drastically reduced iteration counts — **smoke test only**; prints `mode: QUICK (smoke — NOT publishable)` in its banner |
| `-h`, `--help` | usage |

## What each group measures

| Group | Source under test |
|---|---|
| `prims` | `pq_crypto::kem` (ML-KEM-768), `classical` (X25519), `signature` (ML-DSA-65) — each on its production public API |
| `roster` | the D12 uniform-verification loop from `ServerHandshake::complete_m1`, replicated exactly, at roster sizes 1…1024 |
| `handshake` | a full handshake through the real `ClientHandshake`/`ServerHandshake` state machines, transport faked by handing emitted `WirePacket`s to the peer |
| `cover` | `CoverScheduler::on_deadline` (virtual time + control loop), `interval_from_rate_bps` sweep, AEAD / `CipherSession::encrypt` of a 1280-byte record |
| `cadence` | the Windows `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` cover-clock wake cadence (D23/M9A), replicating `cover_clock::wait_until` |
| `derived` | arithmetic on the measured values plus constants read from the source tree, with every step printed |

## Results and methodology

See **`docs/performance/I-benchmark-methodology.md`** for the full methodology,
the raw results tables, the derived figures with explicit arithmetic, and the
verbatim raw output of each run.

## Hygiene notes

* The roster loop places the signing key **last** in the roster and uses bitwise
  `|=`, matching `complete_m1` — no early exit is possible, as D12 mandates.
* The handshake bench uses a distinct source port per iteration. This is
  required, not cosmetic: `rate_limit_burst = 16` per 10 s per source address
  admits only 8 handshakes per window from one address, which would make the
  DoS gate reject the benchmark itself. The rate limiter stays fully enabled.
* `bench/Cargo.lock` and `bench/target/` are gitignored.
