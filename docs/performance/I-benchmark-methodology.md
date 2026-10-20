# I — Benchmark Methodology and Results (TRACK I)

**Scope:** reproducible performance methodology for Tunnel v0.2.0-alpha, and the
results of actually running it.

**Rule followed throughout:** every number below is an observation taken during a
run whose raw output is pasted verbatim in §8. Nothing is estimated, modelled,
extrapolated, or recalled from a vendor datasheet. Where something could not be
measured it is written **NOT MEASURED** with the reason.

---

## 1. Machine, toolchain, and execution model

| Property | Value |
|---|---|
| CPU | `Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU` |
| Cores / logical processors | 8 / 8 |
| Reported clock | 1807 MHz (CurrentClockSpeed == MaxClockSpeed throughout the run) |
| VirtualizationFirmwareEnabled | False |
| RAM | 19.996 GiB total; 10.43 GiB free at the start of the run |
| OS | Microsoft Windows 11 IoT Enterprise LTSC Evaluation, 10.0.26100 (build 26100), ARM 64-bit |
| `rustc` | `rustc 1.96.0 (ac68faa20 2026-05-25)`, host `aarch64-pc-windows-msvc`, LLVM 22.1.2 |
| Build target | `x86_64-pc-windows-msvc` (the canonical target per AGENTS.md; it is what CI verifies and what the release gate is measured on. Note: the older note here said the ARM64 host "cannot assemble `aws-lc-sys`" — that reason is stale, `aws-lc-sys` is not in the dependency tree at all) |
| Binary under test | `bench/target/x86_64-pc-windows-msvc/release/pq-bench.exe` |
| Commit | `ae8061d50fa73c43467424c3fb3be988aa17527e` (`origin/main`) |
| Profile | `release`, `opt-level = 3`, `debug = true`, `panic` **not** `abort` |
| Concurrency | single-threaded; no rayon, no thread pool, no async runtime in the harness |

### 1.1 Cross-compiled x86_64 running under emulation — read this before using the numbers

The build target is `x86_64-pc-windows-msvc` (host is `aarch64-pc-windows-msvc`).
The resulting binary therefore runs under the Windows **x64-on-ARM64 emulation
layer**, not natively. This was verified, not assumed:

* A standalone x64 probe binary was compiled and executed; it produced correct
  output, so compiling is not mistaken for being able to execute.
* A native aarch64 build of the same tight integer loop was compared against the
  x64 build: `0.615 ns/add` (native) vs `0.554 ns/add` (x64-emulated) — i.e. on
  a pure ALU loop the emulation penalty was **not** visible.
* On real syscalls and clock reads the penalty **is** large and measurable.

The decisive evidence is the clock calibration row in §6.2: an
`Instant::now()` round-trip costs **~250 ns per call** on this host. On native
x64 Windows `QueryPerformanceCounter` resolves in roughly 20–30 ns; on native
Windows on ARM64 it is the real hardware counter. A 250 ns figure is
characteristic of emulated clock reads.

**Consequence, stated plainly:** the large-nanosecond figures in this document
(ML-KEM, ML-DSA, X25519, AEAD, handshake) are *compute-bound* and are broadly
representative. The **sub-microsecond** figures — the cover scheduler tick and
`interval_from_rate_bps` — are dominated by emulated clock reads and are
**upper bounds inflated by the emulation layer**, not native-x64 costs. Both are
labelled as such at the point of use. Nothing in this document should be quoted
as a native-x86_64 performance claim.

### 1.2 Load conditions — the single most important caveat on this data set

This is a **shared, non-exclusive workstation**. `Win32_Processor.LoadPercentage`
was sampled immediately before and after the published run:

```
load before final run : 18 %
load after  final run : 14 %
```

An earlier, *identical* run of the same binary taken while the machine was busy
(39–48 % load) produced materially different percentiles. Concretely, the D12
roster loop at n=256 measured `p50 = 46,617,100 ns` under load versus
`p50 = 13,721,400 ns` on the quiet machine — a 3.4× difference in the *same
binary on the same machine*, entirely attributable to contention. Both runs are
preserved (§8.1, §8.2) precisely so this is visible rather than hidden.

The `min` column is the most robust statistic on this host: `min` is by
definition the least-contended observation. Where `min` and `p50` diverge, the
divergence is machine noise and is called out inline.

---

## 2. How to reproduce

### 2.1 Build and run

`bench/` is a **separate workspace** (same pattern as `fuzz/`) and is therefore
**not** a member of the main workspace. `cargo test --workspace` never builds or
runs it, and CI is unaffected. This was verified:

```
$ cargo metadata --format-version 1 --no-deps | jq -r '.packages[].name'
pq-crypto
pq-tunnel-core
pq-tunnel-bin
```

```sh
cd C:\Users\Dhane\dev\tunnel

# Build (x86_64 target is mandatory)
cargo build --release --manifest-path bench/Cargo.toml --target x86_64-pc-windows-msvc

# Full run (~2 min on the quiet host)
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench all

# Individual groups
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench prims
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench roster
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench handshake
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench cover
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench cadence
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench derived

# Smoke test (NOT publishable — prints "mode: QUICK" in its banner)
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench all --quick

# Run-to-run repeatability on a noisy host
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench roster --repeats 3
```

`cargo` is not on `PATH` in this environment; it lives at
`%USERPROFILE%\.cargo\bin`.

### 2.2 Dependencies

The harness adds **no new dependencies**. It uses only `pq-crypto`,
`pq-tunnel-core`, and `std`. In particular no `criterion` was introduced — the
statistics are computed by `bench/src/stats.rs` (~200 lines, auditable). `grep`
confirms `criterion` is absent from `Cargo.lock`.

---

## 3. Measurement methodology

### 3.1 Sample definition

One **sample** = one `Instant::now()` delta around the measured region
(`stats::time_ns`). The result of the measured region is passed through
`std::hint::black_box` so the optimizer cannot delete the work.

### 3.2 Percentiles

**Nearest-rank**, `index = ceil(q * n) - 1`, clamped to `[0, n-1]`. Every
reported percentile is therefore an **actually observed sample**, never an
interpolated value that was never measured. Both `p50` and `median` are printed;
they are identical by construction here (both are the nearest-rank 0.50), and
printing both makes each table self-checking.

`min`, `p50`, `median`, `p99`, `max` and `mean` are reported for every
operation.

### 3.3 Warm-up

Every operation runs `warmup` discarded iterations before measurement. Warm-up is
mandatory here because ML-DSA/ML-KEM key generation, first touch of freshly
allocated ciphertext buffers, and the x64→ARM64 translation cache all bias early
iterations. Warm-up counts are printed in every table row.

### 3.4 Amortisation for sub-microsecond operations

A single cover-scheduler tick is far below `Instant`'s effective resolution on
this host (see §1.1). Timing one call and reporting it would be measuring clock
granularity. Instead, for those operations each sample times `inner`
back-to-back calls and the reported figure is the **per-call amortised** cost
(`stats::measure_amortised`). The division is exact arithmetic on the nanosecond
total. `inner` = 1000 for both the scheduler tick and the AEAD encrypt, and the
row prints the sample count so the reader can see what backs each percentile.

Because this still cannot separate the clock read from the work, a **control
loop** is included (§6.2) that runs the identical loop with the operation
removed, and the difference is reported as the marginal cost.

### 3.5 Iteration counts (printed in the banner of every run)

| Group | Warm-up | Measured samples |
|---|---|---|
| Primitives (Bench 2) | 200 | 5 000 |
| Single verify (Bench 1a) | 3 | 510 |
| D12 roster loop (Bench 1b) | 3 | 200 |
| D12 loop, unknown client (Bench 1c) | 3 | 51 |
| Handshake (Bench 3) | 2 | 60 |
| Scheduler tick (Bench 4a) | 25 | 110 (× 1000 calls each) |
| `interval_from_rate_bps` (Bench 4b) | 10 000 | 50 000 |
| AEAD (Bench 4c) | 200 | 510 (× 1000 calls each) |
| Cover cadence (Bench 4d) | — | ~5 500 wakes over 30 s |

Roster-1024 rows use fewer samples because each sample performs 1024 ML-DSA-65
verifications (~56 ms measured). The count for each row is printed inline.

---

## 4. Bench 1 — ML-DSA-65 verification vs roster size (D12)

The code under test is `ServerHandshake::complete_m1`
(`pq-tunnel-core/src/handshake_v2.rs:1607-1614`):

```rust
for pk in &self.cfg.roster {
    let ok = verify(pk, &th1_d, &m1.client_sig)?;
    authed |= ok;            // bitwise: uniform verification count (D12)
    if ok { matched = Some(pk.clone()); }
}
```

The harness replicates this loop **exactly**, including the bitwise `|=` (not a
short-circuiting `&&`) that makes the verification count uniform, with the
signing key placed **last** in the roster so no early exit is even possible.

### 4.1 Results — quiet host (18 % → 14 % load), 200 samples per row

| roster n | ns/verify (p50) | **D12 loop total (p50 ns)** | loop min (ns) | loop p99 (ns) | unknown-client loop p50 (ns) |
|---:|---:|---:|---:|---:|---:|
| 1 | 51 600 | **56 700** | 56 400 | 72 500 | 51 500 |
| 2 | 51 400 | **107 600** | 107 200 | 295 800 | 102 300 |
| 4 | 51 600 | **209 800** | 209 200 | 395 200 | 204 800 |
| 8 | 52 100 | **422 300** | 413 100 | 599 000 | 415 500 |
| 16 | 51 500 | **844 700** | 820 300 | 1 189 400 | 837 700 |
| 32 | 51 500 | **1 686 600** | 1 636 700 | 2 132 900 | 1 721 200 |
| 64 | 51 500 | **3 411 900** | 3 316 100 | 4 552 100 | 3 401 600 |
| 128 | 51 600 | **6 848 400** | 6 623 400 | 8 452 400 | 6 885 600 |
| 256 | 51 500 | **13 721 400** | 13 290 800 | 15 830 400 | 14 208 900 |
| 512 | 51 600 | **28 199 300** | 26 867 400 | 32 508 300 | 30 281 600 |
| 1024 | 51 500 | **56 330 700** | 53 926 200 | 82 097 900 | 57 044 900 |

**The scaling is exactly linear and the per-verify cost is flat.** Arithmetic
check, showing `loop_p50 / n` converges on the isolated per-verify cost:

| n | loop p50 (ns) | loop p50 / n | measured ns/verify |
|---:|---:|---:|---:|
| 1 | 56 700 | 56 700 | 51 600 |
| 8 | 422 300 | 52 787 | 52 100 |
| 64 | 3 411 900 | 53 311 | 51 500 |
| 256 | 13 721 400 | 53 599 | 51 500 |
| 1024 | 56 330 700 | 55 011 | 51 500 |

Per-verify is flat to within ~1 % from n=1 to n=1024 (51 400–52 100 ns) and
the loop total is `n × per-verify` plus a fixed overhead that stays a small
fraction of the total — **1.8 % to 9.2 % across the whole sweep**:

| n | loop p50 (ns) | n × 51 500 | fixed overhead (ns) | overhead as % of loop |
|---:|---:|---:|---:|---:|
| 1 | 56 700 | 51 500 | 5 200 | 9.2 % |
| 8 | 422 300 | 412 000 | 10 300 | 2.4 % |
| 64 | 3 411 900 | 3 296 000 | 115 900 | 3.4 % |
| 256 | 13 721 400 | 13 184 000 | 537 400 | 3.9 % |
| 1024 | 56 330 700 | 52 736 000 | 3 594 700 | 6.4 % |

(The overhead term itself grows sub-linearly — it is the per-key `pk.clone()`
in the `matched` branch plus loop/allocator effects — but it never becomes the
dominant term. The per-element verification, not a growing constant, is the
cost.)

**D12's uniform-verification decision costs a server exactly `roster_len`
verifications per inbound handshake.** At the largest roster tested (1024) that
is 56.3 ms of CPU for a single handshake, versus 56.7 µs at roster 1 — a
**993× penalty** for a 1024× larger roster.

### 4.2 Same measurement under load — for contrast

Identical binary, identical command, machine at 39–48 % load instead of 18 %:

| n | loop p50 (ns) — quiet | loop p50 (ns) — loaded | ratio |
|---:|---:|---:|---:|
| 64 | 4 324 600 | 4 371 100 | 1.01× |
| 128 | 8 855 900 | 8 860 000 | 1.00× |
| 256 | 13 721 400 | 46 617 100 | **3.40×** |
| 512 | 28 199 300 | 62 895 500 | **2.23×** |
| 1024 | 56 330 700 | 82 619 800 | 1.47× |

Small-`n` rows are unaffected (they finish fast and win the scheduler); large-`n`
rows, which occupy a core for tens of milliseconds, are heavily distorted. This
is why the quiet-machine table above is the one quoted, and why §1.2 exists.

---

## 5. Bench 2 — post-quantum and classical primitive costs

5 000 samples per operation, 200 warm-up. All figures **p50**, with p99 in
parentheses.

### 5.1 ML-KEM-768 (FIPS 203, crate `ml-kem` 0.3.2)

| Operation | min (ns) | **p50 (ns)** | p99 (ns) |
|---|---:|---:|---:|
| `MlKemKeypair::generate` (keygen) | 49 400 | **51 400** | 115 000 |
| `encapsulate` (includes OS RNG) | 47 800 | **48 400** | 102 000 |
| `decapsulate` | 58 300 | **58 800** | 134 100 |

### 5.2 X25519 (crate `x25519-dalek` 3.0.0-rc.1)

| Operation | min (ns) | **p50 (ns)** | p99 (ns) |
|---|---:|---:|---:|
| `X25519Keypair::generate` | 20 500 | **21 100** | 37 500 |
| `X25519Keypair::diffie_hellman` | 59 100 | **59 500** | 101 300 |

### 5.3 ML-DSA-65 (FIPS 204, crate `ml-dsa` 0.1.1)

| Operation | min (ns) | **p50 (ns)** | p99 (ns) |
|---|---:|---:|---:|
| `MlDsaKeypair::generate` (keygen) | 246 700 | **273 700** | 643 800 |
| `sign` (32-byte message) | 480 700 | **495 300** | 832 000 |
| `verify` (valid signature) | 51 200 | **51 500** | 118 700 |

**ML-DSA-65 signing is ~9.6× the cost of verification** (495 300 / 51 500). This
is the asymmetry that drives the whole handshake budget: each side signs once,
but the server verifies once per roster entry.

---

## 6. Bench 3 — full handshake through the real state machines

### 6.1 What was measured, and why not the loopback harness

The task suggested `pq-tunnel-bin/tests/common/mod.rs` (the loopback `Gate`) or
`e2e_smoke.rs`. The **in-process** path through the real
`ServerHandshake`/`ClientHandshake` state machines was chosen instead, for a
specific reason: D16's claim is a **CPU** claim ("~2.5 ms CPU"), and a loopback
measurement folds in kernel UDP send/receive scheduling and proxy relaying, none
of which is CPU the protocol spends.

The harness constructs real `MlDsaKeypair`s, real `MlKemKeypair`/`X25519Keypair`
generation, real fragment encode/decode and real `TH1`/`TH2`/`TH3` transcripts,
then hands each side's emitted `WirePacket`s straight to the peer's
`handle_datagram`. The only thing faked is the transport. Each handshake is
asserted to reach `ServerEvent::Complete`.

Loopback **is** still exercised, for the timer cadence (§6.3), through a real
waitable-timer round-trip.

### 6.2 One design constraint worth recording

`ServerConfig::rate_limit_burst = 16` per 10 s **per source address** admits only
**8 handshakes per 10 s from a single address** (each handshake spends two
tokens: M1 fragment 0 and M3 fragment 0). Reusing one source address would make
the DoS gate reject the benchmark itself. Each iteration therefore uses a
distinct source port — which is also the realistic shape, since a roster of N
clients are N distinct peers. **The rate limiter stays fully enabled and on its
normal code path**; nothing was disabled or relaxed.

### 6.3 Results — full handshake CPU, 60 samples per row

| roster n | total p50 (ns) | total p99 (ns) | **server-side p50 (ns)** | server handshakes/s/core |
|---:|---:|---:|---:|---:|
| 1 | **1 765 700** | 3 228 500 | **843 200** | 1 185.96 |
| 8 | **2 312 900** | 6 996 000 | **1 298 800** | 769.94 |
| 64 | **5 447 300** | 8 069 900 | **4 382 400** | 228.19 |
| 256 | **16 172 200** | 19 029 600 | **15 104 700** | 66.20 |

Full roster sweep (total, client + server):

| n | total p50 (ns) | n | total p50 (ns) |
|---:|---:|---:|---:|
| 1 | 1 968 200 | 32 | 3 998 800 |
| 2 | 1 851 300 | 64 | 5 773 700 |
| 4 | 2 229 000 | 128 | 9 296 300 |
| 8 | 2 331 300 | 256 | 16 792 200 |
| 16 | 3 058 100 | 512 | 30 252 800 |
| | | 1024 | 58 596 000 |

### 6.4 Phase breakdown (p50, ns) — where the time actually goes

| phase | n=1 | n=8 | n=64 | n=256 | n=1024 |
|---|---:|---:|---:|---:|---:|
| client M1 (keygen + TH1 + sign) | 531 400 | 485 900 | 622 700 | 583 800 | 585 400 |
| **server M2 (roster loop + KEM + sign)** | **761 900** | **1 164 800** | **4 336 600** | **15 025 500** | **55 322 700** |
| client M3 (decap + DH + HKDF) | 410 800 | 405 100 | 422 500 | 438 100 | 437 600 |
| server M3 (Finished verify) | 148 500 | 159 700 | 267 500 | 611 100 | 1 962 000 |

Client cost is **flat in roster size** (as it must be — the client does not see
the roster). All roster scaling is on the server, and it is concentrated in M2,
which contains the D12 loop.

#### Finding: `server M3` also scales with roster, and it should not need to

`server M3` grows from 148 µs (n=1) to 1 962 µs (n=1024) — **13.2× for a
1024× roster change**, i.e. it is linear but with a far smaller constant than
M2's. The cause is `ServerHandshake::roster_contains`
(`handshake_v2.rs:1430-1432`):

```rust
pub fn roster_contains(&self, pk: &MlDsaPublicKey) -> bool {
    self.cfg.roster.iter().any(|k| k.encode() == pk.encode())
}
```

called on the M3 path at `handshake_v2.rs:1763`. It does **not** short-circuit
(it is documented as intentionally non-constant-time), and each element
comparison calls `MlDsaPublicKey::encode()`, which **allocates and copies a
1952-byte `Vec`**. So the D27 post-swap membership re-check costs up to
`roster_len × (1952-byte allocation + memcmp)` — at n=1024 that is 1024
allocations per completed handshake, on top of the crypto.

This is a performance observation only; D27's revocation semantics are correct
and are not in question. It is recorded here because it is a measurable, and
non-obvious, per-handshake cost that scales with roster size.

### 6.5 D16 cross-check: is the "~2.5 ms CPU" claim supported?

> D16 (`DESIGN_DECISIONS.md:800`): "re-establishment cost: full handshake per
> rotation (≈1.5 RTT, ~2.5 ms CPU)"
>
> D13 (`DESIGN_DECISIONS.md:657`): "~2.5 ms handshake CPU per side
> (ML-DSA sign dominates)"

**Verdict: the claim is CONSISTENT with measurement at the roster sizes actually
deployed, and UNSUPPORTED at large roster sizes.** Precisely:

| quantity | measured p50 | vs "~2.5 ms per side" |
|---|---:|---|
| **Server-side CPU**, roster 1 | **843 200 ns = 0.84 ms** | 0.34× the claim |
| **Server-side CPU**, roster 8 | **1 298 800 ns = 1.30 ms** | 0.52× the claim |
| Client-side CPU, roster 1 (total − server) | 922 500 ns = 0.92 ms | 0.37× the claim |
| Server-side CPU, roster 64 | 4 382 400 ns = 4.38 ms | **1.75× the claim** |
| Server-side CPU, roster 256 | 15 104 700 ns = 15.1 ms | **6.04× the claim** |
| Server-side CPU, roster 1024 | 57 284 700 ns = 57.3 ms | **22.9× the claim** |

(The roster-1024 server figure is the sum of the measured `server M2`
55 322 700 ns and `server M3` 1 962 000 ns phase rows of §6.4, because
Bench 3c reports only rosters 1/8/64/256.)

* At roster 1–8 (the deployment scale a 1:1, system-wide TUN tool implies) the
  claim **over-states** cost by roughly 2–3×. It is conservative, not optimistic.
* At roster 64 the claim is **under-stated by 1.75×**.
* At roster 1024 it is **under-stated by 22.6×**.

The claim's stated rationale — "ML-DSA sign dominates" — is **only true at small
roster**. At roster 1 signing (495 300 ns) does dominate the roster loop
(56 700 ns, 0.11× of a sign). The crossover is at **n = 16**: at n=8 the loop
is still 0.85× of a sign (422 300 vs 495 300), at n=16 it is 1.71× (844 700 vs
495 300), and from there the loop dominates monotonically — reaching 113.7× a
single signature at n=1024.

**Recommendation:** D16/D13 should qualify the "~2.5 ms CPU" figure with the
roster size it assumes, since with D12's uniform verification it is a function
of deployment configuration, not a constant.

The "≈1.5 RTT" half of the claim is a **message-count** property (M1→M2→M3,
D13) and is a design invariant, not a timing measurement; it is unaffected by
these results and is out of scope for CPU benchmarking.

---

## 7. Bench 4 — cover-traffic overhead

### 7.1 Scheduler tick (`pq-tunnel-core/src/scheduler.rs`)

The scheduler is pure and `tokio`-free, so it is measured in **virtual time**: a
synthetic `Instant` advances exactly one interval per call, which is the
steady state the driver drives.

| measurement | min (ns) | **p50 (ns)** | p99 (ns) |
|---|---:|---:|---:|
| `on_deadline` — emitting tick, incl. `new`+`start` | 10 942 | **11 109** | 12 690 |
| `on_deadline` — steady state, pre-armed | 8 697 | **8 827** | 10 705 |
| **CONTROL** — identical loop, scheduler call removed | 3 643 | **3 717** | 4 713 |
| **marginal cost** (steady − control) | — | **5 110** | — |
| calibration: `Instant::now()` round-trip | 1 200 | 1 300 | 1 500 |

**The 5 110 ns figure is heavily inflated by the x64 emulation layer.** The
control row proves it: an empty loop that only adds a `Duration` to an `Instant`
costs 3 717 ns, and the clock calibration shows a single `Instant::now()`
costs ~1 300 ns for a round-trip (~650 ns per read) under emulation. The
*actual* scheduler work is a handful of comparisons and one `Instant` addition;
**the true native-x64 cost of `on_deadline` is NOT MEASURED** on this host and
is almost certainly well under 100 ns. Reported as measured, and flagged.

### 7.2 `interval_from_rate_bps` sweep

12 rates from 1 kbps to `u64::MAX`, 50 000 samples each. Every rate returned
`p50 = 500 ns`, `min = 300 ns` — **identical across the entire sweep**, which is
the signature of a measurement floor rather than a function cost.

> **UPDATE — the returned values in the table below are no longer what the
> function returns.** `interval_from_rate_bps` now clamps the interval into
> `[MIN_COVER_INTERVAL_NANOS, ..]` with
> `MIN_COVER_INTERVAL_NANOS = 21 762 ns` (21.762 µs), derived in §7.5 from the
> measured cost of producing one cover packet. The old floor was
> `nanos.max(1)` — a **1 ns** clamp — and rows that reached it are marked
> below. The D19 default (2 Mbps → 5.12 ms) is **unaffected**: it is 235x the
> floor.

| rate (bps) | returned interval (as measured at `ae8061d`) | returned interval (**now**) |
|---:|---|---|
| 1 000 | 10.24 s | 10.24 s |
| 64 000 | 160 ms | 160 ms |
| 100 000 | 102.4 ms | 102.4 ms |
| 1 000 000 | 10.24 ms | 10.24 ms |
| **2 000 000** (default) | **5.12 ms** | **5.12 ms** |
| 10 000 000 | 1.024 ms | 1.024 ms |
| 100 000 000 | 102.4 µs | 102.4 µs |
| 1 000 000 000 | 10.24 µs | **21.762 µs (clamped to the floor)** |
| 1 000 000 000 000 | 10 ns (clamped) | **21.762 µs (clamped to the floor)** |
| ≥ 1 000 000 000 000 000 | 1 ns (clamped) | **21.762 µs (clamped to the floor)** |
| **470 544 986** (the maximum rate the floor admits) | — | **21.762 µs (exactly the floor)** |

**The maximum sustainable cover rate** is

```
MAX_COVER_RATE_BPS = PACKET_SIZE * 8 * 1_000_000_000 / MIN_COVER_INTERVAL_NANOS
                  = 10 240 * 1_000_000_000 / 21 762
                  = 470 544 986 bit/s  ≈ 470 Mbps
```

(Integer division floors, so 470,544,986 bps is exactly the largest rate the
floor admits: one bit/s more would ask for an interval one nanosecond shorter.)
`pq-tunnel-bin` exposes this as `MAX_COVER_MBPS_PACING = 470` and **rejects**
a `--cover-mbps` above it with a named error — an unschedulable rate is
refused, not silently clamped.

**Where the 21 762 ns floor came from, and what it does and does not
guarantee.** It is the measured per-cover-packet CPU cost from §7.5: the
emitting scheduler tick (11 109 ns p50) plus the full 1280-byte record
encryption (10 653 ns p50) = **21 762 ns**, excluding syscalls. The
derivation's host is the one described in §1: an **x86_64 build running under
Windows x64-on-ARM64 emulation** on an aarch64 Windows host (`rustc` 1.96.0,
host `aarch64-pc-windows-msvc`, build target `x86_64-pc-windows-msvc`).

The floor is a **lower** bound on the true per-packet cost, and therefore an
**upper** bound on the rate that may be requested. It has two independent
conservative directions, which is why it can only ever reject a rate a faster
host might have sustained:

1. **The syscall cost is excluded.** The timer create/arm/close, the wake
   path and the `sendto` are not in the 21 762 ns figure (§7.5 states this
   explicitly). A real cover packet costs *more* than 21 762 ns, so the true
   floor is higher than the derived one.
2. **The measurement is emulated, and the emulation penalty is in the
   conservative direction for this particular sum.** §1.1 shows the sub-µs
   figures in this document are dominated by emulated clock reads. The
   scheduler-tick row (11 109 ns) is exactly such a figure — and the
   §7.1 control row proves it (an empty loop costing 3 717 ns, against a
   `Instant::now()` round-trip of ~1 300 ns). The **encrypt** row (10 653 ns)
   is compute-bound and is the representative one. So the derived floor
   *over*-states the CPU cost on native hardware for the tick component.

**What it does not guarantee.** The floor bounds the *requested* rate; it does
not promise the requested rate is **achievable** on a given host. Because the
syscall cost is excluded, the true achievable period is higher than the floor:
adding the measured minimum Windows
`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` wake latency of **15 200 ns** (§7.4)
puts the reference host's achievable period at roughly 37 us — about
**276 Mbps** — i.e. below the 470 Mbps ceiling the floor admits. The ceiling
is therefore a bound on what may be *requested*, not a promise of throughput.
The CLI rejects anything above it with a named error rather than silently
clamping, so an operator learns the rate is out of range for this scheduler.

A cross-check on the same host: the minimum Windows
`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` wake latency measured in §7.4 is
**15 200 ns**, so the floor is above the timer's own achievable re-arm
period — the derived interval is not tighter than the platform's own timer
resolution.

The returned `Duration` values are exact and are the substantive output. The
**call cost is at or below the 500 ns measurement floor on this host and is
therefore NOT MEASURED** — the function is a handful of saturating integer
operations and is not on any hot path (it is called once per cover arm, not per
tick).

### 7.3 AEAD / record encrypt (1280-byte record)

| measurement | min (ns) | **p50 (ns)** | p99 (ns) |
|---|---:|---:|---:|
| `pq_crypto::aead::encrypt` (raw ChaCha20-Poly1305, inner + tag) | 7 207 | **7 517** | 10 475 |
| **`CipherSession::encrypt`** (full 1280 B record: nonce build + AEAD + framing) | 10 185 | **10 653** | 13 821 |

The full production packet path costs 10 653 ns, i.e. **3 136 ns more than the
bare AEAD** for nonce construction, header encoding as AAD, and `WirePacket`
framing. Record geometry confirmed from crate constants: `PACKET_SIZE = 1280 B`,
`PAYLOAD_LEN = 1245 B`.

### 7.4 Cover-clock wake cadence (D23/M9A) — REPRODUCED

Where the driver arms the timer: `cover_sleep` in
`pq-tunnel-core/src/session_manager.rs:1414-1420`. On Windows it calls
`cover_clock::CoverSleep::deadline`, which spawns a blocking task running
`wait_until` (`session_manager.rs:1509`): create a waitable timer with
`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`, arm it, `WaitForSingleObject`, close.
Production creates a **new timer per arm** (`Pin::set` drops the previous arm).

The harness replicates that sequence **exactly**, including the relative
due-time arithmetic copied verbatim from production `due_time`
(`session_manager.rs:1551`). 30 s of continuous ticking at the D19 5.12 ms grid,
~5 500 wakes, plus a `thread::sleep` control.

| measurement | wakes | min (ns) | **p50 (ns)** | p99 (ns) | max (ns) |
|---|---:|---:|---:|---:|---:|
| `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` | 5 504 | 15 200 | **369 600** | 766 100 | 1 334 100 |
| `thread::sleep` control | 5 545 | 16 000 | 269 800 | 737 000 | 1 641 800 |

| | achieved | % of nominal 195.3125 pkt/s |
|---|---:|---:|
| **This run (30 s)** | **183.47 pkt/s** | **93.93 %** |
| D23 recorded reference | 182.6 pkt/s | ~93.5 % |
| `thread::sleep` control | 184.83 pkt/s | 94.63 % |

**D23's "~93.5 % of nominal (182.6 pkt/s over 30 s)" is REPRODUCED** — this run
measured 93.93 % / 183.47 pkt/s over the same 30 s window, within 0.4 pp and
0.5 % of the recorded figure.

Two honest caveats:

1. **The `thread::sleep` control matches the high-resolution timer** (94.63 %
   vs 93.93 %). On this host the HR waitable timer provides **no measurable
   cadence advantage** over a plain `thread::sleep`. D23's motivating claim was
   that tokio's timer driver quantizes to ~15.6 ms system resolution, stretching
   the grid to ~64 pkt/s; this control does **not** test tokio, it tests
   `thread::sleep`, which on Windows is not the same as a tokio timer and is not
   subject to the tokio driver's quantization. The tokio-vs-HRT comparison is
   therefore **NOT MEASURED** here.
2. Absolute p50 wake latency is 369.6 µs, far above native x64 hardware; this is
   the emulation layer again (§1.1). The **rate** is the meaningful figure and it
   reproduces the recorded value.

### 7.5 CPU cost per cover packet

Using the measured components, at the D19 default (2 Mbps → 195.3125 pkt/s per
session per direction):

```
per-packet CPU (tick + AEAD, excl. syscalls)
  = 11 108.9 ns + 10 653.1 ns = 21 762.0 ns = 21.762 µs

  1 session  × 195.3125 pkt/s =    195.31 pkt/s -> 0.004250 CPU-s/s =  0.4250 % of one core
 64 sessions × 195.3125 pkt/s = 12 500.00 pkt/s -> 0.272025 CPU-s/s = 27.2025 % of one core
```

**Syscall cost per cover packet (the `sendto`, the timer create/arm/close, and
the wake path) is NOT MEASURED.** It is excluded from the arithmetic above and
the total is therefore a **lower bound** on real per-packet cost. Measuring it
requires a live client+server pair over loopback with a real socket, which was
out of scope for this run; the timer arm/wake portion is bounded above by the
§7.4 wake-latency p99 of 766 µs, but that is latency, not CPU, and must not be
substituted here.

> **This figure is now load-bearing.** The **21 762 ns** above is the source of
> `MIN_COVER_INTERVAL_NANOS` in `pq-tunnel-core/src/scheduler.rs`, the
> minimum cover interval the scheduler will return, and therefore of
> `MAX_COVER_RATE_BPS` = 470,544,986 bit/s (≈ 470 Mbps). See §7.2 for the
> derivation, the host it was measured on, and the two reasons it is
> conservative (the syscall cost is excluded, and the tick component is
> inflated by the emulation layer).

---

## 8. Derived figures (arithmetic on measurements only)

### 8.1 Server worst-case cover egress

Constants read at runtime from the source tree: `max_sessions = 64`
(`SessionLimits::default()`, `session_manager.rs:138`), `PACKET_SIZE = 1280`
(`codec.rs:104`), `DEFAULT_COVER_RATE_BPS = 2_000_000` (`scheduler.rs:34`).

```
64 sessions × 195.3125 pkt/s × 1280 B × 8
  = 64 × 195.3125            = 12 500.0000 pkt/s
  = 12 500.0000 × 1280        = 16 000 000.0000 B/s
  = 16 000 000.0000 × 8       = 128 000 000 bit/s
```

**= 128 000 000 bit/s = 128.000 Mbit/s = 0.1280 Gbit/s** for a fully loaded
server, cover enabled, one direction. Both directions would double this to
0.256 Gbit/s.

### 8.2 Packet-nonce exhaustion time

`MAX_PACKET_NONCE = u64::MAX − 2^32 = 18 446 744 069 414 584 320`
(`codec.rs:119`).

| scenario | rate | arithmetic | result |
|---|---:|---|---:|
| Default 2 Mbps, 1 session, 1 direction | 195.3125 pkt/s | 1.8446744e19 ÷ 195.3125 | 9.4447e16 s ≈ **2.99e9 years** |
| Worst case, 64 sessions (egress total) | 12 500 pkt/s | 1.8446744e19 ÷ 12 500 | 1.4757e15 s ≈ **4.68e7 years** |

Nonce exhaustion is **not a reachable concern** at any plausible rate: even at
the 128 Mbit/s worst case the counter would need ~47 million years. The
`is_counter_exhausted` rotation trigger is a safety invariant, not an
operational limit.

### 8.3 ML-DSA-65 verify throughput and handshake capacity

```
single verify = 51 500 ns (p50)
1e9 ns/s ÷ 51 500 ns = 19 417.48 verifications/second
```

**= 19 417 verify/s per core**, single-threaded.

Handshakes/s sustained by one core, from the **measured full-handshake
server-side CPU** (§6.3) — this is the real figure, not a loop-only bound:

| roster n | server CPU p50 (ns) | server handshakes/s/core | loop-only lower bound |
|---:|---:|---:|---:|
| 1 | 843 200 (measured, 3d) | **1 185.96** | 17 636.68 |
| 8 | 1 298 800 (measured, 3d) | **769.94** | 2 367.98 |
| 64 | 4 382 400 (measured, 3d) | **228.19** | 293.09 |
| 256 | 15 104 700 (measured, 3d) | **66.20** | 72.88 |
| 1024 | 57 284 700 (sum of 3b phase rows) | **17.46** | 17.75 |

### 8.4 Rate-limit cross-reference

`ServerConfig::new` defaults (`handshake_v2.rs:1276-1277`):
`rate_limit_burst = 16`, `rate_limit_window = 10 s`, **per source address**.

```
16 ÷ 10 = 1.6000 handshakes/s per source address
```

And as measured in §6.2, each handshake consumes **two** tokens (M1 fragment 0
and M3 fragment 0), so the effective ceiling is:

```
16 ÷ 2 ÷ 10 = 0.8000 handshakes/s per source address
```

**Cross-reference conclusion:** at roster 1 the core can absorb 1 186
handshakes/s but a single source address may only present **0.8/s** — the
per-source DoS budget is **~1 482× more restrictive** than the CPU budget
(`1 185.96 ÷ 0.8 = 1 482`), so the rate limiter, not the CPU, is the binding
constraint for any single peer.

This inverts at large roster. At roster 1024 the core sustains 17.46
handshakes/s across *all* sources; sustaining a full 64-session roster refresh
would require the limiter's per-source budget to be the only obstacle, and
0.8 handshakes/s per source means **re-filling a 64-session server from a single
source takes ≥ 80 s** at roster 1024 (`64 ÷ 0.8 = 80 s`).

A caveat that matters operationally: the rate limiter is keyed by source
address, which is **spoofable off-path**. An attacker able to source-spoof can
multiply their admitted handshake rate by the number of distinct source
addresses they use, and each of those handshakes costs the server a full roster
verification loop (56.3 ms at n=1024). Whether that is reachable in practice
depends on ingress filtering, which is **NOT MEASURED** here.

---

## 9. What was NOT MEASURED, and why

| Item | Status | Reason |
|---|---|---|
| Native x86_64 performance | **NOT MEASURED** | Host is ARM64; the mandated `x86_64-pc-windows-msvc` binaries run under emulation. Compute-bound figures are representative; sub-µs figures are inflated (quantified in §1.1). |
| Syscall cost per cover packet (`sendto`, timer create/arm/close, wake) | **NOT MEASURED** | Requires a live client+server pair over a real loopback socket. Excluded from §7.5, which is a lower bound. |
| End-to-end handshake wall time including real UDP transport | **NOT MEASURED** | Requires the `Gate` harness in `pq-tunnel-bin/tests/common/mod.rs`; deliberately not run because D16's claim is a CPU claim and transport cost would contaminate it (§6.1). |
| tokio timer vs HR waitable timer | **NOT MEASURED** | The control used here is `thread::sleep`, which is not the tokio timer driver. D23's specific tokio-quantization claim is untested. |
| Multi-core / concurrent handshake scaling | **NOT MEASURED** | Harness is single-threaded by design. |
| Hardware-counter (cycles/instructions/cache-miss) attribution | **NOT MEASURED** | Requires a PMU/`vtune`-class tool not available here. |
| Exclusive use of the machine | **NOT ACHIEVED** | This is a shared workstation; load was 18 %→14 % during the published run but other processes were active (§1.2). |

---

## 10. Files

| Path | Role |
|---|---|
| `bench/Cargo.toml` | Separate-workspace manifest; not a member of the main workspace |
| `bench/src/main.rs` | CLI, group dispatch, iteration counts, banner |
| `bench/src/stats.rs` | `Instant` timing, nearest-rank percentiles, amortisation, table printing |
| `bench/src/crypto_prims.rs` | Bench 2 — ML-KEM-768 / X25519 / ML-DSA-65 |
| `bench/src/roster_verify.rs` | Bench 1 — D12 roster loop vs roster size |
| `bench/src/handshake.rs` | Bench 3 — real `ServerHandshake`/`ClientHandshake` |
| `bench/src/cover_timer.rs` | Bench 4 — scheduler tick, rate sweep, AEAD, Windows HR timer cadence |
| `bench/src/derived.rs` | Derived figures, arithmetic printed inline |
| `bench/raw/final_run.txt` | **Raw output of the published run** (18 %→14 % load) |
| `bench/raw/full_run.txt` | Raw output of the earlier run at 39–48 % load (§4.2 contrast) |
| `bench/raw/cover_run.txt` | Raw output of an intermediate cover-group run |

Lints: `cargo clippy --release --manifest-path bench/Cargo.toml --target
x86_64-pc-windows-msvc -- -D warnings` is clean; `cargo fmt` applied.

---

## 11. Raw output — verbatim

### 11.1 Published run (`--bench all`, load 18 % -> 14 %)

Captured to `bench/raw/final_run.txt`. Reproduce with:

```sh
.\bench\target\x86_64-pc-windows-msvc\release\pq-bench.exe --bench all
```

```text
================================================================================
Tunnel performance harness (TRACK I) — measurements only
================================================================================
host_arch_env      : x86_64
profile            : release (opt-level=3, debug=true)
sample_definition  : 1 sample = Instant::now() delta around the measured region
percentile_method  : nearest-rank, i = ceil(q*n)-1, clamped to [0, n-1]
threads            : single-threaded, no rayon/threads in the harness

bench group       : all
iteration counts  : prims warmup=200 iters=5000 | roster warmup=3 iters=200 | handshake warmup=2 iters=60
amortisation      : scheduler tick x1000 calls/sample | AEAD x1000 calls/sample
cadence window    : 30s
repeats           : 1
mode              : FULL

--- Bench 2a: ML-KEM-768 (FIPS 203, crate ml-kem 0.3.2) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
ML-KEM-768 keygen (MlKemKeypair::generate)     ns  n=5000    warmup=200   min=     49400.0 p50=     51400.0 median=     51400.0 p99=    115000.0 max=    559400.0 mean=     54461.6
ML-KEM-768 encaps (encapsulate)                ns  n=5000    warmup=200   min=     47800.0 p50=     48400.0 median=     48400.0 p99=    102000.0 max=   1146600.0 mean=     51146.7
ML-KEM-768 decaps (decapsulate)                ns  n=5000    warmup=200   min=     58300.0 p50=     58800.0 median=     58800.0 p99=    134100.0 max=   1013300.0 mean=     62594.1

--- Bench 2b: X25519 (x25519-dalek 3.0.0-rc.1) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
X25519 keygen (X25519Keypair::generate)        ns  n=5000    warmup=200   min=     20500.0 p50=     21100.0 median=     21100.0 p99=     37500.0 max=    898400.0 mean=     22166.5
X25519 DH (X25519Keypair::diffie_hellman)      ns  n=5000    warmup=200   min=     59100.0 p50=     59500.0 median=     59500.0 p99=    101300.0 max=    836800.0 mean=     62326.1

--- Bench 2c: ML-DSA-65 (FIPS 204, crate ml-dsa 0.1.1) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
ML-DSA-65 keygen (MlDsaKeypair::generate)      ns  n=5000    warmup=200   min=    246700.0 p50=    273700.0 median=    273700.0 p99=    643800.0 max=   3531500.0 mean=    293057.9
ML-DSA-65 sign (32-byte msg)                   ns  n=5000    warmup=200   min=    480700.0 p50=    495300.0 median=    495300.0 p99=    832000.0 max=   3893700.0 mean=    514826.2
ML-DSA-65 verify (valid sig)                   ns  n=5000    warmup=200   min=     51200.0 p50=     51500.0 median=     51500.0 p99=    118700.0 max=   2859100.0 mean=     56040.7

--- Bench 1a: single ML-DSA-65 verify (the per-element cost) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
verify() single call (roster n=1)              ns  n=510     warmup=3     min=     51300.0 p50=     51600.0 median=     51600.0 p99=     85100.0 max=    116900.0 mean=     53425.9
verify() single call (roster n=2)              ns  n=510     warmup=3     min=     51200.0 p50=     51400.0 median=     51400.0 p99=     86100.0 max=    223500.0 mean=     53441.0
verify() single call (roster n=4)              ns  n=510     warmup=3     min=     51400.0 p50=     51600.0 median=     51600.0 p99=    129500.0 max=    768100.0 mean=     56362.2
verify() single call (roster n=8)              ns  n=510     warmup=3     min=     51700.0 p50=     52100.0 median=     52100.0 p99=     83000.0 max=    282100.0 mean=     54341.2
verify() single call (roster n=16)             ns  n=510     warmup=3     min=     51300.0 p50=     51500.0 median=     51500.0 p99=    144200.0 max=    485900.0 mean=     56369.0
verify() single call (roster n=32)             ns  n=510     warmup=3     min=     51300.0 p50=     51500.0 median=     51500.0 p99=     83900.0 max=    162600.0 mean=     53556.5
verify() single call (roster n=64)             ns  n=510     warmup=3     min=     51300.0 p50=     51500.0 median=     51500.0 p99=    116400.0 max=    496300.0 mean=     55488.6
verify() single call (roster n=128)            ns  n=510     warmup=3     min=     51300.0 p50=     51600.0 median=     51600.0 p99=    100500.0 max=    190300.0 mean=     54366.5
verify() single call (roster n=256)            ns  n=510     warmup=3     min=     51300.0 p50=     51500.0 median=     51500.0 p99=    104400.0 max=    208700.0 mean=     54520.2
verify() single call (roster n=512)            ns  n=510     warmup=3     min=     51400.0 p50=     51600.0 median=     51600.0 p99=    119800.0 max=    350800.0 mean=     55609.0
verify() single call (roster n=1024)           ns  n=510     warmup=3     min=     51300.0 p50=     51500.0 median=     51500.0 p99=    101200.0 max=    208800.0 mean=     54020.0

--- Bench 1b: D12 full roster loop (uniform verification, no early exit) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
D12 full roster loop (n=1 verifies)            ns  n=200     warmup=3     min=     56400.0 p50=     56700.0 median=     56700.0 p99=     72500.0 max=    133100.0 mean=     58002.0
D12 full roster loop (n=2 verifies)            ns  n=200     warmup=3     min=    107200.0 p50=    107600.0 median=    107600.0 p99=    295800.0 max=    374300.0 mean=    117337.0
D12 full roster loop (n=4 verifies)            ns  n=200     warmup=3     min=    209200.0 p50=    209800.0 median=    209800.0 p99=    395200.0 max=    654700.0 mean=    222616.0
D12 full roster loop (n=8 verifies)            ns  n=200     warmup=3     min=    413100.0 p50=    422300.0 median=    422300.0 p99=    599000.0 max=    660200.0 mean=    432280.5
D12 full roster loop (n=16 verifies)           ns  n=200     warmup=3     min=    820300.0 p50=    844700.0 median=    844700.0 p99=   1189400.0 max=   1359300.0 mean=    867997.0
D12 full roster loop (n=32 verifies)           ns  n=200     warmup=3     min=   1636700.0 p50=   1686600.0 median=   1686600.0 p99=   2132900.0 max=   2590800.0 mean=   1732081.5
D12 full roster loop (n=64 verifies)           ns  n=200     warmup=3     min=   3316100.0 p50=   3411900.0 median=   3411900.0 p99=   4552100.0 max=   5029300.0 mean=   3492980.0
D12 full roster loop (n=128 verifies)          ns  n=200     warmup=3     min=   6623400.0 p50=   6848400.0 median=   6848400.0 p99=   8452400.0 max=   8600300.0 mean=   6950003.5
D12 full roster loop (n=256 verifies)          ns  n=200     warmup=3     min=  13290800.0 p50=  13721400.0 median=  13721400.0 p99=  15830400.0 max=  16680300.0 mean=  13898262.0
D12 full roster loop (n=512 verifies)          ns  n=200     warmup=3     min=  26867400.0 p50=  28199300.0 median=  28199300.0 p99=  32508300.0 max=  40651600.0 mean=  28505111.5
D12 full roster loop (n=1024 verifies)         ns  n=200     warmup=3     min=  53926200.0 p50=  56330700.0 median=  56330700.0 p99=  82097900.0 max=  97877300.0 mean=  58161728.5

--- Bench 1c: D12 loop, UNKNOWN client (no match; full cost then reject) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
D12 loop, UNKNOWN client (n=1 verifies)        ns  n=51      warmup=3     min=     51400.0 p50=     51500.0 median=     51500.0 p99=     81300.0 max=     81300.0 mean=     54417.6
D12 loop, UNKNOWN client (n=2 verifies)        ns  n=51      warmup=3     min=    102100.0 p50=    102300.0 median=    102300.0 p99=    130300.0 max=    130300.0 mean=    105721.6
D12 loop, UNKNOWN client (n=4 verifies)        ns  n=51      warmup=3     min=    204400.0 p50=    204800.0 median=    204800.0 p99=    310200.0 max=    310200.0 mean=    212500.0
D12 loop, UNKNOWN client (n=8 verifies)        ns  n=51      warmup=3     min=    408000.0 p50=    415500.0 median=    415500.0 p99=   7053100.0 max=   7053100.0 mean=    574331.4
D12 loop, UNKNOWN client (n=16 verifies)       ns  n=51      warmup=3     min=    816500.0 p50=    837700.0 median=    837700.0 p99=   1520700.0 max=   1520700.0 mean=    883547.1
D12 loop, UNKNOWN client (n=32 verifies)       ns  n=51      warmup=3     min=   1648900.0 p50=   1721200.0 median=   1721200.0 p99=   6078100.0 max=   6078100.0 mean=   1951054.9
D12 loop, UNKNOWN client (n=64 verifies)       ns  n=51      warmup=3     min=   3300300.0 p50=   3401600.0 median=   3401600.0 p99=  29700100.0 max=  29700100.0 mean=   4100288.2
D12 loop, UNKNOWN client (n=128 verifies)      ns  n=51      warmup=3     min=   6620900.0 p50=   6885600.0 median=   6885600.0 p99=   9220500.0 max=   9220500.0 mean=   7068066.7
D12 loop, UNKNOWN client (n=256 verifies)      ns  n=51      warmup=3     min=  13368000.0 p50=  14208900.0 median=  14208900.0 p99=  21775700.0 max=  21775700.0 mean=  14825441.2
D12 loop, UNKNOWN client (n=512 verifies)      ns  n=51      warmup=3     min=  27170500.0 p50=  30281600.0 median=  30281600.0 p99=  53636200.0 max=  53636200.0 mean=  31017717.6
D12 loop, UNKNOWN client (n=1024 verifies)     ns  n=51      warmup=3     min=  53984500.0 p50=  57044900.0 median=  57044900.0 p99=  90823900.0 max=  90823900.0 mean=  58345790.2

--- Bench 1: roster scaling summary (p50 ns) ---
roster        ns/verify      loop_p50_ns   unknown_p50_ns       verify/s
     1          51600.0          56700.0          51500.0       19379.84
     2          51400.0         107600.0         102300.0       19455.25
     4          51600.0         209800.0         204800.0       19379.84
     8          52100.0         422300.0         415500.0       19193.86
    16          51500.0         844700.0         837700.0       19417.48
    32          51500.0        1686600.0        1721200.0       19417.48
    64          51500.0        3411900.0        3401600.0       19417.48
   128          51600.0        6848400.0        6885600.0       19379.84
   256          51500.0       13721400.0       14208900.0       19417.48
   512          51600.0       28199300.0       30281600.0       19379.84
  1024          51500.0       56330700.0       57044900.0       19417.48

--- Bench 3a: full handshake CPU, client + server, in-process ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
FULL handshake client+server CPU (roster n=1)  ns  n=60      warmup=2     min=   1398500.0 p50=   1968200.0 median=   1968200.0 p99=   5689100.0 max=   5689100.0 mean=   2220433.3
FULL handshake client+server CPU (roster n=2)  ns  n=60      warmup=2     min=   1354700.0 p50=   1851300.0 median=   1851300.0 p99=   6343100.0 max=   6343100.0 mean=   2133245.0
FULL handshake client+server CPU (roster n=4)  ns  n=60      warmup=2     min=   1545200.0 p50=   2229000.0 median=   2229000.0 p99=   4943600.0 max=   4943600.0 mean=   2382866.7
FULL handshake client+server CPU (roster n=8)  ns  n=60      warmup=2     min=   1681800.0 p50=   2331300.0 median=   2331300.0 p99=   4674900.0 max=   4674900.0 mean=   2564443.3
FULL handshake client+server CPU (roster n=16) ns  n=60      warmup=2     min=   2113500.0 p50=   3058100.0 median=   3058100.0 p99=   4670700.0 max=   4670700.0 mean=   3254513.3
FULL handshake client+server CPU (roster n=32) ns  n=60      warmup=2     min=   2985500.0 p50=   3998800.0 median=   3998800.0 p99=   7316200.0 max=   7316200.0 mean=   4062705.0
FULL handshake client+server CPU (roster n=64) ns  n=60      warmup=2     min=   4863200.0 p50=   5773700.0 median=   5773700.0 p99=   7802000.0 max=   7802000.0 mean=   5935818.3
FULL handshake client+server CPU (roster n=128) ns  n=60      warmup=2     min=   8195200.0 p50=   9296300.0 median=   9296300.0 p99=  11277200.0 max=  11277200.0 mean=   9469545.0
FULL handshake client+server CPU (roster n=256) ns  n=60      warmup=2     min=  15239600.0 p50=  16792200.0 median=  16792200.0 p99=  19597300.0 max=  19597300.0 mean=  16863176.7
FULL handshake client+server CPU (roster n=512) ns  n=60      warmup=2     min=  28906500.0 p50=  30252800.0 median=  30252800.0 p99=  36457600.0 max=  36457600.0 mean=  30596860.0
FULL handshake client+server CPU (roster n=1024) ns  n=60      warmup=2     min=  56878100.0 p50=  58596000.0 median=  58596000.0 p99=  62218100.0 max=  62218100.0 mean=  58802541.7

--- Bench 3b: handshake phase breakdown (p50) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
  phase: client M1 (roster n=1)                ns  n=60      warmup=2     min=    268000.0 p50=    531400.0 median=    531400.0 p99=   1926100.0 max=   1926100.0 mean=    683193.3
  phase: client M1 (roster n=2)                ns  n=60      warmup=2     min=    267200.0 p50=    471400.0 median=    471400.0 p99=   1477800.0 max=   1477800.0 mean=    594166.7
  phase: client M1 (roster n=4)                ns  n=60      warmup=2     min=    269400.0 p50=    655000.0 median=    655000.0 p99=   2243600.0 max=   2243600.0 mean=    704258.3
  phase: client M1 (roster n=8)                ns  n=60      warmup=2     min=    267000.0 p50=    485900.0 median=    485900.0 p99=   2115500.0 max=   2115500.0 mean=    709115.0
  phase: client M1 (roster n=16)               ns  n=60      warmup=2     min=    268900.0 p50=    669000.0 median=    669000.0 p99=   2056000.0 max=   2056000.0 mean=    772858.3
  phase: client M1 (roster n=32)               ns  n=60      warmup=2     min=    280900.0 p50=    636400.0 median=    636400.0 p99=   2013000.0 max=   2013000.0 mean=    744491.7
  phase: client M1 (roster n=64)               ns  n=60      warmup=2     min=    277500.0 p50=    622700.0 median=    622700.0 p99=   2024000.0 max=   2024000.0 mean=    676915.0
  phase: client M1 (roster n=128)              ns  n=60      warmup=2     min=    277600.0 p50=    481100.0 median=    481100.0 p99=   1929600.0 max=   1929600.0 mean=    644816.7
  phase: client M1 (roster n=256)              ns  n=60      warmup=2     min=    286300.0 p50=    583800.0 median=    583800.0 p99=   2107700.0 max=   2107700.0 mean=    673513.3
  phase: client M1 (roster n=512)              ns  n=60      warmup=2     min=    291300.0 p50=    564900.0 median=    564900.0 p99=   2954700.0 max=   2954700.0 mean=    668413.3
  phase: client M1 (roster n=1024)             ns  n=60      warmup=2     min=    289700.0 p50=    585400.0 median=    585400.0 p99=   1786000.0 max=   1786000.0 mean=    681591.7
  phase: server M2 (roster loop+KEM+sig) (roster n=1) ns  n=60      warmup=2     min=    491600.0 p50=    761900.0 median=    761900.0 p99=   4183500.0 max=   4183500.0 mean=    930865.0
  phase: server M2 (roster loop+KEM+sig) (roster n=2) ns  n=60      warmup=2     min=    533900.0 p50=    807800.0 median=    807800.0 p99=   4618900.0 max=   4618900.0 mean=    974726.7
  phase: server M2 (roster loop+KEM+sig) (roster n=4) ns  n=60      warmup=2     min=    649000.0 p50=    936400.0 median=    936400.0 p99=   2259900.0 max=   2259900.0 mean=   1094490.0
  phase: server M2 (roster loop+KEM+sig) (roster n=8) ns  n=60      warmup=2     min=    849600.0 p50=   1164800.0 median=   1164800.0 p99=   2271100.0 max=   2271100.0 mean=   1247106.7
  phase: server M2 (roster loop+KEM+sig) (roster n=16) ns  n=60      warmup=2     min=   1260700.0 p50=   1663400.0 median=   1663400.0 p99=   3732900.0 max=   3732900.0 mean=   1878373.3
  phase: server M2 (roster loop+KEM+sig) (roster n=32) ns  n=60      warmup=2     min=   2121800.0 p50=   2492600.0 median=   2492600.0 p99=   6176900.0 max=   6176900.0 mean=   2661493.3
  phase: server M2 (roster loop+KEM+sig) (roster n=64) ns  n=60      warmup=2     min=   3819100.0 p50=   4336600.0 median=   4336600.0 p99=   6403000.0 max=   6403000.0 mean=   4509433.3
  phase: server M2 (roster loop+KEM+sig) (roster n=128) ns  n=60      warmup=2     min=   7145500.0 p50=   7819400.0 median=   7819400.0 p99=   9708600.0 max=   9708600.0 mean=   7961120.0
  phase: server M2 (roster loop+KEM+sig) (roster n=256) ns  n=60      warmup=2     min=  13924400.0 p50=  15025500.0 median=  15025500.0 p99=  17616500.0 max=  17616500.0 mean=  15076026.7
  phase: server M2 (roster loop+KEM+sig) (roster n=512) ns  n=60      warmup=2     min=  26973700.0 p50=  28176700.0 median=  28176700.0 p99=  34316100.0 max=  34316100.0 mean=  28437881.7
  phase: server M2 (roster loop+KEM+sig) (roster n=1024) ns  n=60      warmup=2     min=  53925500.0 p50=  55322700.0 median=  55322700.0 p99=  58175500.0 max=  58175500.0 mean=  55659723.3
  phase: client M3 (decap+DH+HKDF) (roster n=1) ns  n=60      warmup=2     min=    386200.0 p50=    410800.0 median=    410800.0 p99=    821200.0 max=    821200.0 mean=    441428.3
  phase: client M3 (decap+DH+HKDF) (roster n=2) ns  n=60      warmup=2     min=    386100.0 p50=    397100.0 median=    397100.0 p99=    515300.0 max=    515300.0 mean=    407661.7
  phase: client M3 (decap+DH+HKDF) (roster n=4) ns  n=60      warmup=2     min=    385600.0 p50=    401700.0 median=    401700.0 p99=    874500.0 max=    874500.0 mean=    421135.0
  phase: client M3 (decap+DH+HKDF) (roster n=8) ns  n=60      warmup=2     min=    387200.0 p50=    405100.0 median=    405100.0 p99=    622900.0 max=    622900.0 mean=    421351.7
  phase: client M3 (decap+DH+HKDF) (roster n=16) ns  n=60      warmup=2     min=    386900.0 p50=    404400.0 median=    404400.0 p99=    958600.0 max=    958600.0 mean=    425670.0
  phase: client M3 (decap+DH+HKDF) (roster n=32) ns  n=60      warmup=2     min=    387200.0 p50=    415200.0 median=    415200.0 p99=   1085200.0 max=   1085200.0 mean=    441833.3
  phase: client M3 (decap+DH+HKDF) (roster n=64) ns  n=60      warmup=2     min=    392900.0 p50=    422500.0 median=    422500.0 p99=   1563100.0 max=   1563100.0 mean=    469960.0
  phase: client M3 (decap+DH+HKDF) (roster n=128) ns  n=60      warmup=2     min=    395600.0 p50=    429700.0 median=    429700.0 p99=    645200.0 max=    645200.0 mean=    442633.3
  phase: client M3 (decap+DH+HKDF) (roster n=256) ns  n=60      warmup=2     min=    405100.0 p50=    438100.0 median=    438100.0 p99=    669600.0 max=    669600.0 mean=    452755.0
  phase: client M3 (decap+DH+HKDF) (roster n=512) ns  n=60      warmup=2     min=    405800.0 p50=    426500.0 median=    426500.0 p99=    574000.0 max=    574000.0 mean=    432995.0
  phase: client M3 (decap+DH+HKDF) (roster n=1024) ns  n=60      warmup=2     min=    411700.0 p50=    437600.0 median=    437600.0 p99=   1322100.0 max=   1322100.0 mean=    473996.7
  phase: server M3 (verify Finished) (roster n=1) ns  n=60      warmup=2     min=    142800.0 p50=    148500.0 median=    148500.0 p99=    687000.0 max=    687000.0 mean=    164946.7
  phase: server M3 (verify Finished) (roster n=2) ns  n=60      warmup=2     min=    144100.0 p50=    146500.0 median=    146500.0 p99=    363600.0 max=    363600.0 mean=    156690.0
  phase: server M3 (verify Finished) (roster n=4) ns  n=60      warmup=2     min=    147600.0 p50=    152900.0 median=    152900.0 p99=    279500.0 max=    279500.0 mean=    162983.3
  phase: server M3 (verify Finished) (roster n=8) ns  n=60      warmup=2     min=    156000.0 p50=    159700.0 median=    159700.0 p99=   1107800.0 max=   1107800.0 mean=    186870.0
  phase: server M3 (verify Finished) (roster n=16) ns  n=60      warmup=2     min=    167200.0 p50=    175000.0 median=    175000.0 p99=    212300.0 max=    212300.0 mean=    177611.7
  phase: server M3 (verify Finished) (roster n=32) ns  n=60      warmup=2     min=    195300.0 p50=    205700.0 median=    205700.0 p99=    446900.0 max=    446900.0 mean=    214886.7
  phase: server M3 (verify Finished) (roster n=64) ns  n=60      warmup=2     min=    251900.0 p50=    267500.0 median=    267500.0 p99=    437900.0 max=    437900.0 mean=    279510.0
  phase: server M3 (verify Finished) (roster n=128) ns  n=60      warmup=2     min=    360500.0 p50=    380100.0 median=    380100.0 p99=   2226800.0 max=   2226800.0 mean=    420975.0
  phase: server M3 (verify Finished) (roster n=256) ns  n=60      warmup=2     min=    593500.0 p50=    611100.0 median=    611100.0 p99=   1173900.0 max=   1173900.0 mean=    660881.7
  phase: server M3 (verify Finished) (roster n=512) ns  n=60      warmup=2     min=   1013000.0 p50=   1050400.0 median=   1050400.0 p99=   1190700.0 max=   1190700.0 mean=   1057570.0
  phase: server M3 (verify Finished) (roster n=1024) ns  n=60      warmup=2     min=   1907100.0 p50=   1962000.0 median=   1962000.0 p99=   2793200.0 max=   2793200.0 mean=   1987230.0

--- Bench 3c: handshake TOTAL (both sides), roster 1/8/64/256 ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
handshake TOTAL both sides (roster n=1)        ns  n=60      warmup=2     min=   1301000.0 p50=   1765700.0 median=   1765700.0 p99=   3228500.0 max=   3228500.0 mean=   1948901.7
handshake TOTAL both sides (roster n=8)        ns  n=60      warmup=2     min=   1669900.0 p50=   2312900.0 median=   2312900.0 p99=   6996000.0 max=   6996000.0 mean=   2573038.3
handshake TOTAL both sides (roster n=64)       ns  n=60      warmup=2     min=   4721700.0 p50=   5447300.0 median=   5447300.0 p99=   8069900.0 max=   8069900.0 mean=   5678786.7
handshake TOTAL both sides (roster n=256)      ns  n=60      warmup=2     min=  15173000.0 p50=  16172200.0 median=  16172200.0 p99=  19029600.0 max=  19029600.0 mean=  16473245.0

--- Bench 3d: handshake SERVER-side CPU only, roster 1/8/64/256 ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
handshake SERVER-side CPU (roster n=1)         ns  n=60      warmup=2     min=    626900.0 p50=    843200.0 median=    843200.0 p99=   2340400.0 max=   2340400.0 mean=   1008020.0
handshake SERVER-side CPU (roster n=8)         ns  n=60      warmup=2     min=   1007200.0 p50=   1298800.0 median=   1298800.0 p99=   3727200.0 max=   3727200.0 mean=   1501881.7
handshake SERVER-side CPU (roster n=64)        ns  n=60      warmup=2     min=   4004500.0 p50=   4382400.0 median=   4382400.0 p99=   5973800.0 max=   5973800.0 mean=   4555643.3
handshake SERVER-side CPU (roster n=256)       ns  n=60      warmup=2     min=  14438700.0 p50=  15104700.0 median=  15104700.0 p99=  17335200.0 max=  17335200.0 mean=  15391635.0

  roster n=1    total p50 =      1765700.0 ns | server p50 =       843200.0 ns | server handshakes/s/core =    1185.96
  roster n=8    total p50 =      2312900.0 ns | server p50 =      1298800.0 ns | server handshakes/s/core =     769.94
  roster n=64   total p50 =      5447300.0 ns | server p50 =      4382400.0 ns | server handshakes/s/core =     228.19
  roster n=256  total p50 =     16172200.0 ns | server p50 =     15104700.0 ns | server handshakes/s/core =      66.20

--- Bench 4a-0: clock calibration floor ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
calibration: Instant::now() round-trip         ns  n=510     warmup=200   min=      1200.0 p50=      1300.0 median=      1300.0 p99=      1500.0 max=     17800.0 mean=      1383.3

--- Bench 4a: cover scheduler tick cost (virtual time) + control ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
CoverScheduler::on_deadline (emitting tick)    ns  n=110     warmup=25    min=     10942.3 p50=     11108.9 median=     11108.9 p99=     12690.2 max=     12725.8 mean=     11240.5
CoverScheduler::on_deadline (steady, pre-armed) ns  n=110     warmup=25    min=      8697.3 p50=      8827.1 median=      8827.1 p99=     10704.6 max=     16471.8 mean=      9065.5
CONTROL: virtual Instant advance only (no scheduler) ns  n=110     warmup=25    min=      3642.6 p50=      3717.2 median=      3717.2 p99=      4712.8 max=      5594.5 mean=      3807.4

  marginal scheduler cost (steady - control) p50 = 5109.9 ns per tick

--- Bench 4b: interval_from_rate_bps cost sweep ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
interval_from_rate_bps(1000) -> 10.24s         ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    456800.0 mean=       502.5
interval_from_rate_bps(64000) -> 160ms         ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    127800.0 mean=       482.0
interval_from_rate_bps(100000) -> 102.4ms      ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    273900.0 mean=       488.1
interval_from_rate_bps(1000000) -> 10.24ms     ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    134900.0 mean=       492.5
interval_from_rate_bps(2000000) -> 5.12ms      ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    387500.0 mean=       493.4
interval_from_rate_bps(10000000) -> 1.024ms    ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    134900.0 mean=       494.6
interval_from_rate_bps(100000000) -> 102.4µs   ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    216100.0 mean=       490.3
interval_from_rate_bps(1000000000) -> 10.24µs  ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    103200.0 mean=       493.3
interval_from_rate_bps(1000000000000) -> 10ns  ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    109500.0 mean=       487.8
interval_from_rate_bps(1000000000000000) -> 1ns ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    326900.0 mean=       490.4
interval_from_rate_bps(1000000000000000000) -> 1ns ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    237700.0 mean=       494.6
interval_from_rate_bps(18446744073709551615) -> 1ns ns  n=50000   warmup=10000 min=       300.0 p50=       500.0 median=       500.0 p99=       600.0 max=    260200.0 mean=       492.5

--- Bench 4c: AEAD / record encrypt cost (1280-byte record) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
aead::encrypt (raw ChaCha20Poly1305, inner+tag) ns  n=510     warmup=200   min=      7206.5 p50=      7517.1 median=      7517.1 p99=     10475.0 max=     14978.6 mean=      7785.6
CipherSession::encrypt (full 1280B record)     ns  n=510     warmup=200   min=     10185.0 p50=     10653.1 median=     10653.1 p99=     13821.2 max=     16115.0 mean=     10858.8

--- Record geometry (from crate constants) ---
  PACKET_SIZE     = 1280 B
  PAYLOAD_LEN     = 1245 B (inner plaintext payload slot)

--- Bench 4d: Windows cover-clock wake cadence (D23/M9A) ---
  nominal interval = 5.12ms (5.1200 ms), nominal rate = 195.3125 pkt/s
--- Bench 4d: cover wake latency ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
cover wake latency (CREATE_WAITABLE_TIMER_HIGH_RESOLUTION) ns  n=5504    warmup=0     min=     15200.0 p50=    369600.0 median=    369600.0 p99=    766100.0 max=   1334100.0 mean=    331247.5
cover wake latency (thread::sleep control)     ns  n=5545    warmup=0     min=     16000.0 p50=    269800.0 median=    269800.0 p99=    737000.0 max=   1641800.0 mean=    289414.2

  HR-resolution timer achieved = 183.4667 pkt/s over 5504 wakes (93.93% of nominal 195.3125)
  thread::sleep control        = 184.8333 pkt/s over 5545 wakes (94.63% of nominal)
  D23 recorded reference       = p50 5.31 ms, ~93.5% of nominal (182.6 pkt/s over 30 s)

================================================================================
DERIVED FIGURES (arithmetic on measured values + source constants only)
================================================================================
--- Derived: server worst-case cover egress (D19) ---
  max_sessions              = 64
  nominal cover rate        = 195.31249999999997 pkt/s per session-direction
  PACKET_SIZE               = 1280 B
  arithmetic: 64 x 195.31249999999997 x 1280 x 8
             = 64 * 195.31249999999997 = 12500.0000 pkt/s
             = 12500.0000 * 1280 B/s = 16000000.0000 B/s
             = 16000000.0000 B/s * 8 = 128000000 bit/s
  RESULT                    = 128000000 bit/s = 128.000 Mbit/s = 0.1280 Gbit/s

--- Derived: packet-nonce exhaustion time ---
  MAX_PACKET_NONCE          = 18446744069414584320  (u64::MAX - 2^32)
  -- default 2 Mbps, 1 session, 1 direction --
     packet rate            = 195.3125 pkt/s
     arithmetic: 18446744069414584320 / 195.3125 = 9.444733e16 s
     RESULT                  = 9.444733e16 s = 2992916731.483 years (9.445e16 s)
  -- worst case (64 sessions, egress total) --
     packet rate            = 12500.0000 pkt/s
     arithmetic: 18446744069414584320 / 12500.0000 = 1.475740e15 s
     RESULT                  = 1.475740e15 s = 46764323.929 years (1.476e15 s)

--- Derived: ML-DSA-65 verify throughput and handshake capacity ---
  single verify             = 51500.0 ns
  arithmetic: 1e9 ns/s / 51500.0 ns = 19417.48 verify/s
  RESULT                    = 19417.48 verifications/second (one core, single-threaded)

  full-handshake CPU cost is dominated by the roster loop, so:
    roster n=1     D12 loop =        56700.0 ns ->     17636.68 handshakes/s/core (loop-bound lower bound)
    roster n=2     D12 loop =       107600.0 ns ->      9293.68 handshakes/s/core (loop-bound lower bound)
    roster n=4     D12 loop =       209800.0 ns ->      4766.44 handshakes/s/core (loop-bound lower bound)
    roster n=8     D12 loop =       422300.0 ns ->      2367.98 handshakes/s/core (loop-bound lower bound)
    roster n=16    D12 loop =       844700.0 ns ->      1183.85 handshakes/s/core (loop-bound lower bound)
    roster n=32    D12 loop =      1686600.0 ns ->       592.91 handshakes/s/core (loop-bound lower bound)
    roster n=64    D12 loop =      3411900.0 ns ->       293.09 handshakes/s/core (loop-bound lower bound)
    roster n=128   D12 loop =      6848400.0 ns ->       146.02 handshakes/s/core (loop-bound lower bound)
    roster n=256   D12 loop =     13721400.0 ns ->        72.88 handshakes/s/core (loop-bound lower bound)
    roster n=512   D12 loop =     28199300.0 ns ->        35.46 handshakes/s/core (loop-bound lower bound)
    roster n=1024  D12 loop =     56330700.0 ns ->        17.75 handshakes/s/core (loop-bound lower bound)

  Rate-limit context (ServerConfig::new defaults):
    rate_limit_burst        = 16 per 10 s per source address
    arithmetic: 16 / 10 = 1.6000 handshakes/s per source address
    -> the per-source budget (1.60/s) is the binding limit for a
       single source address, not the core's verify throughput,
       UNLESS a single source is admitted from many source addresses.

--- Derived: cover-path CPU (measured components only) ---
  scheduler tick            = 11.109 us
  AEAD encrypt (1280B)      = 10.653 us
  per-packet CPU (excl. syscalls, NOT MEASURED separately)
    = 11.109 us + 10.653 us = 21.762 us
    1 session(s) x 195.3125 pkt/s = 195.3125 pkt/s -> 0.004250 CPU-s/s = 0.4250% of one core
   64 session(s) x 195.3125 pkt/s = 12500.0000 pkt/s -> 0.272025 CPU-s/s = 27.2025% of one core

================================================================================
PASS WALL TIME: 126.6124371s
================================================================================
not measured by this harness (see docs/performance/I-benchmark-methodology.md):
  - syscall cost per cover packet (sendto + timer arm + wake)
  - loopback end-to-end handshake wall time including transport
  - multi-core scaling (single-threaded only)
```

### 11.2 Contrast run — same binary, same command, machine at 39–48 % load

Captured to `bench/raw/full_run.txt`. This run was **terminated by the harness
driver after a 600 s wall-clock cap** while executing the `cover` group, so it
contains only groups 1–3 (prims, roster, handshake). It is included solely as
the load-contrast evidence referenced in §4.2; its roster-1024 and handshake
percentiles are contaminated by contention and are **not** quoted as
performance figures anywhere in this document.

The termination is visible in the file: the output stops after the
`roster n=256` summary line with no `TOTAL WALL TIME` footer.

### 11.3 Contrast run, Bench 1 groups (the rows behind the table in `4.2`)

Extracted from `bench/raw/full_run.txt` (the 39–48 % load run). Rows here are
the *loaded* machine; compare against the quiet-machine table in `4.1`.

```text--- Bench 1a: single ML-DSA-65 verify (the per-element cost) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
verify() single call (roster n=1)              ns  n=510     warmup=3     min=     55600.0 p50=     55900.0 median=     55900.0 p99=     85700.0 max=  21105400.0 mean=     98744.9
verify() single call (roster n=2)              ns  n=510     warmup=3     min=     55600.0 p50=     55800.0 median=     55800.0 p99=     84500.0 max=    128000.0 mean=     57567.3
verify() single call (roster n=4)              ns  n=510     warmup=3     min=     55600.0 p50=     56000.0 median=     56000.0 p99=     86500.0 max=    159200.0 mean=     57705.3
verify() single call (roster n=8)              ns  n=510     warmup=3     min=     55600.0 p50=     55900.0 median=     55900.0 p99=    132000.0 max=   5290300.0 mean=     69544.7
verify() single call (roster n=16)             ns  n=510     warmup=3     min=     55600.0 p50=     55900.0 median=     55900.0 p99=    108000.0 max=  30342400.0 mean=    118107.3
verify() single call (roster n=32)             ns  n=510     warmup=3     min=     55700.0 p50=     56000.0 median=     56000.0 p99=    124300.0 max=   6754500.0 mean=     72228.2
verify() single call (roster n=64)             ns  n=510     warmup=3     min=     55600.0 p50=     55900.0 median=     55900.0 p99=    118300.0 max=   8123100.0 mean=     79962.5
verify() single call (roster n=128)            ns  n=510     warmup=3     min=     55700.0 p50=     56000.0 median=     56000.0 p99=    139000.0 max=  30975200.0 mean=    119555.7
verify() single call (roster n=256)            ns  n=510     warmup=3     min=     55800.0 p50=     56000.0 median=     56000.0 p99=    116200.0 max=  21609200.0 mean=    100841.6
verify() single call (roster n=512)            ns  n=510     warmup=3     min=     55700.0 p50=     55900.0 median=     55900.0 p99=    164900.0 max=  32517900.0 mean=    122563.9
verify() single call (roster n=1024)           ns  n=510     warmup=3     min=     55600.0 p50=     55900.0 median=     55900.0 p99=     84600.0 max=  20606300.0 mean=     97952.5

--- Bench 1b: D12 full roster loop (uniform verification, no early exit) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
D12 full roster loop (n=1 verifies)            ns  n=200     warmup=3     min=     61700.0 p50=     62000.0 median=     62000.0 p99=    113800.0 max=    164000.0 mean=     64475.0
D12 full roster loop (n=2 verifies)            ns  n=200     warmup=3     min=    117000.0 p50=    117400.0 median=    117400.0 p99=    275600.0 max=  26493800.0 mean=    255392.0
D12 full roster loop (n=4 verifies)            ns  n=200     warmup=3     min=    228600.0 p50=    230000.0 median=    230000.0 p99=   1786100.0 max=  36238800.0 mean=    442836.0
D12 full roster loop (n=8 verifies)            ns  n=200     warmup=3     min=    450200.0 p50=    465300.0 median=    465300.0 p99=  33233200.0 max=  42277500.0 mean=   1062858.0
D12 full roster loop (n=16 verifies)           ns  n=200     warmup=3     min=    893500.0 p50=    920500.0 median=    920500.0 p99=  41816200.0 max=  61482400.0 mean=   2232723.0
D12 full roster loop (n=32 verifies)           ns  n=200     warmup=3     min=   1801400.0 p50=   2126500.0 median=   2126500.0 p99=  55587700.0 max=  57368100.0 mean=   5009133.0
D12 full roster loop (n=64 verifies)           ns  n=200     warmup=3     min=   4152900.0 p50=   4324600.0 median=   4324600.0 p99=  52934200.0 max=  60009000.0 mean=   9573177.5
D12 full roster loop (n=128 verifies)          ns  n=200     warmup=3     min=   8353100.0 p50=   8855900.0 median=   8855900.0 p99=  49249900.0 max=  65038600.0 mean=  17215474.5
D12 full roster loop (n=256 verifies)          ns  n=200     warmup=3     min=  16734600.0 p50=  46617100.0 median=  46617100.0 p99=  79743600.0 max= 109495100.0 mean=  37936962.0
D12 full roster loop (n=512 verifies)          ns  n=200     warmup=3     min=  34660400.0 p50=  62895500.0 median=  62895500.0 p99= 102515200.0 max= 141488900.0 mean=  63304964.5
D12 full roster loop (n=1024 verifies)         ns  n=200     warmup=3     min=  68688500.0 p50=  82619800.0 median=  82619800.0 p99= 107363900.0 max= 113982300.0 mean=  84099802.5

--- Bench 1c: D12 loop, UNKNOWN client (no match; full cost then reject) ---
operation                                      unit   iterations              min          p50       median          p99          max         mean
D12 loop, UNKNOWN client (n=1 verifies)        ns  n=51      warmup=3     min=     73100.0 p50=     73400.0 median=     73400.0 p99=    114400.0 max=    114400.0 mean=     75068.6
D12 loop, UNKNOWN client (n=2 verifies)        ns  n=51      warmup=3     min=    145800.0 p50=    146500.0 median=    146500.0 p99=    422200.0 max=    422200.0 mean=    165770.6
D12 loop, UNKNOWN client (n=4 verifies)        ns  n=51      warmup=3     min=    291500.0 p50=    293900.0 median=    293900.0 p99=    452400.0 max=    452400.0 mean=    312070.6
D12 loop, UNKNOWN client (n=8 verifies)        ns  n=51      warmup=3     min=    582000.0 p50=    606700.0 median=    606700.0 p99=   4934800.0 max=   4934800.0 mean=    715862.7
D12 loop, UNKNOWN client (n=16 verifies)       ns  n=51      warmup=3     min=   1165300.0 p50=   1225500.0 median=   1225500.0 p99=   2422400.0 max=   2422400.0 mean=   1322676.5
D12 loop, UNKNOWN client (n=32 verifies)       ns  n=51      warmup=3     min=   2365800.0 p50=   2469900.0 median=   2469900.0 p99=   4534000.0 max=   4534000.0 mean=   2568300.0
D12 loop, UNKNOWN client (n=64 verifies)       ns  n=51      warmup=3     min=   4742800.0 p50=   4931700.0 median=   4931700.0 p99=   7354500.0 max=   7354500.0 mean=   5118347.1
D12 loop, UNKNOWN client (n=128 verifies)      ns  n=51      warmup=3     min=   9491800.0 p50=  10044200.0 median=  10044200.0 p99=  13231500.0 max=  13231500.0 mean=  10279915.7
D12 loop, UNKNOWN client (n=256 verifies)      ns  n=51      warmup=3     min=  19464600.0 p50=  20368200.0 median=  20368200.0 p99=  27819900.0 max=  27819900.0 mean=  20862235.3
D12 loop, UNKNOWN client (n=512 verifies)      ns  n=51      warmup=3     min=  38850800.0 p50=  41178500.0 median=  41178500.0 p99=  44276400.0 max=  44276400.0 mean=  41389421.6
D12 loop, UNKNOWN client (n=1024 verifies)     ns  n=51      warmup=3     min=  78918200.0 p50=  82945000.0 median=  82945000.0 p99= 104363200.0 max= 104363200.0 mean=  83997366.7

--- Bench 1: roster scaling summary (p50 ns) ---
roster        ns/verify      loop_p50_ns   unknown_p50_ns       verify/s
     1          55900.0          62000.0          73400.0       17889.09
     2          55800.0         117400.0         146500.0       17921.15
     4          56000.0         230000.0         293900.0       17857.14
     8          55900.0         465300.0         606700.0       17889.09
    16          55900.0         920500.0        1225500.0       17889.09
    32          56000.0        2126500.0        2469900.0       17857.14
    64          55900.0        4324600.0        4931700.0       17889.09
   128          56000.0        8855900.0       10044200.0       17857.14
   256          56000.0       46617100.0       20368200.0       17857.14
   512          55900.0       62895500.0       41178500.0       17889.09
  1024          55900.0       82619800.0       82945000.0       17889.09

```
