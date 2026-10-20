# 04 — Reproducibility Guide (for a third party)

> **This is an internal self-assessment, not an audit.** Nothing below was
> produced or endorsed by anyone outside the Tunnel project. What follows is an
> honest assessment of **whether an outside party can reproduce this project's
> evidence from the public tree** — with the answer, in most cases, **no, not
> completely**.

**Baseline for every command:** from a clean checkout of `origin/main` at
`ae8061d`. If your tree differs, see §7 first — the working tree at the time
this package was written did **not** compile.

---

## 1. Verdict up front

| Question | Answer |
|---|---|
| Can a third party build the workspace? | **Yes**, if they install Rust ≥ 1.85 and ignore the target flag. |
| Can a third party run the test suite? | **Yes.** 356 tests observed passing by this package (344 unit + 12 E2E) **at `ae8061d` + the then-uncommitted working tree**; 422 at `86cf7bd`; **467 on the current tree**, all on `x86_64-pc-windows-msvc`. |
| Can a third party verify the KATs? | **Yes**, for the 8 externally-anchored primitives. **No** for Tunnel's own construction. |
| Can a third party reproduce the *exact* build? | **No** — no pinned toolchain, and the fuzz dependency set is unpinned. |
| Can a third party reproduce the fuzz runs? | **Partially** — 1,000 runs/target yes (CI does it); the 1M-run campaigns have no published artefacts. |
| Can a third party reproduce the metadata measurements (§13.4–13.6)? | **No.** The harness is at `R:\pq-tunnel-lab`; raw CSVs are described as volatile. |
| Can a third party check the CI results? | **Yes**, with GitHub access — but no run id is published in the repo. |
| Can a third party verify the supply chain? | **No** — no SBOM, no advisory scan. |

---

## 2. Prerequisites

### 2.1 Required

| Item | Version | Where it is declared |
|---|---|---|
| Rust toolchain | **≥ 1.85.0** (MSRV) | `Cargo.toml:12` → `rust-version = "1.85"` |
| Cargo | ships with Rust | — |
| Network access to crates.io | — | — |

`rust-version = "1.85"` is declared **only in the workspace manifest**. It is
not in the README. An auditor reading the README would not know the MSRV.

### 2.2 Recommended but not declared

| Item | Version used by this package | Problem |
|---|---|---|
| Rust (stable) | **1.96.0** (`rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0`) | **No `rust-toolchain.toml` exists.** CI uses `stable` (`.github/workflows/ci.yml:19-21,45-47`), which floats. Two runs a month apart can differ. |
| `cargo-fuzz` | 0.13.2 (per `checkpoints/VALIDATION_LINUX_E2E_FUZZ.md:34`) | Not declared anywhere in the public tree; `fuzz.yml:81` installs it with `--locked` but pins no version. |
| Linux (for fuzz execution) | any x86-64 with ASan | Not stated as a *requirement*; only implied. |

---

## 3. Step-by-step reproduction

### Step 1 — Get the code

```bash
git clone <repo-url>
cd tunnel
git rev-parse HEAD          # expect ae8061d for this package's baseline
git status --porcelain      # MUST be empty; see §7
```

### Step 2 — Build

```bash
# Non-Windows, or any host that is not aarch64-Windows:
cargo build --workspace --locked

# Windows x86_64 host (the project's canonical target):
cargo build --workspace --locked --target x86_64-pc-windows-msvc
```

**About the `--target` convention.** `README.md:127-131` and `AGENTS.md` both
instruct you to pass `--target x86_64-pc-windows-msvc`, explaining that "the
development host is aarch64 Windows" and that the flag "pins the tested
toolchain". Two problems for an outside reproducer:

1. **The stated reason is stale.** `aws-lc-sys` was the ARM64 blocker, and D20
   removed the entire QUIC/TLS stack that pulled it in
   (`DESIGN_DECISIONS.md:1035-1039` — "the `aws-lc-sys` build constraint
   disappears"). The constraint no longer exists.
   **[CORRECTED since]** — `AGENTS.md` no longer cites `aws-lc-sys`; it
   records that the crate is absent from the dependency tree, that the
   workspace has no `cc`/`nasm`-driven native build, and that the x86_64
   target is canonical because it is what CI verifies and what the release
   gate is measured on.
2. **It is machine-shaped.** On Linux or macOS you must drop the flag
   (`README.md:131-133`). Nothing in the repository explains, in normative
   language, when the flag is required and when it is not.

**Verdict:** the instruction is harmless but should be rewritten as "Tunnel
builds and tests on any host with Rust ≥ 1.85; `--target x86_64-pc-windows-msvc`
selects the reference Windows target."

### Step 3 — Format, lint, test

```bash
cargo fmt --all --check
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test --workspace --locked --target x86_64-pc-windows-msvc
```

**Expected result** (observed by this package on `x86_64-pc-windows-msvc`, at
`ae8061d` **plus the then-uncommitted working tree**, all green):

```
pq-crypto       lib:  67 passed
pq-tunnel-bin   lib:  41 passed
pq-tunnel-core  lib: 236 passed
e2e_smoke              3 passed
e2e_adversarial        6 passed
e2e_stress             3 passed
                          ---
                          356 passed, 0 failed
```

> **Later measurement — use this if you are reproducing today.** The current
> tree measures **467 passed, 0 failed** on `x86_64-pc-windows-msvc`
> (at commit `86cf7bd` it measured 422):
>
> ```
> pq-crypto       lib:  85 passed
> pq-tunnel-core  lib: 280 passed
> pq-tunnel-bin   lib:  77 passed
> e2e_adversarial        6 passed
> e2e_smoke               3 passed
> e2e_stress              3 passed
> revocation_lifetime    13 passed
>                           ---
>                           467 passed, 0 failed
> ```
>
> Exactly **3** of the 280 core tests are `#[cfg(windows)]`, so **277** core
> tests run on a non-Windows host. The figures are measurements of
> **different trees**, not a discrepancy.

The E2E suites should be serialized (`-- --test-threads=1`), as CI does
(`ci.yml:33`), because they bind UDP sockets.

### Step 4 — Verify the known-answer vectors

```bash
# Each of these is individually addressable:
cargo test -p pq-crypto --locked --target x86_64-pc-windows-msvc kat
cargo test -p pq-crypto --locked --target x86_64-pc-windows-msvc rfc8439
cargo test -p pq-crypto --locked --target x86_64-pc-windows-msvc rfc5869
cargo test -p pq-crypto --locked --target x86_64-pc-windows-msvc rfc7748
cargo test -p pq-crypto --locked --target x86_64-pc-windows-msvc wycheproof
```

**What this proves:** the 8 externally-anchored constants in
`pq-crypto/src/kat_vectors.rs` match their published sources, and the wrappers
in `pq-crypto/src/{aead,kdf,kem,signature,classical}.rs` produce the same
answers.

**What this does NOT prove** — and this is the point of §5:

- the master-secret derivation (`pq-crypto/src/kdf.rs:164-188`);
- `TH1`/`TH2`/`TH3` (`pq-tunnel-core/src/handshake_v2.rs:750-778`);
- the Finished key and MAC (`pq-crypto/src/kdf.rs:191-227`);
- the traffic keys and nonce prefixes (`pq-crypto/src/kdf.rs:97-139`).

None of these has an external vector. They are pinned only by tests whose oracles
were written in the same crate.

### Step 5 — Build the fuzz targets

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cargo +nightly fuzz build --fuzz-dir fuzz                    # Linux/macOS
cargo +nightly fuzz build --fuzz-dir fuzz --target x86_64-pc-windows-msvc  # Windows x86_64
```

There are 10 targets (`fuzz/Cargo.toml:16-55`):
`wire_packet_from_bytes`, `inner_plaintext_decode`, `envelope_decrypt`,
`replay_window`, `handshake_message_decode`, `handshake_driver_receive`,
`session_manager_receive`, `cover_scheduler`, `relay_overlay`,
`manager_churn`.

### Step 6 — Run the fuzz targets (needs an ASan-capable host)

```bash
for t in wire_packet_from_bytes inner_plaintext_decode envelope_decrypt \
         replay_window handshake_message_decode handshake_driver_receive \
         session_manager_receive cover_scheduler relay_overlay manager_churn; do
  cargo +nightly fuzz run "$t" --fuzz-dir fuzz -- -runs=1000
done
```

This is exactly what CI does (`.github/workflows/ci.yml:63-71`). A clean run
prints `Done 1000 runs` per target with no `== ERROR` line.

For a longer campaign, `.github/workflows/fuzz.yml` is a manual
`workflow_dispatch` workflow with `runs` (default 1,000,000) and
`max_total_time` (default 3600 s) inputs and a sanitizer selector.

**Honest note:** this package ran **neither** Step 5 nor Step 6. Fuzz execution
is not possible on this host (`README.md:161-163` — the ASan runtime fails DLL
initialisation under VBS with `0xC000026F`).

### Step 7 — Reproduce the CI gates exactly

The authoritative gate is `.github/workflows/ci.yml`. Three jobs:

| Job | Runner | What it runs | `file:line` |
|---|---|---|---|
| `windows` | `windows-latest` | `cargo fmt --all --check`; `cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings`; `cargo test --workspace --locked --target x86_64-pc-windows-msvc`; `cargo test --locked --target x86_64-pc-windows-msvc --test e2e_smoke -- --test-threads=1` | `ci.yml:24-34` |
| `linux` | `ubuntu-latest` | `cargo clippy --all-targets -- -D warnings`; `cargo test --workspace --locked`; `cargo +nightly fuzz build --fuzz-dir fuzz`; 10 × `cargo +nightly fuzz run -- -runs=1000` | `ci.yml:49-72` |
| `msrv` | `ubuntu-latest` | Rust 1.85.0; `cargo check --workspace --locked --all-targets` | `ci.yml:73-89` |

All jobs use `--locked`. CI never pushes, publishes, or releases.

### Step 8 — Reproduce the end-to-end behaviour manually

```bash
# 1. Provision identity (server + client).  Keys must be distributed out of band.
cargo run --release --locked --target x86_64-pc-windows-msvc --bin pq-tunnel -- \
  keygen --identity server-id.pqti --public-key server-pub.pqti

cargo run --release --locked --target x86_64-pc-windows-msvc --bin pq-tunnel -- \
  keygen --identity client-id.pqti --public-key client-pub.pqti \
          --append-roster roster.pqti

# 2. Server (roster on the server, identity on both)
cargo run --release --locked --target x86_64-pc-windows-msvc --bin pq-tunnel -- \
  server --listen 0.0.0.0:4433 --identity server-id.pqti --roster roster.pqti

# 3. Client (server public key pinned)
cargo run --release --locked --target x86_64-pc-windows-msvc --bin pq-tunnel -- \
  client --remote 127.0.0.1:4433 --identity client-id.pqti --server-key server-pub.pqti

# 4. Send a datagram through the local relay (loopback-only, default 127.0.0.1:51821)
#    ... from any UDP client, e.g. an echo service.
```

Sources: `README.md:93-123`. Fingerprints for out-of-band verification are
`SHA-256(encoded_key)[..16]` (32 hex chars) — `DESIGN_DECISIONS.md:834-835`.

---

## 4. The build helper — and its trap

`build.ps1` is described as "local convenience build wrapper (portable)"
(`README.md:55`). It is 13 lines:

```powershell
param(
    [ValidateSet("check", "test", "build", "clippy", "fmt")]
    [string]$Command = "check",
    [string]$Package = "pq-crypto"        # <-- line 4
)
...
cargo $Command -p $Package --target x86_64-pc-windows-msvc @args   # <-- line 13
```

Two problems:

1. **The default package is `pq-crypto`, not the workspace.** A reader following
   `README.md:146-148` (`.\build.ps1 test            # pq-crypto`) gets *one
   crate's* tests and may believe they have run the suite.
2. **It is PowerShell-only.** There is no `build.sh`. A Linux auditor has
   nothing equivalent, and `--target x86_64-pc-windows-msvc` is hard-coded —
   so the "portable" helper is actually Windows-specific.

**Recommended fix:** add `build.sh`, or replace both with a `justfile`/
`Makefile`, and make the workspace the default.

---

## 5. Reproducing the *cryptographic* evidence — the honest gap

This is the section an auditor should read twice.

### 5.1 What is anchored

| Constant | Anchor | Provenance recorded at |
|---|---|---|
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 | `pq-crypto/src/kat_vectors.rs:5-8` |
| HKDF-SHA256 | RFC 5869 §A.1 tc1 | `kat_vectors.rs:9-10` |
| X25519 | RFC 7748 §6.1 | `kat_vectors.rs:11-13` |
| ML-KEM-768 keygen / encaps | Wycheproof `mlkem_768_test.json` tcId 1; `mlkem_768_encaps_test.json` testGroups[1] tcId 14 | `kat_vectors.rs:14-18` |
| ML-DSA-65 verify / sign / keygen | Wycheproof `mldsa_65_verify_test.json`, `mldsa_65_sign_seed_test.json` grp0 tcId1 | `kat_vectors.rs:19-25` |

This is **excellent practice** and matches the D21 policy
(`DESIGN_DECISIONS.md:1186-1230`).

### 5.2 What is NOT anchored

| Construction | Where it lives | External vector? |
|---|---|---|
| `master = HKDF-SHA256(ssA‖ssB‖dh_cs, [0;32], "pq-tunnel-master-v2"‖VER‖SID‖TH3)` | `pq-crypto/src/kdf.rs:164-188` | **NONE** |
| `TH1 = SHA256(dom‖M1_z)` | `handshake_v2.rs:750-757` | **NONE** |
| `TH2 = SHA256(dom‖M1_s‖M2_z)` | `handshake_v2.rs:759-769` | **NONE** |
| `TH3 = SHA256(dom‖M1_z‖M2_z‖M3_z)` | `handshake_v2.rs:771-778` | **NONE** |
| `finished_key = HKDF(master, [0;32], "pq-tunnel-finished-v1"‖VER‖SID)` | `kdf.rs:191-210` | **NONE** |
| `client_finished = HMAC-SHA256(finished_key, TH3)[..16]` | `kdf.rs:212-227` | **NONE** (and HMAC itself has no RFC 2104 vector) |
| `c2s_key` / `s2c_key` (labels `pq-tunnel-c2s-v2` / `-s2c-v2`) | `kdf.rs:97-116` | **NONE** |
| `nonce_prefix` (labels `pq-tunnel-nonce-c2s-v2` / `-s2c-v2`) | `kdf.rs:118-139` | **NONE** |

**Why this matters:** the RFC/Wycheproof vectors prove that Tunnel's *wrappers*
call the right standard primitives correctly. They say nothing about whether
Tunnel's *own* composition is right — the concatenation order, the zero salt, the
label strings, the transcript inputs, the truncation length. That composition is
the part a second implementation would have to reproduce byte-for-byte, and it
is the part with no external reference.

### 5.3 A remediation path the project could take

For each unanchored construction, publish a **published-input / expected-output**
vector computed by an *independent* implementation (a second codebase, or a
careful hand-computation with published intermediate values). Precedent exists:
`CRYPTO_PROFILE.md:429` already commits to external anchoring as a principle —
it was simply never applied to the construction. See
[`spec/crypto-construction.md`](spec/crypto-construction.md), which is the
skeleton for writing it down.

---

## 6. Reproducing the metadata measurements — not possible

`THREAT_MODEL.md §13.4–13.6` contains the project's most valuable quantitative
work. None of it is reproducible from the public tree:

| Measurement | Cited at | Why not reproducible |
|---|---|---|
| λ·W ≥ 1 detection bound | `THREAT_MODEL.md:509-518` | Derivation is in `R:\pq-tunnel-lab\RQ2-0*.md` (`:509`); "no code" |
| Cover cadence p50/p90/p99 | `THREAT_MODEL.md:533-551` | Raw CSVs "volatile"; harness on a `R:` lab copy (`:538-540`) |
| Establishment window, H1–H4 | `THREAT_MODEL.md:574-641` | Same; `e2a`/`e2b` used 12 s windows (`:643`) |
| Fuzz run counts (1M, 1.9M, 105,350, ~6.9M) | `THREAT_MODEL.md:461-483` | Ledger at `R:\pq-tunnel-lab` (`:455`) |
| M9 live R1/R2 results | `DESIGN_DECISIONS.md:1169-1178` | Run transcripts not in the tree |

The `R:\` drive path is also a **machine-local path** that an outside reader
cannot resolve. An auditor can either (a) accept the numbers as internal claims,
or (b) re-derive them from the wire format — which requires a normative wire
spec, which does not exist.

**What the project should publish:** the measurement harness (or at least a
description of it plus the raw CSVs) so that §13 is checkable rather than
merely readable. The maths in §13.4 is derivable from the spec and needs no
harness — it just needs the spec.

---

## 7. Baseline caveats — the tree this package describes

`git status` at package time:

```
 M pq-tunnel-bin/src/identity.rs
 M pq-tunnel-bin/src/lib.rs
 M pq-tunnel-core/src/handshake_v2.rs
 M pq-tunnel-core/src/session_manager.rs
?? docs/                                       # includes this package
?? pq-crypto/tests/
?? pq-tunnel-bin/tests/revocation_lifetime.rs   # <-- does not compile
```

**`cargo test --workspace --locked` fails** with 9 compile errors, all in the
untracked `pq-tunnel-bin/tests/revocation_lifetime.rs`:

```
error[E0432]: unresolved import `pq_tunnel_core::MlDsaPublicKeyUnused`
error[E0425]: cannot find type `HandshakeOutcome` in this scope
error[E0015]: cannot call non-const method `core::str::…::parse::<SocketAddr>` in constants  (×3)
error[E0599]: no method named `cfg_max_attempts` found for mutable reference `&mut ClientHandshake`
error[E0308]: mismatched types
error[E0382]: borrow of moved value: `client_kp`
```

**If you are reproducing, check out a clean `main` and do not copy this working
tree.** The failures are in a file that is not in `main`.

Also note that the untracked code cites a decision **`D27`** that does not exist
in `DESIGN_DECISIONS.md` (highest: D24) and a document
`docs/decisions/D27-revocation-and-session-lifetime.md` that is not in the tree.

> **HISTORICAL.** This section describes the tree at `ae8061d` plus an
> uncommitted working tree. Since commit `86cf7bd` the `docs/` tree and
> `pq-tunnel-bin/tests/revocation_lifetime.rs` are **tracked**, the workspace
> **compiles**, and `docs/decisions/D27-revocation-and-session-lifetime.md`
> exists. The `D27` entry is still absent from `DESIGN_DECISIONS.md`.

### 7.1 The tree kept moving

After §7 was recorded, `pq-crypto/src/classical.rs` was additionally modified to
return `None` from `diffie_hellman` on an all-zero shared secret (an RFC 7748
§6.1 contributory check), `pq-tunnel-core/src/handshake_v2.rs` grew by ~135
lines correspondingly, and a `bench/` directory appeared — all uncommitted.

**The 356-test figure in §Step 3 was measured before that edit.** Re-measure.
See gap G-23 in [`05-gaps.md`](05-gaps.md).

> **HISTORICAL.** The contributory check and its tests are now committed
> (`68273a8`), and `bench/` is now a tracked, separate workspace.

---

## 8. Missing for full reproducibility — checklist

Ordered by how much they block an auditor.

| # | Missing | Blocks | Effort |
|---|---|---|---|
| R-1 | A normative wire-format specification | Writing a second implementation; checking the metadata claims | Large (see `spec/wire-format.md`) |
| R-2 | A normative cryptographic-construction specification | Verifying the key schedule independently of the code | Large (see `spec/crypto-construction.md`) |
| R-3 | External known-answer vectors for the construction (master, TH1/2/3, Finished MAC) | Falsifying the composition without trusting the code | Medium — compute once, publish |
| R-4 | `rust-toolchain.toml` | Byte-identical builds across time | Trivial |
| R-5 | Commit `fuzz/Cargo.lock`; add `--locked` to the fuzz CI/fuzz.yml invocations | Reproducible fuzz runs | Trivial |
| R-6 | A cross-platform build entry point (`build.sh`, or workspace default in `build.ps1`) | Reproduction on non-Windows | Trivial |
| R-7 | Published exact versions: rustc, cargo, cargo-fuzz, libFuzzer | Environment reproducibility | Trivial |
| R-8 | The §13 measurement harness, or the raw CSVs | Verifying the metadata claims | Medium |
| R-9 | A published CI run id + retention policy | Checking "CI is green" claims | Trivial |
| R-10 | `cargo deny` / SBOM in CI | Supply-chain review | Small |
| R-11 | A test that forward secrecy holds (compromise an identity key, confirm history stays sealed) | Substantiating the headline claim | Medium |
| R-12 | A test asserting the KEM-after-signature ordering | Substantiating a DoS-gate invariant | Small |
| R-13 | RFC 2104 KAT for HMAC-SHA256 | Anchoring the Finished MAC's primitive | Trivial |
| R-14 | ~~Removal of the wrong-answer branch in the SHA-256 "abc" test~~ **[DONE]** | Removing an incorrect-output escape hatch | Trivial — **done**: the test now asserts exactly one digest, the canonical `...f20015ad`. *(The finding as first written was inverted: the crate was always right and the test was wrong.)* |
| R-15 | Test names for D24's "10 new focused tests" (`DESIGN_DECISIONS.md:1359`) | Letting an auditor find the evidence | Trivial |
| R-16 | A decision index (TOC) for `DESIGN_DECISIONS.md` | Navigating 1,400 lines | Small |
| R-17 | Correct D-record ordering, and a `supersedes` field per decision | Traceability | Small |
| R-18 | Supersession of D18 by the TUN architecture | Accuracy of the product record | Small (the design already exists) |
| R-19 | A published statement of the server's egress/SSRF posture | Deployment risk | Small — *partly addressed: a minimal egress guard has shipped (see `docs/design/D28-server-egress-policy-1to1.md`); the full D28 policy and its CLI flags have not, and the posture is still not stated in `THREAT_MODEL.md` or the README.* |
| R-20 | ~~Publishing `docs/design/`~~ **[DONE — tracked since `86cf7bd`]** | Seeing the actual design trajectory | Trivial — **done**; `git ls-files docs` → 17 files. *(Promoting the content into the decision record remains open.)* |

**R-4, R-5, R-6, R-7, R-9, R-13, R-14, R-15 and R-20 together are perhaps a
day of work** and would move the package from "partially reproducible" to
"reproducible except for the two specifications". R-1 and R-2 are the real
work, and both skeletons are provided.