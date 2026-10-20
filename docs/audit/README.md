# Tunnel — Audit Evidence Package (Entry Point)

> **STATUS OF THIS PACKAGE — READ FIRST.**
> This package is **evidence offered for audit**. It is **not** an audit.
> Every statement in this directory is a **self-attested, internal claim**
> made by the Tunnel authors, compiled so that a third party *could* audit it.
> **No independent third party has reviewed, verified, endorsed, or approved
> anything in this package.** Nothing here constitutes independent assurance,
> certification, accreditation, compliance attestation, or a security
> certification of any kind. The words "audited", "assured", "certified",
> "compliant" and "verified secure" are **not used** about this project's own
> work anywhere in this package. Where the package needs to say a claim is
> unsupported, it says **"asserted without evidence"** — that is a statement
> about the *documentation*, not about the software.
>
> The authors of this package are the same people who wrote the code and the
> tests. That is a structural weakness of the evidence, not a defect to be
> smoothed over: an audit performed by the authors of a system has an obvious
> conflict of interest, and any reader should treat everything below with the
> corresponding discount.

- **Package date:** 2026-10-05
- **Package baseline commit:** `ae8061d` (`origin/main` at time of writing:
  `ae8061d`), **plus the then-uncommitted working tree** described in §4 and
  §4.1a. Every `file:line` citation and every count in this package is
  stated against *that* tree — it is not a statement about any later commit.
- **Working tree at package time:** **not clean, and it changed during the
  session** — see §4 and §4.1a
- **Version under assessment:** `v0.2.0-alpha` (`Cargo.toml:10` → `version = "0.2.0"`)
- **Corrections applied after the package was written:** see §0. A finding
  marked **[RESOLVED]** or **[CORRECTED]** in this directory was true when
  the package was written and has since been fixed or re-measured in the
  tree. The original finding is kept, so that the record of what the package
  actually observed survives — the substance of the finding is not rewritten
  away.

---

## 0. Correction log (added after the package was written)

This package was written against `ae8061d` plus an uncommitted working tree.
Since then the tree moved. The corrections below are the ones an outside
reader would otherwise trip over. Each is a **factual** correction, verified
against the code, the git history and the primary source named — not a
re-grading of the package's substance.

| # | What was recorded | What is true now | Verified against |
|---|---|---|---|
| **X-1** | The SHA-256 "abc" known-answer test "accepts two answers, one of which is wrong", and the *canonical* FIPS digest was described as ending in a different four bytes than it does (05-gaps G-13, 01-evidence K-09, 02-claims C-64, 03-limitations L-39, E §5.2/§6 G-6). | **The finding was inverted.** The canonical value of `SHA-256("abc")` is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` — it ends **`...f20015ad`**. The crate's implementation was always correct; the *test* was wrong. The "Windows-on-ARM64 emulation produces different SHA-256 last bytes" story was false. The strict, single-answer test is now in the tree. | RFC 6234 §8.5 (TEST1 = `"abc"` → `…f20015ad`); FIPS 180-4 §5.1.1; `pq-crypto/src/transcript.rs` — `sha256_known_vector` (strict, single expected digest). |
| **X-2** | The D16 nonce-exhaustion full-loop driver E2E was "in the untracked `pq-crypto/tests/`" and "not located and run by name"; the commit it cited is a **dangling object** — unreachable from any ref (02-claims C-11; THREAT_MODEL §13.2). | The test lives in `pq-tunnel-core/src/session_manager.rs` (`client_driver_nonce_exhaustion_reestablishes`, `server_driver_nonce_exhaustion_recovers`) and was merged as **`3f6d4f6`**, which **is** reachable from `main`. `pq-crypto/tests/` is an empty directory. `THREAT_MODEL.md` §13.2 now cites `3f6d4f6` and names the two tests. | `git cat-file -t`; `git branch -a --contains 3f6d4f6` → `main`; `git log --oneline 3f6d4f6`; the previously cited object → `git branch -a --contains` returns empty. |
| **X-3** | `docs/` is "not tracked in git (`git ls-files docs` → empty)"; the design documents under `docs/design/` are "untracked"; `docs/design/*.md` are "not tracked" (README §3, §4.1, §4.3, §6; 03-limitations L-34; 05-gaps G-02, G-20). | **HISTORICAL.** Since commit `86cf7bd` the `docs/` tree **is** tracked — `git ls-files docs` returns 17 files, including this package. The claim was true when the package was written and is false now. | `git ls-files docs` → 17 entries at `86cf7bd`. |
| **X-4** | Test counts: the package measured **356** (344 unit + 12 E2E) at `ae8061d`+worktree and found the README's "352" not reconciling. | Both figures are **measurements at different commits**, and both are marked as such. At `86cf7bd` the workspace measured **422** on `x86_64-pc-windows-msvc` (85 + 259 + 53 unit + 25 E2E); the current tree measures **467** (85 + 280 + 77 unit + 25 E2E) after the D24 fail-gate, handshake-rate-limiter, roster-limit, cover-pacing and egress-guard work. | `cargo test --workspace --target x86_64-pc-windows-msvc` at `86cf7bd` and on the current tree. |
| **X-5** | `README.md:74` was cited for the "352 tests pass" claim. | The README now states the count anchored to a target — "**467 tests pass** … measured on the `x86_64-pc-windows-msvc` target" — and names the per-crate breakdown (85 + 280 + 77 unit + 25 E2E). Its Linux core-test figure is **277** (280 − 3 `#[cfg(windows)]`). The previously published figure was 422 at `86cf7bd`. | `README.md`; 3 `#[cfg(windows)]` test functions confirmed in `pq-tunnel-core/src/session_manager.rs`. |

Items X-1 … X-5 do not weaken any finding in this package: X-1 and X-2 close
findings that were **wrong as written**, and X-3 … X-5 re-date measurements
that were never wrong, only measured against an older tree.

> **The original wording of each corrected passage is preserved in the
> committed versions of these files** (for example
> `git show 86cf7bd:docs/audit/05-gaps.md`), so each correction stays
> auditable against the text it corrects. The incorrect values are
> deliberately **not** restated inline, so that a reader (or a grep) cannot
> mistake them for current facts.

---

## 1. What this package is

This package answers one question: **if a qualified third party wanted to audit
Tunnel, what would they need, what does the project already have, and where are
the holes?**

It contains five indexes and two spec skeletons:

| Artifact | Purpose | Read it when |
|---|---|---|
| [`README.md`](README.md) | This file. Scope, caveats, map. | First. |
| [`01-evidence-index.md`](01-evidence-index.md) | Master table: every audit-relevant requirement → evidence → `file:line` → PRESENT / PARTIAL / MISSING / INTERNAL-ONLY. | To orient yourself in the whole codebase. |
| [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) | **The most important artifact.** Every security claim found in the project docs, the evidence offered for it, the strength of that evidence, and the gap. Ruthless by design. | To judge how much of the project's own marketing is actually backed. |
| [`03-limitations-register.md`](03-limitations-register.md) | Consolidated known limitations, each traced to its decision record, plus limitations the project docs **do not** currently admit to. | To understand the real boundary of the design. |
| [`04-reproducibility.md`](04-reproducibility.md) | Step-by-step reproduction instructions for a third party, and what is missing. | To try to reproduce the build, tests, KATs and fuzz runs. |
| [`05-gaps.md`](05-gaps.md) | Prioritized gap list, each marked `blocks-audit` or `nice-to-have`. | To plan the remediation work. |
| [`spec/wire-format.md`](spec/wire-format.md) | **Skeleton** normative wire-format specification, every known field pre-filled from source with `file:line`, unknowns marked `[TO BE AUTHORED]`. | To write or check the wire spec. |
| [`spec/crypto-construction.md`](spec/crypto-construction.md) | **Skeleton** normative cryptographic-construction specification: every constant, label, step, salt, transcript input and nonce rule an auditor needs. | To write or check the construction spec. |

### How to use this package

1. Read §2 (caveats) and §3 (the one-paragraph honest summary) below.
2. If you want the blunt assessment, go straight to
   [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md).
3. If you are here to *do* the audit, the package tells you where to start:
   [`04-reproducibility.md`](04-reproducibility.md) first, then the two
   skeletons under `spec/` (which are the actual gaps), then the code.

---

## 2. What this package is NOT

It is **not**:

- a security audit, and not a substitute for one;
- a certification of any kind (no SOC 2, ISO 27001, FIPS 140-2/3,
  Common Criteria, or equivalent);
- a statement that Tunnel is secure, correct, or fit for any purpose;
- a penetration test or red-team report;
- a third-party statement of the correctness of the cryptographic construction;
- a compatibility or interoperability statement (no second implementation
  exists — see [`03-limitations-register.md`](03-limitations-register.md) L-01);
- a formal proof of any property.

**The README of the project itself already states this** and this package
reinforces rather than weakens it:

> "**No independent third-party security audit has been performed.**
> Everything asserted here was produced and checked in-tree. The design record
> (`DESIGN_DECISIONS.md`) is maintained by the authors, and the test suite —
> including its fuzz targets — is self-referential in the sense that its
> oracles are written by the same project. Treat the cryptographic and protocol
> claims as *unreviewed by outsiders*."
> — `README.md:204-211`

That statement is the honest frame for everything in this directory. The
package's value is not that it changes that frame; it is that it maps, in
detail, exactly *how much* is resting on in-tree evidence alone.

### Terminology used in this package

| Term | Meaning here |
|---|---|
| **measured** | A number was produced by a run and the number is recorded with its provenance (run id, date, host). |
| **tested-asserted** | A test asserts the property, the test passes, but the test's oracle was written by the same authors and the property is not externally anchored. |
| **argued** | A reasoned argument in prose with no executable or external anchor. |
| **asserted-only** | The claim is stated in documentation with **no** supporting artefact of any kind. |
| **UNVERIFIED** | The authors of this package (i.e. the Track G documentation pass) could not confirm the claim from the tree. |
| **INTERNAL-ONLY** | The evidence exists but lives in a location an outside reader cannot see (see §4). |

---

## 3. The honest one-paragraph summary

Tunnel's *documentation culture* is unusually strong for a project at
`v0.2.0-alpha`: there is a maintained decision record (D1–D24), a threat model
that has been **revised by measurement** rather than only asserted, a crypto
profile that pins an external known-answer anchoring policy, a threat model
whose §13 subsections candidly record *where its own guarantees stop*, and a
README whose "Known issues / limitations" section is more candid than most
shipping products. That is a real strength and this package does not
understate it.

The weakness is equally clear and equally structural: **almost nothing the
project asserts about its cryptography exists as a normative specification.**
`PROTOCOL_SPEC.md` is, by its own status line, a *requirements* document that
explicitly declines to define the handshake, the wire format, or the
cryptographic construction. The wire format exists as Rust doc-comments inside
`pq-tunnel-core/src/codec.rs`. The key schedule, the transcript hashes, the
nonce construction and the Finished MAC exist as doc-comments in
`pq-crypto/src/kdf.rs` and `pq-tunnel-core/src/handshake_v2.rs` — excellent
doc-comments, but doc-comments are not a specification an auditor can check a
*second implementation* against, and they are not versioned independently of
the code. The hybrid master-secret KDF chain, the canonical transcript hashes
and the Finished MAC — the three pieces of construction that are *Tunnel's own
invention* rather than a published standard — have **no external known-answer
vector at all**; they are pinned only by self-generated tests. That is the
single most important structural gap in the package, and it is why
[`spec/crypto-construction.md`](spec/crypto-construction.md) exists as a
skeleton with so few `[TO BE AUTHORED]` markers filled in.

A second, sharper gap: **`D18` is obsolete as a product model.** It records
"the v0.2 product decision is a local UDP relay client (no TUN, no admin)" as
an *Accepted* decision (`DESIGN_DECISIONS.md:860-864`). The product
architecture has since changed direction to a **system-wide OS/networking tool
(TUN device + system routes)**. The `docs/design/D25-D26-*.md` proposal states
this explicitly and correctly flags D18 as no longer the product model — but
that proposal is **PROPOSED, not accepted** and is not in the decision record.
An auditor reading `DESIGN_DECISIONS.md` alone would reach the wrong conclusion
about the product. This is documented in [`05-gaps.md`](05-gaps.md) as
`blocks-audit` gap **G-02**.

> **HISTORICAL NOTE (package was written against `ae8061d` + an uncommitted
> working tree).** The text as first written also said that this proposal "is
> **not tracked in git** (`git ls-files docs` → empty)". That was true of the
> tree this package inspected. It is **no longer true**: since commit
> `86cf7bd` the `docs/` tree is tracked — `git ls-files docs` returns 17
> files, including this package and `docs/design/D25-D26-*.md`. The
> substantive finding (D18 is stale and the correcting document is not a
> decision of record) is **unchanged**; only the "an outside auditor cannot
> see it" part has been overtaken by events.

---

## 4. Baseline caveats — an auditor must know before reading anything

These are properties of the tree as it stood when this package was written
(`ae8061d` **plus the uncommitted working tree**). They matter because several
of them mean the committed `main` branch is *not* the same as what was
inspected here. **Everything in §4 is a statement about that tree, not about
the current one** — see §0.

### 4.1 The tree was not clean, and the difference is material

`git status` at package time:

```
 M pq-tunnel-bin/src/identity.rs
 M pq-tunnel-bin/src/lib.rs
 M pq-tunnel-core/src/handshake_v2.rs
 M pq-tunnel-core/src/session_manager.rs
?? docs/                                  <- untracked, including THIS package
?? pq-crypto/tests/                       <- untracked
?? pq-tunnel-bin/tests/revocation_lifetime.rs  <- untracked
```

Two consequences an auditor must not miss:

1. **The untracked working tree was BROKEN at package time.**
   `cargo test --workspace --locked --target x86_64-pc-windows-msvc` failed to
   compile with 9 errors in the untracked test target
   `pq-tunnel-bin/tests/revocation_lifetime.rs`:
   `unresolved import pq_tunnel_core::MlDsaPublicKeyUnused`,
   `cannot find type HandshakeOutcome in this scope`, three
   `cannot call non-const method ... SocketAddr::parse in constants`,
   `no method named cfg_max_attempts found for mutable reference`, plus type
   and borrow errors. **This failure is not present on clean `main`** — it is
   caused by the untracked file. Do not attribute it to the product.
   *(HISTORICAL: the file is now tracked and the tree compiles; see §0.)*
2. **The untracked code references decision `D27`, which does not exist in
   `DESIGN_DECISIONS.md`.** A grep for `D27` across the tree hits
   `pq-tunnel-bin/src/identity.rs:439` ("A hot-swappable client roster backed by
   a provisioning file (D27)"), `pq-tunnel-core/src/session_manager.rs:357,363`,
   `pq-tunnel-core/src/handshake_v2.rs:1389,1400,1738`, and
   `pq-tunnel-bin/tests/revocation_lifetime.rs:1,75,347,434,466` — the last of
   which cites `docs/decisions/D27-revocation-and-session-lifetime.md`, a path
   that **is not present in the tree**. The decision record's highest numbered
   entry is `D24`.

### 4.1a The tree continued to change while this package was written

After §4.1 was recorded, the working tree changed again — two files were edited
and a new directory appeared, **without any commit**:

```
 M pq-crypto/src/classical.rs          <- NEW since §4.1
 M pq-tunnel-bin/src/identity.rs
 M pq-tunnel-bin/src/lib.rs
 M pq-tunnel-core/src/handshake_v2.rs
 M pq-tunnel-core/src/session_manager.rs
?? bench/                              <- NEW
?? docs/
?? pq-tunnel-bin/tests/revocation_lifetime.rs
```

`pq-crypto/src/classical.rs` now adds an X25519 **contributory check** —
`diffie_hellman` returns `None` on an all-zero shared secret, citing RFC 7748
§6.1 ("MAY check … whether K is the all-zero value and abort if so") and §7
(Curve25519 cofactor 8 / small-order points).

**This is a security improvement, and it is not recorded anywhere:**
there is no decision record entry for it, no threat-model note, and no README
mention. `handshake_v2.rs` grew by ~135 lines of corresponding work in the
same window.

**An auditor must treat this as an open question, not a resolved item:** the
change is live in the working tree, unreviewed by anyone, unrecorded in the
decision record, and it alters a key-establishment code path. Either it lands
with a D-record and tests, or it should be re-evaluated.

> **HISTORICAL (partially overtaken).** The "live in the working tree, nothing
> committed" half of that paragraph is **no longer true**: the contributory
> check was **committed** as `68273a8` ("fix(crypto): add X25519 contributory
> check and KAT boundary tests"), and `docs/decisions/D27-revocation-and-session-lifetime.md`
> is now tracked. The other half **still stands**: as of `86cf7bd` there is
> still **no decision-record entry** for the contributory rule, no
> `THREAT_MODEL.md` note, and no `CRYPTO_PROFILE.md` statement of the DH-leg
> validity rule. See §0 and [`05-gaps.md`](05-gaps.md) G-23.

**Consequence for the 356-test figure in §5:** that count was measured before
this edit landed. Re-measure before relying on it.

### 4.2 Evidence in `checkpoints/` is not public

`checkpoints/` is listed in `.gitignore:38` (`checkpoints/`), and
`git ls-files` confirms **no file under `checkpoints/` is tracked**. That
directory holds the project's richest validation artefacts, including
`VALIDATION_LEDGER.md` (which cites a specific GitHub Actions run id,
`32086456238`, and its per-test counts) and `SECURITY_RELEASE_AUDIT.md` (a
1,900-word internal self-assessment). An outside auditor cannot see any of it.

Everything in this package sourced from `checkpoints/` is therefore marked
**INTERNAL-ONLY**. The authors of this package read it; a third party cannot.

### 4.3 The design documents under `docs/design/` are untracked

`docs/design/` contains three substantial documents:

- `D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md` — the system-wide TUN architecture
  proposal (this is the document that makes "D18 is obsolete" explicit);
- `D28-server-egress-policy-1to1.md` — a server egress/SSRF policy design;
- `references-1to1.md` — a citation pass over RFCs, IANA registries, vendor
  metadata-service docs, WireGuard, OWASP and CISA.

None of them are tracked by git. They are drafts, not decisions of record.

> **HISTORICAL — the "not tracked" half is now false.** At package time
> `git ls-files docs` returned empty. Since commit `86cf7bd` the whole `docs/`
> tree is tracked (`git ls-files docs` → 17 files), so an auditor cloning the
> repo **does** see them. The other half still stands and is the substance of
> the finding: they remain **drafts, not decisions of record** — none of them
> is in `DESIGN_DECISIONS.md`, and `D25-D26` still carries
> `Status: PROPOSED`. See §0 and [`05-gaps.md`](05-gaps.md) G-20.

### 4.4 Fuzz *execution* on this host was not performed

Per `AGENTS.md` and `README.md:161-163`, the `cargo-fuzz` ASan runtime cannot
initialise on this Windows/VBS host (`0xC000026F`). The 10 fuzz targets
**build**; the 1,000-run-per-target executions evidenced in
`checkpoints/VALIDATION_LEDGER.md` were performed on GitHub Actions
`ubuntu-latest`, not here. See [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md)
§"Fuzz" and [`04-reproducibility.md`](04-reproducibility.md) for exactly what
was and was not run.

---

## 5. What was actually executed for this package

Honesty about the package's own evidence, because a package that lies about
its own basis is worthless.

| Action | Result |
|---|---|
| `cargo test --workspace --locked --target x86_64-pc-windows-msvc --lib` | **PASS** — `pq-crypto` 67, `pq-tunnel-bin` 41, `pq-tunnel-core` 236 (344 unit tests, 0 failed) |
| `cargo test --locked --target x86_64-pc-windows-msvc -p pq-tunnel-bin --test e2e_smoke -- --test-threads=1` | **PASS** — 3 passed |
| `... --test e2e_adversarial -- --test-threads=1` | **PASS** — 6 passed |
| `... --test e2e_stress -- --test-threads=1` | **PASS** — 3 passed |
| `cargo test --workspace` (including the untracked `revocation_lifetime.rs`) | **FAIL — compile error**, caused by the untracked file, see §4.1 |
| `cargo fmt --check` / `cargo clippy -D warnings` | **NOT RUN** by this package |
| `cargo fuzz` build / run | **NOT RUN** by this package |
| CI status at `ae8061d` | **NOT CHECKED** — this package has no network access to GitHub Actions |
| `checkpoints/VALIDATION_LINUX_E2E_FUZZ.md` per-test counts | **UNVERIFIED** — file is untracked and its CI run id was not re-checked |

So: **356 tests were observed passing** (344 unit + 12 E2E) on
`x86_64-pc-windows-msvc` at the time of writing, on a tree that has since
changed (§4.1a) — re-measure before relying on the figure. The project's own
README claimed "352 tests pass" (`README.md:74`) and
`checkpoints/VALIDATION_LINUX_E2E_FUZZ.md` claims 327 (native ARM64) — these
counts are all from different trees and different targets and **do not
reconcile**; see [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) row
**C-19** / **C-43**.

> **Later measurement, for reconciliation only.** At commit `86cf7bd` the
> workspace measured **422 tests passing** on `x86_64-pc-windows-msvc`; the
> current tree measures **467** after the D24 fail-gate, handshake-rate-limiter,
> roster-limit, cover-pacing and egress-guard work:
> `cargo test --workspace --target x86_64-pc-windows-msvc` → `pq-crypto` 85,
> `pq-tunnel-core` 280, `pq-tunnel-bin` 77 unit + 25 E2E (6 adversarial + 3
> smoke + 3 stress + 13 revocation/lifetime). Exactly **3** of the 280 core
> tests are `#[cfg(windows)]`, so **277** core tests run on Linux. The
> project's README now states the count anchored to that target. The figures —
> 356 (this package, at `ae8061d` + worktree), 327 (the internal Linux ledger,
> native ARM64), 422 (at `86cf7bd`) and 467 (current tree) — are measurements
> of **different trees on
> different targets**, and are not expected to agree. They are recorded here
> so that a reader does not mistake the movement for a discrepancy in the
> product.

---

## 6. Map to the rest of the project

The project documents that this package indexes. All are at the repository root
except where noted.

| Project document | Assessed here? | Where the assessment lands |
|---|---|---|
| [`PROJECT_CHARTER.md`](../../PROJECT_CHARTER.md) | Partially — principles only | [`05-gaps.md`](05-gaps.md) G-07 |
| [`THREAT_MODEL.md`](../../THREAT_MODEL.md) | Yes | [`01-evidence-index.md`](01-evidence-index.md) §T; gaps G-05, G-06 |
| [`PROTOCOL_SPEC.md`](../../PROTOCOL_SPEC.md) | Yes — **largest gap** | [`05-gaps.md`](05-gaps.md) G-01; §1 of [`spec/wire-format.md`](spec/wire-format.md) |
| [`CRYPTO_PROFILE.md`](../../CRYPTO_PROFILE.md) | Yes | [`05-gaps.md`](05-gaps.md) G-03; §1 of [`spec/crypto-construction.md`](spec/crypto-construction.md) |
| [`DESIGN_DECISIONS.md`](../../DESIGN_DECISIONS.md) | Yes | [`05-gaps.md`](05-gaps.md) G-02, G-04 |
| [`IMPLEMENTATION_GUIDE.md`](../../IMPLEMENTATION_GUIDE.md) | Barely — it is generic prose | [`05-gaps.md`](05-gaps.md) G-08 |
| [`README.md`](../../README.md) | Yes | [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) §README |
| [`CHANGELOG.md`](../../CHANGELOG.md) | Yes | [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) C-18 |
| `pq-tunnel-core/src/codec.rs` | Yes — the de facto wire spec | [`spec/wire-format.md`](spec/wire-format.md) |
| `pq-tunnel-core/src/handshake_v2.rs` | Yes — the de facto handshake spec | [`spec/crypto-construction.md`](spec/crypto-construction.md) |
| `pq-crypto/src/kdf.rs` | Yes — the de facto key schedule | [`spec/crypto-construction.md`](spec/crypto-construction.md) |
| `pq-crypto/src/kat_vectors.rs` | Yes | [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) §KAT |
| `.github/workflows/ci.yml` | Yes | [`04-reproducibility.md`](04-reproducibility.md) |
| `.github/workflows/fuzz.yml` | Yes | [`04-reproducibility.md`](04-reproducibility.md) |
| `build.ps1`, `.cargo/config.toml.example` | Yes | [`04-reproducibility.md`](04-reproducibility.md) |
| `checkpoints/*.md` (7 files) | Read; **not public** | Marked INTERNAL-ONLY throughout |
| `docs/design/*.md` (3 files) | Read; **tracked since `86cf7bd`** (was untracked at package time — HISTORICAL) | [`05-gaps.md`](05-gaps.md) G-02, G-20 |

### Source-of-truth ladder (which document wins?)

Where documents disagree, this package follows this order, because it matches
the order in which the code was actually written:

```
source code  >  design decisions (D-record)  >  threat model §13  >  spec/profiles  >  README/CHANGELOG
```

This matters because, for example, `README.md:74` said "352 tests" while
`README.md:173-176` said "67 + 236 + 37 + 12" (= 352) — but the bin crate
actually had 41 unit tests at package time, not 37. The code wins.

*(HISTORICAL: the README has since been corrected — it now states "467 tests
pass", anchored to the `x86_64-pc-windows-msvc` target, and its Linux
core-test figure is 277. See §0 X-5.)*

---

## 7. The three sentences a reviewer should take away

1. **Tunnel's threat model is better than its protocol spec.** §13 of
   `THREAT_MODEL.md` measures and honestly bounds the limits of its own
   metadata guarantees, including a mathematical statement that raising the
   cover rate cannot close the activity-detection channel. That is the kind of
   honesty that rarely survives contact with a real audit, and it should be
   preserved verbatim.
2. **The normative specifications do not exist yet.** An auditor cannot
   currently check a *second implementation* of Tunnel against anything,
   because there is no versioned, standalone description of the wire format or
   the cryptographic construction. Both skeletons in `spec/` exist to close
   exactly that hole, and both are mostly pre-filled from the code.
3. **D18 is now wrong and says it is right.** The decision record's product
   model is stale relative to the actual direction of the product, and the
   document that says so is a proposal that is not a decision of record
   (*HISTORICAL: that proposal was untracked at package time; it has been
   tracked since `86cf7bd` — but it is still not in `DESIGN_DECISIONS.md`*).
   Until D18 is superseded in `DESIGN_DECISIONS.md`, the project's own record
   of "what Tunnel is" is inaccurate. — **And the working tree is moving
   faster than the record (§4.1a).**

---

## 8. Document conventions used in this package

- Every non-obvious statement carries a **`file:line`** citation.
- Line numbers refer to the tree at commit `ae8061d` plus the uncommitted
  working-tree changes described in §4.1 and §4.1a. Lines in files touched by
  those changes are marked `[WORKING TREE]`.
- **Where a claim could not be checked, the package says UNVERIFIED and names
  what would be needed to check it. It does not guess.** Where the package
  *was* wrong, the correction is recorded in §0 and the original finding is
  left in place, marked `[CORRECTED]` / `[RESOLVED]`, rather than being
  quietly deleted.
- Where a claim could not be checked, the package says **UNVERIFIED** and
  names what would be needed to check it. It does not guess.
- Numbers reported as counts (test counts, packet rates, budgets) are quoted
  with their source; they are not recomputed unless stated.
- Deliberate omissions: this package does **not** re-derive the M7/M8/M9/M10
  measurement campaigns. Those live in `checkpoints/` and
  `THREAT_MODEL.md §13.4–13.6` and are reported as cited, not as checked.