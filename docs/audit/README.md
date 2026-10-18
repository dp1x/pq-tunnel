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
  `ae8061d`)
- **Working tree at package time:** **not clean, and it changed during the
  session** — see §4 and §4.1a
- **Version under assessment:** `v0.2.0-alpha` (`Cargo.toml:10` → `version = "0.2.0"`)

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
that proposal is **PROPOSED, not accepted**, is not in the decision record, and
is **not tracked in git** (`git ls-files docs` → empty). An auditor reading
`DESIGN_DECISIONS.md` alone would reach the wrong conclusion about the
product. This is documented in [`05-gaps.md`](05-gaps.md) as `blocks-audit`
gap **G-02**.

---

## 4. Baseline caveats — an auditor must know before reading anything

These are properties of the tree as it stood when this package was written.
They matter because several of them mean the committed `main` branch is *not*
the same as what was inspected here.

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

1. **The untracked working tree is currently BROKEN.**
   `cargo test --workspace --locked --target x86_64-pc-windows-msvc` fails to
   compile with 9 errors in the untracked test target
   `pq-tunnel-bin/tests/revocation_lifetime.rs`:
   `unresolved import pq_tunnel_core::MlDsaPublicKeyUnused`,
   `cannot find type HandshakeOutcome in this scope`, three
   `cannot call non-const method ... SocketAddr::parse in constants`,
   `no method named cfg_max_attempts found for mutable reference`, plus type
   and borrow errors. **This failure is not present on clean `main`** — it is
   caused by the untracked file. Do not attribute it to the product.
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
README claims "352 tests pass" (`README.md:74`) and
`checkpoints/VALIDATION_LINUX_E2E_FUZZ.md` claims 327 (native ARM64) — these
counts are all from different trees and different targets and **do not
reconcile**; see [`02-claims-vs-evidence.md`](02-claims-vs-evidence.md) row
**C-19** / **C-43**.

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
| `docs/design/*.md` (3 files) | Read; **not tracked** | [`05-gaps.md`](05-gaps.md) G-02 |

### Source-of-truth ladder (which document wins?)

Where documents disagree, this package follows this order, because it matches
the order in which the code was actually written:

```
source code  >  design decisions (D-record)  >  threat model §13  >  spec/profiles  >  README/CHANGELOG
```

This matters because, for example, `README.md:74` says "352 tests" while
`README.md:173-176` says "67 + 236 + 37 + 12" (= 352) — but the bin crate
actually has 41 unit tests today, not 37. The code wins.

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
   document that says so is an untracked proposal. Until D18 is superseded in
   `DESIGN_DECISIONS.md`, the project's own record of "what Tunnel is" is
   inaccurate. — **And the working tree is moving faster than the record
   (§4.1a).**

---

## 8. Document conventions used in this package

- Every non-obvious statement carries a **`file:line`** citation.
- Line numbers refer to the tree at commit `ae8061d` plus the uncommitted
  working-tree changes described in §4.1 and §4.1a. Lines in files touched by
  those changes are marked `[WORKING TREE]`.
- Where a claim could not be checked, the package says **UNVERIFIED** and
  names what would be needed to check it. It does not guess.
- Numbers reported as counts (test counts, packet rates, budgets) are quoted
  with their source; they are not recomputed unless stated.
- Deliberate omissions: this package does **not** re-derive the M7/M8/M9/M10
  measurement campaigns. Those live in `checkpoints/` and
  `THREAT_MODEL.md §13.4–13.6` and are reported as cited, not as checked.