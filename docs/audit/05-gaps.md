# 05 — Prioritized Gap List

> **This is an internal self-assessment, not an audit.** These are gaps *this
> package* found in the project's evidence. They are not findings about the
> software's correctness — an auditor may find none of them matters, or may find
> worse ones. Nothing here constitutes assurance of any kind.

**Two labels:**

- **`blocks-audit`** — an independent, competent audit of the protocol cannot be
  completed while this gap stands. Not "the project is insecure", but "the
  question cannot be *asked*".
- **`nice-to-have`** — improves auditability, trust, or efficiency; does not stop
  an audit from proceeding.

**Effort** is a rough S/M/L for a competent engineer already familiar with the
codebase: S ≈ under a day, M ≈ a few days, L ≈ a week or more.

---

## Summary

| ID | Gap | Label | Effort |
|---|---|---|---|
| **G-01** | No normative wire-format specification | `blocks-audit` | **L** |
| **G-02** | **D18 is obsolete as a product model and the record does not say so** | `blocks-audit` | **S** |
| **G-03** | No normative cryptographic-construction specification | `blocks-audit` | **L** |
| **G-04** | No decision index; superseded decisions untraceable | `blocks-audit` (light) | **S** |
| **G-05** | No threat→mitigation→test cross-reference | `blocks-audit` | **M** |
| **G-06** | No STRIDE-style mapping | `nice-to-have` | **S** |
| **G-07** | Headline guarantees (HNDL, FS) have no executable evidence | `blocks-audit` | **M** |
| **G-08** | The construction has no external known-answer vectors | `blocks-audit` | **M** |
| **G-09** | Verification-order invariant is untested | `nice-to-have` | **S** |
| **G-10** | `PROTOCOL_SPEC.md` is stale and self-referential | `blocks-audit` | **M** |
| **G-11** | `CRYPTO_PROFILE.md` §14 overstates external anchoring | `nice-to-have` | **S** |
| **G-12** | Test counts do not reconcile | `nice-to-have` | **S** |
| **G-13** | SHA-256 test accepts an incorrect digest | `nice-to-have` | **S** |
| **G-14** | Toolchain not pinned; fuzz deps not locked | `nice-to-have` | **S** |
| **G-15** | `build.ps1` is Windows-only and defaults to one crate | `nice-to-have` | **S** |
| **G-16** | `ip_packet_len` has no production caller or dedicated target | `nice-to-have` | **S** |
| **G-17** | The measurement harness for §13 is not published | `blocks-audit` (for the metadata claim) | **M** |
| **G-18** | No supply-chain artefact | `nice-to-have` | **S** |
| **G-19** | The server egress / SSRF posture is unstated | `blocks-audit` (deployment) | **M** |
| **G-20** | Design documents under `docs/design/` are untracked | `nice-to-have` | **S** |
| **G-21** | HMAC-SHA256 has no RFC 2104 vector | `nice-to-have` | **S** |
| **G-22** | Evidence cited by test *name* is given by name nowhere | `nice-to-have` | **S** |
| **G-23** | Key-establishment changes are landing in the working tree with no decision record | `blocks-audit` | **S** |

---

## `blocks-audit`

### G-01 — No normative wire-format specification

**What exists.** The wire format is specified, precisely, in Rust doc-comments
inside `pq-tunnel-core/src/codec.rs:1-160` (layout diagram, every constant with a
rationale, compile-time partition asserts at `:143-160`) and
`pq-tunnel-core/src/handshake_v2.rs:7-34,113-177` (handshake framing).

**What is missing.** Any document that states the format independently of this
source tree. `PROTOCOL_SPEC.md:490` says "Exact wire format is defined after
protocol design decisions are finalized" — they were (D13), and the result was
never fed back.

**Why it blocks an audit.** An auditor's core technique for a wire protocol is
to write an independent implementation from the specification and diff the bytes.
That is impossible when the only specification is the implementation. Every
"the format is 1280 bytes" claim is checkable only by trusting the compiler.

**The argument for "doc-comments are good enough"** — and why it fails:
doc-comments are unusually high quality here (rationale per constant, MTU
reasoning at `codec.rs:94-102`, nonce-misuse warnings at `:112-118`, and a
compile-time assertion that the codec and the KDF agree at `:156-160`). But
doc-comments (a) are not versioned separately from the code, so a
backwards-incompatible change ships with a doc-comment edit rather than a spec
version bump; (b) cannot express normative MUST/SHOULD, default-behaviour rules,
or interoperability requirements; (c) are read by implementers of *this* crate,
not by second implementers; and (d) have no change-control. They are excellent
engineering documentation and are not a specification.

**Skeleton provided:** [`spec/wire-format.md`](spec/wire-format.md).

---

### G-02 — D18 is obsolete as a product model, and the record does not say so

**Flagged prominently, as requested.**

`DESIGN_DECISIONS.md:855-864` records:

> "## D18 — Application Model: UDP Relay Client + Forwarding Backend
> **Status:** Accepted (v0.2.0-alpha)
> **Context:** The v0.2 product decision is a local **UDP relay** client (no
> TUN, no admin) …"

The product architecture has since changed direction. Tunnel is now a
**system-wide OS/networking tool** using a **TUN device and system routes**. The
project's own design proposal states this in its own words
(`docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:18-27`):

> "Tunnel is a **system-wide OS/networking tool**, not an application proxy …
> D18 … is **not** the product model. The relay code is implementation
> infrastructure: it is the app-facing *ingress* for the v0.2 datagram plane and
> remains useful as a diagnostic, a conformance harness for the slot codec, and a
> fallback on platforms without a usable TUN."

**Three problems:**

1. **D18 is marked `Accepted` and is now wrong.** An auditor reading
   `DESIGN_DECISIONS.md` concludes Tunnel is a loopback-only UDP relay proxy with
   no privileges — which misdescribes both the shipped product and its direction.
2. **The correcting document is not a decision.** It is `Status: PROPOSED`
   (`:3`), it is "not yet in `DESIGN_DECISIONS.md`" (`:14`), and it is
   **untracked by git** (`git ls-files docs` → empty).
3. **"Relay code is implementation infrastructure" is a claim an auditor cannot
   verify** — it is a design intent, and the code still has the relay as the
   *only* `data_tx` producer (`docs/design/D25-D26-...md:36`).

**Required action:**

- Add a D25/D26 entry to `DESIGN_DECISIONS.md` with Status, Context, Decision,
  Consequences, matching the existing format.
- Mark D18 as **superseded by D25** with a `superseded by:` line and a pointer.
- Reclassify the relay code explicitly as infrastructure (ingress + conformance
  harness), and say in the D-record *why* it is retained.
- Re-evaluate every D18-derived limitation in
  [`03-limitations-register.md`](03-limitations-register.md) §A.3 against the TUN
  model — L-20 (UDP-only), L-23 (1236 B cap) and L-50 (egress policy) all change
  meaning.
- Re-examine `README.md:93-123` (usage) and `README.md:1-30` (framing), which
  currently describe the relay as *the product*.

**Effort:** S for the record change; M for the doc consequences.

---

### G-03 — No normative cryptographic-construction specification

**What exists.** The key schedule is specified in doc-comments:
`pq-crypto/src/kdf.rs:151-188` (master derivation), `:191-210` (finished key),
`:212-227` (Finished MAC), `:229-235` (session nonce);
`pq-tunnel-core/src/handshake_v2.rs:36-58` (transcript and key schedule);
`DESIGN_DECISIONS.md:558-590` (the prose statement of the same).

**What is missing.** A single normative document stating, in order: inputs,
exact byte concatenations, label strings, salt values, output lengths, and the
verification order — with no reference to the implementation.

**Why it blocks an audit.** `CRYPTO_PROFILE.md:432-436` pins "ML-KEM-768 +
X25519 hybrid (HKDF-SHA256 shared-secret merge), ML-DSA-65, ChaCha20-Poly1305".
That is a *suite list*. It does not say that `ikm = ssA ‖ ssB ‖ dh_cs` in **that**
order (an order-sensitivity bug is exactly what D13 was written to prevent —
`DESIGN_DECISIONS.md:568-570`), nor that the salt is 32 zero bytes (an unusual
choice that needs justifying on the record — it appears as a bare `[0u8; 32]` at
six call sites), nor that the info strings are `"pq-tunnel-master-v2"`,
`"pq-tunnel-c2s-v2"`, `"pq-tunnel-nonce-c2s-v2"`, `"pq-tunnel-finished-v1"`.
An auditor cannot check a claim of "ML-KEM-768 + X25519 hybrid" against
"ML-KEM-768 + X25519 hybrid".

**Skeleton provided:** [`spec/crypto-construction.md`](spec/crypto-construction.md).

---

### G-04 — No decision index; superseded decisions untraceable

**What exists.** 24 decisions in `DESIGN_DECISIONS.md`, each with Status /
Context / Decision / Consequences. Quality is high.

**What is missing:**

1. **No index.** 1,400 lines with no table of contents. An auditor must read it
   all or grep.
2. **No `supersedes` / `superseded by` fields.** Only one supersession is
   recorded anywhere (`DESIGN_DECISIONS.md:1018-1022`, D20 on the v1
   deprecation schedule).
3. **Numbering is non-chronological**: D22 (`:1054`) and D23 (`:1104`) precede
   D21 (`:1184`) in the file; D24 (`:1232`) follows it. The record is appended
   to, not maintained.
4. **D27 is referenced by code but absent from the record**
   (`pq-tunnel-bin/src/identity.rs:439`; `pq-tunnel-core/src/session_manager.rs:357,363`;
   `pq-tunnel-core/src/handshake_v2.rs:1389,1400,1738`).

**Why it blocks an audit (lightly).** An auditor must be able to ask "what
supersedes this?" and get an answer. Without a supersession field, the only way
to know D18 is stale is to find the contradicting document by accident — which is
how this package found it, in an untracked file.

**Effort:** S. Add a decision table (ID, title, status, date, supersedes,
superseded by, file anchor) and a per-decision front-matter block.

---

### G-05 — No threat→mitigation→test cross-reference

`THREAT_MODEL.md` §4 enumerates five adversary classes; §11 states four
security claims; the test suite contains hundreds of named tests. **Nothing
joins them.** An auditor asking "which test demonstrates §5.6 replay protection?"
must grep for "replay" and infer.

**What exists that is close:** `checkpoints/SECURITY_RELEASE_AUDIT.md:43-66`
contains exactly such a table (16 threats × test names × strength × gap) — but
it is **INTERNAL-ONLY** (`.gitignore:38`).

**Required:** publish a threat→control→test matrix in `docs/audit/` or
`THREAT_MODEL.md`, with test names that actually resolve.

**Effort:** M.

---

### G-07 — Headline guarantees have no executable evidence

The project's two stated objectives (`PROJECT_CHARTER.md:29-33`) are HNDL
resistance and metadata resistance.

**HNDL / forward secrecy** — `PROTOCOL_SPEC.md:200-206` requires it;
`DESIGN_DECISIONS.md:677-694` argues it from the key schedule. **No test
exists** that demonstrates compromise of a long-term identity key reveals no
historical traffic. The argument is sound but it is an argument.

**Metadata resistance** — measured on loopback only, with the harness not
published (G-17), and correctly bounded by the project's own §13.4. The *bound*
is derivable from the spec — but there is no spec (G-01).

**Required:** at minimum a test that (a) runs a handshake, (b) archives the
derived keys, (c) re-derives after "compromise" of the identity seed, (d) shows
no equality. It would not prove HNDL, but it would convert `argued` into
`tested-asserted`.

**Effort:** M.

---

### G-08 — The construction has no external known-answer vectors

See [`04-reproducibility.md`](04-reproducibility.md) §5.2 and
[`spec/crypto-construction.md`](spec/crypto-construction.md).

D21 (`DESIGN_DECISIONS.md:1186-1230`) commits to external anchoring, and
`CRYPTO_PROFILE.md:429` states the selection "is anchored to external
known-answer vectors per D21". Both are true **of the primitives**. Neither is
true **of the construction**. Eight vectors anchor standards; none anchor
Tunnel's own composition.

**Required:** publish published-input/expected-output vectors for
`derive_master_secret_v2`, TH1, TH2, TH3, `derive_finished_key`,
`compute_client_finished`, `derive_client_to_server_key`, and the nonce
prefixes — computed by an independent implementation.

**Effort:** M. This is the highest value-per-effort cryptographic gap.

---

### G-10 — `PROTOCOL_SPEC.md` is stale and self-referential

- §16 (`:580-590`) lists six items as future decisions that D12–D16/D21 resolved.
- §8's state diagram (`:372-431`) does not match the implemented `CloseReason`
  set (`pq-tunnel-core/src/session_manager.rs:154-178`): no capacity, idle,
  lifetime, liveness or handshake-timeout states.
- §5 uses MUST/SHOULD but nothing in the codebase cites a conformance test for
  any of them.
- The document's own status line (`:4`) says "Draft — Requirements
  Specification", and §17 (`:600-611`) explicitly declines to define the wire
  format, the handshake, or the cryptography — all three of which now exist.

**Cross-reference defect:** `CRYPTO_PROFILE.md:281-284` says "Exact nonce
construction belongs in: `PROTOCOL_SPEC.md`". `PROTOCOL_SPEC.md` does not
define it. `pq-crypto/src/kdf.rs:229-235` does. **Two documents pointing at
each other for a definition that neither contains.**

**Required:** either promote `PROTOCOL_SPEC.md` to a normative spec (merging
`spec/wire-format.md` and the handshake construction), or retitle it clearly as
a requirements document and add a normative section index pointing at the two
specs.

**Effort:** M.

---

### G-17 — The measurement harness for §13 is not published

`THREAT_MODEL.md §13.4–13.6` is the most valuable quantitative content in the
project — and none of it is reproducible. The evidence ledger is at
`R:\pq-tunnel-lab` (`:455,509-510`), a machine-local path; raw CSVs are
"volatile" (`:539-540,578-579`).

An auditor can re-derive **§13.4's mathematics** from a normative spec alone
(no harness needed). They cannot re-derive **§13.5/13.6's numbers** (cadence
p50/p90/p99, establishment window, H3 detection rate) without the harness.

**Required:** publish the instrumentation (or a precise description of it plus
the raw CSVs), and check in the analysis scripts — including the withdrawn-stub
script, so the withdrawal is auditable rather than merely asserted
(`THREAT_MODEL.md:606-608`).

**Effort:** M.

---

### G-19 — The server egress / SSRF posture is unstated

The shipped v0.2 server is a forwarding backend that sends UDP to a
**client-chosen destination** (`DESIGN_DECISIONS.md:884-891`). The client is
authenticated, but it is still a remote party directing the server's network
egress. The project's own research says this plainly
(`docs/design/references-1to1.md:300-312`):

> "Tunnel's forwarding backend is structurally an SSRF gadget with a
> cryptographic front end: the client picks the destination, the server issues
> the request."

`docs/design/D28-server-egress-policy-1to1.md` proposes a deny-by-default CIDR
policy with an explicit `--allow-cidr` override and a port-0 rejection — but it
is **untracked and unimplemented**, and its own status is a proposal.

The D-record, the README and the THREAT_MODEL are all **silent** on this. An
operator deploying a v0.2 server exposes it.

**Required:** state the posture in `THREAT_MODEL.md` (an infrastructure-level
adversary obtaining a client credential can pivot the server — that is
`§4.5`, which currently understates it), and state in the README whether D28 is
in scope for the release.

**Effort:** M.

---

## `nice-to-have`

### G-06 — No STRIDE-style mapping

`THREAT_MODEL.md` enumerates adversaries by *capability* (§4.1–4.5), not by
STRIDE category. The mapping is trivially derivable and would let an auditor
check completeness against a familiar taxonomy (spoofing → identity pinning;
tampering → AEAD AAD; repudiation → no audit log, **absent entirely**;
information disclosure → metadata; denial of service → §7.1; elevation of
privilege → relay egress, cf. G-19).

**Note a gap STRIDE would surface that the current taxonomy misses:** there is
**no non-repudiation story at all**. A peer can deny having sent a packet. For a
tunnel this is usually acceptable, but it should be a stated decision rather than
an omission.

**Effort:** S.

### G-09 — Verification-order invariant is untested

`DESIGN_DECISIONS.md:589-590`: "Verification order on both sides:
version/sid checks → decode → signature verify → KEM. **Never KEM before
signature.**" Repeated at `handshake_v2.rs:60-61`. It is a DoS gate
(`DESIGN_DECISIONS.md:526-527`).

**No test asserts the ordering.** A refactor could invert it and the suite would
stay green.

**Required:** a test that feeds a valid-looking but wrongly-signed M1 whose
encapsulation key is garbage, and asserts the failure mode is signature
verification (not a KEM error path), or a structural assertion on the call order.

**Effort:** S.

### G-11 — `CRYPTO_PROFILE.md` §14 overstates external anchoring

`CRYPTO_PROFILE.md:429` reads: "Selection is anchored to external known-answer
vectors per D21 (RFC 8439, RFC 5869, RFC 7748, Wycheproof ML-KEM-768/ML-DSA-65)
and to D13–D15/D19."

Read plainly, this says the selection is anchored. What is anchored is the
*primitive set*. The construction (master, transcript, Finished MAC) is not, and
§14 never mentions the construction at all — `CRYPTO_PROFILE.md:24-31` still
declines to define "final handshake construction" and "packet formats".

**Required:** narrow the sentence and add a "Construction is specified in
`docs/audit/spec/crypto-construction.md` (TO BE AUTHORED)" pointer once G-03
lands.

**Effort:** S.

### G-12 — Test counts do not reconcile

Three published numbers, none matching measurement:

| Source | Number |
|---|---|
| `README.md:74` | 352 |
| `README.md:173-176` | 67 + 236 + 37 + 12 = 352 |
| `checkpoints/VALIDATION_LINUX_E2E_FUZZ.md:76` | core = 223 |
| **Measured by this package** (`x86_64-pc-windows-msvc`) | **67 + 41 + 236 + 12 = 356** |

These are the only numbers an outside reader can verify independently, and they
are wrong.

**Required:** have CI emit the count into a file the README links, or state the
count as of a named commit and date.

**Effort:** S.

### G-13 — SHA-256 test accepts an incorrect digest

`pq-crypto/src/transcript.rs:131-139`:

```rust
assert!(
    result == fips_vector || result == platform_vector,
    "SHA-256 of 'abc' must match a known test vector; got: {:02x?}", result
);
```

`platform_vector` ends `...f20015ad`; the FIPS 180-4 value ends `...f200186d`.
The comment at `:122-126` says the x86-64-emulation difference is "a platform
bug, not a code bug". But `sha2` is built with `force-soft-compact`
(`pq-crypto/Cargo.toml:14`) — scalar, no NEON/SHA-NI — and the sibling test at
`:145-157` correctly asserts only the FIPS value for `SHA-256("")`, passing
today.

A test that accepts an incorrect cryptographic output is worse than no test: it
can hide a real regression. If the platform issue is genuinely fixed, delete the
escape hatch.

**Effort:** S.

### G-14 — Toolchain not pinned; fuzz dependencies not locked

- **No `rust-toolchain.toml`.** CI uses `stable` (`ci.yml:19-21,45-47`); only the
  MSRV *check* job pins 1.85.0 (`:83-85`). `rustc` on the reference host is
  1.96.0.
- **`fuzz/Cargo.lock` is git-ignored** (`.gitignore:12`) and `fuzz/` is its own
  workspace (`fuzz/Cargo.toml:57-58`), so `cargo fuzz` floats dependency
  versions — including `libfuzzer-sys`.
- `fuzz.yml:83,92` does not pass `--locked`.
- `Cargo.lock` *is* committed for the main workspace and CI *does* use `--locked`
  there (`ci.yml:31,52,89`) — so the main workspace is fine; the gap is
  fuzz-specific.

**Effort:** S.

### G-15 — `build.ps1` is Windows-only and defaults to one crate

`build.ps1:4` defaults `$Package` to `pq-crypto`, so a bare `.\build.ps1 test`
runs one crate. `build.ps1:13` hard-codes `--target x86_64-pc-windows-msvc`.
There is no `build.sh`. Described as "portable" at `README.md:55`, which it is
not.

**Effort:** S.

### G-16 — `ip_packet_len` has no production caller or dedicated fuzz target

`pq-tunnel-bin/src/packet_len.rs:13` parses the real IP packet length out of a
zero-padded slot. Its module doc (`:5`) already says "the client's slot → TUN
write" and `:12` "never write garbage to a tun" — describing a TUN ingress
boundary that does not exist yet. Confirmed at
`docs/design/D25-D26-...md:39`: the only callers are its own tests and
`fuzz/fuzz_targets/relay_overlay.rs:20,76`.

**It *is* fuzz-covered**, as a sub-target of `relay_overlay` with four assertions
(`relay_overlay.rs:76-89`) — so this is not a coverage hole today. It becomes
one when TUN lands and this becomes a network-facing parser: a standalone target
with its own corpus, and its own reviewable invariant list, would be the right
shape.

**Effort:** S (extract the target now).

### G-18 — No supply-chain artefact

No `cargo deny`, no `deny.toml`, no SBOM, no advisory policy. The dependency set
is small and pure-Rust (verified by inspection of `pq-crypto/Cargo.toml`), and
`checkpoints/SECURITY_RELEASE_AUDIT.md:112-121` records a good supply-chain
review — but that file is INTERNAL-ONLY.

**Effort:** S.

### G-20 — Design documents under `docs/design/` are untracked

Three substantial documents exist on disk and are in git's ignore path's blind
spot (`docs/` is not itself ignored, but the files were never added —
`git ls-files docs` → empty). An auditor cloning the repo sees none of them.

This matters more than it sounds: `D25-D26-*.md` is the **only** place in the
project that says D18 is no longer the product model (G-02), and
`D28-*.md` is the **only** place the SSRF posture is analysed (G-19).

**Effort:** S (add them, or promote the content into the decision record).

### G-21 — HMAC-SHA256 has no RFC 2104 vector

`pq-crypto/src/kat_vectors.rs` has no HMAC constants. The Finished MAC — the only
thing preventing handshake assassination (`DESIGN_DECISIONS.md:730-738`) — is
built on `HMAC-SHA256` truncated to 16 bytes, and its only cross-check is a
hand-rolled HMAC in the same file (`kdf.rs:497-523`) and the same crate.

**Effort:** S. Add RFC 2104 test case 1 as a vector.

### G-22 — Evidence cited by test name is given by name nowhere

- `DESIGN_DECISIONS.md:1359-1366` cites "10 new focused tests" for D24's
  invariants — **no test names**.
- `DESIGN_DECISIONS.md:1359` also says "226 core tests green"; `README.md:175`
  says 236.
- `CHANGELOG.md:102-108` describes the D16 nonce-exhaustion E2E without a name.

`checkpoints/SECURITY_RELEASE_AUDIT.md:45-66` *does* give names — but is
INTERNAL-ONLY.

**Rule worth adopting:** any decision that cites a test as evidence must name it.

**Effort:** S.

---

### G-23 — Key-establishment changes are landing with no decision record

**Observed during this package's session, after the baseline was recorded.**

`pq-crypto/src/classical.rs` gained an X25519 **contributory check**:
`diffie_hellman` now returns `None` when the shared secret is all-zero, citing
RFC 7748 §6.1 (*"MAY check … whether K is the all-zero value and abort if so"*)
and §7 (Curve25519 has cofactor 8, so a small-order peer key drives every scalar
multiple to the identity element). `handshake_v2.rs` grew by roughly 135 lines
in the same window to handle the `None` case.

**This is a genuine security improvement and the reasoning is correct.** The
problem is that it is **entirely unrecorded**:

- no `DESIGN_DECISIONS.md` entry (highest is D24; D27 is referenced by other
  uncommitted code but also absent);
- no `THREAT_MODEL.md` note, despite it changing what a malicious peer can do;
- no `CRYPTO_PROFILE.md` statement of the DH-leg validity rule;
- no test named anywhere;
- nothing committed — `git status` shows `M pq-crypto/src/classical.rs`.

**Why it blocks an audit.** An auditor must be able to enumerate every change to
the key-establishment path and find its rationale and its tests. At the moment
the key-establishment path is a moving target inside the working tree.

**Required:** add a decision record entry (D27 or D28, after reconciling the
existing D27 references), state the contributory rule in
`spec/crypto-construction.md` §8/§13, add a test with a small-order public key
(e.g. the all-zero point, or a point of order 8), and commit.

**Effort:** S — the analysis is already done and correct; only the record is
missing.

---

## Sequencing suggestion

If the project wants to move from "evidence package" toward
"auditable specification", this order minimises wasted work:

1. **G-14, G-15, G-20, G-12** — trivial, unblocks reproduction. (½ day)
2. **G-13, G-21, G-22, G-09, G-11** — small, closes specific wrong/incomplete
   claims. (1–2 days)
3. **G-04, G-02, G-23** — decision-record hygiene; **G-02 is *required* for the
   record to be truthful**, and **G-23 stops the record from falling further
   behind the code**. (1 day)
4. **G-01, G-03** — write the two specifications from the skeletons in `spec/`.
   This is the real work and everything else is a distraction from it. (L)
5. **G-08** — compute and publish construction vectors, once G-03 defines the
   construction. (M)
6. **G-07, G-05, G-17** — executable evidence for the headline claims, and the
   cross-reference table. (M)
7. **G-10, G-16, G-18, G-06, G-19** — consolidation. (M)

Steps 1–3 are cheap and should not wait for step 4. Step 4 is the gate on
everything else, because without a normative construction, step 5's vectors have
no definition to anchor to.