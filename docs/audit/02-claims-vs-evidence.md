# 02 — Claims vs. Evidence

> **This is an internal self-assessment, not an audit.** Every "Claim" below is
> quoted from the project's own documentation. The "Evidence" column records what
> the project offers *in support of that claim* — it does **not** endorse it. The
> "Strength" column grades the evidence, **not** the claim's truth. A claim marked
> `asserted-only` may well be true; what is absent is anything a third party could
> check.

**This document exists to be unflattering.** Its purpose is to answer one
question honestly: *for each thing Tunnel says about itself, what would an auditor
actually be able to check?*

---

## How to read the Strength column

| Strength | Definition |
|---|---|
| **measured** | A number was produced by a run; the number and its provenance are recorded. |
| **tested-asserted** | A test asserts the property and passes; the test's oracle was written by the same authors and the property is not anchored to anything external. |
| **anchored** | The property is pinned to an external, published artefact (an RFC vector, a Wycheproof vector, a fixed external measurement). Still not *proof*, but falsifiable by someone outside the project. |
| **argued** | A reasoned argument in prose. No executable or external anchor. |
| **asserted-only** | Stated in documentation. **No** supporting artefact of any kind. |
| **self-contradicted** | The claim is contradicted elsewhere in the project's own material. |

---

## 1. The headline claims (README.md)

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-01** | "post-quantum, metadata-resistant secure networking protocol and reference implementation" (`README.md:1-2`) | ML-KEM-768 + X25519 hybrid key establishment; ChaCha20-Poly1305; cover traffic at 2 Mbps fixed | **tested-asserted** for the crypto; **argued** for "metadata-resistant" | "Metadata-resistant" is a property of the *traffic*, not the code. The project's own analysis says the activity channel is **not** closed (`THREAT_MODEL.md:509-518`). The README hedges at `README.md:40-42` ("It is *not* traffic-flow anonymity") — good, but the headline noun is unqualified. |
| **C-02** | "keep traffic confidential against harvest-now-decrypt-later adversaries (including future quantum computers)" (`README.md:4-6`) | Dual-ephemeral hybrid KEX: both ML-KEM-768 *and* X25519 are fresh per session (`DESIGN_DECISIONS.md:561-563`); identity keys never enter the key schedule (`DESIGN_DECISIONS.md:503-505,627-631`); master derives only from ephemeral secrets (`DESIGN_DECISIONS.md:693-694`) | **argued** | The *reasoning* is sound and is stated clearly. But there is **no test that a compromised long-term key does not reveal past traffic**, because such a test would need to capture and re-decrypt historical traffic. No key-compromise simulation exists anywhere. The property is *argued from the key schedule*, and the key schedule is documented only in doc-comments. |
| **C-03** | "1.5-RTT, mutual-authentication, hybrid (ML-KEM-768 + X25519) handshake" (`README.md:9-13`) | `handshake_v2.rs` module doc `:1-85`; 3-message flow; e2e smoke tests | **tested-asserted** | RTT count is a design fact, not measured. No timing measurement of RTT exists in the public tree. |
| **C-04** | "fixed 1280-byte wire datagrams" (`README.md:11-12`) | `PACKET_SIZE = 1280` + compile-time partition asserts | **anchored** (to the code, and via `design_decisions`) | Fully verifiable and true. One of the strongest claims in the README. |
| **C-05** | "AEAD envelope with a sliding **1024-bit** replay window over a 64-bit sequence counter" (`README.md:11-13`) | `WINDOW_BITS = 1024` (`replay.rs:37`), `replay.rs` test suite, `e2e_adversarial.rs:248,267`, fuzz target `replay_window` | **tested-asserted** | Strong. The window semantics (`bit i ↔ counter highest-i-1`) are documented (`replay.rs:44-48`) and exercised. |
| **C-06** | "per-direction nonce accounting" (`README.md:12-13`) | `derive_nonce_prefix_c2s/_s2c` (`kdf.rs:118-139`); test `nonce_prefixes_are_different` (`kdf.rs:297-303`) | **tested-asserted** | The test asserts the two prefixes differ for a *fixed* master — it does not test the cross-session uniqueness property at the point where it matters. A stronger test (`different_session_ids_derive_different_nonce_prefixes`, `kdf.rs:330-343`) does exist. Adequate. |
| **C-07** | "single-event-per-call session manager with DoS-rate limiting and fail-secure semantics" (`README.md:12-14`) | `ManagerEvent` single-output design (`session_manager.rs:180-217`); fail-gate (`session_manager.rs:126-135`); D24's 10 invariant tests | **tested-asserted** | D24's tests are genuinely good (`DESIGN_DECISIONS.md:1359-1366`): they assert "4096 distinct ports allocate **zero** buckets". |
| **C-08** | "**Validation (v0.2.0-alpha released): 352 tests pass**" (`README.md:74`) | — | **self-contradicted** | Measured on this host at package time: **344 unit** (67 + 41 + 236) + **12 E2E** = **356**. `README.md:173-176` itself sums to 67+236+37+12 = 352, but the bin crate has 41 unit tests, not 37. **Three numbers, none of which reconcile.** See C-19. |
| **C-09** | "including external known-answer vectors (RFC 8439 …, RFC 5869 …, RFC 7748 …, Wycheproof ML-KEM-768 and ML-DSA-65 — D21)" (`README.md:75-78`) | `kat_vectors.rs` with per-constant provenance comments; 8 KAT test functions | **anchored** | **The strongest cryptographic claim in the README and it is true.** One caveat: the SHA-256 "abc" vector test accepts a wrong answer (`transcript.rs:131-139`). That test is not in the README's list, but it is in the same family of claims. |
| **C-10** | "adversarial end-to-end cases (garbage, forged handshake, version downgrade, AEAD tamper, replay, reordering) that assert a silent drop plus a healthy post-attack round trip" (`README.md:78-81`) | 6 named tests | **tested-asserted** | The names check out: `e2e_adversarial.rs:104,146,202,225,247,266`. Each is real and each ran green in this session (6 passed). **No gap** — the claim is accurate. |
| **C-11** | "the D16 nonce-exhaustion full-loop driver E2E (close → auto re-establish → continue)" (`README.md:81-83`) | Cited at `CHANGELOG.md:102-108` | **UNVERIFIED** | The test is in the untracked `pq-crypto/tests/` + referenced from `THREAT_MODEL.md:479-484` as commit `9db71df`. This package did not locate and run it by name. |
| **C-12** | "Adversarial design-review campaigns (cryptography, protocol, security) were completed and their findings fixed" (`README.md:83-85`) | None in the public tree | **asserted-only** | No campaign briefs, no reviewer identities, no findings list, no fix commits referenced. **The word "adversarial" implies an adversary outside the project; nothing supports that reading.** See the README's own disclaimer at `:204-211`. |
| **C-13** | "the modern-harness cargo-fuzz targets **compile**" (`README.md:85-87`) | `fuzz/Cargo.toml:16-55`; `README.md:161` | **tested-asserted** | Honest phrasing ("compile", not "ran") and the README immediately explains why (`README.md:161-163`). **No gap — this is precisely the right way to phrase it.** |
| **C-14** | "Detailed validation logs are kept private (not part of the public release)." (`README.md:88-89`) | — | **PRESENT and correctly disclosed** | This is the honest sentence that makes C-12 interpretable. An auditor should read it as: *the evidence exists, you cannot see it.* |
| **C-15** | "`v0.2.0-alpha` is tagged and **signed**" (`README.md:89-90`) | Not checkable from this tree | **UNVERIFIED** | A signature claim is checkable by anyone with the repo and the key. Good that it is made; this package did not verify it. |

---

## 2. HNDL and forward secrecy

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-16** | "Tunnel requires forward secrecy" (`PROTOCOL_SPEC.md:200`) / "Compromise of long-term key material MUST NOT automatically reveal previously protected sessions" (`PROTOCOL_SPEC.md:202`) | D14's key hierarchy: identity keys never enter key agreement (`DESIGN_DECISIONS.md:677-678`); master derives only from ephemeral secrets (`:693-694`) | **argued** | No test. A test is *constructible*: generate identity key A, run a handshake, archive the session keys, then delete A and confirm the archived traffic is undecryptable. **No such test exists.** This is the project's headline guarantee and it has zero executable evidence. |
| **C-17** | "Forward secrecy depends on the complete key establishment construction. A post-quantum KEM alone does not automatically provide forward secrecy." (`CRYPTO_PROFILE.md:161-162`) | — | **argued** | Correct, and a good thing to say. But it is followed (`:165-170`) by a list of *requirements*, not a proof that the implementation meets them. |
| **C-18** | "ML-KEM-768 both directions, plus X25519 both directions" — all legs ephemeral (`DESIGN_DECISIONS.md:561`) | `handshake_v2.rs` imports both keypair types (`:97-99`); `MlKemKeypair::generate()` / `X25519Keypair::generate()` | **tested-asserted** | The handshake tests run end to end. That the keys are *fresh per session* is visible in the code (`generate()` per handshake) but is not asserted by a test that counts distinct keys across two sessions. |

---

## 3. Metadata resistance — the honest and the un-honest parts

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-20** | "metadata resistance is a core Tunnel objective" / "Protect the content and protect the pattern." (`PROTOCOL_SPEC.md:44-50`) | — | **argued** | A goal statement, not a claim. Fine as stated. |
| **C-21** | "Metadata resistance is a primary design goal." (`THREAT_MODEL.md:288`) | — | **argued** | Same. |
| **C-22** | "reduced metadata leakage **compared with conventional encrypted tunnels**" (`THREAT_MODEL.md:415`) | Fixed 1280-byte size; 2 Mbps cover grid; §13.4's λ·W ≥ 1 bound | **argued** + **partly measured** | The comparison is to "conventional encrypted tunnels" — a class, not a named system. No comparison against a specific baseline (WireGuard, etc.) is made. §13.4 supports the "reduced" part honestly. **The comparative claim is unquantified.** |
| **C-23** | "Default policy is fixed and permanent for v0.2 alpha: cover enabled, fixed-rate, 2 Mbps (5.12 ms per 1280-byte slot)." (`DESIGN_DECISIONS.md:938-941`) | `DEFAULT_COVER_RATE_BPS = 2_000_000` (`scheduler.rs:36`); `interval_from_rate_bps` (`scheduler.rs:70`) | **measured** | §13.5 records the wire measurement: server 182.6 pkt/s = 93.5% of nominal, p50 5.5 ms (`THREAT_MODEL.md:543-547`). **This is a claim with real numbers behind it and an honest shortfall disclosure.** Exemplary. |
| **C-24** | "the wire pattern of an established idle link is a constant, predictable packet stream per direction — **no timing/idle/burst leakage from the shaper**" (`DESIGN_DECISIONS.md:975-976`) | §13.5 measurement | **argued, and overstated** | The project itself contradicts the "no … leakage" half: activity **above** the floor is separable with λ·W ≥ 1, and session count is exactly N packets per tick (`THREAT_MODEL.md:509-518`). The claim is scoped to "from the shaper", which is true — but a reader skimming the Advantages list will take it as a broader statement than it is. **Recommend rewording.** |
| **C-25** | "Cover traffic must create a **stable observable traffic pattern over time** — a protocol-level constant rate — not perfectly timed packets." (`DESIGN_DECISIONS.md:931-932`) | `CoverScheduler` pure-periodic semantics; single-catch-up-on-stall | **tested-asserted** | The single-emit rule is unit-tested (`scheduler.rs` tests, cited at `DESIGN_DECISIONS.md:978-979`). |
| **C-26** | "A passive observer at the source vantage detects establishment **30/30** (Wilson 95% CI [0.886, 1.000])" (`THREAT_MODEL.md:621-622`) | M10 campaign, `THREAT_MODEL.md:574-578` | **measured (loopback)** | Honestly scoped: "burst survival across real links is untested (loopback vantage)" (`:623`). **Good.** |
| **C-27** | "Session linkability (H2) — **INCONCLUSIVE**" (`THREAT_MODEL.md:604`) | Single-identity dataset; "an earlier '0/30 NN match' figure was an analysis-script stub and is withdrawn" (`:606-608`) | **disclosed negative result** | **This is the single strongest act of intellectual honesty in the entire project.** A stubbed number was found, withdrawn, and replaced with "inconclusive". Rare. Preserve this. |
| **C-28** | "the client's M3 retransmit budget … must complete strictly inside the session manager's default handshake deadline" (`DESIGN_DECISIONS.md:638-643`) | `m3_max_attempts = 4` (≈9.3 s) vs `handshake_timeout = 30 s` (`session_manager.rs:145`) | **tested-asserted** | A regression test is claimed (`DESIGN_DECISIONS.md:640`; `CHANGELOG.md:58-65`). **UNVERIFIED** by this package: the test name is not given. |

---

## 4. Cryptographic correctness

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-29** | "KATs exercise production paths … **KATs are not helper-only**." (`checkpoints/SECURITY_RELEASE_AUDIT.md:81`) | Real `encapsulate`/`decapsulate`/`encrypt`/`decrypt` calls in the KAT tests | **tested-asserted** | The claim is correct — inspected at `pq-crypto/src/kem.rs:169-200`, `aead.rs:218`, `kdf.rs:560-575`, `classical.rs:77-125`. But the source of this claim is **INTERNAL-ONLY** (`checkpoints/`). A reader of the public tree cannot check it without doing the inspection themselves. |
| **C-30** | "**Vectors are never adjusted** to make a test pass. A failing KAT means the implementation under test, or the transcription, is defective" (`DESIGN_DECISIONS.md:1204-1206`) | Policy statement | **argued** | Sound policy. **No mechanism enforces it.** A reviewer cannot tell whether a vector was ever edited — there is no hash of the upstream JSON, no file hash, no signed manifest. Git history would help, but there is no recorded rule that vector bytes may not be touched in a PR. |
| **C-31** | "Pinning: **anchored to external known-answer vectors per D21** (RFC 8439, RFC 5869, RFC 7748, Wycheproof ML-KEM-768/ML-DSA-65)" (`CRYPTO_PROFILE.md:429`) | 8 KAT functions with provenance comments | **anchored** | True for the 8 primitives. **The anchoring claim silently does not extend to Tunnel's own construction** — master secret, TH1/TH2/TH3, Finished MAC, traffic keys, nonce prefixes all have **no external vector**. `CRYPTO_PROFILE.md:429` reads as if the whole suite is anchored. **This is the most misleading sentence in the crypto documentation.** |
| **C-32** | "RFC 7748 X25519" KAT | `x25519_rfc7748_6_1_kat` (`classical.rs:77`) | **anchored** | Correct. Note this test was added later than D21 was written — D21 (`:1186`) predates the classical.rs module. Minor. |
| **C-33** | "the `ml-dsa` deterministic variant … is pinned by `ml_dsa_sign_is_deterministic` plus the external known-answer vector in `ml_dsa_65_wycheproof_sign_kat`" (`DESIGN_DECISIONS.md:618-620`) | `signature.rs:324`, `signature.rs:303` | **anchored** | The provenance note at `kat_vectors.rs:26-33` explains why the Wycheproof sign vector is genuinely deterministic (`rnd` absent ⇒ zero). **Well-reasoned.** |
| **C-34** | "Cross-checked against an independent HMAC implementation" for the Finished MAC (`kdf.rs:525-526`) | Hand-rolled RFC 2104 HMAC in `kdf.rs:497-523` | **tested-asserted** | "Independent" means *written by the same authors*, not *by a third party*. The HMAC-SHA256 primitive itself has **no RFC 2104 KAT** (`kat_vectors.rs` has no HMAC constants). The Finished MAC is HMAC over a *truncated digest* — the one place where a subtle HMAC bug would be silent. |
| **C-35** | "domain separation: distinct HKDF `info` labels" (`checkpoints/SECURITY_RELEASE_AUDIT.md:74`) | 7 distinct labels in `kdf.rs:79,102,112,124,134,143,148,178,202` | **tested-asserted** | Test `finished_key_is_label_separated_from_traffic_keys` (`kdf.rs:481-492`) checks *inequality* only — it does not check that outputs are *independent*. Inequality of 32-byte outputs from HKDF is essentially guaranteed by the PRF, so this test is nearly vacuous. It cannot fail in practice. |

---

## 5. Replay, integrity, fail-secure

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-36** | "envelope decrypt fuzz (1M runs) — **no path to acceptance of unauthenticated data found**" (`THREAT_MODEL.md:463-464`) | `fuzz/fuzz_targets/envelope_decrypt.rs`, 1M runs | **INTERNAL-ONLY** | The 1M figure comes from `R:\pq-tunnel-lab` (`THREAT_MODEL.md:455`), not from the tree. This package did not query it. **The CI-documented figure is 1,000 runs** (`ci.yml:63-71`). |
| **C-37** | "all adversarial E2E cases **fail by disconnection, never by acceptance**" (`THREAT_MODEL.md:472-473`) | 6 tests, all green | **tested-asserted** | Verified: 6 passed in this session. **Claim holds for the 6 enumerated cases.** |
| **C-38** | "**every peer-input failure → `ManagerEvent::None` (silent drop, zero state mutation)**; no error datagrams emitted" (`checkpoints/SECURITY_RELEASE_AUDIT.md:36`) | `ManagerEvent::None` (`session_manager.rs:216`); handshake "silent drops" (`handshake_v2.rs:185-191`) | **tested-asserted** | INTERNAL-ONLY source. The property is visible in the code and is fuzz-covered by `handshake_driver_receive` and `session_manager_receive`. |
| **C-39** | "no downgrade path" / "The version byte is the full profile selector: strict equality both directions, no negotiation, mismatch → silent drop" (`DESIGN_DECISIONS.md:605-607`) | `PacketHeader::decode` rejects `version != PROTOCOL_VERSION` (`codec.rs:295-301`); `e2e_adversarial_version_downgrade_rejected` (`e2e_adversarial.rs:202`) | **anchored (to code) + tested-asserted** | One of the better claims. The check is 3 lines and a test exists. |
| **C-40** | "verification order … **never KEM before signature**" (`DESIGN_DECISIONS.md:589-590`) | Stated in D13 and `handshake_v2.rs:60-61` | **asserted-only** | **No test asserts the ordering.** This is a security-relevant ordering (it is a DoS gate, per `DESIGN_DECISIONS.md:526-527`) and it could be inverted in a refactor without any test failing. |

---

## 6. Resource exhaustion (D24 — the project's best-documented area)

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-41** | "unknown-SID traffic across 4,096 distinct ports on one IP allocates **zero** buckets" (`DESIGN_DECISIONS.md:1360-1362`) | "10 new focused tests assert the resource invariants directly" (`:1359`) | **tested-asserted** | Test names are **not given**. An auditor cannot find them by grepping. This is a recurring pattern (see C-28). |
| **C-42** | "the M1 limiter's exact M1=2 / M1+M3=3 accounting is pinned through observable gate behaviour with no wall clock" (`DESIGN_DECISIONS.md:1365-1366`) | 2 tests | **tested-asserted** | Same: no test names. |
| **C-43** | "Memory was sound (genuinely capped); CPU was the defect." (`DESIGN_DECISIONS.md:1259`) | Analysis + fix | **argued** | Sound. The analysis is concrete (65,535 ports per IP; 409.6 datagrams/window). |
| **C-44** | "Out of scope: … a server deliberately saturated by a very large number of distinct well-formed sources" (`THREAT_MODEL.md:332-335`) | — | **PRESENT, correctly disclosed** | Good. An auditor should note this is an **admitted** DoS ceiling. |

---

## 7. Fuzz and test claims

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-45** | "10 `cargo-fuzz` targets are defined; all use the modern `fuzz_target!` harness and compile" (`README.md:176-179`) | `fuzz/Cargo.toml:16-55` (10 `[[bin]]` targets) | **tested-asserted** | Accurate. Four independent places list the same 10 targets and they agree — a small but real hygiene win. |
| **C-46** | "≈6.9 M executed units … **Harness-only defects found, zero product defects**" (`THREAT_MODEL.md:481-483`) | `R:\pq-tunnel-lab` | **INTERNAL-ONLY + UNVERIFIED** | Cannot be checked. Also note `THREAT_MODEL.md:487` correctly says "Absence of defects in fuzzed paths does not imply a proof of correctness elsewhere" — which materially weakens C-46 and is stated in the same section. **The caveat is more useful than the claim.** |
| **C-47** | "session/handshake driver fuzz (≈1.9 M combined runs) plus scripted churn over both managers (105,350 runs)" (`THREAT_MODEL.md:466-469`) | as above | **INTERNAL-ONLY + UNVERIFIED** | Same. |
| **C-48** | "MSan/UBSan unavailable on the current toolchain (`rust-src` missing, `-Zsanitizer=undefined` invalid) — outstanding, **not silent**" (`THREAT_MODEL.md:486-489`) | — | **PRESENT, correctly disclosed** | `fuzz.yml:45-58` does offer a `sanitizer` input including `memory`/`thread` and a `rustflags` escape hatch, so the capability exists but was not exercised. **Honest.** |
| **C-49** | "Fuzz execution is unavailable on Windows/VBS hosts" (`README.md:219-220`, `CHANGELOG.md:120-121`) | — | **PRESENT, correctly disclosed** | Accurate. This package did not attempt fuzz execution. |

---

## 8. Claims about the platform / build

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-50** | "the canonical build/test target is `x86_64-pc-windows-msvc` (the development host is aarch64 Windows; the `--target` flag pins the tested toolchain)" (`README.md:127-131`) | `AGENTS.md` build section; `build.ps1:9-13` | **argued** | The stated reason (aarch64 host can't compile `aws-lc-sys`) is **stale**: D20 removed the QUIC/TLS stack and `aws-lc-sys` is gone — stated in `DESIGN_DECISIONS.md:1035-1039`. The `--target` convention survives for a reason that no longer applies. An external auditor following this instruction on Linux is told to drop the flag (correct) but the justification is wrong. |
| **C-51** | "CI enforces fmt, clippy, tests, fuzz build + smoke on Windows, Linux, and MSRV 1.85" (`CHANGELOG.md:54-56`) | `.github/workflows/ci.yml` | **anchored (to the workflow file)** | Verified present. But the specific CI *outcomes* are not in the repo — only run logs on GitHub, which this package could not reach. |
| **C-52** | "`Cargo.lock` — pinned, reproducible dependency set" (`README.md:57`) | `Cargo.lock` tracked | **anchored** | True for the main workspace. **False as stated for fuzz**: `fuzz/Cargo.lock` is git-ignored (`.gitignore:12`) and `fuzz/` is a separate workspace (`fuzz/Cargo.toml:57-58`), so `cargo fuzz` resolves floating versions. |
| **C-53** | "Workspace is clippy-clean under `-- -D warnings`" (`CHANGELOG.md:53-54`) | `ci.yml:30,49` | **UNVERIFIED** | This package did not run clippy. The claim is consistent with `AGENTS.md` ("the workspace is clippy-clean under it") but is asserted in two places by the same authors. |
| **C-54** | "workspace uses no native-C crypto backends; `aws-lc-sys`/`ring`/`openssl` **absent**" (`checkpoints/SECURITY_RELEASE_AUDIT.md:119`) | — | **INTERNAL-ONLY** | A reader can verify by inspecting `pq-crypto/Cargo.toml` (it lists only pure-Rust crates), so the claim is *checkable* — but the claim itself lives in an untracked file. |

---

## 9. Known-issues section (the strongest part of the README)

| # | Claim (quoted) | Evidence offered | Strength | Gap |
|---|---|---|---|---|
| **C-55** | "**No independent third-party security audit has been performed.** Everything asserted here was produced and checked in-tree." (`README.md:204-207`) | — | **PRESENT** | **This single sentence is the most valuable line in the entire documentation set.** It should be the first thing any reader sees. Currently it is buried in a "Known issues" list at line 204 of a 250-line README. Recommend promoting it to the top. |
| **C-56** | "its oracles are written by the same project. Treat the cryptographic and protocol claims as *unreviewed by outsiders*." (`README.md:208-211`) | — | **PRESENT** | Precisely correct. This is the statement that makes the whole README honest, and it is already there. |
| **C-57** | "interoperability with other implementations is not yet verified (no independent implementation exists yet)" (`README.md:212-215`) | — | **PRESENT** | Accurate. The consequence — that the protocol therefore cannot be *tested* for interoperability, and that no conformance test exists — is not stated. See `05-gaps.md` G-09. |

---

## 10. Cross-document consistency findings

| # | Finding | Evidence | Severity |
|---|---|---|---|
| **C-58** | **Test counts do not reconcile.** `README.md:74` = 352. `README.md:173-176` = 67+236+37+12 = 352. Measured today = 67 + 41 + 236 + 12 = 356. `checkpoints/VALIDATION_LINUX_E2E_FUZZ.md:76` says core = 223; measured = 236. | as cited | **Medium** — an auditor who runs the suite and gets a different number loses confidence in the rest. |
| **C-59** | **`PROTOCOL_SPEC.md` §16 still lists six items as "future design decisions"** (`PROTOCOL_SPEC.md:580-590`) that D12–D16 and D21 resolved. | as cited | **Medium** — the spec is stale relative to the decision record. |
| **C-60** | **`CRYPTO_PROFILE.md:281-284` says nonce construction belongs in `PROTOCOL_SPEC.md`; `PROTOCOL_SPEC.md` does not define it.** Neither document does. The actual definition is `pq-crypto/src/kdf.rs:229-235`. | as cited | **Medium** — a reader following the document cross-references finds nothing. |
| **C-61** | **`D18` describes a product model the project has moved past** (`DESIGN_DECISIONS.md:860-864` vs `docs/design/D25-D26-...md:18-27`). | as cited | **High** — an auditor reading the decision record reaches the wrong conclusion about what Tunnel is. |
| **C-62** | **Decision numbering is non-chronological**: D22 (`:1054`) and D23 (`:1104`) appear before D21 (`:1184`). | as cited | **Low** for content, **Medium** for auditability — it signals the file is appended to rather than maintained. |
| **C-63** | **`README.md:127-131` justifies the `--target` convention with `aws-lc-sys`**, which D20 removed (`:1035-1039`). | as cited | **Low** — stale rationale. |
| **C-64** | **The SHA-256 "abc" test accepts a wrong answer.** `transcript.rs:131-139` passes if the digest ends `...f20015ad` as well as the FIPS `...f200186d`, and the comment calls the correct one "a platform bug" (`:122-126`). | as cited | **Medium** — a test that accepts an incorrect cryptographic output is worse than no test. The `sha256("")` test at `:145-157` correctly asserts only the FIPS value, which makes the inconsistency visible. |
| **C-65** | **Untracked code references a decision `D27` that does not exist** in `DESIGN_DECISIONS.md` (highest is D24) and a document path `docs/decisions/D27-revocation-and-session-lifetime.md` that is not in the tree. | `pq-tunnel-bin/src/identity.rs:439`; `pq-tunnel-bin/tests/revocation_lifetime.rs:3` | **Medium** — the working tree is ahead of the decision record, and one test file does not compile. |

---

## 11. The ruthless summary

Ranked by how much weight the claim carries versus how much evidence stands
behind it.

| Rank | Claim | The problem |
|---|---|---|
| 1 | **C-02 / C-16 — HNDL resistance and forward secrecy** | The project's entire mission. Evidence is a **key schedule documented only in doc-comments**, plus a correct argument. **No test demonstrates that compromising a long-term key reveals nothing.** No external KAT for the master-secret derivation. No spec to check it against. |
| 2 | **C-31 — "anchored to external known-answer vectors"** | Reads as if the whole crypto suite is externally anchored. It is not: **the four construction pieces Tunnel invented itself (master secret, TH1/TH2/TH3, Finished MAC, traffic/nonce keys) have no external anchor at all.** The sentence needs narrowing. |
| 3 | **C-12 — "Adversarial design-review campaigns … were completed"** | **Zero public evidence.** No briefs, no reviewers, no findings, no fix commits. Combined with "no independent audit" (`C-55`), the natural reading is *internal review presented with adversarial vocabulary*. |
| 4 | **C-24 — "no timing/idle/burst leakage from the shaper"** | Contradicted in spirit by the project's own §13.4. True only under a scope the reader must infer. |
| 5 | **C-46 / C-47 — the 6.9M-unit fuzz campaign** | The numbers are impressive and completely unverifiable from the public tree. |
| 6 | **C-40 — "never KEM before signature"** | A security-relevant ordering with no test. Cheap to fix, and it would be a real improvement. |
| 7 | **C-08 / C-58 — test counts** | Small numbers, but they are the *only* numbers an auditor can verify independently, and they are wrong. |
| 8 | **C-64 — SHA-256 test accepts a wrong digest** | Concrete defect in a cryptographic test. |

### And what the project gets right

Listing this is not politeness; it is what makes the rest of this table credible:

- `README.md:204-211` volunteers the single most important caveat in the whole
  documentation set, unprompted (C-55, C-56).
- `THREAT_MODEL.md:604-608` withdraws a previously-published figure because it
  turned out to be a **stub**, and replaces it with "INCONCLUSIVE" (C-27).
- `THREAT_MODEL.md:509-518` derives a mathematical limit on its own design and
  states plainly that **raising the cover rate cannot fix it** (C-22, C-24).
- `DESIGN_DECISIONS.md:1076-1080` narrows the metadata promise from anonymity to
  reduction, in the decision record, explicitly (C-07 in the index).
- `DESIGN_DECISIONS.md:1365-1366` and `THREAT_MODEL.md:332-335` admit a DoS
  ceiling rather than arguing it away (C-44).
- `THREAT_MODEL.md:486-489` names the sanitizers it could **not** run and says
  "not silent" (C-48).
- `README.md:161-163` says fuzz targets *compile*, not that they *ran*, and
  explains why in the next sentence (C-13).

A project that writes like this in its threat model does not need an auditor to
tell it where it is weak. It needs an auditor to tell it whether the key schedule
it wrote in doc-comments is actually right — and that is precisely the work this
package is trying to *enable*.