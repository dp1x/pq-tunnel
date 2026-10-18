# 03 — Limitations Register

> **This is an internal self-assessment, not an audit.** Each entry records a
> limitation the project itself states, or one this package found that the
> project's documentation does not currently state. The second category is
> labelled **[NOT ADMITTED]** — it is *this package's* reading, not the project's,
> and the authors of the project may disagree. Nothing here is a defect finding.

**Structure:** §A holds limitations the project already admits, each traced to
the decision record that owns it. §B holds limitations this package believes are
missing from the project's own admissions. §C holds limits on the evidence
itself.

Severity is about *consequence*, not urgency:

- **Acceptable** — a deliberate, bounded, documented tradeoff the design intends.
- **Material** — a real constraint that changes how the software should be
  deployed or judged.
- **Structural** — a gap in the *record*, not necessarily in the software.

---

## §A — Limitations the project already states

### A.1 — Metadata

| ID | Limitation | Source | Severity |
|---|---|---|---|
| **L-01** | **The metadata target is leakage *reduction*, not traffic-flow anonymity.** Activity above the cover floor, volume, server session count, session liveness and lifecycle events are all observable by design. | `DESIGN_DECISIONS.md:1076-1080` (D22); `THREAT_MODEL.md:509-518` (§13.4); `README.md:40-42` | **Acceptable** — stated three times in three documents, including by the authors who built it. This is a *correct* limitation, not a defect. |
| **L-02** | **Raising the cover rate does not close the activity channel.** Bound λ·W ≥ 1: a 1 pkt/s source separates in ≈2–3 s; a 100-packet burst in one window; raising the floor rate changes nothing. | `THREAT_MODEL.md:509-518` | **Acceptable** — mathematically derived and stated. Strongest self-criticism in the project. |
| **L-03** | **Absorbing (slot-capped) emission — the design that would close the channel — is rejected for v1.** It is a different architecture with its own threat model, not a patch. | `DESIGN_DECISIONS.md:1080-1086` | **Acceptable** — correctly framed as a future milestone. |
| **L-04** | **The client emits no cover during connection establishment.** Observable cover onset, asymmetric between client and server. Measured window: default p50 7.78 s, p90−p10 = 1.42 s, min–max 2.00 s. | `THREAT_MODEL.md:552-566` (§13.5), `:578-600` (§13.6) | **Acceptable (disposition C)** — quantified and accepted as residual under D22. |
| **L-05** | **The M3 retransmit budget is an externally visible implementation fingerprint.** Median establishment 7.78 s (budget 4) vs 0.76 s (budget 1) vs 0.27 s (budget 0); 60/60 correctly classified with disjoint populations. | `THREAT_MODEL.md:602-605` | **Material** — this is an active fingerprint, correctly identified. |
| **L-06** | **Session linkability is undetermined.** The dataset was single-identity; an earlier "0/30 NN match" figure was an analysis-script stub and is withdrawn. | `THREAT_MODEL.md:604-610` | **Acceptable** — a disclosed negative result. Tunnel makes **no claim** in either direction. |
| **L-07** | **Establishment bursts are detectable 30/30 from the source vantage** (Wilson 95% CI [0.886, 1.000]); burst survival across real links is untested. | `THREAT_MODEL.md:620-624` | **Acceptable** — inherent to D13's 4-fragment M1; loopback vantage correctly scoped. |
| **L-08** | **Cover cadence lands at ~93.5% of nominal on Windows** (182.6 pkt/s vs 195.3; period p50 5.5 ms). One ≥15 ms gap in a 30 s run. | `THREAT_MODEL.md:543-551`; `CHANGELOG.md:74-77` | **Acceptable** — measured, and correctly argued to be non-material because §13.4's bound is rate-independent. |
| **L-09** | **Cover traffic costs 2 Mbps even when idle**; ~195 Hz wakeups per session; no per-flow differentiation. | `DESIGN_DECISIONS.md:979-985` | **Acceptable** — the stated price of the default guarantee. |
| **L-10** | **Adaptive shaping is future, user-selected work — never a default, never negotiated.** Not implemented in v0.2. | `DESIGN_DECISIONS.md:942-946`; `README.md:216-218` | **Acceptable** — correctly closed off. |

### A.2 — Cryptography and protocol

| ID | Limitation | Source | Severity |
|---|---|---|---|
| **L-11** | **Rekey is close-and-re-establish.** No in-place key transition; full handshake per rotation; brief connectivity interruption. The master is never retained. | `DESIGN_DECISIONS.md:770-802` (D16); `README.md:219` | **Acceptable** — fail-secure and simple by choice. |
| **L-12** | **Provisioning is not a PKI.** Distribution, rotation and revocation of rosters remain **manual operational processes**. | `DESIGN_DECISIONS.md:844-847` (D17 tradeoffs) | **Material** — operationally significant; see L-13. |
| **L-13** | **Identity seed files are protected only by host permissions.** No encryption-at-rest wrapper; explicitly out of scope for v1. | `DESIGN_DECISIONS.md:847-849` | **Material** — an auditor should weigh this against L-12. |
| **L-14** | **No anonymous mode.** Every endpoint must be provisioned out of band; there is no anonymous access to a v1 server. | `DESIGN_DECISIONS.md:500-510,528-533` (D12) | **Acceptable** — deliberate, and correctly justified as closing a downgrade vector. |
| **L-15** | **X25519 is retained as the classical leg but is deprecated as a *sole* mechanism** and "must never be used alone". | `CRYPTO_PROFILE.md:429`; `pq-crypto/src/lib.rs:16-21` | **Acceptable** — correctly enforced by construction (both legs always present). |
| **L-16** | **A mis-keyed session is detected only when the server's first packet fails to decrypt** — bounded by the liveness timeout. | `DESIGN_DECISIONS.md:757-762` (D15 tradeoffs) | **Acceptable** — explicit, with a bound. |
| **L-17** | **The handshake is 1.5 RTT, ~2.5 ms CPU per side** (ML-DSA signing dominates), 12,800 wire bytes over 10 datagrams. | `DESIGN_DECISIONS.md:653-660` (D13 tradeoffs) | **Acceptable** — cost of mutual auth + dual-ephemeral hybrid. |
| **L-18** | **Handshake datagrams must be indistinguishable from data packets**; 8192-byte handshake datagrams are rejected. | `DESIGN_DECISIONS.md:592-603` | **Acceptable** — a constraint, correctly embraced. |
| **L-19** | **The legacy v1 `derive_master_secret` path leaves its `ikm` staging buffer un-zeroized** and remains reachable from `pq_crypto::kdf`. | `pq-crypto/src/kdf.rs:156-161` (acknowledged in the v2 doc comment) | **Material** — acknowledged in a comment; **whether the v1 path is live is UNVERIFIED**. If it is dead code, it should be removed; if it is live, it is a zeroization defect. |

### A.3 — Transport and application model

| ID | Limitation | Source | Severity |
|---|---|---|---|
| **L-20** | **UDP only in v0.2.** TCP through the relay requires a stream layer and is deferred. | `DESIGN_DECISIONS.md:901-903,916-918` (D18) | **Material** — most real traffic is TCP. **Superseded in intent by D25/D26 (see L-33).** |
| **L-21** | **Relay replies are last-writer-wins** when two local apps share one remote destination. | `DESIGN_DECISIONS.md:913-915`; `pq-tunnel-bin/src/relay.rs:20-22` | **Material** — documented, but it is a real correctness hazard for multi-app local use. |
| **L-22** | **No ICMP / unreachable feedback in v0.2.** Oversized datagrams are dropped with a warning only. | `DESIGN_DECISIONS.md:882-884,918` (D18) | **Material** — poor diagnosability; applications see silent loss. |
| **L-23** | **Maximum relayed datagram is 1236 B (IPv4) / 1224 B (IPv6)**; larger is dropped. A consequence of the fixed 1245-byte slot. | `DESIGN_DECISIONS.md:876-884`; `pq-tunnel-bin/src/relay.rs:45-48` | **Material** — smaller than a 1500-byte MTU. **Becomes a fragmentation concern under D25/D26.** |
| **L-24** | **The relay refuses non-loopback binds** (fail-closed), because the destination→endpoint record is unauthenticated last-writer-wins. | `DESIGN_DECISIONS.md:869-874` | **Acceptable** — a correct fail-closed choice, and the reason is stated. |
| **L-25** | **Socket pools are capped with an idle TTL; exhaustion drops the oldest.** Per-session and global. | `DESIGN_DECISIONS.md:892-898` | **Acceptable** — bounded, no unbounded growth. |
| **L-26** | **A vanished peer is not actively torn down** — it lingers until idle eviction reaps it. | `DESIGN_DECISIONS.md:1157-1159` (D23 tradeoffs) | **Material** — resource held for up to `idle_timeout` (default 5 min, `session_manager.rs:141`). |
| **L-27** | **ICMP-derived resets are informational, not fatal.** Windows loopback ICMP delivery is non-deterministic (reset WARN observed in only 2/4 runs). | `DESIGN_DECISIONS.md:1128-1143,1169-1176` | **Acceptable** — correctly classified; the non-determinism is disclosed. |
| **L-28** | **The Windows cover clock is an extra platform-specific surface** (~100 lines, `cfg(windows)`); other platforms keep the tokio timer arm. | `DESIGN_DECISIONS.md:1161-1163` | **Acceptable** — the single non-test `cfg` divergence in the codebase. |
| **L-29** | **`pq-proxy` (SOCKS5) is parked, not deleted** — excluded from the workspace, does not compile against the v2 core, scheduled for a rewrite. | `DESIGN_DECISIONS.md:1043-1048` (D20); `README.md:58,177` | **Acceptable** — correctly disclosed, but it is dead code in-tree. |

### A.4 — Process and evidence

| ID | Limitation | Source | Severity |
|---|---|---|---|
| **L-30** | **No independent third-party security audit.** Everything asserted was produced and checked in-tree; test oracles are self-authored. | `README.md:204-211` | **Structural** — the defining limitation of this whole package. |
| **L-31** | **Interoperability is unverified** — no independent implementation exists. | `README.md:212-215`; `CHANGELOG.md:111` | **Structural** — the protocol cannot be conformance-tested. |
| **L-32** | **MSan/UBSan were never run** (`rust-src` missing; `-Zsanitizer=undefined` invalid). Only ASan (+LSan per `THREAT_MODEL.md:485-486`). | `THREAT_MODEL.md:485-489` | **Acceptable** — disclosed as "outstanding, not silent". |
| **L-33** | **Detailed validation logs are private.** The evidence ledger is at `R:\pq-tunnel-lab` and the summaries at `checkpoints/`, which `.gitignore:38` excludes. | `THREAT_MODEL.md:455,509-510,538-540`; `README.md:88-89`; `checkpoints/` untracked | **Structural** — see §C. |

---

## §B — Limitations the project does NOT currently state

> **[NOT ADMITTED]** — these are this package's findings. They are *not* the
> project's admissions, and are stated here so that a reviewer can accept or
> reject each one independently.

| ID | Limitation | Evidence | Severity |
|---|---|---|---|
| **L-34** | **D18 is obsolete as a product model and the decision record does not say so.** D18 records "no TUN, no admin" as *Accepted*. The product direction is now a system-wide TUN + routes tool; the correction lives only in an **untracked, PROPOSED** document. | `DESIGN_DECISIONS.md:855-864` (D18 status) vs `docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:3` (`Status: PROPOSED`), `:18-27` ("D18 … is **not** the product model"); `git ls-files docs` → empty | **Structural** — the record of what Tunnel is, is wrong. **This package's highest-priority limitation.** |
| **L-35** | **The wire format and the cryptographic construction have no standalone normative specification.** Both exist only as Rust doc-comments, so a second implementation cannot be written against them and an auditor cannot check them independently of this source tree. | `PROTOCOL_SPEC.md:490` ("Exact wire format is defined after protocol design decisions are finalized"); `CRYPTO_PROFILE.md:281-284` defers nonce construction to `PROTOCOL_SPEC.md`, which does not define it; actual definitions at `codec.rs:88-160` and `kdf.rs:151-235` | **Structural** — blocks interoperability and independent verification. |
| **L-36** | **Tunnel's own construction has no external known-answer vectors.** The master-secret derivation, TH1/TH2/TH3, the Finished MAC and the traffic/nonce keys are pinned only by self-generated tests. | `pq-crypto/src/kat_vectors.rs` contains **no** constants for any of them (only RFC 8439/5869/7748 + Wycheproof); contrast with `CRYPTO_PROFILE.md:429`'s "Selection is anchored to external known-answer vectors per D21" | **Structural** — the eight anchored primitives are standards; the construction is the project's own and is unanchored. |
| **L-37** | **There is no test that forward secrecy holds.** Nothing demonstrates that compromising a long-term identity key reveals no historical traffic. The property is argued from the key schedule. | No such test exists in `pq-tunnel-core/`, `pq-crypto/` or `pq-tunnel-bin/tests/`; the argument is `DESIGN_DECISIONS.md:677-694` | **Material** — the project's headline guarantee. |
| **L-38** | **The verification-order invariant ("never KEM before signature") has no test.** | Asserted at `DESIGN_DECISIONS.md:589-590` and `handshake_v2.rs:60-61`; no test references ordering | **Material** — it is a DoS gate (`DESIGN_DECISIONS.md:526-527`) and could be inverted silently. |
| **L-39** | **The SHA-256 known-answer test accepts an incorrect digest.** | `pq-crypto/src/transcript.rs:131-139` accepts `...f20015ad` alongside the correct FIPS `...f200186d`; the comment at `:122-126` labels the *correct* value as a platform bug | **Material** — a cryptographic test with a deliberately wrong escape hatch. The empty-string test at `:145-157` asserts only the FIPS value, exposing the inconsistency. |
| **L-40** | **HMAC-SHA256 has no RFC 2104 known-answer vector.** The only check of the Finished MAC is a hand-rolled HMAC in the same crate. | No `RFC2104_*` constants exist in `kat_vectors.rs`; `kdf.rs:497-523` is the only cross-check | **Material** — a bug in HMAC would be silent, and the Finished MAC is the only thing standing between an attacker and a committed-but-mis-keyed server. |
| **L-41** | **The fuzz dependency set is not pinned.** `fuzz/Cargo.lock` is git-ignored and `fuzz/` is a separate workspace, so `cargo fuzz` floats dependency versions — including `libfuzzer-sys`. | `.gitignore:12` (`fuzz/Cargo.lock`); `fuzz/Cargo.toml:57-58` (`[workspace]`); `.github/workflows/fuzz.yml:83,92` run fuzz without `--locked` | **Material** — fuzz results are not reproducible across time. |
| **L-42** | **No `rust-toolchain.toml`; the build toolchain floats.** CI uses `stable`; only the MSRV *check* job is pinned (1.85.0). | No `rust-toolchain*` file in the tree; `ci.yml:19-21,45-47` vs `:83-85`; `rustc` on the reference host is 1.96.0 | **Material** — "reproducible build" is weakened; a dependency can bump its MSRV-adjacent behaviour between runs. |
| **L-43** | **Test counts are stated in three places and reconcile in none.** | `README.md:74` (352); `README.md:173-176` (67+236+37+12=352); measured (67+41+236+12=356); `checkpoints/VALIDATION_LINUX_E2E_FUZZ.md:76` (core 223 vs measured 236) | **Material** — the only independently verifiable numbers in the project are wrong. |
| **L-44** | **The `build.ps1` helper defaults to a single crate, not the workspace.** A bare `.\build.ps1 test` runs `pq-crypto` only. There is no `build.sh`. | `build.ps1:1-13` (`$Package = "pq-crypto"`, `cargo $Command -p $Package`) | **Structural** — a reproduction trap for anyone following the README literally. |
| **L-45** | **There is no supply-chain artefact in the public tree** — no SBOM, no `cargo deny`, no advisory policy, no `deny.toml`. | `.github/workflows/` contains only `ci.yml` and `fuzz.yml`; `Cargo.toml` has no `[workspace.metadata]` for supply chain | **Material** — the dependency set is pinned but unmonitored. |
| **L-46** | **`PROTOCOL_SPEC.md` is stale relative to the decision record.** Its §16 lists six items as future decisions that D12–D16/D21 resolved; its §8 state diagram does not match the implemented close reasons. | `PROTOCOL_SPEC.md:580-590`, `:372-431` vs `pq-tunnel-core/src/session_manager.rs:154-178` | **Material** — the document titled "Protocol Specification" does not describe the protocol. |
| **L-47** | **`packet_len.rs::ip_packet_len` has no production caller and only incidental fuzz coverage.** It is the parser that *will* become the TUN ingress boundary. | Only callers are `packet_len.rs` tests and `fuzz/fuzz_targets/relay_overlay.rs:20,76`; confirmed at `docs/design/D25-D26-...md:39` | **Material (forward-looking)** — when TUN lands this becomes a network-facing parser with a sub-target's worth of coverage. |
| **L-48** | **`packet_len.rs` doc comments already describe TUN behaviour that does not exist** ("the client's slot → TUN write", "never write garbage to a tun"). | `pq-tunnel-bin/src/packet_len.rs:5,12`; flagged as stale at `docs/design/D25-D26-...md:37` | **Structural (minor)** — a doc comment describing unimplemented behaviour is a documentation defect. |
| **L-49** | **The working tree references an unrecorded decision `D27` and a missing document, and does not compile.** | `pq-tunnel-bin/src/identity.rs:439`; `pq-tunnel-core/src/session_manager.rs:357,363`; `pq-tunnel-core/src/handshake_v2.rs:1389,1400,1738`; `pq-tunnel-bin/tests/revocation_lifetime.rs:3` (cites `docs/decisions/D27-...md`, absent); `cargo test --workspace` fails with 9 compile errors in that file | **Material** — the decision record is behind the code. |
| **L-50a** | **A key-establishment change landed in the working tree with no record.** `pq_crypto::classical::X25519Keypair::diffie_hellman` was changed to return `None` on an all-zero shared secret (RFC 7748 §6.1 contributory check; cofactor-8 small-order points), and `handshake_v2.rs` grew correspondingly. No decision record entry, no threat-model note, no README mention, no test named. | `[WORKING TREE]` `pq-crypto/src/classical.rs:29+` (doc comment cites RFC 7748 §6.1/§7); `git status` shows `M pq-crypto/src/classical.rs`; `DESIGN_DECISIONS.md` has no corresponding entry | **Material** — a security improvement, correctly motivated, but unreviewed and unrecorded. An auditor must decide whether to accept it as-is or require a decision record and tests. |
| **L-50** | **The server's forwarding backend is an SSRF gadget by construction and the shipped v0.2 path has no egress policy.** The client picks the destination; the server issues the request. A design for this exists (`docs/design/D28-server-egress-policy-1to1.md`) but is untracked and unimplemented. | `DESIGN_DECISIONS.md:884-891`; the SSRF framing is stated explicitly in `docs/design/references-1to1.md:300-330`; D28 is untracked | **Material** — the highest-severity operational exposure in the current product, and the project's own research says so. |

---

## §C — Limits on the evidence in this package

| ID | Limit | Detail |
|---|---|---|
| **L-51** | **No CI status was checked.** | This package could not reach GitHub Actions. Every "CI passed" statement in the project documentation (`checkpoints/VALIDATION_LEDGER.md:10`, citing run `32086456238`) is reported as cited, never as checked. |
| **L-52** | **No fuzz target was built or executed.** | ASan cannot initialise on this host (`AGENTS.md`; `README.md:161-163`). Claims about fuzz runs are all INTERNAL-ONLY. |
| **L-53** | **No clippy / fmt run.** | `C-53` in `02-claims-vs-evidence.md` is unverified. |
| **L-54** | **The M7–M10 measurement campaigns were not re-derived.** | They are cited from `THREAT_MODEL.md §13` and `checkpoints/`. Raw CSVs are described as volatile (`THREAT_MODEL.md:539-540,578-579`). An auditor would need `R:\pq-tunnel-lab` or a re-run. |
| **L-55** | **The untracked design proposals were read but not reviewed as designs.** | `docs/design/D25-D26-*.md` and `D28-*.md` are large proposals; this package assessed only their *effect on the evidence package* (namely L-34, L-47, L-50), not their technical merit. |
| **L-56** | **This package did not attempt an independent verification of the key schedule.** | Doing so is exactly the work an auditor should do, and this package deliberately does not pre-empt it. The skeletons in `spec/` exist to make that work possible. |

---

## §D — What the project should add to this register itself

For the project's benefit, and listed here because a limitations register is
more useful when it is complete:

1. Promote `README.md:204-211` (no independent audit) from a bullet in
   "Known issues" to the **first paragraph** of the README.
2. Add **D18's supersession** to `DESIGN_DECISIONS.md` with an explicit
   "superseded by D25" marker, and move the TUN architecture into the record.
3. Add the **forward-secrecy test** (L-37) and the **verification-order test**
   (L-38) or state plainly that they do not exist.
4. Add **L-19** (v1 zeroization) to the D-record, or delete the v1 path.
5. Reconcile the **test counts** (L-43) — ideally by generating them in CI and
   publishing the number rather than hand-writing it.
6. Remove the **wrong-answer escape hatch** from the SHA-256 test (L-39).
7. Pin the **fuzz toolchain and dependencies** (L-41, L-42).
8. State the **server egress/SSRF posture** of the shipped product (L-50), and
   whether D28 is in scope.
9. Fix the `packet_len.rs` doc comments that describe TUN behaviour which does
   not exist (L-48).
10. Bring **D27** into the decision record, or land the code that cites it (L-49).