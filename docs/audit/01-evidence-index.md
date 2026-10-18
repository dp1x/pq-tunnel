# 01 — Evidence Index

> **This is an internal self-assessment, not an audit.** Statuses describe what
> a third party could find *in a checkout of `origin/main`* (plus, where marked
> `[WORKING TREE]`, in the uncommitted working tree). "PRESENT" means the
> artefact exists and is findable — **not** that it is correct, and **not** that
> anyone outside the project has checked it.

## Status vocabulary

| Status | Meaning |
|---|---|
| **PRESENT** | The evidence exists in the public tree and an auditor can read it. |
| **PARTIAL** | Some of the evidence exists; a specific, named piece is missing. The missing piece is named in the Gap column. |
| **MISSING** | No evidence of this kind exists anywhere. |
| **INTERNAL-ONLY** | The evidence exists but only under `checkpoints/`, which `.gitignore:38` excludes and which `git ls-files` confirms is untracked. An outside auditor cannot see it. |
| **UNVERIFIED** | The package could not confirm the claim. Named in the Gap column. |

---

## §P — Protocol specification

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| P-01 | A **normative** protocol specification (not requirements) | None. `PROTOCOL_SPEC.md:4` states `Draft — Requirements Specification`; `:20-25` explicitly does not define "specific cryptographic algorithms", "final handshake construction"; `:600-611` §17 repeats the boundary | `PROTOCOL_SPEC.md:4,20-25,600-611` | **MISSING** | The single largest gap. The document that claims to be the protocol spec disclaims being one. |
| P-02 | Security requirements are enumerated normatively (MUST/SHOULD) | §5.1–5.7 | `PROTOCOL_SPEC.md:170-255` | **PRESENT** | Requirements exist; they are not tied to conformance tests (§T-14). |
| P-03 | Packet structure requirement (header / AD / protected fields) | §11 states the requirement | `PROTOCOL_SPEC.md:474-490` | **PRESENT** | Requirement only. `:490` says "Exact wire format is defined after protocol design decisions are finalized" — it was, and it was not fed back here. |
| P-04 | Versioning / downgrade requirement | §15 | `PROTOCOL_SPEC.md:568-576` | **PRESENT** | — |
| P-05 | Lifecycle states defined | §8 | `PROTOCOL_SPEC.md:372-431` | **PRESENT** | The document's state diagram (`INITIAL/HANDSHAKE/ESTABLISHED/REKEY/CLOSED`) is *not* the implemented one; the implementation adds idle/lifetime/liveness/capacity close reasons. See `CloseReason` at `pq-tunnel-core/src/session_manager.rs:154-178`. |
| P-06 | Handshake requirements | §9 | `PROTOCOL_SPEC.md:434-449` | **PRESENT** | `:449` defers construction to "later design decisions" — D13, which lives in the D-record, not the spec. |
| P-07 | §16 "Future Design Decisions" still lists resolved items | §16 lists "handshake construction, identity model, cryptographic profile, packet encoding, nonce construction, rekey timing" as future | `PROTOCOL_SPEC.md:580-590` | **PARTIAL** | All six were resolved by D12–D16, D21. The spec was never updated. An auditor reading `PROTOCOL_SPEC.md` alone cannot tell what is decided. |
| P-08 | Rekey requirements | §13 | `PROTOCOL_SPEC.md:536-554` | **PARTIAL** | `:550` "The rekey process MUST define: trigger conditions, transition behaviour, failure handling" — the actual answer is D16 (close-and-re-establish), in the D-record only. |

---

## §W — Wire format

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| W-01 | Total on-wire packet size | `PACKET_SIZE = 1280` with MTU rationale | `pq-tunnel-core/src/codec.rs:103` (doc `:94-102`) | **PRESENT** | — |
| W-02 | Header length = 17 | `HEADER_LEN = VERSION_LEN + SESSION_ID_LEN + PACKET_NONCE_LEN` | `codec.rs:132` | **PRESENT** | — |
| W-03 | Header field order and widths | `PacketHeader::encode` | `codec.rs:273-280` | **PRESENT** | — |
| W-04 | Packet-nonce encoding (big-endian u64) | `to_be_bytes()` | `codec.rs:277` | **PRESENT** | — |
| W-05 | AEAD ciphertext length = 1247 | `INNER_PLAINTEXT_LEN = PACKET_SIZE - HEADER_LEN - AEAD_TAG_LEN` | `codec.rs:134-135` | **PRESENT** | — |
| W-06 | AEAD tag length = 16 | `AEAD_TAG_LEN = 16` | `codec.rs:108` | **PRESENT** | — |
| W-07 | Payload length = 1245 | `PAYLOAD_LEN = INNER_PLAINTEXT_LEN - 2` | `codec.rs:139` | **PRESENT** | — |
| W-08 | Header is AEAD associated data | `aad() = header_bytes()` | `codec.rs:514-516` | **PRESENT** | — |
| W-09 | `MessageType` enumeration (0x00–0x03), strict reject | `from_u8` | `codec.rs:182-209` | **PRESENT** | — |
| W-10 | `Direction` enumeration (0x00/0x01), strict reject | `from_u8` | `codec.rs:231-238` | **PRESENT** | — |
| W-11 | Layout partition is compile-time asserted | 3 `const _: () = assert!(...)` | `codec.rs:143-152,156-160` | **PRESENT** | This is good practice and unusual. |
| W-12 | Nonce-exhaustion bound | `MAX_PACKET_NONCE = u64::MAX - (1<<32)`; `is_counter_exhausted` | `codec.rs:121,127-129` | **PRESENT** | The *enforcement* is elsewhere (`envelope.rs`, `wire_session.rs`); the constant alone is not the contract. |
| W-13 | Handshake fragment framing (12-byte header, body ≤ 1268) | `HS_FRAG_HEADER_LEN`, `HS_FRAG_BODY_MAX` | `pq-tunnel-core/src/handshake_v2.rs:120-122` | **PRESENT** | — |
| W-14 | `hs_type` byte values (0x10/0x20/0x30) and disjointness from `MessageType` | constants + `const _` assert | `handshake_v2.rs:113-117,174-177` | **PRESENT** | — |
| W-15 | M1/M2/M3 body lengths (4534 / 5622 / 1113) | constants + `const _` assert pinning exact values | `handshake_v2.rs:130-144,171-173` | **PRESENT** | — |
| W-16 | Fragment counts (4 / 5 / 1) | `M1_FRAG_COUNT` etc. + compile-time partition asserts | `handshake_v2.rs:147-151,156-169` | **PRESENT** | — |
| W-17 | Byte-9 dispatch rule (handshake vs data) | `is_handshake_fragment`, module doc | `handshake_v2.rs:280-283,26-34` | **PRESENT** | The 2^60-packet reachability argument is in a doc comment only (`:30-34`). |
| W-18 | Replay window width (1024 bits) | `WINDOW_BITS = 1024` | `pq-tunnel-core/src/replay.rs:37` | **PRESENT** | — |
| W-19 | Relay overlay framing (family/addr/port/len/datagram) | module doc + constants + `encode_relay`/`decode_relay` | `pq-tunnel-bin/src/relay.rs:7-13,35-48,71-145` | **PRESENT** | Application-layer only; never on the wire. |
| W-20 | **A standalone wire-format specification document** | None | — | **MISSING** | The format exists only as Rust doc-comments. See `spec/wire-format.md` and `05-gaps.md` G-01. |

---

## §C — Cryptographic construction

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| C-01 | Algorithm suite pinned | §14 pinned block | `CRYPTO_PROFILE.md:432-436` | **PRESENT** | Pinned in prose and in code. |
| C-02 | Dependency versions pinned | `ml-kem = 0.3.2`, `ml-dsa = 0.1.1`, `x25519-dalek = "=3.0.0-rc.1"`, `curve25519-dalek = "=5.0.0-rc.1"`, `chacha20poly1305 = 0.10`, `hkdf = 0.12`, `hmac = 0.12`, `sha2 = 0.10 (force-soft-compact)` | `pq-crypto/Cargo.toml:11-25` | **PRESENT** | Two `=X` exact pins, the rest caret ranges resolved by `Cargo.lock`. |
| C-03 | `Cargo.lock` committed | Present and tracked | `Cargo.lock` (tracked per `git ls-files`) | **PRESENT** | — |
| C-04 | HKDF-SHA256 as the KDF, salt pinned to `[0;32]` | `kdf_derive`, `KDF_SALT_BYTES = 32` | `pq-crypto/src/kdf.rs:4,8-19` | **PRESENT** | Rationale for the all-zero salt is given for the Finished key (`kdf.rs:196-197`) but not for the others. |
| C-05 | Master-secret derivation (v2) formula | doc comment + code | `kdf.rs:151-188` | **PRESENT** | `info = "pq-tunnel-master-v2" ‖ VERSION ‖ SID ‖ TH3`; `ikm = ssA ‖ ssB ‖ dh_cs`. **No external KAT.** |
| C-06 | Per-direction traffic keys | `derive_client_to_server_key` / `derive_server_to_client_key`, labels `pq-tunnel-c2s-v2` / `pq-tunnel-s2c-v2` | `kdf.rs:97-116` | **PRESENT** | **No external KAT.** |
| C-07 | Nonce prefixes (4 bytes each) | `derive_nonce_prefix_c2s` / `_s2c`, labels `pq-tunnel-nonce-c2s-v2` / `-s2c-v2` | `kdf.rs:118-139` | **PRESENT** | **No external KAT.** |
| C-08 | Session nonce construction | `build_session_nonce(prefix[4] ‖ counter_be[8])` | `kdf.rs:229-235` | **PRESENT** | — |
| C-09 | Finished key + Finished MAC | `derive_finished_key` (label `pq-tunnel-finished-v1`), `compute_client_finished` = `HMAC-SHA256(fk, TH3)[..16]` | `kdf.rs:191-227` | **PRESENT** | **No external KAT.** Cross-checked against a hand-rolled RFC 2104 HMAC in-test (`kdf.rs:497-537`) — self-authored oracle. |
| C-10 | Transcript hash definitions TH1/TH2/TH3 | `th1_from_m1`, `th2_from_m1_m2`, `th3_from_m1_m2_m3` | `handshake_v2.rs:750-778` | **PRESENT** | **No external KAT.** These are Tunnel's own construction. |
| C-11 | Transcript domain string | `HANDSHAKE_DOMAIN = b"pq-tunnel-v1"` | `handshake_v2.rs:154` | **PRESENT** | — |
| C-12 | Canonical form rules (zero-filled signature/MAC slot, no padding, no fragment headers) | `canonical_zerofill` | `handshake_v2.rs:725-739` | **PRESENT** | **No external KAT.** |
| C-13 | Key hierarchy (D14) | diagram + rules | `DESIGN_DECISIONS.md:676-716` | **PRESENT** | — |
| C-14 | ML-DSA deterministic signing is a pinned profile choice | D13 + test | `DESIGN_DECISIONS.md:617-621`; test `ml_dsa_sign_is_deterministic` (`pq-crypto/src/signature.rs:324`) | **PRESENT** | — |
| C-15 | Verification order (version → decode → signature → KEM) | stated in D13 and module doc | `DESIGN_DECISIONS.md:589`; `handshake_v2.rs:60-61` | **PRESENT** | **Asserted in prose; no test asserts the ordering itself.** |
| C-16 | Constant-time comparison used where needed | `subtle::ConstantTimeEq` | `handshake_v2.rs:102` | **PARTIAL** | Used; no test asserts constant-time behaviour. |
| C-17 | Zeroization of secret material | `#[derive(Zeroize)]`, `Drop` impls, `kdf_derive_to_bytes` | `kdf.rs:43-71`; `codec.rs:429-436,545-548`; `kdf.rs:184-186` | **PRESENT** | `derive_master_secret` (v1) leaves its `ikm` staging buffer un-zeroized and is **still reachable** — acknowledged at `kdf.rs:156-161`. Is the v1 path live? **UNVERIFIED.** |
| C-18 | **A standalone crypto-construction specification document** | None | — | **MISSING** | Everything above is doc-comments. See `spec/crypto-construction.md`, `05-gaps.md` G-03. |
| C-19 | Agility: algorithm swap does not break the profile | §13 prose | `CRYPTO_PROFILE.md:395-418` | **PARTIAL** | Asserted. No test or mechanism exercises a swap. |

---

## §K — Known-answer test provenance

| # | Primitive / constant | External anchor | Provenance comment | Status |
|---|---|---|---|---|
| K-01 | ChaCha20-Poly1305 (key, nonce, AAD, plaintext, ct‖tag) | RFC 8439 §2.8.2 | `pq-crypto/src/kat_vectors.rs:5-8,46-63` | **PRESENT** |
| K-02 | HKDF-SHA256 (IKM, salt, info, OKM) | RFC 5869 §A.1 tc 1 | `kat_vectors.rs:9-10,66-74` | **PRESENT** |
| K-03 | X25519 (Alice/Bob keys, shared secret) | RFC 7748 §6.1 | `kat_vectors.rs:11-13,77-87` | **PRESENT** |
| K-04 | ML-KEM-768 keygen | Wycheproof `mlkem_768_test.json` tcId 1 | `kat_vectors.rs:14-15,91-92` | **PRESENT** |
| K-05 | ML-KEM-768 encaps | Wycheproof `mlkem_768_encaps_test.json` testGroups[1] tcId 14 | `kat_vectors.rs:16-18` | **PRESENT** |
| K-06 | ML-DSA-65 verify | Wycheproof `mldsa_65_verify_test.json` grp0 tcId1 | `kat_vectors.rs:19-21,244` | **PRESENT** |
| K-07 | ML-DSA-65 **sign** | Wycheproof `mldsa_65_sign_seed_test.json` grp0 tcId1, `.sig` | `kat_vectors.rs:22-25,247-317` | **PRESENT** |
| K-08 | ML-DSA-65 keygen from seed | same file, grp0 | `kat_vectors.rs:22-24,319-361` | **PRESENT** |
| K-09 | SHA-256 | FIPS 180-4 vectors, inline in tests | `pq-crypto/src/transcript.rs:119-143,145-157` | **PARTIAL** — the "abc" vector test **accepts two answers**, one of which is wrong (`transcript.rs:131-139` accepts `...f20015ad`, and the comment at `:122-126` calls the other "a platform bug"). This is a live accepted-wrong-answer escape hatch. |
| K-10 | HMAC-SHA256 | RFC 2104 | **NONE** — no `RFC2104_*` constant exists in `kat_vectors.rs`; the only check is a hand-rolled HMAC inside `kdf.rs:497-537` | **MISSING** |
| K-11 | Hybrid master secret (`derive_master_secret_v2`) | **NONE** | — | **MISSING** |
| K-12 | Canonical transcript hashes TH1/TH2/TH3 | **NONE** | — | **MISSING** |
| K-13 | Finished key / Finished MAC | **NONE** | — | **MISSING** |
| K-14 | Traffic keys and nonce prefixes | **NONE** | — | **MISSING** |
| K-15 | `derive_master_secret` (v1 legacy path) | **NONE** | — | **MISSING** |
| K-16 | Provenance policy itself is a decision | D21 | `DESIGN_DECISIONS.md:1186-1230` | **PRESENT** |

---

## §T — Threat model

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| T-01 | Purpose and objectives | §1 | `THREAT_MODEL.md:1-20` | **PRESENT** | — |
| T-02 | Protected assets enumerated | §2.1–2.4 | `THREAT_MODEL.md:24-107` | **PRESENT** | — |
| T-03 | Security assumptions enumerated | §3 | `THREAT_MODEL.md:109-131` | **PARTIAL** | Six assumptions listed; none tied to a check. |
| T-04 | Adversary classes enumerated | §4.1–4.5 (passive, HNDL, active, local, infrastructure) | `THREAT_MODEL.md:135-243` | **PRESENT** | **No STRIDE mapping.** No per-class property/evidence cross-reference table. |
| T-05 | Quantum threat model | §5 | `THREAT_MODEL.md:246-263` | **PARTIAL** | Prose only; no statement of *what quantum cost* breaks what. |
| T-06 | Metadata threat model | §6 | `THREAT_MODEL.md:266-291` | **PRESENT** | Cross-referenced well to §13.4. |
| T-07 | Resource exhaustion / bounded resources | §7.1 | `THREAT_MODEL.md:313-338` | **PRESENT** | Strong. Corrected by D24. Invariants listed: bounded pending table, per-source failure budget, lookup-first no-allocation, bounded gate state. |
| T-08 | Out of scope stated | §8 | `THREAT_MODEL.md:342-352` | **PRESENT** | Six exclusions. |
| T-09 | Security claims | §11 | `THREAT_MODEL.md:408-427` | **PRESENT** | Four claims; all hedged with "designed to provide" / "reduced ... compared with". Assessed in `02-claims-vs-evidence.md`. |
| T-10 | Adversarial reassessment with measurements | §13.1–13.3 | `THREAT_MODEL.md:451-503` | **INTERNAL-ONLY** | Evidence ledger is at `R:\pq-tunnel-lab` (`:455`), not in the tree. Counts (1M replay runs, 1.9M driver runs, 105,350 churn runs, ~6.9M units) are **UNVERIFIED** by this package. |
| T-11 | Mathematical bounds on the cover floor | §13.4 | `THREAT_MODEL.md:506-530` | **PRESENT** | This is the strongest single piece of self-criticism in the project: it states λ·W ≥ 1 and that raising the rate cannot close it. |
| T-12 | Cadence shortfall measurement | §13.5 | `THREAT_MODEL.md:533-571` | **PRESENT** | Raw CSVs explicitly volatile (`:539-540`). |
| T-13 | Establishment-window quantification | §13.6 | `THREAT_MODEL.md:574-641` | **PRESENT** | Includes an explicitly **withdrawn** prior figure (`:606-608`) — good practice. |
| T-14 | Every threat mapped to a mitigation and a test | — | — | **MISSING** | §11 lists claims; §4 lists adversaries; nothing joins them to specific test names. See `05-gaps.md` G-06. |

---

## §D — Design decisions

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| D-01 | D-record exists with status vocabulary | Header + status list | `DESIGN_DECISIONS.md:30-36` | **PRESENT** | — |
| D-02 | D1–D24 all present | 24 headers found | `DESIGN_DECISIONS.md` (§D1 at `:41` … §D24 at `:1232`) | **PARTIAL** | **Numbering order is wrong:** D22, D23 appear at `:1054`/`:1104`, *before* D21 at `:1184`, and D24 at `:1232` after. Chronological ≠ numerical. |
| D-03 | **A decision index / table of contents** | None | — | **MISSING** | 1,400 lines with no index. An auditor must read the whole file or grep. |
| D-04 | Superseded decisions marked | D20 records that it supersedes the v1 deprecation schedule | `DESIGN_DECISIONS.md:1018-1022` | **PARTIAL** | Only one supersession is recorded. No "supersedes"/"superseded by" fields per decision. |
| D-05 | **D18 reflects the current product** | D18 says "local **UDP relay** client (no TUN, no admin)" | `DESIGN_DECISIONS.md:860-864` | **PARTIAL — STALE** | The product direction is a system-wide TUN + routes tool. `docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:18-27` says so explicitly and calls D18 "**not** the product model", but that file is (a) `Status: PROPOSED` (`:3`), (b) **untracked by git**. **D18 must be superseded.** See `05-gaps.md` G-02. |
| D-06 | D21 (KAT policy) placed correctly | Appears after D23 in file order | `DESIGN_DECISIONS.md:1184` vs `:1104` | **PARTIAL** | Ordering inconsistency; harmless to content, harmful to auditability. |
| D-07 | D22 correctly framed as a limitation, not a claim | Decision text: "metadata-leakage **reduction**, not traffic-flow anonymity" | `DESIGN_DECISIONS.md:1076-1080` | **PRESENT** | This is exemplary. |
| D-08 | D23's "vanished peer lingers until idle eviction" recorded | Tradeoff bullet | `DESIGN_DECISIONS.md:1157-1159` | **PRESENT** | — |
| D-09 | D24's invariants mirrored in the threat model | §7.1 | `THREAT_MODEL.md:313-338` | **PRESENT** | Rare and good: a decision and the threat model agree. |
| D-10 | Every decision has Consequences/Tradeoffs | Spot-checked D12–D24 | e.g. `DESIGN_DECISIONS.md:514-534` | **PRESENT** | — |
| D-11 | "Open Design Decisions" section is current | Lists D12–D24 as resolved; "Version 1 Scope" is empty | `DESIGN_DECISIONS.md:1372-1394` | **PARTIAL** | `:1389-1393` "Unresolved: mandatory v1 features / deferred features / deployment assumptions" — a stub. D27 is referenced in code but absent here. |

---

## §R — Fuzz and test coverage

| # | Surface | Target / test | `file:line` | Status |
|---|---|---|---|---|
| R-01 | `WirePacket::from_bytes` | `wire_packet_from_bytes` | `fuzz/fuzz_targets/wire_packet_from_bytes.rs` | **PRESENT** |
| R-02 | `InnerPlaintext::decode` | `inner_plaintext_decode` | `fuzz/fuzz_targets/inner_plaintext_decode.rs` | **PRESENT** |
| R-03 | AEAD envelope decrypt | `envelope_decrypt` | `fuzz/fuzz_targets/envelope_decrypt.rs` | **PRESENT** |
| R-04 | Replay window | `replay_window` | `fuzz/fuzz_targets/replay_window.rs` | **PRESENT** |
| R-05 | Handshake message decode | `handshake_message_decode` | `fuzz/fuzz_targets/handshake_message_decode.rs` | **PRESENT** |
| R-06 | Handshake **driver** receive (client + server) | `handshake_driver_receive` | `fuzz/fuzz_targets/handshake_driver_receive.rs` | **PRESENT** |
| R-07 | Session manager receive | `session_manager_receive` | `fuzz/fuzz_targets/session_manager_receive.rs` | **PRESENT** |
| R-08 | Cover scheduler | `cover_scheduler` | `fuzz/fuzz_targets/cover_scheduler.rs` | **PRESENT** |
| R-09 | Relay overlay + **`ip_packet_len`** | `relay_overlay` | `fuzz/fuzz_targets/relay_overlay.rs:20,76-89` | **PRESENT** — see R-14 |
| R-10 | Manager churn | `manager_churn` | `fuzz/fuzz_targets/manager_churn.rs` | **PRESENT** |
| R-11 | Target list is declared in two places and agrees | `fuzz/Cargo.toml:16-55`; `.github/workflows/ci.yml:66-71`; `fuzz.yml:66-67`; `README.md:155-159` | — | **PRESENT** — all four agree on 10 targets. |
| R-12 | Adversarial E2E suite | 6 cases | `pq-tunnel-bin/tests/e2e_adversarial.rs:104,146,202,225,247,266` | **PRESENT** — names: garbage/wrong-lengths, forged handshake, version downgrade, AEAD tamper, replay, reorder+in-window replay. |
| R-13 | Smoke / stress E2E | 3 + 3 | `pq-tunnel-bin/tests/e2e_smoke.rs`, `e2e_stress.rs` | **PRESENT** |
| R-14 | **`ip_packet_len` coverage status** | Fuzzed as a *sub-target* of `relay_overlay` with 4 assertions | `fuzz/fuzz_targets/relay_overlay.rs:76-89` | **PARTIAL** |
| R-15 | **TUN ingress boundary** | None | — | **MISSING** — there is no TUN code in the tree (see `docs/design/D25-D26-...md:31`), so there is nothing to fuzz yet. **But `packet_len.rs:5,12` doc comments already describe "the client's slot → TUN write", and the module has no production caller** (`docs/design/D25-D26-...md:39`). When TUN lands, this becomes the ingress parser with only a sub-target's worth of incidental coverage. |
| R-16 | Fuzz **execution** on this host | None | `AGENTS.md` fuzz section; `README.md:161-163` | **MISSING on this host** — ASan runtime cannot init under VBS (`0xC000026F`). |
| R-17 | Fuzz **execution** evidence | CI Linux job, 10 targets × `-runs=1000` | `.github/workflows/ci.yml:63-71`; INTERNAL-ONLY run log cited at `checkpoints/VALIDATION_LEDGER.md:19` | **INTERNAL-ONLY** — this package did not query GitHub Actions. |
| R-18 | Long-running fuzz campaign | `fuzz.yml` manual dispatch, 1M runs/target, 1h guard | `.github/workflows/fuzz.yml:60-97` | **PRESENT** (infrastructure). No evidence any such run was executed. |

---

## §B — Build, CI and reproducibility

| # | Requirement | Evidence | `file:line` | Status | Gap |
|---|---|---|---|---|---|
| B-01 | MSRV declared | `rust-version = "1.85"` | `Cargo.toml:12` | **PRESENT** | In the workspace manifest only; **not** stated in `README.md`. |
| B-02 | MSRV enforced in CI | `toolchain: 1.85.0` + `cargo check --workspace --locked --all-targets` | `.github/workflows/ci.yml:73-89` | **PRESENT** | — |
| B-03 | Pinned toolchain for normal builds | **None** — no `rust-toolchain.toml`, no `rust-toolchain` file in the tree | (absent) | **MISSING** | CI uses `stable` (`:19-21`, `:45-47`). Stable floats. `rustc` on this host is 1.96.0. |
| B-04 | `Cargo.lock` committed | Yes | `Cargo.lock` (tracked) | **PRESENT** | But `fuzz/Cargo.lock` is **git-ignored** (`.gitignore:12`) and `fuzz/` is its own workspace (`fuzz/Cargo.toml:57-58`). **The fuzz dependency set is not pinned.** |
| B-05 | CI uses `--locked` | Yes on all jobs | `ci.yml:31,33,52,89` | **PRESENT** | `fuzz.yml:81,92` does **not** use `--locked` for `cargo install cargo-fuzz --locked` — it does use `--locked` there (`:81`), but `cargo +nightly fuzz build/run` (`:83,92`) do not. |
| B-06 | Canonical target documented for outsiders | `README.md:127-131`, `AGENTS.md` build section | — | **PARTIAL** | The `--target x86_64-pc-windows-msvc` convention is explained as a *development-host* artefact ("the development host is aarch64 Windows"). An external Linux/macOS auditor is told "you may drop the `--target` flag" — which is correct but the *reason* is host-specific and machine-shaped. |
| B-07 | Canonical build script, cross-platform | `build.ps1` | `build.ps1:1-13` | **PARTIAL** | PowerShell only — **no `build.sh`**. Default `-Package pq-crypto` means a bare `.\build.ps1 test` runs only `pq-crypto`, not the workspace — surprising. |
| B-08 | Local cargo config is not committed, template is | `.cargo/*` ignored, `.cargo/config.toml.example` tracked | `.gitignore:17-21`; `.cargo/config.toml.example` | **PRESENT** | The template is entirely commented out (`:5-11`) — it documents no active setting. |
| B-09 | CI = fmt + clippy + tests + e2e smoke (Windows) | Yes | `ci.yml:24-34` | **PRESENT** | — |
| B-10 | CI = clippy + tests + fuzz build + fuzz smoke (Linux) | Yes | `ci.yml:49-72` | **PRESENT** | — |
| B-11 | CI never pushes / publishes | True (no `deploy`/`release` steps anywhere in `ci.yml`/`fuzz.yml`) | — | **PRESENT** | Consistent with `AGENTS.md`. |
| B-12 | Dependency supply-chain statement | `checkpoints/SECURITY_RELEASE_AUDIT.md` §7 | — | **INTERNAL-ONLY** | Not in the public tree. No SBOM, no `cargo audit`/deny.toml in CI. |
| B-13 | **A third-party reproduction guide** | README "Build"/"Tests"/"Fuzzing" sections | `README.md:125-189` | **PARTIAL** | See `04-reproducibility.md` for what is missing (exact rustc/cargo versions, `cargo-fuzz` version, fuzz `--locked`, corpus handling, expected-output samples). |

---

## §X — Cross-cutting documentation integrity

| # | Requirement | Evidence | Status | Gap |
|---|---|---|---|---|
| X-01 | Document hierarchy is respected (charter / threat / spec / decisions do not overlap) | Each file has a "Purpose" + "This document does not define" section | **PARTIAL** | The boundaries are *declared* (`PROTOCOL_SPEC.md:20-30`, `CRYPTO_PROFILE.md:24-31`, `DESIGN_DECISIONS.md:13-24`, `IMPLEMENTATION_GUIDE.md:23-30`) and mostly honoured — but `CRYPTO_PROFILE.md:281-284` says nonce construction belongs in `PROTOCOL_SPEC.md`, which does not define it. Three documents point at each other for the nonce and nobody writes it down normatively. |
| X-02 | Every document has a Status line | Yes | **PRESENT** | All say "Draft" — including `PROTOCOL_SPEC.md` and `CRYPTO_PROFILE.md` at `v0.2.0-alpha` release. |
| X-03 | Test counts reconcile across documents | No | **MISSING** | `README.md:74` says 352; `README.md:173-176` sums to 67+236+37+12; measured today: 67+41+236 = 344 unit. Three different numbers. |
| X-04 | Code references in docs resolve | Spot-checked | **PARTIAL** | D-record and codec citations resolve. `CRYPTO_PROFILE.md` cites §8 for nonce uniqueness (`codec.rs:112-118` agrees). But `docs/design/D25-D26-...md` cites `pq-tunnel-bin/src/identity.rs` line numbers that shift with the working tree. |
| X-05 | README does not overclaim | Yes | **PRESENT** | `README.md:204-211` is unusually candid. This is a genuine strength and this package does not discount it. |
| X-06 | The decision record covers the key-establishment code | **No** — see row D-12 | — | **MISSING** |
| D-12 | Every change to the KEX path has a decision record | **No** | `[WORKING TREE]` `pq-crypto/src/classical.rs:29+` adds an RFC 7748 §6.1 contributory check (`diffie_hellman` → `None` on all-zero shared secret); `pq-tunnel-core/src/handshake_v2.rs` grew ~135 lines correspondingly; **no D-entry, no test named, nothing committed** | **MISSING** | Correctly-motivated security improvement that is entirely unrecorded. See `05-gaps.md` G-23. |

---

## Summary counts

| Status | Count |
|---|---|
| PRESENT | 47 |
| PARTIAL | 20 |
| MISSING | 15 |
| INTERNAL-ONLY | 3 |
| UNVERIFIED (named in gaps) | 7 |

The 14 MISSING rows are the remediation list; they are enumerated and
prioritised in [`05-gaps.md`](05-gaps.md).