# Track E — Crypto Validation Gaps Audit

> **This is an internal self-assessment, not an audit.** Every finding and
> every test below was produced and checked by the Tunnel project's own
> authors, in-tree. **No independent third party has reviewed, verified,
> endorsed or approved any of it**, and nothing in this document constitutes
> assurance, certification or a third-party statement of correctness. The
> project's own disclaimer stands: *"No independent third-party security
> audit has been performed."* The "audit" in the title names the *method*
> (a gap-finding pass over the crypto surface), not an external reviewer.

**Scope:** `pq-crypto` (X25519, HKDF/key schedule, transcript, KEM, signature, AEAD,
KAT vectors), `pq-tunnel-core` (codec, v2 handshake), `pq-tunnel-bin` (relay framing,
packet length recovery).

**Base commit:** `ae8061d` (`origin/main`).

**Status:** audit + tests landed. **NOT committed** — per task instruction. Two findings
require a human decision before the corresponding behaviour is pinned as permanent (§6).

> **HISTORICAL:** the "NOT committed" status above describes the tree at
> package time. The changes this track produced **were** committed — as
> `68273a8` ("fix(crypto): add X25519 contributory check and KAT boundary
> tests") — and the tests listed below are present in the current tree. The
> two open human gates (§6 G-1, G-2) are unaffected and remain open.

Per D21, this report keeps two classes of test strictly separated and never blurs them:

- **(EXT)** — externally anchored. The expected value is quoted verbatim from an RFC,
  FIPS publication, or the Google/C2SP Wycheproof corpus. Never derived by this project.
- **(SELF)** — self-consistency / regression only. The assertion describes *this
  implementation's* contract. It catches regressions and some classes of defect, but a
  test I wrote is **not** an external anchor and provides zero independent confirmation
  that the value is cryptographically correct.

---

## 1. Gap table

| # | Item | Risk | Current state (file:line) | Proposed / added test | Anchor | Gate |
|---|---|---|---|---|---|---|
| E-1 | X25519 does not reject low-order / non-contributory peer keys | **High** (defense-in-depth gap) | `pq-crypto/src/classical.rs:29` — returns the raw 32 bytes, no contributory check | `low_order_peer_keys_are_rejected`, `low_order_rejection_is_symmetric`, `contributory_exchange_is_never_rejected` | (SELF) | **CLOSED** — implemented + tested |
| E-2 | Is key substitution *detectable* via the signed transcript? | High if no | `handshake_v2.rs:756` `th1_from_m1`, `:764` `th2_from_m1_m2` | `th1_binds_the_clients_x25519_key`, `th2_binds_the_servers_x25519_key` | (SELF) | **CLOSED** — defence already existed, now pinned |
| E-3 | End-to-end: a roster member presenting a low-order key | Medium | `handshake_v2.rs` `complete_m1`, `on_complete_m2` | `server_rejects_non_contributory_client_x25519_key`, `client_rejects_non_contributory_server_x25519_key` | (SELF) | **CLOSED** — silent drop (D12) |
| E-4 | `derive_master_secret_v2` does **not** directly bind the KEM ciphertexts or ephemeral public keys | **Medium** (real gap in the *direct* surface; closed transitively) | `pq-crypto/src/kdf.rs:167` — `ikm = ss_a‖ss_b‖dh_cs`, `info = label‖ver‖sid‖th3` | `master_v2_direct_binding_surface_is_pinned` (SELF); `th3_binds_the_client_kem_public_key`, `th3_binds_both_kem_ciphertexts`, `th3_binds_both_server_ephemeral_keys`, `master_secret_changes_when_only_the_ciphertext_changes` (SELF) | (SELF) | **CLOSED** — transitive binding proven; see §2 |
| E-5 | No end-to-end key-schedule KAT with an independent expected value | **High** (validation gap) | none exists | Design sketched in §3 — **cannot be sourced** without an invented label | n/a | **OPEN — human gate G-2** |
| E-6 | Cross-label separation not proven for the full label set | Medium | `pq-crypto/src/kdf.rs` — 9 labels, no matrix | `every_kdf_label_is_pairwise_separated`, `master_labels_v1_and_v2_are_separated`, `handshake_init_labels_are_separated_from_traffic_labels`, `nonce_prefixes_are_pairwise_distinct_as_four_byte_values` | (SELF) | **CLOSED** |
| E-7 | Transcript order/concatenation-boundary sensitivity untested | Medium | `pq-tunnel-core/src/handshake_v2.rs:746` `hash_with_domain`; `pq-crypto/src/transcript.rs:34` `update` | `transcript_fields_are_injection_resistant`, `domain_prefix_changes_the_digest`, plus 6 pre-existing transcript tests | (SELF) | **CLOSED** |
| E-8 | Parser len-1/len/len+1 boundaries | Medium | see §4 table | 18 boundary tests added | (SELF) | **CLOSED** |
| E-9 | `MlDsaSignature::from_bytes` is **not total** at the exact signature length | Low-Med (fail-secure, but callers must not assume `Ok`) | `pq-crypto/src/signature.rs:137` — `Signature::decode` returns `None` on unrepresentable hint encodings | `signature_from_bytes_length_boundaries` documents the non-totality; `ml_dsa_verify_rejects_tampered_signature` pre-existing | (SELF) | **DOCUMENTED** — see §4.2 |
| E-10 | `ip_packet_len` reads the IPv6 payload-length field from a buffer as short as 20 bytes | Low (robustness, not memory safety) | `pq-tunnel-bin/src/packet_len.rs:14` — single `len < 20` guard for both branches | `ipv6_branch_reads_a_short_buffer_without_panicking`, `sub_minimum_lengths_are_rejected`, `never_panics_across_lengths_and_versions` | (SELF) | **DOCUMENTED** — human gate G-3 |
| E-11 | `pq-crypto/src/lib.rs` contained a U+FFFD mojibake | Low (documentation defect) | was at byte offset 549 | byte-level scan + textual verification | (SELF) | **CLOSED** — fixed |
| E-12 | PQC dependencies are **unaudited**; `x25519-dalek` is a release candidate | **High** (supply chain) | `pq-crypto/Cargo.toml:10` `=3.0.0-rc.1`; `ml-kem` 0.3.2, `ml-dsa` 0.1.1 | none possible — a KAT cannot establish audit status | n/a | **OPEN — human gate G-1** |
| E-13 | FIPS 203/204 have open "potential updates" errata | Low-Medium (documentation accuracy) | `CRYPTO_PROFILE.md`, `DESIGN_DECISIONS.md:1202` | — | n/a | **OPEN — human gate G-4** |
| E-14 | D12 violated on the contributory check (error instead of silent drop) | Medium | **introduced then fixed** during this audit | `server_rejects_non_contributory_client_x25519_key` asserts `ServerEvent::None` | (SELF) | **CLOSED** |

---

## 2. Item 1 — X25519 low-order defence-in-depth

### 2.1 Dependency and API semantics (verified, not assumed)

`Cargo.toml:10` pins `x25519-dalek = "=3.0.0-rc.1"`; `Cargo.lock:1089-1098` resolves
`3.0.0-rc.1`, which depends on `curve25519-dalek 5.0.0-rc.1`
(`cargo tree -p pq-crypto` confirms both).

Reading the vendored source
(`%USERPROFILE%\.cargo\registry\src\...\x25519-dalek-3.0.0-rc.1\src\x25519.rs`):

- `StaticSecret::diffie_hellman` (line 212) is `SharedSecret(their_public.0.mul_clamped(self.0))`
  — **no rejection**.
- `SharedSecret::was_contributory` (line 335) is `!self.0.is_identity()`.
- `curve25519-dalek-5.0.0-rc.1/src/montgomery.rs:128-132`: `impl Identity for MontgomeryPoint`
  returns `MontgomeryPoint([0u8; 32])`.
- `curve25519-dalek-5.0.0-rc.1/src/traits.rs:41-48`: the blanket `IsIdentity` impl is
  `self.ct_eq(&T::identity()).into()` — a **constant-time** comparison.

So the check is both available and side-channel-free. RFC 7748 §6.1 (fetched in full) states
both parties "MAY check, without leaking extra information about the value of K, whether K is
the all-zero value and abort if so", and §7 adds "a large number of existing implementations
do not do this."

### 2.2 Is the DH leg bound into the master secret?

Yes. `derive_master_secret_v2` (`pq-crypto/src/kdf.rs:167`) takes `dh_cs` as the third
`ikm` component. `derive_master_secret_v2_binds_dh_leg` (`kdf.rs:424`) already proved this.
So a forced all-zero DH output does change the master — the two peers do not simply agree on
a "known" secret.

### 2.3 Precise argument: is a forced-zero DH leg a break?

It is **not** a break of the hybrid, but it is a real reduction that should not be silent.

1. `TH1 = SHA256(dom ‖ M1_z)` includes `x_c` (M1 offset 1193, inside the 4534-byte M1 body).
   The client signs `TH1`. A MITM substituting `x_c` produces a different `TH1`, so the
   client's signature no longer verifies → silent drop.
   Proven by `th1_binds_the_clients_x25519_key`.
2. `TH2 = SHA256(dom ‖ M1_s ‖ M2_z)` includes **all** of M2, hence `eph_pk_s`, `x_s`, and
   `ct2`. The server signs `TH2`. Substituting `x_s` breaks it.
   Proven by `th2_binds_the_servers_x25519_key`.
3. Therefore a MITM cannot inject a low-order key without a signature failure — **the primary
   defence already exists** and is sound.

What remains is the case where the *authenticated* peer itself supplies a low-order key: a
buggy client, a compromised client key, or a future protocol revision that reuses `x_c` for a
different purpose. Then:

4. `ikm = ss_a ‖ ss_b ‖ 0…0`. The master is still `HKDF-SHA256` over a **full-entropy**
   `ss_a`/`ss_b`, so it retains ≥ the KEM leg's security — ML-KEM-768 gives ~192 bits.
   HNDL resistance is **preserved**; it does not depend on the classical leg.
5. But two properties are degraded, and the profile's *documented* entropy is no longer what
   the code computes:
   - The session silently degrades from "hybrid, contributory on both legs" to
     "post-quantum-only in practice", with no signal to either peer or to the operator.
   - Post-quantum confidentiality with an unauthenticated/compromised classical peer is
     exactly the scenario the hybrid exists to hedge; accepting it silently defeats the point
     of *failing loudly*.
6. Neither side could detect it. That is precisely the failure mode RFC 7748 §7 and the
   `was_contributory` doc comment describe ("it is also impossible for Alice and Bob to detect
   the intrusion").

**Conclusion.** Not a break (KEM leg carries HNDL resistance), but a silent downgrade of a
security property — which AGENTS.md forbids ("Never: silently reduce security guarantees").
Rejecting is the correct behaviour.

### 2.4 Is this a protocol-semantic change?

**No — fail-secure validation, not a wire change.** Argue precisely:

- No byte on the wire changes. No field is added, removed, reordered, or reinterpreted.
- A conforming peer cannot trigger it: `X25519Keypair::generate()` clamps a CSPRNG scalar,
  whose public key has order `8·ℓ`, so `[k]·P` is non-identity for every `k`. Pinned by
  `contributory_exchange_is_never_rejected` (64 iterations).
- D12/D13 already require that peer-input failures be silent drops with no state mutation and
  no emitted datagram. The contributory failure is one more such input, and is handled
  identically: `complete_m1` removes the pending entry and returns `ServerEvent::None`;
  `on_complete_m2` resets the assembler and returns `ClientEvent::None`.
- Risk of breaking a legitimate handshake: zero, by the argument above.

**It is nevertheless a human decision gate (G-5)**, because it changes a documented crypto
behaviour from "accept" to "reject", and `DESIGN_DECISIONS.md` has no entry for it.

### 2.5 What changed

`X25519Keypair::diffie_hellman` now returns `Option<[u8; 32]>` — `None` when
`!shared.was_contributory()`. Both call sites in `handshake_v2.rs` handle `None` as a silent
drop.

### 2.6 One correction to the task's premise

The task asserted symmetry would hold for both peers. It does not, and the code is right:

> For a peer point `P` of order 8, `[k]P` is the identity only when `8 | k`. A clamped X25519
> scalar satisfies `k ≡ 1 (mod 8)`, so `[k]P = P ≠ O` for the honest peer — yet the output is
> all-zero anyway, because the **u-coordinate of `P` and of `−P` are equal**.

X25519 returns only the u-coordinate, so detection is on `u`, and both peers observe all-zero.
`low_order_rejection_is_symmetric` therefore asserts the honest side rejects and the
low-order holder never receives an all-zero secret.

---

## 3. Item 2 — Hybrid key-schedule KATs

### 3.1 What `derive_master_secret_v2` actually binds

From `pq-crypto/src/kdf.rs:167-186`:

```
ikm  = ss_a (32) ‖ ss_b (32) ‖ dh_cs (32)                       -- 96 bytes, order pinned
salt = [0u8; 32]
info = "pq-tunnel-master-v2" ‖ version (1) ‖ session_id (8) ‖ th3 (32)
```

**Directly bound:** the two KEM shared secrets, the X25519 shared secret, the protocol
version, the session id, and the transcript digest `TH3`.

**Not directly bound:** `ct2`, `ct3`, `eph_pk_c`, `eph_pk_s`, `x_c`, `x_s`.

### 3.2 Is that a real finding?

**Partly — and the "attacker could swap the ciphertext" framing does not hold.** The missing
fields are not unbound; they are bound *transitively*:

`TH3 = SHA256(dom ‖ M1_z ‖ M2_z ‖ M3_z)`, and each of `ct2`, `ct3`, `eph_pk_c`, `eph_pk_s`,
`x_c`, `x_s` is a **fixed-offset field** of one of those three messages. So a change to any of
them changes `TH3`, which changes `info`, which changes the master.

Proven by the four new tests in `handshake_v2.rs`, including
`master_secret_changes_when_only_the_ciphertext_changes`, which holds all three shared secrets
constant and varies only `ct3`.

Two properties make the transitive binding sound, and both are pinned:

- **Fixed offsets.** M1 = 4534, M2 = 5622, M3 = 1113 bytes, pinned by `const _: () = assert!(...)`
  at `handshake_v2.rs:157-177`. No field can shift without a compile error.
- **Fixed widths.** `version` is exactly one `u8` and `session_id` exactly 8 bytes, so the
  `info` concatenation is unambiguous — pinned by `master_v2_version_and_sid_are_independently_observable`.

The genuine residual risk is **drift**: `master_v2_direct_binding_surface_is_pinned` documents
that the *direct* tests would still pass if a future revision dropped `th3` from `info`, which
would silently unbind the ciphertexts. The transitive tests are the guard against that, and
they must be kept alongside the direct ones.

**Conclusion:** not a vulnerability today. It is a documented-implicit binding rather than an
explicit one, and it now has tests.

### 3.3 The end-to-end key-schedule KAT — the real gap

There is **no** test anywhere that pins `derive_master_secret_v2` (or `derive_finished_key`,
or `compute_client_finished`) to an externally supplied expected value. Every such test is
self-consistency. A systematic error in the `info` layout — a transposed field, a missing
separator, a wrong label — would pass the whole suite.

**Why no anchor is available (the design the task asked for, with the outcome):**

| Candidate source | Verdict |
|---|---|
| RFC 5869 §A.1-3 | **Not applicable.** Anchors `HKDF` itself, not a hybrid combiner. Already covered by `rfc5869_a1_hkdf_sha256_kat`. |
| X25519MLKEM768 (`draft-ietf-tls-ecdhe-mlkem`) | **Wrong combiner.** TLS uses `HKDF-Extract(early_secret, ECDHE) → HKDF-Expand(0, "derived")`, a different scheme from Tunnel's `HKDF(ss_a‖ss_b‖dh, salt=0, info=label‖ver‖sid‖th3)`. Not comparable. |
| NIST/ACVP vectors | Absorb the FIPS 203/204 primitives, not an application key schedule. |
| A second implementation | This project has no reference implementation, and writing one to generate the expected value makes it **self-derived** — it would launder a self-test into an apparent external anchor. Prohibited by D21. |

**Conclusion: no genuinely independent expected value exists for this construction.** The
honest options are (a) accept the gap and rely on the primitive-level KATs plus the
separation/binding tests added here, or (b) obtain an independent reviewer's implementation
and compare — which is a human/process gate, not a code change. Recorded as **G-2**.

**Recommended mitigation if G-2 is accepted as permanent:** freeze the `info` layout in a
single `const` tuple and add a test asserting the *exact concatenated byte string* for a fixed
input. That converts accidental drift into a loud failure even though the anchor is self-derived.

---

## 4. Item 4 — Parser boundary audit

### 4.1 Parser inventory

| Parser | file:line | Length rule | Boundary test | Verdict |
|---|---|---|---|---|
| `PacketHeader::decode` | `pq-tunnel-core/src/codec.rs:287` | `>= HEADER_LEN` | `packet_header_decode_length_boundaries`, `packet_header_decode_never_panics_near_the_boundary` | sound (see 4.3) |
| `InnerPlaintext::decode` | `codec.rs:389` | `== INNER_PLAINTEXT_LEN` | `inner_plaintext_decode_length_boundaries` | sound |
| `InnerPlaintext::new` | `codec.rs:352` | `== PAYLOAD_LEN` | `inner_plaintext_new_length_boundaries` | sound |
| `WirePacket::from_bytes` | `codec.rs:464` | `== PACKET_SIZE` | `wire_packet_from_bytes_length_boundaries` | sound |
| `WirePacket::from_parts` | `codec.rs:573` | `== PACKET_SIZE - HEADER_LEN`, version first | `wire_packet_from_parts_length_boundaries` | sound |
| `WirePacket::{header_bytes,ciphertext,tag}` | `codec.rs:484,491,503` | compile-time only | `region_accessors_are_in_bounds_for_both_constructors` | sound |
| `HandshakeFragment::from_datagram` | `handshake_v2.rs:317` | fixed-size input | `fragment_body_length_is_exact_for_every_index_and_type` | sound |
| `ClientHello::decode` | `handshake_v2.rs:527` | `== M1_BODY_LEN` | `client_hello_decode_length_boundaries` | sound |
| `ServerHello::decode` | `handshake_v2.rs:612` | `== M2_BODY_LEN` | `server_hello_decode_length_boundaries` | sound |
| `ClientConfirm::decode` | `handshake_v2.rs:689` | `== M3_BODY_LEN` | `client_confirm_decode_length_boundaries` | sound |
| `MlKemPublicKey::from_bytes` | `pq-crypto/src/kem.rs:82` | `== 1184` | `public_key_from_bytes_length_boundaries` | sound |
| `MlKemCiphertext::from_bytes` | `kem.rs:101` | `== 1088` | `ciphertext_from_bytes_length_boundaries` | sound |
| `MlDsaPublicKey::from_bytes` | `signature.rs:120` | `== 1952` | `public_key_from_bytes_length_boundaries` | sound |
| `MlDsaSignature::from_bytes` | `signature.rs:137` | `== 3309` | `signature_from_bytes_length_boundaries` | **not total** (4.2) |
| `decode_relay` | `pq-tunnel-bin/src/relay.rs:102` | header + `len <= max` | 5 boundary tests | sound |
| `ip_packet_len` | `pq-tunnel-bin/src/packet_len.rs:13` | `>= 20` both branches | 4 boundary tests | robust gap (4.4) |

### 4.2 `MlDsaSignature::from_bytes` is not total — genuine finding

`EncodedSignature::try_from` accepts any 3309 bytes, but the following
`Signature::decode` returns `None` for hint encodings it cannot represent. So
`from_bytes(&[0x5A; 3309])` is `Err` even though the length is exactly right.

**Not a vulnerability** — it is fail-secure on the attacker-controlled M1/M2 signature slot.
The pre-existing `ml_dsa_verify_rejects_tampered_signature` already anticipated this by
counting both rejection paths. The gap was that *no test documented it*, so a future caller
could write `from_bytes(..).expect(..)` on attacker data. Now documented in
`signature_from_bytes_length_boundaries`.

### 4.3 `PacketHeader::decode`'s `.expect()` — sound

`codec.rs:308`:

```rust
let packet_nonce = u64::from_be_bytes(
    data[1 + SESSION_ID_LEN..1 + SESSION_ID_LEN + PACKET_NONCE_LEN]
        .try_into()
        .expect("already bounds-checked above: data.len() >= HEADER_LEN"),
);
```

The guard at `codec.rs:289` is `data.len() < HEADER_LEN → Err`, with
`HEADER_LEN = 1 + 8 + 8 = 17`. The slice starts at index 9 and is 8 bytes long, so it needs
`len >= 17` — exactly the guarded condition. The `expect` is unreachable. Sound.

Note the two other `expect`s in the region accessors (`codec.rs:487, 499, 510`) are guarded
only by `const _: () = assert!(...)` plus `debug_assert!`. They are sound because `self.0` is
`[u8; PACKET_SIZE]` by type — the slices can never be out of bounds — and
`region_accessors_are_in_bounds_for_both_constructors` now runs them in release
configurations too.

### 4.4 `ip_packet_len` — robustness finding (confirmed)

The task's hypothesis is correct and confirmed by reading and by test:

```rust
if payload.len() < 20 { return 0; }         // IPv4 minimum
match payload[0] >> 4 {
    6 => { let payload_len = u16::from_be_bytes([payload[4], payload[5]]); ... }
```

- **Not a memory-safety issue.** Bytes 4..6 need `len >= 6`; the guard gives `len >= 20`. In
  bounds. `never_panics_across_lengths_and_versions` confirms no panic for any length in
  `0..=PAYLOAD_LEN+8` × versions {0,4,6,15}.
- **A correctness issue.** An IPv6 header is 40 bytes. For a 20..=39-byte buffer with the
  version nibble `6`, bytes 4..6 are read as a "payload length" when they are not an IPv6
  payload-length field at all. Those bytes are attacker-controlled (the relay forwards an
  arbitrary framed datagram into the slot), so the returned length is derived from garbage.
- **Fail-safe in the direction that matters:** `total > payload.len()` still rejects, so the
  function never reports a length longer than the buffer — nothing over-long reaches the TUN.
- **Residual:** for `payload_len = 0` it returns `40` on a 20-byte buffer, and the caller
  would then read 40 bytes from a 20-byte buffer. **This needs caller verification before
  being dismissed** → human gate G-3.

### 4.5 `decode_relay` ordering claim — verified true

`pq-tunnel-bin/src/relay.rs:97-100` claims "Capacity is checked **before** the truncation
check". Source (`relay.rs:136-142`) confirms it: `if len > max { TooLarge }` precedes
`if msg.len() < hdr_len + len { Truncated }`.

`capacity_check_precedes_truncation_check` pins the boundary: a header-only buffer declaring
`max + 1` returns `TooLarge`; a header-only buffer declaring exactly `max` returns
`Truncated` (the declared length is legal, the buffer is simply short). The two error classes
are disjoint by construction, which is the correct reading of the claim.

### 4.6 Panic / `unwrap` inventory on the attacker-reachable path

Production-code occurrences of `unwrap` / `expect` / `unreachable!` reachable from
pre-authentication input:

| Location | Kind | Reachable pre-auth? | Why it is safe |
|---|---|---|---|
| `codec.rs:308` | `expect` | **Yes** (header decode) | Guarded by `len >= HEADER_LEN`; §4.3 |
| `codec.rs:487, 499, 510` | `expect` | Yes | `self.0: [u8; 1280]` by type; slices are statically in bounds |
| `pq-crypto/src/kem.rs:57` | `unwrap` | Yes | `<[u8;32]>::try_from(&SharedKey)`; the shared secret is 32 bytes by FIPS 203 §4. Pinned by `ml_kem_768_shared_secret_has_correct_size` |
| `pq-crypto/src/aead.rs:117` | `expect` | No | `random_nonce`, OS RNG |
| `pq-crypto/src/kdf.rs:36, 221` | `expect` | No | Output-length mismatch / HMAC key length — both structurally impossible |
| `handshake_v2.rs:349, 378` | `expect` | Yes | `message_body_len(hs_type)` after `expected_frag_count(hs_type)` returned `Some`; the two are matched on the same pinned `hs_type` |
| `handshake_v2.rs:991, 1126, 1144, 1602, 1628, 1705` | `expect` | Yes | "fixed lengths" — messages built by `encode_m*` at pinned sizes |
| `handshake_v2.rs:1064, 1487, 1492, 1504, 1520-1522, 1538, 1542, 1642, 1703, 1704, 1720` | `expect` | Yes | Internal state-machine invariants, all guarded by the `pending.contains_key` / `state ==` check immediately above. Not attacker-controlled |
| `handshake_v2.rs:398` | `expect` | No | A 1280-byte buffer always parses |
| `handshake_v2.rs:1188` | `unreachable!()` | No | Just assigned `M3Sent` on the line above |

No attacker-reachable panic was found. The `fuzz/` targets cover the same surfaces out of band.

---

## 5. Item 5 — RFC / FIPS provenance

### 5.1 Verified independently (sources fetched during this audit)

| Algorithm | Standard | Status verified | Anchor in repo | Anchor genuinely external? |
|---|---|---|---|---|
| ML-KEM-768 | **FIPS 203** | **Final, 13 Aug 2024.** Planning note (11/17/2025): *"We've identified an issue that will be corrected in a future update/revision"* | `mlkem_768_test.json` **group 0** (source `CCTV/strcmp` v0.1) **tcId 1** → `KEM_KEYGEN_{SEED,EK,C,K}` | **YES** |
| ML-KEM-768 encaps | **FIPS 203** | as above | `mlkem_768_encaps_test.json` **group 1** (source `FIPS 203` v1.0) **tcId 14** → `KEM_ENCAPS_{EK,M,C,K}` | **YES** |
| ML-DSA-65 verify | **FIPS 204** | **Final, 13 Aug 2024.** Planning note (07/31/2026): *"several minor issues ... corrected in a future update/revision"* | `mldsa_65_verify_test.json` group 0 `publicKey` + tcId 1 (`ValidSignature`, comment `baseline`) → `DSA_{PK,MSG,SIG}` | **YES** |
| ML-DSA-65 sign | **FIPS 204** | as above | `mldsa_65_sign_seed_test.json` group 0 `privateSeed`/`publicKey` + tcId 1 (`baseline`) → `DSA_{SEED,KEYGEN_PK,SIG}` | **YES** |
| ML-DSA-65 keygen | **FIPS 204** | as above | `mldsa_65_sign_seed_test.json` group 0 `privateSeed` = `2a2a…2a`, `publicKey` = `DSA_KEYGEN_PK` | **YES** |
| ChaCha20-Poly1305 | **RFC 8439 §2.8.2** | Informational (2018) | `RFC8439_*` (key/nonce/AAD/114-byte plaintext/130-byte ct‖tag) | **YES** |
| HKDF-SHA256 | **RFC 5869 §A.1 TC1** | Informational (2010) | `RFC5869_{IKM,SALT,INFO,OKM}` | **YES** |
| X25519 | **RFC 7748 §6.1** | Informational (2016) | `RFC7748_{ALICE_*,BOB_*,SHARED}` | **YES** |
| SHA-256 | **FIPS 180-4** / RFC 6234 §8.5 | — | `transcript.rs` — `sha256_known_vector` (`"abc"`), `sha256_empty_string_known_vector` (`""`) | **YES** |
| Hybrid key schedule | — (none) | — | **NONE** | **NO — gap, §3.3** |
| Transcript digest TH1/2/3 | — (Tunnel-specific) | — | **NONE** | **NO — gap** |

**Byte-exact verification performed.** Every constant was extracted programmatically from
`pq-crypto/src/kat_vectors.rs` and compared against the freshly downloaded Wycheproof files:

```
DSA_PK        == sign_seed.group0.publicKey        -> True
DSA_PK        == verify.group0.publicKey           -> True
DSA_SEED      == sign_seed.group0.privateSeed      -> True
DSA_SIG       == sign_seed.group0.tcId1.sig        -> True
DSA_SIG       == verify.group0.tcId1.sig           -> True
DSA_MSG       == sign_seed.g0.tcId1.msg            -> True
KEM_KEYGEN_*  == mlkem_768_test.g0.tcId1 (all 4)   -> True
KEM_ENCAPS_*  == mlkem_768_encaps.g1.tcId14 (all 4)-> True
```

All four Wycheproof filenames cited in `kat_vectors.rs` exist in the current corpus
(`C2SP/wycheproof`, `testvectors_v1/`). The transcription is faithful.

One nuance worth recording: `sign_seed.g0.tcId1` carries **no `rnd` and no `ctx` field**, which
that schema defines as the deterministic (`rnd = 0`) empty-context case — exactly what the
`ml-dsa` `Signer` produces. The `kat_vectors.rs` header comment's reasoning is correct.

### 5.2 Dependency versions and audit status — HIGH-severity finding

`cargo tree -p pq-crypto --target x86_64-pc-windows-msvc`:

| Crate | Version | Note |
|---|---|---|
| `ml-kem` | **0.3.2** | README: *"The implementation contained in this crate has **never been independently audited**! USE AT YOUR OWN RISK!"* |
| `ml-dsa` | **0.1.1** | README: same warning |
| `x25519-dalek` | **=3.0.0-rc.1** | **release candidate**, pinned exactly |
| `curve25519-dalek` | **=5.0.0-rc.1** | **release candidate**, pinned exactly |
| `sha2` | 0.10.9 (`force-soft-compact`) | |
| `chacha20poly1305` | 0.10.1 | |
| `hkdf` / `hmac` | 0.12.4 / 0.12.1 | |
| `zeroize` | 1.9.0 | |

Two release candidates and two explicitly unaudited crates sit under the project's two primary
security guarantees. The KATs prove *conformance to the published vectors*; they cannot prove
absence of implementation defects. `CRYPTO_PROFILE.md` and `DESIGN_DECISIONS.md` do not
mention this. Recorded as **G-1**.

> **Update — the posture is now recorded.** `CRYPTO_PROFILE.md` §14.1 ("Dependency
> posture of the pinned suite") now states these exact versions and their
> upstream review posture, and names the `chacha20poly1305` 0.10.1 NCC Group
> audit that was missing here. The finding itself is **unchanged**: the
> versions are still release candidates and still carry the upstream
> "never been independently audited" warning, and `DESIGN_DECISIONS.md` still
> does not record the acceptance.

**[CORRECTED — the SHA-256 note that followed this paragraph was inverted.]**
The text as first written described `pq-crypto/src/transcript.rs` as
"documenting a Windows-on-ARM64 SHA-256 discrepancy" and permitting "either
the FIPS vector or a `platform_vector` ending in `15ad`". **That was
backwards, and the "platform discrepancy" story was false.**

- The canonical value of `SHA-256("abc")` is
  `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` — it
  ends **`...f20015ad`**. That is the FIPS 180-4 / RFC 6234 §8.5 value
  (RFC 6234 §8.5, TEST1 = `"abc"`), and it is the value the crate's
  implementation produced. The *other* value — the one this track recorded as
  "the FIPS vector" — differs from it in its last four bytes and is **not** the
  FIPS value.
- The crate's SHA-256 was always correct: it is pure-software SHA-256 via
  `sha2` with `force-soft-compact` (`pq-crypto/Cargo.toml:14`) — scalar, no
  NEON/SHA-NI — and it produced the canonical digest on every platform
  including this Windows/ARM64 host. There was never a "Windows-on-ARM64
  discrepancy". The empty-string test asserted only the FIPS value and
  passed throughout, which is what made the inconsistency visible.
- **The defect was in the test, not the implementation.** The old
  `sha256_known_vector` accepted either digest and the comment labelled the
  *correct* one "a platform bug". A test that accepts a wrong answer is
  worse than no test.

**Current state (resolved):** `pq-crypto/src/transcript.rs` now asserts
**exactly one** expected digest — the canonical `...f20015ad` — with no
escape hatch. Gate **G-6** is therefore **CLOSED**, and no follow-up decision
is needed.

### 5.3 Documentation claims vs. reality

| Claim | Reality | Verdict |
|---|---|---|
| `DESIGN_DECISIONS.md:1202` — "Google Wycheproof JSON vectors (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65)" | Vectors are real and byte-exact (§5.1). Attribution says "Google"; the corpus now lives at `C2SP/wycheproof` (Google-authored, transferred). | **Accurate**, attribution slightly stale |
| `CRYPTO_PROFILE.md` §14 — "anchored to external known-answer vectors per D21 (RFC 8439, RFC 5869, RFC 7748, Wycheproof ML-KEM-768/ML-DSA-65)" | True for the **primitives**. Silent on the hybrid key schedule having no anchor. | **Accurate but incomplete — since narrowed.** §14 now states explicitly that the D21 anchoring covers the *primitive set only*, and that the master-secret derivation, traffic keys, nonce prefixes and TH1/TH2/TH3 have **no external vector** and are pinned only by self-authored tests. |
| "FIPS 203" / "FIPS 204" as final | Both final (13 Aug 2024), both with **open errata** pending a revision. | **Accurate; add errata note** |
| Nothing claims FIPS validation / certification | Nothing does. | **Correct** |

### 5.4 Mojibake — confirmed

`pq-crypto/src/lib.rs` line 18 contained `U+FFFD` (`EF BF BD 3F`) where an em-dash belonged,
producing `both ephemeral �?" DESIGN_DECISIONS D13`. A byte-level scan of every `.rs` and
`.md` file outside `target/` found **exactly one** occurrence, at byte offset 549. The
corrupted text is replaced with a proper em-dash (`U+2014`). Verified: no `U+FFFD` remains in
the file.

---

## 6. Human decision gates

| Gate | Decision needed | Why it needs a human | Recommendation |
|---|---|---|---|
| **G-1** | Accept two release-candidate dependencies (`x25519-dalek 3.0.0-rc.1`, `curve25519-dalek 5.0.0-rc.1`) and two unaudited crates (`ml-kem 0.3.2`, `ml-dsa 0.1.1`) under the project's primary guarantees? Record the trade-off in `CRYPTO_PROFILE.md` / `DESIGN_DECISIONS.md`. | A supply-chain risk acceptance for HNDL resistance and metadata resistance. Not reversible by a code change. | Record it explicitly. Add a CI job that fails when a pinned PQ dependency is a pre-release. |
| **G-2** | Accept that the hybrid key schedule and TH1/2/3 have **no** external anchor, or commission an independent implementation to compare against? | Per D21 a self-derived vector is not an anchor, so "just add a KAT" is not available. Either accept the gap or pay for independence. | Accept the gap; add the exact-`info`-bytes regression test so drift is loud. |
| **G-3** | Fix `ip_packet_len`'s IPv6 branch to require `len >= 40`? | Changes behaviour for 20..=39-byte buffers (currently returns a length derived from non-IPv6 bytes). Must confirm the caller cannot over-read. | Fix it. Split the minimum-length guard per version. Verify the caller first. |
| **G-4** | Record the FIPS 203 / FIPS 204 errata ("potential updates" dated 11/17/2025 and 07/31/2026) in `CRYPTO_PROFILE.md`? | Documentation accuracy; the current text implies the standards are settled. | Yes — one line each, with the NIST planning-note dates. |
| **G-5** | Ratify the non-contributory X25519 rejection as a `DESIGN_DECISIONS` entry, and ratify `diffie_hellman` returning `Option`? | It changes a documented crypto behaviour from accept to reject. Argued fail-secure and not a wire change (§2.4), but the decision belongs to the maintainer. | Ratify. Add a D-number next to the `Option` doc comment. |
| **G-6** | ~~Remove the permissive `platform_vector` branch in `transcript.rs::sha256_known_vector`?~~ **CLOSED — done.** The branch is gone; the test asserts exactly one digest, the canonical `SHA-256("abc")` = `…f20015ad`. | A KAT that accepts two values is a weaker anchor. Removing it restores a strict external anchor. | **Done.** No `#[cfg(target_arch = "aarch64")]` carve-out is needed or wanted: the "ARM64 tolerance" the old gate proposed to preserve was protecting a value that was never the FIPS one. |

---

## 7. Test classification — the two lists kept separate

### (EXT) Externally anchored — expected values from RFC / FIPS / Wycheproof

**Pre-existing (M5.1), all unchanged by this audit:**

| Test | Anchor |
|---|---|
| `classical::tests::x25519_rfc7748_6_1_kat` | RFC 7748 §6.1 |
| `kdf::tests::rfc5869_a1_hkdf_sha256_kat` | RFC 5869 §A.1 TC1 |
| `aead::tests::rfc8439_2_8_2_chacha20_poly1305_kat` | RFC 8439 §2.8.2 |
| `kem::tests::ml_kem_768_wycheproof_keygen_kat` | `mlkem_768_test.json` g0 tcId 1 |
| `kem::tests::ml_kem_768_wycheproof_decaps_kat` | `mlkem_768_test.json` g0 tcId 1 |
| `kem::tests::ml_kem_768_wycheproof_encaps_kat` | `mlkem_768_encaps_test.json` g1 tcId 14 |
| `signature::tests::ml_dsa_65_wycheproof_verify_kat` | `mldsa_65_verify_test.json` g0 tcId 1 |
| `signature::tests::ml_dsa_65_wycheproof_keygen_kat` | `mldsa_65_sign_seed_test.json` g0 |
| `signature::tests::ml_dsa_65_wycheproof_sign_kat` | `mldsa_65_sign_seed_test.json` g0 tcId 1 |
| `transcript::tests::sha256_known_vector` | FIPS 180-4 / RFC 6234 §8.5 — **strict, single expected digest** (`…f20015ad`); the permissive branch is gone (gate G-6, **CLOSED**) |
| `transcript::tests::sha256_empty_string_known_vector` | FIPS 180-4 |

**Added by this audit — none.** No new test in this audit carries an external expected value.
The low-order-point u-coordinates in `classical.rs` are the *inputs* (public constants from the
curve's group structure), not expected outputs; the assertion is about this wrapper's
behaviour. This is stated explicitly so the distinction is not blurred later.

### (SELF) Self-consistency / regression only — added by this audit

**Item 1 (6 tests):** `low_order_peer_keys_are_rejected`,
`low_order_rejection_is_symmetric`, `contributory_exchange_is_never_rejected`,
`th1_binds_the_clients_x25519_key`, `th2_binds_the_servers_x25519_key`,
`server_rejects_non_contributory_client_x25519_key`,
`client_rejects_non_contributory_server_x25519_key`,
`contributory_check_does_not_perturb_a_valid_exchange`.

**Item 2 (7 tests):** `master_v2_direct_binding_surface_is_pinned`,
`master_v2_distinguishes_absent_and_zero_transcript`,
`master_v2_version_and_sid_are_independently_observable`,
`th3_binds_the_client_kem_public_key`, `th3_binds_both_kem_ciphertexts`,
`th3_binds_both_server_ephemeral_keys`,
`master_secret_changes_when_only_the_ciphertext_changes`.

**Item 3 (6 tests):** `every_kdf_label_is_pairwise_separated`,
`master_labels_v1_and_v2_are_separated`,
`handshake_init_labels_are_separated_from_traffic_labels`,
`nonce_prefixes_are_pairwise_distinct_as_four_byte_values`,
`transcript_fields_are_injection_resistant`, `domain_prefix_changes_the_digest`.

**Item 4 (18 tests):** `packet_header_decode_length_boundaries`,
`packet_header_decode_never_panics_near_the_boundary`,
`inner_plaintext_decode_length_boundaries`, `inner_plaintext_new_length_boundaries`,
`wire_packet_from_bytes_length_boundaries`, `wire_packet_from_parts_length_boundaries`,
`region_accessors_are_in_bounds_for_both_constructors`,
`client_hello_decode_length_boundaries`, `server_hello_decode_length_boundaries`,
`client_confirm_decode_length_boundaries`, `message_codecs_never_panic_across_the_length_window`,
`fragment_body_length_is_exact_for_every_index_and_type`,
`public_key_from_bytes_length_boundaries`, `ciphertext_from_bytes_length_boundaries`,
`decapsulate_accepts_any_ciphertext_and_never_panics`,
`signature_from_bytes_length_boundaries`, `verify_never_panics_and_never_accepts_unsigned_bytes`,
`capacity_check_precedes_truncation_check`, `relay_header_length_boundaries`,
`decode_relay_never_panics_across_all_lengths`, `declared_length_exact_buffer_boundary`,
`encoder_decoder_capacity_agree_at_the_edge`, `ipv4_minimum_length_boundary`,
`ipv4_slot_length_boundary`, `ipv6_minimum_length_boundary`, `ipv6_slot_length_boundary`,
`ipv6_branch_reads_a_short_buffer_without_panicking`,
`sub_minimum_lengths_are_rejected`, `never_panics_across_lengths_and_versions`.

Every test added in this audit asserts a property of **this implementation** against a
locally-chosen input. None of them establishes that Tunnel's construction is cryptographically
correct. D21 remains satisfied: **no vector was adjusted to make a test pass.** Where a test
of mine failed, the cause was the test, not the code — except in two cases where the code was
genuinely wrong and was fixed (E-14, and the `Option`-vs-error contract), plus E-9 and E-10,
which are documented rather than fixed.
