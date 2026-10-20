# Cryptographic Construction Specification — SKELETON

> **THIS IS A SKELETON, NOT A SPECIFICATION.**
> Prepared by a documentation pass. **Not reviewed by anyone outside the Tunnel
> project.** Not normative. Not a conformance document. It exists so that a
> normative construction specification can be written without re-deriving the
> construction from source.
>
> **The gap this document addresses:** `CRYPTO_PROFILE.md` §14
> (`:432-436`) pins the **suite** —
> *"ML-KEM-768 + X25519 hybrid (HKDF-SHA256 shared-secret merge), ML-DSA-65,
> ChaCha20-Poly1305, HKDF-SHA256"* — but the document's own status section
> (`:24-31`) **declines to define "final handshake construction"**, and
> `CRYPTO_PROFILE.md:281-284` defers nonce construction to `PROTOCOL_SPEC.md`,
> which does not define it either.
>
> **A suite list cannot be verified against an implementation.** A second
> implementation must reproduce byte-for-byte: the concatenation order, the salt,
> every label string, the transcript inputs, and the truncation length. None of
> that is written down anywhere as a normative requirement.
>
> **Markers:** ✅ from source with `file:line` · ⚠️ from a decision record ·
> 🔶 inferred from code, not stated anywhere · `[TO BE AUTHORED]` no source of
> truth exists · `[TO BE VERIFIED]` stated, code match unconfirmed.
>
> **Source of truth:** `pq-crypto/src/kdf.rs`, `pq-crypto/src/transcript.rs`,
> `pq-tunnel-core/src/handshake_v2.rs`, `pq-tunnel-core/src/envelope.rs`.

---

## 0. Document control

| Field | Value |
|---|---|
| Profile version | ✅ `v0.2.0-alpha` — `CRYPTO_PROFILE.md:422` |
| Applies to protocol version | ✅ `2` — `codec.rs:81` |
| Profile identity | `[TO BE AUTHORED]` — how does a peer know which profile is in use? Answer today: it does not negotiate; the version byte is the only selector (`DESIGN_DECISIONS.md:605-607`). Is that sufficient? |
| Agility policy | ✅ "algorithm replacement may require a protocol version change" ⚠️ `CRYPTO_PROFILE.md:414-417` |

---

## 1. Suite

### 1.1 Pinned algorithms

| Role | Algorithm | Sizes | Source |
|---|---|---|---|
| PQ KEM | **ML-KEM-768** (FIPS 203) | ek 1184, dk 2400, ct 1088, ss 32 | ✅ `CRYPTO_PROFILE.md:434`; `pq-crypto/src/lib.rs:37-38`; `handshake_v2.rs:131,139` |
| Classical KEX | **X25519** (RFC 7748) | pk/sk 32, ss 32 | ✅ `CRYPTO_PROFILE.md:434`; `pq-crypto/src/classical.rs:1` |
| Signature | **ML-DSA-65** (FIPS 204) | pk 1952, sig 3309, seed 32 | ✅ `CRYPTO_PROFILE.md:435`; `pq-crypto/src/lib.rs:40` |
| KDF | **HKDF-SHA256** | okm variable | ✅ `CRYPTO_PROFILE.md:436`; `pq-crypto/src/kdf.rs:8-19` |
| MAC | **HMAC-SHA256** | 32 (truncated to 16) | ✅ `pq-crypto/src/kdf.rs:212-227` |
| Hash | **SHA-256** | 32 | ✅ `pq-crypto/src/transcript.rs:1` |
| AEAD | **ChaCha20-Poly1305** | key 32, nonce 12, tag 16 | ✅ `CRYPTO_PROFILE.md:435`; `pq-crypto/src/lib.rs:24` |

### 1.2 Implementation library versions

| Crate | Version | Source |
|---|---|---|
| `ml-kem` | 0.3.2 (features `getrandom`, `zeroize`) | ✅ `pq-crypto/Cargo.toml:11` |
| `ml-dsa` | 0.1.1 (features `getrandom`, `zeroize`) | ✅ `pq-crypto/Cargo.toml:12` |
| `x25519-dalek` | **`=3.0.0-rc.1`** (exact pin) | ✅ `pq-crypto/Cargo.toml:13` |
| `curve25519-dalek` | **`=5.0.0-rc.1`** (exact pin) | ✅ `pq-crypto/Cargo.toml:20` |
| `sha2` | 0.10, feature `force-soft-compact` | ✅ `pq-crypto/Cargo.toml:14` |
| `chacha20poly1305` | 0.10 | ✅ `pq-crypto/Cargo.toml:21` |
| `hkdf` | 0.12 | ✅ `pq-crypto/Cargo.toml:22` |
| `hmac` | 0.12 | ✅ `pq-crypto/Cargo.toml:23` |
| `signature` | 3 | ✅ `pq-crypto/Cargo.toml:17` |
| `kem` | 0.3 | ✅ `pq-crypto/Cargo.toml:18` |
| `zeroize` | 1 (feature `derive`) | ✅ `pq-crypto/Cargo.toml:15` |

**Note `[TO BE AUTHORED]`:** the exact pin `x25519-dalek = "=3.0.0-rc.1"` is a
**release candidate**. Whether a release candidate is acceptable in a
cryptographic profile — and what happens when 3.0.0 final ships — is not
discussed anywhere. `CRYPTO_PROFILE.md:82-91` requires "publicly reviewed"
cryptography; an RC is not a stable reviewed release. **This should be
addressed explicitly.**

**Note:** `sha2` with `force-soft-compact` forces scalar SHA-256 ✅
(`pq-crypto/Cargo.toml:14`). Rationale: avoids NEON/SHA-NI codegen divergence
across platforms. **The rationale is stated only in an INTERNAL-ONLY file**
(`checkpoints/SECURITY_RELEASE_AUDIT.md:119`). It belongs here.

**No native-C crypto backends:** `aws-lc-sys`, `ring`, `openssl` are absent from
the dependency graph ✅ (verifiable by inspecting `pq-crypto/Cargo.toml`). The
claim is stated at `checkpoints/SECURITY_RELEASE_AUDIT.md:119` — INTERNAL-ONLY.

---

## 2. Shared constants

| Constant | Value | Length | Source |
|---|---|---|---|
| HKDF salt | **32 zero bytes** | 32 | ✅ `pq-crypto/src/kdf.rs:4` (`KDF_SALT_BYTES`), used at `:77,100,111,122,133,143,147,183,206` |
| Transcript domain string | `pq-tunnel-v1` | 12 | ✅ `handshake_v2.rs:154` → `HANDSHAKE_DOMAIN` |
| HKDF function | HKDF-SHA256 (Extract-then-Expand) | — | ✅ `kdf.rs:30-31` |
| Session id length | 8 | 8 | ✅ `codec.rs:105` |

### 2.1 The zero salt — `[TO BE AUTHORED]`

Nine separate call sites use `let salt = [0u8; 32];`. The only justification
given is for the **Finished key** ✅ (`kdf.rs:196-197`):

> "The salt is pinned to the zero 32-byte string (it is NOT the KEM shared
> secret — the master is already the Extract output)."

That argument is specific to a derivation whose IKM is *already* an HKDF
Extract output. It does **not** transfer to `derive_client_to_server_key`
(`kdf.rs:97-116`), whose IKM is the 32-byte master — arguably the same
situation — but it is never stated there.

**Required for the final spec:** a per-derivation statement of the salt and its
justification, or a single blanket statement covering all nine.

---

## 3. Key hierarchy

```
Identity keys (ML-DSA-65 statics, SIGNATURE ONLY — never in key agreement)
        │  D14: "identity keys never enter key agreement"  ✅ DESIGN_DECISIONS.md:677-678
        │  (no edge — this line means *exclusion*)
        ▼
Ephemeral secrets:  ssA, ssB (ML-KEM-768 shared secrets), dh_cs (X25519)
        │
        ▼
Master  = HKDF-SHA256(...)                                    §4
        │  lifetime = session lifetime; zeroized at close
        ▼
Finished key  = HKDF-SHA256(master, ...)                      §6
        │
        ▼
Traffic keys (c2s, s2c) + nonce prefixes (c2s, s2c)           §5
        │  all session_id-bound
        ▼
Packet protection: ChaCha20-Poly1305                          §7
```

**Normative statements** ✅/⚠️:

1. Identity keys MUST NOT enter any key derivation. ⚠️ `DESIGN_DECISIONS.md:677-678`
   — "Identity keys are signature-only: they never enter the key schedule
   (`CRYPTO_PROFILE.md §3`)" ⚠️ `:507-509`.
2. The master MUST be derived only from ephemeral secrets. ⚠️ `DESIGN_DECISIONS.md:693-694`
3. The master MUST NOT outlive the session and MUST NOT be retained for rekey.
   ⚠️ `DESIGN_DECISIONS.md:695-696`
4. Derived keys MUST be bound to `session_id`. ✅ `kdf.rs:88-96` (`session_info`)
   — "Binding the `session_id` into the derivation makes the derived keying
   material *per-session*, not merely per-master".
5. Derivation MUST be one-way and domain-separated. ⚠️ `DESIGN_DECISIONS.md:701-702`

**Point 4 is well-argued in the source** (`kdf.rs:86-96`): two sessions sharing a
master still get independent keys and nonce prefixes, so a counter reset in one
cannot collide with another session's AEAD nonce space. This reasoning belongs
in the specification.

---

## 4. Master secret derivation

### 4.1 Formula ✅

```
ssA    : 32 bytes   ML-KEM-768 shared secret from ct2
         (server encapsulates to the client's ephemeral key; client decapsulates)
ssB    : 32 bytes   ML-KEM-768 shared secret from ct3
         (client encapsulates to the server's ephemeral key; server decapsulates)
dh_cs  : 32 bytes   X25519 shared secret (client ephemeral × server ephemeral)
```

**Validity requirement on `dh_cs` — `[WORKING TREE]`, no record:**
the working tree changes `X25519Keypair::diffie_hellman` to return `None` when
the shared secret is all-zero, citing RFC 7748 §6.1 ("MAY check … whether K is
the all-zero value and abort if so") and §7 (Curve25519 has cofactor 8, so a
small-order peer public key drives every scalar multiple to the identity
element). Without the check, a peer can supply a low-order key and dictate the
DH leg's contribution — including making it all-zero.

**The rule is correct; it is simply not written down anywhere.** It appears only
in the doc comment of `[WORKING TREE] pq-crypto/src/classical.rs:29+`, with no
decision record entry, no threat-model note, and no named test. This skeleton
must add it to §4 as a normative MUST, and the project must record it — see
[`../05-gaps.md`](../05-gaps.md) **G-23**.

**Required normative text:** a peer-supplied X25519 public key of small order
MUST be rejected; a zero shared secret MUST NOT be used as `dh_cs`.

ikm    = ssA ‖ ssB ‖ dh_cs                    (96 bytes)
salt   = 00 × 32
info   = "pq-tunnel-master-v2" ‖ VERSION(1) ‖ SID(8) ‖ TH3(32)
                                             (53 bytes)

master = HKDF-SHA256(ikm, salt, info, L = 32)
```

**Source:** ✅ `pq-crypto/src/kdf.rs:164-188`; restated ⚠️
`DESIGN_DECISIONS.md:566-568`; `handshake_v2.rs:52-54`.

### 4.2 Ordering is normative and was a bug ✅

> "Concatenation order is pinned (`ssA ‖ ssB ‖ dh_cs` on both sides); XOR
> combination is banned (the pre-v2 XOR-combiner derivation bug)."
> — ✅ `kdf.rs:154-157`, ⚠️ `DESIGN_DECISIONS.md:568-570`

**Test:** `derive_master_secret_v2_order_is_pinned` ✅ `kdf.rs:409-421` —
swapping ssA/ssB MUST change the master.

**Normative:** a combiner that is order-insensitive (XOR, or a commutative
operation) MUST NOT be used. **This is a security-relevant rule with a real
historical precedent in this codebase and it must be in the spec.**

### 4.3 Binding requirements ✅

`version`, `sid` and `th3` MUST each change the master when changed. Tested by
`derive_master_secret_v2_binds_version_sid_th3` ✅ `kdf.rs:432-450`, and
`derive_master_secret_v2_binds_dh_leg` ✅ `kdf.rs:423-431`.

### 4.4 Zeroization

`ikm` and `info` staging buffers are zeroized after use ✅ (`kdf.rs:185-186`).

**`[TO BE VERIFIED]` — the legacy v1 path:** `derive_master_secret`
(`kdf.rs:73-80`) leaves its `ikm` staging buffer **un-zeroized**. This is
acknowledged at `kdf.rs:156-161`:
> "Unlike the v1 `derive_master_secret` (which leaves its `ikm` staging buffer
> un-zeroized — see that function) …"

The v1 function is still exported (`pq-crypto/src/lib.rs:29`). **Whether it is
reachable from production code is UNVERIFIED by this package.** Either remove it
or document why it remains.

---

## 5. Traffic keys and nonce prefixes

All four derivations use `session_info(label, session_id) = label ‖ session_id`
✅ (`kdf.rs:88-96`), salt `00 × 32` ✅, IKM = the 32-byte master.

| # | Output | Length | `info` | Source |
|---|---|---|---|---|
| 5.1 | `c2s_key` | 32 | `"pq-tunnel-c2s-v2"` ‖ SID | ✅ `kdf.rs:97-107` |
| 5.2 | `s2c_key` | 32 | `"pq-tunnel-s2c-v2"` ‖ SID | ✅ `kdf.rs:109-117` |
| 5.3 | `nonce_prefix_c2s` | **4** | `"pq-tunnel-nonce-c2s-v2"` ‖ SID | ✅ `kdf.rs:119-127` |
| 5.4 | `nonce_prefix_s2c` | **4** | `"pq-tunnel-nonce-s2c-v2"` ‖ SID | ✅ `kdf.rs:129-139` |

**Label suffixes are versioned (`-v2`) and MUST be treated as frozen wire
constants** ✅ `kdf.rs:102,112,124,134`. Changing one silently forks the
protocol; `CryptoError::Kdf` would not fire.

**Label-disjointness test:** `derive_master_secret_v2_label_is_disjoint_from_v1`
✅ `kdf.rs:453-461`.

**Tests covering §5:** `per_direction_keys_are_different` ✅ `kdf.rs:286-294`;
`nonce_prefixes_are_different` ✅ `kdf.rs:297-303`;
`different_session_ids_derive_different_keys` ✅ `kdf.rs:310-324`;
`different_session_ids_derive_different_nonce_prefixes` ✅ `kdf.rs:330-343`.

⚠️ **Limitation to record:** these tests assert **inequality** of 32-byte
outputs. Inequality of HKDF outputs is essentially guaranteed by the PRF, so
these tests are close to vacuous — they can only fail if the code is literally
wrong. They do **not** demonstrate independence. A real domain-separation
argument belongs in the specification.

### 5.5 Legacy v1 labels — `[TO BE AUTHORED]`

| Output | Length | `info` | Source |
|---|---|---|---|
| `master_v1` | 32 | `"pq-tunnel-master-v1"` | ✅ `kdf.rs:77-80` |
| `handshake_init_key` | 32 | `"pq-tunnel-init-v1"` | ✅ `kdf.rs:141-144` |
| `handshake_init_nonce` | 12 | `"pq-tunnel-init-nonce-v1"` | ✅ `kdf.rs:146-149` |

These are exported (`pq-crypto/src/lib.rs:29-30`). Are they live? If not,
remove; if yes, specify. `[TO BE VERIFIED]`.

---

## 6. Canonical transcript and signatures

### 6.1 Canonical form rules ✅

For a message being hashed:

1. Fragment headers are **NOT** hashed ⚠️ `DESIGN_DECISIONS.md:578-580`,
   ✅ `handshake_v2.rs:37-40`
2. Padding is **NOT** hashed ⚠️ same
3. The signature slot (M1/M2, 3309 bytes) or the Finished-MAC slot (M3, 16
   bytes) is **zero-filled** ✅ `handshake_v2.rs:725-739` (`canonical_zerofill`)
4. The message MUST be exactly the pinned body length, else the function returns
   `None` ✅ `handshake_v2.rs:733-736`
5. The domain string is prepended **once** ✅ `handshake_v2.rs:742-748`
   (`Transcript::new_with_initial(HANDSHAKE_DOMAIN)`)

**Zero-fill position:** the LAST `slot` bytes of the message ✅
`handshake_v2.rs:735-738` — which is correct because the signature is the final
field of both M1 and M2 ✅ `handshake_v2.rs:10-13`.

### 6.2 The three digests ✅

```
TH1 = SHA256( "pq-tunnel-v1" ‖ M1_z )                            client signs TH1
TH2 = SHA256( "pq-tunnel-v1" ‖ M1_s ‖ M2_z )                     server signs TH2
TH3 = SHA256( "pq-tunnel-v1" ‖ M1_z ‖ M2_z ‖ M3_z )
```

| Digest | Function | Source |
|---|---|---|
| `TH1` | `th1_from_m1` | ✅ `handshake_v2.rs:750-757` |
| `TH2` | `th2_from_m1_m2` | ✅ `handshake_v2.rs:759-769` |
| `TH3` | `th3_from_m1_m2_m3` | ✅ `handshake_v2.rs:771-778` |

**`M1_z`** = M1 with the client-signature slot zero-filled.
**`M1_s`** = M1 **with** the client signature — the server signs the real M1, not
the zeroed form ✅ `handshake_v2.rs:761-762`.
**`M2_z`** = M2 with the server-signature slot zero-filled.
**`M3_z`** = M3 with the Finished-MAC slot zero-filled.

**ML-DSA signs the 32-byte digest, never the raw transcript** ✅
`handshake_v2.rs:46-48`.

### 6.3 Full-coverage requirement ⚠️

> "Full coverage including the server ephemeral key and ct2 is mandatory;
> partial coverage is prohibited (it would allow re-framing a captured M2 under
> a valid signature)." — ⚠️ `DESIGN_DECISIONS.md:583-585`

**Normative and important.** A partial TH2 would be a real vulnerability. It
belongs in the specification as a MUST, with the attack it prevents.

### 6.4 Signing mode is a pinned profile choice ⚠️

**Deterministic** ML-DSA-65 (FIPS 204 Algorithm 2, `rnd = 0`) ✅
`DESIGN_DECISIONS.md:617-620`.

Rationale given ✅ `DESIGN_DECISIONS.md:621-631`:
- Not a metadata weakness: both signed digests bind a fresh CSPRNG `sid`, a fresh
  ML-KEM-768 ek and a fresh X25519 key, so no digest is ever signed twice.
- Hedged signing is **rejected**.
- Retransmission is guaranteed by **byte caching** (`m1_frags`, `m3_frags`,
  `m2_cache`), never by re-signing ✅ `DESIGN_DECISIONS.md:628-631`.

**Tests:** `ml_dsa_sign_is_deterministic` ✅ `pq-crypto/src/signature.rs:324`;
external Wycheproof vector ✅ `signature.rs:303`.

⚠️ **`[TO BE VERIFIED]`:** the byte-caching requirement ("Cached handshake bytes
MUST NOT be re-derived on retransmit", `DESIGN_DECISIONS.md:630-631`) is a
critical retransmission invariant. **Is there a test that a retransmitted
fragment is byte-identical to the original?** This package found no such test
named. See gap G-22.

---

## 7. Key confirmation (D15)

### 7.1 Finished key ✅

```
info       = "pq-tunnel-finished-v1" ‖ VERSION(1) ‖ SID(8)     (30 bytes)
finished_key = HKDF-SHA256(master, 00 × 32, info, L = 32)
```

✅ `pq-crypto/src/kdf.rs:191-210`.

Tests: `derive_finished_key_is_deterministic_and_bound` ✅ `kdf.rs:462-479`
(version and SID MUST change the key); `finished_key_is_label_separated_from_traffic_keys`
✅ `kdf.rs:481-492`.

### 7.2 Client→server Finished MAC ✅

```
client_finished = HMAC-SHA256(finished_key, TH3)[0..16]     (16 bytes on the wire)
```

✅ `pq-crypto/src/kdf.rs:212-227`; ⚠️ `DESIGN_DECISIONS.md:739-741`;
✅ `handshake_v2.rs:57`.

**The server MUST verify it before entering ESTABLISHED** ⚠️
`DESIGN_DECISIONS.md:742-744`. A forged or raced M3 is silently dropped **without
mutating session state** ✅ `handshake_v2.rs:71-73`.

### 7.3 Server→client confirmation is implicit ⚠️

The client confirms the server when the first AEAD packet decrypts successfully
⚠️ `DESIGN_DECISIONS.md:745-747`. The client MUST NOT deliver application data
before that, or MUST enforce a liveness timeout ✅ `session_manager.rs:118-122`
(`liveness_timeout`, default 30 s at `:144`).

### 7.4 HMAC cross-check is self-authored ⚠️

The only HMAC check is a hand-rolled RFC 2104 implementation in the same file
✅ `kdf.rs:497-537`. `pq-crypto/src/kat_vectors.rs` contains **no** RFC 2104
constants. See gap G-21.

---

## 8. Packet protection

### 8.1 AEAD call ✅

```
key    = c2s_key  (client→server)  or  s2c_key  (server→client)
nonce  = nonce_prefix_direction[4] ‖ packet_nonce.to_be_bytes()[8]
aad    = the 17-byte cleartext header, verbatim
ct||tag = ChaCha20-Poly1305(key, nonce, aad, inner_plaintext)   → 1247 ‖ 16
```

| Element | Source |
|---|---|
| `build_session_nonce` | ✅ `pq-crypto/src/kdf.rs:229-235` |
| AEAD nonce length 12 = 4 + 8 | ✅ `codec.rs:110`, compile-time assert `codec.rs:156-160` |
| AAD = header bytes | ✅ `codec.rs:514-516` |
| Exact plaintext length contract | ✅ `codec.rs:353-361` (`InnerPlaintext::new` rejects ≠ 1245) |

### 8.2 Nonce uniqueness — the central invariant ✅

⚠️ `CRYPTO_PROFILE.md:263-276` ("unique nonce usage" is mandatory);
✅ `pq-tunnel-core/src/envelope.rs:23-29` ("Nonce uniqueness & replay (the
central invariant)").

The argument has three parts:

1. **Per-direction prefix** — c2s and s2c use different 4-byte prefixes
   ✅ `kdf.rs:118-139`.
2. **Per-session prefix** — session_id is bound into the prefix derivation
   ✅ `kdf.rs:88-96`, tested `kdf.rs:330-343`. Two sessions sharing a master
   cannot overlap in nonce space.
3. **Monotonic counter with an exhaustion pre-empt** ✅ `codec.rs:112-128`:
   `MAX_PACKET_NONCE = u64::MAX − 2^32`; `is_counter_exhausted(counter)` fires at
   that point, and the session MUST be rotated, not wrapped
   ⚠️ `DESIGN_DECISIONS.md:781-787` (D16).

**Normative:** nonce reuse MUST be impossible under all conditions. A counter
wrap MUST close the session, never wrap. ✅ `[TO BE VERIFIED]` — the enforcement
point (envelope vs. session layer) is not confirmed by this package.

**An auditor's note:** the 4-byte prefix is 32 bits. With many concurrent
sessions sharing a master (which cannot currently happen — the master is
per-handshake), collision probability would be non-negligible at birthday scale.
Worth stating the operational bound explicitly.

### 8.3 Replay window

See [`wire-format.md`](wire-format.md) §8. ✅ `pq-tunnel-core/src/replay.rs:37,44-48`.
**Normative rules `[TO BE AUTHORED]`** — implemented, not written down.

---

## 9. Verification order

⚠️ `DESIGN_DECISIONS.md:589-590`; ✅ `handshake_v2.rs:60-61`:

> "Verification order on both sides: version/sid checks → decode → signature
> verify → KEM. **Never KEM before signature.**"

**Why it matters** ⚠️ `DESIGN_DECISIONS.md:526-527`:
> "cheap pre-crypto DoS gate: the client signature verifies before any KEM work"

**`[TO BE AUTHORED]` — and it is a gap, see G-09:** this is a
security-relevant ordering with **no test asserting it**. A refactor could invert
it silently.

---

## 10. Authentication model (D12)

| Property | Value | Source |
|---|---|---|
| Mode | **Mutual, mandatory.** No anonymous mode, no server-only mode. | ⚠️ `DESIGN_DECISIONS.md:499-501` |
| Auth mode derivation | **Never from any wire value.** Configuration-pinned on both endpoints. | ⚠️ `DESIGN_DECISIONS.md:502-504` |
| Client → server | ML-DSA-65 signature over `TH1` | ⚠️ `DESIGN_DECISIONS.md:499` |
| Server → client | ML-DSA-65 signature over `TH2` | ⚠️ `DESIGN_DECISIONS.md:499` |
| Trust anchoring | Out-of-band pinning. Client pins the server pk; server holds a client roster. | ⚠️ `DESIGN_DECISIONS.md:505-509` |
| Unknown key | **Fail closed.** TOFU rejected. | ⚠️ `DESIGN_DECISIONS.md:509-510` |
| Identity keys on the wire | **Never** — neither keys nor fingerprints | ⚠️ `DESIGN_DECISIONS.md:505-507` |
| Roster verification | Entire roster, **no early exit** (uniform verification count) | ✅ `handshake_v2.rs:75-76` |
| Missing/invalid client signature | Hard silent rejection, **no fallback** | ⚠️ `DESIGN_DECISIONS.md:503-504` |

**The downgrade rationale is the strongest argument in the D-record** ⚠️
`DESIGN_DECISIONS.md:491-497`:
> "Security review found that any optional or wire-negotiated client
> authentication is a downgrade vector: an active attacker strips the client
> signature and the server infers anonymous mode."

This belongs in the specification, not only in a decision record.

---

## 11. Randomness

| Use | Source | Failure behaviour |
|---|---|---|
| ML-KEM keygen / encaps | `ml-kem` `getrandom` feature ✅ `pq-crypto/Cargo.toml:11` | `[TO BE AUTHORED]` |
| ML-DSA keygen | `ml-dsa` `getrandom` ✅ `Cargo.toml:12` | `[TO BE AUTHORED]` |
| X25519 | `StaticSecret::random()` ✅ `classical.rs:24` | `[TO BE AUTHORED]` |
| `session_id` | CSPRNG, mandatory ⚠️ `DESIGN_DECISIONS.md:607-608` | reject on collision ⚠️ `:609` |

⚠️ `CRYPTO_PROFILE.md:384-390` requires: "Failure of required randomness sources
MUST result in secure failure." **[TO BE VERIFIED]** — is a `getrandom` failure
surfaced as an error at every call site, or could a fallback path exist?

---

## 12. Secret-material zeroization

| Material | Zeroized? | Source |
|---|---|---|
| `MasterSecret` | ✅ on `Drop` | `kdf.rs:67-70` |
| HKDF staging buffers (`okm`) | ✅ `kdf.rs:38` | `kdf.rs:37-39` |
| `ikm` / `info` (v2 master) | ✅ | `kdf.rs:185-186` |
| `InnerPlaintext.payload` | ✅ on `Drop` | `codec.rs:429-436` |
| `WirePacket` buffer | ✅ on `Drop` | `codec.rs:545-548` |
| `MlDsaSecretKey` / `AeadKey` | `[TO BE VERIFIED]` | — |
| Ephemeral KEM/X25519 secrets after derivation | ⚠️ required `DESIGN_DECISIONS.md:703-705` | `[TO BE VERIFIED]` |
| `derive_master_secret` (v1) `ikm` | ❌ **NOT** | `kdf.rs:73-80`, acknowledged `kdf.rs:156-161` |

**Also required:** a `Debug` redaction discipline — `InnerPlaintext` prints
`<redacted: N bytes>` ✅ `codec.rs:333-345`; `MasterSecret` prints
`[REDACTED]` ✅ `kdf.rs:55-58`; `WirePacket` redacts the counter ✅ `codec.rs:531-541`.
**This is good practice and should be stated as a requirement in the spec.**

---

## 13. External known-answer anchoring (D21)

⚠️ `DESIGN_DECISIONS.md:1186-1230`; ✅ `pq-crypto/src/kat_vectors.rs:1-32`.

### 13.1 What IS anchored ✅

| Constant | External source | Provenance comment |
|---|---|---|
| ChaCha20-Poly1305 | RFC 8439 §2.8.2 | `kat_vectors.rs:5-8` |
| HKDF-SHA256 | RFC 5869 §A.1 tc 1 | `kat_vectors.rs:9-10` |
| X25519 | RFC 7748 §6.1 | `kat_vectors.rs:11-13` |
| ML-KEM-768 keygen | Wycheproof `mlkem_768_test.json` tcId 1 (CCTV/strcmp) | `kat_vectors.rs:14-15` |
| ML-KEM-768 encaps | Wycheproof `mlkem_768_encaps_test.json` testGroups[1] tcId 14 (FIPS 203) | `kat_vectors.rs:16-18` |
| ML-DSA-65 verify | Wycheproof `mldsa_65_verify_test.json` grp0 tcId1 | `kat_vectors.rs:19-21` |
| ML-DSA-65 sign | Wycheproof `mldsa_65_sign_seed_test.json` grp0 tcId1 `.sig` | `kat_vectors.rs:22-25` |
| ML-DSA-65 keygen | same file, grp0 | `kat_vectors.rs:22-24` |

The `rnd`-absent reasoning for the signing vector ✅ `kat_vectors.rs:26-33` is
**excellent** — it is exactly the analysis an auditor would need to confirm the
signing vector is genuinely deterministic.

### 13.2 What is NOT anchored — **the gap (G-08)**

| Construction | §| External vector |
|---|---|---|
| `master = HKDF-SHA256(ssA‖ssB‖dh_cs, …)` | 4 | **NONE** |
| `TH1`, `TH2`, `TH3` | 6.2 | **NONE** |
| `finished_key` | 7.1 | **NONE** |
| `client_finished = HMAC(finished_key, TH3)[..16]` | 7.2 | **NONE** (and HMAC has no RFC 2104 vector) |
| `c2s_key`, `s2c_key` | 5.1–5.2 | **NONE** |
| `nonce_prefix_c2s`, `nonce_prefix_s2c` | 5.3–5.4 | **NONE** |
| `master_v1`, `init_key`, `init_nonce` | 5.5 | **NONE** |

⚠️ **The overstatement to fix:** `CRYPTO_PROFILE.md:429` says "Selection is
anchored to external known-answer vectors per D21". That is true of the
*primitives*. It is not true of the *construction*, and `CRYPTO_PROFILE.md`
never mentions the construction at all (`:24-31`).

### 13.3 Required remediation

For each unanchored construction, publish a
**published-input / expected-output** vector computed by an **independent**
implementation, with intermediate values where useful (e.g. the Extract output,
the PRK, the T-counter blocks).

**Suggested first vector — the master derivation.** It exercises the most
surface: concatenation order, salt, label, version, sid and transcript binding
in one value. Publish, for one fixed `(ssA, ssB, dh_cs, VERSION, SID, TH3)`, the
resulting 32-byte `master`, and ideally the `master` for two further cases that
differ in exactly one input each — demonstrating the §4.3 binding requirements
numerically.

---

## 14. Open questions for the author

Ordered by how much they matter.

1. **Is `x25519-dalek = "=3.0.0-rc.1"` acceptable in a cryptographic profile?**
   (§1.2) An RC is not a stable reviewed release; `CRYPTO_PROFILE.md:82-91`
   requires "publicly reviewed". What is the plan for the final release?
2. **Should the X25519 contributory rule (§4.1) be a decision record entry?**
   The working-tree change is correct and cites RFC 7748, but nothing records it
   and no test is named. See G-23.
3. **Is the legacy v1 key schedule live?** `derive_master_secret`
   (`kdf.rs:73-80`) does not zeroize its `ikm` and is still exported. Remove it
   or specify it. Same question for `derive_handshake_init_key` /
   `derive_handshake_init_nonce` (`kdf.rs:141-149`).
4. **What enforces `MAX_PACKET_NONCE`?** `codec.rs:112-118` declares the
   contract; which component enforces it?
5. **Is there a test that the verification order (signature before KEM) holds?**
   (§9) If not, this is a live gap.
6. **Is there a test that a retransmitted handshake fragment is byte-identical
   to the original?** (§6.4) The cached-bytes rule is security-relevant.
7. **Why is the HKDF salt 32 zero bytes for the traffic-key derivations, and not
   just the Finished key?** (§2.1) The existing justification covers one
   derivation.
8. **How does `getrandom` failure propagate?** (§11)
9. **Should the replay-window accept/reject rules be written down as normative
   statements?** (`wire-format.md` §8)
10. **What is the operational bound on concurrent sessions per master?** (§8.2) —
    not currently constrained, since the master is per-handshake, but stating it
    would close the question for future designs.
11. **Will `CRYPTO_PROFILE.md` §14 be narrowed** to say that anchoring covers the
    primitives, with the construction anchored separately (§13.2)?