# Wire Format Specification — SKELETON

> **THIS IS A SKELETON, NOT A SPECIFICATION.**
> It is a template prepared by a documentation pass. It is **not** a normative
> specification, it has **not** been reviewed by anyone outside the Tunnel
> project, and it is **not** a conformance document. It exists so that a
> normative specification can be written without re-deriving the format from
> source.
>
> **How to read the markers:**
>
> | Marker | Meaning |
> |---|---|
> | ✅ | Filled in from source, with the exact `file:line`. Verify before use. |
> | ⚠️ | Filled in from a *decision record*, not from code. Verify against code. |
> | 🔶 | Filled in by **inference** from the code. **Not** stated anywhere. Confirm. |
> | `[TO BE AUTHORED]` | The source of truth does not exist. Someone must decide and write it. |
> | `[TO BE VERIFIED]` | Something is stated; whether the code matches is unconfirmed. |
>
> **Source of truth for everything below:**
> `pq-tunnel-core/src/codec.rs` (data plane) and
> `pq-tunnel-core/src/handshake_v2.rs` (handshake plane).
>
> **Fill-in rule:** when this document and the code disagree, the code is right
> today, but the code will change and this document will not unless it is
> version-controlled and changed deliberately.

---

## 0. Document control

| Field | Value |
|---|---|
| Protocol version | **2** ✅ (`codec.rs:81` → `PROTOCOL_VERSION: u8 = 2`) |
| Wire version history | `[TO BE AUTHORED]` — what was version 0, and does version 0 exist on the wire? |
| Version-negotiation rule | Strict equality; no negotiation ✅ (`codec.rs:296-301`) |
| Change policy | "Bumping this constant signals an incompatible wire-format change" ✅ (`codec.rs:80`) — but the *process* is `[TO BE AUTHORED]` |
| Known incompatible predecessors | Pre-v2 QUIC framing, 8192 bytes, own MsgType set ✅ (`DESIGN_DECISIONS.md:996-1003`) — removed in D20 |
| Stability | **Not stable before 1.0** ✅ (`README.md:90`, `CHANGELOG.md:29-30`) |

---

## 1. Scope and layer

Tunnel's on-wire record is a single fixed-size datagram, used for **both** the
data plane and the handshake plane. §4 (data plane) and §5 (handshake plane) are
two readings of the same 1280 bytes.

```
+----------------------------------------------------------------+
|  Layer 3: UDP datagram = exactly 1280 bytes, always             |
+----------------------------------------------------------------+
|  Layer 2 (this document): Tunnel datagram layout                |
+----------------------------------------------------------------+
|  Layer 1: application payload (opaque; §6, §7)                  |
+----------------------------------------------------------------+
```

**Normative statement needed:** Tunnel operates over UDP. Is any other transport
permitted? `[TO BE AUTHORED]` — `PROTOCOL_SPEC.md §7.5` (`:360-366`) says the
transport layer "provides packet delivery" and should avoid MTU assumptions, but
does not fix the transport. D13 (`:592`) rejects 8192-byte handshake datagrams.

---

## 2. Datagram size

| Property | Value | Source |
|---|---|---|
| Total datagram size | **1280 bytes, exactly** | ✅ `codec.rs:103` → `PACKET_SIZE: usize = 1280` |
| Only size permitted on the wire | 1280 | ✅ `codec.rs:464-469` — `from_bytes` rejects any other length |
| Rationale | Fits IPv4 (1500) and IPv6 (1280) MTUs without jumbo frames | ✅ `codec.rs:95-99` |
| Is the size a confidentiality parameter? | No — it is uniform, so it reveals nothing about content | ✅ `codec.rs:446-448`, `PROTOCOL_SPEC.md §12` |
| 8192-byte datagrams | Rejected | ⚠️ `DESIGN_DECISIONS.md:600-603` |

**Normative:** a receiver MUST discard any datagram whose length ≠ 1280.
✅ Implemented at `codec.rs:464-469`; exercised by
`e2e_adversarial.rs:105` (`e2e_adversarial_garbage_and_wrong_lengths_dropped`).

**Open question:** what happens to a datagram larger than the receive buffer?
`[TO BE AUTHORED]` — a UDP datagram larger than the buffer is truncated by the
OS before the application sees it; whether that truncation is distinguishable, and
whether Tunnel cares, is unstated.

---

## 3. Region partition

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| V |      Session ID (8)         |      Packet Nonce (8, BE)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                AEAD ciphertext (1247 bytes)                   ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    AEAD tag (16 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                 <- 1280
```

| Region | Offset | Length | Source |
|---|---|---|---|
| Header (cleartext, = AEAD AAD) | 0 | **17** | ✅ `codec.rs:132` → `HEADER_LEN = 1 + 8 + 8` |
| AEAD ciphertext | 17 | **1247** | ✅ `codec.rs:134-135` → `INNER_PLAINTEXT_LEN = 1280 - 17 - 16` |
| AEAD tag | 1264 | **16** | ✅ `codec.rs:108` → `AEAD_TAG_LEN = 16` |

### 3.1 Partition invariant

The layout MUST partition 1280 exactly. ✅ Enforced at compile time by
`codec.rs:143-152`:

```rust
const _: () = assert!(
    HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN == PACKET_SIZE, …);
```

**This is exemplary practice and should be called out as such in the final
spec.**

### 3.2 Cross-component invariant

The cleartext counter width MUST equal the KDF nonce construction's counter
width minus the 4-byte prefix. ✅ Enforced at `codec.rs:156-160`:

```rust
const _: () = assert!(
    AEAD_NONCE_LEN == PACKET_NONCE_LEN + 4,
    "AEAD nonce must equal 4-byte session prefix + 8-byte packet counter");
```

The comment calls this "a silent nonce-misuse hazard" — correct, and the guard is
the right response. **Note:** this couples `codec.rs` to `kdf.rs` via a magic
`4`. The final spec must state the 4.

---

## 4. Header fields (data plane)

### 4.1 `version` — offset 0, 1 byte

| Property | Value |
|---|---|
| Encoding | unsigned integer |
| Required value | **1** |
| Cleartext? | Yes — part of the AEAD AAD |
| Rejection rule | MUST reject if ≠ 1 ✅ (`codec.rs:296-301`) |
| Source | ✅ `codec.rs:81`, `:295-301` |
| Rationale | Downgrade detection must happen before any cryptographic work ✅ `codec.rs:77-79` |

**Normative:** the version byte MUST be checked before any key lookup,
decryption, or state mutation.

### 4.2 `session_id` — offset 1, 8 bytes

| Property | Value |
|---|---|
| Encoding | opaque 8 bytes ✅ (`codec.rs:274-276`) |
| Chosen by | the client, CSPRNG, never reused ✅ ⚠️ `DESIGN_DECISIONS.md:607-610` |
| Secret? | **No.** `PROTOCOL_SPEC.md:150-154` — "not an identity … not authentication material … must not be treated as a secret credential" ✅ |
| Bound to source address? | **No** — `PROTOCOL_SPEC.md:466-470`; roaming re-binds ✅ |
| Authenticated? | Yes — it is AAD |
| Source | ✅ `codec.rs:105`, `:275-276` |

**Entropy requirement:** `[TO BE AUTHORED]` — "8 bytes, CSPRNG-mandatory" is
stated in `DESIGN_DECISIONS.md:607-608`, but the minimum entropy, the collision
policy on the server, and the collision *rate* are not specified numerically.

### 4.3 `packet_nonce` — offset 9, 8 bytes

| Property | Value |
|---|---|
| Encoding | **big-endian** u64 ✅ (`codec.rs:277`, `:306-309`) |
| Meaning | per-direction monotonic sequence counter |
| Cleartext? | Yes — the receiver needs it to reconstruct the AEAD nonce without decrypting ✅ `codec.rs:43-49` |
| Source | ✅ `codec.rs:105-107`, `:277` |

**Related but not on the wire:** the AEAD nonce is
`nonce_prefix[4] ‖ packet_nonce.to_be_bytes()[8]` — see §6.3.

---

## 5. Handshake plane framing

Handshake datagrams use the **same 1280-byte datagram** with a different field
layout in bytes 9–11.

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| V |      Session ID (8)         | hs_type | frag | total |    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~                body (≤ 1268 bytes)                            ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~                zero padding to 1280                           ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Offset | Length | Source |
|---|---|---|---|
| `version` | 0 | 1 | ✅ `handshake_v2.rs:120` |
| `session_id` | 1 | 8 | ✅ `handshake_v2.rs:120` |
| `hs_type` | 9 | 1 | ✅ `handshake_v2.rs:120` (`HS_FRAG_HEADER_LEN = 1 + 8 + 3`) |
| `frag_idx` | 10 | 1 | ✅ `handshake_v2.rs:120` |
| `frag_total` | 11 | 1 | ✅ `handshake_v2.rs:120` |
| body | 12 | ≤ **1268** | ✅ `handshake_v2.rs:122` → `HS_FRAG_BODY_MAX = 1280 - 12` |
| padding | — | remainder | 🔶 zero-filled to 1280 (`handshake_v2.rs:396-398` writes body then leaves the rest) |

### 5.1 `hs_type` values

| Value | Message | Source |
|---|---|---|
| `0x10` | ClientHello (M1) | ✅ `handshake_v2.rs:113` |
| `0x20` | ServerHello (M2) | ✅ `handshake_v2.rs:115` |
| `0x30` | ClientConfirm (M3) | ✅ `handshake_v2.rs:117` |
| any other | data plane | ✅ `handshake_v2.rs:26-28` |

**Byte-disjointness from the data-plane `MessageType` (0x00–0x03)** is enforced
at compile time ✅ (`handshake_v2.rs:174-177`).

### 5.2 Dispatch rule

**Byte 9 of every datagram selects the plane.** ✅ `handshake_v2.rs:26-28`, `:280-283`

> `0x10` / `0x20` / `0x30` → handshake fragment; anything else → data plane.

**The collision caveat, which a specification MUST state** ✅
`handshake_v2.rs:30-34`: in the data plane, byte 9 is the most-significant byte
of the packet nonce. It could only take a handshake value after 2^60 packets in
one direction (≈35,000 years at 1 Gbps). If it ever did, the fragment path
would still reject it, because `frag_total` is pinned per `hs_type`
(`handshake_v2.rs:262-265`).

`[TO BE AUTHORED]` — a second implementer needs this stated as a normative
guarantee, including the argument. It is currently a comment.

### 5.3 Message bodies

| Message | Body length | Fragments | Source |
|---|---|---|---|
| M1 ClientHello | **4534** | **4** | ✅ `handshake_v2.rs:130-134,147,171-173` |
| M2 ServerHello | **5622** | **5** | ✅ `handshake_v2.rs:136-141,149,171-173` |
| M3 ClientConfirm | **1113** | **1** | ✅ `handshake_v2.rs:143-144,151,171-173` |

Body layouts ✅ `handshake_v2.rs:9-17`, `DESIGN_DECISIONS.md:556-559`:

```
M1: VERSION(1) ‖ SID(8) ‖ eph_pk_c(1184) ‖ x_c(32) ‖ client_sig(3309)   = 4534
M2: VERSION(1) ‖ SID(8) ‖ eph_pk_s(1184) ‖ x_s(32) ‖ ct2(1088) ‖ server_sig(3309) = 5622
M3: VERSION(1) ‖ SID(8) ‖ ct3(1088) ‖ client_finished(16)                = 1113
```

**Component sizes:** `eph_pk_*` = ML-KEM-768 encapsulation key = 1184 ✅
(`handshake_v2.rs:131`); `x_*` = X25519 public = 32 ✅ (`handshake_v2.rs:125`);
`ct*` = ML-KEM-768 ciphertext = 1088 ✅ (`handshake_v2.rs:139,144`);
`*_sig` = ML-DSA-65 signature = 3309 ✅ (`handshake_v2.rs:727`);
`client_finished` = 16 ✅ (`handshake_v2.rs:127`).

**Total handshake wire cost: 10 datagrams = 12,800 bytes** ⚠️
`DESIGN_DECISIONS.md:660`. Utilisation ≈87% ⚠️ `DESIGN_DECISIONS.md:600`.

Fragment-count pinning is compile-time asserted ✅ (`handshake_v2.rs:156-173`).

### 5.4 Reassembly

- `frag_idx` MUST be `< frag_total`, and `frag_total` MUST equal the pinned count
  for the `hs_type` ✅ (`handshake_v2.rs:262-265`).
- Fragment bodies MUST appear in index order; body slice for fragment *i* is
  `message[i*1268 .. min(len, (i+1)*1268)]` ✅ (`handshake_v2.rs:394-396`).
- `[TO BE AUTHORED]` — the reassembly algorithm's tolerance for out-of-order or
  duplicated fragments. The implementation collects `received: [bool; N]`
  (`handshake_v2.rs:423,436`), implying order-independence, but the **rule** is
  not stated.

---

## 6. Data-plane inner plaintext (encrypted)

Everything below is inside the AEAD region and is **never** visible on the wire.

### 6.1 Layout

```
offset 0      : msg_type (1)
offset 1      : direction (1)
offset 2..1247: payload (1245)
```

| Field | Length | Source |
|---|---|---|
| `msg_type` | 1 | ✅ `codec.rs:373-379` |
| `direction` | 1 | ✅ `codec.rs:374-376` |
| `payload` | **1245** | ✅ `codec.rs:139` → `PAYLOAD_LEN = 1247 - 2` |

### 6.2 Enumerations

`msg_type` ✅ `codec.rs:184-209`:

| Value | Name |
|---|---|
| `0x00` | Handshake |
| `0x01` | Data |
| `0x02` | Cover |
| `0x03` | Close |
| other | **MUST reject** ✅ `codec.rs:204-208` |

`direction` ✅ `codec.rs:226-238`: `0x00` ClientToServer, `0x01` ServerToClient,
other **MUST reject**.

**Forward compatibility policy:** rejecting unknown enum values means a future
version cannot add a message type without bumping `PROTOCOL_VERSION`
✅ `codec.rs:179-182`. `[TO BE AUTHORED]` — is that the intended long-term
policy, or should a reserved range be defined? The current answer (strict) is
safe but is a protocol-freeze decision that is not stated as one.

### 6.3 Why direction is encrypted

✅ `codec.rs:216-224`: direction is carried **inside** the ciphertext so a
passive observer cannot tell which way a packet is travelling
(`PROTOCOL_SPEC.md §12`). The field is retained in the cleartext-free form so
the receiver can check the packet matches its expected role — an integrity check
that costs nothing observable.

---

## 7. AEAD binding

| Property | Value | Source |
|---|---|---|
| Algorithm | ChaCha20-Poly1305 | ✅ `CRYPTO_PROFILE.md:435` |
| Key length | 32 | ✅ `pq-crypto/src/lib.rs:24` (`AEAD_KEY_BYTES`) |
| Nonce length | **12** | ✅ `codec.rs:110`, `pq-crypto/src/lib.rs:24` |
| Tag length | **16** | ✅ `codec.rs:108` |
| **Associated data** | the **17-byte cleartext header**, verbatim | ✅ `codec.rs:514-516` (`aad() = header_bytes()`) |
| Nonce construction | `nonce_prefix[4] ‖ packet_nonce.to_be_bytes()[8]` | ✅ `pq-crypto/src/kdf.rs:229-235` |
| Nonce prefix source | per-direction, per-session, HKDF-derived, secret | ✅ `pq-crypto/src/kdf.rs:118-139` |

**Normative:** any change to a header byte MUST cause AEAD decryption to fail.
✅ Tested: `tamper_session_id_aad_rejected`,
`tamper_packet_counter_rejected`, `version_byte_is_aad_covered` (named at
`checkpoints/SECURITY_RELEASE_AUDIT.md:33`; **INTERNAL-ONLY** — this package did
not locate them by name; see gap G-22).

---

## 8. Replay protection

| Property | Value | Source |
|---|---|---|
| Window width | **1024 bits** | ✅ `pq-tunnel-core/src/replay.rs:37` |
| Storage | 16 × u64 bitmap | ✅ `replay.rs:39` |
| Bit mapping | bit *i* ↔ counter `highest - i - 1` | ✅ `replay.rs:44-48` |
| Too-old packets | rejected without a bitmap lookup | ✅ `replay.rs:46-49` |
| Counter-exhaustion trigger | `MAX_PACKET_NONCE = u64::MAX − 2^32` | ✅ `codec.rs:121` |
| Is the trigger enforced? | at the envelope/session layer | `[TO BE VERIFIED]` |

**Normative rules** `[TO BE AUTHORED]` — the code implements them but they are
not written as rules:
1. A counter ≤ `highest − 1024` MUST be rejected.
2. A counter already marked in the bitmap MUST be rejected.
3. A counter > `highest` MUST be accepted and advance `highest`, shifting the
   bitmap.
4. A counter in `(highest−1024, highest]` not yet marked MUST be accepted.

**Rationale worth preserving:** 1024 bits is "the same width as WireGuard's
replay window" ✅ (`replay.rs:16-18`), covering ~1 second of traffic at the
default cover rate.

---

## 9. What is NOT in this specification

Deliberately, because they are application layer and never on the wire:

| Format | Where it lives | On the wire? |
|---|---|---|
| Relay overlay `family(1)‖addr(4\|16)‖port(2)‖len(2)‖datagram` | `pq-tunnel-bin/src/relay.rs:7-13` | **No** — inside the encrypted 1245-byte payload |
| `.pqti` identity/provisioning files | `DESIGN_DECISIONS.md:820-826` | **No** — out of band |
| Rosters | same | **No** — out of band |
| Any identity key or fingerprint | `DESIGN_DECISIONS.md:505-507` | **Never** |

**This is a security property, not an implementation detail:** the relay
destination header is invisible to an observer because it is inside the AEAD.
✅ `DESIGN_DECISIONS.md:911`.

---

## 10. Interoperability checklist (for a second implementer)

`[TO BE AUTHORED]` — nothing in the project currently exists for this.

- [ ] Datagram is exactly 1280 bytes.
- [ ] Bytes 0–16 are the AAD, byte-for-byte.
- [ ] Byte 0 must be `0x01`.
- [ ] Bytes 9–16 are a big-endian u64.
- [ ] Byte 9 dispatches the plane (0x10/0x20/0x30 = handshake).
- [ ] ChaCha20-Poly1305, 32-byte key, 12-byte nonce, 16-byte tag.
- [ ] Nonce = secret 4-byte prefix ‖ big-endian counter.
- [ ] Replay window is 1024 bits with the stated bit mapping.
- [ ] Unknown enum values are rejected, not ignored.
- [ ] Wrong-length datagrams are discarded, not parsed.
- [ ] `frag_total` must equal the pinned count for the `hs_type`.
- [ ] **Not yet specifiable:** the key schedule. See
      [`crypto-construction.md`](crypto-construction.md).

---

## 11. Open questions for the author

1. **Is `version = 2` currently the only version ever emitted?** If a v1
   existed on the wire, the downgrade story needs a sentence.
2. **Should `frag_total` be pinned per `hs_type`, or is a version-2
   renegotiation planned?** Currently pinned (`handshake_v2.rs:262-265`).
3. **What is the intended policy for adding a new `msg_type`?** Strict rejection
   means a version bump; is that accepted?
4. **Who enforces `MAX_PACKET_NONCE`?** The codec declares the contract
   (`codec.rs:112-118`); the envelope/session layer must enforce it. Confirm
   where.
5. **Is UDP the only permitted transport?** `PROTOCOL_SPEC.md §7.5` does not
   say.
6. **What is a receiver required to do with an oversized datagram** (larger than
   its buffer)? Truncation may be observable.
7. **Should the padding in §5 be specified as zero?** The code leaves it
   zero-initialised (`handshake_v2.rs:396-398`) but does not reject non-zero
   padding — is that deliberate?