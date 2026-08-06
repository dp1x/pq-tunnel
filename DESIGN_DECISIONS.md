# Tunnel Design Decisions

## Status

Draft — Design Decision Record

## Purpose

This document records the major design decisions behind the Tunnel protocol.

It answers:

> Why was this design direction chosen?

This document does not define:

- protocol requirements
- exact wire formats
- cryptographic algorithms
- implementation details

Those belong in:

- `PROTOCOL_SPEC.md`
- `CRYPTO_PROFILE.md`
- `IMPLEMENTATION_GUIDE.md`

---

# Decision Status

Each decision has one of the following states:

- **Accepted** — Design direction is decided.
- **Proposed** — Direction is under consideration.
- **Deferred** — Intentionally postponed.

---

# D1 — Cryptographic Key Establishment Model

## Status

Accepted

## Context

Tunnel requires protection against future cryptographic threats, including harvest-now-decrypt-later attacks.

The protocol requires a key establishment mechanism capable of providing:

- forward secrecy
- resistance against future cryptographic advances
- cryptographic agility

## Decision

Tunnel requires PQ-capable key establishment.

The exact construction, including:

- hybrid composition,
- selected algorithms,
- negotiation mechanism,

is defined separately in `CRYPTO_PROFILE.md`.

Tunnel separates:

- security requirements
- protocol structure
- cryptographic selection

## Consequences

**Advantages:**

- allows cryptographic evolution
- avoids premature algorithm lock-in
- preserves long-term protocol design

**Tradeoffs:**

- increased abstraction complexity
- more design decisions required later

**v1 Profile (2026-08):**

The v1 handshake profile uses hybrid key establishment — ML-KEM-768
(post-quantum leg) combined with X25519 (classical leg), both ephemeral —
with an HKDF concatenation combiner (XOR combination is explicitly banned).
X25519 is retained as the classical leg of the hybrid; it remains deprecated
as a *sole* mechanism and must never be used alone. See D13.

---

# D2 — Forward Secrecy Requirement

## Status

Accepted

## Context

Long-term key compromise should not automatically expose historical communication.

## Decision

Tunnel requires forward secrecy.

Session protection must rely on short-lived cryptographic material so that compromise of long-term identity material does not reveal previously completed sessions.

## Consequences

**Advantages:**

- limits damage from key compromise
- protects historical traffic

**Tradeoffs:**

- requires additional key management complexity

---

# D3 — Identity and Authentication Separation

## Status

Accepted

## Context

A networking identifier should not become an authentication mechanism.

Binding identity directly to network-level identifiers creates problems with:

- NAT
- roaming
- changing network paths

## Decision

Tunnel separates:

- identity
- authentication
- session identification

A connection identifier is not an identity credential.

A connection identifier does not prove peer authenticity.

## Consequences

**Advantages:**

- supports mobility
- reduces coupling between identity and transport

**Tradeoffs:**

- requires explicit identity mechanisms

---

# D4 — Connection Identification Model

## Status

Accepted

## Context

Traditional network identifiers such as IP addresses are unsuitable as permanent session identifiers.

They may change due to:

- NAT
- mobility
- network changes

## Decision

Tunnel uses connection identifiers to associate packets with active sessions.

Connection identifiers:

- identify sessions
- do not identify users
- do not authenticate peers
- are not secret credentials

## Consequences

**Advantages:**

- supports roaming
- supports changing network paths

**Tradeoffs:**

- connection identifiers must be managed carefully to avoid unnecessary metadata leakage

---

# D5 — Metadata Resistance as a Core Security Goal

## Status

Accepted

## Context

Traditional encrypted tunnels primarily protect payload contents.

Encrypted traffic can still reveal:

- timing patterns
- packet sizes
- communication frequency
- traffic behaviour

## Decision

Metadata resistance is a core Tunnel objective.

Tunnel treats communication patterns as a security concern.

The protocol must consider:

- traffic shaping
- padding
- cover traffic mechanisms

## Consequences

**Advantages:**

- stronger privacy guarantees

**Tradeoffs:**

- increased bandwidth and computational cost

---

# D6 — Traffic Shaping Philosophy

## Status

Accepted

## Context

Metadata protection requires controlling observable traffic behaviour.

Automatic optimization may accidentally reduce privacy.

## Decision

The default Tunnel operating mode prioritizes predictable privacy behaviour.

The default design direction is:

- fixed traffic behaviour
- explicit cover traffic support

Adaptive scheduling may exist only as an explicit configuration choice.

Adaptive behaviour must not silently reduce metadata protection.

## Consequences

**Advantages:**

- predictable privacy properties
- easier security analysis

**Tradeoffs:**

- reduced efficiency compared to unconstrained traffic

---

# D7 — Parameters Are Not Security Guarantees

## Status

Accepted

## Context

Configurable parameters affect tradeoffs but should not redefine the security model.

Examples:

- packet size
- traffic rate
- scheduling behaviour

## Decision

Configuration parameters control tradeoffs.

They do not redefine core security guarantees.

Any reduction in security or privacy must be:

- intentional
- visible
- documented
- reversible

## Consequences

**Advantages:**

- prevents hidden insecurity
- improves user understanding

**Tradeoffs:**

- requires clearer configuration design

---

# D8 — Conservative Cryptographic Design

## Status

Accepted

## Context

Cryptographic systems require public analysis and long-term confidence.

## Decision

Tunnel uses:

- publicly reviewed cryptography
- established primitives
- transparent security mechanisms

Tunnel must not:

- invent cryptographic primitives
- rely on secret algorithms
- hide security-critical behaviour

## Consequences

**Advantages:**

- easier review
- stronger trust model

**Tradeoffs:**

- fewer opportunities for custom optimization

---

# D9 — Secure Defaults and Explicit Tradeoffs

## Status

Accepted

## Context

Systems often weaken security silently for convenience.

Tunnel must avoid hidden compromises.

## Decision

Tunnel defaults must represent the intended security model.

Security reductions must be:

- explicit
- visible
- documented
- reversible

Tunnel must not silently:

- downgrade cryptography
- disable protections
- reduce metadata resistance

## Consequences

**Advantages:**

- predictable security behaviour

**Tradeoffs:**

- less automatic optimization

---

# D10 — Fail-Secure Behaviour

## Status

Accepted

## Context

Security failures must not result in insecure operation.

## Decision

Tunnel fails securely.

Examples:

```text
Authentication failure:
  Reject communication

Cryptographic failure:
  Terminate session

Invalid protocol state:
  Reject operation
```

Tunnel must prefer failure over insecure continuation.

## Consequences

**Advantages:**

- prevents accidental security bypass

**Tradeoffs:**

- may reduce availability during errors

---

# D11 — Cryptographic Agility

## Status

Accepted

## Context

Cryptographic algorithms may eventually become deprecated or replaced.

A long-lived protocol must allow evolution.

## Decision

Tunnel separates protocol requirements from cryptographic profiles.

Cryptographic components should be replaceable without invalidating the overall protocol architecture.

## Consequences

**Advantages:**

- easier migration
- longer protocol lifetime
- resistance to algorithm retirement

**Tradeoffs:**

- increased abstraction complexity

---

# D12 — Authentication Model

## Status

Accepted

## Context

PROTOCOL_SPEC §9 requires authenticated establishment, and §5.2 requires
authorizing participation (rejecting peers the server cannot verify). D3
separates identity, authentication, and session identification. The
metadata-resistance goal (D5) requires that identity material not be
observable on the wire. Security review found that any optional or
wire-negotiated client authentication is a downgrade vector: an active
attacker strips the client signature and the server infers anonymous mode.

## Decision

v1 requires mandatory mutual authentication. Each peer proves possession of
a static, unique ML-DSA-65 identity key by signing the canonical handshake
transcript (client signs TH1, server signs TH2, D13).

- One profile, no modes: there is no anonymous or server-only mode in v1,
  and the auth mode is never derived from any wire value. Auth policy is
  configuration-pinned on both endpoints. Under mutual policy, a missing or
  invalid client signature is a hard, silent rejection with no fallback.
- Identity keys are pinned out-of-band: the client pins the server's public
  key; the server pins a roster of client public keys. Identity public keys
  and fingerprints never appear on the wire. The server verifies the client
  signature against its pinned roster.
- Identity keys are signature-only: they never enter the key schedule
  (CRYPTO_PROFILE §3).
- Trust anchoring is deployment provisioning. TOFU (trust on first use) is
  rejected: an unknown key fails closed (§5.7).
- X.509/PKI and PSK-primary are rejected for v1: PKI adds parser attack
  surface and leaks identity certificates on the wire; a PSK is a group
  secret with no peer distinction (D3).

## Consequences

**Advantages:**

- no downgrade or mode-confusion vector (§15)
- no identity material on the wire (metadata posture, D5)
- simple WireGuard-style deployment; fail-closed by default
- cheap pre-crypto DoS gate: the client signature verifies before any KEM
  work

**Tradeoffs:**

- every endpoint must be provisioned with peer identity keys out-of-band
- server verifies against the roster (one verify per roster key)
- no anonymous access to a v1 server

---

# D13 — Handshake Construction

## Status

Accepted

## Context

PROTOCOL_SPEC §9 requires authenticated establishment, forward secrecy,
HNDL resistance, and parameter agreement. With a pure KEM, both ciphertexts
must cross the wire, and a ciphertext can be produced only after its target
ephemeral key is on the wire: mutual ephemeral agreement therefore requires
at least three messages. A 2-message flow necessarily targets a static KEM
key (violating §5.4 forward secrecy) or uses classical DH alone (violating
§5.5). Handshake datagrams must not be distinguishable from data packets
(§12, D5): the codec's uniform 1280-byte packet is the only on-wire size.

## Decision

A 3-message client-initiated flow over uniform 1280-byte datagrams.

### Message layouts (canonical, fixed-size fields)

- `M1 ClientHello`: `VERSION(1) ‖ SID(8) ‖ eph_pk_c(1184) ‖ x_c(32) ‖ client_sig(3309)`
- `M2 ServerHello`: `VERSION(1) ‖ SID(8) ‖ eph_pk_s(1184) ‖ x_s(32) ‖ ct2(1088) ‖ server_sig(3309)`
- `M3 ClientConfirm`: `VERSION(1) ‖ SID(8) ‖ ct3(1088) ‖ client_finished(16)`

### Key establishment (hybrid, all legs ephemeral)

- ML-KEM-768 both directions, plus X25519 both directions (D1 v1 profile).
- `master = HKDF-SHA256(ikm = ssA ‖ ssB ‖ dh_cs, salt = [0;32],
  info = "pq-tunnel-master-v2" ‖ VERSION ‖ SID ‖ TH3)`.
- `ssA` = share from ct2 (server encapsulates to client ephemeral; client
  decapsulates); `ssB` = share from ct3 (client encapsulates to server
  ephemeral; server decapsulates); `dh_cs` = X25519 shared secret.
- Concatenation order is pinned (`ssA ‖ ssB ‖ dh_cs` on both sides); XOR
  combination is banned (legacy HybridIdentity bug).
- The handshake survives compromise of either family: ML-KEM protects
  against CRQC; X25519 protects against a classical break of the lattice
  family.

### Transcript and signatures

- One canonical transcript: fixed-order, fixed-size fields, padding
  excluded, signature slots zero-filled, domain string `"pq-tunnel-v1"`
  prepended. Fragment headers are transport artifacts and are not hashed.
- `TH1 = SHA256(canon M1)` — signed by the client.
- `TH2 = SHA256(canon M1-with-sig ‖ canon M2)` — signed by the server. Full
  coverage including the server ephemeral key and ct2 is mandatory;
  partial coverage is prohibited (it would allow re-framing a captured M2
  under a valid signature).
- `TH3 = SHA256(canon M1 ‖ canon M2 ‖ canon M3-without-MAC)` — bound into
  the master derivation and the Finished MAC.
- Verification order on both sides: version/sid checks → decode → signature
  verify → KEM. Never KEM before signature.

### Framing

- Handshake messages fragment over uniform 1280-byte datagrams:
  `VERSION(1) ‖ SID(8) ‖ hs_type(1) ‖ frag_idx(1) ‖ frag_total(1) ‖ body(≤1268) ‖ padding → 1280B`.
- `hs_type`: `0x10` ClientHello, `0x20` ServerHello, `0x30` ClientConfirm —
  byte-disjoint from codec `MessageType` (0x00–0x03) and legacy
  `handshake::MsgType` (0x01–0x03).
- The first 9 bytes match the data-path header layout (uniform sid routing,
  version pre-filter). Fragment counts: M1 = 4, M2 = 5, M3 = 1 (10
  datagrams, ≈87% utilization). 8192-byte handshake datagrams are rejected
  (§7.5 MTU independence, §12 size uniformity).

### Versioning, sid, failure behaviour

- The version byte is the full profile selector: strict equality both
  directions, no negotiation, mismatch → silent drop. Version, SID, and all
  key material are inside every digest and the master `info` (§15, D11).
- `sid`: client-chosen, 8 bytes, CSPRNG-mandatory; the server echoes it and
  the client verifies the echo before crypto; collision → reject newcomer;
  never reused; one session per sid (D4).
- Every failure path is a silent drop or `Handshake → Closed`; no error
  datagrams (no oracle, no amplification); no fallback (§5.7, D10).
- Retransmission is client-driven: M1 and M3 retransmitted byte-identical
  with jittered backoff and bounded budgets; the server caches M2 per sid
  (duplicate M1 → resend cached M2).
- DoS posture (D7 defaults): per-source M1 rate limit; bounded pending-state
  table with TTL; no session state before verified client signature; no
  ESTABLISHED before verified M3 Finished MAC.

## Consequences

**Advantages:**

- satisfies §9 authenticated establishment, §5.4 forward secrecy, and §5.5
  HNDL resistance (dual-ephemeral hybrid)
- uniform 1280-byte framing preserves the §12 metadata posture
- no negotiation surface → no downgrade path

**Tradeoffs:**

- +0.5 RTT time-to-first-data on each side vs a (rejected) 2-message scheme
- ~2.5 ms handshake CPU per side (ML-DSA sign dominates)
- 12,800 bytes wire per session over 10 datagrams; fragment reassembly
  state on the server

---

# D14 — Key Hierarchy

## Status

Accepted

## Context

CRYPTO_PROFILE §9 (key separation) and §10 (key hierarchy) require a
one-way, domain-separated derivation chain. Review found the legacy XOR
combiner lacked key separation, and a retained master would break forward
secrecy across rekeys.

## Decision

```text
Identity Keys (ML-DSA-65 statics, signature-only)
    |
    v  (identity keys never enter key agreement)
Handshake Secrets (ssA, ssB, dh_cs — ephemeral, zeroized after derivation)
    |
    v
Master (HKDF per D13; lifetime = session lifetime; zeroized at close)
    |
    v
Session Keys (traffic keys + nonce prefixes, kdf -v2 labels,
              session_id-bound: keys and nonce prefixes)
    |
    v
Traffic Keys
```

- The master is derived only from ephemeral handshake secrets (D13) and is
  bound to the transcript and session_id.
- Session keys and nonce prefixes bind session_id (kdf labels `-v2`), so
  unique session protection keys hold even if two sessions share a master
  (§10).
- The master never outlives the session and is never retained for rekey;
  rekey requires a fresh handshake with fresh ephemerals (D16).
- Zeroization (CRYPTO_PROFILE §12, IMPLEMENTATION_GUIDE §6): ephemeral
  KEM/X25519 secret keys after decapsulation/derivation; ssA/ssB/dh_cs after
  master derivation; master at session close. Only the zeroizing KDF path
  (`kdf_derive_to_bytes`) is used for secret material.

## Consequences

**Advantages:**

- forward secrecy is preserved across every rotation
- one-way derivation: no key reveals its ancestors
- session_id binding protects against master reuse

**Tradeoffs:**

- rekey costs a full handshake (D16)

---

# D15 — Key Confirmation Mechanism

## Status

Accepted

## Context

PROTOCOL_SPEC §16 lists key confirmation as an unresolved future decision.
Security review found that an unauthenticated M3 allows handshake
assassination: an on-path attacker injects its own M3 for the observed sid,
the server commits to the attacker's share, and the client's packets never
decrypt. Key confirmation must exist, and its placement must provide the
earliest confirmation points.

## Decision

- Client→server confirmation is explicit: M3 carries a 16-byte Finished MAC —
  `finished_key = HKDF(master, info = "pq-tunnel-finished-v1" ‖ VERSION ‖ SID)`,
  `client_finished = HMAC-SHA256(finished_key, TH3)[..16]`. Only the real
  client (holder of the ephemeral secret keys) can compute it. The server
  verifies it before entering ESTABLISHED; a forged or raced M3 is silently
  dropped without mutating session state.
- Server→client confirmation is implicit: the client confirms the server
  when the first AEAD packet decrypts successfully under the session keys
  (replay window included).
- The client MUST NOT deliver application data before the first
  authenticated server packet decrypts; alternatively it MUST enforce a
  liveness timeout that closes mis-keyed sessions (fail closed, §5.7).

## Consequences

**Advantages:**

- closes the M3-assassination and forged-M3 DoS findings
- confirmation at the earliest possible moments; no extra RTT
- explicit, MAC-authenticated definition of a duplicate M3

**Tradeoffs:**

- a mis-keyed session is detected only when the server's first packet fails
  to decrypt (bounded by the liveness timeout)

---

# D16 — Rekeying Model

## Status

Accepted

## Context

PROTOCOL_SPEC §13 requires defined rekey triggers, transition, and failure
handling. The session layer blocks the data path at nonce exhaustion (no
in-place path). A compromised traffic key must not expose a session's whole
history: exposure is bounded by the session lifetime.

## Decision

- v1 rekey = close and re-establish: on nonce exhaustion (or a configured
  lifetime cap), the session enters REKEY with the data path blocked and
  must be closed; a fresh handshake (fresh ephemerals, fresh sid, fresh
  master) re-establishes it (D13).
- No in-place key transition in v1. The master is never retained or
  re-derived.
- A configurable session-lifetime cap bounds traffic-key exposure (D7
  parameter, does not redefine guarantees).

## Consequences

**Advantages:**

- fail-secure; simple, auditable rotation
- forward secrecy is refreshed on every rotation (D14)
- no rekey state machine in the data path

**Tradeoffs:**

- re-establishment cost: full handshake per rotation (≈1.5 RTT, ~2.5 ms CPU)
- brief connectivity interruption during re-establishment

---

# D17 — Key Provisioning & Identity File Format

## Status

Accepted (v0.2.0-alpha, `pq-tunnel keygen`)

## Context

v2 authentication (D12) pins the server's ML-DSA-65 public key client-side and
authenticates clients against a server-held roster. Keys must move between
machines out of band. A human-inspectable text file was chosen over binary
keystores; the format must be versioned, strict, and cheap to audit by hand.

## Decision

- Provisioning files are text with a minimal, versioned header — no second
  key format or protocol:
  `PQTI` / `version: 1` / `type: identity|public-key|roster` / hex payload.
- `identity` holds the 32-byte ML-DSA-65 seed (secret); `public-key` holds the
  1952-byte encoded key; `roster` holds one encoded public key per line
  (blank lines and `#` comments ignored).
- Parsing fails closed: wrong magic, version, or type is rejected; no silent
  downgrade; `identity`/`public-key` payloads must be exactly one line of the
  expected byte length; an empty roster is rejected.
- `keygen` refuses to overwrite existing outputs (kernel O_EXCL, not a
  pre-check) without `--force`, rejects two outputs resolving to the same
  path, appends to rosters idempotently, and never prints or logs the seed.
- Fingerprints for out-of-band verification are `SHA-256(encoded_key)[..16]`
  (32 hex chars, 128-bit binding).

## Consequences

**Advantages:**

- minimal surface: one format, strict grammar, no parser ambiguity
- out-of-band-friendly: printable, diffable, grep-able, copy-pasteable
- fail-closed load path is shared by server and client provisioning

**Tradeoffs:**

- text files are not a full PKI: distribution, rotation, and revocation of
  rosters remain manual operational processes
- the seed file must be protected at rest by host permissions (out of scope
  for v1; no encryption-at-rest wrapper)

---

# D18 — Application Model: UDP Relay Client + Forwarding Backend

## Status

Accepted (v0.2.0-alpha)

## Context

The v0.2 product decision is a local **UDP relay** client (no TUN, no admin)
and a **forwarding backend** server that delivers decrypted datagrams to their
real destinations and relays replies back to the client. The wire protocol
stays fixed 1280-byte envelopes (D13); everything below is application layer
*inside* the encrypted slot.

## Decision

- **Client**: binds an application-facing UDP socket (`--relay-listen`, default
  `127.0.0.1:51821`). Applications send UDP to any destination; the client
  prepends a compact destination header and feeds the result into the tunnel.
  The relay **refuses non-loopback binds** (fail closed): its
  `destination → app endpoint` record is unauthenticated last-writer-wins, so
  the socket must not be reachable by anything that cannot already read the
  local host's traffic.
- **Relay message format** (inside the encrypted `PAYLOAD_LEN`=1245-byte slot,
  zero-padded by the session layer):

  `family(1) ‖ address(4|16) ‖ port(2) ‖ len(2) ‖ datagram(len)`

  - `family`: `0x04` (IPv4, 9-byte header) or `0x06` (IPv6, 21-byte header);
    anything else is dropped (fail closed).
  - `len` is explicit: the slot is zero-padded, and a UDP datagram may
    legitimately contain trailing zero bytes, so the length is signaled, not
    inferred from padding. Maximum relayed datagram: 1236 B (IPv4) / 1224 B
    (IPv6); oversized datagrams are dropped with a warning (ICMP/error
    feedback is out of v0.2 scope).
- **Server**: the default backend parses the header, forwards the datagram to
  the real destination over UDP, and relays replies back to the client.
  - Reply routing: the server keeps per-`(session, destination)` connected
    sockets, so a reply arriving on a socket identifies both the session and
    the original destination; the server re-labels the reply with that
    destination header. The client only needs a short-lived
    `(destination → local app endpoint)` map.
  - Resource bounds: socket pools are capped (per-session and global) with an
    idle TTL; exhaustion drops the oldest (fail closed, no unbounded growth).
    Idle TTLs are enforced on every datagram, not just on new insertions, so a
    quiet session's descriptors are reclaimed by the next frame rather than
    lingering until pool pressure.
- **Echo** remains as an opt-in (`--echo`) test/diagnostic mode; it is not the
  default product path.
- **Scope**: UDP only in v0.2. TCP through the relay requires a stream layer
  and is deferred.

## Consequences

**Advantages:**

- the v0.2 path needs no admin privileges anywhere (relay + backend, no TUN)
- arbitrary destinations in a single tunnel; the wire format is unchanged
- the destination header is invisible on the wire (inside AEAD, fixed slots)

**Tradeoffs:**

- per-datagram destination state on server and client; when two local apps
  share one remote destination, replies follow last-writer-wins (documented)
- UDP-only: TCP apps need a stream milestone
- no ICMP / unreachable feedback in v0.2

---

# Open Design Decisions

The following areas remain intentionally unresolved.

These require further protocol design before finalization.

Resolved areas are recorded above: Authentication Model (D12), Handshake
Construction (D13), Key Hierarchy (D14), Key Confirmation Mechanism (D15),
Rekeying Model (D16), Key Provisioning (D17), Application Model (D18).

---

# Packet Protection Model

Unresolved:

- header visibility
- authenticated associated data usage
- nonce construction
- packet encoding
- replay window design

---

# Rekeying Model

Unresolved:

- rekey triggers
- key transition process
- failure handling
- session continuity behaviour

---

# Traffic Scheduling Model

Unresolved:

- exact scheduler design
- padding strategy
- fixed-rate behaviour
- adaptive mode limitations

---

# Version 1 Scope

Unresolved:

- mandatory v1 features
- deferred features
- deployment assumptions

---

# Final Principle

Tunnel design decisions follow one rule:

> Security guarantees are fixed. Implementations and mechanisms may evolve.

The protocol must preserve:

- HNDL resistance
- metadata resistance
- secure defaults
- transparent tradeoffs
- cryptographic adaptability