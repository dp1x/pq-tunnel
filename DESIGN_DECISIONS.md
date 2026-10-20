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
  combination is banned (the pre-v2 XOR-combiner derivation bug).
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
- Signature generation uses the **deterministic** variant of ML-DSA-65
  (FIPS 204 Algorithm 2, `rnd = 0`). This is a deliberate profile choice, not
  an incidental property of the `ml-dsa` dependency, and it is pinned by
  `ml_dsa_sign_is_deterministic` plus the external known-answer vector in
  `ml_dsa_65_wycheproof_sign_kat`.
  - It is **not** a metadata weakness. Both signed digests bind a fresh
    per-session CSPRNG `sid`, a fresh ML-KEM-768 encapsulation key and a fresh
    X25519 key (`M1_z` / `M2_z` under `canonical_zerofill`), so no digest is
    ever signed twice and no observer can link two sessions by signature
    equality. Hedged signing is therefore **rejected**: it would add a
    randomness dependency to the handshake path (CRYPTO_PROFILE §12) for no
    privacy gain.
  - Byte-identical retransmission is guaranteed by **byte caching**
    (`m1_frags`, `m3_frags`, `m2_cache`), never by re-signing, so the
    retransmission contract is independent of the signing mode. Cached
    handshake bytes MUST NOT be re-derived on retransmit.
  - Consequence for operators: the identity key alone reveals nothing about
    past sessions, because traffic keys derive from ephemeral secrets only
    (D14) — identity keys never enter the key schedule.
- Default timing invariant (fixed M6): the client's M3 retransmit budget —
  the only path to client establishment (passive server, no M4) — must
  complete strictly inside the session manager's default handshake deadline.
  Defaults: `m3_max_attempts = 4` (≈9.3s worst case incl. ±20% jitter) vs
  `handshake_timeout = 30s`. The earlier 8-attempt default budgeted ~38s
  worst case, so a default-configured client could never establish.
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

# D19 — Cover Traffic Scheduling Model

## Status

Accepted (v0.2.0-alpha; implemented in M3)

## Context

PROTOCOL_SPEC §12 commits Tunnel to metadata resistance from traffic
behaviour: timing, volume, idle periods and bursts are all observable even
when packet content is sealed (D5/D6). Cover traffic must create a **stable
observable traffic pattern over time** — a protocol-level constant rate — not
perfectly timed packets.

## Decision

- **Default policy is fixed and permanent for v0.2 alpha**: cover **enabled**,
  **fixed-rate**, **2 Mbps** (5.12 ms per 1280-byte slot). The default is not
  adaptive. Rationale: the purpose of the default is *predictable* metadata
  resistance — fixed rate is easier to reason about, test, audit, and explain;
  adaptive behaviour creates observable state changes (rate/timing/pattern
  changes) that can themselves leak information.
- **Adaptive modes are future, user-selected policies only** — never the
  default, never negotiated. When (if) built they require an explicit warning.
  M3 implements the fixed scheduler only; adaptive code paths are not added
  now (extra attack surface and test burden for no v0.2 requirement).
- **Scheduling semantics**: pure-periodic (D5) with *jitter tolerance*. The
  scheduler tracks a monotonic deadline; when the deadline passes it yields
  **at most one** emission and reschedules from "now". A delayed driver wake
  (OS scheduling) therefore produces a single catch-up packet — never a
  buffered burst, which would itself be a traffic fingerprint. No
  "only-when-data" behaviour: an established idle session keeps emitting.
- **Cover traffic is a transport behaviour, not a handshake property.** The
  policy lives in the session/driver layer (`pq-tunnel-core::scheduler`),
  never in `ClientConfig`/`ServerConfig`, so it cannot become part of the
  protocol negotiation surface. Future protocol versions must not negotiate
  it either.
- **Emission rules**: cover only while a session is established (no churn
  during handshake); client emits on its single session, server emits one
  cover packet per established session per interval; cover rides the exact
  same encrypted packet path as data (`WireSession::cover` → AEAD slot) and
  consumes session nonce state like real traffic, so nonce exhaustion closes
  and re-establishes per D16.
- **Disabling is explicit and visible**: `--no-cover` is the only way to turn
  it off (documented reduction, PROTOCOL_SPEC §12.2); `--cover-mbps` tunes the
  fixed rate.

## Consequences

**Advantages:**

- the shaper never bursts: a stalled host produces a single delayed record,
  never a queued backlog, so the shaper itself contributes no burst or idle
  structure — but the resulting pattern is bounded, not constant: the
  measured steady-state cadence is 182.6 pkt/s (93.5% of the nominal 195.3)
  with a p50 period of 5.5 ms against a nominal 5.12 ms, and session count,
  liveness and lifecycle events stay observable by construction
  (THREAT_MODEL.md §13.4–§13.6)
- single-emit-on-stall rescheduling is clock-independent and unit-testable in
  virtual time
- the scheduler is a pure module: core owns policy/timing, binary drivers own
  async execution

**Tradeoffs:**

- fixed 2 Mbps overhead even when the user has nothing to send (the price of
  the default guarantee; explicitly tunable or disable-able)
- per-interval wakeups in the driver loops (~195 Hz at the default rate)
- a single global interval per session — no per-flow differentiation yet
  (future scheduler work, still user-selected only)

---

# D20 — Removal of the Pre-v2 QUIC/TLS Transport

## Status

Accepted (v0.2.0-alpha; implemented in M4)

## Context

Before the v2 datagram plane, Tunnel shipped a QUIC/TLS-based transport
(`--transport quic`): a v1 8192-byte handshake framing with its own
`MsgType` set (0x10/0x11 for data/cover, byte-incompatible with the codec),
a self-signed-certificate server, a client that performed **no
server-certificate validation** (`SkipServerVerification`), ephemeral
self-generated identities with no roster pinning, and a `HybridIdentity`
XOR-combiner (D14 rationale). The v2 datagram plane (D13-D18) replaced every
one of these guarantees, and the v1 path was retained only as a transitional
bootstrap.

## Decision

- **Delete the legacy stack entirely** (M4): `pq-tunnel-bin/src/quic.rs`
  (flood/cover/flatline/TUN modes, including its hardcoded 100 pkt/s cover
  loop), the core v1 modules (`client`, `server`, `handshake`, `config`,
  `session`), the `HybridIdentity` XOR-combiner in `pq-crypto`, the
  `TunnelError` enum, the v1 CLI surface (`--transport`, `--flood`,
  `--cover`, `--flatline`, `--packet-size`, `--rate`, `--duration`,
  `--tun-addr`, `--mtu`, `--handshake-timeout`), and the v1-only workspace
  members (`pq-tun` deleted; `pq-proxy` excluded from the workspace, parked
  in-tree for a future v2 rewrite).
- **The deprecation schedule is superseded**: `HybridIdentity` carried a
  "scheduled for removal in v2.1" deprecation note. The crate has never
  shipped 1.0 and the alpha release removes it now, with the whole legacy
  path, in one breaking change (README already declares pre-1.0 breaking
  changes).
- **Removal is a security-positive refactor**: the single largest attack
  surface (QUIC + rustls + rcgen self-signed certificates + no-certificate
  validation) and its dependency chain (including `aws-lc-sys`) leave the
  dependency graph entirely.

## Consequences

**Advantages:**

- one wire format (the 1280-byte codec), one handshake (v2), one identity
  model (ML-DSA roster pinning) — no dual-framing confusion (the old
  `MsgType` collision assertions became moot)
- the unauthenticated v1 path (no cert validation, self-generated identities)
  can no longer be deployed by mistake
- dependency graph shrinks by a full TLS stack; the `aws-lc-sys` build
  constraint disappears (the x86_64 `--target` convention is retained
  regardless as the tested toolchain)
- no dead public API: `connect`, `listen`, `Session`, `TunnelConfig`,
  `HandshakeError`, `TunnelError` are gone

**Tradeoffs / notes:**

- `pq-proxy` (SOCKS5-over-QUIC) is parked, not deleted: it is excluded from
  the workspace and does not compile against the v2-only core. It is
  scheduled for a v2 rewrite (SOCKS5 over the relay plane) rather than
  maintenance.
- `state.rs` (`ProtocolState`) is retained: it is the live v2 `WireSession`
  state machine (D16 rekey states), not dead code.
- Public API removals are intentional and documented as pre-1.0 breaking
  changes.

---

# D22 — Metadata Resistance Target: Reduction, Not Anonymity (RQ2 outcome)

## Status

Accepted (2026-08-09, M8)

## Context

M7/M8 (RQ2 dossiers 01–02 in `R:\pq-tunnel-lab\`; THREAT_MODEL §13.4)
proved where the cover design (D19) stops protecting: application traffic
is emitted **additively on top of** the per-session cover grid, so a
passive observer's detection bound is λ·W ≥ 1 — any sustained positive
application rate is separable from the deterministic floor, and **raising
the cover rate cannot close that channel** (the floor is a constant, the
excess is exact). Also observable by construction: server session count
(exactly N packets per 5.12 ms tick), session liveness, and
establish/rekey/close lifecycle events (plaintext fragment markers,
burst structure, sid churn, cleartext per-sid counters).

## Decision

- For v1-alpha, Tunnel's metadata target is **metadata-leakage
  reduction, not traffic-flow anonymity** — matching the Charter §2.2 /
  PROTOCOL_SPEC §2.2 wording ("reduce", not "eliminate").
- Observable residuals are accepted by design: activity above the floor,
  volume, server session count, session liveness, lifecycle events.
- The **absorbing emission model** (app data riding the existing slot to
  the per-tick cap, overflow = queue/loss) is **NOT adopted now**: it is
  a different protocol architecture trading throughput/latency/
  buffering semantics for stronger traffic-flow privacy, not a small
  security patch.
- If hiding activity/volume ever becomes a core requirement, it opens a
  **new architectural milestone** with its own threat model, capacity
  model, protocol design, implementation and validation — never a
  bolt-on to M7/M8.

## Consequences

**Advantages:** the privacy claim is exactly as strong as the
implementation; no hidden promise; cheap, usable default preserved; the
mathematical boundary of the current design is on record.

**Tradeoffs:** traffic-flow anonymity is explicitly out of scope; an
operator who needs it must wait for the future milestone and pay its
bandwidth/latency/backpressure costs themselves.

---

# D23 - M9: Recoverable Transport Reset Isolation + Windows Cover Clock

## Status

Accepted (2026-08-11/12, M9A + M9B)

## Context

Two M8.5 measurements surfaced engineering surprises in an otherwise
validated v2 data plane:

- **M9B (server isolation)**: a client that disappears without a Close
  message triggers ICMP port-unreachable feedback on the peer's UDP
  socket. On Windows this surfaces as `WSAECONNRESET` (and
  connection-refused on other platforms) on a *later* recv, and the
  pre-M9 server and relay drivers treated any transport error as fatal:
  one dead client could kill unrelated sessions or the whole server.
- **M9A (cover grid on Windows)**: the D19 5.12 ms cover grid depends on
  the driver's timer arm. tokio's timer driver quantizes to the system
  timer resolution (~15.6 ms at the Windows default), which would stretch
  the grid to ~64 pkt/s — far below the 195.3 pkt/s D19 floor.

## Decision

- **Recoverable reset classification**: `UdpError::is_recoverable_reset()`
  recognizes `ConnectionReset`/`ConnectionRefused` as *informational* UDP
  signals (the peer or its port vanished), never protocol failures.
  `HandshakeV2Error::TransportReset` is added so drivers can distinguish
  it from a fatal transport fault.
- **R1 (relay)**: the client's relay socket treats a recoverable reset as
  `continue` with one throttled warn per episode — a dead server must not
  kill the local relay.
- **R2 (server manager)**: the server driver maps a recoverable reset to
  a session-local `continue` (one throttled warn per reset episode); the
  vanished peer's session is reaped by the existing idle-eviction path
  (D16). Unrelated sessions and the server process stay up.
- **M9A (Windows cover clock)**: `cover_sleep` on Windows drives the
  scheduler's absolute deadline on a raw waitable timer created with
  `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` (spawn-blocking wait, so the
  async worker never stalls). The scheduler itself stays clock-agnostic;
  non-Windows platforms keep the tokio timer arm. No protocol change.
- **No protocol, crypto, or broad error-handling changes**: the wire
  format, D13 handshake, D19 scheduler semantics and the fail-secure rule
  ("a security failure closes the session") are untouched.

## Consequences

**Advantages:**

- one client's disappearance/reset can no longer kill unrelated sessions
  or the server process; the reset WARN is throttled to one per episode
- the D19 grid is realized on Windows at the measured cadence (p50 5.31
  ms in the pre-release bench; ~5.5 ms steady-state on the wire — the
  residual is per-tick wakeup skew, absorbed by the D19 relative re-arm)

**Tradeoffs:**

- a vanished peer is not actively torn down — it lingers until idle
  eviction reaps it (documented D16 behaviour)
- the Windows cover clock is an extra platform-specific surface (~100
  lines, cfg-windows, unit-tested); other platforms keep the tokio arm

**Validation (M9):** gates green (check, fmt, clippy `-D warnings`, 221
workspace tests incl. 7 new: reset classification, driver-survives-reset
via `ResetOnce` transport, cover-arm deadline/inert tests, real
`WSAECONNRESET` recv loop, recoverable-classification).  Live evidence:
R1 2/2 (500-pkt inject, close-delay 0/200 ms — client survives, one
throttled WARN); R2 4/4 server survival (client force-kill, runs up to
3.9 min / 42,798 cover sends) with reset WARN in 2/4 (Windows loopback
ICMP delivery is non-deterministic); post-reboot 5/5 stall diagnostic
ALIVE-OK.  M9A wire validation: server p50 5.595 / p90 6.196 / p99
7.009 ms (n=2358), client p50 5.696 / p90 6.155 / p99 7.156 (n=1013);
post-reboot 30 s confirmation: server 182.6 pkt/s (93.5% of nominal),
period p50 5.5 / p90 5.8 / p99 6.0 ms, per-sec counts uniform, one
≥15 ms gap total — no material impact on the THREAT_MODEL §13.4 bounds
(M9A-residual, see THREAT_MODEL §13.5).  One unreproduced server-stall
episode recorded as a watch item (r2b, 2026-08-11), no redesign.

---

# D21 - External Known-Answer Anchoring Policy

## Status

Accepted (M5.1)

## Context

Cryptographic primitives need ground truth that is independent of the code
under test. Self-derived vectors cannot distinguish an implementation error
from a wrong assumption. Tunnel contracts against canonical external sources
so a failing test always means the wrapper or the transcription is wrong,
never the vector.

## Decision

- **Authoritative vector sources**: RFC test vectors (RFC 8439 ChaCha20-Poly1305,
  RFC 5869 HKDF-SHA256, RFC 7748 X25519) and Google Wycheproof JSON vectors
  (FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65). Vectors are transcribed verbatim
  into `pq-crypto/src/kat_vectors.rs` (a `#[cfg(test)]` module) with a
  provenance comment naming the exact source and test case.
- **Vectors are never adjusted** to make a test pass. A failing KAT means the
  implementation under test, or the transcription, is defective; it is root-
  caused and fixed, never the vector.
- **Test-only access**: KATs may use `#[cfg(test)]` internal hooks but must not
  introduce production API solely to serve them. Deterministic encapsulation
  use in KATs stays behind a doc-hidden path already compiled in the crate.
- **Provenance per constant**: every constant carries its source test name so
  a mismatch can be re-verified against the published source.

## Consequences

**Advantages:**

- defeats self-referential test design; a green KAT is evidence the wrapper
  boundary is faithful to the published specification
- deterministic and reproducible (no randomness in KAT inputs)
- external vectors pin behavior against future dependency upgrades

**Tradeoffs / notes:**

- Wycheproof JSON is large; only the relevant test case is transcribed
- transcription is itself error-prone; lengths are validated as a smoke check
- a KAT failure path is unambiguous by construction: fail → fix the wrapper,
  never the vector

---

# D24 - Data-Path Failure Budget: What Is Counted and What Is Bounded

## Status

Accepted (M11, N-4; amended — the resource-bound claim this entry originally
made was measured false and is replaced below; the counting rules are
unchanged)

## Context

The data path carries a per-source failure gate: a token (burst 64 / 10 s) is
consumed only when an AEAD decrypt actually fails, and an exhausted source has
its packets dropped without decrypt work. That gate was sound in intent but
wrong in two mechanical details, both found in the M11 N-4 review.

- **The gate counted the wrong thing, and touched state it had no business
  touching.** `fail_gate_peek` ran *before* the sid was extracted and before
  the session table was consulted, and it both *tested* and *created/refilled*
  the bucket. So a datagram naming an unknown session id minted a full 64-token
  bucket for its source and then returned `None` — zero AEAD work performed,
  zero tokens consumed, one bucket created.
- **The consequence was unbounded attacker-controlled CPU.** The prune pass ran
  on every call once the table exceeded 32 entries, and at the 4096-entry cap a
  `min_by_key` scan ran per packet. Because the source key is the full
  `SocketAddr`, one IP address yields up to **65,535** distinct keys. An
  attacker could therefore saturate the table and *hold* it there
  indefinitely — roughly 409.6 datagrams per window keeps every bucket's
  `last_refill` fresh enough to survive the prune — paying two O(n) scans per
  packet forever. Memory was sound (genuinely capped); CPU was the defect.

Resource exhaustion was also missing from the formal threat-model enumeration
altogether (see `THREAT_MODEL.md` §7, corrected alongside this decision).

**A later verification pass found that the M11 fix did not finish the job, and
that this entry's own resource-bound claim was false.** Two defects survived
the lookup-first reordering, both confirmed by measurement on the pre-fix tree
rather than by reading alone.

- **Both linear scans were still on the packet path.** The reordering moved
  *bucket creation* behind the AEAD failure, but the prune (`retain`) and the
  cap eviction (`min_by_key`) still ran on every failing datagram, and the
  table could still be driven to its cap — so the O(n)-per-packet cost the M11
  review set out to remove was still reachable. Measured on the pre-fix tree:
  40,000 AEAD-failing datagrams against a 200-entry table produced **12,600
  prune passes and 2,520,000 bucket visits**; driving a 64-entry cap from
  distinct source ports produced **136 cap scans and 8,704 bucket visits**.
- **"Fail-gate state is bounded by the active session population" was false.**
  The sid is cleartext in every packet header (it is AEAD associated data, not
  a secret), so a party that observes one datagram learns a live sid and can
  then present AEAD-failing traffic from a fresh source port per datagram.
  Measured on the pre-fix tree: **one** live session plus **200** distinct
  source ports produced **200** buckets. The table tracks *failing sources*,
  not sessions; the live-session population was never a bound on it. The bound
  is `max_fail_buckets` (default 4096) — exactly the bound the M11 review had
  already identified for the table's *memory*, and the bound this entry
  mis-stated as if it were a property of the *population*.

The two defects have different shapes, and the fix must cover both: the CPU
defect is about *where* the work happens (packet path versus off-path), and
the false claim is about *what the bound is*.

## Decision

- **What the gate counts is expensive authenticated/decryption work — not
  bytes and not datagrams.** A token is consumed only when an AEAD decrypt
  actually fails. Traffic that never reaches a decrypt is never charged;
  charging it would be accounting for work the server did not do.
- **The source key is `SocketAddr`, port included.** This is stated explicitly
  because it is the fact that made the old behaviour exploitable: one IP
  address is up to 65,535 distinct keys, so "per-source" must never be read as
  "per-host". It is also the reason the source key space is *reachable* by an
  unauthenticated party: the sid is cleartext in every header, so knowing a
  live sid is enough to present a fresh source key per datagram.
- **Lookup-first invariant (the fix).** Traffic bearing an unknown or unowned
  session id is resolved against the session table and dropped **before** the
  gate. It must not allocate or touch a fail-gate bucket. Such traffic performs
  no decryption and consumes no budget, so charging it is meaningless work that
  only inflates attacker-controlled state. The gate is now a pure *test* on the
  packet path and bucket creation happens only on the real-failure path, which
  is its sole writer. (Unchanged by this amendment.)
- **Resource bound (corrected — the earlier claim was false).** Fail-gate state
  is bounded by `max_fail_buckets` (default 4096) and by **nothing else**. It
  is *not* bounded by the active session population: the sid is cleartext in
  every packet header, so one observed datagram is enough to learn a live sid,
  and a party holding a live sid can mint one bucket per source port. The
  supersession of the earlier claim is explicit and measured: one live session
  plus 200 distinct source ports produced 200 buckets on the pre-fix tree.
  `max_fail_buckets` remains the hard backstop and the fail-closed switch:
  `max_fail_buckets == 0` disables the data path.
- **Work bound (the fix that removes the O(n)-per-packet cost).** The CPU
  bound is separate from the memory bound, and it is now stated per operation:
  - the **packet path is O(1)**: the gate performs hash lookups only. No
    datagram — failing, succeeding, or unknown-sid — scans the fail-gate
    table, whatever the table holds;
  - the **cap eviction is O(1)**: the victim is the oldest-inserted tracked
    source, taken from an insertion-order queue maintained in lockstep with
    the table — one table entry visited per eviction, not `n`;
  - the **expiry sweep is off the packet path**: it runs in the manager's 1 Hz
    tick, at most one pass per `fail_window`, so its cost is bounded by
    `max_fail_buckets` bucket visits per `fail_window`. That is a *rate* bound:
    the table's reclamation cost no longer scales with the attacker's datagram
    rate, which is what the pre-fix per-datagram prune did.
- **Expiry semantics.** A bucket is *logically* expired `fail_window` after
  its last refill: the gate treats an expired bucket as absent (a full burst is
  allowed) and refills it to a full burst on that source's next failure.
  Physical reclamation of expired entries is a *memory cleanup* and happens in
  the tick path, at most one pass per `fail_window`; a stale entry that has not
  yet been reclaimed costs memory, never an accept/reject decision.
- **Eviction victim policy (changed, and not a weakening).** The victim is now
  the oldest-*inserted* tracked source rather than the least-recently-*refilled*
  one. The two policies are equivalent for the adversary's achievable
  throughput: what bounds a source's failure rate is that source's own budget
  and the number of distinct sources it can present, not which tracked bucket
  is sacrificed — and under table pressure *both* policies allow a budget
  reset, because the least-recently-refilled bucket is precisely the one a
  table-filling attacker would target (an attacker that keeps failing keeps
  its own bucket fresh). The FIFO victim costs one queue pop and no scan.
- **Why the added mechanism is safe (and what it is not).** This entry
  originally declined to add "a clock or LRU eviction pass" because a second
  eviction mechanism is a second thing to get wrong in the one path whose
  failure mode is "the attacker shapes our internal state". That concern is
  respected here in a specific way: the mechanism added is **not** a second
  scan and **not** an LRU with a second ordering to keep consistent. It is an
  insertion-order queue with one invariant — it holds exactly the table's keys,
  `order.len() == buckets.len()` — maintained by construction: every insert
  appends, every eviction pops the front and removes the same key from the
  table, and the expiry sweep removes the same keys from both. The D29
  analysis supplies the safety argument that makes moving the sweep off the
  packet path legitimate at all: *a stale bucket costs memory, never
  correctness*, so skipping a sweep can never change an accept/reject
  decision.
- **The gate still applies to known sessions.** Reordering the gate does not
  ungate it. A datagram that presents a live session id and then fails AEAD is
  charged, and once a source's budget is exhausted its packets are dropped
  without decrypt work even if they are authentic.
- **NAT / shared-source consequence is accepted, not solved.** Per-source
  semantics are preserved deliberately. A global token gate was considered and
  rejected: it would let one noisy client starve every other client behind the
  same address, converting a per-source limit into a trivially-triggered
  global denial of service. The known consequence — clients behind one NAT
  egress share one budget — is accepted, and is benign in practice because
  consumption is failure-only, so honest traffic never drains the shared budget.
- **Actual M1 accounting, recorded precisely.** A full 4-fragment M1 costs
  exactly **2** tokens; M1 + M3 costs exactly **3**. The charge points, which
  already existed in code and are now recorded here as contract:
  - fragment 0 → **1 token**, charged *before* the pending entry is allocated
    (allocation is what an attacker can force to grow);
  - the completing fragment → **1 token**, charged *before* the expensive
    crypto (roster verification + KEM);
  - fragments 1–2 → **free**, because they are pure reassembly: a `memcpy`
    into an already-allocated buffer, no allocation and no crypto;
  - M3 → **1 token**, before decapsulation/HKDF/HMAC.
  The gate on the completing fragment now runs *before* the ~5.6 KiB
  `asm.message().to_vec()` copy, so a refused source never pays for the copy.
  The copy is pure local work with no side effects, so this reordering changes
  neither token accounting nor retransmission semantics nor the success path.

### Relationship to accepted decisions

D24 **does not modify** D13 (handshake construction and its DoS posture), D16
(rekey as close + re-establish), D20 (pre-v2 transport removal), or D12
(authentication model). It refines *where* the existing data-path gate is
evaluated and *when* buckets are materialised, and it pins the accounting that
D13's per-source limiter already implemented. D22 and D24 share no surface.
The amendment aligns the data path with the shape the handshake path already
uses (`handshake_v2::rate_ok`, D29 item 1: a window-gated prune that runs at
most one pass per window); the handshake path's own cap-eviction question
(D29 item 2, an open gate) is a separate decision on a different code path and
is not changed by this entry. Resource exhaustion is recorded in
`THREAT_MODEL.md` §7 as an adversary
consideration; the bounded-resource invariants it lists — bounded pending table
with TTL, per-source failure budget, lookup-first no-allocation — are the
protocol-level statements of this decision. Out of scope for D24 remains what
§8 already excludes: compromised endpoints, malware, and OS failures. D24 does
not and cannot bound traffic *volume* a well-behaved peer sends, nor make a
server survive being deliberately saturated by a very large number of distinct
legitimate-looking sources.

## Consequences

**Advantages:**

- unknown-session traffic performs no gate work at all, so the
  attacker-controlled CPU sink (O(n) scans per packet over a 4096-entry table
  held fresh by ~409.6 pkt/s) is gone
- no datagram scans the fail-gate table any more — not an unknown-sid one, not
  a failing one, not a successful one — so the O(n)-per-packet cost is gone
  from the *whole* data path, not only from the unknown-sid branch
- the fail-gate table's cost is now bounded by a *rate* (at most
  `max_fail_buckets` bucket visits per `fail_window`) rather than by the
  attacker's packet rate, and its cap eviction is O(1)
- the memory bound is honest and measured: `max_fail_buckets`, and nothing
  else — the table tracks failing sources, and the claim that the live-session
  population bounded it has been withdrawn with the measurement that refutes it
- the bucket table's only writer is a real AEAD failure, which makes the
  "failure-only" property true by construction rather than by convention

**Tradeoffs / notes:**

- the sid is parsed before the gate, so a gated source still pays a
  fixed-size slice read and a hash lookup — negligible, and unavoidable if the
  gate is to remain keyed on the session that will be decrypted
- clients sharing a NAT egress share a failure budget; accepted (§ above) and
  benign because honest traffic never consumes it
- a deliberately large number of genuinely distinct sources that each cause
  real failures can still reach `max_fail_buckets`; that is now the correct
  signal (real failures, not probe noise), and the cap still holds
- the eviction victim is now the oldest-*inserted* tracked source rather than
  the least-recently-*refilled* one; the two are equivalent for the
  adversary's achievable throughput (§ above), and the FIFO victim is O(1)
- the expiry sweep runs from the manager's 1 Hz tick, so if the tick stops,
  expired entries linger in the table (still capped) until it resumes; the
  accounting is unaffected either way, because expiry is a property of the
  budget, not of the table's contents
- the per-source budget still bounds *a source's* failure rate, not the
  total: a party that learns a live sid can present up to 65,535 distinct
  source keys, so the total AEAD work it can request is bounded by the
  number of source keys it can present, not by `max_fail_buckets`

**Validation:** the invariants are asserted directly, by structure and not by
timing.

*M11 (lookup-first).* 10 focused tests: unknown-SID traffic across 4,096
distinct ports on one IP allocates **zero** buckets; the same volume repeated
8× still allocates zero; the gate demonstrably still bites on a known sid
whose AEAD fails; shared-source fairness holds; and the handshake limiter's
exact M1=2 / M1+M3=3 accounting is pinned through observable gate behaviour
with no wall clock.

*This amendment (work bound and the corrected resource bound).* 7 further
tests, all deterministic:

- `d24_fail_gate_state_is_bounded_by_the_configured_cap` — unknown-SID
  churn across 2,000 sources still allocates **zero** buckets, and the table
  holds exactly one entry per *failing source*. (This test replaces the
  superseded `d24_fail_gate_state_is_bounded_by_session_population`, whose
  name asserted the claim this entry withdraws.)
- `d24_one_live_session_can_drive_the_table_to_the_cap` — the counterexample
  that refutes the withdrawn claim, pinned as a test: one live session plus
  200 source ports reaches the configured cap.
- `d24_repeated_aead_failure_does_no_table_scan` — an instrumented
  table-visit counter proves the hot path visits **zero** table entries
  across 1,000 repeated AEAD failures, and that the cap eviction visits
  **exactly one** entry (O(1)), not the whole table.
- `d24_unknown_sid_path_visits_no_fail_gate_entry` — 1,000 unknown-SID
  datagrams from 1,000 sources allocate no bucket and visit no table entry.
- `d24_cap_boundary_behaviour_is_defined` — the table never exceeds
  `max_fail_buckets` under sustained churn, and the victim policy
  (oldest-inserted) is pinned by observation.
- `d24_expired_budget_is_refreshed_for_the_source` and
  `d24_expired_buckets_are_reclaimed_by_the_sweep` — expiry semantics on the
  crate's virtual clock: a budget expires `fail_window` after the last
  refill, and stale entries are reclaimed by the tick-path sweep, at most one
  pass per window.
- `d24_per_source_budget_is_not_shared_between_sources` — an exhausted
  source is gated while a different source is not starved, and successes
  allocate no bucket.

The pre-fix measurements quoted in the Context were taken on the baseline tree
with an instrumented copy of the failure path: 12,600 prune passes and
2,520,000 bucket visits for 40,000 failing datagrams against a 200-entry
table; 136 cap scans and 8,704 bucket visits while filling a 64-entry cap;
and 200 buckets from a single live session across 200 source ports. Existing
suite: 280 core tests green, plus the wider workspace gates.

---

# Open Design Decisions

The following areas remain intentionally unresolved.

These require further protocol design before finalization.

Resolved areas are recorded above: Authentication Model (D12), Handshake
Construction (D13), Key Hierarchy (D14), Key Confirmation Mechanism (D15),
Rekeying Model (D16), Key Provisioning (D17), Application Model (D18), Cover
Traffic Scheduling Model (D19), Removal of the Pre-v2 QUIC/TLS Transport (D20),
External Known-Answer Anchoring Policy (D21), Metadata Resistance Target:
Reduction, Not Anonymity (D22), Recoverable Transport Reset Isolation +
Windows Cover Clock (D23), Data-Path Failure Budget: What Is Counted and
What Is Bounded (D24).

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