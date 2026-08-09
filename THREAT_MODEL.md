# Tunnel Threat Model

## 1. Purpose

Tunnel is a privacy-focused networking protocol designed around two primary security objectives:

1. **Harvest Now, Decrypt Later (HNDL) resistance**
2. **Metadata resistance**

Tunnel is designed for environments where communication may be observed, collected, analyzed, and potentially attacked by future adversaries.

The threat model defines:

- what Tunnel protects,
- what attackers are considered,
- what assumptions exist,
- what guarantees Tunnel attempts to provide,
- and what is explicitly outside the scope.

Tunnel focuses not only on protecting the contents of communication, but also reducing information leakage from communication patterns.

---

# 2. Protected Assets

Tunnel protects several categories of information.

---

## 2.1 Communication Confidentiality

Tunnel protects the contents of communication from unauthorized access.

This includes:

- transmitted data,
- application payloads,
- exchanged information.

The objective is that unauthorized observers cannot read protected communication.

---

## 2.2 Communication Authenticity

Tunnel protects communication integrity and identity verification.

This includes protection against:

- packet modification,
- forged communication,
- impersonation,
- malicious injection.

Confidentiality alone is insufficient.

A secure system must ensure that received data is both:

- secret,
- and authentic.

---

## 2.3 Metadata Privacy

Tunnel treats metadata as a primary security concern.

Metadata includes information such as:

- packet timing,
- packet sizes,
- traffic volume,
- idle periods,
- communication patterns,
- directionality,
- session behaviour,
- traffic bursts.

Encrypted content may still reveal sensitive information through observable patterns.

Tunnel therefore considers traffic analysis a first-class threat.

---

## 2.4 Cryptographic State

Tunnel protects cryptographic material required for secure operation.

This includes:

- session keys,
- key derivation state,
- authentication state,
- cryptographic parameters,
- temporary secrets.

Exposure of cryptographic state may compromise security properties.

Tunnel therefore considers:

- secure key handling,
- key lifecycle management,
- rekeying,
- secure erasure,

as important parts of the security model.

---

# 3. Security Assumptions

Tunnel assumes:

- endpoints run trusted Tunnel implementations,
- cryptographic randomness generation is secure,
- selected cryptographic primitives remain secure,
- operating systems provide basic memory isolation,
- users protect authentication credentials,
- implementation vulnerabilities are not present.

Tunnel cannot provide security if endpoints are fully compromised.

A compromised endpoint may expose:

- plaintext data,
- keys,
- user activity,
- application behaviour.

---

# 4. Adversary Model

Tunnel considers multiple classes of adversaries.

---

# 4.1 Passive Network Observer

The attacker can:

- observe network traffic,
- capture packets,
- store traffic,
- analyze timing and patterns.

Examples:

- ISP-level observers,
- network monitoring systems,
- malicious WiFi observers.

The attacker cannot:

- modify traffic,
- inject packets,
- compromise endpoints.

Tunnel aims to reduce both content exposure and metadata leakage against this attacker.

---

# 4.2 Harvest Now, Decrypt Later (HNDL) Adversary

The attacker:

1. records encrypted traffic today,
2. stores it,
3. attempts decryption in the future using improved technology.

This includes future advances such as:

- quantum computing,
- cryptanalytic improvements,
- stronger computational resources.

Tunnel aims to provide protection against future decryption attempts when:

- the selected cryptographic profile remains secure,
- endpoints remain uncompromised,
- protocol assumptions remain valid.

---

# 4.3 Active Network Attacker

The attacker can:

- modify packets,
- inject packets,
- replay packets,
- drop packets,
- interfere with communication.

Tunnel must protect against:

- forged messages,
- unauthorized modification,
- replay attacks,
- downgrade attempts.

---

# 4.4 Local Attacker

The attacker has access to the local environment.

Examples:

- malicious local network users,
- compromised local infrastructure,
- nearby attackers.

Capabilities may include:

- observing local traffic,
- attempting interference,
- fingerprinting communication.

Tunnel does not protect against a fully compromised endpoint.

---

# 4.5 Infrastructure-Level Attacker

The attacker may compromise or observe parts of the networking infrastructure.

Examples:

- compromised servers,
- malicious hosting providers,
- network infrastructure observers.

The impact depends on deployment architecture.

Infrastructure compromise may expose:

- availability information,
- operational metadata,
- server-side observations.

However, compromise of infrastructure does not automatically imply compromise of endpoint cryptographic guarantees.

---

# 5. Quantum Threat Model

Tunnel considers future quantum computers as a long-term threat.

The primary concern is:

**Harvest Now, Decrypt Later.**

An attacker may collect encrypted traffic today and attempt decryption when stronger capabilities become available.

Tunnel therefore requires consideration of:

- post-quantum key establishment,
- post-quantum authentication,
- forward secrecy,
- cryptographic agility.

Symmetric encryption security and asymmetric cryptographic security are considered separately.

---

# 6. Metadata Threat Model

Tunnel considers traffic analysis a major threat.

An observer may attempt to infer information from:

- packet sizes,
- packet timing,
- traffic volume,
- idle periods,
- bursts,
- session duration,
- directionality.

Tunnel aims to reduce metadata leakage through mechanisms such as:

- consistent packet structures,
- controlled timing behaviour,
- traffic shaping,
- cover traffic.

Metadata resistance is a primary design goal.

---

# 7. Active Attack Considerations

Tunnel considers active attacks including:

- replay attacks,
- packet injection,
- packet modification,
- downgrade attempts,
- protocol manipulation,
- traffic probing.

Security mechanisms must ensure:

- authenticated communication,
- correct protocol state handling,
- rejection of invalid states,
- no silent fallback to weaker security.

---

# 8. Out of Scope

Tunnel does not attempt to protect against:

- fully compromised endpoints,
- malware on user devices,
- malicious applications with endpoint access,
- physical compromise of secured devices,
- insecure user authentication practices,
- failures of underlying operating systems.

Tunnel protects communication security, not general device security.

---

# 9. Security Priorities

Tunnel prioritizes:

1. Long-term confidentiality (HNDL resistance)
2. Metadata resistance
3. Authentication and integrity
4. Secure defaults
5. Transparency
6. Deployment practicality
7. Performance

Performance optimizations must not silently weaken security properties.

---

# 10. Requirements Derived From Threat Model

The threat model requires Tunnel to consider:

## HNDL Protection

- post-quantum capable cryptography,
- forward secrecy,
- cryptographic agility,
- secure key lifecycle management.

## Metadata Protection

- traffic pattern resistance,
- timing resistance,
- size resistance,
- configurable traffic shaping.

## Secure Operation

- authenticated communication,
- replay protection,
- downgrade resistance,
- fail-secure behaviour.

## User Control

Any security reduction must be:

- intentional,
- visible,
- documented,
- reversible.

---

# 11. Security Claims

Tunnel is designed to provide:

- protection against unauthorized reading of communication,
- protection against unauthorized modification,
- improved resistance against future cryptographic advances,
- reduced metadata leakage compared with conventional encrypted tunnels.

These properties depend on:

- secure implementations,
- secure cryptographic profiles,
- uncompromised endpoints,
- valid security assumptions.

No cryptographic system can guarantee security if its underlying assumptions fail.

---

# 12. Threat Model Evolution

The threat model must evolve as:

- cryptographic research advances,
- attacker capabilities change,
- deployment environments change,
- new vulnerabilities are discovered.

The core objectives remain:

- resist long-term cryptographic threats,
- minimize metadata leakage,
- use transparent security engineering,
- preserve user control.

Implementation details may change.

Security objectives remain stable.

---

# 13. M7 Adversarial Reassessment (2026-08-09)

Record of the M7 verification milestone against this threat model.
Evidence ledger: `R:\pq-tunnel-lab` (dossiers W1..W15, gap ledger,
campaign summary). This section is a dated assessment, not a promise.

## 13.1 Claims re-verified

- **§2.2 authenticity** (replay, tamper, injection): replay-window
  bit-slice semantics property-tested (1M runs); adversarial E2E covers
  forged/fragmented handshake and envelope tampering; envelope decrypt
  fuzz (1M runs) — no path to acceptance of unauthenticated data found.
- **§2.3 metadata resistance** (timing/size/shape): cover-driver oracle
  (interval monotonic, never 0, clamp regression pinned by unit test);
  size invariants fuzzed per frame type; no channel found that lets an
  unauthenticated peer distort scheduling state.
- **§7 active attacks**: session/handshake driver fuzz (≈1.9 M combined
  runs) plus scripted churn over both managers (105,350 runs) exercised
  retry loops, DoS caps, rearm/reset/teardown races without fault.
- **§10 fail-secure requirements** (clients): all adversarial E2E cases
  fail by disconnection, never by acceptance; teardown-race stress
  validates the "reject, don't guess" rule under concurrency.

## 13.2 Residual assumptions (still open, by design)

1. **RQ2 traffic-analysis proof** (§§ 6, 10): timing/cover guarantees are
   empirically exercised, not formally proven. This is a proof problem,
   parked outside M7 (G6 in ledger).
2. **Nonce-exhaustion E2E (D16)** (§2.1, HNDL/key life): rekey nonce
   hygiene is unit-proven at the envelope layer; the full-loop E2E test
   is explicitly user-gated for post-M7.
3. **Sanitizer classes**: LSan sweeps green across the 9-target matrix
   (2026-08-08, W12); MSan/UBSan unavailable on the current toolchain
   (`rust-src` missing, `-Zsanitizer=undefined` invalid) — outstanding,
   not silent; see W12 dossier.
4. **Harness-only defects found, zero product defects**: two fuzz-harness
   panics (input-buffer framing; selector consumption) were fixed in the
   harnesses; no protocol or implementation defect was discovered across
   the ≈6.9 M executed units. Absence of defects in fuzzed paths does not
   imply a proof of correctness elsewhere.

## 13.3 Sinks, no model change

M7 produced no change to claims, assumptions, or adversary classes:
all findings were harness defects or clamp/correctness fixes with
behavioral-equivalent unit tests. The guarantees in §11 remain as
stated; the residual list above is the honest boundary of what a
fuzzing campaign can and cannot establish.

---

## 13.4 RQ2 precision — bounds of the cover floor (2026-08-09)

Derived in M8 Step 3 analysis (`R:\pq-tunnel-lab\RQ2-0*.md`, no code).

The cover floor (D19) makes the idle session wire a deterministic
195.3 pkt/s grid per direction (one 1280-byte packet per 5.12 ms tick
per session). It does **not** hide activity above the floor: the
additive emission of application packets is detectable as extra
packets per observation window — bound λ·W ≥ 1 (a 1 pkt/s source is
separated in ≈2–3 s, a 100-packet burst in one window, under lossless
capture). **Raising the cover rate does not change this bound.**
Session count on a server is observable per tick (one cover packet per
established session; batch size is exact), and session liveness,
handshake/rekey/close events are visible by construction (fragment
markers, bursts, sid churn, per-sid cleartext counters).

The design that would silence the application-activity channel is
**slot-absorbing emission capped at one packet per tick** — the wire
then equals the grid for all loads up to ≈1.94 Mbps usable per
direction per session (defaults) and beyond (overflow becomes loss, not
signal). That is an architecture change, explicitly deferred for user
decision; it is not a parameter table toggling "more cover".

The claim in §11 ("reduced metadata leakage compared with conventional
encrypted tunnels") remains valid as written; §13.4 states precisely
what "reduced" means before and after any such change.