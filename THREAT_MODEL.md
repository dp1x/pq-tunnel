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
signal). That is an architecture change, recorded and **rejected for
v1-alpha in DESIGN_DECISIONS D22** (2026-08-09): the adopted target is
metadata-leakage reduction, not traffic-flow anonymity; hiding activity/
volume would be a new architectural milestone with its own costs.

The claim in §11 ("reduced metadata leakage compared with conventional
encrypted tunnels") remains valid as written; §13.4 states precisely
what "reduced" means before and after any such change.
---

## 13.5 M9 empirical closure - cadence shortfall and the establishment window (2026-08-12)

Empirical results of M9 (D23) and the M9A-residual measurement campaign
(lab wirelog instrumentation on the R: harness copy, loopback runs
2026-08-12, post-reboot; raw CSVs volatile, this section is the durable
record).

**Cadence shortfall is not material.** Steady-state cover (30 s run,
both endpoints): server 182.6 pkt/s = 93.5% of the nominal 195.3 grid,
period p50 5.5 ms / p90 5.8 / p99 6.0 ms; client identical once
covering.  Per-second counts are uniform (178-185) and the full run
contains exactly one gap >= 15 ms (a single 29.3 ms stall at startup;
no 15.6 ms fallback runs, no burst accumulation).  The 5.12 -> ~5.5 ms
inflation is the per-tick wakeup skew of the D19 relative re-arm
(scheduler semantics: `next = now + interval`), constant and
stationary.  The 13.4 additive-detection bound (lambda*W >= 1) is
independent of the floor rate - 13.4 itself states raising the rate
does not change the bound, so a constant ~7% shortfall cannot either.
The grid remains deterministic, uniform and stationary: no new
metadata channel opens because of the shortfall.

**Establishment window (recorded for M10, pre-existing design).**  The
client emits **no cover during connection establishment**: it reaches
D15 ready only after the D13 M3-retransmit budget sweep (~8-9.3 s worst
case with defaults; 4 attempts at jittered exponential backoff from a
250 ms base, M6.2-documented in CHANGELOG).  During that window the
client sends only handshake retransmits at wire-visible exponential
intervals (measured backoff rows 549.8 / 1021.8 / 1842.4 / 4471 ms
match backoff_delay(250 ms, 1..4) +-20% exactly), while the server
covers immediately at its own establishment - asymmetric, observable
cover onset.  This is D13/D15 design (cover is encrypted traffic on an
established session; M9 changed only the sleep clock, not the gate),
not an M9 regression.  M10 (2026-08-12) quantified the window; the
outcome and the decision are recorded in §13.6: the establishment-phase
metadata profile is accepted as residual leakage under D22
(disposition C), and randomized-establishment behaviour is deferred as
a future research question, not implemented.

---

## 13.6 M10 establishment-window quantification (2026-08-12)

Empirical campaign on the lab wirelog instruments (R: harness copy,
loopback runs 2026-08-12, post-reboot, debug build; raw CSVs volatile —
this section is the durable record).  Cells: e1 default x30, e2a M3-budget=1 x15, e2b
M3-budget=0 x15, e3a server delay 500 ms x5, e3b server delay
2000 ms x5, e4 fresh-process x20, e5 steady x5.  Gap math uses
process-relative microseconds exclusively.

**Establishment window (H1) — disposition C, accepted residual.**
Client cover onset (first steady ~5.5 ms cadence): default config
min 6.86 / p10 7.01 / p50 7.78 / p90 8.43 / max 8.86 s,
p90-p10 = 1.42 s, observed min-max range 2.00 s.  Theoretical support
(jittered(250) + sum(jittered(500..4000)) at factors .8/1.19) =
[6.25, 9.22] s, ~2.9 s wide.  The window is RTT-independent below
~250 ms (the client's handshake retransmit timer is armed once at phase
start and never re-armed at M3 emission), so release builds (M2 RTT
~ ms) show the same distribution over real links.
Establishment-phase metadata is intentionally observable under the
current D13 handshake design.  The measured window and M3-budget
distinguishability are accepted residual leakage under D22's
metadata-reduction objective, pending future research.
Randomized-establishment behaviour stays a future research question —
"Can randomized establishment behaviour materially reduce observer
inference without unacceptable handshake cost?" — recorded only, not
implemented.

**M3-budget distinguishability (H2-adjacent) — externally observable.**
Median window 7.78 s (budget 4) vs 0.76 s (1) vs 0.27 s (0);
correct classification 60/60 with disjoint populations (e2a max
0.86 s < e1 min 6.86 s).  The retransmit budget is an implementation
fingerprint visible through establishment duration alone.

**Session linkability (H2) — INCONCLUSIVE.**  The E-series dataset is
single-identity (one process spawn configuration), so no
identity-vs-identity contrast exists; an earlier "0/30 NN match" figure
was an analysis-script stub and is withdrawn.  Descriptive only:
same-identity gap fingerprints (M2 RTT + 5 retransmit slots) are not
self-similar (pairwise log-distance p50 0.625).  Tunnel does not claim
that establishment patterns prevent session linkability; an
identity-vs-identity cell (two or more identities, interleaved,
30+ runs each) is required before any claim in either direction.

**Establishment onset (H3) — inherent / expected.**  Every session
opens with a 4-datagram (<1 ms gaps) M1 fragment burst at t = 0; a
passive observer at the source vantage detects establishment 30/30
(Wilson 95% CI [0.886, 1.000]) and steady cover cannot produce false
positives (min cover gap 5.1 ms).  This is D13 framing (M1 = 4 uniform
1280-byte datagrams), already listed among §13.4's accepted residuals
("burst structure"); burst survival across real links is untested
(loopback vantage).

**Retransmit schedule (H4) — verified.**  Post-M3 gaps match
jittered(500, 1000, 2000, 4000) x [0.80, 1.19] (code factors
80..119/100): 9/220 = 4.1% outside the band (Wilson 95% upper
0.076 < 10%); excluding the one race-corrupted run (M1-retransmit
timer fired before M2 arrived; single occurrence, requires M2 RTT
> ~200 ms, debug-build-only) leaves 5/216 = 2.3%, all high-edge
overshoots <= 11.7 ms attributable to the Windows 15.6 ms tokio sleep
quantum (retransmits sleep on tokio; only cover uses the HR waitable
timer).  Slot-0 model verified against the code's once-armed semantics:
(slot0 + M2 RTT) = jittered(250) in 50/55.  The M9A backoff rows
(549.8 / 1021.8 / 1842.4 / 4471 ms) are confirmed as slots 1-4.

**Cell-integrity notes.**  e2a/e2b ran 12 s windows (not 18 s) —
irrelevant to the duration-independent window metrics; e4 exercised no
intra-run reconnection (20 extra default-config samples); server.csv
is echo-mixed in e1-e5 and was not used beyond the e0 clean
single-session capture (M2 5-fragment burst + immediate cover,
confirming the §13.5 asymmetry).
