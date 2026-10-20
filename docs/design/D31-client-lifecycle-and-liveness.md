# D31 — Client Lifecycle, Liveness and the Session-Lifetime Cap

**Status:** DESIGN PROPOSAL (implementation in this tree; the human decision
gate in §9 is **not** yet approved).

**Scope:** the client/session lifecycle of the v2 datagram plane: the state
machine, the D15 confirmation gate, the in-session liveness control message,
the session-lifetime cap and the bounded outbound queue.

**Baseline:** `c6c0f12373f45cba02f6e8f44b386ea46d5da659` (`origin/main`).

**Out of scope (other tracks):** roster hot-reload and revocation (D27 §2–§5),
the TUN data plane (D25/D26/D30), the server's egress policy (D28).

---

## 0. What was wrong (verified at the baseline)

Sixteen defects were verified against `c6c0f12` and are fixed by this change.
They are listed with their evidence in §8.  The three that shaped the design:

| # | Defect | Consequence |
|---|---|---|
| **B1/B2** | The client created its session only after the **M3 retransmission budget was exhausted** (≈6.2–9.3 s), and while the handshake machine was alive it swallowed *every* non-M2 datagram. | The server's first authenticated packets (its cover traffic, its first data) were silently discarded and never reached the replay window. |
| **B3** | The client's `not_confirmed` liveness check was gated on `!self.ready`, so it could **never** fire after confirmation. | With `--no-cover` the client had no peer-loss detection at all: an infinite re-handshake loop with no liveness signal. |
| **B4** | The server refreshed `last_activity` on its **own outbound** traffic (cover + app replies). | The idle timeout never fired with cover enabled (the default), so abandoned sessions, failed-handshake orphans and rotation orphans accumulated without bound. The code contradicted its own documented contract ("last authenticated receive"). |

---

## 1. The client lifecycle

### 1.1 States

`ClientManagerState` (previously `Idle | Handshaking | Established`) becomes:

| State | Meaning | Session held? | Handshake machine held? |
|---|---|---|---|
| `Idle` | No handshake running, no session. | no | no |
| `Handshaking` | The M1 was sent; the M2 is awaited. | **no** | **yes** |
| `Unconfirmed` | The M3 was transmitted: the peer is **authenticated** (its ML-DSA-65 signature over TH2 was verified while the M2 was assembled) and the shared key material exists — but the key agreement is **not yet confirmed**, because no authenticated server packet has decrypted yet. | yes | no |
| `Established` | Established **and confirmed**: an authenticated server packet has decrypted, so the D15 gate is open. | yes | no |

> **`Unconfirmed` is not "not yet authenticated".**  The peer is already known
> to be genuine in this state; what is missing is *key confirmation*.  Calling
> it anything else misleads implementers into weakening the gate.

### 1.2 The one-live-object invariant

> **The manager never holds the handshake machine and a session at the same
> time.**

The machine exists only while the M2 is awaited.  The moment the M3 is
emitted the manager **drops** it and takes ownership of

* the cached M3 fragments (for byte-identical retransmission),
* the derived outcome (the session is created from it),
* the M3 retransmission budget, and
* the prepared session.

This is what makes `begin_handshake()` safe after *every* teardown path: the
manager is either holding a handshake or holding a session, never both, so
the "handshake already running or session established" guard can never be
tripped by a legitimate transition.  (The baseline had the opposite shape —
the session was created *after* the machine was dropped, which forced the
manager to hold both for ≈6–9 s, and `begin_handshake` refused while it did.)

### 1.3 Transition table

| # | From | Event | Guard | Action | To | Observable |
|---|---|---|---|---|---|---|
| 1 | `Idle` | `begin_handshake()` | — | Draw a **never-used** sid, build the M1, emit it | `Handshaking` | M1 fragments |
| 2 | `Handshaking` | M2 assembles and the server signature verifies | — | Derive the master, **create** the session (unconfirmed), cache the M3, drop the machine, emit the M3 **plus a liveness probe** | `Unconfirmed` | M3 + probe |
| 3 | `Handshaking` | M1 budget exhausted / overall handshake deadline | — | Drop the machine, `Closed{HandshakeTimeout}` | `Idle` | `Closed{HandshakeTimeout}` |
| 4 | `Unconfirmed` | an authenticated server packet decrypts (data, cover or ack) | — | Open the D15 gate, reset the liveness counter, roam the peer | `Established` | `Ready` |
| 5 | `Unconfirmed` | `confirm_timeout` (30 s) elapses | — | Send an encrypted `Close`, drop the session (keys zeroized), `Closed{NotConfirmed}` | `Idle` | `Close` + `Closed{NotConfirmed}` |
| 6 | `Established` | N consecutive unanswered liveness rounds | `rounds_unanswered ≥ liveness_rounds` | Send an encrypted `Close`, drop the session, `Closed{PeerUnresponsive}` | `Idle` | `Close` + `Closed{PeerUnresponsive}` |
| 7 | any | peer `Close` (0x03) | — | Drop the session (no `Close` in reply), `Closed{PeerClosed}` | `Idle` | `Closed{PeerClosed}` |
| 8 | any | lifetime cap reached | `now − prepared_at ≥ lifetime_cap` | Send an encrypted `Close` (retransmitted), drop the session, `Closed{LifetimeCap}` | `Idle` | `Close` + `Closed{LifetimeCap}` |
| 9 | any | nonce counter exhausted | — | Drop the session, `Closed{NonceExhausted}` | `Idle` | `Closed{NonceExhausted}` |
| 10 | any | app-driven close | — | Send an encrypted `Close` (retransmitted), drop the session, `Closed{UserClosed}` | `Idle` | `Close` + `Closed{UserClosed}` |

`prepared_at` is the moment the **M3 was transmitted** — the origin of the
client's lifetime clock *and* of the confirmation deadline.  The server's
clock starts when the M3's Finished MAC verifies.  The two clocks therefore
differ by ≈1 RTT plus the server's M3-processing latency, **not** by the
whole retransmission budget; the `Close` message is what makes the semantics
exact (the clocks are never assumed to agree).

### 1.4 Routing

* Handshake fragments reach the handshake machine **only while the M2 is
  awaited**.  Once the M3 is emitted the machine is gone, so a late or
  duplicated M2 fragment is stale and dropped.
* Non-handshake packets (data / cover / close / in-session control) go to
  the prepared or established session if one exists, and are dropped
  otherwise.  The **prepared session takes priority over the handshake
  machine** — this is the fix for B2 and it is what makes fast confirmation
  possible.
* The **sid (bytes 1..9) is compared against the session's sid before the
  decrypt**, on both roles.  A packet for an unknown sid costs no AEAD work.
  Without this, the previous session's cover traffic (195 pkt/s) cost a full
  AEAD attempt each, forever.

---

## 2. The D15 gate

**Preserved, not weakened.**

* Inbound **application data** is delivered only after an authenticated
  server packet has decrypted.  The first authenticated server packet *is*
  delivered (it is authenticated; withholding it would break the
  request/response shape the gate exists to protect).
* A **cover** packet and an in-session **ack** are authenticated server
  packets too, so they confirm the session just the same.
* Outbound is deliberately **not** gated.  The baseline's reason ("gating
  would deadlock request/response flows with a passive server after
  re-establishment") is still correct, but it was stated as if the outbound
  path were free of consequences.  It is not:
  * before the session exists there is nothing to encrypt with, so the
    payload is **buffered** (§6) — not dropped, and not injected into the
    tunnel long after the application sent it;
  * in the **unconfirmed window** the session *does* exist, so the payload is
    encrypted and sent even though the peer may not yet hold the session (the
    M3 may be in flight).  Such data is **lost at the peer**, with no signal
    to the application either way.  This is the price of not gating the
    outbound (D15) and it is accepted: the alternative is a request/response
    deadlock against a passive server.
* The confirmation deadline is a single, named deadline (§3.2).  The client
  never accepts unauthenticated server data, and the replay/nonce state is
  never reset to make reconnection easier.

---

## 3. Liveness

### 3.1 The in-session control message

`MessageType::Handshake` (0x00) — a type that **already exists** in the
protocol's type space — is given a meaning.  This is a *semantic extension of
an existing authenticated type*: **no new wire bytes, no new framing, no
change to the AAD, the nonce construction, the KDF, the transcript or the
replay window.**  The message rides the ordinary encrypted session slot.

Sub-type in `payload[0]`:

| Value | Meaning | Behaviour |
|---|---|---|
| `0x01` | liveness **probe** | The server answers with an ack to that session's peer.  Consumed internally: never relayed to the application, never charged to the failure gate. |
| `0x02` | liveness **ack** | Confirms the key agreement (D15).  Consumed internally. |
| anything else | unknown | **Ignored**: no state change, no failure-gate charge. |

The client is the *prober* in this version.  A client that receives a probe
ignores it (no reply): the server is the only role that answers, so the
client's D19 grid is never perturbed by an unsolicited answer.

### 3.2 One deadline, named once

The baseline armed **two** competing deadlines on the unconfirmed path: the
M3 retransmission budget (≈7.75 s) and the `liveness_timeout` (30 s).  The
budget always fired first, which made the probe period dead code and
"≈1 RTT confirmation" unreachable.

| Knob | Value | Role |
|---|---|---|
| `confirm_timeout` | 30 s | The **only** deadline on the unconfirmed path.  Pre-confirmation only. |
| `liveness_probe_interval` | 5 s | The post-confirmation heartbeat interval. |
| `liveness_rounds` | 3 | The number of **consecutive unanswered** rounds after which the peer is declared dead. |
| `m3_max_attempts` | 4 | A **retransmission policy**, not a deadline.  When it is spent the M3 stops; the session stays prepared and the client keeps probing until `confirm_timeout`. |

The two liveness knobs are **distinct fields**, not one overloaded
`liveness_timeout`.  The post-confirmation decision is made on N
*consecutive* rounds, never on a single timeout: transient packet loss must
not kill a healthy session.

### 3.3 The probe replaces a cover slot (client side only)

The **client** emits **at most one packet per session slot**.  A slot is
filled by, in order:

1. a buffered application payload (the outbound flush),
2. a due liveness probe, or
3. cover traffic.

A probe therefore **replaces** a cover packet rather than adding to it, and
the D19 grid's rate is invariant in the client-to-server direction.  While the
cover schedule is running the cover arm owns the slot; when it is not running
(cover disabled, or the session not yet confirmed) a dedicated session-slot
arm owns it, so the probe and the flush still flow.

*Documented deviation, server side:* the **server's ack is additive**.  The
server has no session slot: the ack is emitted immediately on the probe, in
addition to the cover packet the cover arm emits.  The server-to-client rate
is therefore `195.3 (cover) + 0.2 (ack) = 195.5 pkt/s` — a constant `+0.1 %`
— with one extra packet per probe period, at a fixed 5 s cadence.  This is a
new metadata residual and is recorded in `THREAT_MODEL.md` §13; it is **not**
claimed to be covered by the D19 grid invariant, which holds for the client's
outbound only.

*Documented deviation:* in the **unconfirmed window** the probe is not on the
cover grid, because the cover schedule is not running yet (it starts at
`Ready`).  That window is bounded by `confirm_timeout` and is part of the
establishment phase, which is inherently off-grid (M1/M2/M3 already are).

### 3.4 The probe keeps the server's session alive

This only becomes meaningful once **B4** is fixed: `last_activity` tracks
**authenticated receives only**, so the server's own cover emissions and
application replies no longer refresh the idle clock.  Then

* the client's probe (an authenticated receive) keeps a live-but-quiet
  session alive, and
* a departed peer's session is reaped within `idle_timeout`.

The configuration invariant `idle_timeout > liveness_probe_interval` is
**validated at construction** (fail closed): otherwise the server would evict
a live client before its probe arrives.

---

## 4. The session-lifetime cap

| Item | Decision |
|---|---|
| Spelling | `--lifetime-cap-secs` on **both** the client and the server; `0` means unbounded.  This is D27 §1's recommended spelling. |
| Default | 24 h (86400 s) at the **product surface**; the **core** `SessionLimits::default().lifetime_cap` stays `None` so library users are unaffected. |
| Clock | Starts at the **M3 transmission** (client) / the Finished-MAC verification (server). |
| Convergence | When the cap fires the endpoint sends an **encrypted `Close`** to the peer before dropping the session.  The `Close` is the convergence mechanism: the two clocks are never assumed to agree. |
| Retransmission | The `Close` is retransmitted up to **3 times** (1 s / 2 s backoff).  A fire-and-forget `Close` over UDP can be lost, which would strand the peer for a whole cap period. |
| After the cap | The client tears down and re-establishes (D16: fresh sid, fresh ephemerals, fresh master).  The server tears down and stays down for that sid; the client's re-handshake creates a new session. |
| Exposure bound | **Per side: `cap + ≈4 s`** — the cap itself, plus ≤1 s of 1 Hz tick granularity, plus ≈3 s during which the `Close` is retransmitted and the session (and therefore its traffic keys) is still held.  The **union** across the two endpoints is `cap + Δ + 4 s`, where Δ is the offset between the two clocks (the server's M3-processing latency, ≈1 RTT in practice, **not bounded** under server overload).  The **per-side** bound is the D16 property and is hard; the union is not a hard bound and is not relied upon.  See below. |
| Simultaneous close | Both sides cap at once ⇒ both send `Close` ⇒ each may receive a `Close` for a session it just closed.  That is a **graceful, silent drop** (the sid is unknown to the receiver): not an error, and not charged to the failure gate. |
| Clock skew | Irrelevant: the `Close` carries the truth, not the clock. |

The client also sends a `Close` on the **failed-establishment** path
(`NotConfirmed`), so the server does not accumulate orphan sessions for a
client that never came up.  With B4 fixed, the server's idle timeout reaps
any that still leak.

### 4.1 The exposure bound, precisely

Each endpoint runs its **own** monotonic clock, so the per-side window carries
**no RTT term at all**:

* **Client side**: `prepared_at` (the M3 transmission) → `prepared_at + cap`,
  plus ≤1 s of tick granularity, plus ≈3 s of `Close`-retransmission key
  retention ⇒ **cap + ≈4 s**.
* **Server side**: `established_at` (the Finished-MAC verification) →
  `established_at + cap`, plus the same ≈4 s ⇒ **cap + ≈4 s**.
* **Union** (any traffic key alive at time T): **cap + Δ + ≈4 s**, where Δ is
  the offset between the two clocks.  Δ is the server's M3-processing latency
  plus its event-loop queueing delay; it is ≈1 RTT in practice and is **not
  bounded** under server overload.

The per-side bound is the D16 property and it is hard.  The union is not a
hard bound and nothing relies on it.  Two consequences are recorded
explicitly:

* The bound holds **only if both endpoints enforce the cap**.  With
  `--lifetime-cap-secs 0` on either side, that side's window is unbounded
  (bounded only by the peer's idle timeout, if the peer has one).
* The `Close`-retransmission window is a deliberate trade: the traffic keys
  live ≈3 s past the teardown so the peer can be told.  It is bounded and
  pinned by a test (`the_session_keys_are_released_after_the_close_retransmission_budget`).

---

## 5. The failure gate (D24) — what may spend a token

> A token is consumed **only** when an AEAD decrypt actually fails.

The baseline collapsed every per-packet rejection into one error class, so a
**successfully decrypted** packet — and a **replayed but authentic** packet —
was charged to the source's failure budget.  An off-path attacker who
captured 64 packets from the victim's source port could drain the victim's
budget and get its legitimate traffic dropped for a whole window.

The error taxonomy is now split, **locally only**:

| Class | Meaning | Failure-gate charge |
|---|---|---|
| `CodecError::DecryptionFailed` | The AEAD tag did not verify. | **yes** |
| `CodecError::Rejected` | Everything else: a replayed counter, invalid inner framing, a direction mismatch, a wrong version byte. | **no** |

The *wire* behaviour is identical for both classes (silent drop, no reply,
no error datagram), so the "uniform rejection" property of the wire is
preserved exactly; only the **local** accounting distinguishes them.

---

## 6. The bounded outbound queue

Application data pushed while the client has no session used to be dropped
silently (`Err(NoSession) => {}` — no log, no counter, no notification).

| Property | Value |
|---|---|
| Capacity | **64** entries, explicitly bounded (an unbounded buffer turns a stalled tunnel into a memory-exhaustion vector). |
| Overflow policy | **Drop-newest.**  The oldest request is the one the application is still waiting for, so it is never the one discarded. |
| Per-entry TTL | **≤ 2 s.**  A stale datagram is not injected into the tunnel long after the application sent it. |
| Survival | The queue survives a re-establishment (the application asked for it) and is flushed onto the new session. |
| Pacing | The flush is **rate-paced through the session slot** — one payload per slot, never a burst. |
| Reporting | An exact cumulative **drop counter**, exposed as `ManagerNotification::OutboundDropped { dropped }`, plus a rate-limited log. |

---

## 7. Compatibility

### 7.1 The wire format is unchanged

No new message type, no new framing, no change to the AAD, the nonce
construction, the KDF, the transcript, the handshake or the `ReplayWindow`.
`MessageType::Handshake` (0x00) already existed and was dropped by both data
paths; giving it a meaning is a semantic extension of an existing
authenticated type.

**One protocol-lifecycle clarification, documented in PROTOCOL_SPEC §8.3:**
the protocol-level `ESTABLISHED` state means *the session layer is live* (the
keys are derived, the nonce state is active).  It does **not** assert that the
peer holds the same master.  Key **confirmation** is a separate fact, tracked
by the endpoint and confirmed by the first authenticated server packet that
decrypts (D15).  The client manager owns that fact (`ClientManagerState`:
`Unconfirmed` vs `Established`, §1.1), not `ProtocolState`.  This matters
because the client now creates its session at the M3 transmission rather than
after the retransmission budget was spent.

`PROTOCOL_VERSION` stays **1**.  It is checked with strict equality on both
sides, so cross-version peers are already impossible: a version bump would
not enable a mixed deployment, it would only *break* one that the strict
equality already forbids.

### 7.2 The mixed-build behaviour (a new client against an old server)

| Configuration | Behaviour | Severity |
|---|---|---|
| New client, **old** server, cover **on** | The old server maps the probe to its "unexpected inner type" path and drops it — and, in the baseline, **charges its failure gate** once for it (baseline defect B8).  At one probe per 5 s the 64-token burst is never reached, so the effect is negligible.  The old server's cover traffic keeps the client satisfied, so the session works exactly as before. | **none** |
| New client, **old** server, `--no-cover` | The old server never answers the probe.  The client stays `Unconfirmed` until `confirm_timeout` (30 s), then re-establishes.  The tunnel therefore re-handshakes every confirm window. | **degraded, not a security break**: the data path is unchanged, the keys are still correct, the traffic is still authenticated.  The observable cost is a periodic re-handshake (an M1/M2/M3 burst every 30 s). |
| **Old** client, new server | The old client never sends a probe.  With cover enabled (the default) the old client's **own** cover traffic is an authenticated *receive* at the new server and therefore keeps its `last_activity` fresh, so the session is **not** reaped and there is **no** churn.  With `--no-cover` on the client nothing refreshes the clock, and the session is reaped after `idle_timeout` (5 min), at which point the old client re-establishes. | **degraded with `--no-cover` only**: a periodic re-establishment.  The old client keeps working; it just churns.  With cover on (the default) there is no degradation at all. |

Neither direction is a security break: no key material is reused, no
authentication is weakened, and no data is accepted that was not
authenticated.

### 7.3 The version-bump question

**No bump is required, and none was made.**  The extension is confined to the
*meaning* of an already-authenticated type; a peer that does not know the
meaning ignores the message.  The remaining question — whether the project
wants a *negotiated* capability bit so a new client can detect an old server
and fall back to the "wait for the confirm window" behaviour instead of
re-handshaking every 30 s — is a **human decision** (§9, item 3).  It would
require a wire change and therefore a version bump, and it is not needed for
correctness.

---

## 8. The sixteen baseline defects

Line references are to the tree that implements this document
(`pq-tunnel-core/src/…` unless stated).  They are a convenience, not the
contract: the **symbol names** in each row are authoritative, because line
numbers drift as the file changes.

| # | Defect | Status | Evidence |
|---|---|---|---|
| **B1** | The client created its session only after the M3 budget was exhausted. | **FIXED** | `session_manager.rs:1487` (`on_m3_sent` creates the session at the M3 transmission); `handshake_v2.rs:1140` (the M3-budget arm is now an explicit `Err(Timeout)`, never a success). |
| **B2** | The handshake machine swallowed every non-M2 datagram. | **FIXED** | `session_manager.rs:1459` (`ClientSessionManager::handle_datagram`) — handshake fragments reach the machine **only while it exists**; the prepared session takes priority for everything else. |
| **B3** | `not_confirmed` was gated on `!self.ready` ⇒ no post-confirmation peer-loss detection. | **FIXED** | `session_manager.rs:1789` (`take_probe`: the liveness rounds are counted only on a confirmed session) and `session_manager.rs:1879` (the `PeerUnresponsive` decision). |
| **B4** | The server refreshed `last_activity` on its own outbound traffic. | **FIXED** | `session_manager.rs:838` (refreshed on an authenticated receive only); `session_manager.rs:1000` (`cover_packet`: outbound does **not** refresh it). |
| **B5** | The two endpoints' clocks differed by ≈6–9 s. | **FIXED** | The client's clock starts at the M3 transmission (`prepared_at`, `session_manager.rs:1521`); the server's at the Finished-MAC verification.  The residual is ≈1 RTT. |
| **B6** | `lifetime_cap` defaulted to `None`. | **FIXED (product surface)** | The core default stays `None` (`session_manager.rs:198`, `SessionLimits::default`); the CLI default is 86400 s (`pq-tunnel-bin/src/lib.rs`, `--lifetime-cap-secs`). |
| **B7** | The cap path emitted no `Close`. | **FIXED** | `session_manager.rs:1065` (`begin_close`) and `session_manager.rs:1145` (`retransmit_closes`); the server's `tick` (`session_manager.rs:1096`) and `close_session` (`session_manager.rs:1048`) both send it. |
| **B8** | A decrypted control message was charged to the failure gate. | **FIXED** | `session_manager.rs:848` — `MessageType::Handshake` ⇒ `DataResult::Control` ⇒ `on_control_message` (`session_manager.rs:903`) ⇒ no charge. |
| **B9** | A replayed authentic packet was charged to the failure gate. | **FIXED** | `session_manager.rs:893` — `CodecError::Rejected` ⇒ `DataResult::Rejected` ⇒ no charge; only `DataResult::Failed` (an AEAD failure) charges (`session_manager.rs:888`). |
| **B10** | Application data pushed while handshaking was dropped silently. | **FIXED** | `session_manager.rs:1924` (`enqueue`: the bounded queue, drop-newest; the cap is `session_manager.rs:1212`) + `ManagerNotification::OutboundDropped`. |
| **B11** | The client decrypted any datagram with whatever session it held, without comparing the sid. | **FIXED** | `session_manager.rs:1573` — the sid is compared **before** the decrypt (both roles; the server already did). |
| **B12** | `establish` recreated the session (reset send counter + fresh replay window). | **FIXED** | `session_manager.rs:1493` (a second outcome is refused) and `session_manager.rs:2030` (`retire_sid`: a torn-down sid is retired). |
| **B13** | `begin_handshake` refused while a session existed ⇒ the driver exited ⇒ the tunnel stayed down. | **FIXED** | The one-live-object invariant (`session_manager.rs:1501`: the machine is dropped at the M3) + `begin_handshake` (`session_manager.rs:1404`) + the `needs_rearm()` backstop (`session_manager.rs:1390`) + a non-fatal `rearm_client`. |
| **B14** | `rate_ok` ran before the pending-entry lookup on the M3 path. | **FIXED** | `handshake_v2.rs:1977` — the entry is resolved first, then gated. |
| **B15** | `random_sid()` had no reuse check. | **FIXED** | `session_manager.rs:1425` — `fresh_sid` draws from a bounded history of never-used sids. |
| **B16** | The cached-M2 resend did not refresh `last_seen`. | **FIXED** | `handshake_v2.rs:1836` — the `AwaitM3` branch refreshes `last_seen`. |

---

## 9. Human decision gate

1. **The 24 h value and where the default lives.**  The core default stays
   `None`; the CLI default is 86400 s.  The integrator's call: keep the CLI
   default, or set it to `0` (unbounded) until the cap is signed off.  Both
   are one-line changes.
2. **Whether unbounded may ever be the product default.**  A single
   `--lifetime-cap-secs 0` restores unbounded exposure silently.  D27 §1
   asked whether that needs a separately-named flag (mirroring `--no-cover`).
3. **Capability negotiation.**  §7.3: a new client cannot tell an old
   server from a silent one, so it re-handshakes every confirm window under
   `--no-cover`.  A negotiated capability bit would fix that but needs a
   wire change and a version bump.
4. **The probe period (5 s) and the round count (3).**  A detection bound of
   ≈3 × (5 s + RTT) with cover disabled, against a server idle timeout of
   5 min.  Both are parameters (D7), but the *ratio* between the probe
   period and the idle timeout is a security-relevant choice.
5. **Whether the server should also probe.**  Today the server reaps a
   departed peer by idle timeout only; a server-initiated probe would detect
   a client that vanished faster but would add traffic to the server's grid.
6. **The `Unconfirmed` name.**  The state is *authenticated but not key
   confirmed*; the name is a compromise between precision and brevity.

---

## 10. Verification

**`pq-tunnel-core` (300 unit tests, all passing).**  The new tests:

| Test | What it pins |
|---|---|
| `client_m3_sent_yields_unconfirmed_then_established` | Test 1: the session exists at the M3, in the **unconfirmed** state; the ack confirms it. |
| `application_data_before_confirmation_is_buffered_not_lost` | Test 2: the payload is buffered and flushed through the session slot, one per slot. |
| `confirmation_lost_delayed_duplicated_and_reordered` | Test 3: lost / delayed / duplicated / reordered confirmations. |
| `m3_budget_exhaustion_is_never_a_success_and_retries_fresh` | Test 4: the budget is a policy, not a deadline; the deadline is explicit; the retry uses a fresh sid. |
| `dead_peer_is_detected_within_the_liveness_bound` | Test 5: N consecutive unanswered rounds ⇒ `PeerUnresponsive`; the tunnel recovers. |
| `lifetime_cap_closes_and_both_endpoints_converge` | Test 7: the cap sends an encrypted `Close`; the peer converges. |
| `a_lost_close_is_covered_by_the_peers_own_cap` | Test 7: when the client's `Close` is lost entirely, the **server's own cap** still converges — this is what makes "both ends enforce the cap ⇒ bounded exposure" true. |
| `the_session_keys_are_released_after_the_close_retransmission_budget` | The exposure bound of §4.1: the retained session (and its traffic keys) is dropped once the `Close` budget is spent. |
| `lost_close_is_retransmitted_and_the_peer_converges` | Test 8: a lost `Close` is retransmitted and the peer converges. |
| `lost_confirmation_is_recovered_by_the_next_probe_round` | Test 8: a lost confirmation does not kill a healthy session. |
| `replayed_server_packet_is_rejected_and_nonce_state_is_never_reset` | Test 9: the replay is rejected; a late event cannot create a second session. |
| `outbound_queue_is_bounded_drops_newest_and_expires` | Test 10: overflow drops the newest, the count is exact, entries expire. |
| `readiness_is_one_round_trip_not_the_m3_budget` | Test 12: the client is ready in ≈1 RTT, with **no** M3 retransmission. |
| `control_message_and_replay_consume_no_failure_token` | Test 13: neither a control message nor a replay spends a token; an AEAD failure does. |
| `server_idle_eviction_counts_receives_only` | Test 14: a departed peer is reaped. |
| `a_live_but_quiet_peer_is_not_reaped` | Test 14: a probe-driven peer is not. |
| `simultaneous_close_is_graceful` | A simultaneous close is a silent drop, not an error, and not charged to the gate. |
| `begin_handshake_succeeds_after_every_teardown_path` | Test 15: after every teardown path, and every sid is distinct. |
| `b14_retransmitted_m3_for_a_consumed_sid_costs_no_rate_token` | The B14 regression. |
| `b16_duplicate_m1_refreshes_the_pending_entry` | The B16 regression. |

**`pq-tunnel-bin/tests/client_lifecycle.rs` (4 tests).**  The driver-level
behaviour: a dead peer must not kill the driver; application data pushed
during the handshake must be **delivered** (the test drives it through a live
server and asserts the server receives every payload, so it fails against the
pre-fix code, which dropped them all); the drop counter must reach the
application; a vanished peer must be detected by the liveness rounds.

**`pq-tunnel-bin/tests/revocation_lifetime.rs` (13 tests).**  Updated for
the new `Close`-on-teardown behaviour and the `liveness_timeout` →
`confirm_timeout` rename.  Two assertion changes are recorded here so they
are visible rather than silent:

* `only_close_reason` now filters the `SendPacket` events (the `Close`
  packets the cap now emits) out of the event list and asserts on the
  `Closed` events alone.  The number of `Close` packets is asserted
  separately by `close_packets`, so the two properties are still both pinned.
* The `paused_before_m3` / `established` helpers take the M3 outcome from the
  `M3Sent` event instead of spending the retransmission budget.

**`pq-tunnel-bin/src/lib.rs` (3 tests).**  The `--lifetime-cap-secs` spelling
(`0` means unbounded) and the **shipped** default of 86400 s on both roles —
the shipped default is the single line that decides whether the binaries
enforce D16's exposure bound, and nothing else in the tree would notice a
change to it.

**`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
`cargo test --workspace` are clean** on `x86_64-pc-windows-msvc`.
