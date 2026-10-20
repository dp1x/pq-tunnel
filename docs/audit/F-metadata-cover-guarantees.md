# Track F — Metadata / Cover-Traffic Guarantees Audit

> **This is an internal self-assessment, not an audit.** Everything below was
> produced and checked by the Tunnel project's own authors, in-tree. **No
> independent third party has reviewed, verified, endorsed or approved any of
> it**, and nothing in this document constitutes assurance or a third-party
> statement of correctness. The project's own disclaimer stands: *"No
> independent third-party security audit has been performed."* The "audit" in
> the title names the *method* (a static-source gap-finding pass), not an
> external reviewer.

**Track:** F (re-run) · **Scope:** cover-traffic guarantees, aggregate cost, idle/lifetime coupling
**Date:** 2026-10-05 · **Status:** analysis only, documentation only, no source modified, nothing committed.
**Method:** static source reading only. **New measurements: NOT MEASURED.** D23/M9A empirical
numbers are cited as prior art from `THREAT_MODEL.md` §13.5 and `docs/performance/I-benchmark-methodology.md`.

**Scope guard honoured:** D22 (metadata target = reduction, not anonymity; absorbing emission
explicitly **not** adopted) is treated as settled and is not re-litigated. Every item below is
checked against D22's boundary and only genuinely new leakage is claimed as NEW.

---

## 1. The constant-rate floor — what it actually guarantees

### 1.1 Call sites (both sides confirmed)

| Role | File:line | Mechanism |
|---|---|---|
| Client driver, cover arm created | `pq-tunnel-core/src/session_manager.rs:1219-1222` | `CoverScheduler::new(cover)`, pinned sleep arm |
| Client driver, arm **started** on ready | `session_manager.rs:1237-1240` | `cover_sched.start(Instant::now())` when `is_ready()` first true |
| Client driver, **tick** → emit | `session_manager.rs:1363-1382` | `_ = &mut cover_arm => if cover_sched.on_deadline(now) { manager.cover_packet() }` |
| Client driver, stopped on Close | `session_manager.rs:1288`, `:1305`, `:1338` | `cover_sched.stop()` then D16 re-arm |
| Server driver, cover arm created | `session_manager.rs:1073-1076` | `CoverScheduler::new(cover)` |
| Server driver, arm **started** on `Established` | `session_manager.rs:1110-1112` | `cover_sched.start(Instant::now())` |
| Server driver, **tick** → emit to *all* sessions | `session_manager.rs:1170-1190` | `manager.cover_packet_all()?` |
| Server driver, stops at zero sessions | `session_manager.rs:1185-1188` | `if manager.session_count() == 0 { cover_sched.stop() }` |
| Scheduler policy/timing (pure, tokio-free) | `pq-tunnel-core/src/scheduler.rs:85-147` | `CoverPolicy`, `on_deadline` |
| CLI → policy (both binaries) | `pq-tunnel-bin/src/v2_server.rs:55`, `v2_client.rs:50` → `pq-tunnel-bin/src/lib.rs:152` | `cover_policy_from_args(args.no_cover, args.cover_mbps)` |

So `CoverScheduler` is reached from **both** the client and server drivers. Confirmed.

### 1.2 The precise statement

Constants: `PACKET_SIZE = 1280` (`codec.rs:104`), `DEFAULT_COVER_RATE_BPS = 2_000_000`
(`scheduler.rs:36`), and the exact integer interval function
`interval_from_rate_bps` (`scheduler.rs:71-76`):

```
interval_ns = PACKET_SIZE_bits * 1_000_000_000 / rate_bps
            = 1280 * 8 * 1e9 / 2_000_000
            = 10_240 * 1e9 / 2_000_000
            = 5_120_000 ns = 5.12 ms exactly
```

Asserted in-tree at `scheduler.rs:163` and `scheduler.rs:169-175`.

**Claim (what the floor actually guarantees):** for an *established* session in each direction, the
driver emits one 1280-byte encrypted record per 5.12 ms tick, i.e. **195.3125 packets/s**
(10 240 bits ÷ 5.12 ms), indefinitely, **including while completely idle**. This matches D19's
decision bullet 3 ("No 'only-when-data' behaviour: an established idle session keeps emitting",
`DESIGN_DECISIONS.md:952-954`) and D22/§13.4's "deterministic 195.3 pkt/s grid per direction"
(`THREAT_MODEL.md:510-512`).

Qualifiers that must travel with the claim:

- Cover is armed **only while a session is established**. The client emits nothing during
  handshake establishment (measured cover onset p50 7.78 s, `THREAT_MODEL.md:586-590`). The server
  covers from its own `Established` onward. This asymmetry is accepted residual under D22
  (`THREAT_MODEL.md:570-573`, §13.6 disposition C).
- The *emission count* is exact; the *wall-clock cadence* is not. D23 measured p50 5.5 ms (server
  182.6 pkt/s ≈ 93.5 % of nominal) over a 30 s loopback run, uniform per-second counts 178-185
  (`THREAT_MODEL.md:543-549`). Prior art, not re-measured here.
- "Exactly one per 5.12 ms" holds in *packet count* per tick, not in absolute time alignment. D19
  explicitly rejects wall-clock alignment as the invariant (`scheduler.rs:26-27`, `DESIGN_DECISIONS.md:930-934`).

---

## 2. The un-capped aggregate — the key finding

### 2.1 What the code does

`cover_packet_all` (`session_manager.rs:562-573`):

```rust
pub fn cover_packet_all(&mut self) -> Result<Vec<ManagerEvent>, ManagerError> {
    let mut sids: Vec<[u8; SESSION_ID_LEN]> = self.sessions.keys().copied().collect();
    sids.sort_unstable();
    let mut out = Vec::with_capacity(sids.len());
    for sid in sids {
        match self.cover_packet(&sid)? { /* ... */ }
    }
    Ok(out)
}
```

It iterates the **entire session map**, one 1280-byte AEAD record per established session, per tick.
Each of those becomes an unconditional `transport.send_to(...)` at `session_manager.rs:1173-1175`.

### 2.2 Is there any global rate limiter? — No.

Searched the workspace for `rate_limit|global_cap|token_bucket|MAX_SESSIONS|max_sessions|aggregate|per_session_cap|budget`.
Every hit is either:

- a **per-source handshake** limiter — `ServerConfig::rate_limit_burst = 16` per 10 s
  (cited at `bench/src/handshake.rs:53`, `session_manager.rs:3195-3199`, D24), which charges on
  the *completing M1 fragment* (`handshake_v2.rs:1536`) and has nothing to do with egress; or
- the per-session **failure** gate (`fail_gate_peek` / `fail_gate_consume`,
  `session_manager.rs:645+`, D24) which counts decrypt *failures*; or
- `max_sessions = 64` (`session_manager.rs:139`), an entry-count bound, not a rate bound.

**There is no aggregate, per-server, per-process egress rate limiter over cover traffic anywhere
in the codebase.** The only bound on server cover egress is the session-table cardinality
(`max_sessions`, default 64, `session_manager.rs:139`) combined with the per-session fixed rate.

### 2.3 The arithmetic

Per session, per direction:

```
rate = DEFAULT_COVER_RATE_BPS = 2_000_000 bit/s
    = 2 Mbit/s = 250 000 B/s (application bytes)
    = 195.3125 pkt/s  (250 000 / 1280)
```

At the default `max_sessions = 64`, server egress, one direction:

```
64 sessions x 195.3125 pkt/s            = 12 500.0 pkt/s
12 500.0 pkt/s x 1280 B/pkt              = 16 000 000 B/s
16 000 000 B/s x 8                       = 128 000 000 bit/s
                                       = 128 Mbit/s = 0.128 Gbit/s
```

Both directions combined: **256 Mbit/s**. This matches `docs/performance/I-benchmark-methodology.md:575-585`
("= 128 000 000 bit/s = 128.000 Mbit/s = 0.1280 Gbit/s for a fully loaded server, cover enabled,
one direction. Both directions would double this to 0.256 Gbit/s") — i.e. this audit **re-derives
rather than discovers** that number; the documentation was already there.

Per-session figure (2 Mbit/s) is the guarantee side; the 128 Mbit/s figure is the **unguarded
aggregate** side. The gap between them is the finding: nothing in the code, the CLI, or the threat
model ties operator egress cost to the session count.

### 2.4 Exploitability: pre-auth or post-auth?

**Post-authentication only.** Establishing a session requires completing M1/M2 against the
server's roster, and M1 verifies an ML-DSA-65 signature against a roster entry
(`handshake_v2.rs:1617-1630` per D29 §8 item 8). There is no unauthenticated path into
`self.sessions`:

- the data path drops any datagram naming an unknown sid before allocating or decrypting
  (`session_manager.rs:455-457`, D24 lookup-first);
- pending-handshake state is separate, bounded by `max_pending = 64` with a 30 s TTL, and is not
  a `sessions` entry (D29 §9 rows 1-2).

So an adversary cannot force 64× cover bandwidth anonymously. A flooder with one source address is
additionally bounded by the per-source handshake budget: `rate_limit_burst = 16` per 10 s
(`handshake_v2.rs:1287`), charged on the *completing M1 fragment* (`handshake_v2.rs:1536`, D24) —
at most 1.6 completing handshakes/s/address, hence at most **3.2 Mbit/s** of cover amplification per
source address. Reaching 64 sessions (128 Mbit/s) requires 64 *roster members*, or one member
churning through LRU eviction (`session_manager.rs:415`): 64 is reached by legitimate accumulation,
not by one flooder. What a roster member can then do:

- hold N sessions established and never send application data → the server emits 2N Mbit/s
  forever, from authenticated-but-idle sessions;
- because `idle_timeout` cannot fire while cover is on (§5 below), those sessions are **held open
  by the server's own cover emissions**, so the member needs to send almost nothing to sustain the
  cost — only its own cover return path and periodic liveness. One member holding 64 sessions costs
  the operator ≈ USD 2 074/month (§4.3).

**This is a resource-exhaustion / cost-amplification surface for a legitimate insider or a
compromised member credential, not a pre-auth DoS.** THREAT_MODEL §7.1 already scopes out "the
volume of traffic a legitimate key-holder sends" as out of scope for availability
(`THREAT_MODEL.md:334-337`). So the *class* is known; what is **new** here is that the server's own
cover traffic — not the member's own data — is the thing being multiplied, and that it is
multiplied by an operator-side cost the operator never chose. Per D7 this is a tradeoff parameter
gap, not a guarantee redefinition: capping aggregate egress is an operator-configurable resource
bound, the same family as `max_pending` / `max_sessions` / `MAX_RATE_BUCKETS`.

Scope of "operator never chose": `--cover-mbps` tunes the *per-session* rate
(`pq-tunnel-bin/src/lib.rs:152-167`, `--cover-mbps 1` on a 64-session server still yields
64 Mbit/s). There is no CLI surface expressing an aggregate egress target.

---

## 3. Limits under an adaptive observer (beyond D22's λ·W)

D22 / `THREAT_MODEL.md` §13.4 bounds **content and volume** above the floor: λ·W ≥ 1, additive
emission, and — already recorded — "Session count on a server is observable per tick (one cover
packet per established session; batch size is exact), and session liveness, handshake/rekey/close
events are visible by construction" (`THREAT_MODEL.md:515-520`).

### 3.1 Censorship by packet counting — **KNOWN**

Session count and liveness are observable **by construction** because the tick emits exactly N
packets. This is stated verbatim in `THREAT_MODEL.md:515-517`, inside §13.4. It is also consistent
with D25/D26 §1.12 item 4, which records the session-liveness residual ("a user who brings the
client up and never uses it emits a constant 2 Mbps stream indefinitely while a user who never
starts the client emits nothing") as accepted-by-design
(`docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:551-556`). **Not new.**

### 3.2 Scheduler jitter fingerprinting (host timer granularity / power states) — **NEW**

D19's `on_deadline` reschedules from *now*:

```rust
Some(due) if now >= due => { self.next = Some(now + self.policy.interval); true }
```
(`scheduler.rs:140-144`)

So the grid is defined *relative to OS wakeups*, not against an absolute schedule. Two consequences
an observer can read off the inter-arrival distribution:

1. **Timer granularity fingerprinting.** The observed period is
   `interval + ε(wakeup)`. If ε quantises to the host's timer resolution, the empirical
   distribution of inter-arrival times carries that quantum. D23 measured p50 5.5 ms / p90 5.8 /
   p99 6.0 ms on a specific Windows host with
   `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` (`scheduler.rs` M9A design; `THREAT_MODEL.md:543-548`).
   A host without high-resolution timers would present a coarser quantum — a **host-class
   discriminator**, not merely a cadence statistic.
2. **Power-management state fingerprinting.** When the host suspends, throttles, or the scheduler
   preempts the timer thread, the *first* emission after the stall is delayed by the whole stall
   length (`next = now + interval` after a late wakeup). Over a long-lived session, gaps of
   duration ≈ a few seconds to minutes therefore mark **host idle/suspend transitions**, and
   multi-gap shapes mark scheduler-preemption events. This is a *host-activity* channel, distinct
   from the *tunnel-activity* channel D22 bounds.

**Why this is not covered by §13.4.** §13.4 states its bound over "extra packets per observation
window" — a **count** statistic under lossless capture — and explicitly separates itself from
timing: the D19/D6 invariant is "a protocol-level constant rate — a stable, observable pattern over
time — not perfectly timed packets" (`DESIGN_DECISIONS.md:930-934`), and
`scheduler.rs:26-27` repeats it. §13.5/§13.6 then dispose of the *cadence shortfall* by measuring
it as "constant and stationary" and "non-material" (`THREAT_MODEL.md:547-553`,
`DESIGN_DECISIONS.md:1157`). "Stationary" is exactly the assumption this item questions: a
stationary summary statistic is not the same as an absence of structure, and no capture above
5-30 s was analysed for conditional structure (a gap conditioned on host state). This is
**outside the λ·W counting bound**, so it is **NEW** relative to §13.4/§13.5.

Closest existing coverage: D25/D26 §1.12 item 4 names the *session-liveness* residual but only in
the coarse "client up vs client down" form; it does not name intra-session jitter as a
host-fingerprint channel. Label: **NEW (unmeasured)** — no experiment has been run to characterise
the jitter distribution conditioned on host state, so the *exploitability* is unestablished even
though the *channel* is derivable from the code.

### 3.3 What this does NOT claim

It does not claim the grid is a weakness per se. D19 chose relative re-arm deliberately, to avoid
burst accumulation, and the alternative (absolute schedule) leaks absolute time-of-day phase.
Both options leak something; the finding is that the *current* choice leaks host state and that
this trade has not been written down.

---

## 4. Bandwidth cost, honestly

### 4.1 Per-record framing overhead

Wire record is exactly `PACKET_SIZE = 1280 B` with
`HEADER_LEN = 1 (VERSION) + 8 (SESSION_ID) + 8 (PACKET_NONCE) = 17 B` (`codec.rs:85,107,108,133`)
and `AEAD_TAG_LEN = 16 B` (`codec.rs:109`). Therefore
`INNER_PLAINTEXT_LEN = 1280 - 17 - 16 = 1247 B` (`codec.rs:136`, asserted `codec.rs:145`).
Cover records carry a full 1247-byte padded plaintext slot (`send_encrypted` zero-pads,
`session_manager.rs:530-533`) and are therefore **not** smaller than data records.

Framing overhead per record = `(17 + 16) / 1280 = 33 / 1280 = 2.578 %`. Adding 2 B of assumed
UDP+IPv4 framing (8 B IPv4 + 8 B UDP) gives `(33 + 16) / 1280 = 49 / 1280 = 3.828 %`. Stating
both because "2.7 %" is only defensible against a 35-byte denominator; the code-verified
protocol framing is **33 B = 2.578 %**, and full network framing is **~3.8 %**.

**A second-order note:** the *configured* rate is `PACKET_SIZE x 8 x rate_bps` — the nominal
2 Mbit/s is already the full 1280-byte record, so framing is **not** on top of the configured rate
at all. It is on top only of the *useful* payload, which for a cover record is zero bytes (cover
carries a zero-padded 1247 B plaintext slot and no application content). In other words the honest
efficiency figure for cover is **0 payload bits per 10 240 record bits**; the 2.578 % is the cost of
*data* records' framing, which is the number that matters when comparing cover cost against
useful-throughput cost.

### 4.2 Per-session and aggregate

| Sessions | Per direction | Both directions |
|---:|---:|---:|
| 1 | 2 Mbit/s | 4 Mbit/s |
| 8 | 16 Mbit/s | 32 Mbit/s |
| 32 | 64 Mbit/s | 128 Mbit/s |
| **64 (default `max_sessions`)** | **128 Mbit/s** | **256 Mbit/s** |

Linear in N: cost = 2N Mbit/s per direction. Client cost is 2 Mbit/s (one session).

### 4.3 Monthly cost, at an explicitly assumed price

No project document fixes a transit price, so the assumption is stated here: **USD 0.05 per GB
egress** (a representative unmetered-cloud-listening-price figure; NOT MEASURED, NOT from any
project source — change it and every number below scales linearly).

Server, 64 sessions, one direction:

```
128 Mbit/s = 16.000 MB/s (decimal) = 16.0 x 10^6 B/s
seconds/month = 30 x 24 x 3600 = 2 592 000
bytes/month   = 16.0e6 x 2 592 000 = 4.1472e13 B = 41 472 GB (decimal)
cost         = 41 472 GB x $0.05/GB = $2 073.60 /month
```

Both directions: **≈ USD 4 147 /month**. At the single-client 2 Mbit/s case:
`0.25 MB/s x 2 592 000 = 648e9 B = 648 GB/month → ≈ USD 32.40/month`, ≈ USD 64.80 both ways.
Framing overhead at 2.578 % adds ~USD 53/month at the 64-session case (protocol bytes only).

The order of magnitude is the point: **one idle 64-session server costs more per month than the
entire tunnel software.** An operator who has not priced this cannot run the default at scale.

### 4.4 What the floor actually BUYS, given D22

State it without overselling:

**It buys:**

- **Silence is not a signal.** With the floor on, an idle session and a busy session are
  indistinguishable *below the floor*: both present exactly one 1280 B record per tick, forever.
  D22's concession (app data is additive above the floor, bound λ·W ≥ 1) is the price, and it is
  paid knowingly.
- **No burst structure from the sender's own scheduling.** Because of at-most-one-per-missed-
  deadline (`scheduler.rs:139-145`) a stalled host produces a *single* delayed record, never a
  queued backlog. A buffer-and-drain design would give an observer a clean "host was busy" burst
  that is far more identifying than volume.

**It does not buy:**

- **Not activity hiding.** Above the floor, activity is countable: λ·W ≥ 1
  (`THREAT_MODEL.md:512-515`), a ~7 % cadence shortfall does not change that
  (`THREAT_MODEL.md:551-553`), and raising `--cover-mbps` does not change it (§13.4's explicit
  statement).
- **Not volume hiding.** The grid itself is a volume disclosure: total emitted bytes are exactly
  predictable from session count. `THREAT_MODEL.md:515-517` already says so.
- **Not anonymity.** D22's adopted target is reduction. Any sentence implying cover makes traffic
  *unlinkable* or *unidentifiable* is unsupported by the code and would contradict D22.
- **Not aggregate cost control.** §2.4: N sessions ⇒ 2N Mbit/s, uncapped.

Net: the floor converts an *unbounded, structured, load-dependent* observable into a *constant,
bounded-per-session, structure-free* observable. That is a genuine and large reduction in metadata
leakage, and it is the whole of what D22 claims. It is worth 2 Mbit/s per session; whether that is
worth 128 Mbit/s per idle server is an operator decision that **no current CLI surface supports**.

---

## 5. Idle and lifetime semantics

### 5.1 Verified in source

- `cover_packet` sets `entry.last_activity = Instant::now()` on a successful cover encrypt
  (`session_manager.rs:544`).
- `cover_packet_all` calls `cover_packet` for every established session
  (`session_manager.rs:562-573`).
- **Any** successfully decrypted packet sets `entry.last_activity = now`
  (`session_manager.rs:468`), and `MessageType::Cover` on the receive side is a `DataResult::Payload`
  (`session_manager.rs:473`), consumed silently at `session_manager.rs:487-490`.
- `tick` evicts when `now - last_activity >= idle_timeout` or `now - established_at >= lifetime_cap`,
  **lifetime taking precedence** (`session_manager.rs:616-635`, reason chosen at `:624-630`).
- Defaults: `idle_timeout = Some(5 min)`, `lifetime_cap = None` (`session_manager.rs:140-141`).

### 5.2 Conclusion: the idle timeout can never fire while cover is enabled

On the **server**, its own `cover_packet_all` refreshes `last_activity` every 5.12 ms for every
established session. On the **client**, the peer's 195.3125 pkt/s cover stream arrives as
authenticated decrypts that refresh `last_activity` at `session_manager.rs:468`. Both ends emit
(D19). Therefore, with cover enabled, `now - last_activity` never approaches 5 minutes, and
**`idle_timeout` is unreachable dead code for an established session**. With `--no-cover`, no party
emits anything, `last_activity` freezes at the last real exchange, and the 5-minute default *does*
fire — this is the behaviour asserted by `pq-tunnel-bin/tests/revocation_lifetime.rs:305-320`
(`idle_timeout_before_cap_reports_idle_timeout`) and by D29 §8's table row 3
(`docs/design/D29-handshake-resource-hardening.md:392-394`).

This is **KNOWN**, not new: `D29:382-400` states it explicitly ("the idle timeout is effectively
dead code for an established link"). The mechanism it cites (`:386-388`) is slightly imprecise —
it attributes the effect to the *peer's* cover being an authenticated receive, omitting that the
*local* side also self-refreshes via `cover_packet` (`:544`) — so this audit's §5.1 chain is the
tighter statement. Same conclusion, better derivation.

### 5.3 The coupling this creates — **KNOWN mechanism, undocumented consequence**

`idle_timeout` silently means two different things depending on a transport policy flag:

| Configuration | `idle_timeout` (default 5 min) |
|---|---|
| cover on (default) | **unreachable**; eviction happens only at `lifetime_cap` / `max_sessions` LRU pressure / Close |
| `--no-cover` | real bound on silence in either direction |

`--no-cover` is defined in `pq-tunnel-bin/src/lib.rs:101-104` (server) / `:132-135` (client) as
"Disable cover traffic entirely (v2; explicit, documented reduction — cover never silently turns
off, PROTOCOL_SPEC §12.2)". The *privacy* meaning of the flag is documented; the **lifecycle**
meaning is not: no doc states that `--no-cover` simultaneously activates a 5-minute session reaper.
PROTOCOL_SPEC §12.2's "explicit, visible, documented" requirement
(`PROTOCOL_SPEC.md:522-530`) is satisfied for the metadata reduction but arguably not for this
second-order effect. D7's "parameters are not guarantees" cuts the other way here: `idle_timeout`
is a parameter whose *reachability* is controlled by a different parameter.

### 5.4 Rotation on the wire, and why it never happens

D16 rotation is close-and-re-establish: handshake burst (M1..M3) plus a cover gap. The gap is
observable — cover stops at `Closed` (`session_manager.rs:1188` client-side stop at `:1288`) and the
handshake is bursty. D19 already accepts this ("Rotation is close-and-re-establish (D16), so there
is a brief window with no cover — an observable signal, recorded in D19", D29 §8 table row 5).
**KNOWN.**

But triggering it is the part that matters, and the arithmetic is unambiguous:

```
MAX_PACKET_NONCE = u64::MAX - 2^32                       (codec.rs:121)
                = 18 446 744 073 709 551 615 - 4 294 967 296
                = 18 446 744 069 414 584 320  ≈ 1.8446744e19 packets/direction/session

Per session per direction at the default rate:
    18 446 744 069 414 584 320 / 195.3125 pkt/s
  = 9.4447e16 s
  = 9.4447e16 / (365.25 * 24 * 3600) years
  = 9.4447e16 / 3.15576e7 years
  ≈ 2.99e9 years
```

(`docs/performance/I-benchmark-methodology.md:588-598` records the same two rows, including
4.68e7 years at the 64-session 12 500 pkt/s aggregate.)

With `lifetime_cap = None` (the shipped default, `session_manager.rs:141`) and nonce exhaustion at
~3 billion years, and with `idle_timeout` unreachable (§5.2), and with the only remaining trigger
being explicit `Close` or LRU eviction under `max_sessions` pressure:

> **Stated plainly: with cover enabled and default `SessionLimits`, a session is effectively
> immortal. It rotates on nothing. The only events that ever end it are an explicit Close, roster
> removal, or LRU eviction caused by a 65th session.**

Consequence for the cost model in §4: "lifetime_cap is the knob that would bound both crypto
exposure *and* the number of concurrently immortal 2 Mbit/s emitters" — and it ships off.

---

## 6. Novelty-labelled issue list

Grep-to-confirm was run against `THREAT_MODEL.md` and `DESIGN_DECISIONS.md` (patterns:
`aggregate|12,500|128 Mbit|per-server|unbounded egress|amplif`, `cover traffic|constant rate|censor`,
`power management|timer granularity|host fingerprint|wakeup skew|idle_timeout.*cover`,
`framing overhead|bandwidth cost|egress cost`). Verdict column records what that grep found.

| # | Issue | Label | Evidence / disposition |
|---|---|---|---|
| F-1 | Server cover egress is **uncapped in aggregate**; `cover_packet_all` emits per session with no global limiter. N sessions ⇒ 2N Mbit/s; 64 ⇒ 128 Mbit/s/direction. Post-auth only (roster membership required), but an authenticated-but-idle member can hold 64 immortal sessions open because §5.2 makes idle eviction unreachable. | **NEW** | No hit for aggregate/128 Mbit/global cap in `THREAT_MODEL.md` or `DESIGN_DECISIONS.md`. `I-benchmark-methodology.md:575-585` has the *number* as a benchmark cost, not as a threat. Closest bound, `THREAT_MODEL.md:334-337`, scopes out "the volume a legitimate key-holder sends" — but that is the member's own data, not server-generated cover. `D29 §8` covers idle/lifetime, never the aggregate. Cap is a D7 resource bound, not a guarantee change. |
| F-2 | **Scheduler jitter fingerprinting**: relative re-arm (`scheduler.rs:140-144`) makes the grid a function of OS wakeups. Inter-arrival quantisation may expose host timer granularity; stall-sized gaps expose host suspend/throttle state. Outside §13.4's λ·W *count* bound, which is explicitly over "extra packets per observation window". | **NEW** | `THREAT_MODEL.md:545-553` disposes of cadence shortfall as "constant and stationary"/"non-material" — that is a stationary summary, not an absence of conditional structure. `scheduler.rs:26-27` and `DESIGN_DECISIONS.md:930-934` explicitly decline wall-clock alignment. No doc names host-state fingerprinting. **Exploitability unmeasured (NOT MEASURED).** |
| F-3 | `idle_timeout` never fires with cover on; it silently becomes a live 5-minute reaper under `--no-cover`. | **KNOWN** | `D29-handshake-resource-hardening.md:382-400` states both halves; test `revocation_lifetime.rs:305-320`. This audit adds the tighter derivation (§5.1) and flags only the *undocumented coupling* as a docs gap. |
| F-4 | Sessions are **effectively immortal** by default (`lifetime_cap = None`, idle unreachable, nonce ~2.99e9 years). | **KNOWN** | `D29:394` ("~3,000,000 years", "effectively unbounded"); `I-benchmark-methodology.md:588-598` gives the arithmetic incl. the 4.68e7-year aggregate row. **NEW only in combination with F-1**: immortality is what converts a per-session cost into an unbounded aggregate. |
| F-5 | Session count and liveness are observable **by construction** (exact N per tick); censors can count sessions and liveness. | **KNOWN** | `THREAT_MODEL.md:515-517` (verbatim, in §13.4); `D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:551-556`. |
| F-6 | Cover is additive above the floor; λ·W ≥ 1; raising the rate does not change the bound. | **REJECTED / settled** | `DESIGN_DECISIONS.md` D22 (`:1056-1103`) — target is reduction, not anonymity; absorbing emission recorded and **rejected for v1-alpha**; `THREAT_MODEL.md:512-515, 522-529`. Per scope guard, not re-opened. |
| F-7 | Rotation on the wire (handshake burst + cover gap) is observable. | **KNOWN** | D19 (via `D29:398-400`, D19 table row 5); moot in practice per F-4. |
| F-8 | Framing overhead is 33 B / 1280 B = **2.578 %** on the wire; **0 %** against the configured cover *rate* (see note). | **NEW (minor, documentation)** | Derived from `codec.rs:85,104,107,108,109,136`. No hit for `framing overhead|2.7%|35 B` in any `.md`. The brief's "35 B / 2.7 %" is not the code-verified figure: the header is **17 B**, not 19 B (`HEADER_LEN = 1 + 8 + 8`). |
| F-8a | **Parallel NEW finding (outside the cover floor, surfaced by the §2 search):** `ServerConfig::roster` is unbounded (`handshake_v2.rs:1269-1287` shows `max_pending = 64`, `pending_ttl = 30 s`, `rate_limit_burst = 16` — no roster ceiling), while M1 verifies against every entry (`handshake_v2.rs:1617-1630`). The per-source burst bounds *concurrent* work, not total work, so N-entry rosters are a pre-auth **work** amplification. | **NEW (duplicate of open D29 §4 item, deliberately recorded here so the F-track ledger is complete)** | `D29-handshake-resource-hardening.md:319-350` = §4 "Item 4 — roster size — NEEDS-DECISION", same arithmetic (~57 µs/verify ⇒ 100 k entries ⇒ ~5.7 s CPU per completing M1). **It is NOT counted in the 12 500 pkt/s figure**: `rate_limit_burst = 16` per 10 s per source caps *completing* handshakes at 1.6/s per address, so per-source cover amplification is bounded at 1.6 x 2 Mbit/s ≈ 3.2 Mbit/s, and the 64-session ceiling is reached by legitimate roster members, not by one flooder. Work amplification and bandwidth amplification are separate axes and both land on a 64-session server. |
| F-9 | `--cover-mbps` tunes the per-session rate but there is **no CLI surface for an aggregate egress target**; `--cover-mbps 1` on 64 sessions still costs 64 Mbit/s. | **NEW (same fix family as F-1)** | `pq-tunnel-bin/src/lib.rs:143-167` — `cover_policy_from_args(no_cover, mbps)` builds only a per-session `CoverPolicy`; `CoverPolicy` has exactly two fields, `enabled` and `interval` (`scheduler.rs:44-50`) — there is no aggregate field to set. D7 makes adding one a parameter, not a guarantee change. |
| F-10 | D23's 93.5 %-of-nominal cadence shortfall. | **KNOWN** | `THREAT_MODEL.md:543-553`; `DESIGN_DECISIONS.md:1157`; `CHANGELOG.md:115`. Not re-measured here. |

### Recommendation shape (not implemented — documentation only)

F-1 and F-9 are the only NEW items with a security dimension, and they share one fix family: an
operator-configurable aggregate egress bound, in the same family as `max_pending` (64),
`max_sessions` (64) and `MAX_RATE_BUCKETS` (4096). It is a **resource** bound (D7), not a metadata
guarantee change, and it would have to fail visibly rather than silently thin the floor — a server
that cannot honour the cap must say so, because silently emitting less than the promised floor
would be exactly the PROTOCOL_SPEC §12.2 violation D29 §5 caught in the `--cover-mbps` overflow.
F-2 needs a measurement campaign (jitter conditioned on host state), not a code change; it is
recorded here as a channel with **unestablished exploitability**.

---

## 7. TUN interaction (brief — Track A owns the design)

A TUN device keeps the tunnel link up, and cover is armed off `is_ready` in the client driver
(`session_manager.rs:1237-1240`) with **no reference to the TUN**. So an up-but-silent TUN emits the
full 2 Mbit/s grid, which is **exactly what D19 requires** ("an established idle session keeps
emitting", `DESIGN_DECISIONS.md:952-954`): a TUN that stopped cover when idle would make idle
*distinguishable*, inverting D22's residual. Track A has already recorded this as consistent
(`D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:521-556`).

**Should the client ever bring the link down?** No — and the tension is the point: *bringing it down
is itself the observable event*. Tearing down the link flaps the host network and emits a
lifecycle transition (silence, then a handshake burst) that is far more identifying than the
volume channel D22 accepts. Track A's conclusion — "the TUN link state is decoupled from session
liveness and is never used as a privacy control" (`:543-549`) — is correct and I endorse it
unchanged. If an operator wants less traffic, `--no-cover` is the honest switch, and §5.3 says
exactly what that switch costs in lifecycle terms.

One F-track observation that lands on TUN's lap: under TUN the always-on 2 Mbit/s is paid by the
whole machine, so F-1's per-server 128 Mbit/s becomes a per-*host* 2 Mbit/s on every client. The
aggregate problem moves from "one operator's bill" to "every user's link", which strengthens the
case for an operator-facing egress figure. Design ownership stays with Track A.

---

## 8. Provenance and honesty ledger

| Claim | Basis |
|---|---|
| `PACKET_SIZE=1280`, `DEFAULT_COVER_RATE_BPS=2_000_000`, 5.12 ms, 195.3125 pkt/s | Source read + in-tree asserts (`scheduler.rs:163,169-175`); brief's baseline confirmed |
| `HEADER_LEN=17`, `AEAD_TAG_LEN=16`, `INNER_PLAINTEXT_LEN=1247` | `codec.rs:85,104,107,108,109,136,145` — read directly |
| 128 Mbit/s at 64 sessions, both-direction cost | Arithmetic shown; matches pre-existing `I-benchmark-methodology.md:575-585` |
| Nonce exhaustion ≈ 2.99e9 years (and 4.68e7 y at 12 500 pkt/s) | Arithmetic shown; matches `I-benchmark-methodology.md:588-598` |
| D23 cadence: p50 5.5 ms, 182.6 pkt/s, 93.5 % of nominal, uniform 178-185/s | **Prior art, cited, NOT re-measured** — `THREAT_MODEL.md:543-553` |
| Idle-unreachable-with-cover | Source chain in §5.1, cross-checked against `D29:382-400` |
| No aggregate cover rate limiter exists | Exhaustive grep (§2.2) over `rate_limit|global_cap|token_bucket|max_sessions|aggregate|budget` — every hit enumerated |
| USD 0.05/GB egress assumption | **ASSUMED BY ME.** No project source. Monthly figures scale linearly with this price. |
| ~USD 2 074 /USD 4 147 per month at 64 sessions | Derived from the above. Arithmetic shown in §4.3. |
| F-2 exploitability (jitter → host fingerprint) | **UNVERIFIED / NOT MEASURED.** Channel is derivable from `scheduler.rs:140-144`; no experiment run. |
| Any latency/throughput figure other than cited D23 | **NOT MEASURED** |
| Pre-auth reachability of `sessions` | Source read: unknown-sid drop before allocation (`session_manager.rs:455-457`), roster-verified M1 (`handshake_v2.rs:1617-1630`) |

**No source file was modified. Nothing was committed.**