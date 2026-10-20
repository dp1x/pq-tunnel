# D29 — Handshake Resource Hardening

## Status

**Partially implemented.** Several fixes are in the tree (§5, §7, and the
amendment notes below); the remainder are proposals pending the decision gates
in §10. Nothing here changes HNDL resistance, metadata resistance, the wire
format, or any cryptographic or protocol semantic.

> **Implementation status as of the current tree (fact-checked, 2026-10).**
> The gates in §10 that were open when this document was written have since
> been closed in code:
>
> | Gate | State now | Where |
> |---|---|---|
> | Gate 1 — handshake cap eviction | **IMPLEMENTED.** The `min_by_key` scan is gone; the cap victim is the oldest-*inserted* tracked source, taken from an insertion-order queue maintained in lockstep with the table, so the eviction is **O(1)**. | `pq-tunnel-core/src/handshake_v2.rs` — `rate_order`, `ServerHandshake::rate_ok` |
> | Gate 2 — roster size | **IMPLEMENTED.** `MAX_ROSTER_SIZE` / `ServerConfig::max_roster_size`, enforced at load, at parse and in `set_roster` (fails closed). | `pq-tunnel-bin/src/identity.rs` |
> | Gate 3 — `--cover-mbps` maximum | **IMPLEMENTED, with a derived ceiling.** The ceiling is not the 10,000 Mbps this document recommended but the *sustainable* rate: 470 Mbps (`MAX_COVER_MBPS_PACING`), derived from a measured 21,762 ns per cover packet. A rate above it is **rejected at the CLI** with a named error, not silently clamped. | `pq-tunnel-core/src/scheduler.rs` (`MIN_COVER_INTERVAL_NANOS`, `MAX_COVER_RATE_BPS`), `pq-tunnel-bin/src/lib.rs` |
> | Item 3 — cheap roster select | **RESEARCH-ONLY**, unchanged. It would change the wire format. | — |
> | Item 8 — pre-auth DoS inventory | **RESEARCH-ONLY**, unchanged. | — |
>
> §9's row 11 and §1's context paragraph contained two claims about the
> **data-path** failure gate that were later measured to be false; they are
> corrected in place below and do not change any of this document's
> conclusions about the **handshake** path.

> Scope note: this document is Track D of a multi-track review. It covers the
> **resource** posture of the unauthenticated server surface only. It does not
> revisit D12 (authentication), D13 (handshake construction), D19 (cover
> scheduling), or D24's data-path work, except where the analogy is the point.

---

## 1. Context

D24 fixed a concrete CPU-exhaustion defect on the **data** path: the per-source
failure gate ran an O(n) prune on every packet once its table exceeded 32
entries, and the source key is a full `SocketAddr` — so one IP address yields up
to 65,535 distinct keys and an attacker could *hold* a 4096-entry table fresh,
paying two O(n) scans per packet indefinitely. D24's fix was **lookup-first**: a
datagram naming an unowned sid is dropped before the gate.

> **CORRECTION — the sentence this paragraph originally ended with was
> false, on two counts.**
>
> The original text read: *"D24's fix was **lookup-first**: a datagram naming
> an unowned sid is dropped before the gate, so the table is bounded by the
> active session population (at most `max_sessions`, default 64)."*
>
> 1. **The table was never bounded by the active session population.** The
>    session id is cleartext in every packet header (it is AEAD associated
>    data, not a secret), so a party that observes one datagram learns a live
>    sid and can then present AEAD-failing traffic from a fresh source port
>    per datagram. Measured on the pre-fix tree: **one** live session plus
>    **200** distinct source ports produced **200** buckets. The table tracks
>    *failing sources*, not sessions. The real bound is **`max_fail_buckets`**
>    (default **4096**) — and by nothing else. D24 has since been amended and
>    now states this correctly.
> 2. **Lookup-first did not amortize the per-failing-packet scan.** It moved
>    *bucket creation* behind the AEAD failure, but the prune and the cap
>    eviction still ran on every failing datagram, so the O(n)-per-packet cost
>    this document set out to measure was still reachable on that path.
>    Measured on the pre-fix tree: 40,000 AEAD-failing datagrams against a
>    200-entry table produced **12,600 prune passes and 2,520,000 bucket
>    visits**.
>
> **Where the data path stands now (D24, as amended):** the packet path is
> **O(1)** — no datagram, failing or succeeding, scans the fail-gate table;
> the cap eviction is **O(1)** (oldest-inserted victim from an insertion-order
> queue); and the expiry sweep runs **off the packet path**, in the manager's
> 1 Hz tick, at most one pass per `fail_window`, so the table's reclamation
> cost is bounded by `max_fail_buckets` bucket visits per `fail_window` rather
> than by the attacker's packet rate.
>
> None of this changes this document's thesis: the **handshake** rate limiter
> is a separate code path, and the table below is its own measurement.

D24 explicitly scoped itself to the data path and stated that it "does not
modify D13 (handshake construction and its DoS posture)". The **handshake**
rate limiter in `ServerHandshake::rate_ok` still has the same shape, at a **64x
larger bound**. This document establishes whether that is a real defect,
bounds it, and proposes the remaining fixes.

### Measured facts this document rests on

All measurements on this host, `x86_64-pc-windows-msvc`, release profile (the
workspace sets no `[profile.dev]` override, so debug is ~70x slower for these
crates and is not deployment-relevant).

| Measurement | Value |
| --- | --- |
| ML-DSA-65 `verify`, valid signature | **56.6 us** |
| ML-DSA-65 `verify`, wrong key | **59.7 us** (within 5% of valid) |
| ML-DSA-65 `verify`, tampered signature | **59.6 us** (within 5% of valid) |
| ML-DSA-65 `sign` | 497 us |
| `rate_ok` at the 4096 cap, **before** fix | **65.4 us/pkt** |
| `rate_ok` at the 4096 cap, **after** fix | **2.29 us/pkt** |
| `rate_ok` on a small (at most 32) table | 1.6 us/pkt |
| M1 body / fragments | 4534 B / 4 |
| M2 body / fragments | 5622 B / 5 |
| Nonce exhaustion threshold | `u64::MAX - 2^32`, about 1.84e19 packets/direction |

> **Provenance of the three `rate_ok` rows — read this before quoting them.**
> The `rate_ok` per-packet figures (65.4 / 2.29 / 1.6 us/pkt) were measured
> on the author's host for this document. **No committed artefact contains
> them.** The benchmark harness in `bench/` measures the ML-DSA/ML-KEM
> primitives, the roster-verify cost and the handshake CPU
> (`bench/src/crypto_prims.rs`, `bench/src/roster_verify.rs`,
> `bench/src/handshake.rs`); it contains **no rate-limiter benchmark**, and
> `bench/src/handshake.rs` only *mentions* `rate_limit_burst` to explain why
> each benchmark iteration uses a distinct source address. These three numbers
> are therefore **unreproducible from the public tree**, in the same way the
> §13 measurement campaign is (see `docs/audit/05-gaps.md` G-17).
>
> Two arithmetic corrections to how they were used here:
>
> - **65.4 / 1.6 = 40.9x, not "33x".** The "~33x amplification" figure quoted
>   in §4b was wrong; the correct ratio is ≈ **40.9x**. (65.4 / 2.29 = 28.6x,
>   so the "~28x" figure quoted for the before/after pair in §4d was right.)
> - The two ratios are **not** independent evidence: 1.6 us/pkt is the small-table
>   baseline that the 40.9x is computed against, and 2.29 us/pkt is the
>   post-fix cost *at* the cap.
>
> The direction of the finding — that the per-packet cost at the 4096 cap was
> far above the small-table cost, and therefore a single-source CPU primitive
> — is a structural property of the code (an O(n) scan over a table the
> attacker can hold fresh) and does not depend on the exact figures. The
> *magnitude* should be re-measured before it is quoted as a number.

The `verify` numbers are the empirical answer to "is ML-DSA verify
input-independent?" — the three cases differ by less than the measurement noise
floor. §3 explains why the source code says the same thing structurally.

---

## 2. Decision table

| # | Item | Current state (file:line) | Proposed change | Risk | Gate |
| --- | --- | --- | --- | --- | --- |
| 1 | Handshake `rate_ok` per-packet O(n) prune | `handshake_v2.rs` — `rate_ok`, `last_rate_prune` | Amortize prune to at most 1 pass per `rate_limit_window` via `last_rate_prune` | **LOW-RISK** | **IMPLEMENTED** |
| 2 | Handshake cap-eviction `min_by_key` O(n) at 4096 | `handshake_v2.rs` — `rate_order` + `rate_ok` | Replace with O(1) (ring/LRU) or lower `MAX_RATE_BUCKETS` | **MEDIUM** | **IMPLEMENTED** *(was: NEEDS-DECISION, gate 1 — the `min_by_key` scan is gone; the victim is the oldest-inserted source, popped from an insertion-order queue)* |
| 3 | Roster scan: no early exit, uniform verify count | `handshake_v2.rs` — `complete_m1` | **No change.** A cheap select is impossible without a protocol change | — | **RESEARCH-ONLY** |
| 4 | No upper bound on roster size | `pq-tunnel-bin/src/identity.rs` — `MAX_ROSTER_SIZE`, `ServerConfig::max_roster_size` | Cap roster at construction **and** parse time | **LOW-RISK** (D7 parameter) | **IMPLEMENTED** *(was: NEEDS-DECISION, gate 2 — enforced at load, at parse and in `set_roster`; over-long rosters fail closed)* |
| 5 | `--cover-mbps` unchecked `u64` multiply | `pq-tunnel-bin/src/lib.rs` — `cover_policy_from_args` | `checked_mul`, fail closed with a named error | **LOW-RISK** | **IMPLEMENTED** |
| 6 | `--cover-mbps` has no sane maximum (busy loop) | `pq-tunnel-core/src/scheduler.rs` — `MIN_COVER_INTERVAL_NANOS`, `MAX_COVER_RATE_BPS`; `pq-tunnel-bin/src/lib.rs` — `MAX_COVER_MBPS_PACING` | Reject rates above a documented ceiling | **LOW-RISK**, but changes accepted values | **IMPLEMENTED** *(was: NEEDS-DECISION, gate 3 — the ceiling is the derived **470 Mbps** sustainable rate, not the 10,000 Mbps this document recommended; an unschedulable rate is rejected at the CLI, not silently clamped)* |
| 7 | Cover / idle / lifetime interaction undocumented | `pq-tunnel-core/src/session_manager.rs` — `cover_packet`, `on_data_packet`, `tick` | Document the truth table (§8). No code change | — | **IMPLEMENTED** (doc) — *with one factual correction, see §8* |
| 8 | Pre-auth DoS surface inventory | §9 | None — every path is already bounded | — | **RESEARCH-ONLY** |

---

## 3. Item 3 — the roster scan: `biased;` select is **not** justified

**Question.** Should `complete_m1`'s uniform roster loop use `biased;` select
semantics (early exit on match)?

**Finding: no, and the loop is not the problem it appears to be.**

### The verify is input-independent — verified two ways

Structurally, in `ml-dsa` 0.1.1 `src/verifying.rs:107-127`, `raw_verify_mu` is
FIPS-204 Algorithm 8 and is **straight-line**: the matrix product
`A_hat * z_hat`, the inverse NTT, `use_hint`, and `encode_w1` all execute
unconditionally. The only data-dependent decision is the final
`sigma.c_tilde == cp_tilde` comparison — a byte compare performed *after* all
the expensive work. There is no early return anywhere on the validity path.
`sample_in_ball` (`src/sampling.rs:66-95`) is rejection sampling whose loop
count depends on the signature, but it is a bounded sampler, not a verification
early-exit, and it dominates nothing.

Empirically (table in §1): valid / wrong-key / tampered all verify in
56.6–59.7 us. The three paths are indistinguishable in cost.

**Therefore the uniform-verification-count rationale buys almost nothing against
a timing attacker** — there is no timing signal to suppress, because the
comparison is already at the end and the work before it is fixed. A `biased;`
early exit would save the *tail* verifies, and the tail is the only part
attacker-influenced.

### What the loop actually costs

`for pk in &self.cfg.roster { verify(...)? }` at ~57 us each means a handshake
costs **N x 57 us** of server CPU. For the shipped 1:1 deployment (D28: one
client per server) **N = 1**, so the loop is a single verify and there is
nothing to amortize. The cost only becomes real if an operator provisions a
large roster — which is item 4, not item 3.

### Why a cheap select is impossible here

`ClientHello::decode` (`handshake_v2.rs:527-558`) parses exactly:
`VERSION(1) || SID(8) || eph_pk_c(1184) || x_c(32) || client_sig(3309)`.
**The client sends no key identifier.** The server cannot select on anything
cheap, because the only thing it has is a signature, and a signature cannot be
indexed by key. A roster hash-map is therefore structurally impossible: you
cannot look up "which key verifies this signature" without trying keys.

Adding a key hint to M1 would:

- change the wire format (M1 is a fixed 4534-byte body in 4 fragments — D13),
- change the canonical transcript `TH1` and therefore every signed M2,
- break the fixed 1280-byte record assumption for fragment sizing,
- add a *new* unauthenticated attacker-controlled field that becomes a
  membership oracle — a "your key is not on my roster" signal is strictly worse
  than a uniform scan.

**Conclusion: `biased;` semantics are not justified, and the D12 uniform loop
should stay exactly as it is.** A cheap select is a protocol change and is
therefore out of Track D's mandate. Item 3 is RESEARCH-ONLY and the
recommendation is *no change*.

---

## 4. Items 1–2 — the handshake `rate_ok` scans

### 4a. Is the handshake path still exposed? — **Yes, and it is reachable.**

`rate_ok` is called from four places, all keyed by the full `SocketAddr` and
all reachable **before** any authentication:

| Call site | file:line | Gate placement |
| --- | --- | --- |
| M1 frag 0, new sid | `handshake_v2.rs:1584` | before `pending` insert |
| M1 completing fragment | `handshake_v2.rs:1536` | before roster verify + KEM |
| M1 frag 0 in `AwaitM3` (M2 resend) | `handshake_v2.rs:1573` | before the resend |
| M3 any fragment | `handshake_v2.rs:1697` | **before the `pending` lookup** |

The M3 gate is the clearest case: it fires before the pending entry is even
looked up, so an attacker sending well-formed M3 fragments from a range of
source ports mints a bucket per port with no state prerequisite at all. The
existing test `server_rate_bucket_table_is_capped` (`handshake_v2.rs:2968`)
already demonstrates the table being driven to 4096 from one IP with varying
ports.

So the port-diversity amplification D24 identified **does** apply here, and the
handshake path was never given D24's lookup-first fix.

### 4b. Does D24's "the win is small against a bound of 64" argument transfer to 4096?

**No. It does not transfer, and the measurements are why.**

D24's argument was made against a table bounded by `max_sessions` = 64, where
an O(64) scan per packet is noise. `MAX_RATE_BUCKETS` is 4096 — 64x larger —
and the measured per-packet cost at that bound is:

- **65.4 us/pkt** (pre-fix) versus **1.6 us/pkt** on a small table: a **~40.9x
  amplification**, on the unauthenticated path, from one attacker varying
  source ports.

> **Two corrections.** (1) The original text said "~33x"; the ratio of the two
> measured figures is 65.4 / 1.6 = **40.9x**. (2) All three `rate_ok` figures
> have **no committed artefact** — see the provenance note in §1. The
> *direction* of the argument is structural and survives; the exact multiplier
> should be re-measured before it is quoted.

At ~14,500 packets/s — trivially achievable over UDP — that is roughly a full
core spent in `rate_ok` scans alone, with no packet ever reaching a session.
"Small but real" was a fair characterisation at 64; at 4096 it is a
single-source CPU-exhaustion primitive, which is precisely the defect class D24
was raised to remove.

### 4c. Why D24's rejected fix (clock/LRU) is *not* the fix here either

D24 declined to add "a clock or LRU eviction pass" because a second eviction
mechanism is a second thing to get wrong. That reasoning is respected — and it
is also *not needed* for the dominant cost, because of a property the code
already has:

> **A stale rate bucket costs memory, never correctness.** In `rate_ok`, a
> bucket older than `rate_limit_window` is refilled to a full burst on its next
> touch (`handshake_v2.rs:1481-1484`). So the `retain` prune is a *memory
> cleanup*, not a correctness requirement. Skipping it cannot change any
> accept/reject decision — it can only leave entries in the map longer, and
> `MAX_RATE_BUCKETS` is the real memory bound.

This makes amortization **sound and non-evadable**: the attacker cannot make the
prune more frequent, and keeping buckets fresh (the D24 attack) only makes the
prune *remove nothing* — it is now run at most once per window regardless.
This is why the implemented fix is not the mechanism D24 rejected.

### 4d. What was implemented (item 1) — IMPLEMENTED

`ServerHandshake` gained `last_rate_prune: Instant`, and the prune is gated:

```rust
if self.rate_buckets.len() > 32
    && now.duration_since(self.last_rate_prune) >= self.cfg.rate_limit_window
{
    self.last_rate_prune = now;
    self.rate_buckets
        .retain(|_, b| now.duration_since(b.last_refill) < self.cfg.rate_limit_window);
}
```

Measured effect at the 4096 cap: **65.4 us/pkt to 2.29 us/pkt (~28x)**. With the
prune no longer per-packet, the attacker's 4096-entry table costs nothing per
packet. The cap remains the memory backstop and is unchanged.

**Invariants preserved:** no accept/reject decision changes (stale buckets
refill on touch); the `min_by_key` cap eviction is untouched; token accounting
is untouched, so D24's pinned M1 = 2 / M1+M3 = 3 accounting still holds.

### 4e. What is NOT implemented (item 2) — NEEDS-DECISION

> **STATUS UPDATE: item 2 is now IMPLEMENTED.** The `min_by_key` cap scan is
> gone. The victim is the **oldest-*inserted*** tracked source, popped from an
> insertion-order queue (`rate_order`) maintained in lockstep with the table —
> the same shape the data-path failure gate uses after D24's amendment — so the
> eviction is **O(1)** and visits exactly one entry. The text below is the
> original analysis and recommendation, preserved as the decision record.

Decomposing the pre-fix cost showed the `retain` prune was ~40 us and
**dominant**; the `min_by_key` cap scan did not even fire during the
measurement (after the prune the table fell just below the cap). With the
prune amortized, the cap scan is now the only remaining O(n) term and fires
only when a source pushes the table back to exactly 4096.

Options, none of which Track D will pick unilaterally:

| Option | Effect | Cost / risk |
| --- | --- | --- |
| **A.** Leave the `min_by_key` | Correct, O(n) only at the cap | Residual: an attacker that keeps 4095 entries live and pokes a 4096th pays one O(4096) scan per packet |
| **B.** Lower `MAX_RATE_BUCKETS` to e.g. 256 | Scans shrink 16x | Changes a D7 tunable; reduces how many distinct sources can hold state concurrently. **Narrowest, most honest fix** |
| **C.** Ring/heap for O(1) stalest-eviction | Removes the term entirely | A second data structure to get exactly right in the "attacker shapes our state" path — the thing D24 warned about |

**Recommendation: B**, with A as the status quo if the owner prefers not to
change a tunable. B is preferred over C because it is a one-line constant
change with a defence-in-depth rationale, whereas C trades a measured ~1 us for
a new invariant. **Gate 1 below.**

*Outcome: neither B nor C exactly — the implementation follows C's *shape*
(an O(1) insertion-order queue with one invariant) while leaving
`MAX_RATE_BUCKETS` at 4096.*

---

## 5. Item 5 — `--cover-mbps` overflow — IMPLEMENTED

`cover_policy_from_args` computed `mbps * 1_000_000` **unchecked**.

### The exact boundary (verified)

`u64::MAX = 18_446_744_073_709_551_615`.
`u64::MAX / 1_000_000 = 18_446_744_073_709` (largest safe value).
The **smallest** overflowing input is therefore **`mbps = 18_446_744_073_710`**.
This is pinned by `cover_mbps_overflow_boundary_is_exact` so a multiplier
change cannot silently re-base it.

### Why it matters (not just a debug panic)

- **Debug:** panics — a crash from a command-line argument.
- **Release:** wraps. A wrapped-small bitrate becomes an *enormous* interval,
  i.e. cover traffic is effectively switched off **without `--no-cover`**. That
  is a silent reduction of metadata resistance, which PROTOCOL_SPEC §12.2
  reserves for the explicit flag and D19 requires to be "explicit and visible".
  So the overflow is a (minor) security-semantics bug, not merely a panic.

### The fix (TDD, red verified first)

`pq-tunnel-bin/src/lib.rs` now uses `checked_mul` and fails closed:

```rust
let bps = mbps.checked_mul(1_000_000).ok_or_else(|| {
    format!("--cover-mbps {mbps} overflows a u64 bitrate (max {MAX_COVER_MBPS})")
})?;
```

Four tests added. The red phase was observed before the fix:

```
test tests::cover_mbps_above_u64_bitrange_is_rejected_not_wrapped ... FAILED
thread '...' panicked at pq-tunnel-bin\src\lib.rs:153:42:
attempt to multiply with overflow
test result: FAILED. 40 passed; 1 failed
```

---

## 6. Item 6 — the `--cover-mbps` busy loop — IMPLEMENTED

> **STATUS UPDATE: implemented, with a derived ceiling rather than the
> suggested one.** `interval_from_rate_bps` now clamps the interval to
> `MIN_COVER_INTERVAL_NANOS` = **21,762 ns** (the measured cost of producing
> one cover packet), so the highest admissible rate is
> `MAX_COVER_RATE_BPS` = **470,544,986 bit/s** — 470 Mbps as an integer
> megabit value (`MAX_COVER_MBPS_PACING`). `cover_policy_from_args` **rejects**
> a `--cover-mbps` above that with a named error; it is not silently clamped.
> The 10,000 Mbps ceiling suggested below was not adopted: a rate above what
> the scheduler can be *asked* for is not merely fast, it is unschedulable.
> The ceiling bounds the **requested** rate; it is not a promise of achievable
> throughput on a given host (the measurement excludes the timer and `sendto`
> syscalls — see `docs/performance/I-benchmark-methodology.md` §7.2).

`interval_from_rate_bps` (`scheduler.rs:74-78`) ends in `nanos.max(1)`. That is
a **lower** clamp on the *interval*, i.e. an upper clamp on the *rate* — and it
is deliberate (a zero interval would turn `sleep_until` into a busy loop). But
it means there is **no upper bound on the rate at all**:

| `--cover-mbps` | interval | packet rate |
| --- | --- | --- |
| 2 (default) | 5.12 ms | 195/s |
| 100 | 102.4 us | 9,766/s |
| 1,000 | 10.24 us | 97,656/s |
| 10,000 | 1.024 us | 976,563/s |
| 100,000 | 102 ns | 9.8 M/s |
| 10,240,000 | **1 ns** | 1 G/s (clamp floor) |

On Windows the driver re-arms a `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` wait on
**every** wake (`session_manager.rs:1171-1193`, `cover_sleep` at
`session_manager.rs:1415`). A 1 ns interval therefore becomes a spin loop that
burns a core.

**Severity, stated honestly:** this is **operator-triggered, not
attacker-reachable**. The input is a local CLI flag, and the consequence is
self-inflicted CPU burn. It is a robustness and input-validation defect, not a
remote DoS. It matters because (a) it is a foot-gun with no error message, and
(b) the fix is the same shape as the overflow fix already landed.

**Why Track D did not implement it:** adding a maximum *narrows the set of
accepted operator inputs*, which is an interface change even though it is not a
protocol change. That is gate 3. Suggested ceiling: **10,000 Mbps (10 Gbps)** —
already ~1 M pkt/s, far beyond any real link, and 1000x the default. The
existing `absurd_rate_is_clamped_to_nonzero_interval` test in `scheduler.rs`
documents the clamp and should be extended, not replaced, if this is approved.

---

## 7. Item 4 — roster size — IMPLEMENTED

> **STATUS UPDATE: implemented.** The roster is bounded by
> `MAX_ROSTER_SIZE` / `ServerConfig::max_roster_size`, enforced at load, at
> parse and in `set_roster` — an over-long roster fails closed. The text below
> is the original analysis, preserved as the decision record.

### The exposure

`load_roster` (`identity.rs:378-390`) reads every payload line with no upper
bound, and `ServerConfig.roster: Vec<MlDsaPublicKey>` (`handshake_v2.rs:1257`)
is unbounded. Since `complete_m1` verifies against **every** roster entry at
~57 us, a 100,000-entry roster costs **~5.7 seconds of CPU per completing M1**.

`rate_limit_burst = 16` per 10 s bounds this *per source*, but 16 tokens per
10 s x 5.7 s each is not a bound on total work — it is a bound on *concurrent*
work, and the cost is trivially amplified across sources. Note the budget only
charges on the *completing* fragment (`handshake_v2.rs:1536`), which is exactly
where the N verifies happen, so the accounting is right; the problem is N.

### What D16's "≈2.5 ms CPU" refers to

D16's figure is the **re-establishment** cost — one ML-KEM keygen +
encapsulate + decapsulate + two ML-DSA operations + X25519 — i.e. a **roster of
one**. At the measured 57 us/verify and ~500 us/sign, a single-client handshake
is consistent with that figure. **D16's number is an N = 1 number and does not
scale to large rosters**; it should not be read as evidence that roster size is
free.

### Is a bound a protocol/security semantic change?

**No — and the argument is D7.** D7 ("Parameters Are Not Security Guarantees")
establishes that parameters control tradeoffs and do not redefine guarantees. A
roster maximum is an operator-configurable *resource* bound, in exactly the
same family as `max_pending` (64), `max_sessions` (64), and
`MAX_RATE_BUCKETS` (4096), all of which are already accepted DoS-posture bounds.
D17's "empty roster fails closed" is the lower edge; a maximum is its symmetric
upper edge and is the same kind of fail-closed rule.

**The one caveat that does make this a gate:** a maximum can make a *previously
working* deployment refuse to start. That is a real operational change, so it
gets a nod rather than being slipped in.

### Proposal

- **Enforce at both ends** (defence in depth, matching the existing
  load-time + construct-time split for emptiness):
  - `load_roster` — parse-time, fail closed with a new
    `IdentityError::RosterTooLarge { path, got, max }`, *before* the keys are
    materialised, so a hostile or corrupt file cannot force 100,000 key decodes.
  - `ServerConfig::new` / `ServerSessionManager::new` — construction-time, so
    the bound also covers programmatic construction (fuzz targets, tests, future
    config loaders) that bypasses the file parser.
  - `set_roster` (`handshake_v2.rs:1401`) — the D27 hot-swap path, which is
    currently the **one way to sidestep any parse-time bound**. It must be
    bounded too or the cap is decorative.
- **Suggested value: 64.** Rationale: the product is 1:1 (D28), so 64 is ~64x
  headroom over any real deployment; at 57 us/verify it caps a completing-M1 at
  **~3.6 ms**, which is the same order as D16's stated ~2.5 ms handshake CPU and
  therefore does not make the *normal* path meaningfully worse. It also matches
  `max_sessions` (64), so the bound is consistent with the rest of the DoS
  posture.
- **Must also be a `ServerConfig` field, not a bare const**, so an operator with
  a genuine large-roster deployment can raise it — otherwise it is a hard
  product limit, which is a different (and larger) decision.

---

## 8. Item 7 — cover / idle / lifetime: the actual guarantees

Read from `session_manager.rs`. `last_activity` is refreshed on **any
successfully authenticated receive** (`on_data_packet`) *and* on every
locally-generated cover packet (`cover_packet`) *and* on every other
locally-generated packet (`send_encrypted`). `tick` evicts when
`now - last_activity >= idle_timeout` **or**
`now - established_at >= lifetime_cap`, lifetime taking precedence.

> **CORRECTION.** The row below originally said: *"Each side's own cover
> emission does not refresh its own `last_activity`, but the *peer's* cover
> packets are authenticated receives that do."* **That is false.** The local
> side's own cover emission **does** refresh its own `last_activity`:
> `SessionManager::cover_packet` sets `entry.last_activity = Instant::now()`
> on a successful cover encrypt, and `send_encrypted` does the same for every
> other outbound packet. The *peer's* cover also refreshes it, via the
> authenticated-decrypt path in `on_data_packet`. The **conclusion** of the row
> is unchanged — with cover enabled the idle timeout still cannot fire for an
> established link — but it rests on **both** refresh paths, not on the
> peer's alone. The same tightening is recorded in
> `docs/audit/F-metadata-cover-guarantees.md` §5.2.

| Configuration | Real exposure bound | Why |
| --- | --- | --- |
| cover **on** (default 2 Mbps), `idle_timeout` 5 min | **Idle timeout never fires for an established link.** Each side's own cover emission refreshes its own `last_activity` (`cover_packet`), *and* the peer's cover packets are authenticated receives that refresh it too (`on_data_packet`) — and both ends emit | An established link is never idle by construction. |
| cover on, `lifetime_cap = None` (default) | **Nonce exhaustion only**: `u64::MAX - 2^32` packets/direction. At 195 pkt/s that is **~3,000,000 years** | Effectively unbounded. This is a *deliberate* D16 posture, not an oversight. |
| `--no-cover` | `idle_timeout` becomes the real bound (5 min default) of **silence in either direction** | Without cover, an established-but-quiet session looks identical to a dead peer and is reaped at 5 min. |
| cover on, `lifetime_cap` set | The **stricter** of lifetime and nonce exhaustion; lifetime wins | `tick` checks lifetime first and reports `CloseReason::LifetimeCap`. |
| cover on close/rotation | Cover is armed **only while a session is established** (the server driver starts it on `Established`) and goes inert on `Closed` and when the session count hits 0 | No churn during handshake, and no cover for a dead session (D19). Rotation is close-and-re-establish (D16), so there is a brief window with no cover — an observable signal, recorded in D19. |

**Stated plainly:** with cover enabled and `lifetime_cap` unset (the shipped
default), a session lives until its traffic keys' nonce space is exhausted —
centuries — and the idle timeout is effectively dead code for an established
link. That is the correct security posture (forward secrecy is not weakened by
keeping a link up), but it should be an explicit operator-facing statement, not
a discovery.

### Does cover make D22's metadata claim better or worse under TUN?

**Better, and the D25/D26 design already reasons about it.** D22 claims
metadata *reduction*, not anonymity. Under full-system TUN egress (D25), the
*inbound* direction is a real VPN: app traffic arrives with its own timing,
volume and burst structure, and without cover that structure is the observable.
Cover overlays a constant-rate grid on top of it, so the observer sees the
stable grid rather than the underlying application rhythm.

The cost is real and must stay visible: the link becomes a **constant 2 Mbps in
each direction regardless of load**, which is itself a highly regular
fingerprint — "this host emits exactly 195.3 packets/second forever" is a
stronger signal than "this host's traffic is bursty", and it is what makes the
tool identifiable *as this tool*. Under TUN that cost is paid by the whole
machine rather than one application. D25 §2.4 already records cover as an
always-on cost; this document confirms it and adds the idle-interaction row.

---

## 9. Item 8 — pre-authentication DoS surface: complete inventory

Everything an **unauthenticated** remote attacker can reach on the server before
a handshake completes. "Bound" means the state or cost is capped by a constant
the operator configures.

| # | Surface | file:line | Bound | Real issue? |
| --- | --- | --- | --- | --- |
| 1 | Pending-handshake table | `handshake_v2.rs:1584-1588` | `max_pending` = **64**; nothing allocated before a validated frag 0 | **No.** Bounded. |
| 2 | Pending entry lifetime | `handshake_v2.rs:1439-1442` | `pending_ttl` = 30 s, swept by `evict_expired` | **No.** |
| 3 | `evict_expired` on every datagram | `handshake_v2.rs:1490` (M1), `handshake_v2.rs:1688` (M3) | O(pending), at most 64 per packet | **No.** 64 is a constant; this is exactly the bound D24 accepted. |
| 4 | M1 reassembly buffer | `handshake_v2.rs:420-437` | fixed `[bool; 5]` + one 4534 B body, allocated only after frag 0 passes | **No.** Fixed-size, one per pending entry. |
| 5 | The ~4.5 KiB reassembly copy | `handshake_v2.rs:1536-1544` | runs **after** `rate_ok`, and only on the completing fragment | **No.** Correctly ordered (D24's accounting). |
| 6 | M2 cache | `handshake_v2.rs:1664-1665` | one 5622 B `Vec` per `AwaitM3` pending entry, at most 64 | **No.** Bounded. |
| 7 | Rate-bucket table | `handshake_v2.rs:1444-1473` | `MAX_RATE_BUCKETS` = **4096** | **CPU, pre-fix — FIXED** (item 1). Residual O(n) cap scan = gate 1. |
| 8 | Roster verifies per M1 | `handshake_v2.rs:1617-1630` | N x 57 us, N unbounded | **Yes — unbounded in N.** Gate 2. |
| 9 | ML-KEM keygen + encapsulate per completing M1 | `handshake_v2.rs:1639-1641` | once per token (at most 16/10 s per source) | **No.** Budgeted; amplifiable only across sources, which `THREAT_MODEL.md` §7.1 already scopes out. |
| 10 | Session table | `session_manager.rs:415-419` | `max_sessions` = **64**, LRU eviction | **No.** Pre-auth traffic cannot create sessions. |
| 11 | Data-path fail buckets | `pq-tunnel-core/src/session_manager.rs` — `FailGate` | lookup-first (D24); bounded by **`max_fail_buckets`** (default **4096**) and by nothing else — **not** by the session population; packet path O(1), expiry sweep off the packet path | **No.** *(Corrected: this row originally said "bounded by session population". That claim was false and has been withdrawn by D24's amendment — the sid is cleartext in every header, so one observed datagram plus 200 source ports produced 200 buckets.)* |
| 12 | `WirePacket` / fragment parse | `handshake_v2.rs:314`, `udp.rs` | fixed 1280 B, wrong-size rejected | **No.** |
| 13 | `MlDsaSignature::from_bytes` in `ClientHello::decode` | `signature.rs:134-145` | fixed 3309 B; may reject structurally | **No.** Cheap, input-bounded. |
| 14 | Idle/lifetime `tick` sweep | `pq-tunnel-core/src/session_manager.rs` — `tick` | 1 Hz, O(sessions), at most 64 | **No.** |
| 15 | `--cover-mbps` busy loop | `pq-tunnel-bin/src/lib.rs` — `cover_policy_from_args`; `pq-tunnel-core/src/scheduler.rs` — `MIN_COVER_INTERVAL_NANOS` | **bounded** (operator input): the interval is floored at 21,762 ns and the CLI rejects a rate above the derived 470 Mbps sustainable ceiling | **No — resolved.** *(Was: "Yes — operator-triggered, not remote. Gate 3." Gate 3 is now implemented.)* |

**Summary:** after item 1, the only *remote, unauthenticated* resource issue
that survives is the unbounded roster (item 8 / gate 2). Everything else is
either bounded by a small constant or is an operator-input robustness issue.

> **Update — gate 2 is now closed.** The roster is bounded:
> `MAX_ROSTER_SIZE` / `ServerConfig::max_roster_size`, enforced at load, at
> parse and in `set_roster`, failing closed. Item 8 is therefore **CLOSED**
> for the shipped code, and the surviving remote, unauthenticated resource
> issues in this table are **none**.

---

## 10. Decision gates — what needs owner approval

> **All three gates have since been decided and implemented in code.** The
> text below preserves the original options and recommendations as the
> decision record; the state of each gate is in the Status table at the top of
> this document.

**Gate 1 — handshake cap-eviction (NEEDS-DECISION).**
Choose **A** (leave the `min_by_key`, status quo), **B** (lower
`MAX_RATE_BUCKETS`, e.g. 4096 to 256), or **C** (O(1) ring/heap eviction).
*Recommendation: B.* Only A and B are cheap; C adds a new invariant to the one
code path whose failure mode is "attacker shapes our internal state".
*Implemented as a variant of C — an insertion-order queue with one invariant
(`rate_order.len() == rate_buckets.len()`), the same shape the data-path gate
uses after D24's amendment.*

**Gate 2 — roster-size bound (NEEDS-DECISION).**
Approve a maximum, the value (**64** recommended), the enforcement points
(`load_roster` + `ServerConfig::new` + **`set_roster`**, the last being the
hot-swap bypass), and whether it is a `ServerConfig` field (operator-tunable,
recommended) or a bare constant (hard product limit).
*Implemented: the limit is a `ServerConfig` field (`max_roster_size`), and all
three enforcement points are in place.*

**Gate 3 — `--cover-mbps` maximum (NEEDS-DECISION).**
Approve a documented ceiling (**10,000 Mbps** recommended) to stop the 1 ns
busy loop. This narrows accepted operator input; it is not a protocol change
and not attacker-reachable, but it is an interface change.
*Implemented with a different (derived) ceiling: **470 Mbps**, the rate the
cover path can actually sustain at the measured 21,762 ns per cover packet. A
rate above it is rejected at the CLI with a named error rather than clamped.*

**Explicitly NOT gated** (already implemented, no protocol semantics touched):
the `rate_ok` prune amortization (item 1) and the `checked_mul` overflow fix
(item 5). Both are internal hardening with no wire-format, cryptographic, or
authentication effect. The `rate_ok` change is provably decision-preserving
because a stale bucket refills on touch; the `checked_mul` change only converts
a panic or a silent wrap into a named error.

**Deliberately not done, pending a protocol decision that is out of scope here:**
a cheap-select index for roster verification (item 3). It would require a key
hint in M1, which changes the wire format, the canonical transcript, and the
fragment arithmetic, and would introduce a membership oracle. The recommendation
is to *not* do it.

---

## 11. Validation

Gate commands, all with the mandatory `--target x86_64-pc-windows-msvc`
(the target CI runs and the release gate is measured on — note that the
"ARM64 host cannot build `aws-lc-sys`" reason formerly quoted here is stale:
`aws-lc-sys` is not in the dependency tree at all):

```sh
cargo fmt --check
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test -p pq-tunnel-bin   --target x86_64-pc-windows-msvc
cargo test -p pq-tunnel-core  --target x86_64-pc-windows-msvc
```

Observed results on this host:

| Gate | Result |
| --- | --- |
| `cargo fmt --check` | exit 0 |
| `cargo clippy --all-targets ... -- -D warnings` | exit 0 for `pq-tunnel-core` + `pq-tunnel-bin`; the workspace-wide run is blocked by a `clippy::type_complexity` lint in `pq-crypto/src/kdf.rs:589` test code belonging to a concurrent track, unrelated to this work |
| `cargo test -p pq-tunnel-bin` | 77 lib + 6 adversarial + 3 smoke + 3 stress + 13 revocation — all pass |
| `cargo test -p pq-tunnel-core` | 280 pass |

**New tests (6 total, all passing):**

| Test | File | Pins |
| --- | --- | --- |
| `cover_mbps_overflow_boundary_is_exact` | `pq-tunnel-bin/src/lib.rs` | the exact `u64` boundary, written out in decimal |
| `cover_mbps_above_u64_bitrange_is_rejected_not_wrapped` | `pq-tunnel-bin/src/lib.rs` | the overflow is rejected, never wrapped |
| `cover_mbps_at_u64_boundary_is_accepted` | `pq-tunnel-bin/src/lib.rs` | the largest legal value still works |
| `cover_mbps_zero_is_rejected_and_no_cover_wins` | `pq-tunnel-bin/src/lib.rs` | pre-existing lower bound + `--no-cover` precedence |
| `rate_ok_prune_is_amortized_not_per_packet` | `pq-tunnel-core/src/handshake_v2.rs` | at most one prune pass per window, under a 500-source flood |
| `rate_ok_prune_still_reclaims_after_window` | `pq-tunnel-core/src/handshake_v2.rs` | amortization does not defeat the memory reclaim |

**TDD and non-vacuity.** The overflow test was run and observed **failing**
before the fix:

```
test tests::cover_mbps_above_u64_bitrange_is_rejected_not_wrapped ... FAILED
panicked at pq-tunnel-bin\src\lib.rs:153:42: attempt to multiply with overflow
test result: FAILED. 40 passed; 1 failed
```

The amortization test was likewise verified **non-vacuous** by temporarily
restoring per-packet pruning, which makes it fail:

```
assertion `left == right` failed: no packet inside the window may trigger another prune pass
  left: Instant { t: 50896.6683086s }
 right: Instant { t: 50896.6430762s }
```

Both invariants are asserted structurally (observed prune timestamps and table
lengths), never by wall-clock timing.

**Flakiness note (not caused by this change).** Across roughly a dozen full
`pq-tunnel-core` runs, three different pre-existing tests failed once each and
then passed in isolation and on every subsequent full run:
`envelope::tests::fuzz_decrypt_error_uniformity`,
`handshake_v2::tests::server_rejects_non_contributory_client_x25519_key`, and
`handshake_v2::tests::th3_binds_the_client_kem_public_key`. A different test
failing each time, each passing in isolation, is the signature of
timing/parallelism sensitivity in the crypto-heavy tests rather than a logic
regression — none of the three touch `rate_ok`, the bucket table, or the cover
policy. **This is worth a follow-up, and is not fixed here** (fixing unrelated
test flakiness is out of Track D's scope).

## 12. Cross-references

`DESIGN_DECISIONS.md` D7 (parameters), D12 (uniform authentication), D13
(handshake DoS posture), D16 (rekey, ~2.5 ms figure), D17 (provisioning,
fail-closed), D19 (cover scheduling), D22 (metadata reduction), D24 (data-path
failure budget — the defect this mirrors), D27 (roster hot-swap: `set_roster`
is a bypass any roster cap must cover), D28 (1:1 deployment).
`THREAT_MODEL.md` §7.1 (bounded resources), `PROTOCOL_SPEC.md` §12.2 (cover
disabling is explicit).
