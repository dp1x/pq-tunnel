# D27 — Revocation and Session-Lifetime Semantics

## Status

Proposed (implementable; the owner gates in "Human decision gate" below are
not yet approved)

## Context

Three related questions were open:

1. **Session lifetime.** `SessionLimits::lifetime_cap` exists, is documented as
   the D16 traffic-key-exposure bound, and defaults to `None`
   (`pq-tunnel-core/src/session_manager.rs:141`). Nothing in the shipped binary
   ever sets it. The proposed default is `Some(1 day)`.
2. **Revocation.** The client roster is a file read once at server startup
   (`pq-tunnel-bin/src/v2_server.rs:52`). There is no reload path, so revoking
   a client key means restarting the server — which kills every live session,
   including unrelated ones.
3. **Atomicity.** A reload must never leave the server trusting a partial,
   half-parsed, or empty roster.

This record fixes the semantics for all three.

---

## §1 The `lifetime_cap` default

### 1.1 Current state (verified)

`lifetime_cap` is set to a non-`None` value in **exactly five places, all
tests**. Every production site uses `None`:

| Site | Value | Kind |
|---|---|---|
| `session_manager.rs:141` | `None` | `Default` |
| `session_manager.rs:1915` | `None` | test (`server_idle_eviction_and_activity_refresh`) |
| `session_manager.rs:1951` | `Some(3600 s)` | test (`server_lifetime_cap_precedes_idle`) |
| `session_manager.rs:3236` | `Some(7200 s)` | test (capacity eviction) |
| `session_manager.rs:4054` | `Some(20 s)` | test (idle-vs-cap precedence) |
| `session_manager.rs:2401` | `Some(..)` | test (`client_lifetime_cap_closes_established`) |

**There is no CLI flag.** `ServerArgs` / `ClientArgs`
(`pq-tunnel-bin/src/lib.rs:73-136`) expose only `listen`, `stats_interval`,
`identity`, `roster`, `echo`, `cover_mbps`, `no_cover`, `remote`, `relay_listen`,
`server_key`. Both `v2_server.rs:56` and `v2_client.rs:51` construct
`SessionLimits::default()` with no override. **Confirmed: `lifetime_cap` is
currently unreachable by an operator.**

### 1.2 The decisive arithmetic: nonce exhaustion is not the real bound

`MAX_PACKET_NONCE = u64::MAX - 2^32 = 18_446_744_073_709_551_615`
(`pq-tunnel-core/src/codec.rs:121`).

At the default cover rate (`--cover-mbps 2`, `DEFAULT_COVER_RATE_BPS = 2_000_000`,
`scheduler.rs:36`) with `PACKET_SIZE = 1280` (`codec.rs:104`):

```
bits per packet      = 1280 * 8 = 10_240
emission interval    = 10_240 / 2_000_000 = 5.12 ms
packets/sec          = 1 / 0.00512 = 195.3125 pkt/s
seconds to exhaust   = 18_446_744_073_709_551_615 / 195.3125
                     = 94_447_329_657_392_903  ≈ 9.4447e16 s
years                = 9.4447e16 / 31_557_600 ≈ 2.99e9 years
```

Even at a sustained **10 Gbps** of pure payload (978_515 pkt/s, ~50x the cover
budget):

```
9.4447e16 s / 978_515 pkt/s = 9.6541e10 s ≈ 597_377 years
```

**Conclusion: nonce exhaustion is astronomically beyond any operational
horizon. It is a correctness backstop against `u64` wrap (a hard AEAD nonce
uniqueness requirement), not a lifetime bound.** The user-provided "1 day"
assumption cannot be justified as "preventing nonce exhaustion" — that framing
is refuted by three orders of magnitude.

### 1.3 The real finding: the exposure bound is *cover-dependent*

Server idle eviction keys off `last_activity`
(`session_manager.rs:621`), which is refreshed on **every authenticated
receive**, regardless of message type:

- `on_data_packet`: `entry.last_activity = now;` on any successful decrypt
  (`session_manager.rs:468`), which covers `Data`, `Cover`, and `Close`
  (`session_manager.rs:454-457`).
- `send_encrypted`: `entry.last_activity = Instant::now();`
  (`session_manager.rs:585`) — the server's own cover emissions count too.
- `cover_packet`: same, `entry.last_activity = Instant::now();`
  (`session_manager.rs:544`).

So:

- **With cover enabled (the default):** cover packets are authenticated
  receives. A session with cover on **never goes idle**. Therefore
  **`idle_timeout` does NOT bound traffic-key exposure at all** in the default
  configuration. The session's exposure window is unbounded up to
  `lifetime_cap`.
- **With `--no-cover`:** an idle session does go idle after 5 minutes
  (`SessionLimits::default().idle_timeout`, `session_manager.rs:141`), so
  `idle_timeout` *does* bound exposure — but only for sessions that happen to be
  quiet.

This is the decisive argument for a `lifetime_cap` default. **In the default
configuration, `lifetime_cap` is the *only* bound on traffic-key exposure.** That
is precisely the D16 promise ("exposure is bounded by the session lifetime",
`DESIGN_DECISIONS.md:774-776`) — and today it is unbounded because the default
is `None`.

### 1.4 D7 analysis: does changing the default redefine a guarantee?

**No.** D7 (`DESIGN_DECISIONS.md:286`) states that parameters control tradeoffs
and do not redefine guarantees; D9 requires secure defaults and *visible*
tradeoffs.

- Before: HNDL resistance and forward secrecy are **unaffected either way**. They
  come from D1/D2/D14 (ephemeral KEM + X25519 per handshake, keys zeroized on
  drop), not from session length. A 1-day session and a 1-year session have
  identical HNDL properties.
- What the cap bounds is *post-compromise* exposure: if a traffic key is
  captured (lawful-compel-style endpoint compromise), a shorter session limits
  how much of that session's plaintext the attacker can decrypt.
- Setting the default to `Some(1 day)` therefore **tightens a parameter that was
  previously off**, and does not weaken any guarantee. It cannot be a security
  regression in D7's terms.

**Tradeoff, stated plainly:** a 1-day cap forces a full D16 rekey (≈1.5 RTT, a
brief connectivity blip, `DESIGN_DECISIONS.md:800-802`) once per day per
session. For a 1:1 deployment (one client identity per server) that is one
blip per day — negligible. It must remain **visible and configurable**, per D9.

### 1.5 Does a 1-day cap interact badly with anything?

- **D16 rotation re-runs the roster check.** Re-establishment is a full
  handshake (`session_manager.rs:790` `begin_handshake`, driver
  `rearm_client` at `session_manager.rs:1560`+). The client's M1 is verified
  against the roster at `complete_m1` (`handshake_v2.rs:1547-1578`). So a
  revoked key **cannot** rotate back in: the re-establishment fails silently at
  M1 and the client burns its `m1_max_attempts` budget (default 8,
  `handshake_v2.rs:926`) then reports `Closed{HandshakeTimeout}`. Fail-secure,
  verified by test `revoked_key_cannot_re_establish` and
  `revoked_client_retry_loop_never_establishes`.
- **The server does not auto-close on cap-expiry.** Server-side eviction is
  silent (a `Closed` notification to the app; `session_manager.rs:1160-1169`).
  The client, which owns the re-establish loop, closes with
  `Closed{LifetimeCap}` (`session_manager.rs:939-948`) and re-arms. So the
  rotation is **client-driven** and needs no server cooperation.
- **No leak in close/re-establish.** The master is dropped and zeroized on
  close; re-establishment draws fresh ephemerals and a fresh sid (verified:
  `client_side_lifetime_cap_closes_and_re_arms` asserts the new sid differs).
- **Cover-scheduler interaction:** on the client, `Closed{LifetimeCap}` stops
  cover (`session_manager.rs:1349-1351`), then re-establishment restarts it on
  the next `Ready` (`session_manager.rs:1238-1246`). No stale emissions.

### 1.6 Decision on §1

**`lifetime_cap` default becomes `Some(24h)`, with a visible CLI override.**
The justification is *not* nonce exhaustion (refuted, §1.2) — it is that with
default cover enabled, `lifetime_cap` is the only exposure bound (§1.3). The
value 1 day is a starting default, not a derived constant; the owner gate below
covers whether 1 day is the right number and whether to make it mandatory.

---

## §2 Runtime revocation vs restart-only

The roster is loaded exactly once: `identity::load_roster(roster_path)` at
`v2_server.rs:52`, then moved into `HandshakeV2ServerConfig::new(keypair, roster)`
(`v2_server.rs:54`) and into `ServerSessionManager::new` → `ServerHandshake::new`
(`session_manager.rs:339`), which clones it (`handshake_v2.rs:1372-1377`). **It is
never re-read. Confirmed.**

Options assessed:

| Option | Atomic? | In-flight handshake race | Verdict |
|---|---|---|---|
| **(a) SIGHUP / file-watch** | Yes, if parse-then-swap | Handshake that authenticated before the swap could complete after it | Acceptable **if** M3 re-checks membership (§4) |
| **(b) Admin RPC/socket** | Yes | Same as (a) | Rejected: new listening surface, new auth story, new DoS surface, for a 1:1 deployment |
| **(c) Periodic re-read** | Yes | Same as (a) | Acceptable; strictly worse than (a) — same effect, with up to one interval of delay and a permanently polling process |
| **(d) Restart-only** (status quo) | Trivially | N/A | Rejected: revoking one key kills every unrelated session and drops all cover state |

**Decision: (a), a file-watch/periodic-reload on the roster path, implemented as
an explicit operator-triggered reload of a snapshot-swapped handle.** For a 1:1
deployment the whole administrative surface is "replace this file, reload" —
there is no multi-tenant case that would justify (b)'s complexity.

This also **closes a D17 gap**: D17 explicitly records that "distribution,
rotation, and revocation of rosters remain manual operational processes"
(`DESIGN_DECISIONS.md:845-846`). D27 makes rotation/revocation a runtime
operation while keeping distribution manual (still out-of-band).

---

## §3 Atomic roster replacement

**Invariant: parse-then-swap, never mutate-in-place.** A reload either fully
adopts a new roster or changes nothing.

Implementation (`RosterHandle`, `pq-tunnel-bin/src/identity.rs`):

- `reload()` calls `load_roster` → `parse_blobs` → per-key
  `MlDsaPublicKey::from_bytes`. Any error returns `Err` **without touching the
  published snapshot**.
- An empty parse result is rejected (`IdentityError::EmptyRoster`,
  `identity.rs:92-93`) — a reload can never narrow the trusted set to nothing.
  Note `load_roster` already fails closed here; `RosterHandle::reload`
  re-checks defensively because it is a security boundary.
- **Exactly one publication point:** `self.current = Arc::new(parsed);`. Readers
  take `Arc::clone(&self.current)`.
- `ServerHandshake::set_roster` (`handshake_v2.rs`) likewise validates
  non-empty before assigning `self.cfg.roster`.

**What concurrent readers see:** a reader holding an `Arc` snapshot keeps seeing
its complete generation for as long as it holds it, even after a swap — the old
roster stays alive until the last reader drops it. A reader that samples after
the swap sees the entire new roster. **No reader can ever observe a partial,
empty, or mixed roster.** This is pinned by
`roster_replacement_is_atomic_under_concurrent_readers` (3 threads × 200 swaps)
and `held_snapshot_survives_a_swap_unchanged`.

Note the existing `write_atomic` helper (`identity.rs:279`) already writes
provisioning files via temp-file + rename, so a *writer* using
`save_roster`/`append_roster` cannot produce a torn file. A hand-edited
non-atomic write is still possible; that is why the reader is fail-closed rather
than trusting the file.

---

## §4 In-flight handshake semantics (the M3 re-check)

Authentication happens at **`complete_m1`** (`handshake_v2.rs:1595-1626`):
the roster is iterated with no early exit (D12, line 1619), the matched key is
stored in `entry.verified_client` (line 1661), and the entry moves to
`AwaitM3`.

A handshake that authenticated at M1 and completes at M3
(`on_m3_fragment`, `handshake_v2.rs:1669`+) therefore creates a session
**without re-consulting the roster** in the pre-D27 code. Window: `pending_ttl`
(default 30 s, `handshake_v2.rs:1276`).

**Decision: re-check membership at M3, immediately before the outcome is
returned.** Implemented in `on_m3_fragment`, right after the Finished-MAC
comparison and before `ServerEvent::Complete`:

```rust
let peer_identity = entry.verified_client.clone().expect("set at M2");
...
if !self.roster_contains(&peer_identity) {
    self.pending.remove(&sid);
    return Ok(ServerEvent::None);
}
```

Properties:

- **Position is after the MAC check**, so an attacker cannot forge an M3 and
  learn anything from the re-check; it is a no-op on the unauthenticated path.
- **Fail-closed:** the pending entry is dropped (its key material zeroized on
  drop, D14) and no outcome is returned. The client gets no session and simply
  retries into its own budget.
- **Silent**, matching every other peer-input failure (D12/D13).
- `roster_contains` compares full encoded keys; it is **not** constant-time and
  is **not** on any authentication path — it only answers "is this key still
  trusted", after the signature has already verified.

Pinned by `midflight_revocation_blocks_m3_completion`, which is load-bearing:
disabling the check makes that test fail (verified).

---

## §5 Established sessions on revocation

**Decision: revocation gates *future* establishment. It does not tear down an
already-established session. `lifetime_cap` is what bounds the session.**

Justification:

1. **What an attacker with a captured traffic key learns.** Keys are
   session-scoped (D14: per-direction keys derived from a per-session master,
   D4: the sid identifies sessions, not users). A captured key decrypts only its
   own session's packets. The bound that matters is *how much of one session's
   traffic* is exposed. `lifetime_cap` bounds that. Killing the session at
   revocation time does **not** retroactively protect the traffic already
   captured — it only stops *future* packets.
2. **Operational cost of an immediate kill.** In a 1:1 deployment the revoked
   key usually *is* the attacker's key, and the legitimate client's session is
   a different session. Killing everything on any roster change would let a
   routine key rotation drop the legitimate tunnel. Immediate teardown
   additionally has no signal to distinguish "operator rotated keys" from
   "operator revoked an attacker".
3. **The session was authenticated at establishment** (M1 roster verify, §4).
   A live session's continued existence is a consequence of a valid
   authentication, not a stale grant.

The exposure window for a session whose key is revoked mid-flight is therefore
`time_of_revocation → established_at + lifetime_cap`, bounded by the cap. With
the §1 default that is at most 24 h, and it closes with
`Closed{LifetimeCap}` — which is exactly the D16 rotation that would have
happened anyway.

Pinned by `revocation_defers_to_lifetime_cap_for_established_sessions`.

---

## §6 D16 rotation and revoked keys

Confirmed by reading the code path:

- Rekey = close + full re-establish (`DESIGN_DECISIONS.md:780-786`).
- The client closes with `Closed{NonceExhausted}` (`session_manager.rs:981-987`)
  or `Closed{LifetimeCap}` (`session_manager.rs:939-948`), and the driver calls
  `rearm_client` (`session_manager.rs:1560`), which calls `begin_handshake`
  (`session_manager.rs:790`) — a **fresh sid, fresh ephemerals, fresh master**.
- The new handshake's M1 is verified against the **current** roster
  (`complete_m1`, `handshake_v2.rs:1595`).

**Therefore re-establishment after a revoked key fails cleanly:** M1 does not
authenticate → no M2 → the client exhausts `m1_max_attempts` (8) →
`HandshakeV2Error::Timeout` → `Closed{HandshakeTimeout}` (`session_manager.rs:871-879`).
No session is created, no keys are derived, and the tunnel stays down. This is
fail-secure per AGENTS.md.

Verified by `revoked_key_cannot_re_establish`,
`revoked_client_retry_loop_never_establishes`, and
`revocation_defers_to_lifetime_cap_for_established_sessions` (which asserts
post-cap re-establishment against the revoked roster produces nothing).

---

## State machine

### Diagram

```
                         ROSTER RELOAD (atomic swap)
                         ┌──────────────────────────────────────────┐
                         │  parse-then-swap; on error: no change    │
                         └──────────────────────────────────────────┘
                                          │
   ┌──────────┐   M1 fragments   ┌────────▼─────────┐  no M2 within
   │          │ ────────────────>│  HANDSHAKING      │  pending_ttl (30 s)
   │  IDLE    │                  │  (M1 authed,      │──────────────┐
   │ (client) │                  │   roster verified)│              │
   └──────────┘                  └────────┬─────────┘              v
        ▲                                │ M3 + Finished MAC    ┌──────────┐
        │                                │ + roster re-check    │  DROPPED │
        │                    ┌───────────┴───────────┐           │ (silent) │
        │                    │                       │ revoked   └──────────┘
        │                 PASS (member)          FAIL (revoked)
        │                    │                       │
        │                    v                       └──> DROPPED (pending entry
        │          ┌──────────────────┐                  removed, keys zeroized,
        │          │   ESTABLISHED    │ <──────────────  no session, no M2/M3
        │          │ (session created)│                 returned)
        │          └────────┬─────────┘
        │                   │
        │     ┌─────────────┼──────────────┬─────────────────┐
        │     │             │              │                 │
        │  lifetime_cap  idle_timeout   NonceExhausted   peer Close (0x03)
        │  (>= cap)      (server, no    (D16 rekey      (client tears down,
        │                cover activity)  trigger)        no ack)
        │     │             │              │                 │
        │     v             v              v                 v
        │  ┌──────────────────────────────────────────────────┐
        └──│  Closed{LifetimeCap|NotConfirmed|NonceExhausted │
           │          |PeerClosed|UserClosed|...}             │
           │  └──────────────────────────────────────────────────┘
                         │
                         │  client driver: rearm_client → begin_handshake
                         │  (fresh sid, fresh ephemerals, fresh master)
                         v
                    back to IDLE

  Server-side effect of any Closed: session removed, keys zeroized on drop (D14).
  The server does NOT re-accept the revoked key: the next M1 fails the roster
  check (§4) and the handshake is dropped silently.
```

### Transition table

States: `IDLE` (client, no session), `HANDSHAKING` (M1 authenticated),
`ESTABLISHED`, `DROPPED` (terminal for that handshake).

| # | From | Event | Guard / Condition | Action | To | Observable |
|---|---|---|---|---|---|---|
| 1 | `IDLE` | operator starts / re-establish | none | `begin_handshake`: fresh sid, fresh ephemerals; emit M1 | `HANDSHAKING` | M1 fragments |
| 2 | `HANDSHAKING` | M1 roster verify | key **in** roster | generate KEM/X25519 ephemerals, sign M2, store `verified_client`, state `AwaitM3` | `HANDSHAKING` | M2 fragments |
| 3 | `HANDSHAKING` | M1 roster verify | key **not** in roster | drop pending entry, no M2, no state | `DROPPED` | nothing (silent) |
| 4 | `HANDSHAKING` | M3 + Finished MAC verify | MAC **bad** | silent drop, entry stays `AwaitM3` (retry-friendly) | `HANDSHAKING` | nothing |
| 5 | `HANDSHAKING` | M3 + Finished MAC **and** roster re-check | revoked since M1 | remove pending entry (keys zeroized), no outcome | `DROPPED` | nothing (silent) |
| 6 | `HANDSHAKING` | M3 + Finished MAC **and** roster re-check | still a member | create session, `established_at = now` | `ESTABLISHED` | `Established{sid, peer}` |
| 7 | `HANDSHAKING` | `pending_ttl` (30 s) elapsed | none | evict pending entry | `DROPPED` | nothing |
| 8 | `HANDSHAKING` | M1 budget exhausted (8) | none | `Closed{HandshakeTimeout}` | `IDLE` | `Closed{HandshakeTimeout}` → rearm |
| 9 | `ESTABLISHED` | tick | `now - established_at >= lifetime_cap` | remove session, keys zeroized | `IDLE` | `Closed{LifetimeCap}` → rearm |
| 10 | `ESTABLISHED` | tick (server) | `now - last_activity >= idle_timeout` **and** cap not reached | remove session | `IDLE` | `Closed{IdleTimeout}` |
| 10′| `ESTABLISHED` | tick (server) | both expired | reason = `LifetimeCap` (precedence, `session_manager.rs:626`) | `IDLE` | `Closed{LifetimeCap}` |
| 11 | `ESTABLISHED` | encrypt/decrypt at `MAX_PACKET_NONCE` | counter exhausted | remove session (D16 rekey) | `IDLE` | `Closed{NonceExhausted}` → rearm |
| 12 | `ESTABLISHED` | tick (client) | unconfirmed past `liveness_timeout` (30 s) | close | `IDLE` | `Closed{NotConfirmed}` → rearm |
| 13 | `ESTABLISHED` | peer `Close` (0x03) | decrypts | remove session, no ack | `IDLE` | `Closed{PeerClosed}` → rearm |
| 14 | `ESTABLISHED` | app-driven close | none | emit `Close`, then remove | `IDLE` | `Closed{UserClosed}` → rearm |
| 15 | `ESTABLISHED` | **roster reload, key NOT removed** | none | **nothing** — session continues | `ESTABLISHED` | data still flows |
| 16 | `ESTABLISHED` | **roster reload, key removed** | none | **nothing** — session continues to its cap | `ESTABLISHED` | data still flows (row 9 then bounds it) |
| 17 | any | **roster reload fails to parse / empty** | none | **nothing** — previous roster stays in force | unchanged | reload reports `Err` |
| 18 | `ESTABLISHED`/`HANDSHAKING` | `set_roster(vec![])` | empty | reject; old roster in force | unchanged | `Err` |

Row 16 + row 9 compose into the D27 §5 answer: a revoked-but-established
session is bounded by `lifetime_cap`, not killed at revocation time.
Rows 15–17 are the atomicity guarantee; row 18 is the fail-closed guard.

---

## Consequences

**Advantages:**

- Restores the D16 promise that exposure is bounded by session lifetime; in the
  default cover-on configuration `lifetime_cap` is the *only* such bound (§1.3).
- Revocation without restart: routine key rotation no longer drops unrelated
  sessions (there are none in 1:1, but the server process and its state survive).
- The M3 re-check closes a real window in which a revoked key could still obtain
  a session (§4).
- Atomic swap with immutable snapshots: no reader ever sees a partial roster
  (§3), and every failure path is fail-closed.
- No new network surface: file + reload, not an admin socket (§2).

**Tradeoffs:**

- `lifetime_cap` becomes a real operational behavior change (a daily rekey blip).
  Mitigated by a visible CLI flag per D9; the default itself is a gate below.
- Revocation does not kill live sessions (§5). An operator revoking a
  *suspected-compromised* key must wait out the cap (≤ 24 h by default) to stop
  that session's traffic. A `revoke_grace` / immediate-kill option is a
  deliberate future addition, not a default.
- Reload detection is operator-triggered (or poll-based); a server whose roster
  file is edited but never reloaded keeps the old roster. A watcher or signal
  handler is not wired in this change — `RosterHandle::reload()` is the
  primitive.
- `roster_contains` is a non-constant-time key comparison. Acceptable because
  it runs only after signature verification and only answers a trust question,
  but it is a documented non-guarantee.

---

## Verification

- `pq-tunnel-bin/tests/revocation_lifetime.rs` — 13 tests, all passing:
  - `lifetime_cap_fires_and_yields_closed_lifetime_cap`
  - `client_side_lifetime_cap_closes_and_re_arms`
  - `lifetime_cap_takes_precedence_over_idle_timeout`
  - `idle_timeout_before_cap_reports_idle_timeout`
  - `revoked_key_cannot_re_establish`
  - `midflight_revocation_blocks_m3_completion` (**verified load-bearing**: the
    test fails when the M3 re-check is disabled)
  - `empty_roster_swap_is_rejected_fail_closed`
  - `revoked_client_retry_loop_never_establishes`
  - `established_session_survives_non_removing_roster_swap`
  - `revocation_defers_to_lifetime_cap_for_established_sessions`
  - `roster_reload_is_fail_closed_on_bad_input`
  - `roster_replacement_is_atomic_under_concurrent_readers`
  - `held_snapshot_survives_a_swap_unchanged`
- `cargo test -p pq-tunnel-core --target x86_64-pc-windows-msvc` — 242 passed,
  0 failed (the count includes tests added concurrently by other tracks; the
  D27 change adds no new core unit tests — coverage lives in the integration
  suite below).
- `cargo test -p pq-tunnel-bin --target x86_64-pc-windows-msvc` — all targets
  green (41 lib + 6 adversarial + 3 smoke + 3 stress + 13 new).
- `cargo clippy -p pq-tunnel-core -p pq-tunnel-bin --all-targets -- -D warnings`
  clean.

### Not covered / UNVERIFIED

- The 1-day default itself is **not yet implemented** — `session_manager.rs:141`
  still reads `None`, and no CLI flag was added. §1 records the analysis and the
  recommendation; the code change is behind the owner gate below.
- The reload **trigger** (watcher / SIGHUP / poll interval) is not implemented;
  only the atomic `RosterHandle` primitive and `ServerHandshake::set_roster`.
- No test asserts the *value* 86400 anywhere, by design: the constant is the
  gate, and tests pin behaviour rather than a magic number.
- Multi-tenant concerns are out of scope by the 1:1 product constraint.

---

## Human decision gate

**Needs owner approval (genuinely a judgment call, not an implementation detail):**

1. **The 1-day value itself.** The analysis proves a cap is *needed* (§1.3) and
   that 1 day is not justified by nonce arithmetic (§1.2). But 24 h vs 12 h vs
   7 days is an operational judgment: daily rekey blips vs a longer compromise
   window. **Recommended: 24 h, CLI-overridable, `--lifetime-cap-secs` with
   `0` meaning "unbounded".**
2. **Whether the cap may ever be unbounded in production.** Defaulting to
   "off is allowed" preserves D7's parameter philosophy but means a single
   `--lifetime-cap-secs 0` silently restores unbounded exposure. Decide whether
   unbounded requires an explicit, separately-named flag
   (e.g. `--no-lifetime-cap`, mirroring the `--no-cover` precedent at
   `lib.rs:103-107`).
3. **§5 — whether revocation should ever kill live sessions.** Recommended: no
   (bounded by cap). A `revoke_grace 0` / immediate-kill mode is a reasonable
   future option for a *suspected-compromised* key; it is a security-vs-availability
   tradeoff the owner should own, not a default.
4. **Reload trigger.** File-watch vs poll interval vs SIGHUP-equivalent. The
   primitive is built and tested; the trigger is an operational choice. For
   1:1, poll-on-interval is the simplest and needs no platform signal API.
5. **Whether `lifetime_cap` should be split per role.** Currently one field for
   both roles. A server may reasonably want a longer cap than a client (the
   client drives rotation, so a short cap causes client-side churn). Splitting
   is an API change.

**Safe to implement without asking (behaviour-preserving or strictly
tightening, already verified):**

- The M3 roster re-check (§4) — pure fail-closed hardening, no new surface, no
  new configuration; only ever rejects sessions a revoked key would have got.
- `ServerHandshake::set_roster` / `roster_contains` / `roster_len` and
  `ServerSessionManager::set_roster` / `roster_len` — additive API.
- `RosterHandle` with parse-then-swap and fail-closed reload — the atomicity
  invariant and its tests.
- Renaming D17's "revocation remains manual" limitation once a trigger exists.

---

# Amendment A — Track B (runtime revocation), 2026-10-21

**Prior status of this record (unchanged above, restated for the record):**
*Proposed (implementable; the owner gates in "Human decision gate" below are not
yet approved).*

**Status after this amendment:** *Proposed (amended — the runtime-revocation
mechanism described in §2, §3 and the Human decision gate below is now
specified in `docs/design/D32-runtime-revocation.md`; the reload trigger, the
data-sharing model and the file-read protocol are settled there and the
corresponding gates below are marked RESOLVED. The `lifetime_cap` default and
gates 1, 2, 3 and 5 remain open.)*

This amendment **appends** to D27. It does not rewrite, delete or re-interpret
the text above; where the two disagree, this section states the correction
explicitly. The implementation-ready detail is
[`docs/design/D32-runtime-revocation.md`](../design/D32-runtime-revocation.md)
("D32"); all `file:line` citations below are against the baseline commit
`c6c0f12`.

## A.1 The M3 re-check is load-bearing and must not be weakened

**CONFIRMED, and confirmed to be load-bearing.** D27 §4's re-check is present
at `pq-tunnel-core/src/handshake_v2.rs:1949-1952`, positioned **after** the
Finished-MAC comparison (`:1932-1937`) and **before** `ServerEvent::Complete`
(`:1954-1960`). It reads the roster that is in force at M3 time
(`roster_contains` reads `self.cfg.roster`, `:1577`; `set_roster` replaces it
wholesale, `:1563`).

`pq-tunnel-bin/tests/revocation_lifetime.rs:365`
(`midflight_revocation_blocks_m3_completion`) fails if the block is removed,
because the pending entry would then complete and `ManagerEvent::Established`
would be emitted.

**Amendment:** the re-check is a **permanent, load-bearing** control. It must
not be weakened, reordered before the MAC check, made conditional, or replaced
by a membership pre-filter in front of the D12 uniform verification loop
(`handshake_v2.rs:1813-1819`). A pre-filter would make the number of ML-DSA
verifications attacker-observable and would permit the early exit D12 rejects.

## A.2 Runtime reload was never wired into the shipped server

**CONFIRMED.** `set_roster` has **zero production call sites**. Its only
occurrences are the definition (`handshake_v2.rs:1550`), the delegation on
`ServerSessionManager` (`session_manager.rs:551-552`), and three `#[cfg(test)]`
call sites in `handshake_v2.rs` (`:3573`, `:3596`, `:3599`).

`RosterHandle` appears only in its own definition
(`pq-tunnel-bin/src/identity.rs:540`) and in the test suite
(`pq-tunnel-bin/tests/revocation_lifetime.rs:28`, `:561`, `:626`, `:694`).

The shipped server loads the roster once (`pq-tunnel-bin/src/v2_server.rs:52`),
builds the config (`:54`) and constructs the manager (`:56`).

**Amendment:** D27 §2's decision ("a file-watch/periodic-reload on the roster
path") and its Consequences bullet ("A watcher or signal handler is not wired
in this change — `RosterHandle::reload()` is the primitive") remain accurate as
a statement about the tree. D27's "Not covered / UNVERIFIED" bullet "The
reload **trigger** ... is not implemented" is likewise confirmed. **The
revocation feature does not exist in the shipped server**: revoking a client
key still requires a restart, which kills every live session.

## A.3 The `RosterHandle` clone defect

**CONFIRMED.** `RosterHandle` is `#[derive(Clone)]` with an
`Arc<Vec<MlDsaPublicKey>>` field (`identity.rs:539-542`) and publishes a new
generation by **replacing** that `Arc` (`identity.rs:609`).

`Clone` for `Arc<T>` increments the strong count and copies the pointer, so a
clone shares the same allocation. A `reload` on the original installs a
*different* allocation in the original only. **A clone therefore stays pinned to
the generation that was current at clone time and never observes a subsequent
reload.** The divergence is permanent, not a transient race.

In the shipped tree this is a latent trap rather than an active defect: the
roster is read only by the handshake machine, which owns its own `Vec`. But
`RosterHandle` is a **public** type of `pq_tunnel_lib`, so any future change
that wants a second reader of the roster (a health endpoint, an admin
interface) steps directly on it and gets a silently stale view of the trust
anchor.

**Amendment:** D27 §3's description of the implementation (`RosterHandle`,
"Exactly one publication point: `self.current = Arc::new(parsed);`. Readers
take `Arc::clone(&self.current)`") is **withdrawn**. The replacement design has
**no shared roster cell**; see A.5.

## A.4 The shipped atomicity test is vacuous with respect to the swap

**CONFIRMED, and the claim in the review brief is correct.**
`pq-tunnel-bin/tests/revocation_lifetime.rs:616-683`
(`roster_replacement_is_atomic_under_concurrent_readers`).

The reader threads hold a **clone** of the handle (`:631`). Because of A.3,
that clone's `Arc` is the *same allocation* the original used, and `reload`
replaces the original's pointer without ever mutating that allocation. Every
sample therefore yields exactly the generation `[A]`:

- `is_a == true` always (`:644`),
- the assertion `is_a || is_ab` (`:646-650`) **can never fail**,
- the assertion `!snap.is_empty()` (`:639`) **can never fail**,
- `total_samples > 0` (`:678-680`) proves only that the threads ran.

**The readers never observe generation 2 at all.** The property D27 §3 claims
the test pins -- "A reader that samples after the swap sees the entire new
roster" (D27 §3, lines 215-221) -- is **not exercised**.

**What the test *does* still pin, precisely.** Because the readers are pinned
to the same allocation, an implementation that mutated the `Vec` **in place**
(leaving `self.current` unchanged while clearing and refilling it) *would* be
caught. The test therefore pins exactly one thing:

> **The published `Vec` is never mutated in place; it is replaced wholesale.**

It pins nothing about the swap, about generation ordering, or about a reader
ever observing the new generation.

**Amendment:** D27 §3's claim that the atomicity property is "pinned by
`roster_replacement_is_atomic_under_concurrent_readers` (3 threads x 200 swaps)
and `held_snapshot_survives_a_swap_unchanged`" is **corrected**: the first of
those two tests must be **deleted and replaced** by one that observes both
generations and can actually fail. D32 §12.3 specifies the replacement
(`roster_read_is_whole_under_concurrent_replacement`, which asserts
`saw_a && saw_ab`, and `roster_read_never_publishes_a_torn_prefix`, which pins
the stability check). `held_snapshot_survives_a_swap_unchanged` is retained but
re-purposed.

## A.5 The adopted reload model

D27 §2's option table is unchanged: (b) an admin RPC/socket stays **rejected**,
(d) restart-only stays **rejected**, and the file-watch/poll path is **adopted**.

What is now settled (D32 §§3 to 5):

- **Trigger.** `--roster-watch <secs>`, default 5, `0` disables. Plus an
  opt-in Unix `SIGHUP` (`--roster-reload-on-hup`), off by default because
  installing a handler changes SIGHUP's conventional meaning. A poll was
  chosen over a signal because SIGHUP does not exist on Windows and
  `tokio::signal::ctrl_break` needs a console and a process group, so a poll is
  the only trigger that behaves identically on the CI target and the primary
  deployment platform. **No new network surface.**
- **Data-sharing model.** **Single owner, message passing.** The roster stays a
  plain `Vec<MlDsaPublicKey>` owned by `ServerHandshake.cfg.roster` inside the
  one task that owns the driver. A reload is delivered to that owner as an
  `mpsc` message and adopted through `ServerSessionManager::set_roster`. There
  is no `Arc<RwLock<...>>`, no `arc-swap` dependency, and no shareable roster
  handle that could be cloned. **"A reader observes exactly one whole
  generation" is therefore true by construction**, because every read and the
  single write take `&mut self` and execute in one task.
- **File-read protocol.** One handle; metadata captured from the handle before
  and after a single `read_to_end`; the read is refused if the file changed
  underneath it; then the strict `PQTI` / `version: 1` / `type: roster`
  grammar, then validation (at most `max_roster_size` payload lines **checked
  before any key is decoded**, at least one key, every key exactly 1952 bytes,
  every key a decodable ML-DSA-65 public key). A candidate is published only
  if every check passes.
- **Fail-closed gate.** The gate is the **parse/validation** gate (malformed,
  empty, oversize, unstable) -- never a size- or membership-based rule. D27 §3's
  "parse-then-swap, never mutate-in-place" invariant is retained and is now
  enforced by the single-`Vec`-move publication point.

**The valid-subset policy (new, and it settles the ambiguity in D27 §3 and
§5).** A roster file that parses, is non-empty and is within the bound is
**published even if it is a strict subset of the roster in force**. A narrowing
IS revocation. Refusing a narrowing would be a *silent failure to revoke* (a
security failure); publishing one that was not intended is an *availability*
failure, which is loud -- the reload is logged at `warn!` with the roster size,
the roster fingerprint and the per-key fingerprints of the added and removed
keys. **An availability failure is the safe direction; a security failure is
not.** D10 ("Tunnel fails securely") is about not continuing *insecurely*; it
does not require refusing to *act*.

The defence against an unintended narrowing is therefore **operational and
observable**, not a validation rule: the operator replaces the roster
**atomically**; the server detects an in-flight in-place rewrite and refuses
it; every adoption is logged; and the roster fingerprint is a stable,
order-independent identifier of the *set*, so the operator can confirm that
what is in force is what they intended. The server **cannot** distinguish
"revoked" from "rotated" from "clobbered by an old backup": there is no signed
manifest, no generation counter in the file and no per-key revocation record,
and adding any of them is out of scope for this wave.

**Failure behaviour.** A **runtime** reload failure is **never fatal**: the
roster in force stays in force, the server keeps serving, the failure is
logged and retried on the next poll. A **startup** failure remains **fatal**
(the server does not start with an untrusted roster). The asymmetry is
deliberate: at startup there is no previous roster to fall back to. **Fail-secure
is not fail-stop**: the secure state is "the last known-good roster", not "no
server".

**Latency, stated plainly.** The effective time of a revocation is **the moment
the driver applies the swap**, not the moment the operator edited the file. The
bound is the poll interval plus the 1 s quiescence window -- about 6 s with the
defaults. A second, sub-millisecond window remains in the same `select!`
iteration and is closed by draining the reload channel at the top of the
transport branch.

## A.6 Policy for already-established sessions (unchanged, with the reasoning re-verified)

D27 §5's decision stands: **revocation gates future establishment; it does not
tear down an already-established session.** The re-verification added three
points of reasoning that were not in the original text:

1. **Revoking the identity key does not expose the established session.** The
   traffic keys are session-scoped and derived from ephemeral handshake
   secrets (D14), and the identity key never enters the key schedule
   (`DESIGN_DECISIONS.md:509-510`). An attacker who steals the client's
   *identity* seed can forge new handshakes; it gives them nothing about an
   already-established session's traffic keys. Killing the session protects
   against essentially nothing.
2. **The signal is ambiguous.** Without a signed manifest or a per-key
   revocation record, the server cannot distinguish "the operator revoked A"
   from "the operator rotated A to B" from "the operator restored an old
   backup". A "kill sessions whose key left the roster" policy would kill the
   legitimate session during a routine rotation -- a self-inflicted denial of
   service with no security benefit.
3. **D16 rotation already re-runs the roster check**, so a revoked client
   cannot rotate back in: M1 does not authenticate, no M2 is produced, the
   client burns its `m1_max_attempts` budget and reports
   `Closed{HandshakeTimeout}`. Verified by
   `revoked_key_cannot_re_establish` (`revocation_lifetime.rs:330`) and
   `revoked_client_retry_loop_never_establishes` (`:417`).

## A.7 The 24 h `lifetime_cap` is the exposure bound

D27 §5 already bounds the exposure window of a revoked-but-alive session by
`lifetime_cap`. This amendment names the bound explicitly and records the
dependency it creates:

> **The 24 h cap is the bound on exposure; revocation is not.** With the cap
> enabled, a session established by a revoked key lives at most until
> `established_at + 24 h`, after which `Closed{LifetimeCap}` fires
> (`CloseReason::LifetimeCap`, `pq-tunnel-core/src/session_manager.rs:170`) and
> the client re-establishes -- which fails at M1 against the revoked roster.

`SessionLimits::lifetime_cap` is currently `None` by default
(`session_manager.rs:150`) and is **not** enabled by any shipped binary. The
consequence must be recorded rather than left implicit:

> **Without the cap, a revoked-but-alive session is unbounded.** Revocation
> bounds only *future* establishment. The runtime-revocation feature must not
> be read as fixing the D27 §1.3 exposure hole; the cap is what closes it.

This dependency is why D27 §1.6's default decision (`Some(24h)`, with a visible
CLI override) matters beyond its own section: it is the bound that makes
"revocation does not kill live sessions" an acceptable trade.

## A.8 Citation drift in this record

The `file:line` citations in the text above were written against an earlier
tree and no longer resolve. **They are left unchanged** (this amendment does
not rewrite the record), but the verified locations are:

| D27's citation | Verified location at baseline `c6c0f12` |
|---|---|
| `session_manager.rs:141` (`lifetime_cap` default `None`) | `session_manager.rs:150` |
| `session_manager.rs:141` (`idle_timeout` default) | `session_manager.rs:149` |
| `session_manager.rs:141` (`max_sessions` default) | `session_manager.rs:148` |
| `session_manager.rs:468` / `:585` / `:544` (the `last_activity` refresh sites) | `session_manager.rs:659` / `:776` / `:735` |
| `session_manager.rs:621` (`last_activity` read) | `session_manager.rs:812` |
| `codec.rs:121` (`MAX_PACKET_NONCE`) | `codec.rs:129` |
| `codec.rs:104` (`PACKET_SIZE`) | `codec.rs:112` |
| `handshake_v2.rs:1595-1626` (`complete_m1`) | `handshake_v2.rs:1793-1830` |
| `handshake_v2.rs:1661` (the matched key is stored) | `handshake_v2.rs:1868` |
| `handshake_v2.rs:1669` (`on_m3_fragment`) | `handshake_v2.rs:1879` |
| `handshake_v2.rs:1276` (`pending_ttl`) | `handshake_v2.rs:1353` |
| `handshake_v2.rs:1372-1377` (`ServerHandshake::new` clones the roster) | `handshake_v2.rs:1511-1515` |
| `identity.rs:92-93` (`EmptyRoster`) | `identity.rs:105-106` |
| `identity.rs:279` (`write_atomic`) | `identity.rs:325-352` |

D32 Appendix A records the further drift between the baseline and the working
tree as of this amendment.

## A.9 Human decision gate -- gate-by-gate status

The gate list in the text above is unchanged. This amendment records which
gates it closes and which it leaves open.

| Gate | Status after this amendment |
|---|---|
| 1. The 1-day value itself | **OPEN.** Unchanged. |
| 2. Whether the cap may ever be unbounded in production | **OPEN.** Unchanged. |
| 3. Whether revocation should ever kill live sessions | **OPEN**, but **the recommendation is unchanged and now carries three arguments** (A.6). A kill mode would need a per-key revocation marker in the file, which is out of scope for this wave. |
| 4. Reload trigger | **RESOLVED.** Poll on the roster path, default 5 s, plus an opt-in Unix SIGHUP. No admin socket. A failed reload is not fatal and is retried. See A.5 and D32 §4. |
| 5. Whether `lifetime_cap` should be split per role | **OPEN.** Unchanged. Not a dependency of the runtime-revocation design. |

New gates raised by the runtime-revocation design, carried in D32 §13: the
poll interval and whether polling is on by default (H1), whether an unintended
narrowing should be published or confirmed (H2), whether SIGHUP is worth
having at all (H3), whether duplicate roster keys should be rejected (H5),
whether the over-limit-roster startup error should be legible (H6), whether
the STATS line should carry the roster generation (H7), whether aggregate
rejected-handshake counters are added (H8), whether the quiescence window
should be configurable (H10, recommended: no), and whether `RosterHandle` is
deleted or deprecated (H11, recommended: deleted).
