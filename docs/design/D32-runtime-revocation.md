# D32 -- Runtime Key Revocation: Design and Implementation Record

**Status:** DESIGN PROPOSAL. **No code in this document is implemented.** The
revocation *mechanism* described here is the subject of an amendment to
[`docs/decisions/D27-revocation-and-session-lifetime.md`](../decisions/D27-revocation-and-session-lifetime.md);
this document is the implementation-ready detail behind that amendment.
**Baseline commit:** `c6c0f12373f45cba02f6e8f44b386ea46d5da659` (read-only analysis).
**Scope:** the *server-side* roster lifecycle -- how a trusted-client roster is
provisioned, reloaded, published, observed and audited. It does not change the
handshake, the key schedule, the AEAD, the cover schedule or the wire format.

## Citation convention

Every `file:line` reference in this document is against the **baseline commit
`c6c0f12`**, verified by reading the file at that commit. The working tree is
concurrently under edit by another track, so line numbers in
`pq-tunnel-core/src/handshake_v2.rs` and `pq-tunnel-core/src/session_manager.rs`
have already drifted upward; the *constructs* are unchanged. The drift that was
observed at the time of writing is listed in Appendix A.

External protocol and platform claims carry an RFC section or a platform-doc
reference. Where a claim could not be verified, it is marked **[UNVERIFIED]**
rather than asserted.

## Relationship to D27

D27 owns the *semantics* of revocation and session lifetime. D27's §2 chose "a
file-watch/periodic-reload on the roster path"; D27's §3 specified the atomic
swap in terms of a `RosterHandle`; D27's §4 specified the M3 re-check. This
document:

1. **Corrects two defects** in D27's §3 implementation description (the
   `RosterHandle` clone trap and the vacuous atomicity test -- §1.3 and §1.4
   below).
2. **Confirms that D27's §4 M3 re-check is load-bearing** and must not be
   weakened (§1.1).
3. **Records that D27's reload trigger was never wired into the shipped
   server** and specifies it (§1.2, §4).
4. **Restates the established-session policy** (D27 §5) with the reasons that
   survived an adversarial review (§8).

Nothing here changes D27's decision that a **narrowing** (a strict subset of the
roster in force) is legitimate and must be published. §5.3 gives the explicit
reasoning.

---

## 1. Verified baseline findings

### 1.1 The M3 re-check exists, is correctly positioned, and is load-bearing

**CONFIRMED.** The server's M3 handler verifies the Finished MAC and *then*
re-checks roster membership before any outcome is produced.

| Step | What happens | Evidence (baseline `c6c0f12`) |
|---|---|---|
| M1: authenticate | The roster is iterated with **no early exit**; every roster entry's signature is verified and the results are OR-ed together. | `pq-tunnel-core/src/handshake_v2.rs:1813-1819` (`authed |= ok;` at `:1815`) |
| M1: reject | If nothing verifies, the pending entry is removed, **no M2 is produced**, and the handler returns `ServerEvent::None`. | `handshake_v2.rs:1820-1824` |
| M1: remember | The matched key is stored in `entry.verified_client`. | `handshake_v2.rs:1868` |
| M2 | KEM and X25519 work happens only *after* the signature verifies (D13 ordering). | `handshake_v2.rs:1826-1828` |
| M3: MAC | The Finished MAC is compared with `ct_eq`; a mismatch is a **silent drop with no state mutation**. | `handshake_v2.rs:1932-1937` |
| M3: re-check | `if !self.roster_contains(&peer_identity) { self.pending.remove(&sid); return Ok(ServerEvent::None); }` | `handshake_v2.rs:1949-1952` |
| M3: complete | `ServerEvent::Complete` is returned only after the re-check passes. | `handshake_v2.rs:1954-1960` |

**Why the position matters (three independent reasons):**

1. **After** the MAC check: the re-check can therefore only ever *reject*, never
   accept. Moving it before the MAC check would turn it into an unauthenticated
   oracle that distinguishes "key is in the roster" from "key is not" for
   arbitrary inputs.
2. **The roster read at M3 time** is whatever generation is in force at that
   instant: `roster_contains` reads `self.cfg.roster` (`handshake_v2.rs:1577`),
   and `set_roster` replaces that `Vec` wholesale (`handshake_v2.rs:1563`).
3. **The M1 verification loop is the membership check.** It must not be
   refactored into a separate `roster_contains` pre-filter. A pre-filter would
   make the number of ML-DSA verifications attacker-observable and would permit
   the early exit that D12's uniform verification count explicitly rejects.

**Load-bearing:** `pq-tunnel-bin/tests/revocation_lifetime.rs:365`
(`midflight_revocation_blocks_m3_completion`) fails if the block at
`handshake_v2.rs:1949-1952` is removed, because the pending entry would then
complete and `ManagerEvent::Established` would be emitted.

**Verdict:** the M3 re-check is correct as implemented and **must not be
weakened**, reordered, or made conditional. D27's §4 statement that it is
load-bearing is verified.

### 1.2 Runtime reload was never wired into the shipped server

**CONFIRMED.** `set_roster` has **zero production call sites**:

| Location | Kind |
|---|---|
| `pq-tunnel-core/src/handshake_v2.rs:1550` | definition |
| `pq-tunnel-core/src/handshake_v2.rs:3573`, `:3596`, `:3599` | `#[cfg(test)]` unit tests |
| `pq-tunnel-core/src/session_manager.rs:551-552` | definition + delegation to the handshake machine |
| `pq-tunnel-bin/src/identity.rs:599` | `RosterHandle::reload` (definition) |

The shipped server loads the roster exactly **once**:

- `pq-tunnel-bin/src/v2_server.rs:52` -- `identity::load_roster_with_limit(roster_path, args.max_roster_size)`
- `pq-tunnel-bin/src/v2_server.rs:54` -- `HandshakeV2ServerConfig::with_roster_limit(keypair, roster, args.max_roster_size)`
- `pq-tunnel-bin/src/v2_server.rs:56` -- `ServerSessionManager::new(&cfg, SessionLimits::default())`

`RosterHandle` appears only in its own definition (`pq-tunnel-bin/src/identity.rs:540`)
and in the test suite (`pq-tunnel-bin/tests/revocation_lifetime.rs:28`, `:561`,
`:626`, `:694`). **There is no production caller.**

**Consequence:** revoking a client key today requires **restarting the server**,
which kills every live session. This is the gap D27 was written to close, and
it is still open in the tree at the baseline.

### 1.3 The `RosterHandle` clone defect: an instance-local `Arc` that is replaced, not mutated

**CONFIRMED, with the exact mechanism.**

`pq-tunnel-bin/src/identity.rs:539-547`:

```rust
#[derive(Clone)]
pub struct RosterHandle {
    path: PathBuf,
    current: std::sync::Arc<Vec<MlDsaPublicKey>>,   // line 542
    max_roster_size: usize,
}
```

`#[derive(Clone)]` expands to `current: Clone::clone(&self.current)`. The
`Clone` impl for `Arc<T>` is "increment the strong count, copy the pointer" --
**not** a deep copy. So a clone shares the *same allocation* as the original.

`RosterHandle::reload` (`identity.rs:599-611`) publishes a new generation with:

```rust
self.current = std::sync::Arc::new(parsed);   // identity.rs:609 -- NEW allocation
```

This **replaces the pointer** in `self`. The old allocation survives only
because clones still hold strong references to it.

**The failure mode, stated exactly:**

> A clone taken at time *T* holds a strong reference to generation *g*. A
> `reload` on the original installs a **different** `Arc` (generation *g+1*) in
> the original **only**. The clone's `current` still points at *g*, and
> `clone.snapshot()` returns `Arc::clone(&clone.current)` == *g*, **forever**.
> The divergence is not a transient race; it is permanent.

**Severity in the shipped tree:** low. The roster is currently read only by the
handshake machine, which owns its own `Vec` and never uses `RosterHandle`.
`RosterHandle` is a latent trap in a **public** type of `pq_tunnel_lib`: any
future "let the health endpoint report the roster" or "let the admin UI show the
current roster" change steps directly on it, and the failure would be a
**silently stale** view of the trust anchor with no error and no log line.

**Design consequence:** the runtime reload must not be built on a
`Clone`-able shared roster handle. §3 adopts a single-owner model in which this
defect is structurally impossible.

### 1.4 The shipped atomicity test is vacuous with respect to the swap

**CONFIRMED.** The claim is correct.

`pq-tunnel-bin/tests/revocation_lifetime.rs:616-683`
(`roster_replacement_is_atomic_under_concurrent_readers`). State trace:

| Line | Event | `handle.current` | `reader_handle.current` |
|---|---|---|---|
| 626 | `RosterHandle::load` | `Arc₁` = `[A]` | -- |
| 631 | `let reader_handle = handle.clone();` | `Arc₁` | **`Arc₁`** (same allocation, count 2) |
| 666 | `handle.reload()` (x200) | `Arc₂, Arc₃, ...` (a new allocation each time) | **`Arc₁`** -- unchanged |
| 638 | `reader_handle.snapshot()` | -- | `Arc::clone(&Arc₁)` == `Arc₁`, **always** |

`Arc₁` is never written to after line 631: `reload` replaces the *original's*
pointer, it does not mutate the allocation. Therefore **every** sample yields
exactly `[A]`, and:

- `is_a == true` always (`revocation_lifetime.rs:644`),
- the assertion `is_a || is_ab` (`revocation_lifetime.rs:646-650`) **can never
  fail**,
- the assertion `!snap.is_empty()` (`revocation_lifetime.rs:639`) **can never
  fail** either, because `Arc₁` is immutable,
- `total_samples > 0` (`revocation_lifetime.rs:678-680`) proves only that the
  reader threads ran, not that they saw two generations.

**The readers never observe generation 2 at all.** The property D27 §3 claims
the test pins -- "A reader that samples after the swap sees the entire new
roster" (`docs/decisions/D27-revocation-and-session-lifetime.md:215-221`) --
is **not exercised**.

**What the test *does* still pin -- precisely.** Because the readers are pinned
to the *same allocation* the original used, an implementation that mutated the
`Vec` **in place** (leaving `self.current` unchanged while clearing and
refilling the `Vec`) *would* be caught: the readers would observe a torn or
empty roster and the assertions would fire.

So the test is not entirely inert. It pins exactly this:

> **The published `Vec` is never mutated in place. It is replaced wholesale.**

It pins **nothing** about the swap itself, about generation ordering, or about
a reader ever observing the new generation. A test suite that *looks* like it
covers atomic replacement while covering only in-place-mutation is worse than
no test, because a future maintainer will trust it.

**Required action:** delete the test and replace it with one that (a) observes
*both* generations and (b) can actually fail. §12 specifies the replacement.

### 1.5 The "publishing an unintended valid subset" hazard

**CONFIRMED as a real hazard.** A roster file that parses cleanly, is
non-empty, and is within the size bound is a *legal* roster -- there is
nothing in the file that distinguishes "the operator revoked A" from "the
operator rotated A to B" from "a buggy script clobbered the file with an old
copy". No signed manifest, no generation counter in the file, no per-key
revocation record exists, and adding any of them is out of scope for this wave.

The direction of the error is what matters, and it is analysed in full in §5.3.
Summary: **refusing** a narrowing is a *silent failure to revoke* (a security
failure); **publishing** an unintended narrowing is an *availability* failure
(a loud outage). The design publishes, loudly.

### 1.6 Additional defects found by the analysis

These were not in the original brief. All are verified against the baseline.

| # | Defect | Evidence | Severity |
|---|---|---|---|
| **D6** | `roster_contains` allocates on **every** comparison: `k.encode() == pk.encode()` and `encode()` returns a fresh `Vec<u8>` of 1952 bytes. `any` short-circuits, so the cost depends on the key's position: up to 65 allocations (one per roster entry plus one for the argument), about 124 KB, per completed handshake at the 64-key bound. The ML-DSA verification dominates the cost, so this is a performance wart, not a security issue. | `handshake_v2.rs:1576-1578`; `pq-crypto/src/signature.rs:115-118` | Low (perf) |
| **D7** | `ServerConfig::with_roster_limit` **silently empties** an over-limit roster (`if roster.len() <= max_roster_size { cfg.roster = roster }` -- otherwise `cfg.roster` stays `Vec::new()`). `ServerHandshake::new` does the same. The operator therefore sees "roster must not be empty" for a 65-key roster instead of "roster of 65 keys exceeds the maximum of 64". The **reload** path is precise (`set_roster` reports the size). | `handshake_v2.rs:1342-1361` (specifically `:1357-1359`); `handshake_v2.rs:1511-1515` | Low (ergonomics); worth fixing because reload errors must be legible |
| **D8** | A **stale twin** of the trusted set lives in `v2_server::run`'s local `cfg` for the whole process lifetime: `ServerSessionManager::new(&cfg, ...)` takes `&ServerConfig` and `ServerHandshake::new` deep-clones it (`handshake_v2.rs:1512`). It is never read after construction, so it is not a correctness bug today, but it is a second copy of the trust anchor that a reload would not update. | `pq-tunnel-bin/src/v2_server.rs:54-57`; `handshake_v2.rs:1511-1515` | Low; one-line fix (`drop(cfg)` after the manager is built) |
| **D9** | `roster_contains` short-circuits on the first match, so the *position* of a key in the roster is timing-observable. This is post-authentication only and is on no authentication path. D27 §4 already records `roster_contains` as a non-constant-time comparison; the position leak is a sharper statement of the same non-guarantee. | `handshake_v2.rs:1576-1578` | Accepted, documented |

**Not a defect, recorded to avoid a false positive:** the roster contains only
**public** keys. `ServerConfig` derives `Clone` and `ServerHandshake::new`
deep-copies the `Vec`; a deep copy of public material is safe, and no
zeroization is required. The secret material -- the identity *seed* -- lives in
a separate file (`pq-tunnel-bin/src/identity.rs:378`).

---

## 2. The state machine

The roster lifecycle is a **server-side** state machine. It is deliberately
*not* the client handshake state machine (D27's diagram,
`docs/decisions/D27-revocation-and-session-lifetime.md:336-379`).

```
                              server start
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  load_roster_with_limit()     │   identity.rs:443
                    │  (read → parse → validate)   │
                    └───┬──────────────────────┬───┘
              ok, ≥1 key │                      │ any error (missing / empty /
                        │                      │  bad header / bad hex /
                        ▼                      │  oversize / unreadable)
      ┌───────────────────────────┐            │
      │      PROVISIONED          │            ▼
      │  generation = 1           │      ┌──────────────────────┐
      │  roster in force          │      │  PROCESS EXIT (1)    │
      └───────────┬───────────────┘      │  fail closed: never  │
                  │                      │  start with no       │
                  │                      │  trusted clients     │
                  │                      └──────────────────────┘
                  ▼
      ┌────────────────────────────────────────┐
      │             ACTIVE(gen N)               │  ← the only state in which
      │  published roster = G(N)                │    the server serves
      │  G(N) is immutable once published       │
      └────┬─────────────────────────────┬─────┘
           │                             │
           │ reload requested            │ reload attempt FAILED
           │ (file changed / SIGHUP)     │ (parse error / empty / oversize /
           ▼                             │  missing / unreadable / unstable read)
   ┌───────────────────────────┐         │
   │        RELOADING          │         │
   │  candidate C built off to  │         │
   │  the side; G(N) STILL IN  │         │
   │  FORCE (nothing published)│         │
   └───┬───────────────────┬───┘         │
       │                   │             │
       │ C validates       │ C fails     │
       │ (non-empty,       │             │
       │  ≤ max_roster_size│             │
       │  every key decodes)│             │
       ▼                   └─────────────┤
   ┌───────────────────────────┐         │
   │  ACTIVE(gen N+1)          │         │
   │  published = G(N+1)       │◄────────┘
   │  (single publication      │  previous roster retained,
   │   point; whole snapshot)  │  last error recorded,
   └───────────────────────────┘  retry pending
```

### 2.1 Invariants

| ID | Invariant | Enforced at |
|---|---|---|
| **I1** | The published roster is **never empty**. A reload that parses to zero keys is rejected; the previous roster stays in force. The server never degrades to "trust nobody" because of a reload -- it fails closed at *startup* instead. | `identity.rs:313-319` (parser); `handshake_v2.rs:1551-1555` (`set_roster`) |
| **I2** | The published roster length is **<= `max_roster_size`**, checked at load **and** again at adoption. The roster is never truncated -- it is adopted whole or not at all. | `identity.rs:245-270` (count before decode); `handshake_v2.rs:1556-1562` |
| **I3** | A reader observes **exactly one whole generation** -- never a partial, mixed, or empty roster. | §3.4 (proof) |
| **I4** | There is **exactly one publication point** per generation change. | `handshake_v2.rs:1563` |
| **I5** | A failed reload leaves the in-force roster **byte-identical**. Nothing is partially applied. | `handshake_v2.rs:1550-1565` (validate-then-assign) |
| **I6** | Revocation is **never silently disabled**: every adoption is logged (size + fingerprint + per-key added/removed fingerprints); every rejection is logged at `warn!`; a *narrowing* is logged at `warn!` even on success. | §9 |
| **I7** | A failed reload **never terminates the server** and never requires a restart. | §10 |
| **I8** | A **missing** roster file at runtime is a *failed reload*, **not** an empty roster. | §5.2 |
| **I9** | D12's uniform whole-roster verification is preserved verbatim: the roster is never narrowed to make a verification succeed, and no membership pre-filter is added before the verify loop. | `handshake_v2.rs:1813-1819` |
| **I10** | The effective time of a revocation is **the moment the driver applies the swap**, not the moment the operator edited the file. | §7.3 |

### 2.2 Failure edges (exhaustive)

Every distinguishable input to the reload path, and the required outcome:

| Edge | In-force roster | Server | Operator signal |
|---|---|---|---|
| Startup: file missing | none | **does not start** | startup error, exit 1 |
| Startup: file unreadable | none | **does not start** | startup error, exit 1 |
| Startup: bad magic | none | **does not start** | startup error, exit 1 |
| Startup: unsupported `version:` | none | **does not start** | startup error, exit 1 |
| Startup: wrong `type:` | none | **does not start** | startup error, exit 1 |
| Startup: bad hex | none | **does not start** | startup error, exit 1 |
| Startup: truncated key | none | **does not start** | startup error, exit 1 |
| Startup: key that does not decode | none | **does not start** | startup error, exit 1 |
| Startup: empty roster (header only) | none | **does not start** | startup error, exit 1 |
| Startup: oversize roster (> `max_roster_size`) | none | **does not start** | startup error, exit 1 |
| Reload: file missing | G(N) retained | running | `warn!` |
| Reload: file unreadable (permissions) | G(N) retained | running | `warn!` |
| Reload: bad magic / version / `type:` | G(N) retained | running | `warn!` |
| Reload: bad hex / truncated key / key that does not decode | G(N) retained | running | `warn!` |
| Reload: **empty** roster | G(N) retained | running | `warn!` |
| Reload: **oversize** roster | G(N) retained | running | `warn!` |
| Reload: file changed during the read (unstable) | G(N) retained | running | `warn!` |
| Reload: file modified too recently to trust (quiescence) | G(N) retained | running | `debug!` (retried next poll) |
| Reload: valid, non-empty, in-bounds | G(N+1) published | running | `info!` (`warn!` if narrowing) |

---

## 3. The data-sharing model

### 3.1 Options compared

| Option | Verdict | Reason |
|---|---|---|
| **(a) `Arc<RwLock<Arc<Snapshot>>>`** (double-`Arc` cell) | **Rejected as the primary; specified as the documented fallback** | It is *correct*, but the shipped topology has **exactly one consumer** of the roster (the driver task). A shared cell would create a **second copy of the trust anchor** next to the core's `ServerHandshake.cfg.roster` -- two sources of truth that can disagree (`handle.len()` vs `manager.roster_len()`). It also puts a lock in the core's path for no benefit. It is exactly the right shape *if* a future topology needs concurrent readers (for example a health endpoint reporting the roster), so it is specified below in order that it is not re-litigated. |
| **(b) `arc-swap`** | **Rejected** | A new dependency. The project has an explicit supply-chain posture: a pinned `cargo-audit` gate (`.github/workflows/ci.yml:129-155`), a tracked `fuzz/Cargo.lock` with a lock-sync gate (`ci.yml:68-107`), an MSRV 1.85 gate (`ci.yml:157-173`), and a `Cargo.toml` whose workspace dependency list contains **twelve** entries and **no concurrency crate at all** (`Cargo.toml:15-27`). The read frequency is *once per handshake*, not per packet; the lock-free property buys nothing that a `Vec` move does not. |
| **(c) Move the manager into the driver task, so the roster must be reachable from the driver's `select!`** | **ADOPTED** | See below. |

### 3.2 The adopted model: single owner, message passing ("actor")

**The core keeps the roster exactly where it is today: as a plain
`Vec<MlDsaPublicKey>` owned by `ServerHandshake.cfg.roster`.** The reload is
delivered *to* the task that owns the manager; nothing is shared.

```
   ┌────────────────────────────────┐
   │ bin: RosterWatcher task        │  owns: path, max_roster_size,
   │  (the only file reader)        │        last-published signature,
   │                                │        last-published fingerprints
   │  poll → stat → (changed?) →    │
   │  read whole file → parse →     │
   │  validate → candidate          │
   └──────────────┬─────────────────┘
                  │  mpsc::Sender<RosterReload>  (capacity 1)
                  │  -- a message, not shared state --
                  ▼
   ┌───────────────────────────────────────────────┐
   │ bin: driver task -- owns `&mut ServerSessionManager` │
   │   tokio::select! {                              │
   │     transport.recv()      → handle_datagram    │
   │     roster_rx.recv()      → manager.set_roster │  ← publication point
   │     app_rx.recv()         → app_outbound       │
   │     ticker.tick()         → manager.tick       │
   │     cover_arm             → cover_packet_all   │
   │   }                                            │
   └───────────────────────────────────────────────┘
```

**How the `&mut ServerSessionManager` borrow problem is solved: it is not
shared.** The driver task owns `&mut manager`
(`pq-tunnel-core/src/session_manager.rs:1193-1199`) and also owns the receiver
end of the reload channel. A `select!` branch hands the candidate to the one
owner. There is no `Arc<Mutex<ServerSessionManager>>`, no `Arc<RwLock<...>>`,
and no second task that can touch the roster. This is the same ownership
discipline the driver already uses for `app_tx` / `app_rx`
(`session_manager.rs:1196-1197`).

### 3.3 Ownership and lifetime of every value on the roster path

**There are no `Arc`s in the roster path.** That is the important structural
consequence of the choice.

| Object | Owner | Lifetime |
|---|---|---|
| `ServerConfig.roster: Vec<MlDsaPublicKey>` (`handshake_v2.rs:1268`) | `v2_server::run`'s local `cfg` | process lifetime -- the "stale twin" of defect **D8**; removed by `drop(cfg)` after the manager is built |
| `ServerHandshake.cfg.roster: Vec<MlDsaPublicKey>` (`handshake_v2.rs:1473`, assigned at `:1512` and `:1563`) | the `ServerHandshake` inside the `ServerSessionManager` inside the driver task | until the next successful `set_roster`, then dropped. The keys are **public**, so no zeroization is required |
| `PendingSession.verified_client: Option<MlDsaPublicKey>` (`handshake_v2.rs:1425`) | the pending entry | dropped with the entry; public material, no zeroization needed |
| `Arc<AtomicU64>` statistics counters (`pq-tunnel-bin/src/v2_server.rs:73-74`) | shared between the STATS task and the driver/app | process lifetime; they carry *counters*, never roster state |
| `RosterReload` message (`Vec<MlDsaPublicKey>`) | the `mpsc` channel | one poll interval at most; dropped if the driver is gone |

`ServerConfig` derives `Clone` (`handshake_v2.rs:1258`) and `ServerHandshake::new`
deep-copies the roster (`handshake_v2.rs:1512`). A deep copy of a `Vec` of
**public** keys is safe: no secret material is in the roster. The only secret is
the identity *seed*, which lives in a separate file (`identity.rs:378`).

### 3.4 Proof: readers see exactly one whole generation

1. The roster has **exactly one authoritative owner** at any instant:
   `ServerHandshake.cfg.roster`.
2. Every read of the roster happens inside a `&mut self` (or `&self` on an
   exclusively borrowed object) method of `ServerHandshake`:
   - `complete_m1` reads `&self.cfg.roster` (`handshake_v2.rs:1813`),
   - `roster_contains` reads `&self.cfg.roster` (`handshake_v2.rs:1577`),
   - `roster_len` reads `&self.cfg.roster` (`handshake_v2.rs:1569`).
3. Every write happens inside `set_roster(&mut self, ...)` and consists of **one
   whole-`Vec` move**: `self.cfg.roster = roster;` (`handshake_v2.rs:1563`).
4. `&mut` is exclusive: no read can overlap the write, and no read can observe a
   partially-assigned `Vec` (a `Vec` assignment moves a pointer + length +
   capacity; the old buffer is not mutated).
5. All of these are called from `&mut self` methods of `ServerSessionManager`
   (`session_manager.rs:551-558`), which are called **only** from the driver
   task (`session_manager.rs:1193`, `:1229`).

**Therefore:** every read observes one whole generation. There is **no torn
state by construction, not by convention**.

The `Arc`-based design's weakness -- a clone pinned to a stale allocation
(§1.3) -- is *structurally impossible* here, because there is no shareable
roster handle to clone. The `RosterHandle` type must be **deleted**, not
deprecated: leaving a `Clone`-able roster handle in a public API re-creates the
trap for the next change that wants a second reader.

### 3.5 The documented fallback, if a second reader ever appears

```rust
// pq-tunnel-core/src/roster.rs (future; only if a second reader appears)
pub type SharedRoster = std::sync::Arc<std::sync::RwLock<std::sync::Arc<RosterSnapshot>>>;
pub struct RosterSnapshot { pub generation: u64, pub keys: Vec<MlDsaPublicKey> }
```

Rules if it is ever adopted:

1. The cell is `Clone` and **every clone shares the same cell** -- never a copy
   of the `Arc` (this is exactly the §1.3 defect).
2. Publication is a single `*guard = Arc::new(snapshot)` under the write lock.
3. Readers take `guard.clone()` and **drop the guard before any `.await`** --
   a `std::sync` lock must never be held across a suspension point.
4. A poisoned lock is treated as "keep the previous roster" (fail closed), not
   as "publish nothing".

---

## 4. The reload trigger and the operator experience

### 4.1 Primary: file-change polling on the roster path

**`--roster-watch <secs>`, default 5, `0` disables.**

Rationale:

- **The operator action *is* "replace the file."** D27 §2 already chose a
  file-based scheme over an admin RPC
  (`docs/decisions/D27-revocation-and-session-lifetime.md:177-187`) precisely
  because an admin socket is "a new listening surface, new auth story, new DoS
  surface, for a 1:1 deployment". A poll keeps that property: **no new network
  surface.**
- **Windows-first.** SIGHUP does not exist on Windows; `tokio::signal::ctrl_break()`
  needs a console and a process group and does not work under the Windows
  Service Control Manager. A stat-poll is the only trigger that behaves
  identically on the CI target and the primary deployment platform
  (`AGENTS.md:330-334`).
- **The revocation latency is bounded and published**: `<= poll_interval +
  quiescence window`. With the defaults that is about 6 s.
- **Cost**: one `stat` per 5 s. A roster file is at most 64 x 3904 hex
  characters, about 250 KB, and is page-cached.

**Change detection** uses `(len, mtime, file-identity)`, not `(len, mtime)`
alone:

- `len` + `mtime` catches every ordinary edit and every `cp` that does not
  preserve timestamps.
- `file-identity` -- on Unix `MetadataExt::ino()` + `dev()`; on Windows
  `MetadataExt::file_index()` + `volume_serial_number()` -- catches an
  **atomic replace that preserves the mtime** (`cp -p`, `rsync --times`,
  `robocopy /copyall`): the inode or file index changes even though the
  timestamp does not. The Windows `file_index`/`volume_serial_number` methods
  on `std::fs::Metadata` are stable since Rust 1.63.
- **Residual hole:** an **in-place** rewrite onto the same inode with the same
  length and a preserved mtime is invisible to any metadata-based detector. It
  is closed by the §6 stability check only if the write is in progress at the
  moment of the read; otherwise it is undetectable without hashing the file on
  every poll. **Mitigation: an explicit trigger** (below).

### 4.2 Secondary: SIGHUP (Unix only), opt-in

`--roster-reload-on-hup` installs a `SIGHUP` handler that forces an immediate
reload. It is **off by default** because installing a handler changes SIGHUP's
conventional meaning (terminate the process) -- an operator who uses SIGHUP to
stop the server must not be surprised. It is documented in `--help` and in the
decision record.

### 4.3 Not chosen

| Option | Why not |
|---|---|
| Windows console `CTRL_BREAK_EVENT` | Requires a console and a process group; unavailable under the SCM; `tokio::signal::ctrl_break` is `#[cfg(windows)]`-only. |
| Admin socket / RPC | D27 §2 rejected it: a new listening surface plus a new auth story plus a new DoS surface for a 1:1 deployment. |
| Reusing `ServerAppCommand` (`session_manager.rs:252-258`) for roster control | That type is *per-session application payload* (`sid` + `payload`) owned by the `Forwarder` (`pq-tunnel-bin/src/v2_server.rs:103`). Overloading it with roster control conflates application data with administrative control in a core type, and the roster is a *provisioning* concept (D17) that the core must not learn about. |
| Polling the **content hash** every interval | Correct, but it re-reads and re-parses up to 64 ML-DSA keys every 5 s for no benefit. The metadata detector plus an explicit trigger is the right cost/benefit. |

### 4.4 The exact operator experience

```
# startup
INFO  pq_tunnel: v2 server bound to 0.0.0.0:4433
INFO  pq_tunnel: roster loaded path=C:\etc\tunnel\roster.pqti size=1 generation=1 fingerprint=6b1f0c3d9a2e4f57b8c0d1e2f3a4b5c6

# a reload that adds a client -- membership changed
INFO  pq_tunnel: roster reloaded generation=2 size=2 fingerprint=91d0c7a4e2b6f835 added=[6b1f0c3d9a2e4f57b8c0d1e2f3a4b5c6] removed=[6b1f0c3d9a2e4f57b8c0d1e2f3a4b5c6]

# a reload that NARROWS the roster -- a revocation -- louder
WARN  pq_tunnel: roster reloaded (narrowed) generation=3 size=1 fingerprint=0e5a91b7c3d2468f added=[] removed=[91d0c7a4e2b6f835]

# a failed reload -- the previous roster stays in force; the server keeps running
WARN  pq_tunnel: roster reload REJECTED path=C:\etc\tunnel\roster.pqti error="invalid hex: invalid hex character 'z'" -- generation=2 size=1 remains in force; retrying
```

The log lines carry: the roster **size**, the roster **fingerprint** (a 128-bit
one-way digest of the *set* of public keys), and the **per-key fingerprints**
of the added and removed keys. They carry **no key material** (§9.1).

### 4.5 Exit behaviour

- A **startup** failure is **fatal** (exit 1). Unchanged from
  `pq-tunnel-bin/src/v2_server.rs:52` (the `?` on the roster load) and
  `pq-tunnel-bin/src/main.rs:7` (`std::process::exit(1)`).
- A **runtime** reload failure is **never fatal**. The previous roster stays
  fully in force, the server keeps serving, and the watcher retries (§10).
  Rationale: the in-force roster *is* a valid trust anchor; a broken file is an
  operator error, not a security event. Killing the server would convert a typo
  into an outage -- and a restart would then hit the *same* broken file at
  startup and fail closed, turning a typo into a total outage.
  **Fail-secure is not fail-stop**: the secure state is "the last known-good
  roster", not "no server".
- The only way revocation can be silently disabled is if the operator never
  triggers it. Hence the poll is **on by default** and every adoption is logged.

---

## 5. The read protocol and the malformed-file policy

### 5.1 The protocol

```
read_roster_candidate(path, max_roster_size):
  1. open ONE handle:  f = File::open(path)          → Err(Read) on failure
  2. before = f.metadata()                            (len, mtime)  [handle-based]
  3. bytes = f.read_to_end()                          [single read_to_end]
  4. after  = f.metadata()                            (len, mtime)
  5. STABILITY: after.len() == bytes.len()            → else UnstableRead
                before.len() == after.len()
                before.modified() == after.modified()
  6. parse the WHOLE buffer under the strict grammar:
        line 0 == "PQTI"                               (identity.rs:205)
        line 1 == "version: 1"                         (identity.rs:211)
        line 2 == "type: roster"                       (identity.rs:218)
        then one hex payload line per key; '#' comments
        and blank lines are stripped                    (identity.rs:193-197)
  7. VALIDATE:
        - payload line count <= max_roster_size, checked BEFORE any key is
          materialised                                (identity.rs:259-270)
        - >= 1 key                                     (identity.rs:313-319)
        - every key exactly 1952 bytes                 (identity.rs:287-297;
                                                       pq-crypto/src/signature.rs:8)
        - every key decodes to a valid ML-DSA-65 key   (identity.rs:456-459)
  8. return the candidate. NOTHING is published here.
```

Steps 5 to 7 are the fail-closed gate. A candidate is published **only** if
every one of them passes.

### 5.2 Per-case behaviour

| Case | Result | Rationale |
|---|---|---|
| **Empty file** (0 bytes) | `Err(BadHeader)` -- "expected PQTI/version/type header" | A headerless file is malformed, not an empty roster. Fails closed. (`identity.rs:199-204`) |
| **Header-only roster** (`PQTI` / `version: 1` / `type: roster`, no keys) | `Err(EmptyRoster)` | Fails closed (D12). **Never** published -- the server must not degrade to trusting nobody. (`identity.rs:313-319`) |
| **Truncated key** (valid hex, fewer than 1952 bytes) | `Err(BadLength)` | Fails closed. (`identity.rs:287-297`) |
| **Wrong magic** | `Err(BadHeader)` | No silent downgrade (D17). (`identity.rs:205-210`) |
| **Wrong `type:`** (for example `identity`) | `Err(BadType)` | No silent downgrade (D17). (`identity.rs:217-224`) |
| **Unsupported `version:`** | `Err(BadHeader)` | No silent downgrade (D17). (`identity.rs:211-216`) |
| **Non-hex payload** | `Err(BadHex)` | Fails closed. (`identity.rs:81-131`) |
| **Key of correct length that does not decode** | `Err(BadPublicKey)` | Fails closed. (`identity.rs:456-459`) |
| **Oversize roster** (> `max_roster_size`) | `Err(RosterTooLarge)` -- checked **before** any key is decoded, so a hostile file cannot force unbounded ML-DSA decodes | D29 gate 2. The roster is **never truncated**: it is adopted whole or not at all. (`identity.rs:259-270`) |
| **Duplicate keys** | **Accepted** (not an error) | A duplicate is not a security problem -- D12's loop verifies every entry, and the last match wins (`handshake_v2.rs:1816-1818`). But a duplicate inflates the roster length against the bound, which is exactly what the bound is for. The writer `append_roster` already de-duplicates by `encode()` (`identity.rs:507`). See §13 (H5). |
| **A strict SUBSET of the current roster** | **Accepted and published** | **This is what revocation *is*.** See §5.3. |
| **A strict SUPERSET** | **Accepted and published** | Adding a client. |
| **Same size, different membership** (rotation A to B) | **Accepted and published** | The operator's intent. The diff (`added=[fp(B)] removed=[fp(A)]`) is logged. |
| **Unreadable (permissions)** | `Err(Read)` | The previous roster stays in force. **Never** interpreted as "revoke everyone". |
| **File does not exist** | `Err(Read)` | Same. **A missing file at runtime is a failed reload, not an empty roster** (invariant I8). |
| **File being rewritten at the moment of the read** | `Err(UnstableRead)` (new variant), or a parse error | Either way the previous roster stays in force. §6. |
| **File modified less than the quiescence window ago** | deferred (not an error) | The writer may still be working; retried on the next poll. |

### 5.3 The "valid subset" question, answered explicitly

> *Is a roster file that is a subset of the roster in force legitimate (a
> deliberate revocation) or a mistake?*

**It is legitimate, and it must be published.** The reasoning is directional,
and it is the crux of the fail-closed discipline:

- **Refusing to publish a narrowing is a silent failure to revoke.** The revoked
  key keeps authenticating. That is a *security* failure -- the exact thing this
  feature exists to prevent.
- **Publishing a narrowing that was not intended is an availability failure.**
  The legitimate client cannot connect. That is loud: the server logs
  `WARN roster reloaded (narrowed) ... removed=[fp]`, and the client fails to
  connect within seconds.

**An availability failure is the safe direction; a security failure is not.**
D10 ("Tunnel fails securely", `DESIGN_DECISIONS.md:406-433`) is about not
continuing *insecurely*; it does not require refusing to *act*.

Therefore:

1. **The fail-closed gate is the parse/validation gate** (malformed, empty,
   oversize, unstable) -- never a size- or membership-based rule.
2. **The defence against an unintended narrowing is operational and
   observable**, not a validation rule:
   1. The operator replaces the file **atomically** (§6).
   2. The server **detects an in-flight in-place rewrite** and refuses it (the
      stability check).
   3. **Every adoption is logged** with the size, the set fingerprint, and the
      per-key fingerprints of the added and removed keys -- and a narrowing is
      logged at `warn!`, so it is visible at the default log level.
   4. The roster **fingerprint** is a stable, order-independent identifier of
      the *set*, so the operator can confirm that what is in force is what they
      intended: `SHA-256` over the sorted encoded keys, first 16 bytes, hex --
      the same 128-bit shape D17 already uses for single keys
      (`identity.rs:614-623`).

**1:1 makes this safer still.** The production roster has exactly **one** key
(D28/D29 describe the deployed roster as 1; the server's own default bound is
64, `handshake_v2.rs:1320`). In that topology the only strict subsets are the
empty set (rejected) and the set itself. An accidental narrowing to a
*different* single key is a **rotation**, not a truncation, and it produces an
immediate, loud outage -- not a silent security hole.

**What the server genuinely cannot do** (and the constraint set forbids
fixing): it cannot distinguish "the operator revoked A" from "the operator
rotated A to B" from "a buggy script clobbered the file with an old copy".
There is no signed manifest, no generation counter in the file and no per-key
revocation record. Any attempt to add one is out of scope for this wave. The
design therefore makes the *observable diff* the operator's verification
mechanism.

---

## 6. Safe file replacement and TOCTOU

### 6.1 What a single-handle `read_to_end` guarantees

- The bytes come from **one file object**: on POSIX one inode, on Windows one
  file handle referring to one NTFS file object.
- **An atomic replace cannot produce a torn read.** `rename(2)` replaces the
  *directory entry*; an already-open file descriptor keeps referring to the old
  inode. `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` -- what `std::fs::rename`
  uses on Windows -- likewise replaces the directory entry, and the reader's
  handle keeps referring to the old file. The rename can even succeed while the
  reader holds the handle, because Rust's `File::open` on Windows uses
  `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`. The reader may
  therefore legitimately read the *old* file -- a whole, consistent file -- and
  the next poll picks up the new one.
- The read is **whole-file**: `read_to_end` on a regular file returns the
  entire file (short reads are retried by `std`), so no interleaving with
  another writer is possible on the same handle.

### 6.2 What it does *not* guarantee

- That you read the **newest** version. Bounded by the poll interval.
  Harmless: the next poll catches up.
- Anything against an **in-place rewrite** (`write` + `truncate` on the same
  file object). Here the reader and the writer share one file object, so the
  reader can observe a truncated prefix -- and on Windows the writer's open
  succeeds despite the reader's handle, because of the share mode above. On
  POSIX the same happens (same inode, `O_TRUNC`).
- That the file was *complete* when it was opened.

### 6.3 The mitigations, in order of strength

1. **Mandate atomic replacement in the operator recipe.** The project's own
   writers already do it: `write_atomic` writes `.{name}.{pid}.tmp` and renames
   over the target (`identity.rs:325-352`); `save_roster`
   (`identity.rs:470-492`) and `append_roster` (`identity.rs:500-527`) both go
   through it. Documented recipe for a hand-authored roster:

   ```
   write new.pqti.tmp ; then:  mv -f new.pqti.tmp /etc/tunnel/roster.pqti
   ```

   (`mv` maps to `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` on Windows --
   atomic on both platforms for a same-directory rename.)

   **Or simply use `pq-tunnel keygen --append-roster <path>`**, which is atomic
   by construction.

2. **The stability check** (step 5 of the read protocol). Read the metadata
   **from the handle** before and after the read and require
   `before.len() == after.len() == bytes.len()` and
   `before.modified() == after.modified()`. This detects an in-place write that
   was *in flight* during the read. New error variant
   `IdentityError::UnstableRead { path }`.

   *Why handle-based metadata matters:* if you `stat` the **path** before the
   read and the path is renamed over in between, you compare the metadata of two
   different files and get a spurious "unstable" verdict. Taking `before` and
   `after` from the **same handle** compares the same file object, so a
   rename-over is invisible (correctly -- the read was of a consistent file)
   and only a genuine in-place mutation is caught.

3. **A quiescence window.** Before attempting a reload, require the file's
   mtime to be at least `ROSTER_QUIESCENCE` (1 s, a named constant) older than
   now. If the file was touched more recently, defer to the next poll. This
   catches the "writer paused mid-write" case that the stability check alone
   can miss. It is a **heuristic**, not a proof, and is documented as such.

4. **Belt-and-braces: the parse gate.** A torn file that happens to end exactly
   on a line boundary parses as a *valid smaller roster*. Nothing in the file
   can distinguish it from a deliberate revocation. The remaining defences are
   (1), (2), (3) and the operator-visible diff log.

### 6.4 Residual risk, stated honestly

An in-place writer that pauses for longer than the quiescence window at a line
boundary, in a way that leaves a syntactically valid prefix, **can be
published**. This is inherent to an unsigned, unversioned text file with no
generation counter, and the constraint set for this wave forbids adding one
(no signed manifest, no new PKI). It is mitigated by the atomic-replace recipe
and bounded by the operator-visible `removed=[fp]` log line.

In the 1:1 production topology (a one-key roster) the practical exposure of
this residual is close to nil: the only valid prefix of a one-key file is the
empty set (rejected) or a partial key (rejected on length).

---

## 7. Concurrent handshakes during a replacement

### 7.1 The ordering guarantee

**The swap and the M3 completion are strictly ordered, not racy.** Both happen
in the **same task**, on the **same object**, through **exclusive `&mut`
borrows**:

- `manager.handle_datagram(&pkt, from)` to `ServerHandshake::on_m3_fragment`,
  to the re-check at `handshake_v2.rs:1949` -- a synchronous `&mut self` call.
- `manager.set_roster(roster)` to `handshake_v2.rs:1563` -- a synchronous
  `&mut self` call.

The driver is a single task (`session_manager.rs:1193-1199`, `select!` at
`:1208`); neither call awaits. Therefore:

> **A handshake that authenticated against generation N cannot complete if
> generation N+1 revoked that key -- provided the swap was applied before the
> M3 was processed.**

The re-check reads `self.cfg.roster` *at M3 time* (`handshake_v2.rs:1949` to
`:1577`), so it sees whichever generation is in force at that instant.

### 7.2 The two residual windows, named precisely

| Window | Description | Does a session get minted from a key revoked "microseconds" earlier? | Bound |
|---|---|---|---|
| **W1 -- apply latency** | The operator replaces the file at *t0*; the server applies the swap at *t1* >= *t0*. Between *t0* and *t1* the old roster is still in force, so a handshake completing in that window **is** minted. | **Yes.** | The poll interval (default 5 s) plus the quiescence window (1 s), about **6 s**. This is the real cost of a file-based revocation scheme and it is the number the operator must be told about. It is not a bug; it is the published latency bound. |
| **W2 -- same-instant ordering** | The reload candidate and an inbound M3 are both ready in the same `select!` iteration. `tokio::select!` picks a ready branch **pseudo-randomly**, so the M3 may be processed first -- a session is minted from a key that the *pending* reload would have revoked. | **Yes.** | About one datagram-processing iteration (sub-millisecond). **Tightening (recommended):** drain the reload channel with `try_recv` at the *top of the transport branch*, before the datagram is handled. Then any reload that is already pending is applied before the next packet is processed. This costs one `try_recv` per inbound datagram (a relaxed atomic check) and closes W2 almost entirely, without `biased;` -- which would change the fairness of the existing `transport`/`cmd`/`ticker`/`cover` branches and could starve the lifetime-cap tick under a packet flood. |

### 7.3 The statement that must be made plainly

> **The effective time of a revocation is the moment the driver applies the
> swap, not the moment the operator edited the file.** Any claim stronger than
> that is false for a file-based scheme, and it must not appear in the operator
> documentation.

**Does W1/W2 matter for 1:1?** The revoked key's owner is the attacker; the
legitimate client is a *different* session. A session minted inside W1 is a
session the attacker holds. It is bounded by the **24 h lifetime cap** (§8.2)
-- and, more importantly, **revoking the identity key does not give the
attacker the traffic keys of an already-established session** (§8.1). W1 is
therefore a *bounded* exposure, not an unbounded one.

---

## 8. Policy for already-established sessions

The two mechanisms are **separate** and must not be conflated.

### 8.1 Credential revocation -- the identity key is revoked

**Recommendation: do NOT tear down the established session.** This is D27 §5
(`docs/decisions/D27-revocation-and-session-lifetime.md:273-303`) and this
design does not overturn it. Three independent arguments, in decreasing order
of force:

1. **Revoking the identity key does not expose the existing session.** The
   traffic keys are session-scoped and derived from ephemeral handshake secrets
   (D14, `DESIGN_DECISIONS.md:663-706`); the identity key never enters the key
   schedule (`DESIGN_DECISIONS.md:509-510`). An attacker who steals the
   client's *identity* seed can **forge new handshakes**; it gives them nothing
   about an already-established session's traffic keys. Killing the session
   protects against essentially nothing -- it only stops future packets over a
   channel the attacker cannot read.
2. **The signal is ambiguous.** Without a signed manifest or a per-key
   revocation record, the server cannot distinguish "the operator revoked A"
   from "the operator rotated A to B" from "the operator restored an old
   backup". A "kill sessions whose key left the roster" policy would kill the
   legitimate session during a routine rotation -- a self-inflicted DoS with no
   security benefit (per argument 1).
3. **D16 rotation already re-runs the roster check.** Re-establishment is a
   full handshake whose M1 is verified against the *current* roster, so a
   revoked client cannot rotate back in: M1 does not authenticate, so no M2 is
   produced; the client burns its `m1_max_attempts` budget and reports
   `Closed{HandshakeTimeout}` (D27 §6,
   `docs/decisions/D27-revocation-and-session-lifetime.md:307-328`). Verified
   today by `revoked_key_cannot_re_establish`
   (`pq-tunnel-bin/tests/revocation_lifetime.rs:330`) and
   `revoked_client_retry_loop_never_establishes` (`:417`).

**Trade-off, stated plainly:** an operator with a **suspected-compromised**
client identity key must wait for the live session to die on its own -- bounded
by the **24 h lifetime cap** (§8.2) -- because the attacker keeps
authenticating until the key is removed from the roster, and any session they
establish before the removal stays alive until the cap. **This is the exposure
the cap bounds.** It is the price of not having a revocation-vs-rotation
distinction.

**Explicitly out of scope (recommended):** an immediate-kill mode
(`revoke_grace 0`). D27's human gate #3
(`docs/decisions/D27-revocation-and-session-lifetime.md:500-503`) already
recommends deferring it, and per argument 2 it would need a
revocation-vs-rotation signal that this wave's constraints forbid. Listed as a
human decision in §13.

### 8.2 Session expiration -- the lifetime cap

**A different mechanism entirely.** `SessionLimits::lifetime_cap`
(`pq-tunnel-core/src/session_manager.rs:125-127`), currently `None` by default
(`session_manager.rs:150`), driven by `manager.tick(...)` in the driver's ticker
branch. It fires `Closed{LifetimeCap}` (`CloseReason::LifetimeCap`,
`session_manager.rs:170`) and is **independent of the roster**: a session
expires because it is old, not because its key was revoked.

**The 24 h cap is the bound on exposure; revocation is not.** With the cap
enabled, a session established by a revoked key lives at most until
`established_at + 24 h`; after that `Closed{LifetimeCap}` fires and the client
re-establishes -- which fails at M1 against the revoked roster.

**This design does not implement the cap and does not depend on its details.**
It is a separate track's work. But the dependency must be stated: **without
the cap, a revoked-but-alive session is unbounded.** Revocation bounds only
*future* establishment. This must be recorded in the decision record rather
than left implicit, and it is the reason the D27 amendment names the cap as
the exposure bound.

The existing test `revocation_defers_to_lifetime_cap_for_established_sessions`
(`pq-tunnel-bin/tests/revocation_lifetime.rs:493`) already pins this
composition.

---

## 9. Logging and observability

### 9.1 Redaction discipline (verified in the current code)

- `pq-tunnel-bin/src/identity.rs:26`: "These functions never log key material."
- `pq-crypto/src/signature.rs:56-72`: the `Debug` impls for `MlDsaPublicKey`,
  `MlDsaSecretKey` and `MlDsaSignature` all print `[REDACTED]`. A
  `#[derive(Debug)]` struct containing an `MlDsaPublicKey` therefore **cannot**
  leak key material through `tracing`'s `?` / `%` formatting. This is a hard,
  load-bearing guarantee for the log lines below.
- `IdentityError`'s messages (`identity.rs:81-131`) contain only the path, the
  expected and actual byte counts, a hex-character error, a decode reason and
  the roster size. **No key material.** Verified case by case.

### 9.2 What is logged

| Event | Level | Fields | Rationale |
|---|---|---|---|
| Roster loaded at startup | `info!` | `path`, `size`, `generation=1`, `fingerprint` | The path and the size are **not sensitive**; the fingerprint is a 128-bit one-way digest of *public* keys. |
| Roster adopted (reload) | `info!` | `generation`, `size`, `fingerprint`, `added=[fp...]`, `removed=[fp...]` | Per-key fingerprints (D17's format, `identity.rs:614-623`) let the operator confirm "the key I revoked is gone" without ever logging key material. |
| Roster adopted **and the set narrowed** | `warn!` | same | Invariant I6: a narrowing must be visible at the default log level. |
| Roster adoption **rejected by the driver** (empty or oversize -- a defence-in-depth no-op) | `warn!` | `error`, `generation` (the one still in force), `size` | Fail closed, loudly. |
| Reload **failed** (parse, I/O, unstable, missing) | `warn!` on the first failure of an episode, `debug!` for repeats | `path`, `error`, `generation` (still in force), `size` | Never floods; never silent. |
| Reload **succeeded after failures** | `info!` | `attempts`, `generation` | Closes the episode visibly. |
| Watcher task stopped (driver gone, or the channel closed) | `warn!` once | -- | Revocation can no longer happen -- the operator must know. |
| **Rejected handshake** | **nothing, per handshake** | -- | D12/D13: peer-input failures are silent drops. A per-handshake log line is a DoS amplifier (an attacker can force unbounded log I/O) and a behavioural oracle. |
| Rejected handshakes, **aggregate** | in the existing `STATS:` line (`pq-tunnel-bin/src/v2_server.rs:84-86`) | `handshakes`, `sessions`, plus optional `roster_gen`, `roster_size`, `roster_stale` | Aggregates do not change the wire behaviour and are not an oracle. |

**Never logged:** the identity seed, any secret key, any session key, or the
raw roster file contents. Raw *public* keys would not be secret, but the
project convention is fingerprints -- and a roster line is 3904 hex characters,
which would be unreadable and a log-volume hazard.

### 9.3 The roster fingerprint

`roster_fingerprint(keys)` = `SHA-256` over the **sorted** concatenated encoded
keys, first 16 bytes, hex (32 characters). Sorted means order-independent, so a
reordering is not a change: it identifies the *set*, not a sequence. Per-key
identification uses the existing `identity::fingerprint`
(`identity.rs:614-623`). `sha2` is already a dependency of both the bin and
the core (`Cargo.toml:22` for the workspace entry) -- **no new dependency**.

---

## 10. Recovery after transient file errors

| Requirement | Design |
|---|---|
| **The previous roster stays fully in force** | The candidate is built entirely off to the side; the core's single publication point (`handshake_v2.rs:1563`) is never reached on a failure. The in-force `Vec` is not even read. |
| **No degradation to an empty roster** | Invariant I1. `set_roster` rejects an empty roster (`handshake_v2.rs:1551-1555`); the parser rejects an empty parse (`identity.rs:313-319`). A **missing** file is a failed reload, never an empty roster (I8). |
| **No restart required** | Invariant I7. The watcher keeps retrying; the driver keeps serving. |
| **Retry cadence** | The poll interval *is* the retry cadence (default 5 s). The watcher tracks the signature of the file **that is in force**, not the last one it *observed*, so a failed load leaves the signature mismatched and the next poll retries automatically. |
| **Back-off** | Not exponential: the poll interval already bounds the retry rate. A floor of 1 s applies -- the poll interval may not be set below 1 s. |
| **Log discipline** | First failure of an episode is `warn!`; subsequent identical failures are `debug!`; success is `info!` ("roster reloaded after N failed attempts"). A persistently broken file does not flood the log. |
| **Operator visibility** | The `STATS:` line should carry `roster_gen` / `roster_size` / `roster_stale` (recommended; see §13 H7). `roster_stale=true` means "the file on disk does not match the roster in force" -- the operator's at-a-glance signal that something is wrong. |
| **Duplicated candidates** | The watcher offers a candidate at most **once per distinct file signature**; a candidate identical to the one in force is not re-offered. A persistent failure therefore produces one `warn!` per episode, not one per poll. |
| **Watcher death** | If the watcher task exits (the channel closed), the driver logs `warn!` once ("roster watcher stopped; the roster will not be reloaded") and keeps serving with the roster in force. The server does **not** exit: revocation becoming impossible is a degraded state, not a crash. |
| **Startup versus runtime asymmetry** | A startup failure is **fatal** (the server does not start with an untrusted roster). A runtime failure is **not** fatal. The asymmetry is deliberate: at startup there is no previous roster to fall back to. |

---

## 11. Minimal API changes

### 11.1 `pq-tunnel-core/src/handshake_v2.rs` -- **ZERO changes required**

Everything this design needs already exists and is already correct:

| Existing | Line | Used for |
|---|---|---|
| `set_roster(&mut self, Vec<MlDsaPublicKey>) -> Result<(), HandshakeV2Error>` | 1550-1565 | The publication point (empty and over-bound rejected; single assignment at `:1563`) |
| `roster_len` | 1568-1570 | Diagnostics |
| `roster_contains` | 1576-1578 | The M3 re-check (`:1949`) |
| The D12 uniform verification loop | 1813-1819 | Authentication (must not change) |
| The M3 re-check after the MAC check | 1949-1952 | The mid-flight revocation gate |

*One optional addition* (not required): a per-key fingerprint accessor for the
reload diff -- see §11.4.

### 11.2 `pq-tunnel-core/src/session_manager.rs` -- three changes

```rust
// 1. A named type for the reload message.  It documents intent; the driver
//    re-validates the candidate, so a producer that skips validation cannot
//    widen or empty the trusted set.
#[derive(Debug)]
pub struct RosterReload {
    /// The candidate trusted-client roster.
    pub roster: Vec<MlDsaPublicKey>,
}

// 2. The existing entry point keeps its signature and delegates.
pub async fn run_server_manager<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ServerSessionManager,
    app_tx: mpsc::Sender<ManagerNotification>,
    app_rx: mpsc::Receiver<ServerAppCommand>,
    cover: CoverPolicy,
) -> Result<(), ManagerError> {
    let (_tx, rx) = mpsc::channel::<RosterReload>(1);
    drop(_tx);                       // closed => the branch disables itself
    run_server_manager_with_roster(transport, manager, app_tx, app_rx, cover, rx).await
}

// 3. The new driver: the same loop, plus one select! branch.
pub async fn run_server_manager_with_roster<T: HandshakeTransport>(
    transport: &mut T,
    manager: &mut ServerSessionManager,
    app_tx: mpsc::Sender<ManagerNotification>,
    mut app_rx: mpsc::Receiver<ServerAppCommand>,
    cover: CoverPolicy,
    mut roster_rx: mpsc::Receiver<RosterReload>,
) -> Result<(), ManagerError> {
    let mut roster_closed = false;
    let mut generation: u64 = 1;      // generation 1 = the startup roster
    let mut published_fps: Vec<String> = /* seeded from the startup roster */;
    // ... the existing loop body, with two additions ...
}
```

The added branch inside the existing `tokio::select!` (`session_manager.rs:1208`):

```rust
// -- NEW BRANCH ---------------------------------------------------------
reload = roster_rx.recv(), if !roster_closed => {
    match reload {
        Some(r) => {
            let new_fps = roster_key_fingerprints(&r.roster);      // sorted
            let added: Vec<_> = new_fps.iter()
                .filter(|f| !published_fps.contains(f)).cloned().collect();
            let removed: Vec<_> = published_fps.iter()
                .filter(|f| !new_fps.contains(f)).cloned().collect();
            match manager.set_roster(r.roster) {   // <-- THE publication point
                Ok(()) => {
                    generation += 1;
                    published_fps = new_fps;
                    let fp = roster_fingerprint_of(&published_fps);
                    if removed.is_empty() {
                        info!(generation, size = published_fps.len(), fingerprint = %fp,
                              added = ?added, removed = ?removed, "roster reloaded");
                    } else {
                        warn!(generation, size = published_fps.len(), fingerprint = %fp,
                              added = ?added, removed = ?removed,
                              "roster reloaded (narrowed or rotated)");
                    }
                }
                Err(e) => {
                    warn!(error = %e, generation, size = published_fps.len(),
                          "roster reload REJECTED; the previous roster remains in force");
                }
            }
        }
        None => { roster_closed = true; }   // the watcher is gone
    }
}
```

And, at the **top of the transport branch** (`session_manager.rs:1227`), a drain
that closes window **W2** (§7.2):

```rust
Ok((pkt, from)) => {
    // Apply any pending roster reload BEFORE handling this datagram, so a
    // reload that is already waiting cannot be overtaken by a handshake
    // that it would revoke.
    while let Ok(r) = roster_rx.try_recv() { apply_reload(manager, r, ...); }
    ...
}
```

`roster_closed` must also be set when `try_recv` returns `Disconnected`.

**Conflict note:** `session_manager.rs` is on another track's edit list. The
changes above are (i) a new type, (ii) a new function containing the loop body,
(iii) one new `select!` branch, (iv) one drain. The *bodies* of
`complete_m1` / `on_m3_fragment` are not touched. The new function's body is a
**move** of the existing loop, which is the highest-conflict region. If a
conflict is unacceptable, the alternative is to put the reload branch in a
`tokio::select!` *nested* inside the existing one -- which is not possible --
or to give the driver the roster through a shared cell (option (a)), which is
strictly worse.

### 11.3 `pq-tunnel-core/src/roster.rs` -- **NEW module** (about 40 lines)

```rust
//! Roster identity helpers: stable, non-secret fingerprints.

/// Short, stable fingerprint of a public key: SHA-256(encoded_key)[..16],
/// hex (32 characters).  D17's out-of-band verification format.
pub fn fingerprint(key: &MlDsaPublicKey) -> String;

/// Fingerprints of a roster's keys, sorted (order-independent).
pub fn roster_key_fingerprints(keys: &[MlDsaPublicKey]) -> Vec<String>;

/// Fingerprint of a roster *set*: SHA-256 over the sorted encoded keys,
/// first 16 bytes, hex.
pub fn roster_fingerprint(keys: &[MlDsaPublicKey]) -> String;
```

`sha2` is already a core dependency. Exported via `pq-tunnel-core/src/lib.rs`
(`pub mod roster;` plus re-exports). **A new file avoids any textual conflict**
with concurrent work.

### 11.4 The optional `handshake_v2.rs` accessor -- and the cheaper alternative

```rust
impl ServerHandshake {
    /// Fingerprints of the roster keys currently in force (sorted).
    /// Diagnostics only -- never used on an authentication path, and never a
    /// substitute for the D12 uniform verification loop.
    pub fn roster_fingerprints(&self) -> Vec<String> { ... }
}
```

plus a three-line delegation on `ServerSessionManager`.

**Preferred alternative that avoids touching `handshake_v2.rs` entirely:** the
driver keeps the previous fingerprint list **itself**, seeded from the roster it
loaded at startup in `v2_server.rs` -- the driver already holds the startup
`Vec<MlDsaPublicKey>` before it is moved into the manager. **Recommend this
alternative**: it removes the last `handshake_v2.rs` change and keeps the
core-side footprint to `session_manager.rs` plus one new module.

### 11.5 `pq-tunnel-bin/src/identity.rs` -- four changes

```rust
// (1) NEW error variant
    /// The file changed while it was being read (an in-place rewrite was in
    /// progress).  The reload is refused; the previous roster stays in force.
    #[error("{}: file changed while it was being read (unstable read)", path.display())]
    UnstableRead { path: PathBuf },

// (2) STABLE READ -- replaces `fs::read_to_string(path)` at identity.rs:184
fn read_stable_to_string(path: &Path) -> Result<String, IdentityError> {
    let mut f = fs::File::open(path).map_err(|source| IdentityError::Read { path: path.to_path_buf(), source })?;
    let before = f.metadata().map_err(/* -> Read */)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(/* -> Read */)?;
    let after = f.metadata().map_err(/* -> Read */)?;
    // Handle-based metadata: a rename-over is invisible (the handle still
    // refers to one consistent file); an in-place rewrite is caught.
    if after.len() != bytes.len() as u64
        || before.len() != after.len()
        || before.modified() != after.modified()
    {
        bytes.zeroize();
        return Err(IdentityError::UnstableRead { path: path.to_path_buf() });
    }
    String::from_utf8(bytes).map_err(|_| IdentityError::Read {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, "roster file is not valid UTF-8"),
    })
}

// (3) NEW: a cheap, clone-stable file signature for change detection
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileSignature { pub len: u64, pub modified: SystemTime, pub file_id: u64 }
pub fn file_signature(path: &Path) -> Result<FileSignature, IdentityError>;   // cfg-gated file_id

// (4) DELETE `RosterHandle` (identity.rs:539-612) and replace it with a
//     single-owner, NON-Clone watcher.
//
//     RosterHandle's `#[derive(Clone)]` + `Arc<Vec<..>>` field (identity.rs:539-542)
//     + `self.current = Arc::new(parsed)` (identity.rs:609) is the defect that
//     made the shipped atomicity test vacuous.  The new design has no shared
//     roster cell, so the type is unnecessary -- and leaving a `Clone`-able
//     roster handle in a public API re-creates the trap.
pub struct RosterWatcher {
    path: PathBuf,
    max_roster_size: usize,
    published_signature: Option<FileSignature>,
    published_fingerprints: Vec<String>,
    last_error: Option<String>,
}
impl RosterWatcher {
    pub fn new(path: PathBuf, max_roster_size: usize) -> Self;
    pub fn path(&self) -> &Path;
    pub fn current_signature(&self) -> Result<FileSignature, IdentityError>;
    pub fn read_candidate(&self) -> Result<Vec<MlDsaPublicKey>, IdentityError>;  // stable read + parse + validate
    pub fn mark_published(&mut self, sig: FileSignature, keys: &[MlDsaPublicKey]);
    pub fn published_fingerprints(&self) -> &[String];
}
// NOTE: deliberately NOT `Clone`.  A `Clone` impl would be a compile-time
// regression guard: a `static_assertions`-style check or a doc test asserting
// `RosterWatcher` is not `Clone`.
```

`identity::fingerprint` (`identity.rs:614-623`) **delegates** to
`pq_tunnel_core::roster::fingerprint` so the digest logic exists once.

**The startup load path also benefits from (2)**: a torn read at startup now
fails closed instead of silently adopting a valid-looking prefix.

### 11.6 `pq-tunnel-bin/src/lib.rs` -- one change (two CLI flags)

```rust
pub struct ServerArgs {
    ...
    /// Poll the roster file for changes every <secs> seconds and reload it.
    ///
    /// The revocation latency is bounded by this interval (plus a 1 s
    /// quiescence window).  `0` disables polling, which makes revocation
    /// require an explicit trigger -- an explicit, visible reduction.
    /// Default: 5.
    #[arg(long, default_value_t = 5)]
    pub roster_watch_secs: u64,

    /// Unix only: reload the roster on SIGHUP instead of terminating.
    /// Opt-in, because installing a handler changes SIGHUP's conventional
    /// meaning (terminate the process).
    #[arg(long)]
    pub roster_reload_on_hup: bool,
}
```

`ServerArgs` is at `pq-tunnel-bin/src/lib.rs:75`; `max_roster_size` is already
there (`:122-123`).

### 11.7 `pq-tunnel-bin/src/v2_server.rs` -- the wiring

```rust
// 1. Startup: unchanged, plus remember the loaded roster for the diff seed
let roster = identity::load_roster_with_limit(roster_path, args.max_roster_size)?;   // existing, line 52
let cfg = HandshakeV2ServerConfig::with_roster_limit(keypair, roster.clone(), args.max_roster_size);
let mut manager = ServerSessionManager::new(&cfg, SessionLimits::default())...;      // existing, line 56
drop(cfg);                       // <-- FIX for D8: drop the stale twin of the trust anchor

// 2. The reload channel
let (reload_tx, reload_rx) = mpsc::channel::<RosterReload>(1);

// 3. The watcher task (only when polling is enabled)
if args.roster_watch_secs > 0 {
    tokio::spawn(watch_roster(reload_tx.clone(), roster_path.to_path_buf(),
                               args.max_roster_size, args.roster_watch_secs, initial_fps));
}
// The SIGHUP task (Unix only, opt-in)
#[cfg(unix)]
if args.roster_reload_on_hup { tokio::spawn(sighup_reload(reload_tx.clone(), ...)); }

// 4. The driver -- now with the reload input
let driver = tokio::spawn(async move {
    run_server_manager_with_roster(&mut udp, &mut manager, app_tx, cmd_rx, cover, reload_rx).await
});
```

The watcher task (blocking file I/O, therefore `spawn_blocking`):

```rust
async fn watch_roster(tx: mpsc::Sender<RosterReload>, path: PathBuf,
                       max: usize, interval_secs: u64, initial: Vec<String>) {
    let mut w = RosterWatcher::new(path, max);
    w.set_published_fingerprints(initial);
    let mut iv = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        iv.tick().await;
        let sig = match w.current_signature() { Ok(s) => s, Err(e) => { /* warn once per episode */ continue } };
        if Some(sig) == w.published_signature() { continue; }        // unchanged
        if w.is_too_recent(sig) { continue; }                          // quiescence
        let candidate = match tokio::task::spawn_blocking({
            let p = path.clone();
            move || identity::load_roster_with_limit(&p, max)
        }).await {
            Ok(Ok(keys)) => keys,
            Ok(Err(e))  => { w.note_error(&e); warn!(...); continue; }  // failed reload
            Err(_)      => { warn!("roster watcher task panicked"); break; }
        };
        // Only offer a candidate that differs from the one in force.
        let fps = pq_tunnel_core::roster::roster_key_fingerprints(&candidate);
        if fps == w.published_fingerprints() { w.mark_signature(sig); continue; }
        if tx.send(RosterReload { roster: candidate }).await.is_err() { break; }   // driver gone
        w.mark_signature(sig); w.set_published_fingerprints(fps);
    }
}
```

**Ordering note:** `w.mark_signature(sig)` happens **only on success**, so a
failed load leaves the signature mismatched and the next poll retries
automatically (§10).

### 11.8 Summary of the change footprint

| File | Change | Approximate size | Conflicts with concurrent work |
|---|---|---|---|
| `pq-tunnel-core/src/handshake_v2.rs` | **none** (or one optional accessor) | 0 | **none** |
| `pq-tunnel-core/src/session_manager.rs` | new type, new driver function, one `select!` branch, one drain | ~70 | Medium (the loop body moves) |
| `pq-tunnel-core/src/roster.rs` | **new file** | ~40 | none |
| `pq-tunnel-core/src/lib.rs` | `pub mod roster;` plus exports | ~4 | none |
| `pq-tunnel-bin/src/identity.rs` | stable read, `UnstableRead`, `FileSignature`, `RosterWatcher` replaces `RosterHandle`, `fingerprint` delegates | ~120 | none |
| `pq-tunnel-bin/src/lib.rs` | two new CLI flags | ~20 | Low (the `ServerArgs` struct) |
| `pq-tunnel-bin/src/v2_server.rs` | watcher task, channel, `drop(cfg)` | ~90 | Medium |

---

## 12. Test plan

All tests are deterministic. The poll-dependent tests use a 1 s interval with
generous timeouts, or drive the watcher directly rather than waiting for a
tick.

### 12.1 `pq-tunnel-bin/src/identity.rs` (unit tests, same module)

| Test | Asserts |
|---|---|
| `roster_read_rejects_a_file_changed_during_the_read` | A file rewritten in place between the open and the read yields `Err(UnstableRead)` (or a parse error), **never** a published prefix. Deterministic: hold a `File` handle open, truncate and rewrite from another handle, then call the reader. |
| `roster_read_of_a_whole_file_is_accepted` | A complete file parses to the expected key set. |
| `roster_read_of_an_empty_file_is_rejected` | `Err(BadHeader)` -- not `EmptyRoster`, and never a published empty roster. |
| `roster_read_of_a_header_only_file_is_rejected` | `Err(EmptyRoster)`. |
| `roster_read_of_a_truncated_key_is_rejected` | `Err(BadLength)`. |
| `roster_read_of_a_bad_magic_is_rejected` / `_bad_version_` / `_bad_type_` | The corresponding error. |
| `roster_read_of_an_oversize_file_is_rejected_before_any_key_decodes` | `Err(RosterTooLarge)` with `got` / `max`. The existing test at `identity.rs:944` is kept. |
| `file_signature_changes_on_atomic_replace` | Replacing the file by rename changes the signature **even when the mtime is preserved**. This is the test that pins the `file_id` field's value. |
| `file_signature_is_stable_when_nothing_changes` | Two consecutive signatures of an untouched file are equal. |

### 12.2 `pq-tunnel-core/src/roster.rs` (new unit tests)

| Test | Asserts |
|---|---|
| `roster_fingerprint_is_order_independent` | Two rosters with the same keys in different orders have the same fingerprint. |
| `roster_fingerprint_changes_when_membership_changes` | A different key set gives a different fingerprint. |
| `roster_fingerprint_is_32_hex_chars` | The format matches `identity::fingerprint` (D17). |
| `roster_key_fingerprints_are_sorted` | Sorted output gives set semantics. |

### 12.3 `pq-tunnel-bin/tests/revocation_lifetime.rs` (integration)

**C1 -- the test that would have caught the vacuous atomicity test.**

| Test | Asserts |
|---|---|
| `roster_watcher_is_not_cloneable` | A **compile-time** property: `RosterWatcher` must not implement `Clone`. Implement as a `trybuild`-style compile-fail test, or more cheaply as a doc test or a `static_assertions`-style check. *Minimum viable alternative:* a unit test asserting the watcher's published state advances after a reload **through the same handle** -- the property the old test failed to exercise. |
| `roster_read_is_whole_under_concurrent_replacement` | **The real replacement for the vacuous test.** A writer thread replaces the file 200 times, alternating between two whole generations `[A]` and `[A,B]`, using an **atomic rename** each time. A reader thread calls `load_roster_with_limit` in a loop. **Every successful read must yield exactly one of the two whole generations** -- never a mix, never a partial key, never an empty roster. Additionally: the reader must observe **both** generations at least once (`saw_a && saw_ab`), which is the assertion the old test was missing. |
| `roster_read_never_publishes_a_torn_prefix` | A writer thread rewrites the file **in place** (`write` + `truncate`) in a loop with a partial write between truncates. Every read must either succeed with a whole generation or **fail**; it must never yield a generation that is not one of the two intended ones. This is the test that pins the stability check. |

**C2 -- the concurrent-handshake tests.**

| Test | Asserts |
|---|---|
| `reload_in_flight_blocks_m3_completion_through_the_driver` | Uses the **production path**: spawn the real driver with a reload channel over the in-process UDP harness. Drive M1 (authenticated against generation 1), then send a `RosterReload` revoking the client's key through the channel, wait for it to be applied, then deliver M3. Asserts: **no `ManagerEvent::Established`**, `session_count() == 0`, and the pending entry is gone. This proves the *shipped wiring* closes the window; the existing `midflight_revocation_blocks_m3_completion` (`revocation_lifetime.rs:365`) only proves it via a direct `mgr.set_roster` call. |
| `reload_of_a_revoked_key_is_applied_before_the_next_datagram` | Pins the **W2 drain** (§7.2): with a reload already queued, the next inbound datagram is processed *after* the reload is applied. Asserts the revoked client cannot establish even when its M3 is already in the socket buffer. |

**C3 -- policy tests.**

| Test | Asserts |
|---|---|
| `a_narrowing_roster_is_adopted_not_rejected` | A strict subset **is** published (revocation works). Asserts the roster length drops and the removed key can no longer establish. This pins the §5.3 policy decision in code, so that a future "let's be safe and reject narrowings" change breaks a test rather than silently disabling revocation. |
| `a_superset_roster_is_adopted` | Adding a client works. |
| `a_rotation_same_size_different_membership_is_adopted` | An A-to-B rotation is published. |
| `reload_rejected_empty_leaves_the_previous_roster_in_force` | An empty `RosterReload` through the channel is rejected, the previous roster is unchanged, and the previously trusted client can still establish. |
| `reload_rejected_oversize_leaves_the_previous_roster_in_force` | Same for an over-limit roster. |
| `closing_the_reload_channel_does_not_stop_the_server` | Drop the sender: the driver keeps serving (a later handshake still works); the server does not exit. |
| `a_failed_file_reload_does_not_stop_the_server` | Point the watcher at a corrupt file: the server keeps running with the previous roster. |

**C4 -- the existing tests that must be kept and re-verified.**

| Test | Line | Note |
|---|---|---|
| `revoked_key_cannot_re_establish` | `:330` | Unchanged. |
| `midflight_revocation_blocks_m3_completion` | `:365` | Unchanged. **Re-verify that it is still load-bearing** after the refactor. |
| `empty_roster_swap_is_rejected_fail_closed` | `:394` | Unchanged. |
| `revoked_client_retry_loop_never_establishes` | `:417` | Unchanged. |
| `established_session_survives_non_removing_roster_swap` | `:456` | Unchanged. |
| `revocation_defers_to_lifetime_cap_for_established_sessions` | `:493` | Unchanged; it is the D27 §5 / 24 h cap composition. |
| `roster_reload_is_fail_closed_on_bad_input` | `:555` | Extended to cover the new `UnstableRead` case. |
| `held_snapshot_survives_a_swap_unchanged` | `:688` | **Re-purposed**: with no shared cell this becomes "a snapshot taken before a swap is unaffected by it" at the file-read level. |
| `roster_replacement_is_atomic_under_concurrent_readers` | `:616` | **DELETED and replaced by C1.** Leaving it in place keeps a test that proves nothing while appearing to prove the atomicity property. |

### 12.4 `pq-tunnel-core/src/session_manager.rs` (unit tests)

| Test | Asserts |
|---|---|
| `driver_adopts_a_roster_reload` | The driver's `set_roster` is invoked with the candidate; `manager.roster_len()` changes. |
| `driver_rejects_an_empty_reload` | `set_roster` fails and the old roster is retained. |
| `driver_survives_a_closed_reload_channel` | The driver keeps processing datagrams. |
| `driver_applies_a_pending_reload_before_the_next_datagram` | The W2 drain is exercised deterministically. |

---

## 13. Remaining human decisions

These are genuine judgment calls. Each is listed with a recommendation; none
should be assumed.

| # | Decision | Recommendation |
|---|---|---|
| **H1** | **Poll interval default (5 s), and whether polling is on by default.** | **On, 5 s.** Off-by-default creates the "operator replaced the file and believed the key was revoked" hazard -- a *silent* revocation failure, the one thing D12 and D27 exist to prevent. Cost: one `stat` per 5 s. |
| **H2** | **Should an unintended narrowing be published, or should the server require confirmation?** | **Publish, loudly.** Refusing is a silent failure to revoke (a security failure); publishing is an availability failure (loud). If a confirmation step is wanted, it must be an explicit, separately-named flag (for example `--roster-confirm-narrowing`) and must not be the default. |
| **H3** | **Is SIGHUP worth it at all, given the poll?** | **Yes, but opt-in** (`--roster-reload-on-hup`). Installing a handler changes SIGHUP's conventional meaning. An explicit, non-poll trigger on **Windows** (where there is no SIGHUP) is an open question -- a "reload request file" is the cross-platform option if one is wanted. **Recommend: not now; the poll covers it.** |
| **H4** | **Should revocation ever kill a live session?** (D27 gate #3, still open.) | **No.** Per §8.1 the identity key does not expose the established session, and without a revocation-vs-rotation signal an immediate kill would drop the legitimate tunnel during a rotation. If wanted, it needs a new mechanism (a per-key revocation marker in the file) that is out of scope here. |
| **H5** | **Should duplicate keys in a roster file be rejected?** | **Yes, reject at parse time.** A duplicate is not a security bug, but it inflates the roster length against the `max_roster_size` bound, and the file's line count then differs from the number of *distinct* trusted clients -- which makes the logged "size" misleading. Small change in `parse_blobs`. |
| **H6** | **Should `ServerConfig::with_roster_limit` report the size error instead of silently emptying the roster?** (defect **D7**) | **Yes.** The startup error "roster must not be empty" for a 65-key roster is actively misleading, and reload errors must be legible -- the operator is the one who has to fix it. One-line change; low risk. |
| **H7** | **Should the STATS line carry `roster_gen` / `roster_size` / `roster_stale`?** | **Yes, but it needs a `ManagerNotification` variant**, which is a wider diff and touches `v2_server.rs`. **Recommend: defer**; the reload log lines already carry everything. Alternative with a much smaller diff: the *bin*'s STATS task reads the watcher's counters directly, because the watcher is a separate task that owns them. |
| **H8** | **Should aggregate counters for rejected handshakes (M1 authentication failures, M3 roster rejections) be added?** | **Yes, eventually** -- they are the operator's only visibility into a revocation *attempt*. But they touch `handshake_v2.rs` and inherit H7's `ManagerNotification` problem. **Recommend: defer.** |
| **H9** | **Should the 24 h cap be split per role (server versus client)?** (D27 gate #5, still open; a different track's territory.) | **Out of scope here.** Do not let this design depend on it. |
| **H10** | **Should the file-read quiescence window be operator-configurable?** | **No -- keep it a constant (1 s).** It is a safety heuristic, not a tradeoff knob. Making it configurable invites a value of 0, which disables the protection. |
| **H11** | **Should `RosterHandle` be deleted or deprecated?** | **Deleted.** A deprecated `Clone`-able roster handle in a public API re-creates the §1.3 trap (§15, F-14). |

---

## 14. Ways this design can fail (adversarial self-review)

| # | Failure mode | Assessment |
|---|---|---|
| **F-1** | **The poll never fires** (an in-place rewrite with a preserved mtime and the same length). | The signature includes the **file identity**, not just the mtime, so a rename is always detected. An *in-place* rewrite with a preserved mtime and the same length is the blind spot; it is closed by the explicit trigger and bounded by the operator-visible diff log. |
| **F-2** | **The in-place writer pauses at a line boundary** and a syntactically valid prefix roster is published. | **The main residual risk.** Mitigated by the atomic-replace recipe, the quiescence window and the loud `removed=[fp]` log. Not fully eliminable without a signed manifest (out of scope). In 1:1 the prefix of a one-key roster is either the empty set (rejected) or a partial key (rejected) -- the hazard essentially vanishes at the production roster size. |
| **F-3** | **The operator rotates A to B and the legitimate client (A) is dropped mid-session.** | By design (§8.1): A's session continues to its cap and then fails to re-establish. The operator must provision B on the client **before** rotating the server roster. This must be in the operator documentation -- it is the most likely operational surprise. |
| **F-4** | **The reload channel is full and the driver is busy.** | Capacity 1 plus `send().await` gives back-pressure; the watcher blocks until the driver consumes. The driver consumes within one `select!` iteration. No loss. |
| **F-5** | **The driver is stuck in a long `transport.recv()`.** | `recv()` is a `select!` branch and the reload branch is independently ready, so this cannot block the reload. A *blocking* file read inside the driver would stall it -- and there is none: the file read happens in the **watcher** task via `spawn_blocking`, never in the driver. |
| **F-6** | **Two reload candidates race** (the operator changes the file twice quickly). | The watcher's `send().await` serialises them; each is a complete generation; the last one wins. The intermediate generation may be applied briefly. Harmless. |
| **F-7** | **The core's `set_roster` rejects what the watcher accepted** (a limit mismatch between the watcher's `max_roster_size` and the manager's). | Both derive from `args.max_roster_size` (`pq-tunnel-bin/src/v2_server.rs:52`, `:54`). If they ever diverge, the driver logs `warn!` and keeps the old roster -- fail-closed and visible. |
| **F-8** | **The `select!` random branch selection lets a datagram overtake a pending reload (W2).** | Mitigated by the `try_recv` drain at the top of the transport branch. A residual sub-millisecond window remains; bounded and documented. |
| **F-9** | **The watcher's `spawn_blocking` task panics** (for example an allocation failure in the parser). | The watcher logs `warn!` and stops. The server keeps serving with the roster in force; the operator is told that revocation has stopped. Not silent. |
| **F-10** | **The startup `Vec` deep copy leaves a stale twin in `v2_server::run`'s `cfg`** (defect **D8**). | Fixed by `drop(cfg)` after the manager is built. If that is missed, the stale copy is never *read* -- a hygiene issue, not a security one. Worth a test: after a reload, nothing in the process still holds the old roster. |
| **F-11** | **`roster_watch_secs` is set to 0** and the operator forgets. | The flag is visible in `--help` and in the startup log line ("roster watching disabled; revocation requires an explicit trigger"). **Recommendation: log that at startup.** It is an explicit, visible reduction, not a silent one. |
| **F-12** | **The `roster_contains` timing leak** (defect **D9**) -- the position of a key in the roster is timing-observable at M3. | Post-authentication only, and already documented as a non-guarantee in D27 §4. Acceptable. A sorted-by-hash index would remove it, which is out of scope. |
| **F-13** | **The 24 h cap is never enabled** (a separate track's work) and a revoked-but-alive session is therefore unbounded. | This is exactly the exposure D27 §1.3 identifies. **This design does not fix it, and must not be read as fixing it.** The cap is the bound; without it, revocation bounds only *future* establishment. The dependency is stated in §8.2 and in the D27 amendment. |
| **F-14** | **The implementer keeps the old `RosterHandle` alongside the new watcher** "just in case". | That re-creates the stale-clone trap in a public API. The type must be **deleted**, not deprecated (H11). |
| **F-15** | **`RosterWatcher` gains a `Clone` impl later** for convenience. | The whole defect class returns. Add a compile-fail test asserting `RosterWatcher: !Clone` (§12.3). |
| **F-16** | **The watcher and the driver disagree about which generation is in force** (for example the driver rejects a candidate the watcher already marked published). | The watcher must mark its published signature **only after** the driver confirms adoption. The §11.7 sketch marks the signature after `send().await` succeeds, which is "queued", not "adopted" -- a stricter design would carry an acknowledgement back. **Recommend: the queue-then-adopt gap is acceptable** because the worst case is a redundant re-offer of an identical candidate, which the fingerprint comparison suppresses. This is recorded as a known simplification, not an oversight. |

---

## Appendix A -- Citation drift observed between the baseline and the working tree

At the time of writing, another track had uncommitted edits in
`pq-tunnel-core/src/handshake_v2.rs`, `pq-tunnel-core/src/session_manager.rs`,
`pq-tunnel-core/src/envelope.rs`, `pq-tunnel-core/src/wire_session.rs`,
`pq-tunnel-core/src/error.rs`, `pq-tunnel-bin/src/lib.rs`,
`pq-tunnel-bin/src/relay.rs`, `pq-tunnel-bin/src/v2_client.rs`,
`pq-tunnel-bin/src/v2_server.rs` and the test files. The constructs cited in
this document were confirmed still present; only the line numbers moved.

| Construct | Baseline `c6c0f12` | Working tree at the time of writing |
|---|---|---|
| `ServerHandshake::set_roster` | `handshake_v2.rs:1550` | `handshake_v2.rs:1601` |
| `roster_contains` | `handshake_v2.rs:1576-1578` | `handshake_v2.rs:1627` |
| The D12 uniform verification loop | `handshake_v2.rs:1813-1819` | `handshake_v2.rs:1887-1893` (`authed \|= ok` at `:1889`) |
| `entry.verified_client = matched` | `handshake_v2.rs:1868` | `handshake_v2.rs:1942` |
| The M3 re-check | `handshake_v2.rs:1949-1952` | `handshake_v2.rs:2033-2036` (still after the MAC check at `:2016-2021`) |
| `ServerSessionManager::set_roster` | `session_manager.rs:551-552` | `session_manager.rs:724-725` |

`pq-tunnel-core/src/codec.rs`, `pq-tunnel-core/src/replay.rs`,
`pq-tunnel-core/src/udp.rs`, `pq-tunnel-bin/src/identity.rs`,
`pq-tunnel-bin/src/forward.rs` and `pq-tunnel-bin/src/packet_len.rs` were
unmodified; their line numbers are cited directly.

## Appendix B -- What could not be verified

| Claim | Status |
|---|---|
| The Windows `MetadataExt::file_index()` / `volume_serial_number()` API and its availability on the pinned toolchain (1.99.0) | **[UNVERIFIED]** -- the methods are documented as stable since Rust 1.63, but the exact behaviour of `file_index()` across a rename-over was not exercised on this host. |
| The precise `MoveFileExW` share-mode semantics that make a rename-over succeed while a reader holds the handle | Documented behaviour of `std::fs::rename` on Windows; **not** exercised on this host in this wave. |
| The `lib.rs` flag surface (`--roster-watch`, `--roster-reload-on-hup`) | Design only. **Not implemented**, so no `clap` conflict check was performed. |
| The MSRV of the `sha2` digest usage in `pq-tunnel-core` | `sha2` is already a workspace dependency (`Cargo.toml:22`), so no new MSRV surface is introduced. |
| The `trybuild` / `static_assertions` mechanism for the `!Clone` compile-fail test | **Not present in the tree today**; either a new dev-dependency or a hand-rolled doctest is required. The recommendation in §12.3 prefers the hand-rolled doctest precisely to avoid a new dependency. |
