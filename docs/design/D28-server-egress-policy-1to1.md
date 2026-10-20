# D28 — Server Egress Policy (1:1 deployment)

## Status

**Proposed design; a MINIMAL subset is implemented.** The full policy below is
a **design proposal** — none of the table in §4, and none of the CLI flags in
§5, has shipped. What *has* shipped is a deliberately small guard that closes
the highest-severity hole (cloud-credential theft via the instance metadata
plane). See **§0 — What actually shipped** below for the exact list, and
§4/§5 for what did **not**.

> Scope note: this document is written against a **1:1 deployment** — one
> server, one client identity. It deliberately contains no multi-tenant
> machinery: no per-tenant policy engines, no tenant ACL systems, no
> capability tokens, no plugin sandboxing. Where a future multi-tenant design
> would need a different structure, that is recorded as DEFERRED in §7, not
> built.

---

## 0. What actually shipped (fact-checked against the tree)

A **minimal** server-side egress guard is implemented in
`pq-tunnel-bin/src/forward.rs` (module `egress`). It is a pure function of the
destination address and port — no I/O, no DNS, no state — and it is evaluated
**before any socket is created**, so a denied destination produces no outbound
datagram and no client-visible reply; the frame is dropped exactly like an
unroutable one. Denials are visible to the operator only through a bounded,
non-sensitive per-rule counter, never through per-destination logging.

### Shipped

| Rule | Denied | Notes |
|---|---|---|
| `port_zero` | destination port 0 | Not a port. The OS accepts it on some platforms, so the tunnel refuses it itself. |
| `v4_loopback` | `127.0.0.0/8` | |
| `v6_loopback` | `::1/128` | |
| `v4_unspecified` | `0.0.0.0/8` | "this network" / unspecified (RFC 1122). |
| `v6_unspecified` | `::/128` | |
| `v4_multicast` | `224.0.0.0/4` | |
| `v6_multicast` | `ff00::/8` | |
| `v4_broadcast` | `255.255.255.255/32` | limited broadcast. |
| `metadata_imds_v4` | `169.254.169.254` | AWS / GCP / Azure IMDS. |
| `metadata_alibaba_v4` | `100.100.100.200` | Alibaba ECS IMDS. |
| `metadata_aws_v6` | `fd00:ec2::254` | AWS IMDS over IPv6. |
| `metadata_gcp_v6` | `fd20:ce::254` | GCP metadata over IPv6. |

Two ordering properties matter and are implemented as such:

- The four **exact** metadata hosts are evaluated **before any range rule**,
  so they are denied even though their enclosing ranges (`169.254.0.0/16`,
  `100.64.0.0/10`) are **not** denied.
- IPv4-embedded IPv6 forms are normalised to IPv4 **before** the IPv4 rules
  run, so `::ffff:127.0.0.1` cannot be used to reach the IPv4 loopback behind
  the IPv4 rules.

### NOT shipped

- **The full §4 table.** Rows 8/9 (link-local `169.254.0.0/16` and
  `fe80::/10`), row 16 (`100.64.0.0/10` CGNAT), row 18/19/20 (6to4, Teredo,
  NAT64), row 22 (subnet-directed broadcast), row 23 (`240.0.0.0/4`
  reserved), row 24 (DNS on the operator's LAN) and the rest of the table are
  **not enforced**.
- **The §5 CLI flags.** `--allow-cidr` and `--allow-all-egress` do not exist.
- **The §4 defaults "deny `100.64.0.0/10`" and "deny the operator's LAN
  DNS".** Neither is implemented, and neither should be taken as-is: both are
  **product-breaking for a VPN** whose purpose is reaching private networks
  and resolving names on the operator's LAN. RFC1918, ULA, CGNAT, link-local
  and port 53 all remain reachable **by design** in the shipped guard.
- **The raw-IP / TUN egress policy.** Under the product's end state
  (system-wide TUN egress) the destination space is total, and the policy
  must be revisited for it. That is deferred to the TUN milestone; this
  document's table is written for the shipped relay's destination set.

The scope note in §4 — that the client can already name any destination under
the relay — remains accurate. The shipped guard reduces the blast radius; it
does not turn the forwarding backend into something other than a
server-side egress path for an authenticated remote party.

---

## Context

Tunnel's shipped v0.2 path (D18) is a UDP relay client plus a forwarding
backend server. The *product*, however, is a system-wide OS/networking tool:
the primary target is a TUN device plus system routes, i.e. full-system VPN
egress where the server forwards essentially arbitrary IP traffic. Per-process
masking and split tunnelling are backlog.

This distinction matters for egress policy. Under the shipped relay, a client
can already name any destination. Under full-system egress, the *volume and
diversity* of destinations becomes total, and the operator is knowingly
providing a general-purpose network path from a remote endpoint into whatever
the server host can reach. The honest statement of the hazard is not that
Tunnel has a bug but that the operator's server becomes trusted egress
infrastructure, and a compromised or malicious client can aim traffic at it.

Three concrete failure modes, in descending severity:

1. **Cloud credential theft.** An unauthenticated-but-authorized client, or an
   over-privileged one, uses the server as an SSRF gadget against the instance
   metadata service. The server is, by construction, *inside* the instance
   whose credentials are at stake. AWS names this exact configuration as a
   hazard: IMDSv2 is "designed to protect against EC2 instances that have been
   misconfigured as open routers, layer 3 firewalls, VPNs, tunnels, or NAT
   devices" (references §3.2). This is the highest-severity item by a wide
   margin.
2. **Server loopback compromise.** The D18 client relay refuses non-loopback
   binds, so the application-facing surface is local by construction. A
   forwarder that can reach `127.0.0.0/8` hands the remote client the server's
   own loopback — undoing that protection entirely. Services bound to loopback
   with no host firewall are the normal case.
3. **Infrastructure pivot.** Link-local, ULA, multicast and broadcast reach the
   server's own interfaces and the networks it sits in, enabling access to
   operator infrastructure that was never intended to be exposed.

Separately, two mechanical defects exist in the current forwarder that this
decision must also settle: **port 0 is accepted on the wire** (§2), and the
**socket pool caps are sized for a single application, not a full-system TUN
egress** (§3).

A fourth item is explicitly *not* a defect but a trap: RFC 1918 private space.
A VPN whose entire purpose is reaching private networks must not blanket-block
it. §4 analyses this tension carefully, because getting it wrong in either
direction is a product failure.

### What already exists

- `Forwarder` is a per-`(session, destination)` connected-UDP-socket pool
  (`pq-tunnel-bin/src/forward.rs:61-66`), with idle TTL and per-session/global
  caps (`forward.rs:37-42`).
- The relay framing is `family(1) ‖ address(4|16) ‖ port(2) ‖ len(2) ‖
  datagram(len)` (`relay.rs:5-8`), parsed by `decode_relay`
  (`relay.rs:103-144`).
- `decode_relay` already fails closed on unknown family, truncation and
  over-capacity length (`relay.rs:105-141`), and `forward.rs:87-96` drops
  malformed frames silently. **There is therefore an existing, proven
  fail-closed idiom to extend.** The policy check belongs in exactly that
  place.
- Cover-traffic policy is established as a transport-layer, never-negotiated
  concern (D19). D28 follows the same discipline.

---

## Decision

### 1. Destination special-range handling

**The model: default-deny on a small, fixed, hardcoded set of ranges, with an
explicit operator allow-override that is always weaker than the deny set
unless the operator also disables the deny set.**

The ordering is the security property, so it is stated first:

1. **Allow-override** (`--allow-cidr`) is consulted and a match permits.
2. **Deny set** is consulted and a match refuses.
3. Otherwise **allow**.

No — that ordering makes the allow-override useless, because the deny set
contains exactly the private ranges an operator legitimately wants. The correct
ordering, and the one D28 adopts, is:

1. **Deny set** is consulted first. A match refuses, **unless** the address is
   also matched by an operator allow-override *and* the operator has not
   enabled strict mode (§4.3).
2. Otherwise, an allow-override match permits (no-op — already permitted).
3. Otherwise, allow.

This is deliberately "deny wins, with a documented, logged, explicitly
narrow exception." The exception exists so that the private-network use case
works, and it is narrow in three ways: it is per-CIDR, it is operator-supplied
at startup, and it is logged as a security-relevant configuration at startup
(§5). The alternative — pure allow-list — is correct in the abstract and
unusable here, because the destination set for a full-system VPN is genuinely
unbounded. That is exactly "Case 2" in the OWASP sheet (references §4.3),
where allow-lists are documented as inapplicable.

**Non-negotiable floor (not overridable).** `0.0.0.0/8`, `127.0.0.0/8`, `::1/128`
and `::/128` are denied unconditionally, with **no** override. Reaching the
server's own loopback is never a legitimate operator intent, and the D18
loopback protection must not be defeatable by configuration. Loopback is
fail-closed by AGENTS.md's "Fail securely" rule and by the D18 decision itself.

#### 1.1 The CIDR/port policy table

Default = what ships with no operator flags. "Override" = the minimum mechanism
that changes it.

| # | Range / value | Default | Override | Rationale |
| --- | --- | --- | --- | --- |
| 1 | `0.0.0.0/8` "this network" | **DENY** | **none — hard floor** | `Destination: False` (RFC 6890). Semantically "this host on this network"; not a routable destination. On some stacks a send to `0.0.0.0` resolves to loopback. Cheap deny, no legitimate loss. |
| 2 | `127.0.0.0/8` loopback | **DENY** | **none — hard floor** | `Destination: False`. **Critical.** Defeats the D18 non-loopback-bind protection at `v2_client.rs:76-87` entirely: the client cannot reach loopback directly, but can reach it *through* the server. Unconditional. |
| 3 | `::1/128` loopback | **DENY** | **none — hard floor** | v6 equivalent of #2. Hard floor. |
| 4 | `::/128` unspecified | **DENY** | **none — hard floor** | `Destination: False`; ambiguous destination, some stacks treat as loopback. |
| 5 | `10.0.0.0/8` | **ALLOW** | `--block-cidr` to deny | RFC 1918. **Deliberately allowed by default** — see §4. A VPN that cannot reach `10.x` is not a VPN. |
| 6 | `172.16.0.0/12` | **ALLOW** | `--block-cidr` | RFC 1918. Same reasoning. |
| 7 | `192.168.0.0/16` | **ALLOW** | `--block-cidr` | RFC 1918. Same reasoning. |
| 8 | `169.254.0.0/16` link-local | **DENY** | `--allow-cidr` (logged) | `Forwardable: False`. Reaches the server's own interfaces and any L2 segment. This is where the cloud metadata endpoints live (#12, #13). |
| 9 | `fe80::/10` link-local unicast | **DENY** | `--allow-cidr` (logged) | `Forwardable: False`. v6 link-local; requires a zone/scope to be meaningful, which a relay header cannot carry, so it is malformed for this transport anyway. |
| 10 | `224.0.0.0/4` multicast | **DENY** | `--allow-cidr` (logged) | Amplification and abuse surface. A remote client could use the server to reflect traffic onto every host on every attached segment. **Not an RFC 6890 row** (multicast is RFC 5771, UNVERIFIED) — denied on abuse grounds. |
| 11 | `ff00::/8` multicast | **DENY** | `--allow-cidr` (logged) | v6 equivalent of #10. |
| 12 | `169.254.169.254` (AWS/Azure/GCP IMDS) | **DENY** | **none** | **Highest severity.** Reaches cloud instance credentials / IAM role tokens. Explicitly named by AWS as the hazard for "open routers, layer 3 firewalls, VPNs, tunnels, or NAT devices". No operator has a legitimate reason to relay this. Covered by #8 but listed separately because the severity deserves its own row and its own test. |
| 13 | `fd00:ec2::254` (AWS IMDS v6) | **DENY** | **none** | AWS's documented IPv6 IMDS endpoint. Inside ULA so #14 covers it; named for clarity and coverage. |
| 14 | `fc00::/7` ULA | **ALLOW** | `--block-cidr` to deny | "not globally routed" (RFC 4193/6890). **Deliberately allowed by default**, on the same reasoning as RFC 1918 (#5–#7): ULA is the v6 private space and a VPN must reach it. It also happens to cover #13, but see row #15 for why relying on that is not good enough. |
| 15 | `fd20:ce::254` (GCP IMDS v6) | **DENY** | **none** | **Correction to the task brief:** GCP's IPv6 metadata endpoint is `fd20:ce::254`; `fd00:ec2::254` is AWS's. Both are ULA, so #14 covers them by default. But **#14's default is ALLOW**, so a ULA block is *not* sufficient by default. **The metadata rows must therefore be independent hard denies, evaluated before the ULA allow.** This row existing separately from #13 is the point. |
| 16 | `100.64.0.0/10` shared address space (CGNAT) | **DENY** | `--allow-cidr` (logged) | **Contains `100.100.100.200`, the Alibaba Cloud ECS metadata endpoint** (references §3.5). This is inside **neither** `169.254.0.0/16` **nor** RFC 1918, so a link-local+RFC1918 denylist — the obvious one, and the one the OWASP sheet's minimum list corresponds to — **misses it**. Row #16 exists purely to close that gap. |
| 17 | `::ffff:0:0/96` IPv4-mapped | **DENY** | **none — hard floor** | `Destination: False`, `Reserved-by-Protocol: True`. The critical property: a check written only against v4 ranges will not classify this, and some stacks will route it to the embedded v4 address. **Must be normalised before any v4 range test**, not tested after. Hard floor: a v4-mapped address is never a legitimate distinct destination. |
| 18 | `2002::/16` 6to4 | **DENY** | `--allow-cidr` (logged) | Encodes a v4 address in the prefix (`2002:<v4>::/48`). Lets a client reach v4 space through a "v6" path that a naive v4 filter never sees. |
| 19 | `2001::/32` Teredo | **DENY** | `--allow-cidr` (logged) | Same class as #18 — tunnels to v4 through a v6 prefix. |
| 20 | `64:ff9b::/96` NAT64 | **DENY** | `--allow-cidr` (logged) | `Globally Reachable: True` but it is a v4 translation prefix; same tunnel-through-a-v6-prefix hazard as #18/#19. |
| 21 | `255.255.255.255` limited broadcast | **DENY** | **none** | The one RFC 6890 block with `Destination: True` / `Forwardable: False`. Reflects onto every local segment. Never a legitimate relay target. |
| 22 | Subnet-directed broadcast (e.g. `x.y.z.255/24`) | **DENY** | **none** | The forwarder has no subnet mask knowledge (it forwards a `SocketAddr`, not an interface), so it cannot compute directed broadcast. Denying all `.255` hosts is the only sound approximation. **Tradeoff: this can deny a legitimate host whose address happens to end in .255.** For 1:1 with an operator-specified `--allow-cidr`, that host is recoverable. |
| 23 | `240.0.0.0/4` reserved | **DENY** | `--allow-cidr` (logged) | `Destination: False`, `Reserved-by-Protocol: True`. Includes `255.255.255.255`, so it subsumes #21. |
| 24 | DNS on the operator's LAN, `53/tcp`+`53/udp` | **DENY** | `--allow-cidr` for the resolver address | The forwarder is **UDP-only** (D18), so only 53/udp is actually reachable today; 53/tcp is listed because a future TCP milestone must not silently acquire it. Denying a **specific resolver address** is the default posture: the operator's LAN DNS is reachable at the operator's own LAN addresses, and relaying arbitrary LAN DNS turns the server into a DNS amplifier and a route to internal resolver state. |
| 25 | **Port `0`** | **DENY (malformed)** | **none** | See §2. Reserved on both tcp and udp (references §2.1, §2.2). Reject as malformed. |
| 26 | Any other destination | **ALLOW** | `--block-cidr` | The product's purpose. |

Three rows deserve emphasis because they are the ones a checklist-derived
denylist would get wrong:

- **#16 (`100.64.0.0/10`)** — the Alibaba metadata endpoint. Missed by the
  obvious "link-local + RFC1918" denylist.
- **#15 (`fd20:ce::254`)** — GCP's v6 metadata endpoint, whose block (#14) is
  *allowed by default*. The temptation to write "ULA is denied" is the mistake;
  D28 allows ULA because a VPN must reach private v6.
- **#17 (`::ffff:0:0/96`)** — must be normalised *before* v4 classification, not
  checked after.

#### 1.2 Normalisation order (a correctness requirement, not a detail)

The check must run in this order, and this is a real bug class if it does not:

1. Parse the `SocketAddr` from `decode_relay`.
2. If v6, unwrap `::ffff:a.b.c.d` to `a.b.c.d` **and re-run the whole v4 deny
   set on the result**. (Rows #1, #2, #5–#8, #12, #16, #21, #22, #23.)
3. If v6, reject `2002::/16`, `2001::/32`, `64:ff9b::/96` as tunnel-through
   prefixes (rows #18–#20).
4. Apply the v6 deny set (rows #3, #4, #9, #11, #13, #14-if-blocked).
5. Apply the v4 deny set.
6. Apply the metadata hard-denies (#12, #13, #15) — **before** any allow-by-
   default for their containing block.

`std::net::Ipv6Addr::to_ipv4_mapped()` performs step 2; `to_ipv4()` alone is
**not** sufficient because it also matches IPv4-compatible addresses, which is
a different and undesired widening.

### 2. Port 0 — reject as malformed

**Findings from reading the code and from measurement.**

`decode_relay` parses the port at `relay.rs:111` (v4) and `relay.rs:124` (v6)
with `u16::from_be_bytes(...)` and constructs a `SocketAddr` with no range
check. **`port == 0` is therefore representable end-to-end**: it decodes, it
becomes the pool key at `forward.rs:120`, `prune_and_insert` binds a socket
(`forward.rs:199`) and calls `sock.connect(dest)` (`forward.rs:206`), and the
datagram is sent at `forward.rs:133`. A client can therefore ask the server to
`connect` + `send` to port 0 today.

**The task brief's premise about OS behaviour is wrong, and I measured it
rather than assuming.** The brief said "on Windows generally fails". On this
host, using the exact syscall sequence `forward.rs` uses
(`bind(0.0.0.0:0)` → `connect(127.0.0.1:0)` → `send`):

```
CONNECT_PORT0_OK local=127.0.0.1:54351
SEND_AFTER_CONNECT_OK sent=4
```

Both `connect()` and `send()` **succeeded**. Port 0 is not rejected by
Winsock. (A separate `UdpClient.Send` to port 0 also returned success:
`SENDTO_PORT0_OK sent=4`.) So the "fail-closed to the OS" assumption is not
available on Windows, and port 0 must be rejected by Tunnel itself.
**UNVERIFIED**: no Linux measurement was possible — WSL is installed on this
host but has no distro. Since D28 rejects port 0 regardless of platform, this
does not affect the decision; it affects only the rationale text.

**Port 0 is meaningless as a destination.** It is `Reserved` for both tcp and
udp in the IANA registry, and RFC 6335 §6 includes `0` among the range-edge
values that are "assigned to IANA for special purposes" and "not available for
regular assignment" (references §2.1, §2.2). A send to port 0 has no
well-defined remote behaviour; on Linux it is implementation-dependent, and on
Windows it is accepted at the syscall level with no delivery guarantee.

**Policy: reject port 0 as malformed. No override. Fail-closed**, consistent
with AGENTS.md "Fail securely" and with the existing D18 fail-closed idiom at
`forward.rs:87-96` ("Unknown family/truncated: drop, fail-closed").

**Do not confuse this with the *source* port 0.** `forward.rs:195-198` binds
`0.0.0.0:0` / `[::]:0`, which is correct and required — port 0 as a *source*
means "pick an ephemeral port" and is documented Winsock behaviour
(references §2.3). The two must be checked separately; a naive "reject port 0"
grep would break the bind.

**Exact code location.** Two candidate sites, and the choice matters:

| Site | File:line | Assessment |
| --- | --- | --- |
| `decode_relay` | `relay.rs:103-144` | **Rejected.** `decode_relay` is shared by the client relay (`relay.rs:210`, `relay.rs:257`) and the server forwarder (`forward.rs:87`), and is exercised by the fuzz target `fuzz/fuzz_targets/relay_overlay.rs`. Rejecting there would change the *client's* decode contract and require the fuzz target's round-trip assertions to be revisited — a protocol-framing change dressed as a policy change. Also, per the D28 model, a destination is a *policy* input, not a *framing* input. |
| `Forwarder::handle` | `forward.rs:81-96`, immediately after `decode_relay` returns `Ok`, before the `echo` branch and before `prune_and_insert` | **Chosen.** Server-side only, no framing change, no client-visible change, sits inside the existing fail-closed path, and covers both the `echo` and forward branches. |

Concretely, the check belongs between `forward.rs:96` (end of the `decode_relay`
match) and `forward.rs:98` (the `if self.echo` block), as an
`if dest.port() == 0 { return; }`. It is four lines and needs no new type.

### 3. Socket and resource quotas

**Current state, verbatim** (`forward.rs:37-42`):

```rust
pub const IDLE_TTL: Duration = Duration::from_secs(60);
pub const PER_SESSION_CAP: usize = 128;
pub const GLOBAL_CAP: usize = 512;
```

**Are they adequate for full-system TUN egress? No, and the analysis is
specific rather than hand-wavy.**

- `PER_SESSION_CAP = 128` is a *distinct destination* cap per session. A single
  web page load touches dozens of distinct hosts; a single `apt`/SDK/container
  pull touches hundreds to thousands. 128 distinct destinations is a low bar
  that a normal workload crosses and then churns against. Under TUN this is not
  a generous cap, it is a cap that evicts constantly.
- `GLOBAL_CAP = 512` is `4 × PER_SESSION_CAP`. With 1:1 there is one session, so
  `GLOBAL_CAP` is *never* the binding constraint — `PER_SESSION_CAP` binds
  first, at 128. `GLOBAL_CAP` is effectively dead weight under the 1:1
  assumption, and the compile-time assertion at `forward.rs:299-301` that
  `GLOBAL_CAP >= PER_SESSION_CAP` is satisfied trivially.
- `IDLE_TTL = 60 s` is adequate and should be kept. It bounds descriptor
  lifetime and is enforced on every datagram, not only on insert
  (`forward.rs:82-84`, `forward.rs:225-234`) — that is correct and was
  deliberately fixed earlier. Under TUN, *more* traffic means *fewer* idle
  sockets, so TTL pressure goes the right way.

**Actual eviction behaviour, precisely as implemented.** It is
**drop-oldest-by-last-use (LRU)**, not true FIFO, and not a separate LRU
structure — it is a linear scan over a `HashMap`:

- `prune_idle` (`forward.rs:225-234`): collects every entry whose
  `now - last_use > IDLE_TTL` and drops them. Unconditional sweep, runs on
  every datagram via `handle` (`forward.rs:84`).
- `prune_and_insert` (`forward.rs:155-190`): first calls `prune_idle`; then if
  `sockets.len() >= GLOBAL_CAP` it drops the single globally-oldest entry via
  `oldest()` (`forward.rs:237-242`, a `min_by_key` over the whole map); then,
  in a loop, while that session's own entry count is `>= PER_SESSION_CAP`, it
  drops that session's oldest entry (`forward.rs:174-189`, a `min_by_key` over
  the session's keys).
- `drop_entry` (`forward.rs:244-248`): removes from the map and `abort()`s the
  reader task.

**Complexity note.** Every `prune_and_insert` does one O(n) scan for the
per-session eviction (rebuilding `sid_entries` on each loop iteration,
`forward.rs:167-189`) and `oldest()` is O(n) over the global map. Under 1:1
`n ≤ 128` so this is cheap. D24 explicitly declined to add a second eviction
algorithm for the same reason (bounded by a small constant). D28 keeps that
discipline: **no new LRU data structure is proposed.**

**Is drop-oldest right for TUN? Yes — but it has a specific cost that must be
recorded rather than glossed.**

The reason it is right: dropping an entry loses only the *in-flight source-port
binding* for that destination. The next datagram for that destination lazily
re-creates the socket (`forward.rs:121-122` → `prune_and_insert`). Nothing is
lost but a NAT/firewall state entry. Crucially, the module doc at
`forward.rs:16-19` explains why this beats returning `ForwardError`: "a
`ForwardError` would turn a DoS into a tunnel teardown; eviction is the
documented tradeoff." Eviction degrades; tearing down the session does not.

The cost: under TUN the working set of *distinct destinations* is large and
bursty, so the pool will sit at cap and churn. Each eviction costs a socket
close and re-open, and a **new ephemeral source port** — which is exactly the
thing §3.3 is about.

**Gaps identified.**

1. **No byte or datagram accounting per session.** `SessionMetrics`
   (`pq-tunnel-core/src/metrics.rs:4-11`) tracks `bytes_sent`/`packets_sent`,
   but that is the **tunnel** direction, not forwarder egress, and it is only
   readable on a `WireSession` (`wire_session.rs:164`). Nothing bounds how much
   a client can make the server *emit* to the internet. Under TUN this is the
   difference between "the client is expensive" and "the client is an
   amplifier". **Recorded as a gap; sizing deferred to §7.**
2. **No datagram-rate limit in the forwarder.** The per-source failure gate
   (D24) charges *decrypt failures only*, by deliberate design. Successful
   datagrams from an authorized client are entirely unbounded toward the
   internet. This is stated in `THREAT_MODEL.md` §7.1 as an accepted
   non-guarantee ("Out of scope: the volume of traffic a legitimate key-holder
   sends"). D28 does not change that — but a TUN deployment should know it.
3. **Source-port exhaustion from the server's perspective.** This is the real
   gap and it is easy to miss. Each pooled entry binds an **ephemeral source
   port** on the server. The Windows dynamic port range is 49152–65535
   (references §2.3), so roughly **16 384 ports** exist. With `PER_SESSION_CAP`
   at 128 there is ample headroom — **but if the caps are raised naively for
   TUN (say to 8192) and churn causes rapid eviction/re-bind, the server can
   exhaust its ephemeral port range**, and it will do so silently: bind failures
   only `warn!` at `forward.rs:201` and the datagram is lost. This is a
   self-inflicted outage that looks like packet loss. **The cap must be sized
   against the ephemeral port range, not against comfort.**
4. **Churn amplifies #3.** Drop-oldest under a working set larger than the cap
   means near-constant re-binding. The mitigation is to size the cap *above* the
   expected working set, not to add clever eviction.

**Quota recommendation (1:1).** Raise `PER_SESSION_CAP` and keep the
GLOBAL/PER relationship. Concretely: `PER_SESSION_CAP` → **2048**, and keep
`GLOBAL_CAP` at **4096** (2× — it is a backstop for leaked entries, not a
functional cap at 1:1). 2048 sockets is roughly 12.5% of the Windows ephemeral
port range, leaving ample room. `IDLE_TTL` unchanged at 60 s.

**This is a NEEDS-DESIGN item, not a LOW-RISK one** — see §6. The constant is a
one-line change but the *choice of 2048* is a judgement about real TUN
working-set size that has not been measured on this codebase. Flagged in §9.

### 4. RFC 1918: the tension, and the resolution

This is the item where getting it wrong is a product failure, so the analysis
is explicit.

**The tension.** RFC 1918 §3 says "packets with private source or destination
addresses should not be forwarded across such links" (references §1.4). A VPN
server forwarding to `10.1.2.3` is doing precisely what that sentence
discourages. But a VPN whose purpose is reaching an office LAN *is* forwarding
to `10.1.2.3`, on the operator's explicit instruction. The RFC's sentence is a
general hygiene default; the operator's deployment is a deliberate,
enumerated exception to it.

The tempting resolutions are both wrong:

- **Blanket-block RFC 1918** (the classic SSRF denylist shape, and what the
  OWASP minimum block list does). This makes Tunnel useless as a VPN. The
  product breaks. Not acceptable.
- **Allow everything (no policy at all)** — the current shipped behaviour. The
  server is a general-purpose pivot into the operator's LAN, and into cloud
  metadata. Not acceptable.

**The resolution, and why it is not "allow-list everything".** Three properties
together:

1. **Private space is allowed by default** (#5–#7, #14). The product works out
   of the box. This is a deliberate departure from the SSRF-checklist default
   and the doc must say so plainly rather than hide it.
2. **A hard floor of never-reachable ranges** (#1–#4, #17) sits underneath, so
   the server's own loopback is unreachable no matter what. The one thing a
   forwarding service must never expose.
3. **Metadata endpoints are unconditional hard denies** (#12, #13, #15, #16)
   that are evaluated *before* the allow-by-default of their containing block.
   This is what makes allowing RFC 1918 and ULA safe. Allowing `10.0.0.0/8` is
   only acceptable because the specific credential-bearing endpoints inside it
   are carved out independently.

**Why an explicit allowlist was rejected as the primary model.** An allowlist
(`--allow-cidr 10.20.0.0/16 --allow-cidr ...`) is the textbook-correct shape and
WireGuard's `AllowedIPs` works exactly that way (references §4.1). For 1:1 it
is viable — an operator can enumerate. But as the *only* mechanism it makes the
default posture of every fresh install "deny everything", which turns a
one-command install into a policy-authoring project and will simply not be
adopted. The safe default and the usable default are different here, and the
resolution is to ship the usable one with a hard floor, plus a narrow
`--allow-cidr` escape for the specific case where an operator wants a range
allowed *despite* an explicit deny (e.g. re-enabling a link-local range they
know is not metadata).

**4.3 Strict mode (optional, recommended to defer).** An alternative worth
naming and explicitly *not* building now: a `--strict-private` mode where
RFC 1918 and ULA are denied unless explicitly allowed — the allowlist-first
posture. It is defensible. It is deferred because (a) it adds a second,
conflicting default to reason about, (b) 1:1 has exactly one operator who can
be told "add the CIDR", and (c) it is the first thing to add if D28 ever grows a
multi-client story. Recorded in §7.

### 5. Operator overrides — the minimal surface

**The smallest set that lets a 1:1 operator reach what they legitimately need.**
Three flags, in `ServerArgs` (`pq-tunnel-bin/src/lib.rs:74-105`):

| Flag | Type | Default | Effect |
| --- | --- | --- | --- |
| `--allow-cidr <CIDR>` | repeatable | none | Permits a range **despite** the deny set. Longest-prefix match wins. Logged at startup. |
| `--block-cidr <CIDR>` | repeatable | none | Denies a range that would otherwise be allowed (e.g. a specific `10.x` the client should not reach). Deny wins over the default. Logged at startup. |
| `--allow-all-egress` | bool | `false` | **Disables the entire deny set** (rows #1–#24, excluding the port-0 rule). Logged at `WARN` at startup. |

Three flags. That is the surface. Notes on each:

- **CIDR parsing.** The workspace has no `ipnet` dependency
  (`pq-tunnel-bin/Cargo.toml:15-25` has no net-parsing crate). Adding one is a
  dependency decision — see §6 step 5 and §9 gate 3. A hand-rolled parser is
  **explicitly rejected**: AGENTS.md forbids inventing parsing/crypto-adjacent
  code, and address-parsing bypasses (hex, octal, dword) are a documented
  attack class (references §4.3). Two flags, not four: `--allow-cidr` and
  `--block-cidr` cover every legitimate need; separate "allowed"/"blocked"
  naming would be a second vocabulary for one concept.
- **`--allow-all-egress` is deliberately separate and deliberately loud.** It
  is the escape hatch for an operator who says "I understand the metadata
  exposure." It must not be reachable by combining other flags, because then
  its use would not be greppable in a config or a log. It `WARN`s, not `info`s.
- **Startup logging is a hard requirement, not polish.** AGENTS.md: security
  tradeoffs must be "intentional, visible, documented, reversible". So at
  startup, `v2_server.rs` logs: every `--allow-cidr`, every `--block-cidr`, and
  a `WARN` line for `--allow-all-egress` naming the *disabled* protections. The
  existing precedent is right next door: `--no-cover` is documented as "an
  explicit, documented reduction" (`lib.rs:101-104`, D19). Same pattern.
- **Reversibility.** Because all three are startup-only CLI flags with no
  runtime reconfiguration and no persistence, reversing is removing a flag and
  restarting. There is no state to migrate.

**D19 compliance — this is the rule that constrains the design.** Cover
traffic and lifecycle policy must **never** become handshake state
(`DESIGN_DECISIONS.md` D19: "The policy lives in the session/driver layer ...
never in `ClientConfig`/`ServerConfig`, so it cannot become part of the
protocol negotiation surface"). Egress policy is the same class of
decision: it is **server-local deployment configuration**, it is **not** in
`HandshakeV2ServerConfig` (`pq-tunnel-core/src/handshake_v2.rs`), it is **not**
in `ClientConfig`, and it is **not** carried in any handshake message. The
policy object is constructed in the binary crate from CLI flags and handed
directly to `Forwarder::new`. **No mechanism exists by which a client could
influence, learn, or negotiate it.** This is a structural property worth
stating in the code so a future change cannot quietly violate it.

### 6. What must be redesigned vs reused

| Component | Verdict | File:line | Note |
| --- | --- | --- | --- |
| Relay framing / codec | **Reuse unchanged** | `relay.rs:71-144` | `encode_relay`/`decode_relay` stay byte-for-byte identical. D28 is a policy layer *above* the codec. Fuzz target `fuzz/fuzz_targets/relay_overlay.rs` keeps passing with no edit. |
| Client relay | **Reuse unchanged** | `relay.rs:152-299`, `v2_client.rs:32-104` | Egress policy is a **server** concern. The client must not gain a policy surface. |
| `Forwarder` struct | **Reuse** | `forward.rs:61-66` | Add one `policy` field. `sockets`/`commands` unchanged. |
| `Forwarder::new` | **Modify (LOW-RISK)** | `forward.rs:70-77` | Add an `EgressPolicy` parameter. Signature change; 3 call sites (`v2_server.rs:103`, `tests/e2e_smoke.rs:135`, `tests/common/mod.rs:295`). |
| `Forwarder::handle` | **Modify (LOW-RISK)** | `forward.rs:81-96` | Add the port-0 check (§2) and the policy call, both before the `echo` branch. Fail-closed, mirroring the existing drop at `forward.rs:87-96`. |
| `prune_idle` | **Reuse unchanged** | `forward.rs:225-234` | Correct as-is. `IDLE_TTL` unchanged. |
| `prune_and_insert` | **Modify (NEEDS-DESIGN)** | `forward.rs:155-190` | Called only from a policy-approved path after §2's change, so its internals stay; the **caps** change (§3). Also gains a real bind-failure counter instead of `warn!`-only (`forward.rs:201`). |
| `drop_entry` / `oldest` | **Reuse unchanged** | `forward.rs:237-248` | Drop-oldest LRU semantics kept. No new data structure (D24 precedent). |
| `reply_reader` | **Reuse unchanged** | `forward.rs:261-292` | Replies are relabelled for a destination that was already approved at request time. No re-check needed — the destination is a `let` binding from an approved socket. |
| `ServerArgs` | **Modify (LOW-RISK)** | `lib.rs:74-105` | Add three flags. |
| `v2_server::run` | **Modify (LOW-RISK)** | `v2_server.rs:38-150` | Build the policy from args, pass to `Forwarder::new` (`v2_server.rs:103`), log at startup. |
| `SessionLimits` | **Reuse unchanged** | `session_manager.rs:105-131` | Session-table limits are orthogonal to socket-pool limits. D24 already bounds session state. |
| `SessionMetrics` | **Reuse, extend later** | `metrics.rs:4-11` | Not on the egress path today; no change now (§7). |
| `HandshakeV2ServerConfig` / `ClientConfig` | **MUST NOT be touched** | `pq-tunnel-core/src/handshake_v2.rs` | D19 structural guarantee. |
| New `egress` module | **Create (NEEDS-DESIGN)** | `pq-tunnel-bin/src/egress.rs` | Policy type + CIDR matching + the table. Pure, no I/O, unit-testable. |
| `pq-tunnel-core` | **Reuse unchanged** | whole crate | No core change at all. Egress policy is a binary/driver-layer concern, exactly like `CoverPolicy`. |
| New fuzz target | **Create (LOW-RISK)** | `fuzz/fuzz_targets/egress_policy.rs` | `egress_policy` must be total and panic-free on any `(IpAddr, u16)`. |

**The single most important line in this table:** `reply_reader` needs **no**
policy check. That is a deliberate security property worth recording — the
policy is evaluated exactly once, at the point the destination is first
requested, and the pool key is the already-approved `dest`. There is no path
by which a reply can introduce an unapproved destination.

### 7. Minimal code change plan

Ordered. Each step marked **LOW-RISK** (mechanical, no design judgement),
**NEEDS-DESIGN** (requires a decision not yet made), or **RESEARCH-ONLY**
(investigate, do not build).

| # | Step | File / function | Risk |
| --- | --- | --- | --- |
| 1 | Add port-0 rejection: `if dest.port() == 0 { return; }` after the `decode_relay` match, before the `echo` branch. Unit test: `decode_relay(b"\x04\x7f\x00\x00\x01\x00\x00...")` then assert no socket is created. | `forward.rs:96`→`98` | **LOW-RISK** |
| 2 | Create `egress.rs` with `EgressPolicy { allow: Vec<Cidr>, block: Vec<Cidr>, allow_all: bool }` and `fn check(&self, dest: &SocketAddr) -> Verdict`. Hard-code the §1.1 table as a `const`. Pure functions only. | new `pq-tunnel-bin/src/egress.rs` | **NEEDS-DESIGN** (table transcription) |
| 3 | Unit tests for `egress::check` covering **every** row of §1.1 — one positive and one negative per row. Includes the `::ffff:127.0.0.1` normalisation case and the `fd20:ce::254` / `100.100.100.200` cases. | `egress.rs` `#[cfg(test)]` | **LOW-RISK** |
| 4 | Thread `EgressPolicy` into `Forwarder` (one field) and `Forwarder::new` (one param). Update the 3 call sites: `v2_server.rs:103`, `e2e_smoke.rs:135`, `common/mod.rs:295`. Tests pass `EgressPolicy::default()`. | `forward.rs:61-77`, 3 sites | **LOW-RISK** |
| 5 | Add the three CLI flags to `ServerArgs`; build the policy in `v2_server::run`; log every `--allow-cidr` / `--block-cidr` at `info!` and `--allow-all-egress` at `warn!` naming the disabled protections. | `lib.rs:74-105`, `v2_server.rs:38-103` | **NEEDS-DESIGN** (CIDR dependency choice) |
| 6 | Re-raise `PER_SESSION_CAP` 128 → 2048, `GLOBAL_CAP` 512 → 4096, keep `IDLE_TTL` 60 s. Update the compile-time assertion at `forward.rs:299-301`. | `forward.rs:37-42` | **NEEDS-DESIGN** (see §9 gate 2) |
| 7 | Call `policy.check(&dest)` in `handle` before the `echo` branch; drop silently on `Deny` (fail-closed, consistent with `forward.rs:87-96`). | `forward.rs:96-98` | **LOW-RISK** |
| 8 | Fuzz target `egress_policy`: `egress_policy(addr_bytes, port)` must never panic and must never classify a mapped-IPv4 loopback/ULA/link-local as allowed. | new `fuzz/fuzz_targets/egress_policy.rs` | **LOW-RISK** |
| 9 | E2E test: drive the real stack and assert a relay-framed datagram to `169.254.169.254` produces **no** outbound packet and **no** app reply, then assert a normal roundtrip still works (recovery, matching the `e2e_adversarial.rs` recovery pattern). | new case in `tests/e2e_adversarial.rs` | **LOW-RISK** |
| 10 | Document: add D28 to `DESIGN_DECISIONS.md`; add the pivot threat to `THREAT_MODEL.md` §4/§7; add the flags to `IMPLEMENTATION_GUIDE.md` and `CHANGELOG.md`. | docs | **LOW-RISK** |
| 11 | **Investigate only:** measure real distinct-destination working set for a TUN egress to validate 2048. Do **not** build a bytes/datagrams-per-session counter in this pass. | — | **RESEARCH-ONLY** |
| 12 | **Investigate only:** confirm whether `to_ipv4_mapped()` alone is sufficient or whether IPv4-compatible addresses need separate handling. Do **not** add IPv4-compatible handling speculatively. | — | **RESEARCH-ONLY** |

Gate commands after steps 1–10 (per AGENTS.md, `--target x86_64-pc-windows-msvc`
is the canonical target; note that the "ARM64 host cannot build `aws-lc-sys`"
reason formerly quoted here is stale — `aws-lc-sys` is not in the dependency
tree at all):

```sh
cargo fmt --check
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test --workspace --target x86_64-pc-windows-msvc
cargo +nightly fuzz build --fuzz-dir fuzz --target x86_64-pc-windows-msvc
```

### 8. Explicitly DEFERRED (and why)

Deferred means *deliberately not built*, not *forgotten*.

| Deferred | Why |
| --- | --- |
| **Multi-tenant / per-client policy** | Out of scope by settled assumption (1:1). No per-tenant policy engine, no tenant ACLs, no capability tokens, no plugin sandboxing. |
| **Per-session byte / datagram accounting** (§3 gap 1) | The mechanism does not exist (D24's gate is failure-only, by design) and adding a rate limiter is a *new* design with its own DoS and fairness analysis — a separate decision, not a D28 addendum. Needs the TUN working-set measurement first (step 11). |
| **DNS resolver policy beyond a deny row** (#24) | The forwarder is UDP-only; there is no TCP path to accidentally acquire 53/tcp. Blocking a specific resolver *address* is the correct minimal shape. Full DNS-aware policy (per-domain, DoH detection) is a different product feature. |
| **Subnet-directed broadcast done exactly** (#22) | The forwarder forwards a `SocketAddr` with no subnet-mask knowledge; it structurally cannot compute directed broadcast. The `.255` approximation is honest. Exactness would require interface/route knowledge the forwarder deliberately does not have. |
| **`--strict-private` / allowlist-first mode** (§4.3) | Defensible, but a second conflicting default for 1:1 where one operator can just add a CIDR. First thing to add if multi-client ever lands. |
| **Per-process masking / split tunnelling** | Backlog, outside D28. D28 is the server side; masking is the client side. |
| **Rewriting eviction to a real LRU** | D24 already declined this for the same reason: bounded small constant, and a second eviction algorithm is a second thing to get wrong in a path whose failure mode is "attacker shapes our internal state". |
| **Rate-limiting the forwarder data path** | Would contradict D24's deliberate "charge failures, not traffic" design. Changing it is a D24 amendment, and D28 should not silently revise an accepted decision. |
| **Policy reload / runtime reconfiguration** | 1:1, startup-only. Runtime reload adds a mutation surface with no corresponding need. |
| **Notifying the client when its traffic was denied** | Deliberate silence. Any feedback would be an oracle distinguishing "blocked by policy" from "no reply", which is a metadata-resistance regression (D5/D22) and an error oracle (D12). Denials are server-side logs only. |
| **`pq-tunnel-core` changes** | None needed. Keeping the policy in the binary crate mirrors `CoverPolicy` and keeps the D19 separation obvious. |

### 9. Human decision gates

These need a human answer before implementation. Each is a genuine judgement,
not a lookup.

**Gate 1 — Approve the §1.1 default posture.** Specifically: is it acceptable
that **RFC 1918 and ULA are ALLOWED by default**, and that the protection
against metadata theft rests on rows #12/#13/#15/#16 rather than on denying
private space? This is the central product trade-off and the one most likely to
be contested. The alternative is `--strict-private` (§4.3).

**Gate 2 — Approve the cap values.** `PER_SESSION_CAP = 2048` and
`GLOBAL_CAP = 4096` are reasoned from the Windows ephemeral port range
(49152–65535, references §2.3) and an *estimated* TUN working set. 2048 leaves
~12.5% port headroom. If the measured working set (step 11) is far larger, the
cap must rise and the port-exhaustion risk must be re-evaluated with it. **Do
not take 2048 on faith.**

**Gate 3 — Approve the CIDR-parsing dependency.** D28 needs CIDR parse + match.
The workspace has no such crate. Options: add `ipnet` (or `ipnetwork`), or
implement matching by hand. **Hand-rolling is recommended against** (parsing
bypasses are a known attack class). This is a new dependency in a security
crate and warrants an explicit yes.

**Gate 4 — Confirm the hard floor is genuinely non-overridable.** Rows #1–#4
and #17 deny with *no* escape, including from `--allow-all-egress`. That means
an operator cannot, even deliberately, relay to the server's own loopback.
Confirm that is the intent and that no legitimate 1:1 use needs it.

**Gate 5 — Confirm silence on denial** (§8, last row). Denied destinations
produce no client-visible signal. Confirm the operator is content to debug via
server-side logs only, and that no log line will be emitted at `warn!` per
denied datagram (that would be a log-volume DoS; it must be rate-limited or
count-only).

---

## Consequences

**Advantages:**

- The server's own loopback becomes unreachable by the client, restoring and
  protecting the D18 non-loopback-bind guarantee (`v2_client.rs:76-87`) that an
  unfiltered forwarder silently defeats.
- The highest-severity exposure — cloud instance credential theft — is closed
  by construction, at the point where the destination is first requested,
  before any socket is created. AWS's own guidance names this exact deployment
  shape as the hazard (references §3.2), and this is the primary control rather
  than relying on hop limits we do not control.
- The product's actual purpose keeps working out of the box: private networks
  are reachable with no configuration, which a blanket-RFC1918 block would
  break.
- Port 0 is rejected by Tunnel itself, because **measurement showed the OS
  does not reject it** — the assumption in the task brief was wrong and the
  defect is real on Windows today.
- Resource bounds are re-sized against a measured property (the ephemeral port
  range) rather than left at values chosen for one application.
- Zero change to the wire format, the codec, the client, or
  `pq-tunnel-core`. The fuzz target for the relay overlay needs no edit.
- The policy is structurally incapable of becoming handshake state: it is
  constructed from CLI flags in the binary crate and never touches
  `HandshakeV2ServerConfig` (D19).
- Overrides are three flags, all startup-only, all logged — visible, reversible,
  and greppable.

**Tradeoffs:**

- **The default allows private space, which diverges from SSRF-checklist
  practice** (references §4.3). This is intentional and product-driven, but it
  means the security of the default rests on the metadata carve-outs being
  complete and correct. That is the central risk of this decision.
- **The deny set is a denylist, and denylists are bypass-prone** — stated
  plainly in the OWASP sheet and accepted here. A denylist is not completeness;
  it is a floor.
- The block list is transcribed by hand into a `const` (step 2). A
  transcription error is a silent policy hole. Mitigation: step 3's one-test-
  per-row requirement, plus step 8's fuzz target.
- `.255` broadcast denial (row #22) can deny a legitimate host whose address
  ends in `.255`. Recoverable via `--allow-cidr`, but it is a real false
  positive, and `--allow-all-egress` does **not** lift it (it is a hard deny).
  This asymmetry is a deliberate complexity that deserves a second look.
- Raising `PER_SESSION_CAP` 16× increases the server's own exposure to
  resource pressure and to ephemeral-port exhaustion. Bounded, but real.
- Denials are silent to the client, so a misconfiguration presents as
  mysterious packet loss. Operational cost accepted deliberately for
  metadata-resistance and error-oracle reasons.
- Hand-maintained CIDR constants will drift as IANA updates the registries
  (the live IPv4 registry changed as recently as 2025-10-09,
  references §1.2). A periodic review obligation is created.
- D28 fixes the *forwarder*. It does not make the server safe as a general
  network path: no byte accounting, no rate limiting, and `THREAT_MODEL.md`
  §8 continues to place compromised endpoints out of scope. D28 narrows the
  pivot surface; it does not close it.

---

## Relationship to existing decisions

D28 **refines** D18 (application model) by adding a server-side egress policy
layer above the relay framing, and **shares surface with** D24 (data-path
failure budget) only in the sense that D24's gate is failure-only and D28
leaves it alone.

D28 **does not modify**: D13 (handshake construction), D12 (authentication),
D16 (rekey), D19 (cover scheduling), or D22 (metadata target).

D28 **structurally reinforces** D19's rule that cover/lifecycle policy is never
handshake state, by applying the identical discipline to egress policy and
never placing it in `HandshakeV2ServerConfig`.

D28 **preserves HNDL resistance and metadata resistance**: it changes neither
the wire format, the envelope, the key schedule, nor the cover scheduler. It
adds no per-destination signal to anything observable on the wire, and it
deliberately returns no feedback to the client, so it opens no new metadata
channel. It adds no assumptions. It does not weaken authentication — the
policy is applied strictly *after* AEAD decryption and session lookup succeed,
on a destination that only an established, roster-authenticated peer can
supply. It **does** increase the number of decisions an operator must make,
which is why §9 gates them to a human.

---

## Cross-references

- `pq-tunnel-bin/src/forward.rs` — the forwarding backend (D18), pool caps,
  `handle`, `prune_and_insert`, `reply_reader`.
- `pq-tunnel-bin/src/relay.rs` — relay framing, `decode_relay` port parsing
  (`relay.rs:111`, `relay.rs:124`).
- `pq-tunnel-bin/src/lib.rs:74-105` — `ServerArgs`, the override surface.
- `pq-tunnel-bin/src/v2_client.rs:76-87` — the D18 non-loopback bind
  protection that D28's loopback floor defends from the other side.
- `DESIGN_DECISIONS.md` D18, D19, D24 — application model, cover policy
  discipline, data-path failure budget.
- `THREAT_MODEL.md` §7.1 (bounded resources), §8 (out of scope) — where
  D28's residual gaps are recorded.
- `docs/design/references-1to1.md` — all external citations, each one fetched,
  with an explicit UNVERIFIED section.
