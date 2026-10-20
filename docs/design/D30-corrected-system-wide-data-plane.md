# D30 — Corrected System-Wide Data Plane: Both Ends of the Tunnel

**Status:** DESIGN PROPOSAL (supersedes the design content of
`docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md`, which is **not** accepted as written).
**Baseline:** `86cf7bd4871a86cea4565e475d87517cacc2ec1f` (read-only analysis).
**Scope:** redesign of the *data plane* (client TUN ↔ server egress) for a 1:1 system-wide
tunnel. No code is included or proposed as diff-ready; this is an implementation-ready
architecture.

All file/line references are to the baseline clone. External facts are marked
**[EXT]** and carry a primary-source URL; everything else is inference or a decision.

### Verification status — read before implementing

This document is a **design proposal produced by an automated analysis
against the `86cf7bd` baseline**. It is **not** a decision of record, it is
**not** in `DESIGN_DECISIONS.md`, and **no code implements it**. It replaces
the *design content* of `D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md`, which
contains statements that are known to be wrong (see the supersession note in
that document).

An independent integration review re-derived the **in-tree** claims against
the baseline and confirmed: the 1280-byte record sizing, the shared
`send_counter`, the 1024-counter replay window, the relay's single-slot
`MAX_DATAGRAM_V4 = 1236` ceiling, the absence of a production caller for
`ip_packet_len()`, and the false "1280 fits a 1280-MTU path" claim in
`pq-tunnel-core/src/codec.rs`.

The **external** claims (platform TUN behaviour, Windows firewall rule
precedence, Linux IPv6 MTU enforcement, and the cited RFC text) were **not**
independently re-verified against their primary sources in this wave. The RFC
quotes are attributed to specific sections and URLs so a reviewer can check
them; treat them as **cited, not checked**. The open questions in this
document are the parts that must be settled before any implementation starts.

**Do not implement from this document alone.** The gates in §14 (dependency
graph) and the unresolved questions must be closed first.

---

## 0. Hard facts that constrain the design (read this first)

| # | Fact | Evidence |
|---|---|---|
| F1 | Tunnel record = UDP payload = **1280 B**. Cleartext header = 17 B (version 1 ‖ sid 8 ‖ packet_nonce 8), which is also the AEAD AAD. Inner plaintext 1247 B = type(1) ‖ dir(1) ‖ payload(1245). | `pq-tunnel-core/src/codec.rs:104-152` |
| F2 | The 8-byte `packet_nonce` is **cleartext and strictly monotonic**, incremented once per emitted packet for *both* data and cover (one shared `send_counter`). | `codec.rs:42-50`; `envelope.rs:257-300` (single `send_counter`, `checked_add(1)`) |
| F3 | Replay window = **1024 counters** (`WINDOW_BITS`). A counter more than 1024 below the highest accepted is rejected. | `pq-tunnel-core/src/replay.rs:37`, `:88-140` |
| F4 | Cover is a **separate driver path** (a `tick()` deadline) at a user-tunable rate (`--cover-mbps`, `lib.rs:97-103`), default 2 Mbps = 5.12 ms/packet = 195.3125 pkt/s. | `scheduler.rs:36`, `:70-76`; `session_manager.rs` `cover_packet` / tick loop |
| F5 | The relay framing is `family(1)‖addr(4\|16)‖port(2)‖len(2)‖datagram`; only family `0x04`/`0x06` decode. Any other first byte → `RelayError::BadFamily`. The server forwarder **drops it silently**. | `pq-tunnel-bin/src/relay.rs:36-48`, `:103-145`; `pq-tunnel-bin/src/forward.rs:87-92` |
| F6 | `MAX_DATAGRAM_V4 = 1236 < PAYLOAD_LEN = 1245` — the relay framing is single-slot by construction and cannot carry a 1500-byte IP packet. | `relay.rs:41-48` |
| F7 | `ip_packet_len()` exists, is fuzz-covered, and has **no production caller**. It returns 0 for a non-IP buffer; it accepts IPv4 total ∈ [20, buf_len] and IPv6 total = 40+payload_len. | `pq-tunnel-bin/src/packet_len.rs:13-39` |
| F8 | The outer transport binds **one** address family (`0.0.0.0:0` or `[::]:0` from the remote) and is deliberately left *unconnected* so `set_peer` roaming works. | `pq-tunnel-core/src/udp.rs:97-106` |
| F9 | `PROTOCOL_VERSION = 1`, strict equality, no negotiation, no downgrade window. It is bound into the transcript bodies **and** the KDF `info` strings. | `codec.rs:82`, `:288-302`; `handshake_v2.rs:129-154`, `:782-795`; `pq-crypto/src/kdf.rs` (`"pq-tunnel-master-v2"‖VERSION‖SID‖TH3`, `"pq-tunnel-finished-v1"‖VERSION‖SID`) |
| F10 | The handshake's `FragmentAssembler` tolerates out-of-order and ignores duplicates, but `frag_total` is **pinned per message type** (4/5/1) and `frag_idx < frag_total` is structurally enforced. | `handshake_v2.rs:146-151`, `:259-265`, `:314-365`, `:414-477` |
| F11 | The identity file is written with `File::create` + `rename` and reserved with `create_new` — **no permission/ACL hardening** (default umask ⇒ typically world-readable secret seed on Unix). | `pq-tunnel-bin/src/identity.rs:279-325` |
| F12 | `SessionLimits::default()` = `max_sessions: 64`, `idle_timeout: 5 min`, `liveness_timeout: 30 s`, `handshake_timeout: 30 s`, `lifetime_cap: None`. | `session_manager.rs:136-148` |
| F13 | `ManagerEvent::Send { packets: Vec<WirePacket>, peer }` already exists (used for handshake fragments) — a multi-datagram burst channel is available without a new event type. | `session_manager.rs:184-193` |

### External facts (primary sources)

| # | Fact | Source |
|---|---|---|
| E1 | **RFC 8200 §4.5:** "unlike IPv4, fragmentation in IPv6 is performed only by source nodes, **not by routers** along a packet's delivery path". | https://www.rfc-editor.org/rfc/rfc8200.txt §4.5 |
| E2 | **RFC 8200 §5:** "IPv6 requires that every link in the Internet have an MTU of 1280 octets or greater. This is known as the IPv6 minimum link MTU." Configurable-MTU links "must be configured to have an MTU of at least 1280 octets". A node "must be able to accept a fragmented packet that, after reassembly, is as large as 1500 octets". | https://www.rfc-editor.org/rfc/rfc8200.txt §5 |
| E3 | **RFC 8200 §4.5:** IPv6 fragment reassembly must be abandoned if incomplete "within 60 seconds of the reception of the first-arriving fragment". | https://www.rfc-editor.org/rfc/rfc8200.txt §4.5 |
| E4 | **RFC 8201 App. A:** "there is no DF bit in IPv6 packets". §4: a node "must not reduce its estimate of the Path MTU below the IPv6 minimum link MTU". §1: if ICMPv6 PTB is blocked → "black-hole connection". | https://www.rfc-editor.org/rfc/rfc8201.txt |
| E5 | **RFC 791 §3.1:** IPv4 "Total Length" = length of the datagram including header, max 65 535; DF bit (bit 1 of Flags) = "Don't Fragment". §3.2: a router "MUST silently discard a packet if the interface on which the packet was received is not the interface on which a packet would be forwarded to reach the address contained in the source address" (RFC 1812 §5.3.8 wording). | https://www.rfc-editor.org/rfc/rfc791.txt ; https://www.rfc-editor.org/rfc/rfc1812.txt §5.3.8 |
| E6 | **Linux kernel `include/uapi/linux/ipv6.h`:** `#define IPV6_MIN_MTU 1280`. | https://github.com/torvalds/linux/blob/master/include/uapi/linux/ipv6.h |
| E7 | **Linux kernel `net/ipv6/addrconf.c`:** `ipv6_add_dev()` → `if (dev->mtu < IPV6_MIN_MTU && dev != blackhole_netdev) return ERR_PTR(-EINVAL);` and the `NETDEV_CHANGEMTU` / `NETDEV_UP` notifier paths → `/* if MTU under IPV6_MIN_MTU stop IPv6 on this interface. */ if (dev->mtu < IPV6_MIN_MTU) { addrconf_ifdown(dev, ...); break; }`. **Consequence: on Linux an IPv6-capable interface cannot have MTU < 1280; lowering it disables IPv6 on the interface.** | https://github.com/torvalds/linux/blob/master/net/ipv6/addrconf.c (lines ~385, ~3692-3696, ~3799-3803) |
| E8 | **`ip-rule(8)`:** the RPDB is scanned in order of increasing priority number (lower = higher priority) and the **first matching rule terminates the lookup**. `iif`/`oif`/`not from`/`fwmark`/`table`/`blackhole`/`unreachable`/`prohibit` selectors/actions exist. | https://man7.org/linux/man-pages/man8/ip-rule.8.html |
| E9 | **`ip-route(8)`:** route types `unicast|unreachable|blackhole|throw|prohibit|local|broadcast|multicast|nat`; `blackhole` = "Packets are discarded silently. The local senders get an EINVAL error." `ip route add ... mtu lock <N>` disables PMTU discovery. | https://man7.org/linux/man-pages/man8/ip-route.8.html |
| E10 | **Upstream `wg-quick` (linux.bash) `add_default()`:** `ip rule add not fwmark $table table $table` ; `ip rule add table main suppress_prefixlength 0` ; `ip route add "$1" dev "$INTERFACE" table $table` ; the outer UDP packets are marked by an nftables/iptables CONNMARK rule (`-m mark --mark $table -p udp -j CONNMARK --save-mark`). **No source-address selector is used.** | https://git.zx2c4.com/wireguard-tools/plain/src/wg-quick/linux.bash |
| E11 | **Windows `New-NetRoute`:** there is **no route-type parameter** — the accepted values are `DestinationPrefix`, `InterfaceAlias|InterfaceIndex`, `NextHop`, `RouteMetric`, `PolicyStore`, `Publish`, `Protocol` (Bbn/Bgp/Dhcp/…/Local/NetMgmt/Other), lifetimes. `NextHop 0.0.0.0` means "on the local subnet". **There is no `blackhole` route type on Windows.** | https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute |
| E12 | **Windows Firewall rule precedence:** "1. Explicitly defined allow rules take precedence over the default block setting. 2. **Explicit block rules take precedence over any conflicting allow rules.** 3. More specific rules take precedence over less specific rules, *except* if there are explicit block rules." Outbound rules follow the same precedence. | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules |
| E13 | **Wintun 0.14.1** is a signed L3 TUN driver for Windows, distributed as `wintun.dll`; integration is by including the DLL. | https://www.wintun.net/ ; https://git.zx2c4.com/wintun/ |
| E14 | **`tun` crate 0.8.14** (current), edition 2024, **no declared `rust-version`**, deps `nix 0.31`, `windows-sys 0.61`, `wintun-bindings 0.7.39`. `Configuration` exposes a **single** `address`/`netmask`/`destination`/`broadcast` plus `mtu`, `up`, `platform_config`; it installs **no routes**. | https://docs.rs/tun/0.8.14/tun/ ; https://crates.io/api/v1/crates/tun/0.8.14 |
| E15 | **RFC 1812 §5.3.8** (source address validation) and **RFC 2827 / BCP 38** (ingress filtering) are the normative references for router-side source-address validation. | https://www.rfc-editor.org/rfc/rfc1812.txt ; https://www.rfc-editor.org/rfc/rfc2827.txt |

---

## 1. The two structural findings that invalidate the existing draft

### 1.1 A 1280-byte IPv6 packet can **never** fit in one Tunnel record

The record's IP-carrying capacity is `PAYLOAD_LEN` = 1245 B, minus the overlay header
(§3.3 below) = **1231 B**. The IPv6 minimum link MTU is **1280 B** (E2), and Linux
*enforces* that: an interface with MTU < 1280 cannot have IPv6 at all (E7).

Therefore, with a conformant TUN MTU of 1280:

* every minimum-MTU IPv6 packet costs **2 slots**;
* every full-MSS IPv4 packet at MTU 1280 (IP packet = 1280 B) also costs **2 slots**;
* tunnel efficiency for a 1280-byte IP packet is 1280 / 2560 = **50 %**.

The draft's recommendation of a 1241-byte TUN MTU (§1.2) would give 1 slot per packet —
but it is **non-conformant** (E2) and **operationally impossible for IPv6 on Linux** (E7):
the kernel disables IPv6 on the interface. The draft's own §1.8 rule ("refuse to come up as
a v4-only tunnel") therefore contradicts its own MTU recommendation. This is a hard
trade-off, not a tunable: *conformant IPv6 ⟹ MTU ≥ 1280 ⟹ 2 slots per minimum-MTU packet.*

The alternative — growing `PACKET_SIZE` so one record can hold a 1280-byte IP packet —
is a wire-format change (see §9) and worsens the outer PMTU problem (§7).

### 1.2 The outer path must have PMTU ≥ 1328 B, and the codec's documentation is wrong

Outer IP packet = 20 (IPv4) or 40 (IPv6) + 8 (UDP) + 1280 (record) =
**1308 B (IPv4 outer)** / **1328 B (IPv6 outer)**.

* On a 1500-byte link MTU: fits (1472/1452 bytes of UDP payload available).
* On a 1280-byte link MTU: **does not fit**, in either family.
  * IPv4: the router would have to fragment (or drop + ICMP frag-needed).
  * IPv6: routers **never** fragment (E1); the packet is dropped + ICMPv6 PTB.

`codec.rs:94-98` claims the 1280-byte record "fits a standard IPv4/IPv6 MTU (1500 / 1280)".
**That is false for the 1280 case.** The record imposes a hard minimum path MTU of
1328 B (IPv6 outer) / 1308 B (IPv4 outer). PROTOCOL_SPEC §7.5 ("SHOULD avoid depending
on … specific MTU sizes") is therefore *not* satisfied by the current record — a constant
record size is still a path-MTU assumption. This must be recorded as an explicit residual,
and the codec doc comment corrected.

---

## 2. Server-side raw-IP path (task 1)

### 2.1 Options

| Option | Mechanism | Verdict |
|---|---|---|
| **(a) Server runs a TUN + kernel IP forwarding + stateful NAT** | The client's inner IP packets are written into the server's TUN; the server kernel routes them out its physical NIC; replies come back through the TUN. Requires `ip_forward`/`forwarding`, a NAT, and a source-address check. | **RECOMMENDED.** Only option that preserves real IP semantics end-to-end (ICMP, TCP, the client's own source addresses) and keeps the server stateless per flow. |
| (b) Client wraps raw IP into a socket-like frame | The client re-frames raw IP as `family/addr/port/len` for the existing forwarder. | **REJECTED.** The frame has no IP header, no protocol field, no notion of the IP packet's own length, and a 1236-byte cap (F6). It reintroduces per-destination socket state and per-destination NAT, i.e. it is the *old* product model. A 1500-byte IP packet is unrepresentable. |
| (c) Server forwards via raw sockets / a userspace forwarder | The server crafts reply IP headers itself (`IP_HDRINCL`). | **REJECTED for v1.** Re-implements the IP stack: routing, fragmentation, checksum offload, neighbour discovery, path MTU — a large new attack surface. On Windows, `IP_HDRINCL` raw sockets cannot carry IPv6 and require admin. Keep as a documented fallback only for platforms that cannot do forwarding (a container without `NET_ADMIN`, Windows without the routing stack). |

### 2.2 Recommended server topology (1:1)

```
  client host                                   server host
 ┌───────────────────────────┐                ┌──────────────────────────────┐
 │  pqtun0  10.77.0.2/32     │                │  pqtun0  10.77.0.1/32       │
 │           fd00:77::2/128  │   Tunnel       │           fd00:77::1/128     │
 │  default 0.0.0.0/0 → tun  │ ──UDP/1280──▶ │  ip_forward=1 ; NAT          │
 │  default ::/0      → tun  │ ◀─UDP/1280──  │  egress: eth0 (default route)│
 └───────────────────────────┘                └──────────────────────────────┘
        outer socket: bound to the physical interface, source = physical IP
```

Server-side mandatory controls, applied **in the tunnel server's code, before the packet
is written into the server's TUN** (never delegated to the kernel, which cannot know the
client↔address mapping):

1. **Source-address validation (mandatory; new requirement with no analogue in the socket model).**
   The inner source address MUST equal the client's assigned address
   (`10.77.0.2` / `fd00:77::2`) — or lie inside the client's assigned prefix if a prefix
   is used. Any other source is **silently dropped**. Rationale: in the socket model the
   source is the *server's own* ephemeral IP, so there is nothing for the client to
   spoof; in a raw-IP path the client chooses the source of every packet, so the server
   becomes a reflection/amplification gadget and a pivot into RFC 1918 space otherwise
   (RFC 1812 §5.3.8, RFC 2827/BCP 38 — E5/E15).
   *Kernel-side belt-and-braces:* `net.ipv4.conf.<tun>.rp_filter=1` and an nftables
   rule `-i <tun> -s <client-addr> -j accept; -i <tun> -j drop`.
2. **Destination policy (mandatory).** The D28 CIDR table
   (`docs/design/D28-server-egress-policy-1to1.md` §1.1) applied to the **inner IP
   destination**, evaluated *before* the write. This preserves D28's hard floor
   (127.0.0.0/8, ::1/128, 0.0.0.0/8, ::/128, 169.254.0.0/16 — cloud metadata —,
   fe80::/10, multicast, broadcast) and prevents the SSRF/IMDS and loopback-compromise
   classes D28 identified. In the raw-IP path this control is *more* load-bearing than in
   the socket path, because the server's own kernel will otherwise happily route to its
   own link-local metadata service.
3. **L4 port-0 rejection** (D28 §2) — requires parsing the TCP/UDP header of the inner
   packet.
4. **IP-level fragment rejection (mandatory, new).** An inner IPv4 packet with MF=1 or a
   non-zero fragment offset, or an inner IPv6 packet carrying a Fragment header (next
   header 44), MUST be dropped. The tunnel performs its own fragmentation; carrying
   IP-level fragments into the server's kernel would create a second, conflicting
   reassembly layer.
5. **Stateful NAT** on the server, so the reply's source is restored to the original
   destination (plain SNAT alone would break the client's TCP checks).
   * Linux: nftables `nat` chain, `masquerade` on the tun→physical path.
   * Windows: `New-NetNat -InternalIPInterfaceAddressPrefix 10.77.0.1/32`.
   * Operator alternative: routed assignment (no NAT) where the operator owns prefix
     space — an explicit deployment choice, not a default.

### 2.3 Server session limits for 1:1

`SessionLimits::default().max_sessions = 64` (F12) is wrong for a 1:1 deployment: it is
a multi-tenant capacity number and it also multiplies the per-session socket/state caps.
A 1:1 server MUST run with `max_sessions = 1`; a second client MUST be refused (and the
refusal MUST be a *loud local* failure, never a silent drop — this is a capacity decision,
not peer-input failure).

---

## 3. In-slot message formats and dispatch (task 2)

### 3.1 The dispatch must be a `MessageType`, not an in-band payload byte

Today `MessageType` has four values (0x00 Handshake, 0x01 Data, 0x02 Cover, 0x03 Close),
all inside the AEAD plaintext; the handshake fragments are dispatched by **byte 9 of the
cleartext header** (0x10/0x20/0x30), which is disjoint (F9, `handshake_v2.rs:26-34`).

The draft proposes to distinguish the TUN overlay from the legacy relay frame by an
in-band `hdr_ver` byte at `payload[0]`. **That is exactly the silent interop failure
named in the brief**: a legacy server decoding an overlay payload sees `payload[0] = 0x01`
→ `RelayError::BadFamily` → `forward.rs` drops it **silently** (F5). The client would
have an established session, an installed default route, and no data — an opaque black
hole.

**Decision: add a `MessageType`.**

```
MessageType::TunData = 0x04
```

* `0x04` is byte-disjoint from the codec types (0x00-0x03) and from the handshake
  fragment types (0x10/0x20/0x30). It is in a **different namespace** from the relay
  `family` byte (0x04/0x06) — that is a documentation hazard, so the enum doc must say
  so explicitly, and a compile-time assertion should pin that the *relay* namespace is
  only ever read from a `MessageType::Data` payload.
* `MessageType::Data` (0x01) keeps its current meaning (the legacy D18 relay frame) so
  the existing relay client/server, the conformance harness and `pq-proxy` remain usable
  as a diagnostic path.
* `MessageType::TunData` carries the overlay of §3.3. `Direction` is already separate and
  already per-direction keyed, so **one** new message type suffices for both directions.
* No new *control* message type is needed: the address assignment, the MTU and the
  tunnelled-link parameters are **deployment-local configuration** on a 1:1 link
  (consistent with D19: nothing about the data plane is negotiated).

### 3.2 What a peer does with an unknown `MessageType`

`InnerPlaintext::decode` → `MessageType::from_u8` → `CodecError::InvalidMessageType`
(`codec.rs:201-209`) → the envelope returns a uniform `DecryptionFailed` → the packet is
dropped (PROTOCOL_SPEC §14). A v1 peer therefore drops a v2 `TunData` packet silently.
**That is exactly why the version must also be bumped** (§9): with `PROTOCOL_VERSION = 2`
the v1 peer rejects at the *header* version check, and — critically — the **handshake
fails**, so the client never reaches "established but dead".

### 3.3 The TUN overlay (the in-slot format)

Inside `InnerPlaintext.payload` (1245 B) for `MessageType::TunData`:

```
 offset  size  field            semantics
 ------  ----  ---------------  ---------------------------------------------
   0      1    overlay_version  = 0x01 (MUST be 1; other values → drop)
   1      1    frag_index       0-based index of this fragment, 0 ≤ idx < count
   2      1    frag_count       total fragments for this IP packet, 1 ≤ count ≤ 54
   3      1    reserved         MUST be 0 (bits 1..7 reserved, MUST be 0)
   4      2    ip_total_len     BE u16: total length of the *reassembled* IP packet
   6      4    datagram_id      BE u32: per-direction monotonic datagram identity
  10      4    datagram_tag     BE u32: consistency tag over fragment 0 (§3.4)
  14   1231    ip_fragment      this fragment's slice of the IP packet
```

Derived constants (compile-time asserted):

```
PAYLOAD_LEN         = 1245                       (codec.rs:139)
OVERLAY_HEADER_LEN  = 14
FRAG_CAP            = PAYLOAD_LEN - OVERLAY_HEADER_LEN = 1231
MAX_IP_PACKET_LEN   = 65535                      (§3.5)
MAX_FRAG_COUNT      = ceil(65535 / 1231) = 54
```

`ip_total_len` is 16-bit, so `MAX_IP_PACKET_LEN` is 65535 — the IPv4 maximum total length.
An IPv6 packet whose *total* exceeds 65535 (i.e. an IPv6 payload length > 65495) is
**rejected as unsupported**. This is a deliberate, documented limit: it is a 40-byte
window at the very top of the IPv6 length space, unreachable on any real path, and it
buys a single uniform 16-bit length field for both families. (RFC 8200 §5 requires a node
to accept a reassembled packet of at least 1500 B — 65535 ≫ 1500, so E2 is satisfied.)

---

## 4. Fragmentation / reassembly: the exact rules (tasks 3-6)

### 4.1 Identity: a per-direction `datagram_id`, independent of the AEAD counter

**Decision: `datagram_id` is an independent, per-direction, monotonically increasing u32.
It is NOT derived from, and MUST NOT be inferred from, the AEAD `packet_nonce`.**

Why the draft's scheme ("reassembly key = (session_id, packet_nonce-of-FIRST, direction)",
draft §1.1) is wrong, on four independent counts:

1. **Cover interleaves.** Cover is a separate driver path (F4) and data and cover share
   one `send_counter` (F2). Nothing in the code prevents a cover packet from being
   emitted between fragment *k* and fragment *k+1* of one IP packet.
2. **Concurrency interleaves.** Nothing serialises the fragments of one IP packet
   against another IP packet's fragments; the TUN reader is a stream.
3. **The receiver cannot compute the key.** The key is "the counter of the FIRST
   fragment", but a receiver that sees fragment 3 first has no way to know the counter of
   fragment 0.
4. **It couples the data plane to the cover schedule**, which D19 forbids as a
   *negotiated* concern and which is a user-tunable knob.

`datagram_id` is instead allocated by the **sender** from a per-direction u32 counter that
increments once per IP packet. It is opaque to the receiver.

### 4.2 Fragment grouping

* Sender: one IP packet → `frag_count = ceil(ip_total_len / FRAG_CAP)` fragments.
  Fragment *i* carries bytes `[i*FRAG_CAP, min((i+1)*FRAG_CAP, ip_total_len))`.
  All fragments except the last carry exactly `FRAG_CAP` bytes; the last carries
  `ip_total_len - (frag_count-1)*FRAG_CAP` bytes ∈ [1, FRAG_CAP].
  **The fragment length is therefore fully derivable** — no extra length field is needed.
* Receiver: the reassembly key is `(session, direction, datagram_id)`. The entry stores
  `frag_count`, `ip_total_len`, a received-bitmap, a byte buffer of exactly
  `ip_total_len` bytes, and a deadline.
* The `datagram_tag` (4 B) is the first 32 bits of SHA-256 over **fragment 0's bytes**
  (the IP header + the first `FRAG_CAP` bytes). Every fragment of a datagram carries the
  same tag. It is a **consistency check, not a security boundary** (the security boundary
  is the AEAD); it exists so that a datagram assembled from fragments of *two different*
  IP packets is *detected* rather than silently written to the OS stack. SHA-256 is
  already a dependency (`pq-crypto`); no new primitive is introduced.

### 4.3 Sender serialisation: required, and for a different reason than the draft gives

**Rule S1 (burst serialisation).** The fragments of one IP packet MUST be emitted as a
**contiguous burst**: no other *data* datagram may be emitted between them. Cover packets
MAY be emitted between them (D19's cover grid is not negotiable and is not a data-plane
concern).

**Rule S2 (replay-window span check).** Before emitting each fragment, the sender MUST
check that the AEAD counter distance from the *first* fragment of this burst to the
current fragment is `< REPLAY_WINDOW_BITS` (1024, F3). If the check fails, the sender
**aborts the burst and drops the whole IP packet** (fail-secure, silent). Rationale: the
receiver's replay window rejects any counter more than 1024 below the highest accepted, so
a fragment outside that horizon could never be reassembled regardless of any timeout.
The sender owns the counter, so this check is exact and free.

**Rule S3 (no interleaved cover stall).** The burst must be emitted without yielding to
the cover tick in a way that lets more than one cover deadline pass. The existing
`CoverScheduler::on_deadline` semantics ("at most one emission per deadline, reschedule
from now", `scheduler.rs:133-147`) already provide the required behaviour: if a cover
deadline passed during the burst, exactly one catch-up cover packet is emitted
afterwards. No D19 change is required.

**Rule S4 (id non-reuse).** `datagram_id` MUST NOT wrap within a session. On exhaustion
(the u32 counter reaching 2³²) the session transitions to rekey, exactly like the
existing `CloseReason::NonceExhausted` path (`session_manager.rs:163`, `wire_session.rs:222-226`).
At the default cover rate this is unreachable; at a 10⁵ pkt/s burst rate it is ~12 h,
which is why the rekey (not an id wrap) is the correct mechanism.

### 4.4 Receiver rules: out-of-order, duplicate, missing, replayed

Let `E` be the entry for `(session, direction, datagram_id)`, if it exists.

| Situation | Rule |
|---|---|
| **New datagram** (no `E`) | Validate the fragment header (§4.5). Create `E` with `frag_count`, `ip_total_len`, an empty bitmap, a buffer of exactly `ip_total_len` bytes, and a deadline. Accept the fragment. If `frag_index == 0`, immediately perform the IP-header validation of §4.6 (eagerly, so a bad datagram is killed at once). |
| **Out-of-order** (a later fragment arrives first) | Accepted. `E` is created by that fragment; the IP-header check is deferred until fragment 0 arrives. Completion requires fragment 0. **No packet is ever written without fragment 0.** |
| **Duplicate** (`frag_index` already filled, identical bytes) | **Ignored** (no state change), counted in a metric. |
| **Duplicate** (`frag_index` already filled, *different* bytes) | **Poison** `E`: `E` is marked dead, nothing is ever written for this `datagram_id`, and the entry is dropped at its deadline. The new fragment is discarded. Fail-secure. |
| **`frag_count` or `ip_total_len` mismatch** against `E` | **Collision** (id reuse) → **poison** `E`, discard the new fragment, do **not** create a new entry for this id. Fail-secure. |
| **Poisoned `E`** | Every subsequent fragment for that id is discarded. |
| **Missing fragment** | The entry is dropped at its deadline; **nothing is written**. There is no NAK and no retransmission (see §4.7). |
| **Replayed fragment** | Never reaches this layer: the AEAD replay window (F3) rejects a repeated counter before the plaintext is produced. A *duplicate at the overlay layer* with a *new* counter is the "Duplicate" row above. |
| **Fragment for an `ip_total_len` that disagrees with the assembled IP header** | Poison; see §4.6. |

**Completion.** When all `frag_count` indices are present:
1. fragment 0 must be present and its IP header valid (§4.6);
2. the assembled length must be exactly `ip_total_len`;
3. the last fragment's length must be exactly `ip_total_len - (frag_count-1)*FRAG_CAP`
   and every other fragment's length exactly `FRAG_CAP`;
4. only then is the buffer written to the TUN — **as a single write of exactly
   `ip_total_len` bytes**.

**The TUN writer only ever receives a complete, validated buffer.** There is no path by
which a partial or corrupt IP packet reaches the OS stack.

### 4.5 Fragment-header validation (on every fragment, before any allocation)

```
overlay_version == 1
1 ≤ frag_count ≤ MAX_FRAG_COUNT (54)
0 ≤ frag_index  < frag_count
reserved == 0
20 ≤ ip_total_len ≤ MAX_IP_PACKET_LEN (65535)
(frag_count - 1) * FRAG_CAP  <  ip_total_len  ≤  frag_count * FRAG_CAP
```

The last line is the **exact inequality** that ties the fragment count to the packet
length: `frag_count == ceil(ip_total_len / FRAG_CAP)`. A violation is a protocol
violation → drop the fragment; if the datagram entry exists, poison it.

`ip_total_len` is validated **before** the buffer is allocated, so the allocation size is
always known and bounded.

### 4.6 IP-header length vs fragment count: the authoritative rule

**The IP header is authoritative. The overlay's `ip_total_len` and `frag_count` are
cross-checks against it — never the other way round.**

This is the opposite of the draft's §1.7 claim that `frag_total` "is more trustworthy than
parsing a length field out of a header, because it is authenticated rather than merely
structurally validated". That is inverted: the *host's* TCP/IP stack honours the IP
header's total-length field. A reassembled buffer whose length disagrees with its own IP
header is corrupt, and writing it to the TUN would inject a malformed packet into the
host's IP stack.

The final consistency check, applied to the **assembled** buffer:

```
L = the length declared by the assembled IP header
    IPv4: bytes 2..4, big-endian "Total Length"   (RFC 791 §3.1, includes the header)
    IPv6: 40 + bytes 4..6, big-endian "Payload Length" (RFC 8200 §3)
```

All of the following MUST hold, or the datagram is poisoned and **nothing is written**:

* **C1** `L == ip_total_len` (the header and the overlay agree exactly).
* **C2** `L ≥ 20` (IPv4) or `L ≥ 40` (IPv6).
* **C3** IPv4 structural validity: version nibble = 4, IHL ≥ 5, and `4*IHL ≤ L`.
* **C4** IPv6 structural validity: version nibble = 6.
* **C5** `frag_count == ceil(L / FRAG_CAP)` — the *same* inequality as §4.5, now checked
  against the header-derived length. This is the required cross-check between the
  fragment count and the IP header.
* **C6** the *first* fragment alone must contain the whole IP header: the header length
  (`4*IHL` for IPv4, 40 for IPv6) must be ≤ `FRAG_CAP` (1231) — always true — and the
  header must lie entirely within fragment 0.

**Zero-length and header-less datagrams.**

* `ip_total_len == 0` → rejected by §4.5 (`≥ 20`) → the fragment is dropped; if an entry
  exists it is poisoned. **A zero-length IP packet is never written.**
* A datagram whose fragment 0 does not begin with a plausible IP header (version nibble
  ∉ {4, 6}, or a truncated header) → rejected by C2/C3/C4 → poisoned. **A header-less
  datagram is never written.**
* A *legitimate* minimal IP packet is fine: an IPv4 packet with total length exactly 20
  (header only) and an IPv6 packet with payload length 0 (total 40) both satisfy C1-C5
  with `ip_total_len` = 20 / 40 respectively. Note the existing `ip_packet_len()` already
  accepts both (it rejects `total < 20` for IPv4 and `total < 40` for IPv6 — F7), so it
  can be retained as a **redundant** cross-check on the assembled buffer; it must not be
  the *only* check, because it does not validate IHL or the version-specific minimum.

### 4.7 No tunnel-layer retransmission — and its cost, stated

There is no NAK and no retransmission. Rationale: a NAK is a *new observable* (a hole in
the packet stream), and D22 fixes the metadata target as leakage *reduction*, with traffic
absorption explicitly rejected for v1. The cost must be documented rather than hidden:

* **Loss amplification.** An IP packet split across *N* slots is lost if *any* slot is
  lost. At a path loss rate *p*, an *N*-slot datagram is lost with probability
  ≈ *N·p*. For a 1280-byte IP packet (N = 2) at *p* = 0.1 %, that is ~0.2 % — a 2×
  amplification of the effective loss rate, which TCP then has to repair at the
  application layer. This is the price of a 1280-byte carrier and must appear in
  `THREAT_MODEL.md` and in the operator's expectations.
* **Mitigation by MTU choice:** a TUN MTU of 1231 would make a full-MSS packet a single
  slot, but it is non-conformant (E2) and impossible for IPv6 on Linux (E7). The
  amplification is therefore accepted, not designed away, in v1.

### 4.8 Bounded reassembly (task 7)

| Bound | Value | Justification |
|---|---|---|
| Entries per session | **256** | 1:1 ⇒ 1 session. 256 concurrent in-flight datagrams is far above the in-flight count at any realistic rate (see the timeout note below). |
| Bytes per entry | exactly `ip_total_len` (≤ 65 535) | allocated only after `ip_total_len` is validated; no over-allocation. |
| Bytes per session (process-global; 1:1 ⇒ the same cap) | **16 MiB** | 256 × 65 535 = 16 776 960 B = 16.0 MiB exactly, so the byte cap binds at the same point as the entry cap in the worst case, and binds far earlier in the realistic case (a 1280-byte datagram costs 1231 B, so 16 MiB holds ~13 600 datagrams). |
| Entries per **process** | 16 MiB total, i.e. one global byte counter across all sessions | a process-global byte cap, not only a per-entry cap. |

**Timeout.** The reassembly deadline is an **implementation parameter (D7) derived from a
latency budget**. It is **NEVER** derived from `--cover-mbps` (the draft's §1.5 value of
"2 × cover interval" is wrong *and* dangerous — see §11 W6).

Derivation and recommended value:

* **What the deadline actually bounds.** The fragments of a datagram are emitted as one
  burst (Rule S1), so their arrival spread is the path's *reordering/jitter* spread, not
  the RTT. The deadline must exceed the worst-case reordering delay of the target path
  and must be short enough to release memory promptly.
* **Upper bound from the precedents.** RFC 791/RFC 8200 §4.5 use 60 s for IP-level
  fragment reassembly (E3). The tunnel's deadline must be **stricter** than that (the host
  stack's timer is the outer safety net; the tunnel must not hold a datagram longer).
* **Effective ceiling from the replay window.** The receiver's replay window is 1024
  counters (F3). At the cover floor alone (195.3125 pkt/s, F4) 1024 packets span
  **5.24 s**; at 10 Mbit/s of tunnel payload (9 765 pkt/s) they span **105 ms**. So the
  *effective* deadline is `min(configured, replay-window horizon)`. A configured deadline
  longer than the replay horizon is not "safer" — it is meaningless, because the late
  fragment will be rejected by the replay window anyway and the datagram is lost.
* **Recommended default: 2 s** (implementation parameter, D7). It is ≥ 100× any observed
  reordering delay, is far stricter than the 60 s IP precedent, and bounds the in-flight
  memory at (tunnel byte rate) × 2 s — which the 16 MiB cap then clamps. It is a
  *default*, not a derived constant: see unresolved question **Q1**.

**Cleanup.** The deadline is enforced by the session manager's existing `tick()`
(`session_manager.rs` tick/eviction path), so no new timer machinery is needed. Expired
entries are dropped and their buffers zeroized. A session close drops the whole table.

---

## 5. Bounds summary and the "zero-length" edge case

```
MAX_FRAG_COUNT  = 54         (ceil(65535 / 1231))
FRAG_CAP        = 1231
OVERLAY_HEADER_LEN = 14
MAX_IP_PACKET_LEN   = 65535
```

At a 1280-byte TUN MTU: `ceil(1280 / 1231) = 2` slots per minimum-MTU packet.
At a 1231-byte TUN MTU (non-conformant for IPv6, Linux-forbidden): 1 slot.
At a 1500-byte TUN MTU: `ceil(1500 / 1231) = 2` slots.

---

## 6. DNS, leak prevention and fail-secure behaviour (task 13)

1. **The inner plane is dual-stack; the outer plane is single-family.** The outer
   transport binds v4 **or** v6 (F8). That is fine: the inner plane carries both IPv4
   and IPv6 IP packets over whichever outer family is configured (6-in-4 / 4-in-6). A
   v4 outer does **not** cause an IPv6 leak, provided the TUN captures IPv6.
2. **Leak prevention is a routing property, not a socket property.** The TUN must have
   BOTH a v4 and a v6 address AND both `0.0.0.0/0` and `::/0` default routes. If either
   the v6 address or the `::/0` route cannot be installed, **the client MUST refuse to
   come up** — a v4-only "full-system" tunnel is an insecure default (the draft's §1.8
   rule is correct and is retained).
3. **`--no-ipv6` is an explicit, loud, documented reduction** — the startup banner must
   say "IPv4 only; IPv6 traffic is NOT tunnelled", never "tunnel up".
4. **DNS must be routed into the tunnel and the reconfiguration must be fail-secure.**
   The OS resolver is pointed at an address inside the tunnelled path. If the resolver
   reconfiguration **fails**, the tunnel MUST NOT come up (or must tear down completely):
   leaving the system resolver pointing at the ISP leaks DNS even when the data plane is
   perfectly tunnelled. Partial reconfiguration must be rolled back before the failure is
   reported.
   * Windows: per-interface DNS via `Set-DnsClientServerAddress` / `GetAdaptersAddresses`
     (`FirstDnsServerAddress`); journal the prior value and restore it.
   * Linux: `resolvectl`/`systemd-resolved` preferred; `/etc/resolv.conf` only with an
     explicit opt-in **and** a backup/restore.
5. **Documented residuals** (not mitigations): per-application DoH (Chrome), NSS/mDNS, and
   DNS volume as a browsing fingerprint. The draft's §1.13 point about DNS volume being a
   qualitatively stronger signal than the relay's per-destination volume is correct and
   should be carried into `THREAT_MODEL.md`.

---

## 7. MTU, PMTU and the DF decision (tasks 8, 9)

### 7.1 The tunnelled link vs the carrier link

* **Carrier link (the tunnel's physical carrier):** 1231 B of IP payload per 1280-byte
  record. One record is one UDP datagram.
* **Tunnelled link (what the endpoints' IP stacks see):** the TUN interface MTU, which
  MUST be ≥ 1280 (E2, E7) and SHOULD be equal on both ends.

The tunnel is therefore a **fragmenting link**: the tunnelled link MTU (1280) exceeds the
carrier's per-record capacity (1231). This is a legitimate design (the carrier is a
private sub-link, not an Internet link), but it MUST be documented: the tunnel's overlay
fragmentation is a **private mechanism and is NOT RFC 8200 fragmentation**. The tunnel
MUST NOT emit IPv6 Fragment headers and MUST NOT rely on any router fragmenting.

### 7.2 Recommended TUN MTU

* **Default: 1280** — the IPv6 minimum link MTU (E2), the value Linux enforces (E7), and
  the smallest conformant value (⇒ fewest slots).
* Allow 1500 as an operator option (both ends must agree; the tunnelled link MTU is
  `min(client, server)`). 1500 still costs 2 slots per full-MSS packet.
* The MTU is a **local, per-side parameter** and is never negotiated (PROTOCOL_SPEC §7.5,
  D19). The two sides must be configured consistently by the operator; a mismatch is
  detectable (packets larger than the smaller MTU are dropped by the smaller side).

### 7.3 The outer path: requirement and DF decision

* **Requirement: the outer path must have PMTU ≥ 1328 B (IPv6 outer) or ≥ 1308 B
  (IPv4 outer).** A 1280-byte-MTU path is **not** sufficient in either family.
* **DF decision: set DF on the outer transport.**
  * Linux: `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (sets DF and enables the kernel PMTU cache).
  * Windows: `IP_DONTFRAGMENT` (sets DF).
  * IPv6 outer: DF is implicit — IPv6 has no DF bit and routers never fragment (E1, E4).
  Rationale:
  1. IPv6 makes router fragmentation impossible, so the behaviour must be identical
     across families; letting the IPv4 outer fragment while the IPv6 outer cannot is an
     inconsistency that produces family-dependent metadata (the number of packets on the
     wire).
  2. Router-level fragmentation of the outer packet would multiply the observable packet
     count and create path state — both are metadata changes the design should not make
     implicitly.
  3. With DF set, an under-MTU path fails *loudly* at the socket (`EMSGSIZE` /
     `WSAEMSGSIZE`) instead of silently.
* **Startup gate (mandatory):** the outer transport's first sends must be checked for
  `EMSGSIZE`. A path-MTU failure at startup MUST abort the client's come-up with a
  clear "path MTU too small (need ≥ 1328 B)" message. Silent degradation is forbidden.
  (Windows' exact error surface is an open question — **Q5**.)
* **The codec's doc comment (`codec.rs:94-98`) must be corrected** to state the true
  outer sizes and the ≥1328/≥1308 requirement, and `PROTOCOL_SPEC.md` must record the
  path-MTU assumption explicitly (it is a residual against §7.5's "SHOULD avoid
  depending on … specific MTU sizes").

---

## 8. Routing, kill switch, privileges and lifecycle (tasks 10-12)

### 8.1 Linux — the correct formulation (the draft's rule loops)

**The draft's rule `ip rule add not from <tun-addr> lookup 100` creates exactly the loop
it claims to prevent.** The tunnel's outer socket sources its packets from the *physical*
interface's address, which is "not from \<tun-addr\>", so the rule **matches** the
tunnel's own outer traffic, looks it up in table 100, and finds `default dev pqtun0` —
the outer packet is written into the TUN and re-encapsulated. Loop.

The correct formulation uses a **destination** exception, not a source one, and therefore
cannot loop:

```sh
# 1. the tunnel device and its addresses (point-to-point: /32 and /128)
ip link set dev pqtun0 up
ip addr add 10.77.0.2/32   dev pqtun0
ip -6 addr add fd00:77::2/128 dev pqtun0

# 2. the BYPASS: a /32 (or /128) host route to the tunnel server via the physical NIC,
#    in the MAIN table. Installed BEFORE the default route.
ip route  replace <SERVER_V4>/32  dev eth0
ip -6 route replace <SERVER_V6>/128 dev eth0

# 3. the tunnel table
ip route  add default dev pqtun0 table 100
ip -6 route add default dev pqtun0 table 100
ip route  add 10.77.0.0/24 dev pqtun0 table 100      # the tunnel's own subnet

# 4. the policy rules. The RPDB is scanned in increasing priority number and the FIRST
#    match terminates the lookup (E8).
ip  rule add priority 100 to <SERVER_V4>/32  lookup main
ip -6 rule add priority 100 to <SERVER_V6>/128 lookup main
ip  rule add priority 200 lookup 100
ip -6 rule add priority 200 lookup 100
```

**Why it works.** The server-bound packet matches rule 100 (its *destination* is the
server) → `lookup main` → main's longest-prefix match finds the /32 host route via
`eth0` → it egresses physically. Every other packet falls to rule 200 → table 100 →
`default dev pqtun0` → into the tunnel. **No source-address selector is used anywhere**,
so the draft's loop is structurally impossible.

**Linux hardening (belt-and-braces, WireGuard's current model — E10):** set `SO_MARK` on
the outer socket (requires `CAP_NET_ADMIN`/`CAP_NET_RAW`) and use
`ip rule add not fwmark <mark> table 100` + `ip rule add table main suppress_prefixlength 0`.
The `suppress_prefixlength 0` matters: it prevents the fallback to `main` from matching
the physical default route, so a lookup failure in the tunnel table cannot leak traffic
out of the physical interface. The outer UDP packets are marked by an nftables CONNMARK
rule on the tunnel interface.

### 8.2 Windows — routes, restoration, kill switch

**Routes** (Windows selects by longest prefix first, then lowest combined metric):

```powershell
# bypass first, so the outer socket can never be captured
New-NetRoute -DestinationPrefix "<SERVER_V4>/32"  -InterfaceIndex <phys> -NextHop <phys-gw> -RouteMetric 1 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix "<SERVER_V6>/128" -InterfaceIndex <phys> -NextHop <phys-gw> -RouteMetric 1 -PolicyStore ActiveStore
# then the tunnel defaults (a /0 via the TUN loses to the /32 above by prefix length,
# regardless of metric)
New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex <tun> -NextHop "0.0.0.0" -RouteMetric 0 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix "::/0"      -InterfaceIndex <tun> -NextHop "::"      -RouteMetric 0 -PolicyStore ActiveStore
Set-NetIPInterface -InterfaceIndex <tun> -InterfaceMetric 1
```

**Windows has no `blackhole` route type** (E11): `New-NetRoute` exposes no route-type
parameter, and `NextHop 0.0.0.0` means "on the local subnet". The native kill-switch
mechanism is **Windows Defender Firewall with Advanced Security (WFAS)**, and the
precedence rules (E12) dictate the shape:

* An **explicit block rule beats an explicit allow rule**. So "block all outbound on the
  physical interface" + "allow the server" **does not work** — the block wins.
* An **explicit allow rule beats the *default* block setting**. So the working strict
  form is: set the firewall profile's `DefaultOutboundAction = Block` and add an explicit
  **allow** rule for the server (address + UDP + server port). The allow beats the
  *default* block per rule 1.
* A **per-interface** kill switch is *not* usable as "block outbound on the TUN": that
  would block the host's packets *into* the tunnel, i.e. break the tunnel itself. (The
  correct per-interface semantics are achieved by the **route**, not the firewall.)

**Kill-switch design (both platforms, layered):**

| Level | Mechanism | Guarantee |
|---|---|---|
| **L1 — fail-closed routing (always on)** | The `0.0.0.0/0` and `::/0` default routes via the TUN are installed for the **whole process lifetime** and are **never removed while the process lives** — not when the session drops, not when the handshake fails. Traffic therefore has nowhere to go except into the TUN, where nobody reads it. | While the process is alive, no traffic escapes. Covers session loss, rekey, handshake failure. **Does not survive a process crash.** |
| **L2 — crash-safe firewall (opt-in, strict)** | Windows: per-profile `DefaultOutboundAction = Block` + explicit allow rule for the server (E12 rule 1). Linux: `ip rule add priority 110 blackhole` with a `priority 100 to <server> lookup main` exception (E8/E9 — Linux *does* have a `blackhole` rule type, which Windows lacks). | Survives process death; leaves the machine offline until the service is stopped. Journaled and restored. |
| **L3 — WFP-API strict interface scoping** | Windows Filtering Platform filters with an explicit `NOT_EQUAL` remote-address condition and filter weight, so "block everything on the physical interface except the server" is expressible. The NetSecurity cmdlets cannot express a negation. | Per-interface strictness without changing the machine-wide default. **Open question Q12.** |

**Route/DNS/interface journal and restoration:**

* **Journal before mutate.** Every installed artefact is recorded *before* it is created:
  Windows — interface index/LUID, destination prefix, next hop, route metric, policy store
  (`ActiveStore` vs `PersistentStore`), and the interface's prior `InterfaceMetric`; the
  prior per-interface DNS server list; the prior per-profile `DefaultOutboundAction`.
  Linux — the `ip route`/`ip rule`/`ip addr` commands and the `resolvectl` state.
* **Restore in reverse order**, on **every** exit path: normal return, `SIGINT`, `SIGTERM`,
  Windows SCM stop, and panic (a `Drop` + an explicit actor).
* **Idempotent removal:** "already gone" is success, not an error. A crash-loop must
  converge.
* **Bounded deadline:** restoration gets a deadline (5 s recommended) after which it
  proceeds anyway and the process exits non-zero with a loud "network may be broken"
  message. Restoration must never hang.
* **Reconcile on start, never accumulate:** startup reads the journal (and, on Linux,
  `ip rule show` / `ip route show table 100`) and removes anything left over *before*
  installing. Two consecutive starts must not produce two default routes.
* **A single shutdown actor** owns the ordering. No ad-hoc `Drop` may mutate routes.

### 8.3 Windows privilege / service model

* **The outer socket must live in the same privileged process as the route installer.**
  Routing is per-host, so a separate unprivileged process's outer socket would be
  captured by the tunnel's own default route → the loop. The identity seed, the outer
  socket, the TUN and the routes therefore all live in one process.
* **Windows Service (SCM).** `pq-tunnel service install|run|stop`. The service reports
  state to the SCM and stops cleanly on SCM stop. Least privilege: run under a **virtual
  service account** (or `LocalService`) with only the rights required; creating a Wintun
  adapter and installing routes requires elevation, so adapter *creation* may need an
  elevated installer step while the *service* only opens the existing adapter.
* **Control channel:** a named pipe with an explicit DACL granting **Administrators and
  the service SID only**. The channel carries **state and commands only** — never keys.
  Unprivileged local processes must not be able to reconfigure routes or read key
  material.
* **Identity-file ACLs (mandatory, and currently missing — F11):** the PQTI identity file
  MUST be created with an explicit restrictive DACL/ACL (Windows: the service SID +
  SYSTEM, inheritance disabled; Unix: mode 0600 in a 0700 directory) and the code that
  creates it (`identity.rs:279-325`, `keygen.rs`) MUST set the permissions explicitly
  rather than inheriting the umask. `keygen` MUST refuse to write into a world-readable
  directory without a warning, and MUST print the resulting mode. Today it writes with
  the process umask ⇒ a **world-readable ML-DSA-65 secret seed** on a default-umask Unix
  host. This is a standalone security defect worth fixing regardless of the TUN work.
* **Linux:** a systemd unit with `AmbientCapabilities=CAP_NET_ADMIN` (and `CAP_NET_RAW`
  if `SO_MARK` is used) plus `NoNewPrivileges`; the identity file owned by the service
  user, mode 0600.

### 8.4 Startup / shutdown ordering

**Startup (each step's failure unwinds all prior steps):**

1. Load and validate the identity + pinned server key (fail closed).
2. Create/open the TUN device; configure **both** a v4 and a v6 address (see §10 Q3:
   `tun` 0.8.14's `Configuration` takes a **single** address — the second must be added
   through the platform address API).
3. Install the **bypass** host route(s) to the server address (BEFORE any default route).
4. Install the tunnel default routes `0.0.0.0/0` and `::/0` (both, or refuse — §6.2).
5. Apply the kill switch (L1 route state is already in place; L2 firewall rules if
   requested).
6. Configure DNS into the tunnel; **roll back on failure and refuse to come up**.
7. Start the session manager; begin the handshake.
8. Only on `ManagerNotification::Ready` enable the TUN **forwarding** direction (i.e.
   start writing server→client packets into the TUN) and start reading host→TUN packets
   into the tunnel.

Note step 8: the *route* is installed before the session is ready (so traffic fails
closed, not open), but the *data plane* is gated on `Ready`. This ordering is the
difference between "fail-closed" and "fail-open".

**Shutdown (reverse order, on every path):**

1. Stop reading from the TUN; drain and drop in-flight reassembly entries.
2. Restore DNS to its pre-tunnel state.
3. Remove the tunnel default routes (reverse of install).
4. Remove the bypass host route(s).
5. Remove the kill-switch firewall rules / restore the profile default.
6. Close the session (fire-and-forget `Close`).
7. Close/delete the TUN device.

**Crash recovery.** A crash leaves routes installed. Startup must be a **reconcile**
(remove leftovers, then install), never an accumulate. On Linux, stale `ip rule`/`ip route`
entries are reconciled on the next start. On Windows, the Wintun adapter is removed with
the adapter driver, but the *routes* persist in the TCP/IP stack until removed — so the
journal (persisted to a state file, fsync'd before each mutation) is the recovery record.
The honest statement is **"reconciled on next start"**, not "guaranteed restored".

**Session churn (D16) must not flap the link.** When the session closes and re-establishes,
the routes, the TUN and the DNS stay up; only the crypto session is rebuilt. Tearing the
link down on every rekey would flap the host's network and emit a distinctive lifecycle
fingerprint that D22 does not concede (it concedes volume, not link-state transitions).

---

## 9. Protocol version decision (task 15)

### 9.1 Does the overlay need a version bump?

**Yes.** The reasoning is not "the record changed" (it did not) but "the failure mode
changed":

* With `PROTOCOL_VERSION = 1` and a new `MessageType::TunData = 0x04`, a **v1 server**
  decrypts the packet fine and then fails `MessageType::from_u8(0x04)` → silent drop
  (§3.2). The client has an established session, an installed default route, and no data:
  an **opaque black hole**.
* With `PROTOCOL_VERSION = 2`, the v1 server rejects at the **header version check** —
  and, decisively, the **handshake fails**, because the client's M1 carries version 2 and
  the v1 server's `ClientHello::decode` rejects it. The client never reaches "established
  but dead" and can report "the server speaks v1, this client speaks v2" **at startup**.

That is the whole argument: convert a silent data-plane black hole into a loud,
startup-time handshake failure. It is exactly the D13 principle ("no downgrade, strict
equality, version detection before any cryptographic work").

### 9.2 The cost, stated precisely

`PROTOCOL_VERSION` is bound into:

* the cleartext wire header (`codec.rs:82`, `:288-302`);
* the M1/M2/M3 message bodies (`handshake_v2.rs:129-144`);
* the transcript hashes (via the bodies);
* the KDF `info` strings — `"pq-tunnel-master-v2" ‖ VERSION ‖ SID ‖ TH3` and
  `"pq-tunnel-finished-v1" ‖ VERSION ‖ SID` (F9) — so the master secret, the finished
  key and the Finished MAC all change.

**What does NOT change:** the M1/M2/M3 body *lengths* (4534 / 5622 / 1113) and therefore
the **pinned fragment counts (4 / 5 / 1)** and the handshake fragmentation layout — the
version byte's *value* changes, not its width. The codec's fixed layout, the compile-time
partition asserts, `WINDOW_BITS`, the cover schedule and the replay window are all
unaffected. The handshake fragmentation is **not** re-derived.

**The cost is therefore:** a hard, non-negotiated interoperability break (no version
negotiation, no downgrade window, no mixed fleet); re-derived KAT vectors
(`pq-crypto/src/kat_vectors.rs`) and the audit artifacts in `docs/audit/`; a
`HANDSHAKE_DOMAIN` / doc-string update (the literal `"pq-tunnel-v1"` should become
`"pq-tunnel-v2"` for clarity, though it is a separate string, not derived from
`VERSION`); and updates to `PROTOCOL_SPEC.md`, `DESIGN_DECISIONS.md`, `THREAT_MODEL.md`,
`CHANGELOG.md` and the KAT/audit evidence.

**Recommendation: bump `PROTOCOL_VERSION` to 2** and add `MessageType::TunData = 0x04`.
Do it as a single, well-labelled change together with the overlay codec, so that the
"established but dead" window never exists in any released build.

### 9.3 If the owner refuses the version break

Fallback: keep version 1, add `MessageType::TunData` anyway, and make the *server's*
TUN mode an explicit operator flag on both ends. The overlay is then distinguished by
the `MessageType`, so no in-band `payload[0]` convention is needed and the legacy relay
stays intact. The residual is the silent-blackhole risk for a v1 server, which must then
be mitigated by a **startup self-test** (the client sends a synthetic datagram and
requires a response within a bounded time; on timeout it tears the route down and
reports "the server does not support the TUN data plane"). The self-test is *not* a
substitute for the version bump — it detects the failure, it does not prevent it.

---

## 10. Security invariants and fail-secure behaviours

### 10.1 Invariants (each MUST be testable)

| # | Invariant |
|---|---|
| I1 | The Tunnel record is always exactly 1280 B; the cleartext header is always 17 B; the AEAD region is always 1263 B. The codec's compile-time partition asserts remain in force. |
| I2 | Every peer-input failure is a **silent drop with zero state mutation** (PROTOCOL_SPEC §14). No error datagram is ever emitted. |
| I3 | The TUN writer only ever receives a **complete, validated** IP packet of exactly `ip_total_len` bytes whose IP header declares exactly that length. There is no code path that writes a partial or unvalidated buffer. |
| I4 | `ip_total_len` is validated *before* any buffer is allocated; every allocation is bounded by `MAX_IP_PACKET_LEN`; the session's total reassembly bytes are bounded by 16 MiB. |
| I5 | A datagram is written only if fragment 0 is present, the fragment count satisfies `(count-1)*FRAG_CAP < ip_total_len ≤ count*FRAG_CAP`, and the assembled IP header's declared length equals `ip_total_len`. |
| I6 | The overlay never influences the AEAD nonce, the counter, the cover schedule or the replay window. The data plane and the cover grid are independent. |
| I7 | The sender emits a datagram's fragments as a contiguous burst and never lets the AEAD counter distance within a burst reach `REPLAY_WINDOW_BITS`. |
| I8 | `datagram_id` never wraps within a session; exhaustion triggers rekey, not wrap. |
| I9 | The server accepts an inner packet only if its source equals the client's assigned address, its destination passes the D28 policy, its L4 port is non-zero, and it is not an IP-level fragment. |
| I10 | The server never writes an inner packet into its TUN before all four checks of I9 pass. |
| I11 | The client never installs a default route for a family it cannot actually carry. Both `0.0.0.0/0` and `::/0` are installed, or the client refuses to come up. |
| I12 | The DNS reconfiguration is all-or-nothing. A partial DNS state is rolled back; a failed DNS reconfiguration prevents the tunnel from coming up. |
| I13 | The outer socket is never routed into the tunnel. This is enforced by a **destination**-based policy rule (Linux) or a **prefix-length**-based host route (Windows) — never by a source-address selector. |
| I14 | The default routes via the TUN remain installed for the whole process lifetime, including while the session is down. |
| I15 | Restoration is idempotent, bounded by a deadline, and runs in reverse install order on every exit path. |
| I16 | The identity file is created with an explicit restrictive ACL/permission; it is never world-readable. |
| I17 | The outer transport sets DF; a path-MTU failure (`EMSGSIZE`) aborts come-up with a diagnostic. |
| I18 | The fragment count, the datagram id and the datagram tag are all **inside the AEAD ciphertext**. The cleartext header is unchanged (17 B). |
| I19 | The session's reassembly table is destroyed when the session closes. |
| I20 | A 1:1 server runs with `max_sessions = 1`; a second client is refused **loudly** (a capacity decision, not a peer-input failure). |

### 10.2 Fail-secure behaviour matrix

| Condition | Required behaviour |
|---|---|
| Malformed overlay header, bad `frag_count`/`frag_index`/`ip_total_len`, bad `reserved`, unknown `overlay_version` | **Drop the fragment silently.** If a datagram entry exists, poison it. No allocation, no TUN write. |
| Fragment count inconsistent with `ip_total_len` | Drop; poison the entry. |
| Assembled IP header length ≠ `ip_total_len`, bad version nibble, bad IHL, header-less datagram | **Poison; write nothing.** |
| Zero-length datagram (`ip_total_len == 0`) | Rejected at the header check; write nothing. |
| Missing fragment (deadline expiry) | Drop the entry; write nothing. No NAK. |
| Duplicate fragment, identical bytes | Ignore. |
| Duplicate fragment, different bytes | Poison the entry; write nothing. |
| Datagram-id collision (mismatched `frag_count`/`ip_total_len`) | Poison both; write nothing. |
| Replayed packet (AEAD counter) | Rejected by the replay window; never reaches the overlay layer. |
| Nonce / datagram-id exhaustion | Session transitions to rekey (`CloseReason::NonceExhausted`); the tunnel's link, routes and DNS stay up. |
| IPv6 default route or v6 address cannot be installed | **Refuse to come up.** (Unless `--no-ipv6`, which is loud and documented.) |
| DNS reconfiguration fails (or partially fails) | Roll back; **refuse to come up** / tear down. |
| Outer path MTU too small (`EMSGSIZE`) | **Refuse to come up**, with the required PMTU in the message. |
| Session drops / rekey / handshake retry | Routes, TUN and DNS **stay up**; the data plane is gated on `Ready`. Traffic fails closed. |
| Process crash | Reconcile on the next start (journal + route-table inspection). Not "restored" — reconciled. |
| Server receives an inner packet with a spoofed source | **Silent drop** (I9). |
| Server receives an inner packet to a denied destination (loopback, link-local/metadata, multicast) | **Silent drop** (D28 hard floor). |
| Server receives an inner IP-level fragment | Silent drop. |
| A second client connects to a 1:1 server | Refused loudly; the existing session is untouched. |
| Reassembly table byte cap reached | New datagrams are **dropped** (fail-secure), existing entries are not evicted. Evicting a live entry would let a lost fragment be spliced into a later datagram. |
| Reassembly entry cap reached | New datagrams are dropped. |
| Restore deadline exceeded | Log loudly, exit non-zero, report "network may be broken". Never hang. |

---

## 11. Mandatory vs optional

### 11.1 MANDATORY

| # | Item | Where |
|---|---|---|
| M1 | `PROTOCOL_VERSION` → 2, plus `MessageType::TunData = 0x04`; KAT vectors and audit artifacts re-derived. | `codec.rs`, `pq-crypto/src/kat_vectors.rs` |
| M2 | New `pq-tunnel-core::dataplane` module: the overlay codec (encode/decode/validate) with strict, panic-free, silently-rejecting semantics. | new module |
| M3 | The reassembler (§4.4-§4.8) in `pq-tunnel-core`, per session, with the exact rules and the bounds. | new module |
| M4 | Sender-side burst serialisation + the replay-window span check (S1, S2). | `session_manager.rs` / `wire_session.rs` |
| M5 | A multi-datagram outbound API (reuse `ManagerEvent::Send`) and an inbound path that delivers **reassembled IP packets** to the driver. | `session_manager.rs:184-193`, `:499-517`, `:959-972` |
| M6 | Server-side TUN + IP forwarding + stateful NAT + source validation + D28 destination policy + L4 port-0 rejection + IP-fragment rejection. | new server module |
| M7 | A TUN device layer: dual-stack addresses, MTU, no panicking `split()`, no `ensure_root_privileges`. | new crate (`pq-tun` or equivalent) |
| M8 | The routing layer: Linux policy rules + Windows routes, journaled, reversible, reconciled. | new module |
| M9 | The DNS integration: routed into the tunnel, all-or-nothing, journaled, reversible. | new module |
| M10 | ICMP pass-through (automatic — it is just another inner IP packet) plus the client's answers for its own TUN address if the host ARPs/NDPs for it. | §12 |
| M11 | The kill switch: L1 always; L2 (Windows profile-default-block + allow; Linux `blackhole` rule) opt-in; L3 (WFP) optional. | §8.2 |
| M12 | Identity-file permission/ACL hardening (the current code writes a world-readable secret seed). | `identity.rs:279-325`, `keygen.rs` |
| M13 | IPv6 leak prevention: dual-stack TUN, `::/0` route, refuse v4-only, loud `--no-ipv6`. | §6 |
| M14 | Correct `codec.rs:94-98` (and add the outer-size/PMTU statement). | `codec.rs` |
| M15 | The route/DNS/interface restoration actor: journal-before-mutate, reverse-order restore, bounded deadline, reconcile-on-start. | new module |
| M16 | DF on the outer transport + the `EMSGSIZE` startup gate + the documented ≥1328/≥1308 path-MTU requirement. | `udp.rs` + driver |
| M17 | Documentation: `PROTOCOL_SPEC.md` (a data-plane section), `DESIGN_DECISIONS.md` (D30/D31), `THREAT_MODEL.md` (the new residuals), `IMPLEMENTATION_GUIDE.md`, `CHANGELOG.md`, `CRYPTO_PROFILE.md` (if the KAT vectors change). | docs |
| M18 | Tests: (a) overlay-contract tests **before** any runtime code; (b) a fuzz target for the overlay codec + reassembler; (c) E2E over a real TUN; (d) an explicit IPv6-leak test; (e) a `kill -9`-mid-install restoration test; (f) an interop test asserting a v1↔v2 handshake failure is **loud**; (g) a PMTU-too-small test; (h) a spoofed-source test on the server. | tests |
| M19 | `max_sessions = 1` for the 1:1 server, with a loud refusal for a second client. | `session_manager.rs` |

### 11.2 Optional optimisations (explicitly NOT v1)

* O1. Dropping the `datagram_tag` and relying solely on the sender's non-reuse invariant
  (S4). Saves 4 B/slot and removes the SHA-256 per datagram. Acceptable only if the owner
  accepts that a sender bug could splice two datagrams.
* O2. `SO_MARK` + the WireGuard-style `not fwmark` rules on Linux (E10) as an addition to
  the destination-exception rules.
* O3. The WFP-API strict interface kill switch (L3).
* O4. A 1500-byte TUN MTU as an operator option.
* O5. A shipped caching DNS resolver (rejected by default: a new always-on, network-
  exposed attack surface; D28-style reasoning).
* O6. `--idle-shutdown` — an explicit, documented **reduction** (it converts a constant
  pattern into an on/off pattern), never presented as a privacy win.
* O7. Per-process masking / split tunnelling — backlog, excluded.
* O8. ECN / DSCP / congestion control inside the tunnel.
* O9. A userspace server forwarder (option (c)) for platforms that cannot do forwarding.
* O10. A `l3mdev`/VRF-based Linux topology instead of policy rules.

---

## 12. ICMP, NDP and other protocol behaviour (task 14)

**ICMP needs no new wire format.** ICMPv4 (protocol 1) and ICMPv6 (protocol 58) are
inner IP packets; they ride the same overlay as everything else. This is the same
simplification the draft identified for DNS, and it generalises.

What the system needs beyond "carry it":

1. **ARP / NDP for the TUN.** With the default route installed as `dev pqtun0` (no
   `via`), the host does **not** ARP/NDP for a gateway — there is no next-hop address to
   resolve. The draft's W7 ("answer ARP/NDP for the TUN's own gateway") is therefore
   **over-general**: with the correct route form, no ARP/NDP responder is needed for the
   default route.
   * The tunnel interface should be configured **point-to-point** (`/32` for v4, `/128`
     for v6) so that the host has **no on-link neighbours** to resolve. With a `/64` on
     the TUN, the host would NDP for on-link addresses and the server's kernel would not
     answer them (the server does not hold the client's prefix) → stalls.
   * The client must still answer ARP/NDP for **its own** TUN address if the host asks
     (it will not, with point-to-point addressing, but the behaviour must be verified
     rather than assumed).
   * If the operator instead assigns a prefix and wants on-link reachability, the server
     must act as a **NDP proxy** (RFC 4861 §7.2.5) and an ARP proxy — a larger feature,
     explicitly out of v1.
2. **IPv6 Router Solicitations.** The host sends RS on the TUN when it comes up. Those
   packets enter the tunnel and are answered by the server's kernel only if the server
   runs RA on its TUN. The client does not need the answer (its routes are installed
   explicitly), but the RS must not be treated as an error. The server's TUN should have
   RA disabled (`accept_ra=0`) so the *server* does not consume a default route from the
   client.
3. **PMTU (ICMPv6 Packet Too Big / ICMPv4 frag-needed) inside the tunnel.** The tunnel
   fragments internally, so the endpoints' IP stacks should not need PTB for the
   tunnelled path — as long as both TUN MTUs are equal. If they are not, the larger side
   will push packets the smaller side must drop. **Equal MTUs on both ends is a
   configuration invariant**, and the client should log both values at startup.
4. **ICMP errors from the tunnel.** Because the tunnel is transparent at the IP layer,
   ICMP "destination unreachable"/"port unreachable" generated by the *server's* hosts
   travels back as an inner IP packet and is delivered to the client — correct end-to-end
   behaviour, and a large functional improvement over the UDP-only relay (which carries
   no ICMP at all).
5. **What the tunnel must NOT do:** synthesise ICMP itself. The draft's option C
   (synthesising "packet too big" to shrink the host's packets) is rejected: the tunnel
   is a link, not a router, and the host's MTU is set locally. The only synthesis the
   client may perform is answering for its own TUN address.

---

## 13. Implementation dependency graph

```
                       ┌───────────────────────────────────────────────┐
                       │ GATE 0 — PROTOCOL VERSION DECISION (§9)       │
                       │ PROTOCOL_VERSION 1→2 + MessageType::TunData   │
                       │ + KAT re-derivation + audit artifacts         │
                       │ BLOCKS every wire-visible change              │
                       └───────────────┬───────────────────────────────┘
                                       │
        ┌──────────────────────────────┼───────────────────────────────────┐
        │                              │                                   │
  CLIENT TRACK                 SERVER TRACK (raw IP)                SHARED TRACK
        │                              │                                   │
 ┌──────▼──────┐               ┌───────▼────────┐              ┌────────▼────────┐
 │ C1 overlay  │               │ S1 server TUN  │              │ H1 dataplane   │
 │   codec     │               │   + fwd + NAT  │              │   module        │
 │ C2 reassemb │               │ S2 src valid.  │              │   (codec+       │
 │   ler       │               │   + D28 dest   │              │    reassembly)  │
 │ C3 sender   │               │   policy       │              │ H2 fuzz target  │
 │   burst+    │               │ S3 max_sess=1  │              │ H3 contract     │
 │   span check│               │   + loud 2nd   │              │   tests        │
 └──────┬──────┘               └───────┬────────┘              └────────┬────────┘
        │                              │                                   │
 ┌──────▼──────┐               ┌───────▼────────┐                       │
 │ C4 TUN dev  │               │ S4 egress      │                       │
 │   (dual-    │               │   policy for   │                       │
 │   stack)    │               │   raw IP       │                       │
 └──────┬──────┘               └────────────────┘                       │
        │                                                              │
 ┌──────▼──────┐                                                      │
 │ C5 routing  │  Linux policy rules / Windows routes + journal        │
 │ C6 DNS      │  routed into the tunnel, all-or-nothing                │
 │ C7 kill     │  L1 route fail-closed; L2 firewall; L3 WFP (optional)  │
 │   switch    │                                                       │
 │ C8 lifecycle│  journal → install → gate on Ready → reverse restore   │
 └──────┬──────┘                                                      │
        │                                                              │
        └──────────────────────┬───────────────────────────────────────┘
                               │
                     ┌─────────▼──────────┐
                     │ C9/S5 integration  │
                     │   + E2E + leak     │
                     │   + PMTU + spoof   │
                     │   + restore tests  │
                     └────────────────────┘

PARALLELISM
  * C1‖C2, C4, C5, C6, C7, S1, S2, S3, H1 can all proceed in parallel once GATE 0
    is decided (H1's *contract tests* can precede GATE 0 entirely — they are pure
    format tests).
  * C3 depends on C1 (the overlay header).
  * C4 → C5 (the route form depends on the addressing form).
  * C5 → C7 (the kill switch's route state depends on the routes).
  * C6 is independent of C1-C5 but must precede C8's "Ready" gate.
  * S1 → S2 → S3 (the TUN must exist before the policy is applied).
  * H2/H3 depend on H1.

SERIAL CHAIN (critical path)
  GATE 0 → H1 → C1 → C3 → C9/S5
  GATE 0 → S1 → S2 → S3 → C9/S5
  C4 → C5 → C7 → C8 → C9

NOTE: the server track is **independent** of the client's TUN work. It can be built and
tested against a synthetic "inner IP packet" injector before the client exists. This is
the single biggest schedule win available and it is why the server track is a separate
branch above.
```

---

## 14. Verdict on `docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md`

### 14.1 CORRECT (retain)

| # | Claim | Comment |
|---|---|---|
| C1 | The wire record, header, AEAD region and the codec's compile-time invariants are untouched by an in-slot overlay. | Verified against `codec.rs:104-152`, `envelope.rs:257-300`. |
| C2 | The overlay header must live inside the AEAD ciphertext; the `PAYLOAD_LEN` contract is met by zero-padding the tail. | Correct. |
| C3 | The relay framing and the TUN overlay are two different in-slot conventions that must be explicitly disambiguated, and the disjointness must be pinned by a test. | Correct in principle; the draft's *mechanism* is wrong (W4). |
| C4 | An incomplete datagram is silently dropped; there is no partial write to the TUN. | Correct and structural. |
| C5 | The reassembly table needs a **global** byte cap, not only a per-entry cap. | Correct. |
| C6 | The MTU is a local parameter and is never negotiated (PROTOCOL_SPEC §7.5, D19). | Correct. |
| C7 | IPv6 leak prevention must be fail-secure: refuse to come up as a v4-only "full-system" tunnel; `--no-ipv6` is a loud, documented reduction. | Correct, and decisive (it is what makes the draft's own MTU choice unimplementable — W3). |
| C8 | The privilege model: a privileged service; the identity key must not be reachable by unprivileged local processes; the control channel carries state only. | Correct. |
| C9 | Journal-before-mutate, reverse-order restore, idempotent removal, reconcile-on-start (never accumulate). | Correct. |
| C10 | The TUN link state is decoupled from session liveness; session churn must not flap the link. | Correct. |
| C11 | DNS needs no new wire format — it is just IP packets on the TUN. | Correct, and it generalises to ICMP (§12). |
| C12 | The dual-stack requirement, and that the deleted `pq-tun` is ~0 % reusable. | Correct — and I add that `tun` 0.8.14 *still* takes a single address (E14), so the dual-stack problem was not solved by the crate's evolution. |
| C13 | Fragment count is a D22-accepted observable class. | Correct, but understated: the cleartext `packet_nonce` (F2) already exposes the **entire** packet timeline (counts and gaps), which is a stronger existing residual the draft fails to record (M-F). |
| C14 | The draft's own "what exists today" table is accurate: `ip_packet_len()` has no production caller; the relay is socket-centric and single-slot; the tree has no route/DNS/service code. | Verified. |

### 14.2 WRONG (must be corrected)

| # | Claim | Correction |
|---|---|---|
| W1 | §1.3 option A(i): "IPv6 does **not** fragment at the source — RFC 8200 requires the *router* to fragment and forbids source fragmentation." | **INVERTED.** RFC 8200 §4.5: "fragmentation in IPv6 is performed only by source nodes, **not by routers** along a packet's delivery path" (E1). §5 confirms source fragmentation is the mechanism (discouraged, not forbidden) (E2). |
| W2 | §1.8(4): "we never set DF and never ask the host to fragment — which is correct for IPv6, where source fragmentation is forbidden." | **WRONG.** IPv6 *source* fragmentation is permitted (though discouraged); *router* fragmentation is forbidden. The real argument for tunnel-layer fragmentation is family-symmetry and independence from the host stack. |
| W3 | §1.2 / W12: TUN MTU = **1241**. | **Non-conformant** (E2) **and impossible for IPv6 on Linux** (E7: `ipv6_add_dev()` returns `-EINVAL`; the MTU-change notifier calls `addrconf_ifdown()` → IPv6 is disabled on the interface). The draft's own §1.8 "no v4-only tunnel" rule therefore makes its own MTU recommendation unimplementable. Use **1280**. |
| W4 | §1.6: the relay frame "can never be 0x01 or 0x04/0x06 in a TUN overlay slot because `hdr_ver` occupies that byte" — treated as making the disjointness safe. | **Circular.** A *legacy server* decoding an overlay payload sees `hdr_ver` (e.g. 0x01) → `BadFamily` → **silent drop** (F5). That is precisely the silent interop failure the brief names. Use a new `MessageType` (§3.1). |
| W5 | §1.1: "Reassembly key = (session_id, packet_nonce-of-FIRST, direction). Every fragment of one packet is emitted back-to-back … so the session's monotonically increasing `packet_nonce` already orders them." | **FALSE** on four counts (§4.1): cover interleaves (F4); concurrency interleaves; the receiver cannot know the counter of the unseen first fragment; the AEAD counter is shared with cover (F2). Use an independent `datagram_id`. |
| W6 | §1.5: "Reassembly deadline: 2 × cover interval (≈ 10.24 ms at default)." | **WRONG and dangerous.** It couples a correctness-critical deadline to a user-tunable metadata knob (`--cover-mbps`, `lib.rs:97-103`): at `--cover-mbps 200` the deadline becomes 102.4 µs — shorter than any RTT, so reassembly would *always* fail. Derive from a latency budget (§4.8). |
| W7 | §1.7: "Multi-slot reassembly must use `frag_total` … as the authoritative datagram length — which is more trustworthy than parsing a length field out of a header." | **INVERTED.** The host's IP stack honours the **IP header's** total-length field. The header is authoritative; `frag_total`/`ip_total_len` are cross-checks (§4.6). The draft's §1.7 also contradicts its own §1.3 option B ("Length is recoverable … for the single-slot case" vs "**Every** overlay slot fails the existing parser"). |
| W8 | §1.4 / W6: `ip rule add not from <tun-addr> lookup 100`. | **Creates the loop it claims to prevent** (§8.1). The outer socket's source is the physical address → "not from \<tun-addr\>" matches → table 100 → `default dev tun0` → the outer packet enters the TUN. Use a **destination** exception; upstream `wg-quick` uses `not fwmark` + `table main suppress_prefixlength 0` and no source selector at all (E10). |
| W9 | Q5(c): "let the OS fragment the outer UDP datagram (IP-level, outside the tunnel's control)." | Incompatible with an IPv6 outer transport (routers never fragment, E1) and it changes the observable packet count. Set DF and document the ≥1328/≥1308 path-MTU requirement (§7.3). |
| W10 | §0.1 / `codec.rs:94-98`: the 1280-byte record "fits a standard IPv4/IPv6 MTU (1500 / 1280)". | **FALSE** for the 1280 case: the outer IP packet is 1308 (v4) / 1328 (v6) bytes (§1.2). The record imposes a hard minimum path MTU. PROTOCOL_SPEC §7.5's "SHOULD avoid … specific MTU sizes" is therefore not met by the current record — record it as an explicit residual. |
| W11 | §1.5: "Max slots per datagram: 53 (65535 / 1241)". | The arithmetic ignores the overlay header the draft itself proposes (which changes the per-slot capacity) and silently drops the IPv6 case (whose total can reach 65575). With the §3.3 header the bound is `ceil(65535/1231) = 54`. |
| W12 | §1.4: "Linux: `ip route add default dev <tun> table 100` + `ip rule add not from <tun-addr> lookup 100` … plus an explicit `ip route add <server-ip>/32 dev <physical>` in the main table." | The main-table /32 alone is not sufficient once a policy table is in play, and the rule it pairs with is inverted (W8). The correct pair is: /32 in main + `to <server>/32 lookup main` (priority 100) + `lookup <table>` (priority 200) (§8.1). |
| W13 | §1.10: DNS reconfiguration "must either complete reconfiguration or restore the prior state". | Correct for the *partial* case, but the draft never states the **consequence** for the tunnel's state: a resolver that still points at the ISP leaks DNS even with a perfectly tunnelled data plane. The client MUST refuse to come up (§6.4). |
| W14 | §1.4/§1.11: the `--kill-switch` is "a reject-all route and does not establish a tunnel". | That is not a kill switch *during* an outage. The mechanism that actually provides fail-closed behaviour is the **default route staying installed for the whole process lifetime** (L1 in §8.2) plus a firewall for the crash case (L2). |
| W15 | §1.2: "Set the TUN device MTU to 1241 for IPv4 and 1201 for IPv6 … So TUN MTU = 1241 for both families." | Internally inconsistent (the sentence and its parenthetical disagree) *and* both values are wrong (W3). |
| W16 | §4.3: "W1 must adopt the same shape for the TUN overlay, with the bounds being 1 <= frag_total <= 53", citing the handshake's pinned `frag_total` as "the defence that prevents an arbitrary datagram from ever being interpreted as a fragment". | The pinned `frag_total` is exactly the property a variable-range overlay does **not** inherit (F10). The draft cites the defence and then removes it, without naming the replacement. The replacement is §4.5's inequality + the IP-header cross-check. |

### 14.3 MISSING (absent from the draft)

| # | Gap |
|---|---|
| M-A | **A server-side raw-IP path.** The draft's Q4 leaves it as an open question, and its recommended option (a) "client TUN only, server stays a UDP forwarder" is *acknowledged* not to deliver a full-system VPN. This is the largest gap. See §2. |
| M-B | **Server-side source-address anti-spoofing** — mandatory in a raw-IP path, with no analogue in the socket model (E5, E15). See §2.2. |
| M-C | **A per-datagram identity independent of the AEAD nonce counter**, with collision/reuse rules. See §4.1, §4.3 S4, §4.4. |
| M-D | **The replay-window interaction** (`WINDOW_BITS = 1024`, F3) — never mentioned; it invalidates any "consecutive counters" scheme (Rule S2) and caps the effective reassembly deadline (§4.8). |
| M-E | **Fragmentation loss amplification** (an *N*-slot datagram is lost if any slot is lost) and its connection to the TUN-MTU choice. See §4.7. |
| M-F | **The cleartext-counter metadata property**: the 8-byte `packet_nonce` in the cleartext header already exposes the entire packet timeline (counts and gaps). The draft treats the fragment count as a new observable class and misses the stronger existing one. |
| M-G | **The dual-stack address problem in the *current* `tun` crate** (0.8.14's `Configuration` takes a single address, E14) — the second address needs the platform address API. |
| M-H | **The Windows kill switch**: no `blackhole` route type (E11); the WFAS precedence rules (E12) forbid "block all + allow server"; the working form is a profile `DefaultOutboundAction = Block` + an explicit allow. |
| M-I | **Identity-file permission hardening** — the current code creates the secret seed with the process umask (F11). |
| M-J | **The DF/PMTU decision** and the ≥1328/≥1308 path-MTU requirement. |
| M-K | **The `EMSGSIZE` startup gate** (detect an under-MTU path and refuse to come up). |
| M-L | **The non-mixing guarantee** (`datagram_tag`) — without it, a sender bug could splice two datagrams and write a corrupt IP packet to the host stack. |
| M-M | **IP-level fragment rejection at the server** (IPv4 MF/offset, IPv6 Fragment header) — a client could otherwise deliver IP fragments into the server's kernel. |
| M-N | **The protocol-version cost analysis** and the recommendation (the draft's Q1 is unanswered and the option list omits the "silent black hole" reasoning). |
| M-O | **The structural fact that a 1280-byte IPv6 packet can never fit in one Tunnel record**, and the 50 %-efficiency consequence. |
| M-P | **`MessageType`-based dispatch** (the draft uses an in-band `payload[0]` convention). |
| M-Q | **The Windows service/ACL details**: the control channel's DACL, the identity file's DACL, and the requirement that the outer socket live in the same privileged process as the route installer. |
| M-R | **The server egress policy adapted to raw IP** (D28's CIDR table at the IP layer; the port rules need L4 parsing; the destination check must happen *before* the write into the server's TUN). |
| M-S | **The point-to-point addressing of the TUN** (`/32` and `/128`) and the consequent absence of on-link ARP/NDP — which makes the draft's W7 ("NDP/ARP responder", "the #1 practical TUN bug") unnecessary in the correct route form. |
| M-T | **The 1:1 session-limit reconciliation** (`max_sessions = 1`, loud refusal of a second client). |

---

## 15. Unresolved questions (with the exact evidence needed)

None of these may be guessed.

| # | Question | Evidence required | Interim position |
|---|---|---|---|
| Q1 | The concrete reassembly timeout. | (a) A measured reordering-delay distribution for the target paths (a long-running capture, or a measurement service); (b) the deployment's expected peak tunnel rate, to compute the replay-window horizon (`1024 / rate_pps`); (c) the operator's stated latency budget. | **2 s** as a D7 parameter, with the derivation method of §4.8 and the explicit statement that it is a *default*, not a derived constant. **Never** `--cover-mbps`-derived. |
| Q2 | The TUN MTU. | The operator's path MTUs and the desired tunnelled-link MTU. | **1280** (derived: E2 + E7). 1500 as an opt-in. Both ends equal. |
| Q3 | The TUN library. | A spike: `cargo +1.85.0 check`/`clippy -- -D warnings` for `tun 0.8.14` on `x86_64-pc-windows-msvc` **and** on Linux, with `Cargo.lock` pinned; `tun` declares no `rust-version` and its deps (`nix 0.31`, `windows-sys 0.61`, `wintun-bindings 0.7.39`) may require > 1.85. Also: `tun` 0.8.14's `Configuration` supports **one** address → the dual-stack address step needs a platform API. | `tun 0.8.14` is the leading candidate (it uses `wintun-bindings` on Windows), **subject to the MSRV spike**. A raw `wintun-bindings` + `netlink`/IP-Helper layer is the fallback. |
| Q4 | Windows' minimum IPv6 interface MTU, and whether Windows clamps or disables IPv6 below 1280 (as Linux does, E7). | A Microsoft platform statement, or an empirical test on the supported Windows versions. | Assume Windows mirrors Linux (clamp/disable) until proven otherwise; therefore 1280 is the safe floor on both platforms. |
| Q5 | The Windows outer-transport PMTU failure surface (`WSAEMSGSIZE` vs a silent drop vs an ICMP-driven PMTU cache). | The IP Helper / Winsock documentation, or an empirical test on a deliberately small-MTU path. | Assume `EMSGSIZE` is surfaced; the startup gate treats *any* outer-send failure that is not a peer-reset as fatal. |
| Q6 | Server addressing: NAT or routed assignment? | The deployment's address plan (does the operator own routable v4 and/or v6 prefix space?). | **Stateful NAT** as the default (Linux nftables / `New-NetNat`); routed assignment as an explicit operator option. |
| Q7 | The server's raw-IP egress policy: which D28 rows apply at the IP layer, and which require L4 (port) parsing? | An owner decision on whether to implement L4 inspection of the inner packet (TCP/UDP header parsing, plus the ICMP case). | Apply the full D28 CIDR table at the IP layer; implement the port-0 rule with L4 parsing; defer the per-port policy. |
| Q8 | Is the legacy D18 relay retained in v2, and is `MessageType::TunData = 0x04` the right value? | An owner product decision. | Retain the relay as `MessageType::Data` (diagnostic/conformance); add `TunData = 0x04`. |
| Q9 | The identity-file ACL model per platform. | The deployment's account model (a virtual service account vs LocalSystem vs a per-user service) and the threat model for a local attacker. | Windows: DACL = service SID + SYSTEM, inheritance disabled. Unix: 0600 in a 0700 directory, owned by the service user. |
| Q10 | The concrete reassembly entry/byte caps. | The deployment's peak tunnel rate × the timeout, and the server's memory budget. | 256 entries / 16 MiB per session (process-global byte counter). |
| Q11 | The `datagram_id` exhaustion cadence (u32 over a 24 h session). | The deployment's peak IP-packet rate → the rekey cadence. | Rekey on exhaustion (mirroring `CloseReason::NonceExhausted`); the cadence is a consequence of the rate, not a design choice. |
| Q12 | Is the strict WFP-API Windows kill switch (L3) required, or is the profile-default-block form (L2) sufficient? | The operator's tolerance for changing the machine's firewall default, and the local-attacker threat model. | L2 (profile default + allow) is sufficient for the stated threat model; L3 if per-interface strictness is required. |
| Q13 | Does the server write into its TUN, or does the kernel route into it? | The platform's forwarding model. | The tunnel writes into the TUN (the server's kernel then routes it out), so the source/destination policy is applied *before* the write and is not delegated to the kernel. |
| Q14 | The exact TUN→host interface MTU behaviour when the server's egress path is larger than the tunnelled MTU (IPv6 PTB vs kernel fragmentation). | Empirical per-platform tests. | The server's TUN MTU equals the client's; unequal MTUs are a configuration error that is logged at startup. |

---

## 16. Primary sources

* RFC 8200, *IPv6 Specification* — §3 (header), §4.5 (Fragment header; **"fragmentation in IPv6 is performed only by source nodes, not by routers"**), §5 (Packet Size Issues; **IPv6 minimum link MTU 1280**; 60 s reassembly timer is in §4.5).
  https://www.rfc-editor.org/rfc/rfc8200.txt
* RFC 8201, *Path MTU Discovery for IP version 6* — §4 (PTB handling; the 1280 floor), §6 (black-hole connections), App. A (**"there is no DF bit in IPv6 packets"**).
  https://www.rfc-editor.org/rfc/rfc8201.txt
* RFC 791, *Internet Protocol* — §3.1 (header; Total Length; DF), §3.2 (addressing, fragmentation/reassembly, 60 s timer).
  https://www.rfc-editor.org/rfc/rfc791.txt
* RFC 1812, *Requirements for IP Version 4 Routers* — §5.3.8 (Source Address Validation), §5.3.9 (packet filtering).
  https://www.rfc-editor.org/rfc/rfc1812.txt
* RFC 2827 / BCP 38, *Network Ingress Filtering*.
  https://www.rfc-editor.org/rfc/rfc2827.txt
* RFC 4861, *Neighbor Discovery for IP version 6* — §7.2.5 (Proxy NDP).
  https://www.rfc-editor.org/rfc/rfc4861.txt
* RFC 4443, *ICMPv6 for IPv6* — Packet Too Big, Parameter Problem.
  https://www.rfc-editor.org/rfc/rfc4443.txt
* Linux kernel — `include/uapi/linux/ipv6.h` (`IPV6_MIN_MTU 1280`) and `net/ipv6/addrconf.c` (`ipv6_add_dev` rejects `mtu < IPV6_MIN_MTU`; the MTU-change/up notifier calls `addrconf_ifdown`).
  https://github.com/torvalds/linux/blob/master/include/uapi/linux/ipv6.h
  https://github.com/torvalds/linux/blob/master/net/ipv6/addrconf.c
* `ip-rule(8)`, `ip-route(8)` — RPDB semantics, `blackhole` rule and route types.
  https://man7.org/linux/man-pages/man8/ip-rule.8.html
  https://man7.org/linux/man-pages/man8/ip-route.8.html
* Upstream `wg-quick` (linux.bash) — the current WireGuard policy-routing formulation (`not fwmark`, `table main suppress_prefixlength 0`, CONNMARK of the outer UDP packets).
  https://git.zx2c4.com/wireguard-tools/plain/src/wg-quick/linux.bash
* Microsoft — `New-NetRoute` (**no route type; no `blackhole`**).
  https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute
* Microsoft — *Windows Firewall Rules* (rule precedence: an explicit block beats an explicit allow; an explicit allow beats the *default* block).
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
* Wintun — signed L3 TUN driver for Windows.
  https://www.wintun.net/
* `tun` crate 0.8.14 — `Configuration` (a single address; no route installation; no declared MSRV).
  https://docs.rs/tun/0.8.14/tun/
  https://crates.io/api/v1/crates/tun/0.8.14
* `setsockopt` (Winsock) — `SO_*` options; `IP_UNICAST_IF` / `IP_DONTFRAGMENT` live in the `IPPROTO_IP`/`IPPROTO_IPV6` option pages.
  https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-setsockopt
