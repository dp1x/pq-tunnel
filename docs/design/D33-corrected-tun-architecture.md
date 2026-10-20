# D33 -- Corrected System-Wide TUN/IP Architecture

**Status:** DESIGN PROPOSAL. **Research only -- no code, no TUN implementation.**
**Baseline commit:** `c6c0f12373f45cba02f6e8f44b386ea46d5da659` (read-only analysis).
**Scope:** the complete end-to-end architecture of a system-wide TUN/IP data
plane for a 1:1 tunnel: the byte and MTU arithmetic, the client path, the server
path, the inner-packet framing and the tunnel's own fragmentation, the core
invariants, the platform implementation graph, and the milestone sequence.

## 0. What this document is, and what it replaces

This document re-derives the system-wide data plane from the code and from
primary sources, and corrects five substantive errors and two stale premises in
[`D30-corrected-system-wide-data-plane.md`](D30-corrected-system-wide-data-plane.md).
It also supersedes the *design content* of
[`D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md`](D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md),
which is marked **SUPERSEDED** and must not be implemented from.

| | Document | Status |
|---|---|---|
| D25/D26 | System-wide TUN architecture | **SUPERSEDED** -- do not implement |
| D30 | Corrected system-wide data plane | **SUPERSEDED by this document** (the corrections are recorded in D30's own amendment section) |
| D33 | This document | The corrected successor |

**The product framing from D25/D26 §0 is retained and is correct:** Tunnel is a
system-wide OS/networking tool, not an application proxy. D18's UDP relay is
implementation infrastructure -- the app-facing ingress for the v0.2 datagram
plane -- and remains useful as a diagnostic, a conformance harness for the slot
codec, and a fallback on platforms without a usable TUN. Nothing here removes
it.

### 0.1 Scope guard: what this document does not claim

- **D22's scope is unchanged and is not widened here.** Tunnel's metadata target
  for v1-alpha is **metadata-leakage reduction, not traffic-flow anonymity**
  (`DESIGN_DECISIONS.md:1061-1105`, decision at `:1080-1095`). A fixed record
  size does **not** make traffic indistinguishable. It makes the *size* of each
  packet constant. What remains observable under this design, and is accepted
  by design, includes: the number of packets per unit time, the gaps between
  them, the session count, session liveness, the establish/rekey/close
  lifecycle, and -- newly introduced by a system-wide tunnel -- DNS query
  volume and link-state transitions. Each of these is a *residual to be
  recorded*, not a residual to be solved here.
- **Nothing here weakens HNDL resistance.** The overlay header, the
  reassembly table and the routing changes are all inside or below the AEAD;
  the traffic keys and their lifetime are unchanged.
- **No new cryptography is invented.** The overlay header is a framing. The
  one integrity check it introduces is a CRC-32, which is an error-detecting
  code, not a cryptographic primitive (see §4.6).

### 0.2 Citation convention

Every `file:line` reference is against the **baseline commit `c6c0f12`**. The
working tree is concurrently under edit; `pq-tunnel-core/src/codec.rs`,
`pq-tunnel-core/src/replay.rs`, `pq-tunnel-core/src/udp.rs`,
`pq-tunnel-bin/src/forward.rs`, `pq-tunnel-bin/src/relay.rs`,
`pq-tunnel-bin/src/packet_len.rs` and `pq-tunnel-bin/src/identity.rs` are
unmodified at the baseline and are cited directly. Claims that could not be
verified are marked **[UNVERIFIED]** and collected in §11.

---

## 1. The byte and MTU arithmetic, re-derived

### 1.1 The Tunnel record

From `pq-tunnel-core/src/codec.rs`:

| Constant | Value | Line |
|---|---|---|
| `PACKET_SIZE` | 1280 | `codec.rs:112` |
| `VERSION_LEN` | 1 | `codec.rs:85` |
| `SESSION_ID_LEN` | 8 | `codec.rs:115` |
| `PACKET_NONCE_LEN` | 8 | `codec.rs:116` |
| `AEAD_TAG_LEN` | 16 | `codec.rs:117` |
| `HEADER_LEN` = version + sid + nonce | 1 + 8 + 8 = **17** | `codec.rs:141` |
| `INNER_PLAINTEXT_LEN` = `PACKET_SIZE - HEADER_LEN - AEAD_TAG_LEN` | 1280 - 17 - 16 = **1247** | `codec.rs:144` |
| `PAYLOAD_LEN` = `INNER_PLAINTEXT_LEN - 2` (type + direction) | 1247 - 2 = **1245** | `codec.rs:147` |

The partition is enforced at compile time by a `const` assertion
(`codec.rs:152-160`): `HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN ==
PACKET_SIZE`.

**`PACKET_SIZE` is the UDP payload, not an IP packet.** `pq-tunnel-core/src/udp.rs:142`
sends `packet.as_bytes()` -- the whole 1280-byte array -- as one datagram, and
`udp.rs:143-150` rejects any write whose length is not 1280. The receive buffer
is `PACKET_SIZE + 1` (`udp.rs:168`) so that an oversize datagram is *detected*
rather than silently truncated; the length check is at `udp.rs:182`.

### 1.2 The outer IP packet sizes

```
outer IPv4 total length = 20 (IPv4 header, IHL=5) + 8 (UDP) + 1280 (record) = 1308 bytes
outer IPv6 total length = 40 (IPv6 header)           + 8 (UDP) + 1280 (record) = 1328 bytes
```

Usable UDP payload on a given path MTU:

| Path | Usable UDP payload | Fits the 1280-byte record? |
|---|---|---|
| IPv4, 1500-byte MTU | 1500 - 20 - 8 = 1472 | **Yes** -- 192 bytes spare |
| IPv6, 1500-byte MTU | 1500 - 40 - 8 = 1452 | **Yes** -- 172 bytes spare |
| IPv4, 1280-byte MTU | 1280 - 20 - 8 = 1252 | **No** -- 28 bytes over |
| IPv6, 1280-byte MTU | 1280 - 40 - 8 = 1232 | **No** -- 48 bytes over |

**Minimum required outer path MTU: 1308 bytes (IPv4 outer) / 1328 bytes (IPv6
outer).** A 1280-byte-MTU path is insufficient in *both* families.

The codec's own documentation already states this correctly at the baseline:
"The record is the UDP payload, so the complete outer packet is 1280 + 8 (UDP) +
20 (IPv4) = **1308 bytes**, or 1280 + 8 + 40 (IPv6) = **1328 bytes** ...
**not** a 1280-byte-MTU path ... A deployment therefore requires a path MTU of
at least 1328 bytes" (`codec.rs:98-106`). **D30 §1.2's attribution of a
different claim to `codec.rs:94-98` is stale -- see §10.2.**

> A coincidence worth recording: 1232 = 1280 - 40 - 8 is the same number
> RFC 6946 §3 quotes for an IPv6 atomic fragment's payload ("the payload may
> have to be reduced to 1232 octets (1280 minus 40 for the IPv6 header and 8 for
> the Fragment header)").

### 1.3 The IPv6 1280-byte minimum-MTU analysis

**RFC 8200 §4.5 (Fragment header)** -- verified verbatim:

> "The Fragment header is used by an IPv6 source to send a packet larger than
> would fit in the path MTU to its destination. (Note: unlike IPv4,
> **fragmentation in IPv6 is performed only by source nodes, not by routers
> along a packet's delivery path** -- see Section 5.)"

**RFC 8200 §5 (Packet Size Issues)** -- verified verbatim:

> "IPv6 requires that every link in the Internet have an MTU of 1280 octets or
> greater. This is known as the IPv6 minimum link MTU. On any link that cannot
> convey a 1280-octet packet in one piece, link-specific fragmentation and
> reassembly must be provided at a layer below IPv6."
> "Links that have a configurable MTU (for example, PPP links [RFC1661]) must be
> configured to have an MTU of at least 1280 octets ..."
> "A node must be able to accept a fragmented packet that, after reassembly, is
> as large as 1500 octets."

**RFC 8200 §4.5 (reassembly timer)** -- verified verbatim:

> "If insufficient fragments are received to complete reassembly of a packet
> within 60 seconds of the reception of the first-arriving fragment of that
> packet, reassembly of that packet must be abandoned and all the fragments that
> have been received for that packet must be discarded."

**RFC 8201 Appendix A** -- verified verbatim: "there is no DF bit in IPv6
packets".

**RFC 4443 §3.2 (Packet Too Big)** -- ICMPv6 Type 2 is defined here, **not** in
RFC 8200. Verified verbatim:

> "Type 2 ... MTU -- The Maximum Transmission Unit of the next-hop link. ... A
> Packet Too Big MUST be sent by a router in response to a packet that it cannot
> forward because the packet is larger than the MTU of the outgoing link."

**RFC 6946 §3 / §4** -- verified verbatim: "IPv6 atomic fragments: IPv6 packets
that contain a Fragment Header with the Fragment Offset set to 0 and the M flag
set to 0"; "A host that receives an IPv6 packet that includes a Fragment Header
with the 'Fragment Offset' equal to 0 and the 'M' flag equal to 0 **MUST process
that packet in isolation** from any other packets/fragments". Appendix A's
operating-system survey records Linux 3.0.0-15, OpenBSD and Solaris 11 as
conformant, and Windows XP SP2 / Vista / 7 as **not** conformant.

**Linux kernel enforcement** -- `include/uapi/linux/ipv6.h:13` defines
`#define IPV6_MIN_MTU 1280`, and `net/ipv6/addrconf.c` enforces it in
`ipv6_add_dev()` (`if (dev->mtu < IPV6_MIN_MTU && dev != blackhole_netdev)
return ERR_PTR(-EINVAL);`) and in the `NETDEV_CHANGEMTU` notifier path
(`/* if MTU under IPV6_MIN_MTU stop IPv6 on this interface. */ if (dev->mtu <
IPV6_MIN_MTU) { addrconf_ifdown(dev, dev != net->loopback_dev); break; }`).

**Consequence:** an inner (TUN) MTU below 1280 is not merely "non-conformant"
-- on Linux it **disables IPv6 on the interface**. The inner MTU floor of
**1280** is enforced by the operating system, not chosen by us. This is a hard
constraint, not a tunable.

### 1.4 The inner (tunnelled) plane arithmetic

```
PAYLOAD_LEN         = 1245                       codec.rs:147
OVERLAY_HEADER_LEN  =   20                       (this design, §4.1)
FRAG_CAP            = 1245 - 20 = 1225          bytes of inner IP per record
MAX_FRAG_COUNT      = ceil(65535 / 1225) = 54
   check: 53 * 1225 = 64 925 < 65 535 <= 66 300 = 54 * 1225
MAX_IP_PACKET_LEN   = 65535
```

Slots and efficiency at the candidate inner MTUs:

| Inner MTU | Records per datagram | Carrier bytes | Efficiency |
|---|---|---|---|
| 1280 | ceil(1280/1225) = 2 | 2 x 1280 = 2560 | 1280 / 2560 = **50.0 %** |
| 1500 | ceil(1500/1225) = 2 | 2 x 1280 = 2560 | 1500 / 2560 = **58.6 %** |

**Structural fact (unavoidable):** a 1280-byte inner IP packet can **never**
fit in one Tunnel record. The payload is 1245 B; even with a *zero*-length
overlay header, 1245 < 1280. Therefore `ceil(1280 / FRAG_CAP) = 2` for every
conformant overlay, and the tunnelled link is necessarily a **fragmenting
link**.

**=> Minimum-MTU IPv6 packets cost 2 records. Tunnel efficiency at inner MTU
1280 is exactly 50 %.** The ways out are all rejected:

- *Lower the inner MTU below 1280* -- non-conformant (RFC 8200 §5) and
  IPv6-disabled on Linux (`addrconf.c`). Rejected.
- *Raise `PACKET_SIZE`* -- a wire-format change, and it worsens the outer PMTU
  problem (a 2608-byte record needs a 2608+ byte path). Rejected.
- *Set the outer DF and let the OS fragment the outer packet* -- routers would
  fragment (IPv4) while IPv6 routers never do, giving family-dependent
  observable packet counts. Rejected; DF is set (§2.6).

### 1.5 Loss amplification, stated rather than hidden

An inner packet split across *N* records is lost if any one record is lost. At
path loss rate *p*, an *N*-record datagram is lost with probability
approximately *N*p*. At inner MTU 1280 (*N* = 2) and *p* = 0.1 %, the effective
loss is approximately 0.2 % -- a 2x amplification that TCP must repair.

This is the **price of a 1280-byte carrier**. It belongs in `THREAT_MODEL.md`
as an accepted residual (D30 §4.7 gets this right and is retained).

---

## 2. The client path

### 2.1 The end-to-end client path

```
  ┌──────────────────────────────── host ─────────────────────────────────┐
  │                                                                       │
  │  app socket ──► IP stack ──► route lookup (RPDB / Windows route table) │
  │                       │                                               │
  │                       │  dest ∉ tunnel-table  →  (server? bypass)     │
  │                       │                          → phys NIC            │
  │                       │                                               │
  │                       └──► default route 0.0.0.0/0, ::/0 ──► pqtun0  │
  │                                       (INNER MTU = 1280)             │
  │  ═══════════════════════════════════════════════════════════════      │
  │  pqtun0 = L3 TUN device (Linux /dev/net/tun IFF_TUN | Wintun L3 |     │
  │            macOS utunN).  Read = one inner IP packet, exactly          │
  │            MTU bytes, no PI header (IFF_NO_PI).                        │
  │  ═══════════════════════════════════════════════════════════════      │
  │                                                                       │
  │  TUN reader ──► [dataplane::encapsulate]                              │
  │      · validate the inner packet (length, version, link-local)        │
  │      · compute CRC-32 over the whole inner IP packet                   │
  │      · split into ceil(len/FRAG_CAP) records                           │
  │      · assign datagram_id (per-session, per-direction, u64, ++)        │
  │      · build the overlay header (20 B) per record                      │
  │      │                                                                │
  │      └──► [envelope]  CipherSession::encrypt(MessageType::TunData,..) │
  │            → WirePacket (1280 B)  codec.rs:112, envelope.rs:257        │
  │               │                                                       │
  │               └──► ManagerEvent::Send { packets: [pkt…], peer }        │
  │                        (burst channel, session_manager.rs:193-198)    │
  │                             │                                         │
  │                    ┌────────▼─────────┐                               │
  │                    │  UDP socket      │  DF set (IP_MTU_DISCOVER /     │
  │                    │  1280 B payload  │  IP_DONTFRAGMENT); IPv6 has   │
  │                    │  unconnected     │  no DF bit (RFC 8201 App. A)  │
  │                    └────────┬─────────┘                               │
  └─────────────────────────────┼─────────────────────────────────────────┘
                                │  outer IPv4 = 20+8+1280 = 1308 B
                                │  outer IPv6 = 40+8+1280 = 1328 B
                                ▼
                     ┌──────────────────────────────────┐
                     │  server host                    │
                     │  UdpTransport::bind (udp.rs:82)  │  udp.rs:182 rejects
                     │  → session manager               │  anything != 1280
                     └───────────────┬──────────────────┘
                                     │  WirePacket (1280 B)
                     ┌───────────────▼──────────────────┐
                     │  CipherSession::decrypt          │ envelope.rs:311
                     │   version → AEAD → replay → dir  │  (all failures →
                     │   → InnerPlaintext               │   DecryptionFailed,
                     │                                  │   silent drop, §6)
                     └───────────────┬──────────────────┘
                                     │  MessageType::TunData
                     ┌───────────────▼──────────────────┐
                     │  [dataplane::reassemble]         │  ← §4.3 rules
                     │   key = (session, direction, id) │
                     │   deadline = 2 s (fixed)         │
                     └───────────────┬──────────────────┘
                                     │  ONE complete, validated inner IP packet
                     ┌───────────────▼──────────────────┐
                     │  SERVER EGRESS GUARD             │ ← §3.3 (D28 at the
                     │   1. source == client addr       │   IP layer)
                     │   2. destination passes policy   │
                     │   3. L4 port != 0 (if parseable)  │
                     │   4. link-local src/dst rejected  │
                     └───────────────┬──────────────────┘
                                     │  write to the server TUN (L3, no fragmenting)
                     ┌───────────────▼──────────────────┐
                     │  server pqtun0 (MTU 1280)        │
                     │  kernel: ip_forward=1 + conntrack│
                     │          + SNAT/MASQUERADE        │
                     └───────────────┬──────────────────┘
                                     ▼  real Internet / LAN
```

### 2.2 The TUN device model, per OS

#### 2.2.1 Linux

- **Device/API:** `/dev/net/tun`; `open("/dev/net/tun", O_RDWR)` then
  `ioctl(fd, TUNSETIFF, &ifreq)`. Verified from the kernel headers:
  `include/uapi/linux/if_tun.h:34` defines `#define TUNSETIFF _IOW('T', 202, int)`,
  `:66` `#define IFF_TUN 0x0001`, `:67` `#define IFF_TAP 0x0002`,
  `:76` `#define IFF_NO_PI 0x1000`, `:81` `#define IFF_MULTI_QUEUE 0x0100`,
  `:39` `#define TUNGETFEATURES _IOR('T', 207, unsigned int)`.
- **`IFF_TUN` alone means L3, pure IP** -- which is what a VPN needs. `IFF_TAP`
  adds a link-layer (Ethernet) header, which is wrong for an IP data plane: the
  inner plane has no Ethernet header and the server has no L2 to strip it.
  **Any design that offers `IFF_TUN|IFF_TAP` for this product is offering the
  wrong device.**
- **`IFF_NO_PI` must be set**, so the 4-byte `struct tun_pi` header is not
  prepended. Otherwise every read needs the prefix stripped and every write
  needs it synthesised.
- **Privilege:** `CAP_NET_ADMIN` to create and configure the interface (`ip
  link`, `ip addr`); the file descriptor itself needs no privilege once opened.
  `TUNSETOWNER` (`if_tun.h:36`) and `TUNSETGROUP` (`if_tun.h:38`) allow handing
  the descriptor to a non-root group, which keeps the *data plane* unprivileged
  while the *route installer* stays privileged.
- **Multi-queue:** `IFF_MULTI_QUEUE` on the first descriptor enables a
  multi-queue device.

#### 2.2.2 macOS

- **Device/API:** `utunN`, obtained through the `com.apple.net.utun_control`
  control socket, **not** through `/dev/tun` ioctls. The `tun` crate 0.8.14
  uses `getpeername()` plus `ioctl(fd, CTLIOCGINFO, ...)` over file descriptors
  0 to 1024 to find the utun descriptor (`src/platform/apple/mod.rs`,
  `src/platform/macos/sys.rs:6`).
- **Naming:** the name must have the form `utunN` with *N* numeric.
- **Privilege:** creating a utun and configuring addresses and routes requires
  **root**.
- **[UNVERIFIED]:** the macOS route/DNS command surface (`route`,
  `networksetup`, `scutil`) and the exact utun creation syscall sequence for a
  non-`tun`-crate implementation were **not** verified in this wave. The
  *design pattern* (journal, install, gate on Ready, reverse-order restore,
  reconcile) is platform-independent and is what §2.7 specifies; the command
  surface needs a spike.

#### 2.2.3 Windows -- Wintun

- **Recommended: Wintun.** A signed L3 TUN driver distributed as `wintun.dll`.
  The `tun` crate's Windows path loads it with
  `wintun_bindings::load_from_path(&config.platform_config.wintun_file)`
  (`tun` 0.8.14 `src/platform/windows/device.rs`), and `Layer::L3` is the
  default: `let layer = config.layer.unwrap_or(Layer::L3);` in `device.rs`, and
  `#[default] L3` on the `Layer` enum in `src/configuration.rs`.
- **The DLL path default is `"wintun.dll"`** -- `PlatformConfig::default()`
  in `src/platform/windows/mod.rs` sets `wintun_file: "wintun.dll".into()`.
  The crate's own doc for `PlatformConfig::wintun_file` carries a security
  note that is directly load-bearing for this design:

  > "Use a custom path to the wintun.dll instead of looking in the working
  > directory. **Security note: It is up to the caller to ensure that the
  > library can be safely loaded from the indicated path.**"

  The crate is telling the caller that the DLL's provenance is the caller's
  responsibility. §9.1 takes that seriously.
- **The crate's Windows path installs more than the device.** Verified in
  `src/platform/windows/device.rs`: it opens the adapter and **creates** it if
  absent (`Adapter::open`, then `Adapter::create` on failure); sets the
  unicast address and, for an IPv4 `destination`, calls
  `sys::set_default_route(luid_value, gw)`; sets the interface metric from
  `config.metric`; sets the DNS servers from `platform_config.dns_servers`
  (`adapter.set_dns_servers`); and sets the MTU. It reports
  `packet_information() == false` -- "wintun does not support packet
  information" -- so there is **no PI header** on the Windows path.
  **Correction to D30's E14:** the claim that the crate "installs **no
  routes**" is **not** accurate for the Windows path in 0.8.14.
- **The crate's Windows IPv6 support is limited.** `Device::address()` finds
  only an IPv4 address, and `Device::set_address()` returns
  `unimplemented!("do not support IPv6 yet")` for an IPv6 address. The default
  `PlatformConfig` also sets `wait_for_ipv6_interface: false` with the note
  "IPv6 interface never appears if IPv6 is disabled on the system".
  **Consequence:** the v6 address and the `::/0` route must be installed
  through the platform address/route APIs, not through the crate -- which
  matches the design's own requirement that routes and DNS are Tunnel's job.
- **The built-in "Tunneling" adapter family** (`IP_ADAPTER` with a tunnel type,
  `iptypes.h`) is an **OS-managed IPsec interface**. It is not a
  general-purpose L3 TUN for a userspace data plane, and using it that way is
  not a supported pattern. **Do not design against it.**
- **Privilege:** creating a Wintun adapter requires **Administrator**; the
  `tun` crate shells out to `netsh` (`src/platform/windows/netsh.rs`) to add the
  adapter.
- **Lifetime:** a Wintun adapter created without the persistence registry key
  is **temporary** and disappears when the last handle closes. That is the
  Windows stale-route failure mode (§2.6.4).

### 2.3 Routing that cannot loop the outer socket

`ip-rule(8)` semantics, verified verbatim from the man page:

> "The RPDB is scanned in order of decreasing priority (note that a lower number
> means higher priority, see the description of PREFERENCE below). The selector
> of each rule is applied to {source address, destination address, incoming
> interface, tos, fwmark} and, if the selector matches the packet, the action is
> performed. ... the RPDB lookup is terminated. Otherwise, the RPDB program
> continues with the next rule."

and, for the `priority` selector:

> "PREFERENCE is an unsigned integer value, higher number means lower priority,
> and rules get processed in order of increasing number."

The default RPDB is: priority 0 -> `local` (table 255); priority 32766 ->
`main` (table 254); priority 32767 -> `default` (table 253).

**The correct formulation -- a destination exception, never a source
exception:**

```sh
# 1. device + point-to-point addresses
ip link set dev pqtun0 up
ip addr add 10.77.0.2/32    dev pqtun0
ip -6 addr add fd00:77::2/128 dev pqtun0

# 2. BYPASS: a host route to the server via the physical NIC, in MAIN.
#    Installed BEFORE any default route.
ip route  replace <SERVER_V4>/32  dev eth0
ip -6 route replace <SERVER_V6>/128 dev eth0

# 3. the tunnel table
ip route  add default dev pqtun0 table 100
ip -6 route add default dev pqtun0 table 100

# 4. policy rules (lower number = higher priority; the first match terminates)
ip  rule add priority 100 to <SERVER_V4>/32  lookup main
ip -6 rule add priority 100 to <SERVER_V6>/128 lookup main
ip  rule add priority 200 lookup 100
ip -6 rule add priority 200 lookup 100
```

**Why it cannot loop:** the outer socket's packets have **destination = the
server**. Rule 100 is a *destination* selector, so it matches and terminates
the lookup into `main`; main's longest-prefix match finds the /32 (or its own
default) via `eth0`, and the packet egresses physically. The `default dev
pqtun0` route lives in table 100, which is only consulted for packets that did
**not** match rule 100. **No source-address selector appears anywhere**, so no
rule can match the tunnel's own outer traffic and divert it into the TUN.

A source-based rule (`not from <tun-addr>`) *would* match the outer traffic
(whose source is the physical address) and would create exactly the loop it is
meant to prevent. This is the defect that made the D25/D26 recipe unusable, and
it is corrected in D30 §8.1 and retained here.

**Additional Linux hardening (recommended, not optional):** `SO_MARK` on the
outer socket (`include/uapi/asm-generic/socket.h:56` defines `#define SO_MARK
36`), plus:

```sh
ip rule add priority 100 not fwmark <MARK> lookup 100
ip rule add priority 101 table main suppress_prefixlength 0
```

`suppress_prefixlength 0` is what stops a *failed* lookup in table 100 from
falling through to main's physical default route -- it makes the tunnel **fail
closed** rather than leak. `ip-rule(8)` documents `suppress_prefixlength
NUMBER` as "reject routing decisions that have a prefix length of NUMBER or
less", and `blackhole` as "the rule causes a silent drop the packet". This
requires `CAP_NET_ADMIN` (plus `CAP_NET_RAW` for `SO_MARK`). Note `not fwmark`
is a *mark* selector, not a source selector, so it does not create the loop.

#### 2.3.1 Windows routing

Route selection is longest-prefix first, then lowest combined metric
(interface metric + route metric). `New-NetRoute` exposes
`-DestinationPrefix`, `-InterfaceIndex`, `-NextHop`, `-RouteMetric`,
`-PolicyStore`, `-Protocol` and **no route-type parameter** -- there is
**no `blackhole` route type on Windows**.

```powershell
# 1. bypass first -- the /32 beats 0.0.0.0/0 by prefix length, regardless of metric
New-NetRoute -DestinationPrefix "<SERVER_V4>/32"  -InterfaceIndex <phys> -NextHop <phys-gw> -RouteMetric 1 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix "<SERVER_V6>/128" -InterfaceIndex <phys> -NextHop <phys-gw> -RouteMetric 1 -PolicyStore ActiveStore
# 2. tunnel defaults
New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex <tun> -NextHop "0.0.0.0" -RouteMetric 0 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix "::/0"      -InterfaceIndex <tun> -NextHop "::"      -RouteMetric 0 -PolicyStore ActiveStore
Set-NetIPInterface -InterfaceIndex <tun> -InterfaceMetric 1
```

`SetIpForwardEntry` / `DeleteIpForwardEntry` (IP Helper) take a
`MIB_IPFORWARDROW`, must set `dwForwardProto = MIB_IPPROTO_NETMGMT`, and
require administrative privileges (`ERROR_ACCESS_DENIED` is documented for
Vista / Server 2008 "when the user lacks the required administrative
privileges"). The modern replacements are `CreateIpForwardEntry2` /
`DeleteIpForwardEntry2` (`netioapi`). **Recommendation:** use
`New-NetRoute` / `Remove-NetRoute` (or the netioapi `*2` functions) for the TUN
routes. *Enabling* IP forwarding on the server is a different operation
(`Set-NetIPInterface -Forwarding Enabled`), not `SetIpForwardEntry`.

**Hard structural requirement:** the **outer socket must live in the same
privileged process as the route installer**. Routing is per-host; a separate
unprivileged process's outer socket would be captured by the tunnel's own
default route -- the loop. The identity seed, the outer socket, the TUN, the
routes, the DNS configuration and the firewall therefore all live in **one**
process (plus an optional control channel).

#### 2.3.2 macOS routing

macOS has no `ip rule`; route selection is longest-prefix within the
interface's route table, and the default route is per-interface. The design
pattern is identical: install a per-destination bypass route for the server
**before** the per-interface default route via the utun.
**[UNVERIFIED]:** the exact `route` / `networksetup` invocations and the metric
semantics. Needs a spike.

### 2.4 DNS

- **Who resolves:** the host's resolver, unchanged. The tunnel does **not** ship
  a resolver (a new always-on, network-exposed attack surface).
- **How DNS is directed into the tunnel:** two mechanisms, and **both** are
  needed in general:
  1. **Routing.** With the default route installed, a resolver address reached
     via the default route goes into the tunnel automatically.
  2. **Explicit resolver configuration.** If the OS resolver is on-link (for
     example a LAN resolver at `192.168.1.1`), the on-link /24 route beats
     `0.0.0.0/0` by prefix length and the DNS **bypasses the tunnel**. The
     resolver must therefore be explicitly pointed at an address reached
     through the tunnel, or the on-link route must be removed or blackholed.
- **Leak prevention: the DNS reconfiguration is all-or-nothing.** A partial
  reconfiguration MUST be rolled back, and a failed reconfiguration MUST
  prevent the tunnel from coming up (or tear it down completely) -- leaving
  the system resolver pointing at the ISP leaks DNS even when the data plane
  is perfectly tunnelled.
  - **Windows:** per-interface DNS via `Set-DnsClientServerAddress`; journal
    the prior value; restore it (or `ResetServerAddresses`) on shutdown.
    `GetAdaptersAddresses` / `Get-DnsClientServerAddress` supply
    `FirstDnsServerAddress`.
  - **Linux:** `resolvectl dns <iface> <addr>` preferred (inverse:
    `resolvectl revert <iface>`); `/etc/resolv.conf` only with an explicit
    opt-in **and** a backup/restore.
- **Documented residuals (not mitigations):** per-application DoH (Chrome),
  NSS/mDNS, and **DNS query volume as a browsing fingerprint**. Under a
  system-wide tunnel the DNS query *volume* is a qualitatively stronger signal
  than the D18 relay's per-destination volume. This is a new residual within
  D22's "reduction, not anonymity" scope
  (`DESIGN_DECISIONS.md:1080-1095`), and it belongs in `THREAT_MODEL.md`.

### 2.5 The kill switch

| Level | Mechanism | Guarantee | Survives process death? |
|---|---|---|---|
| **L1 -- fail-closed routing (always on)** | The `0.0.0.0/0` and `::/0` default routes via the TUN are installed for the **whole process lifetime** and are **never removed while the process lives** -- not on session loss, not on handshake failure, not on rekey. Traffic therefore has nowhere to go except into the TUN, where nobody reads it (the data plane is gated on `Ready`). | While the process is alive, nothing escapes. | **No** |
| **L2 -- crash-survivable firewall (opt-in)** | **Windows:** set the firewall profile's `DefaultOutboundAction = Block`, then add an **explicit allow** rule for the server's address + UDP + server port. **Linux:** `ip rule add priority 110 blackhole` with `ip rule add priority 100 to <server>/32 lookup main` ahead of it. | Survives death; leaves the machine offline until the service is stopped. | **Yes** |
| **L3 -- WFP strict interface scoping (optional)** | Windows Filtering Platform filters with an explicit `NOT_EQUAL` remote-address condition and a filter weight. The NetSecurity cmdlets cannot express a negation. | Per-interface strictness without changing the machine-wide default. | Yes |

**Windows firewall precedence -- verified verbatim** (Microsoft, *Windows
Firewall Rules*):

> "1. Explicitly defined allow rules take precedence over the default block
> setting. 2. **Explicit block rules take precedence over any conflicting allow
> rules.** 3. More specific rules take precedence over less specific rules,
> except if there are explicit block rules as mentioned in 2."
> "Outbound rules follow the same precedence behaviors."
> "Windows Firewall doesn't support weighted, administrator-assigned rule
> ordering."

Two consequences:

- **"block all outbound + allow the server" does NOT work** -- an explicit
  block beats an explicit allow. The working strict form is *default* block +
  explicit allow.
- A **per-interface block on the TUN** would block the host's packets **into**
  the tunnel, i.e. it would break the tunnel. The correct per-interface
  semantics come from the **route**, not the firewall.

**Linux has `blackhole`** (`ip-rule(8)`: "the rule causes a silent drop the
packet"); **Windows does not** (`New-NetRoute` has no route-type parameter).

**Traffic generated before the tunnel is up.** The routes are installed
**before** the handshake begins, so traffic produced between process start and
route installation is a window of exposure. It is the only unavoidable leak
window and it is bounded by "process start to route install", which is
milliseconds. It must be minimised by installing the routes **first**, before
the identity load and the handshake. **Residual, documented.**

**After the session drops:** the routes stay installed, so traffic enters the
TUN and is dropped -- **fail closed**. **After the process exits normally:**
the restore actor removes the routes in reverse order (§2.7). **After a crash:**
§2.6.4.

### 2.6 The outer path-MTU failure and the DF decision

- **Set DF on the outer transport.** Linux: `IP_MTU_DISCOVER` with
  `IP_PMTUDISC_DO` ("Always DF"). Windows: `IP_DONTFRAGMENT` on `IPPROTO_IP`.
  IPv6 outer: DF is implicit -- RFC 8201 Appendix A, verified: "there is no DF
  bit in IPv6 packets".
- **Rationale:** (i) IPv6 makes router fragmentation impossible, so the
  behaviour must be family-symmetric or the observable packet count becomes
  family-dependent; (ii) router fragmentation of the outer packet multiplies
  the observable packet count and creates path state; (iii) with DF, an
  under-MTU path fails **loudly** at the socket instead of silently.
- **Startup gate (mandatory):** the first outer sends must be checked for
  `EMSGSIZE`. `ip(7)` documents: "EMSGSIZE -- Datagram is bigger than an MTU on
  the path and it cannot be fragmented." A path-MTU failure at startup **must
  abort come-up** with a message naming the required PMTU (at least 1308 for an
  IPv4 outer, at least 1328 for an IPv6 outer). Silent degradation is forbidden.
- **Outer PMTUD is the operating system's job.** With DF set, the host's IP
  stack performs RFC 1191 (IPv4) / RFC 8201 (IPv6) discovery on the physical
  path; the resulting ICMP frag-needed / PTB is delivered to the *local* host
  and adjusts the local route's PMTU. **It never enters the tunnel.** The
  tunnel implements no PMTUD machinery for the outer path beyond setting DF and
  surfacing `EMSGSIZE`.

#### 2.6.4 The Windows stale-route failure mode, addressed explicitly

**The failure mode.** The client installs `0.0.0.0/0` and `::/0` via the TUN
adapter and points the system resolver at a tunnelled address. The process is
killed (`kill -9`, power loss, BSOD). The Wintun adapter is temporary and
disappears with the last handle, **but the routes remain in the TCP/IP stack**
pointing at a now-absent interface index, and the DNS configuration still names
the tunnelled resolver. Result: **the host has no working default route and no
working name resolution** -- the machine appears to have lost its network
entirely -- and it stays that way until something cleans the routes up. A
subsequent Tunnel start is the natural cleanup point, but a user who has not
started Tunnel again cannot reach the network to diagnose anything.

**Mitigation (four layers, all required):**

1. **Journal before mutate.** Every artefact is written to a journal file and
   **fsync'd before** the mutation: adapter GUID and name, interface index and
   LUID, each destination prefix + next hop + route metric + policy store, the
   interface's prior `InterfaceMetric`, the prior per-interface DNS server
   list, the prior per-profile `DefaultOutboundAction`, and every firewall
   rule's identity.
2. **Reconcile on start, never accumulate.** At startup, read the journal
   *and* enumerate the live route table; delete every route whose destination
   is `0.0.0.0/0` or `::/0` bound to a **non-existent** interface index, and
   every rule previously installed. Two consecutive starts must not produce two
   default routes.
3. **A route janitor.** A small helper -- or the Windows Service's recovery
   action, `SERVICE_CONFIG_FAILURE_ACTIONS` -- that removes the stale routes if
   the main process dies. Without this the machine stays offline until a human
   runs a command.
4. **An explicit repair command.** `pq-tunnel repair-routes` (and the Linux
   equivalent), documented in the runbook, which performs the reconcile without
   starting a session.

**The honest statement is "reconciled on the next start", not "guaranteed
restored."** This is a *user-impacting* failure, so L2 alone does **not** fix
it -- the firewall keeps the machine *offline* rather than *leaking*, but the
machine is still broken. The journal + reconcile + janitor is what makes it
survivable.

**On Linux:** `ip rule` entries and table-100 routes survive a crash; whether
routes bound to a deleted netdev are removed by the kernel was **not**
verified. The design must not depend on it: the same journal/reconcile/janitor
applies, and `ip rule` staleness must be reconciled explicitly (rule entries are
never auto-removed).

### 2.7 The client lifecycle: journal, install, gate, restore

**Startup** (each step's failure unwinds all prior steps, in reverse):

1. **Reconcile** the journal and the live route table (remove leftovers).
2. Load and validate the identity and the pinned server key (fail closed).
3. Create or open the TUN device; set the MTU to 1280; assign **both** the v4
   (/32) and the v6 (/128) addresses.
4. Install the **bypass** host route(s) to the server -- **before** any default
   route.
5. Install the tunnel default routes `0.0.0.0/0` and `::/0`. **If the v6
   address or the `::/0` route cannot be installed, refuse to come up** -- a
   v4-only "full-system" tunnel is an insecure default. (`--no-ipv6` exists
   only as a loud, documented reduction, and the banner must say "IPv4 only;
   IPv6 traffic is NOT tunnelled".)
6. Apply the kill switch (L1 is already in place by step 5; L2/L3 if
   requested).
7. Configure DNS into the tunnel -- **all-or-nothing**; on failure roll back
   and refuse to come up.
8. Start the session manager; begin the handshake.
9. Only on `ManagerNotification::Ready` (`session_manager.rs:237-239`) enable
   the TUN **write** direction and start reading host-to-TUN packets into the
   tunnel.

**Shutdown** (reverse order, on **every** path: normal return, SIGINT, SIGTERM,
SCM stop, panic):

1. Stop reading the TUN; drain and drop the in-flight reassembly entries
   (zeroized).
2. Restore DNS to its pre-tunnel state.
3. Remove the tunnel default routes.
4. Remove the bypass host route(s).
5. Remove the kill-switch firewall rules, or restore the profile default.
6. Close the session (fire-and-forget `Close`).
7. Close or delete the TUN device.

**Rules:** restoration is **idempotent** ("already gone" is success); it is
**bounded by a deadline** (5 s recommended) after which it proceeds anyway and
the process exits **non-zero** with a loud "network may be broken" message --
restoration must never hang; a **single shutdown actor** owns the ordering (no
ad-hoc `Drop` may mutate routes).

**Session churn must not flap the link.** On rekey or re-establishment the
routes, the TUN and the DNS **stay up**; only the crypto session is rebuilt.
Tearing the link down on every rekey would emit a distinctive lifecycle
fingerprint -- and D22 concedes *volume*, not link-state transitions
(`DESIGN_DECISIONS.md:1085-1086`).

### 2.8 ICMP and IPv6 neighbour discovery

#### 2.8.1 Handled locally at the tunnel boundary -- never tunnelled

| Packet | Why it must not be tunnelled | Mechanism |
|---|---|---|
| IPv6 **Router Solicitation** (133) | The client installs its routes explicitly; it needs no RA. | `net.ipv6.conf.<tun>.accept_ra = 0` (Linux) / `DisableRouterDiscovery=1` (Windows). Belt-and-braces: an overlay-level drop filter. |
| IPv6 **Router Advertisement** (134) | An RA would install a competing default route and prefix on the client, overriding the tunnel's routes. | same |
| IPv6 **Neighbour Solicitation / Advertisement** (135/136) | The inner link is **point-to-point** (a /32 and a /128, with `default dev pqtun0` and **no** `via`), so the client has **no on-link neighbours** and must emit **no** NDP for the tunnelled path. A tunnelled NS would leak a link-local scope and invite the proxy-NDP attack class (RFC 4861 §7.2.5). | same, plus the link-local drop filter below |
| IPv6 **Redirect** (137) | same | same |
| IPv6 **MLD** (143-147) | link-local multicast | same |
| **ARP** | not an IP packet; a TUN is L3, so ARP never appears on it | n/a |
| **IPv4 IGMP** | link-local multicast | filter |
| Any inner packet whose **source or destination is link-local** (`fe80::/10`, `169.254.0.0/16`) | A link-local address is meaningful only on its own link; carrying it across the tunnel creates a cross-link address-confusion surface. | **drop at the tunnel boundary, both directions**, before the packet enters the overlay. This also covers the TUN's own auto-assigned `fe80::` address, which the kernel would otherwise try to use as a source. |

**This is the concrete answer to "NDP must not be tunnelled":** the inner link
is point-to-point *by construction* (a /32 and a /128, with `default dev
pqtun0` and **no** `via`), so the host has no next-hop to resolve and emits no
NDP for the tunnelled path. The only NDP the host could emit is for its *own*
TUN address, which the kernel answers locally. To be safe against a stack that
ignores `accept_ra=0`, the tunnel **additionally** drops all five NDP message
types and all link-local-sourced or link-local-destined packets at the overlay
boundary, on both ends.

The alternative -- assigning a prefix (for example a /64) so that on-link
reachability exists -- requires the server to be an **NDP proxy** (RFC 4861
§7.2.5) *and* an ARP proxy. That is a larger feature and is explicitly out of
v1.

#### 2.8.2 Tunnelled end to end

Everything else is just an inner IP packet and rides the same overlay:

- **ICMPv4:** echo request/reply (8/0), destination unreachable (3) codes
  0/1/2/3/5/8/9/10/11/12/13, time exceeded (11), parameter problem (12),
  timestamp (13/14), address mask (17/18), router discovery (9/10 -- rare, and
  filterable).
- **ICMPv6:** echo request/reply (128/129), destination unreachable (1) codes
  0/1/2/3/4/5/6, time exceeded (3), parameter problem (4), plus any
  extension-header ICMPv6.

This is a **major functional improvement over the D18 relay**, which carries no
ICMP at all (`DESIGN_DECISIONS.md:917`: "no ICMP / unreachable feedback in
v0.2").

#### 2.8.3 PMTUD inside the tunnel -- there is none, and that is correct

The tunnel fragments the inner packet itself, so the tunnelled link's MTU is
**known and static**: it is the TUN interface MTU, set locally on both ends.
The host's stack learns it from the interface, not from a PTB.

- **The tunnel MUST NOT synthesise ICMP PTB or frag-needed.** It is a link, not
  a router; the inner MTU is a local parameter.
- **Equal inner MTUs on both ends is a hard configuration invariant.** If the
  client's TUN is 1500 and the server's is 1280, the server would have to
  IP-fragment the 1500-byte packet it receives -- a second, conflicting
  fragmentation layer. The tunnel therefore requires
  `inner_mtu(client) == inner_mtu(server)`. The MTU is **not negotiated**
  (PROTOCOL_SPEC §7.5, "SHOULD avoid depending on ... specific MTU sizes";
  D19 keeps the data plane out of the handshake). Both sides log their value at
  startup; a mismatch is a configuration error, detected and reported loudly.
- **The inner MTU and the outer path PMTU are different things** and must not be
  conflated. The inner MTU bounds the inner IP packet; the outer PMTU bounds
  the UDP record. The tunnel's own fragmentation bridges them.

---

## 3. The server path

### 3.1 The forwarding model: the choice and its justification

| Option | Mechanism | Privilege | NAT | Statefulness | ICMP | Throughput | Portability | 1:1 fit | D28 fit |
|---|---|---|---|---|---|---|---|---|---|
| **(a) Server TUN + kernel forwarding + NAT** | write the inner packet into the server's TUN; the server kernel routes it out the physical NIC | `CAP_NET_ADMIN` / Administrator | kernel conntrack SNAT | full L3/L4 stateful | kernel-generated, correct | kernel-fast | Linux and Windows both | **perfect** (one client = one inner address = one NAT) | the policy is applied in the tunnel code, before the write |
| **(b) Server TUN + userspace routing** | the tunnel implements the routing decision | same | hand-written | partial | hand-written | slower | same | poor | same |
| **(c) `SOCK_RAW` IP forwarding in userspace** | craft reply IP headers (`IP_HDRINCL`) | `CAP_NET_RAW` | hand-written | none | hand-written | one userspace copy per packet | IPv4 only on Windows (`IP_HDRINCL` cannot carry IPv6) and requires admin | poor | the policy must be re-implemented |
| **(d) Userspace TCP/IP stack + raw socket** | a full stack in userspace | `CAP_NET_RAW` | hand-written | hand-written | hand-written | worst | portable in principle | poor | worst -- the policy layer must live inside the stack |

**Recommendation: (a).**

- **Privilege:** the server is operator-controlled; a system-wide VPN server
  inherently runs privileged. (a) needs only the privilege the TUN itself
  needs.
- **NAT correctness:** the 1:1 model wants the client to hold a private address
  and the server to translate. Kernel conntrack gives **stateful** SNAT with a
  correct reverse mapping, correct TCP MSS clamping, and correct rewriting of
  the original datagram embedded in ICMP errors -- all of which a hand-written
  NAT gets wrong in ways that only show up under load. (a) is the only option
  where "correct" is the default.
- **Statefulness:** conntrack gives the kernel the L4 state it needs to
  distinguish a legitimate reply from a spoofed one and to generate the right
  ICMP.
- **ICMP handling:** the server's kernel generates destination-unreachable and
  port-unreachable natively and forwards ICMP errors back through the tunnel.
  (c) and (d) must synthesise them, correctly, including the
  embedded-original-datagram rewriting that conntrack does for free.
- **Throughput:** (a) keeps the data path in the kernel; (c) costs a userspace
  copy per packet; (d) costs a full stack traversal.
- **Portability:** (a) works on Linux (`net.ipv4.ip_forward=1`, nftables `nat` /
  `masquerade`) and Windows (`Set-NetIPInterface -Forwarding Enabled`,
  `New-NetNat -InternalIPInterfaceAddressPrefix`).
- **D28 consistency:** the destination policy must be evaluated **in the
  tunnel's code, before the packet is written into the server's TUN** -- the
  server's kernel would otherwise happily route to `127.0.0.1` or
  `169.254.169.254`. That is exactly where D28 places the check ("evaluated
  *before any socket is created*", D28 §0).

**(b), (c) and (d) are rejected for v1:** each re-implements routing, NAT,
fragmentation, checksums, neighbour discovery and PMTU -- a large new attack
surface in a security-critical path. **(c) is retained as a documented fallback
only** for deployments that cannot run kernel forwarding (a container without
`NET_ADMIN`, a Windows host without the forwarding stack). It is explicitly
not the default.

### 3.2 What happens to `forward.rs`

**The current path (D18 relay, `MessageType::Data`) is the *relay* path, not
the TUN path.** `pq-tunnel-bin/src/forward.rs` today:

- `Forwarder` holds a **per-(session, destination) connected-UDP-socket pool**:
  `sockets: HashMap<([u8;8], SocketAddr), ForwardEntry>` (`forward.rs:85-87`).
  The comment at `forward.rs:5-11` states the design intent: "a connected
  socket's bound source port *is* `dest.port`, so reply datagrams emerge from
  the exact address the client relay recorded".
- `handle()` decodes the D18 relay frame (`decode_relay`, `forward.rs:134`),
  applies the egress guard (`forward.rs:148`), then either echoes
  (`forward.rs:159-177`) or sends the datagram on a pooled connected UDP socket
  (`forward.rs:192`).
- `reply_reader` re-labels replies with the relay header and returns them via
  `ServerAppCommand` (`forward.rs:918`).
- Caps: `PER_SESSION_CAP = 128`, `GLOBAL_CAP = 512`, `IDLE_TTL = 60 s`
  (`forward.rs:61-65`).

**Explicitly, for the TUN path:**

| Component | Verdict | Detail |
|---|---|---|
| The **socket pool** (`forward.rs:87`, `prune_and_insert` `:241`, `reply_reader` `:918`) | **REMOVED** | The server's kernel does the forwarding. There is no per-destination state, no source-port binding, no LRU, and no ephemeral-port exhaustion risk. This *eliminates* D28 §3's gap 3 (server ephemeral-port exhaustion) outright. |
| The **relay framing** (`relay.rs`) | **UNCHANGED, kept for `MessageType::Data`** | `family(1) ‖ addr(4\|16) ‖ port(2) ‖ len(2) ‖ datagram` (`relay.rs:7-14`); `MAX_DATAGRAM_V4 = 1245 - 9 = 1236`, `MAX_DATAGRAM_V6 = 1245 - 21 = 1224` (`relay.rs:41-48`). It remains the D18 diagnostic and conformance path. |
| The **egress guard's policy and ordering** (`forward.rs:382-409`, `:470-478`) | **REUSED, input adapted** | `egress::deny_reason` (`forward.rs:470-478`) becomes `deny_reason(&IpAddr, ...)`: the IP-layer rows apply directly; the port-0 rule needs L4 parsing. Same ordering -- the exact metadata hosts are evaluated **before** the range rules (`forward.rs:455-466`); same IPv4-embedded normalisation (`forward.rs:531-536`); same bounded per-rule counters (`EgressGuard`, `forward.rs:580`) and the same power-of-two log sampling (`should_log`, `forward.rs:644-646`). "No per-destination logging" is preserved. |
| `ServerAppCommand` (`session_manager.rs:252-258`) | **REUSED** | The server's TUN reader emits `ServerAppCommand { sid, payload }`; the driver encrypts it. Its `sid` attributes a return packet to a session. |
| `ManagerEvent::Send { packets: Vec<WirePacket>, peer }` (`session_manager.rs:193-198`) | **REUSED for bursts** | It already exists (used for the handshake fragments). A large inner packet needs a **multi-record** outbound, so this is the right channel. |
| `app_outbound` (`session_manager.rs:707-724`) | **EXTENDED** | Today it zero-pads a payload of at most `PAYLOAD_LEN` into one slot and encrypts it as `MessageType::Data`. A TUN burst needs `app_outbound_burst(sid, records) -> ManagerEvent::Send { packets, peer }`. |
| `SessionLimits::default().max_sessions = 64` (`session_manager.rs:148`) | **MUST become 1 for 1:1** | 64 is a multi-tenant capacity number. A 1:1 server must run with `max_sessions = 1` and refuse a second client **loudly** -- a capacity decision, not a peer-input failure, and the existing session must be untouched. |

### 3.3 The egress policy at the IP layer (D28, adapted)

**The shipped guard is a deliberate minimal subset.** D28 §0 "Shipped" lists
exactly twelve rules: `port_zero`, `v4_loopback`, `v6_loopback`,
`v4_unspecified`, `v6_unspecified`, `v4_multicast`, `v6_multicast`,
`v4_broadcast`, `metadata_imds_v4`, `metadata_alibaba_v4`, `metadata_aws_v6`,
`metadata_gcp_v6` (`forward.rs:382-409`). **Not** enforced today:
`169.254.0.0/16`, `fe80::/10`, `100.64.0.0/10`, `::ffff:0:0/96` as a range,
6to4/Teredo/NAT64, subnet-directed broadcast, `240.0.0.0/4`, operator-LAN DNS.

D28 itself defers the raw-IP policy to exactly this milestone (D28 §0
"NOT shipped": "The raw-IP / TUN egress policy ... is deferred to the TUN
milestone").

**For the TUN path, the policy applied to the inner packet's destination is:**

1. The **full D28 §1.1 table**, evaluated at the **IP layer**: rows 1-4 (the
   hard floor: `0.0.0.0/8`, `127.0.0.0/8`, `::1/128`, `::/128`), rows 8/9
   (link-local `169.254.0.0/16`, `fe80::/10`), rows 10/11 (multicast), row 16
   (`100.64.0.0/10`), rows 18/19/20 (6to4/Teredo/NAT64), rows 21/22/23
   (broadcast and `240.0.0.0/4`), and the exact metadata hosts (rows 12/13/15)
   as hard denies evaluated **before** the range rules.
2. The **port-0** rule, which now requires **L4 parsing** of the inner TCP/UDP
   header.
3. Rows 5-7 (RFC 1918) and row 14 (ULA) stay **ALLOW** by default -- a VPN
   that cannot reach `10.x` is not a VPN. The metadata carve-outs are what
   make that safe.
4. **Ordering matters** and is the security property: exact hosts, then range
   rules, then allow-by-default.

**One D28 inconsistency to settle at the IP layer.** D28 §1.1 row 17 says
`::ffff:0:0/96` (IPv4-mapped) is **DENY with no override**. The **shipped code
does the opposite**: `deny_ipv6` normalises a v4-mapped address to IPv4 and
then applies the v4 rules (`forward.rs:531-536`), and the test asserts
`::ffff:10.0.0.1 -> None` (allowed) while `::ffff:127.0.0.1 -> V4Loopback`
(`forward.rs:785-818`). D28 §0 acknowledges row 17 is "not enforced". **The
recommendation is to normalise** -- apply the v4 rules to the embedded address
-- because normalising is *more precise* (it correctly permits a mapped public
address while blocking a mapped loopback), and because an outright denial of
all mapped addresses would break legitimate dual-stack traffic. **This
contradicts D28 row 17 and needs a D28 amendment.** The same normalisation must
be applied to the **source**-address check.

**The L4 port-0 rule and IP fragments.** The port rule needs the inner TCP or
UDP header. For an inner IP **fragment** that is not the first fragment there
is no L4 header to parse, so the port rule cannot be evaluated on it. The
design therefore evaluates the port rule **only on datagrams that carry a
parsable transport header** (the first fragment of an IPv4 datagram, or any
IPv6 datagram whose Fragment header has offset 0), and skips it otherwise. The
source and destination checks (§3.4, §3.3.1) apply to **every** inner packet,
fragment or not.

### 3.4 Source-IP assignment and anti-spoofing

**Assignment.** The client is assigned a **fixed, deployment-local** inner
address pair, identical on both ends, configured out of band (like the pinned
server key):

```
client: 10.77.0.2/32    and   fd00:77::2/128
server: 10.77.0.1/32    and   fd00:77::1/128
```

- **Not negotiated.** D19 discipline: the data plane's parameters are
  deployment-local, never handshake state. Negotiating the address would put it
  in the handshake transcript and change the KDF binding for no security
  benefit (the address is not secret). 1:1 means exactly one assignment.
- **Point-to-point (/32 and /128)** means no on-link neighbours, hence no ARP
  and no NDP for the tunnelled path (§2.8.1). A prefix assignment would require
  the server to be an NDP/ARP proxy -- out of v1.

**Acceptance rule (server, mandatory).** The inner source address MUST equal
the client's assigned address for that family. **Any other source is silently
dropped.** The check:

- is performed in the **tunnel server's code, before the write into the
  server's TUN** -- *not* delegated to the kernel, because the kernel's
  `rp_filter` is a reverse-path filter, not a forward-source validator, and
  because a hard security property must not rest on a best-effort kernel
  control;
- is applied to **every** inner packet, including IP-level fragments;
- is normalised first (a v4-mapped source is unwrapped to v4 before the
  comparison), consistently with §3.3.

**Normative references:** RFC 1812 §5.3.8 (source address validation) and
RFC 2827 / BCP 38 (ingress filtering). In the D18 socket model there is nothing
to spoof -- the source is the server's own ephemeral address. In the raw-IP path
the client chooses the source of every packet, so without this check the server
becomes a reflection/amplification gadget and a pivot into RFC 1918 space.

**Kernel-side belt and braces (defence in depth, *not* the primary control):**
Linux `net.ipv4.conf.<tun>.rp_filter = 1` plus an nftables rule
`-i <tun> -s <client_addr> -j accept; -i <tun> -j drop`; Windows a
`New-NetFirewallRule` restricted to the TUN interface with `-RemoteAddress`
limited to the client address, plus `Set-NetIPInterface -Forwarding Enabled` on
the server's egress interface.

### 3.5 Return-path mapping

Under the **default stateful NAT**, the server's kernel rewrites the client's
`10.77.0.2` to the server's egress address on the way out and reverses it on
the way back; conntrack owns the mapping. A return packet therefore reaches the
server's TUN with source = the remote host and destination = the client's inner
address (post-de-NAT), and the tunnel forwards it to the single session. **The
tunnel itself keeps no per-client address map under NAT.**

Under the **routed-assignment** operator option (no NAT; the operator owns
prefix space), the server needs a route for the client's prefix via the TUN, and
the tunnel attributes the TUN-read packet to a session via
`ServerAppCommand.sid` -- with 1:1 there is exactly one session, so no map is
needed either way.

---

## 4. The inner-packet framing and the tunnel's own fragmentation

### 4.1 The overlay header

**The inner packet's own IP header is authoritative.** There is **no separate
length prefix** that acts as the authority:

- For IPv4, the **Total Length** field (bytes 2..4, big-endian, including the
  header) is authoritative -- RFC 791 §3.1.
- For IPv6, the total is `40 + Payload Length` (bytes 4..6, big-endian) --
  RFC 8200 §3.

**Why the header and not an explicit prefix:**

1. The **host's own IP stack** honours the header's length field. A buffer
   whose length disagrees with its own header is corrupt; writing it to the TUN
   injects a malformed packet into the host's stack.
2. An explicit prefix creates **two** length authorities that can disagree --
   the classic "which one wins?" bug.
3. The existing `ip_packet_len()` helper already implements exactly this rule
   (`pq-tunnel-bin/src/packet_len.rs:13-39`): IPv4 -> total in [20, buf_len];
   IPv6 -> `40 + payload_len <= buf_len`; a version nibble outside {4, 6} -> 0.
   It has **no production caller** today (only its own tests and the
   `relay_overlay` fuzz sub-target), so it becomes a *network-facing* parser
   when the TUN lands -- which is exactly why it needs a dedicated fuzz target
   first.

**But a length field in the overlay is still required**, for a different
reason: the receiver must know the reassembled size **before** it allocates, and
it must detect a length/count inconsistency **before** reassembly. So
`ip_total_len` is a **capacity claim**, cross-checked against the header at
completion -- never the authority.

**Overlay header (20 bytes, inside the AEAD ciphertext):**

```
 off  size  field            semantics
   0    1   overlay_version  MUST be 0x01; other values -> drop
   1    1   frag_index       0-based; 0 <= idx < frag_count
   2    1   frag_count       1 <= count <= 54
   3    1   flags            all bits reserved, MUST be 0
   4    2   ip_total_len     BE u16: total length of THIS inner IP packet
   6    2   reserved         MUST be 0
   8    8   datagram_id      BE u64: per-(session, direction) sender-assigned
  16    4   datagram_crc     BE u32: CRC-32 of the WHOLE inner IP packet
  20 1225   ip_fragment      this fragment's slice of the inner IP packet
```

Derived constants (compile-time asserted):

```
OVERLAY_HEADER_LEN = 20
FRAG_CAP           = PAYLOAD_LEN - 20 = 1225
MAX_FRAG_COUNT     = ceil(65535 / 1225) = 54
MAX_IP_PACKET_LEN  = 65535
```

**Deltas from D30 §3.3, and why:**

| D30 | This design | Reason |
|---|---|---|
| 14-byte header, `FRAG_CAP = 1231` | 20-byte header, `FRAG_CAP = 1225` | +6 B = 0.48 % of the slot; buys a u64 id, a CRC and alignment. The fragment count stays 54; the records per datagram at MTU 1280 stays 2; the efficiency stays 50 %. |
| `datagram_id` u32 | **u64** | A u32 exhausts in about 24 h at 1 Gbit/s (§4.5). |
| `datagram_tag` = the first 32 bits of SHA-256 over **fragment 0** | **`datagram_crc` = CRC-32 over the whole packet** | A fragment-0-only tag cannot detect splicing in any *later* fragment. A whole-packet CRC detects it anywhere. |
| -- | `reserved` u16 + an aligned u64 | Future overlay revisions without re-laying-out the header. |

### 4.2 The sender's rules

- **S1 -- burst serialisation.** The fragments of one inner packet are emitted
  as a **contiguous burst**: no other *data* datagram may be emitted between
  them. Cover packets MAY be interleaved -- D19's cover grid is not negotiable
  and is not a data-plane concern. `CoverScheduler::on_deadline` yields at most
  one emission per deadline and reschedules from "now", so a missed deadline
  produces a single catch-up packet, never a burst.
- **S2 -- fragment-length convention.** All fragments except the last carry
  exactly `FRAG_CAP` bytes; the last carries
  `ip_total_len - (frag_count-1)*FRAG_CAP` bytes in [1, `FRAG_CAP`]. **The
  length is therefore fully derivable** -- no per-fragment length field is
  needed, and a receiver that receives a short non-final fragment detects the
  violation immediately.
- **S3 -- replay-window span check.** Before emitting fragment *k*, the sender
  MUST verify that `send_counter(current) - send_counter(first fragment of this
  burst) < WINDOW_BITS`. If not, the sender **aborts the burst and drops the
  whole inner packet** (fail-secure, silent). The sender owns the counter, so
  the check is exact and free. **This is what guarantees the burst is always
  inside the transport's replay window.**
- **S4 -- id non-reuse.** `datagram_id` MUST NOT wrap within a session. On
  exhaustion (the u64 counter reaching its limit) the session transitions to
  rekey, exactly like the existing `CloseReason::NonceExhausted` path
  (`session_manager.rs:172`, `envelope.rs:269-273`).

### 4.3 The receiver's rules

Let `E` be the entry for `(session, direction, datagram_id)`.

| Situation | Rule |
|---|---|
| New datagram (no `E`) | Validate the overlay header (§4.5) **before any allocation**. Create `E` with `frag_count`, `ip_total_len`, an empty received-bitmap, a buffer of exactly `ip_total_len` bytes, and a deadline. Accept the fragment. |
| Out-of-order (a later fragment first) | Accepted; `E` is created by that fragment. The IP-header check is deferred until fragment 0 arrives. **Completion requires fragment 0.** No packet is ever written without fragment 0. |
| Duplicate, **identical bytes** | **Ignored** (no state change). Counted in a metric. This is the overlay layer's own duplicate suppression. |
| Duplicate, **different bytes** | **Poison** `E`: it is marked dead, nothing is ever written for this id, and the entry is dropped at its deadline. The new fragment is discarded. Fail-secure. |
| `frag_count` / `ip_total_len` / `datagram_crc` mismatch against `E` | **Collision** (id reuse) -> **poison** `E`, discard the new fragment, and do **not** create a new entry for that id. Fail-secure. |
| Poisoned `E` | Every subsequent fragment for that id is discarded. |
| Missing fragment | The entry is dropped at its deadline; **nothing is written**. There is no NAK and no retransmission (§4.7). |
| Replayed *transport* packet | Never reaches this layer: the AEAD replay window (`replay.rs:37`, `WINDOW_BITS`) rejects a repeated counter **before** the plaintext is produced (`envelope.rs:347-357`). A duplicate at the overlay layer with a *new* counter is the "Duplicate" row above. |
| Assembled length not equal to the header's declared length | **Poison; write nothing.** |

**Completion** (all must hold):

1. All `frag_count` indices are present.
2. Fragment 0 is present and its IP header is valid (§4.5).
3. The assembled length is exactly `ip_total_len`.
4. The last fragment's length is exactly
   `ip_total_len - (frag_count-1)*FRAG_CAP`; every other fragment's length is
   exactly `FRAG_CAP`.
5. `CRC-32(assembled)` equals the `datagram_crc` carried in every fragment.

**Only then** is the buffer written to the TUN -- **as a single write of exactly
`ip_total_len` bytes**. There is no code path by which a partial or unvalidated
buffer reaches the operating system's IP stack.

### 4.4 The fragment-header validation, and the strict caps

**Validation, on every fragment, before any allocation:**

```
overlay_version == 1
flags == 0 and reserved == 0
1 <= frag_count <= 54
0 <= frag_index  < frag_count
20 <= ip_total_len <= 65535
(frag_count - 1) * 1225  <  ip_total_len  <=  frag_count * 1225
```

The last line is the exact inequality that ties the fragment count to the packet
length: `frag_count == ceil(ip_total_len / FRAG_CAP)`. A violation is a protocol
violation -> drop the fragment; if the entry exists, poison it.

`ip_total_len` is validated **before** the buffer is allocated, so the
allocation size is always known and bounded.

**The assembled-buffer cross-checks** (the IP header remains the authority):

| # | Check |
|---|---|
| C1 | The length `L` declared by the assembled IP header equals `ip_total_len` exactly. |
| C2 | `L >= 20` (IPv4) or `L >= 40` (IPv6). |
| C3 | IPv4 structural validity: the version nibble is 4, IHL >= 5, and `4*IHL <= L`. |
| C4 | IPv6 structural validity: the version nibble is 6. |
| C5 | `frag_count == ceil(L / FRAG_CAP)` -- the same inequality as above, checked against the header-derived length. |
| C6 | The first fragment alone contains the whole IP header: the header length (`4*IHL` for IPv4, 40 for IPv6) is at most `FRAG_CAP` (1225) -- always true -- and the header lies entirely within fragment 0. |

**Strict caps:**

| Bound | Value | Derivation |
|---|---|---|
| **Bytes per entry** | exactly `ip_total_len`, at most 65 535 | allocated only after `ip_total_len` is validated; no over-allocation |
| **Entries per session** | **256** | 1:1 means one session. 256 concurrent in-flight datagrams is far above the in-flight count at any realistic rate. |
| **Bytes per session (and per process -- one global counter)** | **16 MiB** (16 777 216 B) | 256 x 65 535 = 16 776 960 B, so the byte cap binds *at* the entry cap in the worst case, and far earlier in the realistic case (a 1280-byte datagram costs 1225 B of buffer, so 16 MiB holds about 13 700 datagrams). |
| **Fragments per datagram** | **54** | `ceil(65535 / 1225)` |
| **Records per datagram (typical)** | 2 at inner MTU 1280 or 1500 | `ceil(1280/1225)`, `ceil(1500/1225)` |
| **Fragment-header overhead per record** | 20 B | §4.1 |

**On reaching a cap:** new datagrams are **dropped** (fail-secure) and existing
entries are **not** evicted. Evicting a live entry would let a lost fragment be
spliced into a later datagram.

### 4.5 The identifier scheme and the collision-freedom proof

**Scheme.** `datagram_id` is allocated by the **sender** from a
per-**(session, direction)** `u64` counter that starts at 0 and increments by
exactly 1 per **datagram** (not per fragment). It is **independent of, and not
derivable from, the AEAD `packet_nonce`**. It is carried **inside the AEAD
ciphertext** (overlay offset 8), so it is authenticated.

**Why not the AEAD counter.** The AEAD counter is shared between data and
cover (`envelope.rs:138`, `:257-300`: one `send_counter` for both), so a cover
packet can be emitted between fragment *k* and *k+1*. Worse, a receiver that
sees fragment 3 first **cannot compute the counter of the unseen fragment 0**,
so a counter-derived key is not computable by the receiver. And a
counter-derived deadline would couple a correctness-critical timer to a
user-tunable metadata knob (`--cover-mbps`) -- at a high cover rate a
2x-cover-interval deadline becomes shorter than any RTT, and reassembly would
fail *always*.

**Proof of collision-freedom.**

> **Claim.** Within one session and one direction, no two distinct datagrams
> share a `datagram_id`.
>
> *Proof.* The sender's allocator holds a counter `next_id` initialised to 0 at
> session establishment. `allocate()` returns the current value and then
> increments the counter by exactly 1. The counter is **never decremented,
> never reset and never reused** within the session. The allocator **refuses**
> to allocate once the counter reaches its exhaustion limit and instead
> terminates the session with `CloseReason::NonceExhausted` -- it never wraps.
> Hence the sequence of allocated ids is the strictly increasing sequence 0, 1,
> 2, ..., N with all elements distinct. ∎
>
> **Corollary 1 (no cross-datagram splicing).** The receiver's table is keyed
> by `(session, direction, datagram_id)`. Two distinct datagrams have distinct
> ids, so their fragments occupy distinct entries and can never be merged. The
> only residual is a *sender-side* reuse of an id for two different packets;
> the sender's counter forbids it, and the `datagram_crc` independently detects
> it if the sender is buggy. ∎
>
> **Corollary 2 (no cross-session collision).** The reassembly table is
> **per-session** and is destroyed when the session closes. A new session
> starts its id counter at 0, but its table is a different object, so ids from
> different sessions are never compared. The session id is also bound into the
> key schedule (`envelope.rs:189-192`), so two sessions never share keying
> material. ∎
>
> **Corollary 3 (no wrap).** `next_id` is a `u64`. At the maximum plausible
> tunnel rate of 1 Gbit/s = 97 656.25 records/s, a 1280-byte inner packet
> consumes 2 records, so 48 828.125 datagrams/s. 2^64 / 48 828.125 = 3.778e14
> seconds = **about 1.2e7 years** (about 12 million years). The exhaustion path
> is unreachable in practice, but it is **enforced** (mirroring
> `codec::is_counter_exhausted`, `codec.rs:134-136`), not assumed. ∎

For comparison, the same calculation with a **u32** id gives
2^32 / 48 828.125 = 87 964 seconds = **about 24.4 hours** at 1 Gbit/s. That is
why the id is a u64.

### 4.6 `datagram_crc` -- a consistency check, not a security boundary

**The security boundary is the AEAD** (`envelope.rs:257-301`). The AEAD
authenticates each *record*, not the *datagram* that spans several records, so
it cannot by itself detect fragments of two different datagrams being
assembled together. The CRC's job is exactly that: guarantee that a datagram
assembled from fragments of two different inner packets is **detected** rather
than written to the host's stack.

- It is computed by the sender over the whole inner packet **before**
  fragmenting, carried identically in every fragment, and recomputed by the
  receiver over the assembled buffer before the write.
- A mismatch between fragments of the same datagram, or between the CRC and the
  assembled buffer, **poisons** the entry.
- **CRC-32 is an error-detecting code, not a cryptographic primitive.** It is a
  standard, well-defined code; nothing is invented here, and it is not relied
  on for any security property. It needs **no new dependency** -- `sha2` is
  already a core dependency, but a CRC is the right tool: the threat is a
  *sender bug*, not an adversary.

### 4.7 No tunnel-layer retransmission, and its cost

There is no NAK and no retransmission. Rationale: a NAK is a *new observable* (a
hole in the packet stream), and D22 fixes the metadata target as leakage
*reduction* (`DESIGN_DECISIONS.md:1082-1084`). The cost must be documented
rather than hidden:

- **Loss amplification.** An inner packet split across *N* records is lost if
  any record is lost. At a path loss rate *p*, an *N*-record datagram is lost
  with probability approximately *N*p*. For a 1280-byte inner packet (*N* = 2)
  at *p* = 0.1 %, that is about 0.2 % -- a 2x amplification of the effective
  loss rate, which TCP then has to repair. §1.5.
- **Mitigation by MTU choice:** a TUN MTU of 1225 would make a full-MSS packet
  a single record, but it is non-conformant (RFC 8200 §5) and impossible for
  IPv6 on Linux. The amplification is therefore accepted, not designed away, in
  v1.

### 4.8 The reassembly deadline, and why it is independent of the cover cadence

**The deadline is an implementation parameter (D7) derived from a latency
budget.** It is **never** derived from `--cover-mbps`. Coupling a
correctness-critical deadline to a user-tunable metadata knob is the defect
D30 §14.2 W6 already identified in the earlier draft (at a high cover rate a
2x-cover-interval deadline becomes shorter than any RTT, so reassembly would
fail *always*).

**What the deadline bounds.** The fragments of a datagram are emitted as one
burst (S1), so their arrival spread is the path's *reordering and jitter*
spread, not the round-trip time. The deadline must exceed the worst-case
reordering delay of the target path and must be short enough to release memory
promptly.

**Upper bound from the precedent.** RFC 791 and RFC 8200 §4.5 use 60 s for
IP-level fragment reassembly. The tunnel's deadline must be **stricter** than
that: the host stack's timer is the outer safety net, and the tunnel must not
hold a datagram longer.

**The binding constraint is the replay window, and it is rate-dependent.** The
receiver's replay window is 1024 counters (`WINDOW_BITS`, `replay.rs:37`). The
horizon -- the wall-clock span those 1024 counters cover -- is
`1024 / (record rate)`:

| Aggregate record rate | Records per second | Replay horizon |
|---|---|---|
| Default cover alone (195.3125 pkt/s, 2 Mbit/s) | 195.3125 | **5.24 s** |
| 10 Mbit/s of tunnel payload | 976.5625 | **1.05 s** |
| 100 Mbit/s of tunnel payload | 9 765.625 | **105 ms** |

**Therefore the effective reassembly deadline is `min(configured, replay
horizon)`.** A configured deadline longer than the horizon is not "safer" -- it
is unreachable, because the late fragment is rejected by the replay window
anyway and the datagram is lost.

**Two consequences that must be recorded:**

1. **A fixed 2 s deadline is only achievable below about 5.2 Mbit/s of
   aggregate record rate** (1024 counters / 2 s = 512 counters/s = 512 x 1280 B
   x 8 = 5.24 Mbit/s). Above that, the replay horizon binds first.
2. **A deployment that needs a 2 s deadline at a high tunnel rate must raise
   `WINDOW_BITS`.** 2 s at 100 Mbit/s needs about 19 532 counters, so 32 768
   (a 4096-byte bitmap per session per direction) would suffice. That is a
   change to a protocol-relevant parameter and belongs in the same change set as
   the overlay.

**Recommended default: 2 s** (an implementation parameter, D7). It is far
stricter than the 60 s IP precedent, it bounds the in-flight memory at
(tunnel byte rate) x 2 s -- which the 16 MiB cap then clamps -- and it is a
*default*, not a derived constant. **It is independent of the cover cadence.**

**Cleanup.** The deadline is enforced by the session manager's existing `tick()`
path (`session_manager.rs:807`), so no new timer machinery is needed. Expired
entries are dropped and their buffers zeroized. A session close drops the whole
table.

### 4.9 IP-level fragments inside the inner plane

**This is a correction to D30, and it is load-bearing.**

D30 §2.2 item 4, its invariant I9, its fail-secure matrix and its gap M-M all
require the tunnel to **reject** inner IP-level fragments (IPv4 MF/offset, IPv6
Fragment header). **That is wrong.** IPv4 IP-level fragmentation is *routine*
on a TUN: when the host's IP stack sends a datagram larger than the TUN MTU to
an off-link destination, it fragments the datagram itself and writes each
fragment to the TUN. Rejecting them breaks large UDP transfers and any
TCP transfer that exceeds the inner MTU.

**The correct rules:**

- The tunnel **carries inner IP-level fragments verbatim**. The end hosts' IP
  stacks reassemble them, exactly as they would on a physical link. This is
  what a link does.
- The tunnel **does not implement IP-level reassembly**. That is RFC 6946 §1
  to §4's whole subject: IPv6 fragment-based attacks are the reason the
  mechanism is discouraged. The tunnel is not a router and does not reassemble.
- The tunnel's **overlay-level** fragmentation (§4.2) is a **separate, private
  mechanism** and is explicitly **not** RFC 8200 fragmentation. The tunnel MUST
  NOT emit IPv6 Fragment headers and MUST NOT rely on any router fragmenting.
- An IPv6 **atomic fragment** (Fragment header, offset 0, M flag 0) must be
  processed in isolation by the receiving host (RFC 6946 §4). Because the
  tunnel delivers the inner datagram to the host's stack as a whole packet, the
  host's stack does that; the tunnel does nothing and needs no special case.
- The **source-address check (§3.4) and the destination policy (§3.3) apply to
  every inner packet**, fragment or not. The **L4 port-0 rule is evaluated only
  where a transport header is parsable** (§3.3).

---

## 5. The core invariants

Each is checkable by a named test.

| # | Invariant | Checkable by |
|---|---|---|
| I1 | The Tunnel record is always exactly 1280 B; the cleartext header is always 17 B; the AEAD region is always 1263 B. The codec's compile-time partition assertions remain in force. | `codec.rs:152-160` (already a compile-time assertion) |
| I2 | Every peer-input failure is a **silent drop with zero state mutation** (PROTOCOL_SPEC §14). No error datagram is ever emitted. | a drop-counting transport in the E2E harness |
| I3 | The TUN writer only ever receives a **complete, validated** IP packet of exactly `ip_total_len` bytes whose IP header declares exactly that length. | an instrumented TUN writer that asserts on every write |
| I4 | `ip_total_len` is validated *before* any buffer is allocated; every allocation is bounded by 65 535; the session's total reassembly bytes are bounded by 16 MiB. | a counting allocator in the reassembler's tests |
| I5 | A datagram is written only if fragment 0 is present, the fragment count satisfies `(count-1)*FRAG_CAP < ip_total_len <= count*FRAG_CAP`, and the assembled IP header's declared length equals `ip_total_len`. | the overlay contract tests |
| I6 | The overlay never influences the AEAD nonce, the counter, the cover schedule or the replay window. | a test that runs the data plane with cover disabled and asserts the cover grid is unchanged |
| I7 | The sender emits a datagram's fragments as a contiguous burst and never lets the AEAD counter distance within a burst reach `WINDOW_BITS`. | a sender-side test that counts the counter span across a burst |
| I8 | `datagram_id` never wraps within a session; exhaustion triggers rekey, not wrap. | a test that drives the counter to its limit |
| I9 | The server accepts an inner packet only if its source equals the client's assigned address, its destination passes the D28 policy, and -- where a transport header is parsable -- its L4 port is non-zero. | a table-driven server-side test over every D28 row |
| I10 | The server never writes an inner packet into its TUN before every check of I9 passes. | an instrumented TUN writer on the server side |
| I11 | The client never installs a default route for a family it cannot actually carry. Both `0.0.0.0/0` and `::/0` are installed, or the client refuses to come up. | a startup test that removes the v6 address and asserts the refusal |
| I12 | The DNS reconfiguration is all-or-nothing. A partial DNS state is rolled back; a failed DNS reconfiguration prevents the tunnel from coming up. | a fault-injection test on the DNS setter |
| I13 | The outer socket is never routed into the tunnel. This is enforced by a **destination**-based policy rule (Linux) or a **prefix-length**-based host route (Windows) -- never by a source-address selector. | a live route-table assertion plus an E2E test that the tunnel comes up |
| I14 | The default routes via the TUN remain installed for the whole process lifetime, including while the session is down. | a test that drops the session and inspects the route table |
| I15 | Restoration is idempotent, bounded by a deadline, and runs in reverse install order on every exit path. | a `kill -9`-mid-install test plus an idempotence test |
| I16 | The identity file is created with an explicit restrictive ACL or permission; it is never world-readable. | a mode/ACL assertion on the created file |
| I17 | The outer transport sets DF; a path-MTU failure (`EMSGSIZE`) aborts come-up with a diagnostic. | a test on a deliberately small-MTU path |
| I18 | The fragment count, the datagram id and the datagram CRC are all **inside the AEAD ciphertext**. The cleartext header is unchanged (17 B). | a byte-level assertion on the wire record |
| I19 | The session's reassembly table is destroyed when the session closes. | a test that closes the session and asserts the table is empty and its buffers zeroized |
| I20 | A 1:1 server runs with `max_sessions = 1`; a second client is refused **loudly** (a capacity decision, not a peer-input failure). | a two-client test |
| I21 | The tunnel's overlay fragmentation is private and is **not** RFC 8200 fragmentation. The tunnel never emits an IPv6 Fragment header and never performs IP-level reassembly. | a test that sends an inner IPv4 fragment and asserts it is carried, and that no Fragment header is ever synthesised |
| I22 | The reassembly deadline is independent of `--cover-mbps`: running the tunnel at two different cover rates does not change the deadline. | a test that asserts the deadline is constant across cover rates |

---

## 6. Failure and leak cases

### 6.1 Fail-secure behaviour matrix

| Condition | Required behaviour |
|---|---|
| Malformed overlay header, bad `frag_count` / `frag_index` / `ip_total_len`, bad `reserved`, unknown `overlay_version` | **Drop the fragment silently.** If a datagram entry exists, poison it. No allocation, no TUN write. |
| Fragment count inconsistent with `ip_total_len` | Drop; poison the entry. |
| Assembled IP header length not equal to `ip_total_len`, bad version nibble, bad IHL, header-less datagram | **Poison; write nothing.** |
| Zero-length datagram (`ip_total_len == 0`) | Rejected at the header check; write nothing. |
| Missing fragment (deadline expiry) | Drop the entry; write nothing. No NAK. |
| Duplicate fragment, identical bytes | Ignore. |
| Duplicate fragment, different bytes | Poison the entry; write nothing. |
| Datagram-id collision (mismatched `frag_count` / `ip_total_len` / CRC) | Poison; write nothing. Do not create a second entry for that id. |
| Replayed packet (AEAD counter) | Rejected by the replay window; never reaches the overlay layer. |
| Nonce or datagram-id exhaustion | The session transitions to rekey (`CloseReason::NonceExhausted`); the tunnel's link, routes and DNS stay up. |
| IPv6 default route or v6 address cannot be installed | **Refuse to come up.** (Unless `--no-ipv6`, which is loud and documented.) |
| DNS reconfiguration fails, or partially fails | Roll back; **refuse to come up**, or tear down. |
| Outer path MTU too small (`EMSGSIZE`) | **Refuse to come up**, with the required PMTU in the message. |
| Session drops, rekey, or handshake retry | Routes, TUN and DNS **stay up**; the data plane is gated on `Ready`. Traffic fails closed. |
| Process crash | Reconcile on the next start (journal plus route-table inspection). Not "restored" -- reconciled. |
| Server receives an inner packet with a spoofed source | **Silent drop** (I9). |
| Server receives an inner packet to a denied destination (loopback, link-local/metadata, multicast) | **Silent drop** (D28 hard floor). |
| Server receives an inner IP-level fragment | **Carried verbatim** -- the end host's stack reassembles it (§4.9). The source and destination checks still apply. |
| A second client connects to a 1:1 server | Refused loudly; the existing session is untouched. |
| Reassembly table byte cap reached | New datagrams are **dropped** (fail-secure); existing entries are not evicted. |
| Reassembly entry cap reached | New datagrams are dropped. |
| Restore deadline exceeded | Log loudly, exit non-zero, report "network may be broken". Never hang. |

### 6.2 Leak cases

| Leak | Where it comes from | Status |
|---|---|---|
| Traffic before the routes are installed | The window between process start and route installation. | **Residual**, bounded by milliseconds, minimised by installing the routes first. Documented in `THREAT_MODEL.md`. |
| DNS query volume | Under a system-wide tunnel the resolver's query volume is a much stronger signal than the relay's per-destination volume. | **Residual** within D22's "reduction, not anonymity" scope. Documented. |
| Link-state transitions | Tearing the link down on rekey would emit a distinctive lifecycle fingerprint. | **Avoided by design**: the routes, the TUN and the DNS stay up across rekey (§2.7). |
| Packet count and inter-packet gaps | The cleartext `packet_nonce` exposes the whole packet timeline, and the overlay's fragment count is a further observable class. | **Residual**, already inherent in D19/D22. The overlay does not add a *new* class beyond the fragment count. |
| IPv6 traffic not tunnelled | A v4-only "full-system" tunnel. | **Refused at startup** unless `--no-ipv6` is explicitly given, and then loudly announced. |
| Resolver left pointing at the ISP | A partial DNS reconfiguration. | **All-or-nothing**; a failure prevents come-up (I12). |
| The outer socket captured by the tunnel's own default route | A source-address routing rule, or a split process. | **Structurally impossible** with a destination exception (I13) and a single privileged process. |
| A stale route after a crash (Windows) | The temporary Wintun adapter disappears but the routes persist. | **Residual**, mitigated by journal + reconcile + janitor + an explicit repair command (§2.6.4). Not "guaranteed restored". |

---

## 7. The versioning decision

**Decision: bump `PROTOCOL_VERSION` from 1 to 2 and add `MessageType::TunData =
0x04`.**

**The reasoning is not "the record changed" (it did not) but "the failure mode
changed":**

- With `PROTOCOL_VERSION = 1` and a new `MessageType::TunData = 0x04`, a **v1
  server** decrypts the packet fine and then fails `MessageType::from_u8(0x04)`
  (`codec.rs:209-217`) -> a silent drop. The client has an established session,
  an installed default route, and no data: an **opaque black hole**.
- With `PROTOCOL_VERSION = 2`, the v1 server rejects at the **header version
  check** (`codec.rs:305-308`) -- and, decisively, the **handshake fails**,
  because the client's M1 carries version 2 and the v1 server's
  `ClientHello::decode` rejects it. The client never reaches "established but
  dead", and it can report "the server speaks v1, this client speaks v2" **at
  startup**.

That is the whole argument: convert a silent data-plane black hole into a
loud, startup-time handshake failure. It is exactly the D13 principle ("no
downgrade, strict equality, version detection before any cryptographic work")
and PROTOCOL_SPEC §15 ("Version negotiation MUST: prevent incompatible
communication ... prevent downgrade attacks").

**The cost, stated precisely.** `PROTOCOL_VERSION` is bound into:

- the cleartext wire header (`codec.rs:82`, `:281-288`);
- the M1/M2/M3 message bodies;
- the transcript hashes (via the bodies);
- the KDF `info` strings -- so the master secret, the finished key and the
  Finished MAC all change.

**What does NOT change:** the M1/M2/M3 body *lengths* and therefore the pinned
handshake fragment counts. The version byte's *value* changes, not its width.
The codec's fixed layout, the compile-time partition assertions, the cover
schedule and the replay window are unaffected. The handshake fragmentation is
**not** re-derived.

**The cost is therefore:** a hard, non-negotiated interoperability break (no
version negotiation, no downgrade window, no mixed fleet); re-derived KAT
vectors and the audit artifacts in `docs/audit/`; and updates to
`PROTOCOL_SPEC.md`, `DESIGN_DECISIONS.md`, `THREAT_MODEL.md`, `CHANGELOG.md` and
the KAT/audit evidence.

**Recommendation:** bump to 2 and add `MessageType::TunData = 0x04` as a
single, well-labelled change together with the overlay codec, so that the
"established but dead" window never exists in any released build.

**Fallback if the owner refuses the version break.** Keep version 1, add
`MessageType::TunData` anyway, and make the *server's* TUN mode an explicit
operator flag on both ends. The overlay is then distinguished by the
`MessageType`, so no in-band `payload[0]` convention is needed and the legacy
relay stays intact. The residual is the silent-blackhole risk for a v1 server,
which must then be mitigated by a **startup self-test** (the client sends a
synthetic datagram and requires a response within a bounded time; on timeout it
tears the route down and reports "the server does not support the TUN data
plane"). The self-test is **not** a substitute for the version bump -- it
detects the failure, it does not prevent it.

**`MessageType::TunData = 0x04` and the relay namespace.** `0x04` is
byte-disjoint from the codec's message types (0x00 to 0x03, `codec.rs:192-201`)
and from the handshake fragment types (0x10 / 0x20 / 0x30). It is in a
**different namespace** from the relay's `family` byte, which is also `0x04`
for IPv4 (`relay.rs:36`) -- that is a documentation hazard, so the enum's doc
must say so explicitly, and a compile-time assertion should pin that the
*relay* namespace is only ever read from a `MessageType::Data` payload.

---

## 8. The platform-specific implementation graph

### 8.1 Linux

```
        ┌──────────────────────────────────────────────────────────┐
        │  privileged helper (CAP_NET_ADMIN [+ CAP_NET_RAW])       │
        │                                                          │
        │   ┌────────────┐   ┌────────────┐   ┌──────────────┐   │
        │   │ TUN device │   │ routing    │   │ DNS          │   │
        │   │ /dev/net/  │   │ ip rule /  │   │ resolvectl   │   │
        │   │ tun        │   │ ip route   │   │ (or resolv.  │   │
        │   │ IFF_TUN    │   │ table 100  │   │  conf)       │   │
        │   │ IFF_NO_PI  │   │ + suppress │   │              │   │
        │   └─────┬──────┘   └─────┬──────┘   └──────┬───────┘   │
        │         │                │                 │           │
        │         └────────┬───────┴─────────────────┘           │
        │                  ▼                                     │
        │          ┌───────────────┐    ┌──────────────────┐      │
        │          │ session mgr   │◄──►│ outer UDP socket │      │
        │          │ (core)        │    │ SO_MARK + DF     │      │
        │          └───────────────┘    └──────────────────┘      │
        └──────────────────────────────────────────────────────────┘
```

- **Privilege:** `CAP_NET_ADMIN` for the device, the addresses, the routes and
  the rules; `CAP_NET_RAW` if `SO_MARK` is used. A systemd unit with
  `AmbientCapabilities=CAP_NET_ADMIN` and `NoNewPrivileges`.
- **Identity file:** owned by the service user, mode 0600, in a 0700
  directory.
- **Rollback path:** the journal + reconcile + janitor of §2.6.4. `ip rule`
  entries and table-100 routes survive a crash; whether routes bound to a
  deleted netdev are removed by the kernel was **not** verified, so the design
  must not depend on it. `ip rule` staleness is reconciled explicitly.

### 8.2 Windows

```
        ┌──────────────────────────────────────────────────────────┐
        │  Windows Service (SCM) -- virtual service account,       │
        │  Administrator for adapter creation and route install    │
        │                                                          │
        │   ┌────────────┐   ┌────────────┐   ┌──────────────┐   │
        │   │ Wintun L3  │   │ routes     │   │ DNS          │   │
        │   │ adapter    │   │ New-NetRoute│  │ Set-DnsClient│   │
        │   │ wintun.dll │   │ + metrics  │   │ ServerAddress│   │
        │   └─────┬──────┘   └─────┬──────┘   └──────┬───────┘   │
        │         │                │                 │           │
        │         └────────┬───────┴─────────────────┘           │
        │                  ▼                                     │
        │          ┌───────────────┐    ┌──────────────────┐      │
        │          │ session mgr   │◄──►│ outer UDP socket │      │
        │          └───────────────┘    │ IP_DONTFRAGMENT  │      │
        │                               └──────────────────┘      │
        │                                                          │
        │   ┌──────────────────────────────────────────────────┐   │
        │   │ named pipe control channel: state and commands   │   │
        │   │ only -- never keys. DACL: Administrators + the   │   │
        │   │ service SID.                                      │   │
        │   └──────────────────────────────────────────────────┘   │
        └──────────────────────────────────────────────────────────┘
```

- **Privilege:** creating a Wintun adapter and installing routes requires
  elevation. The design therefore splits: an **elevated installer step** that
  creates the adapter, and a **least-privilege service** that only opens the
  existing adapter.
- **The control channel** carries state and commands only -- never keys.
  Unprivileged local processes must not be able to reconfigure routes or read
  key material.
- **Identity-file ACLs (mandatory, and currently missing).** The PQTI identity
  file must be created with an explicit restrictive DACL (Windows: the service
  SID plus SYSTEM, inheritance disabled; Unix: mode 0600 in a 0700
  directory). Today the code writes with the process umask, which on a
  default-umask Unix host yields a **world-readable ML-DSA-65 secret seed**.
  This is a standalone security defect worth fixing regardless of the TUN work.
- **Rollback path, and the stale-route failure mode.** The four-layer
  mitigation of §2.6.4 applies: journal before mutate (fsync'd); reconcile on
  start (enumerate the live route table and delete every default route bound to
  a non-existent interface index); a route janitor (the Service's
  `SERVICE_CONFIG_FAILURE_ACTIONS` recovery action); and an explicit
  `pq-tunnel repair-routes` command. The honest statement is **"reconciled on
  the next start"**, not "guaranteed restored".

### 8.3 macOS

- **Privilege:** root for the utun, the addresses, the routes and the resolver
  configuration. A `launchd` system daemon with a dedicated user and a
  `launchd` `KeepAlive`/exit-code policy for the janitor.
- **Rollback path:** the same journal + reconcile pattern, with the resolver
  state restored through `networksetup` / `scutil`.
- **[UNVERIFIED]:** the exact command surface. Needs a spike before any
  implementation.

---

## 9. Prioritized milestones

Each milestone is **independently shippable**: it can be merged, reviewed and
released on its own without the next one.

### M0 -- The gate: the version decision and the overlay contract

- **Content:** the `PROTOCOL_VERSION` bump to 2, `MessageType::TunData =
  0x04`, the re-derived KAT vectors and audit artifacts, and the **overlay
  contract tests** (pure format tests, no runtime code).
- **Independently shippable:** yes. It is a version bump plus tests. Nothing
  depends on the TUN.
- **Test plan:** the contract tests assert the overlay header layout, the
  compile-time constants (`OVERLAY_HEADER_LEN = 20`, `FRAG_CAP = 1225`,
  `MAX_FRAG_COUNT = 54`), the strict inequality, the `MessageType` byte
  disjointness from the relay namespace, and that a v1 peer rejects a v2
  handshake **loudly**.
- **Risk:** low. This is the milestone D30's dependency graph called GATE 0,
  and it is right that everything wire-visible is blocked on it.

### M1 -- The core data plane: the overlay codec and the reassembler

- **Content:** a new `pq-tunnel-core::dataplane` module with the overlay
  encode/decode/validate, the reassembler with the exact rules of §4.3 to
  §4.5, the strict caps, the CRC, and the sender-side burst serialisation plus
  the replay-window span check (S1 to S3). **No TUN, no routing, no privilege.**
- **Independently shippable:** yes -- a library module with a complete test
  suite and a fuzz target.
- **Test plan:** the overlay contract tests; the reassembler's table-driven
  cases (out-of-order, duplicate-identical, duplicate-different, collision,
  missing, poisoned, completion); the sender-side span check; a **new fuzz
  target** for the overlay codec and the reassembler (the existing
  `relay_overlay` target covers `ip_packet_len` only as a sub-target, and
  `ip_packet_len` becomes a network-facing parser with the TUN).
- **Risk:** medium. The reassembler's state machine is where a subtle bug
  becomes a memory-safety or a splice bug. Mitigated by the fuzz target and by
  the "poison, write nothing" failure discipline.

### M2 -- The server-side raw-IP path

- **Content:** the server TUN, kernel forwarding, stateful NAT, the
  source-address validation, the D28 destination policy at the IP layer, the
  L4 port-0 rule, and `max_sessions = 1` with a loud refusal for a second
  client.
- **Independently shippable:** yes. It can be built and tested against a
  **synthetic inner-IP-packet injector** before the client exists -- this is
  the single biggest schedule win in the design.
- **Test plan:** a table-driven server-side test over every D28 row, in both
  families, plus the v4-embedded normalisation cases; a spoofed-source test
  (every inner packet with a wrong source is dropped, including fragments); an
  "inner packet to `169.254.169.254` never leaves the host" test; a
  "second client is refused loudly and the first session is untouched" test; an
  "inner IP fragment is carried and the server's kernel reassembles it" test.
- **Risk:** **the highest of any milestone.** A source-validation or policy bug
  here is a network pivot or an SSRF, and it is *silent* -- the tunnel simply
  does not forward. It also changes the server's privilege model and its
  network position. **This is the stage most likely to need the most review.**

### M3 -- The client TUN device layer

- **Content:** the per-OS TUN device: Linux `/dev/net/tun` with `IFF_TUN |
  IFF_NO_PI`, macOS `utunN`, Windows Wintun L3. Device creation, MTU, the dual
  addresses, and the read/write plumbing. **No routing, no DNS, no kill switch
  yet.**
- **Independently shippable:** yes -- the device layer can ship and be tested
  with a synthetic packet injector on the client side too.
- **Test plan:** a device round-trip test (write an inner packet, read it
  back); an MTU assertion; an address assertion; a privilege assertion (the
  test refuses to run unprivileged on Linux and says so).
- **Risk:** medium-high. It is the first privileged code in the client, and it
  is the point at which the project acquires a native dependency (see §9.1).

### M4 -- Routing, DNS, the kill switch and the lifecycle journal

- **Content:** the Linux policy rules and the Windows routes, the DNS
  integration, the three kill-switch levels, and the journal/reconcile/janitor
  restoration actor.
- **Independently shippable:** yes -- the routing layer can ship behind an
  explicit operator flag while the data plane is still gated off.
- **Test plan:** a live route-table assertion after install and after teardown;
  the "the outer socket is never captured by the tunnel" E2E test; the
  `kill -9`-mid-install restoration test; the idempotence test (restore twice);
  the "no source-address selector anywhere in the rule set" static assertion;
  the DNS all-or-nothing fault-injection test.
- **Risk:** high on the **availability** axis -- a routing mistake takes the
  host's network down, and the Windows stale-route failure mode leaves the
  machine offline until a human intervenes. It is the milestone most likely to
  generate a user-visible incident.

### M5 -- Integration, E2E and the leak tests

- **Content:** the client data plane (the TUN reader/writer wired to the
  session manager), the integration of M1 to M4, and the end-to-end tests.
- **Independently shippable:** yes, but it is the milestone that makes the
  product real.
- **Test plan:** an end-to-end IPv4 and IPv6 test over a real TUN; an explicit
  **IPv6-leak test** (assert that IPv6 traffic does not leave the physical
  interface when the tunnel is up); a PMTU-too-small test; an interop test
  asserting a v1-to-v2 handshake failure is **loud**; a spoofed-source test on
  the server; a `kill -9` restoration test; and a test that the routes, the TUN
  and the DNS stay up across a rekey.

### 9.1 The dependency, supply-chain and MSRV position

**Candidate crate:** `tun` 0.8.14.

| crate | version | edition | declared `rust-version` |
|---|---|---|---|
| `tun` | 0.8.14 | **2024** | **none declared** |
| `wintun-bindings` | 0.7.39 | **2024** | **none declared** |

Independently verified from the crates.io API for this document.

- **MSRV impact: the headroom is exactly zero.** The workspace MSRV is **1.85**
  (`Cargo.toml:12`) and the workspace itself is edition 2024 (`Cargo.toml:11`).
  A crate that is edition 2024 requires Rust 1.85 or newer to compile, and
  neither `tun` nor `wintun-bindings` declares a `rust-version` to enforce it.
  Every other transitive dependency of `tun` declares at most 1.71, so the
  binding constraint is the edition-2024 pair -- exactly at the floor.
  **Mitigation: pin exactly** -- `tun = "=0.8.14"` -- and add a CI assertion
  that `wintun-bindings` stays at or below 0.7.39. Exact pinning is established
  practice in this workspace (`Cargo.toml:23`,
  `x25519-dalek = "=3.0.0-rc.1"`). A future `tun` release could move to
  edition 2027 or require 1.86 and break the MSRV job
  (`.github/workflows/ci.yml:157-173`) with no warning.
- **No native compilation is introduced.** Verified from the crates.io
  dependency lists: neither `tun` nor `wintun-bindings` depends on `cc`,
  `cmake` or `bindgen`. `wintun-bindings` uses `libloading` (a runtime DLL
  load) and `windows-sys`. **The CI matrix does not change for native-build
  reasons.** `tun` does have a **build script** (`serde_json` as a build
  dependency), so `Cargo.lock` gains a build-time dependency and `fuzz/Cargo.lock`
  must be re-synced or the CI lock-sync gate fails (`ci.yml:68-107`).
- **The real new supply-chain surface is a runtime binary artifact:**
  `wintun.dll` must ship next to the executable. It is a third-party signed
  binary that `cargo-audit` **cannot see** (`ci.yml:129-155` audits the Rust
  lockfiles only). **Owner decision required:** vendor it with a pinned
  SHA-256, or download and verify it at install time. There is a partial
  mitigation available in the dependency itself: both `tun` and
  `wintun-bindings` expose a `verify_binary_signature` feature (the `tun`
  feature forwards to `wintun-bindings/verify_binary_signature`), so Authenticode
  verification of the DLL is available as a feature flag rather than requiring
  a bespoke check. The alternative -- hand-rolling the Wintun IOCTL protocol
  against `windows-sys` alone -- removes the `wintun-bindings` crate but
  **not** the DLL.
- **What the `tun` crate does *not* do.** Verified against the crate's own
  source (`src/configuration.rs`, `src/platform/windows/mod.rs`): the
  `Configuration` builder has a **single** `address` / `netmask` /
  `destination` / `broadcast` (one family only), plus `tun_name`,
  `platform_config`, `mtu`, `up`/`down`, `layer`, `metric` (Windows),
  `ring_capacity` (Windows), `raw_fd` / `raw_handle`, `close_fd_on_drop`
  (Unix) and a **deprecated** `queues` (always 1). There is **no `routes`
  field** and **no DNS field on `Configuration`**. DNS is available on Windows
  only, through `platform_config.dns_servers`. The **default route**, the
  **interface metric** and the **DNS servers** are set by the crate's Windows
  device path, but **every route beyond that single default** -- the bypass
  host route, the second family's default, and the policy rules -- plus the
  whole kill-switch and the journal are **Tunnel's job, not the library's**.
  This keeps the library's API surface close to "packet I/O plus a minimal
  device bring-up", and it means Tunnel must own the ordering: the crate's
  Windows path wants to install a default route itself, and the design's
  ordering requirement (bypass route first, then the tunnel default, then the
  DNS, all journaled) is **not** what the crate does on its own.

---

## 10. The D30 corrections this document supersedes

The full, itemised correction list -- with the verified status of each of
D30's claims, the corrected value for each error, the byte-arithmetic
correction, the pointer to this document, and the corrected "is a TUN library
the first native dependency" premise -- is recorded in
[`D30-corrected-system-wide-data-plane.md`](D30-corrected-system-wide-data-plane.md)
under its own amendment section. The summary:

| D30 claim | Verdict | Corrected value |
|---|---|---|
| §2.2(4), I9, §10.2, M-M: the tunnel must **reject** inner IP-level fragments | **WRONG** | The tunnel **carries** inner IP-level fragments verbatim and does not reassemble them (§4.9). |
| §4.8, Q1: the effective deadline is `min(configured, replay-window horizon)`; default 2 s | **INCOMPLETE and optimistic** | The horizon is **rate-dependent**: 5.24 s at the cover floor, 1.05 s at 10 Mbit/s, 105 ms at 100 Mbit/s (§4.8). A 2 s deadline is achievable only below about 5.2 Mbit/s of aggregate record rate, and a high-rate deployment must raise `WINDOW_BITS`. |
| §4.8: "at 10 Mbit/s of tunnel payload (9 765 pkt/s) they span 105 ms" | **ARITHMETIC ERROR** | 9 765 pkt/s corresponds to **100** Mbit/s, not 10. At 10 Mbit/s the rate is 976.6 pkt/s and the horizon is **1.05 s**. |
| §3.3, §4.1, S4, Q11: `datagram_id` is a u32 | **SUBOPTIMAL** | A u32 exhausts in about **24.4 h** at 1 Gbit/s. Use a **u64** (§4.5). |
| §3.3, §4.2: `datagram_tag` = the first 32 bits of SHA-256 over fragment 0 | **SUBOPTIMAL** | A fragment-0-only tag cannot detect splicing in a later fragment. Use a **whole-packet CRC-32** (§4.6). |
| §1.2, §7.3, W10, M14: `codec.rs:94-98` claims the 1280-byte record "fits a standard IPv4/IPv6 MTU (1500 / 1280)" | **STALE** | The baseline codec **already** states the outer sizes correctly: 1308 (IPv4) / 1328 (IPv6) and "requires a path MTU of at least 1328 bytes" (`codec.rs:98-106`). D30's instruction to correct the codec is obsolete; the codec needs no change. |
| §3.3, §4.4, §5: `OVERLAY_HEADER_LEN = 14`, `FRAG_CAP = 1231` | **CORRECT BUT SUPERSEDED** | This document uses **20** and **1225** (§4.1). The fragment count stays 54 and the efficiency stays 50 %. |
| §9, §3.1: bump the version and add `MessageType::TunData = 0x04` | **AGREE** | Retained and sharpened (§7). |
| §0 E14: the `tun` crate "installs **no routes**" | **WRONG for the Windows path** | `tun` 0.8.14's Windows device path **does** install a default route (`sys::set_default_route` when `config.destination` is IPv4), the interface metric and the DNS servers. There is still **no `routes` field**, and the crate's IPv6 support is limited (`set_address` is `unimplemented!` for IPv6) (§2.2.3, §9.1). |
| §4.4, §4.6, I9: the **IP header** is authoritative and `ip_total_len` is a cross-check | **AGREE** | Retained (§4.1). |
| §8.1: the routing recipe uses a **destination** exception, never a source selector | **AGREE** | Retained and extended with `SO_MARK` + `suppress_prefixlength 0` (§2.3). |
| §13 Q3: "a TUN library choice may be the FIRST native dependency and that changes the CI matrix" | **FALSE PREMISE** | `tun` 0.8.14 and `wintun-bindings` 0.7.39 need no `cc` / `cmake` / `bindgen`, so the CI matrix does **not** change for native-build reasons. The real constraints are **zero MSRV headroom** (edition 2024 against a 1.85 floor) and the **runtime `wintun.dll` binary artifact** (§9.1). |
| "RFC 8200 §6.4 (Packet Too Big / ICMPv6 Type 2)" | **FALSE PREMISE** | There is no RFC 8200 §6.4. ICMPv6 Type 2 is **RFC 4443 §3.2** (§1.3). |
| "RFC 8981 (IPv6 fragment header size)" | **FALSE PREMISE** | RFC 8981 is *Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6*. The Fragment header's fixed 8-octet size is **RFC 8200 §4.5**, and RFC 6946 §4 refers to "the length of the Fragment Header (that is, 8)". |
| F5, F6, F7, F8, F9, F10, F12, F13: the relay framing, `MAX_DATAGRAM_V4 = 1236`, `ip_packet_len`, the single-family outer bind, version strict-equality, the pinned handshake fragment counts, `SessionLimits::default()`, and `ManagerEvent::Send` | **VERIFIED CORRECT** | Retained (§3.2). |

---

## 11. What could not be verified

| Item | Status |
|---|---|
| The `tun` crate's `Configuration` surface, the `Layer::L3` default, the `"wintun.dll"` path default, the Windows device path's route/metric/DNS handling, and the crate's own "Security note" about the DLL's provenance | **Verified** against the crate's source (`src/configuration.rs`, `src/platform/windows/mod.rs`, `src/platform/windows/device.rs` of `tun` 0.8.14). Note the correction to D30's E14: the crate **does** install a default route on the Windows path. |
| The macOS route, DNS and resolver command surface (`route`, `networksetup`, `scutil`), and the utun creation syscall sequence for a non-`tun`-crate implementation | **[UNVERIFIED]** -- needs a spike on macOS. The `tun` crate's macOS path uses the `com.apple.net.utun_control` socket and a `getpeername()` + `ioctl(fd, CTLIOCGINFO, ...)` scan over file descriptors 0 to 1024; that is the crate's implementation, not a specification, and it was not exercised. |
| Whether the Linux kernel removes routes bound to a deleted netdev after a crash | **[UNVERIFIED]** -- the design does not depend on it (§8.1). |
| Windows' minimum IPv6 interface MTU, and whether Windows clamps or disables IPv6 below 1280 as Linux does | **[UNVERIFIED]** -- assume Windows mirrors Linux until proven otherwise, so 1280 is the safe floor on both platforms. |
| The Windows outer-transport PMTU failure surface (`WSAEMSGSIZE` versus a silent drop versus an ICMP-driven PMTU cache) | **[UNVERIFIED]** -- assume `EMSGSIZE` is surfaced; the startup gate treats any outer-send failure that is not a peer reset as fatal. |
| The `tun` crate's behaviour on the pinned toolchain (1.99.0) and on 1.85.0, for both `x86_64-pc-windows-msvc` and Linux | **[UNVERIFIED]** -- the MSRV spike in D30's Q3 is still open. The crate's declared metadata is verified (§9.1); its actual compilability is not. |
| A measured reordering-delay distribution for any target path, and therefore the "right" reassembly deadline | **[UNVERIFIED]** -- 2 s is a parameter with a stated derivation method, not a derived constant (§4.8). |
| The exact Windows Service Control Manager recovery-action semantics (`SERVICE_CONFIG_FAILURE_ACTIONS`) for the route janitor | **[UNVERIFIED]** -- the platform-doc reference is standard, but the behaviour was not exercised. |
| Whether `wintun.dll`'s Authenticode signature chain is verifiable in the target deployment environment (for example with a revoked intermediate CA) | **[UNVERIFIED]** -- the `verify_binary_signature` feature exists (§9.1); its behaviour in a given environment was not exercised. |
| The behaviour of `tun` 0.8.14's `Configuration` regarding a **second** address on Linux and Windows in practice | **[UNVERIFIED]** -- the metadata and the source are verified (§2.2.3, §9.1); the runtime behaviour of the crate's own bring-up path on each platform was not exercised. |
| The exact inner-packet write path on the server: whether the server's TUN write can be made non-blocking and how the kernel's conntrack interacts with a write into a TUN | **[UNVERIFIED]** -- this is the core of milestone M2 and needs the synthetic-injector spike. |
