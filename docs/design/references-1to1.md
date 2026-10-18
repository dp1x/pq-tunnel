# D28 external references (1:1 deployment)

Every URL below was fetched during the D28 research pass. Quotations are taken
only from text that was actually retrieved in this session. Items that could
not be retrieved are listed in the final section and are **not** relied upon by
the D28 design doc.

Repository state at research time: `origin/main = ae8061d`, clean tree.

---

## 1. Special-purpose address registries (the normative basis for the CIDR table)

### 1.1 RFC 6890 — Special-Purpose IP Address Registries

- URL fetched: <https://www.rfc-editor.org/rfc/rfc6890.html>
- BCP 153, April 2013. Obsoletes RFCs 4773, 5156, 5735, 5736.

Directly relevant registry rows confirmed in the retrieved text:

| Block | Name | RFC | Source | Destination | Forwardable | Global |
| --- | --- | --- | --- | --- | --- | --- |
| `0.0.0.0/8` | "This host on this network" | RFC 1122 §3.2.1.3 | True | **False** | False | False |
| `10.0.0.0/8` | Private-Use | RFC 1918 | True | True | True | **False** |
| `127.0.0.0/8` | Loopback | RFC 1122 §3.2.1.3 | False | **False** | False | False |
| `169.254.0.0/16` | Link Local | RFC 3927 | True | True | **False** | False |
| `172.16.0.0/12` | Private-Use | RFC 1918 | True | True | True | **False** |
| `192.168.0.0/16` | Private-Use | RFC 1918 | True | True | True | **False** |
| `240.0.0.0/4` | Reserved | RFC 1112 §4 | False | **False** | False | False |
| `255.255.255.255/32` | Limited Broadcast | RFC 919 §7 | False | **True** | False | False |
| `::1/128` | Loopback Address | RFC 4291 | False | **False** | False | False |
| `::/128` | Unspecified Address | RFC 4291 | True | **False** | False | False |
| `::ffff:0:0/96` | IPv4-mapped Address | RFC 4291 | False | **False** | False | False |
| `2001::/32` | TEREDO | RFC 4380 | True | True | True | N/A |
| `2002::/16` | 6to4 | RFC 3056 | True | True | True | N/A |
| `fc00::/7` | Unique-Local | RFC 4193 | True | True | True | **False** |
| `fe80::/10` | Link-Local Unicast | RFC 4291 | True | True | **False** | False |

Two facts from this RFC drive design decisions directly:

- **RFC 6890 does not list `224.0.0.0/4` (IPv4 multicast) at all.** Multicast
  allocation is owned by RFC 5771, which is outside the special-purpose
  registries. D28 treats `224.0.0.0/4` as a policy block on its own merits
  (amplification), not as an RFC 6890 row. **UNVERIFIED**: RFC 5771 itself was
  not fetched.
- **`255.255.255.255/32` is the one block whose `Destination` flag is True
  while `Forwardable` and `Global` are False.** Every other denied block here
  is `Destination: False`. This is why broadcast is treated as a separate
  policy row in the D28 table rather than folded into "special-purpose".

### 1.2 IANA IPv4 Special-Purpose Address Registry (live)

- URL fetched: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
- Page reported `Last Updated 2025-10-09`. Registry renamed
  "Formerly known as IANA IPv4 Special-Purpose Address Registry".

The live registry **adds entries RFC 6890 did not**, notably
`192.0.0.170/32, 192.0.0.171/32` (NAT64/DNS64 Discovery, RFC 8880/7050) and
`100:0:0:1::/64` on the v6 side. It also shows `192.88.99.0/24` as
"Deprecated (6to4 Relay Anycast)" with a 2015-03 termination date.

Registry note quoted from the page: "Address prefixes listed in the
Special-Purpose Address Registry are not guaranteed routability in any
particular local or global context." This is the strongest available
statement that a static deny-list is a *policy* choice and not a claim of
universal unsuitability — which is exactly why D28 requires an explicit,
logged allow override rather than treating the deny-list as absolute.

### 1.3 IANA IPv6 Special-Purpose Address Registry (live)

- URL fetched: <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>
- Page reported `Last Updated 2025-10-09`.

Confirmed rows relevant to D28: `::1/128`, `::/128`, `::ffff:0:0/96`,
`64:ff9b::/96` (IPv4-IPv6 Translation, **Globally Reachable: True**),
`2001::/32` TEREDO, `2002::/16` 6to4, `fc00::/7` ULA,
`fe80::/10` Link-Local Unicast.

Footnote quoted for ULA: "The Unique-Local prefix is drawn from the IPv6
Global Unicast Address range, but is specified as not globally routed."

### 1.4 RFC 1918 — Address Allocation for Private Internets

- URL fetched: <https://www.rfc-editor.org/rfc/rfc1918.html>
- BCP 5, February 1996.

The three blocks, quoted: "10.0.0.0 - 10.255.255.255 (10/8 prefix)",
"172.16.0.0 - 172.31.255.255 (172.16/12 prefix)",
"192.168.0.0 - 192.168.255.255 (192.168/16 prefix)".

Critically, §3 states: "Because private addresses have no global meaning,
routing information about private networks shall not be propagated on
inter-enterprise links, and packets with private source or destination
addresses should not be forwarded across such links."

**This is the key tension the D28 design must resolve.** RFC 1918 says
private-destination packets *should not* be forwarded across inter-enterprise
links. A VPN server is by definition forwarding private-destination packets
across a link, on the operator's explicit instruction. So the RFC's default is
*not* a security requirement the operator can adopt unmodified — it is a
general hygiene recommendation that the operator's deployment deliberately
overrides for a specific, enumerated set of destinations. That is why D28
proposes deny-by-default with an explicit `--allow-cidr` grant, never
allow-by-default with a block list.

§6 of RFC 1918 states plainly: "Security issues are not addressed in this
memo." So RFC 1918 gives us the *address plan*, not a security argument.

---

## 2. Port 0

### 2.1 RFC 6335 — IANA Procedures for the Port Number Registry

- URL fetched: <https://www.rfc-editor.org/rfc/rfc6335.html>
- BCP 165, August 2011.

§6 defines the three ranges: System Ports 0-1023, User Ports 1024-49151,
Dynamic Ports 49152-65535. Of the assignable ranges, a port is Assigned,
Unassigned, or **Reserved**. Quoted: "Reserved port numbers are not available
for regular assignment; they are 'assigned to IANA' for special purposes.
Reserved port numbers include values at the edges of each range, e.g., **0**,
1023, 1024, etc."

### 2.2 IANA Service Name and Transport Protocol Port Number Registry (live)

- URL fetched: <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml>
- Page reported `Last Updated 2026-09-30`.

First rows of the table confirm: port `0`, tcp — "Reserved" (modification date
2024-12-20, reference RFC 6335); port `0`, udp — "Reserved" (same).

So port 0 is a **Reserved**, never-assigned, never-service port on both
transports. There is no legitimate destination for it.

### 2.3 Winsock `bind` documentation (empirical context for port 0 as a *source*)

- URL fetched: <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind>

Relevant to a *different* use of port 0 that is legitimate: "For TCP/IP, if the
port is specified as zero, the service provider assigns a unique port to the
application from the dynamic client port range." That is why
`forward.rs:195-198` binding `0.0.0.0:0` / `[::]:0` is correct and must not be
confused with a destination port of 0. The two must be checked separately.

### 2.4 Measured behaviour on this host (empirical, this session)

The task brief asserted "on Windows generally fails" for `sendto` to port 0.
**That assertion is contradicted by direct measurement on this machine** (see
the D28 design doc §2 for the full writeup). Winsock `connect()` and
`send()` to UDP port 0 both returned success. Port 0 must therefore be
rejected by Tunnel's own validation; it cannot be left to the OS.

---

## 3. Cloud instance metadata services (the highest-severity item)

### 3.1 AWS EC2 Instance Metadata Service

- URL fetched: <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>

Quoted: "The examples below use the IPv4 address of the Instance Metadata
Service (IMDS): `169.254.169.254`. If you are retrieving instance metadata for
EC2 instances over the IPv6 address, ensure that you enable and use the IPv6
address instead: `[fd00:ec2::254]`."

So AWS's IPv6 IMDS endpoint is **`fd00:ec2::254`** — and note it is inside
`fd00::/8`, which is ULA (`fc00::/7`). D28's ULA block covers it; it does not
need its own row, but it is called out for operator clarity.

The page also documents the defence-in-depth rationale explicitly for SSRF:
"our own analysis of real-world vulnerabilities found that this combination
protects against the vast majority of SSRF vulnerabilities" (IMDSv2 session
tokens obtained via HTTP PUT, which SSRF payloads rarely issue).

### 3.2 AWS Security Blog — IMDSv2, and why open routers/VPNs are a named threat

- URL fetched: <https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/>

This is the single most on-point external source for D28. Quoted, under
"Protecting against open layer 3 firewalls and NATs":

> "there is a final layer of defense in IMDSv2 that is designed to protect
> against EC2 instances that have been misconfigured as **open routers, layer 3
> firewalls, VPNs, tunnels, or NAT devices**."

AWS then explains the IP-hop-limit mechanism that contains the blast radius.
The structural point for Tunnel: **a cloud VM acting as a VPN/NAT device is
the exact configuration AWS names as a hazard**, and IMDSv2's hop-limit is a
mitigation Tunnel must not rely on. A blocked destination at the Tunnel server
is the primary control; hop limits are defence in depth we do not control.

### 3.3 Google Cloud Compute Engine metadata server

- URL fetched: <https://docs.cloud.google.com/compute/docs/metadata/overview>

Quoted from "Metadata server endpoints":

- IPv4 address: `http://169.254.169.254/computeMetadata/v1`
- IPv6 address (only for IPv6-only VMs): `http://[fd20:ce::254]/computeMetadata/v1`

**Correction to the task brief:** the brief stated "the IPv6 `fd00:ec2::254`".
That address is AWS's. GCP's IPv6 metadata endpoint is **`fd20:ce::254`**.
Both are ULA, so D28's `fc00::/7` block covers both — but the design doc
records the correct per-provider addresses.

Quoted security posture: "When you make a request to get information from the
metadata server, your request and the subsequent metadata response never leave
the physical host that is running the VM. However, any process that can query
the metadata URL, has access to all values in the metadata server."

### 3.4 Azure Instance Metadata Service

- URL fetched: <https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service>

Quoted: "IMDS is a REST API that's available at a well-known, non-routable IP
address (`169.254.169.254`). You can only access it from within the VM.
Communication between the VM and IMDS never leaves the host."

Azure documents no separate IPv6 metadata endpoint on this page. The page does
note the platform-internal VIP `168.63.129.16` in routing-table examples as
Azure's wire server, distinct from IMDS.

Quoted guidance relevant to Tunnel as a platform: "IMDS is **not** a channel
for sensitive data. The API is unauthenticated and open to all processes on
the VM." And the recommended local mitigation: "you can set local firewall
rules to limit the access."

Note the header `Metadata: true` requirement — Azure rejects requests without
it. Tunnel relaying arbitrary UDP cannot synthesise that, so an Azure IMDS
pivot is largely defeated by the service itself. It remains a block row
because relying on a cloud service's own header check is not a control Tunnel
can verify.

### 3.5 Alibaba Cloud ECS instance metadata

- URL fetched: <https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata>
  (Two earlier candidate URLs under `/help/en/ecs/user-guide/` returned 404 and
  are **not** cited.)

Quoted: `TOKEN=`curl -X PUT "http://100.100.100.200/latest/api/token" -H "X-aliyun-ecs-metadata-token-ttl-seconds:21600"``
and `curl http://100.100.100.200/latest/meta-data/instance-id`.

So Alibaba's endpoint is **`100.100.100.200`**, confirmed. Crucially, that
address is inside **`100.64.0.0/10`** (RFC 6598, Shared Address Space / CGNAT)
— **not** `169.254.0.0/16` and **not** RFC 1918. This is the single most
important finding for the D28 table: **blocking link-local alone does not
block the Alibaba metadata endpoint.** `100.64.0.0/10` needs its own row.

Alibaba also states the reachability boundary: "Can I access instance address
from a local host? No. `100.100.100.200` is a link-local address reachable only
from within an ECS instance over its virtual network interface. Requests from
outside the instance cannot be routed to this address." Tunnel's server would
be *inside* the instance, so that boundary does not protect it.

Alibaba's SSRF framing, quoted: "A typical attack exploits an application
feature such as downloading an image from an external URL. An attacker crafts a
request that tricks the server into querying the metadata service, stealing the
RAM role's temporary credentials."

---

## 4. VPN / tunnel egress-policy practice

### 4.1 WireGuard `wg(8)`

- URL fetched: <https://man7.org/linux/man-pages/man8/wg.8.html>

The `AllowedIPs` field is the closest widely-deployed analogue to what D28
proposes, and it is worth being precise about its semantics. Quoted:
"AllowedIPs — A comma-separated list of IP (v4 or v6) addresses with CIDR masks
from which incoming traffic for this peer is allowed and to which outgoing
traffic for this peer is directed. The catch-all *0.0.0.0/0* may be specified
for matching all IPv4 addresses, and *::/0* may be specified for matching all
IPv6 addresses."

The example configuration in the same page is a **destination allow-list of
narrow CIDRs** — `10.192.122.3/32, 10.192.124.1/24`, `192.168.0.0/16`,
`10.10.10.230/32` — never a bare `0.0.0.0/0` in a real peer. This supports
D28's position that reaching private networks is a **configured** capability,
not a default. It also demonstrates the granularity is a CIDR, which is
exactly D28's `--allow-cidr` unit.

Note what WireGuard does **not** have: no per-destination deny capability, no
port-based policy, no special-range blocklist. D28 is strictly stronger than
the most widely deployed tunnel default, which is the relevant comparison.

### 4.2 Cloudflare — What is a VPN

- URL fetched: <https://www.cloudflare.com/learning/vpn/what-is-a-vpn/>

Confirms the product framing D28 is designed against. Quoted on the trust
boundary: "The VPN server decrypts the data from the user's device and then
connects to the Internet to access the web server in an unencrypted
communication." And: "A VPN service does not guarantee an increased level of
security; users can only feel secure if they trust the VPN provider."

That second quote is the honest statement of D28's threat: the operator's
server is trusted infrastructure, and a client that is compromised can aim
traffic anywhere the operator's host can reach. That is a pivot, not a bug.

### 4.3 OWASP SSRF Prevention Cheat Sheet

- URL fetched: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>

Tunnel's forwarding backend is structurally an SSRF gadget with a
cryptographic front end: the client picks the destination, the server issues
the request. The cheat sheet's own framing: "SSRF is an attack vector that
abuses an application to interact with the internal/external network or the
machine itself."

The cheat sheet's deny-list section is useful but is framed as a **last
resort**, quoted: "Deny-lists are bypass-prone. Prefer allow-lists." and "When
unavoidable, block these minimum ranges:" — which lists AWS IMDS, GCP Metadata,
Azure IMDS, Localhost, RFC1918, IPv6 ULA, IPv6 Link-Local, Multicast.

D28's position differs deliberately and the difference is worth stating: for a
VPN whose stated purpose is reaching arbitrary destinations, an allow-list is
not always possible (the destination set is genuinely unbounded — that is
"Case 2" in the cheat sheet, where allow lists "cannot be used here"). So D28
is the cheat sheet's "Case 2" shape: a block-list *plus* a narrow explicit
allow override for the private ranges that the operator genuinely intends to
expose, rather than a pure deny-list. The cheat sheet's own minimum block list
does **not** include `100.64.0.0/10`, which is why the Alibaba finding above
matters — a checklist-derived denylist would miss it.

The cheat sheet also warns that block-lists are "bypass-prone" — D28 accepts
this residual and records it as a tradeoff rather than claiming completeness.

---

## 5. CISA

- URL fetched: <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a>
  (Alert AA22-320A, revised 2022-11-25.)

Fetched while looking for a CISA advisory specifically on IMDS/metadata egress
filtering. **AA22-320A is not such an advisory** — it is an Iranian-APT
Log4Shell/VMware Horizon intrusion advisory. It is retained here only because
one mitigation is adjacent and quotable: the Proxy technique (T1090) mitigation
M1037 reads "Traffic to known anonymity networks and C2 infrastructure can be
blocked through the use of network allow and block lists."

That is generic support for the *technique* of egress allow/block listing. It
is **not** cited anywhere in the D28 design doc as authority for any specific
CIDR. A dedicated CISA/NCSC advisory on blocking instance metadata endpoints
was **not located** in this pass — see §6.

---

## 6. Not retrieved / UNVERIFIED

The following were sought but not obtained. **No D28 decision depends on
them.** They are recorded so a later agent does not mistake absence of a
citation for absence of consideration.

| Item | Why sought | Status |
| --- | --- | --- |
| RFC 5771 (IP Multicast) | Would be the normative citation for `224.0.0.0/4` / `ff00::/8`, which RFC 6890 does not cover | **UNVERIFIED** — not fetched. D28 blocks multicast on amplification-abuse grounds, not on RFC authority. |
| A CISA/NCSS advisory specifically on blocking cloud metadata endpoints | Would be a direct citation for the highest-severity row | **UNVERIFIED** — not located. The per-vendor vendor documentation (§3.1, §3.3, §3.4, §3.5) carries that row instead, and those are first-party. |
| OPNsense / OpenVPN egress-filtering documentation | Would have been the "mature firewall appliance" practice datapoint alongside WireGuard | **UNVERIFIED** — two candidate URLs returned 404. WireGuard (§4.1) plus the OWASP sheet (§4.3) are the retrieved practice references. |
| Linux `sendto`/`connect` to UDP port 0 | Would confirm the Linux half of the port-0 OS-behaviour question | **UNVERIFIED** — WSL is present on this host but has no installed distro, so no Linux run was possible. Only the Windows measurement is empirical. The D28 design does not depend on the answer (port 0 is rejected by Tunnel regardless), but the *rationale text* claims only what was measured. |
| Alibaba ECS IPv6 metadata endpoint | Would complete the IPv6 metadata picture | **UNVERIFIED** — the fetched Alibaba page documents only `100.100.100.200`; no IPv6 metadata address is given. |
| `web_search` tool | Broader discovery | **UNAVAILABLE** this session (`426 Upgrade Required`). All external material above came from direct `web_fetch` of known-primary URLs. This narrows discovery — the reference set is deep on primary/vendor sources but not broad. |
