# Track H — TCP / Stream Transport: Research Verdict

**Status:** Research only. No implementation code. No commit.
**Scope:** Whether and when a stream transport belongs in pq-tunnel.
**Working tree:** HEAD `ae8061d` == `origin/main` (verified `git rev-parse`, 2026-10-05).

---

## 0. Verdict

> ## **Do not add a native TCP/stream transport. Ever — as a transport of record.**
>
> The TCP application gap that D18 defers is real, but it is **not a
> transport-layer problem, and solving it at the transport layer is the wrong
> layer and the wrong cost.** Two other routes exist that keep the D19 cover
> floor, the D13 1280-byte record model, and the D20 single-transport posture
> completely intact.
>
> | If the need is… | Use | Never |
> |---|---|---|
> | TCP apps *today*, pre-TUN | TCP-over-UDP (userspace TCP stack in the tunnel's fixed slot) | native stream transport |
> | TCP apps *after* TUN (D25/D26) | **nothing** — the OS terminates TCP locally | native stream transport |
> | Reachability past UDP blocking | a **separate, transport-agnostic carrier** milestone (obfs4-style), explicitly a *second* transport | folding it into the D13 record plane |

**The decisive argument is §7.3.** With TUN (D25/D26) as the primary target, the
tunnel carries **IP packets**, and the host OS terminates TCP locally. The tunnel
therefore *never carries a TCP connection*. A transport-level "stream mode" is
code with no call site. Building it before TUN ships is building for a world
that the primary transport target deletes.

**The three findings that make this unusually clear-cut:**

1. **The nonce discipline makes native stream framing dangerous.** `CipherSession::encrypt`
   *always* advances `send_counter` (`envelope.rs:294-299`). There is no
   "re-emit at the same counter" path for data records. A TCP retransmit at the
   application level would either burn nonces or require a byte-cache discipline
   that exists for the handshake (`handshake_v2.rs:976-1021`) but **not** for
   data records. See §5.
2. **The arithmetic is worse than the brief assumed.** RFC 6298 mandates
   `RTO = SRTT + max(G, 4·RTTVAR)` with a **1-second floor** (§2.4) and
   **exponential backoff** (§5.5). The brief's "RTO ~100–200 ms" is not
   RFC-6298-compliant TCP. Real stall cost is **195–780 missed cover slots**,
   not 20–40. See §1.2.
3. **A lossy stream destroys the exact property D19 exists to provide.** D19's
   pure-periodic grid is *our* pattern. TCP hands its timing to the network's
   congestion control, and RFC 5681 §3.1 mandates behaviour that is
   *anti*-periodic by construction. This is the "burst = fingerprint" failure
   D19 was designed against. See §4.3.

---

## 1. Stream framing

### 1.1 Fixed-size reads are genuinely the easy case

`PACKET_SIZE = 1280` is a compile-time constant
([`codec.rs:103`](C:/Users/Dhane/dev/tunnel/pq-tunnel-core/src/codec.rs)) and
the layout is guarded by `const _: () = assert!(HEADER_LEN + INNER_PLAINTEXT_LEN + AEAD_TAG_LEN == PACKET_SIZE, ...)`
(`codec.rs:145-151`). So a stream *can* read exactly 1280 bytes per frame with
no length prefix. **This part of the analysis is correct and it is the only part
that is easy.**

**But "no prefix" buys nothing on a stream.** §3.7 of RFC 9293 is explicit:

> "TCP guarantees no correlation between the boundaries of TCP segments sent and
> received and the boundaries of the read or write buffers of user application
> data."
> — [RFC 9293 §3.7](https://www.rfc-editor.org/rfc/rfc9293.html)

On a stream, record boundaries exist **only** at the sender's `write()` calls.
A passive observer sees none of them (§4). But so does the *receiver's
framer* — it must count bytes. That is fine and cheap.

**The cost that fixed framing does NOT remove: desynchronization.** If the
framer ever loses count, it is permanently desynchronized. The datagram plane's
answer is structural and already free: `UdpTransport::recv` rejects any
datagram that is not exactly `PACKET_SIZE` (`udp.rs:169-186`), and both
oversize and undersize map to `UdpError::WrongSize`. A stream has no such
invariant — there is no "size" to check, only a byte count, and a one-byte
framer bug reads every record as garbage.

This is why D13's handshake pins a fragment-count invariant
(`frag_total` must equal a *pinned* count; `frag_idx < frag_total` —
`handshake_v2.rs:334-348` per D25-D26 §4.3). A stream framing layer would
need the same discipline with no independent check available.

### 1.2 Head-of-line blocking — quantified (and worse than briefed)

**The arithmetic.**

- Cover interval: `interval_from_rate_bps(2_000_000)` =
  `1280 × 8 × 1e9 / 2_000_000` = **5,120,000 ns = 5.12 ms exactly**
  ([`scheduler.rs:164-166`](C:/Users/Dhane/dev/tunnel/pq-tunnel-core/src/scheduler.rs) asserts this).
- Cover rate: `1 / 0.00512 s` = **195.3125 pkt/s per session per direction**.

**RFC-6298-compliant RTO, not the briefed figure.** From
[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html):

- §2.4: "if it is less than 1 second, then the RTO SHOULD be rounded up to **1 second**."
- §5.5: "The host MUST set `RTO <- RTO * 2`" on each timeout.
- §2.3: `RTO = SRTT + max(G, 4·RTTVAR)`, α=1/8, β=1/4.

So with steady-state `RTT = R`, `RTTVAR = R/2` at steady state, giving
`RTO ≈ R + 2R = 3R`, floored at 1 s:

| Path | Steady-state RTO (no floor) | Effective RTO | Missed cover slots @ 5.12 ms |
|---|---|---|---|
| LAN, R ≈ 1 ms | 3 ms | **1 s (floor)** | **195** |
| Regional, R ≈ 40 ms | 120 ms | **1 s (floor)** | **195** |
| Transatlantic, R ≈ 150 ms | 450 ms | **1 s (floor)** | **195** |
| Long-haul R ≈ 400 ms | 1.2 s | **1.2 s** | **234** |
| + one timeout (backoff ×2) | — | **2.4 s** | **469** |
| + second timeout (×2 again) | — | **4.8 s** | **938** |

The brief's "RTO ~100-200 ms → ~20-40 missed slots" understates the impact by
**roughly an order of magnitude**, because it assumes a sub-second RTO that
RFC 6298 §2.4 explicitly forbids. Even under the brief's own optimistic
assumption, 100-200 ms / 5.12 ms = **19.5–39 slots** — and those slots are
*silently* absent rather than re-emitted, because §1.5 shows the scheduler
cannot.

**Crucially, the stall is not bounded by the RTO.** With `cwnd` reduced on loss
(RFC 5681 §3.1: `ssthresh = max(FlightSize/2, 2·SMSS)`), after an RTO
recovery TCP enters **slow start** and must rebuild the window from 1 segment.
Rebuilding to a cwnd sufficient for 195.3 pkt/s takes multiple RTTs. So the
true disturbance is `RTO + slow-start-rebuild`, and for the default 2 Mbps
cover rate on a WAN path the total can reach **several seconds** — i.e. **10³+
missed cover slots**, against a D19 grid whose entire design premise is
stability.

**Fast retransmit does not save us.** RFC 5681 §3.2 requires 3 duplicate ACKs
before retransmitting. A single segment loss in a mostly-in-order TCP stream
generates *one* dup-ACK, not three — so the first loss of a stream
**necessarily** waits for the RTO. HoL is the common case, not the rare one.

### 1.3 Cover over a separate UDP path while data uses TCP

**Does it preserve the D19 floor?** Nominally yes — the grid stays on UDP and
stays periodic. **But it creates a strictly worse observable, and it does not
actually preserve the floor.**

Two problems, one fatal:

1. **It requires two tunnels.** Each tunnel has its own `sid`, its own
   handshake (D13: 10 datagrams, ~12,800 bytes), and its own nonce space. An
   observer sees **two established sessions from the same host**, with two
   independent lifecycles. §6.2 covers why that is a signal in itself.
2. **It does not work with one handshake.** The D13 handshake produces **one**
   `CipherSession` per role, and `WireSession::cover` and `WireSession::encrypt`
   share the same `send_counter` (`wire_session.rs:210-240` → `envelope.rs:294-299`).
   Splitting cover onto a second transport means a second session, a second
   handshake, and D16 rekey applies to both. This is not a transport change; it
   is a **multi-session protocol**, and D24's session-count and fail-gate
   reasoning would have to be re-derived for two coupled sessions per host.

So "cover on UDP, data on TCP" preserves the *letter* of the D19 floor while
multiplying the session-lifecycle leakage that D22 already lists as an accepted
residual ("server session count, session liveness, establish/rekey/close
lifecycle events"). **It trades a timing leak for a session-count leak.**

### 1.4 Two-flow separability

An observer sees flow A: constant 195.3 pkt/s, uniform 1280 B, no variance.
Flow B: bursty, congestion-controlled, retransmitting. **Separating them is
trivial and does not require breaking either flow's crypto.** Per-connection
statistics — packet-size distribution, inter-arrival variance, retransmission
rate — are the *easiest* classifier features available. The two-flow structure
is not a side effect an observer must work to find; it is the signal.

---

## 2. Padding

### 2.1 Record-level padding: unchanged, and not the risk

`PAYLOAD_LEN = 1245`, `INNER_PLAINTEXT_LEN = 1247`, no length field,
implicit zero-fill (`codec.rs:137-139`). On a stream this is identical — every
record is 1280 B regardless of content. **Record-level size leakage: zero
change. This part of the datagram-plane argument survives a stream intact.**

### 2.2 Segment-level padding — the honest answer

The brief asks whether padding TCP *segments* would help hide per-record timing.
**It would not, and it would be self-defeating:**

- **Segment sizes are chosen by the receiver's advertised MSS** (RFC 9293
  §3.7.1: `Eff.snd.MSS = min(SendMSS, MMS_S) - TCPhdrsize - IPoptionsize`).
  Padding to a *fixed* segment size forces a small MSS on high-MTU paths,
  multiplying segment count; padding to *variable* sizes pads nothing.
- **Nagle (§3.7.4) plus delayed ACK (§4.2 of RFC 5681: "an ACK SHOULD be
  generated for at least every second full-sized segment") produces exactly the
  1-segment / 1-ACK oscillation the datagram plane has no analogue of.** RFC
  9293 §3.7.4 notes "there are problematic interactions between the Nagle
  algorithm and delayed acknowledgments." This is a *known, documented*
  artefact, and it is per-connection state an observer can characterise.
- **Timing jitter on a stream is dominated by congestion control, not by our
  scheduler.** RFC 5681 §3.1 mandates cwnd growth/decay driven by ACK arrival
  and loss. Our D19 scheduler has *no* influence on it once bytes are handed to
  the socket. Padding segments cannot restore a cadence we no longer control.

**The honest summary: on a stream we lose control of the observable timing
pattern, and padding segments is not a way to get it back.** D19's guarantee is
protocol-level, and TCP substitutes network-level timing for it.

### 2.3 A segment-padding side effect worth flagging

Padding segments to fixed sizes is itself **an active fingerprint**: a
connection that emits only one segment size forever, with no variation, is not
normal TCP behaviour. RFC 9293 §3.7.1 lists the *legitimate* reasons TCP
segments vary (reducing packets in flight, reducing overhead, avoiding MTU
limits). A frozen segment-size distribution is a signature, not camouflage.

---

## 3. Backpressure

### 3.1 The benefit, and why it is a hazard here

Flow control is a genuine benefit the datagram plane lacks. But it converts
"fire and forget" into "block", and blocking is exactly what D19's scheduler
cannot tolerate (§3.4).

### 3.2 Required bounds

At `--cover-mbps 2` the cover grid alone is **2,000,000 bits/s ÷
(1280 × 8) bits/packet = 195.3125 pkt/s**. Any buffer sizing must assume the
sender is *permanently* producing at this rate:

- Per-connection **send** buffer ≥ `Bdp` (bandwidth-delay product). On a
  100 Mbps path with 50 ms RTT: `100e6 × 0.05 / 8` = **625 KB**. Unbounded, a
  slow reader accumulates this per session.
- **Read** buffer: at minimum one full 1280-B record plus headroom;
  **fail-closed on overflow** per `AGENTS.md` — never silently drop, never grow.
- **Multiplied by `max_sessions`** (default 64, D24): 64 × 625 KB = **40 MB**
  of pure buffer for one throughput-dominant path, before any real payload.

Per D24's existing posture ("Resource exhaustion was also missing from the
formal threat-model enumeration altogether"), every one of these numbers is a
**new attacker-influenceable bound requiring a new decision**. A stream does not
add one bounded resource; it adds a *family* of them.

### 3.3 Nonce interaction — the decisive correctness point

> **Backpressure must NOT cause nonce skipping.** `MAX_PACKET_NONCE =
> u64::MAX - (1<<32)` ([`codec.rs:121`](C:/Users/Dhane/dev/tunnel/pq-tunnel-core/src/codec.rs))
> and `is_counter_exhausted` is checked *before* encryption
> (`envelope.rs:269-273`); hitting it returns `CodecError::NonceExhausted` and
> drives rekey per D16. Nonces are a **dense monotonic sequence**, and the
> receiver's replay window is keyed on exactly that density
> (`replay.rs:88-151`).

If backpressure caused the sender to *skip* counters to "save" them, the
receiver's `ReplayWindow` would see a gap. Looking at `accept()`: a forward gap
larger than `WINDOW_BITS = 1024` **clears the window** (`replay.rs:95-120`), and
a gap that lands a legitimate in-flight record outside the window **rejects it
as a replay** (`replay.rs:127-135`). So skipping nonces would not merely waste
counter space — it would **break in-flight delivery** of already-sent records.
Skipping is therefore not merely undesirable, it is **incorrect**.

The only correct options are: (a) block until writable (delays the cover
deadline — §3.4), or (b) buffer records (costs memory — §3.2). There is no
third option that preserves both the nonce sequence and the D19 deadline.

### 3.4 Backpressure directly conflicts with D19's "at most one emission" rule

D19's scheduler is *explicitly* designed so that a stall produces **exactly one**
catch-up packet and **never a burst** ([`scheduler.rs:24-27`](C:/Users/Dhane/dev/tunnel/pq-tunnel-core/src/scheduler.rs),
`DESIGN_DECISIONS.md:949-953`):

> "when the deadline passes it yields **at most one** emission and reschedules
> from 'now'. A delayed driver wake (OS scheduling) therefore produces a single
> catch-up packet — never a buffered burst, which would itself be a traffic
> fingerprint."

This works on the datagram plane because `send_to` on a UDP socket does not
block. On a full stream, the scheduler's emission **cannot be delivered**, so
the driver must either:
- skip it (→ D19 violation: the slot is simply absent, §1.2), or
- queue it (→ D19 violation: a burst, which D19 names as the fingerprint), or
- block the scheduler loop (→ all subsequent deadlines slip; the grid shifts
  phase permanently, because each re-arm is from `now + interval`).

Every branch degrades D19. **Cover-over-TCP is not merely risky for D19 — it is
incoherent with D19's specified semantics.** D19 assumes the scheduler's output
reaches the wire immediately and unconditionally; a stream removes that
assumption.

---

## 4. Timing / length leakage — the core question

### 4.1 Datagram plane (today)

Constant 1280 B records, constant 195.3125 pkt/s, per session per direction.
Leakage, per D22, accepted by design:

- volume / activity above the floor (the λ·W ≥ 1 bound),
- server session count, session liveness,
- lifecycle events (establish / rekey / close).

Per-record content is sealed inside the AEAD with `MessageType` and `Direction`
both inside the ciphertext (`codec.rs:221-224`). **This is a well-characterised,
documented, bounded leakage profile.**

### 4.2 Stream plane — the argument is genuinely mixed

**In favour of a stream (stated honestly):** record boundaries become
**invisible** to a passive observer. In the datagram plane, every record is a
separately-visible 1280-byte datagram and the *count* is directly observable.
On a stream, an observer sees an opaque byte stream and cannot segment it into
records without the key. For a specific narrow question — "is there exactly one
AEAD record per X bytes?" — a stream is genuinely *better*.

**Against (and this dominates):** TCP exports a much larger observable surface:

| Observable | Datagram plane | Stream plane |
|---|---|---|
| Record boundaries | Visible (1 per datagram) | **Invisible** ✅ |
| Record size | Constant 1280 B | Constant 1280 B, but buried |
| Inter-record timing | ~constant 5.12 ms | **Congestion-controlled, not constant** ❌ |
| Segment size distribution | N/A (uniform) | **Varies with MSS, cwnd, Nagle, delayed ACK** ❌ |
| ACKs | None | **Every ~2 segments; carries RTT + cwnd state** ❌ |
| Retransmissions | None | **Distinctive duplicate byte-runs** ❌ |
| RTT / cwnd / ssthresh | None | **Observable by design** ❌ |
| SYN/FIN lifecycle | Datagram-shaped | **Standard TCP fingerprint** ❌ |
| Congestion response | None (fire-and-forget) | **RFC 5681-mandated, attacker-triggerable** ❌ |

**Quantitative verdict:** a stream removes **one** observable (record
boundaries) and adds **eight**, of which the timing row is the one D19 exists to
prevent. Under D22's framing ("reduction, not anonymity"), the *marginal*
leakage of the datagram plane is an accepted residual; the stream's leakage is
a **new class** — one whose worst cases (multi-second stalls, RTO-driven
cwnd collapse, bursty recovery) produce *high-entropy, connection-specific*
patterns that are far easier to fingerprint than a constant offset from a floor.

### 4.3 Does adding TCP undermine D19? — yes, and this is the strongest argument against

**D19's premise** (`DESIGN_DECISIONS.md:931-935`): cover must create a "**stable
observable traffic pattern over time** — a protocol-level constant rate." The
word *protocol-level* is load-bearing. The guarantee is that the pattern is
produced by *our* logic, not by the network's.

**TCP hands the pattern to the network.** Three RFC-mandated behaviours drive
the observable pattern directly away from periodicity:

1. **RTO recovery collapses the rate.** RFC 5681 §3.1: on timeout, "cwnd MUST
   be set to no more than the loss window, LW, which equals 1 full-sized
   segment." A 195.3 pkt/s stream becomes a 1-packet-per-RTT stream, then
   slow-starts back. The observable is a **rate collapse and exponential
   recovery** — the canonical congestion signal, and trivially classifiable.
2. **cwnd is a visible, attacker-influenceable state variable.** RFC 5681 §5
   (Security Considerations) says so directly: "An attacker can therefore impair
   the performance of a TCP connection by either causing data packets or their
   acknowledgments to be lost, or by forging excessive duplicate
   acknowledgments." **A censor can deliberately induce the fingerprint.** We
   would be shipping a self-inflicted, remotely triggerable traffic anomaly.
3. **Restart-after-idle reintroduces the line-rate burst** (RFC 5681 §4.1).
   A session that was briefly idle emits a cwnd-size burst — again the pattern
   D19 names as the thing to avoid.

**The decisive framing:** a lossy stream converts "constant 195.3125 pkt/s ±
jitter" into **"stalled, then bursty"** — and *burst = fingerprint* is precisely
the failure mode D19 was engineered to design against. **D19's guarantee is
conditional on the transport delivering each emission immediately. A stream
removes that condition.** Adding TCP would therefore not be a neutral
transport swap; it would be a **silent reduction of metadata resistance**,
which `AGENTS.md` forbids outright ("never silently reduce security guarantees;
never remove metadata resistance without explicit approval").

**And note the asymmetry that settles it:** on the datagram plane, a loss
costs *one slot* out of 195.3/s — a statistically invisible event against a
constant background. On a stream, a loss costs **195–938 slots plus a slow-start
rebuild** (§1.2). **The same physical loss event is ~4 orders of magnitude more
observable on a stream.** That is the whole argument, in one line.

---

## 5. Retransmission

### 5.1 Does a retransmitted record fingerprint? Yes — this is a real new surface.

A TCP retransmit emits **the identical byte-run again** (RFC 9293 §3.8: "Because
segments may be lost ... TCP uses retransmission to ensure delivery of every
segment. Duplicate segments may arrive due to network or TCP retransmission").
The record payload is AEAD-protected — but the *duplicate itself* is a
first-class observable: same length, same bytes, later in time. Our design has
**no defence against this and no place to put one**, because it is a property of
the outer transport. An observer sees a 1280-byte exact-duplicate and knows
(a) this is a fixed-size tunnel, and (b) a packet was lost here.

Contrast with the datagram plane: a lost record is simply *absent*. There is no
duplicate, because there is no retransmission. **The datagram plane has no
"same bytes twice" signature.**

### 5.2 The AEAD nonce question — verified in source, and the answer is a hazard

The brief's reasoning is cryptographically correct: ChaCha20-Poly1305 nonce
reuse with the **same plaintext** yields the **same ciphertext** and is not a
break (nonce *reuse* in the dangerous sense means encrypting **different**
plaintexts under the same nonce). So **if** a retransmit is byte-identical,
there is no cryptographic problem.

**But the code does not guarantee byte-identical retransmission for data
records.** This is the important verified finding:

```257:299:C:\Users\Dhane\dev\tunnel\pq-tunnel-core\src\envelope.rs
pub fn encrypt(&mut self, msg_type: MessageType, payload: &[u8])
    -> Result<WirePacket, CodecError> {
    ...
    if codec::is_counter_exhausted(self.send_counter) {
        return Err(CodecError::NonceExhausted { counter: self.send_counter });
    }
    let inner = InnerPlaintext::new(msg_type, self.role.send_direction(), payload)?;
    let header = PacketHeader::new(self.session_id, self.send_counter);
    let aad = header.encode();
    let nonce = AeadNonce::from_bytes(
        build_session_nonce(self.send_prefix(), self.send_counter));
    let mut ciphertext = aead_encrypt(self.send_key(), &nonce, &inner.encode(), &aad)?;
    ...
    let packet = WirePacket::from_parts(&aad, &ciphertext)?;
    ...
    self.send_counter = self.send_counter.checked_add(1)
        .ok_or(CodecError::NonceExhausted { counter: self.send_counter })?;
    Ok(packet)
}
```

**`CipherSession::encrypt` unconditionally advances `send_counter`
(`envelope.rs:294-299`) and has no parameter, variant, or path that re-emits at
the current counter.** The counter is baked into *three* places that must all be
identical for a byte-identical retransmit: the cleartext header
(`PacketHeader::new`, `envelope.rs:276`), the AAD (`header.encode()`,
`envelope.rs:277`), and the AEAD nonce
(`build_session_nonce(..., send_counter)`, `envelope.rs:278-279`).

**Consequences for a stream transport:**

- Calling `encrypt()` twice produces **two different packets with two different
  nonces** — not a duplicate. That is not a retransmit; that is two records,
  and it **burns two nonces for one unit of data**.
- Producing a true byte-identical retransmit requires either
  (a) **caching the encrypted `WirePacket`** and re-sending it, or
  (b) a new "encrypt at counter N" API — which is a **new cryptographic
  entry point** and, per `AGENTS.md`, would need a fresh decision, review, and
  KAT coverage. It is exactly the class of change that created the pre-v2 XOR
  combiner bug called out in D13.

**The discipline exists — but only for the handshake.** D13 mandates it
explicitly (`DESIGN_DECISIONS.md:611-614`, `:627-629`):

> "Retransmission is client-driven: M1 and M3 retransmitted **byte-identical**…"
> "Byte-identical retransmission is guaranteed by **byte caching**
> (`m1_frags`, `m3_frags`, `m2_cache`), never by re-signing… Cached handshake
> bytes MUST NOT be re-derived on retransmit."

And it is implemented that way: `ClientState` stores `m1_frags: Vec<WirePacket>`
(`handshake_v2.rs:976`), accessed via `m1_frags()` / `m3_frags()`
(`handshake_v2.rs:1020-1030`), and retransmission emits
`Ok(ClientEvent::Emit(self.m1_frags.clone()))` (`handshake_v2.rs:1085`, `:1101`).
The server caches `m2_cache: Option<Vec<u8>>` (`handshake_v2.rs:1311`) and
resends the *pristine* bytes (`:1540-1550`).

**So the answer to "does D13's discipline generalize?" is: the *principle* does,
but the *implementation does not exist for data records*, and it cannot be
reused as-is because it is per-session, per-message, and hardcoded to the three
handshake messages. Generalizing it means a general "unacked record cache" in
`WireSession` — which, on a stream, is precisely an unbounded-memory surface
bounded only by the congestion window (§3.2). **This is the single strongest
correctness argument against a native stream transport.**

### 5.3 Summary of §5

| Question | Answer | Evidence |
|---|---|---|
| Same nonce + same plaintext safe for ChaCha20-Poly1305? | **Yes** (deterministic re-encryption) | Standard AEAD property |
| Does the code guarantee a data-record retransmit is byte-identical? | **No** | `envelope.rs:294-299` — counter always advances |
| Is a byte-cache mechanism available? | **Handshake only**, per-message, not generalizable as-is | `handshake_v2.rs:976, 1020-1030, 1085, 1311` |
| Would skipping nonces instead be safe? | **No** — breaks replay window + in-flight delivery | `replay.rs:95-135`; `MAX_PACKET_NONCE` `codec.rs:121` |
| Does TCP retransmission fingerprint? | **Yes** — exact-duplicate byte-runs, new observable | RFC 9293 §3.8 |

---

## 6. Interaction with cover traffic

### 6.1 Jitter a typical RTT/jitter/loss profile introduces

Take a typical regional path: `R = 40 ms`, jitter `σ ≈ 10 ms`, loss `p = 0.5%`.
Cover interval `T = 5.12 ms`.

- **Jitter alone** (no loss): an ACK-driven stream has its cadence perturbed by
  `σ`. Arrival-time std-dev of the 195.3 pkt/s grid becomes
  `≈ sqrt(T² + σ²) = sqrt(5.12² + 10²) ≈ 11.2 ms` — a **~2.2× inflation** of
  the natural grid variance. At this cadence, sub-`T` timing jitter is already
  at the edge of what a 5.12 ms grid can express.
- **Loss 0.5%:** per second, expected losses = `195.3125 × 0.005 = **0.977**`
  — i.e. **roughly one loss per second, every second**, on a perfectly ordinary
  path. Each of those costs a full RTO stall of **1 s** (§1.2) → **195 cover
  slots**. **On a 0.5%-loss path, cover over TCP is essentially non-functional**:
  the grid spends most of its life stalled or in slow-start recovery.
- **Why the datagram plane is immune to this:** it has **no ACK, no cwnd, and no
  RTO**. A 0.5% loss rate just removes 0.5% of packets from a constant
  background — invisible against the floor. **This is the cleanest possible
  statement of the core difference.**

For contrast, loss-free + low-jitter (LAN, σ ≈ 0.5 ms) would keep a stream
usable. That is exactly why a stream would look fine in a lab and fail in
production — and why the D23 Windows clock work (§ measuring an actual host's
wakeup cadence) is the right precedent for how this must be validated.

### 6.2 Separate connections: help or hurt?

**Hurt, unambiguously.** Two flows from one host:

- **Separable by construction.** Flow A: constant rate, zero variance, uniform
  size, zero retransmits. Flow B: all four properties inverted. This is the
  easiest possible classification task — no crypto break required.
- **Session-lifecycle leakage multiplies.** Each tunnel = one `sid`, one D13
  handshake (10 datagrams), one D16 rekey clock, one liveness signal. D22
  already concedes "server session count, session liveness, lifecycle events" —
  this **doubles every one of those residuals**.
- **Correlation between flows is available.** Both flows share a host, a path,
  and (on most networks) a NAT address. A censor measuring at the client's
  egress sees both.

**"Two flows, one constant and one bursty" is not camouflage — it is a
label.** The constant flow is *identified as the cover flow*, which is worse
than having no separate cover flow at all, because it tells the observer
exactly which bytes are the ones to attack.

### 6.3 Is cover-over-TCP coherent with D19's semantics? No.

D19 specifies **pure-periodic, at most one emission per missed deadline,
rescheduled from "now"** (`DESIGN_DECISIONS.md:949-953`;
[`scheduler.rs:130-147`](C:/Users/Dhane/dev/tunnel/pq-tunnel-core/src/scheduler.rs)).
Two preconditions are implicit in that design:

1. **The emission reaches the wire immediately.** A stream with a full send
   buffer removes this. See §3.4 — every handling (skip / queue / block)
   violates D19.
2. **The grid is generated by us.** TCP's cadence is set by ACK arrival and cwnd,
   not by our scheduler (§4.3).

So cover-over-TCP would not be "a transport that makes D19 jittery." It would
be **a transport that makes D19's stated semantics unachievable**, requiring a
D19 rewrite with a weaker, differently-defined guarantee. Per `AGENTS.md`
("missing security requirement → do not silently continue"), that is a
**milestone-scale architectural change, not a transport addition**.

---

## 7. When is it worth adding? — the verdict

### 7.1 What breaks **today** without TCP

D18 (`DESIGN_DECISIONS.md:901-902`, `:914-918`) scopes v0.2 to UDP only and
names two gaps explicitly:

- "**Scope**: UDP only in v0.2. TCP through the relay requires a stream layer
  and is deferred."
- Tradeoffs: "UDP-only: **TCP apps need a stream milestone**"; "**no ICMP /
  unreachable feedback in v0.2**".

Concrete user-visible failures today:

| Application | Behaviour today | Why |
|---|---|---|
| **Web (HTTP/1.1, HTTP/2)** | **Broken** | Both are TCP-only. No browser path exists. |
| **HTTP/3 (QUIC)** | **Works** | Native UDP — it is what the relay already carries. |
| **DNS** | **Works** | UDP port 53. (`D25-D26` Q6 asks whether to ship a resolver — separate concern.) |
| **VoIP / WebRTC** | **Works (UDP), poor on TCP fallback** | STUN/TURN over UDP. |
| **Games (multiplayer)** | **Works** | UDP-native. |
| **Email (SMTP/IMAP), SSH, RDP, SMB, VPN clients, HTTPS APIs** | **Broken** | All TCP-only. |
| **Software update / package fetch** | **Broken** | TCP. |
| **Port-scan reachability** | **No feedback** | No ICMP synthesized (D18). |

**The real damage is the web.** Everything reachable only over HTTP/1.1 or
HTTP/2 — which today is the large majority of the web, since HTTP/3 adoption is
still partial — plus SSH, email, and every package manager. A tunnel that
cannot load a web page is not usable for its stated purpose, so **this gap is
genuinely severe.**

But note what the severity *implies*: the correct remedy is the one that makes
**all of them** work at once — full IP-layer transport (TUN) — or the one that
restores TCP semantics inside the existing record model (TCP-over-UDP). **Neither
is "add a stream transport to the tunnel."**

### 7.2 The decisive argument: with TUN, the tunnel never carries TCP

TUN is the settled primary transport target (D25/D26, and the brief's own
settled assumptions). Reasoning it through:

1. A TUN device presents an **OS network interface** and moves **IP packets**
   (`D25-D26` §1.1: "the tunnel's own outer UDP socket"; §1.2 sets
   `TUN MTU = 1241` and computes `MSS = 1201` for the *inner* TCP).
2. The **host's TCP stack terminates inner TCP connections locally**. MSS is
   negotiated by the OS from the interface MTU; the doc states "OS stacks derive
   this automatically from the interface MTU; we do not clamp sockets."
3. Therefore **every inner TCP byte becomes ordinary IP payload** and is
   fragmented by the D25 in-slot overlay into 1280-byte records — the *same*
   records, the *same* AEAD, the *same* nonce counter, the *same* cover grid.
4. **The tunnel never sees, parses, sequences, retransmits, or acks a TCP
   connection.** It carries a TCP-shaped IP packet the way it carries a UDP
   datagram today.

Therefore, in the TUN world:

- A tunnel-level "stream mode" has **no call site**. There is no stream to
  frame — only IP packets.
- TCP support is **not a transport feature of the tunnel**; it is a property of
  the operating system the tunnel is attached to.
- **TUN delivers full TCP support as a side effect of being a network
   interface**, with zero changes to the D13 record plane, zero new framing, zero
  head-of-line blocking, zero retransmission surface, and zero threat to D19.

This is not an argument that TCP support is unimportant — it is an argument
that **at the transport layer it is the wrong layer.** TUN already contains the
answer. `D25-D26` §1.2 computes the inner MSS (1201) and §4.2 lists `codec.rs`,
`envelope.rs`, `wire_session.rs`, `scheduler.rs`, and `udp.rs` as reusable
**unchanged** — the record plane survives TUN intact.

**Corollary on split tunneling:** per-process masking / split tunneling is
backlog, but it is *not* load-bearing for this verdict. Even in a hypothetical
per-process world, the terminating TCP stack would still be **local** — the OS
terminates inner TCP for the app regardless of which apps are masked. A
remote/streaming TCP proxy would only be needed for apps whose traffic is
deliberately proxied rather than tunnelled as IP, and that is a **product
feature (the D18 relay), not a transport.**

### 7.3 The alternatives, compared

| Criterion | **Native stream transport** | **TCP-over-UDP (userspace TCP stack)** | **TUN with OS TCP stack** |
|---|---|---|---|
| Adds TCP app support | Yes | Yes | **Yes (all TCP, incl. future protocols)** |
| Transports used | **2** (UDP + TCP) | **1** (UDP only) | **1** (UDP only) |
| Keeps `PACKET_SIZE=1280` record model | Yes | **Yes** (stack runs *inside* the slot) | **Yes** (D25-D26 §4.2: `codec.rs`/`envelope.rs`/`wire_session.rs` reused unchanged) |
| D13 handshake reusable | Yes (but two transports → two sessions) | **Yes, unchanged** | **Yes, unchanged** |
| D19 cover grid preserved | **NO** — HoL, §1.2/§4.3/§6.3 | **Yes** — stack is inside a datagram; grid unaffected | **Yes** — `scheduler.rs` "must not be touched" (D25-D26 §4.2) |
| HoL blocking | **Yes, 195–938 slots/RTO** | **No** (one slot lost per drop; stack retransmits in a later slot) | **No** |
| Timing control | **Lost to congestion control** | **Retained** (scheduler unaffected) | **Retained** |
| Record-boundary visibility | Hidden | Visible (as today, uniform) | Visible (as today, uniform) |
| Retransmit fingerprint | **Yes** (dup byte-runs) | No (records independent; inner TCP retransmits inside a new slot) | No |
| Nonce/counter correctness risk | **HIGH** — needs byte-cache for data records (§5.2) | **None** — no nonce reuse path exists | **None** |
| New attacker-influenceable bounds | **Many** (send/read buffers × sessions) | **Some** (per-connection stack state × sessions) | Documented in D25-D26 §1.5 |
| New security decisions needed | **~10** (see §8) | **~3** | Already scoped (D25/D26) |
| Deps / attack surface | New stream impl + congestion control | Userspace TCP stack (e.g. `smoltcp`) | TUN lib (already Q3) |
| Blocks quic-to-tunnel gain from D20 | **Partly** — re-treads removed surface | No | No |
| Operational complexity | **High** (two transports, two sessions) | Medium (one transport, inner state) | **Low** (one transport) |

**TCP-over-UDP is strictly better than a native stream transport on every
criterion that matters, and it is the only option that keeps ONE transport.**

Its costs, stated honestly: (a) it needs a userspace TCP stack in a dependency
(`smoltcp`-class) — which must be evaluated for MSRV 1.85 and the `-D warnings`
clippy gate, the same constraint D25-D26 Q3 flags for TUN; (b) the inner TCP
stack's own behaviour (its RTO, its cwnd) becomes an internal implementation
detail **invisible to the observer**, because it lives inside sealed 1280-byte
records — which is a privacy *benefit*, not a cost; (c) it is genuinely more
work than "open a `TcpStream`."

**But (c) is the whole point: it is more work than adding a transport, and
strictly less work than making the D19 guarantee survive a stream.** It solves
the §7.1 gap without touching any guarantee.

### 7.4 What would have to be true for the verdict to change

The verdict flips to "conditional, worth a milestone" only if **all** of these
hold:

1. **TUN is definitively abandoned or indefinitely delayed**, *and* the product
   commits to being a per-app relay rather than a network interface. Without
   this, TCP-over-UDP dominates (§7.3).
2. **A measured deployment profile shows UDP is blocked/throttled while TCP
   survives** at rates that make the tunnel unusable over UDP alone. This must
   be a **measurement on the target networks**, not an assumption. (Note: §7.5's
   evidence says blocking is increasingly *domain/SNI*-based, which targets
   both transports equally.)
3. **A stream design can show the D19 floor holds under loss** — i.e. a design
   where the cover grid is provably independent of the data path's congestion
   behaviour. Per §1.3/§6.2, this requires **two sessions**, which is a
   multi-session protocol, not a transport. **This is the hard blocker.**
4. **A userspace-TCP-over-UDP spike has been evaluated and rejected** on
   dependency/MSRV grounds with recorded evidence.
5. **D22's absorbing emission model has been adopted.** Per D22, the absorbing
   model is "a different protocol architecture trading throughput/latency/
   buffering semantics for stronger traffic-flow privacy" and is explicitly
   **not adopted now**. A stream is much more coherent with an absorbing
   emission model (where the *rate* is fixed and only the *content* varies)
   than with the current additive model — because the additive model's
   "burst = fingerprint" failure (which HoL makes far worse) simply does not
   exist in the absorbing model. **If D22's absorbing model ever lands, re-open
   this verdict — that is the single most likely trigger.**

**Conversely, the verdict would NOT change because of:** "TCP is more common
than UDP" (irrelevant to observability); "TCP looks normal to a censor" (the
*dynamics* fingerprint in §4.3 is worse, not better); "we can pad the segments"
(§2.2/§2.3 — padding cannot restore cadence we do not control, and a frozen
segment-size distribution is itself a signature).

---

## 8. D-numbers that would need **new decisions** if a native stream transport were pursued

None of these exist today. Each is a **new architectural/security decision**,
not a parameter.

| D | Current status | What a stream transport would force |
|---|---|---|
| **D18** | "UDP only in v0.2… **deferred**" (`:901-902`) | **Must be rewritten.** The explicit deferral becomes an acceptance. Must define the stream relay's destination state, the stream's lifecycle, and its resource bounds. |
| **D19** | Fixed 2 Mbps pure-periodic grid | **Must be rewritten or explicitly weakened.** HoL makes §6.3's semantics unachievable; a weaker timing guarantee must be stated (D7: parameters don't redefine guarantees — but a *transport* that makes the guarantee unachievable is a guarantee change). |
| **D22** | Reduction, not anonymity; additive emission | **Must be re-examined.** The additive model's burst failure mode is *amplified* by HoL. Likely forces reconsideration of the absorbing emission model. |
| **D13** | 3-message handshake over uniform 1280-byte datagrams; byte-identical retransmit via byte caching | **Must extend.** The byte-identical-retransmission contract (`:611-614`, `:627-629`) exists only for `m1_frags`/`m3_frags`/`m2_cache`. Extending it to data records = new caching discipline + new API surface in the crypto envelope. |
| **D16** | Rekey = close and re-establish | **Must be re-examined.** Rekey mid-stream requires the new transport to support re-establishment without an observable gap; on a stream the new handshake competes with queued cover. |
| **D5** | Metadata resistance as a core security goal | **Affected.** Requires an explicit ruling that TCP's transport dynamics are within acceptable bounds, or the goal is weakened. |
| **D6** | Traffic-shaping philosophy | **Affected.** Same reason as D5. |
| **D10** | Fail-secure behaviour | **Needs new failure taxonomy.** Stream-specific failures (desync, half-open, RST) must map to fail-secure outcomes. Silent-drop-on-error (PROTOCOL_SPEC §14) becomes hard to maintain on a stream. |
| **D12** | Authentication model | **Affected.** Session lifetime becomes transport-lifetime; the auth/rekey relationship changes. |
| **D20** | Pre-v2 QUIC/TLS removal; "one wire format, one handshake" | **Partly re-trodden.** A second transport reintroduces the dual-transport surface D20 deleted. Must record why this instance differs. |
| **D24** | Data-path failure budget; bounds | **Must extend.** Every new buffer (send/read per session × `max_sessions`) is a new attacker-influenceable bound (§3.2). D24's resource-enumeration discipline applies. |
| **D14** | Key hierarchy | **Affected** if nonce handling changes (§5.2). |
| **New D** | — | A new decision for **frame resynchronization** — there is currently no equivalent to the UDP `WrongSize` check. |
| **New D** | — | A new decision for **flow control / backpressure bounds and fail-closed overflow behaviour**. |

**~14 decisions, of which 4 are new and 3 are security-posture reductions.**
Compare: TUN requires the D25/D26 work already scoped, and TCP-over-UDP requires
roughly 3 (the userspace-stack dependency choice, its MSRV/clippy validation, and
its per-connection state bounds) — **none of which weaken a guarantee.**

---

## 9. Recommendation

1. **Do not add a native TCP/stream transport.** Record this verdict so the
   question is closed and does not get re-opened speculatively.
2. **Revise D18's "deferred" line** to point at the two real routes (TUN, and
   TCP-over-UDP) rather than leaving "a stream layer" as the implied remedy —
   that phrase is what invites the wrong implementation.
3. **Track the §7.4 trigger conditions**, especially "D22's absorbing emission
   model is adopted."
4. **If a milestone is later approved for TCP app support, evaluate TCP-over-UDP
   first** and require the evaluation to be recorded before a native stream
   transport can be proposed.
5. **Leave `udp.rs` and the `HandshakeTransport` abstraction as-is.** Note for
   the record: `HandshakeTransport` (`handshake_v2.rs:814-823`) is already a
   2-method `send_to`/`recv` trait, so a second transport is *mechanically*
   cheap — but mechanical cheapness is exactly what makes this decision
   dangerous. The cost here is not integration; it is the D19/D22 guarantees
   (§4.3) and the nonce discipline (§5.2).

**Bottom line:** the abstraction is stream-agnostic enough that adding TCP would
be easy, and that is precisely the trap. TCP is the wrong layer: it makes D19's
constant-rate guarantee unachievable, it makes the byte-identical-retransmit
contract a new cryptographic surface, and it becomes **dead code the moment
TUN ships**, because a TUN tunnel carries IP packets and the host OS terminates
TCP locally.

---

## 10. Citations

All URLs below were **fetched during this analysis**. Items marked
**[abstract only]** were read at the arXiv API/abstract level (title + author +
abstract), not in full text.

**Primary standards (fetched, full text)**
- RFC 9293, *Transmission Control Protocol* — STD 7, Aug 2022.
  https://www.rfc-editor.org/rfc/rfc9293.html
  — §2.2 (reliable ordered byte-stream; reliability via retransmission),
  §3.7 ("no correlation between segment boundaries and application read/write
  boundaries"), §3.7.1 (MSS / `Eff.snd.MSS`), §3.7.4 (Nagle + delayed-ACK
  interaction), §3.8 (duplicate segments from retransmission), §3.4.1/§3.4.3
  (ISN, quiet time).
- RFC 6298, *Computing TCP's Retransmission Timer*, Jun 2011.
  https://www.rfc-editor.org/rfc/rfc6298.html
  — §2.3 (`RTO = SRTT + max(G, K·RTTVAR)`, K=4, α=1/8, β=1/4),
  **§2.4 (1-second RTO floor)**, §5.5 (`RTO ← RTO·2` backoff), §2.1 (initial RTO
  1 s), Appendix A (97.5% of connections RTT < 1 s; ~2.5% longer).
  *This is the source that corrects the briefed "RTO ~100-200 ms" figure.*
- RFC 5681, *TCP Congestion Control*, Sep 2009.
  https://www.rfc-editor.org/rfc/rfc5681.html
  — §3.1 (slow start, `ssthresh = max(FlightSize/2, 2·SMSS)`, on timeout
  `cwnd ≤ LW` = 1 segment), §3.2 (fast retransmit requires **3** dup-ACKs),
  §4.1 (restart-after-idle burst), §4.2 (delayed ACK: every 2nd full segment,
  500 ms cap), **§5 (Security Considerations: attacker-induced retransmissions
  and dup-ACK forgery impair a TCP connection)**.
- RFC 9000, *QUIC: A UDP-Based Multiplexed and Secure Transport*, May 2021.
  https://www.rfc-editor.org/rfc/rfc9000.html
  — §1 ("carried in UDP datagrams to better facilitate deployment in existing
  systems and networks"), §2.2 (stream abstraction; flow-controlled, bounded
  buffering), §4 (flow control limits to bound receiver memory commitment),
  §2.1.2 (fixed 1280-byte initial datagram for IPv6 path-MTU floor).
  *Used as the reference design showing that a security-focused protocol
  delivers streams **on top of UDP**, not by adding TCP.*
- RFC 7457, *Summarizing Known Attacks on TLS and DTLS*, Feb 2015.
  https://www.rfc-editor.org/rfc/rfc7457.html
  — §2.13 (DoS: cheap-to-mount attacks against expensive endpoints),
  §2.14 (implementation shortcuts/omitted validation), §2.7 (TLS/QUIC PKI
  attack history).
  *Used for the D20 rationale: transport stacks added to a security protocol are
  a net attack-surface increase, which is why the pre-v2 QUIC/TLS stack was
  removed.*

**Academic literature (arXiv — abstract-level unless noted)**
- Khattak, Simon, Murdoch, Elahi, Goldberg — *Systemization of Pluggable
  Transports for Censorship Resistance* (PoPETS 2016).
  https://arxiv.org/abs/1412.7448
  **[abstract only]** — the pluggable-transport framing: circumvention transports
  are a **separate, transport-agnostic layer** precisely because they must be
  swappable. Supports §7's recommendation that carrier-resistance belongs in a
  separate milestone, not in the record plane.
- Lee, Wang, Jia, Wu, Birge-Lee, Wang, Mittal — *QUICstep: Evaluating connection
  migration based QUIC censorship circumvention*.
  https://arxiv.org/abs/2304.01073
  **[abstract only]** — censors key on "information in the first few packets of
  a connection"; QUIC-based circumvention is evaluated as its **own transport**,
  not by bolting reliability onto an existing datagram protocol.
- Gbur, Tschorsch — *A QUIC(K) Way Through Your Firewall?*
  https://arxiv.org/abs/2107.05939
  **[abstract only]** — a middlebox study showing QUIC's **encrypted transport
  layer** defeats stateful tracking and DPI of transport fields. Directly
  relevant to §4: hiding transport internals is the *goal*, and adding a
  transparent TCP layer would re-expose exactly the fields this class of work
  works to hide.
- MacMillan, Holland, Mittal — *Evaluating Snowflake as an Indistinguishable
  Censorship Circumvention Tool*.
  https://arxiv.org/abs/2008.03254
  **[abstract only]** — **Snowflake is identifiable with 100% accuracy** from
  **handshake structure and packet counts alone**, without decrypting. A direct,
  empirical warning that *observable structure* (not content) is what defeats
  camouflage — which is exactly the §1.3/§2.3/§6.2 "two flows / frozen segment
  sizes" risk.
- Sun, Shmatikov — *Differential Degradation Vulnerabilities in Censorship
  Circumvention Systems*.
  https://arxiv.org/abs/2409.06247
  **[abstract only]** — circumvention systems are blockable "at a low cost,
  without resorting to traffic analysis" because their network requirements
  differ from their cover application's. Supports §4.3's argument that a
  deliberately degradable timing pattern is an attack surface, not just a
  cosmetic leak.
- Grübl, Niu, van den Assen, Stiller — *QUIC-Exfil* (ACM ASIACCS 2025).
  https://arxiv.org/abs/2505.05292
  **[abstract only]** — five anomaly-detection classifiers (incl. Isolation
  Forest and Autoencoder) **failed to detect** exfiltration, and "post-analysis
  of the traffic captures did not reveal any identifiable fingerprint." A useful
  counterweight: **encryption + rate discipline is genuinely strong against
  classifiers**, which is an argument for *keeping* the current datagram posture
  rather than degrading it for TCP (§4.2).
- Maiti — *Block-A-Mole: The Sustainability Frontier of Moving-Target Censorship
  Resistance*.
  https://arxiv.org/abs/2606.08886
  **[abstract only]** — "under the Great Firewall's 2024 shift to **blocking QUIC
  and TLS by domain**, raw rotation speed is not the binding constraint";
  availability is governed by domain burn rate. Supports §7.4(2): present
  blocking is largely **domain/SNI-based**, which does not discriminate TCP vs
  UDP — so "add TCP for reachability" is not well-supported by current
  evidence.
- Umayya, Malik, Gosain, Sharma — *PTPerf: On the performance evaluation of Tor
  Pluggable Transports*.
  https://arxiv.org/abs/2309.14856
  **[abstract only]** — 12 PTs, >1.25M measurements; "PT performance depends on
  the **underlying communication primitive**." Supports treating transport choice
  as a real, measurable tradeoff rather than assuming TCP is safer.
- Briscoe, De Schepper — *Scaling TCP's Congestion Window for Small Round Trip
  Times*.
  https://arxiv.org/abs/1904.07598
  **[abstract only]** — "Nearly all TCP implementations will not run at less
  than **two packets per round trip time**." *Directly corroborates §1.2*: a
  195.3 pkt/s cover grid on a 60 ms path needs cwnd ≈ 12 segments in flight,
  far above the ~2-packet floor most stacks will not go below.

**Primary documents (in-repo, cited with file:line)**
- `pq-tunnel-core/src/codec.rs:103` — `PACKET_SIZE = 1280`;
  `:107-111` field widths; `:121` `MAX_PACKET_NONCE`;
  `:128` `is_counter_exhausted`; `:137-139` `INNER_PLAINTEXT_LEN`/`PAYLOAD_LEN`;
  `:145-151` the compile-time layout assertion; `:221-224` `Direction` inside
  the ciphertext.
- `pq-tunnel-core/src/envelope.rs:269-273` — pre-AEAD exhaustion check;
  **`:276-279` header/AAD/nonce all bind `send_counter`**;
  **`:294-299` `send_counter` unconditionally advances** (no retransmit path);
  `:342-344` post-AEAD exhaustion check; `:353` replay accept.
- `pq-tunnel-core/src/replay.rs:36` — `WINDOW_BITS = 1024`;
  `:88-151` `accept()` — large gaps clear the window (`:95-120`), out-of-window
  counters rejected as replays (`:127-135`).
- `pq-tunnel-core/src/udp.rs:1-27` — datagram-boundary module contract;
  `:90-97` unconnected-socket/roaming rationale; `:169-186` the
  `PACKET_SIZE+1` buffer that detects oversize datagrams (the `WrongSize` check
  a stream **cannot** replicate).
- `pq-tunnel-core/src/scheduler.rs:36` `DEFAULT_COVER_RATE_BPS = 2_000_000`;
  `:64-75` exact integer interval math; `:24-27` and `:130-147` the
  "at most one emission, never a burst" semantics; `:164-166` the test asserting
  the interval is **exactly 5.12 ms**.
- `pq-tunnel-core/src/handshake_v2.rs:814-823` — `HandshakeTransport`
  (`send_to`/`recv`, already a 2-method abstraction);
  `:976` `m1_frags: Vec<WirePacket>`; `:1020-1030` accessors;
  `:1085`, `:1101` `Emit(self.m1_frags.clone())` byte-identical retransmit;
  `:1311` `m2_cache: Option<Vec<u8>>`; `:1540-1550` pristine M2 resend.
- `DESIGN_DECISIONS.md:611-614` — retransmission byte-identical, client-driven;
  `:627-629` — byte caching, never re-derivation;
  `:901-902` — D18 "UDP only in v0.2… deferred";
  `:914-918` — D18 tradeoffs (TCP apps need a stream milestone; no ICMP);
  `:931-935` — D19 "protocol-level constant rate" / stable observable pattern;
  `:949-953` — D19 pure-periodic, at most one emission, never a burst;
  `:1056-1102` — D22 reduction not anonymity, additive model, absorbing model
  **not adopted**;
  `:989-1053` — D20 removal of the pre-v2 QUIC/TLS transport.
- `docs/design/D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md:218-243` — MTU 1241,
  inner **MSS 1201**, "OS stacks derive this automatically… we do not clamp
  sockets"; `:251` — why ICMP/PTB breaks TCP MSS negotiation;
  `:842-852` (§4.3) — the handshake fragmentation is the **existing precedent**
  for multi-record payloads; `:826-840` (§4.2) — `codec.rs`, `envelope.rs`,
  `wire_session.rs`, `scheduler.rs`, `udp.rs` all reusable **unchanged** by TUN,
  and `scheduler.rs` "**must not be touched**".

---

## 11. Verification status

**Verified in source (read directly):**
- `PACKET_SIZE`/`HEADER_LEN`/`INNER_PLAINTEXT_LEN`/`PAYLOAD_LEN`/`MAX_PACKET_NONCE` and the layout assertion — `codec.rs`.
- `CipherSession::encrypt` always advances `send_counter`; no retransmit path — `envelope.rs:257-299`.
- Header, AAD and AEAD nonce all bind `send_counter` — `envelope.rs:276-279`.
- Replay-window behaviour on gaps and out-of-window counters — `replay.rs`.
- Cover interval is exactly 5.12 ms at 2 Mbps, and the scheduler yields at most one emission — `scheduler.rs`.
- `HandshakeTransport` is a 2-method trait; handshake retransmit is byte-cached — `handshake_v2.rs`.
- D13/D18/D19/D20/D22 text and line numbers — `DESIGN_DECISIONS.md`.
- TUN MTU/MSS arithmetic and the reuse table — `D25-D26-TUN-SYSTEM-WIDE-ARCHITECTURE.md`.
- HEAD == `origin/main` == `ae8061d` via `git rev-parse`.

**Computed here (not measured on a host):**
- All RTO/jitter/slot arithmetic in §1.2 and §6.1. Derived from RFC 6298's
  formulas with stated parameter assumptions (R, σ, p). **These are analytical
  estimates, not measurements.** The 5.12 ms interval itself is verified (the
  scheduler test asserts it), but the RTT/jitter/loss profiles are assumed.
- Buffer-sizing figures in §3.2 use an illustrative 100 Mbps / 50 ms path.

**Marked UNVERIFIED (not checked here):**
- Whether a userspace TCP stack (`smoltcp`-class) is viable at MSRV 1.85 and
  under `cargo clippy -- -D warnings`. Same class of open question as D25-D26 Q3.
- Whether the Windows cover-clock residual (D23, measured p50 5.31 ms) would be
  masked or amplified by stream buffering. Requires measurement.
- Current real-world UDP-blocking rates on target networks. §7.4(2) requires a
  measurement; the §10 evidence (arXiv:2606.08886) indicates present blocking is
  predominantly domain/SNI-based, but no deployment-specific figure was obtained.
- Tor/obfs4 pluggable-transport spec text (`spec.torproject.org`) — **DNS
  resolution failed**; §10 cites the academic PT literature instead
  (arXiv:1412.7448, arXiv:2309.14856). No PT-spec claim is made.

**Tooling note:** `web_search` was unavailable for this task (Grok CLI returned
HTTP 426, "version 1.0.5 is outdated"). All external references were obtained via
direct `web_fetch` of rfc-editor.org, the arXiv API, and in-repo documents. No
citation in §10 is from memory.
