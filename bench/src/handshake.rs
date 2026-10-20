//! Bench 3 — end-to-end handshake CPU cost through the REAL state machines.
//!
//! This drives `pq_tunnel_core::handshake_v2::{ClientHandshake, ServerHandshake}`
//! exactly as the production drivers do — real `MlDsaKeypair`s, real
//! `MlKemKeypair`/`X25519Keypair` generation, real fragment encode/decode,
//! real `TH1/TH2/TH3` transcripts — with the transport faked by handing each
//! side's emitted `WirePacket`s straight to the peer's `handle_datagram`.
//!
//! Why in-process rather than the loopback `Gate` harness
//! (`pq-tunnel-bin/tests/common/mod.rs`): D16's "~2.5 ms CPU" is a **CPU**
//! claim, and a loopback measurement folds in kernel UDP send/receive
//! scheduling, Nagle-ish batching and proxy relaying — none of which is CPU
//! the protocol spends. An in-process pump measures the handshake's own CPU
//! and nothing else, which is what the doc claim is about. The loopback path
//! is still exercised: `bench_cadence` (see `cover_timer.rs`) runs a real
//! client+server pair over loopback for the timer cadence.
//!
//! What is measured:
//!
//! * **server M1 cost** = the `complete_m1` roster loop + KEM/DH + `TH2` +
//!   server signature: i.e. the authentication+key-establishment CPU of one
//!   incoming handshake at a given roster size.
//! * **client M1 cost** = keygen + `TH1` + client signature + fragmentation.
//! * **full handshake** = client M1 + server M2 + client M3 + server M3
//!   verification, summed over both sides — the per-side CPU of a complete
//!   1.5-RTT handshake.

use std::net::SocketAddr;

use pq_crypto::signature::MlDsaKeypair;
// `handshake_v2` is a private module; the crate root re-exports these under
// their `HandshakeV2`-prefixed names, so the harness depends only on the
// public surface.
use pq_tunnel_core::{ClientEvent, ClientHandshake, SESSION_ID_LEN, ServerEvent, ServerHandshake};
use pq_tunnel_core::{
    HandshakeV2ClientConfig as ClientConfig, HandshakeV2ServerConfig as ServerConfig,
};

use crate::roster_verify::ROSTER_SIZES;
use crate::stats::Stats;

/// Source-port offset used by warm-up iterations, kept disjoint from the
/// measured range (which starts at 0) so a warm-up handshake never shares a
/// rate-limit bucket with a measured one.
const WARMUP_PORT_BASE: usize = 30_000;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().expect("loopback addr")
}

/// Per-iteration source address for the server.
///
/// D12 rate limiting (`ServerConfig::rate_limit_burst = 16` per 10 s per
/// source) admits a *fixed, small* number of handshakes from any one address
/// — measurably 8 handshakes per window, since each handshake spends two
/// tokens (M1 fragment 0 and M3 fragment 0). Reusing one address would make
/// the DoS gate reject the benchmark itself long before the handshake cost
/// could be sampled.
///
/// Each iteration therefore gets its own source port, which is also the
/// realistic shape: a roster of N clients are N distinct peers, not one peer
/// reconnecting thousands of times. The rate limiter stays fully enabled and
/// on its normal code path — nothing is disabled or relaxed.
fn source_addr(i: usize) -> SocketAddr {
    // Port range chosen above the ephemeral default so it cannot collide with
    // a real listener; the address is never bound, only used as a key.
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        40000u16.wrapping_add((i % 20000) as u16),
    )
}

/// Fixed sid per iteration, supplied explicitly (`ClientHandshake::new` takes
/// an injectable sid). Each iteration uses a distinct sid so a reused
/// `ServerHandshake`'s pending map is never accidentally short-circuited.
fn sid_for(i: usize) -> [u8; SESSION_ID_LEN] {
    let mut s = [0u8; SESSION_ID_LEN];
    s[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    s
}

/// Drive one complete handshake in-process and return the per-phase timings.
///
/// Returns `(client_m1_ns, server_m2_ns, client_m3_ns, server_m3_ns)`.
fn one_handshake(
    server: &mut ServerHandshake,
    client_cfg: &ClientConfig,
    i: usize,
) -> (u128, u128, u128, u128) {
    let sid = sid_for(i);
    let peer = source_addr(i);

    // --- Client builds M1 (ML-KEM + X25519 keygen, TH1, ML-DSA signature,
    //     fragment into 4 datagrams).
    let t0 = std::time::Instant::now();
    let mut ch = ClientHandshake::new(client_cfg, sid).expect("client handshake init");
    let m1_frags = ch.m1_frags().to_vec();
    let client_m1 = t0.elapsed().as_nanos();

    // --- Server receives the 4 M1 fragments; the 4th completes M1 and runs
    //     `complete_m1`: roster loop + KEM + DH + TH2 + server signature.
    let t1 = std::time::Instant::now();
    let mut m2_frags = Vec::new();
    for f in &m1_frags {
        match server
            .handle_datagram(f, peer)
            .expect("server handle M1 frag")
        {
            ServerEvent::Emit(frags, _) => m2_frags = frags,
            ServerEvent::None => {}
            ServerEvent::Complete(_) => panic!("unexpected completion during M1"),
        }
    }
    let server_m2 = t1.elapsed().as_nanos();

    // --- Client receives M2, derives keys, builds M3 (decap + DH + HKDF +
    //     HMAC + fragment).
    let t2 = std::time::Instant::now();
    let mut m3_frags = Vec::new();
    for f in &m2_frags {
        if let ClientEvent::Emit(frags) = ch.handle_datagram(f).expect("client handle M2 frag") {
            m3_frags = frags;
        }
    }
    let client_m3 = t2.elapsed().as_nanos();

    // --- Server verifies M3 (decap + DH + HKDF + HMAC compare).
    let t3 = std::time::Instant::now();
    let mut completed = false;
    for f in &m3_frags {
        if let ServerEvent::Complete(_) = server
            .handle_datagram(f, peer)
            .expect("server handle M3 frag")
        {
            completed = true;
        }
    }
    assert!(
        completed,
        "handshake must complete (M3 Finished MAC verified)"
    );
    let server_m3 = t3.elapsed().as_nanos();

    (client_m1, server_m2, client_m3, server_m3)
}

/// The five tables a handshake run produces: total, then the four phases
/// (client M1, server M2, client M3, server M3), each indexed by
/// [`ROSTER_SIZES`].
type HandshakeTables = (
    Vec<Stats>, // total
    Vec<Stats>, // client M1
    Vec<Stats>, // server M2
    Vec<Stats>, // client M3
    Vec<Stats>, // server M3
);

/// Full-handshake CPU at each required roster size, plus the phase split.
///
/// The client identity is the LAST roster entry, so the server's roster loop
/// always verifies all `n` keys (the signer sits at the end of the list).
pub fn full_handshake(warmup: usize, iters: usize) -> HandshakeTables {
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let mut total = Vec::new();
    let mut c_m1 = Vec::new();
    let mut s_m2 = Vec::new();
    let mut c_m3 = Vec::new();
    let mut s_m3 = Vec::new();

    for n in ROSTER_SIZES {
        let mut roster_keys = Vec::with_capacity(n);
        for _ in 0..n {
            roster_keys.push(MlDsaKeypair::generate().expect("roster keygen"));
        }
        let client_kp = roster_keys[n - 1].clone(); // signer is last
        let roster: Vec<_> = roster_keys.into_iter().map(|k| k.public_key()).collect();

        // The roster sizes measured here deliberately exceed the shipped
        // default limit (`ServerConfig::DEFAULT_MAX_ROSTER_SIZE`), so the
        // benchmark raises the limit explicitly instead of measuring a
        // configuration the server would refuse to start with.
        let sc = ServerConfig::with_roster_limit(server_kp.clone(), roster, roster.len());
        let mut server = ServerHandshake::new(&sc);
        let cc = ClientConfig::new(addr(4433), client_kp, server_kp.public_key());

        let mut v_total = Vec::with_capacity(iters);
        let mut v_c1 = Vec::with_capacity(iters);
        let mut v_s2 = Vec::with_capacity(iters);
        let mut v_c3 = Vec::with_capacity(iters);
        let mut v_s3 = Vec::with_capacity(iters);

        // Warm-up handshakes are run through the same closure shape and
        // discarded; they prime key material and the allocator. Warm-up
        // iterations use disjoint source ports from the measured ones.
        for w in 0..warmup {
            let (a, b, c, d) = one_handshake(&mut server, &cc, WARMUP_PORT_BASE + w);
            std::hint::black_box((a, b, c, d));
        }
        for i in 0..iters {
            let (a, b, c, d) = one_handshake(&mut server, &cc, i);
            v_c1.push(a as f64);
            v_s2.push(b as f64);
            v_c3.push(c as f64);
            v_s3.push(d as f64);
            v_total.push((a + b + c + d) as f64);
        }

        let lbl = format!("(roster n={n})");
        total.push(crate::stats::Stats::from_samples_ns(
            format!("FULL handshake client+server CPU {lbl}"),
            "ns",
            warmup,
            v_total,
        ));
        c_m1.push(crate::stats::Stats::from_samples_ns(
            format!("  phase: client M1 {lbl}"),
            "ns",
            warmup,
            v_c1,
        ));
        s_m2.push(crate::stats::Stats::from_samples_ns(
            format!("  phase: server M2 (roster loop+KEM+sig) {lbl}"),
            "ns",
            warmup,
            v_s2,
        ));
        c_m3.push(crate::stats::Stats::from_samples_ns(
            format!("  phase: client M3 (decap+DH+HKDF) {lbl}"),
            "ns",
            warmup,
            v_c3,
        ));
        s_m3.push(crate::stats::Stats::from_samples_ns(
            format!("  phase: server M3 (verify Finished) {lbl}"),
            "ns",
            warmup,
            v_s3,
        ));
    }
    (total, c_m1, s_m2, c_m3, s_m3)
}

/// Wall-clock handshake through the real `ServerHandshake`/`ClientHandshake`
/// pair, but where the caller only wants the TOTAL as a single number.
///
/// Returns `(total, server_side_only)` where server_side is the portion of
/// the handshake a server pays for an inbound connection — the figure that
/// bounds handshake capacity (the client cost is the client's problem).
pub fn handshake_totals(
    warmup: usize,
    iters: usize,
    roster_sizes: &[usize],
) -> Vec<(usize, Stats, Stats)> {
    let server_kp = MlDsaKeypair::generate().expect("server keygen");
    let mut out = Vec::new();
    for &n in roster_sizes {
        let mut roster_keys = Vec::with_capacity(n);
        for _ in 0..n {
            roster_keys.push(MlDsaKeypair::generate().expect("roster keygen"));
        }
        let client_kp = roster_keys[n - 1].clone();
        let roster: Vec<_> = roster_keys.into_iter().map(|k| k.public_key()).collect();
        // See the note above: the benchmark raises the roster limit so it can
        // measure the D12 verification loop above the shipped default bound.
        let sc = ServerConfig::with_roster_limit(server_kp.clone(), roster, roster.len());
        let mut server = ServerHandshake::new(&sc);
        let cc = ClientConfig::new(addr(4433), client_kp, server_kp.public_key());

        let mut v_all = Vec::with_capacity(iters);
        let mut v_srv = Vec::with_capacity(iters);
        for w in 0..warmup {
            std::hint::black_box(one_handshake(&mut server, &cc, WARMUP_PORT_BASE + w));
        }
        for i in 0..iters {
            let (a, b, c, d) = one_handshake(&mut server, &cc, i);
            v_all.push((a + b + c + d) as f64);
            v_srv.push((b + d) as f64);
        }
        out.push((
            n,
            crate::stats::Stats::from_samples_ns(
                format!("handshake TOTAL both sides (roster n={n})"),
                "ns",
                warmup,
                v_all,
            ),
            crate::stats::Stats::from_samples_ns(
                format!("handshake SERVER-side CPU (roster n={n})"),
                "ns",
                warmup,
                v_srv,
            ),
        ));
    }
    out
}
