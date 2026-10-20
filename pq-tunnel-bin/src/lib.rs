//! `pq-tunnel` — post-quantum, metadata-resistant tunnel (v0.2.0-alpha).
//!
//! Library + binary target: the CLI entry point (`main.rs`) is a thin wrapper
//! over this library, which keeps all drivers and provisioning logic testable
//! from integration tests.
//!
//! Three subcommands:
//!
//! * `keygen` — generate an identity + public key as provisioning files
//!   (optionally appended to a server roster). Out-of-band distribution.
//! * `server` — v2 datagram server (ML-DSA-roster authenticated): a
//!   forwarding backend by default (D18), echo as an opt-in diagnostic.
//! * `client` — v2 datagram client (pinned server key) exposing a local UDP
//!   relay.

pub mod forward;
pub mod identity;
pub mod keygen;
pub mod packet_len;
pub mod relay;
#[cfg(feature = "tun")]
pub mod tun;
pub mod tun_policy;
pub mod v2_client;
pub mod v2_server;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args as ClapArgs, Parser, Subcommand};
use pq_tunnel_core::scheduler::{MAX_COVER_RATE_BPS, MIN_COVER_INTERVAL_NANOS};
use pq_tunnel_core::{CoverPolicy, HandshakeV2ServerConfig, interval_from_rate_bps};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "pq-tunnel",
    version,
    about = "Post-quantum, metadata-resistant tunnel"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate identity and public-key provisioning files.
    Keygen(KeygenArgs),
    /// Run the tunnel server.
    Server(ServerArgs),
    /// Run the tunnel client.
    Client(ClientArgs),
}

/// `pq-tunnel keygen` arguments.
#[derive(ClapArgs, Debug, Clone)]
pub struct KeygenArgs {
    /// Identity (secret seed) file to write.
    #[arg(long, default_value = "identity.pqti")]
    pub identity: PathBuf,

    /// Public key file to write.
    #[arg(long, default_value = "public-key.pqti")]
    pub public_key: PathBuf,

    /// Server roster file to append the public key to (created if absent).
    #[arg(long)]
    pub append_roster: Option<PathBuf>,

    /// Overwrite an existing identity file.
    #[arg(long)]
    pub force: bool,
}

/// `pq-tunnel server` arguments.
#[derive(ClapArgs, Debug, Clone)]
pub struct ServerArgs {
    /// UDP listen address.
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    pub listen: SocketAddr,

    /// Stats reporting interval in seconds.
    #[arg(long, default_value = "5")]
    pub stats_interval: u64,

    /// Server identity seed file (PQTI format).
    #[arg(long)]
    pub identity: Option<PathBuf>,

    /// Client public-key roster file (PQTI format).
    #[arg(long)]
    pub roster: Option<PathBuf>,

    /// Echo decrypted payloads back instead of forwarding (diagnostics).
    #[arg(long)]
    pub echo: bool,

    /// Cover-traffic rate in megabits per second (v2; fixed pure-periodic
    /// shaper, D5/D6).  A visible metadata-resistance knob: lowering it thins
    /// the wire pattern; disabling it is the explicit reduction below.
    /// The value must be between 1 and 470 Mbps — the upper bound is the
    /// highest rate the cover scheduler can be *asked* for without asking it
    /// to emit faster than one cover packet can be produced
    /// (see [`MAX_COVER_MBPS_PACING`]).  It is a bound on the requested rate,
    /// not a promise of achievable throughput on any given host.
    #[arg(long, default_value_t = 2)]
    pub cover_mbps: u64,

    /// Disable cover traffic entirely (v2; explicit, documented reduction —
    /// cover never silently turns off, PROTOCOL_SPEC §12.2).
    #[arg(long)]
    pub no_cover: bool,

    /// Maximum number of client public keys accepted in the roster.
    ///
    /// A resource bound, not a security guarantee (D7): the server verifies
    /// the client signature against **every** roster key with no early exit
    /// (D12 uniform verification), so a larger roster multiplies the CPU
    /// cost of every completing handshake. The limit is enforced when the
    /// roster is loaded and again when the configuration is validated; an
    /// over-limit roster is rejected, never silently truncated (a truncated
    /// roster would silently revoke clients). The deployment model is 1:1,
    /// where the production roster has a single entry.
    #[arg(long, default_value_t = HandshakeV2ServerConfig::DEFAULT_MAX_ROSTER_SIZE)]
    pub max_roster_size: usize,

    /// Session lifetime cap in seconds (`0` = unbounded).
    ///
    /// D16 bounds the traffic-key exposure of a session: with cover traffic
    /// enabled (the default) the lifetime cap is the *only* bound on
    /// exposure, because the server's idle timeout counts authenticated
    /// *receives* only (D27 §1.3).  When the cap fires the endpoint sends an
    /// encrypted `Close` to the peer before dropping the session, so both
    /// ends converge without relying on synchronised clocks.
    ///
    /// The default is 24 h (86400 s).  See `v2_server::run` for the
    /// integration-sign-off marker.
    #[arg(long, default_value_t = 86_400)]
    pub lifetime_cap_secs: u64,

    /// Run in system-wide TUN mode (D33): client TUN device + raw IP.
    #[arg(long)]
    pub tun: bool,
}
#[derive(ClapArgs, Debug, Clone)]
pub struct ClientArgs {
    /// Server UDP address to connect to.
    #[arg(short, long)]
    pub remote: SocketAddr,

    /// Local UDP relay listen address (v2; D18).
    #[arg(long, default_value = "127.0.0.1:51821")]
    pub relay_listen: SocketAddr,

    /// Client identity seed file (PQTI format).
    #[arg(long)]
    pub identity: Option<PathBuf>,

    /// Pinned server public key file (PQTI format).
    #[arg(long)]
    pub server_key: Option<PathBuf>,

    /// Cover-traffic rate in megabits per second (v2; fixed pure-periodic
    /// shaper, D5/D6).  A visible metadata-resistance knob: lowering it thins
    /// the wire pattern; disabling it is the explicit reduction below.
    /// The value must be between 1 and 470 Mbps — the upper bound is the rate
    /// the cover path can actually sustain (see [`MAX_COVER_MBPS_PACING`]).
    #[arg(long, default_value_t = 2)]
    pub cover_mbps: u64,

    /// Disable cover traffic entirely (v2; explicit, documented reduction —
    /// cover never silently turns off, PROTOCOL_SPEC §12.2).
    #[arg(long)]
    pub no_cover: bool,

    /// Session lifetime cap in seconds (`0` = unbounded).
    ///
    /// D16 bounds the traffic-key exposure of a session.  When the cap fires
    /// the client sends an encrypted `Close` to the server, tears the session
    /// down (fresh sid, fresh ephemerals, fresh master on re-establishment)
    /// and re-establishes.  The server, which enforces the same cap, tears
    /// the session down and stays down for that sid.
    ///
    /// The default is 24 h (86400 s).  See `v2_client::run` for the
    /// integration-sign-off marker.
    #[arg(long, default_value_t = 86_400)]
    pub lifetime_cap_secs: u64,

    /// Run in system-wide TUN mode (D33).
    #[arg(long)]
    pub tun: bool,
}
/// `u64::MAX / 1_000_000` = 18_446_744_073_709 Mbps (~1.8e19 bit/s).  Any
/// larger value is rejected rather than wrapped (D29).
///
/// This is the *representability* bound only.  The binding limit is
/// [`MAX_COVER_MBPS_PACING`].
pub const MAX_COVER_MBPS: u64 = u64::MAX / 1_000_000;

/// Largest `--cover-mbps` value the cover scheduler can be **asked** for.
///
/// This is the binding limit, and it is derived rather than chosen: the
/// cover emission costs one scheduler tick plus one 1280-byte record
/// encryption, measured at 21 762 ns per cover packet on the reference host
/// (`docs/performance/I-benchmark-methodology.md` §7.1, §7.3, §7.5; see
/// [`MIN_COVER_INTERVAL_NANOS`] in `pq_tunnel_core::scheduler` for the
/// derivation).  A cover interval shorter than the time it takes to produce
/// one cover packet is unschedulable: the driver is asked to start emission
/// N+1 before emission N could have finished, and the schedule degenerates
/// into a hot re-arm loop whose real rate is set by the OS wake path rather
/// than by the operator's setting.
///
/// `10 240 bits / 21 762 ns` = 470 544 986 bit/s, i.e. **470 Mbps** as an
/// integer megabit value.  The D19 default (2 Mbps) is 235x below it.
///
/// The bound is a **lower** bound on the per-packet cost, so it bounds the
/// *requested* rate; it does not promise the requested rate is achievable on
/// a given host (the measurement excludes the timer and `sendto` syscalls).
pub const MAX_COVER_MBPS_PACING: u64 = MAX_COVER_RATE_BPS / 1_000_000;

/// Build the cover-traffic policy from CLI flags (transport policy, never a
/// handshake property — D19).  Fail-closed on nonsensical input: `--no-cover`
/// is the only supported way to disable.
///
/// The megabit→bit conversion is `checked_mul`, not `*`.  Unchecked, a value
/// at or above `u64::MAX / 1_000_000` wraps (release) or panics (debug) and
/// yields a nonsense rate — e.g. a wrapped-small value becomes an enormous
/// interval, silently disabling cover traffic without `--no-cover`, which
/// PROTOCOL_SPEC §12.2 reserves for the explicit flag (D29).
///
/// The rate is also bounded by what the cover scheduler can be *asked* for
/// ([`MAX_COVER_MBPS_PACING`]).  That bound is *not* cosmetic: a rate above
/// it asks for an interval shorter than one cover packet's production cost,
/// which is the hot-re-arm-loop foot-gun.  It is rejected here (fail closed
/// at the CLI) rather than silently clamped, so the operator learns that the
/// requested rate is not schedulable.
///
/// The bound is a **lower** bound on the per-packet cost, so it bounds the
/// *requested* rate; it does not promise the requested rate is achievable on
/// a given host (the measurement behind it excludes the timer and `sendto`
/// syscalls).  See `MIN_COVER_INTERVAL_NANOS` in `pq_tunnel_core::scheduler`.
pub fn cover_policy_from_args(no_cover: bool, mbps: u64) -> Result<CoverPolicy, String> {
    if no_cover {
        return Ok(CoverPolicy {
            enabled: false,
            interval: CoverPolicy::default().interval,
        });
    }
    if mbps == 0 {
        return Err("--cover-mbps must be >= 1; use --no-cover to disable cover traffic".into());
    }
    let bps = mbps.checked_mul(1_000_000).ok_or_else(|| {
        format!("--cover-mbps {mbps} overflows a u64 bitrate (max {MAX_COVER_MBPS})")
    })?;
    if bps > MAX_COVER_RATE_BPS {
        return Err(format!(
            "--cover-mbps {mbps} exceeds the maximum schedulable cover rate \
             (max {MAX_COVER_MBPS_PACING} Mbps): a cover interval shorter than \
             {MIN_COVER_INTERVAL_NANOS} ns is not schedulable"
        ));
    }
    Ok(CoverPolicy {
        enabled: true,
        interval: interval_from_rate_bps(bps),
    })
}

/// Build the session-lifetime cap from the CLI flag.
///
/// `0` means **unbounded** (the cap is disabled); any other value is the
/// session lifetime in seconds.  D27 §1's human decision gate names 24 h as
/// the recommended default and `--lifetime-cap-secs` with `0` meaning
/// "unbounded" as the CLI spelling — this is that spelling.
pub fn lifetime_cap_from_secs(secs: u64) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

/// Program entry point: tracing init, then dispatch on the subcommand.
#[tokio::main]
pub async fn main_entry() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => keygen::run(&args),
        Command::Server(args) => {
            #[cfg(feature = "tun")]
            if args.tun {
                return crate::tun::server::run(
                    args.listen,
                    args.identity.as_deref(),
                    args.roster.as_deref(),
                    args.cover_mbps,
                    args.no_cover,
                    args.lifetime_cap_secs,
                    args.max_roster_size,
                )
                .await;
            }
            v2_server::run(&args).await
        }
        Command::Client(args) => {
            #[cfg(feature = "tun")]
            if args.tun {
                let identity = args
                    .identity
                    .as_deref()
                    .ok_or("client TUN requires --identity")?;
                let server_key = args
                    .server_key
                    .as_deref()
                    .ok_or("client TUN requires --server-key")?;
                return crate::tun::client::run(
                    args.remote,
                    identity,
                    server_key,
                    crate::cover_policy_from_args(args.no_cover, args.cover_mbps)
                        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?,
                    args.lifetime_cap_secs,
                )
                .await;
            }
            v2_client::run(&args).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The exact overflow boundary: `u64::MAX / 1_000_000` is the largest
    /// megabit value whose bitrate still fits in a `u64`. One more overflows.
    const MAX_SAFE_MBPS: u64 = u64::MAX / 1_000_000;

    /// Pinned arithmetic: the largest in-range value is 18_446_744_073_709,
    /// and 18_446_744_073_710 is the first that does not fit. Written out so a
    /// change to the multiplier fails the test rather than silently re-basing
    /// the boundary.
    #[test]
    fn cover_mbps_overflow_boundary_is_exact() {
        assert_eq!(MAX_SAFE_MBPS, 18_446_744_073_709);
        assert!(MAX_SAFE_MBPS.checked_mul(1_000_000).is_some());
        assert!(
            (MAX_SAFE_MBPS + 1).checked_mul(1_000_000).is_none(),
            "MAX_SAFE_MBPS + 1 must overflow the u64 bitrate"
        );
    }

    /// Regression: `--cover-mbps` above the u64 bitrange must be *rejected*,
    /// never wrapped. The pre-fix code did `mbps * 1_000_000` unchecked, which
    /// wraps in release and panics in debug — either way it silently produced a
    /// nonsense rate (a wrapped-small value became an enormous interval, i.e.
    /// cover effectively switched itself off without `--no-cover`).
    #[test]
    fn cover_mbps_above_u64_bitrange_is_rejected_not_wrapped() {
        for mbps in [MAX_SAFE_MBPS + 1, u64::MAX / 2, u64::MAX] {
            let err = cover_policy_from_args(false, mbps)
                .expect_err("out-of-range --cover-mbps must fail closed");
            assert!(
                err.contains("cover-mbps"),
                "error must name the flag, got: {err}"
            );
        }
    }

    /// The largest **sustainable** `--cover-mbps` value is accepted, and the
    /// one above it is rejected.  The boundary is derived from the measured
    /// cost of producing one cover packet (see
    /// `pq_tunnel_core::scheduler::MIN_COVER_INTERVAL_NANOS`): the value is
    /// written out here, not derived from the constant, so a change to the
    /// constant fails this test rather than silently re-basing it.
    #[test]
    fn cover_mbps_sustainable_ceiling_is_470() {
        assert_eq!(MAX_COVER_MBPS_PACING, 470);
        // The exact bitrate bound behind the ceiling (the core pins the same
        // number against the floor it derives).
        assert_eq!(MAX_COVER_RATE_BPS, 470_544_986);
    }

    /// A rate at the sustainable ceiling is accepted and yields an interval
    /// at or above the derived floor.
    #[test]
    fn cover_mbps_at_sustainable_ceiling_is_accepted() {
        let p = cover_policy_from_args(false, MAX_COVER_MBPS_PACING)
            .expect("the sustainable ceiling must be accepted");
        assert!(p.enabled);
        assert!(
            p.interval >= Duration::from_nanos(MIN_COVER_INTERVAL_NANOS),
            "the accepted interval must respect the derived floor, got {:?}",
            p.interval
        );
    }

    /// One Mbps over the sustainable ceiling is rejected: it would ask for an
    /// interval shorter than one cover packet's production cost, i.e. a hot
    /// re-arm loop.  The rejection is explicit, not a silent clamp.
    #[test]
    fn cover_mbps_one_over_the_sustainable_ceiling_is_rejected() {
        let err = cover_policy_from_args(false, MAX_COVER_MBPS_PACING + 1)
            .expect_err("an unschedulable cover rate must fail closed");
        assert!(
            err.contains("cover-mbps"),
            "error must name the flag, got: {err}"
        );
    }

    /// The u64-representability bound is still exact, but a value inside it
    /// can now be refused for being *unschedulable*.  It is refused, never
    /// wrapped: the error names the schedulable ceiling, not a bitrate.
    #[test]
    fn cover_mbps_at_u64_boundary_is_rejected_as_unschedulable_not_wrapped() {
        let err = cover_policy_from_args(false, MAX_SAFE_MBPS)
            .expect_err("the u64 boundary is far above the schedulable ceiling");
        assert!(
            err.contains("cover-mbps") && err.contains("schedulable"),
            "error must name the flag and the reason, got: {err}"
        );
        // The value is representable — the refusal is about schedulability.
        assert!(MAX_SAFE_MBPS.checked_mul(1_000_000).is_some());
    }

    /// Documented lower bound and the `--no-cover` escape hatch (pre-existing
    /// behaviour, pinned so the new upper bound cannot disturb it).
    #[test]
    fn cover_mbps_zero_is_rejected_and_no_cover_wins() {
        let err = cover_policy_from_args(false, 0).expect_err("0 must be rejected");
        assert!(
            err.contains("no-cover"),
            "error must point at --no-cover: {err}"
        );

        let off = cover_policy_from_args(true, u64::MAX).expect("--no-cover ignores --cover-mbps");
        assert!(!off.enabled);
        assert_eq!(off.interval, CoverPolicy::default().interval);
    }

    /// The lifetime-cap CLI spelling (D27 §1's human decision gate):
    /// `--lifetime-cap-secs` with `0` meaning "unbounded" and the default
    /// being 24 h.
    #[test]
    fn lifetime_cap_zero_is_unbounded_and_the_default_is_24h() {
        assert_eq!(lifetime_cap_from_secs(0), None, "0 means unbounded");
        assert_eq!(
            lifetime_cap_from_secs(86_400),
            Some(Duration::from_secs(24 * 60 * 60)),
            "the default is 24 h"
        );
        assert_eq!(lifetime_cap_from_secs(1), Some(Duration::from_secs(1)));
    }

    /// The **shipped** lifetime-cap default is 24 h, on both roles.
    ///
    /// The value above only pins the helper; this pins the *product surface*:
    /// the `default_value_t` on the two CLI flags is the single line that
    /// decides whether the shipped binaries enforce D16's exposure bound.
    /// Nothing else in the tree would notice a change to it, so it is pinned
    /// here.  Reverting the shipped default to "unbounded" is a deliberate
    /// act: it must fail this test (see `docs/design/D31-client-lifecycle-and-liveness.md`).
    #[test]
    fn shipped_lifetime_cap_default_is_24h_on_both_roles() {
        use clap::Parser;

        let cli = Cli::parse_from(["pq-tunnel", "client", "--remote", "127.0.0.1:4433"]);
        let Command::Client(args) = cli.command else {
            panic!("expected the client subcommand");
        };
        assert_eq!(
            args.lifetime_cap_secs, 86_400,
            "the shipped client must enforce a 24 h session lifetime by default"
        );
        assert_eq!(
            lifetime_cap_from_secs(args.lifetime_cap_secs),
            Some(Duration::from_secs(24 * 60 * 60))
        );

        let cli = Cli::parse_from(["pq-tunnel", "server"]);
        let Command::Server(args) = cli.command else {
            panic!("expected the server subcommand");
        };
        assert_eq!(
            args.lifetime_cap_secs, 86_400,
            "the shipped server must enforce a 24 h session lifetime by default"
        );
    }

    /// `--lifetime-cap-secs 0` must actually mean "unbounded" on the CLI, and
    /// it must be an *explicit* choice: the flag exists so the reduction is
    /// visible rather than silent.
    #[test]
    fn lifetime_cap_zero_flag_yields_an_unbounded_session() {
        use clap::Parser;

        let cli = Cli::parse_from([
            "pq-tunnel",
            "client",
            "--remote",
            "127.0.0.1:4433",
            "--lifetime-cap-secs",
            "0",
        ]);
        let Command::Client(args) = cli.command else {
            panic!("expected the client subcommand");
        };
        assert_eq!(args.lifetime_cap_secs, 0);
        assert_eq!(
            lifetime_cap_from_secs(args.lifetime_cap_secs),
            None,
            "0 must mean unbounded"
        );
    }
}
