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
pub mod v2_client;
pub mod v2_server;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use pq_tunnel_core::{CoverPolicy, interval_from_rate_bps};
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
    #[arg(long, default_value_t = 2)]
    pub cover_mbps: u64,

    /// Disable cover traffic entirely (v2; explicit, documented reduction —
    /// cover never silently turns off, PROTOCOL_SPEC §12.2).
    #[arg(long)]
    pub no_cover: bool,
}

/// `pq-tunnel client` arguments.
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
    #[arg(long, default_value_t = 2)]
    pub cover_mbps: u64,

    /// Disable cover traffic entirely (v2; explicit, documented reduction —
    /// cover never silently turns off, PROTOCOL_SPEC §12.2).
    #[arg(long)]
    pub no_cover: bool,
}

/// Largest `--cover-mbps` value whose bitrate is representable in a `u64`:
/// `u64::MAX / 1_000_000` = 18_446_744_073_709 Mbps (~1.8e19 bit/s).  Any
/// larger value is rejected rather than wrapped (D29).
pub const MAX_COVER_MBPS: u64 = u64::MAX / 1_000_000;

/// Build the cover-traffic policy from CLI flags (transport policy, never a
/// handshake property — D19).  Fail-closed on nonsensical input: `--no-cover`
/// is the only supported way to disable.
///
/// The megabit→bit conversion is `checked_mul`, not `*`.  Unchecked, a value
/// at or above `u64::MAX / 1_000_000` wraps (release) or panics (debug) and
/// yields a nonsense rate — e.g. a wrapped-small value becomes an enormous
/// interval, silently disabling cover traffic without `--no-cover`, which
/// PROTOCOL_SPEC §12.2 reserves for the explicit flag (D29).
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
    Ok(CoverPolicy {
        enabled: true,
        interval: interval_from_rate_bps(bps),
    })
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
        Command::Server(args) => v2_server::run(&args).await,
        Command::Client(args) => v2_client::run(&args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The largest in-range value is accepted, and yields a 1 ns interval —
    /// i.e. acceptance is deliberately allowed to produce the clamp floor.
    /// The clamp itself is pinned separately in `pq-tunnel-core::scheduler`.
    #[test]
    fn cover_mbps_at_u64_boundary_is_accepted() {
        let p = cover_policy_from_args(false, MAX_SAFE_MBPS).expect("boundary must be accepted");
        assert!(p.enabled);
        assert_eq!(
            p.interval,
            interval_from_rate_bps(MAX_SAFE_MBPS * 1_000_000)
        );
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
}
