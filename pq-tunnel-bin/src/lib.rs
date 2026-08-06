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
//!   forwarding backend by default (D18), echo as an opt-in diagnostic; the
//!   legacy v1 QUIC runtime remains behind `--transport quic` until its
//!   scheduled removal.
//! * `client` — v2 datagram client (pinned server key) exposing a local UDP
//!   relay; the legacy v1 QUIC runtime (flood/cover/tunnel modes) remains
//!   behind `--transport quic`.

pub mod forward;
pub mod identity;
pub mod keygen;
pub mod packet_len;
pub mod quic;
pub mod relay;
pub mod v2_client;
pub mod v2_server;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
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

    /// Transport. v1 is deprecated and removed soon; only v2 is supported for
    /// production use.
    #[arg(long, value_enum, default_value_t = TransportKind::V2)]
    pub transport: TransportKind,

    /// TUN MTU in bytes (v1 only).
    #[arg(long, default_value = "1400")]
    pub mtu: u16,

    /// Handshake timeout in seconds (v1 only).
    #[arg(long, default_value = "10")]
    pub handshake_timeout: u64,
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

    /// TUN interface address in CIDR form (v1 only, e.g. 10.0.0.1/24).
    #[arg(short, long, default_value = "10.0.0.1/24")]
    pub tun_addr: String,

    /// TUN MTU in bytes (v1 only).
    #[arg(long, default_value = "1400")]
    pub mtu: u16,

    /// Handshake timeout in seconds.
    #[arg(long, default_value = "10")]
    pub handshake_timeout: u64,

    /// Transport. v1 is deprecated and removed soon; keep the v2 UDP path.
    #[arg(long, value_enum, default_value_t = TransportKind::V2)]
    pub transport: TransportKind,

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

    /// v1 (QUIC): flood mode — send packets at a fixed rate with no backoff.
    #[arg(long)]
    pub flood: bool,

    /// v1 (QUIC): cover mode.
    #[arg(long)]
    pub cover: bool,

    /// v1 (QUIC): flatline check mode.
    #[arg(long)]
    pub flatline: bool,

    /// v1 (QUIC): packet size for flood/cover modes.
    #[arg(long, default_value = "8191")]
    pub packet_size: usize,

    /// v1 (QUIC): send rate in packets/second.
    #[arg(long, default_value = "1000")]
    pub rate: u64,

    /// v1 (QUIC): run duration in seconds.
    #[arg(long, default_value = "10")]
    pub duration: u64,
}

/// Transport selection (v2 = default datagram plane; quic = legacy, to be
/// removed).
#[derive(ValueEnum, Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    #[default]
    V2,
    Quic,
}

/// Build the cover-traffic policy from CLI flags (transport policy, never a
/// handshake property — D19).  Fail-closed on nonsensical input: `--no-cover`
/// is the only supported way to disable.
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
    Ok(CoverPolicy {
        enabled: true,
        interval: interval_from_rate_bps(mbps * 1_000_000),
    })
}

/// Program entry point: tracing init, then dispatch on the subcommand.
#[tokio::main]
pub async fn main_entry() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => keygen::run(&args),
        Command::Server(args) => run_server_subcommand(&args).await,
        Command::Client(args) => run_client_subcommand(&args).await,
    }
}

async fn run_server_subcommand(args: &ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.transport {
        TransportKind::V2 => v2_server::run(args).await,
        TransportKind::Quic => quic::run_server(args).await,
    }
}

async fn run_client_subcommand(args: &ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.transport {
        TransportKind::V2 => {
            if args.flood || args.flatline || args.cover {
                tracing::error!("flood/cover/flatline are v1 (QUIC) modes; use --transport quic");
                return Err("v1-only flags cannot be combined with --transport v2".into());
            }
            v2_client::run(args).await
        }
        TransportKind::Quic => {
            let (tun_ip, tun_mask) = parse_tun_addr(&args.tun_addr)?;
            quic::run_client(args, tun_ip, tun_mask).await
        }
    }
}

/// Parse `IP/CIDR` into an address and a netmask.
///
/// Rejects out-of-range prefixes (e.g. `/33` for IPv4) instead of silently
/// wrapping the shift that would otherwise truncate the mask.
pub fn parse_tun_addr(s: &str) -> Result<(std::net::IpAddr, std::net::IpAddr), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err("expected IP/CIDR format".into());
    }
    let ip: std::net::IpAddr = parts[0]
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let max = match ip {
        std::net::IpAddr::V4(_) => 32u8,
        std::net::IpAddr::V6(_) => 128u8,
    };
    if prefix > max {
        return Err(format!("invalid CIDR prefix {prefix} (max {max})"));
    }
    let mask = match ip {
        std::net::IpAddr::V4(_) => {
            let m = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let b = m.to_be_bytes();
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        std::net::IpAddr::V6(_) => {
            let m = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let b = m.to_be_bytes();
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
        }
    };
    Ok((ip, mask))
}

#[cfg(test)]
mod tests {
    use super::parse_tun_addr;

    #[test]
    fn cidr_v4() {
        let (ip, mask) = parse_tun_addr("10.0.0.1/24").unwrap();
        assert_eq!(ip.to_string(), "10.0.0.1");
        assert!(
            matches!(mask, std::net::IpAddr::V4(m) if m.octets() == [255, 255, 255, 0]),
            "unexpected mask: {mask}"
        );
    }

    #[test]
    fn cidr_v6() {
        let (ip, mask) = parse_tun_addr("fd00::1/64").unwrap();
        assert_eq!(ip.to_string(), "fd00::1");
        assert!(
            matches!(mask, std::net::IpAddr::V6(m) if m.segments() == [0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0]),
            "unexpected mask: {mask}"
        );
    }

    #[test]
    fn prefix_overflow_rejected() {
        assert!(parse_tun_addr("10.0.0.1/33").is_err());
        assert!(parse_tun_addr("10.0.0.1/255").is_err());
    }

    #[test]
    fn cidr_zero_prefix_ok() {
        let (_, mask) = parse_tun_addr("0.0.0.0/0").unwrap();
        assert!(matches!(mask, std::net::IpAddr::V4(m) if m.octets() == [0, 0, 0, 0]));
    }

    #[test]
    fn malformed_rejected() {
        assert!(parse_tun_addr("10.0.0.1").is_err());
        assert!(parse_tun_addr("10.0.0.1/notnum").is_err());
        assert!(parse_tun_addr("not-an-ip/24").is_err());
    }
}
