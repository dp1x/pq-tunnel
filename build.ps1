param(
    [ValidateSet("check", "test", "build", "clippy", "fmt")]
    [string]$Command = "check",
    [string]$Package = "pq-crypto"
)

$ErrorActionPreference = "Stop"

# Tunnel's canonical build/test target is x86_64-pc-windows-msvc. The host
# toolchain may differ (e.g. aarch64-pc-windows-msvc); pass --target when
# invoking cargo directly to stay on the canonical target. This script
# intentionally carries no machine-specific PATH overrides.

cargo $Command -p $Package --target x86_64-pc-windows-msvc @args
