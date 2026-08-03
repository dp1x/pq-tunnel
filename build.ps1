param(
    [ValidateSet("check", "test", "build", "clippy", "fmt")]
    [string]$Command = "check",
    [string]$Package = "pq-crypto"
)

$ErrorActionPreference = "Stop"

# Tunnel builds/test target the x86_64-pc-windows-msvc toolchain. The host may
# differ (aarch64-pc-windows-msvc cannot compile aws-lc-sys); pass --target when
# invoking cargo directly if needed. This script intentionally carries no
# machine-specific PATH overrides.

cargo $Command -p $Package --target x86_64-pc-windows-msvc @args
