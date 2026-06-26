param(
    [ValidateSet("check","test","build","release","clippy")]
    [string]$Command = "check",
    [string]$Package = "pq-crypto",
    [string]$Target = "x86_64-pc-windows-msvc"
)

$ErrorActionPreference = "Stop"

rustup run stable-x86_64-pc-windows-msvc cargo $Command -p $Package --target $Target 2>&1
