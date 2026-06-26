# PQ-Tunnel build script
# Sets up MSVC ARM64 environment with custom CRT libraries
param(
    [string]$Target = "aarch64-pc-windows-msvc",
    [string]$Command = "check",
    [string]$Package = "pq-crypto"
)

$customLibs = Join-Path $PSScriptRoot ".msvc_libs"

# Setup environment using vcvarsall then augment
    if ($_ -match '^([^=]+)=(.*)$') {
        $name = $matches[1]
        $val = $matches[2]
        # Prepend custom libs to existing PATH, LIB, LIBPATH
        if ($name -eq "PATH") {
            $val = "$($vcTools)\bin\Hostarm64\x64;$customLibs;$val"
        } elseif ($name -eq "LIB") {
            $val = "$customLibs;$($sdkDir)\um\arm64;$($sdkDir)\ucrt\arm64;$val"
        } elseif ($name -eq "LIBPATH") {
            $val = "$customLibs;$val"
        }
        Set-Item "env:$name" $val
    }
}

Write-Host "Building with augmented ARM64 environment..."
Write-Host "LIB contains: $($env:LIB.Split(';')[0..3] -join '; ')..."

& cargo $Command -p $Package --target $Target 2>&1
