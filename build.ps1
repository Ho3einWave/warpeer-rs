<#
.SYNOPSIS
    Build the warpeer binary for Windows and/or Linux.

.DESCRIPTION
    Wraps `cargo build` for the native Windows target and, via WSL, the Linux
    (x86_64-unknown-linux-gnu) target. The Linux build uses a separate
    CARGO_TARGET_DIR (target-linux) so it never collides with the Windows
    artifacts in target/.

    The binary name is read from Cargo.toml, so this script is drop-in for any
    single-package crate. Building only needs crates.io; the Rust toolchain
    itself is not downloaded here.

.PARAMETER Target
    Which target(s) to build: windows, linux, or all. Default: all.

.PARAMETER Dev
    Build the debug profile instead of release.

.EXAMPLE
    .\build.ps1
    Builds both Windows and Linux release binaries.

.EXAMPLE
    .\build.ps1 -Target linux
    Builds only the Linux binary via WSL.
#>
[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux', 'all')]
    [string]$Target = 'all',

    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$profileName = if ($Dev) { 'debug' } else { 'release' }

function Get-CrateName {
    $cargoToml = Join-Path $projectRoot 'Cargo.toml'
    if (-not (Test-Path $cargoToml)) { throw "Cargo.toml not found in $projectRoot." }
    foreach ($line in Get-Content $cargoToml) {
        if ($line -match '^\s*name\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    throw "Could not find a crate name in Cargo.toml."
}

function Convert-ToWslPath {
    param([string]$WindowsPath)
    $full = (Resolve-Path $WindowsPath).Path
    $drive = $full.Substring(0, 1).ToLower()
    $rest = $full.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

$crate = Get-CrateName

function Build-Windows {
    Write-Host "==> Building Windows ($profileName)..." -ForegroundColor Cyan
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo not found on PATH. Install Rust from https://rustup.rs first."
    }
    $cargoArgs = @('build')
    if (-not $Dev) { $cargoArgs += '--release' }
    Push-Location $projectRoot
    try {
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "Windows build failed (exit $LASTEXITCODE)." }
    }
    finally { Pop-Location }

    $bin = Join-Path $projectRoot "target\$profileName\$crate.exe"
    if (Test-Path $bin) {
        $size = "{0:N1} MB" -f ((Get-Item $bin).Length / 1MB)
        Write-Host "    Windows binary: $bin ($size)" -ForegroundColor Green
    }
}

function Build-Linux {
    Write-Host "==> Building Linux ($profileName) via WSL..." -ForegroundColor Cyan
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        throw "wsl not found. Install WSL (with a distro that has Rust) to build for Linux."
    }
    $wslRoot = Convert-ToWslPath $projectRoot
    $relFlag = if ($Dev) { '' } else { '--release' }
    $cmd = "cd '$wslRoot' && CARGO_TARGET_DIR=target-linux cargo build $relFlag"
    & wsl bash -lc $cmd
    if ($LASTEXITCODE -ne 0) { throw "Linux build failed (exit $LASTEXITCODE)." }

    $bin = Join-Path $projectRoot "target-linux\$profileName\$crate"
    if (Test-Path $bin) {
        $size = "{0:N1} MB" -f ((Get-Item $bin).Length / 1MB)
        Write-Host "    Linux binary:   $bin ($size)" -ForegroundColor Green
    }
}

switch ($Target) {
    'windows' { Build-Windows }
    'linux'   { Build-Linux }
    'all'     { Build-Windows; Build-Linux }
}

Write-Host "Done." -ForegroundColor Cyan
