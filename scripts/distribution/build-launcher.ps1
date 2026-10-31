<#
.SYNOPSIS
  Builds the `inwire` command-line launcher the installer ships: launcher-rs/.

.DESCRIPTION
    npm run build:launcher              cargo build --release, then stamp, then sign
    npm run build:launcher -- -Test     cargo test first, then the same

  Output: launcher-rs\dist\inwire.exe - what `installer/setup.iss` installs at
  {app}\bin\inwire.exe.

  Same order as scripts/agent/build-rust.ps1, and for the same reason: stamping
  VERSIONINFO rewrites the bytes a signature covers, so cargo, then
  scripts/distribution/stamp-launcher.ts, then scripts/sign/sign.ps1 on the
  stamped copy, and nothing may touch the file after that.

  With no certificate configured, sign.ps1 warns and leaves the file unsigned
  (a development build); INWIRE_REQUIRE_SIGNING=1 makes that fatal.

  The GNU toolchain is named on the command line, not in
  launcher-rs/rust-toolchain.toml; agent-rs/rust-toolchain.toml says why.

  Windows PowerShell 5.1 syntax throughout.
#>
[CmdletBinding()]
param(
  [switch] $Test
)

$ErrorActionPreference = 'Stop'

$Toolchain = 'stable-x86_64-pc-windows-gnu'
$Root      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Crate     = Join-Path $Root 'launcher-rs'
$Built     = Join-Path $Crate 'target\release\inwire.exe'

function Say($m) { Write-Host "[build:launcher] $m" }

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
  $env:PATH = (Join-Path $cargoHome 'bin') + ';' + $env:PATH
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  throw 'rustup is not installed (or not on PATH). See https://rustup.rs - then re-run.'
}

$installed = & rustup toolchain list | ForEach-Object { ($_ -split '\s+')[0] }
if ($installed -notcontains $Toolchain) {
  throw "The $Toolchain toolchain is not installed. Run: rustup toolchain install $Toolchain --profile minimal"
}

function Invoke-Cargo([string[]] $Arguments) {
  Say "cargo +$Toolchain $($Arguments -join ' ')"
  Push-Location $Crate
  try {
    & cargo "+$Toolchain" @Arguments
    if ($LASTEXITCODE -ne 0) { throw "cargo $($Arguments[0]) failed with exit code $LASTEXITCODE" }
  } finally {
    Pop-Location
  }
}

# --locked: the lock file is what was tested; `npm run sync:version` keeps this
# crate's own entry in it current.
if ($Test) { Invoke-Cargo @('test', '--locked') }
Invoke-Cargo @('build', '--release', '--locked')

$size = (Get-Item -LiteralPath $Built).Length
Say ("cargo output: {0} ({1:N0} bytes)" -f $Built, $size)

Push-Location $Root
try {
  & npx tsx scripts/distribution/stamp-launcher.ts
  if ($LASTEXITCODE -ne 0) { throw "stamping failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}

$out = Join-Path $Crate 'dist\inwire.exe'

# Signed AFTER the stamp, by the one script that signs anything in this build,
# in its own process, exactly as build-rust.ps1 does it.
$signer = Join-Path $Root 'scripts\sign\sign.ps1'
$powershell = if ($env:SystemRoot) {
  Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
} else { 'powershell.exe' }
Say "signing $out"
& $powershell -NoProfile -ExecutionPolicy Bypass -File $signer $out
if ($LASTEXITCODE -ne 0) { throw "signing failed with exit code $LASTEXITCODE" }

Say ("output:       {0} ({1:N0} bytes)" -f $out, (Get-Item -LiteralPath $out).Length)
