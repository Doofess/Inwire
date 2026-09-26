<#
.SYNOPSIS
  Builds the capture agent the installer ships: the Rust one in agent-rs/.

.DESCRIPTION
    npm run build:agent              cargo build --release, then stamp
    npm run build:agent -- -Test     cargo test first, then the same

  Output: agent-rs\dist\inwire-agent-windows.exe - the name it is installed
  under, and the file `installer/setup.iss` takes as its agent payload.

  The whole ship order, and this is its first three steps:

    1. cargo build --release             (here)
    2. stamp VERSIONINFO, icon, manifest (here: scripts/agent/stamp-agent.ts)
    3. sign the stamped copy             (here: scripts/sign/sign.ps1)
    4. npm run pack                      (signs Inwire.exe and its DLLs)
    5. iscc installer\setup.iss

  Stamping rewrites the bytes a signature covers, so 2 before 3 is not a
  preference: a resource edit after signing is a file whose signature no
  longer verifies. That is why both happen here, in that order, on the staged
  copy - and why nothing may touch that file between this script and `iscc`.

  With no certificate configured, sign.ps1 warns and leaves the file unsigned
  (a development build, or CI), and this still succeeds; set
  INWIRE_REQUIRE_SIGNING=1 to make that fatal for a release.

  ## Why the toolchain is on the command line

  `agent-rs/rust-toolchain.toml` cannot name the host: rustup refuses a
  channel with a target tuple in it wherever that toolchain is not already
  installed, which is every fresh machine and every CI runner. So the GNU host
  is pinned here instead, with `+toolchain`, which beats every other way rustup
  chooses one. The file explains the rest, including why GNU.

  Windows PowerShell 5.1 syntax throughout, so `powershell` runs it on any
  Windows machine without PowerShell 7.
#>
[CmdletBinding()]
param(
  [switch] $Test
)

$ErrorActionPreference = 'Stop'

$Toolchain = 'stable-x86_64-pc-windows-gnu'
$Root      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Crate     = Join-Path $Root 'agent-rs'
$Built     = Join-Path $Crate 'target\release\inwire-agent.exe'

function Say($m) { Write-Host "[build:agent] $m" }

# rustup installs per-user into %USERPROFILE%\.cargo\bin and edits PATH for new
# logons only, so a shell opened before the install - or a CI step - may not see
# it. Looked for there before giving up.
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
  $env:PATH = (Join-Path $cargoHome 'bin') + ';' + $env:PATH
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  throw 'rustup is not installed (or not on PATH). See https://rustup.rs - then re-run.'
}

# Asked by name, and installing is left to a person: it is a ~200 MB download,
# which is not something a build script should decide to do.
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

# --locked: the lock file is what was tested, and a build that quietly
# re-resolved it would ship something else. `npm run sync:version` keeps the
# crate's own entry in it current, which is what makes this safe to insist on.
if ($Test) { Invoke-Cargo @('test', '--locked') }
Invoke-Cargo @('build', '--release', '--locked')

$size = (Get-Item -LiteralPath $Built).Length
Say ("cargo output: {0} ({1:N0} bytes)" -f $Built, $size)

Push-Location $Root
try {
  & npx tsx scripts/agent/stamp-agent.ts
  if ($LASTEXITCODE -ne 0) { throw "stamping failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}

$out = Join-Path $Crate 'dist\inwire-agent-windows.exe'

# Signed AFTER the stamp, by the one script that signs anything in this build
# (electron-builder's hook and Inno's SignTool call it too), in its own process
# as they do. It picks the certificate and the timestamp server; this passes
# only the file. Windows PowerShell by absolute path, as `electron/sign.cjs`
# runs it: present on every supported Windows, and no PATH lookup to get wrong.
$signer = Join-Path $Root 'scripts\sign\sign.ps1'
$powershell = if ($env:SystemRoot) {
  Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
} else { 'powershell.exe' }
#
# Its own report is the readback: it asks WinVerifyTrust and prints the signer,
# the digest and the timestamp, or says plainly that nothing was signed. A
# second check here with Get-AuthenticodeSignature is worse than none - under
# `npm run`, Windows PowerShell can inherit PowerShell 7's PSModulePath and
# fail to autoload the module that cmdlet lives in, failing a good build.
Say "signing $out"
& $powershell -NoProfile -ExecutionPolicy Bypass -File $signer $out
if ($LASTEXITCODE -ne 0) { throw "signing failed with exit code $LASTEXITCODE" }

Say ("output:       {0} ({1:N0} bytes)" -f $out, (Get-Item -LiteralPath $out).Length)
