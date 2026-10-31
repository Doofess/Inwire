<#
.SYNOPSIS
  The signed release, start to finish: agent, app, payload check, installer.

.DESCRIPTION
    npm run dist:signed

  In this order, and the order is the point:

    1. npm run build:agent   cargo build, stamp VERSIONINFO, THEN sign
                             (scripts/agent/build-rust.ps1 - stamping rewrites
                             the bytes a signature covers)
       npm run build:launcher  the same for the `inwire` command
                             (scripts/distribution/build-launcher.ps1)
    2. npm run pack         vite, electron-builder: fuses flipped in afterPack,
                             THEN Inwire.exe and its DLLs signed (electron/sign.cjs)
    3. verify-payload.ps1    every PE file the installer will carry is signed
    4. iscc /DSIGN           setup.iss runs step 3 again itself, then signs the
                             uninstaller and Inwire-Setup.exe
    5. sign.ps1 -Verify      on installer\output\Inwire-Setup.exe

  INWIRE_REQUIRE_SIGNING=1 is set for all of it, in this process, so every
  child inherits it: sign.ps1 normally warns and leaves a file unsigned when no
  certificate is configured - right for a dev build, wrong here - and with this
  set, any step that would have skipped signing fails instead.

  Step 3 duplicates what ISCC does under /DSIGN on purpose: ISCC can only show
  the verifier's first line, and here the whole per-file report is on screen.

  Every step must succeed; the first that does not stops the build with its
  exit code. Nothing here is elevated - installing the result is.

  ISCC is $env:INWIRE_ISCC when set, else the NEWEST of PATH and the Inno Setup 7 and 6
  per-user and per-machine directories (see Find-Iscc), looked for BEFORE the long steps run.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
trap {
  [Console]::Error.WriteLine("[dist:signed] FAILED: $($_.Exception.Message)")
  exit 1
}

$Root =(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$Here = $PSScriptRoot
$PowerShell = if ($env:SystemRoot) { Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' } else { 'powershell.exe' }

function Say([string]$m) { Write-Host "[dist:signed] $m" }

# **The NEWEST compiler found, not the first.** An upgrade keeps the installed
# unins000.exe whenever that file's version is newer than the one Setup carries
# ("Existing file is a newer version. Skipping.") - so a build from an older
# Inno than the last install leaves the machine on the OLD uninstaller, which is
# unsigned, while every other file is signed. That happened: this PC had an
# Inno 7 build installed and the first signed build came from a per-user Inno 6.
function Find-Iscc {
  if ($env:INWIRE_ISCC) {
    if (Test-Path -LiteralPath $env:INWIRE_ISCC -PathType Leaf) { return $env:INWIRE_ISCC }
    throw "INWIRE_ISCC points at $env:INWIRE_ISCC, which does not exist."
  }
  $candidates = @()
  $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($onPath) { $candidates += $onPath.Source }
  foreach ($base in @((Join-Path $env:LOCALAPPDATA 'Programs'), ${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
    if (-not $base) { continue }
    foreach ($dir in @('Inno Setup 7', 'Inno Setup 6')) { $candidates += Join-Path $base "$dir\ISCC.exe" }
  }
  # Ranked by Setup.e32, the stub Setup and the uninstaller are both built from:
  # its FileVersion (51.1055 for Inno 7, 51.1054 for 6.7.3) is the exact number
  # the upgrade compares. ISCC.exe's own version resource reads 0.0.0.0.
  $rank = {
    $stub = Join-Path (Split-Path -Parent $_) 'Setup.e32'
    $v = if (Test-Path -LiteralPath $stub) { (Get-Item -LiteralPath $stub).VersionInfo.FileVersion } else { '0.0' }
    [version]($v -replace '[^\d.].*$', '')
  }
  $found = @($candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
    Sort-Object -Unique | Sort-Object -Descending $rank)
  if ($found.Count -gt 0) { return $found[0] }
  throw 'ISCC.exe (Inno Setup 6 or 7) not found. Install it, or set INWIRE_ISCC to its path.'
}

function Step([string]$name, [scriptblock]$run) {
  Say "---- $name"
  & $run
  if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
}

$iscc = Find-Iscc
Say "ISCC: $iscc"

$env:INWIRE_REQUIRE_SIGNING = '1'

Push-Location $Root
try {
  Step 'npm run build:agent' { & npm.cmd run build:agent }
  Step 'npm run build:launcher' { & npm.cmd run build:launcher }
  Step 'npm run pack' { & npm.cmd run pack }
  Step 'verify-payload.ps1' {
    & $PowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Here 'verify-payload.ps1') `
      (Join-Path $Root 'release\win-unpacked') (Join-Path $Root 'agent-rs\dist') (Join-Path $Root 'launcher-rs\dist')
  }
  # `$p` is literal here - single quotes - because it is Inno's placeholder for
  # the SignTool parameters in setup.iss, not a PowerShell variable.
  Step 'iscc /DSIGN' {
    & $iscc /DSIGN '/Sinwire=powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass $p' (Join-Path $Root 'installer\setup.iss')
  }
  $setup = Join-Path $Root 'installer\output\Inwire-Setup.exe'
  Step 'sign.ps1 -Verify Inwire-Setup.exe' {
    & $PowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Here 'sign.ps1') -Verify $setup
  }
  Say "done: $setup"
} finally {
  Pop-Location
}
exit 0
