<#
.SYNOPSIS
  The signed release, start to finish: agent, app, payload check, installer.

.DESCRIPTION
    npm run dist:signed

  In this order, and the order is the point:

    1. npm run build:agent   cargo build, stamp VERSIONINFO, THEN sign
                             (scripts/agent/build-rust.ps1 - stamping rewrites
                             the bytes a signature covers)
    2. npm run pack          vite, electron-builder: fuses flipped in afterPack,
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

  ISCC is found at $env:INWIRE_ISCC, on PATH, or in Inno Setup 6's per-user and
  per-machine install directories, and looked for BEFORE the long steps run.
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

function Find-Iscc {
  $candidates = @()
  if ($env:INWIRE_ISCC) { $candidates += $env:INWIRE_ISCC }
  $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($onPath) { $candidates += $onPath.Source }
  if ($env:LOCALAPPDATA) { $candidates += Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' }
  if (${env:ProgramFiles(x86)}) { $candidates += Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }
  if ($env:ProgramFiles) { $candidates += Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe' }
  foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c } }
  throw 'ISCC.exe (Inno Setup 6) not found. Install it, or set INWIRE_ISCC to its path.'
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
  Step 'npm run pack' { & npm.cmd run pack }
  Step 'verify-payload.ps1' {
    & $PowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $Here 'verify-payload.ps1') `
      (Join-Path $Root 'release\win-unpacked') (Join-Path $Root 'agent-rs\dist')
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
