# Puts a freshly built agent under the installed `InwireAgent` service, without
# running the installer. Run it from an ELEVATED prompt.
#
#   .\switch-agent.ps1 -Rust      this directory's build (npm run build:agent)
#   .\switch-agent.ps1 -Python    a PyInstaller build of local-agent/, by hand
#   .\switch-agent.ps1 -Status    what is registered now; needs no elevation
#
# **The installer ships the Rust agent now** (ADR 0037), so `-Rust` is the
# development loop - rebuild, swap, test against the real app - and `-Python` is
# the way back for a comparison such as `scripts/agent/agent-compare.ts`.
#
# **Both install under the installer's own image name**,
# `{app}\agent\inwire-agent-windows.exe`. This script used to copy the Rust
# build in beside it as `inwire-agent-rs.exe` and re-register the service
# there, which was right while the installer put the Python agent at the real
# name and a swap had to leave it intact to swap back to. It is wrong now: the
# next installer run would find a service pointing at a file it did not
# install, and a status check comparing the image to what the installer ships
# would be comparing two different paths. One name means a swap by hand and an
# install leave the service in the same shape, and `install`'s own
# create-or-update (main.rs) keeps the registration in place instead of
# removing and re-creating it.
#
# **The binary is COPIED into Program Files rather than registered where it is
# built, and that is a security decision.** A LocalSystem service whose image
# path is a user-writable directory can be replaced by any process running as
# that user, which turns "I can write my own files" into "I can run code as
# SYSTEM". `agent-rs\dist\` is exactly such a directory. Program Files is not
# writable without elevation, so the copy is what keeps the service's image as
# privileged as the service.
#
# A consequence worth knowing: **rebuilding does not update the service.** Run
# `-Rust` again after `npm run build:agent`, or you will be testing the previous
# binary and it will look like your change did nothing.

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Rust')]   [switch] $Rust,
  [Parameter(ParameterSetName = 'Python')] [switch] $Python,
  [Parameter(ParameterSetName = 'Status')] [switch] $Status
)

$ErrorActionPreference = 'Stop'

$Service   = 'InwireAgent'
$AgentDir  = 'C:\Program Files\Inwire\agent'
$ExeName   = 'inwire-agent-windows.exe'
$Installed = Join-Path $AgentDir $ExeName
# What this script's earlier versions installed the Rust agent as. Removed on
# sight, so a machine that used them converges on the installer's layout.
$OldRustName = Join-Path $AgentDir 'inwire-agent-rs.exe'

# **The stamped copy, not cargo's output.** `target\release\inwire-agent.exe`
# has no VERSIONINFO, icon or manifest; `npm run build:agent` writes the one the
# installer ships here, and that is the only one worth testing as the service.
# (This used to pick the newest of two `target\` paths, because an explicit
# `--target` moved cargo's output; the build script owns that question now.)
$RustBuilt   = Join-Path $PSScriptRoot "dist\$ExeName"
$PythonBuilt = Join-Path $PSScriptRoot "..\local-agent\dist\inwire-agent-windows"

# The descriptor the installer writes, stated in full rather than edited into
# whatever `sc sdshow` returns - string surgery on a security descriptor is how
# somebody eventually writes one that parses and means something else. `IU` gets
# `RP` (start) and deliberately NOT `WP` (stop): `IU` is ANY interactive logon,
# so a stop right would let a second Windows user stop a capture the first is
# running. Both agents stop themselves instead. ADR 0035.
$Sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

function Say($m) { Write-Host "[switch-agent] $m" }

<#
.SYNOPSIS
  Runs one of the agent binaries and WAITS for it, whatever its subsystem.

.DESCRIPTION
  **This exists because `& $exe install` is not enough, and the way that failed
  was silent.** PowerShell waits for console-subsystem processes and does not
  wait for GUI-subsystem ones; the PyInstaller build is the latter (its
  bootloader is `runw.exe`). So `&` returned the instant it was launched,
  `Set-InstallerPolicy` ran `sc sdset` against a service pywin32 had not created
  yet, and pywin32 then created it with the SCM's default descriptor - no `RP`
  on the `IU` ace.

  `Start-Process -Wait -PassThru` waits on a handle rather than on a heuristic,
  so it is right for both agents and stays right if either one's subsystem
  changes again.
#>
function Invoke-AgentVerb {
  param([string] $Exe, [string[]] $Arguments)
  $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
  return $p.ExitCode
}

function Show-State {
  $q = (& sc.exe qc $Service) -join "`n"
  if ($LASTEXITCODE -eq 1060) { Say 'no InwireAgent service is registered'; return }
  $path  = if ($q -match 'BINARY_PATH_NAME\s*:\s*(.+)')  { $Matches[1].Trim() } else { '?' }
  $start = if ($q -match 'START_TYPE\s*:\s*(.+)')        { $Matches[1].Trim() } else { '?' }
  $state = ((& sc.exe query $Service) -join "`n")
  $st    = if ($state -match 'STATE\s*:\s*\d+\s+(\w+)')  { $Matches[1] }        else { '?' }
  # Told apart by what sits beside the exe, because both carry the same name
  # and the same VERSIONINFO strings: the PyInstaller build is a directory with
  # `_internal` in it, and the Rust one is a single file.
  $which = if ($path -like '*inwire-agent-rs.exe*') { 'RUST (old layout - run -Rust to move it)' }
           elseif ($path -notlike "*$ExeName*") { 'unrecognised' }
           elseif (Test-Path (Join-Path $AgentDir '_internal')) { 'PYTHON' }
           else { 'RUST' }
  Say "$which  |  $start  |  $st"
  Say "  image: $path"
  if (Test-Path $Installed) {
    $item = Get-Item $Installed
    Say ("  file:  {0} bytes, version {1}, written {2}" -f $item.Length, $item.VersionInfo.FileVersion, $item.LastWriteTime)
  }
}

function Assert-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This needs an elevated prompt. Registering a service is not something an ordinary user may do.'
  }
}

# Stops the service and makes sure its image is no longer held open, which is
# what the copy below needs. Mirrors the installer's PrepareToInstall: ask, wait,
# and only then force - an agent can be alive and not answer a stop.
function Stop-Agent {
  & sc.exe stop $Service 2>&1 | Out-Null
  for ($i = 0; $i -lt 50; $i++) {
    $out = (& sc.exe query $Service) -join ' '
    if ($LASTEXITCODE -eq 1060 -or $out -match 'STATE\s*:\s*1\s+STOPPED') { return }
    Start-Sleep -Milliseconds 100
  }
  Say 'the service did not stop when asked; ending the process'
  & taskkill.exe /F /IM $ExeName 2>&1 | Out-Null
  & taskkill.exe /F /IM (Split-Path $OldRustName -Leaf) 2>&1 | Out-Null
  # The kernel releases the image's handle when the process object goes, which
  # lags the kill slightly.
  Start-Sleep -Seconds 1
}

# Everything the installer does after `install`, which `install` itself does
# not: the interactive-user start right, the restart-on-failure policy, and the
# npcap ordering - conditional, exactly as the installer makes it, because a
# dependency on a service that does not exist is a service that never starts.
function Set-InstallerPolicy {
  & sc.exe sdset $Service $Sddl | Out-Null
  & sc.exe failure $Service reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
  if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap') {
    & sc.exe config $Service depend= npcap | Out-Null
  }
  # Read back. A descriptor that did not take is indistinguishable from one that
  # did, until somebody presses a button that then does nothing.
  if (((& sc.exe sdshow $Service) -join '') -notmatch '\(A;;CCLCSWRPLOCRRC;;;IU\)') {
    Say 'warning: the IU start grant did not take; the app will need a UAC prompt to start the agent'
  }
}

# What pywin32 registered and the Rust agent never reads - the same cleanup the
# installer's RemovePythonAgentRegistrations does, for the same reason: with
# `_internal` gone, the event-log source's message file is gone with it.
function Remove-PythonRegistrations {
  Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$Service\PythonClass" -Recurse -ErrorAction SilentlyContinue
  $source = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$Service"
  $file = (Get-ItemProperty $source -Name EventMessageFile -ErrorAction SilentlyContinue).EventMessageFile
  if ($file -and $file -like '*\_internal\*') { Remove-Item $source -Recurse }
}

if ($Status -or $PSCmdlet.ParameterSetName -eq 'Status') { Show-State; exit 0 }

Assert-Elevated

if (-not (Test-Path $AgentDir)) {
  throw "$AgentDir does not exist. Install Inwire first - this swaps the agent, it does not install the app."
}

if ($Rust) {
  if (-not (Test-Path $RustBuilt)) {
    throw "No stamped Rust build at $RustBuilt. Run ``npm run build:agent`` first."
  }

  Say 'stopping the service'
  Stop-Agent

  # Named, and with its age, because installing yesterday's binary and being
  # told nothing is the mistake this whole script is written around.
  $age = [int]((Get-Date).ToUniversalTime() - (Get-Item $RustBuilt).LastWriteTimeUtc).TotalMinutes
  Say "copying $RustBuilt (built $age minute(s) ago) to $Installed"
  Say '  admin-only, so the image is as privileged as the service'
  Copy-Item $RustBuilt $Installed -Force

  # The Python agent's tree, if it was there, and this script's old name for the
  # Rust one. Build output both, and removing them is what makes -Status right.
  if (Test-Path (Join-Path $AgentDir '_internal')) {
    Say 'removing the Python agent''s _internal tree'
    Remove-Item (Join-Path $AgentDir '_internal') -Recurse -Force
  }
  Remove-PythonRegistrations

  # Options before the verb, as the installer writes it. Over an existing
  # registration this UPDATES it - image path, start type, LocalSystem, display
  # name - so a registration pointing at the old `inwire-agent-rs.exe` is moved
  # back to the installer's name here.
  Say 'registering, on the installer''s own command line'
  $code = Invoke-AgentVerb $Installed @('--startup', 'manual', 'install')
  if ($code -ne 0) { throw "install failed with exit code $code" }
  if (Test-Path $OldRustName) { Remove-Item $OldRustName -Force }

  Set-InstallerPolicy
  Say 'registered. It is DEMAND start: the app asks the SCM for it at launch,'
  Say 'and it stops itself about two seconds after the last client disconnects.'
  Show-State
  exit 0
}

if ($Python) {
  $pythonExe = Join-Path $PythonBuilt $ExeName
  if (-not (Test-Path $pythonExe)) {
    throw "No PyInstaller build at $PythonBuilt. Run ``pyinstaller local-agent/inwire_agent.spec`` first."
  }

  Say 'stopping the service'
  Stop-Agent

  # The whole --onedir tree: the exe is a bootloader and `_internal` is the
  # agent. Replaced rather than merged, as the installer's [InstallDelete] does.
  Say "copying $PythonBuilt into $AgentDir"
  if (Test-Path (Join-Path $AgentDir '_internal')) {
    Remove-Item (Join-Path $AgentDir '_internal') -Recurse -Force
  }
  Copy-Item (Join-Path $PythonBuilt '*') $AgentDir -Recurse -Force

  # Options before the verb, and here it is not a preference: pywin32's
  # `HandleCommandLine` parses with `getopt`, which stops at the first
  # non-option token, so `install --startup manual` prints a usage screen and
  # exits 1 without registering anything. Over an existing registration pywin32
  # falls through from install to update.
  Say 'registering the Python agent'
  $code = Invoke-AgentVerb $Installed @('--startup', 'manual', 'install')
  if ($code -ne 0) { Say "warning: install reported exit code $code" }

  Set-InstallerPolicy

  & sc.exe start $Service | Out-Null
  Start-Sleep -Seconds 2
  Show-State
  Say 'the next Inwire install puts the Rust agent back.'
  exit 0
}

Show-State
