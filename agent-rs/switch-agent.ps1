# Switches the installed `InwireAgent` service between the Python agent that
# ships and the Rust one in this directory. Run it from an ELEVATED prompt.
#
#   .\switch-agent.ps1 -Rust      the Rust agent, demand start (ADR 0035)
#   .\switch-agent.ps1 -Python    back to what the installer put there
#   .\switch-agent.ps1 -Status    what is registered now; needs no elevation
#
# **Why this exists rather than instructions in a document.** Both agents
# register the same service name, so swapping is remove-then-install and there
# is a window where the machine has no capture agent at all. A script does that
# window in one transaction; a person following a checklist can be interrupted
# in the middle of it.
#
# **The Rust binary is COPIED into Program Files rather than registered where it
# is built, and that is a security decision.** A LocalSystem service whose image
# path is a user-writable directory can be replaced by any process running as
# that user, which turns "I can write my own files" into "I can run code as
# SYSTEM". `agent-rs\target\release\` is exactly such a directory. Program Files
# is not writable without elevation, so the copy is what keeps the service's
# image as privileged as the service.
#
# A consequence worth knowing: **rebuilding does not update the service.** Run
# `-Rust` again after `cargo build --release`, or you will be testing the
# previous binary and it will look like your change did nothing.

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Rust')]   [switch] $Rust,
  [Parameter(ParameterSetName = 'Python')] [switch] $Python,
  [Parameter(ParameterSetName = 'Status')] [switch] $Status
)

$ErrorActionPreference = 'Stop'

$Service   = 'InwireAgent'
$AgentDir  = 'C:\Program Files\Inwire\agent'
$PythonExe = Join-Path $AgentDir 'inwire-agent-windows.exe'
$RustDest  = Join-Path $AgentDir 'inwire-agent-rs.exe'
$RustBuilt = Join-Path $PSScriptRoot 'target\release\inwire-agent.exe'

# The descriptor the installer writes, stated in full rather than edited into
# whatever `sc sdshow` returns - string surgery on a security descriptor is how
# somebody eventually writes one that parses and means something else. `IU` gets
# `RP` (start) and deliberately NOT `WP` (stop): `IU` is ANY interactive logon,
# so a stop right would let a second Windows user stop a capture the first is
# running. Both agents stop themselves instead. ADR 0035.
$Sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

# **There was a `$PythonDesc` here and it is deliberately gone.**
#
# This script first restored the Python agent exactly as it was found on this
# machine: AUTO_START, with a description still reading "for the Inwire web
# app". That was right while the payload in Program Files was the 3.8.0 build
# from 11 September, because restoring a stale binary to a fresh configuration
# is how you get a service whose settings promise behaviour its code does not
# have - demand start on an agent with no idle self-stop is a service that
# starts on request and then never leaves.
#
# The payload is a current build now, so the reasoning expired with it.
# `install` is left to write its own description (`_svc_description_` in
# `service_windows.py`, which has said "desktop app" for two phases) and its own
# start type from `--startup manual`. Both agents are then configured the same
# way, by the same rule, which is what ADR 0035 actually asks for - and what
# `setup.iss` does today.

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

  The result was an agent that looked perfectly installed and could not be
  started by the app without a UAC prompt, which is the exact regression the
  grant exists to prevent. Nothing failed; a step just landed in the wrong
  order.

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
  $which = if ($path -like '*inwire-agent-rs.exe*') { 'RUST' }
           elseif ($path -like '*inwire-agent-windows.exe*') { 'PYTHON' }
           else { 'unrecognised' }
  Say "$which  |  $start  |  $st"
  Say "  image: $path"
}

function Assert-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This needs an elevated prompt. Registering a service is not something an ordinary user may do.'
  }
}

# Remove whatever is registered, whichever agent it is. Both exes take a
# `remove` verb, but the service may point at a binary that is gone, so sc.exe
# is what does it - it talks to the SCM rather than to a file.
function Remove-Registration {
  & sc.exe stop $Service   2>&1 | Out-Null
  for ($i = 0; $i -lt 50; $i++) {
    $out = (& sc.exe query $Service) -join ' '
    if ($LASTEXITCODE -eq 1060 -or $out -match 'STATE\s*:\s*1\s+STOPPED') { break }
    Start-Sleep -Milliseconds 100
  }
  & sc.exe delete $Service 2>&1 | Out-Null
  # The SCM keeps a deleted service until its last handle closes. Registering
  # the replacement inside that window fails with "marked for deletion", which
  # reads as a permissions problem and is not one.
  for ($i = 0; $i -lt 50; $i++) {
    & sc.exe query $Service 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 1060) { return }
    Start-Sleep -Milliseconds 100
  }
  Say 'warning: the old registration is still present; the install below may fail'
}

# Everything the installer does after registering, which `install` itself does
# not: the interactive-user start right, and the restart-on-failure policy.
function Set-InstallerPolicy {
  & sc.exe sdset $Service $Sddl | Out-Null
  & sc.exe failure $Service reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
  # Read back. A descriptor that did not take is indistinguishable from one that
  # did, until somebody presses a button that then does nothing.
  if (((& sc.exe sdshow $Service) -join '') -notmatch '\(A;;CCLCSWRPLOCRRC;;;IU\)') {
    Say 'warning: the IU start grant did not take; the app will need a UAC prompt to start the agent'
  }
}

if ($Status -or $PSCmdlet.ParameterSetName -eq 'Status') { Show-State; exit 0 }

Assert-Elevated

if ($Rust) {
  if (-not (Test-Path $RustBuilt)) {
    throw "No Rust build at $RustBuilt. Run ``cargo build --release`` in agent-rs first."
  }
  if (-not (Test-Path $AgentDir)) {
    throw "$AgentDir does not exist. Install Inwire first - this swaps the agent, it does not install the app."
  }

  Say 'stopping and removing the current registration'
  Remove-Registration

  Say "copying the build into $AgentDir (admin-only, so the image is as privileged as the service)"
  Copy-Item $RustBuilt $RustDest -Force

  Say 'registering, on the installer''s own command line - options before the verb'
  $code = Invoke-AgentVerb $RustDest @('--startup', 'manual', 'install')
  if ($code -ne 0) { throw "install failed with exit code $code" }

  Set-InstallerPolicy
  Say 'registered. It is DEMAND start: the app asks the SCM for it at launch,'
  Say 'and it stops itself about two seconds after the last client disconnects.'
  Show-State
  exit 0
}

if ($Python) {
  if (-not (Test-Path $PythonExe)) {
    throw "$PythonExe is missing. The Python agent's files are gone, not just its registration."
  }

  Say 'stopping and removing the current registration'
  Remove-Registration

  # Options before the verb. pywin32's `HandleCommandLine` parses with `getopt`,
  # which stops at the first non-option token - so `install --startup manual`
  # prints a usage screen and exits 1 without registering anything. The Rust
  # agent's parser accepts either order and the installer writes this one for
  # both, which is why the two lines above and below are identical.
  Say 'registering the Python agent'
  $code = Invoke-AgentVerb $PythonExe @('--startup', 'manual', 'install')
  if ($code -ne 0) { Say "warning: install reported exit code $code" }

  Set-InstallerPolicy

  & sc.exe start $Service | Out-Null
  Start-Sleep -Seconds 2
  Show-State
  exit 0
}

Show-State
