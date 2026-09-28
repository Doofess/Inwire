<#
.SYNOPSIS
  The agent writes a capture's files as its client, never as itself (ADR 0052):
  the by-hand item in docs/verification.md, as one command.

.DESCRIPTION
  The agent is LocalSystem and could write anywhere. It writes each capture's
  pcapng impersonating the client that started it, so a client can only make
  it write where that client could have written itself. With one account both
  ends are the same user, so nothing can tell "the client's identity" from
  "the identity of whoever else is connected" - that needs a second user.

  Run as the SECOND, standard user (B), naming the FIRST user's (A's) capture
  folder:

    powershell -ExecutionPolicy Bypass -File C:\dev\Inwire\scripts\agent\second-account-check.ps1 `
      -Target 'C:\Users\A\AppData\Local\Inwire\captures'

  then, back as A, the command it prints (-VerifyCaptureId), which looks in
  A's folder - B cannot, which is the point.

  Four cases, each over a real connection to \\.\pipe\inwire-agent, each a
  capture on a real adapter:

    1. B names A's folder              -> refused (capture_failed)
    2. B names B's own folder          -> written, and the file is B's
    3. B's own folder, but connected at
       the Identification level        -> refused: no identity to act as
    4. ...at the Anonymous level       -> refused

  Without -Target it runs cases 2-4 only, which any single account can.

  Needs: the Inwire service installed, Npcap, no capture running in any
  Inwire window (a running one answers "busy"), and a non-elevated shell.
  Plain Windows PowerShell 5.1 is enough; nothing from the repository is
  loaded, so it runs for an account that has never run npm.
#>
param(
  # A's capture folder, for case 1. B should not be able to write it.
  [string]$Target,
  # Run as A after B's run: the capture id case 1 named.
  [string]$VerifyCaptureId,
  # An adapter's device name; by default the first Ethernet or Wi-Fi one.
  [string]$Device
)

$ErrorActionPreference = 'Stop'
$script:failures = 0
function Pass([string]$what) { Write-Host "PASS  $what" -ForegroundColor Green }
function Fail([string]$what) { Write-Host "FAIL  $what" -ForegroundColor Red; $script:failures++ }
function Note([string]$what) { Write-Host "      $what" }
function Check([bool]$ok, [string]$what) { if ($ok) { Pass $what } else { Fail $what } }

# --- A's half: nothing appeared in A's folder ---------------------------------
if ($VerifyCaptureId) {
  if (-not $Target) { throw '-VerifyCaptureId needs -Target, the same folder B named' }
  Note "as $(whoami)"
  Check (Test-Path -LiteralPath $Target) "the folder B named exists, so the refusal meant something: $Target"
  Check (-not (Test-Path -LiteralPath (Join-Path $Target $VerifyCaptureId))) `
    "nothing named $VerifyCaptureId was created in it - the service did not write it for B"
  if ($script:failures -gt 0) { exit 1 }
  Write-Host "`nA's half passed."
  exit 0
}

# --- who is running this ------------------------------------------------------
$me = whoami
$groups = whoami /groups /fo csv | ConvertFrom-Csv
$admins = $groups | Where-Object { $_.SID -eq 'S-1-5-32-544' }
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
Note "running as $me"
if ($elevated) {
  Write-Host 'This shell is elevated, so it can write almost anywhere and a refusal proves nothing. Run it unelevated.' -ForegroundColor Yellow
  exit 2
}
if ($Target) {
  if ($admins) { Note 'this account is an administrator (not elevated here); a STANDARD account is the stronger check' }
  else { Note 'a standard account, as the check wants' }
}

# --- the wire: u32 length (payload + 1), u8 kind, UTF-8 JSON (agentFraming.ts)
$FRAME_JSON = 0

function Open-Agent([Security.Principal.TokenImpersonationLevel]$level) {
  $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'inwire-agent',
    [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous, $level)
  try { $pipe.Connect(3000) }
  catch {
    # Demand start: the service may be stopped. An interactive user may start
    # it (the IU ACE has RP), and it stops itself once nobody is connected.
    & sc.exe start InwireAgent | Out-Null
    $pipe.Dispose()
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'inwire-agent',
      [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous, $level)
    $pipe.Connect(10000)
  }
  return @{ Pipe = $pipe; Buffer = New-Object byte[] (1MB); Acc = New-Object byte[] 0; Pending = $null; Heard = New-Object System.Collections.ArrayList }
}

function Send-Command($link, [hashtable]$command) {
  $payload = [Text.Encoding]::UTF8.GetBytes(($command | ConvertTo-Json -Compress -Depth 5))
  $frame = New-Object byte[] (5 + $payload.Length)
  [BitConverter]::GetBytes([uint32]($payload.Length + 1)).CopyTo($frame, 0)
  $frame[4] = $FRAME_JSON
  $payload.CopyTo($frame, 5)
  $link.Pipe.Write($frame, 0, $frame.Length)
  $link.Pipe.Flush()
}

# Reads for $ms, keeping every JSON message; batches of frames are skipped.
function Receive-For($link, [int]$ms) {
  $deadline = [DateTime]::UtcNow.AddMilliseconds($ms)
  while ($true) {
    $left = [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds
    if ($left -le 0) { break }
    if ($null -eq $link.Pending) { $link.Pending = $link.Pipe.ReadAsync($link.Buffer, 0, $link.Buffer.Length) }
    if (-not $link.Pending.Wait($left)) { break }
    $n = $link.Pending.Result
    $link.Pending = $null
    if ($n -le 0) { break }
    $acc = New-Object byte[] ($link.Acc.Length + $n)
    [Array]::Copy($link.Acc, 0, $acc, 0, $link.Acc.Length)
    [Array]::Copy($link.Buffer, 0, $acc, $link.Acc.Length, $n)
    $at = 0
    while ($acc.Length - $at -ge 5) {
      $declared = [BitConverter]::ToUInt32($acc, $at)
      $total = 4 + [int]$declared
      if ($acc.Length - $at -lt $total) { break }
      if ($acc[$at + 4] -eq $FRAME_JSON) {
        $text = [Text.Encoding]::UTF8.GetString($acc, $at + 5, $declared - 1)
        [void]$link.Heard.Add(($text | ConvertFrom-Json))
      }
      $at += $total
    }
    $rest = New-Object byte[] ($acc.Length - $at)
    [Array]::Copy($acc, $at, $rest, 0, $rest.Length)
    $link.Acc = $rest
  }
}

function Close-Agent($link) {
  try { Send-Command $link @{ type = 'stop_capture' }; Receive-For $link 1500 } catch { }
  $link.Pipe.Dispose()
}

function New-CaptureId {
  'cap-{0}-{1:x4}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), (Get-Random -Maximum 65536)
}

function Capture-Failure($link) {
  $link.Heard | Where-Object { $_.type -eq 'error' -and $_.code -eq 'capture_failed' } | Select-Object -First 1
}

# One capture: connect at $level, point the agent at $root, start, listen.
function Try-Capture([Security.Principal.TokenImpersonationLevel]$level, [string]$root, [string]$id, [int]$listenMs) {
  $link = Open-Agent $level
  Send-Command $link @{ type = 'set_capture_root'; dir = $root }
  Send-Command $link @{ type = 'set_interfaces'; interfaces = @($script:device) }
  Send-Command $link @{ type = 'start_capture'; captureId = $id }
  Receive-For $link $listenMs
  Close-Agent $link
  # The agent stops a capture when its client leaves; give it a moment before
  # the next case connects, so that one is not answered "busy".
  Start-Sleep -Milliseconds 1500
  return $link.Heard
}

# --- the adapter --------------------------------------------------------------
$probe = Open-Agent ([Security.Principal.TokenImpersonationLevel]::Impersonation)
Receive-For $probe 1500
$hello = $probe.Heard | Where-Object { $_.type -eq 'hello' } | Select-Object -First 1
$probe.Pipe.Dispose()
if ($null -eq $hello) { Write-Host 'The agent did not say hello - is the Inwire service installed?' -ForegroundColor Red; exit 2 }
if ($hello.state -ne 'idle') { Write-Host 'A capture is running. Stop it in every Inwire window, then run this again.' -ForegroundColor Yellow; exit 2 }
if ($Device) { $script:device = $Device }
else {
  # Wired first, as the live drives capture: Wi-Fi can be up with nothing on it.
  # A label is the connection's name, then the device's.
  $pick = @($hello.interfaces | Where-Object { $_.label -match '^Ethernet\b' }) +
    @($hello.interfaces | Where-Object { $_.label -match '^Wi-?Fi\b' }) | Select-Object -First 1
  if ($null -eq $pick) { Write-Host 'No Ethernet or Wi-Fi adapter found; pass -Device.' -ForegroundColor Red; exit 2 }
  $script:device = $pick.name
  Note "capturing on $($pick.label)"
}
Write-Host ''

# --- 1. B names A's folder -----------------------------------------------------
$attackId = $null
if ($Target) {
  Write-Host "--- 1. naming another user's folder: $Target ---"
  # First, that this account really cannot write there - or a refusal would
  # prove nothing, and a success would not be the agent's doing.
  $writable = $false
  try {
    $probeDir = Join-Path $Target ('probe-' + [Guid]::NewGuid().ToString('n'))
    [void][IO.Directory]::CreateDirectory($probeDir)
    $writable = $true
    Remove-Item -LiteralPath $probeDir -Force
  } catch { }
  if ($writable) {
    Fail "this account can write $Target itself, so the check proves nothing - name a folder it cannot"
  } else {
    Pass 'this account cannot write that folder itself'
    $attackId = New-CaptureId
    $heard = Try-Capture ([Security.Principal.TokenImpersonationLevel]::Impersonation) $Target $attackId 4000
    $failed = Capture-Failure @{ Heard = $heard }
    Note "the agent said: $(if ($failed) { $failed.message } else { '(no capture_failed)' })"
    Check ($null -ne $failed) 'the agent refused to write there for this account'
    Check ($null -eq ($heard | Where-Object { $_.type -eq 'capture_file' -and $_.state -eq 'open' })) '...and reported no file opened'
  }
  Write-Host ''
}

# --- 2. B's own folder: written, and B's --------------------------------------
Write-Host '--- 2. this account''s own folder ---'
$ownRoot = Join-Path $env:TEMP ('inwire-second-account-' + [Guid]::NewGuid().ToString('n').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $ownRoot)
try {
  $ownId = New-CaptureId
  $heard = Try-Capture ([Security.Principal.TokenImpersonationLevel]::Impersonation) $ownRoot $ownId 4000
  $failed = Capture-Failure @{ Heard = $heard }
  if ($failed) { Note "the agent said: $($failed.message)" }
  $files = @(Get-ChildItem -LiteralPath (Join-Path $ownRoot "$ownId\pcapng") -Filter *.pcapng -ErrorAction SilentlyContinue)
  Check ($files.Count -ge 1 -and $null -eq $failed) 'the capture was written into this account''s folder'
  if ($files.Count -ge 1) {
    $owner = (Get-Acl -LiteralPath $files[0].FullName).Owner
    Note "owner $owner, this user $me, $($files[0].Length) bytes"
    Check ($owner -eq $me) '...owned by this account, not SYSTEM: written as the client'
  }

  # --- 3 and 4. no identity to act as -----------------------------------------
  foreach ($level in 'Identification', 'Anonymous') {
    Write-Host ''
    Write-Host "--- $(if ($level -eq 'Identification') { 3 } else { 4 }). connected at the $level level ---"
    $id = New-CaptureId
    $heard = Try-Capture ([Security.Principal.TokenImpersonationLevel]$level) $ownRoot $id 3000
    $failed = Capture-Failure @{ Heard = $heard }
    Note "the agent said: $(if ($failed) { $failed.message } else { '(no capture_failed)' })"
    Check ($null -ne $failed) 'the agent refused: it has no identity it may act as'
    Check (-not (Test-Path -LiteralPath (Join-Path $ownRoot $id))) '...and wrote nothing, not even as itself'
  }
} finally {
  Remove-Item -LiteralPath $ownRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failures -gt 0) { Write-Host "$($script:failures) check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host 'This account''s half passed.' -ForegroundColor Green
if ($attackId) {
  Write-Host ''
  Write-Host 'Now, signed in as the account that owns that folder, run:' -ForegroundColor Cyan
  Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Target '$Target' -VerifyCaptureId $attackId"
}
exit 0
