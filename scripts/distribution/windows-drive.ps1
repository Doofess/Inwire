<#
.SYNOPSIS
  Opt-in end-to-end drive of the signed bootstrap, the installer, the `inwire`
  command and the uninstaller, for a DISPOSABLE clean Windows machine only.

.DESCRIPTION
    powershell -NoProfile -ExecutionPolicy Bypass -File windows-drive.ps1 `
      -Bootstrap C:\drive\install-inwire.ps1 -OlderInstaller C:\drive\Inwire-Setup-old.exe `
      -IAmOnADisposableMachine

  THIS INSTALLS AND UNINSTALLS INWIRE, EDITS THE MACHINE PATH AND STOPS PROCESSES.
  Never run it on a development PC. It refuses unless ALL of these hold, before it
  reads or changes anything else:

    - the -IAmOnADisposableMachine switch is present;
    - the environment variable INWIRE_DISPOSABLE_MACHINE equals 1;
    - the development certificate "CN=Inwire Code Signing (this PC)" is in none of
      Cert:\CurrentUser\My, Cert:\CurrentUser\Root, Cert:\LocalMachine\Root,
      Cert:\LocalMachine\TrustedPublisher (its presence means a dev box, and it
      would also make the clean-trust scenario meaningless);
    - there is no .signing.json two levels above this script;
    - there is no .git two levels above this script (copy the drive OUT of the
      checkout onto the machine);
    - this PowerShell is not elevated (the scenarios need a normal user's UAC).

  Each scenario appends JSON lines (scenario, outcome, details, timestamp) to the
  result file. Outcomes: PASS, FAIL, MANUAL (passed, but a tester attested a
  step), SKIPPED (the tester declined a manual step; NOT a pass).

  -List prints the scenarios and exits 0; it acts on nothing and needs no guard.

  Windows PowerShell 5.1 syntax, ASCII only.

.PARAMETER Bootstrap
  The signed release bootstrap (install-inwire.ps1 as built).
.PARAMETER OlderInstaller
  An older Inwire-Setup.exe, for the upgrade-unsaved scenario.
.PARAMETER ResultFile
  Where the JSON lines go. Default: %TEMP%\inwire-windows-drive.jsonl.
.PARAMETER Scenario
  Scenario names to run. Default: all.
.PARAMETER List
  Print the scenarios and exit 0.
.PARAMETER IAmOnADisposableMachine
  Required to do anything but -List.
#>
[CmdletBinding()]
param(
  [string] $Bootstrap,
  [string] $OlderInstaller,
  [string] $ResultFile,
  [string[]] $Scenario,
  [switch] $List,
  [switch] $IAmOnADisposableMachine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScenarioDescriptions = [ordered]@{
  'uac-decline'     = 'MANUAL: decline the UAC prompt; exit 2 and nothing changed'
  'fresh-install'   = 'bootstrap on a clean machine; files, service, PATH entry once, marker'
  'launch'          = 'bootstrap -Launch: not elevated; a second inwire leaves one main process'
  'command'         = 'inwire --version/--help/--bogus in a fresh shell; stale shell; elevated 77 (manual)'
  'custom-path'     = 'MANUAL: interactive install to C:\Inwire Test & co\; launcher and PATH follow'
  'upgrade-unsaved' = 'older installer, unsaved capture, cancel then accept the close prompt'
  'no-npcap'        = 'install succeeds with or without Npcap and leaves it untouched'
  'clean-trust'     = 'bootstrap signature Valid without the dev certificate; a changed byte is not'
  'uninstall'       = 'silent uninstall removes ours only; captures, monitoring, other PATH, Npcap stay'
  'reinstall'       = 'bootstrap again after uninstall, with no Node, Rust or pwsh'
}

if ($List) {
  foreach ($n in $ScenarioDescriptions.Keys) { Write-Host ('{0,-16} {1}' -f $n, $ScenarioDescriptions[$n]) }
  exit 0
}

# --- guards: everything above acts on nothing; nothing below runs until these pass ---

function Stop-Refused([string[]] $lines) {
  foreach ($l in $lines) { Write-Host ('REFUSED: ' + $l) }
  exit 2
}

if (-not $IAmOnADisposableMachine) {
  Stop-Refused @('the -IAmOnADisposableMachine switch is required. This drive installs and uninstalls Inwire and edits the machine PATH; use it on a disposable machine only.')
}
if ($env:INWIRE_DISPOSABLE_MACHINE -ne '1') {
  Stop-Refused @('the environment variable INWIRE_DISPOSABLE_MACHINE must equal 1 (set it on the disposable machine, never on a development PC).')
}

$DevCertSubject = 'CN=Inwire Code Signing (this PC)'

function Get-GuardProblems {
  $problems = @()
  foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
    try {
      $hit = @(Get-ChildItem -LiteralPath $store -ErrorAction Stop | Where-Object { $_.Subject -eq $DevCertSubject })
      if ($hit.Count -gt 0) { $problems += ('the development certificate "' + $DevCertSubject + '" is in ' + $store + ': this is a development PC') }
    } catch {
      $problems += ('cannot read ' + $store + ' to prove the development certificate is absent: ' + $_.Exception.Message)
    }
  }
  $twoUp = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
  if ($twoUp) {
    if (Test-Path -LiteralPath (Join-Path $twoUp '.signing.json')) { $problems += ('.signing.json exists at ' + $twoUp + ': this is a checkout with signing credentials') }
    if (Test-Path -LiteralPath (Join-Path $twoUp '.git')) { $problems += ('.git exists at ' + $twoUp + ': copy the drive out of the checkout onto the disposable machine') }
  }
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $problems += 'this PowerShell is elevated; run the drive as a normal user (the scenarios need a normal user and a UAC prompt)'
  }
  return $problems
}

$problems = @(Get-GuardProblems)
if ($problems.Count -gt 0) { Stop-Refused $problems }

if (-not $Bootstrap -or -not (Test-Path -LiteralPath $Bootstrap -PathType Leaf)) {
  Stop-Refused @('-Bootstrap must name the signed bootstrap script that exists.')
}
$selected = @($ScenarioDescriptions.Keys)
if ($Scenario) {
  $unknown = @($Scenario | Where-Object { -not $ScenarioDescriptions.Contains($_) })
  if ($unknown.Count -gt 0) { Stop-Refused @('unknown scenario: ' + ($unknown -join ', ') + ' (see -List)') }
  $selected = @($ScenarioDescriptions.Keys | Where-Object { $Scenario -contains $_ })
}
if (-not $ResultFile) { $ResultFile = Join-Path $env:TEMP 'inwire-windows-drive.jsonl' }

# --- from here the drive acts ---

$UninstallSubKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1'
$EnvSubKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$UnrelatedEntry = 'C:\InwireDriveUnrelated'
$ServiceName = 'InwireAgent'

$script:Ev = $null
$script:Failed = $false
$script:Declined = $false
$script:Attested = $false

function Add-Evidence([string] $line) { $script:Ev.Add($line) | Out-Null; Write-Host ('  ' + $line) }
function Expect([string] $name, [bool] $ok, [string] $detail = '') {
  if (-not $ok) { $script:Failed = $true }
  $text = $(if ($ok) { 'PASS ' } else { 'FAIL ' }) + $name
  if ($detail) { $text += ' [' + $detail + ']' }
  Add-Evidence $text
}
function Note([string] $text) { Add-Evidence ('NOTE ' + $text) }

# Asks the tester. Returns yes, no or skip. 'no' fails the scenario; 'skip' makes it SKIPPED.
function Confirm-Manual([string] $instruction) {
  Write-Host ''
  Write-Host ('MANUAL: ' + $instruction)
  $a = (Read-Host 'Result? y = done and as described, n = done but NOT as described, s = skip').Trim().ToLowerInvariant()
  if ($a -eq 'y') { $script:Attested = $true; Add-Evidence ('MANUAL confirmed: ' + $instruction); return 'yes' }
  if ($a -eq 'n') { Expect ('manual step as described: ' + $instruction) $false 'tester said no'; return 'no' }
  $script:Declined = $true; Add-Evidence ('SKIPPED by tester: ' + $instruction); return 'skip'
}

function Write-Result([string] $scenario, [string] $outcome, [string[]] $details) {
  $row = [ordered]@{
    scenario = $scenario
    outcome = $outcome
    details = @($details)
    timestamp = (Get-Date).ToUniversalTime().ToString('o')
  }
  $line = ConvertTo-Json -InputObject $row -Compress
  [System.IO.File]::AppendAllText($ResultFile, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
}

# --- registry and machine state ------------------------------------------------

function Get-HklmValue([string] $subKey, [string] $name, [bool] $raw = $false) {
  foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    try {
      $k = $base.OpenSubKey($subKey)
      if ($null -ne $k) {
        try {
          $opt = $(if ($raw) { [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames } else { [Microsoft.Win32.RegistryValueOptions]::None })
          $v = $k.GetValue($name, $null, $opt)
          if ($null -ne $v) { return $v }
        } finally { $k.Close() }
      }
    } finally { $base.Close() }
  }
  return $null
}

function Get-InstallInfo {
  $ver = Get-HklmValue $UninstallSubKey 'DisplayVersion'
  if ($null -eq $ver) { return $null }
  $loc = Get-HklmValue $UninstallSubKey 'InstallLocation'
  $un = Get-HklmValue $UninstallSubKey 'UninstallString'
  return [pscustomobject]@{
    Version = [string]$ver
    Location = $(if ($null -ne $loc) { ([string]$loc).TrimEnd('\') } else { '' })
    UninstallString = $(if ($null -ne $un) { [string]$un } else { '' })
  }
}

function Get-MachinePath {
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
  try {
    $k = $base.OpenSubKey($EnvSubKey)
    try {
      $raw = $k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      return [pscustomobject]@{ Raw = [string]$raw; Kind = [string]$k.GetValueKind('Path') }
    } finally { $k.Close() }
  } finally { $base.Close() }
}

function Format-PathKey([string] $segment) { return $segment.Trim().Trim('"').TrimEnd('\').ToLowerInvariant() }

function Get-PathEntryCount([string] $raw, [string] $entry) {
  $want = Format-PathKey $entry
  return @($raw.Split(';') | Where-Object { (Format-PathKey $_) -eq $want }).Count
}

# 0 present, 1060 absent, 1072 marked for deletion: locale independent.
function Get-ServiceState {
  & sc.exe qc $ServiceName | Out-Null
  $code = $LASTEXITCODE
  if ($code -eq 0) { return 'present' }
  if ($code -eq 1060) { return 'absent' }
  if ($code -eq 1072) { return 'marked-for-delete' }
  return ('error:' + $code)
}

function Get-NpcapState {
  $v = Get-HklmValue 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst' 'DisplayVersion'
  if ($null -eq $v) { return 'absent' }
  return ('present ' + [string]$v)
}

function Wait-Until([scriptblock] $condition, [int] $seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    if (& $condition) { return $true }
    Start-Sleep -Milliseconds 500
  }
  return [bool](& $condition)
}

function Get-InwireMainProcesses {
  $all = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='Inwire.exe'")
  $ids = @($all | ForEach-Object { $_.ProcessId })
  return @($all | Where-Object { $ids -notcontains $_.ParentProcessId })
}

function Stop-InwireProcesses {
  foreach ($p in @(Get-Process -Name 'Inwire' -ErrorAction SilentlyContinue)) {
    try { $p.Kill() } catch { }
  }
  Wait-Until { @(Get-Process -Name 'Inwire' -ErrorAction SilentlyContinue).Count -eq 0 } 20 | Out-Null
}

# 1 elevated, 0 not, -1 unreadable.
function Get-ProcessElevation([int] $processId) {
  if (-not ('InwireDriveToken' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class InwireDriveToken {
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int cls, out int info, int length, out int returned);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public static int IsElevated(int pid) {
    IntPtr p = OpenProcess(0x1000, false, pid);
    if (p == IntPtr.Zero) return -1;
    IntPtr t;
    if (!OpenProcessToken(p, 0x8, out t)) { CloseHandle(p); return -1; }
    int elevated; int returned;
    bool ok = GetTokenInformation(t, 20, out elevated, 4, out returned);
    CloseHandle(t); CloseHandle(p);
    if (!ok) return -1;
    return elevated != 0 ? 1 : 0;
  }
}
'@
  }
  return [InwireDriveToken]::IsElevated($processId)
}

# --- running things --------------------------------------------------------------

function Get-Tail([string] $path, [int] $n = 6) {
  if (-not (Test-Path -LiteralPath $path)) { return '' }
  return ((@(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue) | Select-Object -Last $n) -join ' | ')
}

# Runs the bootstrap as this normal user (it raises its own UAC prompt).
function Invoke-Bootstrap([bool] $launch = $false, [int] $timeoutMinutes = 40) {
  $out = [System.IO.Path]::GetTempFileName()
  $err = [System.IO.Path]::GetTempFileName()
  try {
    # RemoteSigned, the form docs/distribution.md gives a person on a Restricted
    # machine, never Bypass: PowerShell itself then refuses a bootstrap whose
    # signature is not valid, which is part of what this drive is testing.
    $argString = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $Bootstrap + '"' + $(if ($launch) { ' -Launch' } else { '' })
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $argString `
      -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle
    if (-not $p.WaitForExit($timeoutMinutes * 60000)) {
      return [pscustomobject]@{ ExitCode = -1; TimedOut = $true; Tail = (Get-Tail $out) }
    }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; TimedOut = $false; Tail = ((Get-Tail $out) + ' ' + (Get-Tail $err 2)).Trim() }
  } finally {
    Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue
  }
}

function Start-Elevated([string] $exe, [string[]] $arguments, [int] $timeoutSeconds = 600) {
  $p = Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -PassThru -WindowStyle Hidden
  $null = $p.Handle
  if (-not $p.WaitForExit($timeoutSeconds * 1000)) { return -1 }
  return $p.ExitCode
}

function Split-UninstallString([string] $s) {
  $t = $s.Trim()
  if ($t.StartsWith('"')) {
    $end = $t.IndexOf('"', 1)
    if ($end -gt 0) { return $t.Substring(1, $end - 1) }
  }
  $i = $t.IndexOf(' ')
  if ($i -gt 0) { return $t.Substring(0, $i) }
  return $t
}

function Invoke-SilentUninstall {
  $info = Get-InstallInfo
  if ($null -eq $info) { return $true }
  $exe = Split-UninstallString $info.UninstallString
  if (-not (Test-Path -LiteralPath $exe)) { Note ('uninstaller not found: ' + $exe); return $false }
  Stop-InwireProcesses
  Write-Host '  (click Yes on the UAC prompt for the uninstaller)'
  $code = Start-Elevated $exe @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')
  Note ('uninstaller exit ' + $code)
  # Inno's uninstaller may hand over to a second process; wait for the key to go.
  return (Wait-Until { $null -eq (Get-InstallInfo) } 180)
}

function Assert-Absent {
  if ($null -eq (Get-InstallInfo)) { return }
  Note 'Inwire is installed; removing it first'
  if (-not (Invoke-SilentUninstall)) { throw 'could not bring the machine to the not-installed state' }
}

function Assert-Installed {
  if ($null -ne (Get-InstallInfo)) { return }
  $r = Invoke-Bootstrap $false
  Note ('bootstrap exit ' + $r.ExitCode + ': ' + $r.Tail)
  if ($r.ExitCode -ne 0 -or $null -eq (Get-InstallInfo)) { throw 'could not bring the machine to the installed state' }
}

function Edit-UnrelatedPathEntry([string] $mode) {
  $head = '$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(''SYSTEM\CurrentControlSet\Control\Session Manager\Environment'',$true);$p=[string]$k.GetValue(''Path'','''',''DoNotExpandEnvironmentNames'');'
  if ($mode -eq 'add') {
    $body = 'if(-not (($p -split '';'') -contains ''C:\InwireDriveUnrelated'')){$k.SetValue(''Path'',($p.TrimEnd('';'')+'';C:\InwireDriveUnrelated''),''ExpandString'')};$k.Close()'
  } else {
    $body = '$k.SetValue(''Path'',((($p -split '';'') | Where-Object { $_ -ne ''C:\InwireDriveUnrelated'' }) -join '';''),''ExpandString'');$k.Close()'
  }
  $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($head + $body))
  Write-Host '  (click Yes on the UAC prompt for the PATH edit)'
  $code = Start-Elevated (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) 120
  return ($code -eq 0)
}

# --- scenarios --------------------------------------------------------------------

function Test-InstalledFiles($info) {
  Expect 'uninstall key DisplayVersion present' ($info.Version -ne '') $info.Version
  $app = $info.Location
  Expect 'Inwire.exe exists' (Test-Path -LiteralPath (Join-Path $app 'Inwire.exe')) $app
  Expect 'bin\inwire.exe exists' (Test-Path -LiteralPath (Join-Path $app 'bin\inwire.exe'))
  Expect 'agent\inwire-agent-windows.exe exists' (Test-Path -LiteralPath (Join-Path $app 'agent\inwire-agent-windows.exe'))
  Expect ('service ' + $ServiceName + ' registered') ((Get-ServiceState) -eq 'present') (Get-ServiceState)
}

function Test-PathEntry($info, $before) {
  $entry = $info.Location + '\bin'
  $after = Get-MachinePath
  Expect 'machine PATH value is still REG_EXPAND_SZ' ($after.Kind -eq 'ExpandString') $after.Kind
  Expect 'machine PATH holds our entry exactly once' ((Get-PathEntryCount $after.Raw $entry) -eq 1) ('count ' + (Get-PathEntryCount $after.Raw $entry))
  if ($null -ne $before) {
    $keeps = $after.Raw.StartsWith($before.Raw, [StringComparison]::Ordinal)
    Expect 'every pre-existing PATH entry is byte-identical (prefix kept)' $keeps
    if ($keeps) {
      Expect 'only our entry was appended' ($after.Raw.Substring($before.Raw.Length).Trim(';') -ieq $entry) $after.Raw.Substring($before.Raw.Length)
    }
  }
  $marker = Get-HklmValue 'Software\Inwire' 'LauncherPathEntry'
  Expect 'marker LauncherPathEntry equals the entry' (($null -ne $marker) -and ([string]$marker -ieq $entry)) ([string]$marker)
}

function Scenario-uac-decline {
  Assert-Absent
  $before = Get-MachinePath
  Write-Host ''
  Write-Host 'The bootstrap will now raise a UAC prompt. Click NO.'
  $r = Invoke-Bootstrap $false
  Note ('bootstrap exit ' + $r.ExitCode + ': ' + $r.Tail)
  $answer = Confirm-Manual 'You clicked No on the UAC prompt (it appeared, and you declined it).'
  if ($answer -eq 'skip') { return }
  Expect 'bootstrap exit 2 (cancelled)' ($r.ExitCode -eq 2) ('exit ' + $r.ExitCode)
  Expect 'nothing installed' ($null -eq (Get-InstallInfo))
  Expect 'service not registered' ((Get-ServiceState) -eq 'absent') (Get-ServiceState)
  Expect 'machine PATH unchanged' ((Get-MachinePath).Raw -ceq $before.Raw)
}

function Scenario-fresh-install {
  Assert-Absent
  $before = Get-MachinePath
  Note ('PATH before (raw, ' + $before.Kind + '): ' + $before.Raw)
  $r = Invoke-Bootstrap $false
  Note ('bootstrap output: ' + $r.Tail)
  Expect 'bootstrap exit 0' ($r.ExitCode -eq 0) ('exit ' + $r.ExitCode)
  $info = Get-InstallInfo
  if ($null -eq $info) { Expect 'installed state readable' $false; return }
  Note ('installed ' + $info.Version + ' at ' + $info.Location)
  Test-InstalledFiles $info
  Test-PathEntry $info $before
}

function Scenario-launch {
  Assert-Installed
  Stop-InwireProcesses
  $info = Get-InstallInfo
  $r = Invoke-Bootstrap $true
  Note ('bootstrap -Launch exit ' + $r.ExitCode + ': ' + $r.Tail)
  Expect 'bootstrap -Launch exit 0' ($r.ExitCode -eq 0) ('exit ' + $r.ExitCode)
  $up = Wait-Until { @(Get-Process -Name 'Inwire' -ErrorAction SilentlyContinue).Count -gt 0 } 40
  Expect 'an Inwire.exe process is running' $up
  if ($up) {
    Start-Sleep -Seconds 3
    $unreadable = 0
    foreach ($p in @(Get-Process -Name 'Inwire' -ErrorAction SilentlyContinue)) {
      $e = Get-ProcessElevation $p.Id
      if ($e -eq 1) { Expect ('Inwire.exe pid ' + $p.Id + ' is NOT elevated') $false 'elevated' }
      if ($e -eq -1) { $unreadable++ }
    }
    if ($unreadable -eq 0) { Add-Evidence 'PASS no Inwire.exe process has an elevated token' }
    else {
      Note ($unreadable.ToString() + ' process token(s) unreadable')
      Confirm-Manual 'In Task Manager (Details, add the Elevated column) Inwire.exe shows Elevated = No.' | Out-Null
    }
  }
  if ($null -ne $info) {
    & (Join-Path $info.Location 'bin\inwire.exe')
    Note ('second inwire (absolute path) exit ' + $LASTEXITCODE)
    Start-Sleep -Seconds 5
    $mains = @(Get-InwireMainProcesses).Count
    Expect 'one main Inwire process after the second inwire' ($mains -eq 1) ('main processes ' + $mains)
    Confirm-Manual 'The running Inwire window was brought to the front by the second inwire (minimise it first to be sure).' | Out-Null
  }
  Stop-InwireProcesses
}

function Invoke-FreshShell([string] $argument) {
  $cmd = '$env:Path=[Environment]::GetEnvironmentVariable(''Path'',''Machine'')+'';''+[Environment]::GetEnvironmentVariable(''Path'',''User'');' +
    '$o=(& inwire ' + $argument + ' 2>&1 | Out-String).Trim();Write-Output $o;exit $LASTEXITCODE'
  $text = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -Command $cmd
  return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = (@($text) -join ' ') }
}

function Scenario-command {
  Assert-Installed
  $info = Get-InstallInfo
  $v = Invoke-FreshShell '--version'
  Expect 'fresh shell: inwire --version exit 0' ($v.ExitCode -eq 0) ('exit ' + $v.ExitCode + ' ' + $v.Text)
  Expect 'fresh shell: prints inwire <version>' ($v.Text -match ('^inwire\s+' + [regex]::Escape($info.Version))) $v.Text
  $h = Invoke-FreshShell '--help'
  Expect 'fresh shell: inwire --help exit 0' ($h.ExitCode -eq 0) ('exit ' + $h.ExitCode)
  $b = Invoke-FreshShell '--bogus'
  Expect 'fresh shell: inwire --bogus exit 64' ($b.ExitCode -eq 64) ('exit ' + $b.ExitCode)
  $stale = Get-Command inwire -ErrorAction SilentlyContinue
  Note ('this (stale) process: inwire ' + $(if ($stale) { 'FOUND at ' + $stale.Source + ' (this process already had the new PATH)' } else { 'not found until the environment is refreshed' }))
  Confirm-Manual 'Open an ELEVATED terminal (Run as administrator), type inwire, and check it prints that Inwire does not run as administrator and `echo $LASTEXITCODE` (or %ERRORLEVEL%) shows 77.' | Out-Null
}

function Scenario-custom-path {
  Assert-Absent
  Write-Host ''
  Write-Host 'Run ANY Inwire-Setup.exe by hand (the older one is fine) and, on the folder page, choose:'
  Write-Host '    C:\Inwire Test & co\'
  if ((Confirm-Manual 'Finish the interactive install into C:\Inwire Test & co\ (accept the UAC prompt and the licence).') -ne 'yes') { Assert-Absent; return }
  $info = Get-InstallInfo
  if ($null -eq $info) { Expect 'installed state readable' $false; return }
  Expect 'install location is the chosen folder' ($info.Location -ieq 'C:\Inwire Test & co') $info.Location
  Expect 'launcher is under the chosen folder' (Test-Path -LiteralPath (Join-Path $info.Location 'bin\inwire.exe'))
  $entry = $info.Location + '\bin'
  Expect 'machine PATH holds the custom entry once' ((Get-PathEntryCount (Get-MachinePath).Raw $entry) -eq 1)
  $marker = Get-HklmValue 'Software\Inwire' 'LauncherPathEntry'
  Expect 'marker equals the custom entry' (($null -ne $marker) -and ([string]$marker -ieq $entry)) ([string]$marker)
  $v = Invoke-FreshShell '--version'
  Expect 'fresh shell: inwire --version exit 0 from the custom folder' ($v.ExitCode -eq 0) ('exit ' + $v.ExitCode + ' ' + $v.Text)
  Assert-Absent
}

function Scenario-upgrade-unsaved {
  if (-not $OlderInstaller -or -not (Test-Path -LiteralPath $OlderInstaller -PathType Leaf)) {
    Expect '-OlderInstaller names an existing installer' $false 'pass -OlderInstaller <path> to run this scenario'
    return
  }
  Assert-Absent
  Write-Host '  (click Yes on the UAC prompt for the older installer)'
  $code = Start-Elevated $OlderInstaller @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') 900
  Expect 'older installer exit 0' ($code -eq 0) ('exit ' + $code)
  $old = Get-InstallInfo
  if ($null -eq $old) { Expect 'older version readable' $false; return }
  Note ('older version ' + $old.Version)
  if ((Confirm-Manual 'Open Inwire from the Start menu, and make an UNSAVED capture (start a capture, or import a file). Leave it open.') -ne 'yes') { Stop-InwireProcesses; return }
  Write-Host ''
  Write-Host 'The bootstrap will run now. When Inwire asks about the unsaved capture, CANCEL the close.'
  $r1 = Invoke-Bootstrap $false 15
  Note ('bootstrap (cancel) exit ' + $r1.ExitCode + ' timedOut ' + $r1.TimedOut + ': ' + $r1.Tail)
  $alive = @(Get-Process -Name 'Inwire' -ErrorAction SilentlyContinue).Count -gt 0
  $mid = Get-InstallInfo
  Expect 'Inwire was not force-terminated while the tester cancelled' $alive
  $midVer = $(if ($null -ne $mid) { $mid.Version } else { 'unreadable' })
  Note ('after cancel: version ' + $midVer + ', exit ' + $r1.ExitCode)
  Expect 'a cancelled close is not reported as a finished upgrade' (-not ($r1.ExitCode -eq 0 -and $midVer -ne $old.Version)) ('exit ' + $r1.ExitCode + ' version ' + $midVer)
  if ($r1.TimedOut) { Note 'the bootstrap was still running at the timeout; it was left alone' }
  Write-Host ''
  Write-Host 'Now the bootstrap runs again. This time ACCEPT the close.'
  $r2 = Invoke-Bootstrap $false 20
  Note ('bootstrap (accept) exit ' + $r2.ExitCode + ': ' + $r2.Tail)
  Expect 'accepting the close: bootstrap exit 0' ($r2.ExitCode -eq 0) ('exit ' + $r2.ExitCode)
  $new = Get-InstallInfo
  Expect 'readback version is the new one' (($null -ne $new) -and $new.Version -ne $old.Version) ('old ' + $old.Version + ', now ' + $(if ($null -ne $new) { $new.Version } else { 'unreadable' }))
  Stop-InwireProcesses
}

function Scenario-no-npcap {
  Assert-Absent
  $before = Get-NpcapState
  Note ('Npcap before: ' + $before)
  $r = Invoke-Bootstrap $false
  Note ('bootstrap exit ' + $r.ExitCode + ': ' + $r.Tail)
  Expect 'install succeeds whether or not Npcap is present' ($r.ExitCode -eq 0 -and $null -ne (Get-InstallInfo)) ('exit ' + $r.ExitCode)
  $after = Get-NpcapState
  Expect 'Npcap untouched by the install' ($after -eq $before) ('before ' + $before + ', after ' + $after)
  if ($before -eq 'absent') { Note 'this run had no Npcap; run again on a machine with Npcap for the other half' }
  else { Note 'this run had Npcap; run again without it for the other half' }
}

function Scenario-clean-trust {
  $sig = Get-AuthenticodeSignature -LiteralPath $Bootstrap
  $subject = $(if ($null -ne $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'none' })
  Expect 'bootstrap signature is Valid on this clean machine' ($sig.Status -eq 'Valid') ('status ' + $sig.Status + ', signer ' + $subject)
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('inwire-tampered-' + [guid]::NewGuid().ToString('N') + '.ps1')
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Bootstrap)
    $i = [int]($bytes.Length / 4)
    $bytes[$i] = $bytes[$i] -bxor 1
    [System.IO.File]::WriteAllBytes($tmp, $bytes)
    $bad = Get-AuthenticodeSignature -LiteralPath $tmp
    Expect 'a copy with one byte changed is not Valid' ($bad.Status -ne 'Valid') ('status ' + $bad.Status)
  } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  Confirm-Manual 'Not automated: an installer signed by a DIFFERENT signer is refused (exit 12) before any UAC prompt. The bootstrap tests cover the logic; do it here only if you have such a file.' | Out-Null
}

function Get-UserDataRoot { return (Join-Path $env:LOCALAPPDATA 'Inwire') }

function Get-FileHashText([string] $path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }

function Scenario-uninstall {
  Assert-Installed
  Stop-InwireProcesses
  $info = Get-InstallInfo
  $root = Get-UserDataRoot
  $capDir = Join-Path $root 'captures\drive-dummy'
  $monDir = Join-Path $root 'monitoring\drive-dummy'
  $capFile = Join-Path $capDir 'keep.txt'
  $monFile = Join-Path $monDir 'keep.txt'
  $addedEntry = $false
  try {
    foreach ($d in @($capDir, $monDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    Set-Content -LiteralPath $capFile -Value 'dummy capture' -Encoding ASCII
    Set-Content -LiteralPath $monFile -Value 'dummy monitoring' -Encoding ASCII
    $capHash = Get-FileHashText $capFile
    $monHash = Get-FileHashText $monFile
    $addedEntry = Edit-UnrelatedPathEntry 'add'
    Expect ('unrelated PATH entry added (' + $UnrelatedEntry + ')') $addedEntry
    $npBefore = Get-NpcapState
    $pathBefore = Get-MachinePath
    Expect 'unrelated entry is on PATH before' ((Get-PathEntryCount $pathBefore.Raw $UnrelatedEntry) -eq 1)
    $appDir = $info.Location
    Note ('user data root: ' + $root)

    $ok = Invoke-SilentUninstall
    Expect 'uninstall key gone' $ok
    foreach ($rel in @('Inwire.exe', 'bin\inwire.exe', 'agent\inwire-agent-windows.exe')) {
      Expect ('removed: ' + $rel) (-not (Test-Path -LiteralPath (Join-Path $appDir $rel)))
    }
    Expect 'service gone' ((Get-ServiceState) -ne 'present') (Get-ServiceState)
    Expect 'marker gone' ($null -eq (Get-HklmValue 'Software\Inwire' 'LauncherPathEntry'))
    $pathAfter = Get-MachinePath
    Expect 'our PATH entry gone' ((Get-PathEntryCount $pathAfter.Raw ($appDir + '\bin')) -eq 0)
    Expect 'unrelated PATH entry remains' ((Get-PathEntryCount $pathAfter.Raw $UnrelatedEntry) -eq 1)
    $expected = $pathBefore.Raw.Split(';') | Where-Object { (Format-PathKey $_) -ne (Format-PathKey ($appDir + '\bin')) }
    Expect 'PATH otherwise byte-identical (modulo our segment and a trailing semicolon)' (($pathAfter.Raw.TrimEnd(';')) -ceq (($expected -join ';').TrimEnd(';')))
    Expect 'capture folder remains, unchanged' ((Test-Path -LiteralPath $capFile) -and ((Get-FileHashText $capFile) -eq $capHash))
    Expect 'monitoring folder remains, unchanged' ((Test-Path -LiteralPath $monFile) -and ((Get-FileHashText $monFile) -eq $monHash))
    $npAfter = Get-NpcapState
    Expect 'Npcap untouched' ($npAfter -eq $npBefore) ('before ' + $npBefore + ', after ' + $npAfter)
  } finally {
    if ($addedEntry) { Edit-UnrelatedPathEntry 'remove' | Out-Null }
    Remove-Item -LiteralPath $capDir, $monDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Scenario-reinstall {
  Assert-Absent
  $missing = @(Get-Command node, cargo, pwsh -ErrorAction SilentlyContinue)
  Expect 'no node, cargo or pwsh on this machine (otherwise this run proves nothing about needing them)' ($missing.Count -eq 0) (($missing | ForEach-Object { $_.Name }) -join ', ')
  $r = Invoke-Bootstrap $false
  Note ('bootstrap exit ' + $r.ExitCode + ': ' + $r.Tail)
  Expect 'bootstrap exit 0 after uninstall' ($r.ExitCode -eq 0) ('exit ' + $r.ExitCode)
  $info = Get-InstallInfo
  Expect 'installed state readable' ($null -ne $info)
  if ($null -ne $info) { Test-InstalledFiles $info }
}

# --- run ----------------------------------------------------------------------------

Write-Host ('Inwire clean-machine drive. Result file: ' + $ResultFile)
$counts = @{ PASS = 0; FAIL = 0; MANUAL = 0; SKIPPED = 0 }
foreach ($name in $selected) {
  Write-Host ''
  Write-Host ('=== ' + $name + ' ===')
  $script:Ev = New-Object System.Collections.Generic.List[string]
  $script:Failed = $false
  $script:Declined = $false
  $script:Attested = $false
  try {
    & ('Scenario-' + $name)
  } catch {
    $script:Failed = $true
    Add-Evidence ('FAIL exception: ' + $_.Exception.Message)
  }
  $outcome = 'PASS'
  if ($script:Failed) { $outcome = 'FAIL' }
  elseif ($script:Declined) { $outcome = 'SKIPPED' }
  elseif ($script:Attested) { $outcome = 'MANUAL' }
  $counts[$outcome]++
  Write-Host ('--- ' + $name + ': ' + $outcome)
  try { Write-Result $name $outcome @($script:Ev) } catch { Write-Host ('could not write the result file: ' + $_.Exception.Message) }
}

Write-Host ''
Write-Host ('SUMMARY pass ' + $counts.PASS + ', manual ' + $counts.MANUAL + ', skipped ' + $counts.SKIPPED + ', fail ' + $counts.FAIL)
if ($counts.SKIPPED -gt 0) { Write-Host 'A skipped scenario is not a pass: it was not verified.' }
if ($counts.MANUAL -gt 0) { Write-Host 'A MANUAL scenario passed on the tester''s word for the manual steps.' }
if ($counts.FAIL -gt 0) { exit 1 }
exit 0
