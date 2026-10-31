<#
.SYNOPSIS
  Tests for the `inwire` command: the PATH string functions under the real Inno
  runtime, and the BUILT launcher driven through real shells.

.DESCRIPTION
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\distribution\launcher-tests.ps1

  Needs `npm run build:launcher` first (SKIPs the drive without it) and Inno
  Setup 6 or 7 for the PATH tests (SKIPs without it). Never launches the real
  Electron app and never touches the machine PATH, the registry or any service.

  ## What is driven, and how "does not launch" is checked honestly

  A stand-in `Inwire.exe` is compiled here with the .NET Framework's csc.exe
  (present on every Windows that has PowerShell 5.1): a real GUI-subsystem
  executable whose VERSIONINFO ProductVersion is set from an assembly attribute,
  and which, when it runs, writes `launched.txt` beside itself with its working
  directory and argument count, then sleeps four seconds and exits. A copy of the
  launcher cannot play this part (it has no marker), and a script cannot be read
  for a ProductVersion. Three are built: one that matches the launcher, one that
  matches with the `.0` fourth group, one that does not.

  "Did not start it" is a marker that is absent after a wait that is long enough
  for a started process to have written it; the same marker appearing in the
  positive case is the control that proves the mechanism can see a launch.

  The drive runs in the layout the installer makes,
  `<root>\Inw<i-diaeresis>re & co\bin\inwire.exe` beside
  `<root>\Inw<i-diaeresis>re & co\Inwire.exe`: a space, a non-ASCII letter and an
  ampersand in one path.

  The whole drive runs under Windows PowerShell 5.1 and under pwsh 7 when present,
  each as a child process of this script (`-DriveOnly`). Then, from here: a
  Restricted-policy command line, Git Bash, and the measurements.

  Windows PowerShell 5.1 syntax throughout.
#>
[CmdletBinding()]
param(
  [switch] $DriveOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Launcher = Join-Path $Root 'launcher-rs\dist\inwire.exe'
$Version  = (Get-Content -LiteralPath (Join-Path $Root 'package.json') -Raw | ConvertFrom-Json).version

$script:Passes = 0
$script:Failures = 0
$script:Skips = 0

function Pass([string]$name) { $script:Passes++; Write-Host "PASS  $name" }
function Fail([string]$name, [string]$detail) {
  $script:Failures++
  Write-Host "FAIL  $name"
  if ($detail) { Write-Host "        $detail" }
}
function Skip([string]$name, [string]$why) { $script:Skips++; Write-Host "SKIP  $name ($why)" }
function Check([string]$name, $actual, $expected) {
  if ("$actual" -eq "$expected") { Pass $name } else { Fail $name "expected [$expected], actual [$actual]" }
}
function Check-True([string]$name, [bool]$condition, [string]$detail) {
  if ($condition) { Pass $name } else { Fail $name $detail }
}

# **Windows PowerShell 5.1 reads a BOM-less script as ANSI**, so no non-ASCII
# letter is written in this file: the i-diaeresis is built.
$IDiaeresis = [string][char]0x00EF
$AppFolder = "Inw${IDiaeresis}re & co"

function Find-Iscc {
  if ($env:INWIRE_ISCC -and (Test-Path -LiteralPath $env:INWIRE_ISCC -PathType Leaf)) { return $env:INWIRE_ISCC }
  $candidates = @()
  $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($onPath) { $candidates += $onPath.Source }
  foreach ($base in @((Join-Path $env:LOCALAPPDATA 'Programs'), ${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
    if (-not $base) { continue }
    foreach ($dir in @('Inno Setup 7', 'Inno Setup 6')) { $candidates += Join-Path $base "$dir\ISCC.exe" }
  }
  $found = @($candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
  if ($found.Count -gt 0) { return $found[0] }
  return $null
}

function Test-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- (a) the PATH functions, under Inno itself --------------------------------

function Invoke-PathTests {
  Write-Host "`n--- installer\path.iss, compiled and run by Inno Setup ---`n"
  $iscc = Find-Iscc
  if (-not $iscc) { Skip 'path.iss tests' 'ISCC.exe (Inno Setup 6 or 7) not found; set INWIRE_ISCC'; return }
  $work = Join-Path $env:TEMP ("inwire-path-tests-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  try {
    $script = Join-Path $PSScriptRoot 'path-tests.iss'
    $out = & $iscc /Q "/O$work" $script 2>&1
    if ($LASTEXITCODE -ne 0) { Fail 'path-tests.iss compiles' ($out -join ' '); return }
    $results = Join-Path $work 'results.txt'
    $setup = Join-Path $work 'inwire-path-tests.exe'
    $p = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT', "/RESULTS=$results") -PassThru -Wait
    if (-not (Test-Path -LiteralPath $results)) { Fail 'path-tests.iss produced results' "no results file (exit $($p.ExitCode))"; return }
    $lines = @(Get-Content -LiteralPath $results)
    $summary = $lines | Where-Object { $_ -like 'SUMMARY *' } | Select-Object -First 1
    foreach ($l in $lines) { if ($l -match '^(FAIL|\s+expected|\s+actual)') { Write-Host $l } }
    if ($summary -match 'pass=(\d+) fail=(\d+)') {
      $n = [int]$Matches[1]; $f = [int]$Matches[2]
      if ($f -eq 0 -and $n -gt 0) { $script:Passes++; Write-Host "PASS  path.iss: $n cases ($summary)" }
      else { $script:Failures++; Write-Host "FAIL  path.iss: $summary" }
    } else {
      Fail 'path.iss tests finished' 'no SUMMARY line in the results'
    }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# --- (b) the built launcher ---------------------------------------------------

function Invoke-Exe([string]$Exe, [string]$Arguments, [string]$Cwd, [hashtable]$Env) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = $Arguments
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  $psi.CreateNoWindow = $true
  if ($Cwd) { $psi.WorkingDirectory = $Cwd }
  if ($Env) { foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] } }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = [Diagnostics.Process]::Start($psi)
  # Both streams are read to the end: a launcher that leaked its pipe handles
  # into the app it started would hold these open until the app exited.
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  $sw.Stop()
  return [pscustomobject]@{ Code = $p.ExitCode; Out = $out; Err = $err; Ms = $sw.ElapsedMilliseconds }
}

function Wait-Marker([string]$Path, [int]$Ms) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $Ms) {
    if (Test-Path -LiteralPath $Path) { return $true }
    Start-Sleep -Milliseconds 50
  }
  return (Test-Path -LiteralPath $Path)
}

function New-Fake([string]$Csc, [string]$Dir, [string]$InfoVersion) {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $source = Join-Path $Dir 'fake.cs'
  $code = @"
using System;
using System.IO;
using System.Reflection;
using System.Threading;
[assembly: AssemblyInformationalVersion("$InfoVersion")]
[assembly: AssemblyFileVersion("1.2.3.4")]
class FakeInwire {
  static void Main(string[] args) {
    string here = AppDomain.CurrentDomain.BaseDirectory;
    File.WriteAllText(Path.Combine(here, "launched.txt"),
      "cwd=" + Directory.GetCurrentDirectory() + "|args=" + args.Length);
    Thread.Sleep(4000);
  }
}
"@
  Set-Content -LiteralPath $source -Value $code -Encoding ASCII
  $exe = Join-Path $Dir 'Inwire.exe'
  $log = & $Csc /nologo /target:winexe "/out:$exe" $source 2>&1
  if (-not (Test-Path -LiteralPath $exe)) { throw "csc failed: $($log -join ' ')" }
  return $exe
}

# `<root>\<AppFolder>\bin\inwire.exe`, plus `<AppFolder>\Inwire.exe` from $Desktop.
function New-Layout([string]$Work, [string]$Name, [string]$Desktop) {
  $app = Join-Path (Join-Path $Work $Name) $AppFolder
  $bin = Join-Path $app 'bin'
  New-Item -ItemType Directory -Force -Path $bin | Out-Null
  Copy-Item -LiteralPath $Launcher -Destination (Join-Path $bin 'inwire.exe')
  if ($Desktop) { Copy-Item -LiteralPath $Desktop -Destination (Join-Path $app 'Inwire.exe') }
  return [pscustomobject]@{ App = $app; Launcher = (Join-Path $bin 'inwire.exe'); Marker = (Join-Path $app 'launched.txt') }
}

function Invoke-Drive {
  Write-Host ("`n--- the built launcher, under {0} {1} ---`n" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
  if (-not (Test-Path -LiteralPath $Launcher)) {
    Skip 'launcher drive' 'launcher-rs\dist\inwire.exe is not built; run `npm run build:launcher`'
    return
  }
  $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
  if (-not (Test-Path -LiteralPath $csc)) { Skip 'launcher drive' 'csc.exe (.NET Framework 4) not found'; return }

  $work = Join-Path $env:TEMP ("inwire-launcher-tests-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  try {
    $good  = New-Fake $csc (Join-Path $work 'fakes\good') $Version
    $good4 = New-Fake $csc (Join-Path $work 'fakes\good4') "$Version.0"
    $bad   = New-Fake $csc (Join-Path $work 'fakes\bad') '99.0.0'

    # help / version -----------------------------------------------------------
    $L = New-Layout $work 'a' $good
    $r = Invoke-Exe $L.Launcher '--version' $null $null
    Check '--version exits 0' $r.Code 0
    Check '--version prints "inwire <version>"' $r.Out.Trim() "inwire $Version"
    $r2 = Invoke-Exe $L.Launcher '--help' $null $null
    Check '--help exits 0' $r2.Code 0
    Check-True '--help prints the usage on stdout' ($r2.Out -match '--version' -and $r2.Out -match '--help' -and $r2.Err -eq '') $r2.Out
    Start-Sleep -Milliseconds 900
    Check-True '--help and --version start no process (no marker beside a matching Inwire.exe)' (-not (Test-Path -LiteralPath $L.Marker)) 'launched.txt exists'

    # usage errors -----------------------------------------------------------
    foreach ($bogus in @('--bogus', '-h', '/?', '--help --version', '--version extra', 'extra', '--Help')) {
      $L = New-Layout $work ('u' + [guid]::NewGuid().ToString('N').Substring(0, 6)) $good
      $r = Invoke-Exe $L.Launcher $bogus $null $null
      Check "'$bogus' exits 64" $r.Code 64
      Check-True "'$bogus' prints usage to stderr and nothing to stdout" ($r.Err -match 'usage:' -and $r.Out -eq '') "err=[$($r.Err)]"
      Start-Sleep -Milliseconds 300
      Check-True "'$bogus' starts nothing" (-not (Test-Path -LiteralPath $L.Marker)) 'launched.txt exists'
    }

    # missing payload / wrong layout -----------------------------------------
    $L = New-Layout $work 'missing' $null
    $r = Invoke-Exe $L.Launcher '' $null $null
    Check 'missing Inwire.exe exits 66' $r.Code 66
    Check-True '...and says where it looked' ($r.Err -match 'Inwire\.exe was not found') $r.Err

    # The launcher in `<x>\sub\inwire.exe` with a working Inwire.exe in `<x>`: not a
    # `bin` folder, so it must not guess. (They cannot share a folder: the two
    # names differ only by case, which is one file on NTFS.)
    $nobin = Join-Path $work 'nobin'
    New-Item -ItemType Directory -Force -Path (Join-Path $nobin 'sub') | Out-Null
    Copy-Item -LiteralPath $Launcher -Destination (Join-Path $nobin 'sub\inwire.exe')
    Copy-Item -LiteralPath $good -Destination (Join-Path $nobin 'Inwire.exe')
    $r = Invoke-Exe (Join-Path $nobin 'sub\inwire.exe') '' $null $null
    Check 'a launcher that is not in a bin folder exits 66' $r.Code 66
    Start-Sleep -Milliseconds 500
    Check-True '...and starts nothing' (-not (Test-Path -LiteralPath (Join-Path $nobin 'launched.txt'))) 'launched.txt exists'

    # version mismatch -------------------------------------------------------
    $L = New-Layout $work 'mismatch' $bad
    $r = Invoke-Exe $L.Launcher '' $null $null
    Check 'a different product version exits 65' $r.Code 65
    Check-True '...and names both versions' ($r.Err -match '99\.0\.0' -and $r.Err -match [regex]::Escape($Version)) $r.Err
    Start-Sleep -Milliseconds 600
    Check-True '...and starts nothing' (-not (Test-Path -LiteralPath $L.Marker)) 'launched.txt exists'

    # a malicious Inwire.exe elsewhere is never selected ----------------------
    $evilDir = Join-Path $work 'evil'
    New-Item -ItemType Directory -Force -Path $evilDir | Out-Null
    Copy-Item -LiteralPath $good -Destination (Join-Path $evilDir 'Inwire.exe')
    $evilMarker = Join-Path $evilDir 'launched.txt'

    $L = New-Layout $work 'cwdmissing' $null
    $r = Invoke-Exe $L.Launcher '' $evilDir $null
    Check 'the current directory is not searched: missing payload still exits 66' $r.Code 66
    $oldPath = $env:PATH
    $r = Invoke-Exe $L.Launcher '' $null @{ PATH = "$evilDir;$oldPath" }
    Check 'PATH is not searched: missing payload still exits 66' $r.Code 66
    Start-Sleep -Milliseconds 900
    Check-True '...and the planted Inwire.exe never ran' (-not (Test-Path -LiteralPath $evilMarker)) 'the planted Inwire.exe ran'

    $L = New-Layout $work 'cwdgood' $good
    $r = Invoke-Exe $L.Launcher '' $evilDir @{ PATH = "$evilDir;$oldPath" }
    Check 'with the real Inwire.exe present and a planted one in cwd and PATH, exits 0' $r.Code 0
    $seen = Wait-Marker $L.Marker 5000
    Check-True '...the real one ran' $seen 'no launched.txt beside the real Inwire.exe'
    Start-Sleep -Milliseconds 500
    Check-True '...and the planted one did not' (-not (Test-Path -LiteralPath $evilMarker)) 'the planted Inwire.exe ran'

    # the positive case, and the control for every "starts nothing" above -----
    foreach ($case in @(@('matching version', $good), @('matching version with a .0 fourth group', $good4))) {
      $L = New-Layout $work ('ok' + [guid]::NewGuid().ToString('N').Substring(0, 6)) $case[1]
      $r = Invoke-Exe $L.Launcher '' $null $null
      Check "$($case[0]): exits 0" $r.Code 0
      Check-True "$($case[0]): returns without waiting for the app (took $($r.Ms) ms)" ($r.Ms -lt 2500) "took $($r.Ms) ms"
      $seen = Wait-Marker $L.Marker 5000
      Check-True "$($case[0]): the app started" $seen 'no launched.txt'
      if ($seen) {
        $text = Get-Content -LiteralPath $L.Marker -Raw
        # Compared by tail: $env:TEMP may be spelled as an 8.3 short name here
        # and as the long name in the app's own report of its directory.
        Check-True "$($case[0]): started in its own folder (not bin) with no arguments" `
          ($text.StartsWith('cwd=') -and $text.EndsWith("\$AppFolder|args=0", [StringComparison]::OrdinalIgnoreCase)) $text
      }
    }

    # elevation ---------------------------------------------------------------
    if (Test-Elevated) {
      $L = New-Layout $work 'elevated' $good
      $r = Invoke-Exe $L.Launcher '' $null $null
      Check 'an elevated terminal exits 77' $r.Code 77
      Start-Sleep -Milliseconds 600
      Check-True '...and starts nothing' (-not (Test-Path -LiteralPath $L.Marker)) 'launched.txt exists'
    } else {
      Skip 'elevated terminal exits 77' 'this shell is not elevated; run it from an administrator prompt to cover it'
    }
  } finally {
    Start-Sleep -Milliseconds 300
    # Only the stand-ins under this run's folder: never any other Inwire.exe.
    Get-Process -Name Inwire -ErrorAction SilentlyContinue |
      Where-Object { $_.Path -and $_.Path.StartsWith($work, [StringComparison]::OrdinalIgnoreCase) } |
      ForEach-Object { try { $_.Kill() } catch {} }
    Start-Sleep -Milliseconds 300
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if ($DriveOnly) {
  Invoke-Drive
  Write-Host ("SUMMARY pass={0} fail={1} skip={2}" -f $script:Passes, $script:Failures, $script:Skips)
  if ($script:Failures -gt 0) { exit 1 }
  exit 0
}

# --- the parent: path tests, the shell matrix, the measurements ---------------

Invoke-PathTests

$shells = @()
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path -LiteralPath $ps51) { $shells += ,@('Windows PowerShell 5.1', $ps51) }
$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) { $shells += ,@('PowerShell 7', $pwsh.Source) } else { Skip 'drive under pwsh 7' 'pwsh is not installed' }

foreach ($s in $shells) {
  $name = $s[0]
  $shellExe = $s[1]
  $self = $PSCommandPath
  $output = & $shellExe -NoProfile -ExecutionPolicy Bypass -File $self -DriveOnly 2>&1
  $code = $LASTEXITCODE
  foreach ($line in $output) { Write-Host "$line" }
  $sum = ($output | ForEach-Object { "$_" } | Where-Object { $_ -like 'SUMMARY *' } | Select-Object -Last 1)
  if ($code -eq 0 -and $sum) {
    $script:Passes++
    Write-Host "PASS  drive under ${name}: $sum"
  } else {
    $script:Failures++
    Write-Host "FAIL  drive under ${name} (exit $code)"
  }
}

Write-Host "`n--- other ways to start it ---`n"
if (-not (Test-Path -LiteralPath $Launcher)) {
  Skip 'Restricted policy, Git Bash and measurements' 'launcher-rs\dist\inwire.exe is not built'
} else {
  $work = Join-Path $env:TEMP ("inwire-launcher-shells-" + [guid]::NewGuid().ToString('N'))
  $app = Join-Path (Join-Path $work 'x') $AppFolder
  $bin = Join-Path $app 'bin'
  New-Item -ItemType Directory -Force -Path $bin | Out-Null
  Copy-Item -LiteralPath $Launcher -Destination (Join-Path $bin 'inwire.exe')
  $exe = Join-Path $bin 'inwire.exe'
  try {
    # An exe is not a script: a Restricted execution policy has nothing to refuse.
    $restricted = & $ps51 -NoProfile -ExecutionPolicy Restricted -Command "& '$($exe.Replace("'", "''"))' --version" 2>&1
    Check 'under -ExecutionPolicy Restricted, --version still prints' ("$restricted").Trim() "inwire $Version"

    $bash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    if (Test-Path -LiteralPath $bash) {
      $sh = Join-Path $work 'drive.sh'
      $posix = $exe.Replace('\', '/')
      $body = "exe=`"$posix`"`n`"`$exe`" --version`necho `"exit=`$?`"`n`"`$exe`" --nope 2>/dev/null`necho `"exit=`$?`"`n"
      [IO.File]::WriteAllText($sh, $body, (New-Object Text.UTF8Encoding($false)))
      $bashOut = (& $bash $sh 2>&1) -join '|'
      Check 'from Git Bash, --version prints and exits 0; a bad argument exits 64' $bashOut "inwire $Version|exit=0|exit=64"
      Write-Host ("INFO  Git Bash: " + ((& $bash --version | Select-Object -First 1)))
    } else {
      Skip 'Git Bash' "$bash not found"
    }

    # The measurements are printed, never asserted.
    Write-Host "`n--- measurements (printed, not asserted) ---`n"
    Write-Host ("MEASURE  launcher size: {0:N0} bytes" -f (Get-Item -LiteralPath $Launcher).Length)
    $shim = Join-Path $work 'inwire.cmd'
    Set-Content -LiteralPath $shim -Value "@echo inwire $Version" -Encoding ASCII
    $time = {
      param($file, $args2)
      $samples = New-Object System.Collections.Generic.List[double]
      for ($i = 0; $i -lt 22; $i++) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $file
        $psi.Arguments = $args2
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.CreateNoWindow = $true
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $p = [Diagnostics.Process]::Start($psi)
        [void]$p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        $sw.Stop()
        if ($i -ge 2) { $samples.Add($sw.Elapsed.TotalMilliseconds) }  # two warm-ups dropped
      }
      $sorted = $samples | Sort-Object
      return $sorted[[int][math]::Floor($sorted.Count / 2)]
    }
    $exeMs = & $time $exe '--version'
    $cmdMs = & $time (Join-Path $env:SystemRoot 'System32\cmd.exe') "/c `"$shim`""
    Write-Host ("MEASURE  median of 20: inwire --version = {0:N1} ms; cmd /c inwire.cmd (a one-line shim) = {1:N1} ms" -f $exeMs, $cmdMs)

    # Why not a script shim: what a caller that does not go through a shell sees.
    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) {
      $nodeDir = Join-Path $work 'nodeprobe'
      New-Item -ItemType Directory -Force -Path $nodeDir | Out-Null
      Copy-Item -LiteralPath $shim -Destination (Join-Path $nodeDir 'inwire.cmd')
      Copy-Item -LiteralPath $exe -Destination (Join-Path $nodeDir 'inwire.exe')
      $probe = "const {spawnSync}=require('child_process');const r=spawnSync(process.argv[1],['--version'],{encoding:'utf8'});console.log(r.error?r.error.code:String(r.stdout).trim());"
      $savedPath = $env:PATH
      try {
        $env:PATH = "$nodeDir;$savedPath"
        Remove-Item -LiteralPath (Join-Path $nodeDir 'inwire.exe')
        $viaShim = (& $node.Source -e $probe 'inwire' 2>&1) -join ' '
        Copy-Item -LiteralPath $exe -Destination (Join-Path $nodeDir 'inwire.exe')
        Remove-Item -LiteralPath (Join-Path $nodeDir 'inwire.cmd')
        $viaExe = (& $node.Source -e $probe 'inwire' 2>&1) -join ' '
      } finally {
        $env:PATH = $savedPath
      }
      Write-Host "MEASURE  node spawnSync('inwire') with no shell, shim only on PATH: $viaShim; exe only on PATH: $viaExe"
    }
    $ps1 = Join-Path $work 'inwire.ps1'
    Set-Content -LiteralPath $ps1 -Value "'inwire $Version'" -Encoding ASCII
    $ErrorActionPreference = 'Continue'   # the refusal arrives on stderr
    $viaPs1 = & $ps51 -NoProfile -ExecutionPolicy Restricted -Command "& '$($ps1.Replace("'", "''"))'" 2>&1
    $ErrorActionPreference = 'Stop'
    $oneLine = ((@($viaPs1) | ForEach-Object { "$_" }) -join ' ') -replace '\s+', ' '
    Write-Host ("MEASURE  a .ps1 shim under -ExecutionPolicy Restricted: " + $oneLine.Substring(0, [math]::Min(130, $oneLine.Length)))
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host ("`nTOTAL pass={0} fail={1} skip={2}" -f $script:Passes, $script:Failures, $script:Skips)
if ($script:Failures -gt 0) { exit 1 }
exit 0
