<#
.SYNOPSIS
  Deterministic tests for the PowerShell bootstrap (distribution/Install-Inwire.Core.psm1).

.DESCRIPTION
  Runs under Windows PowerShell 5.1 and PowerShell 7:

    powershell -NoProfile -File scripts/distribution/bootstrap-tests.ps1
    pwsh -NoProfile -File scripts/distribution/bootstrap-tests.ps1

  Nothing here installs anything, elevates, or touches the network: the state
  machine runs against a recording fake platform, the downloader against a fake
  Send that serves MemoryStreams, and the signature check against an in-memory
  certificate. The one place a real certificate store is read is the bundle
  section, which signs a throwaway copy with this PC's code-signing certificate
  when there is one (and prints SKIP when there is not).

  Prints PASS/FAIL lines and exits non-zero on any failure. Source is ASCII
  only on purpose: Windows PowerShell reads a BOM-less file as ANSI.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$script:Failures = 0
$script:Passes = 0
$script:Skips = 0

function Test-That {
  param([string]$Name, $Ok, [string]$Detail = '')
  if ($Ok -eq $true) {
    $script:Passes++
    Write-Host ("PASS  " + $Name)
  } else {
    $script:Failures++
    if ($Detail) { Write-Host ("FAIL  " + $Name + "  (" + $Detail + ")") } else { Write-Host ("FAIL  " + $Name) }
  }
}

function Skip-That {
  param([string]$Name, [string]$Why)
  $script:Skips++
  Write-Host ("SKIP  " + $Name + "  (" + $Why + ")")
}

# One section's exception must not hide the others.
function Invoke-Section {
  param([string]$Name, [scriptblock]$Body)
  try { & $Body } catch {
    $script:Failures++
    Write-Host ("FAIL  section '" + $Name + "' threw: " + $_.Exception.Message + " at line " + $_.InvocationInfo.ScriptLineNumber)
  }
}

# Windows PowerShell started under a PowerShell 7 PSModulePath cannot autoload
# its own security module (scripts/sign/sign.ps1 records the trap).
try { Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop } catch { }

$modulePath = Join-Path $repo 'distribution\Install-Inwire.Core.psm1'
try {
  Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
} catch {
  Write-Host ("FAIL  the core module imports  (" + $_.Exception.Message + ")")
  Write-Host ("0 passed, 1 failed")
  exit 1
}

function Read-JsonFile {
  param([string]$Relative)
  return ,(ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo $Relative) -Raw))
}

$script:TestPolicy = Read-InwirePolicy (Read-JsonFile 'distribution\fixtures\test-policy.json')
$script:Sha = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$script:DefaultBody = '{"schema":1,"artifacts":[{"product":"Desktop","version":"1.2.3","architecture":"x64","url":"https://download.example.invalid/Inwire-1.2.3-x64.exe","sizeBytes":1048576,"sha256":"' + $script:Sha + '"}]}'
$script:Weird = 'C:\Prog Files\In&wire;$(x)' + [string][char]96 + 'bt ' + [string][char]0x00E9 + [string][char]0x4E2D

# --------------------------------------------------------------------------
# The fake platform: every callback records its name, and the answers are data.
# --------------------------------------------------------------------------
function New-World {
  param([hashtable]$Cfg = @{})
  $w = @{
    Calls = (New-Object 'System.Collections.Generic.List[string]')
    InstalledCalls = 0
    DownloadCalls = 0
    LastDownload = $null
    LastRun = $null
    LastLaunch = $null
    Removed = $null
    ReleaseUrl = $null
  }
  $c = @{
    OS = 'Windows'
    Arch = 'x64'
    Elevated = $false
    Installed = @{ State = 'Absent'; Version = ''; InstallPath = ''; Detail = '' }
    InstalledAfter = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' }
    Body = $script:DefaultBody
    Downloads = @(@{ Ok = $true; Reason = ''; Transient = $false; Integrity = $false })
    Verify = @{ Ok = $true; Reason = '' }
    Run = @{ Started = $true; ExitCode = 0; Declined = $false; TimedOut = $false; Reason = '' }
    Launch = @{ Ok = $true; ExitCode = 0; Reason = '' }
    ThrowRelease = $false
  }
  foreach ($k in @($Cfg.Keys)) { $c[$k] = $Cfg[$k] }
  $w.Cfg = $c
  $p = @{}
  $p.GetPlatform = { $w.Calls.Add('GetPlatform'); @{ OS = $c.OS; Architecture = $c.Arch } }.GetNewClosure()
  $p.IsElevated = { $w.Calls.Add('IsElevated'); [bool]$c.Elevated }.GetNewClosure()
  $p.GetInstalled = {
    param($product)
    $w.Calls.Add('GetInstalled'); $w.InstalledCalls++
    if ($w.InstalledCalls -eq 1) { $c.Installed } else { $c.InstalledAfter }
  }.GetNewClosure()
  $p.GetRelease = {
    param($url)
    $w.Calls.Add('GetRelease'); $w.ReleaseUrl = $url
    if ($c.ThrowRelease) { throw 'offline' }
    $c.Body
  }.GetNewClosure()
  $p.NewWorkDir = { $w.Calls.Add('NewWorkDir'); 'C:\fake\work' }.GetNewClosure()
  $p.RemoveWorkDir = { param($d) $w.Calls.Add('RemoveWorkDir'); $w.Removed = $d }.GetNewClosure()
  $p.Download = {
    param($url, $dest, $size, $sha)
    $w.Calls.Add('Download')
    $w.LastDownload = @{ Url = $url; Dest = $dest; Size = $size; Sha = $sha }
    $i = [Math]::Min($w.DownloadCalls, @($c.Downloads).Count - 1)
    $w.DownloadCalls++
    @($c.Downloads)[$i]
  }.GetNewClosure()
  $p.VerifyPublisher = { param($path, $pins) $w.Calls.Add('VerifyPublisher'); $c.Verify }.GetNewClosure()
  $p.RunInstaller = {
    param($path, $log, $elevated)
    $w.Calls.Add('RunInstaller')
    $w.LastRun = @{ Path = $path; Log = $log; Elevated = $elevated }
    $c.Run
  }.GetNewClosure()
  $p.LaunchDesktop = { param($path) $w.Calls.Add('LaunchDesktop'); $w.LastLaunch = $path; $c.Launch }.GetNewClosure()
  $w.Platform = $p
  return $w
}

function Invoke-World {
  param($World, [string]$Product = 'Desktop', $Version = $null, [switch]$Launch, [switch]$Repair, $Policy = $null)
  if ($null -eq $Policy) { $Policy = $script:TestPolicy }
  return (Invoke-InwireInstall -Product $Product -Version $Version -Launch:$Launch -Repair:$Repair -Policy $Policy -Platform $World.Platform)
}

function Get-Calls { param($World) return ($World.Calls -join ',') }

# ==========================================================================
Invoke-Section 'vectors' {
  $vec = Read-JsonFile 'distribution\fixtures\release-vectors.json'
  $policy = Read-InwirePolicy (Read-JsonFile ('distribution\fixtures\' + $vec.policy))
  Test-That 'the fixture policy is accepted' ($null -ne $policy)
  $bad = 0; $n = 0
  foreach ($v in $vec.vectors) {
    $n++
    $r = Read-InwireRelease $v.descriptor $policy
    $accepted = ($null -ne $r)
    $ok = ($accepted -eq [bool]$v.valid)
    if (-not $ok) { $bad++; Test-That ('vector: ' + $v.name) $false ('expected valid=' + $v.valid) }
  }
  Test-That ('all ' + $n + ' release vectors agree with the TypeScript validator') ($bad -eq 0) ($bad.ToString() + ' disagree')

  $upper = $vec.vectors | Where-Object { $_.name -like 'valid: uppercase sha256*' } | Select-Object -First 1
  $r = Read-InwireRelease $upper.descriptor $policy
  Test-That 'an uppercase sha256 is normalised to lowercase' ($null -ne $r -and $r.Artifacts[0].Sha256 -ceq $script:Sha)

  # Policy validator
  $p0 = Read-JsonFile 'distribution\fixtures\test-policy.json'
  Test-That 'policy: the production policy parses' ($null -ne (Read-InwirePolicy (Read-JsonFile 'distribution\release-policy.json')))
  Test-That 'policy: null is refused' ($null -eq (Read-InwirePolicy $null))
  Test-That 'policy: an array is refused' ($null -eq (Read-InwirePolicy @(1, 2)))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m.allowedHosts = @('Download.Example.Invalid')
  Test-That 'policy: an uppercase host is refused' ($null -eq (Read-InwirePolicy $m))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m.publisherCertificateSha256 = @('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')
  Test-That 'policy: an uppercase pin is refused' ($null -eq (Read-InwirePolicy $m))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m.descriptorUrl = 'https://other.example.invalid/release.json'
  Test-That 'policy: a descriptor URL off the allowlist is refused' ($null -eq (Read-InwirePolicy $m))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m.endpointAvailable = 'false'
  Test-That 'policy: endpointAvailable must be a boolean' ($null -eq (Read-InwirePolicy $m))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m | Add-Member -NotePropertyName extra -NotePropertyValue 1
  Test-That 'policy: an unknown key is refused' ($null -eq (Read-InwirePolicy $m))
  $m = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $repo 'distribution\fixtures\test-policy.json') -Raw)
  $m.schema = '1'
  Test-That 'policy: schema must be the number 1' ($null -eq (Read-InwirePolicy $m))
}

Invoke-Section 'versions' {
  Test-That 'version: 1.10.0 is newer than 1.9.0 (numeric, not text)' ((Compare-InwireVersion '1.10.0' '1.9.0') -eq 1)
  Test-That 'version: 1.9.0 is older than 1.10.0' ((Compare-InwireVersion '1.9.0' '1.10.0') -eq -1)
  Test-That 'version: equal' ((Compare-InwireVersion '0.5.0' '0.5.0') -eq 0)
  Test-That 'version: 2.0.0 beats 1.99999.99999' ((Compare-InwireVersion '2.0.0' '1.99999.99999') -eq 1)
  Test-That 'version: select returns the published row' ($null -ne (Select-InwireArtifact (Read-InwireRelease (ConvertFrom-Json -InputObject $script:DefaultBody) $script:TestPolicy) 'Desktop' $null))
  $rel = Read-InwireRelease (ConvertFrom-Json -InputObject $script:DefaultBody) $script:TestPolicy
  Test-That 'version: select with the published version' ($null -ne (Select-InwireArtifact $rel 'Desktop' '1.2.3'))
  Test-That 'version: select with another version is null' ($null -eq (Select-InwireArtifact $rel 'Desktop' '1.2.4'))
  Test-That 'version: select for a product without a row is null' ($null -eq (Select-InwireArtifact $rel 'EndpointAgent' $null))
}

# ==========================================================================
Invoke-Section 'happy path' {
  $w = New-World
  $r = Invoke-World $w
  Test-That 'happy: Installed, exit 0' ($r.State -eq 'Installed' -and $r.ExitCode -eq 0) ($r.State + '/' + $r.ExitCode + ' ' + $r.Message)
  Test-That 'happy: call order' ((Get-Calls $w) -ceq 'GetPlatform,GetInstalled,GetRelease,NewWorkDir,Download,VerifyPublisher,IsElevated,RunInstaller,GetInstalled,RemoveWorkDir') (Get-Calls $w)
  Test-That 'happy: the descriptor is fetched from the policy URL' ($w.ReleaseUrl -ceq $script:TestPolicy.DescriptorUrl)
  Test-That 'happy: the download is the descriptor row, to the fixed name' ($w.LastDownload.Url -ceq 'https://download.example.invalid/Inwire-1.2.3-x64.exe' -and $w.LastDownload.Dest -ceq 'C:\fake\work\Inwire-Setup.exe' -and $w.LastDownload.Size -eq 1048576 -and $w.LastDownload.Sha -ceq $script:Sha)
  Test-That 'happy: setup runs from that file with the fixed log name, not elevated yet' ($w.LastRun.Path -ceq 'C:\fake\work\Inwire-Setup.exe' -and $w.LastRun.Log -ceq 'C:\fake\work\setup.log' -and $w.LastRun.Elevated -eq $false)
  Test-That 'happy: the work folder is removed' ($w.Removed -ceq 'C:\fake\work')
  Test-That 'happy: the result carries the install path and version' ($r.InstalledVersion -ceq '1.2.3' -and $r.InstallPath -ceq 'C:\Program Files\Inwire\')
  Test-That 'happy: no launch was asked for' ($r.Launched -eq $false -and $r.ErrorCode -ceq '')
  $names = @($r.PSObject.Properties | ForEach-Object { $_.Name })
  $want = @('State', 'InstallPath', 'InstalledVersion', 'Launched', 'LaunchMessage', 'ErrorCode', 'Message', 'ExitCode', 'DiagnosticPath')
  Test-That 'happy: the result has the documented fields' ((@($want | Where-Object { $names -notcontains $_ })).Count -eq 0)

  $w = New-World @{ Elevated = $true }
  $r = Invoke-World $w
  Test-That 'happy: an elevated shell passes elevated=true to RunInstaller' ($w.LastRun.Elevated -eq $true -and $r.ExitCode -eq 0)

  $w = New-World
  $r = Invoke-World $w -Launch
  Test-That 'launch: success, exit 0, Launched' ($r.State -eq 'Installed' -and $r.ExitCode -eq 0 -and $r.Launched -eq $true) ($r.Message + ' / ' + $r.LaunchMessage)
  Test-That 'launch: call order' ((Get-Calls $w) -ceq 'GetPlatform,GetInstalled,GetRelease,NewWorkDir,Download,VerifyPublisher,IsElevated,RunInstaller,GetInstalled,LaunchDesktop,RemoveWorkDir') (Get-Calls $w)
  Test-That 'launch: the launcher is the absolute bin\inwire.exe under the registry location' ($w.LastLaunch -ceq 'C:\Program Files\Inwire\bin\inwire.exe') ([string]$w.LastLaunch)

  $w = New-World @{ Launch = @{ Ok = $false; ExitCode = 1; Reason = 'nope' } }
  $r = Invoke-World $w -Launch
  Test-That 'launch: failure is exit 14 and the install is still reported' ($r.ExitCode -eq 14 -and $r.State -eq 'Installed' -and $r.Launched -eq $false -and $r.LaunchMessage -ne '')

  $w = New-World @{ Elevated = $true }
  $r = Invoke-World $w -Launch
  Test-That 'launch: elevated shell installs, exit 14, never launches' ($r.State -eq 'Installed' -and $r.ExitCode -eq 14 -and $r.Launched -eq $false -and (Get-Calls $w) -notmatch 'LaunchDesktop') (Get-Calls $w)
  Test-That 'launch: elevated message names the inwire command' ($r.LaunchMessage -ceq 'this PowerShell is elevated; Inwire does not start elevated - run `inwire` from a normal terminal') $r.LaunchMessage

  $w = New-World @{ InstalledAfter = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = $script:Weird; Detail = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'launch: a path with spaces, &, ;, $(), a backtick and Unicode is passed as one string' ($w.LastLaunch -ceq ($script:Weird + '\bin\inwire.exe')) ([string]$w.LastLaunch)

  $w = New-World @{ InstalledAfter = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = ''; Detail = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'launch: no install location means no launch and exit 14' ($r.ExitCode -eq 14 -and (Get-Calls $w) -notmatch 'LaunchDesktop')

  $w = New-World @{ InstalledAfter = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = 'bin'; Detail = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'launch: a relative install location is never launched from' ($r.ExitCode -eq 14 -and (Get-Calls $w) -notmatch 'LaunchDesktop')
}

Invoke-Section 'refusals before any download' {
  $w = New-World
  $r = Invoke-World $w -Product EndpointAgent
  Test-That 'endpoint: unavailable, exit 20' ($r.State -eq 'Unavailable' -and $r.ExitCode -eq 20) ($r.State + '/' + $r.ExitCode)
  Test-That 'endpoint: nothing but GetPlatform was called' ((Get-Calls $w) -ceq 'GetPlatform') (Get-Calls $w)

  $noPins = Read-InwirePolicy (Read-JsonFile 'distribution\release-policy.json')
  $w = New-World
  $r = Invoke-World $w -Policy $noPins
  Test-That 'no pins: exit 10 before any download' ($r.ExitCode -eq 10 -and (Get-Calls $w) -ceq 'GetPlatform') ((Get-Calls $w) + ' ' + $r.ExitCode)
  Test-That 'no pins: the message says why' ($r.Message -match 'pins no publisher certificate') $r.Message

  $w = New-World @{ Arch = 'arm64' }
  $r = Invoke-World $w
  Test-That 'arm64: refused, exit 10' ($r.ExitCode -eq 10 -and (Get-Calls $w) -ceq 'GetPlatform')
  Test-That 'arm64: the message says emulation is untested' ($r.Message -match 'emulation') $r.Message
  $w = New-World @{ Arch = 'x86' }
  $r = Invoke-World $w
  Test-That 'x86: refused, exit 10' ($r.ExitCode -eq 10)
  $w = New-World @{ OS = 'Linux' }
  $r = Invoke-World $w
  Test-That 'not Windows: refused, exit 10' ($r.ExitCode -eq 10 -and (Get-Calls $w) -ceq 'GetPlatform')

  $w = New-World
  $r = Invoke-World $w -Version '1.2'
  Test-That 'a malformed -Version is exit 10 before any lookup' ($r.ExitCode -eq 10 -and (Get-Calls $w) -ceq 'GetPlatform')
  $w = New-World
  $r = Invoke-World $w -Version '01.2.3'
  Test-That 'a leading-zero -Version is exit 10' ($r.ExitCode -eq 10)
  $w = New-World
  $r = Invoke-World $w -Version '1.2.3-beta'
  Test-That 'a suffixed -Version is exit 10' ($r.ExitCode -eq 10)
}

Invoke-Section 'metadata' {
  $w = New-World @{ ThrowRelease = $true }
  $r = Invoke-World $w
  Test-That 'metadata: a fetch failure is exit 11 and nothing is downloaded' ($r.ExitCode -eq 11 -and (Get-Calls $w) -notmatch 'NewWorkDir|Download') (Get-Calls $w)
  foreach ($body in @('', 'not json', '[1]', '{"schema":2,"artifacts":[]}', ('[' + $script:DefaultBody + ']'))) {
    $w = New-World @{ Body = $body }
    $r = Invoke-World $w
    Test-That ('metadata: a bad descriptor is exit 11 (' + $body.Substring(0, [Math]::Min(18, $body.Length)) + ')') ($r.ExitCode -eq 11 -and (Get-Calls $w) -notmatch 'NewWorkDir')
  }
  $w = New-World
  $r = Invoke-World $w -Version '1.2.4'
  Test-That 'metadata: an unpublished -Version is exit 11 naming the published one' ($r.ExitCode -eq 11 -and $r.Message -match '1\.2\.3') $r.Message
  $w = New-World
  $r = Invoke-World $w -Version '1.2.3'
  Test-That 'metadata: the published -Version installs' ($r.ExitCode -eq 0 -and $r.State -eq 'Installed')
}

Invoke-Section 'installed state' {
  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'same version: AlreadyInstalled, exit 0, no download' ($r.State -eq 'AlreadyInstalled' -and $r.ExitCode -eq 0 -and (Get-Calls $w) -notmatch 'Download|RunInstaller|NewWorkDir') (Get-Calls $w)
  Test-That 'same version: the result names the installed version' ($r.InstalledVersion -ceq '1.2.3')

  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '1.2.3'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w -Repair
  Test-That 'same version with -Repair: installs again' ($r.State -eq 'Installed' -and (Get-Calls $w) -match 'Download.*RunInstaller')

  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '1.10.0'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'newer installed, no -Version: AlreadyInstalled, exit 0, no download' ($r.State -eq 'AlreadyInstalled' -and $r.ExitCode -eq 0 -and (Get-Calls $w) -notmatch 'Download') (Get-Calls $w)
  Test-That 'newer installed: the message says a newer version is installed' ($r.Message -match 'newer') $r.Message

  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '1.10.0'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' }
    Body = $script:DefaultBody.Replace('1.2.3', '1.9.0').Replace('1.2.3', '1.9.0') }
  $r = Invoke-World $w -Version '1.9.0'
  Test-That 'newer installed (1.10.0 over 1.9.0) with an explicit older -Version: refused, exit 10' ($r.ExitCode -eq 10 -and $r.Message -match 'downgrade' -and (Get-Calls $w) -notmatch 'Download') ($r.Message + ' ' + (Get-Calls $w))

  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '1.1.0'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'older installed: upgrades' ($r.State -eq 'Installed' -and (Get-Calls $w) -match 'RunInstaller')

  $w = New-World @{ Installed = @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = 'unreadable' } }
  $r = Invoke-World $w
  Test-That 'unknown installed state without -Repair: exit 13 telling the user to pass -Repair' ($r.ExitCode -eq 13 -and $r.Message -match '-Repair' -and (Get-Calls $w) -notmatch 'GetRelease') $r.Message
  $w = New-World @{ Installed = @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = 'unreadable' } }
  $r = Invoke-World $w -Repair
  Test-That 'unknown installed state with -Repair: proceeds' ($r.State -eq 'Installed' -and $r.ExitCode -eq 0)
  $w = New-World @{ Installed = @{ State = 'Installed'; Version = 'banana'; InstallPath = 'C:\x'; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'an unparseable installed version is treated as unknown' ($r.ExitCode -eq 13)

  $w = New-World @{ Installed = @{ State = 'Installed'; Version = '9.0.0'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'AlreadyInstalled with -Launch launches the installed copy' ($r.State -eq 'AlreadyInstalled' -and $r.Launched -eq $true -and $w.LastLaunch -ceq 'C:\Program Files\Inwire\bin\inwire.exe')
}

Invoke-Section 'download and verification' {
  $bad = @(
    @{ Name = 'bad hash'; D = @{ Ok = $false; Reason = 'The download does not match the published SHA-256.'; Transient = $false; Integrity = $true } },
    @{ Name = 'bad size'; D = @{ Ok = $false; Reason = 'The download is not the published size.'; Transient = $false; Integrity = $true } }
  )
  foreach ($b in $bad) {
    $w = New-World @{ Downloads = @($b.D) }
    $r = Invoke-World $w
    Test-That ('download: ' + $b.Name + ' is exit 12 and setup never runs') ($r.ExitCode -eq 12 -and $r.State -eq 'Failed' -and (Get-Calls $w) -notmatch 'RunInstaller|VerifyPublisher') (Get-Calls $w)
    Test-That ('download: ' + $b.Name + ' removes the untrusted file') ($w.Removed -ceq 'C:\fake\work' -and [string]::IsNullOrEmpty($r.DiagnosticPath))
  }

  foreach ($status in @('NotSigned', 'HashMismatch', 'UnknownError', 'wrong publisher', 'valid but a different pin')) {
    $w = New-World @{ Verify = @{ Ok = $false; Reason = $status; } }
    $r = Invoke-World $w
    Test-That ('verify: ' + $status + ' is exit 12 and setup never runs') ($r.ExitCode -eq 12 -and (Get-Calls $w) -notmatch 'RunInstaller|IsElevated') (Get-Calls $w)
  }

  $w = New-World @{ Downloads = @(@{ Ok = $false; Reason = 'offline'; Transient = $true; Integrity = $false }) }
  $r = Invoke-World $w
  Test-That 'network: a transient fault is retried twice, then exit 11' ($r.ExitCode -eq 11 -and $w.DownloadCalls -eq 3) ('attempts ' + $w.DownloadCalls)
  Test-That 'network: no install after the retries' ((Get-Calls $w) -notmatch 'VerifyPublisher|RunInstaller')

  $w = New-World @{ Downloads = @(@{ Ok = $false; Reason = '404'; Transient = $false; Integrity = $false }) }
  $r = Invoke-World $w
  Test-That 'network: a non-transient fault is not retried' ($r.ExitCode -eq 11 -and $w.DownloadCalls -eq 1)

  $w = New-World @{ Downloads = @(@{ Ok = $false; Reason = 'offline'; Transient = $true; Integrity = $false }, @{ Ok = $true; Reason = ''; Transient = $false; Integrity = $false }) }
  $r = Invoke-World $w
  Test-That 'network: one transient fault, then success, installs' ($r.ExitCode -eq 0 -and $w.DownloadCalls -eq 2)

  $w = New-World @{ Downloads = @(@{ Ok = $false; Reason = 'mismatch'; Transient = $true; Integrity = $true }) }
  $r = Invoke-World $w
  Test-That 'a size/hash mismatch is never retried even if flagged transient' ($r.ExitCode -eq 12 -and $w.DownloadCalls -eq 1)
}

Invoke-Section 'installer outcomes' {
  $w = New-World @{ Run = @{ Started = $false; ExitCode = $null; Declined = $true; TimedOut = $false; Reason = 'declined' } }
  $r = Invoke-World $w
  Test-That 'UAC declined: Cancelled, exit 2, a UAC message' ($r.State -eq 'Cancelled' -and $r.ExitCode -eq 2 -and $r.Message -match 'administrator|UAC|permission') $r.Message
  Test-That 'UAC declined: no readback, no launch' ((Get-Calls $w) -notmatch 'GetInstalled,GetInstalled|LaunchDesktop')

  foreach ($code in 2, 5) {
    $w = New-World @{ Run = @{ Started = $true; ExitCode = $code; Declined = $false; TimedOut = $false; Reason = '' } }
    $r = Invoke-World $w
    Test-That ('installer code ' + $code + ' is Cancelled, exit 2') ($r.State -eq 'Cancelled' -and $r.ExitCode -eq 2 -and $r.ErrorCode -ceq [string]$code)
  }
  $w = New-World @{ Run = @{ Started = $true; ExitCode = 3010; Declined = $false; TimedOut = $false; Reason = '' } }
  $r = Invoke-World $w -Launch
  Test-That '3010: RebootRequired, exit 3010, no launch' ($r.State -eq 'RebootRequired' -and $r.ExitCode -eq 3010 -and (Get-Calls $w) -notmatch 'LaunchDesktop' -and $r.Launched -eq $false) (Get-Calls $w)
  Test-That '3010: the launch message says to restart first' ($r.LaunchMessage -match 'restart')
  Test-That '3010: reads the version back first' ((Get-Calls $w) -match 'RunInstaller,GetInstalled')

  $w = New-World @{ Run = @{ Started = $true; ExitCode = 8; Declined = $false; TimedOut = $false; Reason = '' } }
  $r = Invoke-World $w
  Test-That 'installer code 8 (restart needed before it can proceed): Failed, exit 13' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13 -and $r.ErrorCode -ceq '8' -and $r.Message -match 'restart')
  $w = New-World @{ Run = @{ Started = $true; ExitCode = 1; Declined = $false; TimedOut = $false; Reason = '' } }
  $r = Invoke-World $w
  Test-That 'installer code 1: Failed, exit 13, work folder kept' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13 -and $r.DiagnosticPath -ceq 'C:\fake\work' -and $null -eq $w.Removed)
  $w = New-World @{ Run = @{ Started = $true; ExitCode = 12345; Declined = $false; TimedOut = $false; Reason = '' } }
  $r = Invoke-World $w
  Test-That 'an unknown installer code is never success: exit 13, ErrorCode is the original' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13 -and $r.ErrorCode -ceq '12345')
  $w = New-World @{ Run = @{ Started = $true; ExitCode = $null; Declined = $false; TimedOut = $false; Reason = '' } }
  $r = Invoke-World $w
  Test-That 'no exit code at all is never success' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13)
  $w = New-World @{ Run = @{ Started = $false; ExitCode = $null; Declined = $false; TimedOut = $false; Reason = 'Windows could not start setup' } }
  $r = Invoke-World $w
  Test-That 'setup that never started is Failed, exit 13' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13)

  $w = New-World @{ Run = @{ Started = $true; ExitCode = $null; Declined = $false; TimedOut = $true; Reason = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'timeout: Failed, ErrorCode Timeout, exit 13' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13 -and $r.ErrorCode -ceq 'Timeout')
  Test-That 'timeout: the work folder is kept and named' ($r.DiagnosticPath -ceq 'C:\fake\work' -and $null -eq $w.Removed)
  Test-That 'timeout: the message says setup may still be running; no readback, no launch' ($r.Message -match 'still be running' -and (Get-Calls $w) -notmatch 'LaunchDesktop' -and (Get-Calls $w) -notmatch 'RunInstaller,GetInstalled')

  # Readback
  $w = New-World @{ InstalledAfter = @{ State = 'Installed'; Version = '1.2.0'; InstallPath = 'C:\Program Files\Inwire\'; Detail = '' } }
  $r = Invoke-World $w -Launch
  Test-That 'readback: exit 0 but another version reads back is exit 13' ($r.State -eq 'Failed' -and $r.ExitCode -eq 13 -and $r.Message -match '1\.2\.0' -and (Get-Calls $w) -notmatch 'LaunchDesktop') $r.Message
  $w = New-World @{ InstalledAfter = @{ State = 'Absent'; Version = ''; InstallPath = ''; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'readback: exit 0 but nothing is installed is exit 13' ($r.ExitCode -eq 13)
  $w = New-World @{ InstalledAfter = @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = '' } }
  $r = Invoke-World $w
  Test-That 'readback: an unreadable state is exit 13' ($r.ExitCode -eq 13)
}

# ==========================================================================
# Receive-InwireFile and Receive-InwireText over a fake Send
# ==========================================================================
function New-Fake {
  # $Script maps url -> response hashtable (or a scriptblock returning one)
  param([hashtable]$Routes)
  $log = New-Object 'System.Collections.Generic.List[string]'
  $send = {
    param($url, $token)
    $log.Add($url)
    $r = $Routes[$url]
    if ($null -eq $r) { throw ('no route for ' + $url) }
    if ($r -is [scriptblock]) { return (& $r) }
    return $r
  }.GetNewClosure()
  return @{ Send = $send; Log = $log }
}

function New-Body {
  param([int]$Size, [int]$Extra = 0)
  $b = New-Object byte[] ($Size + $Extra)
  for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [byte](($i * 31 + 7) % 251) }
  return ,$b
}

function Get-HexSha {
  param([byte[]]$Bytes)
  $s = [System.Security.Cryptography.SHA256]::Create()
  try { return (($s.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $s.Dispose() }
}

# A MemoryStream that remembers how far it was ever read, because a disposed
# MemoryStream refuses to say.
if (-not ('InwireTestCountingStream' -as [type])) {
  Add-Type -TypeDefinition @'
public class InwireTestCountingStream : System.IO.MemoryStream {
  public long Max;
  public InwireTestCountingStream(byte[] b) : base(b) { }
  public override System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken ct) {
    System.Threading.Tasks.Task<int> t = base.ReadAsync(buffer, offset, count, ct);
    Max = Position;
    return t;
  }
}
'@
}

function New-Ok {
  param([byte[]]$Bytes, $Length = 'auto')
  $ms = New-Object InwireTestCountingStream(, $Bytes)
  $len = if ($Length -is [string]) { [long]$Bytes.Length } else { $Length }
  return @{ StatusCode = 200; Location = $null; ContentLength = $len; Stream = $ms }
}

function New-Redirect {
  param([string]$To, [int]$Code = 302)
  return @{ StatusCode = $Code; Location = $To; ContentLength = $null; Stream = $null }
}

Invoke-Section 'downloader' {
  $dir = Join-Path ([IO.Path]::GetTempPath()) ('inwire-bootstrap-tests-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $dir | Out-Null
  try {
    $u = 'https://download.example.invalid/Inwire-1.2.3-x64.exe'
    $bytes = New-Body 300000
    $sha = Get-HexSha $bytes
    $dest = Join-Path $dir 'Inwire-Setup.exe'
    function Receive {
      param($Fake, [long]$Size, [string]$Sha, [string]$Url = $u)
      if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
      return (Receive-InwireFile -Url $Url -DestPath $dest -SizeBytes $Size -Sha256 $Sha -Policy $script:TestPolicy -Send $Fake.Send)
    }

    $f = New-Fake @{ $u = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a good download is Ok' ($r.Ok -eq $true) ([string]$r.Reason)
    Test-That 'receive: the file is the bytes, and no partial is left' ((Test-Path -LiteralPath $dest) -and (Get-Item -LiteralPath $dest).Length -eq $bytes.Length -and -not (Test-Path -LiteralPath ($dest + '.partial')))
    Test-That 'receive: the file hashes to the declared digest' ((Get-HexSha ([IO.File]::ReadAllBytes($dest))) -ceq $sha)

    $f = New-Fake @{ $u = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha.ToUpperInvariant()
    Test-That 'receive: an uppercase expected digest still matches' ($r.Ok -eq $true)

    $f = New-Fake @{ $u = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length ('f' * 64)
    Test-That 'receive: a wrong hash is refused as an integrity fault, not transient, and leaves no file' ($r.Ok -eq $false -and $r.Integrity -eq $true -and $r.Transient -eq $false -and -not (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath ($dest + '.partial')))

    $f = New-Fake @{ $u = (New-Ok $bytes) }
    $r = Receive $f (536870912 + 1) $sha
    Test-That 'receive: a declared size over 512 MiB is refused before any request' ($r.Ok -eq $false -and $f.Log.Count -eq 0)
    $r = Receive $f 0 $sha
    Test-That 'receive: a declared size of 0 is refused' ($r.Ok -eq $false -and $f.Log.Count -eq 0)

    $f = New-Fake @{ $u = (New-Ok $bytes $null) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a missing Content-Length is refused' ($r.Ok -eq $false -and $r.Transient -eq $false)

    $f = New-Fake @{ $u = (New-Ok $bytes ([long]($bytes.Length + 5))) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a Content-Length different from the declared size is refused' ($r.Ok -eq $false -and $r.Integrity -eq $true -and $r.Transient -eq $false)

    $longer = New-Body $bytes.Length 1000
    $resp = New-Ok $longer ([long]$bytes.Length)
    $f = New-Fake @{ $u = $resp }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a body longer than declared is refused' ($r.Ok -eq $false -and $r.Integrity -eq $true -and -not (Test-Path -LiteralPath $dest))
    Test-That 'receive: reading stops within one chunk of the declared size' ($resp.Stream.Max -le ($bytes.Length + 262144) -and $resp.Stream.Max -gt 0) ([string]$resp.Stream.Max)

    $short = New-Body ($bytes.Length - 10)
    $f = New-Fake @{ $u = (New-Ok $short ([long]$bytes.Length)) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a body shorter than declared is refused' ($r.Ok -eq $false -and $r.Integrity -eq $true)

    $f = New-Fake @{ $u = @{ StatusCode = 500; Location = $null; ContentLength = $null; Stream = $null } }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: HTTP 500 is transient' ($r.Ok -eq $false -and $r.Transient -eq $true)
    $f = New-Fake @{ $u = @{ StatusCode = 404; Location = $null; ContentLength = $null; Stream = $null } }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: HTTP 404 is not transient' ($r.Ok -eq $false -and $r.Transient -eq $false)
    $f = New-Fake @{ $u = { throw (New-Object System.IO.IOException('the remote name could not be resolved')) } }
    $r = Receive $f $bytes.Length $sha
    Test-That 'receive: a network exception is transient' ($r.Ok -eq $false -and $r.Transient -eq $true)

    # Redirects
    $ok = New-Ok $bytes
    $f = New-Fake @{ $u = (New-Redirect 'https://download.example.invalid/real.exe'); 'https://download.example.invalid/real.exe' = $ok }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: an absolute redirect to the same host is followed' ($r.Ok -eq $true) ([string]$r.Reason)

    $f = New-Fake @{ $u = (New-Redirect '/other/real.exe' 307); 'https://download.example.invalid/other/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: a path-absolute redirect is resolved against the current URL' ($r.Ok -eq $true) ([string]$r.Reason)

    $f = New-Fake @{ $u = (New-Redirect 'real.exe' 301); 'https://download.example.invalid/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: a relative redirect is resolved against the current URL' ($r.Ok -eq $true) ([string]$r.Reason)

    $f = New-Fake @{ $u = (New-Redirect 'http://download.example.invalid/real.exe'); 'http://download.example.invalid/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: https to http is refused, and the http URL is never requested' ($r.Ok -eq $false -and $r.Transient -eq $false -and $f.Log.Count -eq 1)

    $f = New-Fake @{ $u = (New-Redirect 'https://evil.example.invalid/real.exe'); 'https://evil.example.invalid/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: an unknown host is refused, and never requested' ($r.Ok -eq $false -and $f.Log.Count -eq 1)

    $f = New-Fake @{ $u = (New-Redirect 'https://download.example.invalid:443/real.exe'); 'https://download.example.invalid:443/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: host:443 is refused' ($r.Ok -eq $false -and $f.Log.Count -eq 1)

    $f = New-Fake @{ $u = (New-Redirect 'https://user:pw@download.example.invalid/real.exe'); 'https://user:pw@download.example.invalid/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: credentials in the URL are refused' ($r.Ok -eq $false -and $f.Log.Count -eq 1)

    $f = New-Fake @{ $u = (New-Redirect '//evil.example.invalid/real.exe'); 'https://evil.example.invalid/real.exe' = (New-Ok $bytes) }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: a scheme-relative redirect to another host is refused' ($r.Ok -eq $false -and $f.Log.Count -eq 1)

    $f = New-Fake @{ $u = @{ StatusCode = 302; Location = $null; ContentLength = $null; Stream = $null } }
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: a redirect with no Location is refused' ($r.Ok -eq $false)

    # Chain of N redirects before the file
    function New-Chain {
      param([int]$Hops)
      $routes = @{}
      $cur = $u
      for ($i = 1; $i -le $Hops; $i++) {
        $next = 'https://download.example.invalid/hop' + $i
        $routes[$cur] = (New-Redirect $next)
        $cur = $next
      }
      $routes[$cur] = (New-Ok $bytes)
      return $routes
    }
    $f = New-Fake (New-Chain 5)
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: five redirects are allowed' ($r.Ok -eq $true) ([string]$r.Reason)
    $f = New-Fake (New-Chain 6)
    $r = Receive $f $bytes.Length $sha
    Test-That 'redirect: six redirects are refused' ($r.Ok -eq $false -and $r.Transient -eq $false)

    $r = Receive (New-Fake @{}) $bytes.Length $sha 'https://evil.example.invalid/x.exe'
    Test-That 'receive: a first URL off the allowlist is refused without a request' ($r.Ok -eq $false)

    # Text (the descriptor): a 1 MiB cap
    $json = [Text.Encoding]::UTF8.GetBytes($script:DefaultBody)
    $du = $script:TestPolicy.DescriptorUrl
    $f = New-Fake @{ $du = (New-Ok $json) }
    $t = Receive-InwireText -Url $du -MaxBytes 1048576 -TimeoutSeconds 30 -Policy $script:TestPolicy -Send $f.Send
    Test-That 'text: the descriptor is read' ($t.Ok -eq $true -and $t.Text -ceq $script:DefaultBody)
    $big = New-Body 1048577
    $f = New-Fake @{ $du = (New-Ok $big) }
    $t = Receive-InwireText -Url $du -MaxBytes 1048576 -TimeoutSeconds 30 -Policy $script:TestPolicy -Send $f.Send
    Test-That 'text: a descriptor over 1 MiB is refused by its Content-Length' ($t.Ok -eq $false)
    $f = New-Fake @{ $du = (New-Ok $big $null) }
    $t = Receive-InwireText -Url $du -MaxBytes 1048576 -TimeoutSeconds 30 -Policy $script:TestPolicy -Send $f.Send
    Test-That 'text: an over-long body with no Content-Length is cut off at the cap' ($t.Ok -eq $false)
    $bom = [byte[]](@(0xEF, 0xBB, 0xBF) + [int[]]$json)
    $f = New-Fake @{ $du = (New-Ok $bom) }
    $t = Receive-InwireText -Url $du -MaxBytes 1048576 -TimeoutSeconds 30 -Policy $script:TestPolicy -Send $f.Send
    Test-That 'text: a UTF-8 BOM is stripped' ($t.Ok -eq $true -and $t.Text -ceq $script:DefaultBody)
    $f = New-Fake @{ $du = (New-Redirect 'https://evil.example.invalid/release.json') }
    $t = Receive-InwireText -Url $du -MaxBytes 1048576 -TimeoutSeconds 30 -Policy $script:TestPolicy -Send $f.Send
    Test-That 'text: a redirect off the allowlist is refused' ($t.Ok -eq $false)
  } finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# ==========================================================================
Invoke-Section 'URL rule' {
  $hosts = [string[]]@('download.example.invalid')
  Test-That 'url: https on the allowed host' (Test-InwireUrl 'https://download.example.invalid/a/b?c=d' $hosts)
  Test-That 'url: uppercase host' (Test-InwireUrl 'https://DOWNLOAD.example.INVALID/a' $hosts)
  Test-That 'url: http refused' (-not (Test-InwireUrl 'http://download.example.invalid/a' $hosts))
  Test-That 'url: a port refused' (-not (Test-InwireUrl 'https://download.example.invalid:8443/a' $hosts))
  Test-That 'url: :443 refused' (-not (Test-InwireUrl 'https://download.example.invalid:443/a' $hosts))
  Test-That 'url: credentials refused' (-not (Test-InwireUrl 'https://u:p@download.example.invalid/a' $hosts))
  Test-That 'url: a fragment refused' (-not (Test-InwireUrl 'https://download.example.invalid/a#x' $hosts))
  Test-That 'url: a suffix host refused' (-not (Test-InwireUrl 'https://evil-download.example.invalid/a' $hosts))
  Test-That 'url: a prefix host refused' (-not (Test-InwireUrl 'https://download.example.invalid.evil.com/a' $hosts))
  Test-That 'url: a trailing dot refused' (-not (Test-InwireUrl 'https://download.example.invalid./a' $hosts))
  Test-That 'url: backslash tricks refused' (-not (Test-InwireUrl 'https://download.example.invalid\@evil.com/a' $hosts))
  Test-That 'url: whitespace refused' (-not (Test-InwireUrl "https://download.example.invalid/a b" $hosts))
  Test-That 'url: a trailing newline refused' (-not (Test-InwireUrl ("https://download.example.invalid/a" + "`n") $hosts))
  Test-That 'url: a number refused' (-not (Test-InwireUrl 42 $hosts))
  Test-That 'url: null refused' (-not (Test-InwireUrl $null $hosts))
}

Invoke-Section 'signature check' {
  $cert = $null
  try {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=Inwire Test Only', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(1))
  } catch {
    Skip-That 'signature check' ('no in-memory certificates on this runtime: ' + $_.Exception.Message)
    return
  }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $pin = (($sha.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
  $other = 'a' * 64
  $valid = [pscustomobject]@{ Status = 'Valid'; SignerCertificate = $cert }
  Test-That 'signature: Valid and a pinned certificate is accepted' ((Test-InwireSignature $valid ([string[]]@($pin))).Ok -eq $true)
  Test-That 'signature: Valid and one of several pins is accepted' ((Test-InwireSignature $valid ([string[]]@($other, $pin))).Ok -eq $true)
  Test-That 'signature: Valid but a different pin is refused' ((Test-InwireSignature $valid ([string[]]@($other))).Ok -eq $false)
  Test-That 'signature: Valid with no pins is refused' ((Test-InwireSignature $valid ([string[]]@())).Ok -eq $false)
  Test-That 'signature: the pin is compared as lowercase hex, exactly' ((Test-InwireSignature $valid ([string[]]@($pin.ToUpperInvariant()))).Ok -eq $false)
  foreach ($st in 'NotSigned', 'HashMismatch', 'UnknownError', 'NotTrusted', 'Incompatible', 'NotSupportedFileFormat') {
    $sig = [pscustomobject]@{ Status = $st; SignerCertificate = $cert }
    Test-That ('signature: ' + $st + ' is refused even with a matching pin') ((Test-InwireSignature $sig ([string[]]@($pin))).Ok -eq $false)
  }
  $enum = [pscustomobject]@{ Status = [System.Management.Automation.SignatureStatus]::Valid; SignerCertificate = $cert }
  Test-That 'signature: the real SignatureStatus enum is read' ((Test-InwireSignature $enum ([string[]]@($pin))).Ok -eq $true)
  $none = [pscustomobject]@{ Status = 'Valid'; SignerCertificate = $null }
  Test-That 'signature: Valid with no signer certificate is refused' ((Test-InwireSignature $none ([string[]]@($pin))).Ok -eq $false)
  Test-That 'signature: nothing at all is refused' ((Test-InwireSignature $null ([string[]]@($pin))).Ok -eq $false)

  # The real cmdlet on an unsigned file: the adapter-shaped path, no store involved.
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('inwire-bootstrap-sig-' + [Guid]::NewGuid().ToString('N') + '.ps1')
  try {
    [IO.File]::WriteAllText($tmp, "'unsigned'`r`n")
    $real = Get-AuthenticodeSignature -LiteralPath $tmp
    Test-That 'signature: a real unsigned file is refused' ((Test-InwireSignature $real ([string[]]@($pin))).Ok -eq $false)
  } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

Invoke-Section 'elevation seam' {
  $a = Get-InwireElevationCommand
  $b = Get-InwireElevationCommand
  Test-That 'elevation: the command line is a constant' ($a.ArgumentList -ceq $b.ArgumentList -and $a.FilePath -ceq $b.FilePath)
  Test-That 'elevation: it is -NoProfile -NonInteractive -EncodedCommand <base64>' ($a.ArgumentList -cmatch '^-NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$')
  Test-That 'elevation: it runs the 64-bit System32 Windows PowerShell' ($a.FilePath -match '\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$')
  $b64 = ($a.ArgumentList -split ' ')[-1]
  $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
  Test-That 'elevation: the script reads the installer and log from the environment' ($script -match 'INWIRE_BOOT_INSTALLER' -and $script -match 'INWIRE_BOOT_LOG')
  Test-That 'elevation: the script carries the exact installer switches' ($script.Contains('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS'))
  Test-That 'elevation: the script never exits success on a missing exit code' ($script -match 'ExitCode\) \{ exit 70001')
  Test-That 'elevation: no path appears in the command line' ($a.ArgumentList -notmatch 'Inwire-Setup' -and $script -notmatch 'C:\\')
  Test-That 'installer arguments: exactly the documented switches and a quoted log' ((Get-InwireInstallerArguments 'C:\a b\setup.log') -ceq '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS "/LOG=C:\a b\setup.log"')
  $threw = $false
  try { [void](Get-InwireInstallerArguments 'C:\a"b\setup.log') } catch { $threw = $true }
  Test-That 'installer arguments: a log path with a double quote is refused' $threw

  $w32 = New-Object System.ComponentModel.Win32Exception(1223)
  Test-That 'uac: a Win32Exception 1223 is a declined prompt' (Test-InwireUacDeclined $w32)
  $wrapped = New-Object System.InvalidOperationException('wrapper', $w32)
  Test-That 'uac: 1223 inside another exception is a declined prompt' (Test-InwireUacDeclined $wrapped)
  Test-That 'uac: another Win32 code is not' (-not (Test-InwireUacDeclined (New-Object System.ComponentModel.Win32Exception(5))))
  Test-That 'uac: an unrelated exception is not' (-not (Test-InwireUacDeclined (New-Object System.InvalidOperationException('x'))))

  $plat = New-InwireProductionPlatform -Policy $script:TestPolicy
  $need = @('GetPlatform', 'IsElevated', 'GetInstalled', 'GetRelease', 'Download', 'VerifyPublisher', 'RunInstaller', 'LaunchDesktop', 'NewWorkDir', 'RemoveWorkDir')
  Test-That 'production platform: every callback exists' ((@($need | Where-Object { $plat[$_] -isnot [scriptblock] })).Count -eq 0)
  $pi = & $plat.GetPlatform
  Test-That 'production platform: GetPlatform answers Windows' ($pi.OS -ceq 'Windows' -and @('x64', 'arm64', 'x86') -ccontains $pi.Architecture)
  $dir = & $plat.NewWorkDir
  Test-That 'production platform: the work folder is fresh, private and under the user temp' ((Test-Path -LiteralPath $dir -PathType Container) -and $dir.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $dir) -match '^inwire-bootstrap-[0-9a-f]{32}$')
  & $plat.RemoveWorkDir $dir
  Test-That 'production platform: it is removed again' (-not (Test-Path -LiteralPath $dir))
  $outside = Join-Path ([IO.Path]::GetTempPath()) ('keep-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $outside | Out-Null
  & $plat.RemoveWorkDir $outside
  Test-That 'production platform: RemoveWorkDir deletes only folders it made' (Test-Path -LiteralPath $outside)
  Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue
  $inst = & $plat.GetInstalled 'Desktop'
  Test-That 'production platform: GetInstalled reads the registry without throwing' (@('Absent', 'Installed', 'Unknown') -ccontains $inst.State)
  $inst = & $plat.GetInstalled 'EndpointAgent'
  Test-That 'production platform: there is no installed probe for another product' ($inst.State -ceq 'Unknown')
}

# ==========================================================================
Invoke-Section 'bundle' {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('inwire-bootstrap-bundle-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  $hostExe = (Get-Process -Id $PID).Path
  $build = Join-Path $repo 'scripts\distribution\build-bootstrap.ps1'
  try {
    # Test-runner-only: the child is started with a process-scope execution
    # policy bypass because a test machine may be Restricted. The bootstrap
    # itself never touches the policy.
    function Invoke-Child {
      param([string]$Script, [string[]]$Arguments = @())
      $saved = $ErrorActionPreference
      $ErrorActionPreference = 'Continue'
      try {
        $out = & $hostExe -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1
        $code = $LASTEXITCODE
      } finally { $ErrorActionPreference = $saved }
      return @{ Code = $code; Out = (($out | ForEach-Object { [string]$_ }) -join "`n") }
    }
    function Invoke-Build {
      param([string[]]$Arguments)
      return (Invoke-Child $build $Arguments)
    }
    function Test-Bundle {
      param([string]$Path, [string]$Label)
      $tokens = $null; $errors = $null
      [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
      Test-That ($Label + ': it parses with no errors') (@($errors).Count -eq 0) (($errors | ForEach-Object { $_.Message }) -join '; ')
      $text = [IO.File]::ReadAllText($Path)
      foreach ($bad in 'Import-Module', 'Invoke-Expression', 'DownloadString', 'ServerCertificateValidationCallback', 'Set-ExecutionPolicy', 'ExecutionPolicy') {
        Test-That ($Label + ': it never uses ' + $bad) (-not $text.Contains($bad))
      }
      Test-That ($Label + ': it never uses iex') ($text -cnotmatch '(?i)\biex\b')
      Test-That ($Label + ': it is ASCII only') ($text -cnotmatch '[^\x00-\x7F]')
      Test-That ($Label + ': it keeps no source-form markers') ($text -cnotmatch 'INWIRE-(CORE|POLICY|BUILD)-BEGIN' -and -not $text.Contains('$PSScriptRoot'))
      return $text
    }

    # --- fixture bundle, unsigned ---
    $fixture = Join-Path $tmp 'fixture.ps1'
    $b = Invoke-Build @('-Policy', (Join-Path $repo 'distribution\fixtures\test-policy.json'), '-OutFile', $fixture, '-NoSign')
    Test-That 'bundle: the fixture build succeeds' ($b.Code -eq 0 -and (Test-Path -LiteralPath $fixture)) $b.Out
    if (Test-Path -LiteralPath $fixture) {
      $text = Test-Bundle $fixture 'fixture bundle'
      Test-That 'fixture bundle: it is labelled TEST BUILD - fixture policy' ($text.Contains('TEST BUILD - fixture policy'))
      $pkg = Read-JsonFile 'package.json'
      Test-That 'fixture bundle: the header carries the package version' ($text.Contains($pkg.version))
      Test-That 'fixture bundle: it embeds the fixture pin' ($text.Contains('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'))
    }

    # --- production bundle: no pin, so exit 10, and no network call ---
    $prod = Join-Path $tmp 'prod.ps1'
    $b = Invoke-Build @('-OutFile', $prod, '-NoSign')
    Test-That 'bundle: the production build succeeds' ($b.Code -eq 0 -and (Test-Path -LiteralPath $prod)) $b.Out
    if (Test-Path -LiteralPath $prod) {
      $text = Test-Bundle $prod 'production bundle'
      Test-That 'production bundle: it is not labelled as a test build' (-not $text.Contains('TEST BUILD'))
      $run = Invoke-Child $prod
      Test-That 'production bundle: with no pin configured it exits 10 before any download' ($run.Code -eq 10) ('exit ' + $run.Code + ' ' + $run.Out)
      Test-That 'production bundle: it says it pins no publisher certificate' ($run.Out -match 'pins no publisher certificate')
      $run = Invoke-Child $prod @('-Product', 'EndpointAgent')
      Test-That 'production bundle: -Product EndpointAgent exits 20' ($run.Code -eq 20) ('exit ' + $run.Code)
      $run = Invoke-Child $prod @('-Version', '1.2')
      Test-That 'production bundle: a malformed -Version exits 10' ($run.Code -eq 10) ('exit ' + $run.Code)
    }

    # --- a policy that does not validate is not embedded ---
    $badPolicy = Join-Path $tmp 'bad-policy.json'
    [IO.File]::WriteAllText($badPolicy, '{"schema":1}')
    $b = Invoke-Build @('-Policy', $badPolicy, '-OutFile', (Join-Path $tmp 'bad.ps1'), '-NoSign')
    Test-That 'bundle: an invalid policy fails the build and writes nothing' ($b.Code -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $tmp 'bad.ps1')))

    # --- signing, with this PC's certificate when there is one ---
    function Find-Thumbprint {
      if ($env:INWIRE_SIGN_THUMBPRINT) { return $env:INWIRE_SIGN_THUMBPRINT }
      $candidates = @((Join-Path $repo '.signing.json'))
      try {
        $common = (& git -C $repo rev-parse --git-common-dir 2>$null)
        if ($common) {
          $abs = if ([IO.Path]::IsPathRooted($common)) { $common } else { Join-Path $repo $common }
          $candidates += (Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($abs))) '.signing.json')
        }
      } catch { }
      foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
          try {
            $j = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $c -Raw)
            if ($j.thumbprint) { return [string]$j.thumbprint }
          } catch { }
        }
      }
      return $null
    }
    $tp = Find-Thumbprint
    $cert = $null
    if ($tp) {
      $tp = ($tp -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
      foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $p = Join-Path $store $tp
        if (Test-Path -LiteralPath $p) { $cert = Get-Item -LiteralPath $p; break }
      }
    }
    if ($null -eq $cert -or -not $cert.HasPrivateKey) {
      Skip-That 'bundle signing' 'no code-signing certificate is configured on this PC'
    } else {
      $signed = Join-Path $tmp 'signed.ps1'
      $b = Invoke-Build @('-Policy', (Join-Path $repo 'distribution\fixtures\test-policy.json'), '-OutFile', $signed, '-Thumbprint', $tp, '-SkipTimestamp')
      Test-That 'bundle signing: the signing build succeeds' ($b.Code -eq 0) $b.Out
      $sig = Get-AuthenticodeSignature -LiteralPath $signed
      $trusted = ($sig.Status -eq 'Valid')
      $intact = ($sig.Status -eq 'UnknownError' -and $null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Thumbprint -eq $tp -and $sig.StatusMessage -match 'root|trust|chain')
      Test-That 'bundle signing: the signed bundle verifies (Valid, or intact with a root not trusted on this PC)' ($trusted -or $intact) ([string]$sig.Status + ' ' + $sig.StatusMessage)
      Test-That 'bundle signing: it is signed by the configured certificate' ($null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Thumbprint -eq $tp)
      $body = [IO.File]::ReadAllText($signed)
      $tokens = $null; $errors = $null
      [void][System.Management.Automation.Language.Parser]::ParseFile($signed, [ref]$tokens, [ref]$errors)
      Test-That 'bundle signing: it still parses after signing' (@($errors).Count -eq 0)
      $tampered = [regex]::Replace($body, 'fedcba98', 'fedcba99', 1)
      Test-That 'bundle signing: the tamper edit changed exactly the pin' ($tampered -ne $body)
      $tpath = Join-Path $tmp 'tampered.ps1'
      [IO.File]::WriteAllText($tpath, $tampered, (New-Object System.Text.UTF8Encoding($true)))
      $tsig = Get-AuthenticodeSignature -LiteralPath $tpath
      Test-That 'bundle signing: changing one character of the embedded pin breaks the signature (HashMismatch)' ($tsig.Status -eq 'HashMismatch') ([string]$tsig.Status)

      $env:INWIRE_REQUIRE_SIGNING = '1'
      try {
        $b = Invoke-Build @('-Policy', (Join-Path $repo 'distribution\fixtures\test-policy.json'), '-OutFile', (Join-Path $tmp 'req.ps1'), '-Thumbprint', $tp, '-SkipTimestamp')
        Test-That 'bundle signing: INWIRE_REQUIRE_SIGNING=1 refuses to skip the timestamp' ($b.Code -ne 0)
        $b = Invoke-Build @('-Policy', (Join-Path $repo 'distribution\fixtures\test-policy.json'), '-OutFile', (Join-Path $tmp 'req2.ps1'), '-Thumbprint', ('0' * 40), '-SkipTimestamp')
        Test-That 'bundle signing: INWIRE_REQUIRE_SIGNING=1 fails when the certificate is missing' ($b.Code -ne 0)
      } finally { Remove-Item Env:\INWIRE_REQUIRE_SIGNING -ErrorAction SilentlyContinue }
    }
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host ''
Write-Host ($script:Passes.ToString() + ' passed, ' + $script:Failures.ToString() + ' failed, ' + $script:Skips.ToString() + ' skipped')
if ($script:Failures -gt 0) { exit 1 }
exit 0
