<#
.SYNOPSIS
  Downloads, verifies and installs the signed Inwire desktop installer.

.DESCRIPTION
  Fetches the release descriptor, downloads the installer it names, checks the
  size, the SHA-256 and that the Authenticode signature is Valid and made by a
  pinned Inwire certificate, and only then runs setup (asking for Windows
  administrator permission if this PowerShell is not elevated). Afterwards it
  reads the installed version back from the registry.

  The logic lives in Install-Inwire.Core.psm1. The build
  (scripts/distribution/build-bootstrap.ps1) replaces the marked regions below
  with the core's code and the policy as a literal, and signs the result, so
  the file people download has no other file to read.

.PARAMETER Product
  Desktop (the default) or EndpointAgent. The endpoint agent does not exist yet
  and answers exit code 20.

.PARAMETER Version
  The version to install, as 1.2.3. It must be the version the release
  descriptor publishes; older versions are not installable this way.

.PARAMETER Launch
  Start Inwire when setup has finished. Refused from an elevated PowerShell.

.PARAMETER Repair
  Install over an Inwire whose installed state cannot be read, or install the
  published version again over the same version.

.NOTES
  Exit codes: 0 installed or already installed, 2 cancelled, 10 unsupported
  environment, 11 download or metadata fault, 12 verification fault, 13 install
  or readback fault, 14 installed but not started, 20 endpoint agent
  unavailable, 3010 installed and Windows must restart.
#>
param(
  [ValidateSet('Desktop', 'EndpointAgent')][string]$Product = 'Desktop',
  [string]$Version,
  [switch]$Launch,
  [switch]$Repair
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# INWIRE-CORE-BEGIN (source form: the build replaces this region with the core's code)
Import-Module -Name (Join-Path $PSScriptRoot 'Install-Inwire.Core.psm1') -Force -DisableNameChecking
# INWIRE-CORE-END

# INWIRE-BUILD-BEGIN (source form: the build sets the label of the build)
$buildLabel = 'source'
# INWIRE-BUILD-END

# INWIRE-POLICY-BEGIN (source form: the build replaces this region with the policy as a literal)
$policyObject = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release-policy.json') -Raw)
# INWIRE-POLICY-END

$policy = Read-InwirePolicy $policyObject
if ($null -eq $policy) {
  Write-Host 'Inwire bootstrap: this bootstrap carries a policy it cannot read, so it will not install anything.'
  Write-Host 'Exit code 10'
  exit 10
}

$requested = ''
if ($PSBoundParameters.ContainsKey('Version')) { $requested = $Version }

$platform = New-InwireProductionPlatform -Policy $policy
$result = Invoke-InwireInstall -Product $Product -Version $requested -Launch:$Launch -Repair:$Repair -Policy $policy -Platform $platform
Write-InwireSummary $result $(if ($buildLabel -ne 'source' -and $buildLabel -ne 'production') { $buildLabel } else { '' })
exit $result.ExitCode
