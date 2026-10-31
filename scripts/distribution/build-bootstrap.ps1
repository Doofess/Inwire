<#
.SYNOPSIS
  Builds the standalone, signed PowerShell bootstrap.

.DESCRIPTION
  Bundles distribution/install-inwire.ps1, distribution/Install-Inwire.Core.psm1
  and a policy into ONE script: the core is inlined, nothing is imported at
  runtime, no file is read at runtime, and the policy is a PowerShell literal
  generated from the JSON and validated by the same Read-InwirePolicy the
  bootstrap itself runs. The result is release-artifacts/bootstrap/install-inwire.ps1
  unless -OutFile says otherwise, and it is signed with the certificate
  scripts/sign/sign.ps1 would use.

  ## Why the policy is compiled in

  The pinned publisher certificates are what make "signed" mean "signed by
  Inwire" (ADR 0069). They travel inside the signed script, because a policy
  read from anywhere else is a policy whoever writes that file chooses.

  ## Signing, and why this does not call sign.ps1

  sign.ps1 signs and verifies PE files: it reads the PKCS#7 blob out of the PE
  certificate table to check its own work, which a script does not have. The
  certificate lookup is the same (-Thumbprint, INWIRE_SIGN_THUMBPRINT, then
  .signing.json at the repository root, in Cert:\CurrentUser\My then
  Cert:\LocalMachine\My) and so is the timestamp server default
  (INWIRE_SIGN_TIMESTAMP_URL or http://timestamp.digicert.com). The timestamp is
  the one Set-AuthenticodeSignature makes, which is an Authenticode
  countersignature rather than RFC 3161; the signed result is read back and
  must carry this certificate.

  INWIRE_REQUIRE_SIGNING=1 makes a missing certificate, an unsigned result and
  -SkipTimestamp errors. Without it a missing certificate is a warning and the
  output is left unsigned.

.PARAMETER Policy
  The policy JSON. Default distribution/release-policy.json. A policy under
  distribution/fixtures (or naming a .invalid host) makes a bundle labelled
  "TEST BUILD - fixture policy".

.PARAMETER OutFile
  Where to write the bundle.

.PARAMETER NoSign
  Build only.

.PARAMETER SkipTimestamp
  Sign without asking a timestamp server. For tests, which must not call out.
  Refused when INWIRE_REQUIRE_SIGNING=1.

.PARAMETER Thumbprint
  The signing certificate's thumbprint, instead of the environment or .signing.json.
#>
[CmdletBinding()]
param(
  [string]$Policy,
  [string]$OutFile,
  [switch]$NoSign,
  [switch]$SkipTimestamp,
  [string]$Thumbprint,
  [string]$TimestampServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
trap {
  [Console]::Error.WriteLine("build-bootstrap.ps1: $($_.Exception.Message)")
  exit 1
}

# The security module of THIS edition, by path: a PSModulePath inherited from
# the other edition hides it (scripts/sign/sign.ps1 records the trap).
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$DistDir = Join-Path $RepoRoot 'distribution'
Import-Module -Name (Join-Path $DistDir 'Install-Inwire.Core.psm1') -Force -DisableNameChecking

function Resolve-UserPath([string]$p) {
  return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
}

function ConvertTo-PsString([string]$s) {
  return ("'" + $s.Replace("'", "''") + "'")
}

# ---- the policy, validated by the bootstrap's own reader ----
$policyPath = if ($Policy) { Resolve-UserPath $Policy } else { Join-Path $DistDir 'release-policy.json' }
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) { throw "no such policy file: $policyPath" }
$policyObject = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($policyPath))
$p = Read-InwirePolicy $policyObject
if ($null -eq $p) { throw "the policy $policyPath is not valid; nothing was built" }

$fixturesDir = (Join-Path $DistDir 'fixtures') + '\'
$isFixture = $policyPath.StartsWith($fixturesDir, [StringComparison]::OrdinalIgnoreCase)
foreach ($h in $p.AllowedHosts) { if ($h.EndsWith('.invalid', [StringComparison]::Ordinal)) { $isFixture = $true } }
$label = if ($isFixture) { 'TEST BUILD - fixture policy' } else { 'production' }

$lines = @(
  '$policyObject = [pscustomobject]@{',
  '  schema = 1',
  ('  descriptorUrl = ' + (ConvertTo-PsString $p.DescriptorUrl)),
  ('  allowedHosts = @(' + (($p.AllowedHosts | ForEach-Object { ConvertTo-PsString $_ }) -join ', ') + ')'),
  ('  publisherCertificateSha256 = @(' + (($p.PublisherCertificateSha256 | ForEach-Object { ConvertTo-PsString $_ }) -join ', ') + ')'),
  ('  desktopPackageId = ' + (ConvertTo-PsString $p.DesktopPackageId)),
  ('  endpointAvailable = ' + $(if ($p.EndpointAvailable) { '$true' } else { '$false' })),
  '}'
)
$policyLiteral = $lines -join "`n"

# The literal must read back to the same policy, or the generator is wrong.
$roundTrip = & ([scriptblock]::Create($policyLiteral + "`n" + '$policyObject'))
$q = Read-InwirePolicy $roundTrip
if ($null -eq $q -or $q.DescriptorUrl -cne $p.DescriptorUrl -or $q.DesktopPackageId -cne $p.DesktopPackageId -or
    $q.EndpointAvailable -ne $p.EndpointAvailable -or
    (@($q.AllowedHosts) -join '|') -cne (@($p.AllowedHosts) -join '|') -or
    (@($q.PublisherCertificateSha256) -join '|') -cne (@($p.PublisherCertificateSha256) -join '|')) {
  throw 'the generated policy literal does not read back to the policy; nothing was built'
}

# ---- the bundle ----
$pkg = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $RepoRoot 'package.json')))
$entry = [IO.File]::ReadAllText((Join-Path $DistDir 'install-inwire.ps1'))
$core = [IO.File]::ReadAllText((Join-Path $DistDir 'Install-Inwire.Core.psm1'))

function Set-Region([string]$Text, [string]$Name, [string]$Replacement) {
  $pattern = '(?ms)^# INWIRE-' + $Name + '-BEGIN[^\r\n]*\r?\n.*?^# INWIRE-' + $Name + '-END[^\r\n]*(\r?\n|\z)'
  $found = [regex]::Matches($Text, $pattern)
  if ($found.Count -ne 1) { throw "install-inwire.ps1 must hold exactly one INWIRE-$Name region (found $($found.Count))" }
  $m = $found[0]
  return $Text.Substring(0, $m.Index) + $Replacement + "`n" + $Text.Substring($m.Index + $m.Length)
}

$text = $entry
$text = Set-Region $text 'CORE' $core
$text = Set-Region $text 'BUILD' ('$buildLabel = ' + (ConvertTo-PsString $label))
$text = Set-Region $text 'POLICY' $policyLiteral

$header = @(
  "# Inwire bootstrap $($pkg.version) - install-inwire.ps1",
  $(if ($isFixture) { '# TEST BUILD - fixture policy. Not for release: it pins a made-up certificate and a host that does not resolve.' } else { '# Built from distribution/install-inwire.ps1 and distribution/Install-Inwire.Core.psm1 by scripts/distribution/build-bootstrap.ps1.' }),
  "# Policy: $(@($p.PublisherCertificateSha256).Count) pinned publisher certificate(s); allowed host(s): $(@($p.AllowedHosts) -join ', ')."
) -join "`n"
$text = $header + "`n" + $text
$text = $text -replace "`r?`n", "`r`n"

if ($text -cmatch '[^\x00-\x7F]') { throw 'the bundle holds a non-ASCII character; Windows PowerShell would misread it' }
foreach ($bad in 'Import-Module', 'Invoke-Expression', 'DownloadString', 'ServerCertificateValidationCallback', 'ExecutionPolicy', '$PSScriptRoot') {
  if ($text.Contains($bad)) { throw "the bundle contains '$bad'; nothing was built" }
}
if ($text -cmatch '(?i)\biex\b') { throw "the bundle contains 'iex'; nothing was built" }
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
if (@($errors).Count -gt 0) { throw "the bundle does not parse: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }

# ---- sign ----
$required = ($env:INWIRE_REQUIRE_SIGNING -eq '1')
if (-not $NoSign -and $required -and $SkipTimestamp) {
  throw 'INWIRE_REQUIRE_SIGNING=1 forbids -SkipTimestamp: a signature without a timestamp dies with the certificate.'
}

$out = if ($OutFile) { Resolve-UserPath $OutFile } else { Join-Path $RepoRoot 'release-artifacts\bootstrap\install-inwire.ps1' }
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($out))
# Signing goes by file extension, so the working copy keeps .ps1.
$building = [IO.Path]::Combine([IO.Path]::GetDirectoryName($out), ('building-' + [Guid]::NewGuid().ToString('N') + '.ps1'))
try {
  [IO.File]::WriteAllText($building, $text, (New-Object System.Text.UTF8Encoding($true)))

  $signedBy = 'unsigned'
  if (-not $NoSign) {
    $raw = $null
    if ($Thumbprint) { $raw = $Thumbprint }
    elseif ($env:INWIRE_SIGN_THUMBPRINT) { $raw = $env:INWIRE_SIGN_THUMBPRINT }
    else {
      $config = Join-Path $RepoRoot '.signing.json'
      if (Test-Path -LiteralPath $config) {
        $json = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $config -Raw)
        if ($json.PSObject.Properties['thumbprint'] -and $json.thumbprint) { $raw = [string]$json.thumbprint }
      }
    }
    if (-not $raw) {
      if ($required) { throw 'signing is REQUIRED (INWIRE_REQUIRE_SIGNING=1) and no certificate is configured (-Thumbprint, INWIRE_SIGN_THUMBPRINT or .signing.json).' }
      Write-Warning 'build-bootstrap.ps1: no code-signing certificate is configured, so the bootstrap is UNSIGNED. INWIRE_REQUIRE_SIGNING=1 makes this an error.'
    } else {
      $tp = ($raw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
      if ($tp.Length -ne 40) { throw "the thumbprint is not 40 hex digits: '$raw'" }
      $cert = $null
      foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $path = Join-Path $store $tp
        if (Test-Path -LiteralPath $path) { $cert = Get-Item -LiteralPath $path; break }
      }
      if ($null -eq $cert) { throw "no certificate with thumbprint $tp in Cert:\CurrentUser\My or Cert:\LocalMachine\My." }
      $problems = @()
      if (-not $cert.HasPrivateKey) { $problems += 'this account has no private key for it' }
      $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
      if ($eku.Count -eq 0 -or -not (@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains '1.3.6.1.5.5.7.3.3')) { $problems += 'it is not a code-signing certificate' }
      $now = Get-Date
      if ($now -lt $cert.NotBefore -or $now -gt $cert.NotAfter) { $problems += 'it is not within its validity period' }
      if ($problems.Count -gt 0) { throw "cannot sign with $($cert.Subject) [$tp]: $($problems -join '; ')." }

      $sign = @{ LiteralPath = $building; Certificate = $cert; HashAlgorithm = 'SHA256'; IncludeChain = 'NotRoot'; ErrorAction = 'Stop' }
      if (-not $SkipTimestamp) {
        $sign.TimestampServer = if ($TimestampServer) { $TimestampServer } elseif ($env:INWIRE_SIGN_TIMESTAMP_URL) { $env:INWIRE_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
      }
      $r = Set-AuthenticodeSignature @sign
      if (@('NotSigned', 'HashMismatch', 'NotSupportedFileFormat', 'Incompatible') -contains [string]$r.Status) {
        throw "Set-AuthenticodeSignature left the bootstrap $($r.Status): $($r.StatusMessage)"
      }
      $check = Get-AuthenticodeSignature -LiteralPath $building
      if ($null -eq $check.SignerCertificate -or $check.SignerCertificate.Thumbprint -ne $tp) {
        throw "the signed bootstrap does not carry the configured certificate (status $($check.Status))"
      }
      if ($required -and $check.Status -ne 'Valid' -and $cert.Subject -ne $cert.Issuer) {
        throw "the signed bootstrap reads $($check.Status), not Valid"
      }
      $stamp = if ($SkipTimestamp) { 'no timestamp' } else { 'timestamped' }
      $signedBy = "signed by $($cert.Subject) [$tp], $stamp, reads $($check.Status)"
    }
  }

  if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
  Move-Item -LiteralPath $building -Destination $out
  Write-Host "built $out"
  Write-Host "  version $($pkg.version); $label; $signedBy"
} finally {
  if (Test-Path -LiteralPath $building) { Remove-Item -LiteralPath $building -Force -ErrorAction SilentlyContinue }
}
exit 0
