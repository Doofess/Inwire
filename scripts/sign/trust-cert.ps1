<#
.SYNOPSIS
  Trusts Inwire's self-signed code-signing certificate on THIS PC. The one
  elevated step; run it once, as Administrator.

.DESCRIPTION
  Imports the PUBLIC certificate that `new-cert.ps1` exported into

    Cert:\LocalMachine\Root              - so a chain ending in it is trusted:
                                           WinVerifyTrust / Get-AuthenticodeSignature
                                           read Valid instead of an untrusted root,
                                           and UAC names the publisher
    Cert:\LocalMachine\TrustedPublisher  - so policies that trust only listed
                                           publishers (PowerShell AllSigned,
                                           software restriction) accept it too

  ## Why it is this careful

  A certificate in LocalMachine\Root is trusted by every account on the machine
  for whatever the certificate allows. So this refuses anything that could be
  more than a code-signing trust anchor for Inwire:

    - the thumbprint must equal -Thumbprint, the one `new-cert.ps1` printed.
      An elevated script reading a file from a user-writable directory should
      be bound to the exact certificate the person meant, not to whatever is
      at that path when UAC is answered;
    - the subject must be `CN=Inwire Code Signing (this PC)` and self-signed;
    - EKU exactly Code Signing. A root with no EKU is trusted for everything,
      TLS server authentication included - that would make its key a
      machine-wide interception key;
    - Basic Constraints present with cA=FALSE, so it cannot issue;
    - the file must not carry a private key (a .pfx is refused).

  Idempotent: a store that already has the certificate is left alone.
  -WhatIf is a dry run and needs no elevation. -Remove takes it back out of both
  stores, which is what to do once a real certificate replaces it.

  ## What changes afterwards

  `sign.ps1 -Verify -RequireTrusted <file>` and Get-AuthenticodeSignature report
  Valid for anything Inwire signed; the installer's UAC prompt shows
  "Verified publisher: Inwire Code Signing (this PC)" instead of "Unknown".
  SmartScreen and Smart App Control are NOT affected: neither consults this
  store.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign\trust-cert.ps1 -CerPath C:\path\inwire-signing.cer -Thumbprint 0123...CDEF -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [string]$CerPath,

  [Parameter(Mandatory = $true)]
  [string]$Thumbprint,

  [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
trap {
  [Console]::Error.WriteLine("trust-cert.ps1: $($_.Exception.Message)")
  exit 1
}
# This edition's own module, by path, for the Cert: drive: a PSModulePath
# inherited from PowerShell 7 makes Windows PowerShell autoload pwsh's copy,
# which fails, and Cert: then does not exist. See sign.ps1.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop

$ExpectedSubject = 'CN=Inwire Code Signing (this PC)'
$CodeSigningOid = '1.3.6.1.5.5.7.3.3'
$Stores = @('Root', 'TrustedPublisher')

$full = (Resolve-Path -LiteralPath $CerPath).ProviderPath
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [IO.File]::ReadAllBytes($full))
$want = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()

Write-Host "Certificate file: $full"
Write-Host "  subject     $($cert.Subject)"
Write-Host "  thumbprint  $($cert.Thumbprint)"
Write-Host ("  valid       {0:yyyy-MM-dd} to {1:yyyy-MM-dd}" -f $cert.NotBefore, $cert.NotAfter)

$problems = @()
if ($cert.Thumbprint -ne $want) { $problems += "thumbprint is $($cert.Thumbprint), not the $want you passed" }
if ($cert.HasPrivateKey) { $problems += 'the file carries a private key; pass the public .cer only' }
if ($cert.Subject -ne $ExpectedSubject) { $problems += "subject is '$($cert.Subject)', not '$ExpectedSubject'" }
if ($cert.Issuer -ne $cert.Subject) { $problems += 'it is not self-signed' }
$eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($eku.Count -ne 1 -or ((@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -join ',') -ne $CodeSigningOid)) {
  $problems += 'its EKU is not exactly Code Signing (a root without that restriction is trusted for everything)'
}
$bc = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
if ($bc.Count -ne 1 -or $bc[0].CertificateAuthority) { $problems += 'Basic Constraints is missing or says cA=TRUE' }
if (-not $Remove -and (Get-Date) -gt $cert.NotAfter) { $problems += 'it has expired' }
if ($problems.Count -gt 0) {
  [Console]::Error.WriteLine('trust-cert.ps1: refusing this certificate:')
  $problems | ForEach-Object { [Console]::Error.WriteLine("  - $_") }
  exit 1
}

function Test-Trusted {
  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
  [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object System.Security.Cryptography.Oid($CodeSigningOid)))
  $ok = $chain.Build($cert)
  $status = @($chain.ChainStatus | ForEach-Object { $_.Status }) -join ', '
  return [pscustomobject]@{ Ok = $ok; Status = $(if ($status) { $status } else { 'NoError' }) }
}

$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
  [Console]::Error.WriteLine('trust-cert.ps1: this writes the LOCAL MACHINE stores and must run elevated.')
  [Console]::Error.WriteLine('  Run it from an Administrator PowerShell, or add -WhatIf for a dry run.')
  exit 1
}

$before = Test-Trusted
Write-Host "Chain for code signing, before: $(if ($before.Ok) { 'trusted' } else { "NOT trusted ($($before.Status))" })"

foreach ($name in $Stores) {
  $present = Test-Path -LiteralPath "Cert:\LocalMachine\$name\$($cert.Thumbprint)"
  if ($Remove) {
    if (-not $present) { Write-Host "  LocalMachine\$name  not present; nothing to remove"; continue }
    if ($PSCmdlet.ShouldProcess("Cert:\LocalMachine\$name", "Remove $($cert.Subject) [$($cert.Thumbprint)]")) {
      $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'LocalMachine')
      $store.Open('ReadWrite'); try { $store.Remove($cert) } finally { $store.Close() }
      Write-Host "  LocalMachine\$name  removed"
    }
  } else {
    if ($present) { Write-Host "  LocalMachine\$name  already present"; continue }
    if ($PSCmdlet.ShouldProcess("Cert:\LocalMachine\$name", "Add $($cert.Subject) [$($cert.Thumbprint)]")) {
      $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'LocalMachine')
      $store.Open('ReadWrite'); try { $store.Add($cert) } finally { $store.Close() }
      Write-Host "  LocalMachine\$name  added"
    }
  }
}

if ($WhatIfPreference) {
  Write-Host 'Dry run: nothing was changed.'
  exit 0
}

# Read everything back rather than trusting the Add/Remove calls.
$failed = $false
foreach ($name in $Stores) {
  $present = Test-Path -LiteralPath "Cert:\LocalMachine\$name\$($cert.Thumbprint)"
  if ($present -eq [bool]$Remove) {
    [Console]::Error.WriteLine("  FAIL LocalMachine\$name  certificate is $(if ($present) { 'still present' } else { 'absent' })")
    $failed = $true
  }
}
$after = Test-Trusted
Write-Host "Chain for code signing, after:  $(if ($after.Ok) { 'trusted' } else { "NOT trusted ($($after.Status))" })"
if ($after.Ok -eq [bool]$Remove) {
  # After -Remove the chain may STILL build if the same certificate is in
  # CurrentUser\Root; say so rather than calling it a failure of this script.
  if ($Remove) { Write-Host '  (still trusted through another store - check Cert:\CurrentUser\Root)' }
  else { $failed = $true }
}
if ($failed) { exit 1 }

if (-not $Remove) {
  Write-Host ''
  Write-Host 'Done. To confirm against a signed file:'
  Write-Host ("  powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`" -Verify -RequireTrusted <file>" -f (Join-Path $PSScriptRoot 'sign.ps1'))
}
exit 0
