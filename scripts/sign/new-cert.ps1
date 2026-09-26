<#
.SYNOPSIS
  Creates Inwire's self-signed code-signing certificate for THIS PC. Run once,
  unelevated.

.DESCRIPTION
  The certificate lands in Cert:\CurrentUser\My with a NON-EXPORTABLE private
  key: it can sign on this account on this machine and cannot be copied off it.
  What leaves is the public half, exported to -CerPath, which is the file
  `trust-cert.ps1` (the one elevated step) imports into the machine's Root and
  TrustedPublisher stores.

  Nothing about this certificate is written into the repository. The build finds
  it by thumbprint - `sign.ps1 -Thumbprint`, else $env:INWIRE_SIGN_THUMBPRINT,
  else the untracked `.signing.json` at the repository root, which -WriteConfig
  writes - so a real certificate replaces this one by changing a thumbprint, not
  by touching the build.

  What it is and is not worth: a signature this certificate makes is trusted on
  this PC once `trust-cert.ps1` has run, and on no other machine. SmartScreen and
  Smart App Control do not consult the local Root store the way WinVerifyTrust
  does; see `scripts/sign/sign.ps1` for the detail.

  Refuses to create a second certificate with the same subject: it prints the
  one that exists and exits 0, because "there is a certificate" is the state
  this script exists to reach. Two would leave a thumbprint lookup that depends
  on which one somebody copied.

  ## The key has no interactive protection - accepted, and what that costs

  There is no -KeyProtection: no password and no consent prompt stand between
  the key and a signature. ANY process running as this user can sign with it,
  silently. "Non-exportable" does not change that; it is a flag the key storage
  provider enforces, so it stops Export-PfxCertificate and casual copying, but
  it is a software key in this profile, and code running as this user with the
  right tooling can use it, and likely extract it.

  What such a process gains is narrow, because of what the certificate is
  allowed to be: EKU Code Signing only and cA=FALSE, so it can never vouch for
  a TLS server or issue another certificate. It could sign a binary that THIS
  PC then shows as "Verified publisher: Inwire Code Signing (this PC)" - a
  more convincing UAC prompt - or a script that an AllSigned execution policy
  would accept, because trust-cert.ps1 also puts it in TrustedPublisher. On
  any other machine the signature is worth nothing.

  It was accepted because the alternative breaks the build without buying much:
  a protected key prompts on EVERY signature - four files in `npm run pack`,
  two more in ISCC, one for the agent - and a prompt cannot be answered from a
  non-interactive build at all. And a process already running as this user can
  already do almost anything this user can; the one thing it gains is borrowing
  the name. If that trade stops being acceptable: `trust-cert.ps1 -Remove`
  withdraws the trust in one step, and a real certificate (or Azure Artifact
  Signing, whose key never leaves the service) replaces this one by changing a
  thumbprint.

.PARAMETER CerPath
  Where to write the PUBLIC certificate (DER .cer). Keep it outside the
  repository; `scripts/sign/signing.ts` fails on a committed .cer.

.PARAMETER WriteConfig
  Also write the thumbprint to `.signing.json` at the repository root
  (gitignored), so `npm run pack` and the Inno build sign without further setup.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign\new-cert.ps1 -CerPath $env:USERPROFILE\inwire-signing.cer -WriteConfig
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$CerPath,

  [switch]$WriteConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This edition's own module, by path, for the Cert: drive: a PSModulePath
# inherited from PowerShell 7 makes Windows PowerShell autoload pwsh's copy,
# which fails, and Cert: then does not exist. See sign.ps1.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop

$Subject = 'CN=Inwire Code Signing (this PC)'
$CodeSigningOid = '1.3.6.1.5.5.7.3.3'
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ConfigPath = Join-Path $RepoRoot '.signing.json'

# **Unelevated, and that is not a preference.** CurrentUser\My is per account,
# and an elevated shell is not always the same account: over-the-shoulder UAC
# (a standard user typing an administrator's password) runs as the
# administrator, so the key would land in a profile the build never runs as.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Refusing to run elevated. Run this from an ordinary (unelevated) PowerShell as the"
  Write-Host "account that builds Inwire - the private key goes into THAT account's store."
  exit 1
}

function Export-PublicCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
  $dir = Split-Path -Parent ([IO.Path]::GetFullPath($CerPath))
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  # DER, public half only: Export-Certificate never writes a private key.
  Export-Certificate -Cert $Cert -FilePath $CerPath -Type CERT -Force | Out-Null
  Write-Host "Public certificate: $([IO.Path]::GetFullPath($CerPath))"
}

function Write-SigningConfig([string]$Thumbprint) {
  $json = [ordered]@{ thumbprint = $Thumbprint; subject = $Subject } | ConvertTo-Json
  # No BOM: Windows PowerShell's -Encoding UTF8 writes one, and a BOM is not
  # something every JSON reader skips.
  [IO.File]::WriteAllText($ConfigPath, $json + "`n", (New-Object Text.UTF8Encoding($false)))
  Write-Host "Wrote $ConfigPath (gitignored)."
}

$existing = @(Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $Subject })
if ($existing.Count -gt 0) {
  Write-Host "A certificate with subject '$Subject' already exists; not creating another."
  foreach ($c in $existing) {
    Write-Host ("  thumbprint {0}  expires {1:yyyy-MM-dd}  private key: {2}" -f $c.Thumbprint, $c.NotAfter, $c.HasPrivateKey)
  }
  if ($existing.Count -gt 1) {
    Write-Host "More than one exists. Pick one and pass its thumbprint to sign.ps1; delete the rest with certmgr.msc."
    exit 1
  }
  Export-PublicCert $existing[0]
  if ($WriteConfig) { Write-SigningConfig $existing[0].Thumbprint }
  Write-Host "Thumbprint: $($existing[0].Thumbprint)"
  exit 0
}

$cert = New-SelfSignedCertificate `
  -Subject $Subject `
  -FriendlyName 'Inwire Code Signing (this PC)' `
  -Type Custom `
  -KeyAlgorithm RSA -KeyLength 3072 `
  -HashAlgorithm SHA256 `
  -KeyUsage DigitalSignature `
  -KeyExportPolicy NonExportable `
  -Provider 'Microsoft Software Key Storage Provider' `
  -NotAfter (Get-Date).AddYears(5) `
  -CertStoreLocation Cert:\CurrentUser\My `
  -TextExtension @(
    # `-Type Custom` rather than `CodeSigningCert`, so the EKU below is the
    # only one and is not added twice.
    #
    # EKU: code signing and nothing else. This certificate becomes a trust
    # anchor in LocalMachine\Root, and a root with no EKU is trusted for
    # EVERYTHING - including TLS server authentication, which would make its
    # key a machine-wide interception key. Windows intersects a chain's EKUs
    # with the root's, so this bounds what the anchor can ever vouch for.
    "2.5.29.37={text}$CodeSigningOid",
    # Basic Constraints, critical, cA=FALSE: an end entity that cannot issue.
    '2.5.29.19={critical}{text}ca=0'
  )

# Read back what was made, rather than trusting the parameters. Every one of
# these is a property trust-cert.ps1 re-checks before it will import the file.
$problems = @()
if ($cert.Subject -ne $Subject) { $problems += "subject is '$($cert.Subject)'" }
if ($cert.Issuer -ne $Subject) { $problems += 'not self-signed' }
if (-not $cert.HasPrivateKey) { $problems += 'no private key' }
$keySize = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert).KeySize
if ($keySize -ne 3072) { $problems += "key size $keySize" }
if ($cert.SignatureAlgorithm.FriendlyName -notmatch 'sha256') { $problems += "signature algorithm $($cert.SignatureAlgorithm.FriendlyName)" }
$eku = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
if ((-not $eku) -or ((@($eku.EnhancedKeyUsages | ForEach-Object { $_.Value }) -join ',') -ne $CodeSigningOid)) { $problems += 'EKU is not exactly Code Signing' }
$bc = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
if ((-not $bc) -or $bc.CertificateAuthority) { $problems += 'basic constraints missing or cA=TRUE' }
$ku = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' }
if ((-not $ku) -or ($ku.KeyUsages -ne [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)) { $problems += 'key usage is not exactly DigitalSignature' }

# Non-exportable is asserted by trying: the key's own export policy, read back.
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($rsa -is [System.Security.Cryptography.RSACng]) {
  $policy = $rsa.Key.ExportPolicy
  if ($policy -ne [System.Security.Cryptography.CngExportPolicies]::None) { $problems += "key export policy is '$policy'" }
} else {
  $problems += "private key is not a CNG key ($($rsa.GetType().FullName)); export policy not verifiable"
}

if ($problems.Count -gt 0) {
  Write-Host "The certificate was created but is not what was asked for:"
  $problems | ForEach-Object { Write-Host "  - $_" }
  Write-Host "Thumbprint $($cert.Thumbprint). Delete it (certmgr.msc, Personal) before running this again."
  exit 1
}

Write-Host "Created $Subject in Cert:\CurrentUser\My"
Write-Host ("  RSA 3072, SHA-256, valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}, private key NOT exportable" -f $cert.NotBefore, $cert.NotAfter)
Export-PublicCert $cert
if ($WriteConfig) { Write-SigningConfig $cert.Thumbprint }
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host ''
Write-Host 'Next, once, from an ELEVATED PowerShell:'
Write-Host ("  powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`" -CerPath `"{1}`" -Thumbprint {2}" -f `
  (Join-Path $PSScriptRoot 'trust-cert.ps1'), [IO.Path]::GetFullPath($CerPath), $cert.Thumbprint)
exit 0
