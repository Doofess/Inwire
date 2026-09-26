<#
.SYNOPSIS
  Refuses a signed installer whose payload is not signed. Prints its verdict on
  the FIRST line.

.DESCRIPTION
  A signed Inwire-Setup.exe around an unsigned Inwire.exe is worse than an
  unsigned installer: the signature on the outside is what a person checks, and
  it vouches for nothing inside. Inno's SignTool signs only what Inno makes -
  Setup and the uninstaller - so `/DSIGN` on its own would happily wrap a stale
  unsigned pack, or an agent built with no certificate configured.

  So every PE file the installer will carry must be, per `sign.ps1 -Verify`,
  either

    - signed by the configured certificate and whole (digest intact, SHA-256,
      RFC 3161 timestamp; an untrusted root is accepted for a self-signed
      certificate only), or
    - validly signed by somebody else (Microsoft's d3dcompiler_47.dll).

  Directories are searched recursively and a file is a PE file by its CONTENT -
  an MZ header whose e_lfanew points at "PE\0\0" - not by its extension, so a
  `.node` addon or anything else Windows would load is not missed because of
  what it is called. A directory with no PE file in it is a refusal: an empty
  release\win-unpacked is not a signed payload.

  ## Who runs it

  `installer/setup.iss` runs it at compile time whenever /DSIGN is given, before
  a byte is compressed, and turns anything but a pass into a compile error. That
  is why the verdict comes first: ISPP's ExecAndGetFirstLine is the only way the
  preprocessor sees a console program's output, and it sees one line.

    INWIRE-PAYLOAD-OK <n> PE file(s) signed
    INWIRE-PAYLOAD-REFUSED <k> of <n> PE file(s) fail verification: <file> (<reason>), ...
    INWIRE-PAYLOAD-REFUSED payload missing: <path> (...)

  The detail follows, one line per file. `npm run dist:signed` also runs this
  before ISCC, so the same detail is on screen rather than behind a one-line
  compile error.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign\verify-payload.ps1 release\win-unpacked agent-rs\dist\inwire-agent-windows.exe
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string[]]$Path,

  # `-File` mode has no array syntax; see sign.ps1.
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$MorePaths,

  # Demand Valid, not merely intact: for after trust-cert.ps1 has run.
  [switch]$RequireTrusted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Anything unexpected is still a verdict, and still on the first line: the
# caller reading one line must never see a PowerShell error record instead.
trap {
  Write-Output "INWIRE-PAYLOAD-REFUSED verify-payload.ps1 failed: $($_.Exception.Message)"
  exit 1
}

function Test-PeFile([string]$file) {
  $fs = $null
  try {
    $fs = [IO.File]::OpenRead($file)
    if ($fs.Length -lt 0x40) { return $false }
    $br = New-Object IO.BinaryReader($fs)
    if ($br.ReadUInt16() -ne 0x5A4D) { return $false }             # "MZ"
    $fs.Position = 0x3C
    $pe = $br.ReadInt32()
    if ($pe -le 0 -or $pe + 4 -gt $fs.Length) { return $false }
    $fs.Position = $pe
    return $br.ReadUInt32() -eq 0x00004550                           # "PE\0\0"
  } finally {
    if ($fs) { $fs.Dispose() }
  }
}

$missing = @()
$files = @()
foreach ($p in @($Path) + @($MorePaths)) {
  if (-not $p) { continue }
  if (Test-Path -LiteralPath $p -PathType Container) {
    $found = @(Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object { Test-PeFile $_.FullName } | ForEach-Object { $_.FullName })
    if ($found.Count -eq 0) { $missing += "$p (no PE files in it)" }
    $files += $found
  } elseif (Test-Path -LiteralPath $p -PathType Leaf) {
    $files += (Resolve-Path -LiteralPath $p).ProviderPath
  } else {
    $missing += "$p (does not exist)"
  }
}

if ($missing.Count -gt 0) {
  Write-Output "INWIRE-PAYLOAD-REFUSED payload missing: $($missing -join ', ')"
  exit 1
}

# The judgement is sign.ps1's, in its own process, under this same PowerShell,
# so there is one definition of "signed" in the build. Its stdout and stderr are
# both captured: its FAIL lines go to stderr.
$sign = Join-Path $PSScriptRoot 'sign.ps1'
$exe = (Get-Process -Id $PID).Path
$extra = @()
if ($RequireTrusted) { $extra += '-RequireTrusted' }
$ErrorActionPreference = 'Continue'
$lines = @(& $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $sign -Verify @extra -Path @files 2>&1 |
  ForEach-Object { "$_" })
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

$refused = @()
foreach ($l in $lines) {
  $m = [regex]::Match($l, '^\s*FAIL\s+(\S+)\s+(.*)$')
  if (-not $m.Success) { continue }
  # "0x800B0100 TRUST_E_NOSIGNATURE (not signed); ..." reads best as the
  # parenthetical; anything else is cut short rather than dropped.
  $detail = $m.Groups[2].Value
  $named = [regex]::Match($detail, '^0x[0-9A-F]{8}\s+([A-Z0-9_]+)(?:\s+\(([^)]*)\))?')
  $reason = if ($named.Success -and $named.Groups[2].Success) { $named.Groups[2].Value }
            elseif ($named.Success) { $named.Groups[1].Value }
            elseif ($detail.Length -gt 80) { $detail.Substring(0, 80) + '...' }
            else { $detail }
  $refused += "$($m.Groups[1].Value) ($reason)"
}

if ($code -eq 0 -and $refused.Count -eq 0) {
  Write-Output "INWIRE-PAYLOAD-OK $($files.Count) PE file(s) signed"
} else {
  if ($refused.Count -eq 0) { $refused += "sign.ps1 -Verify exited $code" }
  Write-Output ("INWIRE-PAYLOAD-REFUSED {0} of {1} PE file(s) fail verification: {2}" -f $refused.Count, $files.Count, ($refused -join ', '))
}
$lines | ForEach-Object { Write-Output $_ }
if ($code -ne 0 -or $refused.Count -gt 0) { exit 1 }
exit 0
