# Install-Inwire.Core.psm1
#
# All the logic of the Inwire PowerShell bootstrap. The entry script
# (install-inwire.ps1) is thin; the build (scripts/distribution/build-bootstrap.ps1)
# inlines this file into one signed standalone script, so nothing here may rely
# on being a module: no Export-ModuleMember, no `using`, no path relative to the
# script's own folder, and every function is reachable by name.
#
# Compatible with Windows PowerShell 5.1 (.NET Framework 4.x) and PowerShell 7.
# ASCII only: Windows PowerShell reads a BOM-less file as ANSI.
#
# The decision this implements is docs/decisions/0069. The descriptor rules are
# a line-for-line mirror of scripts/distribution/release.ts, and
# distribution/fixtures/release-vectors.json is the answer key both run.
#
# Rules this file keeps:
#   - It never turns certificate validation off, never changes the execution
#     policy, and never evaluates text as code.
#   - Setup is run only after the file has the declared size, the declared
#     SHA-256 AND an Authenticode signature that is Valid and made by a pinned
#     certificate. A failure of any of those stops before elevation is asked for.
#   - A raw installer exit code is never read as success.

Set-StrictMode -Version Latest

$script:InwireMaxDownloadBytes = 536870912      # 512 MiB, MAX_DOWNLOAD_BYTES in electron/updateCenter/manifest.ts
$script:InwireMaxDescriptorBytes = 1048576      # 1 MiB
$script:InwireDownloadTimeoutSeconds = 900      # 15 minutes
$script:InwireDescriptorTimeoutSeconds = 30
$script:InwireInstallTimeoutMs = 1800000        # 30 minutes
$script:InwireMaxRedirects = 5
$script:InwireChunkBytes = 262144
# The uninstall key Inno registers. The doubled closing brace is real: the AppId
# is written `{{GUID}` in setup.iss, Inno reads `{{` as an escaped brace, and
# the key is named after what remains (see InstalledProductVersion there).
$script:InwireUninstallKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F384C012-C351-40DE-B9E9-62AC2B6ED001}}_is1'
$script:InwireInstallerFileName = 'Inwire-Setup.exe'
$script:InwireLogFileName = 'setup.log'
$script:InwireInstallerSwitches = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS'
$script:InwireWrapperFault = 70001
$script:InwireProd = $null

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

# A field of a hashtable or an object, or $null. Always returned wrapped, so a
# one-element array is not unrolled into its element on the way out.
function Get-InwireField {
  param($Object, [string]$Name)
  if ($null -eq $Object) { return $null }
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return ,$Object[$Name] }
    return $null
  }
  $p = $Object.PSObject.Properties[$Name]
  if ($null -eq $p) { return $null }
  return ,$p.Value
}

# The innermost exception, with PowerShell's and Task's wrappers peeled off.
function Get-InwireRootException {
  param($Exception)
  $e = $Exception
  $n = 0
  while ($null -ne $e -and $null -ne $e.InnerException -and $n -lt 8) {
    $e = $e.InnerException
    $n++
  }
  return $e
}

# One line of text for a failure. Never the whole exception object: that can
# carry a proxy address or a path the person did not mean to paste.
function Get-InwireErrorText {
  param($ErrorRecord)
  $root = $null
  if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
    $root = Get-InwireRootException $ErrorRecord.Exception
  } else {
    $root = Get-InwireRootException $ErrorRecord
  }
  if ($null -eq $root) { return 'unknown error' }
  $t = ($root.Message -replace '[\r\n]+', ' ').Trim()
  if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
  return $t
}

function Compare-InwireVersion {
  param([string]$A, [string]$B)
  $pa = $A.Split('.')
  $pb = $B.Split('.')
  for ($i = 0; $i -lt 3; $i++) {
    $x = [int]$pa[$i]
    $y = [int]$pb[$i]
    if ($x -lt $y) { return -1 }
    if ($x -gt $y) { return 1 }
  }
  return 0
}

# ---------------------------------------------------------------------------
# The descriptor and the policy (mirror of scripts/distribution/release.ts)
# ---------------------------------------------------------------------------

# \z, not $: .NET's $ also matches before a trailing newline. [0-9], not \d:
# \d matches other scripts' digits.
function Test-InwireVersionText {
  param($Value)
  return (($Value -is [string]) -and ($Value -cmatch '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\z'))
}

function Test-InwireRecord {
  param($Value)
  if ($null -eq $Value) { return $false }
  if ($Value -is [string]) { return $false }
  if ($Value -is [System.Array]) { return $false }
  if ($Value -is [ValueType]) { return $false }
  if ($Value -is [System.Collections.IDictionary]) { return $true }
  return ($Value -is [System.Management.Automation.PSCustomObject])
}

function Get-InwireKeys {
  param($Record)
  if ($Record -is [System.Collections.IDictionary]) {
    return @($Record.Keys | ForEach-Object { [string]$_ })
  }
  return @($Record.PSObject.Properties | ForEach-Object { $_.Name })
}

# Unknown keys are rejected, not ignored, and the names are compared with their
# case: JSON keys are case-sensitive and PowerShell's property lookup is not.
function Test-InwireExactKeys {
  param($Record, [string[]]$Keys)
  $actual = @(Get-InwireKeys $Record)
  if ($actual.Count -ne $Keys.Count) { return $false }
  foreach ($k in $Keys) {
    if (-not ($actual -ccontains $k)) { return $false }
  }
  return $true
}

function Test-InwireNumber {
  param($Value)
  if ($null -eq $Value) { return $false }
  if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or
      $Value -is [single] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [uint32] -or
      $Value -is [uint64] -or $Value -is [byte]) { return $true }
  return ($Value.GetType().FullName -ceq 'System.Numerics.BigInteger')
}

function Test-InwireIntegerInRange {
  param($Value, [double]$Min, [double]$Max)
  if (-not (Test-InwireNumber $Value)) { return $false }
  $d = [double]$Value
  if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $false }
  if ([Math]::Floor($d) -ne $d) { return $false }
  return ($d -ge $Min -and $d -le $Max)
}

# Whether a URL is acceptable under a host allowlist: https, no credentials, no
# explicit port, no fragment, and the host equal to an allowed one after
# lowercasing - never a suffix match. Any colon in the raw authority is refused
# (a written-out :443 reads back as no port in some parsers and as 443 in
# others). Stricter than the TypeScript rule only at the edges nothing in a
# release uses: anything outside printable ASCII, and a percent-encoded host.
function Test-InwireUrl {
  param($Value, $AllowedHosts)
  if ($Value -isnot [string]) { return $false }
  if ($Value -cnotmatch '^[\x21-\x7e]+\z') { return $false }
  $uri = $null
  if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $false }
  if ($uri.Scheme -cne 'https') { return $false }
  $m = [regex]::Match($Value, '^[Hh][Tt][Tt][Pp][Ss]://([^/?#]*)')
  if (-not $m.Success) { return $false }
  $authority = $m.Groups[1].Value
  if ($authority.Contains(':') -or $authority.Contains('@')) { return $false }
  if ($Value -cmatch '#.') { return $false }
  return (@($AllowedHosts) -ccontains $authority.ToLowerInvariant())
}

# Parses the policy. $null means "no usable policy"; a caller stops.
function Read-InwirePolicy {
  param($Object)
  try {
    if (-not (Test-InwireRecord $Object)) { return $null }
    if (-not (Test-InwireExactKeys $Object @('schema', 'descriptorUrl', 'allowedHosts', 'publisherCertificateSha256', 'desktopPackageId', 'endpointAvailable'))) { return $null }
    $schema = Get-InwireField $Object 'schema'
    if (-not (Test-InwireNumber $schema) -or [double]$schema -ne 1) { return $null }

    $hosts = Get-InwireField $Object 'allowedHosts'
    if ($hosts -isnot [System.Array] -or $hosts.Count -eq 0) { return $null }
    foreach ($h in $hosts) {
      if ($h -isnot [string]) { return $null }
      if ($h -cnotmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\z') { return $null }
    }

    $pins = Get-InwireField $Object 'publisherCertificateSha256'
    if ($pins -isnot [System.Array]) { return $null }
    $seen = @{}
    foreach ($p in $pins) {
      if ($p -isnot [string]) { return $null }
      if ($p -cnotmatch '^[0-9a-f]{64}\z') { return $null }
      if ($seen.ContainsKey($p)) { return $null }
      $seen[$p] = $true
    }

    $url = Get-InwireField $Object 'descriptorUrl'
    if (-not (Test-InwireUrl $url ([string[]]@($hosts)))) { return $null }

    $pkg = Get-InwireField $Object 'desktopPackageId'
    if ($pkg -isnot [string]) { return $null }
    if ($pkg -ne '' -and $pkg -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9.-]*\z') { return $null }

    $endpoint = Get-InwireField $Object 'endpointAvailable'
    if ($endpoint -isnot [bool]) { return $null }

    return @{
      DescriptorUrl = [string]$url
      AllowedHosts = [string[]]@($hosts)
      PublisherCertificateSha256 = [string[]]@($pins)
      DesktopPackageId = [string]$pkg
      EndpointAvailable = [bool]$endpoint
    }
  } catch {
    return $null
  }
}

function Read-InwireArtifact {
  param($Raw, $Policy)
  if (-not (Test-InwireRecord $Raw)) { return $null }
  if (-not (Test-InwireExactKeys $Raw @('product', 'version', 'architecture', 'url', 'sizeBytes', 'sha256'))) { return $null }
  $product = Get-InwireField $Raw 'product'
  $version = Get-InwireField $Raw 'version'
  $arch = Get-InwireField $Raw 'architecture'
  $url = Get-InwireField $Raw 'url'
  $size = Get-InwireField $Raw 'sizeBytes'
  $sha = Get-InwireField $Raw 'sha256'

  if ($product -isnot [string] -or -not (@('Desktop', 'EndpointAgent') -ccontains $product)) { return $null }
  if (-not (Test-InwireVersionText $version)) { return $null }
  if ($arch -isnot [string] -or $arch -cne 'x64') { return $null }
  if (-not (Test-InwireUrl $url $Policy.AllowedHosts)) { return $null }
  if ($sha -isnot [string] -or $sha -notmatch '^[0-9a-f]{64}\z') { return $null }
  if (-not (Test-InwireIntegerInRange $size 1 $script:InwireMaxDownloadBytes)) { return $null }

  return @{
    Product = [string]$product
    Version = [string]$version
    Architecture = 'x64'
    Url = [string]$url
    SizeBytes = [long][double]$size
    Sha256 = ([string]$sha).ToLowerInvariant()
  }
}

# Parses and validates a descriptor against a policy. $null is "no answer"; a
# caller stops and does not fall back to anything.
function Read-InwireRelease {
  param($Object, $Policy)
  try {
    if ($null -eq $Policy) { return $null }
    if (-not (Test-InwireRecord $Object)) { return $null }
    if (-not (Test-InwireExactKeys $Object @('schema', 'artifacts'))) { return $null }
    $schema = Get-InwireField $Object 'schema'
    if (-not (Test-InwireNumber $schema) -or [double]$schema -ne 1) { return $null }
    $arts = Get-InwireField $Object 'artifacts'
    if ($arts -isnot [System.Array] -or $arts.Count -eq 0) { return $null }

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($raw in $arts) {
      $row = Read-InwireArtifact $raw $Policy
      if ($null -eq $row) { return $null }
      foreach ($have in $rows) { if ($have.Product -ceq $row.Product) { return $null } }
      if ($row.Product -ceq 'EndpointAgent' -and -not $Policy.EndpointAvailable) { return $null }
      $rows.Add($row)
    }
    $desktop = $false
    foreach ($have in $rows) { if ($have.Product -ceq 'Desktop') { $desktop = $true } }
    if (-not $desktop) { return $null }
    return @{ Schema = 1; Artifacts = $rows.ToArray() }
  } catch {
    return $null
  }
}

# The product's row when no version was asked for or when it is exactly the one
# asked for. Equality only: the descriptor offers one build per product.
function Select-InwireArtifact {
  param($Release, [string]$Product, $Version)
  if ($null -eq $Release) { return $null }
  foreach ($a in $Release.Artifacts) {
    if ($a.Product -ceq $Product) {
      if ([string]::IsNullOrEmpty([string]$Version) -or $a.Version -ceq [string]$Version) { return $a }
      return $null
    }
  }
  return $null
}

# ---------------------------------------------------------------------------
# Publisher check
# ---------------------------------------------------------------------------

# Status must be Valid AND the signer certificate's SHA-256 (over its DER
# encoding), as lowercase hex, must be in the pins. A valid signature by anyone
# else is a failure: "signed" is not "signed by us".
function Test-InwireSignature {
  param($Signature, $Pins)
  if ($null -eq $Signature) { return @{ Ok = $false; Reason = 'The installer has no signature information.' } }
  $status = [string](Get-InwireField $Signature 'Status')
  if ($status -cne 'Valid') {
    return @{ Ok = $false; Reason = ('The installer signature is not valid (status ' + $status + ').') }
  }
  $cert = Get-InwireField $Signature 'SignerCertificate'
  if ($null -eq $cert) { return @{ Ok = $false; Reason = 'The installer has no signer certificate.' } }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hex = (($sha.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally {
    $sha.Dispose()
  }
  if (@($Pins) -ccontains $hex) { return @{ Ok = $true; Reason = '' } }
  return @{ Ok = $false; Reason = ('The installer is signed by a certificate this bootstrap does not trust (SHA-256 ' + $hex + ').') }
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

function New-InwireFailure {
  param([string]$Reason, [bool]$Transient = $false, [bool]$Integrity = $false)
  return @{ Ok = $false; Reason = $Reason; Transient = $Transient; Integrity = $Integrity }
}

# Network faults worth another try: timeouts, I/O, socket and HTTP-layer errors.
function Test-InwireTransientException {
  param($Exception)
  $e = $Exception
  $n = 0
  while ($null -ne $e -and $n -lt 8) {
    if ($e -is [System.OperationCanceledException] -or $e -is [System.TimeoutException] -or
        $e -is [System.IO.IOException] -or $e -is [System.Net.WebException] -or
        $e -is [System.Net.Sockets.SocketException] -or $e.GetType().Name -ceq 'HttpRequestException') { return $true }
    $e = $e.InnerException
    $n++
  }
  return $false
}

function Resolve-InwireRedirect {
  param([string]$Current, [string]$Location)
  if ($Location -cmatch '^[A-Za-z][A-Za-z0-9+.-]*:') { return $Location }
  if ($Location.StartsWith('//', [StringComparison]::Ordinal)) { return ('https:' + $Location) }
  $m = [regex]::Match($Current, '^(https://[^/?#]*)([^?#]*)')
  if (-not $m.Success) { return $null }
  $origin = $m.Groups[1].Value
  $path = $m.Groups[2].Value
  if ($Location.StartsWith('/', [StringComparison]::Ordinal)) { return ($origin + $Location) }
  if ($Location.StartsWith('?', [StringComparison]::Ordinal)) { return ($origin + $path + $Location) }
  $dir = $path.Substring(0, $path.LastIndexOf('/') + 1)
  if ($dir.Length -eq 0) { $dir = '/' }
  $merged = $origin + $dir + $Location
  $uri = $null
  if (-not [Uri]::TryCreate($merged, [UriKind]::Absolute, [ref]$uri)) { return $null }
  return $uri.AbsoluteUri
}

function Close-InwireResponse {
  param($Response)
  if ($null -eq $Response) { return }
  try {
    $d = Get-InwireField $Response 'Dispose'
    if ($d -is [scriptblock]) { & $d }
  } catch { }
  try {
    $s = Get-InwireField $Response 'Stream'
    if ($null -ne $s) { $s.Dispose() }
  } catch { }
}

# One GET with manual redirects. Every URL, the first and each Location, must
# pass the same rule as the descriptor's. Returns Ok with the 200 response (the
# caller closes it) or a failure.
function Invoke-InwireRequest {
  param([string]$Url, $Policy, [scriptblock]$Send, $Token)
  $current = $Url
  $hops = 0
  while ($true) {
    if (-not (Test-InwireUrl $current $Policy.AllowedHosts)) {
      return (New-InwireFailure 'A download address is not https on an allowed host.')
    }
    $resp = $null
    try {
      $resp = & $Send $current $Token
    } catch {
      $root = Get-InwireRootException $_.Exception
      return (New-InwireFailure ('Network error: ' + (Get-InwireErrorText $_)) (Test-InwireTransientException $root))
    }
    if ($null -eq $resp) { return (New-InwireFailure 'The server gave no response.' $true) }
    $code = [int](Get-InwireField $resp 'StatusCode')
    if (@(301, 302, 303, 307, 308) -contains $code) {
      $location = [string](Get-InwireField $resp 'Location')
      Close-InwireResponse $resp
      if ($hops -ge $script:InwireMaxRedirects) { return (New-InwireFailure 'Too many redirects.') }
      if ([string]::IsNullOrEmpty($location)) { return (New-InwireFailure 'A redirect named no location.') }
      $next = Resolve-InwireRedirect $current $location
      if ($null -eq $next) { return (New-InwireFailure 'A redirect could not be followed.') }
      $hops++
      $current = $next
      continue
    }
    if ($code -ne 200) {
      Close-InwireResponse $resp
      if ($code -ge 500) { return (New-InwireFailure ('The server answered HTTP ' + $code + '.') $true) }
      return (New-InwireFailure ('The server answered HTTP ' + $code + '.'))
    }
    return @{ Ok = $true; Response = $resp }
  }
}

function Get-InwireHex {
  param([byte[]]$Bytes)
  return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

# Downloads Url to DestPath. Refuses anything but the declared size and SHA-256:
# the Content-Length must be present and equal, the body is counted as it
# arrives and the read stops the moment it exceeds the declared size.
function Receive-InwireFile {
  param([string]$Url, [string]$DestPath, [long]$SizeBytes, [string]$Sha256, $Policy, [scriptblock]$Send,
        [int]$TimeoutSeconds = 900)
  if ($SizeBytes -le 0 -or $SizeBytes -gt $script:InwireMaxDownloadBytes) {
    return (New-InwireFailure 'The declared download size is outside the allowed range.')
  }
  $partial = $DestPath + '.partial'
  $cts = New-Object System.Threading.CancellationTokenSource
  $cts.CancelAfter([int]($TimeoutSeconds * 1000))
  $resp = $null
  $fs = $null
  $sha = $null
  try {
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    $req = Invoke-InwireRequest $Url $Policy $Send $cts.Token
    if (-not $req.Ok) { return $req }
    $resp = $req.Response
    $length = Get-InwireField $resp 'ContentLength'
    if ($null -eq $length) { return (New-InwireFailure 'The server did not declare a Content-Length.') }
    if ([long]$length -ne $SizeBytes) {
      return (New-InwireFailure ('The server declared ' + $length + ' bytes, not the published ' + $SizeBytes + '.') $false $true)
    }
    $stream = Get-InwireField $resp 'Stream'
    if ($null -eq $stream) { return (New-InwireFailure 'The server sent no body.' $true) }

    $fs = New-Object System.IO.FileStream($partial, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $buf = New-Object byte[] $script:InwireChunkBytes
    [long]$total = 0
    while ($true) {
      $n = $stream.ReadAsync($buf, 0, $buf.Length, $cts.Token).GetAwaiter().GetResult()
      if ($n -le 0) { break }
      $total += $n
      if ($total -gt $SizeBytes) {
        return (New-InwireFailure 'The download is longer than the published size.' $false $true)
      }
      [void]$sha.TransformBlock($buf, 0, $n, $null, 0)
      $fs.Write($buf, 0, $n)
    }
    [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    $fs.Close()
    $fs = $null
    if ($total -ne $SizeBytes) {
      return (New-InwireFailure ('The download is ' + $total + ' bytes, not the published ' + $SizeBytes + '.') $false $true)
    }
    $got = Get-InwireHex $sha.Hash
    if ($got -cne $Sha256.ToLowerInvariant()) {
      return (New-InwireFailure 'The download does not match the published SHA-256.' $false $true)
    }
    if (Test-Path -LiteralPath $DestPath) { Remove-Item -LiteralPath $DestPath -Force }
    [System.IO.File]::Move($partial, $DestPath)
    return @{ Ok = $true; Reason = ''; Transient = $false; Integrity = $false }
  } catch {
    $root = Get-InwireRootException $_.Exception
    $timedOut = ($root -is [System.OperationCanceledException])
    $text = if ($timedOut) { 'The download timed out.' } else { 'Download error: ' + (Get-InwireErrorText $_) }
    return (New-InwireFailure $text (Test-InwireTransientException $root))
  } finally {
    if ($null -ne $fs) { $fs.Dispose() }
    if ($null -ne $sha) { $sha.Dispose() }
    Close-InwireResponse $resp
    $cts.Dispose()
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue }
  }
}

# The descriptor: the same request rules, a 1 MiB cap, no Content-Length needed.
function Receive-InwireText {
  param([string]$Url, [int]$MaxBytes, [int]$TimeoutSeconds, $Policy, [scriptblock]$Send)
  $cts = New-Object System.Threading.CancellationTokenSource
  $cts.CancelAfter([int]($TimeoutSeconds * 1000))
  $resp = $null
  try {
    $req = Invoke-InwireRequest $Url $Policy $Send $cts.Token
    if (-not $req.Ok) { return $req }
    $resp = $req.Response
    $length = Get-InwireField $resp 'ContentLength'
    if ($null -ne $length -and [long]$length -gt $MaxBytes) {
      return (New-InwireFailure 'The release descriptor is larger than the allowed size.')
    }
    $stream = Get-InwireField $resp 'Stream'
    if ($null -eq $stream) { return (New-InwireFailure 'The server sent no body.' $true) }
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 65536
    while ($true) {
      $n = $stream.ReadAsync($buf, 0, $buf.Length, $cts.Token).GetAwaiter().GetResult()
      if ($n -le 0) { break }
      if (($ms.Length + $n) -gt $MaxBytes) {
        return (New-InwireFailure 'The release descriptor is larger than the allowed size.')
      }
      $ms.Write($buf, 0, $n)
    }
    $bytes = $ms.ToArray()
    $start = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes, $start, $bytes.Length - $start)
    return @{ Ok = $true; Text = $text; Reason = ''; Transient = $false }
  } catch {
    $root = Get-InwireRootException $_.Exception
    $text = if ($root -is [System.OperationCanceledException]) { 'The request timed out.' } else { 'Network error: ' + (Get-InwireErrorText $_) }
    return (New-InwireFailure $text (Test-InwireTransientException $root))
  } finally {
    Close-InwireResponse $resp
    $cts.Dispose()
  }
}

# The real transport: one HttpClient, redirects off (they are followed by hand,
# under the URL rule), the system proxy with the user's default credentials.
# Certificate validation is the platform's, untouched. TLS 1.2 is enabled by
# adding it to what is already on, for Windows PowerShell 5.1's older default.
function New-InwireHttpClient {
  Add-Type -AssemblyName System.Net.Http
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AllowAutoRedirect = $false
  $handler.UseProxy = $true
  $proxy = [Net.WebRequest]::GetSystemWebProxy()
  $proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
  $handler.Proxy = $proxy
  $client = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
  $client.DefaultRequestHeaders.UserAgent.ParseAdd('InwireBootstrap/1')
  return $client
}

function Send-InwireHttp {
  param([string]$Url, $Token)
  if ($null -eq $script:InwireProd.Client) { $script:InwireProd.Client = New-InwireHttpClient }
  $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Url)
  $resp = $script:InwireProd.Client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $Token).GetAwaiter().GetResult()
  $location = $null
  if ($null -ne $resp.Headers.Location) { $location = $resp.Headers.Location.OriginalString }
  $length = $resp.Content.Headers.ContentLength
  $stream = $null
  if ([int]$resp.StatusCode -eq 200) { $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult() }
  $dispose = { $resp.Dispose(); $req.Dispose() }.GetNewClosure()
  return @{ StatusCode = [int]$resp.StatusCode; Location = $location; ContentLength = $length; Stream = $stream; Dispose = $dispose }
}

# ---------------------------------------------------------------------------
# Running setup
# ---------------------------------------------------------------------------

function Get-InwireInstallerArguments {
  param([string]$LogPath)
  if ($LogPath.Contains('"')) { throw 'The log path contains a double quote.' }
  return ($script:InwireInstallerSwitches + ' "/LOG=' + $LogPath + '"')
}

# The script the elevated PowerShell runs. It is a constant: the installer and
# log paths reach it in environment variables, never on the command line, so
# nothing is quoted or interpolated into anything privileged
# (electron/updateCenter/elevate.ts keeps the same rule). It checks the file
# names, never reads a missing exit code as success, and uses a code of its own
# (70001) for its own faults.
$script:InwireElevatedScript = (@(
  '$ErrorActionPreference = "Stop"',
  'try {',
  '  $exe = $env:INWIRE_BOOT_INSTALLER',
  '  $log = $env:INWIRE_BOOT_LOG',
  '  if (-not $exe -or -not $log) { exit 70001 }',
  '  if ([IO.Path]::GetFileName($exe) -cne "Inwire-Setup.exe") { exit 70001 }',
  '  if ([IO.Path]::GetFileName($log) -cne "setup.log") { exit 70001 }',
  '  if ($log.Contains([string][char]34)) { exit 70001 }',
  '  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { exit 70001 }',
  ('  $argv = ''' + $script:InwireInstallerSwitches + ' "/LOG='' + $log + ''"'''),
  '  $p = Start-Process -FilePath $exe -ArgumentList $argv -Wait -PassThru',
  '  if ($null -eq $p.ExitCode) { exit 70001 }',
  '  exit $p.ExitCode',
  '} catch {',
  '  exit 70001',
  '}'
) -join "`n")

function Get-InwireElevationCommand {
  $b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script:InwireElevatedScript))
  return @{
    FilePath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
    ArgumentList = ('-NoProfile -NonInteractive -EncodedCommand ' + $b64)
  }
}

# A declined UAC prompt is a Win32Exception 1223, possibly inside another
# exception. Read from the code, never from the (localised) message.
function Test-InwireUacDeclined {
  param($Exception)
  $e = $Exception
  $n = 0
  while ($null -ne $e -and $n -lt 8) {
    if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { return $true }
    $e = $e.InnerException
    $n++
  }
  return $false
}

function Invoke-InwireProductionRunInstaller {
  param([string]$InstallerPath, [string]$LogPath, [bool]$Elevated)
  $result = @{ Started = $false; ExitCode = $null; Declined = $false; TimedOut = $false; Reason = '' }
  $argv = Get-InwireInstallerArguments $LogPath
  $proc = $null
  try {
    if ($Elevated) {
      $proc = Start-Process -FilePath $InstallerPath -ArgumentList $argv -PassThru -WindowStyle Hidden
    } else {
      $cmd = Get-InwireElevationCommand
      $env:INWIRE_BOOT_INSTALLER = $InstallerPath
      $env:INWIRE_BOOT_LOG = $LogPath
      try {
        $proc = Start-Process -FilePath $cmd.FilePath -ArgumentList $cmd.ArgumentList -Verb RunAs -PassThru -WindowStyle Hidden
      } finally {
        Remove-Item Env:\INWIRE_BOOT_INSTALLER -ErrorAction SilentlyContinue
        Remove-Item Env:\INWIRE_BOOT_LOG -ErrorAction SilentlyContinue
      }
    }
  } catch {
    if (Test-InwireUacDeclined $_.Exception) {
      $result.Declined = $true
      $result.Reason = 'The administrator prompt was declined.'
    } else {
      $result.Reason = 'Windows could not start setup: ' + (Get-InwireErrorText $_)
    }
    return $result
  }
  if ($null -eq $proc) {
    $result.Reason = 'Windows did not return a process for setup.'
    return $result
  }
  $result.Started = $true
  try { $null = $proc.Handle } catch { }
  # Nothing is stopped on a timeout: killing an installer half-way is how a
  # machine ends up with half an Inwire.
  if (-not $proc.WaitForExit($script:InwireInstallTimeoutMs)) {
    $result.TimedOut = $true
    return $result
  }
  $result.ExitCode = $proc.ExitCode
  return $result
}

# ---------------------------------------------------------------------------
# Production adapters. State lives in $script:InwireProd, set by
# New-InwireProductionPlatform, because a scriptblock stored in a table runs in
# this file's scope and cannot see the function that built it.
# ---------------------------------------------------------------------------

function Get-InwireProductionPlatformInfo {
  $os = 'Other'
  if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $os = 'Windows' }
  $arch = ''
  try {
    $arch = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture).ToString()
  } catch { $arch = '' }
  switch ($arch) {
    'X64' { $arch = 'x64' }
    'Arm64' { $arch = 'arm64' }
    'X86' { $arch = 'x86' }
    default {
      $raw = $env:PROCESSOR_ARCHITEW6432
      if (-not $raw) { $raw = $env:PROCESSOR_ARCHITECTURE }
      switch ($raw) {
        'AMD64' { $arch = 'x64' }
        'ARM64' { $arch = 'arm64' }
        'x86' { $arch = 'x86' }
        default { $arch = 'unknown' }
      }
    }
  }
  return @{ OS = $os; Architecture = $arch }
}

function Test-InwireElevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InwireInstalledProduct {
  param([string]$Product = 'Desktop')
  if ($Product -cne 'Desktop') {
    return @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = 'There is no installed-version probe for this product.' }
  }
  $base = $null
  $key = $null
  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $base.OpenSubKey($script:InwireUninstallKey)
    if ($null -eq $key) { return @{ State = 'Absent'; Version = ''; InstallPath = ''; Detail = '' } }
    $version = $key.GetValue('DisplayVersion')
    $path = $key.GetValue('InstallLocation')
    if ($null -eq $path -or [string]$path -eq '') { $path = $key.GetValue('Inno Setup: App Path') }
    $pathText = ''
    if ($null -ne $path) { $pathText = ([string]$path).Trim() }
    if (-not (Test-InwireVersionText $version)) {
      return @{ State = 'Unknown'; Version = ''; InstallPath = $pathText; Detail = 'Inwire is registered but its version could not be read.' }
    }
    return @{ State = 'Installed'; Version = [string]$version; InstallPath = $pathText; Detail = '' }
  } catch {
    return @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = ('The registry could not be read: ' + (Get-InwireErrorText $_)) }
  } finally {
    if ($null -ne $key) { $key.Dispose() }
    if ($null -ne $base) { $base.Dispose() }
  }
}

function Get-InwireProductionRelease {
  param([string]$Url)
  $policy = $script:InwireProd.Policy
  $send = { param($u, $t) Send-InwireHttp $u $t }
  $r = Receive-InwireText -Url $Url -MaxBytes $script:InwireMaxDescriptorBytes -TimeoutSeconds $script:InwireDescriptorTimeoutSeconds -Policy $policy -Send $send
  if (-not $r.Ok) { throw $r.Reason }
  return $r.Text
}

function Invoke-InwireProductionDownload {
  param([string]$Url, [string]$DestPath, [long]$SizeBytes, [string]$Sha256)
  $policy = $script:InwireProd.Policy
  $send = { param($u, $t) Send-InwireHttp $u $t }
  return (Receive-InwireFile -Url $Url -DestPath $DestPath -SizeBytes $SizeBytes -Sha256 $Sha256 -Policy $policy -Send $send -TimeoutSeconds $script:InwireDownloadTimeoutSeconds)
}

function Invoke-InwireProductionVerify {
  param([string]$Path, $Pins)
  $sig = Get-AuthenticodeSignature -LiteralPath $Path
  return (Test-InwireSignature $sig $Pins)
}

function Invoke-InwireProductionLaunch {
  param([string]$LauncherPath)
  if (-not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) {
    return @{ Ok = $false; ExitCode = $null; Reason = 'The inwire command was not found where setup put it.' }
  }
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $LauncherPath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = [System.IO.Path]::GetDirectoryName($LauncherPath)
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit(30000)) { return @{ Ok = $false; ExitCode = $null; Reason = 'The inwire command did not return.' } }
    if ($p.ExitCode -eq 0) { return @{ Ok = $true; ExitCode = 0; Reason = '' } }
    return @{ Ok = $false; ExitCode = $p.ExitCode; Reason = ('The inwire command exited with code ' + $p.ExitCode + '.') }
  } catch {
    return @{ Ok = $false; ExitCode = $null; Reason = ('The inwire command could not start: ' + (Get-InwireErrorText $_)) }
  }
}

function New-InwireProductionWorkDir {
  $dir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('inwire-bootstrap-' + [Guid]::NewGuid().ToString('N')))
  [void][System.IO.Directory]::CreateDirectory($dir)
  return $dir
}

# Deletes only a folder this bootstrap made: the prefix and a 32-hex suffix, and
# directly under the user's temp.
function Remove-InwireProductionWorkDir {
  param([string]$Path)
  if ([string]::IsNullOrEmpty($Path)) { return }
  $leaf = [System.IO.Path]::GetFileName($Path.TrimEnd('\'))
  if ($leaf -cnotmatch '^inwire-bootstrap-[0-9a-f]{32}\z') { return }
  $parent = [System.IO.Path]::GetDirectoryName($Path.TrimEnd('\'))
  $temp = [System.IO.Path]::GetTempPath().TrimEnd('\')
  if ($parent -ine $temp) { return }
  Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function New-InwireProductionPlatform {
  param($Policy)
  $script:InwireProd = @{ Policy = $Policy; Client = $null }
  return @{
    GetPlatform = { Get-InwireProductionPlatformInfo }
    IsElevated = { Test-InwireElevated }
    GetInstalled = { param($Product) Get-InwireInstalledProduct ([string]$Product) }
    GetRelease = { param($Url) Get-InwireProductionRelease ([string]$Url) }
    Download = { param($Url, $DestPath, $SizeBytes, $Sha256) Invoke-InwireProductionDownload ([string]$Url) ([string]$DestPath) ([long]$SizeBytes) ([string]$Sha256) }
    VerifyPublisher = { param($Path, $Pins) Invoke-InwireProductionVerify ([string]$Path) $Pins }
    RunInstaller = { param($Path, $LogPath, $Elevated) Invoke-InwireProductionRunInstaller ([string]$Path) ([string]$LogPath) ([bool]$Elevated) }
    LaunchDesktop = { param($LauncherPath) Invoke-InwireProductionLaunch ([string]$LauncherPath) }
    NewWorkDir = { New-InwireProductionWorkDir }
    RemoveWorkDir = { param($Path) Remove-InwireProductionWorkDir ([string]$Path) }
  }
}

# ---------------------------------------------------------------------------
# The state machine
# ---------------------------------------------------------------------------

function New-InwireResult {
  param([string]$State, [int]$ExitCode, [string]$Message, [string]$ErrorCode = '',
        [string]$InstallPath = '', [string]$InstalledVersion = '', [bool]$Launched = $false,
        [string]$LaunchMessage = '', [string]$DiagnosticPath = '')
  return [pscustomobject]@{
    State = $State
    InstallPath = $InstallPath
    InstalledVersion = $InstalledVersion
    Launched = $Launched
    LaunchMessage = $LaunchMessage
    ErrorCode = $ErrorCode
    Message = $Message
    ExitCode = $ExitCode
    DiagnosticPath = $DiagnosticPath
  }
}

# One platform callback's answer: the last object it wrote, or $null.
function Invoke-InwireCall {
  param($Platform, [string]$Name, [object[]]$Arguments = @())
  $sb = $Platform[$Name]
  if ($sb -isnot [scriptblock]) { throw ('The platform has no ' + $Name + ' callback.') }
  $out = @(& $sb @Arguments)
  if ($out.Count -eq 0) { return $null }
  return ,$out[$out.Count - 1]
}

function Read-InwireInstalled {
  param($Raw)
  $state = [string](Get-InwireField $Raw 'State')
  $version = [string](Get-InwireField $Raw 'Version')
  $path = [string](Get-InwireField $Raw 'InstallPath')
  $detail = [string](Get-InwireField $Raw 'Detail')
  if ($state -ceq 'Installed' -and -not (Test-InwireVersionText $version)) {
    $state = 'Unknown'
    $detail = 'The installed version "' + $version + '" is not a version this bootstrap understands.'
  }
  if (@('Absent', 'Installed', 'Unknown') -cnotcontains $state) {
    $state = 'Unknown'
  }
  return @{ State = $state; Version = $version; InstallPath = $path; Detail = $detail }
}

function Invoke-InwireSteps {
  param([string]$Product, [string]$Version, [bool]$Launch, [bool]$Repair, $Policy, $Platform, $St)

  function Res {
    param([string]$State, [int]$Code, [string]$Message, [string]$ErrorCode = '')
    return (New-InwireResult -State $State -ExitCode $Code -Message $Message -ErrorCode $ErrorCode `
      -InstallPath ([string]$St.InstallPath) -InstalledVersion ([string]$St.InstalledVersion) `
      -Launched ([bool]$St.Launched) -LaunchMessage ([string]$St.LaunchMessage))
  }

  # 1. The platform.
  $plat = Invoke-InwireCall $Platform 'GetPlatform'
  if ($null -eq $plat -or (Get-InwireField $plat 'OS') -cne 'Windows') {
    return (Res 'Unavailable' 10 'The Inwire bootstrap runs on Windows only.' 'UnsupportedOS')
  }
  $arch = [string](Get-InwireField $plat 'Architecture')
  if ($arch -ceq 'arm64') {
    return (Res 'Unavailable' 10 'This PC is arm64. Inwire is built and tested for x64 only, and running it under x64 emulation is untested, so setup refuses rather than guess. Use the Inwire installer from the release page on an x64 PC.' 'UnsupportedArchitecture')
  }
  if ($arch -cne 'x64') {
    return (Res 'Unavailable' 10 ('This PC reports the architecture "' + $arch + '". Inwire is built for x64 only.') 'UnsupportedArchitecture')
  }

  # 2. The endpoint agent does not exist yet.
  if ($Product -ceq 'EndpointAgent' -and -not $Policy.EndpointAvailable) {
    return (Res 'Unavailable' 20 'The Inwire endpoint agent is not available yet. Nothing was downloaded.' 'EndpointUnavailable')
  }

  # 3. A bootstrap with no pinned publisher cannot tell Inwire's installer from anyone's.
  if (@($Policy.PublisherCertificateSha256).Count -eq 0) {
    return (Res 'Unavailable' 10 'This bootstrap pins no publisher certificate, so it cannot tell who signed an installer and will not install one. It was built before a public signing certificate existed.' 'NoPinnedPublisher')
  }
  if ($Version -ne '' -and -not (Test-InwireVersionText $Version)) {
    return (Res 'Failed' 10 ('-Version must look like 1.2.3 (three numbers); "' + $Version + '" does not.') 'BadVersion')
  }

  # 4. What is installed now.
  $inst = $null
  try {
    $inst = Read-InwireInstalled (Invoke-InwireCall $Platform 'GetInstalled' @($Product))
  } catch {
    return (Res 'Failed' 13 ('The installed state of Inwire could not be read: ' + (Get-InwireErrorText $_)) 'InstalledStateError')
  }
  $St.InstallPath = $inst.InstallPath
  $St.InstalledVersion = $inst.Version
  if ($inst.State -ceq 'Unknown' -and -not $Repair) {
    $why = if ($inst.Detail) { ' (' + $inst.Detail + ')' } else { '' }
    return (Res 'Failed' 13 ('The installed state of Inwire could not be read' + $why + '. Run the bootstrap again with -Repair to install over it.') 'InstalledStateUnknown')
  }

  # 5. The release descriptor.
  $body = $null
  try {
    $body = Invoke-InwireCall $Platform 'GetRelease' @($Policy.DescriptorUrl)
  } catch {
    return (Res 'Failed' 11 ('The release descriptor could not be fetched: ' + (Get-InwireErrorText $_)) 'DescriptorFetch')
  }
  # A top-level array is refused up front: Windows PowerShell 5.1 unrolls a
  # one-element array out of ConvertFrom-Json, which would hide it.
  if ($body -isnot [string] -or $body -cnotmatch '^\s*\{') {
    return (Res 'Failed' 11 'The release descriptor is not a JSON object.' 'DescriptorInvalid')
  }
  $parsed = $null
  try {
    $parsed = ConvertFrom-Json -InputObject $body
  } catch {
    return (Res 'Failed' 11 'The release descriptor is not valid JSON.' 'DescriptorInvalid')
  }
  $release = Read-InwireRelease $parsed $Policy
  if ($null -eq $release) {
    return (Res 'Failed' 11 'The release descriptor is not valid, or names a source this bootstrap does not trust.' 'DescriptorInvalid')
  }
  $row = Select-InwireArtifact $release $Product $null
  if ($null -eq $row) {
    return (Res 'Failed' 11 ('The release descriptor publishes no ' + $Product + ' installer.') 'NotPublished')
  }
  if ($Version -ne '' -and $row.Version -cne $Version) {
    return (Res 'Failed' 11 ('Version ' + $Version + ' is not published; the published version is ' + $row.Version + '.') 'NotPublished')
  }

  # 6. Never downgrade, never reinstall the same version unless asked.
  $state = ''
  $code = 0
  if ($inst.State -ceq 'Installed') {
    $cmp = Compare-InwireVersion $inst.Version $row.Version
    if ($cmp -gt 0) {
      if ($Version -ne '') {
        return (Res 'Failed' 10 ('Refusing to downgrade: Inwire ' + $inst.Version + ' is installed, which is newer than the requested ' + $Version + '. Uninstall it first if you really mean to go back.') 'Downgrade')
      }
      $state = 'AlreadyInstalled'
      $St.Message = 'Inwire ' + $inst.Version + ' is already installed, which is newer than the published ' + $row.Version + '. Nothing was changed.'
    } elseif ($cmp -eq 0 -and -not $Repair) {
      $state = 'AlreadyInstalled'
      $St.Message = 'Inwire ' + $inst.Version + ' is already installed. Nothing was changed. Run with -Repair to install it again.'
    }
  }

  if ($state -cne 'AlreadyInstalled') {
    # 7. A private working folder.
    $work = $null
    try { $work = Invoke-InwireCall $Platform 'NewWorkDir' } catch { $work = $null }
    if ($work -isnot [string] -or $work -eq '') {
      return (Res 'Failed' 13 'A private working folder could not be created.' 'WorkDir')
    }
    $St.WorkDir = $work
    $installer = [System.IO.Path]::Combine($work, $script:InwireInstallerFileName)
    $log = [System.IO.Path]::Combine($work, $script:InwireLogFileName)

    # 8. Download, retrying only faults that can pass.
    $attempt = 0
    $dl = $null
    while ($true) {
      $attempt++
      try {
        $dl = Invoke-InwireCall $Platform 'Download' @($row.Url, $installer, [long]$row.SizeBytes, $row.Sha256)
      } catch {
        $dl = @{ Ok = $false; Reason = (Get-InwireErrorText $_); Transient = $false; Integrity = $false }
      }
      if ((Get-InwireField $dl 'Ok') -eq $true) { break }
      $integrity = ((Get-InwireField $dl 'Integrity') -eq $true)
      if ((Get-InwireField $dl 'Transient') -eq $true -and -not $integrity -and $attempt -lt 3) { continue }
      break
    }
    if ((Get-InwireField $dl 'Ok') -ne $true) {
      $reason = [string](Get-InwireField $dl 'Reason')
      if ((Get-InwireField $dl 'Integrity') -eq $true) {
        return (Res 'Failed' 12 ('The download could not be verified: ' + $reason) 'Integrity')
      }
      return (Res 'Failed' 11 ('The installer could not be downloaded: ' + $reason) 'Download')
    }

    # 9. The publisher. Nothing is elevated before this passes.
    $ver = $null
    try {
      $ver = Invoke-InwireCall $Platform 'VerifyPublisher' @($installer, $Policy.PublisherCertificateSha256)
    } catch {
      $ver = @{ Ok = $false; Reason = (Get-InwireErrorText $_) }
    }
    if ((Get-InwireField $ver 'Ok') -ne $true) {
      return (Res 'Failed' 12 ('The publisher of the installer could not be verified:' + [string](Get-InwireField $ver 'Reason')) 'Publisher')
    }

    # 10. Run setup, elevating only if this PowerShell is not already.
    $St.Elevated = [bool](Invoke-InwireCall $Platform 'IsElevated')
    $run = $null
    try {
      $run = Invoke-InwireCall $Platform 'RunInstaller' @($installer, $log, $St.Elevated)
    } catch {
      $St.Keep = $true
      return (Res 'Failed' 13 ('Setup could not be run: ' + (Get-InwireErrorText $_)) 'RunInstaller')
    }
    if ((Get-InwireField $run 'Declined') -eq $true) {
      return (Res 'Cancelled' 2 'The administrator (UAC) prompt was declined, so setup did not run. Run the bootstrap again and choose Yes to install.' 'UacDeclined')
    }
    if ((Get-InwireField $run 'TimedOut') -eq $true) {
      $St.Keep = $true
      return (Res 'Failed' 13 ('Setup did not finish within 30 minutes. It may still be running; nothing was stopped. The setup log and the downloaded installer are kept in' + $work + '.') 'Timeout')
    }
    if ((Get-InwireField $run 'Started') -ne $true) {
      $St.Keep = $true
      return (Res 'Failed' 13 ('Setup did not start: ' + [string](Get-InwireField $run 'Reason')) 'NotStarted')
    }
    $exit = Get-InwireField $run 'ExitCode'
    if ($null -eq $exit) {
      $St.Keep = $true
      return (Res 'Failed' 13 'Setup ran but its exit code could not be read, so success cannot be assumed. Check Settings > Apps for Inwire, and the log in the working folder.' 'NoExitCode')
    }

    # 11. The installer's code, mapped. A raw non-zero code is never success.
    $ec = [int64]$exit
    $ecText = [string]$ec
    if ($ec -eq 2 -or $ec -eq 5) {
      return (Res 'Cancelled' 2 ('Setup was cancelled (code ' + $ec + ').') $ecText)
    }
    if ($ec -eq 8) {
      $St.Keep = $true
      return (Res 'Failed' 13 'Setup could not continue because Windows needs to restart first (code 8). Restart, then run the bootstrap again.' $ecText)
    }
    if ($ec -ne 0 -and $ec -ne 3010) {
      $St.Keep = $true
      $extra = if ($ec -eq $script:InwireWrapperFault) { ' The elevation step could not start setup.' } else { '' }
      return (Res 'Failed' 13 ('Setup failed with code ' + $ec + '.' + $extra + ' Its log is in ' + $work + '.') $ecText)
    }

    # 12. Trust the registry, not the exit code.
    $after = $null
    try {
      $after = Read-InwireInstalled (Invoke-InwireCall $Platform 'GetInstalled' @($Product))
    } catch {
      $after = @{ State = 'Unknown'; Version = ''; InstallPath = ''; Detail = (Get-InwireErrorText $_) }
    }
    if ($after.State -cne 'Installed' -or $after.Version -cne $row.Version) {
      $St.Keep = $true
      $reads = if ($after.State -ceq 'Installed') { 'the installed version reads ' + $after.Version } else { 'no readable installed version was found' }
      return (Res 'Failed' 13 ('Setup exited with code ' + $ec + ' but ' + $reads + ', not ' + $row.Version + '. Its log is in ' + $work + '.') 'Readback')
    }
    $St.InstallPath = $after.InstallPath
    $St.InstalledVersion = $after.Version
    if ($ec -eq 3010) {
      $state = 'RebootRequired'
      $code = 3010
      $St.Message = 'Inwire ' + $after.Version + ' is installed. Windows must restart to finish.'
      $St.ErrorCode = '3010'
    } else {
      $state = 'Installed'
      $St.Message = 'Inwire ' + $after.Version + ' is installed.'
    }
  }

  # 13. Launch, only when asked and only from a normal shell.
  if ($Launch) {
    if ($state -ceq 'RebootRequired') {
      $St.LaunchMessage = 'Restart Windows first; Inwire was not started.'
    } else {
      if ($null -eq $St.Elevated) { $St.Elevated = [bool](Invoke-InwireCall $Platform 'IsElevated') }
      if ($St.Elevated) {
        $St.LaunchMessage = 'this PowerShell is elevated; Inwire does not start elevated - run `inwire` from a normal terminal'
        $code = 14
      } else {
        $ip = [string]$St.InstallPath
        if ($ip -cnotmatch '^[A-Za-z]:\\') {
          $St.LaunchMessage = 'Inwire is installed, but its install location could not be read, so it was not started. Run `inwire` from a new terminal.'
          $code = 14
        } else {
          $launcher = $ip.TrimEnd('\') + '\bin\inwire.exe'
          $l = $null
          try { $l = Invoke-InwireCall $Platform 'LaunchDesktop' @($launcher) } catch { $l = @{ Ok = $false; Reason = (Get-InwireErrorText $_) } }
          if ((Get-InwireField $l 'Ok') -eq $true) {
            $St.Launched = $true
            $St.LaunchMessage = 'Inwire was started.'
          } else {
            $St.LaunchMessage = 'Inwire is installed but could not be started: ' + [string](Get-InwireField $l 'Reason')
            $code = 14
          }
        }
      }
    }
  }
  return (Res $state $code ([string]$St.Message) ([string]$St.ErrorCode))
}

# Installs (or declines to) and returns ONE result object. The exit contract:
#   0 installed / already installed    2 cancelled     3010 installed, restart
#   10 unsupported environment/policy  11 download or metadata fault
#   12 verification fault              13 install or readback fault
#   14 installed, but Inwire was not started    20 endpoint agent unavailable
function Invoke-InwireInstall {
  [CmdletBinding()]
  param(
    [ValidateSet('Desktop', 'EndpointAgent')][string]$Product = 'Desktop',
    [string]$Version = '',
    [switch]$Launch,
    [switch]$Repair,
    [Parameter(Mandatory = $true)]$Policy,
    [Parameter(Mandatory = $true)]$Platform
  )
  $st = @{
    WorkDir = $null; Keep = $false; InstallPath = ''; InstalledVersion = ''
    Launched = $false; LaunchMessage = ''; Message = ''; ErrorCode = ''; Elevated = $null
  }
  $result = $null
  try {
    $result = Invoke-InwireSteps -Product $Product -Version ([string]$Version) -Launch ([bool]$Launch) -Repair ([bool]$Repair) -Policy $Policy -Platform $Platform -St $st
  } catch {
    $st.Keep = ($null -ne $st.WorkDir)
    $result = New-InwireResult -State 'Failed' -ExitCode 13 -Message ('Unexpected error: ' + (Get-InwireErrorText $_)) -ErrorCode 'Unexpected' `
      -InstallPath ([string]$st.InstallPath) -InstalledVersion ([string]$st.InstalledVersion)
  }
  if ($null -ne $st.WorkDir) {
    if ($st.Keep) {
      $result.DiagnosticPath = [string]$st.WorkDir
    } else {
      try { [void](Invoke-InwireCall $Platform 'RemoveWorkDir' @($st.WorkDir)) } catch { }
    }
  }
  return $result
}

function Write-InwireSummary {
  param($Result, [string]$BuildLabel = '')
  if ($BuildLabel) { Write-Host ('[' + $BuildLabel + ']') }
  Write-Host ('Inwire bootstrap: ' + $Result.State + ' - ' + $Result.Message)
  if ($Result.LaunchMessage) { Write-Host $Result.LaunchMessage }
  if ($Result.DiagnosticPath) { Write-Host ('Kept for diagnosis: ' + $Result.DiagnosticPath) }
  Write-Host ('Exit code ' + $Result.ExitCode)
}
