<#
.SYNOPSIS
  Signs Windows PE files with Inwire's code-signing certificate, or verifies
  them. The ONE place in the build that signs anything.

.DESCRIPTION
  Everything that signs goes through this script: electron-builder's hook
  (`electron/sign.cjs`) for Inwire.exe and its DLLs, and Inno Setup's SignTool
  (`installer/setup.iss`) for the uninstaller and Inwire-Setup.exe. Swapping the
  self-signed certificate for a real one is therefore a change of thumbprint and
  nothing else.

  ## Which certificate

  By thumbprint, never by name and never from a file in the repository:

    1. -Thumbprint
    2. $env:INWIRE_SIGN_THUMBPRINT
    3. `.signing.json` at the repository root ({"thumbprint": "..."}), which is
       gitignored and which `new-cert.ps1 -WriteConfig` writes

  looked up in Cert:\CurrentUser\My, then Cert:\LocalMachine\My.

  With none configured, this signs nothing and exits 0 with a warning, so a dev
  build on a machine with no certificate still packs - UNLESS signing is
  required, by -Require or $env:INWIRE_REQUIRE_SIGNING=1, in which case it
  exits 1. The Inno build passes -Require: asking Inno for a signed installer
  and getting an unsigned one is a failure, not a warning.

  ## How, and why it is two steps

  SHA-256 file digest, then an RFC 3161 timestamp (SHA-256 message imprint)
  from $env:INWIRE_SIGN_TIMESTAMP_URL or http://timestamp.digicert.com.

  There is no signtool here - no Windows SDK on the build machine - so the
  signature is `Set-AuthenticodeSignature`. Its own -TimestampServer is NOT
  used, and this is measured, not remembered: in both Windows PowerShell 5.1
  and PowerShell 7.6 it produces a legacy Authenticode countersignature (OID
  1.2.840.113549.1.9.6), not an RFC 3161 token. So the timestamp is added
  afterwards by `mssign32!SignerTimeStampEx2` with SIGNER_TIMESTAMP_RFC3161 -
  the same call signtool's `/tr` makes - and the result is checked for the
  RFC 3161 attribute (1.3.6.1.4.1.311.3.3.1) rather than assumed.

  One trap in that call, recorded because it is an access violation rather than
  an error: the documentation types its fourth parameter as ALG_ID, and the
  export actually takes a PCSTR hash-algorithm OID. Passing CALG_SHA_256
  (0x800C) dereferences 0x800C.

  A timestamp is what keeps a signature valid after the certificate expires; a
  signature without one dies with the certificate. So signing is all or
  nothing: the signature and the timestamp are made on a COPY in %TEMP%,
  verified there, and only then copied over the original. A timestamp server
  that is down fails the file and leaves it exactly as it was - never signed
  but untimestamped, which a re-run would then have to treat as damage.

  ## What is signed, skipped, and refused

    - Not signed: signed.
    - Signed by the configured certificate and whole - digest intact, SHA-256,
      RFC 3161 timestamp: skipped (electron-builder can call twice per file).
    - Validly signed by a PUBLISHER - a CA-issued certificate, like
      Microsoft's on d3dcompiler_47.dll: skipped, always, -Force or not.
      Their signature is better evidence than ours would be.
    - ANY OTHER existing signature: REFUSED, exit 1, unless -Force.
        * Somebody else's that does not verify. Their binary changed after
          they signed it, and writing our signature over theirs would launder
          that.
        * Ours, but broken - the file changed after this certificate signed
          it - or incomplete.
        * One by a different SELF-SIGNED certificate, valid on this PC or not:
          a self-signed signature is only ever valid by a local trust decision,
          so it is not a publisher's. It is most likely this project's own
          earlier certificate, and skipping it would carry the old signature
          silently through a swap to a real one.
      A build never meets these - its outputs are fresh - so meeting one means
      something touched a file after it was signed, and a person should look
      before anything is re-signed. -Force re-signs it with the configured
      certificate, having looked.

  ## Verifying: what "intact" means before the certificate is trusted

  WinVerifyTrust is asked directly, for its HRESULT, rather than read back
  through Get-AuthenticodeSignature - whose Status folds "root not trusted" into
  `UnknownError` alongside every other failure. CERT_E_UNTRUSTEDROOT
  (0x800B0109) is reported only after the digest and the signature have both
  verified: a modified file is TRUST_E_BAD_DIGEST (0x80096010) whatever the
  chain. So until `trust-cert.ps1` has run, 0x800B0109 plus our thumbprint as
  the signer IS an intact signature; afterwards the same file reads Valid (0).
  That tolerance applies only to a self-signed certificate; a CA-issued one
  must verify Valid, full stop.

  -Verify only checks. -RequireTrusted makes it demand Valid.

  ## What this signature is worth

  On this PC, after trust-cert.ps1: Windows shows "Inwire" as the verified
  publisher in the UAC prompt and file properties. SmartScreen and Smart App
  Control do NOT consult the local Root store; they judge by Microsoft's own
  trust program and reputation, so this signature earns nothing there, and on
  any other machine it is an untrusted root.

.PARAMETER Path
  One or more PE files. Relative paths resolve against the current directory.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign\sign.ps1 release\win-unpacked\Inwire.exe

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign\sign.ps1 -Verify release\win-unpacked\Inwire.exe release\win-unpacked\ffmpeg.dll
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string[]]$Path,

  # `-Path a b c` under `powershell -File` binds `a` to -Path and leaves the
  # rest unbound - -File mode has no array syntax, so `a,b,c` arrives as one
  # string. The rest land here, which makes `-Path a b c` and `a b c` both work.
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$MorePaths,

  [string]$Thumbprint,

  [switch]$Verify,

  [switch]$Require,

  [switch]$RequireTrusted,

  # Re-sign a file whose existing signature is broken, incomplete, somebody
  # else's that does not verify, or another self-signed certificate's. Never
  # overrides a publisher's valid signature. See the header.
  [switch]$Force,

  [string]$TimestampServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# One line and exit 1 for anything not handled per file - a configuration
# error, a missing certificate - rather than a PowerShell error record, which
# electron-builder and ISCC would print as a wall of text around one sentence.
trap {
  [Console]::Error.WriteLine("sign.ps1: $($_.Exception.Message)")
  exit 1
}

# **The Cert: drive and Set-AuthenticodeSignature come from THIS edition's
# Microsoft.PowerShell.Security, loaded by path.** A PSModulePath inherited from
# PowerShell 7 lists pwsh's module directories first, and Windows PowerShell 5.1
# started under it autoloads pwsh's copy of that module, which does not load
# there - so `Cert:` simply does not exist ("A drive with the name 'Cert' does
# not exist"). electron-builder hit it: node, started from a pwsh session,
# spawns powershell.exe with that environment, and so does ISCC.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ConfigPath = Join-Path $RepoRoot '.signing.json'

$OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
$OID_SHA256 = '2.16.840.1.101.3.4.2.1'
$OID_RFC3161 = '1.3.6.1.4.1.311.3.3.1'
$OID_LEGACY_COUNTERSIGN = '1.2.840.113549.1.9.6'

# PowerShell reads a 32-bit hex literal as a SIGNED Int32 - 0x800B0100 is
# already negative - which is exactly the type WinVerifyTrust's HRESULT
# arrives as, so these compare and index without conversion.
$S_OK = 0
$TRUST_E_NOSIGNATURE = 0x800B0100
$CERT_E_UNTRUSTEDROOT = 0x800B0109
$TRUST_E_BAD_DIGEST = 0x80096010
$TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003

$HResultNames = @{
  0x00000000 = 'valid'
  0x800B0100 = 'TRUST_E_NOSIGNATURE (not signed)'
  0x800B0109 = 'CERT_E_UNTRUSTEDROOT (signature intact, root not trusted on this PC)'
  0x80096010 = 'TRUST_E_BAD_DIGEST (file modified after signing)'
  0x800B0003 = 'TRUST_E_SUBJECT_FORM_UNKNOWN (not a signable file type)'
  0x800B0101 = 'CERT_E_EXPIRED'
  0x800B010A = 'CERT_E_CHAINING'
  0x800B0111 = 'TRUST_E_EXPLICIT_DISTRUST'
  0x800B0110 = 'CERT_E_WRONG_USAGE'
  0x80096019 = 'TRUST_E_BASIC_CONSTRAINTS'
  0x800B0004 = 'TRUST_E_SUBJECT_NOT_TRUSTED'
  # WinINet, from the timestamp request, which Win32Exception cannot name.
  0x80072EFD = 'ERROR_INTERNET_CANNOT_CONNECT (timestamp server unreachable)'
  0x80072EE7 = 'ERROR_INTERNET_NAME_NOT_RESOLVED (timestamp server name did not resolve)'
  0x80072EE2 = 'ERROR_INTERNET_TIMEOUT (timestamp server timed out)'
}

function Format-HResult([int]$hr) {
  $name = $HResultNames[$hr]
  if (-not $name) { $name = (New-Object ComponentModel.Win32Exception($hr)).Message }
  return ('0x{0:X8} {1}' -f $hr, $name)
}

# ---------------------------------------------------------------------------
# Native helpers. C# 5 on purpose: Windows PowerShell 5.1 compiles Add-Type
# with the .NET Framework compiler, and this runs under both editions.
# ---------------------------------------------------------------------------
if (-not ('InwireSign.Native' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace InwireSign {
  public static class Native {
    // ---- WinVerifyTrust, for the HRESULT itself ----------------------------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO {
      public uint cbStruct;
      [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
      public IntPtr hFile;
      public IntPtr pgKnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA {
      public uint cbStruct;
      public IntPtr pPolicyCallbackData;
      public IntPtr pSIPClientData;
      public uint dwUIChoice;
      public uint fdwRevocationChecks;
      public uint dwUnionChoice;
      public IntPtr pFile;
      public uint dwStateAction;
      public IntPtr hWVTStateData;
      public IntPtr pwszURLReference;
      public uint dwProvFlags;
      public uint dwUIContext;
      public IntPtr pSignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static int Verify(string path) {
      Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
      WINTRUST_FILE_INFO fi = new WINTRUST_FILE_INFO();
      fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
      fi.pcwszFilePath = path;
      IntPtr pFi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
      Marshal.StructureToPtr(fi, pFi, false);
      try {
        WINTRUST_DATA wd = new WINTRUST_DATA();
        wd.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
        wd.dwUIChoice = 2;           // WTD_UI_NONE
        wd.fdwRevocationChecks = 0;  // WTD_REVOKE_NONE
        wd.dwUnionChoice = 1;        // WTD_CHOICE_FILE
        wd.pFile = pFi;
        wd.dwStateAction = 0;        // WTD_STATEACTION_IGNORE
        wd.dwProvFlags = 0x1000;     // WTD_CACHE_ONLY_URL_RETRIEVAL: verifying never dials out
        return WinVerifyTrust(new IntPtr(-1), ref action, ref wd);
      } finally {
        Marshal.DestroyStructure(pFi, typeof(WINTRUST_FILE_INFO));
        Marshal.FreeHGlobal(pFi);
      }
    }

    // ---- RFC 3161 timestamp -------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_FILE_INFO { public uint cbSize; public IntPtr pwszFileName; public IntPtr hFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_SUBJECT_INFO { public uint cbSize; public IntPtr pdwIndex; public uint dwSubjectChoice; public IntPtr pSignerFileInfo; }

    // The 4th parameter is documented as ALG_ID and is really a PCSTR OID.
    [DllImport("mssign32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SignerTimeStampEx2(uint dwFlags, ref SIGNER_SUBJECT_INFO pSubjectInfo,
      string pwszHttpTimeStamp, [MarshalAs(UnmanagedType.LPStr)] string pszTimeStampAlgorithmOid,
      IntPtr psRequest, IntPtr pSipData, out IntPtr ppSignerContext);
    [DllImport("mssign32.dll", ExactSpelling = true)]
    private static extern int SignerFreeSignerContext(IntPtr pSignerContext);

    public static int TimestampRfc3161(string path, string url, string hashOid) {
      IntPtr name = Marshal.StringToHGlobalUni(path);
      IntPtr index = Marshal.AllocHGlobal(4);
      IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SIGNER_FILE_INFO)));
      IntPtr ctx = IntPtr.Zero;
      try {
        Marshal.WriteInt32(index, 0);
        SIGNER_FILE_INFO fi = new SIGNER_FILE_INFO();
        fi.cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_FILE_INFO));
        fi.pwszFileName = name;
        Marshal.StructureToPtr(fi, pFile, false);
        SIGNER_SUBJECT_INFO si = new SIGNER_SUBJECT_INFO();
        si.cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_SUBJECT_INFO));
        si.pdwIndex = index;
        si.dwSubjectChoice = 1;      // SIGNER_SUBJECT_FILE
        si.pSignerFileInfo = pFile;
        return SignerTimeStampEx2(2 /* SIGNER_TIMESTAMP_RFC3161 */, ref si, url, hashOid,
          IntPtr.Zero, IntPtr.Zero, out ctx);
      } finally {
        if (ctx != IntPtr.Zero) SignerFreeSignerContext(ctx);
        Marshal.FreeHGlobal(pFile);
        Marshal.FreeHGlobal(index);
        Marshal.FreeHGlobal(name);
      }
    }

    // ---- The PKCS#7 blob out of a PE's certificate table ----------------------
    public static byte[] ReadPkcs7(string path) {
      using (FileStream fs = File.OpenRead(path))
      using (BinaryReader br = new BinaryReader(fs)) {
        if (fs.Length < 0x40) return null;
        fs.Position = 0x3C;
        int pe = br.ReadInt32();
        if (pe <= 0 || pe + 24 > fs.Length) return null;
        fs.Position = pe;
        if (br.ReadUInt32() != 0x00004550) return null;          // "PE\0\0"
        int opt = pe + 24;
        fs.Position = opt;
        ushort magic = br.ReadUInt16();
        int dirs = magic == 0x20b ? opt + 112 : opt + 96;         // PE32+ : PE32
        fs.Position = dirs + 4 * 8;                               // IMAGE_DIRECTORY_ENTRY_SECURITY
        uint off = br.ReadUInt32();
        uint size = br.ReadUInt32();
        if (off == 0 || size < 8 || off + (long)size > fs.Length) return null;
        fs.Position = off;
        uint len = br.ReadUInt32();
        br.ReadUInt16();                                          // wRevision
        ushort type = br.ReadUInt16();
        if (type != 2 || len < 8 || len > size) return null;      // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        return br.ReadBytes((int)len - 8);
      }
    }

    // ---- Just enough DER to read an RFC 3161 token's TSTInfo -----------------
    // ContentInfo { OID, [0] SignedData { version, digestAlgs, encapContentInfo
    //   { eContentType, [0] OCTET STRING TSTInfo } ... } }
    // TSTInfo { version, policy, messageImprint { hashAlgorithm { OID }, hash },
    //   serialNumber, genTime GeneralizedTime ... }
    // Returns { hash algorithm OID, genTime }.
    public static string[] ReadRfc3161Token(byte[] der) {
      int p = 0; int len;
      Enter(der, ref p, 0x30, out len);       // ContentInfo
      Skip(der, ref p);                        // contentType
      Enter(der, ref p, 0xA0, out len);       // [0]
      Enter(der, ref p, 0x30, out len);       // SignedData
      Skip(der, ref p);                        // version
      Skip(der, ref p);                        // digestAlgorithms
      Enter(der, ref p, 0x30, out len);       // encapContentInfo
      Skip(der, ref p);                        // eContentType
      Enter(der, ref p, 0xA0, out len);       // [0]
      Enter(der, ref p, 0x04, out len);       // OCTET STRING
      Enter(der, ref p, 0x30, out len);       // TSTInfo
      Skip(der, ref p);                        // version
      Skip(der, ref p);                        // policy
      Enter(der, ref p, 0x30, out len);       // messageImprint
      int algLen; Enter(der, ref p, 0x30, out algLen);
      int algEnd = p + algLen;
      int oidLen; Enter(der, ref p, 0x06, out oidLen);
      string oid = Oid(der, p, oidLen);
      p = algEnd;
      Skip(der, ref p);                        // hashedMessage
      Skip(der, ref p);                        // serialNumber
      int tLen; Enter(der, ref p, 0x18, out tLen);
      string gen = Encoding.ASCII.GetString(der, p, tLen);
      return new string[] { oid, gen };
    }

    private static void Header(byte[] d, ref int p, out byte tag, out int len) {
      tag = d[p++];
      int b = d[p++];
      if (b < 0x80) { len = b; return; }
      int n = b & 0x7F; len = 0;
      for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
    }
    private static void Enter(byte[] d, ref int p, byte want, out int len) {
      byte tag; Header(d, ref p, out tag, out len);
      if (tag != want) throw new InvalidDataException(string.Format("DER: expected tag 0x{0:X2}, found 0x{1:X2}", want, tag));
    }
    private static void Skip(byte[] d, ref int p) {
      byte tag; int len; Header(d, ref p, out tag, out len); p += len;
    }
    private static string Oid(byte[] d, int p, int len) {
      StringBuilder sb = new StringBuilder();
      int first = d[p];
      sb.Append(first / 40).Append('.').Append(first % 40);
      long v = 0;
      for (int i = 1; i < len; i++) {
        v = (v << 7) | (uint)(d[p + i] & 0x7F);
        if ((d[p + i] & 0x80) == 0) { sb.Append('.').Append(v); v = 0; }
      }
      return sb.ToString();
    }
  }
}
'@
}

if (-not ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
  try { Add-Type -AssemblyName System.Security } catch { }
  if (-not ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
  }
}

# ---------------------------------------------------------------------------

function Resolve-SigningThumbprint {
  $raw = $null; $source = $null
  if ($Thumbprint) { $raw = $Thumbprint; $source = '-Thumbprint' }
  elseif ($env:INWIRE_SIGN_THUMBPRINT) { $raw = $env:INWIRE_SIGN_THUMBPRINT; $source = 'INWIRE_SIGN_THUMBPRINT' }
  elseif (Test-Path -LiteralPath $ConfigPath) {
    $json = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($json.PSObject.Properties['thumbprint'] -and $json.thumbprint) { $raw = [string]$json.thumbprint; $source = $ConfigPath }
  }
  if (-not $raw) { return $null }
  # certmgr's "copy" puts an invisible U+200E in front, and people paste with
  # spaces; a SHA-1 thumbprint is 40 hex digits and nothing else.
  $tp = ($raw -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
  if ($tp.Length -ne 40) { throw "The thumbprint from $source is not 40 hex digits: '$raw'" }
  return [pscustomobject]@{ Value = $tp; Source = $source }
}

function Get-SigningCertificate([string]$tp) {
  foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
    $p = Join-Path $store $tp
    if (Test-Path -LiteralPath $p) { return Get-Item -LiteralPath $p }
  }
  throw "No certificate with thumbprint $tp in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
}

function Test-SelfSigned([System.Security.Cryptography.X509Certificates.X509Certificate2]$c) {
  return $c.Subject -eq $c.Issuer
}

# Everything this script knows about one file's signature, from three
# independent readings: WinVerifyTrust's HRESULT, the embedded PKCS#7, and the
# RFC 3161 token inside it.
function Get-SignatureInfo([string]$file) {
  $info = [ordered]@{
    Code = [InwireSign.Native]::Verify($file)
    Signer = $null
    Digest = $null
    CmsSignatureOk = $false
    Rfc3161 = $false
    LegacyTimestamp = $false
    TimestampTime = $null
    TimestampDigest = $null
    TimestampSigner = $null
  }
  $blob = [InwireSign.Native]::ReadPkcs7($file)
  if ($blob) {
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($blob)
    $si = $cms.SignerInfos[0]
    $info.Signer = $si.Certificate
    $info.Digest = $si.DigestAlgorithm.Value
    # The signer's signature over the signed attributes, which carry the
    # Authenticode digest. Signature only - the chain is WinVerifyTrust's job.
    try { $si.CheckSignature($true); $info.CmsSignatureOk = $true } catch { $info.CmsSignatureOk = $false }
    foreach ($attr in $si.UnsignedAttributes) {
      if ($attr.Oid.Value -eq $OID_RFC3161) {
        $info.Rfc3161 = $true
        $token = [InwireSign.Native]::ReadRfc3161Token($attr.Values[0].RawData)
        $info.TimestampDigest = $token[0]
        $info.TimestampTime = $token[1]
        $tsCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $tsCms.Decode($attr.Values[0].RawData)
        $info.TimestampSigner = $tsCms.SignerInfos[0].Certificate
      } elseif ($attr.Oid.Value -eq $OID_LEGACY_COUNTERSIGN) {
        $info.LegacyTimestamp = $true
      }
    }
  }
  return [pscustomobject]$info
}

function Describe([object]$info) {
  $parts = @()
  if ($info.Signer) { $parts += "signer $($info.Signer.Subject) [$($info.Signer.Thumbprint)]" }
  if ($info.Digest) { $parts += $(if ($info.Digest -eq $OID_SHA256) { 'sha256' } else { "digest $($info.Digest)" }) }
  if ($info.Rfc3161) {
    $alg = if ($info.TimestampDigest -eq $OID_SHA256) { 'sha256' } else { $info.TimestampDigest }
    # GeneralizedTime, YYYYMMDDHHMMSS[.fff]Z, shown as ISO 8601.
    $when = $info.TimestampTime -replace '^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d+)?Z$', '$1-$2-$3T$4:$5:$6Z'
    $parts += "RFC 3161 timestamp $when ($alg) by $($info.TimestampSigner.GetNameInfo('SimpleName', $false))"
  } elseif ($info.LegacyTimestamp) {
    $parts += 'legacy (non-RFC 3161) timestamp'
  } elseif ($info.Signer) {
    $parts += 'NO timestamp'
  }
  return ($parts -join '; ')
}

# Is this our signature, whole: our thumbprint, SHA-256, a CMS signature that
# checks, an RFC 3161 timestamp with a SHA-256 imprint, and a WinVerifyTrust
# answer that is either Valid or - for a self-signed certificate only - the
# untrusted-root code that is only ever reached after the digest verified.
# Takes the thumbprint rather than the store's certificate, so -Verify works on
# a machine that has the thumbprint but not the key.
function Test-OursAndWhole([object]$info, [string]$thumb, [bool]$demandTrusted) {
  if (-not $info.Signer -or $info.Signer.Thumbprint -ne $thumb) { return $false }
  if ($info.Digest -ne $OID_SHA256 -or -not $info.CmsSignatureOk) { return $false }
  if (-not $info.Rfc3161 -or $info.TimestampDigest -ne $OID_SHA256) { return $false }
  if ($info.Code -eq $S_OK) { return $true }
  if ($info.Code -eq $CERT_E_UNTRUSTEDROOT -and -not $demandTrusted -and (Test-SelfSigned $info.Signer)) { return $true }
  return $false
}

# What is wrong with a signature that is neither ours-and-whole nor a
# publisher's - the sentence a refusal (or a -Force) prints.
function Get-ExistingProblem([object]$info, [string]$thumb) {
  $signer = $info.Signer
  if ($signer.Thumbprint -eq $thumb) {
    $bits = @()
    $untrustedSelf = $info.Code -eq $CERT_E_UNTRUSTEDROOT -and (Test-SelfSigned $signer)
    if ($info.Code -ne $S_OK -and -not $untrustedSelf) { $bits += Format-HResult $info.Code }
    if ($info.Digest -ne $OID_SHA256) { $bits += "digest $($info.Digest)" }
    if (-not $info.CmsSignatureOk) { $bits += 'CMS signature does not verify' }
    if (-not $info.Rfc3161) { $bits += 'no RFC 3161 timestamp' }
    elseif ($info.TimestampDigest -ne $OID_SHA256) { $bits += "timestamp digest $($info.TimestampDigest)" }
    return "this certificate's own signature, but broken ($($bits -join '; '))"
  }
  if (Test-SelfSigned $signer) {
    return "a signature by ANOTHER self-signed certificate, $($signer.Subject) [$($signer.Thumbprint)], " +
      "$(Format-HResult $info.Code) - most likely an earlier certificate of this project's"
  }
  $hint = if ($info.Code -eq $TRUST_E_BAD_DIGEST) { ' - the file changed after they signed it' } else { '' }
  return "a signature by $($signer.Subject) that does not verify ($(Format-HResult $info.Code))$hint"
}

# All or nothing: sign and timestamp a copy, verify the copy, and only then
# replace the original. The copy goes to %TEMP% rather than beside the file,
# because a stray file left in release\win-unpacked by a killed build would be
# packaged by the installer's recursive [Files] glob.
function Invoke-Sign([string]$file, $cert, [string]$tsUrl) {
  $dir = Join-Path ([IO.Path]::GetTempPath()) ('inwire-sign-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $dir | Out-Null
  $work = Join-Path $dir (Split-Path -Leaf $file)
  try {
    Copy-Item -LiteralPath $file -Destination $work
    $r = Set-AuthenticodeSignature -LiteralPath $work -Certificate $cert -HashAlgorithm SHA256 -IncludeChain NotRoot -ErrorAction Stop
    if ($r.Status -eq 'NotSigned' -or $r.Status -eq 'HashMismatch' -or $r.Status -eq 'NotSupportedFileFormat') {
      throw "Set-AuthenticodeSignature left the file $($r.Status): $($r.StatusMessage)"
    }
    $delays = @(0, 2, 5, 10)
    $hr = -1
    foreach ($d in $delays) {
      if ($d -gt 0) { Start-Sleep -Seconds $d }
      $hr = [InwireSign.Native]::TimestampRfc3161($work, $tsUrl, $OID_SHA256)
      if ($hr -eq 0) { break }
      [Console]::Error.WriteLine("  timestamp from $tsUrl failed: $(Format-HResult $hr); retrying")
    }
    if ($hr -ne 0) {
      throw "could not add an RFC 3161 timestamp from $tsUrl ($(Format-HResult $hr)). A signature without one dies with the certificate; the file was left as it was."
    }
    $check = Get-SignatureInfo $work
    if (-not (Test-OursAndWhole $check $cert.Thumbprint $false)) {
      throw "the signed copy does not verify ($(Format-HResult $check.Code); $(Describe $check)); the file was left as it was."
    }
    [IO.File]::Copy($work, $file, $true)
  } finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# ---------------------------------------------------------------------------

$required = $Require -or ($env:INWIRE_REQUIRE_SIGNING -eq '1')
$tsUrl = if ($TimestampServer) { $TimestampServer } elseif ($env:INWIRE_SIGN_TIMESTAMP_URL) { $env:INWIRE_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

$files = @()
foreach ($p in @($Path) + @($MorePaths)) {
  if (-not $p) { continue }
  $resolved = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
  if (-not $resolved -or -not (Test-Path -LiteralPath $resolved.ProviderPath -PathType Leaf)) {
    [Console]::Error.WriteLine("sign.ps1: no such file: $p")
    exit 1
  }
  $files += $resolved.ProviderPath
}

$tp = Resolve-SigningThumbprint
$thumb = if ($tp) { $tp.Value } else { $null }
$cert = $null
if ($tp) {
  if (-not $Verify) {
    $cert = Get-SigningCertificate $thumb
    $problems = @()
    if (-not $cert.HasPrivateKey) { $problems += 'this account has no private key for it' }
    $eku = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -eq 0 -or -not (@($eku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }) -contains $OID_CODE_SIGNING)) { $problems += 'it is not a code-signing certificate' }
    $now = Get-Date
    if ($now -lt $cert.NotBefore -or $now -gt $cert.NotAfter) { $problems += ("it is valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}" -f $cert.NotBefore, $cert.NotAfter) }
    if ($problems.Count -gt 0) {
      [Console]::Error.WriteLine("sign.ps1: cannot sign with $($cert.Subject) [$($cert.Thumbprint)] (from $($tp.Source)): $($problems -join '; ').")
      exit 1
    }
  }
} elseif (-not $Verify) {
  if ($required) {
    [Console]::Error.WriteLine('sign.ps1: signing is REQUIRED (-Require or INWIRE_REQUIRE_SIGNING=1) and no certificate is configured.')
    [Console]::Error.WriteLine("  Give a thumbprint with -Thumbprint, INWIRE_SIGN_THUMBPRINT, or $ConfigPath")
    [Console]::Error.WriteLine('  (scripts\sign\new-cert.ps1 -WriteConfig creates a certificate and writes that file).')
    exit 1
  }
  Write-Warning ("sign.ps1: no code-signing certificate configured - leaving $($files.Count) file(s) UNSIGNED. " +
    'Set INWIRE_SIGN_THUMBPRINT or run scripts\sign\new-cert.ps1 -WriteConfig; INWIRE_REQUIRE_SIGNING=1 makes this an error.')
  foreach ($f in $files) { Write-Host "  unsigned  $f" }
  exit 0
}

$failed = 0
foreach ($file in $files) {
  $name = Split-Path -Leaf $file
  try {
    $info = Get-SignatureInfo $file

    if ($Verify) {
      if ($thumb -and (Test-OursAndWhole $info $thumb ([bool]$RequireTrusted))) {
        $note = if ($info.Code -eq $S_OK) { 'Valid' } else { 'intact; root not trusted on this PC yet (scripts\sign\trust-cert.ps1)' }
        Write-Host "  ok        $name  $note; $(Describe $info)"
      } elseif ($info.Code -eq $S_OK -and $info.Signer -and $info.Signer.Thumbprint -ne $thumb) {
        Write-Host "  ok        $name  Valid; $(Describe $info)"
      } else {
        $why = Format-HResult $info.Code
        if (-not $thumb -and $info.Code -eq $CERT_E_UNTRUSTEDROOT) {
          $why += '; no thumbprint is configured, so a self-signed signature cannot be recognised as this build''s (INWIRE_SIGN_THUMBPRINT or .signing.json)'
        }
        if ($thumb -and $info.Signer -and $info.Signer.Thumbprint -eq $thumb) {
          if (-not $info.Rfc3161) { $why += '; no RFC 3161 timestamp' }
          if ($info.Digest -ne $OID_SHA256) { $why += "; digest $($info.Digest)" }
          if (-not $info.CmsSignatureOk) { $why += '; CMS signature does not verify' }
        }
        [Console]::Error.WriteLine("  FAIL      $name  $why; $(Describe $info)")
        $failed++
      }
      continue
    }

    if ($info.Code -eq $TRUST_E_SUBJECT_FORM_UNKNOWN) {
      throw 'not a file type Authenticode can sign'
    }
    if (Test-OursAndWhole $info $thumb $false) {
      Write-Host "  skipped   $name  already signed by this certificate; $(Describe $info)"
      continue
    }
    if ($info.Signer) {
      # A publisher: valid, not ours, and not self-signed. Never replaced.
      if ($info.Code -eq $S_OK -and $info.Signer.Thumbprint -ne $thumb -and -not (Test-SelfSigned $info.Signer)) {
        Write-Host "  skipped   $name  validly signed by $($info.Signer.Subject)"
        continue
      }
      $problem = Get-ExistingProblem $info $thumb
      if (-not $Force) { throw "carries $problem. Refusing to replace it; look at why, then -Force re-signs it with this certificate." }
      Write-Host "  replacing $name  $problem (-Force)"
    } elseif ($info.Code -ne $TRUST_E_NOSIGNATURE) {
      # WinVerifyTrust sees something that is not "unsigned", and there is no
      # signer this script can read out of the certificate table.
      if (-not $Force) { throw "has a signature this script cannot read ($(Format-HResult $info.Code)). Refusing to replace it; -Force re-signs it." }
      Write-Host "  replacing $name  unreadable signature, $(Format-HResult $info.Code) (-Force)"
    }

    Invoke-Sign $file $cert $tsUrl

    $after = Get-SignatureInfo $file
    if (-not (Test-OursAndWhole $after $thumb $false)) {
      throw "re-verification failed after signing: $(Format-HResult $after.Code); $(Describe $after)"
    }
    $trust = if ($after.Code -eq $S_OK) { 'Valid' } else { 'intact; root not trusted on this PC yet' }
    Write-Host "  signed    $name  $trust; $(Describe $after)"
  } catch {
    [Console]::Error.WriteLine("  FAIL      $name  $($_.Exception.Message)")
    $failed++
  }
}

if ($failed -gt 0) {
  [Console]::Error.WriteLine("sign.ps1: $failed of $($files.Count) file(s) failed.")
  exit 1
}
exit 0
