/**
 * Code signing goes through one script, and no certificate is in the repository.
 *
 *   npx tsx scripts/sign/signing.ts
 *
 * ## What this holds
 *
 * Every signature in the build is made by `scripts/sign/sign.ps1`:
 * electron-builder reaches it through `electron/sign.cjs`, Inno Setup through
 * a `SignTool=` directive. The certificate is picked by thumbprint - from
 * INWIRE_SIGN_THUMBPRINT or the untracked `.signing.json` - so the self-signed
 * certificate this PC uses today can be replaced by a real one without an edit
 * to either build. That property is only real while:
 *
 *   - electron-builder has no certificate of its own configured (a
 *     `certificateSha1` would quietly bypass the script) and routes `sign`
 *     through the hook;
 *   - the hook calls sign.ps1 and nothing else, and does not choose the
 *     certificate itself;
 *   - setup.iss names the same script from its `[Setup]` section and signs the
 *     uninstaller as well as Setup;
 *   - no thumbprint, `.cer` or `.pfx` is committed, and `.signing.json` is
 *     ignored.
 *
 * And a signed build signs, or refuses, everything it ships:
 *
 *   - Inno signs only what Inno makes, so under /DSIGN setup.iss runs
 *     `verify-payload.ps1` over what [Files] installs and turns anything but
 *     its INWIRE-PAYLOAD-OK first line into a compile error. Before this, a
 *     signed Setup would have wrapped the stale, unsigned pack in
 *     release\win-unpacked without a word;
 *   - `npm run dist:signed` runs the whole release in order with
 *     INWIRE_REQUIRE_SIGNING=1, so no step can quietly skip signing;
 *   - sign.ps1 refuses a file whose signature is broken, somebody else's and
 *     invalid, or another self-signed certificate's, unless -Force - and
 *     never replaces a publisher's valid one;
 *   - and signs a copy, replacing the original only once the copy verifies,
 *     so a timestamp outage cannot leave a file signed but untimestamped.
 *
 * ## And the traps sign.ps1 was built around
 *
 * Each of these was found by running it, and each regresses silently:
 *
 *   - `Set-AuthenticodeSignature -TimestampServer` makes a LEGACY Authenticode
 *     countersignature, not RFC 3161, in both PowerShell editions. The RFC 3161
 *     timestamp is `SignerTimeStampEx2` with SIGNER_TIMESTAMP_RFC3161 (2).
 *   - A PSModulePath inherited from PowerShell 7 makes Windows PowerShell
 *     autoload pwsh's Microsoft.PowerShell.Security, which fails, and `Cert:`
 *     does not exist. Each script imports its own edition's copy by path.
 *   - `ForEach-Object Value` (the member-name form) honours ShouldProcess, so
 *     under `-WhatIf` it reads nothing - which made trust-cert.ps1's dry run
 *     reject a correct certificate.
 *   - Windows PowerShell reads a BOM-less script in the ANSI code page, so one
 *     non-ASCII character in a .ps1 is mojibake at best.
 *
 * ## Platforms
 *
 * Everything but the last section is a read of files and of `git`, and runs
 * everywhere - including CI on ubuntu, which is where a committed thumbprint
 * would be caught. The PowerShell parse is Windows-only and SKIPs elsewhere.
 * Nothing here signs, verifies a signature, or touches a certificate store;
 * `sign.ps1 -Verify` is the tool for a packed build.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel: string): string => readFileSync(join(root, rel), 'utf8');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, cond: boolean): void => check(name, cond, true);
const skip = (name: string, why: string): void => console.log(`SKIP  ${name} - ${why}`);

/** A SHA-1 thumbprint is 40 hex digits; a GUID's dashes keep it from matching. */
const THUMBPRINT = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])/;
/** Certificate and key containers that have no business being committed. */
const CERT_FILE = /\.(pfx|p12|pvk|spc|cer|crt|p7b)$/i;

const SIGN_PS1 = 'scripts/sign/sign.ps1';
/** The scripts that touch Cert: or the Authenticode cmdlets. */
const PS1_CERT = ['scripts/sign/sign.ps1', 'scripts/sign/new-cert.ps1', 'scripts/sign/trust-cert.ps1'];
/** Every PowerShell script here: parsed, ASCII, no member-name ForEach, no thumbprint. */
const PS1 = [...PS1_CERT, 'scripts/sign/verify-payload.ps1', 'scripts/sign/build-signed.ps1'];

/** Where a string first occurs, or -1 - for "this comes before that". */
const at = (text: string, needle: string): number => text.indexOf(needle);

// ---------------------------------------------------------------------------
console.log('--- electron-builder.yml routes signing through the hook ---\n');
{
  const yml = read('electron-builder.yml')
    .split('\n')
    .map((line) => line.replace(/(^|\s)#.*$/, '').trimEnd())
    .filter((line) => line.trim() !== '');

  // The `win:` mapping, up to the next top-level key.
  const start = yml.findIndex((l) => /^win:\s*$/.test(l));
  const end = yml.findIndex((l, i) => i > start && /^\S/.test(l));
  const win = start < 0 ? [] : yml.slice(start + 1, end < 0 ? undefined : end);
  const winText = win.join('\n');

  checkTrue('there is a `win:` section', start >= 0);
  checkTrue('win.signtoolOptions.sign is ./electron/sign.cjs',
    /^\s+signtoolOptions:\s*\n(?:\s{4,}.*\n)*?\s{4,}sign:\s*\.\/electron\/sign\.cjs\s*$/m.test(winText + '\n'));

  const list = (key: string): string[] => {
    const i = win.findIndex((l) => new RegExp(`^\\s+${key}:\\s*$`).test(l));
    if (i < 0) return [];
    const indent = win[i].search(/\S/);
    const out: string[] = [];
    for (const l of win.slice(i + 1)) {
      const m = /^(\s*)-\s*(.+)$/.exec(l);
      if (!m || m[1].length <= indent - 1) break;
      out.push(m[2].trim());
    }
    return out;
  };
  check('signingHashAlgorithms is sha256 alone (the default calls the hook twice, sha1 first)',
    list('signingHashAlgorithms'), ['sha256']);
  checkTrue('signExts adds .dll (Electron ships ffmpeg/vulkan/swiftshader DLLs unsigned)',
    list('signExts').includes('.dll'));

  // Any of these would sign WITHOUT the script, or not at all.
  const all = yml.join('\n');
  for (const key of ['certificateFile', 'certificatePassword', 'certificateSha1', 'certificateSubjectName',
    'azureSignOptions', 'cscLink', 'cscKeyPassword']) {
    checkTrue(`no \`${key}\` - the certificate is sign.ps1's to choose`, !new RegExp(`\\b${key}\\s*:`).test(all));
  }
  checkTrue('signing is not switched off (signExecutable / signAndEditExecutable: false)',
    !/\b(signExecutable|signAndEditExecutable)\s*:\s*false\b/.test(all));
  checkTrue('afterPack is still the fuse hook, which electron-builder runs BEFORE signing',
    /^afterPack:\s*electron\/afterPack\.cjs\s*$/m.test(all));
}

// ---------------------------------------------------------------------------
console.log('\n--- electron/sign.cjs calls sign.ps1 and nothing else ---\n');
{
  const raw = read('electron/sign.cjs');
  const code = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const scripts = [...code.matchAll(/['"]([^'"]+\.ps1)['"]/g)].map((m) => m[1]);
  check('the only script it names is sign.ps1', scripts, ['sign.ps1']);
  checkTrue('...at scripts/sign/sign.ps1', /join\(\s*__dirname\s*,\s*'\.\.'\s*,\s*'scripts'\s*,\s*'sign'\s*,\s*'sign\.ps1'\s*\)/.test(code));

  const calls = [...code.matchAll(/\b(spawnSync|spawn|execFileSync|execFile|execSync|exec|fork)\s*\(/g)].map((m) => m[1]);
  check('exactly one child process, spawnSync', calls, ['spawnSync']);
  checkTrue('...running the script with -File', /'-File'\s*,\s*SCRIPT\b/.test(code));

  for (const word of ['signtool', 'Set-AuthenticodeSignature', 'osslsigncode', 'computeSignToolArgs',
    '-Thumbprint', 'INWIRE_SIGN_THUMBPRINT', 'cscInfo']) {
    checkTrue(`it does not reach for \`${word}\` - signing and certificate choice are sign.ps1's`,
      !code.toLowerCase().includes(word.toLowerCase()));
  }

  const hook = createRequire(import.meta.url)(join(root, 'electron', 'sign.cjs')) as { default?: unknown };
  check('it exports a default function, which is what electron-builder calls', typeof hook.default, 'function');
}

// ---------------------------------------------------------------------------
console.log('\n--- installer/setup.iss signs through the same script ---\n');
{
  const lines = read('installer/setup.iss').split(/\r?\n/);
  const section = (l: string): boolean => /^\[[A-Za-z]+\]\s*$/.test(l);
  const setupAt = lines.findIndex((l) => /^\[Setup\]\s*$/.test(l));
  const setupEnd = lines.findIndex((l, i) => i > setupAt && section(l));
  const setup = setupAt < 0 ? [] : lines.slice(setupAt + 1, setupEnd < 0 ? undefined : setupEnd);
  const live = (ls: string[]) => ls.filter((l) => !/^\s*;/.test(l));

  checkTrue('there is a [Setup] section', setupAt >= 0);

  const tool = live(setup).filter((l) => /^SignTool\s*=/i.test(l));
  check('[Setup] has one SignTool= line', tool.length, 1);
  const params = /^SignTool\s*=\s*inwire\s+(.*)$/i.exec(tool[0] ?? '')?.[1] ?? '';
  checkTrue('...naming the `inwire` Sign Tool', params !== '');
  checkTrue('...with the script from #SignScript, -Require and $f',
    /-File\s+\$q\{#SignScript\}\$q/.test(params) && /(^|\s)-Require(\s|$)/.test(params) && /-Path\s+\$f\b/.test(params));

  const define = live(setup).map((l) => /^\s*#define\s+SignScript\s+(.*)$/.exec(l)?.[1]).find(Boolean) ?? '';
  checkTrue('#define SignScript points at scripts\\sign\\sign.ps1, relative to the .iss',
    /SourcePath\s*\+\s*"\.\.\\scripts\\sign\\sign\.ps1"/.test(define));
  checkTrue('[Setup] has SignedUninstaller=yes', live(setup).some((l) => /^SignedUninstaller\s*=\s*yes\s*$/i.test(l)));

  // Gated, so a plain `iscc installer\setup.iss` still compiles: a SignTool
  // name that the command line did not define is a compile error. The block
  // holds a nested `#if`, so its end is found by depth, not by the first
  // `#endif` after it.
  const ifdef = setup.findIndex((l) => /^\s*#ifdef\s+SIGN\s*$/.test(l));
  let endif = -1;
  for (let i = ifdef + 1, depth = 1; ifdef >= 0 && i < setup.length; i++) {
    if (/^\s*#(if|ifdef|ifndef)\b/.test(setup[i])) depth++;
    else if (/^\s*#endif\b/.test(setup[i]) && --depth === 0) { endif = i; break; }
  }
  const gated = ifdef >= 0 && endif > ifdef ? setup.slice(ifdef + 1, endif) : [];
  checkTrue('both directives sit inside #ifdef SIGN ... #endif',
    gated.some((l) => /^SignTool\s*=/i.test(l)) && gated.some((l) => /^SignedUninstaller\s*=/i.test(l)));
  checkTrue('the comments say how to compile it signed (/DSIGN and /Sinwire=)',
    setup.some((l) => /^\s*;.*\/DSIGN\b.*\/Sinwire=/.test(l)));

  // The payload check. Inno signs only what Inno makes, so without this a
  // signed Setup wraps whatever release\win-unpacked and agent-rs\dist happen
  // to hold - a stale unsigned pack, in the case that prompted it.
  const gatedText = gated.join('\n');
  const defineOf = (name: string): string =>
    new RegExp(`^\\s*#define\\s+${name}\\s+(.*)$`, 'm').exec(gatedText)?.[1] ?? '';
  checkTrue('under SIGN, PayloadScript is scripts\\sign\\verify-payload.ps1',
    /SourcePath\s*\+\s*"\.\.\\scripts\\sign\\verify-payload\.ps1"/.test(defineOf('PayloadScript')));
  checkTrue('...checking what [Files] installs: AppSource, and AgentSource\\AgentExeName',
    /SourcePath\s*\+\s*AppSource\s*$/.test(defineOf('PayloadApp'))
    && /SourcePath\s*\+\s*AgentSource\s*\+\s*"\\"\s*\+\s*AgentExeName\s*$/.test(defineOf('PayloadAgent')));
  const verdict = defineOf('PayloadVerdict');
  checkTrue('...run at compile time through ExecAndGetFirstLine, with all three',
    /^ExecAndGetFirstLine\(/.test(verdict) && ['PayloadScript', 'PayloadApp', 'PayloadAgent'].every((n) => verdict.includes(n)));
  checkTrue('...and anything but the INWIRE-PAYLOAD-OK line is a compile Error()',
    /#if\s+Pos\("INWIRE-PAYLOAD-OK ",\s*PayloadVerdict\)\s*!=\s*1\s*\n\s*#expr\s+Error\(/.test(gatedText));

  const outside = live(lines.filter((_, i) => i <= setupAt || (setupEnd >= 0 && i >= setupEnd)));
  check('no SignTool= outside [Setup]', outside.filter((l) => /^SignTool\s*=/i.test(l)).length, 0);
}

// ---------------------------------------------------------------------------
console.log('\n--- no certificate or thumbprint in the repository ---\n');
{
  const gitignore = read('.gitignore').split(/\r?\n/).map((l) => l.trim());
  checkTrue('.signing.json is gitignored', gitignore.includes('.signing.json'));

  const signingFiles = ['.gitignore', 'electron-builder.yml', 'electron/sign.cjs', 'installer/setup.iss', ...PS1,
    'scripts/sign/signing.ts'];
  for (const rel of signingFiles) {
    checkTrue(`${rel} contains no 40-hex-digit thumbprint`, !THUMBPRINT.test(read(rel)));
  }
  const strays = readdirSync(join(root, 'scripts', 'sign')).filter((f) => CERT_FILE.test(f) || f === '.signing.json');
  check('nothing certificate-shaped sits in scripts/sign', strays, []);

  const git = (args: string[]) => spawnSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const ls = git(['ls-files', '-z']);
  if (ls.error || ls.status !== 0) {
    skip('tracked-file checks', 'git is not available here');
  } else {
    const tracked = ls.stdout.split('\0').filter(Boolean);
    check('no .pfx/.p12/.cer/.crt/.pvk/.spc/.p7b is tracked', tracked.filter((f) => CERT_FILE.test(f)), []);
    check('.signing.json is not tracked', tracked.filter((f) => f.endsWith('.signing.json')), []);

    // The one that matters most, and the only way to look for it: THIS
    // machine's thumbprint, anywhere git would commit it - tracked files and
    // untracked-but-not-ignored ones alike.
    let local: string | undefined = process.env.INWIRE_SIGN_THUMBPRINT;
    const cfg = join(root, '.signing.json');
    if (!local && existsSync(cfg)) {
      try { local = (JSON.parse(readFileSync(cfg, 'utf8')) as { thumbprint?: string }).thumbprint; } catch { /* checked below */ }
    }
    const tp = (local ?? '').replace(/[^0-9A-Fa-f]/g, '');
    if (tp.length !== 40) {
      skip('the configured thumbprint appears in no committable file', 'no thumbprint is configured on this machine');
    } else {
      const found = git(['grep', '--untracked', '-I', '-i', '-l', '-F', '-e', tp]);
      // `git grep` exits 1 for "no match", 0 for a match, >1 for an error.
      checkTrue('git grep ran', found.status === 0 || found.status === 1);
      check('the configured thumbprint appears in no committable file',
        found.stdout.split('\n').filter(Boolean), []);
    }
  }
}

// ---------------------------------------------------------------------------
console.log('\n--- sign.ps1 and its siblings keep the fixes they were built on ---\n');
{
  const sign = read(SIGN_PS1);
  for (const [what, needle] of [
    ['reads -Thumbprint', '[string]$Thumbprint'],
    ['reads INWIRE_SIGN_THUMBPRINT', '$env:INWIRE_SIGN_THUMBPRINT'],
    ['reads .signing.json', "'.signing.json'"],
    ['honours INWIRE_REQUIRE_SIGNING', "$env:INWIRE_REQUIRE_SIGNING -eq '1'"],
    ['has a -Verify switch', '[switch]$Verify'],
    ['signs SHA-256', '-HashAlgorithm SHA256'],
    ['checks for the RFC 3161 attribute', '1.3.6.1.4.1.311.3.3.1'],
  ] as const) {
    checkTrue(`sign.ps1 ${what}`, sign.includes(needle));
  }
  const authenticode = sign.split('\n').filter((l) => /^\s*\$\w+\s*=\s*Set-AuthenticodeSignature\b/.test(l));
  check('sign.ps1 calls Set-AuthenticodeSignature once', authenticode.length, 1);
  checkTrue('...WITHOUT -TimestampServer, which makes a legacy countersignature, not RFC 3161',
    authenticode.every((l) => !/-TimestampServer\b/.test(l)));
  checkTrue('the timestamp is SignerTimeStampEx2 with SIGNER_TIMESTAMP_RFC3161 (2)',
    /SignerTimeStampEx2\(2\s*\/\*\s*SIGNER_TIMESTAMP_RFC3161\s*\*\//.test(sign));
  checkTrue('...whose algorithm argument is an OID string, not an ALG_ID (0x800C is an access violation)',
    /\[MarshalAs\(UnmanagedType\.LPStr\)\]\s*string\s+pszTimeStampAlgorithmOid/.test(sign));

  // Refuse, don't overwrite: a signature that is broken, somebody else's and
  // invalid, or another self-signed certificate's means something touched the
  // file after it was signed. Only -Force replaces it; a publisher's valid
  // signature is never replaced.
  checkTrue('sign.ps1 has a -Force switch', /\[switch\]\$Force\b/.test(sign));
  check('...and both replace paths throw unless it is given',
    (sign.match(/if \(-not \$Force\) \{ throw /g) ?? []).length, 2);
  checkTrue('a publisher is valid, not ours, and NOT self-signed (a self-signed "valid" is a local decision)',
    /\$info\.Code -eq \$S_OK -and \$info\.Signer\.Thumbprint -ne \$thumb -and -not \(Test-SelfSigned \$info\.Signer\)/.test(sign));
  checkTrue('...and that skip comes before the -Force check, so -Force never replaces one',
    at(sign, 'validly signed by $($info.Signer.Subject)') >= 0
    && at(sign, 'validly signed by $($info.Signer.Subject)') < at(sign, 'if (-not $Force) { throw '));

  // All or nothing: sign and timestamp a copy, verify it, then replace.
  const invoke = /function Invoke-Sign[\s\S]*?\n\}/.exec(sign)?.[0] ?? '';
  checkTrue('Invoke-Sign signs a COPY ($work), never the file in place',
    /Set-AuthenticodeSignature -LiteralPath \$work\b/.test(invoke)
    && !/Set-AuthenticodeSignature -LiteralPath \$file\b/.test(invoke));
  checkTrue('...timestamps the copy',
    /TimestampRfc3161\(\$work,/.test(invoke));
  checkTrue('...and copies it over the original only after verifying it',
    at(invoke, 'Test-OursAndWhole $check') >= 0
    && at(invoke, 'Test-OursAndWhole $check') < at(invoke, '[IO.File]::Copy($work, $file, $true)'));
  checkTrue('...in %TEMP%, not beside the file (a stray copy there would be packaged)',
    /Join-Path \(\[IO\.Path\]::GetTempPath\(\)\)/.test(invoke));

  const payload = read('scripts/sign/verify-payload.ps1');
  checkTrue('verify-payload.ps1 defers the judgement to sign.ps1 -Verify',
    /-File \$sign -Verify\b/.test(payload));
  checkTrue('...finds PE files by content (MZ, then PE\\0\\0), not by extension',
    /0x5A4D/.test(payload) && /0x00004550/.test(payload));
  checkTrue('...prints its verdict BEFORE the detail (ISPP sees one line)',
    at(payload, 'Write-Output "INWIRE-PAYLOAD-OK') >= 0
    && at(payload, 'Write-Output "INWIRE-PAYLOAD-OK') < at(payload, '$lines | ForEach-Object { Write-Output $_ }'));
  checkTrue('...and fails closed: an unexpected error is still a REFUSED first line',
    /trap \{\s*\n\s*Write-Output "INWIRE-PAYLOAD-REFUSED/.test(payload));
  checkTrue('...and an empty directory is a refusal, not a pass',
    /no PE files in it/.test(payload));

  const pkg = JSON.parse(read('package.json')) as { scripts?: Record<string, string> };
  check('package.json has dist:signed -> scripts/sign/build-signed.ps1', pkg.scripts?.['dist:signed'],
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts/sign/build-signed.ps1');
  const dist = read('scripts/sign/build-signed.ps1');
  const steps = ["Step 'npm run build:agent'", "Step 'npm run pack'", "Step 'verify-payload.ps1'",
    "Step 'iscc /DSIGN'", "Step 'sign.ps1 -Verify Inwire-Setup.exe'"].map((s) => at(dist, s));
  checkTrue('build-signed.ps1 runs agent -> pack -> verify payload -> iscc -> verify Setup, in that order',
    steps.every((i) => i >= 0) && steps.every((i, n) => n === 0 || steps[n - 1] < i));
  checkTrue('...with INWIRE_REQUIRE_SIGNING=1 set before the first step',
    at(dist, "$env:INWIRE_REQUIRE_SIGNING = '1'") >= 0 && at(dist, "$env:INWIRE_REQUIRE_SIGNING = '1'") < steps[0]);
  checkTrue('...and ISCC with /DSIGN and the inwire Sign Tool',
    /& \$iscc \/DSIGN '\/Sinwire=powershell\.exe [^']*\$p'/.test(dist));

  const cert = read('scripts/sign/new-cert.ps1');
  checkTrue('new-cert.ps1 makes the key non-exportable', /-KeyExportPolicy\s+NonExportable\b/.test(cert));
  checkTrue('...in Cert:\\CurrentUser\\My', /-CertStoreLocation\s+Cert:\\CurrentUser\\My\b/.test(cert));
  checkTrue('...RSA 3072', /-KeyAlgorithm\s+RSA\s+-KeyLength\s+3072\b/.test(cert));
  // Code only: the header is allowed to name the cmdlet it is explaining.
  const certCode = cert.replace(/<#[\s\S]*?#>/g, '').replace(/(^|\s)#.*$/gm, '$1');
  checkTrue('...and never writes a .pfx', !/Export-PfxCertificate/i.test(certCode));
  checkTrue('...and says, in its header, that the key has no interactive protection and why that was accepted',
    /no interactive protection/.test(cert) && /ANY process running as this user can sign/.test(cert)
    && /It was accepted because/.test(cert));

  const trust = read('scripts/sign/trust-cert.ps1');
  checkTrue('trust-cert.ps1 writes LocalMachine Root and TrustedPublisher',
    /\$Stores\s*=\s*@\('Root',\s*'TrustedPublisher'\)/.test(trust) && /X509Store\(\$name,\s*'LocalMachine'\)/.test(trust));
  checkTrue('...requires the thumbprint it is to trust',
    /\[Parameter\(Mandatory = \$true\)\]\s*\n\s*\[string\]\$Thumbprint/.test(trust));
  checkTrue('...and supports -WhatIf', /SupportsShouldProcess\s*=\s*\$true/.test(trust));

  for (const rel of PS1_CERT) {
    checkTrue(`${rel} imports this edition's Microsoft.PowerShell.Security by path`,
      /Import-Module \(Join-Path \$PSHOME 'Modules\\Microsoft\.PowerShell\.Security'\)/.test(read(rel)));
  }
  for (const rel of PS1) {
    const text = read(rel);
    checkTrue(`${rel} has no \`ForEach-Object <Member>\` (reads nothing under -WhatIf)`,
      !/ForEach-Object\s+(?![{-])[A-Za-z]/.test(text));
    const bytes = readFileSync(join(root, rel));
    const bom = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
    checkTrue(`${rel} is ASCII (Windows PowerShell reads a BOM-less script as ANSI)`,
      bom || bytes.every((b) => b < 0x80));
  }
}

// ---------------------------------------------------------------------------
console.log('\n--- the scripts parse, under the PowerShell that runs them ---\n');
if (process.platform !== 'win32') {
  skip('Windows PowerShell parses scripts/sign/*.ps1', 'Windows only');
} else {
  const quoted = PS1.map((rel) => `'${join(root, rel).replace(/'/g, "''")}'`).join(',');
  const cmd = `foreach ($f in @(${quoted})) { $e = $null; `
    + '[void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e); '
    + '"{0}|{1}|{2}" -f (Split-Path -Leaf $f), @($e).Count, $(if (@($e).Count) { $e[0].Message } else { "" }) }';
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { encoding: 'utf8' });
  if (ps.error) {
    skip('Windows PowerShell parses scripts/sign/*.ps1', `powershell.exe did not start: ${ps.error.message}`);
  } else {
    const rows = ps.stdout.split(/\r?\n/).filter((l) => l.includes('|'));
    check('one parse result per script', rows.length, PS1.length);
    for (const row of rows) {
      const [file, count, message] = row.split('|');
      check(`${file} parses with no errors${message ? ` (${message})` : ''}`, count, '0');
    }
  }
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED.`);
  process.exit(1);
}
console.log('Signing goes through one script, and no certificate is in the repository.');
process.exit(0);
