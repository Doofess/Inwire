/**
 * The Update Center's decisions, all of them, without a network or a UAC prompt.
 *
 *   npx tsx scripts/electron/update-center.ts
 *
 * This feature downloads an executable and runs it **as an administrator**, so
 * the things it gets wrong are not cosmetic. Four of its decisions are checked
 * here because each has a failure that is silent, confident, and wrong:
 *
 * 1. **The version comparison.** Npcap is `1.88`; the `wpcap.dll` beside it
 *    reports `1.10.6`, which is the libpcap API version. String-compare them,
 *    or read the wrong file, and the row says "update available" forever -
 *    including straight after a successful install.
 * 2. **The registry read.** Npcap registers in the 32-bit view only, so a
 *    plain `reg query` exits 1 with empty stdout, which is precisely the shape
 *    `agentService.ts` reads as proof of absence. The parser is therefore held
 *    to **real captured output**, not to a string this file also wrote.
 * 3. **The manifest.** It is remote input that names an executable to run
 *    elevated. Every field it can lie about is checked, and the download-host
 *    allowlist is checked against the suffix bug (`evilnpcap.com`) rather than
 *    only against the happy path.
 * 4. **The command line.** `ELEVATE_ARGV` is asserted **byte for byte**
 *    against a literal, because a quoting bug there does not fail - it runs a
 *    different file, elevated.
 *
 * What this cannot cover is the UAC prompt itself and a real installer's exit
 * code. Those are `scripts/electron/update-center-drive.ts`, run by hand.
 */
import {
  canApply, compareVersions, decideState, isVersion, versionGroups,
  type Available, type Component,
} from '../../electron/updateCenter/components';
import {
  DEFAULT_UPDATE_FEED_URL, isAllowedDownload, isSha256Hex, MAX_DOWNLOAD_BYTES,
  parseManifest, resolveFeedUrl, UPDATE_FEED_ENV,
} from '../../electron/updateCenter/manifest';
import {
  createDigest, digestMatches, overSize, verifyDownload,
} from '../../electron/updateCenter/verify';
import {
  awaitsInstaller, ELEVATE_ARGV, ELEVATE_SCRIPT, elevationEnv, INSTALLER_ARGS,
  LAUNCH_ARGV, LAUNCH_SCRIPT, readElevationResult,
} from '../../electron/updateCenter/elevate';
import { parseDisplayVersion, readNpcap } from '../../electron/updateCenter/npcap';
import {
  actionLabel, canApply as canApplyInRenderer, EMPTY_SNAPSHOT, isBusy, normalizeSnapshot,
  stateLabel, withAgentRow, type UpdateComponent,
} from '../../src/services/updateCenter';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const FEED = 'https://updates.example.test/manifest.json';

function available(over: Partial<Available> = {}): Available {
  return {
    version: '1.88',
    url: 'https://npcap.com/dist/npcap-1.88.exe',
    sha256: 'a'.repeat(64),
    size: 1320424,
    kind: 'vendor-installer',
    minAppVersion: '1.0.0',
    ...over,
  };
}

console.log('--- comparing versions, including the pair that started this ---\n');

{
  check('equal is zero', compareVersions('1.88', '1.88'), 0);
  check('a newer minor is greater', compareVersions('1.88', '1.79'), 1);
  check('...and the reverse', compareVersions('1.79', '1.88'), -1);

  // The case `installer/setup.iss` wrote its own comparator for: as strings,
  // '1.10.0' sorts before '1.9.0'.
  check('1.10.0 is newer than 1.9.0', compareVersions('1.10.0', '1.9.0'), 1);

  // Npcap's version against the version `wpcap.dll` reports. If this ever
  // answers -1, something has started reading the libpcap number and the
  // Npcap row will offer an update that is already installed.
  check('Npcap 1.88 is newer than libpcap 1.10.6', compareVersions('1.88', '1.10.6'), 1);

  check('missing groups count as zero', compareVersions('1.88', '1.88.0'), 0);
  check('...in both directions', compareVersions('1.88.1', '1.88'), 1);
  check('a leading v is ignored', compareVersions('v2.0', '2.0'), 0);
  check('a build suffix is ignored', compareVersions('1.88-oem', '1.88'), 0);

  check('groups of a plain version', versionGroups('1.10.6'), [1, 10, 6]);
  check('nothing numeric gives nothing', versionGroups('unknown'), []);
  checkTrue('...and that is not a version', !isVersion('unknown'));
  checkTrue('a null installed version is not a version', !isVersion(null));
  checkTrue('an ordinary one is', isVersion('1.88'));
}

console.log('\n--- what the registry actually says ---\n');

{
  // Captured verbatim from
  //   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst
  //             /v DisplayVersion /reg:32
  // on Windows 11 26200 with Npcap 1.88 installed. The leading blank line and
  // the four-space runs are the tool's, not this file's.
  const real = '\r\n'
    + 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NpcapInst\r\n'
    + '    DisplayVersion    REG_SZ    1.88\r\n\r\n';
  check('the installed version is read', parseDisplayVersion(real), '1.88');
  check('a four-part version survives', parseDisplayVersion(real.replace('1.88', '1.88.0.1')), '1.88.0.1');
  check('tabs work as well as spaces',
    parseDisplayVersion(real.replace(/ {4}/g, '\t')), '1.88');

  // The 64-bit view of the same query on the same machine: exit 1, empty
  // stdout. This is what makes the /reg:32 ordering load-bearing.
  check('nothing found is null, never a default', parseDisplayVersion(''), null);
  check('...and so is a key with no DisplayVersion', parseDisplayVersion(
    '\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Npcap\r\n'
    + '    AdminOnly    REG_DWORD    0x0\r\n'
    + '    WinPcapCompatible    REG_DWORD    0x0\r\n'), null);

  // A DWORD where a string was expected must not be read as a version.
  check('a REG_DWORD is not a version',
    parseDisplayVersion('    DisplayVersion    REG_DWORD    0x188\r\n'), null);
}

console.log('\n--- the manifest, and everything it is not allowed to say ---\n');

{
  const good = JSON.stringify({
    schema: 1,
    generated: '2026-09-12T00:00:00Z',
    components: {
      npcap: {
        version: '1.88', kind: 'vendor-installer', minAppVersion: '1.0.0',
        url: 'https://npcap.com/dist/npcap-1.88.exe',
        sha256: 'A'.repeat(64), size: 1320424,
      },
      inwire: {
        version: '1.1.0', kind: 'inwire-installer', minAppVersion: '1.0.0',
        url: 'https://updates.example.test/Inwire-Setup-1.1.0.exe',
        sha256: 'b'.repeat(64), size: 251658240,
      },
    },
  });

  const parsed = parseManifest(good, FEED);
  checkTrue('a well-formed manifest parses', parsed !== null);
  check('...with both rows', Object.keys(parsed?.components ?? {}).sort(), ['inwire', 'npcap']);
  check('...and the hash is lowercased once, here', parsed?.components.npcap?.sha256, 'a'.repeat(64));

  const swap = (find: string, replace: string) => parseManifest(good.replace(find, replace), FEED);

  check('a truncated document is refused', parseManifest(good.slice(0, 40), FEED), null);
  check('an array is refused', parseManifest('[]', FEED), null);
  check('a null document is refused', parseManifest('null', FEED), null);
  check('empty text is refused', parseManifest('', FEED), null);
  check('an unknown schema is refused', swap('"schema":1', '"schema":2'), null);
  check('a missing hash is refused', swap('"' + 'A'.repeat(64) + '"', 'null'), null);
  check('a short hash is refused', swap('A'.repeat(64), 'A'.repeat(63)), null);
  check('a non-hex hash is refused', swap('A'.repeat(64), 'z'.repeat(64)), null);
  check('a zero size is refused', swap('1320424', '0'), null);
  check('a fractional size is refused', swap('1320424', '1320424.5'), null);
  check('a size past the cap is refused', swap('1320424', String(MAX_DOWNLOAD_BYTES + 1)), null);
  check('an unknown kind is refused', swap('vendor-installer', 'powershell-script'), null);
  check('an unparseable version is refused', swap('"1.88"', '"latest"'), null);
  check('an unparseable minAppVersion is refused', swap('"1.0.0"', '"any"'), null);

  // The row that matters most: a feed that has been tampered with cannot
  // nominate a different executable, even with a matching hash it also wrote.
  check('Npcap from anywhere but npcap.com is refused',
    swap('https://npcap.com/dist', 'https://updates.example.test/dist'), null);
  check('...and http is refused even from npcap.com',
    swap('https://npcap.com/dist', 'http://npcap.com/dist'), null);
  check('our own artifact must come from the feed host',
    swap('https://updates.example.test/Inwire', 'https://elsewhere.example/Inwire'), null);

  // A newer feed may carry rows this build has never heard of. Refusing the
  // document over one would make the feed un-evolvable.
  const future = good.replace('"npcap":', '"quantumfoo":{"version":"9"},"npcap":');
  checkTrue('an unknown component id is skipped, not fatal', parseManifest(future, FEED) !== null);
  check('...and does not appear', Object.keys(parseManifest(future, FEED)?.components ?? {}).sort(),
    ['inwire', 'npcap']);
}

console.log('\n--- the download host allowlist ---\n');

{
  checkTrue('npcap.com is allowed',
    isAllowedDownload('npcap', 'https://npcap.com/dist/npcap-1.88.exe', FEED));
  checkTrue('www.npcap.com too',
    isAllowedDownload('npcap', 'https://www.npcap.com/dist/npcap-1.88.exe', FEED));

  // The suffix bug, which is the reason this is an exact match and not
  // `endsWith`. Both of these end with "npcap.com".
  checkTrue('evilnpcap.com is not npcap.com',
    !isAllowedDownload('npcap', 'https://evilnpcap.com/dist/npcap-1.88.exe', FEED));
  checkTrue('a subdomain is not npcap.com either',
    !isAllowedDownload('npcap', 'https://npcap.com.evil.test/x.exe', FEED));
  checkTrue('nor is a userinfo trick',
    !isAllowedDownload('npcap', 'https://npcap.com@evil.test/x.exe', FEED));
  checkTrue('garbage is not a URL',
    !isAllowedDownload('npcap', 'not a url', FEED));
  checkTrue('our own rows follow the feed host',
    isAllowedDownload('inwire', 'https://updates.example.test/a.exe', FEED));
  checkTrue('...and only the feed host',
    !isAllowedDownload('inwire', 'https://npcap.com/a.exe', FEED));
}

console.log('\n--- the feed URL, and its dev override ---\n');

{
  check('no override gives the built-in', resolveFeedUrl({}), DEFAULT_UPDATE_FEED_URL);
  check('an empty override is ignored',
    resolveFeedUrl({ [UPDATE_FEED_ENV]: '   ' }), DEFAULT_UPDATE_FEED_URL);
  check('an override wins', resolveFeedUrl({ [UPDATE_FEED_ENV]: FEED }), FEED);

  // `.invalid` is reserved by RFC 2606 and can never resolve, so a build that
  // ships the placeholder reaches nothing rather than reaching somebody else.
  checkTrue('the placeholder cannot resolve', DEFAULT_UPDATE_FEED_URL.includes('.invalid/'));

  checkTrue('a 64-hex string is a digest', isSha256Hex('0'.repeat(64)));
  checkTrue('...and mixed case is too', isSha256Hex('aF'.repeat(32)));
  checkTrue('63 is not', !isSha256Hex('0'.repeat(63)));
}

console.log('\n--- verifying what arrived ---\n');

{
  // Hashed for real rather than compared as strings, so this also proves the
  // streaming digest is wired to the algorithm it claims.
  const digest = createDigest();
  digest.update(new TextEncoder().encode('abc'));
  const abc = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  check('sha256("abc") is the NIST vector', digest.hex(), abc);

  const chunked = createDigest();
  chunked.update(new TextEncoder().encode('a'));
  chunked.update(new TextEncoder().encode('bc'));
  check('...and chunking does not change it', chunked.hex(), abc);

  checkTrue('a digest matches itself', digestMatches(abc, abc));
  checkTrue('...case-insensitively', digestMatches(abc.toUpperCase(), abc));
  checkTrue('one bit off does not match', !digestMatches(abc.replace('ba7', 'ba6'), abc));

  checkTrue('exactly the declared size is fine', !overSize(1320424, 1320424));
  checkTrue('one byte more is not', overSize(1320425, 1320424));

  check('the happy path verifies', verifyDownload(3, 3, abc, abc), { ok: true });
  check('a truncated download is refused', verifyDownload(2, 3, abc, abc).ok, false);
  check('a long download is refused', verifyDownload(4, 3, abc, abc).ok, false);
  check('a mismatched digest is refused', verifyDownload(3, 3, 'f'.repeat(64), abc).ok, false);
}

console.log('\n--- the elevated command line, byte for byte ---\n');

{
  // A literal, not a re-derivation. Computing the expected value the same way
  // the module does would assert that Buffer is deterministic, which is not in
  // doubt; what is in doubt is whether somebody edits the script and does not
  // notice that the thing being run elevated has changed.
  const expected = [
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    'JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQAgAD0AIAAiAFMAdABvAHAAIgAKAHQAcgB5ACAAewAKACAAIAAkAHAAIAA9ACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABlAG4AdgA6AEkATgBXAEkAUgBFAF8ASQBOAFMAVABBAEwATABFAFIAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJABlAG4AdgA6AEkATgBXAEkAUgBFAF8AQQBSAEcAUwAgAC0AVgBlAHIAYgAgAFIAdQBuAEEAcwAgAC0AVwBhAGkAdAAgAC0AUABhAHMAcwBUAGgAcgB1AAoAIAAgAFcAcgBpAHQAZQAtAE8AdQB0AHAAdQB0ACAAKAAiAEkATgBXAEkAUgBFAF8AUgBFAFMAVQBMAFQAPQBvAGsAOgAiACAAKwAgACQAcAAuAEUAeABpAHQAQwBvAGQAZQApAAoAfQAgAGMAYQB0AGMAaAAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbQBwAG8AbgBlAG4AdABNAG8AZABlAGwALgBXAGkAbgAzADIARQB4AGMAZQBwAHQAaQBvAG4AXQAgAHsACgAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAoACIASQBOAFcASQBSAEUAXwBSAEUAUwBVAEwAVAA9AHcAaQBuADMAMgA6ACIAIAArACAAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBOAGEAdABpAHYAZQBFAHIAcgBvAHIAQwBvAGQAZQApAAoAfQAgAGMAYQB0AGMAaAAgAHsACgAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEkATgBXAEkAUgBFAF8AUgBFAFMAVQBMAFQAPQBlAHIAcgBvAHIAIgAKAH0A',
  ];
  check('the argv is exactly this', [...ELEVATE_ARGV], expected);

  // Decoded as well as encoded, so a failure names what changed rather than
  // printing two 984-character strings and leaving the reader to diff them.
  const decoded = Buffer.from(ELEVATE_ARGV[3], 'base64').toString('utf16le');
  check('...and decodes back to the script', decoded, ELEVATE_SCRIPT);

  // The three properties that make the interpolation-free design work. Each
  // is a separate assertion because each fails differently: a path on the
  // command line is an injection, a missing -Wait loses the exit code, and a
  // missing -PassThru means there is no exit code to lose.
  checkTrue('no argument is ever a filesystem path',
    ELEVATE_ARGV.every((arg) => !arg.includes('\\') && !arg.includes('/')));
  checkTrue('the script waits', ELEVATE_SCRIPT.includes('-Wait'));
  checkTrue('...and asks for the process back', ELEVATE_SCRIPT.includes('-PassThru'));
  checkTrue('it elevates', ELEVATE_SCRIPT.includes('-Verb RunAs'));
  checkTrue('it never prompts on its own', ELEVATE_ARGV.includes('-NonInteractive'));
  checkTrue('it reads the path from the environment',
    ELEVATE_SCRIPT.includes('$env:INWIRE_INSTALLER'));

  // The whole point of the OEM-licence half of this feature.
  checkTrue('nothing here silences an installer', !ELEVATE_SCRIPT.includes('/S'));
  check('Npcap is run with no flags at all', INSTALLER_ARGS['vendor-installer'], '');
  check('ours is silent and does not reboot',
    INSTALLER_ARGS['inwire-installer'], '/VERYSILENT /NORESTART');

  check('the path travels in the environment',
    elevationEnv('C:\\Program Files\\x\\a b.exe', '/S'),
    { INWIRE_INSTALLER: 'C:\\Program Files\\x\\a b.exe', INWIRE_ARGS: '/S' });
}

console.log('\n--- the installer that closes us, which must not be awaited ---\n');

{
  // `setup.iss` sets CloseApplications=yes, so our own installer asks Inwire
  // to exit before it replaces the payload. Await it and both sides wait for
  // the other for ever, with nothing on screen. This is the whole reason
  // there are two scripts.
  checkTrue('ours is not awaited', !awaitsInstaller('inwire-installer'));
  checkTrue('Npcap is', awaitsInstaller('vendor-installer'));
  checkTrue('a database download is too', awaitsInstaller('database'));

  checkTrue('the launch script does not wait', !LAUNCH_SCRIPT.includes('-Wait'));
  checkTrue('...and asks for no exit code it cannot read',
    !LAUNCH_SCRIPT.includes('-PassThru'));
  checkTrue('it still elevates', LAUNCH_SCRIPT.includes('-Verb RunAs'));
  checkTrue('it still reads the path from the environment',
    LAUNCH_SCRIPT.includes('$env:INWIRE_INSTALLER'));

  // The pairing that must never cross. `-Wait` in the launch script is the
  // deadlock; a missing `-Wait` in the elevate script silently reports every
  // install as an instant success.
  checkTrue('the waiting script waits and the launching one does not',
    ELEVATE_SCRIPT.includes('-Wait') && !LAUNCH_SCRIPT.includes('-Wait'));

  const decoded = Buffer.from(LAUNCH_ARGV[3], 'base64').toString('utf16le');
  check('the launch argv decodes to its script', decoded, LAUNCH_SCRIPT);
  check('...and has the same fixed shape',
    [...LAUNCH_ARGV].slice(0, 3), ['-NoProfile', '-NonInteractive', '-EncodedCommand']);
  checkTrue('...carrying no path either',
    LAUNCH_ARGV.every((arg) => !arg.includes('\\') && !arg.includes('/')));
  checkTrue('the two commands are not the same', LAUNCH_ARGV[3] !== ELEVATE_ARGV[3]);

  // A launch reports only whether the elevated process started, so the same
  // reader has to serve both - including telling a decline from a start.
  check('a launch that started reads as ok',
    readElevationResult('INWIRE_RESULT=ok:0', 'inwire-installer'), { kind: 'ok' });
  check('a launch that was declined reads as cancelled',
    readElevationResult('INWIRE_RESULT=win32:1223', 'inwire-installer'), { kind: 'cancelled' });
}

console.log('\n--- reading what the installer said ---\n');

{
  const vendor = (stdout: string) => readElevationResult(stdout, 'vendor-installer');
  const ours = (stdout: string) => readElevationResult(stdout, 'inwire-installer');

  check('zero is success', vendor('INWIRE_RESULT=ok:0'), { kind: 'ok' });
  check('3010 wants a reboot', vendor('INWIRE_RESULT=ok:3010'), { kind: 'reboot-required' });
  check('1641 does too', vendor('INWIRE_RESULT=ok:1641'), { kind: 'reboot-required' });

  // The most likely outcome of the entire feature, and it must never be an
  // error: somebody thought better of it, which is the prompt working.
  check('a declined UAC prompt is cancelled, not failed',
    vendor('INWIRE_RESULT=win32:1223'), { kind: 'cancelled' });
  check('...and so is an exit code saying the same',
    vendor('INWIRE_RESULT=ok:1223'), { kind: 'cancelled' });
  check('1602 is cancelled', vendor('INWIRE_RESULT=ok:1602'), { kind: 'cancelled' });

  // Inno's own codes, which we can read because we own that installer.
  check('Inno 2 is the user backing out', ours('INWIRE_RESULT=ok:2'), { kind: 'cancelled' });
  check('Inno 5 is too', ours('INWIRE_RESULT=ok:5'), { kind: 'cancelled' });

  // Npcap's are deliberately not guessed at: a wrong guess says "cancelled"
  // over a real failure, and a number is something a person can search for.
  check('a vendor 2 is reported, not interpreted',
    vendor('INWIRE_RESULT=ok:2'), { kind: 'failed', code: 2, reason: 'the installer exited with code 2' });

  check('an unknown code fails with its number',
    vendor('INWIRE_RESULT=ok:1603').kind, 'failed');
  check('...and keeps the number', vendor('INWIRE_RESULT=ok:1603'),
    { kind: 'failed', code: 1603, reason: 'the installer exited with code 1603' });
  check('a non-cancel win32 error fails',
    vendor('INWIRE_RESULT=win32:5'),
    { kind: 'failed', code: 5, reason: 'Windows refused to start the installer (5)' });
  check('the catch-all fails',
    vendor('INWIRE_RESULT=error'),
    { kind: 'failed', code: null, reason: 'the installer could not be started' });

  // A script that produced no verdict did not observe one. Reading silence as
  // success would mark an install complete that never ran.
  check('no marker is a failure, not a success',
    vendor('').kind, 'failed');
  check('...and neither is unrelated chatter',
    vendor('Preparing modules for first use.\r\n').kind, 'failed');
  check('a malformed marker fails', vendor('INWIRE_RESULT=ok:').kind, 'failed');
  check('an unknown tag fails', vendor('INWIRE_RESULT=maybe:0').kind, 'failed');

  // PowerShell writes a CLIXML preamble and may lead with a blank line, so the
  // marker is found by scanning rather than by matching the whole output.
  check('a leading blank line does not hide the result',
    vendor('\r\n\r\nINWIRE_RESULT=ok:0\r\n'), { kind: 'ok' });
}

console.log('\n--- what each row settles on ---\n');

{
  const app = '1.0.0';

  check('same version is up to date',
    decideState('1.88', available(), app), { kind: 'up-to-date' });
  check('a newer one is offered',
    decideState('1.79', available(), app), { kind: 'update-available', version: '1.88' });
  check('an older feed does not offer a downgrade',
    decideState('1.90', available(), app), { kind: 'up-to-date' });
  check('absent, with something to install',
    decideState(null, available(), app), { kind: 'not-installed' });
  check('absent, with no feed answer',
    decideState(null, null, app), { kind: 'not-installed' });

  // Not "up to date". Saying that when we simply have not asked is the lie
  // this whole state union exists to avoid.
  check('installed, with no feed answer, is unknown',
    decideState('1.88', null, app), { kind: 'unknown' });

  // An installed version we cannot parse must not be compared. Comparing
  // garbage would confidently offer an update over a working install.
  check('an unreadable installed version is unknown',
    decideState('unknown', available(), app), { kind: 'unknown' });

  check('an update this build cannot apply says so',
    decideState('1.79', available({ minAppVersion: '2.0.0' }), app),
    { kind: 'needs-newer-app', version: '1.88', requires: '2.0.0' });

  const row = (over: Partial<Component>): Component => ({
    id: 'npcap', displayName: 'Npcap', installed: '1.79',
    available: available(), state: { kind: 'update-available', version: '1.88' }, ...over,
  });
  checkTrue('an offered update is actionable', canApply(row({})));
  checkTrue('an absent component with a feed row is actionable',
    canApply(row({ installed: null, state: { kind: 'not-installed' } })));
  checkTrue('an absent component with no feed row is not',
    !canApply(row({ installed: null, available: null, state: { kind: 'not-installed' } })));
  checkTrue('an up-to-date row is not', !canApply(row({ state: { kind: 'up-to-date' } })));
  checkTrue('a row mid-download is not',
    !canApply(row({ state: { kind: 'downloading', received: 1, total: 2 } })));
  checkTrue('a planned row is not', !canApply(row({ state: { kind: 'planned' } })));
}

console.log('\n--- what the renderer accepts, and what it adds ---\n');

{
  const snapshot = {
    checking: false,
    lastChecked: 1_757_000_000_000,
    components: [
      { id: 'inwire', displayName: 'Inwire', installed: '1.0.0', available: null, state: { kind: 'unknown' } },
      { id: 'npcap', displayName: 'Npcap', installed: '1.88', available: null, state: { kind: 'up-to-date' } },
    ],
  };

  const read = normalizeSnapshot(snapshot);
  check('a snapshot reads back', read?.components.length, 2);
  check('...keeping lastChecked', read?.lastChecked, 1_757_000_000_000);

  check('a non-object is refused', normalizeSnapshot('nope'), null);
  check('null is refused', normalizeSnapshot(null), null);
  check('a missing components array is refused',
    normalizeSnapshot({ checking: false, lastChecked: null }), null);
  check('a non-boolean checking is refused',
    normalizeSnapshot({ checking: 'yes', lastChecked: null, components: [] }), null);

  // A row that does not parse is dropped rather than rendered, because a row
  // built from half-understood data shows a button beside a state nobody can
  // name. The document survives - one bad row must not blank the tab.
  const withJunk = { ...snapshot, components: [...snapshot.components, { id: 'x' }, null] };
  check('unreadable rows are dropped, not fatal', normalizeSnapshot(withJunk)?.components.length, 2);
  check('...and so is a row with an invented state',
    normalizeSnapshot({
      ...snapshot,
      components: [{ id: 'npcap', displayName: 'N', installed: null, available: null, state: { kind: 'exploding' } }],
    })?.components.length, 0);

  // The agent's row is composed here because its version lives here.
  const withAgent = withAgentRow(read ?? EMPTY_SNAPSHOT, '3.8.0', false);
  check('the agent sits directly after Inwire',
    withAgent.components.map((c) => c.id), ['inwire', 'agent', 'npcap']);
  check('...carrying its version', withAgent.components[1].installed, '3.8.0');
  check('...and nothing to apply', withAgent.components[1].available, null);
  checkTrue('so its row has no button', !canApplyInRenderer(withAgent.components[1]));

  check('an outdated agent says so',
    withAgentRow(read ?? EMPTY_SNAPSHOT, '3.7.0', true).components[1].state.kind, 'update-available');
  check('an agent that has not spoken is unknown',
    withAgentRow(read ?? EMPTY_SNAPSHOT, null, false).components[1].state.kind, 'unknown');

  // Added twice must not appear twice - the panel re-derives on every render.
  check('adding it twice adds it once',
    withAgentRow(withAgent, '3.8.0', false).components.map((c) => c.id),
    ['inwire', 'agent', 'npcap']);

  check('with no Inwire row it still appears',
    withAgentRow({ ...EMPTY_SNAPSHOT }, '3.8.0', false).components.map((c) => c.id), ['agent']);
}

console.log('\n--- the words in each row ---\n');

{
  check('up to date', stateLabel({ kind: 'up-to-date' }), 'Up to date');
  check('an offer names the version',
    stateLabel({ kind: 'update-available', version: '1.88' }), '1.88 available');
  check('progress is a percentage',
    stateLabel({ kind: 'downloading', received: 660212, total: 1320424 }), 'Downloading 50%');
  check('a zero total does not divide by it',
    stateLabel({ kind: 'downloading', received: 0, total: 0 }), 'Downloading ');
  check('the UAC wait says what it is waiting for',
    stateLabel({ kind: 'elevating' }), 'Waiting for Windows');
  check('a reboot is stated once', stateLabel({ kind: 'reboot-required' }),
    'Installed - restart Windows to finish');
  check('a failure shows its own reason',
    stateLabel({ kind: 'failed', reason: 'the installer exited with code 1603' }),
    'the installer exited with code 1603');

  // "Not checked" and "Up to date" must never be the same words. Saying the
  // second when we have not asked is the lie the state union exists to avoid.
  checkTrue('not-checked does not read as up to date',
    stateLabel({ kind: 'unknown' }) !== stateLabel({ kind: 'up-to-date' }));

  const row = (over: Partial<UpdateComponent>): UpdateComponent => ({
    id: 'npcap', displayName: 'Npcap', installed: '1.79',
    available: { version: '1.88', url: 'https://npcap.com/x', sha256: 'a'.repeat(64), size: 1, kind: 'vendor-installer', minAppVersion: '1.0.0' },
    state: { kind: 'update-available', version: '1.88' }, ...over,
  });
  check('an absent component says Install',
    actionLabel(row({ installed: null })), 'Install');
  check('...and a present one says Update', actionLabel(row({})), 'Update');

  checkTrue('a check in flight is busy', isBusy({ ...EMPTY_SNAPSHOT, checking: true }));
  checkTrue('so is a download',
    isBusy({ ...EMPTY_SNAPSHOT, components: [row({ state: { kind: 'downloading', received: 1, total: 2 } })] }));
  checkTrue('so is a UAC prompt on screen',
    isBusy({ ...EMPTY_SNAPSHOT, components: [row({ state: { kind: 'elevating' } })] }));
  checkTrue('a settled tab is not',
    !isBusy({ ...EMPTY_SNAPSHOT, components: [row({ state: { kind: 'up-to-date' } })] }));
}

console.log('\n--- this machine ---\n');

{
  // Printed, not asserted. Whether Npcap is installed here is a property of
  // the machine, not of the code - the same rule `agent-health.ts` follows
  // when it reads the real service registry.
  const facts = await readNpcap();
  console.log(`      this machine says: ${JSON.stringify(facts)}`);

  checkTrue('the answer has the shape it promises',
    typeof facts.installed === 'boolean'
    && (facts.version === null || typeof facts.version === 'string'));

  // The one thing that is true whatever is installed: a version implies an
  // installation. The reverse does not hold, which is why they are two fields.
  checkTrue('a version means it is installed', facts.version === null || facts.installed);
  checkTrue('a reported version is parseable', facts.version === null || isVersion(facts.version));
}

console.log(failures === 0
  ? '\nAll update center checks passed.'
  : `\n${failures} update center check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
