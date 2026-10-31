/**
 * The release descriptor and the policy that judges it.
 *
 *   npx tsx scripts/distribution/contracts.ts
 *
 * A signed PowerShell bootstrap downloads the installer a `release.json`
 * names, so this document nominates an executable to be run elevated, the same
 * position the update feed is in. The rules are `scripts/distribution/release.ts`;
 * the verdicts they must give are `distribution/fixtures/release-vectors.json`,
 * a file the PowerShell validator reads too, so the two implementations cannot
 * drift apart without one of them failing.
 *
 * It also holds the PRODUCTION policy to what the repo has decided: one host
 * serves both the update feed and the descriptor, no fixture host leaks in as a
 * fallback, and the endpoint agent is not offered.
 */
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_UPDATE_FEED_URL, parseManifest } from '../../electron/updateCenter/manifest';
import {
  chooseArtifact, isReleaseVersion, publicBlockers, readPolicy, readRelease, wingetBlockers,
  type ReleaseDescriptor, type ReleasePolicy,
} from './release';
import { describeInstaller, generateAll, generateRelease } from './generate';
import { DESKTOP_PRODUCT_CODE, yamlString } from './winget';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const readJson = (rel: string): unknown => JSON.parse(readFileSync(path.join(root, rel), 'utf8'));

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : `  (${detail})`}`);
}

async function main(): Promise<void> {
  // ---- the fixture policy and the vectors ----
  const fixturePolicy = readPolicy(readJson('distribution/fixtures/test-policy.json'));
  check('fixture policy is readable', fixturePolicy !== null);
  if (fixturePolicy === null) return;

  const file = readJson('distribution/fixtures/release-vectors.json') as {
    policy: string; vectors: { name: string; valid: boolean; descriptor: unknown }[];
  };
  check('vectors name the fixture policy', file.policy === 'test-policy.json');
  check('there are vectors', file.vectors.length >= 50, String(file.vectors.length));
  for (const vector of file.vectors) {
    const got = readRelease(vector.descriptor, fixturePolicy);
    check(`vector: ${vector.name}`, (got !== null) === vector.valid,
      `expected ${vector.valid ? 'accepted' : 'rejected'}`);
  }

  // ---- normalisation ----
  const upper = file.vectors.find((v) => v.name.includes('uppercase sha256'));
  const normalised = upper === undefined ? null : readRelease(upper.descriptor, fixturePolicy);
  check('uppercase sha256 comes back lowercase',
    normalised !== null && normalised.artifacts[0].sha256 === normalised.artifacts[0].sha256.toLowerCase()
    && /^[0-9a-f]{64}$/.test(normalised.artifacts[0].sha256));
  const upperHost = file.vectors.find((v) => v.name.includes('uppercase URL host'));
  check('uppercase host is accepted',
    upperHost !== undefined && readRelease(upperHost.descriptor, fixturePolicy) !== null);

  // ---- an endpoint row is accepted only when the policy says it exists ----
  const withEndpoint = {
    schema: 1,
    artifacts: [
      { product: 'Desktop', version: '1.2.3', architecture: 'x64', url: 'https://download.example.invalid/a.exe', sizeBytes: 10, sha256: 'a'.repeat(64) },
      { product: 'EndpointAgent', version: '1.2.3', architecture: 'x64', url: 'https://download.example.invalid/b.exe', sizeBytes: 10, sha256: 'b'.repeat(64) },
    ],
  };
  check('endpoint row is rejected while endpointAvailable is false',
    readRelease(withEndpoint, fixturePolicy) === null);
  const endpointPolicy: ReleasePolicy = { ...fixturePolicy, endpointAvailable: true };
  const both = readRelease(withEndpoint, endpointPolicy);
  check('endpoint row is accepted when endpointAvailable is true', both !== null);

  // ---- chooseArtifact ----
  const single = readRelease({ schema: 1, artifacts: [withEndpoint.artifacts[0]] }, fixturePolicy) as ReleaseDescriptor;
  check('choose: null version gives the Desktop row', chooseArtifact(single, 'Desktop', null)?.version === '1.2.3');
  check('choose: exact version', chooseArtifact(single, 'Desktop', '1.2.3')?.sha256 === 'a'.repeat(64));
  check('choose: another version gives null', chooseArtifact(single, 'Desktop', '1.2.4') === null);
  check('choose: "0.5" is not "0.5.0"', (() => {
    const r = readRelease({ schema: 1, artifacts: [{ ...withEndpoint.artifacts[0], version: '0.5.0' }] }, fixturePolicy) as ReleaseDescriptor;
    return chooseArtifact(r, 'Desktop', '0.5') === null && chooseArtifact(r, 'Desktop', '0.5.0') !== null;
  })());
  check('choose: a lexicographically larger version is not "newer"', chooseArtifact(single, 'Desktop', '1.10.0') === null);
  check('choose: EndpointAgent is null when the descriptor has none', chooseArtifact(single, 'EndpointAgent', null) === null);
  check('choose: EndpointAgent is found when present',
    both !== null && chooseArtifact(both, 'EndpointAgent', null)?.sha256 === 'b'.repeat(64));
  check('isReleaseVersion', isReleaseVersion('1.2.3') && !isReleaseVersion('1.2') && !isReleaseVersion(null));

  // ---- readPolicy on bad policies ----
  const goodPolicy = readJson('distribution/fixtures/test-policy.json') as Record<string, unknown>;
  const badPolicies: [string, Record<string, unknown> | null][] = [
    ['http descriptorUrl', { ...goodPolicy, descriptorUrl: 'http://download.example.invalid/release.json' }],
    ['descriptor host not in allowedHosts', { ...goodPolicy, descriptorUrl: 'https://other.example.invalid/release.json' }],
    ['descriptor URL with a port', { ...goodPolicy, descriptorUrl: 'https://download.example.invalid:8443/release.json' }],
    ['uppercase allowed host', { ...goodPolicy, allowedHosts: ['Download.Example.Invalid'], descriptorUrl: 'https://download.example.invalid/release.json' }],
    ['empty allowedHosts', { ...goodPolicy, allowedHosts: [] }],
    ['single-label allowed host', { ...goodPolicy, allowedHosts: ['localhost'] }],
    ['allowed host with a path', { ...goodPolicy, allowedHosts: ['download.example.invalid/x'] }],
    ['short pin', { ...goodPolicy, publisherCertificateSha256: ['abcd'] }],
    ['uppercase pin', { ...goodPolicy, publisherCertificateSha256: ['A'.repeat(64)] }],
    ['non-hex pin', { ...goodPolicy, publisherCertificateSha256: ['g'.repeat(64)] }],
    ['duplicate pin', { ...goodPolicy, publisherCertificateSha256: ['a'.repeat(64), 'a'.repeat(64)] }],
    ['pins not an array', { ...goodPolicy, publisherCertificateSha256: 'a'.repeat(64) }],
    ['extra key', { ...goodPolicy, extra: true }],
    ['missing key', (() => { const c = { ...goodPolicy }; delete c.endpointAvailable; return c; })()],
    ['schema 2', { ...goodPolicy, schema: 2 }],
    ['bad package id (no dot)', { ...goodPolicy, desktopPackageId: 'Inwire' }],
    ['bad package id (space)', { ...goodPolicy, desktopPackageId: 'Example Inc.Inwire' }],
    ['endpointAvailable as string', { ...goodPolicy, endpointAvailable: 'false' }],
    ['null', null],
  ];
  for (const [name, value] of badPolicies) check(`policy rejected: ${name}`, readPolicy(value) === null);
  check('policy accepted: empty package id and empty pins',
    readPolicy({ ...goodPolicy, desktopPackageId: '', publisherCertificateSha256: [] }) !== null);
  check('policy: schema is dropped from the result',
    !('schema' in (readPolicy(goodPolicy) as object)));

  // ---- the production policy ----
  const productionRaw = readJson('distribution/release-policy.json');
  const production = readPolicy(productionRaw);
  check('production policy is readable', production !== null);
  if (production === null) return;
  const feedHost = new URL(DEFAULT_UPDATE_FEED_URL).hostname.toLowerCase();
  check('production hosts include the update feed host (one host for both channels)',
    production.allowedHosts.includes(feedHost), feedHost);
  check('production hosts contain no fixture host',
    production.allowedHosts.every((h) => !fixturePolicy.allowedHosts.includes(h)));
  check('production descriptor URL is not a fixture URL',
    !fixturePolicy.allowedHosts.includes(new URL(production.descriptorUrl).hostname));
  check('production endpointAvailable is false', production.endpointAvailable === false);
  check('production blockers are non-empty exactly while pins are empty',
    (publicBlockers(production).length > 0) === (production.publisherCertificateSha256.length === 0));
  check('fixture policy with a pin has no pin blocker',
    !publicBlockers(fixturePolicy).some((b) => b.includes('no publisher signing certificate')));

  // ---- WinGet blockers ----
  const wb = wingetBlockers(production);
  check('winget blockers: production names the missing package id', wb.some((b) => b.includes('package ID')), wb.join(' | '));
  check('winget blockers: production includes every public blocker (pin)',
    publicBlockers(production).every((b) => wb.includes(b)));
  check('winget blockers: a fixture policy with id and pin has none', wingetBlockers(fixturePolicy).length === 0);
  check('winget blockers: an empty id alone blocks',
    wingetBlockers({ ...fixturePolicy, desktopPackageId: '' }).length === 1);
  check('winget blockers: an empty pin alone blocks',
    wingetBlockers({ ...fixturePolicy, publisherCertificateSha256: [] }).length === 1);

  // ---- the generator's core ----
  const dir = mkdtempSync(path.join(tmpdir(), 'inwire-distribution-'));
  try {
    const small = path.join(dir, 'abc.exe');
    writeFileSync(small, 'abc');
    const info = await describeInstaller(small);
    check('describeInstaller: size of "abc"', info.sizeBytes === 3);
    check('describeInstaller: sha256 of "abc" is the published vector',
      info.sha256 === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

    // Larger than any single stream chunk, so a hash fed only the first chunk fails.
    const big = path.join(dir, 'big.exe');
    const bytes = Buffer.alloc(300_000);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 7) & 0xff;
    writeFileSync(big, bytes);
    const bigInfo = await describeInstaller(big);
    check('describeInstaller: multi-chunk size', bigInfo.sizeBytes === bytes.length);
    check('describeInstaller: multi-chunk sha256',
      bigInfo.sha256 === createHash('sha256').update(bytes).digest('hex'));

    const url = 'https://download.example.invalid/Inwire-1.2.3-x64.exe';
    const made = await generateRelease({ installer: big, version: '1.2.3', url, policy: fixturePolicy });
    check('generateRelease: accepted', made.ok);
    if (made.ok) {
      check('generateRelease: row carries the measured size and hash',
        made.release.artifacts[0].sizeBytes === bytes.length
        && made.release.artifacts[0].sha256 === bigInfo.sha256
        && made.release.artifacts[0].product === 'Desktop'
        && made.release.artifacts[0].architecture === 'x64');
      check('generateRelease: output round-trips through readRelease',
        readRelease(JSON.parse(made.text), fixturePolicy) !== null);
      check('generateRelease: 2-space indent and trailing newline',
        made.text.startsWith('{\n  "schema": 1,') && made.text.endsWith('}\n'));
      check('generateRelease: fixture policy has a pin, so no blockers', made.blockers.length === 0);
    }
    const wrongHost = await generateRelease({ installer: big, version: '1.2.3', url: 'https://evil.example.invalid/x.exe', policy: fixturePolicy });
    check('generateRelease: refuses a host outside the policy', !wrongHost.ok);
    const wrongVersion = await generateRelease({ installer: big, version: '1.2', url, policy: fixturePolicy });
    check('generateRelease: refuses a bad version', !wrongVersion.ok);
    const missing = await generateRelease({ installer: path.join(dir, 'nope.exe'), version: '1.2.3', url, policy: fixturePolicy });
    check('generateRelease: refuses a missing installer', !missing.ok);
    const empty = path.join(dir, 'empty.exe');
    writeFileSync(empty, '');
    const emptyRun = await generateRelease({ installer: empty, version: '1.2.3', url, policy: fixturePolicy });
    check('generateRelease: refuses an empty installer', !emptyRun.ok);
    const pinless = await generateRelease({ installer: big, version: '1.2.3', url: 'https://updates.inwire.app/x.exe', policy: production });
    check('generateRelease: production policy surfaces its blockers while it has no pin',
      pinless.ok && (pinless.blockers.length > 0) === (production.publisherCertificateSha256.length === 0));

    // ---- one inventory, every projection ----
    const feedUrl = 'https://download.example.invalid/manifest.json';
    const all = await generateAll({
      installer: big, version: '1.2.3', url, policy: fixturePolicy, winget: true, fixture: true,
    });
    check('generateAll: fixture policy produces every projection', all.ok && all.winget !== null);
    if (all.ok && all.winget !== null) {
      const rel = JSON.parse(all.releaseText).artifacts[0];
      const feed = parseManifest(all.feedText, feedUrl);
      check('feed projection: parseManifest accepts it on the feed host', feed !== null);
      const row = feed?.components.inwire;
      check('feed projection: the inwire row is the only component, kind inwire-installer',
        row !== undefined && Object.keys(feed?.components ?? {}).join() === 'inwire' && row.kind === 'inwire-installer');
      check('feed projection: minAppVersion defaults to the version', row?.minAppVersion === '1.2.3');
      check('release and feed agree on version, url, size and sha256',
        row !== undefined && row.version === rel.version && row.url === rel.url
        && row.size === rel.sizeBytes && row.sha256 === rel.sha256
        && row.size === bytes.length && row.sha256 === bigInfo.sha256);

      const names = all.winget.files.map((f) => f.name).sort();
      check('winget: three files named for the package',
        names.join() === ['Example.Inwire.installer.yaml', 'Example.Inwire.locale.en-US.yaml', 'Example.Inwire.yaml'].join(), names.join());
      check('winget: directory is <id>/<version>', all.winget.dir === 'Example.Inwire/1.2.3', all.winget.dir);
      const get = (suffix: string): string => all.winget?.files.find((f) => f.name.endsWith(suffix))?.text ?? '';
      const installer = get('.installer.yaml');
      const versionFile = get('Example.Inwire.yaml');
      const locale = get('.locale.en-US.yaml');
      const hasLine = (text: string, line: string): boolean => text.split('\n').includes(line);

      const iss = readFileSync(path.join(root, 'installer', 'setup.iss'), 'utf8');
      const appId = /^AppId=(.+)$/m.exec(iss)?.[1] ?? '';
      // Inno reads `{{` as an escaped brace and keeps a lone `}`; the key is that, plus _is1.
      const productCode = `${appId.replace('{{', '{')}_is1`;
      check('setup.iss AppId was found', /^\{\{[0-9A-F-]{36}\}\}$/.test(appId), appId);
      check('DESKTOP_PRODUCT_CODE is the key setup.iss registers', DESKTOP_PRODUCT_CODE === productCode, DESKTOP_PRODUCT_CODE);
      check('installer manifest names that ProductCode exactly, at both levels',
        hasLine(installer, `ProductCode: ${yamlString(productCode)}`)
        && hasLine(installer, `  - ProductCode: ${yamlString(productCode)}`)
        && hasLine(installer, `    DisplayVersion: "1.2.3"`));
      check('winget agrees with release.json on url, sha256, version',
        hasLine(installer, `    InstallerUrl: ${yamlString(rel.url)}`)
        && installer.includes(`InstallerSha256: "${bigInfo.sha256.toUpperCase()}"`)
        && hasLine(installer, 'PackageVersion: "1.2.3"') && hasLine(versionFile, 'PackageVersion: "1.2.3"')
        && hasLine(locale, 'PackageVersion: "1.2.3"'));
      check('winget: identifier on every file', [installer, versionFile, locale].every((t) => hasLine(t, 'PackageIdentifier: "Example.Inwire"')));
      check('winget: manifest types and one schema version',
        hasLine(versionFile, 'ManifestType: "version"') && hasLine(installer, 'ManifestType: "installer"')
        && hasLine(locale, 'ManifestType: "defaultLocale"')
        && [installer, versionFile, locale].every((t) => hasLine(t, 'ManifestVersion: "1.12.0"')));
      check('winget: inno, machine scope, x64, elevatesSelf, upgrade over, command inwire',
        hasLine(installer, 'InstallerType: "inno"') && hasLine(installer, 'Scope: "machine"')
        && hasLine(installer, '  - Architecture: "x64"') && hasLine(installer, 'ElevationRequirement: "elevatesSelf"')
        && hasLine(installer, 'UpgradeBehavior: "install"') && hasLine(installer, '  - "inwire"'));
      check('winget: extra switches go in Custom and repeat none of WinGet\'s Inno defaults',
        hasLine(installer, '  Custom: "/RESTARTEXITCODE=3010 /NOFORCECLOSEAPPLICATIONS"')
        && !/VERYSILENT|SUPPRESSMSGBOXES|\/SP-|NORESTART"|\/S"/.test(installer));
      const codes = [...installer.matchAll(/InstallerReturnCode: (\d+)\n\s+ReturnResponse: "(\w+)"/g)]
        .map((m) => `${m[1]}=${m[2]}`).sort().join();
      check('winget: return codes map exactly 2,5 cancelled, 8 and 3010 reboot',
        codes === '2=cancelledByUser,3010=rebootRequiredToFinish,5=cancelledByUser,8=rebootRequiredForInstall', codes);
      check('winget: locale file is MIT, publisher Inwire, does not claim WinGet launches the app',
        hasLine(locale, 'License: "MIT"') && hasLine(locale, 'Publisher: "Inwire"') && !/launch/i.test(locale));
      check('winget: no source file URL leaked a placeholder', ![installer, versionFile, locale].some((t) => /TODO|placeholder/i.test(t)));
    }

    // ---- production policy: no package ID and no pin, so no WinGet output ----
    const prodAll = await generateAll({
      installer: big, version: '1.2.3', url: 'https://updates.inwire.app/x.exe', policy: production, winget: true,
    });
    check('generateAll: production policy refuses WinGet output (exit 3)', !prodAll.ok && prodAll.code === 3);
    const prodFixtureFlag = await generateAll({
      installer: big, version: '1.2.3', url: 'https://updates.inwire.app/x.exe', policy: production, winget: true, fixture: true,
    });
    check('generateAll: the fixture flag cannot unlock the production policy', !prodFixtureFlag.ok);
    const prodNoWinget = await generateAll({
      installer: big, version: '1.2.3', url: 'https://updates.inwire.app/x.exe', policy: production, winget: false,
    });
    check('generateAll: production without WinGet still yields release and feed',
      prodNoWinget.ok && prodNoWinget.winget === null
      && parseManifest(prodNoWinget.feedText, DEFAULT_UPDATE_FEED_URL)?.components.inwire?.sha256 === bigInfo.sha256);
    const noId = { ...fixturePolicy, desktopPackageId: '' };
    check('generateAll: fixture flag with an empty package id still refuses',
      !(await generateAll({ installer: big, version: '1.2.3', url, policy: noId, winget: true, fixture: true })).ok);
    const badMin = await generateAll({ installer: big, version: '1.2.3', url, policy: fixturePolicy, winget: false, minAppVersion: 'soon' });
    check('generateAll: refuses a bad --min-app-version', !badMin.ok);

    // ---- the command line writes nothing when it refuses ----
    const generateScript = path.join(root, 'scripts', 'distribution', 'generate.ts');
    const run = (extra: string[]): { status: number | null; stderr: string } => {
      const r = spawnSync(process.execPath, ['--import', 'tsx', generateScript,
        '--installer', big, '--version', '1.2.3', '--url', url, ...extra], { cwd: root, encoding: 'utf8' });
      return { status: r.status, stderr: r.stderr };
    };
    const prodOut = path.join(dir, 'prod-winget');
    const prodUrl = 'https://updates.inwire.app/x.exe';
    const prodRun = spawnSync(process.execPath, ['--import', 'tsx', generateScript,
      '--installer', big, '--version', '1.2.3', '--url', prodUrl, '--out', path.join(dir, 'prod-release.json'),
      '--winget-out', prodOut], { cwd: root, encoding: 'utf8' });
    check('cli: production policy + --winget-out exits 3 and writes no WinGet directory',
      prodRun.status === 3 && !existsSync(prodOut), `status ${prodRun.status}`);
    check('cli: and writes no release.json either (all or nothing)', !existsSync(path.join(dir, 'prod-release.json')));
    const prodFixtureRun = spawnSync(process.execPath, ['--import', 'tsx', generateScript,
      '--installer', big, '--version', '1.2.3', '--url', prodUrl, '--out', path.join(dir, 'prod2.json'),
      '--winget-out', prodOut, '--fixture'], { cwd: root, encoding: 'utf8' });
    check('cli: --fixture with the production policy is refused and writes nothing',
      prodFixtureRun.status !== 0 && !existsSync(prodOut), `status ${prodFixtureRun.status}`);
    const fixtureOut = path.join(dir, 'fixture-winget');
    const okRun = run(['--policy', path.join(root, 'distribution', 'fixtures', 'test-policy.json'),
      '--out', path.join(dir, 'release.json'), '--feed-out', path.join(dir, 'update-feed.json'),
      '--winget-out', fixtureOut, '--fixture']);
    check('cli: fixture policy + --fixture writes all projections', okRun.status === 0
      && existsSync(path.join(dir, 'release.json')) && existsSync(path.join(dir, 'update-feed.json'))
      && existsSync(path.join(fixtureOut, 'Example.Inwire', '1.2.3', 'Example.Inwire.installer.yaml')), okRun.stderr.slice(0, 200));
    const copied = path.join(dir, 'copy-policy.json');
    copyFileSync(path.join(root, 'distribution', 'fixtures', 'test-policy.json'), copied);
    const outsideRun = run(['--policy', copied, '--out', path.join(dir, 'o.json'),
      '--winget-out', path.join(dir, 'outside-winget'), '--fixture']);
    check('cli: --fixture refuses a policy that is not under distribution/fixtures',
      outsideRun.status !== 0 && !existsSync(path.join(dir, 'outside-winget')), `status ${outsideRun.status}`);

    // ---- YAML scalars: always a double-quoted, JSON-compatible string ----
    const tricky = ['a: b', 'x # y', '"quoted"', "it's", '- leading dash', '', ' padded ', 'tab\there', 'line\nbreak',
      'back\\slash', 'Ünïcödé ✓ 日本語', '{{brace}}', '*alias', '!tag', '@at', '`tick', 'null', 'yes', '0123', '%percent', '&anchor', '| pipe', '> fold'];
    for (const s of tricky) {
      const y = yamlString(s);
      let back: unknown;
      try { back = JSON.parse(y); } catch { back = undefined; }
      check(`yamlString round-trips ${JSON.stringify(s)}`,
        y.startsWith('"') && y.endsWith('"') && !y.includes('\n') && back === s, y);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().then(
  () => {
    console.log(failures === 0 ? '\nAll distribution contracts hold' : `\n${failures} distribution check(s) failed`);
    process.exit(failures === 0 ? 0 : 1);
  },
  (error) => {
    console.error(error);
    process.exit(1);
  },
);
