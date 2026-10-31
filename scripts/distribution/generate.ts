/**
 * Writes every release projection for one installer from ONE measurement of it.
 *
 *   npx tsx scripts/distribution/generate.ts --installer <path> --version <x.y.z> \
 *     --url <https url> --out <release.json> [--feed-out <update-feed.json>] \
 *     [--min-app-version <x.y.z>] [--winget-out <dir>] [--policy <path>] \
 *     [--require-public] [--fixture]
 *
 * Projections, all from the same size and sha256 (computed once):
 *   - `release.json`      the descriptor the PowerShell bootstrap reads (--out)
 *   - `update-feed.json`  a complete Update Center feed document with the
 *                         `inwire` row (--feed-out, default beside --out)
 *   - WinGet manifests    `<dir>/<id>/<version>/` (--winget-out), only while
 *                         the policy has no WinGet blockers
 *
 * Run it on the FINAL signed and timestamped installer bytes, never before
 * signing: a signature rewrites the file, so a hash taken first names a file
 * that is never published and every download then fails its size check.
 *
 * Every projection is validated before ANY is written (the descriptor by
 * `readRelease`, the feed by the app's own `parseManifest`), so this cannot
 * emit something a consumer would reject, and a refusal writes nothing.
 * Exit codes: 0 written, 2 refused (bad arguments or invalid result), 3 the
 * policy still has blockers for what was asked (`--require-public`, or any
 * `--winget-out`).
 *
 * `--fixture` exists for the tests: with a policy under `distribution/fixtures/`
 * it lets WinGet manifests be written for a made-up package ID. The core also
 * refuses it for any policy whose hosts are not `.invalid`, so the production
 * policy cannot be unlocked by it from either side.
 *
 * `scripts/distribution/contracts.ts` asserts the core below; this file is the
 * thin command line around it, and WRITES, so `scripts/check.ts` does not run it.
 */
import { createReadStream, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseManifest } from '../../electron/updateCenter/manifest';
import {
  publicBlockers, readPolicy, readRelease, wingetBlockers,
  type ReleaseDescriptor, type ReleasePolicy,
} from './release';
import { renderWingetManifests } from './winget';

type InstallerInfo = { sizeBytes: number; sha256: string };

/** Size and sha256 of a file, streamed: an installer is hundreds of megabytes and is never held whole. */
export async function describeInstaller(file: string): Promise<InstallerInfo> {
  const hash = createHash('sha256');
  let sizeBytes = 0;
  for await (const chunk of createReadStream(file)) {
    const bytes = chunk as Buffer;
    hash.update(bytes);
    sizeBytes += bytes.length;
  }
  return { sizeBytes, sha256: hash.digest('hex') };
}

export type Generated =
  | { ok: true; release: ReleaseDescriptor; text: string; blockers: string[] }
  | { ok: false; message: string };

const INVALID_DESCRIPTOR = 'the descriptor would be invalid under the policy (check --version is x.y.z, --url is https on an allowed host with no port, credentials or fragment, and the installer is not empty or over the size cap)';

function buildRelease(
  info: InstallerInfo, args: { version: string; url: string; policy: ReleasePolicy },
): ReleaseDescriptor | null {
  // The same validator the bootstrap's rules come from: a descriptor this
  // refuses is one no client would accept either.
  return readRelease({
    schema: 1,
    artifacts: [{
      product: 'Desktop', version: args.version, architecture: 'x64',
      url: args.url, sizeBytes: info.sizeBytes, sha256: info.sha256,
    }],
  }, args.policy);
}

async function measure(installer: string): Promise<{ info: InstallerInfo } | { message: string }> {
  try {
    return { info: await describeInstaller(installer) };
  } catch (error) {
    return { message: `cannot read the installer: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export async function generateRelease(args: {
  installer: string; version: string; url: string; policy: ReleasePolicy;
}): Promise<Generated> {
  const measured = await measure(args.installer);
  if ('message' in measured) return { ok: false, message: measured.message };
  const release = buildRelease(measured.info, args);
  if (release === null) return { ok: false, message: INVALID_DESCRIPTOR };
  return { ok: true, release, text: `${JSON.stringify(release, null, 2)}\n`, blockers: publicBlockers(args.policy) };
}

export type AllGenerated =
  | {
    ok: true; release: ReleaseDescriptor; releaseText: string; feedText: string;
    winget: { dir: string; files: { name: string; text: string }[] } | null; blockers: string[];
  }
  | { ok: false; code: 2 | 3; message: string };

/**
 * A policy only a test would write: every host is under the reserved `.invalid`
 * TLD (RFC 2606), which cannot resolve. The production policy cannot satisfy it.
 */
function isFixturePolicy(policy: ReleasePolicy): boolean {
  return policy.allowedHosts.every((h) => h.endsWith('.invalid'));
}

export async function generateAll(args: {
  installer: string; version: string; url: string; policy: ReleasePolicy;
  /** Update Center `minAppVersion`; the release's own version when omitted. */
  minAppVersion?: string;
  winget: boolean;
  /** Tests only: waive the pin blocker for a `.invalid` policy that still names a package. */
  fixture?: boolean;
  /** Overridable so a test can pin the feed's `generated` field. */
  now?: Date;
}): Promise<AllGenerated> {
  const { policy } = args;
  if (args.fixture === true && !isFixturePolicy(policy)) {
    return { ok: false, code: 2, message: '--fixture is for the test policy only; this policy names real hosts' };
  }
  if (args.winget) {
    const blockers = wingetBlockers(policy);
    const waived = args.fixture === true && policy.desktopPackageId !== '';
    if (blockers.length > 0 && !waived) {
      return { ok: false, code: 3, message: `refusing WinGet output:\n  - ${blockers.join('\n  - ')}` };
    }
  }

  const measured = await measure(args.installer);
  if ('message' in measured) return { ok: false, code: 2, message: measured.message };
  const { info } = measured;
  const release = buildRelease(info, args);
  if (release === null) return { ok: false, code: 2, message: INVALID_DESCRIPTOR };
  const row = release.artifacts[0];

  // The feed is served from the descriptor's host (one host for both channels),
  // and `parseManifest` pins our downloads to the host the feed came from.
  const feedUrl = new URL('manifest.json', policy.descriptorUrl).href;
  const feedText = `${JSON.stringify({
    schema: 1,
    generated: (args.now ?? new Date()).toISOString(),
    components: {
      inwire: {
        version: row.version,
        url: row.url,
        sha256: row.sha256,
        size: row.sizeBytes,
        kind: 'inwire-installer',
        minAppVersion: args.minAppVersion ?? row.version,
      },
    },
  }, null, 2)}\n`;
  if (parseManifest(feedText, feedUrl)?.components.inwire === undefined) {
    return {
      ok: false, code: 2,
      message: 'the update feed row would be invalid (check --min-app-version is a dotted version and the url is on the feed host)',
    };
  }

  const winget = args.winget
    ? {
      dir: `${policy.desktopPackageId}/${row.version}`,
      files: renderWingetManifests({
        packageId: policy.desktopPackageId, version: row.version, url: row.url, sha256: row.sha256,
      }),
    }
    : null;

  return {
    ok: true, release, releaseText: `${JSON.stringify(release, null, 2)}\n`, feedText, winget,
    blockers: publicBlockers(policy),
  };
}

const FLAGS = new Set(['require-public', 'fixture']);

function parseArgs(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`unexpected argument ${arg}`);
    const key = arg.slice(2);
    if (FLAGS.has(key)) { out[key] = true; continue; }
    const value = argv[++i];
    if (value === undefined) throw new Error(`--${key} needs a value`);
    out[key] = value;
  }
  return out;
}

async function cli(): Promise<number> {
  let args: Record<string, string | true>;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(String(error instanceof Error ? error.message : error));
    return 2;
  }
  for (const required of ['installer', 'version', 'url', 'out']) {
    if (typeof args[required] !== 'string') {
      console.error(`missing --${required}`);
      return 2;
    }
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.join(here, '..', '..');
  const policyPath = typeof args.policy === 'string'
    ? args.policy : path.join(repo, 'distribution', 'release-policy.json');
  let policy: ReleasePolicy | null = null;
  try {
    policy = readPolicy(JSON.parse(readFileSync(policyPath, 'utf8')));
  } catch {
    policy = null;
  }
  if (policy === null) {
    console.error(`the policy at ${policyPath} is missing or invalid`);
    return 2;
  }

  const fixture = args.fixture === true;
  if (fixture) {
    // The flag is honoured only for a policy file that lives in the fixtures folder.
    const fixtures = realpathSync(path.join(repo, 'distribution', 'fixtures'));
    const relative = path.relative(fixtures, realpathSync(policyPath));
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      console.error('--fixture needs a --policy under distribution/fixtures/');
      return 2;
    }
  }
  const wingetOut = typeof args['winget-out'] === 'string' ? args['winget-out'] : null;

  const result = await generateAll({
    installer: args.installer as string, version: args.version as string,
    url: args.url as string, policy,
    minAppVersion: typeof args['min-app-version'] === 'string' ? args['min-app-version'] : undefined,
    winget: wingetOut !== null, fixture,
  });
  if (!result.ok) {
    console.error(result.message);
    return result.code;
  }
  for (const blocker of result.blockers) console.warn(`warning: ${blocker}`);
  if (args['require-public'] === true && result.blockers.length > 0) {
    console.error('refusing: --require-public and the policy has blockers (above)');
    return 3;
  }

  const out = args.out as string;
  const feedOut = typeof args['feed-out'] === 'string'
    ? args['feed-out'] : path.join(path.dirname(out), 'update-feed.json');
  writeFileSync(out, result.releaseText);
  writeFileSync(feedOut, result.feedText);
  const row = result.release.artifacts[0];
  console.log(`wrote ${out} and ${feedOut}: ${row.sizeBytes} bytes, sha256 ${row.sha256}`);
  if (result.winget !== null && wingetOut !== null) {
    const target = path.join(wingetOut, ...result.winget.dir.split('/'));
    mkdirSync(target, { recursive: true });
    for (const file of result.winget.files) writeFileSync(path.join(target, file.name), file.text);
    console.log(`wrote WinGet manifests to ${target}`);
  }
  return 0;
}

// Importing this module (contracts.ts does) must not run the command line.
if (process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli().then((code) => process.exit(code));
}
