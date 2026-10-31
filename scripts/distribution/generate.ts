/**
 * Writes `release.json` for one installer.
 *
 *   npx tsx scripts/distribution/generate.ts --installer <path> --version <x.y.z> \
 *     --url <https url> --out <release.json> [--policy <path>] [--require-public]
 *
 * Run it on the FINAL signed and timestamped installer bytes, never before
 * signing: a signature rewrites the file, so a hash taken first names a file
 * that is never published and every download then fails its size check.
 *
 * The descriptor it writes is validated by `readRelease` against the policy
 * before it is written, so this cannot emit something the bootstrap would
 * reject. Exit codes: 0 written, 2 refused (bad arguments or invalid result),
 * 3 `--require-public` and the policy still has blockers.
 *
 * `scripts/distribution/contracts.ts` asserts the core below; this file is the
 * thin command line around it, and WRITES, so `scripts/check.ts` does not run it.
 */
import { createReadStream, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  publicBlockers, readPolicy, readRelease,
  type ReleaseDescriptor, type ReleasePolicy,
} from './release';

/** Size and sha256 of a file, streamed: an installer is hundreds of megabytes and is never held whole. */
export async function describeInstaller(file: string): Promise<{ sizeBytes: number; sha256: string }> {
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

export async function generateRelease(args: {
  installer: string; version: string; url: string; policy: ReleasePolicy;
}): Promise<Generated> {
  let info: { sizeBytes: number; sha256: string };
  try {
    info = await describeInstaller(args.installer);
  } catch (error) {
    return { ok: false, message: `cannot read the installer: ${error instanceof Error ? error.message : String(error)}` };
  }
  const candidate = {
    schema: 1,
    artifacts: [{
      product: 'Desktop', version: args.version, architecture: 'x64',
      url: args.url, sizeBytes: info.sizeBytes, sha256: info.sha256,
    }],
  };
  // The same validator the bootstrap's rules come from: a descriptor this
  // refuses is one no client would accept either.
  const release = readRelease(candidate, args.policy);
  if (release === null) {
    return {
      ok: false,
      message: 'the descriptor would be invalid under the policy (check --version is x.y.z, --url is https on an allowed host with no port, credentials or fragment, and the installer is not empty or over the size cap)',
    };
  }
  return { ok: true, release, text: `${JSON.stringify(release, null, 2)}\n`, blockers: publicBlockers(args.policy) };
}

function parseArgs(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`unexpected argument ${arg}`);
    const key = arg.slice(2);
    if (key === 'require-public') { out[key] = true; continue; }
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
  const policyPath = typeof args.policy === 'string'
    ? args.policy : path.join(here, '..', '..', 'distribution', 'release-policy.json');
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

  const result = await generateRelease({
    installer: args.installer as string, version: args.version as string,
    url: args.url as string, policy,
  });
  if (!result.ok) {
    console.error(result.message);
    return 2;
  }
  for (const blocker of result.blockers) console.warn(`warning: ${blocker}`);
  if (args['require-public'] === true && result.blockers.length > 0) {
    console.error('refusing: --require-public and the policy has blockers (above)');
    return 3;
  }
  writeFileSync(args.out as string, result.text);
  console.log(`wrote ${args.out as string}: ${result.release.artifacts[0].sizeBytes} bytes, sha256 ${result.release.artifacts[0].sha256}`);
  return 0;
}

// Importing this module (contracts.ts does) must not run the command line.
if (process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli().then((code) => process.exit(code));
}
