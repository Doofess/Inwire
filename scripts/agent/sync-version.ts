/**
 * Writes the agent's version file from `package.json`.
 *
 *   npm run sync:version
 *
 * The agent's version is Inwire's version (ADR 0035), and `package.json` is
 * where it is authored. Everything else either reads it at build time or is a
 * literal that `scripts/agent/version.ts` holds to it - **except** the Python,
 * which cannot: `package.json` is not in the PyInstaller bundle and a frozen
 * service has no repository to look at.
 *
 * So one generated file, committed, with a check that fails when it drifts.
 * That is deliberately not the same as trusting the generator: a generator
 * somebody forgot to run is exactly the failure a committed artefact invites,
 * and `version.ts` is what turns it into a red build instead of a shipped
 * disagreement.
 *
 * In `NOT_TESTS`: this WRITES a file, and a check suite that rewrites its own
 * inputs cannot fail.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const target = join(root, 'local-agent', 'agent_version.py');

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string };
const version = pkg.version ?? '';

if (!/^\d+\.\d+\.\d+$/.test(version)) {
  // Not a formatting preference. `isAgentOutdated` parses each segment as a
  // number, so a pre-release tag or build metadata would be silently truncated
  // into a different version than the one written down.
  console.error(`package.json version is "${version}", which is not MAJOR.MINOR.PATCH`);
  process.exit(1);
}

const current = readFileSync(target, 'utf8');
const next = current.replace(/^AGENT_VERSION = "[^"]*"$/m, `AGENT_VERSION = "${version}"`);

if (next === current) {
  console.log(`agent_version.py already reads ${version}`);
  process.exit(0);
}
// A replacement, not a rewrite: the file's whole docblock is the explanation of
// why the agent stopped carrying a number of its own, and regenerating it from
// a template here would put that prose in two places.
writeFileSync(target, next);
console.log(`agent_version.py now reads ${version}`);
process.exit(0);
