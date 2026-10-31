/**
 * Writes the agents' version stamps from `package.json`.
 *
 *   npm run sync:version
 *
 * The agent's version is Inwire's version (ADR 0035), and `package.json` is
 * where it is authored. Everything else either reads it at build time or is a
 * literal that `scripts/agent/version.ts` holds to it - **except** the two
 * agents, which cannot read it:
 *
 * - `local-agent/agent_version.py`: `package.json` is not in the PyInstaller
 *   bundle or the Unix tarball, and an installed service has no repository to
 *   look at.
 * - `agent-rs/Cargo.toml`, and the crate's own entry in `agent-rs/Cargo.lock`:
 *   `lib.rs` compiles `CARGO_PKG_VERSION` in, so the crate version IS what
 *   `hello` carries and what `--version` prints - and `stamp-agent.ts` refuses
 *   to stamp a VERSIONINFO that disagrees with it. The lock entry moves with it
 *   because `npm run build:agent` builds `--locked`, and a lock that still
 *   named the old version would fail that build rather than quietly rewrite
 *   itself.
 *
 * So generated files, committed, with a check that fails when they drift.
 * That is deliberately not the same as trusting the generator: a generator
 * somebody forgot to run is exactly the failure a committed artefact invites,
 * and `version.ts` is what turns it into a red build instead of a shipped
 * disagreement.
 *
 * In `NOT_TESTS`: this WRITES files, and a check suite that rewrites its own
 * inputs cannot fail.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version?: string };
const version = pkg.version ?? '';

if (!/^\d+\.\d+\.\d+$/.test(version)) {
  // Not a formatting preference. `isAgentMismatched` parses each segment as a
  // number, so a pre-release tag or build metadata would be silently truncated
  // into a different version than the one written down.
  console.error(`package.json version is "${version}", which is not MAJOR.MINOR.PATCH`);
  process.exit(1);
}

/**
 * One stamp: where it lives, and the replacement that moves it.
 *
 * Each is a replacement, not a rewrite: `agent_version.py`'s docblock is the
 * explanation of why the agent stopped carrying a number of its own, and
 * `Cargo.toml` carries the reasoning for its one dependency - regenerating
 * either from a template here would put that prose in two places.
 */
const STAMPS: { file: string; pattern: RegExp; replacement: string }[] = [
  {
    file: 'local-agent/agent_version.py',
    pattern: /^AGENT_VERSION = "[^"]*"$/m,
    replacement: `AGENT_VERSION = "${version}"`,
  },
  {
    // The first `version = ` at the start of a line is [package]'s. A
    // dependency's version sits inside `{ ... }` and never starts a line.
    file: 'agent-rs/Cargo.toml',
    pattern: /^version = "[^"]*"$/m,
    replacement: `version = "${version}"`,
  },
  {
    // The crate's own entry, found by its name on the line before - the lock
    // holds every dependency's version too.
    file: 'agent-rs/Cargo.lock',
    pattern: /^(name = "inwire-agent"\r?\nversion = )"[^"]*"$/m,
    replacement: `$1"${version}"`,
  },
  {
    // The installed `inwire` launcher compares this with the ProductVersion of
    // the Inwire.exe beside it (exit 65 on a difference), and
    // `build-launcher.ps1` stamps its VERSIONINFO from package.json.
    file: 'launcher-rs/Cargo.toml',
    pattern: /^version = "[^"]*"$/m,
    replacement: `version = "${version}"`,
  },
  {
    file: 'launcher-rs/Cargo.lock',
    pattern: /^(name = "inwire-launcher"\r?\nversion = )"[^"]*"$/m,
    replacement: `$1"${version}"`,
  },
];

let failed = false;
for (const stamp of STAMPS) {
  const path = join(root, stamp.file);
  const current = readFileSync(path, 'utf8');
  if (!stamp.pattern.test(current)) {
    // A pattern that matches nothing would otherwise report "already reads"
    // and leave the stamp wherever it was - the silent kind of failure.
    console.error(`${stamp.file}: found nothing to rewrite - has its shape changed?`);
    failed = true;
    continue;
  }
  const next = current.replace(stamp.pattern, stamp.replacement);
  if (next === current) {
    console.log(`${stamp.file} already reads ${version}`);
    continue;
  }
  writeFileSync(path, next);
  console.log(`${stamp.file} now reads ${version}`);
}
process.exit(failed ? 1 : 0);
