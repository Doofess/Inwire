/**
 * The versions the shipping installer stamps agree with the code it ships.
 *
 *   npx tsx scripts/agent/installer-versions.ts
 *
 * `local-agent/test_protocol.py` already locks `AGENT_VERSION` across
 * `agent.py`, `agentProtocol.ts` and an `.iss` file - but the `.iss` file it
 * reads is `local-agent/installer/setup.iss`, the **legacy** agent-only
 * installer that ADR 0032 calls legacy. The one `iscc` actually produces a
 * product from is `installer/setup.iss`, and until this script existed
 * **nothing read it**: its `MyAgentVersion` and `MyAppVersion` agreed with the
 * code by hand.
 *
 * The second half of that gap is the runner. `test_protocol.py` is Python, and
 * `scripts/check.ts` only discovers TypeScript - so the lock that did exist
 * fired only when somebody remembered to run it, and CLAUDE.md's command list
 * names nothing that does. This one runs on every `npm run check`, which is the
 * point of writing it here rather than extending the Python.
 *
 * ## Why a wrong answer here is expensive
 *
 * `AGENT_VERSION` is the left-hand side of `isAgentOutdated`, so it is an
 * **ordering** and not a label. An installer that stamps a version lower than
 * the agent it installs produces a service the app reads as *newer* than
 * required, which surfaces as "not connected" rather than "update your agent" -
 * a state with no instruction attached to it. `MyAppVersion` is the other kind
 * of wrong: Windows compares it to decide whether an install is an upgrade, so
 * a stale one turns an upgrade into a second install.
 *
 * Both files are checked, not just the shipping one. They are allowed to serve
 * different purposes - the legacy installer stamps its `AppVersion` from
 * `MyAgentVersion`, because it installs only the agent - but the two constants
 * themselves have to mean the same thing in both, or the copy that drifts is
 * the copy nobody is looking at.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_AGENT_VERSION } from '../../src/services/agentProtocol';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

/**
 * Reads a file, and counts a failure rather than throwing if it is not there.
 *
 * A missing `.iss` must not read as "nothing to check". `node-safe.ts` makes
 * the same argument about its import walk: an assertion that passes because it
 * found nothing is worse than no assertion at all, because it prints PASS.
 */
function text(relative: string): string {
  try {
    return readFileSync(join(root, relative), 'utf8');
  } catch {
    failures++;
    console.log(`FAIL  ${relative} could not be read`);
    return '';
  }
}

/** Lines, with the carriage return an `.iss` file carries taken off. */
function lines(source: string): string[] {
  return source.split('\n').map((line) => line.trim());
}

/**
 * The value of an Inno `#define`.
 *
 * Scanned rather than pattern-matched, because the `#define` prefix is doing
 * real work: `MyAgentVersion` also appears in the prose comment above its own
 * definition in both files, and a looser match reads the sentence instead.
 */
function define(source: string, name: string): string | null {
  for (const line of lines(source)) {
    if (!line.startsWith('#define')) continue;
    const rest = line.slice('#define'.length).trim();
    if (!rest.startsWith(name)) continue;
    const after = rest.slice(name.length).trim();
    if (!after.startsWith('"')) continue;
    return after.slice(1, after.indexOf('"', 1));
  }
  return null;
}

/** `AGENT_VERSION = "x.y.z"` out of the agent's source. */
function pythonConstant(source: string, name: string): string | null {
  for (const line of lines(source)) {
    if (!line.startsWith(name)) continue;
    const after = line.slice(line.indexOf('=') + 1).trim();
    if (!after.startsWith('"')) continue;
    return after.slice(1, after.indexOf('"', 1));
  }
  return null;
}

const SHIPPING = 'installer/setup.iss';
const LEGACY = 'local-agent/installer/setup.iss';

const shipping = text(SHIPPING);
const legacy = text(LEGACY);

// The read is itself an assertion: with both of these empty every check below
// compares null to null and passes.
check(`${SHIPPING} was read`, shipping.length > 0, true);
check(`${LEGACY} was read`, legacy.length > 0, true);

// --- The wire-protocol version ----------------------------------------------

const agentVersion = pythonConstant(text('local-agent/agent.py'), 'AGENT_VERSION');

check('agent.py declares an AGENT_VERSION', agentVersion !== null, true);
check('agentProtocol.ts REQUIRED_AGENT_VERSION matches agent.py',
  REQUIRED_AGENT_VERSION, agentVersion);
check(`${SHIPPING} MyAgentVersion matches agent.py`,
  define(shipping, 'MyAgentVersion'), agentVersion);
check(`${LEGACY} MyAgentVersion matches agent.py`,
  define(legacy, 'MyAgentVersion'), agentVersion);

// --- The product version ----------------------------------------------------

const pkg = JSON.parse(text('package.json') || '{}') as { version?: string };
const productVersion = pkg.version ?? null;

check('package.json declares a version', productVersion !== null, true);
check(`${SHIPPING} MyAppVersion matches package.json`,
  define(shipping, 'MyAppVersion'), productVersion);
check(`${LEGACY} MyAppVersion matches package.json`,
  define(legacy, 'MyAppVersion'), productVersion);

// --- The floor, which is the rule with the failure mode behind it ------------

/**
 * Where the ordering had got to when this floor was written.
 *
 * Compared as numbers and never as a string: "3.10.0" sorts *before* "3.9.0"
 * lexically, so a string floor would reject the first version past 3.9 and
 * every version after it. `test_protocol.py` holds the same floor for the same
 * reason; this is the half that runs unprompted.
 */
const FLOOR: readonly [number, number, number] = [3, 9, 0];

function tuple(version: string | null): [number, number, number] {
  const parts = (version ?? '').split('.').map((part) => Number.parseInt(part, 10) || 0);
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function atLeast(a: [number, number, number], b: readonly [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

check(`AGENT_VERSION is not reset below ${FLOOR.join('.')}`,
  atLeast(tuple(agentVersion), FLOOR), true);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
