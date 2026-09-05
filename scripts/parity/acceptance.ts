/**
 * Assertion tests for test/fixtures/acceptance.json - the one tracked piece of
 * the parity harness, and the piece CI can check without the captures.
 *
 *   npx tsx scripts/parity/acceptance.ts
 *
 * The harness itself (parity-check.ts) needs the fixture files and tshark, so
 * it cannot run in CI. What can run is a check that the acceptance file is
 * well-formed and agrees with the README, and that nobody has quietly lowered a
 * floor: floors only go up (docs/decisions/0004, spec Part B recurring gate).
 * A lowered floor is a regression someone chose to hide, and this is the
 * place it becomes visible.
 *
 * The previous floors are read from git, so this needs a checkout; outside one
 * it only validates shape.
 */
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const ACCEPTANCE_PATH = 'test/fixtures/acceptance.json';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

interface Fixture {
  file: string; sha256: string; frames: number;
  floors: Record<string, number>; counts: Record<string, number>; enforce: string[];
}
interface Acceptance { tshark: string; groundTruthFields: string[]; fixtures: Record<string, Fixture> }

const acceptance = JSON.parse(readFileSync(join(root, ACCEPTANCE_PATH), 'utf8')) as Acceptance;
const readme = readFileSync(join(root, 'test/fixtures/README.md'), 'utf8');
const fixtures = Object.entries(acceptance.fixtures);

// --- shape -------------------------------------------------------------------

check('at least one fixture is listed', fixtures.length > 0, true);
check('tshark version recorded', /^\d+\.\d+\.\d+$/.test(acceptance.tshark), true);
check('ground truth ends with Info, so the harness can rejoin split fields',
  acceptance.groundTruthFields.at(-1), '_ws.col.Info');
check('...and carries tcp.reassembled_in and the three fingerprints before it',
  ['tcp.reassembled_in', 'tls.handshake.ja3', 'tls.handshake.ja3s', 'tls.handshake.ja4']
    .every((f) => acceptance.groundTruthFields.includes(f)), true);

for (const [name, f] of fixtures) {
  check(`${name}: file is a capture`, /\.(pcap|pcapng|cap)$/.test(f.file), true);
  check(`${name}: sha256 is 64 hex digits`, /^[0-9a-f]{64}$/.test(f.sha256), true);
  check(`${name}: frames is a positive integer`, Number.isInteger(f.frames) && f.frames > 0, true);
  check(`${name}: every floor is a percentage`,
    Object.entries(f.floors).filter(([, v]) => !(v >= 0 && v <= 100)).map(([k]) => k), []);
  check(`${name}: every enforced count exists`, f.enforce.filter((k) => !(k in f.counts)), []);
  check(`${name}: frames count agrees with the file's frame total`, f.counts.frames, f.frames);
  check(`${name}: README lists the file and its hash`,
    readme.includes(f.file) && readme.includes(f.sha256), true);
}

// --- floors only rise ---------------------------------------------------------

function committedFloors(): Record<string, Record<string, number>> | null {
  try {
    const text = execFileSync('git', ['show', `HEAD:${ACCEPTANCE_PATH}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const prev = JSON.parse(text) as Acceptance;
    return Object.fromEntries(Object.entries(prev.fixtures).map(([n, f]) => [n, f.floors]));
  } catch {
    return null; // not committed yet, or no git - nothing to compare against
  }
}

const previous = committedFloors();
if (previous) {
  for (const [name, f] of fixtures) {
    const before = previous[name] ?? {};
    check(`${name}: no floor was lowered since HEAD`,
      Object.entries(before).filter(([col, v]) => (f.floors[col] ?? 0) < v).map(([col]) => col), []);
  }
} else {
  console.log('skip  floors-only-rise (acceptance.json not in HEAD yet)');
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All acceptance checks passed.');
process.exit(0);
