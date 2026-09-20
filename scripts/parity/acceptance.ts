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

import type { Acceptance, FixtureSpec } from './acceptance-schema';

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

  // --- and the tree's side of it (ADR 0039) -----------------------------------
  //
  // A separate object rather than more keys in `floors`, and the check above is
  // exactly why: it asserts every floor is a percentage, so a layer count of 24
  // would pass as one and a reference vocabulary of 120 would fail as one. The
  // namespaces differ too - `floors` is keyed by display-column name with
  // spaces and capitals, `tree.layers` by lowercase layer token.
  const t = f.tree;
  check(`${name}: has a tree block`, t !== undefined, true);
  if (t === undefined) continue;
  const notACount = (v: number): boolean => !(Number.isInteger(v) && v >= 0);
  check(`${name}: every layer floor is a count`,
    Object.entries(t.layers).filter(([, v]) => notACount(v)).map(([k]) => k), []);
  check(`${name}: every ceiling is a count`,
    Object.entries(t.ceilings).filter(([, v]) => notACount(v)).map(([k]) => k), []);
  check(`${name}: every recorded count is a count`,
    Object.entries(t.counts).filter(([, v]) => notACount(v)).map(([k]) => k), []);
  check(`${name}: protosNamed is a count`, !notACount(t.protosNamed), true);
  check(`${name}: every unimplemented layer says why`,
    Object.entries(t.unimplemented).filter(([, why]) => why.trim().length === 0).map(([k]) => k), []);
  // A layer is floored or declared unimplemented, never both - the second is
  // the statement that the first is deliberately absent.
  check(`${name}: no layer is both floored and unimplemented`,
    Object.keys(t.layers).filter((k) => k in t.unimplemented), []);
}

// --- floors only rise ---------------------------------------------------------

/**
 * The whole committed fixture, not just its `floors`.
 *
 * Widened from `committedFloors()` when the tree gained floors of its own:
 * four ratchets now read from it, and each needs a different part.
 */
function committedFixtures(): Record<string, FixtureSpec> | null {
  try {
    const text = execFileSync('git', ['show', `HEAD:${ACCEPTANCE_PATH}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return (JSON.parse(text) as Acceptance).fixtures;
  } catch {
    return null; // not committed yet, or no git - nothing to compare against
  }
}

const previous = committedFixtures();
if (previous) {
  for (const [name, f] of fixtures) {
    const before = previous[name];
    // `?? 0` rather than an `in` guard, deliberately: **deleting** a floor is
    // the cheapest way to lower one, and an absent key must read as zero so it
    // fails here rather than quietly disappearing.
    check(`${name}: no floor was lowered since HEAD`,
      Object.entries(before?.floors ?? {}).filter(([col, v]) => (f.floors[col] ?? 0) < v).map(([col]) => col), []);

    const was = before?.tree;
    const now = f.tree;
    if (was === undefined || now === undefined) continue;
    check(`${name}: no tree floor was lowered since HEAD`,
      Object.entries(was.layers).filter(([l, v]) => (now.layers[l] ?? 0) < v).map(([l]) => l), []);
    check(`${name}: protosNamed did not fall since HEAD`, now.protosNamed >= was.protosNamed, true);
    // **Ceilings only fall, for the same reason floors only rise.** The two
    // numbers here count defects - a filter with no tree row behind it, and a
    // value that disagrees with the reference - so letting one drift upward is
    // the same act as lowering a floor, wearing the other sign.
    check(`${name}: no ceiling was raised since HEAD`,
      Object.entries(was.ceilings).filter(([k, v]) => (now.ceilings[k] ?? Infinity) > v).map(([k]) => k), []);
    // An entry may only leave `unimplemented` by becoming a floor. Vanishing
    // to nowhere would retire the statement without recording what replaced it.
    check(`${name}: nothing left unimplemented without becoming a floor`,
      Object.keys(was.unimplemented).filter((l) => !(l in now.unimplemented) && !(l in now.layers)), []);
  }
} else {
  console.log('skip  the ratchets - floors, tree floors, protosNamed, ceilings and '
    + 'unimplemented (acceptance.json not in HEAD yet)');
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All acceptance checks passed.');
process.exit(0);
