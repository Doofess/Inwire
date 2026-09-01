/**
 * Assertion tests for the session-lifecycle startup decision.
 *
 *   npx tsx scripts/session/lifecycle.ts
 *
 * The rule being pinned down: captured packet bytes on disk live exactly as
 * long as the app is open. On startup the app must tell three situations apart
 * that all look alike from inside a fresh page load -
 *
 *   - the same tab reloading, which must keep its session;
 *   - a second window opening while the first is still capturing, which must
 *     not touch the first one's data;
 *   - a genuinely new run after the app was closed, which must wipe.
 *
 * Getting the second case wrong destroys a live capture, so it is covered from
 * both directions rather than only the happy path.
 */
import { decideStartupAction } from '../../src/services/sessionLifecycle';

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

// --- A reload keeps its session ----------------------------------------------

// sessionStorage survives a reload and dies with the tab, so a marker that is
// still present is proof this is the same tab coming back.
check('reload of the same tab restores', decideStartupAction('1730000000000', false), 'restore');

check(
  'reload restores even with another window open',
  decideStartupAction('1730000000000', true),
  'restore',
);

// --- A fresh tab beside a live one must not wipe ------------------------------

// The dangerous case: opening a second window while the first is mid-capture.
// The new tab has no marker of its own, and wiping on that basis alone would
// delete the frames the other window is still showing.
check('fresh tab beside a live window restores', decideStartupAction(null, true), 'restore');

// --- A genuinely new run wipes -----------------------------------------------

// No marker and nobody else home: whatever is on disk belongs to a run of the
// app that has already closed.
check('fresh tab with no other window wipes', decideStartupAction(null, false), 'wipe');

// --- The marker is treated as presence, not content ---------------------------

// Guards against a truthiness check creeping in: an empty string is still a
// marker that sessionStorage kept, so it still means "same tab".
check('empty-string marker still counts as present', decideStartupAction('', false), 'restore');

console.log(failures === 0 ? '\nAll lifecycle checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
