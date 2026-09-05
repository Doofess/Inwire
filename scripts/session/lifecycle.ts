/**
 * Assertion tests for the session-lifecycle startup decision.
 *
 *   npx tsx scripts/session/lifecycle.ts
 *
 * **The rule this file pins down was reversed in `docs/decisions/0012`.**
 *
 * It used to be that captured bytes on disk lived exactly as long as the app
 * was open: a fresh tab with nobody else home meant the app had been closed, so
 * whatever was on disk was leftovers and got wiped. These tests enforced that,
 * and the case they guarded hardest was the dangerous one - a second window
 * opening beside a live capture must not delete the first one's frames.
 *
 * The reversal is that "leftovers" was never distinguishable from "a capture
 * someone still wants". The signals below - a per-tab marker, and whether
 * another window answers - tell you the app was closed. They do not tell you
 * the user was finished, and an accidental tab close after three hours of
 * capture looks exactly like being finished.
 *
 * So startup restores, always, and a capture is discarded only when asked for.
 * These tests now hold that line: **no combination of inputs may produce a
 * wipe.** That is a weaker property than the old one, and it is the point -
 * the previous version could delete a user's data, and this one cannot.
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
// still present is proof this is the same tab coming back. Unchanged.
check('reload of the same tab restores', decideStartupAction('1730000000000', false), 'restore');
check(
  'reload restores even with another window open',
  decideStartupAction('1730000000000', true),
  'restore',
);

// --- A fresh tab beside a live one must not wipe ------------------------------

// Opening a second window while the first is mid-capture. This was the case the
// old policy was most careful about, and it still holds - by a stronger route
// now, since nothing wipes at all.
check('fresh tab beside a live window restores', decideStartupAction(null, true), 'restore');

// --- A new run after the app was closed now RESTORES ---------------------------

// The reversal, stated as a test. No marker and nobody else home used to mean
// "wipe": the app had been closed, so the frames were leftovers. It now means
// the app is being reopened, and the capture is still the user's.
check('a fresh run after the app closed restores rather than wiping',
  decideStartupAction(null, false), 'restore');

// --- Nothing may wipe ----------------------------------------------------------

// The property that matters, checked exhaustively rather than case by case: the
// input space is four combinations, and none of them may destroy data. A future
// change that reintroduces an automatic wipe fails here and has to justify
// itself against 0012 rather than slipping in.
for (const marker of [null, '', '1730000000000']) {
  for (const otherWindow of [false, true]) {
    check(
      `no automatic wipe (marker=${JSON.stringify(marker)}, otherWindow=${otherWindow})`,
      decideStartupAction(marker, otherWindow),
      'restore',
    );
  }
}

console.log(failures === 0 ? '\nAll lifecycle checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
