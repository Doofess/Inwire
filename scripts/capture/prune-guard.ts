/**
 * The one function that decides a user's captures are gone.
 *
 *   npx tsx scripts/capture/prune-guard.ts
 *
 * `App.tsx` calls `captureStore.prune(meta?.captureId ? [meta.captureId] : [])`
 * at startup, and the store removes every directory not in that list,
 * recursively. While the store lived in OPFS this was safe by construction:
 * the root was the origin's private filesystem and nothing else could put
 * anything in it, so an empty keep list emptied a directory only this app had
 * ever written to.
 *
 * On a real filesystem it is a recursive delete of a directory a person can
 * open and drop files into - and the empty keep list is not a corner case. It
 * is what happens whenever `loadSessionMeta()` returns nothing: every existing
 * user's first launch of the desktop build, and any launch after the metadata
 * is lost or corrupt.
 *
 * `docs/decisions/0012` says a capture is discarded only when the user asks.
 * On OPFS that was a policy. Here it needs a mechanism, and this is the test
 * for it. The property, stated once: **nothing is removed that this app did
 * not name.**
 */
import {
  CAPTURE_ID_PATTERN, isCaptureId, newCaptureId, planPrune,
} from '../../src/services/capture/captureDirectory';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

console.log('--- the generator and the guard agree ---\n');

{
  // The guard is only as good as its agreement with the generator, which is
  // why they share a file. A thousand ids, every one accepted.
  const ids = Array.from({ length: 1000 }, () => newCaptureId(
    new Date(2020 + Math.floor(Math.random() * 20), Math.floor(Math.random() * 12),
      1 + Math.floor(Math.random() * 28), Math.floor(Math.random() * 24),
      Math.floor(Math.random() * 60), Math.floor(Math.random() * 60)),
  ));
  check('every generated id passes the guard', ids.filter((id) => !isCaptureId(id)), []);
  check('...and they are all distinctly shaped', new Set(ids.map((i) => i.length)).size, 1);
  // The hex suffix is where a `toString(16)` without padding would produce a
  // short id that the pattern then rejects - a capture that could never be
  // pruned, growing for ever.
  checkTrue('the suffix is always four hex digits',
    ids.every((id) => /-[0-9a-f]{4}$/.test(id)));
}

console.log('\n--- what the guard refuses ---\n');

{
  const refused = [
    '', '.', '..', '/', 'C:\\', 'Documents', 'My Captures', '.git', 'node_modules',
    'cap-20260911-143536', 'cap-20260911-143536-e32', 'cap-20260911-143536-E327',
    'cap-20260911-143536-e327.tmp', ' cap-20260911-143536-e327',
    'cap-20260911-143536-e327 ', 'cap-2026091-143536-e327', 'xcap-20260911-143536-e327',
    'cap-20260911-143536-e327/..', 'cap-20260911-143536-zzzz',
  ];
  check('none of these looks like a capture', refused.filter(isCaptureId), []);
  // Anchored at both ends. An unanchored pattern would accept the traversal
  // and the trailing-dot forms above, which is the whole hazard.
  checkTrue('the pattern is anchored at both ends',
    CAPTURE_ID_PATTERN.source.startsWith('^') && CAPTURE_ID_PATTERN.source.endsWith('$'));
  checkTrue('a newline cannot smuggle a name past it',
    !isCaptureId('cap-20260911-143536-e327\nDocuments'));
}

console.log('\n--- the plan ---\n');

{
  const a = 'cap-20260911-100000-aaaa';
  const b = 'cap-20260911-110000-bbbb';
  const c = 'cap-20260911-120000-cccc';

  check('everything but the kept capture goes',
    planPrune([a, b, c], [b]), { remove: [a, c], foreign: [] });
  check('keeping several keeps several',
    planPrune([a, b, c], [a, c]), { remove: [b], foreign: [] });
  check('an empty directory plans nothing',
    planPrune([], []), { remove: [], foreign: [] });
  check('keeping something absent is not an error',
    planPrune([a], ['cap-20990101-000000-ffff']), { remove: [a], foreign: [] });

  // **The case this file exists for.** An empty keep list is the startup path
  // for every user whose session names no capture.
  check('an empty keep list still only removes captures',
    planPrune([a, 'Documents', 'notes.txt', '..'], []),
    { remove: [a], foreign: ['Documents', 'notes.txt', '..'] });

  // Reported rather than silently skipped: something unexpected in the capture
  // directory is worth being able to see, and might mean captures are being
  // written somewhere else entirely.
  check('what it will not touch, it says',
    planPrune(['My Holiday Photos'], []).foreign, ['My Holiday Photos']);

  // Order is the listing's, so a caller removing them in order removes them in
  // the order the directory reported - nothing depends on it, and a plan that
  // reordered would make a failure mid-prune harder to reason about.
  check('the plan preserves the order it was given',
    planPrune([c, a, b], []).remove, [c, a, b]);
}

console.log('\n--- idempotence, which is what a retry needs ---\n');

{
  const a = 'cap-20260911-100000-aaaa';
  const b = 'cap-20260911-110000-bbbb';
  // A prune that fails half way - a file held open by an antivirus scanner is
  // the ordinary reason on Windows - is retried on the next launch, and the
  // second plan must be the remainder rather than something new.
  const first = planPrune([a, b], [b]);
  const second = planPrune([b], [b]);
  check('after removing what it planned, there is nothing left to plan',
    [first.remove, second.remove], [[a], []]);
}

console.log(failures === 0
  ? '\nAll prune guard checks passed.'
  : `\n${failures} prune guard check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
