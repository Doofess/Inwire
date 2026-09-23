/**
 * Assertion tests for where the selection goes when the list changes.
 *
 *   npx tsx scripts/session/selection-anchor.ts
 *
 * The effect this belongs to is in `App.tsx` and is therefore unreachable from
 * this suite - the rule the root `CLAUDE.md` states after a `queue.shift()`
 * inside a `find` predicate took the renderer down: arithmetic worth testing
 * gets lifted somewhere a script can import it. `services/selectionAnchor.ts`
 * is that somewhere.
 *
 * Two properties, and the second is the one that was wrong:
 *
 * - **A surviving selection must not move.** `kept` is a separate answer from
 *   `packet` precisely so the caller can tell "still here" from "go here
 *   instead"; conflating them sets state to the value it already holds, ten
 *   times a second, for the life of a capture.
 * - **A selection that did not survive goes to the nearest frame in time**,
 *   not to the newest one. Typing a filter while reading frame 12,000 of
 *   700,000 used to answer by selecting the last frame in the capture.
 */
import { anchorSelection } from '../../src/services/selectionAnchor';
import type { Packet } from '../../src/types/packet';

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

/** Only `id` is read, so this is the whole frame the function needs. */
const frames = (...ids: number[]): Packet[] => ids.map((id) => ({ id } as Packet));

/** What an assertion cares about: which id, and whether it moved. */
const at = (list: Packet[], id: number) => {
  const anchor = anchorSelection(list, id);
  return [anchor.packet?.id ?? null, anchor.kept];
};

console.log('\n--- a selection that survived does not move ---\n');

const dense = frames(1, 2, 3, 4, 5);
check('the first frame', at(dense, 1), [1, true]);
check('a middle frame', at(dense, 3), [3, true]);
check('the last frame', at(dense, 5), [5, true]);

// A filtered view keeps order and drops entries, which is the whole
// precondition the binary search rests on.
const sparse = frames(10, 40, 90, 400, 9_000);
check('a frame that survived a filter', at(sparse, 90), [90, true]);
check('...at the head', at(sparse, 10), [10, true]);
check('...at the tail', at(sparse, 9_000), [9_000, true]);

console.log('\n--- one that did not goes to the nearest frame, forward first ---\n');

check('a gap resolves to the next match, not the last one',
  at(sparse, 91), [400, false]);
check('...even when the next match is far away',
  at(sparse, 401), [9_000, false]);
check('a selection before the whole list goes to its head',
  at(sparse, 1), [10, false]);
// The one that makes this worth writing down: the OLD behaviour is this
// answer, and it was the answer for every case above too.
check('a selection past the whole list goes to its tail',
  at(sparse, 100_000), [9_000, false]);

console.log('\n--- the edges ---\n');

check('an empty list has nothing to select', at([], 5), [null, false]);
check('a single frame that matches is kept', at(frames(7), 7), [7, true]);
check('a single frame that does not match is still the answer',
  at(frames(7), 3), [7, false]);
check('...from either side', at(frames(7), 99), [7, false]);

console.log('\n--- the property, over every position in a list ---\n');

// A gap-riddled list, asked about every id in and around it. The invariant is
// the one a hand-written case cannot cover: the answer is always the closest
// surviving id, with ties going forward.
{
  const ids = [3, 4, 9, 10, 11, 25, 26, 100];
  const list = frames(...ids);
  let wrongKept = 0;
  let wrongPick = 0;
  for (let id = 0; id <= 110; id++) {
    const anchor = anchorSelection(list, id);
    const present = ids.includes(id);
    if (anchor.kept !== present) wrongKept++;
    if (anchor.packet === null) { wrongPick++; continue; }
    if (present) {
      if (anchor.packet.id !== id) wrongPick++;
      continue;
    }
    // Forward if anything is forward, otherwise the last one behind.
    const forward = ids.find((candidate) => candidate > id);
    const expected = forward ?? ids[ids.length - 1];
    if (anchor.packet.id !== expected) wrongPick++;
  }
  check('`kept` is exactly "the id is in the list", at every position', wrongKept, 0);
  check('the frame chosen is the nearest forward, or the last behind', wrongPick, 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All selection-anchor checks passed.');
process.exit(0);
