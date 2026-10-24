/**
 * Where the minimap draws a marked frame's tick (ADR 0067): the row the frame
 * holds in the list as it is SORTED, not in the buffer.
 *
 *   npx tsx scripts/packet-list/mark-ticks.ts
 *
 * The strip is handed the sorted rows. Bisecting them by id is right only for
 * the buffer's own order; sorted by No. descending (newest first) or by any
 * other column it found no row, or another frame's, for every mark.
 */
import { markTickIndices } from '../../src/lib/minimapMarks';

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

const rows = (ids: number[]) => ids.map((id) => ({ id }));
const marks = new Set([2, 5, 99]);

check('the buffer\'s own order: rows of 2 and 5, 99 held by none',
  markTickIndices(marks, rows([1, 2, 3, 4, 5, 6]), true), [1, 4]);
check('newest first: the same frames, from the other end',
  markTickIndices(marks, rows([6, 5, 4, 3, 2, 1]), false), [1, 4]);
check('sorted by another column: wherever the sort put them',
  markTickIndices(marks, rows([4, 2, 6, 1, 5, 3]), false), [1, 4]);
check('nothing marked: no ticks', markTickIndices(new Set(), rows([1, 2, 3]), true), []);
check('an empty list: no ticks', markTickIndices(marks, [], false), []);

console.log(failures === 0 ? '\nAll mark-tick checks passed.' : `\n${failures} mark-tick check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
