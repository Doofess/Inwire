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
import { markTickIndices, selectedRowIndex } from '../../src/lib/minimapMarks';

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

// The selection's line: found the same way. A finished import selects its first
// frame, and a scan from the end walked the whole buffer on every repaint and
// every slice of the strip's fill (587 ms after a 2.26M-frame import).
check('the selection, in the buffer\'s own order', selectedRowIndex(rows([1, 2, 3, 4, 5, 6]), 2, true), 1);
check('the selection, newest first', selectedRowIndex(rows([6, 5, 4, 3, 2, 1]), 2, false), 4);
check('a selection the list does not hold has no row', selectedRowIndex(rows([1, 2, 3]), 9, true), -1);
check('...nor in another order', selectedRowIndex(rows([3, 1, 2]), 9, false), -1);
check('an empty list: no row', selectedRowIndex([], 1, true), -1);
let reads = 0;
const many = rows(Array.from({ length: 1_000_000 }, (_, i) => i + 1));
const counted = new Proxy(many, { get(target, key, receiver) {
  if (typeof key === 'string' && /^\d+$/.test(key)) reads++;
  return Reflect.get(target, key, receiver);
} });
check('the first of a million, in order, is bisected rather than scanned',
  [selectedRowIndex(counted, 1, true), reads <= 25], [0, true]);

console.log(failures === 0 ? '\nAll mark-tick checks passed.' : `\n${failures} mark-tick check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
