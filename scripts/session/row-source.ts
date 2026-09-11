/**
 * The seam the packet list reads rows through.
 *
 *   npx tsx scripts/session/row-source.ts
 *
 * `packets.length` used to be the capture. It is the RAM window over one now,
 * and the list has to be able to address rows that are not in it - so it asks
 * a `RowSource` for row *i* instead of subscripting an array.
 *
 * What is worth asserting about a four-line pass-through is not the
 * pass-through. It is the two properties everything built on top of it will
 * assume, and both of them fail **silently** if they are wrong:
 *
 *  - **out of range is `unavailable`, never a throw and never `undefined`.**
 *    `rowAt` runs inside render, once per visible row, against a count that
 *    can shrink underneath the scroll position - the exact mismatch
 *    `virtualWindow`'s header describes, which once left a list showing
 *    157,117 pixels of nothing. A source that threw there would take the tab
 *    down instead.
 *  - **`rowSlice` clamps.** It is handed `virtualWindow`'s output, and the
 *    window is computed from a count that was current one render ago.
 *
 * The third is the one that keeps today's captures honest: a source over an
 * array must answer `ready` for every row in it, so nothing about a capture
 * that fits in memory changes by introducing the seam.
 */
import { arrayRowSource, packetAt, rowSlice, type Row, type RowSource } from '../../src/lib/rowSource';
import { virtualWindow } from '../../src/lib/virtualWindow';
import type { Packet } from '../../src/types/packet';

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

function frame(id: number): Packet {
  return { id, info: `frame ${id}`, layers: [], rawBytes: new Uint8Array(0) } as unknown as Packet;
}

const states = (rows: readonly Row[]): string[] => rows.map((r) => r.state);
const ids = (rows: readonly Row[]): number[] =>
  rows.map((r) => (r.state === 'ready' ? r.packet.id : -1));

console.log('--- an array, which is every capture the app handles today ---\n');

{
  const packets = Array.from({ length: 5 }, (_, i) => frame(i + 1));
  const source = arrayRowSource(packets);

  check('the count is the array', source.count, 5);
  check('every row in it is ready', states(rowSlice(source, 0, 5)),
    ['ready', 'ready', 'ready', 'ready', 'ready']);
  check('...in order', ids(rowSlice(source, 0, 5)), [1, 2, 3, 4, 5]);
  check('a row is the packet at that index, not the packet with that id',
    packetAt(source, 2)?.id, 3);
  check('request is a no-op it does not have to implement',
    source.request(0, 5) as unknown, undefined);
}

console.log('\n--- out of range, which render reaches and must survive ---\n');

{
  const source = arrayRowSource([frame(1), frame(2)]);
  check('past the end is unavailable, not undefined', source.rowAt(2).state, 'unavailable');
  check('...and so is far past it', source.rowAt(1_000_000).state, 'unavailable');
  check('a negative index is unavailable too', source.rowAt(-1).state, 'unavailable');
  check('packetAt says null rather than answering with the wrong frame',
    [packetAt(source, 2), packetAt(source, -1)], [null, null]);
  check('an empty source has no rows and no opinions',
    [arrayRowSource([]).count, arrayRowSource([]).rowAt(0).state], [0, 'unavailable']);
}

console.log('\n--- the slice, against a count that moved underneath it ---\n');

{
  const source = arrayRowSource(Array.from({ length: 10 }, (_, i) => frame(i + 1)));
  check('a slice inside the range is exactly it', ids(rowSlice(source, 3, 6)), [4, 5, 6]);
  // The failure mode this clamps for: a filter applied while the list is
  // scrolled deep leaves `virtualWindow`'s output describing the OLD count.
  check('a slice running past the end stops at the end',
    ids(rowSlice(source, 8, 40)), [9, 10]);
  check('a slice entirely past the end is empty rather than ten unavailables',
    rowSlice(source, 40, 80).length, 0);
  check('a negative start is clamped, not wrapped',
    ids(rowSlice(source, -5, 2)), [1, 2]);
  check('an inverted range is empty', rowSlice(source, 6, 3).length, 0);
}

console.log('\n--- driven by the window that actually asks ---\n');

{
  // The two modules meet here, and this is the pairing that matters: whatever
  // `virtualWindow` returns, `rowSlice` must be able to answer it.
  const sizes = [0, 1, 40, 1000, 700_000];
  let everyPairingSafe = true;
  let everySliceMatchesTheWindow = true;
  for (const size of sizes) {
    const source = arrayRowSource(Array.from({ length: size }, (_, i) => frame(i + 1)));
    for (const scrollTop of [0, 21, 1234, 5_000_000, -100]) {
      const w = virtualWindow(source.count, scrollTop, 800, 21, 15);
      const rows = rowSlice(source, w.startIndex, w.endIndex);
      if (rows.length !== Math.max(0, w.endIndex - w.startIndex)) everySliceMatchesTheWindow = false;
      if (rows.some((r) => r.state !== 'ready')) everyPairingSafe = false;
    }
  }
  checkTrue('the window never asks an array source for a row it does not have',
    everyPairingSafe);
  checkTrue('...and the slice is exactly as long as the window said',
    everySliceMatchesTheWindow);
}

console.log('\n--- what a source that has to fetch looks like ---\n');

{
  // Not the real one - that arrives with the capture-backed source - but the
  // shape the list has to render, so the three states are exercised through
  // the same helpers the component uses.
  const asked: [number, number][] = [];
  const held = new Map<number, Packet>([[0, frame(1)], [3, frame(4)]]);
  const source: RowSource = {
    count: 6,
    rowAt(index) {
      if (index < 0 || index >= 6) return { state: 'unavailable', ordinal: index };
      const packet = held.get(index);
      if (packet !== undefined) return { state: 'ready', packet };
      // Row 5 stands for a frame the store cannot supply - a torn tail.
      return index === 5
        ? { state: 'unavailable', ordinal: index }
        : { state: 'loading', ordinal: index };
    },
    request(from, to) { asked.push([from, to]); },
  };

  check('the three states come back distinguishable',
    states(rowSlice(source, 0, 6)),
    ['ready', 'loading', 'loading', 'ready', 'loading', 'unavailable']);
  check('a row that is not ready has no packet, and says which row it is',
    [packetAt(source, 1), (source.rowAt(1) as { ordinal: number }).ordinal], [null, 1]);
  // `loading` and `unavailable` are different answers on purpose: one of them
  // resolves. A spinner that never stops is worse than a row that says so.
  checkTrue('loading and unavailable are not the same state',
    source.rowAt(4).state !== source.rowAt(5).state);

  source.request(2, 5);
  check('the source is told what is about to be asked for', asked, [[2, 5]]);
}

console.log(failures === 0
  ? '\nAll row source checks passed.'
  : `\n${failures} row source check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
