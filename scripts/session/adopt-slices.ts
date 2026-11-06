/**
 * A finished import is handed to the list in slices (`src/lib/adoptSlices.ts`).
 *
 * One `setPackets` of 2.26M rows made every incremental aggregate fold the whole
 * buffer in one render: a 700-760 ms task at the import's end (profiled; the
 * name map's `learnFromPacket` alone ~500 ms). A buffer grown at its tail is a
 * plain extension to `prefixShift`, so each slice folds only its own rows.
 *
 *   npx tsx scripts/session/adopt-slices.ts
 */
import { adoptInSlices, adoptSliceEnds } from '../../src/lib/adoptSlices';
import { prefixShift } from '../../src/services/packetPrefix';
import type { Packet } from '../../src/types/packet';

let failed = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `: ${detail}`}`);
};
const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

check('slice ends step by the slice and end at the total', same(adoptSliceEnds(10, 4), [4, 8, 10]), JSON.stringify(adoptSliceEnds(10, 4)));
check('an exact multiple ends on it once', same(adoptSliceEnds(8, 4), [4, 8]), JSON.stringify(adoptSliceEnds(8, 4)));
check('a buffer under one slice is one slice', same(adoptSliceEnds(3, 4), [3]));
check('an empty import is still shown once (the view must be emptied)', same(adoptSliceEnds(0, 4), [0]));

const rows = Array.from({ length: 10 }, (_, i) => ({ id: i + 1 }) as unknown as Packet);

{
  const shown: Packet[][] = [];
  const firsts: boolean[] = [];
  let yields = 0;
  let yieldedBeforeFirst = false;
  const done = await adoptInSlices(rows, 4, (prefix, first) => {
    shown.push(prefix);
    firsts.push(first);
    return true;
  }, async () => {
    if (shown.length === 0) yieldedBeforeFirst = true;
    yields++;
  });
  check('every slice is shown, in order', same(shown.map((s) => s.length), [4, 8, 10]));
  check('each slice is a prefix of the rows, the same objects',
    shown.every((s) => s.every((p, i) => p === rows[i])));
  check('only the first is marked first', same(firsts, [true, false, false]));
  check('the last slice is the rows array itself (no copy)', shown[shown.length - 1] === rows);
  check('the first slice is shown at once, a task between each later one', !yieldedBeforeFirst && yields === 2, `yields ${yields}`);
  check('it reports completion', done === true);
  check('each slice extends the one before it for the aggregates (prefixShift 0)',
    shown.slice(1).every((s, i) => prefixShift(s, shown[i]) === 0));
}

{
  const shown: number[] = [];
  const done = await adoptInSlices(rows, 4, (prefix) => {
    shown.push(prefix.length);
    return prefix.length < 8;
  }, async () => {});
  check('a show that answers false stops the slices there', same(shown, [4, 8]) && done === false, JSON.stringify(shown));
}

if (failed > 0) {
  console.log(`\n${failed} failed`);
  process.exit(1);
}
console.log('\nall passed');
