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
import { AnnotationReach, adoptImportedRows, annotateProcesses } from '../../src/lib/processAnnotations';
import type { FlowAnnotationStore } from '../../src/services/flowAnnotations';
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

// --- a socket table that lands between two slices is not lost (1.4) ---------------------------
//
// Each later slice sets the buffer to a prefix of the imported rows, and the copies the
// annotator made of the earlier slice's rows go with it. `adoptImportedRows` runs the
// annotator once more after the last slice when a table was applied meanwhile.
{
  const process = { pid: 7, name: 'curl.exe', exe: 'C:\\curl.exe' };
  const store = { isEmpty: false, forEndpoints: () => process } as unknown as FlowAnnotationStore;
  const NOW_US = 1_800_000_000_000_000;
  const rowsOf = (n: number, tsUs: (i: number) => number) => Array.from({ length: n }, (_, i) => ({
    id: i + 1, tsUs: tsUs(i), source: '10.0.0.4', destination: '93.184.216.34', frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    sourcePort: 50000 + i, destPort: 443, fields: {},
  }) as unknown as Packet);
  const named = (buffer: Packet[]) => buffer.filter((p) => p.fields?.['inwire.process.name'] === 'curl.exe').length;

  /** App's side, as the slices go in: `buffer` is `setPackets`'s state. */
  const run = async (imported: Packet[], plan: { betweenSlices?: number; horizon?: number; current?: () => boolean }) => {
    let buffer: Packet[] = [];
    const reach = new AnnotationReach();
    reach.begin();
    let reannotated: number[] = [];
    let slice = 0;
    const done = await adoptImportedRows(imported, 4, {
      current: plan.current ?? (() => true),
      adoptFirst: (prefix) => { buffer = prefix; },
      showPrefix: (prefix) => { buffer = prefix; },
      annotatedReach: () => reach.reach(),
      reannotate: (horizonUs) => { reannotated.push(horizonUs); buffer = annotateProcesses(buffer, horizonUs, store); },
    }, async () => {
      slice++;
      // A socket table arrives between slices: applied to the buffer as it stands.
      if (slice === plan.betweenSlices) {
        const horizon = plan.horizon ?? -Infinity;
        reach.note(horizon);
        buffer = annotateProcesses(buffer, horizon, store);
      }
    });
    return { buffer, done, reannotated };
  };

  const imported = rowsOf(10, (i) => NOW_US + i);
  const lost = await run(imported, { betweenSlices: 1 });
  check('a table applied between slices is still on every row after the last slice',
    lost.done === true && lost.buffer.length === 10 && named(lost.buffer) === 10 && lost.reannotated.length === 1,
    JSON.stringify({ named: named(lost.buffer), reannotated: lost.reannotated }));

  const quiet = await run(rowsOf(10, (i) => NOW_US + i), {});
  check('with no table meanwhile the annotator is not run again, and nothing is named',
    quiet.reannotated.length === 0 && named(quiet.buffer) === 0 && quiet.buffer.length === 10);

  const single = await run(rowsOf(3, (i) => NOW_US + i), { betweenSlices: 1 });
  check('a single slice has no gap to cover', single.reannotated.length === 0 && single.done === true);

  const delta = await run(rowsOf(10, (i) => NOW_US + i * 10_000_000), { betweenSlices: 1, horizon: NOW_US + 50_000_000 });
  check('a delta\'s horizon is kept: only the rows it reaches are named, as the table itself would have',
    named(delta.buffer) === 5 && delta.reannotated[0] === NOW_US + 50_000_000, JSON.stringify({ named: named(delta.buffer), reannotated: delta.reannotated }));

  let live = 2;
  const replaced = await run(rowsOf(10, (i) => NOW_US + i), { betweenSlices: 1, current: () => live-- > 0 });
  check('a replaced adoption stops, and re-annotates nothing', replaced.done === false && replaced.reannotated.length === 0);
}

if (failed > 0) {
  console.log(`\n${failed} failed`);
  process.exit(1);
}
console.log('\nall passed');
