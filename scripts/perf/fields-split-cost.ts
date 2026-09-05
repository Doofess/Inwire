/**
 * Would splitting `Packet.fields` into dense columns and a sparse bag pay?
 *
 *   node --expose-gc --import tsx scripts/perf/fields-split-cost.ts
 *
 * `fields` is 1,431 B a frame, 76% of what a resident record costs
 * (`record-cost.ts`, ADR 0016). ADR 0013 measured three ways to shrink it and
 * took only one: interning the strings (82 MB). Rebuilding the bag was 46 MB
 * and not worth an allocation in the hot path, and **a column per key measured
 * three times WORSE** - 976 B a frame against 294 - because a key only a few
 * frames carry still costs a slot in every frame.
 *
 * That last result is what this re-examines, because the shape of the bag says
 * why it failed and what would not. Over both fixtures: 24.7 entries a frame
 * across 123 keys, but **15 keys hold half of all entries**, and the commonest
 * are near-universal and tiny - `eth.ig` on every frame with 2 distinct values,
 * `tcp.flags.syn` on 22,063 with 2, `ipv6.nxt` on 22,996 with 4.
 *
 * So the failure was applying one representation to both halves. A dense key is
 * cheap as a column and expensive as a property; a sparse key is the reverse.
 * This measures the split rather than either extreme:
 *
 *   dense  (on >= DENSE_THRESHOLD of frames) -> a typed array per key, plus a
 *          presence bit, since "absent" and "zero" are different answers
 *   sparse (everything else)                 -> the object, as today
 *
 * Nothing is built on this. It is here to say whether the split is worth
 * designing, and it reports the answer either way.
 *
 * A measurement, not an assertion: `check.ts` skips it by name.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { clearAddressPool } from '../../src/services/addressFormat';
import type { Packet } from '../../src/types/packet';

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/netview_capture_1788426090876.pcap',
];

/** How much of the capture a key must appear in to be worth a column. */
const DENSE_THRESHOLD = 0.2;

const EMPTY = new Uint8Array(0);

function heap(): number {
  if (global.gc) for (let i = 0; i < 6; i++) global.gc();
  return process.memoryUsage().heapUsed;
}

function median(values: number[]): number {
  return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}

async function dissect(): Promise<Packet[]> {
  clearAddressPool();
  const out: Packet[] = [];
  for (const path of FIXTURES) {
    const parsed = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(path))], 'f.pcap'), 1_000_000,
    );
    for (const p of parsed.packets) { p.rawBytes = EMPTY; out.push(p); }
  }
  return out;
}

async function main() {
  const missing = FIXTURES.filter(f => !existsSync(f));
  if (missing.length > 0) {
    console.log('SKIP  fixture missing: ' + missing[0] + ' (see test/fixtures/README.md)');
    process.exit(0);
  }
  if (!global.gc) {
    console.log('Run with --expose-gc, or these are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/fields-split-cost.ts');
    process.exit(1);
  }

  // --- Which keys are dense, and what can each column hold? --------------------
  const survey = await dissect();
  const frames = survey.length;
  const seen = new Map<string, { count: number; numeric: boolean }>();
  for (const p of survey) {
    for (const [key, value] of Object.entries(p.fields ?? {})) {
      let s = seen.get(key);
      if (!s) { s = { count: 0, numeric: true }; seen.set(key, s); }
      s.count++;
      if (typeof value !== 'number' && typeof value !== 'boolean') s.numeric = false;
    }
  }
  const dense = [...seen.entries()]
    .filter(([, s]) => s.count / frames >= DENSE_THRESHOLD)
    .sort((a, b) => b[1].count - a[1].count);
  const denseKeys = new Set(dense.map(([k]) => k));

  let allEntries = 0;
  let denseEntries = 0;
  for (const [, s] of seen) allEntries += s.count;
  for (const [, s] of dense) denseEntries += s.count;

  console.log(frames.toLocaleString() + ' frames, ' + seen.size + ' distinct keys, '
    + allEntries.toLocaleString() + ' entries');
  console.log('dense = on >= ' + (DENSE_THRESHOLD * 100).toFixed(0) + '% of frames: '
    + dense.length + ' keys, holding ' + denseEntries.toLocaleString() + ' entries ('
    + ((denseEntries / allEntries) * 100).toFixed(1) + '%)');
  const numericDense = dense.filter(([, s]) => s.numeric).length;
  console.log('  ' + numericDense + ' numeric, ' + (dense.length - numericDense) + ' string');
  console.log();

  // --- Three representations of the same data ----------------------------------
  const measure = async (mode: 'whole' | 'sparse-only' | 'split'): Promise<number> => {
    const before = heap();
    const packets = await dissect();
    let held: unknown[] | undefined;
    if (mode === 'whole') {
      held = [packets];
    } else {
      const columns = new Map<string, Float64Array | (string | undefined)[]>();
      const present = new Map<string, Uint8Array>();
      if (mode === 'split') {
        for (const [key, s] of dense) {
          columns.set(key, s.numeric ? new Float64Array(frames) : new Array(frames));
          // "Absent" and "zero" are different answers - a filter asking about a
          // field the frame does not carry must not match - so presence is its
          // own bit and cannot be folded into a sentinel value.
          present.set(key, new Uint8Array(frames));
        }
      }
      for (let i = 0; i < packets.length; i++) {
        const bag = packets[i].fields ?? {};
        // Rebuilt rather than `delete`d, so the removal is real: deleting from
        // an object leaves it in dictionary mode carrying the deleted slots.
        const sparse: Record<string, string | number> = {};
        for (const [key, value] of Object.entries(bag)) {
          if (denseKeys.has(key)) {
            if (mode === 'split') {
              const column = columns.get(key)!;
              if (column instanceof Float64Array) column[i] = Number(value);
              else column[i] = String(value);
              present.get(key)![i] = 1;
            }
            continue;
          }
          sparse[key] = value as string | number;
        }
        packets[i].fields = sparse;
      }
      held = mode === 'split' ? [packets, columns, present] : [packets];
    }
    const after = heap();
    if (held === undefined) throw new Error('nothing held');
    held = undefined;
    void held;
    return after - before;
  };

  const runs = { whole: [] as number[], sparse: [] as number[], split: [] as number[] };
  for (let i = 0; i < 3; i++) {
    runs.whole.push(await measure('whole'));
    runs.sparse.push(await measure('sparse-only'));
    runs.split.push(await measure('split'));
  }
  const whole = median(runs.whole);
  const sparse = median(runs.sparse);
  const split = median(runs.split);

  const per = (v: number) => (v / frames).toFixed(0).padStart(6) + ' B/frame   '
    + ((v / frames) * 1e6 / 1e6).toFixed(0).padStart(5) + ' MB at 1M';

  console.log('the same capture, three ways');
  console.log('  whole record, bag as today   ' + per(whole));
  console.log('  dense keys simply dropped    ' + per(sparse)
    + '   <- the floor the split cannot beat');
  console.log('  dense keys as columns        ' + per(split));
  console.log();
  console.log('  the split would save         ' + per(whole - split));
  console.log('  the columns themselves cost  ' + per(split - sparse));
  console.log();
  console.log('For comparison, ADR 0013 measured a column for EVERY key at 976 B a');
  console.log('frame against 294 for the object - three times worse - because a key');
  console.log('a few frames carry still takes a slot in all of them.');
}

main();
