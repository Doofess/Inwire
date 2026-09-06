/**
 * What is a resident frame record made of, component by component?
 *
 *   node --expose-gc --import tsx scripts/perf/record-cost.ts
 *
 * ADR 0013 measured the summary at 2,342 B a frame and broke it down once. Two
 * things have changed it since - address and field strings are pooled
 * (`services/addressFormat.ts`), and `colorSlot` was added - and the plan's
 * next step is to compact the record component by component, in the order
 * `frameProtocols` -> `analysisFlags` -> `expert` -> `info`, with `fields`
 * last. That order is only worth following if it is the order of the costs.
 *
 * **Method: build the buffer twice.** Once whole, once with one component set
 * to `undefined`, and compare what the heap still holds. The difference is
 * what that component uniquely points at.
 *
 * `undefined` rather than `delete`, deliberately. Deleting changes the object's
 * shape and measures the property SLOT along with its contents, which is not
 * the question: compaction replaces a component with a smaller one in the same
 * slot, so what matters is what the component points at, not that it is there.
 *
 * It under-counts anything shared. A string in the address pool, or one field
 * value repeated across ten thousand frames, stays alive when any one frame
 * lets go of it - so it is charged to no component here. That is the honest
 * answer to "what would compacting this free", which is the question being
 * asked, and it is why the total below is smaller than the sum of the parts
 * would be if each were counted in isolation.
 *
 * A measurement, not an assertion: `check.ts` skips it by name.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { clearAddressPool } from '../../src/services/addressFormat';
import type { Packet } from '../../src/types/packet';

/**
 * Both fixtures, because what this can measure is bounded by how many DISTINCT
 * frames exist - see `build` below - and two captures are 27,640 rather than
 * 12,858.
 */
const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/bulk_capture_1788426090876.pcap',
];

/**
 * The components the compaction plan names, plus the ones it does not - a
 * component nobody proposed to shrink is worth measuring precisely because it
 * might turn out to be the large one.
 */
const COMPONENTS: { name: string; strip: (p: Packet) => void; plan?: string }[] = [
  { name: 'fields (sparse bag)',
    strip: (p) => { (p as { fields?: unknown }).fields = undefined; } },
  // The other half of what `fields` used to be. Stripping the bag does not
  // free these - the block is reached through `cols`, not through the bag - so
  // without a row of its own the columns would be counted in the total and
  // attributed to nothing.
  { name: 'fields (dense columns)',
    strip: (p) => {
      (p as { cols?: unknown }).cols = undefined;
      (p as { row?: unknown }).row = undefined;
    } },
  { name: 'info', plan: 'arena',
    strip: (p) => { (p as { info: unknown }).info = undefined; } },
  { name: 'frameProtocols', plan: 'bitmask',
    strip: (p) => { (p as { frameProtocols?: unknown }).frameProtocols = undefined; } },
  { name: 'analysisFlags', plan: 'bitmask',
    strip: (p) => { (p as { analysisFlags?: unknown }).analysisFlags = undefined; } },
  { name: 'expert', plan: 'pooled',
    strip: (p) => { (p as { expert?: unknown }).expert = undefined; } },
  { name: 'source + destination',
    strip: (p) => {
      (p as { source: unknown }).source = undefined;
      (p as { destination: unknown }).destination = undefined;
    } },
  { name: 'protocolLabel',
    strip: (p) => { (p as { protocolLabel?: unknown }).protocolLabel = undefined; } },
  { name: 'streamPayload',
    strip: (p) => { (p as { streamPayload?: unknown }).streamPayload = undefined; } },
  { name: 'layers (tree)',
    strip: (p) => { (p as { layers: unknown }).layers = undefined; } },
];

/** Shared by every record, so it is charged to none of them. */
const EMPTY_BYTES = new Uint8Array(0);

function heap(): number {
  // A full dissection leaves a lot of transient garbage - the trackers' working
  // state, the trees built and dropped, the ordering window - and one or two
  // collections do not reliably clear it. Under-collecting shows up directly as
  // the noise floor this script prints, and the floor decides which rows below
  // are readable at all.
  if (global.gc) for (let i = 0; i < 6; i++) global.gc();
  const usage = process.memoryUsage();
  // `arrayBuffers` as well as `heapUsed`, because a typed array's bytes live
  // OUTSIDE the JS heap. Since the dense fields moved into typed columns
  // (`dissect/fieldBlock.ts`) most of what this measures would otherwise be
  // invisible - which is exactly how ADR 0017 came to report 33 columns at
  // 47 B a frame when they were 243: it was counting the one string array on
  // the heap and none of the typed ones beside it.
  return usage.heapUsed + usage.arrayBuffers;
}

/** How many times each configuration is measured; the median is reported. */
const PASSES = 3;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

async function main() {
  const missing = FIXTURES.filter(f => !existsSync(f));
  if (missing.length > 0) {
    console.log('SKIP  fixture missing: ' + missing[0] + ' (see test/fixtures/README.md)');
    process.exit(0);
  }
  if (!global.gc) {
    console.log('Run with --expose-gc, or these are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/record-cost.ts');
    process.exit(1);
  }

  /**
   * One measurement: dissect both fixtures for real, strip a component from
   * every frame, and report what the heap still holds.
   *
   * **Real dissection, and no copying.** Two earlier versions of this measured
   * copies instead, and both were wrong in ways that looked like results:
   *
   *   - Repeating one fixture to 200,000 frames shares string objects across
   *     the copies, so `info`, `source` and `protocolLabel` all read **0 B a
   *     frame**. Not a small number - no number.
   *   - Rebuilding each record from JSON fixes the strings and breaks two other
   *     things: it undoes the address pooling the real dissector does
   *     (`services/addressFormat.ts`), so pooled strings are charged as though
   *     they were per-frame, and it builds `fields` with a known shape where
   *     the dissector assigns keys one at a time. It reported `fields` at 451 B
   *     against a real 1,174 measured in ADR 0013.
   *
   * So nothing is copied. The frames are the dissector's own, allocated the way
   * the app allocates them, and a component is stripped after the fact. The
   * pool is cleared between passes or the second pass inherits the first's
   * pooled strings and undercounts everything reached through them.
   *
   * The cost is a full dissection per component. That is the price of measuring
   * the thing rather than a model of it.
   */
  const measure = async (strip?: (p: Packet) => void): Promise<{ bytes: number; frames: number }> => {
    clearAddressPool();
    const before = heap();
    let held: Packet[] | undefined = [];
    for (const path of FIXTURES) {
      const parsed = await PcapService.parseCaptureFile(
        new File([new Uint8Array(readFileSync(path))], 'fixture.pcap'), 1_000_000,
      );
      for (const packet of parsed.packets) {
        // External to `heapUsed`, and already evicted for any frame the store
        // can read back - so not the question and not worth holding.
        packet.rawBytes = EMPTY_BYTES;
        strip?.(packet);
        held.push(packet);
      }
    }
    const after = heap();
    const frames = held.length;
    if (frames === 0) throw new Error('fixtures parsed to zero frames');
    held = undefined;
    void held;
    return { bytes: after - before, frames };
  };

  /**
   * The median of `PASSES` runs of one configuration.
   *
   * A median rather than a mean: one pass whose collection did not finish is an
   * outlier of several megabytes, and it would drag a mean far enough to
   * reorder the table.
   */
  const measureTimes = async (strip?: (p: Packet) => void): Promise<{ bytes: number; frames: number }> => {
    const runs: number[] = [];
    let frames = 0;
    for (let i = 0; i < PASSES; i++) {
      const run = await measure(strip);
      runs.push(run.bytes);
      frames = run.frames;
    }
    return { bytes: median(runs), frames };
  };

  // Two identical configurations, measured separately. Whatever they differ by
  // is what this method cannot resolve, and any row smaller than it is noise
  // wearing a number - so it is printed, and the rows below it are marked.
  const passA = await measureTimes();
  const passB = await measureTimes();
  const FRAMES = passA.frames;
  const floor = Math.abs(passA.bytes - passB.bytes);
  const whole = Math.max(passA.bytes, passB.bytes);

  console.log(FRAMES.toLocaleString() + ' dissected records, bytes released without each component');
  console.log('(raw frame bytes are excluded - external to the heap, and already evicted)');
  console.log();
  console.log('  whole record'.padEnd(28)
    + (whole / FRAMES).toFixed(0).padStart(6) + ' B/frame   '
    + ((whole / FRAMES) * 1e6 / 1e6).toFixed(0).padStart(5) + ' MB at 1M');
  console.log();

  const rows: { name: string; bytes: number; plan?: string }[] = [];
  for (const component of COMPONENTS) {
    const without = await measureTimes(component.strip);
    rows.push({
      name: component.name,
      bytes: Math.max(0, whole - without.bytes),
      plan: component.plan,
    });
  }

  for (const row of rows.sort((a, b) => b.bytes - a.bytes)) {
    const readable = row.bytes > floor;
    console.log('  ' + row.name.padEnd(26)
      + (row.bytes / FRAMES).toFixed(0).padStart(6) + ' B/frame   '
      + ((row.bytes / FRAMES) * 1e6 / 1e6).toFixed(0).padStart(5) + ' MB at 1M'
      + (readable ? '' : '   (under the floor - not a reading)')
      + (readable && row.plan ? '   plan: ' + row.plan : ''));
  }
  console.log();
  console.log('  ' + 'noise floor'.padEnd(26)
    + (floor / FRAMES).toFixed(0).padStart(6) + ' B/frame'
    + '   (two identical configurations, ' + (floor / 1024).toFixed(0) + ' KB apart)');
  console.log();
  console.log('  A row is what stripping that component FREED, so the rows do not sum');
  console.log('  to the whole: two components can each hold the last reference to the');
  console.log('  same shared string, and stripping either alone frees none of it.');
  console.log();
  console.log('A component costing little here cannot be made to cost less by');
  console.log('encoding it, however untidy it looks - and one costing a lot may still');
  console.log('resist, since what it holds may be shared rather than its own.');
}

main();
