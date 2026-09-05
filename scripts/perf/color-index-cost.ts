/**
 * What does colouring a buffer cost, and what would an index change?
 *
 *   node --expose-gc --import tsx scripts/perf/color-index-cost.ts
 *
 * The plan behind this asked for a **colour index**: the matched rule computed
 * once at dissection and kept as one byte per frame, so the packet list and the
 * minimap never walk the rule chain and `fields`, `frameProtocols`,
 * `analysisFlags` and `rawBytes` can eventually stop being resident.
 *
 * Two claims have to hold before that is worth building, and neither had ever
 * been measured:
 *
 *   1. **A rule edit is expensive.** `ColorRulesEngine` memoises in a WeakMap
 *      keyed on the packet, so a repaint is a cache lookup - but a rule edit
 *      builds a NEW engine, and a new engine has a cold cache. The minimap
 *      paints every frame in the buffer on every repaint, so the first repaint
 *      after an edit walks the chain once per frame, synchronously, in a layout
 *      effect. That is the number that decides whether the pass needs to move
 *      off the main thread.
 *   2. **The memo is worth replacing.** A WeakMap entry per frame against a
 *      number on the packet: measured at 41 B and 15 B respectively, and the
 *      warm pass over a million frames at 103.8 ms and 22.7 ms.
 *
 * Two premises in this same plan have already failed measurement - the tree was
 * 3.3% of dissection rather than the bulk of it, and raw bytes were the smaller
 * half of a buffer rather than the larger. So this measures before anything is
 * built on it.
 *
 * A measurement, not an assertion: `check.ts` skips it by name.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { ColorRulesEngine, DEFAULT_COLOR_RULES } from '../../src/services/colorRules';
import { getPacketThemeForApp } from '../../src/services/packetThemes';
import type { Packet } from '../../src/types/packet';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';

/** Buffer sizes to report at, including the cap the app offers today. */
const SIZES = [10_000, 50_000, 100_000, 1_000_000];

function heap(): number {
  if (global.gc) { global.gc(); global.gc(); global.gc(); }
  return process.memoryUsage().heapUsed;
}

function ms(value: number): string {
  return value.toFixed(1).padStart(8) + ' ms';
}

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
    process.exit(0);
  }
  if (!global.gc) {
    console.log('Run with --expose-gc, or the memory numbers are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/color-index-cost.ts');
    process.exit(1);
  }

  const buf = readFileSync(FIXTURE);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), 1_000_000,
  );
  const source = parsed.packets;
  const theme = getPacketThemeForApp('dark');
  console.log('fixture: ' + source.length.toLocaleString() + ' frames');
  console.log('chain:   ' + DEFAULT_COLOR_RULES.length + ' rules, '
    + DEFAULT_COLOR_RULES.filter(r => r.enabled).length + ' enabled');
  console.log();

  // --- What one cold pass over the buffer costs --------------------------------
  //
  // This is a rule edit, exactly: `App.tsx` builds `new ColorRulesEngine(rules)`
  // whenever the chain changes, and the minimap's layout effect then paints
  // every frame through it. A fresh engine's WeakMap is empty, so every frame
  // walks the chain.
  console.log('one full pass over the buffer, cold (what a rule edit triggers)');
  const perFrame: number[] = [];
  for (const size of SIZES) {
    // The fixture is smaller than the larger sizes, so frames repeat. They must
    // be distinct OBJECTS or the WeakMap would answer for the copies and the
    // cold pass would measure a warm one.
    const packets: Packet[] = [];
    for (let i = 0; i < size; i++) packets.push({ ...source[i % source.length] });

    const engine = new ColorRulesEngine(DEFAULT_COLOR_RULES);
    const t0 = performance.now();
    let sink = 0;
    for (const packet of packets) {
      const style = engine.getPacketStyle(packet, theme);
      if (style.background !== undefined) sink++;
    }
    const cold = performance.now() - t0;

    const t1 = performance.now();
    for (const packet of packets) {
      const style = engine.getPacketStyle(packet, theme);
      if (style.background !== undefined) sink++;
    }
    const warm = performance.now() - t1;

    perFrame.push((cold * 1000) / size);
    console.log('  ' + String(size).padStart(9) + ' frames   cold ' + ms(cold)
      + '   warm ' + ms(warm)
      + '   ' + ((cold * 1000) / size).toFixed(2) + ' us/frame'
      + '   (sink ' + sink + ')');
  }
  console.log();
  console.log('  The minimap repaints on a 500 ms cadence and paints EVERY frame in');
  console.log('  the buffer. A cold pass longer than a frame budget is a visible stall,');
  console.log('  and it happens on the main thread inside a layout effect.');
  console.log();

  // --- What holding the answer costs ----------------------------------------------
  //
  // This measured 41 B a frame when the answer lived in a `WeakMap<Packet,
  // ColorRule>`, and 15 B now that it is a packed number on the packet itself.
  // The remaining 15 is the property slot plus the backing store the object
  // grows to hold it - added after construction, since the engine decides it
  // long after the dissector built the packet.
  //
  // The `Uint8Array` row below is the floor a side array indexed by buffer
  // position would reach, and is NOT what is implemented: that would need the
  // engine to own the buffer's ordering and to rebase every time it trims,
  // which is a coupling worth more than the 14 B it would save.
  console.log('holding the answer: on the packet, against the theoretical floor');
  {
    const size = 100_000;
    const packets: Packet[] = [];
    for (let i = 0; i < size; i++) packets.push({ ...source[i % source.length] });

    const before = heap();
    const engine = new ColorRulesEngine(DEFAULT_COLOR_RULES);
    for (const packet of packets) engine.getPacketStyle(packet, theme);
    const after = heap();
    const memo = after - before;

    console.log('  packed slot, ' + size.toLocaleString() + ' frames    '
      + (memo / 1024 / 1024).toFixed(1) + ' MB   '
      + (memo / size).toFixed(0) + ' B/frame   '
      + ((memo / size) * 1e6 / 1e6).toFixed(0) + ' MB at 1M');

    // A Uint8Array of rule indexes: the whole structure, not per entry.
    const index = new Uint8Array(size);
    console.log('  Uint8Array side array (not built)  '
      + (index.byteLength / 1024 / 1024).toFixed(1) + ' MB   '
      + (index.byteLength / size).toFixed(0) + ' B/frame   '
      + '     1 MB at 1M');
    console.log('  (sink ' + engine.getMatchedRuleName(packets[0]) + ')');
  }
  console.log();

  // --- Is a byte enough? ---------------------------------------------------------
  //
  // The index has to name a rule, and a rule's identity is its `id` - not its
  // position, which reordering and disabling both change. So the byte is an
  // index into a side table of ids, and it only works while there are fewer
  // than 255 enabled rules plus a "no rule" value.
  console.log('what the byte has to encode');
  console.log('  enabled rules in the shipped chain  '
    + DEFAULT_COLOR_RULES.filter(r => r.enabled).length);
  console.log('  values a Uint8Array can hold        255 rules + 1 for "no match"');
  console.log('  the chain is user-editable, so this is a cap on the chain, not a');
  console.log('  property of it - and a chain past it must fall back rather than wrap.');
}

main();
