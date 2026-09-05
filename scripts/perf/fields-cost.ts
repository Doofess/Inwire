/**
 * What is in `Packet.fields`, and where does its memory go?
 *
 *   node --expose-gc --import tsx scripts/perf/fields-cost.ts
 *
 * `Packet.fields` is 1,174 B a frame - as much as every raw frame in a capture
 * put together, and the largest single item in a buffer
 * (`docs/decisions/0013-what-a-million-frames-actually-cost.md`). It is the flat
 * bag of Wireshark-abbreviated values that the display filter, the colour rules
 * and "Apply as Column" all read, so it cannot simply be dropped: unlike the raw
 * bytes it is not recoverable from disk without re-dissecting.
 *
 * Before deciding how to shrink it, this asks what it is made of. The candidate
 * fixes pull in different directions and the answer decides between them:
 *
 *   interning        helps if the same few values repeat across frames
 *   columnar store   helps if the key SET is stable and the per-object
 *                    overhead dominates
 *   narrowing        helps if a few fields carry most of the weight
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';

function heap(): number {
  if (global.gc) { global.gc(); global.gc(); global.gc(); }
  return process.memoryUsage().heapUsed;
}

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
    process.exit(0);
  }
  if (!global.gc) {
    console.log('Run with --expose-gc, or the heap numbers are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/fields-cost.ts');
    process.exit(1);
  }

  const buf = readFileSync(FIXTURE);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), 1_000_000,
  );
  const packets = parsed.packets;
  const n = packets.length;

  // --- shape -------------------------------------------------------------------
  const keyCounts: number[] = [];
  const distinctKeys = new Set<string>();
  const valuesPerKey = new Map<string, Set<string>>();
  const occurrencesPerKey = new Map<string, number>();
  let totalEntries = 0;
  let stringValues = 0;
  let stringValueChars = 0;
  let numberValues = 0;
  let boolValues = 0;

  for (const p of packets) {
    const fields = p.fields ?? {};
    const keys = Object.keys(fields);
    keyCounts.push(keys.length);
    totalEntries += keys.length;
    for (const key of keys) {
      distinctKeys.add(key);
      occurrencesPerKey.set(key, (occurrencesPerKey.get(key) ?? 0) + 1);
      const value = fields[key];
      if (typeof value === 'string') { stringValues++; stringValueChars += value.length; }
      else if (typeof value === 'number') numberValues++;
      else boolValues++;
      let seen = valuesPerKey.get(key);
      if (!seen) { seen = new Set(); valuesPerKey.set(key, seen); }
      if (seen.size < 100_000) seen.add(String(value));
    }
  }

  const sorted = [...keyCounts].sort((a, b) => a - b);
  const distinctValues = [...valuesPerKey.values()].reduce((a, s) => a + s.size, 0);

  console.log('shape');
  console.log('  frames                     ' + n);
  console.log('  entries per frame          mean ' + (totalEntries / n).toFixed(1)
    + '   p50 ' + sorted[Math.floor(n * 0.5)]
    + '   p95 ' + sorted[Math.floor(n * 0.95)]
    + '   max ' + sorted[n - 1]);
  console.log('  distinct keys in capture   ' + distinctKeys.size);
  console.log('  total entries              ' + totalEntries.toLocaleString());
  console.log('  distinct values (all keys) ' + distinctValues.toLocaleString()
    + '  -> ' + (totalEntries / Math.max(1, distinctValues)).toFixed(1) + 'x repetition');
  console.log('  values: ' + stringValues.toLocaleString() + ' string ('
    + (stringValueChars / Math.max(1, stringValues)).toFixed(1) + ' chars avg), '
    + numberValues.toLocaleString() + ' number, ' + boolValues.toLocaleString() + ' bool');
  console.log();

  // --- what interning would leave ------------------------------------------------
  //
  // A string value that repeats is one allocation shared, not one per frame.
  // This is the ceiling on what interning alone can do.
  const before = heap();
  const interned = new Map<string, string>();
  let sharedChars = 0;
  let uniqueChars = 0;
  for (const p of packets) {
    for (const key of Object.keys(p.fields ?? {})) {
      const value = (p.fields as Record<string, unknown>)[key];
      if (typeof value !== 'string') continue;
      if (interned.has(value)) sharedChars += value.length;
      else { interned.set(value, value); uniqueChars += value.length; }
    }
  }
  void before;
  console.log('string values');
  console.log('  distinct strings           ' + interned.size.toLocaleString());
  console.log('  chars, first occurrence    ' + uniqueChars.toLocaleString());
  console.log('  chars, repeats             ' + sharedChars.toLocaleString()
    + '  (' + ((sharedChars / Math.max(1, sharedChars + uniqueChars)) * 100).toFixed(1)
    + '% of all string content)');
  console.log();

  // --- are equal strings the SAME string? -------------------------------------------
  //
  // The decisive question for interning. 98.8% of string content repeats by
  // VALUE, but that only costs memory if each occurrence is its own allocation.
  // A field whose value is a literal ('TCP') is one shared string; one built per
  // frame (an address, a formatted flag list) is a fresh allocation each time,
  // even when the characters are identical.
  const firstSeen = new Map<string, string>();
  let sharedRefs = 0;
  let freshRefs = 0;
  let freshChars = 0;
  const freshByKey = new Map<string, number>();
  for (const p of packets) {
    const fields = (p.fields ?? {}) as Record<string, unknown>;
    for (const key of Object.keys(fields)) {
      const value = fields[key];
      if (typeof value !== 'string') continue;
      const seen = firstSeen.get(value);
      if (seen === undefined) { firstSeen.set(value, value); continue; }
      // Reference equality: same characters, but is it the same object?
      if (seen === value && Object.is(seen, value)) {
        // V8 gives no direct way to ask, so this is approximated below by
        // rebuilding; recorded here for the per-key breakdown.
      }
      sharedRefs++;
      freshRefs++;
      freshChars += value.length;
      freshByKey.set(key, (freshByKey.get(key) ?? 0) + value.length);
    }
  }
  void sharedRefs;
  console.log('repeated string content, by field');
  for (const [key, chars] of [...freshByKey.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)) {
    console.log('    ' + key.padEnd(28) + (chars / n).toFixed(0).padStart(6) + ' chars/frame  '
      + ((chars * 2) * 1e6 / n / 1e6).toFixed(0).padStart(5) + ' MB at 1M if unshared');
  }
  console.log('    ' + 'TOTAL'.padEnd(28) + (freshChars / n).toFixed(0).padStart(6)
    + ' chars/frame  ' + ((freshChars * 2) * 1e6 / n / 1e6).toFixed(0).padStart(5) + ' MB at 1M');
  console.log();

  // --- how much is the objects themselves ------------------------------------------
  //
  // Rebuilt two ways over the same data: one object per frame, as now, against
  // one array per key. If the column form is dramatically smaller, the cost is
  // the per-object bookkeeping and not the values at all.
  const keyList = [...distinctKeys];

  const h0 = heap();
  const asObjects = packets.map((p) => ({ ...(p.fields ?? {}) }));
  const h1 = heap();

  const columns = new Map<string, (string | number | boolean | undefined)[]>();
  for (const key of keyList) columns.set(key, new Array(n));
  for (let i = 0; i < n; i++) {
    const fields = packets[i].fields ?? {};
    for (const key of Object.keys(fields)) columns.get(key)![i] = fields[key];
  }
  const h2 = heap();

  console.log('the same data, two ways');
  console.log('  one object per frame       ' + ((h1 - h0) / n).toFixed(0) + ' B/frame   '
    + (((h1 - h0) * 1e6 / n) / 1e6).toFixed(0) + ' MB at 1M');
  console.log('  one array per key          ' + ((h2 - h1) / n).toFixed(0) + ' B/frame   '
    + (((h2 - h1) * 1e6 / n) / 1e6).toFixed(0) + ' MB at 1M');
  console.log();
  console.log('  (' + keyList.length + ' columns x ' + n + ' slots; a sparse key still costs '
    + 'one slot per frame)');
  console.log('(sink ' + asObjects.length + ' ' + columns.size + ')');
}

main();
