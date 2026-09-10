/**
 * What does persisting a frame's SUMMARY actually cost?
 *
 *   npx tsx scripts/perf/summary-codec.ts [--fixture inwire|bulk]
 *
 * Step 0 of the disk-backed buffer, and it runs before a line of the codec is
 * written, because its answer decides the format rather than describing one.
 *
 * The problem it exists to size: `toStoredFrame` deliberately persists **only**
 * a frame's raw bytes - "all of them come back out of `raw` on restore, and
 * keeping them is what made the 'store the whole packet' option 4.6x larger."
 * That is the right trade when the disk copy exists to survive a refresh. It is
 * the wrong one when the disk is where an evicted row is *read back from*,
 * because re-dissecting a mid-stream frame does not merely cost time - it can
 * produce a **different** Info line, since a frame's row is a function of the
 * frames before it and not of its own bytes.
 *
 * So the summary has to be stored. This measures what that costs, three ways,
 * because the three answers lead to three different formats:
 *
 *  1. **Raw** - every field written out naively. The ceiling.
 *  2. **Interned** - a per-chunk string table, which is what a chunk of 4,096
 *     frames makes cheap: addresses, protocol labels and expert messages repeat
 *     enormously inside one, and an id costs 2 bytes where the string costs 15.
 *  3. **Deflated** - the interned form compressed per chunk, which is the form
 *     that actually lands on disk.
 *
 * And it splits every one of those into a **fixed-width prefix** and a
 * **variable tail**, because that split is the single format decision that
 * cannot be retrofitted. A whole-capture filter decodes one row per frame; at
 * ~2.5 us a full row that is 11.8 s of CPU on a 5 GB capture and 118 s on a
 * 50 GB one, against ~40 ns to read a fixed-width prefix through a `DataView`.
 * Whether the prefix is big enough to answer the common filters, and small
 * enough to be worth separating, is a measurement and not a preference.
 *
 * A measurement, not a test: there is no right answer to hold it to, so
 * `scripts/check.ts` skips it by name alongside `clone-cost.ts` and
 * `wire-size.ts`. Requires the fixtures (test/fixtures/README.md).
 */
import { existsSync, readFileSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { PcapService } from '../../src/services/pcapParser';
import { fieldEntries } from '../../src/services/dissect/fieldAccess';
import type { Packet } from '../../src/types/packet';

/** Pinned to `BLOCK_ROWS` in dissect/fieldSplit.ts - see the plan. */
const CHUNK_FRAMES = 4096;

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

/**
 * The fixed part of a row, as the plan proposes it.
 *
 * Everything a display filter asks about most of the time, at a known offset so
 * it can be read without decoding anything: the timestamp, both addresses, both
 * ports, the protocol, the length, the status, and the layer set as a bitmap.
 * 16 bytes per address holds IPv6; IPv4 sits in the low four.
 */
const PREFIX_BYTES =
  8 +      // tsNanos u64 - NOT tsUs f64, which cannot represent nanoseconds
  16 + 16 + // source, destination
  2 + 2 +   // sourcePort, destPort
  2 +       // protocol id
  4 +       // length
  1 +       // status
  1 +       // direction signal bits
  8 +       // frameProtocols bitmap
  4;        // streamId

const utf8 = new TextEncoder();

/** A growable byte sink, so the tail is built rather than counted. */
class Sink {
  private buf = new Uint8Array(1 << 16);
  private at = 0;
  private grow(n: number) {
    if (this.at + n <= this.buf.length) return;
    const next = new Uint8Array(Math.max(this.buf.length * 2, this.at + n));
    next.set(this.buf.subarray(0, this.at));
    this.buf = next;
  }
  u8(v: number) { this.grow(1); this.buf[this.at++] = v & 0xff; }
  u16(v: number) { this.grow(2); this.buf[this.at++] = v & 0xff; this.buf[this.at++] = (v >> 8) & 0xff; }
  f64(v: number) {
    this.grow(8);
    new DataView(this.buf.buffer, this.at, 8).setFloat64(0, v, true);
    this.at += 8;
  }
  raw(b: Uint8Array) { this.grow(b.length); this.buf.set(b, this.at); this.at += b.length; }
  get length() { return this.at; }
  bytes(): Uint8Array { return this.buf.subarray(0, this.at); }
}

/**
 * An address as the prefix would hold it: 4 bytes for IPv4, 16 for IPv6, 6 for
 * a MAC, zero-padded to 16.
 *
 * Written for real rather than zero-filled, because the whole question here is
 * how well a chunk COMPRESSES, and a run of zeros compresses to nothing. An
 * earlier version of this script padded the tail with zeros and reported
 * 9.6 B/frame, which measured deflate's handling of zeros and nothing else.
 */
function addressBytes(text: string, into: Uint8Array, at: number): void {
  if (text.includes('.') && !text.includes(':')) {
    const parts = text.split('.');
    for (let i = 0; i < 4 && i < parts.length; i++) into[at + i] = parseInt(parts[i], 10) & 0xff;
    return;
  }
  if (text.includes(':')) {
    const groups = text.split(':');
    // Good enough for a size measurement: hex groups laid down in order.
    let out = at;
    for (const g of groups) {
      if (g === '' || out >= at + 16) continue;
      const v = parseInt(g, 16);
      if (Number.isNaN(v)) continue;
      if (g.length <= 2) { into[out++] = v & 0xff; }
      else { into[out++] = (v >> 8) & 0xff; into[out++] = v & 0xff; }
    }
    return;
  }
  // A resolved name or something else textual - hash it so repeats still repeat.
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); }
  into[at] = h & 0xff; into[at + 1] = (h >> 8) & 0xff;
  into[at + 2] = (h >> 16) & 0xff; into[at + 3] = (h >>> 24) & 0xff;
}

/** Writes one frame's real prefix bytes. */
function writePrefix(p: Packet, into: Uint8Array, at: number, protoId: number): void {
  const view = new DataView(into.buffer, into.byteOffset + at, PREFIX_BYTES);
  view.setFloat64(0, p.tsUs, true);
  addressBytes(p.source, into, at + 8);
  addressBytes(p.destination, into, at + 24);
  view.setUint16(40, p.sourcePort ?? 0, true);
  view.setUint16(42, p.destPort ?? 0, true);
  view.setUint16(44, protoId, true);
  view.setUint32(46, p.length, true);
  view.setUint8(50, p.status.charCodeAt(0));
  view.setUint8(51, (p.direction ?? 0) & 0xff);
  view.setFloat64(52, 0, true);                    // frameProtocols bitmap
  view.setUint32(60, p.streamId ?? 0, true);
}

/** Writes one frame's real interned tail, returning nothing but growing `sink`. */
function writeTail(p: Packet, sink: Sink, id: (s: string) => number): void {
  sink.u16(id(p.source));
  sink.u16(id(p.destination));
  sink.u16(id(p.protocolLabel ?? ''));
  sink.u16(id(p.info));

  for (const list of [p.frameProtocols ?? [], p.analysisFlags ?? []]) {
    sink.u8(list.length);
    for (const item of list) sink.u16(id(item));
  }

  const expert = p.expert ?? [];
  sink.u8(expert.length);
  for (const f of expert) { sink.u8(0); sink.u16(id(f.message ?? '')); }

  const resolved = p.resolved ?? [];
  sink.u8(resolved.length);
  for (const r of resolved) {
    sink.u16(id(r.name));
    sink.u8(r.addresses.length);
    for (const a of r.addresses) sink.u16(id(a));
  }

  const entries = fieldEntries(p);
  sink.u16(entries.length);
  for (const [key, value] of entries) {
    sink.u16(id(key));
    if (typeof value === 'number') { sink.u8(0); sink.f64(value); }
    else { sink.u8(1); sink.u16(id(value)); }
  }
}

async function main(): Promise<void> {
  const name = arg('fixture', 'bulk');
  const path = FIXTURES[name];
  if (!path) {
    console.log(`unknown fixture ${name}; expected one of ${Object.keys(FIXTURES).join(', ')}`);
    process.exit(1);
  }
  if (!existsSync(path)) {
    console.log(`SKIP  ${path} not present (test/fixtures/README.md)`);
    process.exit(0);
  }

  const buf = readFileSync(path);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), Number.POSITIVE_INFINITY,
  );
  const packets = parsed.packets;
  if (packets.length === 0) {
    console.log('SKIP  fixture parsed to zero frames');
    process.exit(0);
  }

  console.log(`fixture ${name}: ${packets.length.toLocaleString()} frames\n`);

  let prefixTotal = 0, tailTotal = 0, tableTotal = 0, deflated = 0, frameBytes = 0;
  let prefixDeflated = 0, tailDeflated = 0;
  let rawTailTotal = 0;
  const protoIds = new Map<string, number>();
  const protoId = (s: string) => {
    let v = protoIds.get(s);
    if (v === undefined) { v = protoIds.size; protoIds.set(s, v); }
    return v;
  };
  const encodeStart = performance.now();

  for (let start = 0; start < packets.length; start += CHUNK_FRAMES) {
    const chunk = packets.slice(start, start + CHUNK_FRAMES);

    // One string table per chunk - the whole reason a chunk exists. Addresses,
    // protocol labels and expert sentences repeat enormously inside 4,096
    // frames, so an id costs 2 bytes where the string costs 15 to 100.
    const table: string[] = [];
    const seen = new Map<string, number>();
    const id = (str: string): number => {
      let v = seen.get(str);
      if (v === undefined) { v = table.length; seen.set(str, v); table.push(str); }
      return v;
    };

    const prefixes = new Uint8Array(chunk.length * PREFIX_BYTES);
    const tail = new Sink();
    for (let i = 0; i < chunk.length; i++) {
      const p = chunk[i];
      writePrefix(p, prefixes, i * PREFIX_BYTES, protoId(p.protocolLabel ?? p.protocol));
      writeTail(p, tail, id);
      frameBytes += p.rawBytes.length;
      // What the same data would cost written out in full, for the comparison.
      rawTailTotal += utf8.encode(
        p.source + p.destination + (p.protocolLabel ?? '') + p.info,
      ).length;
    }

    const tableBlob = utf8.encode(table.join(' '));
    prefixTotal += prefixes.length;
    tailTotal += tail.length;
    tableTotal += tableBlob.length + 4;

    // The chunk exactly as it would land: table, prefixes, tail, one deflate.
    const unit = new Uint8Array(tableBlob.length + prefixes.length + tail.length);
    unit.set(tableBlob, 0);
    unit.set(prefixes, tableBlob.length);
    unit.set(tail.bytes(), tableBlob.length + prefixes.length);
    deflated += deflateRawSync(unit, { level: 6 }).length;
    // The tension this script exists to settle: a filter wants to scan the
    // PREFIXES at DataView speed, and it cannot if they are inside a blob it
    // must inflate first. So measure the split - prefixes on their own, tails
    // on their own - against the everything-in-one-unit figure above.
    prefixDeflated += deflateRawSync(prefixes, { level: 6 }).length;
    const tailUnit = new Uint8Array(tableBlob.length + tail.length);
    tailUnit.set(tableBlob, 0);
    tailUnit.set(tail.bytes(), tableBlob.length);
    tailDeflated += deflateRawSync(tailUnit, { level: 6 }).length;
  }

  const encodeUs = (performance.now() - encodeStart) * 1000 / packets.length;
  const n = packets.length;
  const per = (v: number) => (v / n).toFixed(1).padStart(8);
  const pct = (v: number) => `${(v / frameBytes * 100).toFixed(1)}%`;

  console.log(`${''.padEnd(24)}${'B/frame'.padStart(8)}   vs the frame's own bytes`);
  console.log(`  raw frame bytes       ${per(frameBytes)}   (what we are adding to)`);
  console.log(`  fixed prefix          ${per(prefixTotal)}   ${pct(prefixTotal)}`);
  console.log(`  tail, interned        ${per(tailTotal)}   ${pct(tailTotal)}`);
  console.log(`  string tables         ${per(tableTotal)}   ${pct(tableTotal)}`);
  console.log(`  ${'-'.repeat(52)}`);
  const stored = prefixTotal + tailTotal + tableTotal;
  console.log(`  stored, uncompressed  ${per(stored)}   ${pct(stored)} on top of the frame`);
  console.log(`  stored, deflated      ${per(deflated)}   ${pct(deflated)}  <- lands on disk`);
  console.log(`  (the four main strings alone, written out: ${(rawTailTotal / n).toFixed(0)} B/frame)`);
  console.log(`
  Split into two streams, so a filter can scan prefixes without inflating tails:`);
  console.log(`    prefixes, deflated  ${per(prefixDeflated)}   ${pct(prefixDeflated)}`);
  console.log(`    prefixes, as-is     ${per(prefixTotal)}   ${pct(prefixTotal)}  <- scannable by DataView`);
  console.log(`    tails, deflated     ${per(tailDeflated)}   ${pct(tailDeflated)}`);
  console.log(`    split total (raw prefix + deflated tail) ${((prefixTotal + tailDeflated) / n).toFixed(1)} B/frame`
    + `  vs ${(deflated / n).toFixed(1)} all-in-one`);
  console.log(`
  encode cost           ${encodeUs.toFixed(2)} us/frame`
    + `  -> ${(1e6 / encodeUs).toLocaleString(undefined, { maximumFractionDigits: 0 })} f/s ceiling`);

  const totalPer = frameBytes / n + deflated / n;
  console.log(`
  per frame on disk     ${totalPer.toFixed(0)} B`);
  for (const gb of [5, 50]) {
    const frames = Math.floor((gb * 1024 ** 3) / totalPer);
    console.log(`    ${String(gb).padStart(2)} GB holds ${frames.toLocaleString().padStart(12)} frames`
      + `   summary stream ${(frames * (deflated / n) / 1e6).toFixed(0)} MB`);
  }
}

void main();
