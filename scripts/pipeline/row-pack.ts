/**
 * A shard's rows, packed once and read once at each end (ADR 0053 phase 6,
 * `src/services/pipeline/rowPack.ts`).
 *
 *   npx tsx scripts/pipeline/row-pack.ts
 *
 * A shard packs a batch's rows into one buffer; the coordinator forwards it,
 * once, to each receiver, with an order list saying which row of which pack -
 * or which of its own objects - comes next. Shards interleave frame by frame
 * and a flush is cut by size and time, so nearly every pack is read across two
 * flushes. What is held here: every row comes out exactly once, in the order
 * the flushes named, equal to the row that was packed; a receiver drops a pack
 * when its last row is read, and drops everything at a reset.
 *
 * Every message crosses a `v8.serialize` boundary, as a `postMessage` would.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deserialize, serialize } from 'node:v8';
import { isDeepStrictEqual } from 'node:util';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import {
  PackReader, PackSender, PackedFlush, packRows, unpackRows, type PackedRows, type RowPack,
} from '../../src/services/pipeline/rowPack';
import type { Packet } from '../../src/types/packet';
import { FIXTURES } from './arrival';
import { evictionCapture } from './evictionCapture';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const NO_BYTES = new Uint8Array(0);
const MAX_FRAMES = 20_000;

/** Rows as a shard has them when it packs: tree left behind, bytes set aside. */
async function dissect(bytes: Uint8Array): Promise<{ rows: Packet[]; frameBytes: Uint8Array[] }> {
  const { frames } = await PcapService.extractFrames(new File([bytes], 'capture.pcap'), MAX_FRAMES);
  const clock = new FrameClock();
  const sequencer = new Sequencer();
  const dissector = new FrameDissector({
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  }, undefined, null);
  const rows: Packet[] = [];
  const frameBytes: Uint8Array[] = [];
  frames.forEach((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    try {
      const { packet } = dissector.dissect({
        id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
        origLen: frame.origLen, linktype: frame.linktype,
      });
      frameBytes.push(packet.rawBytes);
      packet.layers = [];
      packet.rawBytes = NO_BYTES;
      rows.push(packet);
    } catch { /* a frame that fails to dissect sends no row */ }
  });
  return { rows, frameBytes };
}

/** A row's own keys equal, treating a key held as `undefined` and one left out as the same. */
function same(a: Packet, b: Packet): boolean {
  const strip = (p: Packet) => JSON.parse(JSON.stringify({ ...p, rawBytes: undefined, tsNanos: p.tsNanos?.toString() }));
  return isDeepStrictEqual(strip(a), strip(b));
}

function cross<T>(message: T): T {
  return deserialize(serialize(message)) as T;
}

/** A pack of `rows`, as a shard sends it: by its own key. */
function pack(key: number, rows: Packet[], lengths: number[]): RowPack {
  return cross(packRows(key, rows, lengths));
}

async function roundTrips(): Promise<Packet[]> {
  const sources: [string, Uint8Array][] = [];
  for (const fixture of FIXTURES) {
    if (existsSync(fixture.path)) sources.push([fixture.name, new Uint8Array(readFileSync(fixture.path))]);
    else if (!fixture.optional) console.log(`SKIP  ${fixture.name}: ${fixture.path} is not present - see test/fixtures/README.md`);
  }
  sources.push(['eviction', evictionCapture()]);
  let sample: Packet[] = [];
  for (const [name, bytes] of sources) {
    const { rows, frameBytes } = await dissect(bytes);
    let wrong: string | null = null;
    for (let at = 0; at < rows.length && wrong === null; at += 384) {
      const batch = rows.slice(at, at + 384);
      const back = unpackRows(pack(at, batch, frameBytes.slice(at, at + 384).map((b) => b.byteLength)));
      const bad = batch.findIndex((row, i) => !same(row, back[i]));
      if (back.length !== batch.length) wrong = `batch at ${at}: ${back.length} rows back for ${batch.length}`;
      else if (bad >= 0) wrong = `frame ${batch[bad].id} differs`;
    }
    check(`${name}: ${rows.length.toLocaleString()} rows come back from their packs as they went in`, wrong === null, wrong ?? '');
    if (sample.length === 0 || name === 'eviction') sample = rows.slice(0, 1200);
  }
  return sample;
}

/** Three packs of 384 interleaved row by row, 20 objects among them, cut at every multiple of 97. */
function interleaving(rows: Packet[]): void {
  const lanes = [rows.slice(0, 384), rows.slice(384, 768), rows.slice(768, 1152)];
  const objects = rows.slice(1152, 1172);
  const packs = lanes.map((lane, s) => pack(100 + s, lane, lane.map(() => 60)));
  const bytesOf = (s: number, i: number) => new Uint8Array([s, i & 0xff, i >> 8]);

  // The order the merge emits: shard rows round-robin, an object every 58th.
  type Step = { kind: 'object'; row: Packet } | { kind: 'packed'; lane: number; index: number };
  const steps: Step[] = [];
  let next = 0;
  for (let i = 0; i < 384; i++) {
    for (let s = 0; s < 3; s++) {
      steps.push({ kind: 'packed', lane: s, index: i });
      if (steps.length % 58 === 0 && next < objects.length) steps.push({ kind: 'object', row: objects[next++] });
    }
  }
  const expected = steps.map((step) => (step.kind === 'object' ? step.row : lanes[step.lane][step.index]));

  const reader = new PackReader();
  const sent = new Map<number, number>();
  const out: Packet[] = [];
  const firstSeen = new Map<number, number>();
  let packsCarried = 0;
  for (let at = 0, flush = 0; at < steps.length; at += 97, flush++) {
    const builder = new PackedFlush();
    for (const step of steps.slice(at, at + 97)) {
      if (step.kind === 'object') builder.object(step.row);
      else builder.packed(packs[step.lane], step.index, bytesOf(step.lane, step.index), null);
    }
    const message = cross(builder.seal(sent));
    for (const p of message.packs) {
      packsCarried++;
      if (!firstSeen.has(p.key)) firstSeen.set(p.key, flush);
    }
    out.push(...reader.read(message));
  }
  check('every row comes out once, in the order the flushes named, across every cut',
    out.length === expected.length && out.every((row, i) => same(row, expected[i])));
  check('...each pack travelling once, on the first flush that used it', packsCarried === 3 && firstSeen.get(102) === 0);
  check('...and the receiver holding nothing once every row is read', reader.held === 0, `held ${reader.held}`);
  let bytesRight = true;
  steps.forEach((step, i) => {
    if (step.kind !== 'packed') return;
    if (!isDeepStrictEqual(Array.from(out[i].rawBytes), Array.from(bytesOf(step.lane, step.index)))) bytesRight = false;
  });
  check('a packed row is given the bytes that travelled beside it', bytesRight);
}

function overlaysAndBytes(rows: Packet[]): void {
  const lane = rows.slice(0, 10);
  const p = pack(7, lane, lane.map(() => 60));
  const builder = new PackedFlush();
  for (let i = 0; i < 10; i++) {
    builder.packed(p, i, i === 4 ? null : new Uint8Array([i]), i === 6 ? { fields: { 'inwire.live.skipped': 5 }, tsPrecision: 9 } : null);
  }
  const out = new PackReader().read(cross(builder.seal(new Map())));
  check('an overlay is applied to its own row', out[6].fields?.['inwire.live.skipped'] === 5 && out[6].tsPrecision === 9);
  check('...and to no other', out.every((row, i) => i === 6 || row.fields?.['inwire.live.skipped'] === undefined));
  check('a row sent without bytes comes back with none', out[4].rawBytes.byteLength === 0);
}

function reset(rows: Packet[]): void {
  const lane = rows.slice(0, 20);
  const old = pack(1, lane, lane.map(() => 60));
  const reader = new PackReader();
  const sent = new Map<number, number>();
  const first = new PackedFlush();
  for (let i = 0; i < 10; i++) first.packed(old, i, null, null);
  reader.read(cross(first.seal(sent)));
  check('a half-read pack is held', reader.held === 1);

  // A new capture: the coordinator's sent set starts again, and says so.
  const fresh = pack(2, lane.slice(0, 5), lane.slice(0, 5).map(() => 60));
  const after = new PackedFlush();
  for (let i = 0; i < 5; i++) after.packed(fresh, i, null, null);
  const message: PackedRows = { ...after.seal(new Map()), packsReset: true };
  const out = reader.read(cross(message));
  check('a reset drops what the last capture left half read', reader.held === 0 && out.length === 5);

  const stale = new PackedFlush();
  stale.packed(old, 12, null, null);
  let threw = false;
  try { reader.read(cross(stale.seal(new Map([[1, 10]])))); } catch { threw = true; }
  check('...and a row of a pack it no longer holds is an error, not a blank row', threw);
}

/** The Worker's side of a reset: one sender per receiver, told to start again. */
function sender(rows: Packet[]): void {
  const lane = rows.slice(0, 20);
  const old = pack(1, lane, lane.map(() => 60));
  const fresh = pack(2, lane.slice(0, 5), lane.slice(0, 5).map(() => 60));
  const sending = new PackSender();
  const reader = new PackReader();

  const first = new PackedFlush();
  for (let i = 0; i < 10; i++) first.packed(old, i, null, null);
  const one = cross(sending.seal(first));
  check('the first seal says packsReset, as a new Worker must', one.packsReset === true && one.packs.length === 1);
  reader.read(one);

  const again = new PackedFlush();
  for (let i = 10; i < 12; i++) again.packed(old, i, null, null);
  const two = cross(sending.seal(again));
  check('...and a later seal does not, nor does it re-send a pack', two.packsReset === undefined && two.packs.length === 0);
  reader.read(two);
  check('a pack with rows still unread is held', reader.held === 1);

  // A new capture: the same pack key is sent again, because the receiver was told to forget.
  sending.reset();
  const after = new PackedFlush();
  after.packed(old, 15, null, null);
  for (let i = 0; i < 5; i++) after.packed(fresh, i, null, null);
  const three = cross(sending.seal(after));
  check('after reset() the next seal says packsReset again and re-sends a pack sent before',
    three.packsReset === true && three.packs.length === 2);
  const out = reader.read(three);
  check('...and a reader fed through it yields only the new rows, holding only the re-sent pack',
    out.length === 6 && out.every((row, i) => i === 0 || row.id === lane[i - 1].id) && reader.held === 1,
    `rows ${out.length}, held ${reader.held}`);
  const rest = new PackedFlush();
  for (let i = 0; i < 20; i++) if (i !== 15) rest.packed(old, i, null, null);
  reader.read(cross(sending.seal(rest)));
  check('...and ends with held === 0 once the new capture reads its last row', reader.held === 0, `held ${reader.held}`);
}

/**
 * A capture that runs for days sends millions of packs to each receiver. The
 * sender must forget a pack once its last row has gone, as the reader does, or
 * its set grows for the whole capture and reaches V8's 2^24-entry limit.
 */
function bounded(rows: Packet[]): void {
  const lane = rows.slice(0, 20);
  const sending = new PackSender();
  const reader = new PackReader();
  let halfway = -1;
  for (let key = 1; key <= 500; key++) {
    const p = pack(key, lane, lane.map(() => 60));
    const front = new PackedFlush();
    for (let i = 0; i < 12; i++) front.packed(p, i, null, null);
    reader.read(cross(sending.seal(front)));
    if (key === 250) halfway = sending.tracked;
    const back = new PackedFlush();
    for (let i = 12; i < 20; i++) back.packed(p, i, null, null);
    reader.read(cross(sending.seal(back)));
  }
  check('a sender keeps a pack while it still has rows to send', halfway === 1, `tracked ${halfway}`);
  check('...and keeps none once every pack\'s last row has gone', sending.tracked === 0 && reader.held === 0,
    `tracked ${sending.tracked}, held ${reader.held}`);
}

async function main(): Promise<void> {
  const sample = await roundTrips();
  interleaving(sample);
  overlaysAndBytes(sample);
  reset(sample);
  sender(sample);
  bounded(sample);
  console.log(failures === 0 ? '\nAll row-pack checks passed.' : `\n${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
