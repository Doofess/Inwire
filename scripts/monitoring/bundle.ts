/**
 * The `.iwmon` evidence bundle (ADR 0063, Task 5): the bytes, what the range covers, what the manifest says,
 * what an expiry or a cancel does to an export in flight, and the sink's one owner. Plain `tsx`.
 *
 * The reader here is this file's own: it checks the magic, every checksum (node's zlib, not the codec under
 * test) and the id sequence, and decodes the prefix by offset. The two byte vectors are authored by hand.
 * A bundle that the encoder and a reader written from the same misreading both accept would prove nothing.
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { crc32 } from 'node:zlib';
import type { ByteSink } from '../../src/lib/saveSink';
import type { SaveOutcome } from '../../src/lib/saveFile';
import { encodeArchiveFragmentBody, runExpiry } from '../../src/services/monitoring/archive';
import {
  BundleError, bundleFileName, encodeBundleEntries, encodeBundleHeader, exportBundle, type BundleClient,
} from '../../src/services/monitoring/bundle';
import { ExportCancelled } from '../../src/services/monitoring/export';
import type { EvidenceInput, MonitoringJournal } from '../../src/services/monitoring/journal';
import { DEFAULT_RETENTION, planExpiry, type ExpiryPlan } from '../../src/services/monitoring/retention';
import { minuteOf } from '../../src/services/monitoring/rollup';
import type { HostRuntime } from '../../src/services/monitoring/runtime';
import type { MemorySegmentDirectory } from '../../src/services/monitoring/segments';
import { DECODER_POLICY_VERSION, LIMITS, type RawEntry, type SegmentSource } from '../../src/services/monitoring/types';
import type { FromMonitoringWorker } from '../../src/services/monitoring/workerHost';
import {
  BASE, boundary, deflate, dgram, HostRig, MIN, NOW, Rig, rollUp, runAll, S1, S2, start, stop, test,
} from './queryRig';
import { EXPORTER } from './fixtures';

const m = (n: number, off = 0): number => BASE + n * MIN + off;
const EXPORTED = 1_700_000_000_000;
const VERSION = '0.0.0-test';
const SOURCE: SegmentSource = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055 };
const SOURCE2: SegmentSource = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.51', port: 2056 };

const hex = (bytes: Uint8Array): string => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');
const unhex = (s: string): Uint8Array => Uint8Array.from(s.trim().split(/\s+/).map((h) => parseInt(h, 16)));
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

// --- the sink ---------------------------------------------------------------------------------------------

class TestSink implements ByteSink {
  chunks: Uint8Array[] = [];
  closes = 0;
  aborts = 0;
  constructor(private onWrite?: (n: number) => void) {}
  async write(chunk: Uint8Array): Promise<void> {
    this.chunks.push(chunk.slice());
    this.onWrite?.(this.chunks.length);
  }
  async close(): Promise<SaveOutcome> { this.closes++; return { saved: true, path: 'x.iwmon' }; }
  async abort(): Promise<void> { this.aborts++; }
  bytes(): Uint8Array {
    const out = new Uint8Array(this.chunks.reduce((n, c) => n + c.length, 0));
    let at = 0;
    for (const c of this.chunks) { out.set(c, at); at += c.length; }
    return out;
  }
}

// --- this file's own reader ----------------------------------------------------------------------------------

interface Entry { id: number; kind: number; body: Uint8Array }
interface Parsed { generation: string; createdMs: number; formatVersion: number; entries: Entry[] }

function parse(bytes: Uint8Array): Parsed {
  assert.ok(bytes.length >= 64, 'a bundle has at least its header');
  assert.equal(text(bytes.subarray(0, 8)), 'INWIREMB');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assert.equal(v.getUint32(60, true), crc32(bytes.subarray(0, 60)), 'the header checksum');
  const entries: Entry[] = [];
  let at = 64;
  while (at < bytes.length) {
    assert.ok(at + 24 <= bytes.length, 'an entry header is cut short');
    assert.equal(v.getUint32(at, true), 0x454a5749, 'the entry magic');
    const length = v.getUint32(at + 4, true);
    assert.ok(at + 24 + length <= bytes.length, 'an entry body is cut short');
    assert.equal(bytes[at + 17], 0, 'flags are zero');
    assert.equal(v.getUint16(at + 18, true), 0, 'reserved is zero');
    const body = bytes.slice(at + 24, at + 24 + length);
    assert.equal(v.getUint32(at + 20, true), crc32(body, crc32(bytes.subarray(at, at + 20))), `entry ${entries.length + 1}'s checksum`);
    entries.push({ id: Number(v.getBigUint64(at + 8, true)), kind: bytes[at + 16], body });
    at += 24 + length;
  }
  return {
    generation: [...bytes.subarray(16, 32)].map((b) => b.toString(16).padStart(2, '0')).join(''),
    createdMs: Number(v.getBigUint64(32, true)),
    formatVersion: v.getUint32(8, true),
    entries,
  };
}

interface JournalItem { bundleId: number; originalId: number; kind: number; policy: number; body: Uint8Array }

interface Decoded {
  parsed: Parsed;
  manifest: Record<string, any>;
  journal: JournalItem[];
  archive: Entry[];
  end: Record<string, number> | null;
}

/** The shape every complete bundle has, then the parts. */
function decode(bytes: Uint8Array, complete = true): Decoded {
  const parsed = parse(bytes);
  const { entries } = parsed;
  entries.forEach((e, i) => assert.equal(e.id, i + 1, `bundle ids run 1, 2, 3 (entry ${i + 1} is ${e.id})`));
  assert.equal(entries[0].kind, 1, 'the manifest is entry 1');
  assert.ok(entries.every((e) => e.kind !== 4), 'kind 4 is reserved and never written');
  const ends = entries.filter((e) => e.kind === 5);
  if (complete) {
    assert.equal(ends.length, 1);
    assert.equal(entries[entries.length - 1].kind, 5, 'the end is last');
  } else {
    assert.equal(ends.length, 0, 'an export that failed wrote no end');
  }
  // Journal entries first, then archive minutes: never interleaved.
  const kinds = entries.map((e) => e.kind).filter((k) => k === 2 || k === 3);
  assert.deepEqual(kinds, [...kinds].sort(), 'kind 2 entries precede kind 3 entries');
  const journal: JournalItem[] = entries.filter((e) => e.kind === 2).map((e) => {
    const v = new DataView(e.body.buffer, e.body.byteOffset, e.body.byteLength);
    assert.ok(e.body.length >= 16);
    assert.equal(e.body[9], 0);
    assert.equal(v.getUint32(12, true), 0);
    return { bundleId: e.id, originalId: Number(v.getBigUint64(0, true)), kind: e.body[8], policy: v.getUint16(10, true), body: e.body.slice(16) };
  });
  journal.forEach((j, i) => { if (i > 0) assert.equal(j.originalId, journal[i - 1].originalId + 1, 'original ids run +1'); });
  return {
    parsed,
    manifest: JSON.parse(text(entries[0].body)),
    journal,
    archive: entries.filter((e) => e.kind === 3),
    end: ends.length === 1 ? JSON.parse(text(ends[0].body)) : null,
  };
}

/** A kind-3 body by offset: u16 key length, the key, the minute, the entry id it is through, then the rollup. */
function fragmentOf(body: Uint8Array): { key: string; minuteMs: number; throughEntryId: number; rollup: Uint8Array } {
  const v = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const n = v.getUint16(0, true);
  return {
    key: text(body.subarray(2, 2 + n)),
    minuteMs: Number(v.getBigUint64(2 + n, true)),
    throughEntryId: Number(v.getBigUint64(10 + n, true)),
    rollup: body.slice(18 + n),
  };
}

/** Every fragment body the archive file holds, read from its bytes. */
function archiveFragments(rig: Rig): Uint8Array[] {
  const bytes = new Uint8Array(rig.afile.size());
  rig.afile.read(0, bytes);
  const v = new DataView(bytes.buffer);
  const out: Uint8Array[] = [];
  let at = 64;
  while (at + 24 <= bytes.length) {
    const length = v.getUint32(at + 4, true);
    if (bytes[at + 16] === 1) out.push(bytes.slice(at + 24, at + 24 + length));
    at += 24 + length;
  }
  return out;
}

// --- driving an export through a real host -----------------------------------------------------------------

interface Hooks { beforeNext?: (n: number) => void | Promise<void> }
type TestClient = BundleClient & { cancels: number[]; settle(): Promise<void> };

function hostClient(h: HostRig, hooks: Hooks = {}): TestClient {
  const cancels: number[] = [];
  const pending: Promise<void>[] = [];
  let nexts = 0;
  return {
    cancels,
    settle: async () => { await Promise.all(pending); },
    async bundleOpen(range, exportedMs, inwireVersion) {
      const id = h.send({ type: 'bundle-open', range, exportedMs, inwireVersion });
      const r = await h.waitFor(() => h.repliesTo(id).find((p) => p.type === 'bundle-reply'), 'the bundle-open reply') as Extract<FromMonitoringWorker, { type: 'bundle-reply' }>;
      return r.ok ? { ok: true, exportId: r.exportId } : { ok: false, code: r.code, message: r.message };
    },
    async bundleNext(exportId) {
      await hooks.beforeNext?.(++nexts);
      const id = h.send({ type: 'bundle-next', exportId });
      const r = await h.waitFor(() => h.repliesTo(id).find((p) => p.type === 'bundle-chunk'), 'the bundle-next reply') as Extract<FromMonitoringWorker, { type: 'bundle-chunk' }>;
      return r.ok ? { ok: true, bytes: r.bytes, done: r.done } : { ok: false, code: r.code, message: r.message };
    },
    bundleCancel(exportId) {
      cancels.push(exportId);
      const id = h.send({ type: 'bundle-cancel', exportId });
      const done = h.waitFor(() => h.repliesTo(id).find((p) => p.type === 'bundle-cancel-reply'), 'the bundle-cancel reply').then(() => undefined);
      pending.push(done);
      return done;
    },
  };
}

async function connected(runtime: HostRuntime): Promise<HostRig> {
  const h = new HostRig(runtime);
  await h.connect();
  return h;
}

const live = (): AbortSignal => new AbortController().signal;

/** A whole export of `range` over a fresh host, into a fresh sink. */
async function bundleOf(rig: Rig, range: { fromMs: number; toMs: number }): Promise<{ sink: TestSink; h: HostRig; d: Decoded }> {
  const h = await rollUp(rig);
  const sink = new TestSink();
  await exportBundle(hostClient(h), range, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION });
  assert.equal(sink.closes, 1);
  assert.equal(sink.aborts, 0);
  return { sink, h, d: decode(sink.bytes()) };
}

/** `runtime` with some members replaced; the rest are the original's, bound to it. */
function wrap(runtime: HostRuntime, over: Record<string, unknown>): HostRuntime {
  return new Proxy(runtime, {
    get(target, key) {
      if (typeof key === 'string' && key in over) return over[key];
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

function rawEntries(rig: Rig, fromId: number, throughId: number): RawEntry[] {
  const snap = { generation: rig.generation, throughEntryId: throughId };
  const out: RawEntry[] = [];
  let after = fromId - 1;
  for (;;) {
    const page = rig.journal.readRawPage(snap, after, 256, 1 << 20);
    out.push(...page.entries);
    after = page.nextAfterId;
    if (page.done) return out;
  }
}

// --- the worlds ----------------------------------------------------------------------------------------------

const startWith = (ms: number, sessionId: string, source: SegmentSource): EvidenceInput => ({ ...start(ms, sessionId), source } as never);

const flow = (n: number) => [{ src: `10.0.0.${n}`, dst: '172.16.0.1', octets: 100 + n, packets: n, srcPort: 1000 + n, dstPort: 443 }];

/**
 * Ten entries over six minutes. Ids: 1 start (session 1), 2-4 datagrams in minutes 0-2, 5 a gap, 6 a datagram,
 * 7 stop, 8 start (session 2), 9-10 datagrams in minutes 4 and 5.
 */
function smallWorld(): Rig {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(0, 1000), flow(1)),
    dgram(m(1, 1000), flow(2)),
    dgram(m(2, 1000), flow(3)),
    boundary('gap', S1, m(2, 30_000), 'the socket was shed', 3),
    dgram(m(3, 1000), flow(4)),
    stop(m(3, 5000), S1, 'user'),
    startWith(m(4), S2, SOURCE2),
    dgram(m(4, 1000), flow(5)),
    dgram(m(5, 1000), flow(6)),
  ]);
  return rig;
}

const SEG_LIMIT = 32 * 1024 * 1024; // 1 MiB segments
const EXP_SOURCE: SegmentSource = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055 };

/** An hour of one datagram a second over two engines, and a wide minute: the same fixture `queries.ts` expires. */
function expiryInputs(): EvidenceInput[] {
  const timed: EvidenceInput[] = [];
  for (let i = 0; i < 3600; i++) {
    const flows = Array.from({ length: 20 }, (_, j) => ({
      src: `10.${i % 5}.${j}.1`, dst: `172.16.${j % 4}.${(i % 9) + 1}`, octets: 100 + j + (i % 13) * 10, packets: 1 + (j % 3),
      srcPort: 1000 + j, dstPort: 443,
    }));
    timed.push(dgram(BASE + 1000 + i * 1000, flows, { engineId: i % 3 === 0 ? 1 : 0, sequence: i }));
  }
  for (let k = 0; k < 600; k++) {
    const flows = Array.from({ length: 30 }, (_, j) => ({
      src: `11.${k >> 8}.${k & 255}.${j}`, dst: '172.31.0.1', octets: 7 + j, packets: 1, srcPort: 2000 + j, dstPort: 80,
    }));
    timed.push(dgram(m(2, 100 + k * 50), flows, { engineId: 0 }));
  }
  timed.sort((a, b) => a.receivedMs - b.receivedMs);
  return [{ ...start(BASE), source: EXP_SOURCE } as never, ...timed];
}

async function expiryWorld(jdir?: MemorySegmentDirectory): Promise<{ rig: Rig; plan: ExpiryPlan; hi: number }> {
  const rig = new Rig(0xa0, SEG_LIMIT, jdir);
  const inputs = expiryInputs();
  for (let at = 0; at < inputs.length; at += 100) rig.append(inputs.slice(at, at + 100));
  await rollUp(rig).then((h) => h.host.settled());
  const segs = rig.journal.segments();
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, SEG_LIMIT, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null && plan.segments.length === 2, 'the fixture seals at least two segments');
  return { rig, plan, hi: minuteOf(plan.throughMs) };
}

/** The expiry, run on the live journal and archive: a Worker holding them sees it happen. */
function expireLive(rig: Rig, plan: ExpiryPlan): void {
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
}

/** The expiry, then a fresh process over the same files. */
function expire(rig: Rig, plan: ExpiryPlan): void {
  expireLive(rig, plan);
  rig.reopen();
}

// --- the bytes -----------------------------------------------------------------------------------------------

test('the header is the bytes the format names', () => {
  const generation = Uint8Array.from({ length: 16 }, (_, i) => i);
  const expected = '49 4e 57 49 52 45 4d 42 01 00 00 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
    + '00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 a6 6e 81';
  assert.equal(hex(encodeBundleHeader(generation, 1_700_000_000_000)), expected);
});

test('a journal entry is a kind-2 entry: the 16-byte prefix, then the body as the journal holds it', () => {
  const body = unhex('7b 68 e5 cf 8b 01 00 00 c0 00 02 0a 07 08 c0 00 02 01 50 c3 00 00 00 00 00 05 00 00');
  const expected = '49 57 4a 45 2c 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 f3 b7 d6 26 '
    + '01 10 00 00 00 00 00 00 01 00 01 00 00 00 00 00 '
    + '7b 68 e5 cf 8b 01 00 00 c0 00 02 0a 07 08 c0 00 02 01 50 c3 00 00 00 00 00 05 00 00';
  assert.equal(hex(encodeBundleEntries([{ entryId: 4097, kind: 1, policy: 1, receivedMs: 1_700_000_000_123, body }], 2)), expected);
});

test('the file is named for its range, in UTC', () => {
  assert.equal(bundleFileName(Date.UTC(2026, 9, 5, 7, 3), Date.UTC(2026, 9, 19, 23, 59)), 'inwire-monitoring-20261005-0703-20261019-2359.iwmon');
});

// --- what a range covers ---------------------------------------------------------------------------------------

test('the manifest names the first and last journal entry, and they are the first and last kind-2 entries written', async () => {
  const rig = smallWorld();
  for (const [from, to, first, last] of [[m(1), m(5), 3, 9], [m(0), m(6), 1, 10], [m(2, 2000), m(4, 2000), 5, 9], [m(4), m(4, 1001), 8, 9]]) {
    const { d } = await bundleOf(rig, { fromMs: from, toMs: to });
    assert.deepEqual(d.manifest.journal, { firstEntryId: first, throughEntryId: last, policies: [DECODER_POLICY_VERSION] }, `range ${from - BASE}..${to - BASE}`);
    assert.equal(d.journal[0].originalId, first);
    assert.equal(d.journal[d.journal.length - 1].originalId, last);
    assert.equal(d.journal.length, last - first + 1);
    assert.deepEqual(d.end, { journalEntries: last - first + 1, archivedMinutes: 0 });
  }
});

test('a range between two entries has no journal part: journal and sessionAtStart are null and the bundle is only a manifest and an end', async () => {
  const rig = new Rig();
  rig.append([startWith(m(0), S1, SOURCE), dgram(m(1, 1000), flow(1)), dgram(m(5, 1000), flow(2))]);
  const { d } = await bundleOf(rig, { fromMs: m(3), toMs: m(4) });
  assert.equal(d.manifest.journal, null);
  assert.equal(d.manifest.sessionAtStart, null);
  assert.equal(d.journal.length, 0);
  assert.deepEqual(d.parsed.entries.map((e) => e.kind), [1, 5]);
  assert.deepEqual(d.end, { journalEntries: 0, archivedMinutes: 0 });
});

test('a clock that stepped back inside the range leaves no hole: the ids in between are all in the bundle', async () => {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(2, 1000), flow(1)),
    dgram(m(4, 1000), flow(2)),
    dgram(m(2, 30_000), flow(3)),
    dgram(m(5, 1000), flow(4)),
  ]);
  const { d } = await bundleOf(rig, { fromMs: m(2), toMs: m(3, 500) });
  // Entry 3 is at minute 4, after the range, and between entries 2 and 4 which are in it (4's clock stepped back).
  assert.deepEqual(d.manifest.journal, { firstEntryId: 2, throughEntryId: 4, policies: [DECODER_POLICY_VERSION] });
  assert.deepEqual(d.journal.map((j) => j.originalId), [2, 3, 4]);
});

test('the slice ends at the last entry really in the range: a later entry whose clock stepped back before it is not pulled in', async () => {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(2, 1000), flow(1)),
    dgram(m(3, 1000), flow(2)),
    dgram(m(1, 30_000), flow(3)),
    dgram(m(5, 1000), flow(4)),
  ]);
  const { d } = await bundleOf(rig, { fromMs: m(2), toMs: m(4) });
  assert.deepEqual(d.manifest.journal, { firstEntryId: 2, throughEntryId: 3, policies: [DECODER_POLICY_VERSION] });
  assert.deepEqual(d.journal.map((j) => j.originalId), [2, 3]);
});

test('the slice starts at the first entry really in the range: an earlier entry whose clock stood after it is not pulled in', async () => {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(9), flow(1)),
    dgram(m(2, 1000), flow(2)),
    dgram(m(3, 1000), flow(3)),
  ]);
  const { d } = await bundleOf(rig, { fromMs: m(2), toMs: m(4) });
  assert.deepEqual(d.manifest.journal, { firstEntryId: 3, throughEntryId: 4, policies: [DECODER_POLICY_VERSION] });
  assert.deepEqual(d.journal.map((j) => j.originalId), [3, 4]);
});

test('a range no entry is in has no journal part even when entries before and after it are out of time order', async () => {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(9), flow(1)),
    dgram(m(1), flow(2)),
  ]);
  const { d } = await bundleOf(rig, { fromMs: m(3), toMs: m(4) });
  assert.equal(d.manifest.journal, null);
  assert.equal(d.journal.length, 0);
});

// --- the round trip --------------------------------------------------------------------------------------------

test('round trip: manifest first, end last, ids +1, bodies exactly the journal\'s, boundaries carried', async () => {
  const rig = smallWorld();
  const { d, sink } = await bundleOf(rig, { fromMs: m(0), toMs: m(6) });
  const parsed = d.parsed;
  assert.equal(parsed.formatVersion, 1);
  assert.equal(parsed.generation, rig.generation);
  assert.equal(parsed.createdMs, EXPORTED);
  assert.deepEqual(Object.keys(d.manifest), ['bundleFormat', 'inwireVersion', 'exportedMs', 'dataset', 'range', 'journal', 'sessionAtStart', 'archive', 'history']);
  assert.equal(d.manifest.bundleFormat, 1);
  assert.equal(d.manifest.inwireVersion, VERSION);
  assert.equal(d.manifest.exportedMs, EXPORTED);
  assert.deepEqual(d.manifest.dataset, { generation: rig.generation, createdMs: NOW, replaced: null });
  assert.deepEqual(d.manifest.range, { fromMs: m(0), throughMs: m(6) - 1 });
  assert.deepEqual(d.manifest.archive, { minutes: 0, policies: [] });
  assert.deepEqual(d.manifest.history, { cuts: [] });
  assert.equal(d.journal.length, 10);
  assert.deepEqual(d.journal.map((j) => j.bundleId), [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  assert.deepEqual(d.journal.map((j) => j.originalId), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const held = rawEntries(rig, 1, 10);
  held.forEach((e, i) => {
    assert.equal(d.journal[i].kind, e.kind);
    assert.equal(d.journal[i].policy, e.policy);
    assert.equal(hex(d.journal[i].body), hex(e.body), `entry ${e.entryId}'s body is the journal's`);
  });
  // The datagrams' bytes are in the bodies whole (a body is the receipt, the addresses and the payload).
  const first = held[1];
  assert.equal(first.kind, 1);
  assert.deepEqual(d.journal.map((j) => j.kind), [2, 1, 1, 1, 2, 1, 2, 2, 1, 1], 'start, datagrams, gap, stop and start are all there');
  assert.deepEqual(d.end, { journalEntries: 10, archivedMinutes: 0 });
  assert.equal(sink.chunks[0].length >= 64, true);
});

test('a boundary\'s body is copied as it is, not decoded and written again: an unknown key survives', async () => {
  const rig = smallWorld();
  const forged = new Map<number, Uint8Array>();
  const runtime = wrap(rig.runtime, {
    readRawPage: async (...args: Parameters<HostRuntime['readRawPage']>) => {
      const page = await rig.runtime.readRawPage(...args);
      return {
        ...page,
        entries: page.entries.map((e) => {
          if (e.kind !== 2) return e;
          const body = new TextEncoder().encode(text(e.body).replace(/}$/, ',"zz":"from a newer build"}'));
          assert.notEqual(text(body), text(e.body), 'the boundary is JSON and the key was added');
          forged.set(e.entryId, body);
          return { ...e, body };
        }),
      };
    },
  });
  const h = await connected(runtime);
  const sink = new TestSink();
  await exportBundle(hostClient(h), { fromMs: m(0), toMs: m(6) }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION });
  const d = decode(sink.bytes());
  assert.equal(forged.size, 4);
  for (const j of d.journal) if (forged.has(j.originalId)) assert.equal(text(j.body), text(forged.get(j.originalId)!));
  assert.ok(d.journal.some((j) => text(j.body).includes('from a newer build')));
});

test('a page that repeats or skips an id is not the journal the export opened over: changed, and nothing ends it', async () => {
  for (const [name, bend] of [
    ['repeats', (e: RawEntry[]) => [e[0], e[0], ...e.slice(2)]],
    ['skips', (e: RawEntry[]) => [e[0], ...e.slice(2)]],
  ] as const) {
    const rig = smallWorld();
    const h = await connected(wrap(rig.runtime, {
      readRawPage: async (...args: Parameters<HostRuntime['readRawPage']>) => {
        const page = await rig.runtime.readRawPage(...args);
        return { ...page, entries: bend(page.entries) };
      },
    }));
    const sink = new TestSink();
    await assert.rejects(
      exportBundle(hostClient(h), { fromMs: m(0), toMs: m(6) }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
      (e: unknown) => e instanceof BundleError && e.code === 'changed', name,
    );
    assert.equal(sink.aborts, 1, name);
    assert.equal(sink.closes, 0, name);
    decode(sink.bytes(), false);
  }
});

// --- where the range started -----------------------------------------------------------------------------------

test('sessionAtStart: mid-session, the session and its source and the entry that started it', async () => {
  const { d } = await bundleOf(smallWorld(), { fromMs: m(1), toMs: m(3) });
  assert.deepEqual(d.manifest.sessionAtStart, { sessionId: S1, source: SOURCE, startEntryId: 1 });
});

test('sessionAtStart: null when the first entry is a start, and null at the journal\'s very first entry', async () => {
  const rig = smallWorld();
  const second = await bundleOf(rig, { fromMs: m(4), toMs: m(6) });
  assert.equal(second.d.manifest.journal.firstEntryId, 8);
  assert.equal(second.d.manifest.sessionAtStart, null, 'a session 1 stop came before it: nothing was open');
  const first = await bundleOf(rig, { fromMs: m(0), toMs: m(1) });
  assert.equal(first.d.manifest.journal.firstEntryId, 1);
  assert.equal(first.d.manifest.sessionAtStart, null);
});

test('sessionAtStart: a suspended session is still open', async () => {
  const rig = new Rig();
  rig.append([
    startWith(m(0), S1, SOURCE),
    dgram(m(0, 1000), flow(1)),
    boundary('suspend', S1, m(1), 'suspend'),
    boundary('resume', S1, m(3)),
    dgram(m(3, 1000), flow(2)),
  ]);
  const { d } = await bundleOf(rig, { fromMs: m(3), toMs: m(4) });
  assert.equal(d.manifest.journal.firstEntryId, 4);
  assert.deepEqual(d.manifest.sessionAtStart, { sessionId: S1, source: SOURCE, startEntryId: 1 });
});

test('sessionAtStart: once the start has expired the segment header still names the session and its source, and startEntryId is null', async () => {
  const { rig, plan } = await expiryWorld();
  expire(rig, plan);
  const { d } = await bundleOf(rig, { fromMs: m(35), toMs: m(37) });
  assert.ok(d.manifest.journal.firstEntryId > 1);
  assert.deepEqual(d.manifest.sessionAtStart, { sessionId: d.manifest.sessionAtStart.sessionId, source: EXP_SOURCE, startEntryId: null });
  assert.match(d.manifest.sessionAtStart.sessionId, /^[0-9a-f]{32}$/);
});

// --- what has expired --------------------------------------------------------------------------------------------

test('a wholly expired range is archive minutes only: the counts agree and the manifest lists the cut', async () => {
  const { rig, plan, hi } = await expiryWorld();
  expire(rig, plan);
  const { d } = await bundleOf(rig, { fromMs: m(6), toMs: hi });
  assert.equal(d.manifest.journal, null);
  assert.equal(d.journal.length, 0);
  assert.ok(d.archive.length > 0);
  assert.equal(d.manifest.archive.minutes, d.archive.length);
  assert.deepEqual(d.manifest.archive.policies, [DECODER_POLICY_VERSION]);
  assert.deepEqual(d.end, { journalEntries: 0, archivedMinutes: d.archive.length });
  const cuts = rig.archive.cuts();
  assert.equal(cuts.length, 1);
  assert.deepEqual(d.manifest.history.cuts, [{
    fromEntryId: cuts[0].fromEntryId, throughEntryId: cuts[0].throughEntryId, fromMs: cuts[0].fromMs, throughMs: cuts[0].throughMs, reason: cuts[0].reason,
  }]);
  // By source and then by minute, a minute of the range only.
  const frags = d.archive.map((e) => fragmentOf(e.body));
  for (let i = 1; i < frags.length; i++) {
    const [a, b] = [frags[i - 1], frags[i]];
    assert.ok(a.key < b.key || (a.key === b.key && a.minuteMs < b.minuteMs), 'sorted by source, then minute');
  }
  assert.ok(frags.every((f) => f.minuteMs >= m(6) && f.minuteMs < hi));
  assert.ok(new Set(frags.map((f) => f.key)).size >= 2, 'both engines');
});

test('a kind-3 entry is the archive\'s fragment body, byte for byte as archive.iwma holds it', async () => {
  const { rig, plan, hi } = await expiryWorld();
  expire(rig, plan);
  const { d } = await bundleOf(rig, { fromMs: m(0), toMs: hi });
  const held = archiveFragments(rig).filter((b) => fragmentOf(b).minuteMs < hi).map(hex).sort();
  assert.ok(held.length > 0);
  assert.deepEqual(d.archive.map((e) => hex(e.body)).sort(), held);
  // And that is what the codec makes of the fragment it was written from.
  const f = fragmentOf(d.archive[0].body);
  assert.equal(hex(encodeArchiveFragmentBody({ sourceKey: f.key, minuteMs: f.minuteMs, throughEntryId: f.throughEntryId, policyVersion: DECODER_POLICY_VERSION, bytes: f.rollup })), hex(d.archive[0].body));
});

test('a range across the cut holds both: archive minutes for what expired, journal entries for what did not', async () => {
  const { rig, plan, hi } = await expiryWorld();
  expire(rig, plan);
  const { d } = await bundleOf(rig, { fromMs: m(6), toMs: m(40) });
  assert.ok(d.journal.length > 0 && d.archive.length > 0);
  assert.equal(d.manifest.journal.firstEntryId, d.journal[0].originalId);
  assert.ok(d.journal[0].originalId > plan.segments.length);
  assert.ok(d.archive.every((e) => fragmentOf(e.body).minuteMs < hi + MIN));
  assert.equal(d.manifest.history.cuts.length, 1);
});

test('pages are bounded: no chunk holds more than a page of journal entries, and the archive minutes are paged too', async () => {
  const { rig, plan, hi } = await expiryWorld();
  const before = await bundleOf(rig, { fromMs: m(0), toMs: m(30) });
  assert.ok(before.d.journal.length > 2 * LIMITS.pageEntries, `${before.d.journal.length} entries is several pages`);
  const perChunk = (sink: TestSink, kind: number): number[] => sink.chunks.map((c, i) => {
    let n = 0;
    for (let at = i === 0 ? 64 : 0; at < c.length; at += 24 + new DataView(c.buffer, c.byteOffset).getUint32(at + 4, true)) if (c[at + 16] === kind) n++;
    return n;
  });
  const journal = perChunk(before.sink, 2);
  assert.ok(Math.max(...journal) <= LIMITS.pageEntries);
  assert.ok(journal.filter((n) => n > 0).length >= 3);

  expire(rig, plan);
  const after = await bundleOf(rig, { fromMs: m(0), toMs: hi });
  const archive = perChunk(after.sink, 3).filter((n) => n > 0);
  assert.ok(archive.length >= 2, `${after.d.archive.length} minutes came in ${archive.length} chunk(s)`);
});

/** A journal that dies as an expiry drops its segments: the archive already holds the cut, the journal still holds the entries. */
function dyingJournal(journal: MonitoringJournal): MonitoringJournal {
  const o = Object.create(journal) as MonitoringJournal;
  o.dropSegments = () => { throw new Error('the process died'); };
  return o;
}

test('an expiry interrupted between the archive and the journal is not counted twice: the archive minutes the journal still holds are left out, and the counts agree', async () => {
  const { rig, plan, hi } = await expiryWorld();
  assert.equal(runExpiry(dyingJournal(rig.journal), rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'failed');
  assert.ok(rig.archive.lastCut() !== null, 'the cut is durable');
  assert.equal(rig.journal.snapshot().firstEntryId, 1, 'and the journal still holds every entry');
  const { d } = await bundleOf(rig, { fromMs: m(0), toMs: hi });
  assert.equal(d.manifest.journal.firstEntryId, 1);
  assert.ok(d.journal.length > 0);
  // Each datagram is in the bundle once: as an entry, not also as a minute folded from it.
  assert.equal(d.archive.length, 0);
  assert.equal(d.manifest.archive.minutes, 0);
  assert.deepEqual(d.manifest.archive.policies, []);
  assert.deepEqual(d.end, { journalEntries: d.journal.length, archivedMinutes: 0 });
});

// --- what moves under an export -----------------------------------------------------------------------------------

test('an expiry mid-export fails changed, aborts the sink and writes no end: a range that is retained, and one that expires', async () => {
  for (const [name, range] of [['retained', { fromMs: m(35), toMs: m(40) }], ['expiring', { fromMs: m(6), toMs: m(30) }]] as const) {
    const { rig, plan } = await expiryWorld();
    const h = await rollUp(rig);
    const sink = new TestSink();
    const client = hostClient(h, { beforeNext: (n) => { if (n === 2) expireLive(rig, plan); } });
    await assert.rejects(
      exportBundle(client, range, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
      (e: unknown) => e instanceof BundleError && e.code === 'changed', name,
    );
    assert.equal(sink.aborts, 1, name);
    assert.equal(sink.closes, 0, name);
    decode(sink.bytes(), false);
  }
});

test('a reopen under an export fails its next chunk changed', async () => {
  const rig = smallWorld();
  const handlers: (() => void)[] = [];
  const h = await connected(wrap(rig.runtime, { onReopened: (fn: () => void) => { handlers.push(fn); } }));
  assert.equal(handlers.length, 1);
  const sink = new TestSink();
  const client = hostClient(h, { beforeNext: (n) => { if (n === 2) handlers[0](); } });
  await assert.rejects(
    exportBundle(client, { fromMs: m(0), toMs: m(6) }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
    (e: unknown) => e instanceof BundleError && e.code === 'changed',
  );
  assert.equal(sink.aborts, 1);
  assert.equal(sink.closes, 0);
});

test('a damaged archive is history-lost, never an empty bundle: the sink is aborted before a byte is written', async () => {
  const { rig, plan, hi } = await expiryWorld();
  expire(rig, plan);
  const bytes = new Uint8Array(rig.afile.size());
  rig.afile.read(0, bytes);
  const at = bytes.length >> 1;
  rig.afile.write(at, Uint8Array.of(bytes[at] ^ 0xff));
  rig.openArchive();
  rig.openSidecar();
  const h = await rollUp(rig);
  const sink = new TestSink();
  await assert.rejects(
    exportBundle(hostClient(h), { fromMs: m(0), toMs: hi }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
    (e: unknown) => e instanceof BundleError && e.code === 'history-lost',
  );
  assert.equal(sink.aborts, 1);
  assert.equal(sink.closes, 0);
  assert.equal(sink.chunks.length, 0);
});

// --- cancel and the sink's one owner -------------------------------------------------------------------------------

test('a second export cancels the first: the first aborts its sink once and never closes it, the second completes', async () => {
  const rig = smallWorld();
  const h = await rollUp(rig);
  const opts = { exportedMs: EXPORTED, inwireVersion: VERSION };
  const sinkB = new TestSink();
  let release: () => void = () => undefined;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let second: Promise<unknown> | null = null;
  const clientA = hostClient(h, {
    beforeNext: async (n) => {
      if (n !== 2) return;
      // A has opened and read its first chunk; B opens now, which ends A's export, and runs to its close.
      second = exportBundle(hostClient(h), { fromMs: m(2), toMs: m(5) }, sinkB, live(), opts);
      try { await second; } finally { release(); }
    },
  });
  const sinkA = new TestSink();
  const first = exportBundle(clientA, { fromMs: m(0), toMs: m(6) }, sinkA, live(), opts);
  await held;
  await assert.rejects(first, (e: unknown) => e instanceof ExportCancelled);
  assert.equal(sinkA.aborts, 1);
  assert.equal(sinkA.closes, 0);
  assert.equal(clientA.cancels.length, 0, 'it was told it was cancelled; it does not cancel again');
  assert.equal(sinkB.closes, 1);
  assert.equal(sinkB.aborts, 0);
  const d = decode(sinkB.bytes());
  assert.equal(d.manifest.journal.firstEntryId, 4);
});

test('an aborted signal sends bundle-cancel once, aborts the sink once and never closes it', async () => {
  const rig = smallWorld();
  const h = await rollUp(rig);
  const controller = new AbortController();
  const client = hostClient(h);
  const sink = new TestSink((n) => { if (n === 1) controller.abort(); });
  await assert.rejects(
    exportBundle(client, { fromMs: m(0), toMs: m(6) }, sink, controller.signal, { exportedMs: EXPORTED, inwireVersion: VERSION }),
    (e: unknown) => e instanceof ExportCancelled,
  );
  await client.settle();
  assert.equal(client.cancels.length, 1);
  assert.equal(sink.aborts, 1);
  assert.equal(sink.closes, 0);
  // The Worker dropped it: the id is no longer open.
  const next = await client.bundleNext(client.cancels[0]);
  assert.equal(next.ok, false);
  assert.equal(next.ok === false && next.code, 'cancelled');
});

test('a write that fails aborts the sink once, tells the Worker, and surfaces the write\'s own error', async () => {
  const rig = smallWorld();
  const h = await rollUp(rig);
  const client = hostClient(h);
  const sink = new TestSink();
  sink.write = async () => { throw new Error('disk full'); };
  await assert.rejects(
    exportBundle(client, { fromMs: m(0), toMs: m(6) }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
    /disk full/,
  );
  await client.settle();
  assert.equal(sink.aborts, 1);
  assert.equal(sink.closes, 0);
  assert.equal(client.cancels.length, 1);
});

test('a bad range is refused at the open and the sink is aborted untouched', async () => {
  const rig = smallWorld();
  const h = await rollUp(rig);
  const sink = new TestSink();
  await assert.rejects(
    exportBundle(hostClient(h), { fromMs: m(3), toMs: m(3) }, sink, live(), { exportedMs: EXPORTED, inwireVersion: VERSION }),
    (e: unknown) => e instanceof BundleError && e.code === 'invalid-request',
  );
  assert.equal(sink.aborts, 1);
  assert.equal(sink.closes, 0);
  assert.equal(sink.chunks.length, 0);
});

test('the monitoring Worker does not reach the capture export writers or dissection', () => {
  // The Worker assembles the bundle, so `bundle.ts` is in its graph; one value import of `export.ts` once
  // pulled the capture CSV writer, and with it the field registry, into the Worker (+200 kB).
  const ENTRY = 'src/workers/monitoring.worker.ts';
  const seen = new Map<string, string | null>([[ENTRY, null]]);
  const queue = [ENTRY];
  while (queue.length > 0) {
    const file = queue.pop()!;
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(/\b(?:import|export)\s+(?!type\b)[^;'"]*?\bfrom\s*['"](\.[^'"]+)['"]|\bimport\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g)) {
      const base = path.posix.join(path.posix.dirname(file), match[1] ?? match[2]);
      const target = [`${base}.ts`, `${base}.tsx`, `${base}/index.ts`, base].find((c) => existsSync(c) && c.endsWith('ts'));
      if (target === undefined || seen.has(target)) continue;
      seen.set(target, file);
      queue.push(target);
    }
  }
  const chain = (file: string): string => { const out = [file]; for (let f = seen.get(file); f; f = seen.get(f)) out.unshift(f); return out.join(' -> '); };
  const offenders = [...seen.keys()].filter((f) => f.startsWith('src/services/export/') || f.startsWith('src/services/dissect/')).map(chain);
  assert.deepEqual(offenders, []);
});

process.exit((await runAll()) === 0 ? 0 : 1);
