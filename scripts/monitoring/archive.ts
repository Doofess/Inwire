/**
 * The sealed archive and the expiry that fills it (ADR 0062).
 *
 * Two halves. The first holds the archive's bytes to the hex vectors in the
 * ADR - authored there, not by the code under test - and to its reopen rules:
 * a torn tail and a cut that never came are truncated, damage in the middle is
 * preserved and refuses everything. The second runs `runExpiry` over a real
 * segmented journal and checks the property that makes retention honest: what
 * leaves the journal is in the archive exactly once, and the totals of the
 * archive and the retained journal together are the totals before.
 *
 * Plain `tsx`; the generator and the harness are `queryRig.ts`.
 */
import assert from 'node:assert/strict';
import { MemoryBlockFile, type BlockFile } from '../../src/services/capture/blockFile';
import {
  ARCHIVE_FRAMING, ArchiveStore, expiryFragments, resumeExpiry, runExpiry, type ArchiveCut, type ArchivedMinute,
} from '../../src/services/monitoring/archive';
import { ENTRY_HEADER_BYTES, FILE_HEADER_BYTES, encodeEntry } from '../../src/services/monitoring/journalCodec';
import { MonitoringJournal } from '../../src/services/monitoring/journal';
import { DEFAULT_RETENTION, planExpiry, type ExpiryPlan } from '../../src/services/monitoring/retention';
import { EngineAdmission, MinuteAccumulator, MinuteAggregator, feedEntry, minuteOf } from '../../src/services/monitoring/rollup';
import { decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { MemorySegmentDirectory } from '../../src/services/monitoring/segments';
import type { Evidence, MinuteRollup, SegmentSource } from '../../src/services/monitoring/types';
import { sourceKey } from '../../src/services/monitoring/v5';
import { EXPORTER } from './fixtures';
import { BASE, FlakyDirectory, MIN, NOW, Rig, SRC, SRC1, askOk, deflate, dgram, inflate, runAll, spec, start, test } from './queryRig';

// --- the ADR's vectors -----------------------------------------------------------------------------------

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join(' ');
const fromHex = (s: string): Uint8Array => Uint8Array.from(s.trim().split(/\s+/).map((h) => parseInt(h, 16)));

const GENERATION = Uint8Array.from({ length: 16 }, (_, i) => i);
const CREATED_MS = 1_700_000_000_000;

const VECTOR_HEADER = `
49 4e 57 49 52 45 4d 41 01 00 00 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5a 76 07 02`;
const VECTOR_ENTRY_1 = `
49 57 4a 45 23 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 59 e9 91 69
0d 00 31 39 32 2e 30 2e 32 2e 31 2f 30 2f 30 e0 19 e5 cf 8b 01 00 00 00 10 00 00 00 00 00 00 01 00 de ad`;
const VECTOR_ENTRY_2 = `
49 57 4a 45 2c 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 4d 60 49 72
01 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 7b 68 e5 cf 8b 01 00 00 d8 8b ee cf 8b 01 00 00
01 00 00 00 01 00 00 00 00 00 00 00`;

const VECTOR_MINUTE: ArchivedMinute = {
  sourceKey: '192.0.2.1/0/0', minuteMs: 1_699_999_980_000, throughEntryId: 4096, policyVersion: 1, bytes: fromHex('01 00 de ad'),
};
const VECTOR_CUT: ArchiveCut = {
  fromEntryId: 1, throughEntryId: 4096, fromMs: 1_700_000_000_123, throughMs: 1_700_000_599_000, fragments: 1,
  reason: 'age', checkpoint: new Uint8Array(0),
};

function bytesOf(file: BlockFile): Uint8Array {
  const out = new Uint8Array(file.size());
  file.read(0, out);
  return out;
}

function fileOf(...parts: Uint8Array[]): MemoryBlockFile {
  const f = new MemoryBlockFile();
  let at = 0;
  for (const p of parts) { f.write(at, p); at += p.length; }
  return f;
}

const INIT = { generation: GENERATION, createdMs: CREATED_MS };
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

test('the header, a minute and a cut are the ADR vectors, byte for byte', () => {
  const file = new MemoryBlockFile();
  const { store, status } = ArchiveStore.open(file, INIT);
  assert.equal(status, 'empty');
  assert.equal(hex(bytesOf(file)), hex(fromHex(VECTOR_HEADER)), 'the header');
  assert.equal(hex(store.generation()!), hex(GENERATION));
  store.append([VECTOR_MINUTE], VECTOR_CUT);
  const want = concat(fromHex(VECTOR_HEADER), fromHex(VECTOR_ENTRY_1), fromHex(VECTOR_ENTRY_2));
  assert.equal(hex(bytesOf(file)), hex(want), 'header, entry 1 and entry 2');
  assert.ok(file.flushes >= 1, 'the cut is flushed before append returns');
  assert.equal(store.bytes(), want.length);
  assert.deepEqual(store.lastCut(), VECTOR_CUT);
  assert.equal(store.coveredThroughMs(), 1_700_000_599_000);
});

test('the vector file opens as ok, and reads its minute back', () => {
  const bytes = concat(fromHex(VECTOR_HEADER), fromHex(VECTOR_ENTRY_1), fromHex(VECTOR_ENTRY_2));
  const file = fileOf(bytes);
  const { store, status } = ArchiveStore.open(file, INIT);
  assert.equal(status, 'ok');
  assert.deepEqual(store.cuts(), [VECTOR_CUT]);
  assert.equal(store.coveredThroughMs(), VECTOR_CUT.throughMs);
  const read = store.read('192.0.2.1/0/0', 1_699_999_980_000, 1_700_000_040_000, 1 << 20);
  assert.deepEqual(read, [VECTOR_MINUTE]);
  assert.deepEqual(store.read('192.0.2.1/0/0', 1_700_000_040_000, 1_700_000_100_000, 1 << 20), [], 'half-open: the next minute holds none');
  assert.deepEqual(store.read('192.0.2.9/0/0', 0, 2e12, 1 << 20), []);
  assert.equal(store.read('192.0.2.1/0/0', 0, 2e12, 3), 'range-too-large', 'refused, never clipped');
  assert.equal(hex(bytesOf(file)), hex(bytes), 'a clean open writes nothing');
});

test('a torn tail is truncated and the archive opens ok', () => {
  const full = concat(fromHex(VECTOR_HEADER), fromHex(VECTOR_ENTRY_1), fromHex(VECTOR_ENTRY_2));
  const stray = encodeEntry(ARCHIVE_FRAMING, 3, 1, new Uint8Array(40)).subarray(0, 30);
  const file = fileOf(full, stray);
  const { status, store } = ArchiveStore.open(file, INIT);
  assert.equal(status, 'ok');
  assert.equal(file.size(), full.length);
  assert.deepEqual(store.lastCut(), VECTOR_CUT);
});

test('fragments with no cut behind them are truncated: the expiry never finished', () => {
  const head = fromHex(VECTOR_HEADER);
  const alone = fileOf(head, fromHex(VECTOR_ENTRY_1));
  let r = ArchiveStore.open(alone, INIT);
  assert.equal(r.status, 'truncated-unfinished');
  assert.equal(alone.size(), FILE_HEADER_BYTES, 'back to the header');
  assert.equal(r.store.lastCut(), null);
  assert.equal(r.store.coveredThroughMs(), null);
  assert.deepEqual(r.store.read('192.0.2.1/0/0', 0, 2e12, 1 << 20), [], 'an uncut fragment is not readable');

  const full = concat(head, fromHex(VECTOR_ENTRY_1), fromHex(VECTOR_ENTRY_2));
  const extra = encodeEntry(ARCHIVE_FRAMING, 3, 1, fromHex('0d 00 31 39 32 2e 30 2e 32 2e 31 2f 30 2f 30 e0 19 e5 cf 8b 01 00 00 00 20 00 00 00 00 00 00 01 00 be ef'));
  const after = fileOf(full, extra);
  r = ArchiveStore.open(after, INIT);
  assert.equal(r.status, 'truncated-unfinished');
  assert.equal(after.size(), full.length, 'back to the end of the last cut');
  assert.deepEqual(r.store.lastCut(), VECTOR_CUT);
  // The archive is usable again: the next expiry appends from the truncated end.
  r.store.append([{ ...VECTOR_MINUTE, minuteMs: 1_700_000_040_000, throughEntryId: 8192 }], {
    ...VECTOR_CUT, fromEntryId: 4097, throughEntryId: 8192, fromMs: 1_700_000_600_000, throughMs: 1_700_000_900_000,
  });
  assert.equal(r.store.cuts().length, 2);
  assert.equal(ArchiveStore.open(after, INIT).status, 'ok', 'and what it wrote reopens');
});

test('damage in the middle is corrupt: nothing repaired, appends refused, reads say history-lost', () => {
  const entry1 = fromHex(VECTOR_ENTRY_1);
  entry1[40] ^= 0xff; // inside entry 1's body, with a whole valid entry behind it
  const bytes = concat(fromHex(VECTOR_HEADER), entry1, fromHex(VECTOR_ENTRY_2));
  const file = fileOf(bytes);
  const { store, status } = ArchiveStore.open(file, INIT);
  assert.equal(status, 'corrupt');
  assert.equal(hex(bytesOf(file)), hex(bytes), 'the file is exactly as it was found');
  assert.throws(() => store.append([VECTOR_MINUTE], { ...VECTOR_CUT, fromEntryId: 4097, throughEntryId: 9000 }));
  assert.equal(hex(bytesOf(file)), hex(bytes), 'and still is after a refused append');
  assert.equal(store.read('192.0.2.1/0/0', 0, 2e12, 1 << 20), 'history-lost');
  assert.equal(store.lastCut(), null);
  assert.equal(store.coveredThroughMs(), null);
});

test('a cut that miscounts its fragments, a reused id and a foreign file are corrupt', () => {
  const head = fromHex(VECTOR_HEADER);
  const miscount = fromHex(VECTOR_ENTRY_2);
  miscount[24 + 32] = 2; // the cut says two fragments; one precedes it
  // Re-seal the checksum: only a writer that was wrong gets this far, not a bit flip.
  const resealed = encodeEntry(ARCHIVE_FRAMING, 2, 2, miscount.subarray(ENTRY_HEADER_BYTES));
  assert.equal(ArchiveStore.open(fileOf(head, fromHex(VECTOR_ENTRY_1), resealed), INIT).status, 'corrupt');

  const idGap = encodeEntry(ARCHIVE_FRAMING, 5, 2, fromHex(VECTOR_ENTRY_2).subarray(ENTRY_HEADER_BYTES));
  assert.equal(ArchiveStore.open(fileOf(head, fromHex(VECTOR_ENTRY_1), idGap), INIT).status, 'corrupt');

  const foreign = fileOf(new Uint8Array(200).fill(7));
  const r = ArchiveStore.open(foreign, INIT);
  assert.equal(r.status, 'corrupt');
  assert.equal(foreign.size(), 200, 'someone else\'s file is not overwritten');
});

test('an empty file, and the first bytes of a header, get a header and open empty', () => {
  const none = new MemoryBlockFile();
  assert.equal(ArchiveStore.open(none, INIT).status, 'empty');
  const torn = fileOf(fromHex(VECTOR_HEADER).subarray(0, 20));
  assert.equal(ArchiveStore.open(torn, INIT).status, 'empty');
  assert.equal(hex(bytesOf(torn)), hex(fromHex(VECTOR_HEADER)));
});

test('a header that cannot be written is failed, and refuses everything', () => {
  const broken: BlockFile = {
    read: () => 0, write: () => { throw new Error('disk full'); }, truncate: () => { throw new Error('disk full'); },
    flush: () => {}, size: () => 0,
  } as unknown as BlockFile;
  const { store, status } = ArchiveStore.open(broken, INIT);
  assert.equal(status, 'failed');
  assert.throws(() => store.append([VECTOR_MINUTE], VECTOR_CUT));
  assert.equal(store.read('x', 0, 1, 10), 'history-lost');
  assert.equal(store.generation(), null);
});

test('append refuses what the archive could not read back, and writes nothing', () => {
  const file = new MemoryBlockFile();
  const { store } = ArchiveStore.open(file, INIT);
  const before = bytesOf(file);
  const bad = (m: ArchivedMinute[], c: ArchiveCut): void => {
    assert.throws(() => store.append(m, c));
    assert.equal(hex(bytesOf(file)), hex(before));
  };
  bad([VECTOR_MINUTE], { ...VECTOR_CUT, fragments: 2 });
  bad([{ ...VECTOR_MINUTE, policyVersion: 2, bytes: fromHex('02 00 de ad') }], VECTOR_CUT);
  bad([{ ...VECTOR_MINUTE, policyVersion: 1, bytes: fromHex('02 00 de ad') }], VECTOR_CUT);
  bad([VECTOR_MINUTE], { ...VECTOR_CUT, throughEntryId: 0 });
  bad([VECTOR_MINUTE], { ...VECTOR_CUT, throughMs: VECTOR_CUT.fromMs - 1 });
  bad([{ ...VECTOR_MINUTE, bytes: new Uint8Array(2 << 20) }], VECTOR_CUT);
  store.append([VECTOR_MINUTE], VECTOR_CUT);
  const after = bytesOf(file);
  assert.throws(() => store.append([], { ...VECTOR_CUT, fragments: 0, fromEntryId: 4000, throughEntryId: 9000 }), Error, 'a cut starts after the last one');
  assert.equal(hex(bytesOf(file)), hex(after));
});

test('a minute under a policy this build does not accept is history-lost, not decoded', () => {
  // Written by a build that accepted policy 7; this one does not. The entry is intact.
  const body = new Uint8Array(2 + 13 + 16 + 4);
  const v = new DataView(body.buffer);
  v.setUint16(0, 13, true);
  body.set(new TextEncoder().encode('192.0.2.1/0/0'), 2);
  v.setBigUint64(15, 1_699_999_980_000n, true);
  v.setBigUint64(23, 4096n, true);
  body.set(fromHex('07 00 de ad'), 31);
  const minute = encodeEntry(ARCHIVE_FRAMING, 1, 1, body);
  const cut = encodeEntry(ARCHIVE_FRAMING, 2, 2, fromHex(VECTOR_ENTRY_2).subarray(ENTRY_HEADER_BYTES));
  const { store, status } = ArchiveStore.open(fileOf(fromHex(VECTOR_HEADER), minute, cut), INIT);
  assert.equal(status, 'ok', 'the file is fine; only that minute is unreadable');
  assert.equal(store.read('192.0.2.1/0/0', 0, 2e12, 1 << 20), 'history-lost');
});

// --- expiry over a real journal --------------------------------------------------------------------------

const LIMIT = 32 * 1024 * 1024; // 1 MiB segments
const SOURCE: SegmentSource = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055 };

function datagram(i: number) {
  const flows = Array.from({ length: 20 }, (_, j) => ({
    src: `10.${i % 5}.${j}.1`, dst: `172.16.${j % 4}.${(i % 9) + 1}`, octets: 100 + j + (i % 13) * 10, packets: 1 + (j % 3),
    srcPort: 1000 + j, dstPort: 443,
  }));
  return dgram(BASE + 1000 + i * 1000, flows, { engineId: i % 3 === 0 ? 1 : 0, sequence: i });
}

/** Enough datagrams for three sealed 1 MiB segments and part of a fourth. */
function fill(rig: Rig, n = 3600): void {
  rig.append([{ ...start(BASE), source: SOURCE } as never]);
  for (let at = 0; at < n; at += 100) rig.append(Array.from({ length: Math.min(100, n - at) }, (_, k) => datagram(at + k)));
}

function readFrom(rig: Rig, afterId: number): Evidence[] {
  const snap = rig.journal.snapshot();
  const out: Evidence[] = [];
  let after = afterId;
  for (;;) {
    const page = rig.journal.readPage(snap, after, 256, 1 << 20);
    out.push(...page.entries);
    after = page.nextAfterId;
    if (page.done) return out;
  }
}

/** What the Worker would hold for these entries, as encoded minutes, from an aggregator started after `afterId`. */
function rollUpEntries(entries: Evidence[], afterId: number, known: string[]): { rollup: MinuteRollup; bytes: Uint8Array }[] {
  const agg = new MinuteAggregator(afterId);
  const admission = new EngineAdmission(known);
  for (const e of entries) feedEntry(agg, admission, e);
  agg.seal(Infinity);
  const drained = agg.drain();
  return (drained?.fragments ?? []).map((f) => ({ rollup: f.rollup, bytes: encodeMinuteRollup(f.rollup, deflate) }));
}

function merge(rollups: MinuteRollup[], key: string, minuteMs: number): MinuteRollup {
  const acc = new MinuteAccumulator(key, minuteMs);
  for (const r of rollups) acc.absorb(r);
  return acc.toRollup();
}

const show = (r: MinuteRollup): string => JSON.stringify(r, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v));

interface World {
  rig: Rig;
  all: Evidence[];
  /** The cache before any expiry: every minute of every source. */
  before: Map<string, MinuteRollup>;
  plan: ExpiryPlan;
  cacheKnown: string[];
}

const keyOf = (src: string, minuteMs: number): string => `${src}@${minuteMs}`;

/** A rig whose cache holds the whole journal, and a plan that expires the first two segments. */
function world(jdir?: MemorySegmentDirectory): World {
  const rig = new Rig(0xa0, LIMIT, jdir);
  fill(rig);
  const segs = rig.journal.segments();
  assert.ok(segs.filter((s) => s.sealed).length >= 3, `the fixture should seal three segments (got ${segs.length} segments)`);
  const all = readFrom(rig, 0);
  const rolled = rollUpEntries(all, 0, []);
  rig.store.appendMinutes(
    rolled.map((r) => ({ sourceKey: r.rollup.sourceKey, minuteMs: r.rollup.minuteMs, bytes: r.bytes })),
    { generation: rig.generation, throughEntryId: rig.through, policyVersion: 1 },
    0,
  );
  const before = new Map<string, MinuteRollup>();
  for (const r of rolled) before.set(keyOf(r.rollup.sourceKey, r.rollup.minuteMs), r.rollup);
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, LIMIT, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null);
  assert.equal(plan.segments.length, 2);
  assert.equal(plan.reason, 'user-before');
  return { rig, all, before, plan, cacheKnown: rig.store.sources() };
}

function archiveRollups(rig: Rig, key: string, fromMs: number, toMs: number): MinuteRollup[] {
  const r = rig.archive.read(key, fromMs, toMs, 64 << 20);
  assert.ok(Array.isArray(r), `archive read: ${String(r)}`);
  return (r as ArchivedMinute[]).map((m) => decodeMinuteRollup(m.bytes, inflate));
}

function expiredBoundaries(rig: Rig): Evidence[] {
  const snap = rig.journal.snapshot();
  const page = rig.journal.readBoundaries(snap, snap.firstEntryId - 1, 1000);
  return page.entries.filter((b) => b.action === 'expired');
}

const SOURCES = [SRC, SRC1];

/** Every (source, minute) of the pre-expiry cache, merged from the archive and from the retained journal. */
function afterExpiry(w: World): Map<string, MinuteRollup> {
  const { rig } = w;
  const first = rig.journal.snapshot().firstEntryId;
  const retained = rollUpEntries(readFrom(rig, first - 1), first - 1, w.cacheKnown);
  const out = new Map<string, MinuteRollup>();
  const minutes = new Set<number>([...w.before.values()].map((r) => r.minuteMs));
  for (const src of SOURCES) {
    for (const minuteMs of minutes) {
      const parts = [
        ...archiveRollups(rig, src, minuteMs, minuteMs + MIN),
        ...retained.filter((r) => r.rollup.sourceKey === src && r.rollup.minuteMs === minuteMs).map((r) => r.rollup),
      ];
      if (parts.length > 0) out.set(keyOf(src, minuteMs), merge(parts, src, minuteMs));
    }
  }
  return out;
}

function assertTotalsEqualBefore(w: World): void {
  const after = afterExpiry(w);
  assert.equal(after.size, w.before.size, 'the same minutes');
  for (const [k, r] of w.before) assert.equal(show(after.get(k)!), show(merge([r], r.sourceKey, r.minuteMs)), `minute ${k}`);
}

test('expiry: the archive holds each expired minute once, and with the retained journal it totals what the cache did', () => {
  const w = world();
  const { rig } = w;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  assert.equal(rig.journal.snapshot().firstEntryId, w.plan.throughEntryId + 1);
  assert.equal(rig.archive.lastCut()!.throughEntryId, w.plan.throughEntryId);
  assert.equal(rig.archive.lastCut()!.reason, 'user-before');
  assertTotalsEqualBefore(w);
  // Once: no (source, minute) has two fragments in the archive.
  const seen = new Set<string>();
  for (const src of SOURCES) {
    const frags = rig.archive.read(src, 0, 4e12, 64 << 20) as ArchivedMinute[];
    for (const f of frags) {
      const k = keyOf(src, f.minuteMs);
      assert.ok(!seen.has(k), `${k} archived twice`);
      seen.add(k);
      assert.ok(f.throughEntryId <= w.plan.throughEntryId);
    }
  }
  assert.equal(rig.archive.lastCut()!.fragments, seen.size);
});

test('a wholly expired minute is byte-identical to the cache minute it replaces', () => {
  const w = world();
  const { rig } = w;
  const seg0 = rig.journal.segments()[0];
  const wholly = minuteOf(BASE + 1000) + MIN; // the second minute: inside segment 0 for sure
  assert.ok(wholly + MIN < seg0.lastReceivedMs);
  const cached = rig.store.readMinutes(SRC, wholly, wholly + MIN, 1 << 20);
  assert.equal(cached.length, 1);
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  const archived = rig.archive.read(SRC, wholly, wholly + MIN, 1 << 20) as ArchivedMinute[];
  assert.equal(archived.length, 1);
  const wantBytes = encodeMinuteRollup(merge([decodeMinuteRollup(cached[0].bytes, inflate)], SRC, wholly), deflate);
  assert.equal(hex(archived[0].bytes), hex(wantBytes));
  assert.equal(archived[0].policyVersion, 1);
});

test('the minute the cut falls inside is split: the archive fragment and the retained one add up to the cache minute', () => {
  const w = world();
  const { rig } = w;
  const lastExpired = w.all.find((e) => e.ref.entryId === w.plan.throughEntryId)!;
  const firstRetained = w.all.find((e) => e.ref.entryId === w.plan.throughEntryId + 1)!;
  const straddle = minuteOf(lastExpired.receivedMs);
  assert.equal(straddle, minuteOf(firstRetained.receivedMs), 'the fixture must put the cut inside a minute');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  for (const src of SOURCES) {
    const fromArchive = archiveRollups(rig, src, straddle, straddle + MIN);
    assert.equal(fromArchive.length, 1, `${src}: an archive fragment for the straddling minute`);
    const first = rig.journal.snapshot().firstEntryId;
    const retained = rollUpEntries(readFrom(rig, first - 1), first - 1, w.cacheKnown)
      .filter((r) => r.rollup.sourceKey === src && r.rollup.minuteMs === straddle).map((r) => r.rollup);
    assert.equal(retained.length, 1, `${src}: a retained fragment`);
    assert.equal(show(merge([...fromArchive, ...retained], src, straddle)), show(merge([w.before.get(keyOf(src, straddle))!], src, straddle)));
    assert.ok(retained[0].records < w.before.get(keyOf(src, straddle))!.records);
  }
});

test('the cut is the range the journal\'s expired boundary records', () => {
  const w = world();
  const { rig } = w;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  const cut = rig.archive.lastCut()!;
  const boundaries = expiredBoundaries(rig);
  assert.equal(boundaries.length, 1);
  const b = boundaries[0];
  assert.ok(b.kind === 'boundary' && b.expired);
  assert.deepEqual(
    { fromEntryId: cut.fromEntryId, throughEntryId: cut.throughEntryId, fromMs: cut.fromMs, throughMs: cut.throughMs },
    b.kind === 'boundary' ? b.expired : null,
  );
  assert.equal(cut.fromEntryId, 1);
  assert.equal(cut.throughMs, w.plan.throughMs);
});

test('after an expiry the cache is empty, and a rebuild from the retained journal has nothing from the expired entries', () => {
  const w = world();
  const { rig } = w;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  assert.equal(rig.store.watermark(), null, 'the cache was reset');
  assert.deepEqual(rig.store.sources(), []);
  const archiveBytes = rig.archive.bytes();
  const first = rig.journal.snapshot().firstEntryId;
  const rebuilt = rollUpEntries(readFrom(rig, first - 1), first - 1, w.cacheKnown);
  const rebuiltRecords = rebuilt.reduce((n, r) => n + r.rollup.records, 0);
  let archivedRecords = 0;
  for (const src of SOURCES) for (const r of archiveRollups(rig, src, 0, 4e12)) archivedRecords += r.records;
  const beforeRecords = [...w.before.values()].reduce((n, r) => n + r.records, 0);
  assert.equal(rebuiltRecords + archivedRecords, beforeRecords, 'every record is in exactly one of the two');
  // A cache reset never touches the archive.
  rig.store.reset();
  rig.store.reset();
  assert.equal(rig.archive.bytes(), archiveBytes);
  rig.openArchive();
  assert.equal(rig.archiveStatus, 'ok');
  assert.equal(rig.archive.bytes(), archiveBytes);
});

test('I2: the cache an expiry resets continues from where the journal now begins: an append from anywhere else is refused', () => {
  const w = world();
  const { rig } = w;
  const wasThrough = rig.through;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  const base = rig.journal.snapshot().firstEntryId - 1;
  assert.ok(base > 0);
  const one = [{ sourceKey: SRC, minuteMs: BASE, bytes: new Uint8Array(0) }];
  const mark = { generation: rig.generation, throughEntryId: wasThrough, policyVersion: 1 };
  assert.throws(() => rig.store.appendMinutes(one, mark, wasThrough), RangeError, 'a batch continuing from the live point the old cache had');
  assert.throws(() => rig.store.appendMinutes(one, mark, 0), RangeError, 'one that covers the entries that expired');
  assert.equal(rig.store.watermark(), null, 'a refusal writes nothing');
  rig.store.appendMinutes(one, mark, base);
  assert.equal(rig.store.watermark()?.throughEntryId, wasThrough, 'from the base it is accepted');
});

test('the default policy never plans an expiry, so nothing runs', () => {
  const w = world();
  const { rig } = w;
  const segs = rig.journal.segments();
  assert.equal(planExpiry(segs, DEFAULT_RETENTION, NOW + 1e12, LIMIT, LIMIT), null);
  assert.equal(rig.archive.lastCut(), null);
  assert.equal(rig.archive.bytes(), FILE_HEADER_BYTES);
});

test('crash (a): fragments written, no cut - the reopened archive drops them and the expiry runs once', () => {
  const w = world();
  const { rig } = w;
  // What a crash between the fragments and the cut leaves: the fragments, no cut, the journal untouched.
  const first = rig.journal.segments()[0].firstEntryId;
  const entries = readFrom(rig, first - 1).filter((e) => e.ref.entryId <= w.plan.throughEntryId);
  const frags = expiryFragments(entries, { knownSources: w.cacheKnown }, deflate);
  assert.ok(frags.length > 10);
  rig.archive.append(frags, {
    fromEntryId: first, throughEntryId: w.plan.throughEntryId, fromMs: entries[0].receivedMs, throughMs: w.plan.throughMs,
    fragments: frags.length, reason: 'user-before', checkpoint: new Uint8Array(0),
  });
  const cutEntry = ENTRY_HEADER_BYTES + 44;
  rig.afile.truncate(rig.afile.size() - cutEntry);
  rig.openArchive();
  assert.equal(rig.archiveStatus, 'truncated-unfinished');
  assert.equal(rig.archive.lastCut(), null);
  assert.equal(rig.afile.size(), FILE_HEADER_BYTES);
  assert.equal(rig.journal.snapshot().firstEntryId, 1, 'the journal never lost anything');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'done');
  assertTotalsEqualBefore(w);
  assert.equal(rig.archive.lastCut()!.fragments, frags.length, 'the same fragments, once');
});

/** A journal whose first `dropSegments` throws: the process died after the cut and before the boundary. */
function dyingJournal(journal: MonitoringJournal): MonitoringJournal {
  const o = Object.create(journal) as MonitoringJournal;
  o.dropSegments = () => { throw new Error('the process died'); };
  return o;
}

/** What History queries over the whole hour answer, for both engines: the numbers an expiry, a crash and a resume must not change. */
async function queryTotals(rig: Rig): Promise<string[]> {
  const out: string[] = [];
  for (const src of SOURCES) {
    const r = await askOk(rig, spec(BASE, BASE + 61 * MIN, 61, { sourceKey: src }));
    out.push(`${src}: ${r.matchingRecords} matching, ${r.malformed} malformed`);
    for (const b of r.buckets) out.push(`${src} ${(b.fromMs - BASE) / MIN}: ${b.records} records, ${b.reportedOctets} octets, ${b.reportedPackets} packets`);
  }
  return out;
}

test('crash (b): a cut and no boundary - the next open resumes: the boundary once, the segments gone, nothing archived twice', async () => {
  const w = world();
  const { rig } = w;
  const before = await queryTotals(rig);
  assert.equal(runExpiry(dyingJournal(rig.journal), rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'failed');
  const archived = bytesOf(rig.afile);
  assert.ok(rig.archive.lastCut() !== null, 'the cut is durable');
  assert.equal(rig.journal.snapshot().firstEntryId, 1);
  assert.equal(expiredBoundaries(rig).length, 0);
  // A fresh process: the archive and the journal reopen as they were. No plan is at hand, and none is needed.
  rig.reopen();
  assert.equal(rig.archiveStatus, 'ok');
  assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive), 'resumed');
  assert.equal(hex(bytesOf(rig.afile)), hex(archived), 'nothing was archived again');
  assert.equal(expiredBoundaries(rig).length, 1);
  assert.equal(rig.journal.snapshot().firstEntryId, w.plan.throughEntryId + 1);
  assert.deepEqual(rig.jdir.list().length, rig.journal.segments().length);
  assert.equal(rig.store.watermark(), null, 'the cache was reset on the way');
  assert.deepEqual(await queryTotals(rig), before, 'a query answers what it did before the crash');
  assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive), 'none', 'and there is nothing left to resume');
  assertTotalsEqualBefore(w);
});

test('crash (c): the boundary written, the segments still there - journal open finishes the unlink, and the resume only resets the cache', async () => {
  const dir = new FlakyDirectory();
  const w = world(dir);
  const { rig } = w;
  const before = await queryTotals(rig);
  dir.failUnlink = true;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'failed');
  assert.ok(rig.archive.lastCut() !== null);
  const archived = bytesOf(rig.afile);
  dir.failUnlink = false;
  rig.reopen();
  assert.equal(rig.jdir.list().length, rig.journal.segments().length, 'open removed the leftovers');
  assert.equal(rig.journal.snapshot().firstEntryId, w.plan.throughEntryId + 1);
  assert.equal(expiredBoundaries(rig).length, 1, 'the boundary the first run wrote');
  assert.ok(rig.store.watermark() !== null, 'the cache was not reset: the process died first');
  assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive), 'resumed');
  assert.equal(expiredBoundaries(rig).length, 1, 'and no second one');
  assert.equal(hex(bytesOf(rig.afile)), hex(archived));
  assert.equal(rig.store.watermark(), null, 'the cache was reset on the way');
  assert.deepEqual(await queryTotals(rig), before);
  assertTotalsEqualBefore(w);
});

test('I3: a drop the journal would refuse writes no cut: the run fails with nothing written, whichever way the journal refuses', () => {
  for (const how of ['no room for the boundary', 'a closed journal'] as const) {
    const w = world();
    const { rig } = w;
    const names = w.plan.segments;
    assert.equal(rig.journal.canDropSegments(names), true, `the control: the plan's segments can go (${how})`);
    if (how === 'a closed journal') rig.journal.close();
    else rig.journal.setLimit(1 << 20);
    assert.equal(rig.journal.canDropSegments(names), false, how);
    assert.equal(rig.journal.canDropSegments(names.slice().reverse()), false, 'and names that are not the oldest, in order, never');
    const archived = bytesOf(rig.afile);
    assert.equal(runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'failed', how);
    assert.equal(rig.archive.lastCut(), null, `no cut was promised (${how})`);
    assert.equal(hex(bytesOf(rig.afile)), hex(archived), `nothing was written to the archive (${how})`);
    assert.equal(rig.journal.snapshot().firstEntryId, 1);
    assert.equal(expiredBoundaries(rig).length, 0);
  }
});

/** A journal whose first `dropSegments` is refused, as a disk that hiccuped would: nothing written, the next call is the real one. */
function refusingOnce(journal: MonitoringJournal): MonitoringJournal {
  const o = Object.create(journal) as MonitoringJournal;
  let refused = false;
  o.dropSegments = (names, reason, nowMs) => {
    if (refused) return journal.dropSegments(names, reason, nowMs);
    refused = true;
    return { snapshot: journal.snapshot(), appended: 0, refused: 1, state: 'open' };
  };
  return o;
}

for (const finish of ['resumeExpiry', 'runExpiry'] as const) {
  test(`I3: a cut whose drop failed transiently is finished by the next ${finish}: the boundary once, nothing archived twice`, async () => {
    const w = world();
    const { rig } = w;
    const before = await queryTotals(rig);
    assert.equal(runExpiry(refusingOnce(rig.journal), rig.store, rig.archive, w.plan, { nowMs: NOW, deflate }), 'failed');
    const archived = bytesOf(rig.afile);
    assert.ok(rig.archive.lastCut() !== null, 'the cut is durable');
    assert.equal(expiredBoundaries(rig).length, 0, 'the drop did not happen');
    const done = finish === 'resumeExpiry'
      ? resumeExpiry(rig.journal, rig.store, rig.archive)
      : runExpiry(rig.journal, rig.store, rig.archive, w.plan, { nowMs: NOW, deflate });
    assert.equal(done, 'resumed');
    assert.equal(hex(bytesOf(rig.afile)), hex(archived), 'nothing was archived again');
    assert.equal(expiredBoundaries(rig).length, 1);
    assert.equal(rig.journal.snapshot().firstEntryId, w.plan.throughEntryId + 1);
    assert.equal(rig.store.watermark(), null, 'the cache was reset');
    assert.deepEqual(await queryTotals(rig), before);
  });
}

test('a replay that throws, or a cache that cannot say who is admitted, fails the run and changes nothing', () => {
  const w = world();
  const { rig } = w;
  const segs = rig.journal.segments().map((s) => s.name);
  const archiveBefore = bytesOf(rig.afile);
  const r = runExpiry(rig.journal, rig.store, rig.archive, w.plan, {
    nowMs: NOW, deflate, replay: () => { throw new Error('out of memory'); },
  });
  assert.equal(r, 'failed');
  assert.equal(hex(bytesOf(rig.afile)), hex(archiveBefore));
  assert.deepEqual(rig.journal.segments().map((s) => s.name), segs);
  assert.ok(rig.store.watermark() !== null, 'the cache is untouched');
  // A plan that is not a prefix of the journal's segments is not run.
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, { ...w.plan, segments: [segs[1], segs[2]] }, { nowMs: NOW, deflate }), 'failed');
  assert.equal(hex(bytesOf(rig.afile)), hex(archiveBefore));
});

test('expiryFragments is deterministic and carries the policy it wrote under', () => {
  const w = world();
  const entries = readFrom(w.rig, 0).slice(0, 700);
  const a = expiryFragments(entries, { knownSources: [] }, deflate);
  const b = expiryFragments(entries, { knownSources: [] }, deflate);
  assert.deepEqual(a.map((m) => hex(m.bytes)), b.map((m) => hex(m.bytes)));
  assert.ok(a.length > 0 && a.every((m) => m.policyVersion === 1 && m.bytes[0] === 1 && m.bytes[1] === 0));
  assert.ok(a.every((m) => m.throughEntryId <= 700));
  assert.equal(sourceKey(EXPORTER, 0, 0), SRC);
});

process.exit((await runAll()) === 0 ? 0 : 1);
