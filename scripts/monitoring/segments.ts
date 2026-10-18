/**
 * The journal as a run of segments, the accepted-policies rule and the source
 * keys (ADR 0062).
 *
 *   npx tsx scripts/monitoring/segments.ts
 *
 * Plain tsx, over `MemorySegmentDirectory`: a segment is a file, and every rule
 * here is a decision about a set of files, so the cases hand-build datasets
 * (whole directories of header-and-entries images) and check what an open does
 * with them. The refusals compare every file byte for byte before and after,
 * because "refused" means "nothing was touched".
 *
 * Images are built with the 0059 codec (`encodeEntry`, `encodeFileHeader`) and
 * the segment header encoder, never with the journal under test, so a fixture
 * is not authored by the thing it checks. `scripts/monitoring/journal.ts` owns
 * the per-entry rules and the real-file cases.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  JOURNAL_FRAMING, KIND_BOUNDARY, KIND_DATAGRAM, crc32, encodeDatagramBody, encodeEntry, encodeFileHeader,
} from '../../src/services/monitoring/journalCodec';
import {
  ExpiredRangeError, MonitoringJournal, encodeBoundaryBody, recoverJournal,
  type BoundaryFields, type EvidenceInput, type JournalOptions,
} from '../../src/services/monitoring/journal';
import {
  LEGACY_JOURNAL_NAME, MemorySegmentDirectory, SEGMENT_HEADER_BYTES, decodeSegmentHeader, encodeSegmentHeader,
  isSegmentFileName, segmentBytesFor, segmentName, type SegmentDirectory,
} from '../../src/services/monitoring/segments';
import { exporterOf, isEngineSourceKey, parseSourceKey, sourceKey, sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import { sourceKey as v5SourceKey } from '../../src/services/monitoring/v5';
import { ACCEPTED_POLICIES, type BoundaryEvidence, type DatagramEvidence, type Evidence, type SegmentSource } from '../../src/services/monitoring/types';
import type { BlockFile } from '../../src/services/capture/blockFile';

let failures = 0;
let passes = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`.slice(0, 900));
  }
}

const KiB = 1024;
const MiB = 1024 * KiB;
const T0 = 1_700_000_000_000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex').replace(/(.{2})/g, '$1 ').trim();
const fromHex = (s: string): Uint8Array => Uint8Array.from(s.split(/\s+/).filter(Boolean).map((h) => parseInt(h, 16)));
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
const GEN_BYTES = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const GEN = Buffer.from(GEN_BYTES).toString('hex');
const OTHER_GEN = Uint8Array.from({ length: 16 }, (_, i) => 0x50 + i);
const rnd = (n: number): Uint8Array => GEN_BYTES.slice(0, n);
const sid = (n: number): string => n.toString(16).padStart(2, '0').repeat(16);
const S1 = sid(1);
const S2 = sid(2);
const SRC: SegmentSource = { exporterIPv4: '192.0.2.1', bindIPv4: '192.0.2.10', port: 2055 };
const sessionBytes = (id: string): Uint8Array => Uint8Array.from(id.match(/../g)!.map((h) => parseInt(h, 16)));

function options(over: Partial<JournalOptions> = {}): JournalOptions {
  return { limitBytes: 32 * MiB, randomBytes: rnd, nowMs: () => T0, ...over };
}

// --- images, built with the codec rather than the journal ------------------------------------------

type Item = { b: BoundaryFields } | { d: number; ms: number };

const startItem = (sessionId: string, ms: number, source?: SegmentSource): Item => ({
  b: { action: 'start', sessionId, receivedMs: ms, reason: '', droppedDatagrams: null, ...(source === undefined ? {} : { source }) },
});
const stopItem = (sessionId: string, ms: number): Item => ({
  b: { action: 'stop', sessionId, receivedMs: ms, reason: 'user', droppedDatagrams: null },
});
const dgItem = (d: number, ms: number): Item => ({ d, ms });

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function itemBytes(id: number, item: Item): Uint8Array {
  if ('b' in item) return encodeEntry(JOURNAL_FRAMING, id, KIND_BOUNDARY, encodeBoundaryBody(item.b));
  return encodeEntry(JOURNAL_FRAMING, id, KIND_DATAGRAM, encodeDatagramBody({
    receivedMs: item.ms, localIPv4: '192.0.2.10', localPort: 2055, remoteIPv4: '192.0.2.1', remotePort: 50000,
    payload: Uint8Array.from([1, 2, 3, item.d & 255]),
  }));
}

function entriesFrom(firstId: number, items: Item[]): Uint8Array {
  return cat(...items.map((it, i) => itemBytes(firstId + i, it)));
}

interface SegSpec {
  first: number;
  items: Item[];
  policy?: number;
  gen?: Uint8Array;
  session?: string | null;
  source?: SegmentSource | null;
}

function segImage(o: SegSpec): Uint8Array {
  const header = encodeSegmentHeader({
    policyVersion: o.policy ?? 1, generation: o.gen ?? GEN_BYTES, createdMs: T0, firstEntryId: o.first,
    openSession: o.session === undefined || o.session === null ? null : sessionBytes(o.session), source: o.source ?? null,
  });
  return cat(header, entriesFrom(o.first, o.items));
}

function legacyImage(items: Item[]): Uint8Array {
  return cat(encodeFileHeader(JOURNAL_FRAMING, { generation: GEN_BYTES, createdMs: T0 }), entriesFrom(1, items));
}

/** Seals a header whose bytes were edited: the CRC at 124 covers 0..124. */
function reseal(header: Uint8Array): Uint8Array {
  const out = header.slice();
  new DataView(out.buffer).setUint32(124, crc32(out.subarray(0, 124)), true);
  return out;
}

/**
 * Two whole segments of one session that ends in a stop: ids 1..3 and 4..5. Segment 2's header carries the session
 * and source that were open when it started, as a roll writes them.
 */
function twoSegments(): Record<string, Uint8Array> {
  return {
    [segmentName(1)]: segImage({ first: 1, items: [startItem(S1, T0, SRC), dgItem(1, T0 + 1), dgItem(2, T0 + 2)] }),
    [segmentName(4)]: segImage({ first: 4, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] }),
  };
}

function bytesOf(dir: MemorySegmentDirectory, name: string): Uint8Array {
  const f = dir.file(name);
  const out = new Uint8Array(f.size());
  f.read(0, out);
  return out;
}

/** Every file's hash by name: equal before and after means nothing was touched. */
function fingerprint(dir: MemorySegmentDirectory): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of dir.list()) out[name] = sha(bytesOf(dir, name));
  return out;
}

function open(dir: SegmentDirectory, over: Partial<JournalOptions> = {}): MonitoringJournal {
  return MonitoringJournal.open(dir, options(over)).journal;
}

function readAll(j: MonitoringJournal): Evidence[] {
  const snap = j.snapshot();
  const out: Evidence[] = [];
  let after = snap.firstEntryId - 1;
  for (;;) {
    const page = j.readPage(snap, after, 256, MiB);
    out.push(...page.entries);
    if (page.done || page.entries.length === 0) return out;
    after = page.nextAfterId;
  }
}

const isBoundary = (e: Evidence): e is BoundaryEvidence => e.kind === 'boundary';
const isDatagram = (e: Evidence): e is DatagramEvidence => e.kind === 'datagram';

function dg(ms: number, payload: Uint8Array): EvidenceInput {
  return { kind: 'datagram', receivedMs: ms, localIPv4: '192.0.2.10', localPort: 2055, remoteIPv4: '192.0.2.1', remotePort: 50000, bytes: payload };
}
function bnd(action: BoundaryEvidence['action'], sessionId: string, ms: number, extra: Partial<BoundaryFields> = {}): EvidenceInput {
  return { kind: 'boundary', sessionId, receivedMs: ms, action, reason: '', droppedDatagrams: null, ...extra };
}
const bigPayload = (n: number): Uint8Array => new Uint8Array(60_000).fill(n & 255);

/** A journal with a session open and `count` 60 kB datagrams in it, so a 1 MiB segment holds about 17. */
function filled(count: number, over: Partial<JournalOptions> = {}): { dir: MemorySegmentDirectory; j: MonitoringJournal; inputs: EvidenceInput[] } {
  const dir = new MemorySegmentDirectory();
  const j = open(dir, over);
  const inputs: EvidenceInput[] = [bnd('start', S1, T0, { source: SRC })];
  for (let i = 0; i < count; i++) inputs.push(dg(T0 + 1 + i, bigPayload(i + 1)));
  const r = j.append(inputs);
  assert.equal(r.refused, 0, `the fill was refused (state ${r.state})`);
  return { dir, j, inputs };
}

// --- the header ------------------------------------------------------------------------------

const VECTOR_HEADER = `
49 4e 57 49 52 45 4d 4a 02 00 01 00 80 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 01 10 00 00 00 00 00 00 a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af
c0 00 02 01 c0 00 02 0a 07 08 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 cd e3 56 70`;

const vectorFields = () => ({
  policyVersion: 1, generation: Uint8Array.from({ length: 16 }, (_, i) => i), createdMs: 1_700_000_000_000, firstEntryId: 4097,
  openSession: Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i), source: SRC,
});

test('segment-header-vector: ADR 0062 header, byte for byte, and back', () => {
  const header = encodeSegmentHeader(vectorFields());
  assert.equal(header.length, SEGMENT_HEADER_BYTES);
  assert.equal(hex(header), hex(fromHex(VECTOR_HEADER)));
  const back = decodeSegmentHeader(header);
  assert.ok(back.ok);
  if (back.ok) {
    const f = vectorFields();
    assert.equal(back.value.formatVersion, 2);
    assert.equal(back.value.policyVersion, 1);
    assert.equal(hex(back.value.generation), hex(f.generation));
    assert.equal(back.value.createdMs, f.createdMs);
    assert.equal(back.value.firstEntryId, 4097);
    assert.equal(hex(back.value.openSession!), hex(f.openSession));
    assert.deepEqual(back.value.source, SRC);
  }
});

test('segment-header-vector: no session and no source encode as zeros with the flag clear', () => {
  const header = encodeSegmentHeader({ ...vectorFields(), openSession: null, source: null });
  assert.equal(header[74], 0);
  assert.ok(header.subarray(48, 74).every((b) => b === 0));
  const back = decodeSegmentHeader(header);
  assert.ok(back.ok);
  if (back.ok) {
    assert.equal(back.value.openSession, null);
    assert.equal(back.value.source, null);
  }
});

test('segment-header-vector: a bad CRC, a non-zero reserved byte, an unknown flag, a bad magic or length are refused', () => {
  const good = encodeSegmentHeader(vectorFields());
  const badCrc = good.slice();
  badCrc[124] ^= 1;
  assert.equal(decodeSegmentHeader(badCrc).ok, false);
  const reserved = good.slice();
  reserved[100] = 1;
  assert.equal(decodeSegmentHeader(reserved).ok, false, 'a reserved byte under a stale CRC');
  const resealed = reseal(reserved);
  const r = decodeSegmentHeader(resealed);
  assert.equal(r.ok, false, 'a reserved byte under a good CRC');
  if (!r.ok) assert.match(r.reason, /reserved/);
  const flagged = good.slice();
  flagged[74] = 3;
  const f = decodeSegmentHeader(reseal(flagged));
  assert.equal(f.ok, false);
  if (!f.ok) assert.match(f.reason, /flag/);
  const magic = good.slice();
  magic[0] = 0x58;
  assert.equal(decodeSegmentHeader(reseal(magic)).ok, false);
  const length = good.slice();
  length[12] = 0x40;
  assert.equal(decodeSegmentHeader(reseal(length)).ok, false);
  assert.equal(decodeSegmentHeader(good.subarray(0, 127)).ok, false);
});

test('names and sizes: segmentName pads to 12 digits and grows past them; segmentBytesFor clamps a 32nd of the limit', () => {
  assert.equal(segmentName(1), 'journal-000000000001.iwmj');
  assert.equal(segmentName(4097), 'journal-000000004097.iwmj');
  assert.equal(segmentName(1_234_567_890_123), 'journal-1234567890123.iwmj');
  assert.throws(() => segmentName(0), RangeError);
  assert.ok(isSegmentFileName(segmentName(7)) && isSegmentFileName(LEGACY_JOURNAL_NAME));
  assert.ok(!isSegmentFileName('journal-1.iwmj') && !isSegmentFileName('rollups.iwmr') && !isSegmentFileName('journal.iwmj.bak'));
  assert.equal(segmentBytesFor(1 * MiB), 1 * MiB);
  assert.equal(segmentBytesFor(16 * MiB), 1 * MiB);
  assert.equal(segmentBytesFor(64 * MiB), 2 * MiB);
  assert.equal(segmentBytesFor(8 * 1024 * MiB), 256 * MiB);
  assert.equal(segmentBytesFor(1024 * 1024 * MiB), 256 * MiB);
});

test('expired-vector: ADR 0062 entry 4200, body and entry header, from the journal\'s own boundary encoder', () => {
  const body = encodeBoundaryBody({
    action: 'expired', sessionId: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf', receivedMs: 1_700_000_600_000, reason: 'age', droppedDatagrams: null,
    source: SRC, expired: { fromEntryId: 1, throughEntryId: 4096, fromMs: 1_700_000_000_123, throughMs: 1_700_000_599_000 },
  });
  assert.equal(
    new TextDecoder().decode(body),
    '{"action":"expired","sessionId":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","receivedMs":1700000600000,"fromEntryId":1,"throughEntryId":4096,'
      + '"fromMs":1700000000123,"throughMs":1700000599000,"reason":"age","source":{"exporterIPv4":"192.0.2.1","bindIPv4":"192.0.2.10","port":2055}}',
  );
  const entry = encodeEntry(JOURNAL_FRAMING, 4200, KIND_BOUNDARY, body);
  assert.equal(hex(entry.subarray(0, 24)), '49 57 4a 45 0e 01 00 00 68 10 00 00 00 00 00 00 02 00 00 00 3e d6 c9 2a');
});

test('boundary bodies: a start with a source ends in it, one without is the old body exactly', () => {
  const plain = encodeBoundaryBody({ action: 'start', sessionId: S1, receivedMs: 5, reason: '', droppedDatagrams: null });
  assert.equal(new TextDecoder().decode(plain), `{"action":"start","sessionId":"${S1}","receivedMs":5,"reason":"","droppedDatagrams":null}`);
  const withSource = encodeBoundaryBody({ action: 'start', sessionId: S1, receivedMs: 5, reason: '', droppedDatagrams: null, source: SRC });
  assert.equal(
    new TextDecoder().decode(withSource),
    `{"action":"start","sessionId":"${S1}","receivedMs":5,"reason":"","droppedDatagrams":null,`
      + '"source":{"exporterIPv4":"192.0.2.1","bindIPv4":"192.0.2.10","port":2055}}',
  );
});

// --- legacy ----------------------------------------------------------------------------------

const CLOSED_LEGACY = (): Item[] => [startItem(S1, T0), dgItem(1, T0 + 1), stopItem(S1, T0 + 2)];

test('legacy-as-first-segment: a closed milestone-1 journal.iwmj opens with policy 1, is never renamed and gains no file', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage(CLOSED_LEGACY()) });
  const before = fingerprint(dir);
  const { journal, recovery } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'open');
  assert.deepEqual(dir.list(), [LEGACY_JOURNAL_NAME]);
  assert.deepEqual(fingerprint(dir), before);
  assert.equal(recovery.status, 'ok');
  assert.deepEqual(recovery.policies, [1]);
  const info = journal.segments();
  assert.equal(info.length, 1);
  assert.equal(info[0].name, LEGACY_JOURNAL_NAME);
  assert.equal(info[0].firstEntryId, 1);
  assert.equal(info[0].lastEntryId, 3);
  assert.equal(info[0].policyVersion, 1);
  assert.equal(info[0].sealed, true, 'a legacy file is never appended to');
  assert.equal(readAll(journal).length, 3);
  assert.equal(journal.snapshot().firstEntryId, 1);
});

test('legacy-sealed: the first append creates journal-<n> and leaves journal.iwmj byte-identical', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage(CLOSED_LEGACY()) });
  const legacy = sha(bytesOf(dir, LEGACY_JOURNAL_NAME));
  const j = open(dir);
  const r = j.append([bnd('start', S2, T0 + 10, { source: SRC }), dg(T0 + 11, Uint8Array.from([9, 9]))]);
  assert.equal(r.appended, 2);
  assert.deepEqual(dir.list(), [segmentName(4), LEGACY_JOURNAL_NAME].sort());
  assert.equal(sha(bytesOf(dir, LEGACY_JOURNAL_NAME)), legacy);
  const info = j.segments();
  assert.deepEqual(info.map((s) => s.name), [LEGACY_JOURNAL_NAME, segmentName(4)]);
  assert.equal(info[1].firstEntryId, 4);
  assert.equal(info[1].sealed, false);
  const header = decodeSegmentHeader(bytesOf(dir, segmentName(4)));
  assert.ok(header.ok);
  if (header.ok) {
    assert.equal(header.value.formatVersion, 2);
    assert.equal(header.value.firstEntryId, 4);
    assert.equal(header.value.openSession, null, 'the legacy session was stopped, so the roll names none');
    assert.equal(Buffer.from(header.value.generation).toString('hex'), GEN, 'the dataset keeps its generation');
  }
  const all = readAll(j);
  assert.deepEqual(all.map((e) => e.ref.entryId), [1, 2, 3, 4, 5]);
  assert.equal(all.filter(isDatagram)[1].sessionId, S2);
  // A restart sees the same dataset.
  const again = open(dir);
  assert.equal(again.state, 'open');
  assert.deepEqual(readAll(again).map((e) => e.ref.entryId).slice(0, 5), [1, 2, 3, 4, 5]);
});

test('legacy with an open session: its interrupted goes into a new segment whose header names no session; journal.iwmj stays identical', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage([startItem(S1, T0), dgItem(1, T0 + 1)]) });
  const legacy = sha(bytesOf(dir, LEGACY_JOURNAL_NAME));
  const j = open(dir);
  assert.equal(j.state, 'open', j.problem ?? '');
  assert.equal(sha(bytesOf(dir, LEGACY_JOURNAL_NAME)), legacy);
  assert.deepEqual(dir.list(), [segmentName(3), LEGACY_JOURNAL_NAME].sort());
  const header = decodeSegmentHeader(bytesOf(dir, segmentName(3)));
  assert.ok(header.ok);
  if (header.ok) assert.equal(header.value.openSession, null);
  const last = j.lastBoundary();
  assert.equal(last?.action, 'interrupted');
  assert.equal(last?.sessionId, S1);
  assert.equal(last?.ref.entryId, 3);
  // Reading it back is accepted: no session in the header, and the first entry is the interrupted that closes S1.
  const again = MonitoringJournal.open(dir, options());
  assert.equal(again.journal.state, 'open', again.journal.problem ?? '');
  assert.equal(again.recovery.status, 'ok');
  assert.equal(again.journal.segments().length, 2);
});

test('legacy with an open session that is not 32 hex: the roll it needs fails literally, naming the id', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage([startItem('S1', T0), dgItem(1, T0 + 1)]) });
  const legacy = sha(bytesOf(dir, LEGACY_JOURNAL_NAME));
  const j = open(dir);
  assert.equal(j.state, 'failed');
  assert.match(j.problem ?? '', /S1/);
  assert.equal(sha(bytesOf(dir, LEGACY_JOURNAL_NAME)), legacy);
  assert.deepEqual(dir.list(), [LEGACY_JOURNAL_NAME], 'no file was invented for it');
  assert.equal(j.append([bnd('start', S2, T0 + 5)]).appended, 0);
});

test('legacy torn header: a lone journal.iwmj with a partial header is ignored, left on disk, and a segment begins beside it', () => {
  const full = legacyImage(CLOSED_LEGACY());
  const torn = full.slice(0, 40);
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: torn });
  const before = sha(bytesOf(dir, LEGACY_JOURNAL_NAME));
  assert.equal(recoverJournal(dir).status, 'empty');
  const j = open(dir);
  assert.equal(j.state, 'open');
  assert.equal(sha(bytesOf(dir, LEGACY_JOURNAL_NAME)), before);
  assert.ok(dir.list().includes(segmentName(1)));
  assert.equal(j.segments().length, 1);
  assert.equal(j.segments()[0].name, segmentName(1));
});

test('legacy-only drop: the expired boundary rolls first, then journal.iwmj goes in the same call', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage(CLOSED_LEGACY()) });
  const j = open(dir);
  const r = j.dropSegments([LEGACY_JOURNAL_NAME], 'age', T0 + 1000);
  assert.equal(r.appended, 1, `state ${r.state}; ${j.problem ?? ''}`);
  assert.equal(r.refused, 0);
  assert.equal(r.state, 'open');
  assert.deepEqual(dir.list(), [segmentName(4)]);
  const info = j.segments();
  assert.equal(info.length, 1);
  assert.equal(info[0].firstEntryId, 4);
  assert.equal(j.snapshot().firstEntryId, 4);
  const expired = j.lastBoundary();
  assert.equal(expired?.action, 'expired');
  assert.equal(expired?.reason, 'age');
  assert.deepEqual(expired?.expired, { fromEntryId: 1, throughEntryId: 3, fromMs: T0, throughMs: T0 + 2 });
  assert.equal(expired?.receivedMs, T0 + 1000);
  // The one segment starts exactly where the cut ends; a restart that knows the cut accepts it.
  const again = open(dir, { lastCutThroughEntryId: 3 });
  assert.equal(again.state, 'open', again.problem ?? '');
  assert.equal(again.lastBoundary()?.action, 'expired');
});

test('legacy dropped beside a newer segment is allowed without a second roll', () => {
  const dir = new MemorySegmentDirectory({ [LEGACY_JOURNAL_NAME]: legacyImage(CLOSED_LEGACY()) });
  const j = open(dir);
  j.append([bnd('start', S2, T0 + 10, { source: SRC }), bnd('stop', S2, T0 + 11, { reason: 'user' })]);
  assert.equal(j.segments().length, 2);
  const r = j.dropSegments([LEGACY_JOURNAL_NAME], 'user-before', T0 + 2000);
  assert.equal(r.appended, 1, `state ${r.state}`);
  assert.equal(dir.list().includes(LEGACY_JOURNAL_NAME), false);
  assert.equal(j.segments()[0].name, segmentName(4));
});

// --- accepted policies and the shape of a dataset --------------------------------------------

test('accepted-policies: only policy 1 is accepted today', () => {
  assert.deepEqual([...ACCEPTED_POLICIES], [1]);
});

test('accepted-policies: a policy-3 segment is refused-version with every file byte-identical; policy 1 opens', () => {
  const files = twoSegments();
  files[segmentName(4)] = segImage({ first: 4, policy: 3, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] });
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  const rec = recoverJournal(dir);
  assert.equal(rec.status, 'unknown-version');
  assert.ok(rec.policies.includes(3));
  const { journal } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'refused-version');
  assert.deepEqual(fingerprint(dir), before);
  assert.equal(journal.append([bnd('start', S2, T0 + 9)]).appended, 0);
  assert.deepEqual(fingerprint(dir), before);

  const ok = new MemorySegmentDirectory(twoSegments());
  assert.equal(open(ok).state, 'open');
});

test('accepted-policies: a policy-3 first segment is refused even where the second is fine', () => {
  const files = twoSegments();
  files[segmentName(1)] = segImage({ first: 1, policy: 3, items: [startItem(S1, T0, SRC), dgItem(1, T0 + 1), dgItem(2, T0 + 2)] });
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  assert.equal(open(dir).state, 'refused-version');
  assert.deepEqual(fingerprint(dir), before);
});

test('accepted-policies: a segment of an unknown format is refused-version, untouched', () => {
  const files = twoSegments();
  const image = files[segmentName(4)].slice();
  image.set(reseal(Uint8Array.from([...image.subarray(0, SEGMENT_HEADER_BYTES)].map((b, i) => (i === 8 ? 7 : b)))), 0);
  files[segmentName(4)] = image;
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  assert.equal(open(dir).state, 'refused-version');
  assert.deepEqual(fingerprint(dir), before);
});

test('a valid hand-built dataset of two segments opens, reads straight through, and appends to the second', () => {
  const dir = new MemorySegmentDirectory(twoSegments());
  const { journal, recovery } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'open', journal.problem ?? '');
  assert.equal(recovery.status, 'ok');
  assert.deepEqual(recovery.segments.map((s) => [s.firstEntryId, s.lastEntryId]), [[1, 3], [4, 5]]);
  const all = readAll(journal);
  assert.deepEqual(all.map((e) => e.ref.entryId), [1, 2, 3, 4, 5]);
  assert.deepEqual(all.filter(isDatagram).map((d) => d.sessionId), [S1, S1, S1]);
  assert.equal(Buffer.from(journal.snapshot().generation, 'hex').length, 16);
});

test('id-gap: a segment that does not start at the previous one\'s last id + 1 is refused-corrupt, every file untouched', () => {
  const files = twoSegments();
  files[segmentName(4)] = segImage({ first: 6, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] });
  delete files[segmentName(4)];
  files[segmentName(6)] = segImage({ first: 6, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] });
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  const rec = recoverJournal(dir);
  assert.equal(rec.status, 'corrupt');
  assert.match(rec.problem ?? '', /\b6\b/);
  const { journal } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);
  assert.equal(journal.append([bnd('start', S2, T0 + 9)]).appended, 0);
  assert.deepEqual(fingerprint(dir), before);
});

test('id-gap: a segment that overlaps the previous one is refused-corrupt too', () => {
  const files = twoSegments();
  delete files[segmentName(4)];
  files[segmentName(3)] = segImage({ first: 3, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] });
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  assert.equal(open(dir).state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);
});

test('generation-mismatch: segments of two generations are refused-corrupt, every file untouched', () => {
  const files = twoSegments();
  files[segmentName(4)] = segImage({ first: 4, gen: OTHER_GEN, session: S1, source: SRC, items: [dgItem(3, T0 + 3), stopItem(S1, T0 + 4)] });
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  assert.equal(recoverJournal(dir).status, 'corrupt');
  const { journal } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'refused-corrupt');
  assert.match(journal.problem ?? '', /generation/i);
  assert.deepEqual(fingerprint(dir), before);
});

test('generation-mismatch: a legacy file of another generation than the segment after it is refused-corrupt', () => {
  const legacy = cat(encodeFileHeader(JOURNAL_FRAMING, { generation: OTHER_GEN, createdMs: T0 }), entriesFrom(1, CLOSED_LEGACY()));
  const dir = new MemorySegmentDirectory({
    [LEGACY_JOURNAL_NAME]: legacy,
    [segmentName(4)]: segImage({ first: 4, items: [startItem(S2, T0 + 10, SRC), stopItem(S2, T0 + 11)] }),
  });
  const before = fingerprint(dir);
  assert.equal(open(dir).state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);
});

test('torn-tail: the newest segment\'s partial last entry is truncated and the rest is kept', () => {
  const files = twoSegments();
  const good = files[segmentName(4)];
  files[segmentName(4)] = cat(good, itemBytes(6, dgItem(9, T0 + 9)).subarray(0, 30));
  const dir = new MemorySegmentDirectory(files);
  const olderBefore = sha(bytesOf(dir, segmentName(1)));
  const rec = recoverJournal(dir);
  assert.equal(rec.status, 'ok');
  assert.ok(rec.tornTail !== null);
  assert.equal(bytesOf(dir, segmentName(4)).length, good.length + 30, 'recoverJournal changes nothing');
  const j = open(dir);
  assert.equal(j.state, 'open');
  assert.equal(bytesOf(dir, segmentName(4)).length, good.length, 'the open cut the tail');
  assert.equal(sha(bytesOf(dir, segmentName(1))), olderBefore, 'and touched no older segment');
  assert.equal(readAll(j).length, 5);
});

test('torn-tail: a torn tail on a segment that is not the newest is corruption, every file untouched', () => {
  const files = twoSegments();
  files[segmentName(1)] = cat(files[segmentName(1)], itemBytes(4, dgItem(9, T0 + 9)).subarray(0, 30));
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  const rec = recoverJournal(dir);
  assert.equal(rec.status, 'corrupt');
  const { journal } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);
});

test('torn-roll: a newest segment holding a header and no entry is unlinked and the previous one carries on', () => {
  const files = twoSegments();
  files[segmentName(6)] = encodeSegmentHeader({
    policyVersion: 1, generation: GEN_BYTES, createdMs: T0 + 50, firstEntryId: 6, openSession: null, source: null,
  });
  const dir = new MemorySegmentDirectory(files);
  const rec = recoverJournal(dir);
  assert.equal(rec.status, 'ok');
  assert.equal(rec.tornRoll, segmentName(6));
  assert.ok(dir.list().includes(segmentName(6)), 'recoverJournal does not unlink');
  const j = open(dir);
  assert.equal(j.state, 'open', j.problem ?? '');
  assert.deepEqual(dir.list(), [segmentName(1), segmentName(4)]);
  assert.equal(j.segments()[1].sealed, false);
  const r = j.append([bnd('start', S2, T0 + 60, { source: SRC })]);
  assert.equal(r.appended, 1);
  assert.equal(j.snapshot().throughEntryId, 6);
});

test('torn-roll: a newest segment with a partial header is removed the same way', () => {
  const files = twoSegments();
  files[segmentName(6)] = encodeSegmentHeader({
    policyVersion: 1, generation: GEN_BYTES, createdMs: T0 + 50, firstEntryId: 6, openSession: null, source: null,
  }).slice(0, 77);
  const dir = new MemorySegmentDirectory(files);
  const j = open(dir);
  assert.equal(j.state, 'open', j.problem ?? '');
  assert.deepEqual(dir.list(), [segmentName(1), segmentName(4)]);
});

test('torn-roll: a lone segment with a torn header is a new dataset, written under the name it will hold', () => {
  const dir = new MemorySegmentDirectory({ [segmentName(1)]: encodeSegmentHeader({
    policyVersion: 1, generation: OTHER_GEN, createdMs: T0, firstEntryId: 1, openSession: null, source: null,
  }).slice(0, 60) });
  const j = open(dir);
  assert.equal(j.state, 'open', j.problem ?? '');
  assert.deepEqual(dir.list(), [segmentName(1)]);
  assert.equal(bytesOf(dir, segmentName(1)).length, SEGMENT_HEADER_BYTES);
  assert.equal(Buffer.from(bytesOf(dir, segmentName(1)).subarray(16, 32)).toString('hex'), GEN);
});

test('leading-gap: the oldest segment must start at 1 or right after the archive cut', () => {
  const files = { [segmentName(5)]: segImage({ first: 5, session: S1, source: SRC, items: [dgItem(1, T0 + 5), stopItem(S1, T0 + 6)] }) };
  const dir = new MemorySegmentDirectory(files);
  const before = fingerprint(dir);
  const { journal, recovery } = MonitoringJournal.open(dir, options());
  assert.equal(recovery.status, 'corrupt');
  assert.equal(journal.state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);
  const wrongCut = MonitoringJournal.open(dir, options({ lastCutThroughEntryId: 3 }));
  assert.equal(wrongCut.journal.state, 'refused-corrupt');
  assert.deepEqual(fingerprint(dir), before);

  const cut = MonitoringJournal.open(dir, options({ lastCutThroughEntryId: 4 }));
  assert.equal(cut.journal.state, 'open', cut.journal.problem ?? '');
  assert.equal(cut.journal.snapshot().firstEntryId, 5);
  const all = readAll(cut.journal);
  assert.deepEqual(all.map((e) => e.ref.entryId), [5, 6]);
  assert.equal((all[0] as DatagramEvidence).sessionId, S1, 'the header seeds the session its predecessors held');
});

test('empty directory: open creates journal-000000000001.iwmj with a format-2 header, policy 1, a new generation and no session', () => {
  const dir = new MemorySegmentDirectory();
  const { journal, recovery } = MonitoringJournal.open(dir, options());
  assert.equal(journal.state, 'open');
  assert.equal(recovery.status, 'empty');
  assert.deepEqual(dir.list(), [segmentName(1)]);
  const header = decodeSegmentHeader(bytesOf(dir, segmentName(1)));
  assert.ok(header.ok);
  if (header.ok) {
    assert.equal(header.value.formatVersion, 2);
    assert.equal(header.value.policyVersion, 1);
    assert.equal(header.value.firstEntryId, 1);
    assert.equal(header.value.openSession, null);
    assert.equal(header.value.source, null);
    assert.equal(Buffer.from(header.value.generation).toString('hex'), GEN);
  }
});

// --- rolling ---------------------------------------------------------------------------------

test('roll: an append past the segment size starts the next segment; ids run on and readback is equal across the boundary', () => {
  const { dir, j, inputs } = filled(40);
  const info = j.segments();
  assert.ok(info.length >= 3, `40 x 60 kB in 1 MiB segments (got ${info.length})`);
  assert.equal(info[0].firstEntryId, 1);
  for (let i = 1; i < info.length; i++) {
    assert.equal(info[i].firstEntryId, info[i - 1].lastEntryId + 1);
    assert.equal(info[i - 1].sealed, true);
    assert.ok(info[i - 1].bytes <= segmentBytesFor(32 * MiB), 'a segment never grows past its size');
  }
  assert.equal(info[info.length - 1].sealed, false);
  assert.deepEqual(dir.list(), info.map((s) => s.name));
  assert.deepEqual(info.map((s) => segmentName(s.firstEntryId)), info.map((s) => s.name));

  const header = decodeSegmentHeader(bytesOf(dir, info[1].name));
  assert.ok(header.ok);
  if (header.ok) {
    assert.equal(header.value.firstEntryId, info[1].firstEntryId);
    assert.equal(hex(header.value.openSession!), hex(sessionBytes(S1)), 'the roll names the open session');
    assert.deepEqual(header.value.source, SRC, 'and the source it recorded');
    assert.equal(Buffer.from(header.value.generation).toString('hex'), GEN);
  }

  const all = readAll(j);
  assert.equal(all.length, inputs.length);
  all.forEach((e, i) => {
    assert.equal(e.ref.entryId, i + 1);
    const want = inputs[i];
    if (isDatagram(e) && want.kind === 'datagram') {
      assert.equal(e.sessionId, S1);
      assert.equal(hex(e.bytes.subarray(0, 4)), hex(want.bytes.subarray(0, 4)));
      assert.equal(e.bytes.length, want.bytes.length);
      assert.equal(e.receivedMs, want.receivedMs);
    }
  });
  const across = info[0].lastEntryId;
  const a = j.readEvidence({ generation: j.snapshot().generation, entryId: across });
  const b = j.readEvidence({ generation: j.snapshot().generation, entryId: across + 1 });
  assert.equal(a?.ref.entryId, across);
  assert.equal(b?.ref.entryId, across + 1);
  assert.equal(b?.kind, 'datagram');
  assert.equal((b as DatagramEvidence).sessionId, S1);
  // A page that starts on the last entry of one segment runs over into the next.
  const page = j.readPage(j.snapshot(), across - 1, 3, MiB);
  assert.deepEqual(page.entries.map((e) => e.ref.entryId), [across, across + 1, across + 2]);
  // And a restart finds the same dataset.
  const again = open(dir);
  assert.equal(again.state, 'open', again.problem ?? '');
  assert.equal(readAll(again).slice(0, inputs.length).length, inputs.length);
});

test('roll: locate and the boundary list see across segments', () => {
  const { j } = filled(40);
  const snap = j.snapshot();
  const ranges = j.locate(snap, T0 + 1, T0 + 40);
  assert.ok(ranges.length > 0);
  assert.ok(ranges[0].fromId <= 2, 'a range may start earlier than the first entry in the window, never later');
  assert.equal(ranges[ranges.length - 1].toId, snap.throughEntryId);
  const boundaries = j.readBoundaries(snap, 0, 64);
  assert.equal(boundaries.entries.length, 1);
  assert.equal(boundaries.entries[0].action, 'start');
  assert.deepEqual(boundaries.entries[0].source, SRC);
});

test('roll-size: a segment is as large as the limit at its creation said; setLimit changes only later ones', () => {
  const dir = new MemorySegmentDirectory();
  const j = open(dir, { limitBytes: 32 * MiB });
  j.setLimit(256 * MiB);
  const inputs: EvidenceInput[] = [bnd('start', S1, T0, { source: SRC })];
  for (let i = 0; i < 220; i++) inputs.push(dg(T0 + 1 + i, bigPayload(i)));
  assert.equal(j.append(inputs).refused, 0);
  const info = j.segments();
  assert.ok(info.length >= 3, `got ${info.length}`);
  assert.ok(info[0].bytes <= 1 * MiB, `the first segment keeps the size 32 MiB gave it (${info[0].bytes})`);
  assert.ok(info[0].bytes > 1 * MiB - 120 * KiB, 'and was filled to it');
  assert.ok(info[1].bytes > 7 * MiB && info[1].bytes <= 8 * MiB, `the second takes 256 MiB / 32 = 8 MiB (${info[1].bytes})`);
});

test('roll-size: after a reopen the open segment\'s size comes from the limit at open', () => {
  const dir = new MemorySegmentDirectory();
  const j = open(dir, { limitBytes: 256 * MiB });
  const inputs: EvidenceInput[] = [bnd('start', S1, T0, { source: SRC })];
  for (let i = 0; i < 40; i++) inputs.push(dg(T0 + 1 + i, bigPayload(i)));
  inputs.push(bnd('stop', S1, T0 + 100, { reason: 'user' }));
  assert.equal(j.append(inputs).refused, 0);
  assert.equal(j.segments().length, 1, 'about 2.4 MB fits one 8 MiB segment');
  j.close();
  const again = open(dir, { limitBytes: 32 * MiB });
  const r = again.append([bnd('start', S2, T0 + 200, { source: SRC })]);
  assert.equal(r.appended, 1);
  assert.equal(again.segments().length, 2, 'the old newest is already past 1 MiB, so the next append starts a segment');
  assert.equal(again.segments()[0].sealed, true);
});

test('start-session-id: a start whose id is not 32 lowercase hex digits is refused and writes nothing', () => {
  const dir = new MemorySegmentDirectory();
  const j = open(dir);
  const size = bytesOf(dir, segmentName(1)).length;
  for (const bad of ['S1', 'session-1', '', 'ab'.repeat(16).toUpperCase(), S1.slice(1), `${S1}0`, 'g'.repeat(32)]) {
    const r = j.append([bnd('start', bad, T0)]);
    assert.equal(r.appended, 0, `"${bad}" was accepted`);
    assert.equal(r.refused, 1);
    assert.equal(r.snapshot.throughEntryId, 0);
  }
  assert.equal(bytesOf(dir, segmentName(1)).length, size);
  assert.equal(j.state, 'open', 'a refused input does not stop the journal');
  const badSource = j.append([bnd('start', S1, T0, { source: { exporterIPv4: '999.1.1.1', bindIPv4: '192.0.2.10', port: 2055 } })]);
  assert.equal(badSource.appended, 0);
  assert.equal(bytesOf(dir, segmentName(1)).length, size);
  assert.equal(j.append([bnd('start', S1, T0, { source: SRC })]).appended, 1);
});

// --- sessions and retention ------------------------------------------------------------------

test('session-across-segments: the second segment\'s header names the session and its source; its datagrams survive dropping the first', () => {
  const { dir, j } = filled(40);
  const info = j.segments();
  const first = info[0];
  const header = decodeSegmentHeader(bytesOf(dir, info[1].name));
  assert.ok(header.ok);
  if (header.ok) {
    assert.equal(hex(header.value.openSession!), hex(sessionBytes(S1)));
    assert.deepEqual(header.value.source, SRC);
  }
  const r = j.dropSegments([first.name], 'age', T0 + 5000);
  assert.equal(r.appended, 1, `state ${r.state}; ${j.problem ?? ''}`);
  assert.equal(dir.list().includes(first.name), false);
  j.close();

  // The oldest retained segment now starts after the cut, so a restart with no cut sees a hole...
  const blind = MonitoringJournal.open(dir, options());
  assert.equal(blind.journal.state, 'open', 'an expired boundary in the dataset explains the hole');
  // ...and one told where the cut was reads it the same way.
  const again = open(dir, { lastCutThroughEntryId: first.lastEntryId });
  assert.equal(again.state, 'open', again.problem ?? '');
  assert.equal(again.snapshot().firstEntryId, first.lastEntryId + 1);
  const datagrams = readAll(again).filter(isDatagram);
  assert.ok(datagrams.length > 0);
  assert.ok(datagrams.every((d) => d.sessionId === S1), 'still the session the dropped segment opened');
  assert.deepEqual(again.segments()[0].firstEntryId, first.lastEntryId + 1);
});

test('drop-segments: refuses the open segment, an unlisted name, a non-prefix, an unordered and an empty list, and writes nothing', () => {
  const { dir, j } = filled(40);
  const info = j.segments();
  assert.ok(info.length >= 3);
  const before = fingerprint(dir);
  const through = j.snapshot().throughEntryId;
  const refusals: string[][] = [
    [info[info.length - 1].name],
    [info[0].name, info[1].name, ...info.slice(2).map((s) => s.name)],
    [info[1].name],
    [info[1].name, info[0].name],
    ['journal-000000999999.iwmj'],
    [],
  ];
  for (const names of refusals) {
    const r = j.dropSegments(names, 'age', T0 + 9000);
    assert.equal(r.appended, 0, JSON.stringify(names));
    assert.equal(r.refused, 1);
    assert.equal(j.snapshot().throughEntryId, through);
    assert.deepEqual(fingerprint(dir), before, JSON.stringify(names));
  }
  assert.equal(j.dropSegments([info[0].name], 'bad' as 'age', T0).refused, 1);
  assert.equal(j.state, 'open');
});

test('drop-segments: the expired boundary carries the dropped ids, times and source, then the files go and the ids are gone', () => {
  const { dir, j } = filled(40);
  const generation = j.snapshot().generation;
  const info = j.segments();
  const names = [info[0].name, info[1].name];
  const lastDropped = info[1];
  const sizeBefore = j.snapshot().writtenBytes;
  const droppedBytes = info[0].bytes + info[1].bytes;
  const r = j.dropSegments(names, 'limit', T0 + 7000);
  assert.equal(r.appended, 1);
  assert.equal(r.refused, 0);
  assert.equal(r.state, 'open');
  for (const n of names) assert.equal(dir.list().includes(n), false);

  const expired = j.lastBoundary()!;
  assert.equal(expired.action, 'expired');
  assert.equal(expired.reason, 'limit');
  assert.equal(expired.sessionId, S1, 'the open session');
  assert.equal(expired.receivedMs, T0 + 7000);
  assert.deepEqual(expired.source, SRC);
  assert.deepEqual(expired.expired, { fromEntryId: 1, throughEntryId: lastDropped.lastEntryId, fromMs: T0, throughMs: lastDropped.lastReceivedMs });
  assert.equal(expired.ref.entryId, r.snapshot.throughEntryId);
  assert.equal(expired.ref.entryId > info[info.length - 1].lastEntryId, true, 'appended after everything');

  const snap = j.snapshot();
  assert.equal(snap.firstEntryId, lastDropped.lastEntryId + 1);
  assert.ok(snap.writtenBytes < sizeBefore - droppedBytes + 2 * KiB, 'the limit no longer counts the dropped bytes');
  assert.equal(j.readEvidence({ generation, entryId: 1 }), null);
  assert.equal(j.readEvidence({ generation, entryId: lastDropped.lastEntryId }), null);
  assert.ok(j.readEvidence({ generation, entryId: lastDropped.lastEntryId + 1 }) !== null);
  assert.throws(() => j.readPage(snap, 0, 10, MiB), (e: unknown) => e instanceof ExpiredRangeError && e.firstRetainedEntryId === lastDropped.lastEntryId + 1);
  assert.throws(() => j.readPage(snap, lastDropped.lastEntryId - 1, 10, MiB), ExpiredRangeError);
  assert.equal(j.readPage(snap, lastDropped.lastEntryId, 3, MiB).entries[0].ref.entryId, lastDropped.lastEntryId + 1, 'the first retained id is the first readable');
  assert.throws(() => j.readBoundaries(snap, 0, 64), ExpiredRangeError);
  const kept = j.readBoundaries(snap, lastDropped.lastEntryId, 64);
  assert.deepEqual(kept.entries.map((b) => b.action), ['expired']);

  // It is only a boundary: the open session goes on.
  const next = j.append([dg(T0 + 8000, Uint8Array.from([1]))]);
  assert.equal(next.appended, 1);
  const last = readAll(j).filter(isDatagram).pop()!;
  assert.equal(last.sessionId, S1);
});

test('drop-segments: at the storage limit a drop makes room, and setLimit says so', () => {
  const dir = new MemorySegmentDirectory();
  const j = open(dir, { limitBytes: 32 * MiB });
  j.append([bnd('start', S1, T0, { source: SRC })]);
  let n = 0;
  while (j.state === 'open' && n < 2000) { j.append([dg(T0 + 1 + n, bigPayload(n))]); n++; }
  assert.equal(j.state, 'storage-limit');
  const names = j.segments().slice(0, 4).map((s) => s.name);
  const r = j.dropSegments(names, 'limit', T0 + 90_000);
  assert.equal(r.appended, 1, `state ${r.state}; ${j.problem ?? ''}`);
  assert.equal(j.state, 'storage-limit', 'a drop alone does not reopen the journal');
  j.setLimit(32 * MiB);
  assert.equal(j.state, 'open');
  // The storage-limit stop closed the session, so the next thing is a start.
  assert.equal(j.append([bnd('start', S2, T0 + 91_000, { source: SRC }), dg(T0 + 91_001, bigPayload(1))]).appended, 2);
});

test('drop-interrupted: a crash between the expired boundary and the unlinks is finished by the next open, with no second expired', () => {
  class FlakyDir implements SegmentDirectory {
    failUnlinks = 1;
    constructor(readonly inner: MemorySegmentDirectory) {}
    list(): string[] { return this.inner.list(); }
    open(name: string): BlockFile { return this.inner.open(name); }
    create(name: string): BlockFile { return this.inner.create(name); }
    unlink(name: string): void {
      if (this.failUnlinks > 0) { this.failUnlinks--; throw new Error('EBUSY: resource busy or locked'); }
      this.inner.unlink(name);
    }
  }
  const { dir: base, j: seedJournal } = filled(40);
  seedJournal.close();
  const info = seedJournal.segments();
  const flaky = new FlakyDir(base);
  const j = open(flaky);
  const victim = info[0];
  const r = j.dropSegments([victim.name], 'age', T0 + 7000);
  assert.equal(r.appended, 1, 'the boundary was written');
  assert.equal(j.state, 'failed');
  assert.match(j.problem ?? '', /could not remove/);
  assert.ok(base.list().includes(victim.name), 'the segment is still there');
  const before = fingerprint(base);

  // A read-only look reports it and touches nothing.
  const rec = recoverJournal(base);
  assert.deepEqual(rec.pendingUnlink, [victim.name]);
  assert.deepEqual(fingerprint(base), before);

  // The next open finishes the job.
  const again = open(base);
  assert.equal(again.state, 'open', again.problem ?? '');
  assert.equal(base.list().includes(victim.name), false, 'the interrupted drop was completed');
  assert.equal(again.snapshot().firstEntryId, victim.lastEntryId + 1);
  const expired = readAll(again).filter(isBoundary).filter((b) => b.action === 'expired');
  assert.equal(expired.length, 1, 'and not repeated');
  assert.equal(expired[0].expired?.throughEntryId, victim.lastEntryId);

  // After it, the dataset is whole: opening again changes nothing and still holds one expired.
  const after = fingerprint(base);
  const third = open(base);
  assert.equal(third.state, 'open');
  assert.deepEqual(readAll(third).filter(isBoundary).filter((b) => b.action === 'expired').length, 1);
  assert.equal(Object.keys(fingerprint(base)).length, Object.keys(after).length);
});

// --- source keys -----------------------------------------------------------------------------

test('source keys: the three forms, and a v5 key is still sourceKey', () => {
  assert.equal(sourceKeyFor('v5', '192.0.2.1', 0, 1), '192.0.2.1/0/1');
  assert.equal(sourceKeyFor('v9', '192.0.2.1', 7), 'v9:192.0.2.1/7');
  assert.equal(sourceKeyFor('ipfix', '192.0.2.1', 3), 'ipfix:192.0.2.1/3');
  assert.equal(parseSourceKey('ipfix:192.0.2.1/3')?.protocol, 'ipfix');
  assert.equal(sourceKeyFor('v5', '10.0.0.1', 255, 255), sourceKey('10.0.0.1', 255, 255));
  assert.equal(v5SourceKey, sourceKey, 'v5.ts re-exports the one function');
});

test('source keys: every form parses back to what made it', () => {
  const cases: [Parameters<typeof sourceKeyFor>, string][] = [
    [['v5', '192.0.2.1', 0, 0], 'v5'], [['v5', '10.1.2.3', 255, 17], 'v5'],
    [['v9', '192.0.2.1', 0], 'v9'], [['v9', '203.0.113.9', 4_294_967_295], 'v9'],
    [['ipfix', '198.51.100.7', 12345], 'ipfix'],
  ];
  for (const [args, protocol] of cases) {
    const key = sourceKeyFor(...args);
    const parsed = parseSourceKey(key);
    assert.ok(parsed !== null, key);
    assert.equal(parsed!.protocol, protocol);
    assert.equal(parsed!.exporter, args[1]);
    assert.equal(parsed!.a, args[2]);
    assert.equal(parsed!.b, args[3]);
    assert.equal(sourceKeyFor(parsed!.protocol, parsed!.exporter, parsed!.a, parsed!.b), key);
    assert.equal(isEngineSourceKey(key), true);
    assert.equal(exporterOf(key), args[1]);
  }
  assert.equal(exporterOf('192.0.2.1'), '192.0.2.1', 'a bare exporter key is its own exporter');
});

test('source keys: garbage, non-canonical numbers and out-of-range ids parse to null; a bare exporter is not an engine key', () => {
  for (const bad of [
    '', 'x', '192.0.2.1', '192.0.2.1/0', '192.0.2.1/0/1/2', '192.0.2.1/01/1', '192.0.2.1/256/0', '192.0.2.1/-1/0', '999.0.0.1/0/0',
    'v9:192.0.2.1', 'v9:192.0.2.1/', 'v9:192.0.2.1/1/2', 'v9:192.0.2.1/4294967296', 'v9:192.0.2.1/01', 'v9:999.1.1.1/1',
    'ipfix:192.0.2.1', 'ipfix:192.0.2.1/x', 'ipfix:192.0.2.1/4294967296', 'V9:192.0.2.1/1', 'v10:192.0.2.1/1', ' v9:192.0.2.1/1',
  ]) {
    assert.equal(parseSourceKey(bad), null, `"${bad}"`);
    assert.equal(isEngineSourceKey(bad), false, `"${bad}"`);
  }
  assert.throws(() => sourceKeyFor('v5', '192.0.2.1', 256, 0), RangeError);
  assert.throws(() => sourceKeyFor('v5', '192.0.2.1', 1), RangeError, 'a v5 source needs both ids');
  assert.throws(() => sourceKeyFor('v9', '192.0.2.1', 1, 2), RangeError, 'a v9 source has one id');
  assert.throws(() => sourceKeyFor('ipfix', '192.0.2.1', -1), RangeError);
  assert.throws(() => sourceKeyFor('v9', '192.0.2.1', 2 ** 32), RangeError);
  assert.throws(() => sourceKeyFor('v9', '192.0.2.1', 1.5), RangeError);
});

test('source keys: no v5 key can equal a v9 or IPFIX key', () => {
  const v5 = new Set<string>();
  for (const t of [0, 1, 255]) for (const e of [0, 1, 255]) v5.add(sourceKeyFor('v5', '192.0.2.1', t, e));
  for (const id of [0, 1, 255, 256, 4_294_967_295]) {
    assert.equal(v5.has(sourceKeyFor('v9', '192.0.2.1', id)), false);
    assert.equal(v5.has(sourceKeyFor('ipfix', '192.0.2.1', id)), false);
    assert.notEqual(sourceKeyFor('v9', '192.0.2.1', id), sourceKeyFor('ipfix', '192.0.2.1', id));
  }
});

if (failures > 0) {
  console.log(`\n${failures} of ${failures + passes} FAILED`);
  process.exit(1);
}
console.log(`\nall passed (${passes})`);
