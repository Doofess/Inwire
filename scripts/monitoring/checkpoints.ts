/**
 * Policy 2 reaches the rollups, the expiry replay and the raw scans (ADR 0066): template checkpoints,
 * `decodeStateBefore`, and the equality that makes any of it safe - a rollup rebuilt from a checkpoint is
 * the rollup a full replay makes, and both are the raw scan's answer.
 *
 *   npx tsx scripts/monitoring/checkpoints.ts
 *
 * Plain tsx, over the query rig. The harness plays the Worker (it feeds `feedEntry` one full-replay
 * `DecodeState`, captures a checkpoint at each segment start and posts both to the sidecar), because
 * faking a watermark would make the sidecar vouch for something the journal does not say. Every datagram
 * is authored from RFC 3954 and RFC 7011 in `fixtures.ts`, and the totals each test expects are summed
 * from the generator's own list of records, never from a decoder.
 */
import assert from 'node:assert/strict';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { expiryFragments, runExpiry } from '../../src/services/monitoring/archive';
import { DecodeState } from '../../src/services/monitoring/decodeState';
import {
  JOURNAL_FRAMING, KIND_BOUNDARY, KIND_DATAGRAM, ROLLUP_FRAMING, encodeDatagramBody, encodeEntry, parseEntryHeader,
} from '../../src/services/monitoring/journalCodec';
import { encodeBoundaryBody, type EvidenceInput } from '../../src/services/monitoring/journal';
import { DEFAULT_RETENTION, planExpiry } from '../../src/services/monitoring/retention';
import {
  EngineAdmission, MinuteAccumulator, MinuteAggregator, feedEntry, type DatagramFold, type RecordFold,
} from '../../src/services/monitoring/rollup';
import { decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { CorruptRollupError } from '../../src/services/monitoring/runtime';
import { MemorySegmentDirectory, encodeSegmentHeader, segmentName } from '../../src/services/monitoring/segments';
import { decodeStateBefore, type StateSource } from '../../src/services/monitoring/stateAt';
import { sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import { LIMITS, SAMPLING_MIXED, type Evidence, type MinuteRollup, type QueryFocus, type StoredCheckpoint } from '../../src/services/monitoring/types';
import {
  EXPORTER, COLLECTOR, be, dataSet, ipfixMessage, templateRecord, templateSet, v5Payload, v9Message, type WireField,
} from './fixtures';
import {
  BASE, MIN, NOW, S1, S2, SRC, Rig, ask, askBoth, askOk, dgram, deflate, inflate, runAll, spec, start, stop, test, withoutProvenance,
} from './queryRig';

const m = (n: number, offset = 0): number => BASE + n * MIN + offset;
const V9 = sourceKeyFor('v9', EXPORTER, 1);

// --- datagrams, authored from the RFCs ---------------------------------------------------------------------

const F_SRC: WireField = { type: 8, length: 4 };
const F_DST: WireField = { type: 12, length: 4 };
const F_OCT: WireField = { type: 1, length: 4 };
const F_PKT: WireField = { type: 2, length: 4 };
const F_SAMP: WireField = { type: 34, length: 4 };
/** Template 256 as first defined: octets, then packets. */
const LAYOUT_A: WireField[] = [F_SRC, F_DST, F_OCT, F_PKT, F_SAMP];
/** The same id redefined: packets first. A reader that kept layout A would swap the two counts. */
const LAYOUT_B: WireField[] = [F_SRC, F_DST, F_PKT, F_OCT, F_SAMP];

type Layout = 'A' | 'B';

function record(layout: Layout, src: string, dst: string, octets: number, packets: number, samp = 0): number[] {
  const counts = layout === 'A' ? [octets, packets] : [packets, octets];
  return [...be.ipv4(src), ...be.ipv4(dst), ...be.u32(counts[0]), ...be.u32(counts[1]), ...be.u32(samp)];
}

let seq = 0;
/** A v9 datagram; the uptime advances with receipt, so the template store never reads a restart. */
function v9(ms: number, sets: number[][], sourceId = 1, skewSecs = 0): EvidenceInput {
  const bytes = v9Message({ uptime: ms - BASE + 1_000_000, secs: Math.floor(ms / 1000) + skewSecs, sequence: seq++, sourceId }, sets);
  return { kind: 'datagram', receivedMs: ms, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}

const tplSet = (layout: Layout, id = 256): number[] =>
  templateSet(9, [templateRecord(9, id, layout === 'A' ? LAYOUT_A : LAYOUT_B)]);

/** One v5 datagram of one flow, for a policy-1 segment. */
const v5Bytes = (i: number): Uint8Array => v5Payload({ sequence: i }, [{ src: '10.9.0.1', dst: '10.9.0.2', octets: 100 + i, packets: 1 }]);

// --- a policy-1 segment, built with the codec rather than the journal ---------------------------------------

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** The generation `Rig(seed)` gives its journal: a hand-built segment must carry it to be adopted. */
const generationOf = (seed: number): Uint8Array => Uint8Array.from({ length: 16 }, (_, i) => (seed + i) & 0xff);

/** Entries 1..datagrams+extra+2 of policy 1: a start, `datagrams` v5 datagrams, the `extra` payloads and a stop. */
function policy1Segment(seed: number, datagrams: number, atMs: number, extra: Uint8Array[] = []): Uint8Array {
  const header = encodeSegmentHeader({
    policyVersion: 1, generation: generationOf(seed), createdMs: atMs, firstEntryId: 1, openSession: null, source: null,
  });
  const parts: Uint8Array[] = [header];
  parts.push(encodeEntry(JOURNAL_FRAMING, 1, KIND_BOUNDARY, encodeBoundaryBody({
    action: 'start', sessionId: S1, receivedMs: atMs, reason: '', droppedDatagrams: null,
  })));
  const payloads = [...Array.from({ length: datagrams }, (_, i) => v5Bytes(i)), ...extra];
  payloads.forEach((payload, i) => {
    parts.push(encodeEntry(JOURNAL_FRAMING, 2 + i, KIND_DATAGRAM, encodeDatagramBody({
      receivedMs: atMs + 1 + i, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4: EXPORTER, remotePort: 40_000, payload,
    })));
  });
  parts.push(encodeEntry(JOURNAL_FRAMING, 2 + payloads.length, KIND_BOUNDARY, encodeBoundaryBody({
    action: 'stop', sessionId: S1, receivedMs: atMs + 1 + payloads.length, reason: 'user', droppedDatagrams: null,
  })));
  return cat(...parts);
}

// --- reading the journal the way a replay does --------------------------------------------------------------

async function allEntries(rig: Rig, through = Infinity): Promise<Evidence[]> {
  const snapshot = await rig.runtime.snapshot();
  const out: Evidence[] = [];
  let after = 0;
  for (;;) {
    const page = await rig.runtime.readPage(snapshot, after, LIMITS.pageEntries, LIMITS.pageBytes);
    for (const e of page.entries) if (e.ref.entryId <= through) out.push(e);
    after = page.nextAfterId;
    if (page.done) break;
  }
  return out;
}

/** The state a full replay from nothing holds after `through`: what a checkpointed state must equal. */
async function steppedState(rig: Rig, through: number): Promise<DecodeState> {
  const state = DecodeState.empty();
  for (const e of await allEntries(rig, through)) state.step(e);
  return state;
}

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

// --- playing the Worker ---------------------------------------------------------------------------------

interface Played {
  minutes: MinuteRollup[];
  watermark: number;
  /** Each segment start's checkpoint as captured (raw, before any tampering). */
  captured: Map<number, { throughMs: number; raw: Uint8Array }>;
  state: DecodeState;
}

interface PlayOptions {
  /** Rewrites a checkpoint's raw bytes before it is deflated and stored; `null` drops it. */
  tamper?: (throughEntryId: number, raw: Uint8Array) => Uint8Array | null;
  /** Segment starts to store a checkpoint at; all of them by default. */
  store?: (throughEntryId: number) => boolean;
}

/** Feeds the journal to one aggregator and one full-replay state, and posts the minutes and checkpoints to the sidecar. */
async function playWorker(rig: Rig, options: PlayOptions = {}): Promise<Played> {
  const snapshot = await rig.runtime.snapshot();
  const geometry = await rig.runtime.segmentGeometry(snapshot);
  const starts = new Set(geometry.slice(1).map((g) => g.firstEntryId));
  const state = DecodeState.empty();
  const agg = new MinuteAggregator(0);
  const admission = new EngineAdmission();
  const captured = new Map<number, { throughMs: number; raw: Uint8Array }>();
  for (const e of await allEntries(rig)) {
    feedEntry(agg, admission, state, e);
    if (starts.has(e.ref.entryId + 1)) captured.set(e.ref.entryId, { throughMs: state.throughMs, raw: state.checkpoint() });
  }
  agg.seal(Infinity);
  const d = agg.drain();
  const minutes = d === null ? [] : d.fragments.map((f) => f.rollup);
  const watermark = d === null ? agg.fedThrough : d.watermark;
  const stored: StoredCheckpoint[] = [];
  for (const [through, c] of captured) {
    if (through > watermark || (options.store !== undefined && !options.store(through))) continue;
    const raw = options.tamper === undefined ? c.raw : options.tamper(through, c.raw);
    if (raw === null) continue;
    stored.push({ role: 1, throughEntryId: through, throughMs: c.throughMs, bytes: deflate(raw) });
  }
  for (let i = 0; i < Math.max(1, Math.ceil(stored.length / 4)); i++) {
    rig.store.appendMinutes(
      i === 0 ? minutes.map((r) => ({ sourceKey: r.sourceKey, minuteMs: r.minuteMs, bytes: encodeMinuteRollup(r, deflate) })) : [],
      { generation: rig.generation, throughEntryId: watermark, policyVersion: 2 },
      i === 0 ? 0 : watermark,
      {},
      stored.slice(i * 4, i * 4 + 4),
    );
  }
  return { minutes, watermark, captured, state };
}

/** A runtime whose reads are recorded, so a test can say which checkpoint a state was built from. */
function spy(rig: Rig): { source: StateSource; reads: number[]; pages: number[] } {
  const reads: number[] = [];
  const pages: number[] = [];
  const source = Object.create(rig.runtime) as StateSource;
  source.readCheckpoint = async (through) => { reads.push(through); return rig.runtime.readCheckpoint(through); };
  source.readPage = async (snapshot, after, maxEntries, maxBytes) => { pages.push(after); return rig.runtime.readPage(snapshot, after, maxEntries, maxBytes); };
  return { source, reads, pages };
}

// --- a journal of three full segments --------------------------------------------------------------------

const FILLER_RECORDS = 2800;

/** A datagram of `FILLER_RECORDS` records of one pair: ~56 KB, so a 1 MiB segment holds about eighteen. */
function filler(ms: number, layout: Layout, octets: number): EvidenceInput {
  const r = record(layout, '10.0.0.1', '10.0.0.2', octets, 1);
  return v9(ms, [dataSet(256, Array.from({ length: FILLER_RECORDS }, () => r))]);
}

interface Scenario {
  rig: Rig;
  /** The first entry id of each segment. */
  firsts: number[];
  /** Σ octets and Σ packets of the decoded records of V9, from the generator's list. */
  octets: bigint;
  packets: bigint;
  records: number;
}

/** Appends until the journal rolls to a new segment; the entry that rolled it is that segment's first. */
function fillUntilRoll(rig: Rig, next: () => EvidenceInput, tally: (inp: EvidenceInput) => void): void {
  const before = rig.journal.segments().length;
  for (let guard = 0; guard < 200; guard++) {
    const inp = next();
    rig.append([inp]);
    tally(inp);
    if (rig.journal.segments().length > before) return;
  }
  throw new Error('the journal never rolled');
}

/**
 * Three segments of one session. Template 256 is defined in segment 1 and redefined (octets and packets
 * swapped) in the middle of segment 2, in a minute that already holds data under the first layout.
 * Segment 3 adds a data set for a template id nobody sent (awaiting) and one with no octet count.
 */
function threeSegments(): Scenario {
  const rig = new Rig(0xa0, 32 << 20);
  const sc: Scenario = { rig, firsts: [1], octets: 0n, packets: 0n, records: 0 };
  let t = m(0);
  let layout: Layout = 'A';
  const tick = (): number => (t += 2000);
  const tally = (inp: EvidenceInput): void => {
    // Fillers are the only datagrams the loop tallies by their record count and octets, taken from the arguments.
    void inp;
  };
  let nextOctets = 7;
  const fill = (): EvidenceInput => {
    const e = filler(tick(), layout, nextOctets);
    sc.octets += BigInt(nextOctets * FILLER_RECORDS);
    sc.packets += BigInt(FILLER_RECORDS);
    sc.records += FILLER_RECORDS;
    return e;
  };
  rig.append([start(t, S1)]);
  rig.append([v9(tick(), [tplSet('A'), dataSet(256, [record('A', '10.0.0.5', '10.0.0.6', 100, 1)])])]);
  sc.octets += 100n; sc.packets += 1n; sc.records += 1;
  fillUntilRoll(rig, fill, tally);
  sc.firsts.push(rig.through);
  // Segment 2: some data under layout A, then the redefinition in the same minute.
  for (let i = 0; i < 3; i++) rig.append([fill()]);
  layout = 'B';
  rig.append([v9(tick(), [tplSet('B'), dataSet(256, [record('B', '10.0.0.3', '10.0.0.4', 500, 5)])])]);
  sc.octets += 500n; sc.packets += 5n; sc.records += 1;
  nextOctets = 9;
  fillUntilRoll(rig, fill, tally);
  sc.firsts.push(rig.through);
  // Segment 3: awaiting (template 300 never sent) and an unsupported template (no octet count), then data.
  const noCount = templateSet(9, [templateRecord(9, 301, [F_SRC, F_DST])]);
  rig.append([v9(tick(), [noCount, dataSet(301, [[...be.ipv4('10.0.0.7'), ...be.ipv4('10.0.0.8')]]), dataSet(300, [[1, 2, 3, 4]]), dataSet(256, [record('B', '10.0.0.9', '10.0.0.10', 40, 4)])])]);
  sc.octets += 40n; sc.packets += 4n; sc.records += 2;
  rig.append([fill(), fill(), stop(tick(), S1)]);
  return sc;
}

// =====================================================================================================
// decodeStateBefore
// =====================================================================================================

test('policy-1-prefix: a policy-2 segment after policy-1 ones starts from empty state at its own first entry', async () => {
  const seed = 0xa0;
  const jdir = new MemorySegmentDirectory({ [segmentName(1)]: policy1Segment(seed, 30, m(0)) });
  const rig = new Rig(seed, 1 << 30, jdir);
  assert.equal(rig.through, 32);
  rig.append([
    start(m(1), S2),
    v9(m(1, 1000), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10)])]),
    v9(m(1, 2000), [dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1, 1)])]),
    v9(m(1, 3000), [dataSet(256, [record('A', '10.0.0.3', '10.0.0.4', 2, 2)])]),
    stop(m(1, 4000), S2),
  ]);
  const snapshot = await rig.runtime.snapshot();
  const geometry = await rig.runtime.segmentGeometry(snapshot);
  assert.deepEqual(geometry.map((g) => [g.firstEntryId, g.lastEntryId, g.policy]), [[1, 32, 1], [33, 37, 2]]);
  const entries = await allEntries(rig);
  const cost = (upTo: number, from = 1): number => entries.filter((e) => e.ref.entryId >= from && e.ref.entryId <= upTo)
    .reduce((n, e) => n + (e.kind === 'datagram' ? e.bytes.length : 0) + 24, 0);
  const budget = 2000;
  assert.ok(cost(32) > budget, `the policy-1 prefix alone (${cost(32)} bytes) exceeds the budget`);
  assert.ok(cost(35) > budget, 'so does a replay from nothing');
  assert.ok(cost(35, 33) < budget, `the policy-2 part (${cost(35, 33)} bytes) fits`);

  const state = await decodeStateBefore(rig.runtime, snapshot, 36, inflate, budget);
  assert.notEqual(state, 'range-too-large');
  const got = state as DecodeState;
  assert.equal(got.throughEntryId, 35);
  const want = await steppedState(rig, 35);
  assert.ok(bytesEqual(got.checkpoint(), want.checkpoint()), 'the state equals one stepped from empty through the same entries');
  // At the first entry of the policy-2 segment nothing is replayed: the state is empty as of entry 32.
  const atStart = await decodeStateBefore(rig.runtime, snapshot, 33, inflate, budget);
  assert.notEqual(atStart, 'range-too-large');
  assert.ok(bytesEqual((atStart as DecodeState).checkpoint(), (await steppedState(rig, 32)).checkpoint()), 'empty as of 32 is the stepped state of the policy-1 prefix');
  assert.equal((atStart as DecodeState).throughMs, entries[31].receivedMs, 'its time is the receipt time of entry 32');
});

test('replay-bound: a replay past maxReplayBytes is refused, and one within it decodes', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0), S1),
    v9(m(0, 1000), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10)])]),
    v9(m(0, 2000), [dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1, 1)])]),
    v9(m(0, 3000), [dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 2, 2)])]),
    stop(m(0, 4000), S1),
  ]);
  const snapshot = await rig.runtime.snapshot();
  assert.equal(await decodeStateBefore(rig.runtime, snapshot, 5, inflate, 200), 'range-too-large');
  const ok = await decodeStateBefore(rig.runtime, snapshot, 5, inflate, 1 << 20);
  assert.notEqual(ok, 'range-too-large');
  assert.ok(bytesEqual((ok as DecodeState).checkpoint(), (await steppedState(rig, 4)).checkpoint()));
  // Before the first entry there is nothing to replay.
  const none = await decodeStateBefore(rig.runtime, snapshot, 1, inflate, 0);
  assert.notEqual(none, 'range-too-large');
  assert.equal((none as DecodeState).throughEntryId, 0);
});

test('checkpoint-newest: the newest checkpoint below the entry is the start, and the replay begins after it', async () => {
  const sc = threeSegments();
  const rig = sc.rig;
  const played = await playWorker(rig);
  assert.equal(sc.firsts.length, 3);
  const cps = await rig.runtime.checkpoints();
  assert.deepEqual(cps.map((c) => c.throughEntryId), [sc.firsts[1] - 1, sc.firsts[2] - 1], 'one checkpoint at each later segment start');
  const snapshot = await rig.runtime.snapshot();
  const before = sc.firsts[2] + 3;
  const { source, reads, pages } = spy(rig);
  const state = await decodeStateBefore(source, snapshot, before, inflate);
  assert.notEqual(state, 'range-too-large');
  assert.deepEqual(reads, [sc.firsts[2] - 1], 'only the newest checkpoint was read');
  assert.equal(pages[0], sc.firsts[2] - 1, 'and the replay began right after it');
  assert.ok(bytesEqual((state as DecodeState).checkpoint(), (await steppedState(rig, before - 1)).checkpoint()));
  // Before the first checkpoint there is none to use: the state is stepped from the start of the journal.
  const early = await decodeStateBefore(source, snapshot, sc.firsts[1] - 1, inflate);
  assert.ok(bytesEqual((early as DecodeState).checkpoint(), (await steppedState(rig, sc.firsts[1] - 2)).checkpoint()));
  void played;
});

test('checkpoint-bad: a checkpoint that does not decode, or cannot be read, is skipped for the one before it', async () => {
  const sc = threeSegments();
  const rig = sc.rig;
  // The newest checkpoint holds bytes that fail their own checksum; the older one is good.
  await playWorker(rig, {
    tamper: (through, raw) => {
      if (through !== sc.firsts[2] - 1) return raw;
      const bad = raw.slice();
      bad[bad.length >> 1] ^= 0xff;
      return bad;
    },
  });
  const snapshot = await rig.runtime.snapshot();
  const before = sc.firsts[2] + 2;
  const want = (await steppedState(rig, before - 1)).checkpoint();
  const a = spy(rig);
  const viaOlder = await decodeStateBefore(a.source, snapshot, before, inflate);
  assert.deepEqual(a.reads, [sc.firsts[2] - 1, sc.firsts[1] - 1], 'the newest was tried, then the one before it');
  assert.ok(bytesEqual((viaOlder as DecodeState).checkpoint(), want), 'the answer is the same state');
  // A checkpoint whose read throws is skipped the same way.
  const b = Object.create(rig.runtime) as StateSource;
  b.readCheckpoint = async (through) => {
    if (through === sc.firsts[2] - 1) throw new CorruptRollupError('a stored checkpoint no longer matches its checksum');
    return rig.runtime.readCheckpoint(through);
  };
  const viaThrow = await decodeStateBefore(b, snapshot, before, inflate);
  assert.ok(bytesEqual((viaThrow as DecodeState).checkpoint(), want));
  // A deflated body that is not deflate at all is skipped too.
  const c = Object.create(rig.runtime) as StateSource;
  c.readCheckpoint = async () => Uint8Array.from([1, 2, 3, 4, 5]);
  const viaGarbage = await decodeStateBefore(c, snapshot, before, inflate);
  assert.ok(bytesEqual((viaGarbage as DecodeState).checkpoint(), want), 'with nothing usable, the replay starts from the first entry');
});

test('checkpoint-errors: an unavailable runtime and an abort are not skipped', async () => {
  const sc = threeSegments();
  const rig = sc.rig;
  await playWorker(rig);
  const snapshot = await rig.runtime.snapshot();
  const { RuntimeUnavailableError } = await import('../../src/services/monitoring/runtime');
  const down = Object.create(rig.runtime) as StateSource;
  down.readCheckpoint = async () => { throw new RuntimeUnavailableError('the port closed'); };
  await assert.rejects(decodeStateBefore(down, snapshot, sc.firsts[2] + 2, inflate), RuntimeUnavailableError);
  const aborted = Object.create(rig.runtime) as StateSource;
  aborted.readCheckpoint = async () => { throw new DOMException('aborted', 'AbortError'); };
  await assert.rejects(decodeStateBefore(aborted, snapshot, sc.firsts[2] + 2, inflate), (e: Error) => e.name === 'AbortError');
});

// =====================================================================================================
// rebuilding from a checkpoint
// =====================================================================================================

/** The minutes an aggregator made from the entries after `after`, started from `state`, as hex of their encoding. */
function fragmentsAfter(entries: Evidence[], state: DecodeState, after: number): string[] {
  const agg = new MinuteAggregator(after);
  const admission = new EngineAdmission();
  for (const e of entries) if (e.ref.entryId > after) feedEntry(agg, admission, state, e);
  agg.seal(Infinity);
  const d = agg.drain();
  return d === null ? [] : d.fragments.map((f) => Buffer.from(encodeMinuteRollup(f.rollup, deflate)).toString('hex'));
}

test('checkpoint-rebuild-equals-raw: a rollup rebuilt from a checkpoint is the full replay, and both are the raw answer', async () => {
  const sc = threeSegments();
  const rig = sc.rig;
  const played = await playWorker(rig);
  const entries = await allEntries(rig);
  const cp = sc.firsts[1] - 1;
  const captured = played.captured.get(cp);
  assert.ok(captured !== undefined, 'a checkpoint was captured at the second segment start');

  // The state a checkpoint stands for is the state a full replay holds there.
  const snapshot = await rig.runtime.snapshot();
  const viaCheckpoint = await decodeStateBefore(rig.runtime, snapshot, cp + 1, inflate);
  assert.ok(bytesEqual((viaCheckpoint as DecodeState).checkpoint(), captured.raw), 'decodeStateBefore returns the captured checkpoint');
  assert.ok(bytesEqual(captured.raw, (await steppedState(rig, cp)).checkpoint()), 'and it equals a state stepped from nothing');

  // Minutes made after the checkpoint equal the minutes a full replay makes for the same entries.
  const rebuilt = fragmentsAfter(entries, DecodeState.fromCheckpoint(captured.raw) as DecodeState, cp);
  const full = fragmentsAfter(entries, await steppedState(rig, cp), cp);
  assert.ok(rebuilt.length > 0);
  assert.deepEqual(rebuilt, full, 'byte for byte');

  // The query: rollups equal the raw scan, and both equal the totals the generator summed.
  const { fast, raw } = await askBoth(rig, spec(m(0), m(3), 3, { sourceKey: V9 }));
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  assert.ok(fast.answeredFrom.rollupMinutes > 0 && fast.answeredFrom.rawMinutes === 0, 'the fast answer is from rollups');
  assert.equal(raw.answeredFrom.rollupMinutes, 0);
  const sum = (key: 'reportedOctets' | 'reportedPackets'): bigint => fast.buckets.reduce((n, b) => n + (b[key] ?? 0n), 0n);
  assert.equal(sum('reportedOctets'), sc.octets);
  assert.equal(sum('reportedPackets'), sc.packets);
  assert.equal(fast.matchingRecords, sc.records);
  assert.equal(fast.awaitingTemplate, 1);
  assert.ok(fast.awaitingBytes > 0);
  assert.equal(fast.unsupportedTemplates, 1);
  assert.equal(fast.conversations.status, 'ok');
  if (fast.conversations.status === 'ok') {
    const row = fast.conversations.rows.find((r) => r.srcAddr === '10.0.0.3' && r.dstAddr === '10.0.0.4');
    assert.deepEqual([row?.reportedOctets, row?.reportedPackets], [500n, 5n], 'the redefined layout was read as layout B');
  }
});

test('checkpoint-query: a raw scan that starts inside the journal reads a checkpoint, and a bad or absent one changes nothing', async () => {
  const answers: string[] = [];
  const kinds: Record<string, number[]> = {};
  const plans: [string, PlayOptions][] = [
    ['good', {}],
    ['absent', { store: () => false }],
    ['tampered', { tamper: (_through, raw) => { const bad = raw.slice(); bad[bad.length >> 1] ^= 0xff; return bad; } }],
  ];
  for (const [name, options] of plans) {
    const sc = threeSegments();
    const rig = sc.rig;
    await playWorker(rig, options);
    const reads: number[] = [];
    const real = rig.runtime.readCheckpoint.bind(rig.runtime);
    rig.runtime.readCheckpoint = async (through: number) => { reads.push(through); return real(through); };
    kinds[name] = reads;
    const entries = await allEntries(rig);
    const at = entries.find((e) => e.ref.entryId === sc.firsts[2] + 1)!.receivedMs;
    const from = Math.floor(at / MIN) * MIN;
    const { fast, raw } = await askBoth(rig, spec(from, from + MIN, 1, { sourceKey: V9 }));
    assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), `${name}: rollup equals raw`);
    assert.ok(raw.matchingRecords > 0, `${name}: the range holds records`);
    answers.push(JSON.stringify(withoutProvenance(raw), (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)));
  }
  assert.ok(kinds.good.length > 0, 'with checkpoints stored, one is read');
  assert.equal(kinds.absent.length, 0, 'with none stored, none is read');
  assert.equal(new Set(answers).size, 1, 'good, absent and tampered checkpoints give the same answer');
});

// =====================================================================================================
// the expiry replay
// =====================================================================================================

/** What a range's answer says besides its tables, which an expiry turns into `evidence-expired` for the cut part. */
/** An expiry appends a boundary, so the snapshot moves; nothing else of an answer over retained time may. */
const noSnapshot = (r: Awaited<ReturnType<typeof askBoth>>['raw']): unknown => { const { snapshot: _s, answeredFrom: _a, ...rest } = r; return rest; };

const untabled = (r: Awaited<ReturnType<typeof askBoth>>['raw']): unknown => ({
  buckets: r.buckets.map((b) => [b.fromMs, b.toMs, b.reportedOctets, b.reportedPackets, b.records]),
  matchingRecords: r.matchingRecords, malformed: r.malformed, unsupported: r.unsupported,
  awaitingTemplate: r.awaitingTemplate, awaitingBytes: r.awaitingBytes, unsupportedTemplates: r.unsupportedTemplates,
  sampling: r.sampling, clock: r.clock,
});

test('checkpoint-expiry: expiring the first two segments keeps the totals, and the state inside the third starts from the cut', async () => {
  const sc = threeSegments();
  const rig = sc.rig;
  await playWorker(rig);
  const inside = sc.firsts[2] + 3;
  const wantCut = (await steppedState(rig, sc.firsts[2] - 1)).checkpoint();
  const wantState = (await steppedState(rig, inside - 1)).checkpoint();
  const whole = spec(m(0), m(3), 3, { sourceKey: V9 });
  const before = (await askBoth(rig, whole)).raw;
  const t3 = (await allEntries(rig)).find((e) => e.ref.entryId === sc.firsts[2])!.receivedMs;
  const window = spec(t3, m(3), 1, { sourceKey: V9 });
  const winBefore = await askBoth(rig, window);
  assert.equal(before.awaitingTemplate, 1);

  const segs = rig.journal.segments();
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, 32 * 1024 * 1024, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null && plan.segments.length === 2);
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
  const cut = rig.archive.lastCut()!;
  assert.equal(cut.throughEntryId, sc.firsts[2] - 1);
  assert.ok(cut.checkpoint.length > 0, 'the cut keeps the state through the last expired entry');
  assert.ok(bytesEqual(cut.checkpoint, wantCut), 'and it is the state a full replay holds there');

  // After the cut the sidecar is reset: no checkpoint remains, so the state inside segment 3 starts from the cut.
  assert.deepEqual(await rig.runtime.checkpoints(), []);
  const snapshot = await rig.runtime.snapshot();
  const { source, reads, pages } = spy(rig);
  source.archive = rig.runtime.archive;
  const state = await decodeStateBefore(source, snapshot, inside, inflate);
  assert.notEqual(state, 'range-too-large');
  assert.deepEqual(reads, []);
  assert.equal(pages[0], sc.firsts[2] - 1, 'the replay began right after the cut');
  assert.ok(bytesEqual((state as DecodeState).checkpoint(), wantState), 'the state equals the one stepped from nothing before the expiry');

  // Totals, awaiting, unsupported, sampling and clock are what they were: the archive and the retained
  // segment together say what the whole journal did.
  const after = { fast: await askOk(rig, whole) };
  const winAfter = await askBoth(rig, window);
  assert.deepEqual(untabled(after.fast), untabled(before), 'rollups: the archive and the retained part total what the whole journal did');
  assert.ok(after.fast.answeredFrom.rollupMinutes > 0);
  // A window wholly inside the retained segment is still exact from the raw journal, and it needs the cut's state.
  assert.deepEqual(noSnapshot(winAfter.raw), noSnapshot(winBefore.raw), 'a raw window after the cut');
  assert.deepEqual(noSnapshot(winAfter.fast), noSnapshot(winBefore.fast), 'and from rollups');
  assert.equal(winAfter.raw.awaitingTemplate, 1);
  assert.equal(winAfter.raw.unsupportedTemplates, 1);
});

test('policy-mix: a minute written under policy 1 and the same minute under policy 2 stay two archive fragments, each read as it was written', async () => {
  const seed = 0xa0;
  const v9Under1 = v9(m(0, 500), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 9, 9)])]);
  const jdir = new MemorySegmentDirectory({ [segmentName(1)]: policy1Segment(seed, 3, m(0), [(v9Under1 as { bytes: Uint8Array }).bytes]) });
  const rig = new Rig(seed, 1 << 30, jdir);
  rig.append([
    start(m(0, 30_000), S2),
    v9(m(0, 31_000), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10)])]),
    dgram(m(0, 32_000), [{ src: '10.9.0.1', dst: '10.9.0.2', octets: 5000, packets: 7 }]),
    stop(m(0, 33_000), S2),
  ]);
  const entries = await allEntries(rig);
  assert.deepEqual([...new Set(entries.map((e) => e.policy))], [1, 2]);

  const { minutes } = expiryFragments(entries, { knownSources: [] }, deflate, DecodeState.empty());
  const v5Minutes = minutes.filter((a) => a.sourceKey === SRC && a.minuteMs === m(0));
  assert.deepEqual(v5Minutes.map((a) => a.policyVersion).sort(), [1, 2], 'one fragment per policy for the same source and minute');
  for (const a of v5Minutes) {
    const decoded = decodeMinuteRollup(a.bytes, inflate);
    assert.equal(decoded.policy, a.policyVersion, 'the rollup says the policy it was written under');
    if (a.policyVersion === 1) assert.equal(decoded.records, 3);
    else assert.equal(decoded.records, 1);
  }
  const unsupportedUnder1 = minutes.filter((a) => a.policyVersion === 1 && decodeMinuteRollup(a.bytes, inflate).unsupported > 0);
  assert.equal(unsupportedUnder1.length, 1, 'the v9 datagram of the policy-1 segment is unsupported there');
  assert.equal(minutes.filter((a) => a.sourceKey === V9).length, 1, 'and the policy-2 v9 datagram is a source of its own');

  await playWorker(rig);
  const v5 = await askBoth(rig, spec(m(0), m(1), 1));
  assert.deepEqual(withoutProvenance(v5.fast), withoutProvenance(v5.raw));
  assert.equal(v5.raw.matchingRecords, 4);
  assert.equal(v5.raw.buckets[0].reportedOctets, 100n + 101n + 102n + 5000n);
  assert.equal(v5.raw.buckets[0].reportedPackets, 3n + 7n);
  assert.ok(v5.raw.unsupported >= 1);
  const nine = await askBoth(rig, spec(m(0), m(1), 1, { sourceKey: V9 }));
  assert.deepEqual(withoutProvenance(nine.fast), withoutProvenance(nine.raw));
  assert.equal(nine.raw.matchingRecords, 1);
  assert.equal(nine.raw.buckets[0].reportedOctets, 1000n);
});

// =====================================================================================================
// legs, focus and sources
// =====================================================================================================

/** One IPFIX message of one observation domain. */
function ipfix(ms: number, sets: number[][], domain: number): EvidenceInput {
  const bytes = ipfixMessage({ secs: Math.floor(ms / 1000), sequence: seq++, domain }, sets);
  return { kind: 'datagram', receivedMs: ms, localIPv4: COLLECTOR, localPort: 4739, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}

const REV = 29305;
const F_OCT8: WireField = { type: 1, length: 8 };
const F_PKT8: WireField = { type: 2, length: 8 };
const BIFLOW: WireField[] = [F_SRC, F_DST, F_OCT8, F_PKT8, { type: 1, length: 8, pen: REV }, { type: 2, length: 8, pen: REV }];

const biflow = (src: string, dst: string, o: number, p: number, ro: number, rp: number): number[] =>
  [...be.ipv4(src), ...be.ipv4(dst), ...be.uint(o, 8), ...be.uint(p, 8), ...be.uint(ro, 8), ...be.uint(rp, 8)];

test('biflow: a reverse count is the opposite leg of the same record, and focus reads legs', async () => {
  const rig = new Rig();
  const IPFIX = sourceKeyFor('ipfix', EXPORTER, 7);
  rig.append([
    start(m(0), S1),
    ipfix(m(0, 1000), [
      templateSet(10, [templateRecord(10, 400, BIFLOW)]),
      dataSet(400, [biflow('10.0.0.1', '10.0.0.2', 1000, 10, 4000, 40), biflow('10.0.0.3', '10.0.0.4', 70, 7, 0, 0)]),
    ], 7),
    stop(m(0, 5000), S1),
  ]);
  await playWorker(rig);
  const q = (focus?: QueryFocus) => askBoth(rig, spec(m(0), m(1), 1, focus === undefined ? { sourceKey: IPFIX } : { sourceKey: IPFIX, focus }));
  const all = await q();
  assert.deepEqual(withoutProvenance(all.fast), withoutProvenance(all.raw));
  assert.equal(all.raw.matchingRecords, 2, 'a biflow record is one record');
  assert.equal(all.raw.buckets[0].reportedOctets, 5070n);
  assert.equal(all.raw.buckets[0].reportedPackets, 57n);
  assert.equal(all.raw.conversations.status, 'ok');
  if (all.raw.conversations.status === 'ok') {
    const rows = all.raw.conversations.rows.map((r) => `${r.srcAddr}>${r.dstAddr}:${r.reportedOctets}/${r.reportedPackets}`).sort();
    assert.deepEqual(rows, ['10.0.0.1>10.0.0.2:1000/10', '10.0.0.2>10.0.0.1:4000/40', '10.0.0.3>10.0.0.4:70/7'], 'a reverse leg only where it carried something');
    const sum = all.raw.conversations.rows.reduce((n, r) => n + r.reportedOctets, 0n);
    assert.equal(sum, all.raw.buckets[0].reportedOctets, 'the rows sum to the bucket');
  }
  const rev = await q({ kind: 'conversation', srcAddr: '10.0.0.2', dstAddr: '10.0.0.1' });
  assert.deepEqual(withoutProvenance(rev.fast), withoutProvenance(rev.raw));
  assert.equal(rev.raw.matchingRecords, 1);
  assert.equal(rev.raw.buckets[0].reportedOctets, 4000n);
  assert.equal(rev.raw.buckets[0].reportedPackets, 40n);
  const fwd = await q({ kind: 'conversation', srcAddr: '10.0.0.1', dstAddr: '10.0.0.2' });
  assert.equal(fwd.raw.buckets[0].reportedOctets, 1000n);
  assert.equal(fwd.raw.matchingRecords, 1);
  const both = await q({ kind: 'endpoint', address: '10.0.0.1' });
  assert.deepEqual(withoutProvenance(both.fast), withoutProvenance(both.raw));
  assert.equal(both.raw.matchingRecords, 1, 'the record counts once though both legs match');
  assert.equal(both.raw.buckets[0].reportedOctets, 5000n);
  assert.equal(both.raw.buckets[0].reportedPackets, 50n);
  const quiet = await q({ kind: 'endpoint', address: '10.0.0.4' });
  assert.equal(quiet.raw.matchingRecords, 1);
  assert.equal(quiet.raw.buckets[0].reportedOctets, 70n, 'a reverse leg that carried nothing is not a leg');
  const none = await q({ kind: 'conversation', srcAddr: '10.0.0.4', dstAddr: '10.0.0.3' });
  assert.equal(none.raw.matchingRecords, 0);
});

test('sources: v5 engines, v9 source ids and IPFIX domains from one exporter are separate rows, up to sixteen', async () => {
  const rig = new Rig();
  const keys: string[] = [];
  const inputs: EvidenceInput[] = [start(m(0), S1)];
  let t = 1000;
  for (let i = 0; i < 5; i++) {
    keys.push(sourceKeyFor('v5', EXPORTER, 0, i));
    inputs.push(dgram(m(0, t += 100), [{ src: '10.1.0.1', dst: '10.1.0.2', octets: 100 + i, packets: 1 }], { engineId: i, sequence: i }));
  }
  const v9Ids = [11, 12, 13, 14, 15, 99];
  const ipfixIds = [21, 22, 23, 24, 25, 26];
  for (const id of v9Ids) {
    keys.push(sourceKeyFor('v9', EXPORTER, id));
    inputs.push(v9(m(0, t += 100), [tplSet('A'), dataSet(256, [record('A', '10.2.0.1', '10.2.0.2', 200 + id, 2)])], id));
  }
  for (const id of ipfixIds) {
    keys.push(sourceKeyFor('ipfix', EXPORTER, id));
    inputs.push(ipfix(m(0, t += 100), [templateSet(10, [templateRecord(10, 300, LAYOUT_A)]), dataSet(300, [record('A', '10.3.0.1', '10.3.0.2', 300 + id, 3)])], id));
  }
  inputs.push(stop(m(0, t + 100), S1));
  rig.append(inputs);
  assert.equal(keys.length, 17);
  await playWorker(rig);
  // Sixteen identities are admitted in arrival order; the seventeenth, the last IPFIX domain, is not.
  const admitted = keys.slice(0, 16);
  const refused = keys[16];
  assert.equal(refused, sourceKeyFor('ipfix', EXPORTER, 26));
  for (const key of keys) {
    const { fast, raw } = await askBoth(rig, spec(m(0), m(1), 1, { sourceKey: key }));
    assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), key);
    if (key === refused) assert.equal(raw.matchingRecords, 0, 'a seventeenth identity is not admitted');
    else assert.equal(raw.matchingRecords, 1, key);
  }
  assert.equal(new Set(admitted).size, 16);
});

test('sidecar-policy: a watermark that names a policy this build does not read makes the sidecar rebuild, not answer', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0), S1),
    v9(m(0, 1000), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10)])]),
    stop(m(0, 2000), S1),
  ]);
  await playWorker(rig);
  const good = rig.sidecarBytes();
  const bounds = { generation: rig.generation, throughEntryId: rig.through };
  const open = (bytes: Uint8Array): ReturnType<typeof RollupStore.open> => {
    const file = new MemoryBlockFile();
    file.write(0, bytes);
    return RollupStore.open(file, bounds);
  };
  assert.equal(open(good).status, 'ok');
  // The closing watermark is the last 50 bytes: a 24-byte entry header and a 26-byte body (generation, through, policy).
  const WATERMARK = 24 + 26;
  const head = parseEntryHeader(ROLLUP_FRAMING, good.subarray(good.length - WATERMARK));
  assert.ok(head.ok && head.kind === 2 && head.bodyLength === 26, 'the last entry is the watermark');
  const body = good.slice(good.length - 26);
  assert.equal(new DataView(body.buffer).getUint16(24, true), 2, 'it names policy 2');
  const tampered = (policy: number): Uint8Array => {
    const b = body.slice();
    new DataView(b.buffer).setUint16(24, policy, true);
    return cat(good.subarray(0, good.length - WATERMARK), encodeEntry(ROLLUP_FRAMING, (head as { entryId: number }).entryId, 2, b));
  };
  assert.equal(open(tampered(2)).status, 'ok', 'the rebuilt entry is itself valid');
  const refused = open(tampered(3));
  assert.equal(refused.status, 'rebuild-required');
  assert.ok(String(refused.reason).includes('policy 3'), String(refused.reason));
});

test('replay-refusal: a raw window that needs more replay than the budget is range-too-large, and a checkpoint brings it within', async () => {
  const limits = LIMITS as unknown as { replayBytes: number };
  const saved = limits.replayBytes;
  try {
    limits.replayBytes = 600_000;
    const outcomes: Record<string, Awaited<ReturnType<typeof ask>>> = {};
    for (const [name, options] of [['with', {}], ['without', { store: () => false }]] as [string, PlayOptions][]) {
      const sc = threeSegments();
      await playWorker(sc.rig, options);
      const t3 = (await allEntries(sc.rig)).find((e) => e.ref.entryId === sc.firsts[2] + 1)!.receivedMs;
      outcomes[name] = await ask(sc.rig, spec(t3, m(3), 1, { sourceKey: V9 }), { forceRaw: true });
    }
    const without = outcomes.without;
    assert.ok(!without.ok && without.code === 'range-too-large', 'no checkpoint: the replay from the start is over the budget');
    if (!without.ok) assert.ok(/checkpoint/.test(without.message), without.message);
    assert.ok(outcomes.with.ok, 'a checkpoint at the start of the segment keeps it within');
    if (outcomes.with.ok) assert.equal(outcomes.with.value.awaitingTemplate, 1);
  } finally {
    limits.replayBytes = saved;
  }
});

// =====================================================================================================
// sampling and the export clock
// =====================================================================================================

const rec = (sampling: RecordFold['sampling'], octets = 10n): RecordFold =>
  ({ recordIndex: 0, octets, packets: 1n, legs: [{ src: '10.0.0.1', dst: '10.0.0.2', octets, packets: 1n }], sampling });
const fold = (records: RecordFold[], skewMs: number | null = null, extra: Partial<DatagramFold> = {}): DatagramFold =>
  ({ sourceKey: V9, records, unsupportedTemplateRecords: 0, awaitingSets: 0, awaitingBytes: 0, skewMs, ...extra });

test('accumulator: sampling folds to known or mixed, an unsupported record is counted, and the clock keeps the last skew of the later fragment', () => {
  const a = new MinuteAccumulator(V9, m(0), 2);
  a.addDatagram(fold([rec({ kind: 'known', interval: 100 }), rec({ kind: 'known', interval: 100 })], -5));
  assert.equal(a.toRollup().samplingInterval, 100);
  a.addDatagram(fold([rec({ kind: 'unknown' })], 5));
  assert.equal(a.toRollup().samplingInterval, 100, 'a record that stated no rate does not change it');
  assert.equal(a.toRollup().unknownSamplingRecords, 1);
  a.addDatagram(fold([rec({ kind: 'unsupported' })], null, { awaitingSets: 2, awaitingBytes: 40, unsupportedTemplateRecords: 3 }));
  const r1 = a.toRollup();
  assert.deepEqual([r1.unsupportedSamplingRecords, r1.awaitingSets, r1.awaitingBytes, r1.unsupportedTemplateRecords], [1, 2, 40, 3]);
  assert.equal(r1.records, 4 + 3 - 0, 'records counts the unsupported-template ones too');
  a.addDatagram(fold([rec({ kind: 'known', interval: 200 })]));
  assert.equal(a.toRollup().samplingInterval, SAMPLING_MIXED);
  a.addDatagram(fold([rec({ kind: 'known', interval: 100 })]));
  assert.equal(a.toRollup().samplingInterval, SAMPLING_MIXED, 'mixed stays mixed');
  assert.deepEqual(a.toRollup().clock, { minSkewMs: -5, maxSkewMs: 5, lastSkewMs: 5 });
  // The rollup survives its own codec.
  assert.deepEqual(decodeMinuteRollup(encodeMinuteRollup(a.toRollup(), deflate), inflate), a.toRollup());

  // Absorbed in entry order, the later fragment's last skew is the minute's.
  const early = new MinuteAccumulator(V9, m(0), 2); early.addDatagram(fold([rec({ kind: 'unknown' })], -5)); early.addDatagram(fold([rec({ kind: 'unknown' })], 5));
  const late = new MinuteAccumulator(V9, m(0), 2); late.addDatagram(fold([rec({ kind: 'unknown' })], 0)); late.addDatagram(fold([rec({ kind: 'unknown' })], 100));
  const forward = new MinuteAccumulator(V9, m(0), 2); forward.absorb(early.toRollup()); forward.absorb(late.toRollup());
  const backward = new MinuteAccumulator(V9, m(0), 2); backward.absorb(late.toRollup()); backward.absorb(early.toRollup());
  assert.deepEqual(forward.toRollup().clock, { minSkewMs: -5, maxSkewMs: 100, lastSkewMs: 100 });
  assert.deepEqual(backward.toRollup().clock, { minSkewMs: -5, maxSkewMs: 100, lastSkewMs: 5 }, 'the order is what decides it');
});

test('accumulator: a policy-1 minute keeps the new fields at nothing and encodes as policy 1', () => {
  const a = new MinuteAccumulator(SRC, m(0), 1);
  a.addDatagram(fold([rec({ kind: 'known', interval: 50 })], null));
  const r = a.toRollup();
  assert.deepEqual([r.policy, r.samplingInterval, r.clock, r.awaitingSets, r.unsupportedTemplateRecords, r.unsupportedSamplingRecords], [1, 0, null, 0, 0, 0]);
  const bytes = encodeMinuteRollup(r, deflate);
  const back = decodeMinuteRollup(bytes, inflate);
  assert.equal(back.policy, 1);
  assert.deepEqual(back, r);
  // Absorbed into a policy-2 minute, it adds only what a policy-1 minute has.
  const merged = new MinuteAccumulator(SRC, m(0), 2);
  merged.absorb(r);
  assert.equal(merged.toRollup().samplingInterval, 0);
  assert.equal(merged.toRollup().records, 1);
});

test('sampling-and-clock: a range reports the rate its records stated, mixed when they differ, and the export clock', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0), S1),
    v9(m(0, 1000), [tplSet('A'), dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10, 100)])]),
    v9(m(1, 1000), [dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10, 200)])]),
    v9(m(2, 1000), [dataSet(256, [record('A', '10.0.0.1', '10.0.0.2', 1000, 10, 100)])], 1, 30),
    stop(m(2, 5000), S1),
  ]);
  await playWorker(rig);
  const ask1 = await askBoth(rig, spec(m(0), m(1), 1, { sourceKey: V9 }));
  assert.deepEqual(withoutProvenance(ask1.fast), withoutProvenance(ask1.raw));
  assert.deepEqual(ask1.raw.sampling, { kind: 'known', interval: 100 });
  assert.equal(ask1.raw.clock.flagged, false);
  const all = await askBoth(rig, spec(m(0), m(3), 3, { sourceKey: V9 }));
  assert.deepEqual(withoutProvenance(all.fast), withoutProvenance(all.raw));
  assert.deepEqual(all.raw.sampling, { kind: 'mixed' });
  assert.deepEqual([all.raw.clock.minSkewMs, all.raw.clock.maxSkewMs, all.raw.clock.latestSkewMs, all.raw.clock.flagged], [0, 30_000, 30_000, true]);
});

// =====================================================================================================

runAll().then((failures) => { process.exit(failures === 0 ? 0 : 1); }, (e) => { console.error(e); process.exit(1); });
