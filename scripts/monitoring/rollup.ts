/**
 * Minute rollups: the aggregator, the sidecar they are posted to, and the one
 * property that makes them safe to have - a rollup answer is the raw-scan
 * answer (ADR 0059).
 *
 *   npx tsx scripts/monitoring/rollup.ts
 *
 * The centre of the file is the equality harness. One generated journal holds
 * every awkward minute at once - edges, a gap, a stepped-back clock that makes
 * two fragments of a minute, a 16,385-key minute, two fragments whose union is
 * past the budget, and a tail of entries after the sidecar's watermark that
 * lands in minutes the sidecar already has - and many ranges and bucket counts
 * are answered twice, from rollups and with every minute read from the journal.
 * `answeredFrom` is the only field allowed to differ, and it is also asserted,
 * because a harness that went raw everywhere would pass for the wrong reason.
 *
 * An independent oracle, computed from the generator's own list of records and
 * not from any decoder, checks the totals on their own.
 */
import assert from 'node:assert/strict';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { EngineAdmission, MinuteAccumulator, MinuteAggregator, minuteOf } from '../../src/services/monitoring/rollup';
import { decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { runExpiry } from '../../src/services/monitoring/archive';
import { DEFAULT_RETENTION, planExpiry } from '../../src/services/monitoring/retention';
import { ACCEPTED_POLICIES, LIMITS, WRITE_POLICY_VERSION,type DatagramEvidence, type HistoryResult, type MinuteRollup, type NormalizedV5 } from '../../src/services/monitoring/types';
import { decodeV5, exporterKey, sourceKey } from '../../src/services/monitoring/v5';
import type { EvidenceInput } from '../../src/services/monitoring/journal';
import { sourceKeyFor } from '../../src/services/monitoring/sourceKeys';
import {
  COLLECTOR, EXPORTER, GENERATION, be, dataSet, evidence, ipfixMessage, templateRecord, templateSet, v5Payload, v9Message,
  type FlowSpec, type HeaderSpec, type WireField,
} from './fixtures';
import {
  BASE, MIN, NOW, S1, S2, S3, SRC, SRC1, Rig, ask, askBoth, askOk, boundary, deflate, dgram, inflate, junk, prng, rollUp, runAll,
  spec, start, stop, test, unreadVersion, withoutProvenance,
} from './queryRig';

const m = (n: number, offset = 0): number => BASE + n * MIN + offset;
const OTHER = '192.0.2.9';
const BUSY = '192.0.2.77';

// --- flows for the unit tests ------------------------------------------------------------------------

function flowsOf(flows: Partial<FlowSpec>[], receivedMs: number, entryId: number, header: Partial<HeaderSpec> = {}): NormalizedV5[] {
  const e: DatagramEvidence = evidence(v5Payload(header, flows), { ref: { generation: GENERATION, entryId }, receivedMs, receiveOrdinal: entryId });
  const d = decodeV5(e, e.remoteIPv4);
  if (d.kind !== 'valid') throw new Error(`the fixture did not decode: ${JSON.stringify(d)}`);
  return d.flows;
}

const ip = (block: number, i: number): string => `10.${block}.${(i >> 8) & 255}.${i & 255}`;

/** `n` flows with unique sources in `block` and one shared destination, in datagrams of 1,364 (the most one can hold). */
function fan(block: number, n: number, receivedMs: number, firstId: number, dst = '172.16.0.1'): NormalizedV5[] {
  const out: NormalizedV5[] = [];
  for (let i = 0, id = firstId; i < n; i += 1364, id++) {
    const flows = Array.from({ length: Math.min(1364, n - i) }, (_, k) => ({ src: ip(block, i + k), dst, octets: 1 + ((i + k) % 7), packets: 1 }));
    out.push(...flowsOf(flows, receivedMs, id));
  }
  return out;
}

const keyCount = (r: MinuteRollup): number => r.endpoints.length + r.conversations.length;

// --- the aggregator ----------------------------------------------------------------------------------------

test('aggregator: an open minute is held, and a minute for the same source retires it', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{}], m(0, 100), 1)) agg.add(f);
  for (const f of flowsOf([{}], m(0, 200), 2)) agg.add(f);
  assert.equal(agg.drain(), null, 'a minute still being filled posts nothing');
  for (const f of flowsOf([{}], m(1, 5), 3)) agg.add(f);
  const d = agg.drain()!;
  assert.equal(d.fragments.length, 1);
  assert.equal(d.fragments[0].rollup.minuteMs, m(0));
  assert.equal(d.fragments[0].rollup.records, 2);
  assert.equal(d.watermark, 2, 'the watermark stops before the earliest entry of the minute still open');
  assert.equal(agg.fedThrough, 3);
});

test('aggregator: a sealed fragment waits for an earlier open minute of another source', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{}], m(0, 1), 1, { engineId: 0 })) agg.add(f); // source A, open from entry 1
  for (const f of flowsOf([{}], m(0, 2), 2, { engineId: 1 })) agg.add(f); // source B, entries 2..3
  for (const f of flowsOf([{}], m(0, 3), 3, { engineId: 1 })) agg.add(f);
  for (const f of flowsOf([{}], m(1, 3), 4, { engineId: 1 })) agg.add(f); // B's minute 0 retires
  assert.equal(agg.drain(), null, 'B minute 0 ends at entry 3 but A, open from entry 1, makes the watermark 0');
  agg.seal(Infinity);
  const d = agg.drain()!;
  assert.equal(d.fragments.length, 3);
  assert.equal(d.watermark, 4);
});

test('aggregator: the watermark settles by iteration, dropping a fragment that another one holds back', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{}], m(0, 1), 1, { engineId: 2 })) agg.add(f); // G: entries 1..3 (sealed below)
  for (const f of flowsOf([{}], m(0, 2), 2, { engineId: 2 })) agg.add(f);
  for (const f of flowsOf([{}], m(0, 3), 3, { engineId: 2 })) agg.add(f);
  for (const f of flowsOf([{}], m(0, 4), 5, { engineId: 0 })) agg.add(f); // A opens at 5 and stays open
  for (const f of flowsOf([{}], m(0, 5), 6, { engineId: 1 })) agg.add(f); // F: entries 6..7
  for (const f of flowsOf([{}], m(0, 6), 7, { engineId: 1 })) agg.add(f);
  agg.seal(m(1)); // retires every open minute before minute 1... A and F included
  // Reopen A so that it is open again at the time of draining.
  for (const f of flowsOf([{}], m(1, 1), 8, { engineId: 0 })) agg.add(f);
  const d = agg.drain()!;
  assert.deepEqual(d.fragments.map((f) => [f.firstId, f.lastId]).sort(), [[1, 3], [5, 5], [6, 7]]);
  assert.equal(d.watermark, 7, 'only the open minute from entry 8 holds the watermark');
});

test('aggregator: a fragment is posted with a watermark below every entry not in the batch', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{}], m(0, 1), 1, { engineId: 2 })) agg.add(f); // G, entry 1..2
  for (const f of flowsOf([{}], m(0, 2), 2, { engineId: 2 })) agg.add(f);
  for (const f of flowsOf([{}], m(1, 2), 3, { engineId: 2 })) agg.add(f); // retires G
  for (const f of flowsOf([{}], m(0, 3), 4, { engineId: 0 })) agg.add(f); // A opens at 4
  for (const f of flowsOf([{}], m(0, 4), 5, { engineId: 1 })) agg.add(f); // F: 5..6
  for (const f of flowsOf([{}], m(0, 5), 6, { engineId: 1 })) agg.add(f);
  for (const f of flowsOf([{}], m(1, 5), 7, { engineId: 1 })) agg.add(f); // retires F
  const d = agg.drain()!;
  assert.deepEqual(d.fragments.map((f) => [f.firstId, f.lastId]), [[1, 2]], 'F (5..6) is behind the open A (from 4)');
  assert.equal(d.watermark, 2, 'G\'s next minute opened at entry 3, so the watermark is the entry before it');
});

test('aggregator: a stepped-back clock makes two fragments of one source and minute', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{ octets: 10 }], m(1, 5), 1)) agg.add(f);
  for (const f of flowsOf([{ octets: 20 }], m(0, 5), 2)) agg.add(f);
  for (const f of flowsOf([{ octets: 30 }], m(1, 9), 3)) agg.add(f);
  agg.seal(Infinity);
  const d = agg.drain()!;
  assert.deepEqual(d.fragments.map((f) => [f.rollup.minuteMs, f.rollup.reportedOctets]), [[m(1), 10n], [m(0), 20n], [m(1), 30n]]);
  assert.equal(d.watermark, 3);
});

test('aggregator: a valid export with no records still makes its minute', () => {
  const agg = new MinuteAggregator();
  agg.touch(SRC, m(2, 1), 1);
  agg.seal(Infinity);
  const r = agg.drain()!.fragments[0].rollup;
  assert.equal(r.records, 0);
  assert.equal(r.sourceKey, SRC);
});

test('aggregator: malformed and unsupported datagrams roll up under the bare exporter address', () => {
  const agg = new MinuteAggregator();
  agg.addMalformed(OTHER, m(2, 1), 1);
  agg.addMalformed(OTHER, m(2, 2), 2);
  agg.addUnsupported(OTHER, m(2, 3), 3);
  agg.seal(Infinity);
  const r = agg.drain()!.fragments[0].rollup;
  assert.equal(r.sourceKey, OTHER);
  assert.equal(r.sourceKey, exporterKey(OTHER));
  assert.equal(r.sourceKey.includes('/'), false, 'an exporter key can never equal a source key');
  assert.equal(r.malformed, 2);
  assert.equal(r.unsupported, 1);
  assert.equal(r.records, 0);
});

test('aggregator: nothing sealed means no post, not even a watermark-only one', () => {
  const agg = new MinuteAggregator(10);
  assert.equal(agg.drain(), null);
  agg.fed(11);
  agg.fed(12);
  assert.equal(agg.drain(), null, 'entries that rolled up nothing post nothing');
  assert.equal(agg.fedThrough, 12);
  agg.fed(5);
  assert.equal(agg.fedThrough, 12, 'fedThrough only rises');
});

test('aggregator: sampling is counted per record, known or not', () => {
  const agg = new MinuteAggregator();
  for (const f of flowsOf([{}, {}], m(0, 1), 1, { sampling: 0 })) agg.add(f);
  for (const f of flowsOf([{}], m(0, 2), 2, { sampling: 0x4064 })) agg.add(f);
  agg.seal(Infinity);
  const r = agg.drain()!.fragments[0].rollup;
  assert.equal(r.records, 3);
  assert.equal(r.unknownSamplingRecords, 2);
});

// --- engine admission --------------------------------------------------------------------------------------

test('admission: the first 16 engines of an exporter, in journal order, and no more', () => {
  const adm = new EngineAdmission();
  for (let e = 0; e < 16; e++) assert.equal(adm.admit(sourceKey(BUSY, 0, e)), true, `engine ${e}`);
  assert.equal(adm.admit(sourceKey(BUSY, 0, 16)), false);
  assert.equal(adm.admit(sourceKey(BUSY, 0, 0)), true, 'an admitted engine stays admitted');
  assert.equal(adm.admit(sourceKey(BUSY, 1, 0)), false, 'type is part of the engine');
  assert.equal(adm.admit(sourceKey(EXPORTER, 0, 16)), true, 'the cap is per exporter');
});

test('admission: learned from the sidecar\'s source keys, and an exporter key is not an engine', () => {
  const known = [exporterKey(BUSY), ...Array.from({ length: 16 }, (_, e) => sourceKey(BUSY, 0, e))];
  const adm = new EngineAdmission(known);
  assert.equal(adm.has(exporterKey(BUSY)), false);
  assert.equal(adm.admit(sourceKey(BUSY, 0, 99)), false, 'the 17th is refused after a restart too');
  const fewer = new EngineAdmission([exporterKey(BUSY), sourceKey(BUSY, 0, 0)]);
  assert.equal(fewer.admit(sourceKey(BUSY, 0, 1)), true, 'an exporter key does not use up a slot');
});

// --- the minute key budget ---------------------------------------------------------------------------------

test('budget: exactly 16,384 keys stay complete and the 16,385th makes the minute incomplete', () => {
  assert.equal(LIMITS.minuteKeyBudget, 16_384);
  const acc = new MinuteAccumulator(SRC, m(0), 2);
  let id = 1;
  const flows = fan(100, 8191, m(0, 1), id); // 8,191 sources + 1 destination + 8,191 conversations = 16,383 keys
  for (const f of flows) acc.addFlow(f);
  assert.equal(acc.keyCount, 16_383);
  assert.equal(acc.complete, true);
  const [a, b, c, d] = [ip(100, 1), ip(100, 2), ip(100, 3), ip(100, 4)];
  for (const f of flowsOf([{ src: a, dst: b, octets: 5, packets: 1 }], m(0, 2), 90)) acc.addFlow(f); // one new conversation: 16,384
  assert.equal(acc.keyCount, 16_384);
  assert.equal(acc.complete, true, 'at the budget is within it');
  for (const f of flowsOf([{ src: a, dst: b, octets: 5, packets: 1 }], m(0, 3), 91)) acc.addFlow(f);
  assert.equal(acc.complete, true, 'a repeat of a key already held costs nothing');
  const octetsBefore = acc.reportedOctets;
  for (const f of flowsOf([{ src: c, dst: d, octets: 7, packets: 1 }], m(0, 4), 92)) acc.addFlow(f); // the 16,385th key
  assert.equal(acc.complete, false);
  const r = acc.toRollup();
  assert.equal(r.complete, false);
  assert.equal(r.endpoints.length + r.conversations.length, 0, 'an incomplete minute lets go of its keys');
  assert.equal(r.reportedOctets, octetsBefore + 7n, 'and keeps its totals exact');
  assert.equal(r.records, 8191 + 3);
  // Once incomplete, later records still count.
  for (const f of flowsOf([{ octets: 100 }], m(0, 5), 93)) acc.addFlow(f);
  assert.equal(acc.toRollup().reportedOctets, octetsBefore + 107n);
});

test('budget: two fragments each within it whose union is past it make the sum incomplete', () => {
  const left = new MinuteAccumulator(SRC, m(0), 2);
  for (const f of fan(110, 4500, m(0, 1), 1)) left.addFlow(f);
  const right = new MinuteAccumulator(SRC, m(0), 2);
  for (const f of fan(111, 4500, m(0, 2), 10)) right.addFlow(f);
  const a = left.toRollup();
  const b = right.toRollup();
  assert.equal(a.complete && b.complete, true);
  assert.ok(keyCount(a) <= LIMITS.minuteKeyBudget && keyCount(b) <= LIMITS.minuteKeyBudget);
  const merged = new MinuteAccumulator(SRC, m(0), 2);
  merged.absorb(a);
  assert.equal(merged.complete, true);
  merged.absorb(b);
  assert.equal(merged.complete, false, 'the union is 18,001 endpoints and conversations');
  const r = merged.toRollup();
  assert.equal(r.reportedOctets, a.reportedOctets + b.reportedOctets);
  assert.equal(r.records, 9000);
});

test('budget: an incomplete fragment makes any sum it joins incomplete', () => {
  const full = new MinuteAccumulator(SRC, m(0), 2);
  full.abandon();
  full.records = 4;
  const sum = new MinuteAccumulator(SRC, m(0), 2);
  for (const f of flowsOf([{}], m(0, 1), 1)) sum.addFlow(f);
  sum.absorb(full.toRollup());
  assert.equal(sum.complete, false);
  assert.equal(sum.toRollup().records, 5);
});

// --- the generated world -------------------------------------------------------------------------------------

interface Rec { ms: number; source: string; src: string; dst: string; octets: number; packets: number; phase: 1 | 2 }
interface Bad { ms: number; exporter: string; kind: 'malformed' | 'unsupported' }
interface World { phase1: EvidenceInput[]; phase2: EvidenceInput[]; recs: Rec[]; bad: Bad[]; split: number }

/**
 * Phase 1 is what the sidecar will hold: every minute sealed by a `stop`.
 * Phase 2 arrives after and is never posted, so the watermark is behind the
 * journal and the tail lands in minutes that already have fragments.
 */
function buildWorld(seed = 7): World {
  const rnd = prng(seed);
  const pick = (n: number): number => Math.floor(rnd() * n);
  const addr = (i: number): string => `10.1.0.${1 + i}`;
  const w: World = { phase1: [], phase2: [], recs: [], bad: [], split: 0 };
  let phase: 1 | 2 = 1;
  const out = (): EvidenceInput[] => (phase === 1 ? w.phase1 : w.phase2);

  const put = (ms: number, engineId: number, flows: Partial<FlowSpec>[], header: Partial<HeaderSpec> = {}, exporter = EXPORTER): EvidenceInput => {
    for (const f of flows) {
      w.recs.push({
        ms, source: sourceKey(exporter, header.engineType ?? 0, engineId), src: f.src!, dst: f.dst!, octets: f.octets!, packets: f.packets!, phase,
      });
    }
    return dgram(ms, flows, { engineId, sampling: 0x4064, ...header }, exporter);
  };
  const rflow = (): Partial<FlowSpec> => ({
    src: addr(pick(10)), dst: rnd() < 0.05 ? addr(pick(10)) : addr(10 + pick(5)), octets: 1 + pick(5000), packets: 1 + pick(50),
  });
  /** A minute's datagrams in ascending time inside `[from, to)`, on engines 0 and 1. */
  const traffic = (n: number, from: number, to: number, count: number, header: Partial<HeaderSpec> = {}): EvidenceInput[] => {
    const times = Array.from({ length: count }, () => from + pick(to - from)).sort((a, b) => a - b);
    return times.map((t) => put(m(n, t), pick(2), Array.from({ length: 1 + pick(5) }, rflow), header));
  };
  const push = (...inputs: EvidenceInput[]): void => { out().push(...inputs); };

  // Session 1: minutes 0..5, stopped part-way through minute 5.
  push(start(m(0, -1000), S1));
  push(...traffic(0, 0, 60_000, 4));
  push(...traffic(1, 0, 60_000, 5));
  push(junk(m(1, 100)), unreadVersion(m(1, 150)), junk(m(1, 160), OTHER));
  w.bad.push({ ms: m(1, 100), exporter: EXPORTER, kind: 'malformed' }, { ms: m(1, 150), exporter: EXPORTER, kind: 'unsupported' });
  push(...traffic(2, 0, 60_000, 4, { sampling: 0 })); // a whole minute whose sampling is unknown
  for (let e = 0; e < 20; e++) push(put(m(2, 1000 + e), e, [rflow()], {}, BUSY)); // 20 engines on one exporter: 16 are admitted
  push(...traffic(3, 0, 60_000, 6));
  push(...traffic(4, 0, 60_000, 4));
  push(unreadVersion(m(4, 200)));
  w.bad.push({ ms: m(4, 200), exporter: EXPORTER, kind: 'unsupported' });
  push(...traffic(5, 0, 40_000, 3));
  push(stop(m(5, 50_000), S1));
  w.split = w.phase1.length; // everything before is sealed, so a rollup of just this much ends cleanly

  // Session 2, after a gap of nearly three minutes in which nothing was collected.
  push(start(m(8, 10_000), S2));
  push(...traffic(8, 20_000, 60_000, 3));
  push(...traffic(9, 0, 30_000, 3));
  push(boundary('gap', S2, m(9, 30_000), 'shed', 7));
  push(...traffic(9, 30_000, 60_000, 3));
  // A clock that steps back: minute 10, 11, 10, 11 in entry order, so each is two fragments.
  push(...traffic(10, 0, 60_000, 3));
  push(...traffic(11, 0, 60_000, 3));
  push(...traffic(10, 0, 60_000, 3));
  push(...traffic(11, 0, 60_000, 3));
  // Minute 12: engine 0 sends 9,548 distinct sources, which is past the budget in endpoints and conversations together.
  for (let k = 0; k < 7; k++) {
    const flows = Array.from({ length: 1364 }, (_, i) => ({ src: ip(100, k * 1364 + i), dst: '172.16.0.1', octets: 1 + (i % 7), packets: 1 }));
    push(put(m(12, 1000 * (k + 1)), 0, flows));
  }
  push(put(m(12, 30_000), 1, [rflow(), rflow()]));
  // Minute 13 twice, with minute 14 between: two complete fragments whose union is past the budget.
  const block = (b: number, k0: number, n: number): Partial<FlowSpec>[] =>
    Array.from({ length: n }, (_, i) => ({ src: ip(b, k0 + i), dst: '172.16.0.1', octets: 2 + (i % 5), packets: 2 }));
  for (let k = 0; k < 4; k++) push(put(m(13, 100 * (k + 1)), 0, block(120, k * 1364, k === 3 ? 408 : 1364)));
  push(put(m(14, 500), 0, [rflow()]));
  for (let k = 0; k < 4; k++) push(put(m(13, 10_000 + 100 * (k + 1)), 0, block(121, k * 1364, k === 3 ? 408 : 1364)));
  push(put(m(14, 20_000), 1, [rflow()]));
  push(stop(m(14, 40_000), S2));

  // Phase 2: a third session, never closed, and entries that land in minutes the sidecar already holds.
  phase = 2;
  push(start(m(15, 5000), S3));
  push(...traffic(15, 6000, 60_000, 4));
  push(put(m(13, 20_000), 0, [rflow()])); // into the union minute
  push(put(m(12, 59_000), 0, [rflow()])); // into the incomplete minute
  push(...traffic(16, 0, 30_000, 4));
  push(put(m(9, 50_000), 1, [rflow(), rflow()])); // into a minute with a gap point
  push(put(m(6, 10_000), 0, [rflow()])); // into the gap itself
  push(put(m(3, 33_000), 0, [rflow()])); // into a complete minute
  push(junk(m(10, 20_000)));
  w.bad.push({ ms: m(10, 20_000), exporter: EXPORTER, kind: 'malformed' });
  push(...traffic(16, 30_000, 60_000, 2));
  return w;
}

interface Built { rig: Rig; world: World; watermark: number }

/** The world in a rig, with phase 1 rolled up by a real host and phase 2 left in the journal's tail. */
async function build(seed = 7, rigSeed = 0xa0): Promise<Built> {
  const world = buildWorld(seed);
  const rig = new Rig(rigSeed);
  rig.append(world.phase1);
  const host = await rollUp(rig);
  host.host.handle({ type: 'shutdown', requestId: 9000 });
  await host.host.settled();
  rig.append(world.phase2);
  const mark = await rig.runtime.watermark();
  assert.ok(mark !== null);
  return { rig, world, watermark: mark.throughEntryId };
}

const built: Promise<Built> = build();

// --- the queries the harness asks -----------------------------------------------------------------------------

const RANGES: [string, number, number, number[]][] = [
  ['everything, minute-aligned', m(0), m(17), [1, 2, 3, 7, 12, 17]],
  ['everything, ragged edges', m(0, 12_345), m(17, -6789), [3, 7, 16]],
  ['one minute inside, aligned', m(3), m(4), [1, 2, 4]],
  ['a minute with a tail entry in it', m(3), m(4), [3]],
  ['inside a minute, both edges raw', m(2, 5000), m(3, 5000), [1, 2]],
  ['a few seconds', m(3, 100), m(3, 20_000), [1, 5]],
  ['across the gap', m(5), m(9), [4, 5]],
  ['into the gap point', m(9, -10_000), m(10, 20_000), [4]],
  ['the stepped-back minutes', m(10), m(12), [2, 3]],
  ['the incomplete minute', m(12), m(13), [1, 3]],
  ['the key-union minutes', m(13), m(15), [2, 6]],
  ['into the tail', m(14), m(17), [3, 4]],
  ['the gap and its neighbours', m(4), m(9, 30_000), [5]],
  ['seven buckets over twelve minutes, so every boundary straddles', m(1), m(13), [7]],
];

const SOURCES = [SRC, SRC1, sourceKey(EXPORTER, 9, 9), sourceKey(BUSY, 0, 3), sourceKey(BUSY, 0, 18)];

function describe(r: HistoryResult): string {
  return `${r.answeredFrom.rollupMinutes} rollup / ${r.answeredFrom.rawMinutes} raw`;
}

test('equality: a rollup answer is the raw-scan answer, over every range, bucket count and source', async () => {
  const { rig } = await built;
  let rollupMinutes = 0;
  let asked = 0;
  const coverage = new Set<string>();
  for (const [label, from, to, counts] of RANGES) {
    for (const n of counts) {
      for (const source of SOURCES) {
        // The unadmitted and the busy exporter's sources are only asked of the wide ranges: they have nothing to say elsewhere.
        if (source !== SRC && source !== SRC1 && label !== 'everything, minute-aligned' && label !== 'the key-union minutes') continue;
        const { fast, raw } = await askBoth(rig, spec(from, to, n, { sourceKey: source }));
        assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), `${label}, ${n} buckets, ${source} (${describe(fast)})`);
        assert.equal(raw.answeredFrom.rollupMinutes, 0, 'the oracle path reads nothing from the sidecar');
        rollupMinutes += fast.answeredFrom.rollupMinutes;
        for (const b of fast.buckets) coverage.add(b.coverage);
        asked++;
      }
    }
  }
  assert.ok(asked > 60, `asked ${asked}`);
  assert.ok(rollupMinutes > 0, 'the harness cannot pass by reading everything raw');
  assert.deepEqual([...coverage].sort(), ['collection-gap', 'no-records', 'observed-records'], 'the ranges reach every coverage');
});

test('equality: the wide aligned range really is answered from rollups, minute by minute', async () => {
  const { rig, watermark } = await built;
  const fast = await askOk(rig, spec(m(0), m(17), 1));
  // A minute the source has nothing in is answered from nowhere and counted nowhere; 12 and 13 are the two it cannot do from rollups.
  const { world } = await built;
  const withData = new Set(world.recs.filter((r) => r.source === SRC).map((r) => Math.floor((r.ms - BASE) / MIN)));
  const complete = [...withData].filter((x) => x !== 12 && x !== 13);
  assert.equal(fast.answeredFrom.rollupMinutes, complete.length, 'one per minute the source has anything in, bar the two it cannot do');
  assert.equal(fast.answeredFrom.rawMinutes, 2, 'minutes 12 and 13');
  assert.ok(watermark < rig.through, 'the sidecar is behind the journal, so the tail was in play');
});

test('equality: a focused query, which is always raw, is the same on both paths', async () => {
  const { rig } = await built;
  for (const focus of [
    { kind: 'endpoint', address: '10.1.0.1' } as const,
    { kind: 'conversation', srcAddr: '10.1.0.2', dstAddr: '10.1.0.12' } as const,
  ]) {
    const { fast, raw } = await askBoth(rig, spec(m(0), m(17), 5, { focus }));
    assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
    assert.equal(fast.answeredFrom.rollupMinutes, 0);
  }
});

test('equality: the bare exporter key is not a source, on either path, and the engine keys agree on what it holds', async () => {
  const { rig } = await built;
  // The sidecar does hold the exporter-level key (it carries the malformed and
  // unsupported counts), so refusing it is a decision and not an absence.
  assert.ok(rig.store.sources().includes(exporterKey(EXPORTER)));
  for (const exporter of [EXPORTER, BUSY, OTHER]) {
    for (const forceRaw of [false, true]) {
      const reply = await ask(rig, spec(m(0), m(17), 5, { sourceKey: exporterKey(exporter) }), { forceRaw });
      assert.ok(!reply.ok && reply.code === 'invalid-query', `${exporter} (forceRaw ${forceRaw}): ${JSON.stringify(reply.ok ? 'ok' : reply.code)}`);
    }
  }
  // What the bare key would have shown is still reachable, from an engine of that exporter, and the two paths agree on it.
  for (const source of [SRC, SRC1, sourceKey(EXPORTER, 9, 9)]) {
    const { fast, raw } = await askBoth(rig, spec(m(0), m(17), 5, { sourceKey: source }));
    assert.equal(fast.malformed, raw.malformed, `malformed through ${source}`);
    assert.equal(fast.unsupported, raw.unsupported, `unsupported through ${source}`);
    assert.ok(raw.malformed > 0 && raw.unsupported > 0, `${source} sees its exporter's bad datagrams: ${raw.malformed}/${raw.unsupported}`);
  }
});

test('equality: the stored sidecar holds every phase-1 record and no phase-2 record', async () => {
  const { rig, world, watermark } = await built;
  assert.equal(watermark, world.phase1.length, 'the watermark is the stop that sealed phase 1');
  let stored = 0;
  const sources = rig.store.sources();
  assert.ok(sources.includes(SRC) && sources.includes(SRC1) && sources.includes(exporterKey(EXPORTER)));
  for (const s of sources) {
    for (const h of rig.store.readMinutes(s, 0, Number.MAX_SAFE_INTEGER, 1 << 30)) {
      assert.ok(h.throughEntryId <= watermark, `a fragment posted at ${h.throughEntryId}, past the watermark ${watermark}`);
      stored += decodeMinuteRollup(h.bytes, inflate).records;
    }
  }
  const admitted = world.recs.filter((r) => r.phase === 1 && !(r.source.startsWith(`${BUSY}/`) && Number(r.source.split('/')[2]) >= 16));
  assert.equal(stored, admitted.length, 'the sidecar holds the admitted records of phase 1 and nothing of phase 2');
});

test('equality: only the 16 admitted engines of the busy exporter have rows', async () => {
  const { rig } = await built;
  const sources = rig.store.sources().filter((s) => s.startsWith(`${BUSY}/`));
  assert.equal(sources.length, 16);
  assert.equal(sources.includes(sourceKey(BUSY, 0, 15)), true);
  assert.equal(sources.includes(sourceKey(BUSY, 0, 16)), false);
  const refused = await askOk(rig, spec(m(0), m(17), 1, { sourceKey: sourceKey(BUSY, 0, 18) }));
  assert.equal(refused.matchingRecords, 0);
  const admitted = await askOk(rig, spec(m(0), m(17), 1, { sourceKey: sourceKey(BUSY, 0, 3) }));
  assert.equal(admitted.matchingRecords, 1);
});

// --- the independent oracle ----------------------------------------------------------------------------------

const numeric = (a: string): number => a.split('.').reduce((n, p) => n * 256 + Number(p), 0);

test('oracle: buckets, tables and counts equal a sum computed from the generator\'s own list', async () => {
  const { rig, world } = await built;
  for (const source of [SRC, SRC1]) {
    for (const buckets of [1, 4, 8, 16]) {
      const from = m(0);
      const to = m(16);
      const got = await askOk(rig, spec(from, to, buckets, { sourceKey: source }));
      const span = (to - from) / buckets;
      for (let i = 0; i < buckets; i++) {
        const mine = world.recs.filter((r) => r.source === source && r.ms >= from + i * span && r.ms < from + (i + 1) * span);
        const b = got.buckets[i];
        assert.equal(b.records, mine.length, `bucket ${i} of ${buckets}`);
        assert.equal(b.reportedOctets, mine.length === 0 ? null : BigInt(mine.reduce((s, r) => s + r.octets, 0)));
        assert.equal(b.reportedPackets, mine.length === 0 ? null : BigInt(mine.reduce((s, r) => s + r.packets, 0)));
      }
      const all = world.recs.filter((r) => r.source === source && r.ms >= from && r.ms < to);
      assert.equal(got.matchingRecords, all.length);
    }
  }
  // Tables, over a range without the incomplete minutes' 9,000-key tables to sort: minutes 0..9.
  const range = world.recs.filter((r) => r.source === SRC && r.ms >= m(0) && r.ms < m(10));
  const sent = new Map<string, bigint>();
  const received = new Map<string, bigint>();
  const pairs = new Map<string, { src: string; dst: string; octets: bigint; packets: bigint }>();
  for (const r of range) {
    sent.set(r.src, (sent.get(r.src) ?? 0n) + BigInt(r.octets));
    received.set(r.dst, (received.get(r.dst) ?? 0n) + BigInt(r.octets));
    const k = `${r.src}>${r.dst}`;
    const p = pairs.get(k) ?? { src: r.src, dst: r.dst, octets: 0n, packets: 0n };
    p.octets += BigInt(r.octets);
    p.packets += BigInt(r.packets);
    pairs.set(k, p);
  }
  const addresses = [...new Set([...sent.keys(), ...received.keys()])];
  const wantEndpoints = addresses
    .map((address) => ({ address, sentOctets: sent.get(address) ?? 0n, receivedOctets: received.get(address) ?? 0n }))
    .sort((a, b) => Number((b.sentOctets + b.receivedOctets) - (a.sentOctets + a.receivedOctets)) || numeric(a.address) - numeric(b.address))
    .slice(0, LIMITS.topRows);
  const wantConversations = [...pairs.values()]
    .sort((a, b) => Number(b.octets - a.octets) || numeric(a.src) - numeric(b.src) || numeric(a.dst) - numeric(b.dst))
    .slice(0, LIMITS.topRows)
    .map((p) => ({ srcAddr: p.src, dstAddr: p.dst, reportedOctets: p.octets, reportedPackets: p.packets }));
  const got = await askOk(rig, spec(m(0), m(10), 5));
  assert.deepEqual(got.endpoints, { status: 'ok', rows: wantEndpoints });
  assert.deepEqual(got.conversations, { status: 'ok', rows: wantConversations });
});

test('oracle: malformed and unsupported datagrams of the source\'s exporter are counted, those of another exporter are not', async () => {
  const { rig, world } = await built;
  for (const [from, to] of [[m(0), m(17)], [m(1), m(2)], [m(4), m(5)], [m(10), m(11)]]) {
    const mine = world.bad.filter((b) => b.exporter === EXPORTER && b.ms >= from && b.ms < to);
    for (const source of [SRC, SRC1]) {
      const got = await askOk(rig, spec(from, to, 1, { sourceKey: source }));
      assert.equal(got.malformed, mine.filter((b) => b.kind === 'malformed').length, `malformed in ${from}-${to}`);
      assert.equal(got.unsupported, mine.filter((b) => b.kind === 'unsupported').length, `unsupported in ${from}-${to}`);
    }
  }
  const other = await askOk(rig, spec(m(0), m(17), 1, { sourceKey: sourceKey(OTHER, 0, 0) }));
  assert.equal(other.malformed, 1, 'the other exporter has its own count');
});

// --- the incomplete minute and the key union ---------------------------------------------------------------------

test('incomplete: a minute over the key budget is stored incomplete and answered from the journal', async () => {
  const { rig, world } = await built;
  const stored = rig.store.readMinutes(SRC, m(12), m(13), 1 << 30);
  assert.equal(stored.length, 1);
  const r = decodeMinuteRollup(stored[0].bytes, inflate);
  assert.equal(r.complete, false);
  assert.equal(r.endpoints.length + r.conversations.length, 0);
  assert.equal(r.records, 7 * 1364, 'the totals are exact');
  const want = world.recs.filter((x) => x.phase === 1 && x.source === SRC && x.ms >= m(12) && x.ms < m(13));
  assert.equal(r.reportedOctets, BigInt(want.reduce((s, x) => s + x.octets, 0)));
  const fast = await askOk(rig, spec(m(12), m(13), 1));
  assert.deepEqual(fast.answeredFrom, { rollupMinutes: 0, rawMinutes: 1 });
  assert.equal(fast.endpoints.status, 'ok');
});

test('incomplete: two complete fragments whose keys are past the budget together are answered from the journal', async () => {
  const { rig } = await built;
  const stored = rig.store.readMinutes(SRC, m(13), m(14), 1 << 30).map((s) => decodeMinuteRollup(s.bytes, inflate));
  assert.equal(stored.length, 2, 'the stepped-back clock left two fragments of minute 13');
  assert.ok(stored.every((s) => s.complete && keyCount(s) <= LIMITS.minuteKeyBudget));
  assert.ok(stored[0].endpoints.length + stored[1].endpoints.length + stored[0].conversations.length + stored[1].conversations.length > LIMITS.minuteKeyBudget);
  const fast = await askOk(rig, spec(m(13), m(14), 1));
  assert.deepEqual(fast.answeredFrom, { rollupMinutes: 0, rawMinutes: 1 }, 'the union, not either fragment, is what is checked');
  const raw = await askOk(rig, spec(m(13), m(14), 1), { forceRaw: true });
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
});

test('incomplete: a complete minute with a tail entry after the watermark is still a rollup minute, with the tail added', async () => {
  const { rig, world } = await built;
  const fast = await askOk(rig, spec(m(3), m(4), 1));
  assert.deepEqual(fast.answeredFrom, { rollupMinutes: 1, rawMinutes: 0 });
  const want = world.recs.filter((x) => x.source === SRC && x.ms >= m(3) && x.ms < m(4));
  assert.ok(want.some((x) => x.phase === 2), 'the fixture put a phase-2 record in the minute');
  assert.ok(want.some((x) => x.phase === 1));
  assert.equal(fast.matchingRecords, want.length);
});

// --- tables --------------------------------------------------------------------------------------------------------

/** `grid` conversations per minute as a rectangle of sources by destinations, in an address block of its own. */
function gridWorld(conversationsPerMinute: [number, number][]): EvidenceInput[] {
  const inputs: EvidenceInput[] = [start(m(0, -1000))];
  conversationsPerMinute.forEach(([srcs, dsts], minute) => {
    const flows: Partial<FlowSpec>[] = [];
    for (let s = 0; s < srcs; s++) {
      for (let d = 0; d < dsts; d++) flows.push({ src: `10.${50 + minute}.${s >> 8}.${s & 255}`, dst: `11.${50 + minute}.${d >> 8}.${d & 255}`, octets: 1 + ((s + d) % 9), packets: 1 });
    }
    for (let i = 0; i < flows.length; i += 1364) inputs.push(dgram(m(minute, 100 + (i / 1364)), flows.slice(i, i + 1364)));
  });
  inputs.push(stop(m(conversationsPerMinute.length, 100)));
  return inputs;
}

async function tableAnswer(grid: [number, number][]): Promise<{ fast: HistoryResult; raw: HistoryResult; flows: number }> {
  const rig = new Rig();
  rig.append(gridWorld(grid));
  const host = await rollUp(rig);
  host.host.handle({ type: 'shutdown', requestId: 9000 });
  await host.host.settled();
  const { fast, raw } = await askBoth(rig, spec(m(0), m(grid.length), grid.length));
  return { fast, raw, flows: grid.reduce((n, [s, d]) => n + s * d, 0) };
}

test('tables: exactly 50,000 distinct conversations are listed', async () => {
  const { fast, raw, flows } = await tableAnswer([[100, 150], [100, 150], [100, 150], [50, 100]]);
  assert.equal(flows, 50_000);
  assert.equal(fast.conversations.status, 'ok');
  assert.equal(fast.matchingRecords, 50_000);
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  assert.ok(fast.answeredFrom.rollupMinutes > 0);
});

test('tables: 50,001 conversations refuse the conversations table and keep every total exact', async () => {
  const { fast, raw, flows } = await tableAnswer([[100, 150], [100, 150], [100, 150], [3, 1667]]);
  assert.equal(flows, 50_001);
  assert.equal(fast.conversations.status, 'range-too-large');
  assert.match((fast.conversations as { message: string }).message, /50,000|50000/);
  assert.equal(fast.endpoints.status, 'ok', 'the endpoints table has its own bound and is nowhere near it');
  assert.equal(fast.matchingRecords, 50_001);
  assert.ok(fast.buckets.every((b) => b.records > 0 && b.reportedOctets !== null && b.reportedPackets !== null));
  assert.equal(fast.buckets.reduce((n, b) => n + b.records, 0), 50_001);
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), 'the raw path refuses the same table in the same words');
  assert.equal(raw.conversations.status, 'range-too-large');
});

// --- the sidecar is a cache --------------------------------------------------------------------------------------

/** The answers the pristine rig gives with every minute read from the journal. */
async function reference(rig: Rig): Promise<HistoryResult[]> {
  const out: HistoryResult[] = [];
  for (const [, from, to, counts] of RANGES) for (const n of counts.slice(0, 2)) for (const s of [SRC, SRC1]) out.push(await askOk(rig, spec(from, to, n, { sourceKey: s }), { forceRaw: true }));
  return out;
}

async function asAnswered(rig: Rig): Promise<{ answers: HistoryResult[]; rollupMinutes: number }> {
  const answers: HistoryResult[] = [];
  let rollupMinutes = 0;
  for (const [, from, to, counts] of RANGES) {
    for (const n of counts.slice(0, 2)) {
      for (const s of [SRC, SRC1]) {
        const a = await askOk(rig, spec(from, to, n, { sourceKey: s }));
        answers.push(a);
        rollupMinutes += a.answeredFrom.rollupMinutes;
      }
    }
  }
  return { answers, rollupMinutes };
}

async function recovered(damage: (rig: Rig) => Promise<void> | void, expectStatus: string[]): Promise<void> {
  const { rig: pristine } = await built;
  const want = (await reference(pristine)).map(withoutProvenance);
  const world = buildWorld();
  const rig = new Rig();
  // Two batches in the sidecar, so a torn tail has an earlier one to keep.
  rig.append(world.phase1.slice(0, world.split));
  const a = await rollUp(rig);
  a.host.handle({ type: 'shutdown', requestId: 9000 });
  await a.host.settled();
  rig.append(world.phase1.slice(world.split));
  const first = await rollUp(rig);
  first.host.handle({ type: 'shutdown', requestId: 9000 });
  await first.host.settled();
  await damage(rig);
  rig.append(world.phase2);
  rig.openSidecar();
  assert.ok(expectStatus.includes(rig.sidecarStatus), 'the sidecar opened as ' + rig.sidecarStatus);
  const second = await rollUp(rig);
  assert.ok(second.phases().includes('live'), 'the rebuild finished');
  const { answers, rollupMinutes } = await asAnswered(rig);
  assert.ok(rollupMinutes > 0, 'the rebuilt sidecar is being used');
  assert.deepEqual(answers.map(withoutProvenance), want);
  const mark = await rig.runtime.watermark();
  assert.ok(mark !== null && mark.generation === rig.generation);
}

test('sidecar: a deleted sidecar is rebuilt to identical answers', async () => {
  await recovered((rig) => { rig.sfile = new MemoryBlockFile(); }, ['empty']);
});

test('sidecar: a sidecar with a torn batch loses the batch and is rebuilt to identical answers', async () => {
  await recovered((rig) => { rig.sfile.truncate(rig.sfile.size() - 37); }, ['ok']);
});

test('sidecar: a sidecar cut in half is rebuilt to identical answers', async () => {
  await recovered((rig) => { rig.sfile.truncate(Math.floor(rig.sfile.size() / 2)); }, ['ok', 'empty']);
});

test('sidecar: a sidecar of another generation is reset and rebuilt to identical answers', async () => {
  const foreign = await build(7, 0x10);
  const bytes = foreign.rig.sidecarBytes();
  assert.ok(bytes.length > 100);
  await recovered((rig) => {
    rig.sfile = new MemoryBlockFile();
    rig.sfile.write(0, bytes);
  }, ['rebuild-required']);
});

// --- replay ------------------------------------------------------------------------------------------------------

interface Posted { sourceKey: string; minuteMs: number; hex: string }

function recordPosts(rig: Rig): { posts: Posted[]; marks: number[] } {
  const posts: Posted[] = [];
  const marks: number[] = [];
  const original = rig.runtime.appendMinutes.bind(rig.runtime);
  rig.runtime.appendMinutes = async (minutes, watermark, afterEntryId) => {
    for (const x of minutes) posts.push({ sourceKey: x.sourceKey, minuteMs: x.minuteMs, hex: Buffer.from(x.bytes).toString('hex') });
    marks.push(watermark.throughEntryId);
    return original(minutes, watermark, afterEntryId);
  };
  return { posts, marks };
}

const byIdentity = (a: Posted, b: Posted): number =>
  a.sourceKey < b.sourceKey ? -1 : a.sourceKey > b.sourceKey ? 1 : a.minuteMs - b.minuteMs || (a.hex < b.hex ? -1 : a.hex > b.hex ? 1 : 0);

test('replay: rebuilding the same journal twice posts byte-identical rollups', async () => {
  const world = buildWorld();
  const runs: { posts: Posted[]; marks: number[] }[] = [];
  for (let i = 0; i < 2; i++) {
    const rig = new Rig();
    rig.append(world.phase1);
    const rec = recordPosts(rig);
    const h = await rollUp(rig);
    h.host.handle({ type: 'shutdown', requestId: 9000 });
    await h.host.settled();
    runs.push(rec);
  }
  assert.ok(runs[0].posts.length > 20);
  assert.deepEqual(runs[1].posts, runs[0].posts, 'same fragments, same order, same bytes');
  assert.deepEqual(runs[1].marks, runs[0].marks);
});

test('replay: following the journal live in small pieces posts the same rollups as rebuilding it', async () => {
  const world = buildWorld();
  const rebuilt = new Rig();
  rebuilt.append(world.phase1);
  const a = recordPosts(rebuilt);
  const h1 = await rollUp(rebuilt);
  h1.host.handle({ type: 'shutdown', requestId: 9000 });
  await h1.host.settled();

  const live = new Rig();
  live.append([world.phase1[0]]);
  const b = recordPosts(live);
  const h2 = await rollUp(live);
  assert.equal(h2.host.rebuildPhase, 'live');
  for (let i = 1; i < world.phase1.length; i += 37) {
    const entries = live.add(...world.phase1.slice(i, i + 37));
    live.runtime.publishLive(entries);
    await h2.host.settled();
  }
  h2.host.handle({ type: 'shutdown', requestId: 9000 });
  await h2.host.settled();

  assert.deepEqual([...b.posts].sort(byIdentity), [...a.posts].sort(byIdentity), 'the same fragments, whenever they were posted');
  assert.equal(b.marks[b.marks.length - 1], a.marks[a.marks.length - 1], 'and the same final watermark');
  assert.equal((await live.runtime.watermark())!.throughEntryId, world.phase1.length);
  // And the byte-for-byte claim, against the codec: what was posted is what encodeMinuteRollup writes.
  for (const p of a.posts.slice(0, 5)) {
    const r = decodeMinuteRollup(Uint8Array.from(Buffer.from(p.hex, 'hex')), inflate);
    assert.equal(Buffer.from(encodeMinuteRollup(r, deflate)).toString('hex'), p.hex);
  }
});

test('replay: asking the same question twice gives the same answer', async () => {
  const { rig } = await built;
  for (const [, from, to, counts] of RANGES.slice(0, 5)) {
    const a = await askOk(rig, spec(from, to, counts[0]));
    const b = await askOk(rig, spec(from, to, counts[0]));
    assert.deepEqual(b, a);
  }
});

test('replay: a restart reopens the same journal and the sidecar, and the answers do not change', async () => {
  const { rig, world } = await built;
  const before = await askOk(rig, spec(m(0), m(17), 6));
  rig.reopen();
  assert.equal(rig.sidecarStatus, 'ok');
  const h = await rollUp(rig);
  const after = await askOk(rig, spec(m(0), m(17), 6));
  assert.equal(after.matchingRecords, before.matchingRecords);
  assert.equal(after.matchingRecords, world.recs.filter((r) => r.source === SRC && r.ms >= m(0) && r.ms < m(17)).length);
  assert.ok(h.phases().includes('live'));
  void minuteOf;
  void ask;
  void NOW;
});

// --- accepted policies and expiry (ADR 0062) -----------------------------------------------------------------

test('codec: a minute is written under its own policy, the newest is the written one, and every accepted policy round-trips', () => {
  assert.equal(WRITE_POLICY_VERSION, Math.max(...ACCEPTED_POLICIES));
  for (const v of ACCEPTED_POLICIES) {
    const acc = new MinuteAccumulator(SRC, m(0), v);
    for (const f of flowsOf([{ src: '10.1.1.1', dst: '10.1.1.2', octets: 5, packets: 2 }], m(0, 5), 1)) acc.addFlow(f);
    const rollup = acc.toRollup();
    const bytes = encodeMinuteRollup(rollup, deflate);
    assert.equal(new DataView(bytes.buffer, bytes.byteOffset).getUint16(0, true), v, `policy ${v} prefix`);
    assert.deepEqual(decodeMinuteRollup(bytes, inflate), rollup, `policy ${v}`);
  }
});

test('codec: a policy this build does not accept is refused before anything is inflated', () => {
  const bytes = encodeMinuteRollup(new MinuteAccumulator(SRC, m(0), 2).toRollup(), deflate);
  const refused = [0, Math.max(...ACCEPTED_POLICIES) + 1, 0xffff].filter((v) => !ACCEPTED_POLICIES.includes(v));
  for (const v of refused) {
    const copy = bytes.slice();
    new DataView(copy.buffer).setUint16(0, v, true);
    // The body after the version is garbage on purpose: a reader that inflated first would fail differently.
    copy.fill(0xee, 2);
    assert.throws(() => decodeMinuteRollup(copy, inflate), /decoder policy version/, `policy ${v}`);
  }
});

test('equality after an expiry: the retained journal is answered the same from rollups and from raw', async () => {
  const LIMIT = 32 * 1024 * 1024; // 1 MiB segments
  const S4 = '04'.repeat(16);
  const world = buildWorld();
  const rig = new Rig(0xa0, LIMIT);
  // Two sealed segments of an earlier session, then the awkward world of the tests above.
  const filler: EvidenceInput[] = [start(m(-61), S4)];
  for (let i = 0; i < 2600; i++) {
    const flows = Array.from({ length: 20 }, (_, j) => ({ src: `10.${i % 5}.${j}.1`, dst: `172.16.${j % 4}.1`, octets: 50 + j, packets: 1 }));
    filler.push(dgram(m(-60, i * 1000), flows, { engineId: i % 3 === 0 ? 1 : 0, sampling: 0x4064 }));
  }
  filler.push(stop(m(-16), S4));
  for (let at = 0; at < filler.length; at += 100) rig.append(filler.slice(at, at + 100));
  rig.append(world.phase1);
  const first = await rollUp(rig);
  first.host.handle({ type: 'shutdown', requestId: 9000 });
  await first.host.settled();
  const segs = rig.journal.segments();
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, LIMIT, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null && plan.segments.length === 2 && plan.throughMs < m(-16), 'only the earlier session expires');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
  rig.reopen();
  assert.ok(rig.journal.snapshot().firstEntryId > 1);
  const second = await rollUp(rig);
  second.host.handle({ type: 'shutdown', requestId: 9001 });
  await second.host.settled();
  rig.append(world.phase2);
  let rollupMinutes = 0;
  let asked = 0;
  for (const [label, from, to, counts] of RANGES) {
    for (const n of counts) {
      for (const source of SOURCES) {
        const { fast, raw } = await askBoth(rig, spec(from, to, n, { sourceKey: source }));
        assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), `${label}, ${n} buckets, ${source}`);
        assert.ok(fast.buckets.every((b) => b.coverage !== 'history-lost' && b.coverage !== 'aggregate-only'), label);
        rollupMinutes += fast.answeredFrom.rollupMinutes;
        asked++;
      }
    }
  }
  assert.ok(asked > 100 && rollupMinutes > 0, 'the property was asked of rollups, not only of raw reads');
});


// --- v9 and IPFIX: the same property over a journal whose records need templates ---------------------------------

const TF_SRC: WireField = { type: 8, length: 4 };
const TF_DST: WireField = { type: 12, length: 4 };
const TF_OCT: WireField = { type: 1, length: 4 };
const TF_PKT: WireField = { type: 2, length: 4 };
const TF_SAMP: WireField = { type: 34, length: 4 };
const LAYOUT_OP: WireField[] = [TF_SRC, TF_DST, TF_OCT, TF_PKT, TF_SAMP];
const LAYOUT_PO: WireField[] = [TF_SRC, TF_DST, TF_PKT, TF_OCT, TF_SAMP];

let tseq = 0;
const V9_1 = sourceKeyFor('v9', EXPORTER, 1);
const V9_2 = sourceKeyFor('v9', EXPORTER, 2);
const IPFIX_5 = sourceKeyFor('ipfix', EXPORTER, 5);

function tdata(layout: 'OP' | 'PO', src: string, dst: string, octets: number, packets: number, samp = 0): number[] {
  const counts = layout === 'OP' ? [octets, packets] : [packets, octets];
  return [...be.ipv4(src), ...be.ipv4(dst), ...be.u32(counts[0]), ...be.u32(counts[1]), ...be.u32(samp)];
}
function v9Ev(ms: number, sets: number[][], id: number, skewSecs = 0): EvidenceInput {
  const bytes = v9Message({ uptime: ms - BASE + 5_000_000, secs: Math.floor(ms / 1000) + skewSecs, sequence: tseq++, sourceId: id }, sets);
  return { kind: 'datagram', receivedMs: ms, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}
function ipfixEv(ms: number, sets: number[][], domain: number): EvidenceInput {
  const bytes = ipfixMessage({ secs: Math.floor(ms / 1000), sequence: tseq++, domain }, sets);
  return { kind: 'datagram', receivedMs: ms, localIPv4: COLLECTOR, localPort: 4739, remoteIPv4: EXPORTER, remotePort: 40_000, bytes };
}
const tplV9 = (id: number, layout: 'OP' | 'PO'): number[] => templateSet(9, [templateRecord(9, id, layout === 'OP' ? LAYOUT_OP : LAYOUT_PO)]);
const tplIpfix = (id: number): number[] => templateSet(10, [templateRecord(10, id, LAYOUT_OP)]);

/** Templates in minute 0, data after; a redefinition mid-minute; awaiting data; a skewed clock; a second session; a tail. */
function templatedWorld(): { phase1: EvidenceInput[]; phase2: EvidenceInput[]; minute1V9: bigint; minute1Ipfix: bigint } {
  const phase1: EvidenceInput[] = [];
  const phase2: EvidenceInput[] = [];
  phase1.push(start(m(0), S1));
  phase1.push(v9Ev(m(0, 1000), [tplV9(256, 'OP')], 1), v9Ev(m(0, 2000), [tplV9(256, 'PO')], 2), ipfixEv(m(0, 3000), [tplIpfix(300)], 5));
  // Minute 1: the templates are a minute old.
  const v9a = [tdata('OP', '10.4.0.1', '10.4.0.2', 1000, 10, 100), tdata('OP', '10.4.0.3', '10.4.0.2', 2000, 20, 100)];
  phase1.push(v9Ev(m(1, 1000), [dataSet(256, v9a)], 1));
  phase1.push(v9Ev(m(1, 2000), [dataSet(256, [tdata('PO', '10.4.1.1', '10.4.1.2', 700, 7)])], 2));
  phase1.push(ipfixEv(m(1, 3000), [dataSet(300, [tdata('OP', '10.4.2.1', '10.4.2.2', 50, 5), tdata('OP', '10.4.2.1', '10.4.2.3', 60, 6)])], 5));
  phase1.push(v9Ev(m(1, 4000), [dataSet(999, [[1, 2, 3, 4]])], 1)); // a template nobody sent
  // Minute 2: id 1 redefines 256 in the middle of the minute, with data either side and a different rate.
  phase1.push(v9Ev(m(2, 1000), [dataSet(256, [tdata('OP', '10.4.0.1', '10.4.0.2', 111, 1, 200)])], 1));
  phase1.push(v9Ev(m(2, 20_000), [tplV9(256, 'PO'), dataSet(256, [tdata('PO', '10.4.0.1', '10.4.0.2', 222, 2, 200)])], 1));
  phase1.push(v9Ev(m(2, 40_000), [dataSet(256, [tdata('PO', '10.4.0.5', '10.4.0.6', 333, 3, 100)])], 1));
  // Minute 3: an export clock 20 s ahead, and a v5 datagram beside the templated ones.
  phase1.push(v9Ev(m(3, 5000), [dataSet(256, [tdata('PO', '10.4.0.1', '10.4.0.2', 5, 5)])], 1, 20));
  phase1.push(dgram(m(3, 6000), [{ src: '10.9.0.1', dst: '10.9.0.2', octets: 9, packets: 9 }]));
  phase1.push(junk(m(3, 7000)));
  phase1.push(stop(m(3, 50_000), S1));
  // A second session, after a gap: whatever the store keeps of the first session's templates, both paths must say the same.
  phase1.push(start(m(5, 10_000), S2));
  phase1.push(v9Ev(m(5, 12_000), [dataSet(256, [tdata('PO', '10.4.0.1', '10.4.0.2', 17, 1)])], 1));
  phase1.push(v9Ev(m(5, 20_000), [tplV9(256, 'OP'), dataSet(256, [tdata('OP', '10.4.0.1', '10.4.0.2', 19, 1)])], 1));
  phase1.push(ipfixEv(m(5, 30_000), [dataSet(300, [tdata('OP', '10.4.2.1', '10.4.2.2', 23, 1)])], 5));
  phase1.push(stop(m(6, 20_000), S2));
  // The tail: a third session the sidecar never sees, with entries that land in minutes it already holds.
  phase2.push(start(m(7, 5000), S3));
  phase2.push(v9Ev(m(7, 6000), [dataSet(256, [tdata('OP', '10.4.0.1', '10.4.0.2', 29, 1)])], 1));
  phase2.push(v9Ev(m(2, 50_000), [dataSet(256, [tdata('OP', '10.4.0.8', '10.4.0.9', 31, 1)])], 1));
  phase2.push(ipfixEv(m(1, 55_000), [dataSet(300, [tdata('OP', '10.4.2.1', '10.4.2.2', 37, 1)])], 5));
  return { phase1, phase2, minute1V9: 1000n + 2000n, minute1Ipfix: 50n + 60n };
}

const templated = (async () => {
  const w = templatedWorld();
  const rig = new Rig(0xb0);
  rig.append(w.phase1);
  const host = await rollUp(rig);
  host.host.handle({ type: 'shutdown', requestId: 9100 });
  await host.host.settled();
  rig.append(w.phase2);
  return { rig, ...w };
})();

const TEMPLATED_RANGES: [string, number, number, number[]][] = [
  ['everything, minute-aligned', m(0), m(9), [1, 3, 9]],
  ['everything, ragged edges', m(0, 12_345), m(9, -6789), [4, 7]],
  ['minute 1, where the templates are a minute old', m(1), m(2), [1, 2]],
  ['the redefined minute', m(2), m(3), [1, 3]],
  ['the skewed minute', m(3), m(4), [1]],
  ['inside a minute, both edges raw', m(2, 5000), m(2, 45_000), [1, 2]],
  ['across the gap into the second session', m(4), m(7), [3]],
  ['into the tail', m(6), m(9), [3]],
];
const TEMPLATED_SOURCES = [V9_1, V9_2, IPFIX_5, SRC, sourceKeyFor('v9', EXPORTER, 3)];

test('templated: a rollup answer is the raw-scan answer over a v9 and an IPFIX journal whose templates came a minute earlier', async () => {
  const { rig } = await templated;
  let asked = 0;
  let rollupMinutes = 0;
  for (const [label, from, to, counts] of TEMPLATED_RANGES) {
    for (const n of counts) {
      for (const source of TEMPLATED_SOURCES) {
        const { fast, raw } = await askBoth(rig, spec(from, to, n, { sourceKey: source }));
        assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), `${label}, ${n} buckets, ${source} (${describe(fast)})`);
        assert.equal(raw.answeredFrom.rollupMinutes, 0);
        rollupMinutes += fast.answeredFrom.rollupMinutes;
        asked++;
      }
    }
  }
  assert.ok(asked > 60 && rollupMinutes > 0, `asked ${asked}, ${rollupMinutes} minutes from rollups`);
});

test('templated: focused queries, which read the journal, are the same on both paths', async () => {
  const { rig } = await templated;
  for (const [source, focus] of [
    [V9_1, { kind: 'endpoint', address: '10.4.0.1' }],
    [V9_1, { kind: 'conversation', srcAddr: '10.4.0.1', dstAddr: '10.4.0.2' }],
    [IPFIX_5, { kind: 'endpoint', address: '10.4.2.1' }],
  ] as const) {
    const { fast, raw } = await askBoth(rig, spec(m(0), m(9), 5, { sourceKey: source, focus }));
    assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw), `${source} ${focus.kind}`);
    assert.ok(raw.matchingRecords > 0, `${source} ${focus.kind} matched something`);
  }
});

test('templated: the totals of a minute whose templates came earlier equal a sum from the generator\'s list', async () => {
  const { rig, minute1V9, minute1Ipfix } = await templated;
  const nine = await askBoth(rig, spec(m(1), m(2), 1, { sourceKey: V9_1 }));
  assert.equal(nine.fast.buckets[0].reportedOctets, minute1V9);
  assert.equal(nine.fast.buckets[0].reportedPackets, 30n);
  assert.equal(nine.fast.matchingRecords, 2);
  assert.equal(nine.fast.awaitingTemplate, 1, 'the data set of the template nobody sent');
  assert.ok(nine.fast.answeredFrom.rollupMinutes > 0, 'answered from rollups');
  // Source id 2 defined layout PO for itself: its 700 octets are 700, not 7.
  const two = await askBoth(rig, spec(m(1), m(2), 1, { sourceKey: V9_2 }));
  assert.equal(two.fast.buckets[0].reportedOctets, 700n);
  assert.equal(two.fast.buckets[0].reportedPackets, 7n);
  // IPFIX: the tail adds one more record of 37 to minute 1.
  const ip = await askBoth(rig, spec(m(1), m(2), 1, { sourceKey: IPFIX_5 }));
  assert.equal(ip.fast.buckets[0].reportedOctets, minute1Ipfix + 37n);
  assert.equal(ip.fast.matchingRecords, 3);
});

process.exit((await runAll()) === 0 ? 0 : 1);
