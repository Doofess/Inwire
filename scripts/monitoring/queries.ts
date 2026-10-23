/**
 * History queries, the Worker host that serves them, the port that carries the
 * runtime to it, and the bounded inflate it reads the sidecar with (ADR 0059).
 *
 * `rollup.ts` holds the property that the rollup answer equals the raw-scan
 * answer over journals built to break it. This file holds everything around it:
 * what a query means (validation, buckets, tables, coverage, focus, the budget),
 * and the host's rule that every request gets exactly one terminal reply however
 * a cancel, a supersede, a shutdown and a finishing query interleave.
 *
 * Plain `tsx`, node's zlib behind the host's `inflate` and `deflate`, node's
 * `MessageChannel` behind `domPort`. The generator is `queryRig.ts`.
 */
import assert from 'node:assert/strict';
import { MessageChannel } from 'node:worker_threads';
import { deflateRawSync } from 'node:zlib';
import type { EvidenceInput } from '../../src/services/monitoring/journal';
import { ExpiredRangeError, StaleGenerationError } from '../../src/services/monitoring/journal';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { boundedInflate } from '../../src/services/monitoring/boundedInflate';
import { LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { historySpec } from '../../src/services/monitoring/historyRange';
import { bucketBounds, recordedSource, runHistoryQuery, validateQuery, type QueryOptions } from '../../src/services/monitoring/queries';
import { resumeExpiry, runExpiry } from '../../src/services/monitoring/archive';
import type { MemorySegmentDirectory } from '../../src/services/monitoring/segments';
import { DEFAULT_RETENTION, planExpiry, type ExpiryPlan } from '../../src/services/monitoring/retention';
import { minuteOf } from '../../src/services/monitoring/rollup';
import { decodeMinuteRollup, encodeMinuteRollup } from '../../src/services/monitoring/rollupCodec';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { RuntimeUnavailableError, type HostRuntime } from '../../src/services/monitoring/runtime';
import { createRuntimeClient, domPort, serveRuntime } from '../../src/services/monitoring/runtimeRpc';
import {
  LIMITS, type Evidence, type EvidenceRef, type QuerySpec, type JournalSnapshot, type Snapshot, type SegmentSource,
  type HistoryResult,
} from '../../src/services/monitoring/types';
import { sourceKey } from '../../src/services/monitoring/v5';
import type { FromMonitoringWorker } from '../../src/services/monitoring/workerHost';
import {
  BASE, FlakyDirectory, HostRig, MIN, NOW, Rig, S1, S2, SRC, SRC1, ask, askBoth, askOk, deflate, dgram, inflate, junk, rollUp, runAll, spec, start, stop,
  test, unreadVersion, waitTick, withoutProvenance, boundary,
} from './queryRig';
import { EXPORTER } from './fixtures';

const m = (n: number, off = 0): number => BASE + n * MIN + off;
const OTHER = '192.0.2.9';

/** The rollup answer and the all-raw answer must agree; returns the rollup one. */
async function check(rig: Rig, query: QuerySpec) {
  await rollUp(rig).then((h) => h.host.settled());
  const { fast, raw } = await askBoth(rig, query);
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  return fast;
}

function entriesOf(rig: Rig): Evidence[] {
  const out: Evidence[] = [];
  const snap = rig.journal.snapshot();
  let after = 0;
  for (;;) {
    const page = rig.journal.readPage(snap, after, 256, 1 << 20);
    out.push(...page.entries);
    after = page.nextAfterId;
    if (page.done) break;
  }
  return out;
}

/** Six minutes, two datagrams each, a stop at the end. */
function smallRig(seed = 0xa0): Rig {
  const rig = new Rig(seed);
  const inputs: EvidenceInput[] = [start(m(0))];
  for (let i = 0; i < 6; i++) {
    inputs.push(dgram(m(i, 1000), [
      { src: '10.0.0.1', dst: '10.0.0.2', octets: 100 + i, packets: 1 },
      { src: '10.7.0.1', dst: '10.0.0.3', octets: 50, packets: 2 },
    ], { sampling: 0x4064 }));
    inputs.push(dgram(m(i, 40_000), [{ src: '10.0.0.2', dst: '10.0.0.1', octets: 10, packets: 1 }], { sampling: 0x4064 }));
  }
  inputs.push(stop(m(6)));
  rig.append(inputs);
  return rig;
}

// --- gating a runtime ---------------------------------------------------------------------------------

type Over = { [K in keyof HostRuntime]?: HostRuntime[K] };

/** A runtime that answers as `target` does except where `over` says otherwise. */
function wrap(target: HostRuntime, over: Over): HostRuntime {
  return new Proxy(target, {
    get(t, p) {
      if (p in over) return (over as Record<PropertyKey, unknown>)[p];
      const v = Reflect.get(t, p, t) as unknown;
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
}

class Gate {
  held = false;
  entered = 0;
  private waiters: (() => void)[] = [];

  async pass(): Promise<void> {
    this.entered++;
    if (!this.held) return;
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  release(): void {
    this.held = false;
    for (const w of this.waiters.splice(0)) w();
  }
}

type Gateable = 'snapshot' | 'readPage' | 'appendMinutes' | 'readEvidence' | 'sources';

function gatedRuntime(rt: HostRuntime, method: Gateable, gate: Gate): HostRuntime {
  const call = (rt[method] as (...a: unknown[]) => Promise<unknown>).bind(rt);
  return wrap(rt, { [method]: async (...a: unknown[]) => { await gate.pass(); return call(...a); } } as Over);
}

async function ticks(n = 6): Promise<void> {
  for (let i = 0; i < n; i++) await waitTick();
}

type QueryReplyMsg = Extract<FromMonitoringWorker, { type: 'query-reply' }>;

function queryReplies(h: HostRig, id: number): QueryReplyMsg[] {
  return h.repliesTo(id).filter((r): r is QueryReplyMsg => r.type === 'query-reply');
}

function codeOf(h: HostRig, id: number): string {
  const r = queryReplies(h, id);
  assert.equal(r.length, 1, `request ${id} has ${r.length} query replies`);
  return r[0].reply.ok ? 'ok' : r[0].reply.code;
}

// =====================================================================================================
// validation
// =====================================================================================================

const NAMES_A_SOURCE = 'a query names a source as exporter/engine type/engine id, like 192.0.2.1/0/0';

test('validation: every malformed query is refused with its own message', async () => {
  const q = spec(0, 600_000, 10);
  const cases: [string, unknown, string][] = [
    ['null', null, 'a query is an object'],
    ['a number', 5, 'a query is an object'],
    ['no source', { ...q, sourceKey: '' }, NAMES_A_SOURCE],
    ['a numeric source', { ...q, sourceKey: 5 }, NAMES_A_SOURCE],
    ['the bare exporter key, which is not a source', { ...q, sourceKey: '192.0.2.1' }, NAMES_A_SOURCE],
    ['an engine type without an id', { ...q, sourceKey: '192.0.2.1/0' }, NAMES_A_SOURCE],
    ['a fourth segment', { ...q, sourceKey: '192.0.2.1/0/0/0' }, NAMES_A_SOURCE],
    ['an engine id past a byte', { ...q, sourceKey: '192.0.2.1/0/256' }, NAMES_A_SOURCE],
    ['a leading zero in the engine', { ...q, sourceKey: '192.0.2.1/00/0' }, NAMES_A_SOURCE],
    ['a name for an address', { ...q, sourceKey: 'router/0/0' }, NAMES_A_SOURCE],
    ['a trailing space in the source', { ...q, sourceKey: '192.0.2.1/0/0 ' }, NAMES_A_SOURCE],
    ['a fractional from', { ...q, fromMs: 1.5 }, 'the range is a pair of whole milliseconds'],
    ['a NaN to', { ...q, toMs: NaN }, 'the range is a pair of whole milliseconds'],
    ['an infinite to', { ...q, toMs: Infinity }, 'the range is a pair of whole milliseconds'],
    ['an unsafe to', { ...q, toMs: 2 ** 53 }, 'the range is a pair of whole milliseconds'],
    ['a string from', { ...q, fromMs: '0' }, 'the range is a pair of whole milliseconds'],
    ['a negative from', { ...q, fromMs: -1 }, 'the range must satisfy 0 <= fromMs < toMs'],
    ['an empty range', { ...q, fromMs: 5, toMs: 5 }, 'the range must satisfy 0 <= fromMs < toMs'],
    ['a reversed range', { ...q, fromMs: 9, toMs: 5 }, 'the range must satisfy 0 <= fromMs < toMs'],
    ['zero buckets', { ...q, bucketCount: 0 }, 'bucketCount is a whole number from 1 to 120'],
    ['121 buckets', { ...q, bucketCount: 121 }, 'bucketCount is a whole number from 1 to 120'],
    ['fractional buckets', { ...q, bucketCount: 1.5 }, 'bucketCount is a whole number from 1 to 120'],
    ['NaN buckets', { ...q, bucketCount: NaN }, 'bucketCount is a whole number from 1 to 120'],
    ['more buckets than milliseconds', { ...q, fromMs: 0, toMs: 5 }, 'the range is shorter than its bucket count'],
    ['an edge product past 2^53', { ...q, fromMs: 0, toMs: 2 ** 52, bucketCount: 120 }, 'the range is too long for its bucket count'],
    ['a short address', { ...q, focus: { kind: 'endpoint', address: '10.0.0' } }, 'a focus address is a dotted IPv4 address'],
    ['an octet past 255', { ...q, focus: { kind: 'endpoint', address: '10.0.0.256' } }, 'a focus address is a dotted IPv4 address'],
    ['a leading zero', { ...q, focus: { kind: 'endpoint', address: '01.0.0.1' } }, 'a focus address is a dotted IPv4 address'],
    ['trailing space', { ...q, focus: { kind: 'endpoint', address: '1.2.3.4 ' } }, 'a focus address is a dotted IPv4 address'],
    ['a bad conversation dst', { ...q, focus: { kind: 'conversation', srcAddr: '1.2.3.4', dstAddr: 'x' } }, 'a focus address is a dotted IPv4 address'],
    ['an unknown focus kind', { ...q, focus: { kind: 'port', address: '1.2.3.4' } }, 'a focus is an endpoint or a conversation'],
    ['a null focus', { ...q, focus: null }, 'a focus is an object'],
  ];
  for (const [what, bad, message] of cases) assert.equal(validateQuery(bad as QuerySpec), message, what);

  // The edges of what is accepted.
  assert.equal(validateQuery(spec(0, 120, 120)), null, 'a span equal to its bucket count');
  assert.equal(validateQuery(spec(0, 119, 120)), 'the range is shorter than its bucket count');
  assert.equal(validateQuery(spec(0, 1, 1)), null);
  assert.equal(validateQuery({ ...q, sourceKey: '192.0.2.1/255/255' }), null, 'the largest engine');
  assert.equal(validateQuery({ ...q, focus: { kind: 'endpoint', address: '255.0.0.0' } }), null);
  assert.equal(validateQuery({ ...q, focus: { kind: 'conversation', srcAddr: '0.0.0.0', dstAddr: '10.20.30.40' } }), null);

  // And a refusal reaches the caller as a reply, not a throw.
  const rig = new Rig();
  const reply = await ask(rig, { ...q, bucketCount: 0 });
  assert.equal(reply.ok, false);
  if (!reply.ok) assert.equal(reply.code, 'invalid-query');
});

// =====================================================================================================
// buckets and placement
// =====================================================================================================

test('buckets: edges are floor(i * span / n), the last is toMs, and a datagram on an edge is in exactly one bucket', async () => {
  assert.deepEqual(bucketBounds(0, 10, 3), [0, 3, 6, 10]);
  assert.deepEqual(bucketBounds(100, 110, 10), [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110]);
  const b = bucketBounds(m(0), m(10), 7);
  assert.equal(b[0], m(0));
  assert.equal(b[7], m(10));
  for (let i = 0; i <= 7; i++) assert.equal(b[i], m(0) + Math.floor((i * 10 * MIN) / 7));

  const rig = new Rig();
  rig.append([
    start(m(0)),
    dgram(m(0), [{ octets: 1 }]),
    dgram(m(1, -1), [{ octets: 2 }]),
    dgram(m(1), [{ octets: 4 }]),
    dgram(m(9, 59_999), [{ octets: 8 }]),
    dgram(m(10), [{ octets: 16 }]),
  ]);
  const r = await check(rig, spec(m(0), m(10), 10));
  const octets = r.buckets.map((x) => x.reportedOctets);
  assert.deepEqual(octets, [3n, 4n, null, null, null, null, null, null, null, 8n], 'the datagram at toMs is outside, the ones at 0 and 1 minute are not shared');
  assert.equal(r.matchingRecords, 4);
  assert.equal(r.buckets[0].fromMs, m(0));
  assert.equal(r.buckets[9].toMs, m(10));

  // An unaligned range into 7 buckets: a datagram exactly on edge i is in bucket i, one millisecond before it in i - 1.
  const from = m(0, 30_000);
  const to = m(3, 45_000);
  const bounds = bucketBounds(from, to, 7);
  const rig2 = new Rig();
  const inputs: EvidenceInput[] = [start(m(0))];
  for (let i = 1; i < 7; i++) {
    inputs.push(dgram(bounds[i] - 1, [{ octets: 1 }]));
    inputs.push(dgram(bounds[i], [{ octets: 100 }]));
  }
  inputs.sort((x, y) => (x.kind === 'boundary' ? -1 : y.kind === 'boundary' ? 1 : x.receivedMs - y.receivedMs));
  rig2.append(inputs);
  const r2 = await check(rig2, spec(from, to, 7));
  assert.deepEqual(r2.buckets.map((x) => x.records), [1, 2, 2, 2, 2, 2, 1]);
  for (let i = 1; i < 6; i++) assert.equal(r2.buckets[i].reportedOctets, 101n, `bucket ${i} holds its own edge and the millisecond before the next`);
  assert.equal(r2.buckets[0].reportedOctets, 1n);
  assert.equal(r2.buckets[6].reportedOctets, 100n);
  for (let i = 0; i < 7; i++) {
    assert.equal(r2.buckets[i].fromMs, bounds[i]);
    assert.equal(r2.buckets[i].toMs, bounds[i + 1]);
  }
});

test('sources: an engine, another engine and another exporter are three different histories', async () => {
  const rig = new Rig();
  const other = sourceKey(OTHER, 0, 0);
  rig.append([
    start(m(0)),
    dgram(m(1), [{ octets: 100 }]),
    dgram(m(1, 1000), [{ octets: 200 }], { engineId: 1 }),
    dgram(m(1, 2000), [{ octets: 400 }], {}, OTHER),
    junk(m(1, 3000)),
    junk(m(1, 4000)),
    junk(m(1, 5000), OTHER),
    unreadVersion(m(1, 6000)),
  ]);
  const a = await check(rig, spec(m(0), m(3), 3));
  const b = await check(rig, spec(m(0), m(3), 3, { sourceKey: SRC1 }));
  const c = await check(rig, spec(m(0), m(3), 3, { sourceKey: other }));
  assert.equal(a.buckets[1].reportedOctets, 100n);
  assert.equal(b.buckets[1].reportedOctets, 200n);
  assert.equal(c.buckets[1].reportedOctets, 400n);
  // Malformed and unsupported datagrams belong to the exporter that sent them.
  assert.deepEqual([a.malformed, a.unsupported], [2, 1]);
  assert.deepEqual([b.malformed, b.unsupported], [2, 1], 'two engines of one exporter share that exporter\'s bad datagrams');
  assert.deepEqual([c.malformed, c.unsupported], [1, 0]);
  // A source the journal has never seen is an empty history, not an error.
  const none = await askOk(rig, spec(m(0), m(3), 3, { sourceKey: sourceKey('192.0.2.77', 0, 0) }));
  assert.equal(none.matchingRecords, 0);
  assert.equal(none.endpoints.status === 'ok' && none.endpoints.rows.length, 0);
});

// =====================================================================================================
// tables
// =====================================================================================================

test('tables: sent and received, a conversation is directional, ties break by address as a number', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0)),
    dgram(m(1), [
      { src: '10.0.0.1', dst: '10.0.0.2', octets: 100, packets: 3 },
      { src: '10.0.0.2', dst: '10.0.0.1', octets: 50, packets: 2 },
      { src: '10.0.0.3', dst: '10.0.0.3', octets: 30, packets: 1 },
      { src: '10.0.0.4', dst: '10.0.0.1', octets: 100, packets: 4 },
    ]),
  ]);
  const r = await check(rig, spec(m(0), m(2), 2));
  assert.deepEqual(r.endpoints, {
    status: 'ok',
    rows: [
      { address: '10.0.0.1', sentOctets: 100n, receivedOctets: 150n },
      { address: '10.0.0.2', sentOctets: 50n, receivedOctets: 100n },
      { address: '10.0.0.4', sentOctets: 100n, receivedOctets: 0n },
      { address: '10.0.0.3', sentOctets: 30n, receivedOctets: 30n },
    ],
  }, 'an address that is both source and destination of one record is credited on both sides');
  assert.deepEqual(r.conversations, {
    status: 'ok',
    rows: [
      { srcAddr: '10.0.0.1', dstAddr: '10.0.0.2', reportedOctets: 100n, reportedPackets: 3n },
      { srcAddr: '10.0.0.4', dstAddr: '10.0.0.1', reportedOctets: 100n, reportedPackets: 4n },
      { srcAddr: '10.0.0.2', dstAddr: '10.0.0.1', reportedOctets: 50n, reportedPackets: 2n },
      { srcAddr: '10.0.0.3', dstAddr: '10.0.0.3', reportedOctets: 30n, reportedPackets: 1n },
    ],
  }, 'A to B and B to A are two conversations');

  // 10.0.0.10 sorts before 10.0.0.9 as text, after it as a number.
  const rig2 = new Rig();
  rig2.append([start(m(0)), dgram(m(1), [{ src: '10.0.0.10', dst: '10.0.0.9', octets: 77, packets: 1 }, { src: '10.0.0.9', dst: '10.0.0.10', octets: 77, packets: 1 }])]);
  const r2 = await check(rig2, spec(m(0), m(2), 2));
  assert.deepEqual(r2.endpoints.status === 'ok' && r2.endpoints.rows.map((e) => e.address), ['10.0.0.9', '10.0.0.10']);
  assert.deepEqual(r2.conversations.status === 'ok' && r2.conversations.rows.map((c) => c.srcAddr), ['10.0.0.9', '10.0.0.10']);
});

test('tables: twenty rows, the biggest first, and the totals do not depend on the cut', async () => {
  const rig = new Rig();
  const flows = Array.from({ length: 25 }, (_, i) => ({ src: `10.1.0.${i + 1}`, dst: '10.2.0.1', octets: i + 1, packets: 1 }));
  rig.append([start(m(0)), dgram(m(1), flows)]);
  const r = await check(rig, spec(m(0), m(2), 1));
  assert.ok(r.endpoints.status === 'ok' && r.conversations.status === 'ok');
  assert.equal(r.endpoints.rows.length, LIMITS.topRows);
  assert.equal(r.endpoints.rows[0].address, '10.2.0.1');
  assert.equal(r.endpoints.rows[1].address, '10.1.0.25');
  assert.equal(r.endpoints.rows[19].address, '10.1.0.7');
  assert.equal(r.conversations.rows.length, LIMITS.topRows);
  assert.equal(r.conversations.rows[0].reportedOctets, 25n);
  assert.equal(r.conversations.rows[19].reportedOctets, 6n);
  assert.equal(r.matchingRecords, 25);
  assert.equal(r.buckets[0].reportedOctets, 325n);
});

// =====================================================================================================
// coverage and gaps
// =====================================================================================================

const coverageOf = (r: { buckets: { coverage: string }[] }): string[] => r.buckets.map((b) => b.coverage);

test('coverage: a stop is a gap that says stopped, and what was recorded before it is not one', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1, 10), [{ octets: 1000, packets: 10 }]), stop(m(3))]);
  const r = await check(rig, spec(m(0), m(6), 6));
  assert.deepEqual(coverageOf(r), ['no-records', 'observed-records', 'no-records', 'collection-gap', 'collection-gap', 'collection-gap']);
  assert.deepEqual(r.gaps, [{ fromMs: m(3), toMs: m(6), reason: 'stopped' }]);
  assert.equal(r.buckets[0].reportedOctets, null, 'no records is null, never 0');
  assert.equal(r.buckets[0].reportedPackets, null);
  assert.equal(r.buckets[1].reportedOctets, 1000n);
  assert.equal(r.buckets[5].reportedOctets, null, 'a gap is never a zero');
  assert.equal(r.buckets[5].records, 0);
});

test('coverage: a suspend and a resume leave a gap that says suspended', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), boundary('suspend', S1, m(2)), boundary('resume', S1, m(4)), stop(m(6))]);
  const r = await check(rig, spec(m(0), m(8), 8));
  assert.deepEqual(r.gaps, [{ fromMs: m(2), toMs: m(4), reason: 'suspended' }, { fromMs: m(6), toMs: m(8), reason: 'stopped' }]);
  assert.deepEqual(coverageOf(r), ['no-records', 'no-records', 'collection-gap', 'collection-gap', 'no-records', 'no-records', 'collection-gap', 'collection-gap']);
});

test('coverage: a stop for the storage limit says so', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{}]), boundary('stop', S1, m(2), 'storage-limit')]);
  const r = await check(rig, spec(m(0), m(4), 4));
  assert.deepEqual(r.gaps, [{ fromMs: m(2), toMs: m(4), reason: 'storage-limit' }]);
});

test('coverage: a reopened journal closes the open session as interrupted, and an open one is not a gap ahead of now', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(5), [{}])]);
  // A session left open is still recording, past now as well.
  const open = await check(rig, spec(NOW - 2 * MIN, NOW + 2 * MIN, 4));
  assert.deepEqual(open.gaps, []);
  assert.deepEqual(coverageOf(open), ['no-records', 'no-records', 'no-records', 'no-records']);

  rig.reopen();
  const closed = await check(rig, spec(NOW - 2 * MIN, NOW + 2 * MIN, 4));
  // The journal stamps the interruption at the last thing it had on disk (minute 5), not at the reopen: it cannot know when the run died.
  assert.deepEqual(closed.gaps, [{ fromMs: NOW - 2 * MIN, toMs: NOW + 2 * MIN, reason: 'interrupted' }]);
  assert.deepEqual(coverageOf(closed), ['collection-gap', 'collection-gap', 'collection-gap', 'collection-gap']);
});

test('coverage: the live edge of a running session is its records, not a gap (the History asks to the close of this minute)', async () => {
  const rig = new Rig();
  const now = m(59, 37_500);
  rig.append([start(m(0)), dgram(m(30), [{ octets: 100 }]), dgram(m(59, 10_000), [{ octets: 4321 }])]);
  await rollUp(rig).then((h) => h.host.settled());
  const q = historySpec(SRC, 60 * MIN, now, 60);
  assert.equal(q.toMs, m(60), 'the range runs to the close of the minute now is in');
  const { fast, raw } = await askBoth(rig, q, { nowMs: now });
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  assert.equal(fast.buckets.at(-1)!.coverage, 'observed-records', 'the current minute draws its traffic');
  assert.equal(fast.buckets.at(-1)!.reportedOctets, 4321n);
  assert.deepEqual(fast.gaps, [], 'the part of this minute still to come is not a period that was not collected');
  // A stopped collector's time after the stop is still a gap, now and after it.
  rig.append([stop(m(59, 20_000))]);
  const stopped = await askOk(rig, q, { nowMs: now });
  assert.deepEqual(stopped.gaps, [{ fromMs: m(59, 20_000), toMs: m(60), reason: 'stopped' }]);
  assert.equal(stopped.buckets.at(-1)!.coverage, 'collection-gap');
});

test('coverage: shed datagrams are a point gap with the count they could be sure of', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0)),
    dgram(m(1, 1000), [{ octets: 5 }]),
    boundary('gap', S1, m(1, 5000), 'shed', 5),
    boundary('gap', S1, m(1, 10_000), 'shed', null),
    boundary('gap', S1, m(3, 1000), 'shed', null),
    boundary('gap', S1, m(5, 1000), 'shed', 7),
    boundary('gap', S1, m(5, 2000), 'shed', 3),
  ]);
  const r = await check(rig, spec(m(0), m(6), 6));
  assert.deepEqual(r.gaps, [
    { fromMs: m(1, 5000), toMs: m(1, 5000), reason: 'shed at least 5 datagrams' },
    { fromMs: m(3, 1000), toMs: m(3, 1000), reason: 'shed an unknown number of datagrams' },
    { fromMs: m(5, 1000), toMs: m(5, 1000), reason: 'shed 10 datagrams' },
  ].concat([{ fromMs: NOW, toMs: NOW, reason: '' }].slice(0, 0)));
  assert.deepEqual(coverageOf(r), ['no-records', 'collection-gap', 'no-records', 'collection-gap', 'no-records', 'collection-gap']);
  assert.equal(r.buckets[1].records, 1, 'a bucket with a gap still reports what was recorded');
  assert.equal(r.buckets[1].reportedOctets, 5n);
});

test('coverage: a silent exporter is no-records everywhere the collector ran, and an empty range is all null', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{ octets: 9 }], {}, OTHER), junk(m(2), OTHER)]);
  const r = await check(rig, spec(m(0), m(4), 4));
  assert.deepEqual(coverageOf(r), ['no-records', 'no-records', 'no-records', 'no-records']);
  assert.ok(r.buckets.every((b) => b.reportedOctets === null && b.reportedPackets === null && b.records === 0));
  assert.deepEqual(r.gaps, [{ fromMs: NOW, toMs: NOW, reason: '' }].slice(0, 0));
  assert.equal(r.malformed, 0, 'another exporter\'s bad datagram is not this one\'s');
  assert.equal(r.matchingRecords, 0);
  assert.equal(r.samplingKnown, false);
  assert.equal(r.endpoints.status === 'ok' && r.endpoints.rows.length, 0);
  assert.deepEqual(r.evidence, []);
});

test('coverage: a clock that stepped back covers the span between the two stamps and nothing more', async () => {
  const rig = new Rig();
  rig.append([start(m(10)), dgram(m(5), [{ octets: 3 }]), stop(m(2))]);
  const r = await check(rig, spec(m(0), m(12), 12));
  assert.deepEqual(r.gaps, [
    { fromMs: m(0), toMs: m(2), reason: 'not-recording' },
    { fromMs: m(10), toMs: m(12), reason: 'stopped' },
  ]);
  assert.deepEqual(coverageOf(r), [
    'collection-gap', 'collection-gap', 'no-records', 'no-records', 'no-records', 'observed-records',
    'no-records', 'no-records', 'no-records', 'no-records', 'collection-gap', 'collection-gap',
  ]);
});

test('sampling: known only where there are records and every one of them said', async () => {
  const rig = new Rig();
  rig.append([
    start(m(0)),
    dgram(m(1), [{}, {}], { sampling: 0x4064 }),
    dgram(m(2), [{}], { sampling: 0 }),
    stop(m(5)),
  ]);
  assert.equal((await check(rig, spec(m(0), m(1), 1))).samplingKnown, false, 'no records');
  assert.equal((await check(rig, spec(m(1), m(2), 1))).samplingKnown, true, 'every record reported');
  assert.equal((await check(rig, spec(m(1), m(3), 2))).samplingKnown, false, 'one record said nothing');
  assert.equal((await check(rig, spec(m(2), m(3), 1))).samplingKnown, false, 'the only record said nothing');
  assert.equal((await check(rig, spec(m(3), m(4), 1))).samplingKnown, false);
});

// =====================================================================================================
// focus and detail
// =====================================================================================================

function focusRig(): { rig: Rig; datagrams: Evidence[] } {
  const rig = new Rig();
  rig.append([start(m(0))]);
  const datagrams: Evidence[] = [];
  for (let d = 0; d < 10; d++) {
    const flows = Array.from({ length: 30 }, (_, k) => (k % 2 === 0
      ? { src: '10.7.0.1', dst: `10.8.0.${k / 2 + 1}`, octets: 10, packets: 1 }
      : { src: '10.9.0.1', dst: '10.9.0.2', octets: 1, packets: 1 }));
    datagrams.push(...rig.add(dgram(m(d < 5 ? 1 : 2, d * 1000), flows)));
  }
  rig.append([stop(m(4))]);
  return { rig, datagrams };
}

test('focus: every match is counted and the first hundred are kept, in journal order', async () => {
  const { rig, datagrams } = focusRig();
  const r = await check(rig, spec(m(0), m(4), 4, { focus: { kind: 'endpoint', address: '10.7.0.1' } }));
  assert.equal(r.matchingRecords, 150);
  assert.equal(r.evidence.length, LIMITS.focusedReferences);
  const expected: { ref: EvidenceRef; recordIndex: number }[] = [];
  for (const d of datagrams) for (let k = 0; k < 30; k += 2) if (expected.length < 100) expected.push({ ref: d.ref, recordIndex: k });
  assert.deepEqual(r.evidence, expected);
  assert.deepEqual(r.evidence[99], { ref: datagrams[6].ref, recordIndex: 18 });
  assert.equal(r.buckets[1].records + r.buckets[2].records, 150);
  assert.equal(r.buckets[1].reportedOctets, 750n);
  assert.ok(r.endpoints.status === 'ok' && !r.endpoints.rows.some((e) => e.address === '10.9.0.1'), 'the tables hold the focus only');
  assert.equal(r.answeredFrom.rollupMinutes, 0, 'a focused query is answered from the journal');

  const dst = await check(rig, spec(m(0), m(4), 4, { focus: { kind: 'endpoint', address: '10.8.0.15' } }));
  assert.equal(dst.matchingRecords, 10, 'an endpoint matches either side');
  const conv = await check(rig, spec(m(0), m(4), 4, { focus: { kind: 'conversation', srcAddr: '10.7.0.1', dstAddr: '10.8.0.1' } }));
  assert.equal(conv.matchingRecords, 10);
  assert.deepEqual(conv.evidence.map((e) => e.recordIndex), Array(10).fill(0));
  const reversed = await check(rig, spec(m(0), m(4), 4, { focus: { kind: 'conversation', srcAddr: '10.8.0.1', dstAddr: '10.7.0.1' } }));
  assert.equal(reversed.matchingRecords, 0, 'a conversation has a direction');
  assert.deepEqual(reversed.evidence, []);
  assert.ok(reversed.buckets.every((b) => b.reportedOctets === null));
  const unfocused = await check(rig, spec(m(0), m(4), 4));
  assert.deepEqual(unfocused.evidence, []);
  assert.equal(unfocused.matchingRecords, 300);
});

test('detail: the exact payload and record, and a refusal for each way a reference can be wrong', async () => {
  const rig = smallRig();
  const h = await rollUp(rig);
  const entries = entriesOf(rig);
  const first = entries.find((e) => e.kind === 'datagram')!;
  assert.equal(first.kind, 'datagram');
  const snapshot: Snapshot = rig.journal.snapshot();
  const detail = async (snap: Snapshot, ref: EvidenceRef, recordIndex: number, hr: HostRig = h) => {
    const id = hr.send({ type: 'detail', snapshot: snap, ref, recordIndex });
    const reply = await hr.waitFor(() => hr.repliesTo(id)[0], 'a detail reply');
    assert.equal(hr.repliesTo(id).length, 1);
    assert.equal(reply.type, 'detail-reply');
    return reply as Extract<FromMonitoringWorker, { type: 'detail-reply' }>;
  };

  const ok = await detail(snapshot, first.ref, 1);
  assert.ok(ok.ok);
  if (ok.ok && first.kind === 'datagram') {
    assert.deepEqual(ok.evidence.bytes, first.bytes);
    assert.equal(ok.evidence.receivedMs, first.receivedMs);
    assert.equal(ok.record.srcAddr, '10.7.0.1');
    assert.equal(ok.record.reportedOctets, 50n);
    assert.equal(ok.record.recordIndex, 1);
  }
  const startBoundary = entries.find((e) => e.kind === 'boundary')!;
  const boundaryReply = await detail(snapshot, startBoundary.ref, 0);
  assert.ok(!boundaryReply.ok && boundaryReply.code === 'not-found');
  for (const index of [2, 99, -1]) {
    const r = await detail(snapshot, first.ref, index);
    assert.ok(!r.ok && r.code === 'not-found', `record ${index}`);
  }
  const beyond = await detail({ ...snapshot, throughEntryId: first.ref.entryId }, { ...first.ref, entryId: first.ref.entryId + 1 }, 0);
  assert.ok(!beyond.ok && beyond.code === 'stale-generation', 'a reference past the snapshot it was asked against');
  const foreign = await detail(snapshot, { ...first.ref, generation: 'f'.repeat(32) }, 0);
  assert.ok(!foreign.ok && foreign.code === 'stale-generation', 'a reference of another generation');

  // The journal moved to another generation under a reference that is still well formed.
  const rt = rig.runtime;
  const moved = new HostRig(wrap(rt, { snapshot: async () => ({ ...(await rt.snapshot()), generation: '0'.repeat(32) }) }));
  await moved.connectOnly();
  const stale = await detail(snapshot, first.ref, 0, moved);
  assert.ok(!stale.ok && stale.code === 'stale-generation');

  // A runtime that cannot be reached, and one that fails.
  const down = new HostRig(wrap(rt, { readEvidence: async () => { throw new RuntimeUnavailableError('port closed'); } }));
  await down.connectOnly();
  const unavailable = await detail(snapshot, first.ref, 0, down);
  assert.ok(!unavailable.ok && unavailable.code === 'runtime-unavailable');
  const broken = new HostRig(wrap(rt, { readEvidence: async () => { throw new Error('disk on fire'); } }));
  await broken.connectOnly();
  const failed = await detail(snapshot, first.ref, 0, broken);
  assert.ok(!failed.ok && failed.code === 'storage-failed');
});

// =====================================================================================================
// the datagram budget
// =====================================================================================================

let bigRig: Rig | null = null;

/** 100,001 single-record datagrams, one millisecond apart from minute 1, then a stop. */
function big(): Rig {
  if (bigRig === null) {
    const rig = new Rig(0xb1);
    rig.append([start(m(0))]);
    for (let at = 0; at <= 100_000; at += 2000) {
      const chunk: EvidenceInput[] = [];
      for (let i = at; i < Math.min(at + 2000, 100_001); i++) chunk.push(dgram(m(1, i), [{ octets: 1 + (i % 9), packets: 1 }]));
      rig.append(chunk);
    }
    rig.append([stop(m(4))]);
    bigRig = rig;
  }
  return bigRig;
}

test('budget: exactly 100,000 datagrams are read and 100,001 are refused, raw and from the unrolled tail', async () => {
  const rig = big();
  const at = (n: number, over: Partial<QuerySpec> = {}): QuerySpec => spec(m(1), m(1, n), 1, over);
  assert.equal(LIMITS.rawQueryDatagrams, 100_000);

  const raw = await ask(rig, at(100_000), { forceRaw: true });
  assert.ok(raw.ok, 'exactly the budget');
  if (raw.ok) assert.equal(raw.value.matchingRecords, 100_000);
  const refused = await ask(rig, at(100_001), { forceRaw: true });
  assert.ok(!refused.ok);
  if (!refused.ok) {
    assert.equal(refused.code, 'range-too-large');
    assert.match(refused.message, /more than 100000 datagrams have to be read from the journal for this range; narrow it\./);
    assert.ok(!/rebuilt/.test(refused.message), 'no rebuild note when nothing is rebuilding');
  }

  // No rollups yet: everything is the tail, and the tail is counted against the same budget.
  const tailOk = await ask(rig, at(100_000));
  assert.ok(tailOk.ok);
  if (tailOk.ok) assert.equal(tailOk.value.matchingRecords, 100_000);
  const tailRefused = await ask(rig, at(100_001));
  assert.ok(!tailRefused.ok);
  if (!tailRefused.ok) assert.equal(tailRefused.code, 'range-too-large');

  // A refusal is the whole query's alone: the same range, narrower, is answered.
  assert.ok((await ask(rig, at(50_000), { forceRaw: true })).ok);
});

test('budget: a rebuild in progress says so in the refusal, and rollups answer what the journal could not', async () => {
  const rig = big();
  const gate = new Gate();
  gate.held = true;
  const h = new HostRig(gatedRuntime(rig.runtime, 'appendMinutes', gate));
  await h.connectOnly();
  await h.waitFor(() => (gate.entered > 0 ? true : undefined), 'the first post to reach the runtime', 60_000);
  assert.equal(h.host.rebuildPhase, 'rebuilding');

  const focus = { kind: 'endpoint', address: '10.0.0.1' } as const;
  const wide = spec(m(1), m(1, 100_001), 1, { focus });
  const during = await h.query('v', wide);
  assert.ok(!during.ok);
  if (!during.ok) {
    assert.equal(during.code, 'range-too-large');
    assert.match(during.message, /The rollups are still being rebuilt \(through entry \d+ of \d+\)/);
    assert.match(during.message, /narrow it\. The rollups/, 'the note follows the instruction');
  }

  gate.release();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.equal(h.phases().at(-1), 'live');
  const after = await h.query('v', wide);
  assert.ok(!after.ok);
  if (!after.ok) assert.ok(!/rebuilt/.test(after.message));

  // The same data, unfocused and minute aligned, is a question the rollups answer.
  const fast = await h.query('w', spec(m(1), m(3), 2));
  assert.ok(fast.ok);
  if (fast.ok) {
    assert.equal(fast.value.matchingRecords, 100_001);
    assert.deepEqual(fast.value.answeredFrom, { rollupMinutes: 2, rawMinutes: 0 });
    assert.equal(fast.value.buckets[0].records + fast.value.buckets[1].records, 100_001);
  }
  const forced = await ask(rig, spec(m(1), m(3), 2), { forceRaw: true });
  assert.ok(!forced.ok && forced.code === 'range-too-large', 'the raw oracle cannot answer it');
});

test('budget: the rebuild note is whatever the caller says, and only on a budget refusal', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{}]), stop(m(2))]);
  const ok = await askOk(rig, spec(m(0), m(2), 2), { rebuildNote: () => 'NOTE' });
  assert.equal(ok.matchingRecords, 1);
  const r = big();
  const refused = await ask(r, spec(m(1), m(1, 100_001), 1), { forceRaw: true, rebuildNote: () => 'NOTE' });
  assert.ok(!refused.ok);
  if (!refused.ok) assert.match(refused.message, /narrow it\. NOTE$/);
});

// =====================================================================================================
// the host
// =====================================================================================================

async function gatedHost(rig: Rig, method: Gateable): Promise<{ h: HostRig; gate: Gate }> {
  const gate = new Gate();
  const h = new HostRig(gatedRuntime(rig.runtime, method, gate));
  await h.connect();
  return { h, gate };
}

test('host: at most two queries run, two wait, and a fifth cancels the oldest waiting one', async () => {
  const { h, gate } = await gatedHost(smallRig(), 'snapshot');
  const q = spec(m(0), m(3), 3);
  gate.held = true;
  const before = gate.entered;
  const ids = ['a', 'b', 'c', 'd'].map((v) => h.queryNoWait(v, q));
  await ticks();
  assert.equal(gate.entered - before, 2, 'two started');
  for (const id of ids) assert.equal(h.repliesTo(id).length, 0);
  const e = h.queryNoWait('e', q);
  await ticks();
  assert.equal(codeOf(h, ids[2]), 'cancelled', 'the oldest waiting query is cancelled at once');
  assert.equal(gate.entered - before, 2, 'still two');
  gate.release();
  await h.host.settled();
  assert.deepEqual([ids[0], ids[1], ids[3], e].map((id) => codeOf(h, id)), ['ok', 'ok', 'ok', 'ok']);
  assert.equal(h.posts.filter((p) => p.type === 'query-reply').length, 5, 'one reply each');
});

test('host: a newer query for the same view supersedes the older one, running or waiting', async () => {
  const { h, gate } = await gatedHost(smallRig(), 'snapshot');
  const q = spec(m(0), m(3), 3);
  gate.held = true;
  const first = h.queryNoWait('v', q);
  await ticks();
  const second = h.queryNoWait('v', q);
  await ticks();
  assert.equal(codeOf(h, first), 'cancelled', 'the running one is answered cancelled immediately');
  assert.equal(h.repliesTo(second).length, 0);
  // Fill the slots and the queue, then supersede one that is waiting.
  const other = h.queryNoWait('x', q);
  const waiting = h.queryNoWait('y', q);
  await ticks();
  const newer = h.queryNoWait('y', q);
  await ticks();
  assert.equal(codeOf(h, waiting), 'cancelled');
  gate.release();
  await h.host.settled();
  assert.deepEqual([second, other, newer].map((id) => codeOf(h, id)), ['ok', 'ok', 'ok']);
  assert.equal(h.posts.filter((p) => p.type === 'query-reply').length, 5);
  assert.equal(codeOf(h, first), 'cancelled', 'and the cancelled one did not answer a second time when it stopped');
});

test('host: cancelling answers the query once and the cancel with whether it did anything', async () => {
  const { h, gate } = await gatedHost(smallRig(), 'snapshot');
  const q = spec(m(0), m(3), 3);
  gate.held = true;
  const running = h.queryNoWait('v', q);
  await ticks();
  const cancel = h.send({ type: 'cancelQuery', targetRequestId: running });
  assert.deepEqual(h.repliesTo(cancel), [{ type: 'cancel-reply', requestId: cancel, cancelled: true }]);
  assert.equal(codeOf(h, running), 'cancelled');
  const again = h.send({ type: 'cancelQuery', targetRequestId: running });
  assert.deepEqual(h.repliesTo(again), [{ type: 'cancel-reply', requestId: again, cancelled: false }]);
  gate.release();
  await h.host.settled();
  assert.equal(queryReplies(h, running).length, 1);

  const finished = await h.query('v', q);
  assert.ok(finished.ok);
  const lastId = h.posts.filter((p) => p.type === 'query-reply').at(-1)!.requestId;
  const late = h.send({ type: 'cancelQuery', targetRequestId: lastId });
  assert.deepEqual(h.repliesTo(late), [{ type: 'cancel-reply', requestId: late, cancelled: false }]);
  const unknown = h.send({ type: 'cancelQuery', targetRequestId: 424_242 });
  assert.deepEqual(h.repliesTo(unknown), [{ type: 'cancel-reply', requestId: unknown, cancelled: false }]);
  const nonsense = h.send({ type: 'cancelQuery', targetRequestId: 'x' as unknown as number });
  assert.deepEqual(h.repliesTo(nonsense), [{ type: 'cancel-reply', requestId: nonsense, cancelled: false }]);
});

test('host: a shutdown answers what is running as cancelled, once, and refuses what comes after', async () => {
  const { h, gate } = await gatedHost(smallRig(), 'snapshot');
  const q = spec(m(0), m(3), 3);
  gate.held = true;
  const running = h.queryNoWait('a', q);
  const waiting = [h.queryNoWait('b', q), h.queryNoWait('c', q), h.queryNoWait('d', q)];
  await ticks();
  const down = h.send({ type: 'shutdown' });
  await ticks();
  // The query that was running is held at the gate, so the shutdown waits for it - up to its bound.
  assert.equal(h.repliesTo(down).length, 0, 'the shutdown reply waits for running work');
  h.timers.fire();
  await h.waitFor(() => h.repliesTo(down)[0], 'the shutdown reply');
  for (const id of [running, ...waiting]) assert.equal(codeOf(h, id), 'cancelled');
  const after = await h.query('e', q);
  assert.ok(!after.ok && after.code === 'cancelled');
  const connect = h.send({ type: 'connect', port: {} });
  const reply = await h.waitFor(() => h.repliesTo(connect)[0], 'a connect reply');
  assert.ok(reply.type === 'connect-reply' && !reply.ok && reply.code === 'cancelled');
  gate.release();
  await h.host.settled();
  for (const id of [running, ...waiting]) assert.equal(queryReplies(h, id).length, 1, 'nothing answers twice when the stopped work finishes');
  assert.equal(h.repliesTo(down).length, 1);
});

test('host: before a connect and for a malformed message, the answer is a refusal and never silence', async () => {
  const rig = smallRig();
  const h = new HostRig(rig.runtime);
  const q = spec(m(0), m(3), 3);
  const early = await h.query('v', q);
  assert.ok(!early.ok && early.code === 'runtime-unavailable');
  const id = h.send({ type: 'detail', snapshot: rig.journal.snapshot(), ref: { generation: rig.generation, entryId: 1 }, recordIndex: 0 });
  const detail = await h.waitFor(() => h.repliesTo(id)[0], 'a detail reply');
  assert.ok(detail.type === 'detail-reply' && !detail.ok && detail.code === 'runtime-unavailable');

  await h.connect();
  const twice = h.send({ type: 'connect', port: {} });
  const second = await h.waitFor(() => h.repliesTo(twice)[0], 'a second connect reply');
  assert.ok(second.type === 'connect-reply' && !second.ok && second.code === 'already-connected');

  const bad = h.host.handle.bind(h.host);
  bad({ type: 'bogus', requestId: 901 });
  assert.deepEqual(h.repliesTo(901), [{ type: 'error-reply', requestId: 901, message: 'unknown message bogus' }]);
  const before = h.posts.length;
  bad({ type: 'query', viewId: 'v', spec: q });
  bad('not an object');
  bad(null);
  bad({ requestId: 5 });
  assert.equal(h.posts.length, before, 'a message with no request id cannot be answered, so it is not');
  bad({ type: 'query', requestId: 902, viewId: 7, spec: q });
  assert.deepEqual(queryReplies(h, 902).map((r) => r.reply.ok === false && r.reply.code), ['invalid-query']);
  bad({ type: 'query', requestId: 903, viewId: 'v', spec: { ...q, bucketCount: 0 } });
  await h.waitFor(() => queryReplies(h, 903)[0], 'a reply to an invalid spec');
  assert.equal(codeOf(h, 903), 'invalid-query');
});

test('host: a journal of another generation is a stale-generation reply, an unreachable runtime is runtime-unavailable', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const q = spec(m(0), m(3), 3);
  const stale = new HostRig(wrap(rt, { snapshot: async () => ({ ...(await rt.snapshot()), generation: 'e'.repeat(32) }) }));
  await stale.connectOnly();
  const staleReply = await stale.query('v', q);
  assert.ok(!staleReply.ok && staleReply.code === 'stale-generation');

  const dead = new HostRig(rt);
  await dead.connect();
  dead.runtime = wrap(rt, { readPage: async () => { throw new RuntimeUnavailableError('the port closed'); } });
  const down = new HostRig(wrap(rt, { readPage: async () => { throw new RuntimeUnavailableError('the port closed'); } }));
  await down.connectOnly();
  const reply = await down.query('v', spec(m(0, 10), m(3), 3));
  assert.ok(!reply.ok && reply.code === 'runtime-unavailable');

  const broken = new HostRig(wrap(rt, { readPage: async () => { throw new Error('torn page'); } }));
  await broken.connectOnly();
  const storage = await broken.query('v', spec(m(0, 10), m(3), 3));
  assert.ok(!storage.ok && storage.code === 'storage-failed');
  assert.match(storage.ok ? '' : storage.message, /torn page/);
});

test('host: work is cut into slices, a cancel lands between two of them, and slicing changes no answer', async () => {
  const rig = new Rig();
  const inputs: EvidenceInput[] = [start(m(0))];
  for (let i = 0; i < 20; i++) for (let k = 0; k < 40; k++) inputs.push(dgram(m(i, k * 1000), [{ src: `10.0.${i}.${k}`, dst: '10.0.0.1', octets: 1 + k, packets: 1 }]));
  inputs.push(stop(m(21)));
  rig.append(inputs);
  const focus = { kind: 'endpoint', address: '10.0.0.1' } as const;
  const q = spec(m(0), m(21), 3, { focus });

  const plain = new HostRig(rig.runtime);
  await plain.connect();
  const expected = await plain.query('v', q);
  assert.ok(expected.ok);
  assert.equal(plain.yields, 0, 'a clock that never advances never yields');

  const sliced = new HostRig(rig.runtime);
  await sliced.connect();
  sliced.step = 3;
  sliced.yields = 0;
  const answer = await sliced.query('v', q);
  assert.ok(sliced.yields > 0, 'a query that runs for more than a slice yields');
  assert.deepEqual(answer, expected, 'and gives the same answer');

  // A cancel that arrives while the query is yielded stops it, and it answers once.
  const cancelled = new HostRig(rig.runtime);
  await cancelled.connect();
  cancelled.step = 3;
  let id = -1;
  cancelled.onYield = () => {
    cancelled.onYield = null;
    cancelled.send({ type: 'cancelQuery', targetRequestId: id });
  };
  id = cancelled.queryNoWait('v', q);
  await cancelled.host.settled();
  assert.equal(codeOf(cancelled, id), 'cancelled');
  assert.equal(cancelled.posts.filter((p) => p.type === 'cancel-reply').length, 1);
  assert.equal(cancelled.yields, 1, 'it did not go on to a second slice');
});

test('host: the rebuild is sliced too, announces its progress, and ends live with the journal in the rollups', async () => {
  const rig = new Rig();
  const inputs: EvidenceInput[] = [start(m(0))];
  for (let i = 0; i < 3000; i++) inputs.push(dgram(m(Math.floor(i / 100), (i % 100) * 500), [{ octets: 1 + (i % 7), packets: 1 }]));
  inputs.push(stop(m(31)));
  rig.append(inputs);
  const h = new HostRig(rig.runtime);
  h.step = 3;
  const reply = await h.connectOnly();
  assert.ok(reply.type === 'connect-reply' && reply.ok);
  await h.host.settled();
  assert.ok(h.yields > 0, 'reading 3,000 entries yields');
  assert.equal(h.host.rebuildPhase, 'live');
  const phases = h.phases();
  assert.equal(phases[0], 'rebuilding');
  assert.equal(phases.at(-1), 'live');
  const progress = h.posts.filter((p): p is Extract<FromMonitoringWorker, { type: 'rebuild' }> => p.type === 'rebuild');
  assert.ok(progress.every((p, i) => i === 0 || p.fedThroughEntryId >= progress[i - 1].fedThroughEntryId), 'progress only goes forward');
  assert.equal(progress.at(-1)!.fedThroughEntryId, rig.through);
  h.step = 0;
  const fast = await h.query('v', spec(m(0), m(31), 31));
  assert.ok(fast.ok);
  if (fast.ok) assert.equal(fast.value.answeredFrom.rawMinutes, 0, 'every minute is in the rollups');
});

test('host: a rollup post that fails stops the rollups and not the queries', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const h = new HostRig(wrap(rt, { appendMinutes: async () => { throw new Error('disk full'); } }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'failed');
  assert.equal(h.phases().at(-1), 'failed');
  const note = h.posts.filter((p) => p.type === 'rebuild').at(-1);
  assert.ok(note !== undefined && note.type === 'rebuild' && /disk full/.test(note.message ?? ''));
  const q = spec(m(0), m(6), 6);
  const reply = await h.query('v', q);
  assert.ok(reply.ok);
  const oracle = await askOk(rig, q, { forceRaw: true });
  if (reply.ok) assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle));
});

// =====================================================================================================
// a sidecar that cannot be used is a cache that is not there: the journal answers, exactly
// =====================================================================================================

/** The runtime and the query path, for a runtime that is not a rig's own. */
function askWith(rt: HostRuntime, query: QuerySpec, over: Partial<QueryOptions> = {}) {
  return runHistoryQuery(rt, rt, query, new AbortController().signal, { inflate, nowMs: NOW, ...over });
}

class FailingWrites extends MemoryBlockFile {
  override write(): void { throw new Error('disk full (injected)'); }
}

/** The journal of `rig` with a sidecar whose file refuses every write: the open fails. */
function failedSidecarRuntime(rig: Rig): { runtime: LocalRuntime; status: string } {
  const snap = rig.journal.snapshot();
  const opened = RollupStore.open(
    new FailingWrites(),
    { generation: snap.generation, throughEntryId: snap.throughEntryId },
    { nowMs: () => NOW },
  );
  const runtime = new LocalRuntime(rig.journal, opened.store, opened.reason === undefined ? { status: opened.status } : { status: opened.status, reason: opened.reason });
  return { runtime, status: opened.status };
}

/** Every way of asking one range that the sidecar could be asked to help with. */
const DEGRADED_QUERIES: [string, QuerySpec, boolean][] = [
  ['unfocused', spec(m(0), m(6), 6), false],
  ['forced raw', spec(m(0), m(6), 6), true],
  ['focused', spec(m(0), m(6), 6, { focus: { kind: 'endpoint', address: '10.0.0.1' } }), false],
  ['one engine', spec(m(0), m(6), 6, { sourceKey: SRC }), false],
];

test('degraded: a sidecar that cannot write answers every kind of query from the journal, exactly', async () => {
  const rig = smallRig();
  const { runtime, status } = failedSidecarRuntime(rig);
  assert.notEqual(status, 'ok', 'the open failed');
  for (const [label, q, forceRaw] of DEGRADED_QUERIES) {
    const oracle = await askOk(rig, q, { forceRaw: true });
    const reply = await askWith(runtime, q, { forceRaw });
    assert.ok(reply.ok, `${label}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
    if (!reply.ok) continue;
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle), label);
    assert.equal(reply.value.answeredFrom.rollupMinutes, 0, `${label}: nothing came from the rollups`);
    assert.ok(reply.value.answeredFrom.rawMinutes > 0, `${label}: the journal answered`);
  }
});

test('degraded: a sidecar whose sources, watermark or minutes cannot be read is not used, mid-query included', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const rt = rig.runtime;
  const healthy = await askOk(rig, spec(m(0), m(6), 6, { sourceKey: SRC }));
  assert.ok(healthy.answeredFrom.rollupMinutes > 0, 'the rollups are there to be refused');

  const boom = (): never => { throw new Error('storage fault (injected)'); };
  const faults: [string, Over][] = [
    ['sources', { sources: async () => boom() }],
    ['watermark', { watermark: async () => boom() }],
    ['readMinutes', { readMinutes: async () => boom() }],
  ];
  for (const [label, over] of faults) {
    const bad = wrap(rt, over);
    for (const [qlabel, q, forceRaw] of DEGRADED_QUERIES) {
      if (forceRaw) continue;
      const oracle = await askOk(rig, q, { forceRaw: true });
      const reply = await askWith(bad, q);
      assert.ok(reply.ok, `${label} / ${qlabel}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
      if (!reply.ok) continue;
      assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle), `${label} / ${qlabel}`);
    }
  }
  // The faults that a whole-minute query reaches say so in the provenance: the rollups were not used.
  for (const label of ['watermark', 'readMinutes']) {
    const over = faults.find(([l]) => l === label)![1];
    const reply = await askWith(wrap(rt, over), spec(m(0), m(6), 6));
    assert.ok(reply.ok);
    if (reply.ok) assert.deepEqual(reply.value.answeredFrom.rollupMinutes, 0, label);
  }
});

test('degraded: a watermark of another policy, another generation or a place past the journal is not trusted', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const rt = rig.runtime;
  const mark = await rt.watermark();
  assert.ok(mark !== null);
  const q = spec(m(0), m(6), 6);
  const oracle = await askOk(rig, q, { forceRaw: true });
  const lies: [string, typeof mark][] = [
    ['policy', { ...mark, policyVersion: mark.policyVersion + 1 }],
    ['generation', { ...mark, generation: 'd'.repeat(32) }],
    ['past the journal', { ...mark, throughEntryId: mark.throughEntryId + 1000 }],
  ];
  for (const [label, lie] of lies) {
    const reply = await askWith(wrap(rt, { watermark: async () => lie }), q);
    assert.ok(reply.ok, `${label}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
    if (!reply.ok) continue;
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle), label);
    assert.equal(reply.value.answeredFrom.rollupMinutes, 0, `${label}: answered raw`);
    assert.ok(reply.value.answeredFrom.rawMinutes > 0, label);
  }
  // The control: the true watermark is used.
  const truth = await askOk(rig, q);
  assert.ok(truth.answeredFrom.rollupMinutes > 0);
});

test('degraded: only a rollup fault degrades; the journal of another generation is still stale-generation', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const rt = rig.runtime;
  const staleJournal = wrap(rt, { snapshot: async () => ({ ...(await rt.snapshot()), generation: 'e'.repeat(32) }) });
  const reply = await askWith(staleJournal, spec(m(0), m(6), 6));
  assert.ok(!reply.ok && reply.code === 'stale-generation', reply.ok ? 'ok' : reply.code);
  const unavailable = wrap(rt, { readPage: async () => { throw new RuntimeUnavailableError('the port closed'); } });
  const down = await askWith(unavailable, spec(m(0), m(6), 6), { forceRaw: true });
  assert.ok(!down.ok && down.code === 'runtime-unavailable', down.ok ? 'ok' : down.code);
  const sidecarDown = wrap(rt, { readMinutes: async () => { throw new RuntimeUnavailableError('the port closed'); } });
  const r2 = await askWith(sidecarDown, spec(m(0), m(6), 6));
  assert.ok(!r2.ok && r2.code === 'runtime-unavailable', 'a lost runtime is not a lost sidecar');
});

test('degraded: the budget still decides, and the refusal says the rollups are unavailable and why', async () => {
  const rig = big();
  const wide = spec(m(1), m(3), 2);
  const bad = wrap(rig.runtime, { watermark: async () => { throw new Error('storage fault (injected)'); } });
  const reply = await askWith(bad, wide);
  assert.ok(!reply.ok && reply.code === 'range-too-large', reply.ok ? 'ok' : reply.code);
  if (!reply.ok) {
    assert.match(reply.message, /The rollups are unavailable \(.*storage fault \(injected\).*\), so every minute of the range is read from the journal\./);
    assert.ok(!/rebuilt/.test(reply.message));
  }
  const told = await ask(rig, wide, { rollupsUnavailable: 'the rollup sidecar has failed' });
  assert.ok(!told.ok && told.code === 'range-too-large');
  if (!told.ok) assert.match(told.message, /The rollups are unavailable \(the rollup sidecar has failed\)/);
  // Narrow enough for the budget, the same degraded path answers.
  const narrow = await askWith(bad, spec(m(1), m(1, 50_000), 1));
  assert.ok(narrow.ok);
});

test('degraded: a host whose rollups have failed does not use the rollups it already holds', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  // More evidence the sidecar has not seen, so the next host has something to post - and fails to.
  rig.append([start(m(7), S2), dgram(m(7, 1000), [{ src: '10.0.0.1', dst: '10.0.0.2', octets: 5, packets: 1 }]), dgram(m(8, 1000), [{ octets: 1 }])]);
  const q = spec(m(0), m(7), 7);
  const oracle = await askOk(rig, q, { forceRaw: true });

  const failing = new HostRig(wrap(rig.runtime, { appendMinutes: async () => { throw new Error('disk full'); } }));
  await failing.connect();
  assert.equal(failing.host.rebuildPhase, 'failed');
  const reply = await failing.query('v', q);
  assert.ok(reply.ok);
  if (reply.ok) {
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle));
    assert.equal(reply.value.answeredFrom.rollupMinutes, 0, 'a failed host asks the journal');
    assert.equal(reply.value.answeredFrom.rawMinutes, 7);
  }

  // The control: a host that is live, over the same sidecar, uses what the sidecar holds.
  const live = new HostRig(rig.runtime);
  await live.connect();
  assert.equal(live.host.rebuildPhase, 'live');
  const fast = await live.query('v', q);
  assert.ok(fast.ok);
  if (fast.ok) {
    assert.deepEqual(withoutProvenance(fast.value), withoutProvenance(oracle));
    assert.ok(fast.value.answeredFrom.rollupMinutes > 0, 'a live host uses its rollups');
  }
});

// =====================================================================================================
// admission stops as soon as it is decided, and counts only the exporter it is deciding for
// =====================================================================================================

const SRC7 = sourceKey(EXPORTER, 0, 7);
const SRC9 = sourceKey(EXPORTER, 0, 9);
let lateRigCache: Rig | null = null;

/**
 * In journal order: 100,001 datagrams of another exporter; this exporter's
 * engine 0/0 and then engine 0/9; 100,000 more of engine 0/0; and only then
 * engine 0/7. Engine 0/9 follows two datagrams of its own exporter however much
 * the other one sent first; engine 0/7 follows 100,002.
 */
function lateRig(): Rig {
  if (lateRigCache === null) {
    const rig = new Rig(0xc7);
    rig.append([start(m(0))]);
    const run = (n: number, at: (i: number) => number, remote: string): void => {
      for (let from = 0; from < n; from += 2000) {
        const chunk: EvidenceInput[] = [];
        for (let i = from; i < Math.min(from + 2000, n); i++) chunk.push(dgram(at(i), [{ octets: 1 + (i % 9), packets: 1 }], {}, remote));
        rig.append(chunk);
      }
    };
    run(100_001, (i) => m(1, i), OTHER);
    rig.append([
      dgram(m(3), [{ octets: 5, packets: 1 }]),
      dgram(m(3, 5), [{ octets: 9, packets: 1 }], { engineId: 9 }),
    ]);
    run(100_000, (i) => m(6, i), EXPORTER);
    rig.append([dgram(m(9, 10), [{ octets: 42, packets: 1 }], { engineId: 7 }), stop(m(10))]);
    lateRigCache = rig;
  }
  return lateRigCache;
}

test('admission: other exporters\' datagrams neither count against the scan nor are decoded, with or without rollups', async () => {
  const rig = lateRig();
  const q = spec(m(3), m(4), 1, { sourceKey: SRC9 });
  const oracleRaw = await askOk(rig, q, { forceRaw: true });
  assert.equal(oracleRaw.matchingRecords, 1, 'engine 0/9 has its one record');
  // No rollups at all: 100,001 datagrams of another exporter come first and are skipped.
  for (const [label, over] of [['no rollups yet', {}], ['rollups unusable', { rollupsUnavailable: 'the rollup sidecar has failed' }]] as const) {
    const reply = await ask(rig, q, over);
    assert.ok(reply.ok, `${label}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
    if (reply.ok) assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracleRaw), label);
  }
  // The exporter's own 100,000 datagrams are exactly the cap: engine 0/7 follows 100,002, so it is not found...
  const refusedAt = await ask(rig, spec(m(9), m(10), 1, { sourceKey: SRC7 }), { rollupsUnavailable: 'x' });
  assert.ok(!refusedAt.ok && refusedAt.code === 'range-too-large');
});

test('admission: a source past the cap of its own exporter is refused with what limits it, rollups or not', async () => {
  const rig = lateRig();
  const q = spec(m(9), m(10), 1, { sourceKey: SRC7 });
  const noRollups = await ask(rig, q);
  assert.ok(!noRollups.ok && noRollups.code === 'range-too-large', noRollups.ok ? 'ok' : noRollups.code);
  if (!noRollups.ok) {
    assert.match(noRollups.message, /The source has no rollups yet, and its first datagram could not be found within the first 100000 datagrams of its exporter after the last rollup\./);
    assert.ok(!/narrow it/.test(noRollups.message), 'narrowing the range cannot help, so it is not advised');
    assert.match(noRollups.message, /a narrower range does not change that/);
  }
  const degraded = await ask(rig, q, { rollupsUnavailable: 'the rollup sidecar has failed' });
  assert.ok(!degraded.ok && degraded.code === 'range-too-large');
  if (!degraded.ok) {
    assert.match(degraded.message, /The rollups are unavailable \(the rollup sidecar has failed\), and the source's first datagram could not be found within the first 100000 datagrams of its exporter in the journal\./);
    assert.ok(!/narrow it/.test(degraded.message));
  }
  const noted = await ask(rig, q, { rebuildNote: () => 'NOTE' });
  assert.ok(!noted.ok);
  if (!noted.ok) assert.match(noted.message, /NOTE$/, 'a rebuild in progress is still said');

  // With the rollups in place the engine is known, and the same question is answered.
  await rollUp(rig).then((h) => h.host.settled());
  const fast = await askOk(rig, q);
  const raw = await askOk(rig, q, { forceRaw: true });
  assert.equal(fast.matchingRecords, 1);
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  assert.ok(fast.answeredFrom.rollupMinutes > 0);
});

test('admission: an exporter that already has its sixteen engines answers "not admitted" without reading to the end', async () => {
  const rig = new Rig(0xc8);
  const inputs: EvidenceInput[] = [start(m(0))];
  for (let e = 0; e < 16; e++) inputs.push(dgram(m(1, e), [{ octets: 1 + e, packets: 1 }], { engineId: e }));
  inputs.push(dgram(m(1, 500), [{ octets: 77, packets: 1 }], { engineId: 16 })); // the seventeenth, never admitted
  // Eight pages of datagrams a long way from the range: reading any of them is the failure.
  for (let i = 0; i < 8 * LIMITS.pageEntries; i++) inputs.push(dgram(m(400, i), [{ octets: 1, packets: 1 }], { engineId: i % 3 }));
  inputs.push(stop(m(500)));
  rig.append(inputs);

  const SRC16 = sourceKey(EXPORTER, 0, 16);
  const q = spec(m(1), m(2), 1, { sourceKey: SRC16 });
  const reading = (rt: HostRuntime): { rt: HostRuntime; pages: number[] } => {
    const seen: number[] = [];
    return {
      pages: seen,
      rt: wrap(rt, {
        readPage: async (snapshot, after, ...rest) => {
          seen.push(after);
          if (after >= 2 * LIMITS.pageEntries) throw new Error(`read past the point where the answer was decided (after ${after})`);
          return rt.readPage(snapshot, after, ...rest);
        },
      }),
    };
  };
  const notAdmitted = (r: Awaited<ReturnType<typeof ask>>): void => {
    assert.ok(r.ok, r.ok ? '' : `${r.code}: ${r.message}`);
    if (!r.ok) return;
    assert.equal(r.value.matchingRecords, 0);
    assert.deepEqual(r.value.endpoints, { status: 'ok', rows: [] });
  };

  // Rollups unusable: the scan starts at entry 1, and ends at the sixteenth engine's cap.
  const degraded = reading(rig.runtime);
  notAdmitted(await askWith(degraded.rt, q, { rollupsUnavailable: 'the rollup sidecar has failed' }));
  assert.ok(degraded.pages.length <= 3, `${degraded.pages.length} pages read: ${degraded.pages.join(',')}`);

  // No rollups yet: the same scan, from the watermark.
  const bare = reading(rig.runtime);
  notAdmitted(await askWith(bare.rt, q));
  assert.ok(bare.pages.length <= 3, `${bare.pages.length} pages read`);

  // Rollups that already hold the sixteen: no admission scan at all.
  await rollUp(rig).then((h) => h.host.settled());
  const known = reading(rig.runtime);
  notAdmitted(await askWith(known.rt, q));
  assert.ok(known.pages.length <= 1, `${known.pages.length} pages read: only the raw pass`);

  // Control: an engine that is one of the sixteen is found, on the same paths.
  const sixteenth = sourceKey(EXPORTER, 0, 15);
  const found = await ask(rig, spec(m(1), m(2), 1, { sourceKey: sixteenth }), { rollupsUnavailable: 'x' });
  assert.ok(found.ok);
  if (found.ok) assert.equal(found.value.matchingRecords, 1);
});

// =====================================================================================================
// connect: a sidecar that cannot be reset is a sidecar that is not there, not a Worker that is not there
// =====================================================================================================

test('connect: a rollup reset or read that fails leaves the host failed and the journal answering', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const rt = rig.runtime;
  const mark = await rt.watermark();
  assert.ok(mark !== null);
  const q = spec(m(0), m(6), 6);
  const oracle = await askOk(rig, q, { forceRaw: true });
  const boom = (): never => { throw new Error('disk full (injected)'); };

  const cases: [string, Over][] = [
    ['reset on a rebuild-required status', { rollupStatus: async () => ({ status: 'rebuild-required' as const, reason: 'a stored batch is torn' }), resetRollups: async () => boom() }],
    ['reset after a generation mismatch', { watermark: async () => ({ ...mark, generation: 'd'.repeat(32) }), resetRollups: async () => boom() }],
    ['reset after a policy mismatch', { watermark: async () => ({ ...mark, policyVersion: mark.policyVersion + 1 }), resetRollups: async () => boom() }],
    ['the watermark after the reset', { rollupStatus: async () => ({ status: 'rebuild-required' as const }), resetRollups: async () => undefined, watermark: async () => boom() }],
    ['the sources', { sources: async () => boom() }],
    ['the sidecar status itself', { rollupStatus: async () => boom() }],
  ];
  for (const [label, over] of cases) {
    const h = new HostRig(wrap(rt, over));
    const reply = await h.connect();
    assert.ok(reply.type === 'connect-reply' && reply.ok, `${label}: ${JSON.stringify(reply)}`);
    assert.equal(h.host.rebuildPhase, 'failed', label);
    assert.equal(h.phases().at(-1), 'failed', label);
    const note = h.posts.filter((p) => p.type === 'rebuild').at(-1);
    assert.ok(note !== undefined && note.type === 'rebuild' && /disk full \(injected\)/.test(note.message ?? ''), `${label}: the failure is announced`);
    // Nothing is fed and nothing posted: the aggregator starts from 0 and the host is not live.
    assert.equal(reply.type === 'connect-reply' && reply.ok ? reply.watermark : -1, 0, `${label}: nothing fed`);
    const answered = await h.query('v', q);
    assert.ok(answered.ok, `${label}: ${answered.ok ? '' : `${answered.code}: ${answered.message}`}`);
    if (answered.ok) {
      assert.deepEqual(withoutProvenance(answered.value), withoutProvenance(oracle), label);
      assert.equal(answered.value.answeredFrom.rollupMinutes, 0, `${label}: the journal answered`);
    }
  }

  // The journal's own faults still fail the connect: there is nothing to answer from.
  const noJournal = new HostRig(wrap(rt, { snapshot: async () => boom() }));
  const failed = await noJournal.connectOnly();
  assert.ok(failed.type === 'connect-reply' && !failed.ok && failed.code === 'storage-failed', JSON.stringify(failed));
  const lost = new HostRig(wrap(rt, { rollupStatus: async () => { throw new RuntimeUnavailableError('the port closed'); } }));
  const gone = await lost.connectOnly();
  assert.ok(gone.type === 'connect-reply' && !gone.ok && gone.code === 'runtime-unavailable', JSON.stringify(gone));
});

test('connect: a plain fault asking for the sidecar status fails the host, not the connect, and is not retried', async () => {
  const rig = smallRig();
  const h = new HostRig(wrap(rig.runtime, { rollupStatus: async () => { throw new Error('status unreadable (injected)'); } }));
  const reply = await h.connect();
  assert.ok(reply.type === 'connect-reply' && reply.ok, JSON.stringify(reply));
  assert.equal(h.host.rebuildPhase, 'failed');
  const before = h.timers.delays.length;
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'failed', 'a sidecar fault is not transient');
  assert.ok(h.timers.delays.length <= before, 'no retry was scheduled');
  const answered = await h.query('v', spec(m(0), m(6), 6));
  assert.ok(answered.ok);
});

// =====================================================================================================
// a lost runtime while the rollups follow the journal is retried; a fault of the sidecar is not
// =====================================================================================================

test('retry: a transient runtime fault while rebuilding goes back to rebuilding and resumes to live', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  let calls = 0;
  const h = new HostRig(wrap(rt, {
    appendMinutes: async (...a: Parameters<HostRuntime['appendMinutes']>) => {
      if (calls++ === 0) throw new RuntimeUnavailableError('the port is busy');
      return rt.appendMinutes(...a);
    },
  }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'rebuilding', 'a lost runtime is not terminal');
  assert.notEqual(h.phases().at(-1), 'failed');
  assert.ok(h.timers.delays.includes(LIMITS.flushMs), `a retry is waiting: ${h.timers.delays.join(',')}`);
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.equal(h.phases().at(-1), 'live');
  const q = spec(m(0), m(6), 6);
  const reply = await h.query('v', q);
  assert.ok(reply.ok);
  if (reply.ok) {
    const oracle = await askOk(rig, q, { forceRaw: true });
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle));
    assert.ok(reply.value.answeredFrom.rollupMinutes > 0, 'the rollups answer again');
  }
});

test('retry: a transient fault on the journal read is retried too, from a fresh snapshot', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  let snapshots = 0;
  let calls = 0;
  const h = new HostRig(wrap(rt, {
    snapshot: async () => { snapshots++; return rt.snapshot(); },
    readPage: async (...a: Parameters<HostRuntime['readPage']>) => {
      if (calls++ === 0) throw new RuntimeUnavailableError('did not answer readPage');
      return rt.readPage(...a);
    },
  }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'rebuilding');
  const taken = snapshots;
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.ok(snapshots > taken, 'the retry took a snapshot of its own');
});

test('retry: the delay doubles, there is a cap, and the last fault is failed with its words', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const h = new HostRig(wrap(rt, { appendMinutes: async () => { throw new RuntimeUnavailableError('the port closed'); } }));
  await h.connect();
  for (let k = 0; k < 5; k++) {
    assert.equal(h.host.rebuildPhase, 'rebuilding', `attempt ${k}: still retrying`);
    assert.ok(h.timers.delays.includes(LIMITS.flushMs * 2 ** k), `attempt ${k}: waits ${LIMITS.flushMs * 2 ** k} ms, had ${h.timers.delays.join(',')}`);
    h.timers.fire();
    await h.host.settled();
  }
  assert.equal(h.host.rebuildPhase, 'failed', 'five retries are all there are');
  assert.equal(h.phases().at(-1), 'failed');
  const note = h.posts.filter((p) => p.type === 'rebuild').at(-1);
  assert.ok(note !== undefined && note.type === 'rebuild' && /the port closed/.test(note.message ?? ''));
  const reply = await h.query('v', spec(m(0), m(6), 6));
  assert.ok(reply.ok, 'the journal still answers');
});

test('retry: a plain fault of the sidecar while rebuilding stays failed', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const h = new HostRig(wrap(rt, { appendMinutes: async () => { throw new Error('disk full (injected)'); } }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'failed');
  const before = h.timers.delays.length;
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'failed');
  assert.ok(h.timers.delays.length <= before, 'no retry was scheduled');
});

test('retry: a shutdown cancels a waiting retry', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const h = new HostRig(wrap(rt, { appendMinutes: async () => { throw new RuntimeUnavailableError('the port closed'); } }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'rebuilding');
  const down = h.send({ type: 'shutdown' });
  await h.waitFor(() => h.repliesTo(down)[0], 'the shutdown reply');
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'rebuilding', 'nothing resumed after the shutdown');
  assert.equal(h.phases().filter((p) => p === 'live').length, 0);
});

test('refusal: a sidecar that refuses to grow pauses the rollups, never fails them, and resumes when there is room', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  let refuse = 8;
  const h = new HostRig(wrap(rt, {
    appendMinutes: async (...a: Parameters<HostRuntime['appendMinutes']>) => {
      if (refuse-- > 0) throw new RangeError('a batch of 9000 bytes does not fit the room the storage limit leaves (0)');
      return rt.appendMinutes(...a);
    },
  }));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'rebuilding', 'a refusal is not final');
  assert.equal(await rt.watermark(), null, 'the sidecar grew by nothing: every post was refused');
  assert.notEqual(h.phases().at(-1), 'failed');
  const note = h.posts.filter((p) => p.type === 'rebuild').at(-1);
  assert.ok(note !== undefined && note.type === 'rebuild' && /paused/.test(note.message ?? '') && /storage limit/.test(note.message ?? ''), JSON.stringify(note));
  // Meanwhile the journal answers.
  const q = spec(m(0), m(6), 6);
  const during = await h.query('v', q);
  // (`rollupMinutes` also counts the minutes folded from the journal's tail past the watermark, so the
  // sidecar's emptiness is asserted above and the answer is held to the journal's own.)
  assert.ok(during.ok, 'the query is answered while the rollups are paused');
  if (during.ok) assert.deepEqual(withoutProvenance(during.value), withoutProvenance(await askOk(rig, q, { forceRaw: true })));
  // Not tightly: the delay grows, and it goes on past the cap on real faults (5) without failing.
  const seen: number[] = [...h.timers.delays];
  for (let k = 0; k < 7; k++) {
    h.timers.fire();
    await h.host.settled();
    assert.equal(h.host.rebuildPhase, 'rebuilding', `refusal ${k + 1}: still paused`);
    seen.push(...h.timers.delays);
  }
  const ceiling = LIMITS.flushMs * 2 ** 5;
  assert.ok(Math.max(...seen) <= ceiling, `the delay stops growing at ${ceiling}: ${seen.join(',')}`);
  assert.ok(seen.includes(ceiling), `and it grew to the ceiling: ${seen.join(',')}`);
  assert.ok(seen.includes(LIMITS.flushMs * 2), 'by doubling, not at once');
  // Room comes back.
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  const after = await h.query('v', q);
  assert.notEqual(await rt.watermark(), null, 'the sidecar grew once there was room');
  assert.ok(after.ok && after.value.answeredFrom.rollupMinutes > 0, 'the rollups answer again');
  if (after.ok) assert.deepEqual(withoutProvenance(after.value), withoutProvenance(await askOk(rig, q, { forceRaw: true })));
});

test('refusal: a lost runtime is still retried to a cap, and a refusal does not spend its attempts', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  let mode: 'refuse' | 'lost' | 'ok' = 'refuse';
  const h = new HostRig(wrap(rt, {
    appendMinutes: async (...a: Parameters<HostRuntime['appendMinutes']>) => {
      if (mode === 'refuse') throw new RangeError('over the per-call cap');
      if (mode === 'lost') throw new RuntimeUnavailableError('the port closed');
      return rt.appendMinutes(...a);
    },
  }));
  await h.connect();
  for (let k = 0; k < 6; k++) { h.timers.fire(); await h.host.settled(); }
  assert.equal(h.host.rebuildPhase, 'rebuilding');
  mode = 'lost';
  for (let k = 0; k < 5; k++) { h.timers.fire(); await h.host.settled(); assert.equal(h.host.rebuildPhase, 'rebuilding', `lost ${k}`); }
  h.timers.fire();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'failed', 'six refusals before did not buy the lost runtime more tries');
});

// =====================================================================================================
// shutdown waits for what is running, with a bound
// =====================================================================================================

test('host: a shutdown waits for a running query to finish, and gives up on one that never does', async () => {
  const q = spec(m(0), m(3), 3);
  const done = await gatedHost(smallRig(), 'snapshot');
  done.gate.held = true;
  done.h.queryNoWait('a', q);
  await ticks();
  const down = done.h.send({ type: 'shutdown' });
  await ticks();
  assert.equal(done.h.repliesTo(down).length, 0, 'still waiting on the running query');
  assert.ok(done.h.timers.delays.includes(LIMITS.flushMs), 'the wait is bounded by a flush window');
  done.gate.release();
  await done.h.waitFor(() => done.h.repliesTo(down)[0], 'the shutdown reply once the query ended');
  assert.equal(done.h.repliesTo(down).length, 1);

  const stuck = await gatedHost(smallRig(), 'snapshot');
  stuck.gate.held = true;
  stuck.h.queryNoWait('a', q);
  await ticks();
  const down2 = stuck.h.send({ type: 'shutdown' });
  await ticks();
  assert.equal(stuck.h.repliesTo(down2).length, 0);
  stuck.h.timers.fire();
  await stuck.h.waitFor(() => stuck.h.repliesTo(down2)[0], 'the shutdown reply at the bound');
  stuck.gate.release();
  await stuck.h.host.settled();
  assert.equal(stuck.h.repliesTo(down2).length, 1, 'answered once');
});

// =====================================================================================================
// a connect that fails after the runtime was opened closes the port it was given
// =====================================================================================================

test('connect: a failure after the runtime was opened closes the port, and a success does not', async () => {
  const rig = smallRig();
  const rt = rig.runtime;
  const boom = (): never => { throw new Error('journal unreadable (injected)'); };
  for (const [label, over, code] of [
    ['a journal fault', { snapshot: async () => boom() }, 'storage-failed'],
    ['a lost runtime', { rollupStatus: async () => { throw new RuntimeUnavailableError('the port closed'); } }, 'runtime-unavailable'],
  ] as [string, Over, string][]) {
    const closed: unknown[] = [];
    const port = { name: label };
    const h = new HostRig(wrap(rt, over), { closePort: (p) => { closed.push(p); } });
    const id = h.send({ type: 'connect', port });
    const reply = await h.waitFor(() => h.repliesTo(id)[0], 'the connect reply');
    assert.ok(reply.type === 'connect-reply' && !reply.ok && reply.code === code, `${label}: ${JSON.stringify(reply)}`);
    assert.deepEqual(closed, [port], `${label}: the port was closed`);
  }
  const closed: unknown[] = [];
  const h = new HostRig(rt, { closePort: (p) => { closed.push(p); } });
  const id = h.send({ type: 'connect', port: { name: 'kept' } });
  const ok = await h.waitFor(() => h.repliesTo(id)[0], 'the connect reply');
  await h.host.settled();
  assert.ok(ok.type === 'connect-reply' && ok.ok);
  assert.deepEqual(closed, [], 'a port in use stays open');
  // A port that cannot be closed does not turn a refusal into a crash.
  const stubborn = new HostRig(wrap(rt, { snapshot: async () => boom() }), { closePort: () => { throw new Error('already closed'); } });
  const sid = stubborn.send({ type: 'connect', port: {} });
  const sreply = await stubborn.waitFor(() => stubborn.repliesTo(sid)[0], 'the connect reply');
  assert.ok(sreply.type === 'connect-reply' && !sreply.ok);
});

// =====================================================================================================
// what is a sidecar fault and what is not
// =====================================================================================================

test('degraded: a stale generation raised by a sidecar call is the sidecar\'s fault; the journal\'s is the journal\'s', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const rt = rig.runtime;
  const stale = (): never => { throw new StaleGenerationError(rig.generation, 'f'.repeat(32)); };
  const q = spec(m(0), m(6), 6);
  const oracle = await askOk(rig, q, { forceRaw: true });
  for (const [label, over] of [
    ['watermark', { watermark: async () => stale() }],
    ['sources', { sources: async () => stale() }],
    ['readMinutes', { readMinutes: async () => stale() }],
  ] as [string, Over][]) {
    const reply = await askWith(wrap(rt, over), q);
    assert.ok(reply.ok, `${label}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
    if (!reply.ok) continue;
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle), label);
    assert.equal(reply.value.answeredFrom.rollupMinutes, 0, `${label}: the rollups were not used`);
  }
  // The same error from the journal is still a stale-generation reply.
  for (const method of ['snapshot', 'readPage', 'locate'] as const) {
    const reply = await askWith(wrap(rt, { [method]: async () => stale() } as Over), q, { forceRaw: true });
    assert.ok(!reply.ok && reply.code === 'stale-generation', `${method}: ${reply.ok ? 'ok' : reply.code}`);
  }
});

test('degraded: a fault of the sidecar after a chunk was folded and with a real tail restarts the query, exactly', async () => {
  const rig = new Rig(0xc3);
  const first: EvidenceInput[] = [start(m(0, -500))];
  for (let i = 0; i < 100; i++) {
    first.push(dgram(m(i, 1000), [{ src: '10.0.0.1', dst: '10.0.0.2', octets: 100 + i, packets: 1 }, { src: '10.0.0.3', dst: '10.0.0.1', octets: 7, packets: 2 }]));
    if (i % 7 === 0) first.push(junk(m(i, 2000)));
    if (i % 11 === 0) first.push(unreadVersion(m(i, 3000)));
  }
  rig.append(first);
  const host = await rollUp(rig);
  host.host.handle({ type: 'shutdown', requestId: 9999 });
  await host.host.settled();
  // Minutes 100..149 are not in the rollups, and one late datagram belongs to a minute that is.
  const tail: EvidenceInput[] = [];
  for (let i = 100; i < 150; i++) {
    tail.push(dgram(m(i, 1000), [{ src: '10.0.0.1', dst: '10.0.0.9', octets: 5 + i, packets: 1 }]));
    if (i % 5 === 0) tail.push(junk(m(i, 2000)));
  }
  tail.push(dgram(m(50, 45_000), [{ octets: 999, packets: 9 }]), stop(m(150)));
  rig.append(tail);
  const mark = await rig.runtime.watermark();
  assert.ok(mark !== null && mark.throughEntryId < rig.through, 'there is a tail above the watermark');

  const queries: [string, QuerySpec][] = [
    ['exporter-wide', spec(m(0), m(150), 30)],
    ['one engine', spec(m(0), m(150), 30, { sourceKey: SRC })],
  ];
  for (const [label, q] of queries) {
    const oracle = await askOk(rig, q, { forceRaw: true });
    const healthy = await askOk(rig, q);
    assert.deepEqual(withoutProvenance(healthy), withoutProvenance(oracle), `${label}: healthy`);
    assert.ok(healthy.answeredFrom.rollupMinutes > 0, `${label}: the rollups are used when they work`);
    // A chunk is 60 minutes and two reads (the source and its exporter): the third read is the second chunk's.
    for (const good of [2, 3]) {
      let calls = 0;
      const bad = wrap(rig.runtime, {
        readMinutes: async (...a: Parameters<HostRuntime['readMinutes']>) => {
          if (++calls > good) throw new Error('io fault (injected mid-query)');
          return rig.runtime.readMinutes(...a);
        },
      });
      const reply = await askWith(bad, q);
      assert.ok(reply.ok, `${label} / ${good}: ${reply.ok ? '' : `${reply.code}: ${reply.message}`}`);
      if (!reply.ok) continue;
      assert.ok(calls > good, `${label} / ${good}: the fault was reached after a chunk had been folded`);
      assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle), `${label} / ${good}`);
      assert.equal(reply.value.answeredFrom.rollupMinutes, 0, `${label} / ${good}: nothing of the first pass survives`);
    }
  }
});

// =====================================================================================================
// one bad stored minute is one raw minute
// =====================================================================================================

/** Flips a byte inside the stored fragment of `key` for `minuteMs`, past its key and minute: its checksum no longer holds. */
function corruptFragment(sfile: MemoryBlockFile, key: string, minuteMs: number): void {
  const k = new TextEncoder().encode(key);
  const pattern = new Uint8Array(2 + k.length + 8);
  new DataView(pattern.buffer).setUint16(0, k.length, true);
  pattern.set(k, 2);
  new DataView(pattern.buffer).setBigUint64(2 + k.length, BigInt(minuteMs), true);
  const all = new Uint8Array(sfile.size());
  sfile.read(0, all);
  outer: for (let i = 0; i + pattern.length <= all.length; i++) {
    for (let j = 0; j < pattern.length; j++) if (all[i + j] !== pattern[j]) continue outer;
    const at = i + pattern.length + 8 + 2; // inside the rollup bytes, after the watermark the entry carries
    sfile.write(at, Uint8Array.of(all[at] ^ 0xff));
    return;
  }
  throw new Error('the fragment to corrupt was not found');
}

test('corrupt minute: a stored minute that fails its checksum is read from the journal and the rest from the rollups', async () => {
  const rig = smallRig();
  await rollUp(rig).then((h) => h.host.settled());
  const q = spec(m(0), m(6), 6);
  const clean = await askOk(rig, q);
  assert.equal(clean.answeredFrom.rollupMinutes, 6);
  const oracle = await askOk(rig, q, { forceRaw: true });

  corruptFragment(rig.sfile, SRC, m(2));
  const hurt = await askOk(rig, q);
  assert.deepEqual(withoutProvenance(hurt), withoutProvenance(oracle));
  assert.deepEqual(hurt.answeredFrom, { rollupMinutes: 5, rawMinutes: 1 }, 'that minute alone went to the journal');

  // The engine's own query is the same: the minute is single, so the halving ends on it.
  const engine = spec(m(0), m(6), 6, { sourceKey: SRC });
  const hurtEngine = await askOk(rig, engine);
  assert.deepEqual(withoutProvenance(hurtEngine), withoutProvenance(await askOk(rig, engine, { forceRaw: true })));
  assert.deepEqual(hurtEngine.answeredFrom, { rollupMinutes: 5, rawMinutes: 1 });

  // And through the host, which holds the sidecar as a cache and not as a fact.
  const h = new HostRig(rig.runtime);
  await h.connect();
  const reply = await h.query('v', q);
  assert.ok(reply.ok);
  if (reply.ok) assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle));
});

test('host: a live append during a query is not in its answer, and is in the next one', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1), [{ src: '10.7.0.1', dst: '10.8.0.1', octets: 10 }])]);
  const gate = new Gate();
  const h = new HostRig(gatedRuntime(rig.runtime, 'readPage', gate));
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'live');
  const focus = { kind: 'endpoint', address: '10.7.0.1' } as const;
  const q = spec(m(0), m(3), 3, { focus });
  const through = rig.through;
  gate.held = true;
  const id = h.queryNoWait('v', q);
  await ticks();
  const added = rig.add(dgram(m(1, 5000), [{ src: '10.7.0.1', dst: '10.8.0.9', octets: 5000 }]));
  rig.runtime.publishLive(added);
  await ticks();
  gate.release();
  await h.host.settled();
  const reply = queryReplies(h, id)[0].reply;
  assert.ok(reply.ok);
  if (reply.ok) {
    assert.equal(reply.value.snapshot.throughEntryId, through);
    assert.equal(reply.value.matchingRecords, 1);
    assert.equal(reply.value.buckets[1].reportedOctets, 10n);
  }
  const next = await h.query('v', q);
  assert.ok(next.ok);
  if (next.ok) {
    assert.equal(next.value.matchingRecords, 2);
    assert.equal(next.value.snapshot.throughEntryId, rig.through);
  }
  // And the rollups followed the journal: an unfocused minute-aligned query agrees with the raw answer.
  rig.append([stop(m(2))]);
  rig.runtime.publishLive(rig.add(boundary('start', S2, m(2, 1)))); // the push may also carry a boundary
  await h.host.settled();
  const fast = await h.query('w', spec(m(0), m(2), 2));
  const raw = await askOk(rig, spec(m(0), m(2), 2), { forceRaw: true });
  assert.ok(fast.ok);
  if (fast.ok) assert.deepEqual(withoutProvenance(fast.value), withoutProvenance(raw));
});

test('host: a fragment posted after the watermark a query read is not read, and its entries come from the tail once', async () => {
  const rig = new Rig();
  rig.append([start(m(0)), dgram(m(1, 1000), [{ octets: 10, packets: 1 }]), dgram(m(2, 1000), [{ octets: 20, packets: 1 }])]);
  const h = await rollUp(rig);
  const oldMark = await rig.runtime.watermark();
  assert.ok(oldMark !== null);
  // The host posts a second fragment for minute 1 and a first one for minute 3, past the watermark the query is about to read.
  rig.runtime.publishLive(rig.add(dgram(m(1, 2000), [{ octets: 40, packets: 1 }]), dgram(m(3, 1000), [{ octets: 80, packets: 1 }])));
  await h.host.settled();
  const newMark = await rig.runtime.watermark();
  assert.ok(newMark !== null && newMark.throughEntryId > oldMark.throughEntryId, 'the sidecar moved on');
  const lagging = wrap(rig.runtime, { watermark: async () => oldMark });
  const q = spec(m(0), m(5), 5);
  const reply = await runHistoryQuery(lagging, lagging, q, new AbortController().signal, { inflate, nowMs: NOW });
  const oracle = await askOk(rig, q, { forceRaw: true });
  assert.ok(reply.ok);
  if (reply.ok) {
    assert.deepEqual(withoutProvenance(reply.value), withoutProvenance(oracle));
    assert.equal(reply.value.buckets[1].reportedOctets, 50n, 'counted once, not as a fragment and as a tail');
    assert.equal(reply.value.buckets[3].reportedOctets, 80n);
  }
});

// =====================================================================================================
// bounded inflate
// =====================================================================================================

test('inflate: a stream may not allocate past what it is allowed, however small it is stored', () => {
  const zeros = new Uint8Array(10 * 1024 * 1024);
  const bomb = new Uint8Array(deflateRawSync(zeros, { level: 9 }));
  assert.ok(bomb.length < 20_000, 'ten megabytes of zeros is a few kilobytes of deflate');
  assert.throws(() => boundedInflate(bomb, 1 << 20), RangeError);
  assert.throws(() => boundedInflate(bomb, 0), RangeError);
  assert.equal(boundedInflate(bomb, zeros.length).length, zeros.length, 'and is accepted at its true size');

  for (const n of [0, 1, 1000, 65_536]) {
    const exact = Uint8Array.from({ length: n }, (_, i) => (i * 7) & 0xff);
    const packed = new Uint8Array(deflateRawSync(exact));
    assert.deepEqual(boundedInflate(packed, n), exact, `exactly ${n}`);
    assert.deepEqual(boundedInflate(packed, n + 100), exact);
    if (n > 0) assert.throws(() => boundedInflate(packed, n - 1), RangeError, `one byte under ${n}`);
  }
  const out = boundedInflate(new Uint8Array(deflateRawSync(Uint8Array.from([1, 2, 3]))), 3);
  assert.equal(out.buffer.byteLength, 3, 'a copy at its own length, not a view of the allowance');
  for (const bad of [-1, 1.5, NaN, Infinity, 2 ** 53]) assert.throws(() => boundedInflate(bomb, bad), RangeError, String(bad));
  assert.throws(() => boundedInflate(Uint8Array.from([0xff, 0xff, 0xff, 0xff]), 100), Error, 'a corrupt stream is refused, not returned');
});

test('inflate: the codec round-trips through it, and a stored rollup that lies about its size is refused', () => {
  const rollup = {
    sourceKey: SRC, minuteMs: m(3), complete: true, records: 2, reportedOctets: 1500n, reportedPackets: 12n,
    endpoints: [{ address: '10.0.0.1', sentOctets: 1000n, receivedOctets: 500n }],
    conversations: [{ srcAddr: '10.0.0.1', dstAddr: '10.0.0.2', reportedOctets: 1500n, reportedPackets: 12n }],
    malformed: 1, unsupported: 2, unknownSamplingRecords: 1,
    policy: 2, awaitingSets: 0, awaitingBytes: 0, unsupportedTemplateRecords: 0, unsupportedSamplingRecords: 0, samplingInterval: 0, clock: null,
  };
  const stored = encodeMinuteRollup(rollup, deflate);
  assert.deepEqual(decodeMinuteRollup(stored, boundedInflate), rollup);
  assert.deepEqual(decodeMinuteRollup(stored, inflate), rollup);

  const body = new Uint8Array(deflateRawSync(new Uint8Array(64 * 1024 * 1024), { level: 9 }));
  const forged = new Uint8Array(2 + body.length);
  new DataView(forged.buffer).setUint16(0, 1, true);
  forged.set(body, 2);
  assert.throws(() => decodeMinuteRollup(forged, boundedInflate), RangeError);
  assert.throws(() => decodeMinuteRollup(forged, inflate), Error);
});

// =====================================================================================================
// the runtime over a port
// =====================================================================================================

function portPair(runtime: Omit<HostRuntime, 'onLive'>, requestMs = 5000) {
  const { port1, port2 } = new MessageChannel();
  const server = serveRuntime(domPort(port1 as never), runtime);
  const timers: { fn: () => void; ms: number; live: boolean }[] = [];
  const client = createRuntimeClient(domPort(port2 as never), {
    requestMs,
    setTimer: (fn, ms) => {
      const t = { fn, ms, live: true };
      timers.push(t);
      return () => { t.live = false; };
    },
  });
  return { port1, port2, server, client, timers, close: () => { port1.close(); port2.close(); } };
}

test('rpc: calls cross a MessagePort and come back as the runtime answered them', async () => {
  const rig = smallRig();
  const p = portPair(rig.runtime);
  try {
    const snap = await p.client.snapshot();
    assert.deepEqual(snap, rig.journal.snapshot());
    const page = await p.client.readPage(snap, 0, 256, 1 << 20);
    const direct = rig.journal.readPage(snap, 0, 256, 1 << 20);
    assert.deepEqual(page, direct);
    const entry = direct.entries.find((e) => e.kind === 'datagram')!;
    assert.deepEqual(await p.client.readEvidence(entry.ref), entry);
    assert.deepEqual(await p.client.locate(snap, m(1), m(2)), rig.journal.locate(snap, m(1), m(2)));
    assert.deepEqual(await p.client.readBoundaries(snap, 0, 256), rig.journal.readBoundaries(snap, 0, 256));
    assert.equal(await p.client.watermark(), null);
    assert.deepEqual(await p.client.sources(), []);
    assert.deepEqual(await p.client.rollupStatus(), await rig.runtime.rollupStatus());

    // A whole query across the port gives the answer the direct one gives.
    const rolled = await rollUp(rig);
    await rolled.host.settled();
    const q = spec(m(0), m(6), 6);
    const across = await new Promise<unknown>((resolve) => {
      void import('../../src/services/monitoring/queries').then(async ({ runHistoryQuery }) => {
        resolve(await runHistoryQuery(p.client, p.client, q, new AbortController().signal, { inflate, nowMs: NOW }));
      });
    });
    assert.deepEqual(across, await ask(rig, q));
    assert.equal(p.timers.filter((t) => t.live).length, 0, 'every deadline is cancelled when its call is answered');
  } finally {
    p.close();
  }
});

test('rpc: the bundle\'s reads cross the port as the runtime answered them: raw pages, the slice, the dataset and the archive', async () => {
  const { rig, plan } = await expiryWorld();
  const hi = minuteOf(plan.throughMs);
  expire(rig, plan);
  const p = portPair(rig.runtime);
  try {
    const snap = rig.journal.snapshot();
    const after = snap.firstEntryId - 1;
    const raw = await p.client.readRawPage(snap, after, 256, 1 << 20);
    assert.deepEqual(raw, rig.journal.readRawPage(snap, after, 256, 1 << 20));
    assert.equal(raw.entries.length, 256);
    assert.ok(raw.entries[0].body instanceof Uint8Array);
    assert.deepEqual(await p.client.bundleSlice(snap, m(35), m(40)), rig.journal.bundleSlice(snap, m(35), m(40)));
    assert.equal(await p.client.bundleSlice(snap, m(6), hi - 1), null, 'a range that wholly expired has no slice');
    assert.deepEqual(await p.client.dataset(), await rig.runtime.dataset());
    const cuts = await p.client.archive!.cuts();
    assert.equal(cuts.length, 1);
    assert.deepEqual(cuts, rig.archive.cuts());
    const summary = await p.client.archive!.summary(m(0), hi, snap.firstEntryId);
    assert.deepEqual(summary, await rig.runtime.archive!.summary(m(0), hi, snap.firstEntryId));
    assert.ok(typeof summary === 'object' && summary.minutes > 0);
    // The bound crosses the port: with every entry retained, no archived minute is one the journal has not folded.
    assert.deepEqual(await p.client.archive!.summary(m(0), hi, 1), { minutes: 0, policies: [] });
    assert.deepEqual(await p.client.archive!.sources(), rig.archive.sources());
    // An expired id crosses as the class a bundle tells apart.
    await assert.rejects(p.client.readRawPage(snap, 0, 256, 1 << 20), (e: unknown) => e instanceof ExpiredRangeError);
    // A stale snapshot likewise.
    await assert.rejects(p.client.bundleSlice({ generation: 'f'.repeat(32), throughEntryId: 1 }, m(0), m(1)), (e: unknown) => e instanceof StaleGenerationError);
  } finally {
    p.close();
  }
});

test('rpc: a runtime without an archive or a dataset answers the archive as empty and the dataset as unavailable', async () => {
  const rig = smallRig();
  const bare = wrap(rig.runtime, { archive: undefined, dataset: async () => { throw new RuntimeUnavailableError('no dataset.json'); } });
  const p = portPair(bare);
  try {
    assert.deepEqual(await p.client.archive!.cuts(), []);
    assert.deepEqual(await p.client.archive!.summary(m(0), m(6), 1), { minutes: 0, policies: [] });
    assert.deepEqual(await p.client.archive!.sources(), []);
    await assert.rejects(p.client.dataset(), (e: unknown) => e instanceof RuntimeUnavailableError && e.message === 'no dataset.json');
  } finally {
    p.close();
  }
});

test('rpc: a runtime whose archive is not served, over a journal that expired, answers unknown and never empty', async () => {
  const { rig, plan } = await expiryWorld();
  const hi = minuteOf(plan.throughMs);
  expire(rig, plan);
  const key = rig.archive.sources()[0];
  assert.ok(key !== undefined, 'the archive holds minutes of what expired');
  // The collector sets the archive aside when it is refused (corrupt, failed, another generation): the runtime has none.
  const refused = wrap(rig.runtime, { archive: undefined });
  const p = portPair(refused);
  try {
    assert.equal(await p.client.archive!.read(key, m(6), hi, 1 << 20), 'history-lost');
    assert.equal(await p.client.archive!.summary(m(0), hi, 1), 'history-lost');
    await assert.rejects(p.client.archive!.cuts(), (e: unknown) => e instanceof Error && e.name === 'HistoryLostError');
    assert.equal(await p.client.archive!.lastCut(), null);
    assert.equal(await p.client.archive!.coveredThroughMs(), null);
    assert.deepEqual(await p.client.archive!.sources(), []);
    // A History query over the expired range, through that port, is an unknown and not a run of zeros.
    await rollUp(rig).then((h) => h.host.settled());
    const reply = await runHistoryQuery(p.client, p.client, perMinute(m(6), hi), new AbortController().signal, { inflate, nowMs: NOW, archive: p.client.archive });
    assert.equal(reply.ok, true);
    if (!reply.ok) return;
    assert.ok(reply.value.buckets.length > 0);
    for (const b of reply.value.buckets) {
      assert.equal(b.coverage, 'history-lost');
      assert.equal(b.reportedOctets, null);
    }
  } finally {
    p.close();
  }
});

test('rpc: a reply that is not the shape the method returns is unavailable, never a value a bundle would write', async () => {
  const rig = smallRig();
  const p = portPair(wrap(rig.runtime, {
    readRawPage: async () => ({ entries: [{ entryId: 1, kind: 3, policy: 1, receivedMs: 0, body: new Uint8Array(1) }], nextAfterId: 1, done: true }),
    bundleSlice: async () => ({ firstEntryId: 1 }),
    dataset: async () => ({ generation: 'short', createdMs: 0, replaced: null }),
  } as never));
  try {
    await assert.rejects(p.client.readRawPage(rig.journal.snapshot(), 0, 1, 1), (e: unknown) => e instanceof RuntimeUnavailableError);
    await assert.rejects(p.client.bundleSlice(rig.journal.snapshot(), 0, 1), (e: unknown) => e instanceof RuntimeUnavailableError);
    await assert.rejects(p.client.dataset(), (e: unknown) => e instanceof RuntimeUnavailableError);
  } finally {
    p.close();
  }
});

test('rpc: errors cross by name, and the classes a query tells apart are rebuilt', async () => {
  const rig = smallRig();
  const p = portPair(wrap(rig.runtime, {
    snapshot: async () => { throw new StaleGenerationError('want', 'got'); },
    readMinutes: async () => { throw new RangeError('over the cap'); },
    resetRollups: async () => { const e = new Error('odd'); e.name = 'Odd'; throw e; },
    rollupStatus: async () => { throw 'a string'; },
  }));
  try {
    await assert.rejects(p.client.snapshot(), (e: unknown) => e instanceof StaleGenerationError && e.wanted === 'want' && e.actual === 'got');
    await assert.rejects(p.client.readMinutes(SRC, 0, 1, 1), (e: unknown) => e instanceof RangeError && e.message === 'over the cap');
    await assert.rejects(p.client.resetRollups(), (e: unknown) => e instanceof Error && e.name === 'Odd' && e.message === 'odd');
    await assert.rejects(p.client.rollupStatus(), (e: unknown) => e instanceof Error && e.message === 'a string');
  } finally {
    p.close();
  }
});

test('rpc: only the whitelisted calls are served', async () => {
  const rig = smallRig();
  const { port1, port2 } = new MessageChannel();
  serveRuntime(domPort(port1 as never), rig.runtime);
  const got: unknown[] = [];
  port2.on('message', (msg) => got.push(msg));
  try {
    const names = ['constructor', '__proto__', 'toString', 'onLive', 'publishLive', 'journal', 'hasOwnProperty', ''];
    names.forEach((method, i) => port2.postMessage({ type: 'req', id: 100 + i, method, args: [] }));
    port2.postMessage({ type: 'req', id: 200, method: 'snapshot', args: 'nope' });
    port2.postMessage({ type: 'req', id: 'x', method: 'snapshot', args: [] });
    port2.postMessage('garbage');
    port2.postMessage(null);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(got.length, names.length + 1, 'one reply for each request that had a numeric id');
    for (const g of got as { id: number; ok: boolean; error: { name: string; message: string } }[]) {
      assert.equal(g.ok, false);
      assert.equal(g.error.name, 'TypeError');
      assert.match(g.error.message, /^unknown runtime call /);
    }
  } finally {
    port1.close();
    port2.close();
  }
});

test('rpc: a call has a deadline, and an answer that comes after it is dropped', async () => {
  const rig = smallRig();
  let release: (v: Snapshot) => void = () => undefined;
  const slow = new Promise<JournalSnapshot>((resolve) => { release = resolve as never; });
  const p = portPair(wrap(rig.runtime, { snapshot: () => slow }), 1234);
  try {
    const pending = p.client.snapshot();
    await ticks(3);
    const timer = p.timers.find((t) => t.live)!;
    assert.equal(timer.ms, 1234);
    timer.fn();
    await assert.rejects(pending, (e: unknown) => e instanceof RuntimeUnavailableError && /did not answer snapshot in 1234 ms/.test((e as Error).message));
    release(rig.journal.snapshot());
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The next call has its own id and its own answer; the late one reached nobody.
    const next = p.client.watermark();
    assert.equal(await next, null);
  } finally {
    p.close();
  }
});

test('rpc: a closed port fails what is pending and everything after it', async () => {
  const rig = smallRig();
  const never = new Promise<never>(() => undefined);
  const p = portPair(wrap(rig.runtime, { snapshot: () => never }));
  try {
    const pending = p.client.snapshot();
    await ticks(3);
    p.port1.close();
    await assert.rejects(pending, (e: unknown) => e instanceof RuntimeUnavailableError && /closed its port/.test((e as Error).message));
    await assert.rejects(p.client.watermark(), RuntimeUnavailableError);
    assert.equal(p.timers.filter((t) => t.live).length, 0, 'the deadline of a failed call is cancelled');
  } finally {
    p.close();
  }
});

test('rpc: the utility pushes appended entries and the client hands them to its listeners in order', async () => {
  const rig = new Rig();
  const p = portPair(rig.runtime);
  try {
    const seen: Evidence[][] = [];
    p.client.onLive((entries) => seen.push(entries));
    const second: Evidence[][] = [];
    p.client.onLive((entries) => second.push(entries));
    const a = rig.add(start(m(0)), dgram(m(1), [{}]));
    const b = rig.add(stop(m(2)));
    p.server.pushLive(a);
    p.server.pushLive(b);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.deepEqual(seen, [a, b]);
    assert.deepEqual(second, [a, b]);
  } finally {
    p.close();
  }
});

test('rpc: notifyReopened reaches onReopened, in order with the live pushes around it, and a closed port ignores it', async () => {
  const rig = new Rig();
  const p = portPair(rig.runtime);
  try {
    const seen: string[] = [];
    p.client.onLive((entries) => { seen.push(`live:${entries.length}`); });
    p.client.onReopened?.(() => { seen.push('reopened'); });
    const a = rig.add(start(m(0)), dgram(m(1), [{}]));
    p.server.pushLive(a);
    p.server.notifyReopened();
    p.server.pushLive(rig.add(stop(m(2))));
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.deepEqual(seen, ['live:2', 'reopened', 'live:1']);
  } finally {
    p.close();
  }
  assert.doesNotThrow(() => p.server.notifyReopened(), 'a closed port has nobody to tell');
});

// --- a dataset reopened under a connected Worker (ADR 0061) ----------------------------------------------

/** A runtime whose backing dataset can be swapped under the host, the way the utility's collector reopens one. */
function switching(initial: HostRuntime) {
  const state = { target: initial, live: [] as ((e: Evidence[]) => unknown)[], reopened: [] as (() => void)[] };
  const rt = new Proxy({} as HostRuntime, {
    get(_, p) {
      if (p === 'onLive') return (h: (e: Evidence[]) => unknown) => { state.live.push(h); };
      if (p === 'onReopened') return (h: () => void) => { state.reopened.push(h); };
      const v = Reflect.get(state.target, p, state.target) as unknown;
      return typeof v === 'function' ? v.bind(state.target) : v;
    },
  });
  return {
    rt,
    switchTo(next: HostRuntime): void { state.target = next; },
    reopened(): void { for (const h of state.reopened) h(); },
    async push(entries: Evidence[]): Promise<void> { await Promise.all(state.live.map((h) => h(entries))); },
  };
}

/** Datagrams of minutes `from` to `to`, two each, from `remote`. */
function minutesOf(from: number, to: number, remote = EXPORTER, octets = 100): EvidenceInput[] {
  const out: EvidenceInput[] = [];
  for (let i = from; i <= to; i++) {
    out.push(dgram(m(i, 1000), [{ src: '10.0.0.1', dst: '10.0.0.2', octets: octets + i, packets: 1 }], { sampling: 0x4064 }, remote));
    out.push(dgram(m(i, 40_000), [{ src: '10.0.0.2', dst: '10.0.0.1', octets: 10 + octets, packets: 1 }], { sampling: 0x4064 }, remote));
  }
  return out;
}

async function rollupThrough(rig: Rig): Promise<number | null> {
  return (await rig.runtime.watermark())?.throughEntryId ?? null;
}

test('reopen: a copy of the same generation that ends earlier is re-fed, so the rollups equal the raw scan', async () => {
  const a = new Rig();
  const b = new Rig();
  const head = [start(m(0)), ...minutesOf(0, 2)];
  a.add(...head);
  b.add(...head);
  await rollUp(b).then((h) => h.host.settled());
  assert.equal(a.generation, b.generation, 'a copy of a dataset is the same generation');
  const sw = switching(a.runtime);
  const h = new HostRig(sw.rt);
  await h.connect();
  await sw.push(a.add(...minutesOf(3, 4)));
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.ok(a.through > b.through, 'the copy ends before where the host has fed to');

  sw.switchTo(b.runtime);
  sw.reopened();
  await h.host.settled();
  await sw.push(b.add(...minutesOf(3, 6, EXPORTER, 500), stop(m(7))));
  await h.host.settled();

  assert.equal(h.host.rebuildPhase, 'live');
  assert.equal(await rollupThrough(b), b.through, 'every entry of the copy reached its sidecar');
  const q = spec(m(0), m(7), 7);
  const { fast, raw } = await askBoth(b, q);
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
  const viaHost = await h.query('v', q);
  assert.ok(viaHost.ok);
  if (viaHost.ok) assert.deepEqual(withoutProvenance(viaHost.value), withoutProvenance(raw));
});

test('reopen: a whole discard (a new generation) goes live again, with the health and the sources started afresh', async () => {
  const a = new Rig(0xa0);
  const b = new Rig(0x33);
  const OTHER_KEY = sourceKey(OTHER, 0, 0);
  a.add(start(m(0)), ...minutesOf(0, 1));
  b.add(start(m(0)), ...minutesOf(0, 1, OTHER));
  assert.notEqual(a.generation, b.generation);
  const sw = switching(a.runtime);
  const h = new HostRig(sw.rt);
  await h.connect();
  await sw.push(a.add(...minutesOf(2, 3)));
  await h.host.settled();
  h.tick();
  assert.ok(h.healthPosts().at(-1)!.health !== null, 'the first host counted live datagrams');
  assert.deepEqual(h.healthPosts().at(-1)!.sources, [SRC]);

  const before = h.posts.length;
  sw.switchTo(b.runtime);
  sw.reopened();
  await h.host.settled();
  h.tick();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.ok(!h.posts.slice(before).some((p) => p.type === 'rebuild' && p.phase === 'failed'), 'it never failed');
  const reset = h.healthPosts().at(-1)!;
  assert.equal(reset.health, null, 'the old exporter is not described any more');
  assert.deepEqual(reset.sources, [OTHER_KEY]);

  await sw.push(b.add(...minutesOf(2, 3, OTHER, 700), stop(m(4))));
  await h.host.settled();
  h.tick();
  assert.equal(h.healthPosts().at(-1)!.health?.exporterIPv4, OTHER, 'new entries are counted');
  assert.equal(await rollupThrough(b), b.through);
  const { fast, raw } = await askBoth(b, spec(m(0), m(4), 4, { sourceKey: OTHER_KEY }));
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
});

test('reopen: a read-only (rollup status failed) dataset reopened writable leaves failed', async () => {
  const a = new Rig();
  const b = new Rig();
  const inputs = [start(m(0)), ...minutesOf(0, 2), stop(m(3))];
  a.add(...inputs);
  b.add(...inputs);
  const sw = switching(wrap(a.runtime, { rollupStatus: async () => ({ status: 'failed' as const }) }));
  const h = new HostRig(sw.rt);
  await h.connect();
  assert.equal(h.host.rebuildPhase, 'failed');

  sw.switchTo(b.runtime);
  sw.reopened();
  await h.host.settled();
  assert.equal(h.host.rebuildPhase, 'live');
  assert.equal(await rollupThrough(b), b.through, 'the writable dataset is rolled up');
});

test('reopen: a notice with no connection, or after shutdown, is ignored', async () => {
  const a = new Rig();
  a.add(start(m(0)), ...minutesOf(0, 1), stop(m(2)));
  const sw = switching(a.runtime);
  const h = new HostRig(sw.rt);
  sw.reopened();
  await h.host.settled();
  await h.connect();
  const id = h.send({ type: 'shutdown' });
  await h.waitFor(() => h.repliesTo(id)[0], 'the shutdown reply');
  const posts = h.posts.length;
  sw.reopened();
  await h.host.settled();
  assert.equal(h.posts.length, posts, 'nothing is posted after shutdown');
});

// --- after an expiry (ADR 0062) ---------------------------------------------------------------------------

const SEG_LIMIT = 32 * 1024 * 1024; // 1 MiB segments
const EXP_SOURCE: SegmentSource = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055 };
const WIDE_MINUTE = 2;

/** An hour of one datagram a second, and one minute (the third) with more keys than a minute's budget. */
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
    timed.push(dgram(m(WIDE_MINUTE, 100 + k * 50), flows, { engineId: 0 }));
  }
  timed.sort((a, b) => a.receivedMs - b.receivedMs);
  return [{ ...start(BASE), source: EXP_SOURCE } as never, ...timed];
}

/** A rig whose Worker has rolled up the whole journal, and the plan that expires its first two sealed segments. */
async function expiryWorld(jdir?: MemorySegmentDirectory): Promise<{ rig: Rig; plan: ExpiryPlan }> {
  const rig = new Rig(0xa0, SEG_LIMIT, jdir);
  const inputs = expiryInputs();
  for (let at = 0; at < inputs.length; at += 100) rig.append(inputs.slice(at, at + 100));
  await rollUp(rig).then((h) => h.host.settled());
  const segs = rig.journal.segments();
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, SEG_LIMIT, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null, 'the fixture seals at least two segments');
  assert.equal(plan.segments.length, 2);
  return { rig, plan };
}

function expire(rig: Rig, plan: ExpiryPlan): void {
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
  rig.reopen();
}

/** The numbers an expiry must not change. */
function totals(r: HistoryResult) {
  return {
    buckets: r.buckets.map((b) => `${(b.fromMs - BASE) / MIN}: ${b.records} records, ${b.reportedOctets} octets, ${b.reportedPackets} packets`),
    matchingRecords: r.matchingRecords, malformed: r.malformed, unsupported: r.unsupported, samplingKnown: r.samplingKnown,
  };
}

const perMinute = (from: number, to: number): QuerySpec => spec(from, to, (to - from) / MIN);

test('an expired range answers aggregate-only: the totals it had, the tables from the archive', async () => {
  const { rig, plan } = await expiryWorld();
  const cutThrough = plan.throughMs;
  const hi = minuteOf(cutThrough);
  assert.ok(hi > m(12), `the cut (${hi - BASE} ms in) leaves room for a range of expired minutes`);
  const q = perMinute(m(6), hi);
  const before = await askOk(rig, q);
  assert.ok(before.buckets.every((b) => b.coverage === 'observed-records'));
  assert.equal(before.endpoints.status, 'ok');
  const wideBefore = await askOk(rig, perMinute(m(6), m(40)));
  expire(rig, plan);
  await rollUp(rig).then((h) => h.host.settled());
  const after = await askOk(rig, q);
  assert.deepEqual(totals(after), totals(before));
  assert.ok(after.buckets.every((b) => b.coverage === 'aggregate-only'), after.buckets.map((b) => b.coverage).join());
  assert.equal(after.endpoints.status, 'ok');
  assert.equal(after.conversations.status, 'ok');
  assert.deepEqual(after.endpoints, before.endpoints);
  assert.deepEqual(after.conversations, before.conversations);
  assert.deepEqual(after.gaps, [], 'an expired range is not a gap');
  assert.deepEqual(after.evidence, []);
  // Across the cut, into what the journal still holds: the totals are still the ones it had...
  const wide = perMinute(m(6), m(40));
  const across = await askOk(rig, wide);
  assert.deepEqual(totals(across), totals(wideBefore));
  assert.ok(across.buckets.every((b) => b.coverage === 'aggregate-only' || b.coverage === 'observed-records'));
  assert.ok(across.buckets[0].coverage === 'aggregate-only' && across.buckets[across.buckets.length - 1].coverage === 'observed-records');
  // ...and on what it still holds, rollups and raw agree.
  const { fast, raw } = await askBoth(rig, perMinute(hi + MIN, m(40)));
  assert.deepEqual(withoutProvenance(fast), withoutProvenance(raw));
});

test('an incomplete expired minute keeps exact totals and loses its tables', async () => {
  const { rig, plan } = await expiryWorld();
  const q = perMinute(m(WIDE_MINUTE), m(WIDE_MINUTE + 1));
  const before = await askOk(rig, q);
  assert.ok(before.matchingRecords >= 600 * 30, 'the wide minute holds its 18,000 records');
  expire(rig, plan);
  await rollUp(rig).then((h) => h.host.settled());
  const after = await askOk(rig, q);
  assert.deepEqual(totals(after), totals(before));
  assert.equal(after.buckets[0].coverage, 'aggregate-only');
  assert.equal(after.endpoints.status, 'evidence-expired');
  assert.equal(after.conversations.status, 'evidence-expired');
  assert.ok(after.endpoints.status === 'evidence-expired' && after.endpoints.expiredMs === plan.throughMs);
});

test('a corrupt archive minute is history-lost, never zero', async () => {
  const { rig, plan } = await expiryWorld();
  const hi = minuteOf(plan.throughMs);
  const q = perMinute(m(6), hi);
  expire(rig, plan);
  // Damage the middle of the sealed archive, then open it again: it is preserved, and every read of it is refused.
  const bytes = new Uint8Array(rig.afile.size());
  rig.afile.read(0, bytes);
  const at = bytes.length >> 1;
  rig.afile.write(at, Uint8Array.of(bytes[at] ^ 0xff));
  rig.openArchive();
  rig.openSidecar();
  await rollUp(rig).then((h) => h.host.settled());
  const after = await askOk(rig, q);
  assert.ok(after.buckets.length > 0);
  for (const b of after.buckets) {
    assert.equal(b.coverage, 'history-lost');
    assert.equal(b.reportedOctets, null);
    assert.equal(b.reportedPackets, null);
    assert.equal(b.records, 0);
  }
  assert.equal(after.endpoints.status, 'evidence-expired');
  // What the journal still holds is unaffected by it.
  const retained = await askOk(rig, perMinute(hi + MIN, m(40)));
  assert.ok(retained.buckets.every((b) => b.coverage === 'observed-records' && b.reportedOctets !== null));
});

test('a focused query over an expired range says the evidence expired, and through when', async () => {
  const { rig, plan } = await expiryWorld();
  const hi = minuteOf(plan.throughMs);
  expire(rig, plan);
  await rollUp(rig).then((h) => h.host.settled());
  assert.equal((await ask(rig, perMinute(m(6), hi))).ok, true, 'unfocused, the same range answers');
  const focused = await ask(rig, { ...perMinute(m(6), hi), focus: { kind: 'endpoint', address: '10.1.0.1' } });
  assert.equal(focused.ok, false);
  if (focused.ok) return;
  assert.equal(focused.code, 'evidence-expired');
  assert.equal(focused.expiredMs, plan.throughMs);
  // A focused query over what is retained is untouched.
  const kept = await ask(rig, { ...perMinute(hi + MIN, hi + 3 * MIN), focus: { kind: 'endpoint', address: '10.1.0.1' } });
  assert.equal(kept.ok, true);
});

test('an expired range says why its evidence is gone, and when', async () => {
  // user-before: the fixture's plan is a "discard before".
  {
    const { rig, plan } = await expiryWorld();
    assert.equal(plan.reason, 'user-before');
    const hi = minuteOf(plan.throughMs);
    expire(rig, plan);
    await rollUp(rig).then((h) => h.host.settled());
    const wide = await askOk(rig, perMinute(m(WIDE_MINUTE), m(WIDE_MINUTE + 1)));
    assert.ok(wide.endpoints.status === 'evidence-expired');
    if (wide.endpoints.status === 'evidence-expired') assert.deepEqual(wide.endpoints.expiry, { kind: 'discard', atMs: plan.throughMs + 1 });
    const focused = await ask(rig, { ...perMinute(m(6), hi), focus: { kind: 'endpoint', address: '10.1.0.1' } });
    assert.ok(!focused.ok);
    if (!focused.ok) assert.deepEqual(focused.expiry, { kind: 'discard', atMs: plan.throughMs + 1 });
  }
  // age: the boundary's receipt time is the nowMs the expiry ran with.
  {
    const { rig } = await expiryWorld();
    const ranAt = NOW + 40 * 86_400_000;
    const plan = planExpiry(rig.journal.segments(), { keepRawDays: 1, atLimit: 'stop' }, ranAt, 0, SEG_LIMIT);
    assert.ok(plan !== null && plan.reason === 'age', 'an age plan');
    assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: ranAt, deflate }), 'done');
    rig.reopen();
    await rollUp(rig).then((h) => h.host.settled());
    const cause = { kind: 'retention', atMs: ranAt };
    const wide = await askOk(rig, perMinute(m(WIDE_MINUTE), m(WIDE_MINUTE + 1)));
    assert.ok(wide.endpoints.status === 'evidence-expired', 'the wide minute loses its tables');
    if (wide.endpoints.status === 'evidence-expired') {
      assert.deepEqual(wide.endpoints.expiry, cause);
      assert.equal(wide.endpoints.incomplete, true, 'an over-budget archived minute with nothing lost is incomplete');
    }
    const focused = await ask(rig, { ...perMinute(m(6), minuteOf(plan.throughMs)), focus: { kind: 'endpoint', address: '10.1.0.1' } });
    assert.ok(!focused.ok);
    if (!focused.ok) assert.deepEqual(focused.expiry, cause);
  }
});

test('a range whose own expiry boundary has itself expired names no cause, never a newer cut\'s', async () => {
  // A discard before a date, then more traffic seals the segment that holds its boundary, then an age
  // expiry takes that segment too: the discarded range's own cut is gone from the journal.
  const { rig, plan } = await expiryWorld();
  expire(rig, plan);
  const later: EvidenceInput[] = [{ ...start(NOW + 500, S2), source: EXP_SOURCE } as never];
  for (let i = 0; i < 3600; i++) {
    const flows = Array.from({ length: 20 }, (_, j) => ({ src: `10.9.${j}.1`, dst: '172.16.0.1', octets: 100 + j, packets: 1, srcPort: 1000 + j, dstPort: 443 }));
    later.push(dgram(NOW + 1000 + i * 1000, flows, { engineId: 0, sequence: 4000 + i }));
  }
  for (let at = 0; at < later.length; at += 100) rig.append(later.slice(at, at + 100));
  const ranAt = NOW + 40 * 86_400_000;
  const age = planExpiry(rig.journal.segments(), { keepRawDays: 1, atLimit: 'stop' }, ranAt, 0, SEG_LIMIT);
  assert.ok(age !== null && age.reason === 'age', 'an age plan');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, age, { nowMs: ranAt, deflate }), 'done');
  rig.reopen();
  await rollUp(rig).then((h) => h.host.settled());
  const wide = await askOk(rig, perMinute(m(WIDE_MINUTE), m(WIDE_MINUTE + 1)));
  assert.ok(wide.endpoints.status === 'evidence-expired', 'the wide minute has no tables');
  if (wide.endpoints.status === 'evidence-expired') {
    assert.equal(wide.endpoints.expiry, null, 'the discard is not reported as the newer age expiry');
  }
});

test('a query the journal keeps expiring under asks again; it never names an expiry it does not know', async () => {
  const { rig } = await expiryWorld();
  const overtaken = wrap(rig.runtime, {
    readBoundaries: () => { throw new ExpiredRangeError(1); },
    readPage: () => { throw new ExpiredRangeError(1); },
  } as Over);
  const reply = await runHistoryQuery(overtaken, overtaken, spec(m(0), m(5), 5), new AbortController().signal, { inflate, nowMs: NOW });
  assert.equal(reply.ok, false);
  if (!reply.ok) {
    assert.equal(reply.code, 'stale-generation', 'the sheet asks again, as it does for a reopen');
    assert.equal(reply.expiredMs, undefined, 'no "expired before 1 Jan 1970"');
  }
});

test('a lost minute is not incomplete', async () => {
  const { rig, plan } = await expiryWorld();
  const hi = minuteOf(plan.throughMs);
  expire(rig, plan);
  const bytes = new Uint8Array(rig.afile.size());
  rig.afile.read(0, bytes);
  const at = bytes.length >> 1;
  rig.afile.write(at, Uint8Array.of(bytes[at] ^ 0xff));
  rig.openArchive();
  rig.openSidecar();
  await rollUp(rig).then((h) => h.host.settled());
  const lost = await askOk(rig, perMinute(m(6), hi));
  assert.ok(lost.endpoints.status === 'evidence-expired');
  if (lost.endpoints.status === 'evidence-expired') assert.equal(lost.endpoints.incomplete, false);
});

test('a query planned before an expiry restarts or says evidence-expired; it never throws or mixes pages', async () => {
  for (const focused of [false, true]) {
    const { rig, plan } = await expiryWorld();
    const hi = minuteOf(plan.throughMs);
    // Ragged edges, so that the plan reads the journal's pages (the leading partial minute) as well as the rollups.
    const q: QuerySpec = { ...spec(m(6, 1000), hi + 1000, 1), ...(focused ? { focus: { kind: 'endpoint' as const, address: '10.1.0.1' } } : {}) };
    const gate = new Gate();
    gate.held = true;
    const gated = gatedRuntime(rig.runtime, 'readPage', gate);
    const pending = runHistoryQuery(gated, gated, q, new AbortController().signal, { inflate, nowMs: NOW, archive: rig.runtime.archive });
    await ticks();
    assert.ok(gate.entered > 0, 'the query is reading pages');
    assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
    gate.release();
    const reply = await pending;
    const fresh = await ask(rig, q);
    if (focused) {
      assert.equal(reply.ok, false);
      if (!reply.ok) { assert.equal(reply.code, 'evidence-expired'); assert.equal(reply.expiredMs, plan.throughMs); }
    } else {
      // Answered again from the start against the journal as it now is: exactly what a new question gets.
      assert.equal(reply.ok, true, JSON.stringify(reply));
      assert.deepEqual(reply, fresh);
    }
  }
});

// --- an expiry between a query's reads (I1) ---------------------------------------------------------------

test('I1: a whole expiry, cache reset included, between the watermark read and the snapshot read never answers zeros', async () => {
  const { rig, plan } = await expiryWorld();
  const wide = perMinute(m(6), m(40));
  const before = totals(await askOk(rig, wide));
  const gate = new Gate();
  gate.held = true;
  const gated = gatedRuntime(rig.runtime, 'snapshot', gate);
  const pending = runHistoryQuery(gated, gated, wide, new AbortController().signal, { inflate, nowMs: NOW, archive: rig.runtime.archive });
  await ticks();
  assert.ok(gate.entered > 0, 'the query has read what it reads before the snapshot and is waiting for it');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
  assert.equal(rig.store.watermark(), null, 'the cache was reset under it');
  gate.release();
  const reply = await pending;
  assert.equal(reply.ok, true, reply.ok ? '' : `${reply.code}: ${reply.message}`);
  if (!reply.ok) return;
  // Exact, never the zeros of retained minutes a reset cache and a stale watermark would give.
  assert.deepEqual(totals(reply.value), before);
});

test('I1: an expiry after the query has read the boundaries and before it reads the sidecar is seen at the end, and restarts it', async () => {
  // The boundaries the query holds are from before the expiry, so the stale-cache rule cannot see it:
  // only the check at the end (the cut moved, or the watermark fell) stands between the query and the
  // reset sidecar's empty answer for every retained minute.
  const { rig, plan } = await expiryWorld();
  const before = totals(await askOk(rig, WIDE));
  const gate = new Gate();
  gate.held = true;
  const gated = gatedRuntime(rig.runtime, 'sources', gate);
  const pending = runHistoryQuery(gated, gated, WIDE, new AbortController().signal, { inflate, nowMs: NOW, archive: rig.runtime.archive });
  await ticks();
  assert.ok(gate.entered > 0, 'the query has read its boundaries and is waiting to ask the sidecar who it knows');
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'done');
  assert.equal(rig.store.watermark(), null, 'the cache was reset under it');
  gate.release();
  const reply = await pending;
  assert.equal(reply.ok, true, reply.ok ? '' : `${reply.code}: ${reply.message}`);
  if (!reply.ok) return;
  assert.deepEqual(totals(reply.value), before);
});

// --- a crash after the boundary, before the cache reset (C1) ----------------------------------------------

/** The journal's `expired` boundaries, as a reader sees them. */
async function expiredBoundaryIds(rig: Rig): Promise<number[]> {
  const snap = rig.journal.snapshot();
  const page = await rig.runtime.readBoundaries(snap, snap.firstEntryId - 1, 1000);
  return page.entries.filter((b) => b.action === 'expired').map((b) => b.ref.entryId);
}

const WIDE = perMinute(m(6), m(40));

/**
 * The state a crash leaves when the cut and the boundary are durable and the cache is not reset: `how` is
 * the process dying inside `cache.reset()`, or the disk refusing the unlink after the boundary. Reopened
 * from the same files, as a new process would. Returns the totals the range had before any of it.
 */
async function crashedAfterBoundary(how: 'dies-before-reset' | 'unlink-fails'): Promise<{ rig: Rig; plan: ExpiryPlan; before: ReturnType<typeof totals> }> {
  const dir = new FlakyDirectory();
  const { rig, plan } = await expiryWorld(dir);
  const before = totals(await askOk(rig, WIDE));
  if (how === 'dies-before-reset') {
    const cache = Object.create(rig.store) as RollupStore;
    cache.reset = () => { throw new Error('the process died'); };
    assert.equal(runExpiry(rig.journal, cache, rig.archive, plan, { nowMs: NOW, deflate }), 'failed');
  } else {
    dir.failUnlink = true;
    assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'failed');
    dir.failUnlink = false;
  }
  rig.reopen();
  const wm = rig.store.watermark();
  const [boundary] = await expiredBoundaryIds(rig);
  assert.ok(boundary !== undefined, 'the boundary is durable');
  if (how === 'dies-before-reset') {
    assert.ok(wm !== null && wm.throughEntryId < boundary, `the cache still describes the world before the boundary (${wm?.throughEntryId} < ${boundary})`);
  } else {
    assert.equal(wm, null, 'a refused unlink still resets the cache, since the boundary is durable');
  }
  assert.equal(rig.journal.snapshot().firstEntryId, plan.throughEntryId + 1, 'the journal finished the unlink');
  return { rig, plan, before };
}

for (const how of ['dies-before-reset', 'unlink-fails'] as const) {
  test(`C1 (${how}): a cache no one reset, below the boundary, does not double the expired minutes in a query`, async () => {
    const { rig, before } = await crashedAfterBoundary(how);
    const after = await askOk(rig, WIDE);
    assert.deepEqual(totals(after), before);
    assert.ok(after.buckets.some((b) => b.coverage === 'aggregate-only'), 'the expired minutes come from the archive');
  });

  test(`C1 (${how}): resumeExpiry resets the cache, a rebuild follows and the totals stay exact`, async () => {
    const { rig, before } = await crashedAfterBoundary(how);
    const archived = rig.archive.bytes();
    assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive), how === 'dies-before-reset' ? 'resumed' : 'none');
    assert.equal(rig.store.watermark(), null, 'the cache was reset');
    assert.equal(rig.archive.bytes(), archived, 'nothing was archived again');
    assert.equal((await expiredBoundaryIds(rig)).length, 1, 'and no second boundary');
    assert.equal(resumeExpiry(rig.journal, rig.store, rig.archive), 'none', 'nothing left to resume');
    assert.deepEqual(totals(await askOk(rig, WIDE)), before, 'before the rebuild');
    await rollUp(rig).then((h) => h.host.settled());
    assert.ok(rig.store.watermark() !== null);
    assert.deepEqual(totals(await askOk(rig, WIDE)), before, 'after the rebuild');
  });

  test(`C1 (${how}): a Worker host that connects to the crashed cache resets it itself, rebuilds, and answers exactly`, async () => {
    const { rig, before } = await crashedAfterBoundary(how);
    const [boundary] = await expiredBoundaryIds(rig);
    const h = await rollUp(rig);
    await h.host.settled();
    const wm = rig.store.watermark();
    assert.ok(wm !== null && wm.throughEntryId >= boundary, `the host did not keep a cache below the boundary (${wm?.throughEntryId} vs ${boundary})`);
    assert.ok(!h.posts.some((p) => p.type === 'rebuild' && p.phase === 'failed'), 'the rebuild did not fail');
    assert.deepEqual(totals(await askOk(rig, WIDE)), before);
  });
}

test('C1 (unlink-fails, live): the process carries on, and a batch continuing from the old watermark is refused', async () => {
  // No reopen: the boundary is durable, the unlink was not, and the live Worker's next batch continues from
  // where the cache was. Accepted, it would lift the watermark past the boundary with the expired minutes
  // still inside, and the stale-cache rule would then trust it.
  const dir = new FlakyDirectory();
  const { rig, plan } = await expiryWorld(dir);
  const before = totals(await askOk(rig, WIDE));
  const old = rig.store.watermark();
  assert.ok(old !== null);
  dir.failUnlink = true;
  assert.equal(runExpiry(rig.journal, rig.store, rig.archive, plan, { nowMs: NOW, deflate }), 'failed');
  dir.failUnlink = false;
  const [boundary] = await expiredBoundaryIds(rig);
  assert.ok(boundary !== undefined, 'the boundary is durable');
  const next = { ...old, throughEntryId: Math.max(old.throughEntryId, boundary) + 1 };
  assert.throws(() => rig.store.appendMinutes([], next, old.throughEntryId), RangeError, 'a batch from the old watermark');
  assert.deepEqual(totals(await askOk(rig, WIDE)), before);
});

// --- engine admission across an expiry (I4) ---------------------------------------------------------------

/** Sixteen engines in the first stretch (what the first expiry takes), a seventeenth only later, in a retained segment. */
function admissionInputs(): EvidenceInput[] {
  const out: EvidenceInput[] = [start(BASE)];
  for (let i = 0; i < 6000; i++) {
    const flows = Array.from({ length: 20 }, (_, j) => ({
      src: `10.${i % 5}.${j}.1`, dst: `172.16.${j % 4}.${(i % 9) + 1}`, octets: 100 + j, packets: 1, srcPort: 1000 + j, dstPort: 443,
    }));
    const engineId = i < 1500 ? i % 16 : i >= 3500 && i < 3700 ? 16 : 0;
    out.push(dgram(BASE + 1000 + i * 1000, flows, { engineId, sequence: i }));
  }
  return out;
}

test('I4: engine admission after an expiry is what a rebuild gives: the sixteen that expired keep the exporter full', async () => {
  const rig = new Rig(0xa0, SEG_LIMIT);
  const inputs = admissionInputs();
  for (let at = 0; at < inputs.length; at += 100) rig.append(inputs.slice(at, at + 100));
  const SRC16 = sourceKey(EXPORTER, 0, 16);
  const q16 = spec(BASE, BASE + 120 * MIN, 120, { sourceKey: SRC16 });
  const q0 = spec(BASE, BASE + 120 * MIN, 120, { sourceKey: SRC });
  await rollUp(rig).then((h) => h.host.settled());
  assert.equal((await askOk(rig, q16)).matchingRecords, 0, 'the seventeenth is not admitted over the whole journal');
  assert.ok(!rig.store.sources().includes(SRC16));
  const wide = totals(await askOk(rig, q0));

  const segs = rig.journal.segments();
  assert.ok(segs.filter((s) => s.sealed).length >= 4, `the fixture seals four segments (got ${segs.length})`);
  const plan = planExpiry(segs, DEFAULT_RETENTION, NOW, 0, SEG_LIMIT, segs[1].lastReceivedMs + 1);
  assert.ok(plan !== null);
  expire(rig, plan);
  assert.equal((await askOk(rig, q16)).matchingRecords, 0, 'after the expiry and a reopen, before any rebuild: the query\'s admission');
  assert.ok(rig.archive.sources().includes(SRC), 'the archive holds the engines that expired');

  await rollUp(rig).then((h) => h.host.settled());
  assert.ok(!rig.store.sources().includes(SRC16), 'the Worker host rebuilt with the sixteen known, not the seventeenth admitted');
  assert.equal((await askOk(rig, q16)).matchingRecords, 0, 'after the rebuild');

  // The segments holding the seventeenth expire next: the archive must not admit it either.
  const next = rig.journal.segments();
  const plan2 = planExpiry(next, DEFAULT_RETENTION, NOW, 0, SEG_LIMIT, next[1].lastReceivedMs + 1);
  assert.ok(plan2 !== null);
  expire(rig, plan2);
  assert.ok(!rig.archive.sources().includes(SRC16), 'expiryFragments did not admit the seventeenth');
  assert.equal((await askOk(rig, q16)).matchingRecords, 0, 'after the second expiry');
  assert.deepEqual(totals(await askOk(rig, q0)), wide, 'and the admitted engine\'s totals are exact throughout');
});

test('the recorded exporter survives the expiry of the only start boundary', async () => {
  const { rig, plan } = await expiryWorld();
  const snap0 = rig.journal.snapshot();
  assert.deepEqual(recordedSource((await rig.runtime.readBoundaries(snap0, 0, 100)).entries), EXP_SOURCE);
  expire(rig, plan);
  const snap = rig.journal.snapshot();
  assert.ok(snap.firstEntryId > 1);
  const kept = await rig.runtime.readBoundaries(snap, snap.firstEntryId - 1, 100);
  assert.ok(!kept.entries.some((b) => b.action === 'start'), 'the start went with the first segment');
  assert.deepEqual(recordedSource(kept.entries), EXP_SOURCE);
});

process.exit((await runAll()) === 0 ? 0 : 1);
