/**
 * Assertion tests for the source-health reducer and the admission budget
 * (ADRs 0058 and 0059).
 *
 *   npx tsx scripts/monitoring/health-budget.ts
 *
 * Both are pure and take their clocks as arguments. That is what makes the
 * one claim worth the most testable: staleness follows the monotonic elapsed
 * time, so a wall clock that is stepped back (NTP, DST, a VM resume) can
 * neither fake freshness nor hide a record.
 */
import assert from 'node:assert/strict';
import { ByteBudget } from '../../src/services/monitoring/budget';
import {
  canAdmitEngine, initialSourceHealth, reduceSourceHealth,
  type HealthEvent, type SourceHealth,
} from '../../src/services/monitoring/sourceHealth';
import { LIMITS } from '../../src/services/monitoring/types';
import { sourceKey } from '../../src/services/monitoring/v5';
import { EXPORTER } from './fixtures';

let failures = 0;
function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${e instanceof Error ? e.message.split('\n').join('\n        ') : String(e)}`);
  }
}

const WALL = 1_760_000_000_000;

/** Folds events, giving each the clocks the test names. */
function run(events: HealthEvent[], from: SourceHealth = initialSourceHealth(EXPORTER)): SourceHealth {
  return events.reduce(reduceSourceHealth, from);
}

function valid(
  elapsedMs: number, engineId: number, sequence: number, flowCount: number, entryId = 1, wallMs = WALL + elapsedMs, admitted?: boolean,
): HealthEvent {
  return {
    kind: 'datagram', outcome: 'valid', engineType: 0, engineId, sequence, flowCount, entryId, elapsedMs, wallMs,
    ...(admitted === undefined ? {} : { admitted }),
  };
}

const listening = (elapsedMs = 0): HealthEvent => ({ kind: 'listener', state: 'listening', elapsedMs, wallMs: WALL + elapsedMs });
const tick = (elapsedMs: number, wallMs = WALL + elapsedMs): HealthEvent => ({ kind: 'tick', elapsedMs, wallMs });
const rejected = (address: string, elapsedMs = 0): HealthEvent => ({ kind: 'rejected-sender', address, elapsedMs, wallMs: WALL + elapsedMs });

// --- the initial state -----------------------------------------------------------------

test('a new source has seen nothing, and says loss is unknown rather than zero', () => {
  const h = initialSourceHealth(EXPORTER);
  assert.equal(h.exporterIPv4, EXPORTER);
  assert.equal(h.listener.state, 'stopped');
  assert.equal(h.storage.state, 'ok');
  assert.equal(h.freshness, 'never');
  assert.equal(h.lastValidWallMs, null);
  assert.deepEqual(h.engines, []);
  assert.equal(h.accepted, 0);
  assert.equal(h.transportLoss, 'unknown');
  assert.equal(h.analyzedThroughEntryId, null);
  assert.equal(h.rolledUpThroughEntryId, null);
});

test('health is plain data: it survives a structured clone unchanged', () => {
  const h = run([listening(), valid(10, 0, 0, 3), rejected('203.0.113.1'), { kind: 'shed', count: 4, elapsedMs: 20, wallMs: WALL }]);
  assert.deepEqual(structuredClone(h), h);
  assert.deepEqual(JSON.parse(JSON.stringify(h)), h);
});

test('the reducer never mutates the state it is given', () => {
  const before = run([listening(), valid(10, 0, 0, 3)]);
  const snapshot = structuredClone(before);
  reduceSourceHealth(before, valid(20, 1, 0, 3));
  reduceSourceHealth(before, rejected('203.0.113.1'));
  assert.deepEqual(before, snapshot);
});

// --- listener and storage ------------------------------------------------------------------

test('listener and storage are separate states with their own errors', () => {
  let h = run([{ kind: 'listener', state: 'starting', elapsedMs: 0, wallMs: WALL }]);
  assert.equal(h.listener.state, 'starting');
  h = run([listening(1)], h);
  assert.equal(h.listener.state, 'listening');
  h = run([{ kind: 'storage', state: 'failed', error: 'ENOSPC', elapsedMs: 2, wallMs: WALL }], h);
  assert.equal(h.storage.state, 'failed');
  assert.equal(h.storage.error, 'ENOSPC');
  assert.equal(h.listener.state, 'listening', 'a full disk does not say the socket is down');
  h = run([{ kind: 'listener', state: 'failed', error: 'EADDRINUSE', elapsedMs: 3, wallMs: WALL }], h);
  assert.equal(h.listener.state, 'failed');
  assert.equal(h.listener.error, 'EADDRINUSE');
  assert.equal(h.storage.error, 'ENOSPC', 'and the reverse');
  h = run([{ kind: 'storage', state: 'ok', elapsedMs: 4, wallMs: WALL }], h);
  assert.equal(h.storage.state, 'ok');
  assert.equal(h.storage.error, null);
});

// --- freshness ----------------------------------------------------------------------------

test('fresh on a valid datagram, stale after staleMs of silence, fresh again on the next', () => {
  let h = run([listening(0), valid(1_000, 0, 0, 1, 1)]);
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.lastValidEntryId, 1);
  h = run([tick(1_000 + LIMITS.staleMs - 1)], h);
  assert.equal(h.freshness, 'fresh');
  h = run([tick(1_000 + LIMITS.staleMs)], h);
  assert.equal(h.freshness, 'stale');
  h = run([valid(1_000 + LIMITS.staleMs + 5, 0, 1, 1, 2)], h);
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.lastValidEntryId, 2);
});

test('nothing received is "never", not "stale", however long it waits', () => {
  const h = run([listening(0), tick(10 * LIMITS.staleMs)]);
  assert.equal(h.freshness, 'never');
});

test('malformed and unsupported datagrams are counted and do not make the source fresh', () => {
  let h = run([
    listening(0),
    { kind: 'datagram', outcome: 'malformed', entryId: 1, elapsedMs: 5, wallMs: WALL },
    { kind: 'datagram', outcome: 'unsupported', entryId: 2, elapsedMs: 6, wallMs: WALL },
    { kind: 'datagram', outcome: 'unsupported', entryId: 3, elapsedMs: 7, wallMs: WALL },
  ]);
  assert.equal(h.malformed, 1);
  assert.equal(h.unsupported, 2);
  assert.equal(h.accepted, 0);
  assert.equal(h.freshness, 'never');
  h = run([valid(8, 0, 0, 1, 4)], h);
  assert.equal(h.accepted, 1);
});

test('a wall clock stepped back neither fakes freshness nor breaks stale detection', () => {
  let h = run([listening(0), valid(1_000, 0, 0, 1, 1, WALL)]);
  // An hour back on the wall clock, a minute forward on the monotonic one.
  h = run([tick(1_000 + LIMITS.staleMs, WALL - 3_600_000)], h);
  assert.equal(h.freshness, 'stale');
  // A datagram stamped before the previous one, by the wall clock.
  h = run([valid(1_000 + LIMITS.staleMs + 10, 0, 1, 1, 2, WALL - 3_600_000)], h);
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.accepted, 2, 'the record is counted, not hidden');
  assert.equal(h.lastValidWallMs, WALL - 3_600_000, 'display time is what was reported, never reordered');
  // A tick that arrives with a smaller elapsed (a bug upstream) cannot un-stale or un-fresh anything.
  const again = run([tick(5)], h);
  assert.equal(again.freshness, 'fresh');
});

test('a stopped source is not fresh', () => {
  let h = run([listening(0), valid(10, 0, 0, 1)]);
  h = run([{ kind: 'listener', state: 'stopped', elapsedMs: 20, wallMs: WALL }], h);
  assert.equal(h.listener.state, 'stopped');
  assert.equal(h.freshness, 'stale');
  assert.equal(h.accepted, 1, 'stopping keeps what was counted');
  h = run([tick(30)], h);
  assert.equal(h.freshness, 'stale');
});

test('a failed listener records its error but does not itself make the source stale', () => {
  // Freshness is a statement about the last valid datagram, decided by elapsed
  // time alone; only an orderly stop marks it stale at once.
  let h = run([listening(0), valid(1_000, 0, 0, 1)]);
  h = run([{ kind: 'listener', state: 'failed', error: 'EADDRINUSE', elapsedMs: 1_100, wallMs: WALL }], h);
  assert.equal(h.listener.state, 'failed');
  assert.equal(h.listener.error, 'EADDRINUSE');
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.accepted, 1);
  h = run([tick(1_000 + LIMITS.staleMs)], h);
  assert.equal(h.freshness, 'stale', 'the silence is what ages it');
  assert.equal(h.listener.state, 'failed');
  // And a failure with no valid datagram before it leaves the source at "never".
  const never = run([{ kind: 'listener', state: 'failed', elapsedMs: 5, wallMs: WALL }]);
  assert.equal(never.freshness, 'never');
  assert.equal(never.listener.error, 'failed', 'an unnamed failure still says it failed');
});

test('starting after stopped keeps the history and a stale source until a datagram arrives', () => {
  let h = run([listening(0), valid(10, 0, 0, 5, 1)]);
  h = run([{ kind: 'listener', state: 'stopped', elapsedMs: 20, wallMs: WALL }], h);
  assert.equal(h.freshness, 'stale');
  h = run([{ kind: 'listener', state: 'starting', elapsedMs: 30, wallMs: WALL }], h);
  assert.equal(h.listener.state, 'starting');
  assert.equal(h.listener.error, null);
  assert.equal(h.freshness, 'stale', 'restarting the socket proves nothing was heard');
  assert.equal(h.accepted, 1);
  assert.equal(h.lastValidEntryId, 1);
  assert.equal(h.engines[0].expectedSequence, 5, 'the sequence chain survives the restart');
  h = run([listening(40), valid(50, 0, 5, 5, 2)], h);
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.engines[0].gaps, 0);
  assert.equal(h.accepted, 2);
});

// --- engines ------------------------------------------------------------------------------

test('engines are separate sources under one exporter, keyed as the decoder keys them', () => {
  const h = run([listening(), valid(1, 0, 0, 2), valid(2, 7, 100, 3)]);
  assert.equal(h.engines.length, 2);
  assert.equal(h.engines[0].sourceKey, sourceKey(EXPORTER, 0, 0));
  assert.equal(h.engines[1].sourceKey, sourceKey(EXPORTER, 0, 7));
  assert.equal(h.engines[0].flows, 2);
  assert.equal(h.engines[1].flows, 3);
});

test('a 17th engine is counted as rejected with engine-limit and never gets a row', () => {
  const events: HealthEvent[] = [listening()];
  for (let id = 0; id < LIMITS.enginesPerExporter; id++) events.push(valid(id + 1, id, 0, 1, id + 1));
  let h = run(events);
  assert.equal(h.engines.length, LIMITS.enginesPerExporter);
  assert.equal(canAdmitEngine(h, 0, 5), true, 'a known engine is admitted');
  assert.equal(canAdmitEngine(h, 0, 99), false, 'a new one is not');
  const acceptedBefore = h.accepted;
  h = run([valid(100, 99, 0, 1, 99)], h);
  assert.equal(h.engines.length, LIMITS.enginesPerExporter);
  assert.equal(h.engineLimitRejected, 1);
  assert.equal(h.accepted, acceptedBefore, 'it was kept in the journal, not accepted');
  assert.ok(!h.engines.some((e) => e.engineId === 99));
  h = run([valid(101, 3, 1, 1, 100)], h);
  assert.equal(h.engines.find((e) => e.engineId === 3)?.accepted, 2, 'a known engine still counts');
  assert.equal(h.engineLimitRejected, 1);
});

test('a changing remote UDP port creates no identity row (the port is not an input at all)', () => {
  // The reducer is never told a port: the same event, repeated, is one engine.
  const h = run([listening(), valid(1, 0, 0, 1), valid(2, 0, 1, 1), valid(3, 0, 2, 1)]);
  assert.equal(h.engines.length, 1);
  assert.equal(h.engines[0].accepted, 3);
});

// --- v5 sequence ---------------------------------------------------------------------------

function engineAfter(...seqs: [number, number][]): SourceHealth['engines'][number] {
  const h = run([listening(), ...seqs.map(([s, c], i) => valid(i + 1, 0, s, c, i + 1))]);
  return h.engines[0];
}

test('sequence: contiguous datagrams report nothing', () => {
  const e = engineAfter([0, 5], [5, 5], [10, 1]);
  assert.equal(e.expectedSequence, 11);
  assert.equal(e.jumpedFlows, 0);
  assert.equal(e.gaps, 0);
  assert.equal(e.duplicates, 0);
  assert.equal(e.reordered, 0);
  assert.equal(e.resets, 0);
});

test('sequence: a forward jump counts the missing flows and one gap', () => {
  const e = engineAfter([0, 5], [20, 1]);
  assert.equal(e.jumpedFlows, 15);
  assert.equal(e.gaps, 1);
  assert.equal(e.expectedSequence, 21);
});

test('sequence: a repeat is a duplicate, and does not move the expectation', () => {
  const e = engineAfter([0, 5], [5, 5], [5, 5]);
  assert.equal(e.duplicates, 1);
  assert.equal(e.expectedSequence, 10);
  assert.equal(e.accepted, 3, 'every datagram stays counted: nothing is deleted');
});

/** The counts the sequence rules own, so a test can name them all and say which are zero. */
function counts(e: SourceHealth['engines'][number]) {
  return {
    gaps: e.gaps, jumpedFlows: e.jumpedFlows, duplicates: e.duplicates,
    reordered: e.reordered, resets: e.resets, unresolved: e.unresolved,
  };
}
const NONE = { gaps: 0, jumpedFlows: 0, duplicates: 0, reordered: 0, resets: 0, unresolved: 0 };

test('sequence: a restart at a small expected value is a reset and loses nothing', () => {
  // The exporter reached expected=100, then restarted at 0 with 30-flow datagrams.
  // Judged by distance this read as four reordered datagrams and 20 missing flows.
  const e = engineAfter([0, 50], [50, 50], [0, 30], [30, 30], [60, 30], [90, 30]);
  assert.deepEqual(counts(e), { ...NONE, resets: 1 });
  assert.equal(e.expectedSequence, 120, 'the new chain was adopted');
  assert.equal(e.pending, null);
});

test('sequence: a datagram arriving far behind is a late arrival, not a reset', () => {
  // Fifteen contiguous datagrams of 1,000 flows, then a copy of one 10,000 flows
  // back held up by the network, then the main chain carries on.
  const chain: [number, number][] = [];
  for (let i = 0; i < 15; i++) chain.push([i * 1000, 1000]);
  const e = engineAfter(...chain, [5000, 1000], [15_000, 1000]);
  assert.deepEqual(counts(e), { ...NONE, reordered: 1 });
  assert.equal(e.expectedSequence, 16_000, 'the main chain was never disturbed');
});

test('sequence: a datagram swapped with the next is one gap, then one late arrival', () => {
  // 0, 10 (jumps over 5), 5 (late), 15: the jump is counted when it happens and
  // is not taken back - which is why jumpedFlows is not a loss figure.
  const e = engineAfter([0, 5], [10, 5], [5, 5], [15, 5]);
  assert.deepEqual(counts(e), { ...NONE, gaps: 1, jumpedFlows: 5, reordered: 1 });
  assert.equal(e.expectedSequence, 20);
  assert.equal(e.pending, null);
});

test('sequence: a step back followed by neither chain is unresolved', () => {
  // Expected 100; 10 steps back (its successor would be 15); 500 is neither 100 nor 15.
  const e = engineAfter([0, 50], [50, 50], [10, 5], [500, 5]);
  assert.deepEqual(counts(e), { ...NONE, unresolved: 1, gaps: 1, jumpedFlows: 400 });
  assert.equal(e.expectedSequence, 505);
  assert.equal(e.pending, null);
});

test('sequence: a step back still waiting for proof is visible as pending', () => {
  const e = engineAfter([0, 50], [50, 50], [10, 5]);
  assert.deepEqual(e.pending, { next: 15 });
  assert.deepEqual(counts(e), NONE, 'nothing is claimed until the next datagram says what it was');
  assert.equal(e.expectedSequence, 100, 'and the expectation has not moved');
});

test('sequence: two step backs in a row leave the first unresolved', () => {
  const e = engineAfter([0, 50], [50, 50], [10, 5], [20, 5], [100, 5]);
  assert.deepEqual(counts(e), { ...NONE, unresolved: 1, reordered: 1 });
  assert.equal(e.expectedSequence, 105);
  assert.equal(e.pending, null);
});

test('sequence: a step back that ends exactly at the expectation is a late arrival, not a restart', () => {
  // 95 + 5 = 100 = expected, so the successor of the step back is also the next
  // in-sequence datagram. Both readings adopt the same chain; the label is the late one.
  const e = engineAfter([0, 50], [50, 50], [95, 5], [100, 5]);
  assert.deepEqual(counts(e), { ...NONE, reordered: 1 });
  assert.equal(e.expectedSequence, 105);
});

test('sequence: a repeat of the previous datagram is a duplicate and moves nothing', () => {
  const e = engineAfter([0, 5], [5, 5], [5, 5], [10, 5]);
  assert.deepEqual(counts(e), { ...NONE, duplicates: 1 });
  assert.equal(e.expectedSequence, 15);
});

test('sequence: the 32-bit counter wraps without a gap', () => {
  const e = engineAfter([0xffff_fffe, 5], [3, 2]);
  assert.deepEqual(counts(e), NONE);
  assert.equal(e.expectedSequence, 5);
  // A datagram that itself straddles 2^32 and the ones after it.
  const across = engineAfter([0xffff_fff0, 0x20], [0x10, 5], [0x15, 2]);
  assert.deepEqual(counts(across), NONE);
  assert.equal(across.expectedSequence, 0x17);
});

test('sequence: empty exports advance nothing and are not duplicates of each other', () => {
  const e = engineAfter([0, 5], [5, 0], [5, 0], [5, 1]);
  assert.deepEqual(counts(e), NONE);
  assert.equal(e.expectedSequence, 6);
});

test('sequence is kept per engine', () => {
  const h = run([listening(), valid(1, 0, 0, 5), valid(2, 1, 900, 5), valid(3, 0, 5, 5), valid(4, 1, 905, 5)]);
  assert.ok(h.engines.every((e) => e.gaps === 0 && e.resets === 0 && e.reordered === 0));
});

// --- rejected senders -------------------------------------------------------------------------

test('unconfigured senders are counted per address, at most 16, then an overflow count', () => {
  let h = run([listening()]);
  for (let i = 1; i <= LIMITS.rejectedSenders; i++) h = run([rejected(`203.0.113.${i}`, i)], h);
  assert.equal(h.rejectedSenders.length, LIMITS.rejectedSenders);
  assert.equal(h.rejectedOverflow, 0);
  h = run([rejected('198.51.100.1', 50)], h);
  assert.equal(h.rejectedSenders.length, LIMITS.rejectedSenders, 'the 17th address gets no row');
  assert.equal(h.rejectedOverflow, 1);
  assert.ok(!h.rejectedSenders.some((r) => r.address === '198.51.100.1'));
  h = run([rejected('203.0.113.4', 51), rejected('203.0.113.4', 52), rejected('198.51.100.2', 53), rejected('198.51.100.1', 54)], h);
  assert.equal(h.rejectedSenders.find((r) => r.address === '203.0.113.4')?.count, 3, 'a listed address keeps counting');
  assert.equal(h.rejectedOverflow, 3, 'every datagram from a 17th-or-later address lands in the overflow count');
  assert.equal(h.rejectedSenders.length, LIMITS.rejectedSenders);
});

test('a rejected sender never makes the source fresh', () => {
  const h = run([listening(), rejected('203.0.113.1', 10)]);
  assert.equal(h.freshness, 'never');
});

// --- shedding, watermarks ------------------------------------------------------------------------

test('shedding is a local count that adds up', () => {
  const h = run([
    { kind: 'shed', count: 3, elapsedMs: 1, wallMs: WALL },
    { kind: 'shed', count: 4, elapsedMs: 2, wallMs: WALL },
  ]);
  assert.equal(h.shedDatagrams, 7);
  assert.equal(h.transportLoss, 'unknown', 'shedding is not kernel loss; that stays unknown');
});

test('watermarks only move forward', () => {
  let h = run([
    { kind: 'watermark', which: 'analyzed', throughEntryId: 50, elapsedMs: 1, wallMs: WALL },
    { kind: 'watermark', which: 'rolled-up', throughEntryId: 40, elapsedMs: 2, wallMs: WALL },
  ]);
  assert.equal(h.analyzedThroughEntryId, 50);
  assert.equal(h.rolledUpThroughEntryId, 40);
  h = run([
    { kind: 'watermark', which: 'analyzed', throughEntryId: 10, elapsedMs: 3, wallMs: WALL },
    { kind: 'watermark', which: 'rolled-up', throughEntryId: 45, elapsedMs: 4, wallMs: WALL },
  ], h);
  assert.equal(h.analyzedThroughEntryId, 50);
  assert.equal(h.rolledUpThroughEntryId, 45);
});

// --- the budget ------------------------------------------------------------------------------------

test('budget: the item count admits up to the limit and refuses past it', () => {
  const b = new ByteBudget(3, 1_000_000);
  assert.equal(b.admit(10), true);
  assert.equal(b.admit(10), true);
  assert.equal(b.admit(10), true);
  assert.equal(b.admit(10), false);
  b.release(10);
  assert.equal(b.admit(10), true);
  assert.equal(b.items, 3);
  assert.equal(b.bytes, 30);
});

test('budget: the byte total admits up to the limit and refuses past it', () => {
  const b = new ByteBudget(100, 1_000);
  assert.equal(b.admit(600), true);
  assert.equal(b.admit(400), true, 'exactly at the limit is within it');
  assert.equal(b.admit(1), false);
  b.release(400);
  assert.equal(b.admit(401), false);
  assert.equal(b.admit(400), true);
});

test('budget: an item larger than the byte limit goes alone, and only when empty', () => {
  const b = new ByteBudget(10, 1_000);
  assert.equal(b.admit(5), true);
  assert.equal(b.admit(2_000), false, 'not beside another item');
  b.release(5);
  assert.equal(b.admit(2_000), true, 'alone, on an empty budget');
  assert.equal(b.admit(1), false, 'and nothing joins it');
  b.release(2_000);
  assert.equal(b.items, 0);
  assert.equal(b.bytes, 0);
  assert.equal(b.admit(1), true);
});

test('budget: the live-credit batch limits admit a maximum-size datagram alone', () => {
  const b = new ByteBudget(LIMITS.liveBatchDatagrams, LIMITS.liveBatchBytes);
  assert.equal(b.admit(LIMITS.maxBodyBytes), true);
  const inbox = new ByteBudget(LIMITS.inboxDatagrams, LIMITS.inboxBytes);
  let admitted = 0;
  while (inbox.admit(LIMITS.maxBodyBytes)) admitted++;
  assert.equal(admitted, Math.floor(LIMITS.inboxBytes / LIMITS.maxBodyBytes), 'bytes run out before 1,024 datagrams do');
  const small = new ByteBudget(LIMITS.inboxDatagrams, LIMITS.inboxBytes);
  let n = 0;
  while (small.admit(100)) n++;
  assert.equal(n, LIMITS.inboxDatagrams, 'and the count binds first for small ones');
});

test('budget: an unadmitted item changes nothing, and a bad size is refused', () => {
  const b = new ByteBudget(2, 100);
  b.admit(60);
  assert.equal(b.admit(50), false);
  assert.equal(b.items, 1);
  assert.equal(b.bytes, 60);
  assert.equal(b.admit(-1), false);
  assert.equal(b.admit(1.5), false);
  assert.equal(b.admit(NaN), false);
  assert.equal(b.items, 1);
});

test('budget: releasing what was never admitted is a bug and throws', () => {
  const b = new ByteBudget(2, 100);
  assert.throws(() => b.release(1));
  b.admit(10);
  assert.throws(() => b.release(11));
  b.release(10);
  assert.equal(b.items, 0);
});

test('a valid datagram the Worker did not admit counts against the engine limit and gives no row, even with room in the list', () => {
  // The Worker's admission knows engines this health never saw (the sidecar's), so it can refuse a
  // datagram while the health's own list has room; the health must not then show a row for it.
  const refused = valid(10, 3, 0, 1, 1, undefined, false);
  const h = run([valid(0, 0, 0, 1), refused]);
  assert.equal(h.engines.length, 1);
  assert.equal(h.engineLimitRejected, 1);
  assert.equal(h.accepted, 1);
  assert.equal(h.lastValidElapsedMs, 0);
  const explicit = run([valid(0, 0, 0, 1, 1, undefined, true)]);
  assert.equal(explicit.accepted, 1);
});

test('a datagram fed after the clock moved on keeps its own age, so an old one is stale and not fresh', () => {
  // A rebuild reads entries that arrived during it, stamped with when they arrived, after ticks
  // have advanced the clock: the high-water mark must not make a 115 s old datagram look new.
  const h = run([valid(0, 0, 0, 1, 1), tick(130_000), valid(15_000, 0, 1, 1, 2)]);
  assert.equal(h.lastValidElapsedMs, 15_000);
  assert.equal(h.freshness, 'stale');
  const recent = run([tick(130_000), valid(100_000, 0, 0, 1, 1)]);
  assert.equal(recent.freshness, 'fresh');
  const older = run([valid(100_000, 0, 0, 1, 1), valid(20_000, 0, 1, 1, 2)]);
  assert.equal(older.lastValidElapsedMs, 100_000, 'an older stamp never moves the last valid time back');
});

// --- v9 and IPFIX sources (ADRs 0064, 0066) ------------------------------------------------

const V9 = `v9:${EXPORTER}/1`;
const IPFIX = `ipfix:${EXPORTER}/7`;
function templated(
  elapsedMs: number, key: string, flowCount: number, over: Partial<{ entryId: number; admitted: boolean; awaitingSets: number; awaitingBytes: number }> = {},
): HealthEvent {
  return {
    kind: 'datagram', outcome: 'valid-template', protocol: key.startsWith('v9:') ? 'v9' : 'ipfix', sourceKey: key, flowCount,
    entryId: over.entryId ?? 1, awaitingSets: over.awaitingSets ?? 0, awaitingBytes: over.awaitingBytes ?? 0,
    elapsedMs, wallMs: WALL + elapsedMs, ...(over.admitted === undefined ? {} : { admitted: over.admitted }),
  };
}

test('a v9 or IPFIX datagram makes the source fresh and gets a row of its own, with no engine and no v5 sequence', () => {
  const h = run([templated(0, V9, 3, { awaitingSets: 1, awaitingBytes: 40 }), templated(10, IPFIX, 2), templated(20, V9, 1)]);
  assert.equal(h.freshness, 'fresh');
  assert.equal(h.accepted, 3);
  assert.equal(h.engines.length, 0);
  assert.deepEqual(h.templateSources.map((r) => [r.sourceKey, r.protocol, r.accepted, r.flows, r.awaitingSets, r.awaitingBytes]), [
    [V9, 'v9', 2, 4, 1, 40], [IPFIX, 'ipfix', 1, 2, 0, 0],
  ]);
  assert.equal(h.lastValidElapsedMs, 20);
});

test('the template sources and the v5 engines share the sixteen rows an exporter gets', () => {
  const engines = Array.from({ length: LIMITS.enginesPerExporter - 1 }, (_, i) => valid(i, i, 0, 1));
  const h = run([...engines, templated(100, V9, 1), templated(101, IPFIX, 1), valid(102, 200, 0, 1)]);
  assert.equal(h.engines.length + h.templateSources.length, LIMITS.enginesPerExporter);
  assert.equal(h.engineLimitRejected, 2, 'the seventeenth identity of either kind');
  assert.equal(canAdmitEngine(h, 0, 200), false);
  const refused = run([templated(0, V9, 1, { admitted: false })]);
  assert.equal(refused.templateSources.length, 0);
  assert.equal(refused.engineLimitRejected, 1);
});

test('the exporter events land on their source\'s row; one for a source with no row changes nothing', () => {
  const t = { elapsedMs: 5, wallMs: WALL + 5 };
  const h = run([
    templated(0, V9, 1),
    { kind: 'source-restart', sourceKey: V9, entryId: 2, ...t },
    { kind: 'export-gap', sourceKey: V9, entryId: 3, missing: 7, ...t },
    { kind: 'export-gap', sourceKey: V9, entryId: 4, missing: 2, ...t },
    { kind: 'clock-skew', sourceKey: V9, entryId: 5, skewMs: 90_000, ...t },
    { kind: 'sampling-changed', sourceKey: V9, entryId: 6, status: { kind: 'known', interval: 100, sinceEntryId: 6 }, ...t },
    { kind: 'awaiting-template', sourceKey: V9, entryId: 7, templateId: 300, ...t },
    { kind: 'source-restart', sourceKey: IPFIX, entryId: 8, ...t },
  ]);
  assert.equal(h.templateSources.length, 1);
  const row = h.templateSources[0];
  assert.equal(row.restarts, 1);
  assert.equal(row.exportGaps, 2);
  assert.equal(row.missingSequence, 9);
  assert.equal(row.clockFlags, 1);
  assert.equal(row.lastFlaggedSkewMs, 90_000);
  assert.deepEqual(row.sampling, { kind: 'known', interval: 100, sinceEntryId: 6 });
  assert.equal(row.lastAwaitingTemplateId, 300);
});

console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
