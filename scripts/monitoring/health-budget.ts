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
  elapsedMs: number, engineId: number, sequence: number, flowCount: number, entryId = 1, wallMs = WALL + elapsedMs,
): HealthEvent {
  return { kind: 'datagram', outcome: 'valid', engineType: 0, engineId, sequence, flowCount, entryId, elapsedMs, wallMs };
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
  assert.equal(e.missingFlows, 0);
  assert.equal(e.gaps, 0);
  assert.equal(e.duplicates, 0);
  assert.equal(e.reordered, 0);
  assert.equal(e.resets, 0);
});

test('sequence: a forward jump counts the missing flows and one gap', () => {
  const e = engineAfter([0, 5], [20, 1]);
  assert.equal(e.missingFlows, 15);
  assert.equal(e.gaps, 1);
  assert.equal(e.expectedSequence, 21);
});

test('sequence: a repeat is a duplicate, and does not move the expectation', () => {
  const e = engineAfter([0, 5], [5, 5], [5, 5]);
  assert.equal(e.duplicates, 1);
  assert.equal(e.expectedSequence, 10);
  assert.equal(e.accepted, 3, 'every datagram stays counted: nothing is deleted');
});

test('sequence: a small step back is reordering, a large one a reset', () => {
  const reordered = engineAfter([0, 5], [10, 5], [5, 5]);
  assert.equal(reordered.reordered, 1);
  assert.equal(reordered.expectedSequence, 15, 'a late datagram does not pull the expectation back');
  const reset = engineAfter([1_000_000, 5], [3, 5]);
  assert.equal(reset.resets, 1);
  assert.equal(reset.expectedSequence, 8, 'a reset restarts from the new number');
});

test('sequence: the 32-bit counter wraps without a gap', () => {
  const e = engineAfter([0xffff_fffe, 5], [3, 2]);
  assert.equal(e.gaps, 0);
  assert.equal(e.resets, 0);
  assert.equal(e.expectedSequence, 5);
});

test('sequence: empty exports advance nothing and are not duplicates of each other', () => {
  const e = engineAfter([0, 5], [5, 0], [5, 0], [5, 1]);
  assert.equal(e.duplicates, 0);
  assert.equal(e.gaps, 0);
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

console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
