/**
 * Which segments expire (ADR 0062): `planExpiry` and `validateRetentionPolicy`.
 *
 *   npx tsx scripts/monitoring/retention.ts
 *
 * Plain tsx. `planExpiry` is a pure function of a list of `SegmentInfo`, so
 * every case builds that list by hand; nothing here opens a journal. What
 * expiring does to files and queries is `archive.ts` and `queries.ts`.
 */
import assert from 'node:assert/strict';
import { planExpiry, validateRetentionPolicy, type RetentionPolicy } from '../../src/services/monitoring/retention';
import { segmentBytesFor, type SegmentInfo } from '../../src/services/monitoring/segments';

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

const MiB = 1024 * 1024;
const DAY = 86_400_000;
const NOW = 1_800_000_000_000;
const LIMIT = 32 * MiB; // segments of 1 MiB, so "two free segments" is 2 MiB
const SEG = segmentBytesFor(LIMIT);

/** A segment of `n`: ids `n*100+1 ..= n*100+100`, last receipt `lastMs`. */
function seg(n: number, lastMs: number, over: Partial<SegmentInfo> = {}): SegmentInfo {
  return {
    name: `journal-${String(n * 100 + 1).padStart(12, '0')}.iwmj`,
    firstEntryId: n * 100 + 1, lastEntryId: n * 100 + 100, lastReceivedMs: lastMs,
    policyVersion: 1, sealed: true, bytes: SEG, ...over,
  };
}
const open = (n: number, lastMs: number): SegmentInfo => seg(n, lastMs, { sealed: false });
const names = (p: { segments: string[] } | null): string[] => (p === null ? [] : p.segments);
const age = (days: number): RetentionPolicy => ({ keepRawDays: days, atLimit: 'stop' });
const limit: RetentionPolicy = { keepRawDays: null, atLimit: 'expire-oldest' };
const OFF: RetentionPolicy = { keepRawDays: null, atLimit: 'stop' };

test('the default policy never expires anything, however old or full', () => {
  const segs = [seg(0, 1), seg(1, 2), open(2, 3)];
  assert.equal(planExpiry(segs, OFF, NOW, LIMIT, LIMIT), null);
});

test('no segments: nothing, under every policy and with a date', () => {
  for (const p of [OFF, age(1), limit, { keepRawDays: 1, atLimit: 'expire-oldest' } as RetentionPolicy]) {
    assert.equal(planExpiry([], p, NOW, 0, LIMIT), null);
    assert.equal(planExpiry([], p, NOW, 0, LIMIT, NOW), null);
  }
});

test('the open segment is never named, however old', () => {
  assert.equal(planExpiry([open(0, 1)], age(1), NOW, 0, LIMIT), null);
  assert.equal(planExpiry([open(0, 1)], limit, NOW, LIMIT, LIMIT), null);
  assert.equal(planExpiry([open(0, 1)], OFF, NOW, 0, LIMIT, NOW), null);
  const segs = [seg(0, 1), open(1, 2)];
  assert.deepEqual(names(planExpiry(segs, age(1), NOW, 0, LIMIT)), [segs[0].name]);
});

test('age: a prefix of segments whose last entry is older than the keep time', () => {
  const segs = [seg(0, NOW - 10 * DAY), seg(1, NOW - 8 * DAY), seg(2, NOW - 2 * DAY), open(3, NOW)];
  const plan = planExpiry(segs, age(7), NOW, 4 * SEG, LIMIT);
  assert.deepEqual(names(plan), [segs[0].name, segs[1].name]);
  assert.equal(plan!.reason, 'age');
  assert.equal(plan!.throughEntryId, segs[1].lastEntryId);
  assert.equal(plan!.throughMs, segs[1].lastReceivedMs);
});

test('age: the cutoff is strict, and a younger segment stops the prefix', () => {
  const edge = seg(0, NOW - 7 * DAY);
  assert.equal(planExpiry([edge, open(1, NOW)], age(7), NOW, 0, LIMIT), null, 'exactly N days old is kept');
  assert.deepEqual(names(planExpiry([seg(0, NOW - 7 * DAY - 1), open(1, NOW)], age(7), NOW, 0, LIMIT)), [seg(0, 0).name]);
  // The second is old but sits behind a young one (a clock that stepped): still a prefix, never a hole.
  const segs = [seg(0, NOW - 9 * DAY), seg(1, NOW - DAY), seg(2, NOW - 9 * DAY), open(3, NOW)];
  assert.deepEqual(names(planExpiry(segs, age(7), NOW, 0, LIMIT)), [segs[0].name]);
  // Nothing old enough at the head, however old the tail is.
  assert.equal(planExpiry([seg(0, NOW - DAY), seg(1, NOW - 9 * DAY), open(2, NOW)], age(7), NOW, 0, LIMIT), null);
});

test('limit: oldest first, until two segments are free', () => {
  const segs = [seg(0, 1), seg(1, 2), seg(2, 3), seg(3, 4), open(4, 5)];
  // 1.5 segments free: one more freed segment makes two.
  const used = LIMIT - SEG - SEG / 2;
  const plan = planExpiry(segs, limit, NOW, used, LIMIT);
  assert.deepEqual(names(plan), [segs[0].name]);
  assert.equal(plan!.reason, 'limit');
  assert.equal(plan!.throughEntryId, segs[0].lastEntryId);
  // Nothing free: two segments.
  assert.deepEqual(names(planExpiry(segs, limit, NOW, LIMIT, LIMIT)), [segs[0].name, segs[1].name]);
  // Two free already: nothing to do.
  assert.equal(planExpiry(segs, limit, NOW, LIMIT - 2 * SEG, LIMIT), null);
  assert.equal(planExpiry(segs, limit, NOW, 0, LIMIT), null);
  // Just under two: one segment.
  assert.deepEqual(names(planExpiry(segs, limit, NOW, LIMIT - 2 * SEG + 1, LIMIT)), [segs[0].name]);
});

test('limit: sums the segments\' own bytes, not a nominal size', () => {
  const segs = [seg(0, 1, { bytes: 100 }), seg(1, 2, { bytes: 600 * 1024 }), seg(2, 3, { bytes: SEG }), open(3, 4)];
  const plan = planExpiry(segs, limit, NOW, LIMIT, LIMIT);
  // 0 free: 100 B is not enough, 100 B + 600 KiB is not 2 MiB, adding the 1 MiB one is still short; the open one never counts.
  assert.equal(plan, null, 'sealed bytes total 1.6 MiB: unreachable');
  const more = [...segs.slice(0, 3), seg(3, 4, { bytes: SEG }), open(4, 5)];
  assert.deepEqual(names(planExpiry(more, limit, NOW, LIMIT, LIMIT)), more.slice(0, 4).map((s) => s.name));
});

test('limit: stop never expires, and an unreachable limit expires nothing', () => {
  const segs = [seg(0, 1), seg(1, 2), open(2, 3)];
  assert.equal(planExpiry(segs, { keepRawDays: null, atLimit: 'stop' }, NOW, LIMIT, LIMIT), null);
  // Only one sealed segment of 1 MiB: expiring it cannot make two free.
  assert.equal(planExpiry([seg(0, 1), open(1, 2)], limit, NOW, LIMIT, LIMIT), null);
  // The limit is unreachable but the age part is not: the age plan stands, as age.
  const aged = [seg(0, NOW - 9 * DAY), open(1, NOW)];
  const plan = planExpiry(aged, { keepRawDays: 7, atLimit: 'expire-oldest' }, NOW, LIMIT, LIMIT);
  assert.deepEqual(names(plan), [aged[0].name]);
  assert.equal(plan!.reason, 'age');
});

test('age and limit together: the limit extends the age prefix, and the reason says which decided', () => {
  const policy: RetentionPolicy = { keepRawDays: 7, atLimit: 'expire-oldest' };
  const segs = [seg(0, NOW - 9 * DAY), seg(1, NOW - DAY), seg(2, NOW - DAY), seg(3, NOW - DAY), open(4, NOW)];
  // Age takes one; no free room, so the limit takes a second.
  const both = planExpiry(segs, policy, NOW, LIMIT, LIMIT);
  assert.deepEqual(names(both), [segs[0].name, segs[1].name]);
  assert.equal(both!.reason, 'limit');
  assert.equal(both!.throughEntryId, segs[1].lastEntryId);
  // Age alone frees two segments' worth: the limit adds nothing, the reason is age.
  const roomy = [seg(0, NOW - 9 * DAY), seg(1, NOW - 9 * DAY), seg(2, NOW - DAY), open(3, NOW)];
  const age2 = planExpiry(roomy, policy, NOW, LIMIT, LIMIT);
  assert.deepEqual(names(age2), [roomy[0].name, roomy[1].name]);
  assert.equal(age2!.reason, 'age');
  // Plenty of room: age only.
  const room = planExpiry(segs, policy, NOW, 0, LIMIT);
  assert.deepEqual(names(room), [segs[0].name]);
  assert.equal(room!.reason, 'age');
});

test('user-before: sealed segments wholly before the date; the segment holding it stays', () => {
  const segs = [seg(0, 100), seg(1, 200), seg(2, 300), open(3, 400)];
  const plan = planExpiry(segs, OFF, NOW, 0, LIMIT, 250);
  assert.deepEqual(names(plan), [segs[0].name, segs[1].name], 'runs with retention off');
  assert.equal(plan!.reason, 'user-before');
  assert.equal(plan!.throughMs, 200, 'reports where the cut actually falls, not the date asked for');
  assert.equal(plan!.throughEntryId, segs[1].lastEntryId);
  assert.deepEqual(names(planExpiry(segs, OFF, NOW, 0, LIMIT, 200)), [segs[0].name], 'strict: a segment ending at the date holds it');
  assert.equal(planExpiry(segs, OFF, NOW, 0, LIMIT, 100), null);
  assert.equal(planExpiry(segs, OFF, NOW, 0, LIMIT, 50), null);
  // The open segment is not named, however early the date is past it.
  assert.deepEqual(names(planExpiry(segs, OFF, NOW, 0, LIMIT, 10_000)), [segs[0].name, segs[1].name, segs[2].name]);
});

test('user-before ignores the policy: no age, no limit extension', () => {
  const segs = [seg(0, NOW - 30 * DAY), seg(1, NOW - 20 * DAY), seg(2, NOW - 10 * DAY), open(3, NOW)];
  const plan = planExpiry(segs, { keepRawDays: 1, atLimit: 'expire-oldest' }, NOW, LIMIT, LIMIT, NOW - 25 * DAY);
  assert.deepEqual(names(plan), [segs[0].name]);
  assert.equal(plan!.reason, 'user-before');
});

test('validateRetentionPolicy: off, N days from 1 to 36,500, stop or expire-oldest', () => {
  assert.deepEqual(validateRetentionPolicy({ keepRawDays: null, atLimit: 'stop' }), { keepRawDays: null, atLimit: 'stop' });
  assert.deepEqual(validateRetentionPolicy({ keepRawDays: 1, atLimit: 'expire-oldest' }), { keepRawDays: 1, atLimit: 'expire-oldest' });
  assert.deepEqual(validateRetentionPolicy({ keepRawDays: 36_500, atLimit: 'stop' }), { keepRawDays: 36_500, atLimit: 'stop' });
  const bad: unknown[] = [
    null, undefined, 7, 'x', [], {}, { atLimit: 'stop' }, { keepRawDays: 7 }, { keepRawDays: undefined, atLimit: 'stop' },
    { keepRawDays: 0, atLimit: 'stop' }, { keepRawDays: -1, atLimit: 'stop' }, { keepRawDays: 36_501, atLimit: 'stop' },
    { keepRawDays: 1.5, atLimit: 'stop' }, { keepRawDays: NaN, atLimit: 'stop' }, { keepRawDays: Infinity, atLimit: 'stop' },
    { keepRawDays: '7', atLimit: 'stop' }, { keepRawDays: 7n, atLimit: 'stop' }, { keepRawDays: 7, atLimit: 'drop' },
    { keepRawDays: 7, atLimit: null }, { keepRawDays: 7, atLimit: 'Stop' },
  ];
  for (const b of bad) assert.equal(validateRetentionPolicy(b), null, JSON.stringify(b, (_, v) => (typeof v === 'bigint' ? `${v}n` : v)));
});

if (failures > 0) {
  console.log(`\n${failures} of ${failures + passes} FAILED`);
  process.exit(1);
}
console.log(`\nall passed (${passes})`);
