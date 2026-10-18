/**
 * The History's range arithmetic (`historyRange.ts`), for the final review's CR3.
 *
 * `queries.ts` answers a minute from the rollups only when it lies wholly inside
 * the range and wholly inside one bucket. The range the History used to ask for
 * ended at `Date.now()` with `span / n` buckets, which satisfies neither, so every
 * minute was read from the journal. These hold the arithmetic that fixes it: the
 * edges are minutes, the current minute is inside the range, and from an hour up a
 * bucket is a whole number of minutes - checked against `bucketBounds`, the
 * function the query itself cuts buckets with, rather than against the formula
 * that produced the count.
 */
import assert from 'node:assert/strict';
import { alignedRange, bucketsFor, historySpec } from '../../src/services/monitoring/historyRange';
import { bucketBounds, validateQuery } from '../../src/services/monitoring/queries';
import { LIMITS } from '../../src/services/monitoring/types';
import { test, runAll } from './queryRig';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const KEY = '192.0.2.1/0/0';
const PRESETS = { '15 min': 15 * MINUTE, '1 h': HOUR, '6 h': 6 * HOUR, '24 h': 24 * HOUR, '7 d': 7 * 24 * HOUR };
// A moment 37.5 seconds into a minute, so neither edge falls on it by luck.
const NOW = Date.UTC(2026, 9, 18, 14, 23, 37, 500);

test('range: both edges are on a minute, whatever the second it is asked at', () => {
  for (const [label, preset] of Object.entries(PRESETS)) {
    for (const off of [0, 1, 999, 30_000, 59_999]) {
      const { fromMs, toMs } = alignedRange(NOW - (NOW % MINUTE) + off, preset);
      assert.equal(fromMs % MINUTE, 0, `${label}: from at +${off}`);
      assert.equal(toMs % MINUTE, 0, `${label}: to at +${off}`);
      assert.equal(toMs - fromMs, preset, `${label}: the span is the preset's`);
    }
  }
});

test('range: the live edge includes the minute now is in', () => {
  const { toMs } = alignedRange(NOW, HOUR);
  assert.ok(toMs > NOW, 'the end is after now');
  assert.ok(toMs - NOW <= MINUTE, 'and no more than a minute after it');
  // A datagram received this very moment sits at NOW; the range must contain it.
  assert.ok(NOW >= alignedRange(NOW, HOUR).fromMs && NOW < toMs);
  // On the boundary itself the new minute is the one included.
  const edge = NOW - (NOW % MINUTE);
  assert.equal(alignedRange(edge, HOUR).toMs, edge + MINUTE);
});

test('range: from an hour up a bucket is a whole number of minutes, and the count stays a chart can draw', () => {
  for (const [label, preset] of Object.entries(PRESETS)) {
    if (preset < HOUR) continue;
    for (const wanted of [1, 2, 7, 24, 60, 100, 120, 150, 240, 333, LIMITS.buckets]) {
      const n = bucketsFor(preset, wanted);
      assert.ok(n >= 1 && n <= Math.min(wanted, preset / MINUTE), `${label}/${wanted}: ${n} buckets`);
      const spec = historySpec(KEY, preset, NOW, wanted);
      assert.equal(spec.bucketCount, n);
      const bounds = bucketBounds(spec.fromMs, spec.toMs, spec.bucketCount);
      for (const b of bounds) assert.equal(b % MINUTE, 0, `${label}/${wanted}: bound ${b} is on a minute`);
      assert.equal(bounds[0], spec.fromMs);
      assert.equal(bounds.at(-1), spec.toMs);
    }
  }
});

test('range: it asks for as many buckets as divide the range, not just any', () => {
  // 7 days is 10,080 minutes: 120 divides it, 121 does not, so 121 wanted gives the divisor below.
  assert.equal(bucketsFor(PRESETS['7 d'], 120), 120);
  assert.equal(10_080 % bucketsFor(PRESETS['7 d'], 121), 0);
  assert.ok(bucketsFor(PRESETS['7 d'], 121) <= 121);
  assert.equal(bucketsFor(HOUR, 60), 60);
  assert.equal(bucketsFor(HOUR, 61), 60, 'an hour cannot be more than 60 whole-minute buckets');
  assert.equal(bucketsFor(HOUR, 1000), 60);
  // A prime number of minutes can only be one bucket under its own size.
  assert.equal(bucketsFor(61 * MINUTE, 40), 1);
});

test('range: 15 minutes is read raw and keeps the chart\'s own bucket count', () => {
  for (const wanted of [1, 30, 90, 150]) assert.equal(bucketsFor(PRESETS['15 min'], wanted), wanted);
  const spec = historySpec(KEY, PRESETS['15 min'], NOW, 90);
  assert.equal(spec.bucketCount, 90);
  assert.equal(spec.fromMs % MINUTE, 0);
  assert.equal(spec.toMs % MINUTE, 0);
});

test('range: every preset at every width is a query the host accepts', () => {
  for (const [label, preset] of Object.entries(PRESETS)) {
    for (const wanted of [1, 12, 90, LIMITS.buckets]) {
      const spec = historySpec(KEY, preset, NOW, wanted);
      assert.equal(validateQuery(spec), null, `${label}/${wanted}: ${validateQuery(spec)}`);
    }
  }
});

test('range: a minute that is wholly in the range is wholly in one bucket (the rollups can answer it)', () => {
  const spec = historySpec(KEY, PRESETS['24 h'], NOW, 90);
  const bounds = bucketBounds(spec.fromMs, spec.toMs, spec.bucketCount);
  for (let minute = spec.fromMs; minute < spec.toMs; minute += MINUTE) {
    const inBucket = bounds.some((lo, i) => i < bounds.length - 1 && minute >= lo && minute + MINUTE <= bounds[i + 1]!);
    assert.ok(inBucket, `minute ${minute} straddles a bucket edge`);
  }
});

process.exit((await runAll()) === 0 ? 0 : 1);
