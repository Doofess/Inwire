/**
 * The range the History asks for, as arithmetic a script can check.
 *
 * `queries.ts` answers a minute from the rollups only when it lies wholly
 * inside the range and wholly inside one bucket, and says so in its header: the
 * caller is expected to choose minute-aligned ranges and bucket widths. A range
 * ending at `Date.now()` with `span / n` buckets satisfies neither, so every
 * minute was read from the journal and a week of history was refused as too
 * large to read. So:
 *
 * - **both edges are on a minute.** The end is the close of the minute that
 *   `nowMs` is in, not the start of it: the current minute's records are
 *   received traffic, and the live edge must show them. The part of that minute
 *   still to come holds nothing.
 * - **from 1 h up, a bucket is a whole number of minutes**, so each bucket
 *   holds whole minutes and the rollups answer. The count is the largest number
 *   of buckets that divides the range into whole minutes and is no more than the
 *   chart can draw. 15 minutes is small enough to read raw, so it keeps the
 *   count the chart asked for and its sub-minute buckets.
 */
import type { QuerySpec } from './types';

const MINUTE_MS = 60_000;

/** Ranges shorter than this are read raw and keep the chart's own bucket count. */
const ROLLUP_FROM_MS = 3_600_000;

/** `[from, to)` on minute edges, `to` being the close of the minute `nowMs` is in. */
export function alignedRange(nowMs: number, presetMs: number): { fromMs: number; toMs: number } {
  const toMs = (Math.floor(nowMs / MINUTE_MS) + 1) * MINUTE_MS;
  return { fromMs: toMs - presetMs, toMs };
}

/**
 * How many buckets to ask for: `wanted` (what the chart has room to draw) for a
 * short range, otherwise the largest divisor of the range's minutes that fits
 * under it. A range of whole minutes always has the divisor 1.
 */
export function bucketsFor(presetMs: number, wanted: number): number {
  if (presetMs < ROLLUP_FROM_MS || presetMs % MINUTE_MS !== 0) return wanted;
  const minutes = presetMs / MINUTE_MS;
  for (let n = Math.min(wanted, minutes); n > 1; n--) if (minutes % n === 0) return n;
  return 1;
}

export function historySpec(sourceKey: string, presetMs: number, nowMs: number, wantedBuckets: number): QuerySpec {
  const { fromMs, toMs } = alignedRange(nowMs, presetMs);
  return { sourceKey, fromMs, toMs, bucketCount: bucketsFor(presetMs, wantedBuckets) };
}
