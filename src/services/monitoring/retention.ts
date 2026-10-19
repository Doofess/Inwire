/**
 * Retention planning (ADR 0062): which whole segments leave the journal, and
 * why. Pure arithmetic over what the journal knows of its segments; it opens no
 * file and removes nothing. `archive.ts` runs the plan.
 *
 * The plan is always an oldest-first prefix of the sealed segments. The open
 * segment is never named, and the first segment that does not qualify ends the
 * prefix, so a plan can never leave a hole in the id sequence.
 */
import { segmentBytesFor, type SegmentInfo } from './segments';

const DAY_MS = 86_400_000;
const MAX_KEEP_DAYS = 36_500;

export interface RetentionPolicy {
  /** Raw evidence older than this many days expires; null keeps it until the limit says otherwise. */
  keepRawDays: number | null;
  /** At the storage limit: refuse new datagrams, or expire the oldest segments to make room. */
  atLimit: 'stop' | 'expire-oldest';
}

export const DEFAULT_RETENTION: RetentionPolicy = { keepRawDays: null, atLimit: 'stop' };

export interface ExpiryPlan {
  segments: string[];
  throughEntryId: number;
  throughMs: number;
  reason: 'age' | 'limit' | 'user-before';
}

/** A clean copy, or null for anything that is not a policy. Extra keys are dropped. */
export function validateRetentionPolicy(p: unknown): RetentionPolicy | null {
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return null;
  const o = p as Record<string, unknown>;
  const days = o.keepRawDays;
  if (days !== null) {
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 1 || days > MAX_KEEP_DAYS) return null;
  }
  if (o.atLimit !== 'stop' && o.atLimit !== 'expire-oldest') return null;
  return { keepRawDays: days as number | null, atLimit: o.atLimit };
}

function planOf(sealed: SegmentInfo[], count: number, reason: ExpiryPlan['reason']): ExpiryPlan | null {
  if (count <= 0) return null;
  const last = sealed[count - 1];
  return {
    segments: sealed.slice(0, count).map((s) => s.name),
    throughEntryId: last.lastEntryId,
    throughMs: last.lastReceivedMs,
    reason,
  };
}

/**
 * `beforeMs` is the user's "delete evidence before this date": it ignores the
 * policy, takes the sealed segments that end before the date, and keeps the one
 * that holds it. Otherwise the age rule runs first, then - only for
 * `expire-oldest` and only when less than two segments of room are free - the
 * limit extends the prefix oldest-first until two are.
 */
export function planExpiry(
  segments: SegmentInfo[],
  policy: RetentionPolicy,
  nowMs: number,
  usedBytes: number,
  limitBytes: number,
  beforeMs?: number,
): ExpiryPlan | null {
  const sealed: SegmentInfo[] = [];
  for (const s of segments) {
    if (!s.sealed) break;
    sealed.push(s);
  }
  if (sealed.length === 0) return null;

  if (beforeMs !== undefined) {
    let n = 0;
    while (n < sealed.length && sealed[n].lastReceivedMs < beforeMs) n++;
    return planOf(sealed, n, 'user-before');
  }

  let n = 0;
  if (policy.keepRawDays !== null) {
    const cutoff = nowMs - policy.keepRawDays * DAY_MS;
    while (n < sealed.length && sealed[n].lastReceivedMs < cutoff) n++;
  }
  let reason: ExpiryPlan['reason'] = 'age';

  if (policy.atLimit === 'expire-oldest') {
    const want = 2 * segmentBytesFor(limitBytes);
    const free = limitBytes - usedBytes;
    if (free < want) {
      let freed = 0;
      for (let i = 0; i < n; i++) freed += sealed[i].bytes;
      let m = n;
      while (free + freed < want && m < sealed.length) freed += sealed[m++].bytes;
      if (free + freed >= want && m > n) {
        n = m;
        reason = 'limit';
      }
    }
  }
  return planOf(sealed, n, reason);
}
