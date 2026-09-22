import { Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';
import { prefixShift } from './packetPrefix';

/**
 * Applying a display filter to a growing packet buffer without re-deciding
 * packets that were already decided.
 *
 * The live buffer is append-only between trims and a packet's match against a
 * fixed filter never changes, so re-filtering the unchanged prefix on every
 * 100ms flush is pure waste - and not cheap waste. Measured against a real
 * 25,704-packet capture, one full pass cost 6.5ms for `tcp` and 28.5ms for
 * `http || tls || tcp.port == 443 || tcp.port == 80`. At ten flushes a second
 * that is up to 285ms of every second, and it scales with the buffer: at the
 * 50,000-packet cap a capture running with a preset applied would spend over
 * half of every second re-answering questions it had already answered.
 *
 * The result is always exactly what filtering the whole buffer would produce.
 * Only the work differs.
 */

export interface FilterCache {
  filter: string;
  /** The exact array this result was computed from. Compared by identity. */
  source: Packet[];
  result: Packet[];
}

/**
 * How many packets the buffer dropped from its head since `cache` was built,
 * or `null` when the cache cannot be reused at all.
 *
 * `0` is the ordinary growth case. A positive number is a trim, and the answer
 * is still recoverable - see `prefixShift`, and `dropLeading` below for the
 * other half of it.
 */
function reusableShift(packets: Packet[], filter: string, cache: FilterCache | null): number | null {
  if (cache === null || cache.filter !== filter) return null;
  return prefixShift(packets, cache.source);
}

/**
 * The cached result with the matches that fell off the front removed.
 *
 * The dropped source packets are a prefix, the result preserves source order,
 * and the buffer is id-ordered - so the matches that went are exactly the ones
 * with an id below the new first frame's, and they are a prefix of `result`.
 * Binary search finds the boundary in O(log n) against the O(buffer) pass this
 * exists to avoid.
 *
 * **Then it checks the answer by identity**, which is what makes relying on id
 * ordering safe rather than assumed: the first surviving match must be the
 * very object sitting at its own arithmetic position in `packets`. If it is
 * not, this returns `null` and the caller does a full pass. The id order is
 * therefore an optimisation this verifies, never a premise it trusts.
 */
function dropLeading(result: Packet[], packets: Packet[]): Packet[] | null {
  const firstId = packets[0].id;
  let lo = 0;
  let hi = result.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (result[mid].id < firstId) lo = mid + 1;
    else hi = mid;
  }
  if (lo === 0) return result;
  const kept = result.slice(lo);
  if (kept.length > 0) {
    const at = kept[0].id - firstId;
    if (!(at >= 0 && at < packets.length && packets[at] === kept[0])) return null;
  }
  return kept;
}

/**
 * Filters `packets` by `filter`, reusing `cache` when it still applies.
 *
 * Returns the new cache alongside the result rather than mutating anything, so
 * the caller decides when to commit it. That matters in React: the caller holds
 * the cache in a ref and assigns it during render, which is only sound because
 * re-running this with the just-stored cache returns the identical `result`
 * array - see the idempotence check in scripts/filter/incremental.ts.
 */
export function filterIncrementally(
  packets: Packet[],
  filter: string,
  cache: FilterCache | null,
): { result: Packet[]; cache: FilterCache | null } {
  const trimmed = filter.trim();
  // An empty filter is the identity, and must hand back the very same array so
  // that consumers memoizing on its reference are not woken for nothing.
  if (!trimmed) return { result: packets, cache: null };

  const shift = reusableShift(packets, trimmed, cache);

  // A trim. Everything from `shift` on was already decided and is still in
  // order, so the answer is the old result minus what fell off the front, plus
  // whatever arrived on the end - rather than re-deciding the whole buffer.
  //
  // This is the path that used to be a freeze. `packetsExtend` refused the
  // moment the head moved, so every trim cost a full pass, in a render, at
  // whatever the buffer had grown to.
  if (shift !== null && shift > 0 && cache !== null) {
    const kept = dropLeading(cache.result, packets);
    if (kept !== null) {
      const decided = cache.source.length - shift;
      const result = packets.length === decided
        ? kept
        : kept.concat(FilterEngine.filterPackets(packets.slice(decided), trimmed));
      return { result, cache: { filter: trimmed, source: packets, result } };
    }
    // `dropLeading` could not confirm its own answer; fall through to the full
    // pass, which is what this call would have cost before any of this existed.
  }

  let result: Packet[];
  if (shift === 0 && cache !== null) {
    // The `concat` below copies every previously-matched packet on every
    // flush, which reads as the same O(n) waste this module exists to remove.
    // Measured, it is not: copying an array of references is memcpy, so at the
    // 50,000 cap it is **0.094 ms a flush, 0.94 ms a second** - against the
    // 28.5 ms *per flush* that re-filtering the whole buffer cost. Even a
    // 700,000-frame buffer is 11 ms a second.
    //
    // It also cannot be removed. Pushing into the retained array in place
    // would keep the same identity, and the identity is the contract: React
    // memoises on it, so a result that grew without changing identity would
    // simply not be re-read. Left alone deliberately.
    result =
      packets.length === cache.source.length
        ? cache.result
        : cache.result.concat(FilterEngine.filterPackets(packets.slice(cache.source.length), trimmed));
  } else {
    result = FilterEngine.filterPackets(packets, trimmed);
  }

  return { result, cache: { filter: trimmed, source: packets, result } };
}
