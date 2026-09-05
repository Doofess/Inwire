import { Packet } from '../types/packet';
import { FilterEngine } from './filterEngine';
import { packetsExtend } from './packetPrefix';

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
 * True when `cache` was built from a prefix of `packets` under the same
 * filter, so only the tail past it needs deciding. The prefix test itself is
 * shared - see `packetsExtend` for why two identity checks are enough.
 */
function prefixIntact(packets: Packet[], filter: string, cache: FilterCache | null): cache is FilterCache {
  return cache !== null && cache.filter === filter && packetsExtend(packets, cache.source);
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

  let result: Packet[];
  if (prefixIntact(packets, trimmed, cache)) {
    result =
      packets.length === cache.source.length
        ? cache.result
        : cache.result.concat(FilterEngine.filterPackets(packets.slice(cache.source.length), trimmed));
  } else {
    result = FilterEngine.filterPackets(packets, trimmed);
  }

  return { result, cache: { filter: trimmed, source: packets, result } };
}
