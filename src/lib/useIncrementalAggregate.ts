import { useRef } from 'react';
import type { Packet } from '../types/packet';
import {
  depsEqual,
  foldIncrementally,
  type AggregateCache,
} from '../services/incrementalAggregate';

/**
 * `useMemo` over a packet buffer, for summaries that can be built one packet at
 * a time.
 *
 * `useMemo(() => walkEveryPacket(packets), [packets])` looks like it caches,
 * and it does - it just never gets to use the cache, because a live capture
 * hands it a new array on every tick. The work it skips is the work nobody was
 * going to do twice anyway. What it cannot skip is the 43,000 packets it has
 * already counted, and that is the whole cost. See `incrementalAggregate` for
 * the measurements.
 *
 * Three callbacks instead of one body:
 *
 *   `create`    a fresh, empty accumulator
 *   `add`       fold ONE packet into it, in place
 *   `finalize`  turn the accumulator into what the component renders
 *
 * `add` runs once per packet ever seen. `finalize` runs once per tick, so it
 * may sort and allocate freely as long as it is O(distinct keys) rather than
 * O(packets) - that is the line this hook exists to keep the widget on.
 *
 * **`deps` covers everything the callbacks read that is not a packet.** A value
 * `add` closes over is baked into work already folded in, so changing one can
 * only be answered by folding again from zero, which is what listing it here
 * does. A value only `finalize` reads still belongs here, because the result is
 * cached per tick and would otherwise be handed back stale. The rule is the
 * familiar one: if the callbacks read it and it can change, list it.
 *
 * The returned value keeps its identity while the packets and deps keep theirs,
 * so it is safe to put in a `useMemo` dependency list or an effect's.
 */
export function useIncrementalAggregate<A, R>(
  packets: Packet[],
  create: () => A,
  add: (accumulator: A, packet: Packet) => void,
  finalize: (accumulator: A) => R,
  deps: readonly unknown[] = [],
): R {
  // Written during render rather than in an effect, because the component is
  // rendering the result NOW - an effect would paint one frame of nothing and
  // then correct it, ten times a second. The same trade, for the same reason,
  // is documented on `filterIncrementally`. It is sound here because the only
  // state carried across renders is a fold whose input is append-only: a render
  // React discards leaves the cache holding a prefix of what the next render
  // passes, which is exactly the case the fold is built to extend. A repeat
  // render with the identical array returns the identical result without
  // touching the accumulator at all.
  const ref = useRef<{ cache: AggregateCache<A>; result: R } | null>(null);
  const previous = ref.current;

  if (previous && previous.cache.source === packets && depsEqual(previous.cache.deps, deps)) {
    return previous.result;
  }

  const cache = foldIncrementally(packets, create, add, deps, previous?.cache ?? null);
  const result = finalize(cache.acc);
  ref.current = { cache, result };
  return result;
}
