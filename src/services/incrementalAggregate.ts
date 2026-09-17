import type { Packet } from '../types/packet';
import { packetsExtend } from './packetPrefix';

/**
 * Folding a growing packet buffer into a summary without re-reading the part
 * that has not changed.
 *
 * Every analytics surface answers a question of the same shape - how many
 * packets per protocol, per conversation, per endpoint, per second - and every
 * one of them answered it by walking the entire buffer, from packet zero, on
 * every tick. Six such passes were running twice a second, back when all six
 * were dock widgets on screen at once.
 *
 * Measured then, on a live capture, production build, at 6x CPU throttle with
 * a 43,000-packet buffer and only ~19 packets a second actually arriving:
 *
 *   those surfaces mounted    24 fps, p90 97ms, 31 long tasks and 3.7s of long
 *                             task time in an 8s window
 *   those surfaces unmounted  92 fps, p90 21ms, ZERO long tasks
 *
 * The dock is gone and the surviving readers - the map, the throughput chart,
 * the size distribution - are unmounted unless their view is active, so no two
 * of them fold at once any more. The fold is still what makes each of them
 * affordable while it IS on screen.
 *
 * Half the main thread, for arithmetic over packets whose contribution had
 * already been counted the last time round. The packet rate barely matters:
 * the cost is buffer size times tick rate, so it grows for the whole length of
 * a capture and is at its worst exactly when someone has been watching longest.
 *
 * The fold below is what removes it. A tick now reads the packets that arrived
 * during that tick.
 *
 * **The accumulator is mutable and is mutated in place.** That is the point -
 * an immutable fold would allocate a new Map per packet - and it is why
 * `foldIncrementally` hands back a cache the caller commits rather than
 * mutating anything the caller can see. See `useIncrementalAggregate` for the
 * React half, which holds the cache in a ref and is only sound because
 * re-running a fold with the cache it just produced is the identity.
 */

export interface AggregateCache<A> {
  /** The accumulator every packet in `source` has been added to, exactly once. */
  acc: A;
  /** The exact array folded so far. Compared by identity, never by length. */
  source: Packet[];
  /**
   * The values `add` closes over, in the deps-array sense.
   *
   * Anything the fold reads that is NOT a packet belongs here, because a
   * changed value there invalidates work already folded in and can only be
   * answered by starting again. Compared element-wise with Object.is.
   */
  deps: readonly unknown[];
}

/** Element-wise `Object.is`, the same comparison React's dependency arrays use. */
export function depsEqual(a: readonly unknown[], b: readonly unknown[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!Object.is(a[i], b[i])) return false;
  return true;
}

/**
 * Adds every packet not already accounted for to `cache`, rebuilding from
 * scratch when it cannot prove that is the same thing.
 *
 * The returned cache is always safe to use as the next call's input. It is a
 * new object even when nothing was added, so the caller can compare by
 * identity without also having to know whether the fold did any work.
 */
export function foldIncrementally<A>(
  packets: Packet[],
  create: () => A,
  add: (accumulator: A, packet: Packet) => void,
  deps: readonly unknown[],
  cache: AggregateCache<A> | null,
): AggregateCache<A> {
  const reusable = cache !== null && depsEqual(cache.deps, deps) && packetsExtend(packets, cache.source);
  const acc = reusable ? cache.acc : create();
  for (let i = reusable ? cache.source.length : 0; i < packets.length; i++) add(acc, packets[i]);
  return { acc, source: packets, deps };
}
