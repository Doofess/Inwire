import type { Packet } from '../types/packet';
import { packetsExtend, prefixShift } from './packetPrefix';

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
 * **A trim is survived only by a fold that can take a packet back.** The
 * buffer's head moves whenever it passes its budget, and a fold with no `drop`
 * cannot un-see the frames that went, so it rebuilds - over a full window that
 * is a pass of a million rows, twice a second. With a `drop`, `prefixShift`
 * says how many frames `k` left the head; `drop` runs on exactly those, taken
 * from the old source, and `add` runs on what arrived after the old tail. A
 * `drop` that does nothing is a legitimate answer: it is how a fold says that
 * what a trimmed frame taught should outlive it (the name map). Changed deps,
 * a replaced buffer or a shift that cannot be proved still rebuild.
 *
 * `drop` receives the packet object the fold held when it was trimmed, which
 * after a patch is the patched copy and not the object `add` saw. A fold whose
 * `drop` reads anything a patch can change (Info, the protocol label, tree
 * links) would not undo what `add` did.
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
  drop?: (accumulator: A, packet: Packet) => void,
): AggregateCache<A> {
  const shift = cache === null || !depsEqual(cache.deps, deps)
    ? null
    : drop ? prefixShift(packets, cache.source) : packetsExtend(packets, cache.source) ? 0 : null;
  if (cache === null || shift === null) {
    const acc = create();
    for (let i = 0; i < packets.length; i++) add(acc, packets[i]);
    return { acc, source: packets, deps };
  }
  const acc = cache.acc;
  if (drop) for (let i = 0; i < shift; i++) drop(acc, cache.source[i]);
  for (let i = cache.source.length - shift; i < packets.length; i++) add(acc, packets[i]);
  return { acc, source: packets, deps };
}
