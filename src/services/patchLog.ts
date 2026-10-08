/**
 * Which frames the buffer has patched, in order, so a cache can refresh
 * exactly those instead of re-reading the buffer.
 *
 * A patch (`[TCP PDU reassembled in N]`, `(reply in N)`) replaces a packet
 * with a copy, because the buffer's consumers memoise on identity. The caches
 * that extend a result flush by flush (`incrementalFilter.ts`,
 * `incrementalAggregate.ts`) used to prove "this is the same buffer, grown" by
 * comparing the packet at the old buffer's last index by identity - so a patch
 * to that one packet, which in a bulk download lands on most flushes, made
 * them start again from nothing. `scripts/perf/ui-burst-drive.ts` measured it:
 * at a 1.9 GB buffer, 93% of the main thread in long tasks with a filter on.
 *
 * Now the prefix proof compares that position by frame id (`packetPrefix.ts`),
 * and a cache that holds packet objects asks this log which ids were replaced
 * since it was built. A patch to a packet deep in the buffer was invisible to
 * the identity check too, so this also ends the filtered list showing a
 * patched frame's stale copy.
 *
 * **Module state, written from inside a React updater, on purpose.**
 * `commitBatch` is the one place every patch is applied, and it runs twice
 * under StrictMode with the same input. Noting an id twice is harmless - a
 * refresh is idempotent - so the log needs no guard. It is bounded: a cache
 * older than the ring is told so (`null`) and does the full pass it would
 * have done anyway.
 */

/** How many patched ids are remembered. A frame patched more than this many patches ago is not. */
const CAPACITY = 1 << 18;

const ring = new Uint32Array(CAPACITY);
/** Ids noted so far, ever: the next one goes at `written % CAPACITY`. */
let written = 0;

export interface PatchSource {
  /** Where the log is now; a cache keeps this to ask `since` later. */
  position(): number;
  /** Every id noted after `position`, oldest first - or null when the log has moved past it. */
  since(position: number): readonly number[] | null;
}

/** Notes frames whose packet was just replaced by a patched copy. */
export function notePatched(ids: Iterable<number>): void {
  for (const id of ids) {
    ring[written % CAPACITY] = id;
    written++;
  }
}

export const PATCH_LOG: PatchSource = {
  position: () => written,
  since(position) {
    if (position > written || written - position > CAPACITY) return null;
    const out: number[] = [];
    for (let i = position; i < written; i++) out.push(ring[i % CAPACITY]);
    return out;
  },
};

/** A log a test owns, so a script can drive a cache without the module's state. */
export function patchLog(): PatchSource & { note(ids: Iterable<number>): void } {
  const ids: number[] = [];
  return {
    position: () => ids.length,
    since: (position) => (position > ids.length ? null : ids.slice(position)),
    note: (more) => { for (const id of more) ids.push(id); },
  };
}
