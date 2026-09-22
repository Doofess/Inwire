import type { Packet } from '../types/packet';

/**
 * True when `packets` provably still begins with `previous`, so only the tail
 * past it can contain anything new.
 *
 * Two identity checks establish that, given the buffer is only ever appended
 * to, trimmed from the front, or replaced wholesale:
 *
 *   - element 0 catches a trim or a clear, since both shift the head;
 *   - the element sitting at `previous`'s final index catches a wholesale
 *     replacement, which is what a pcap import does.
 *
 * Being wrong here must only ever cost time, so every caller falls back to a
 * full pass when this returns false. It is deliberately conservative: two
 * different arrays that happen to share those two elements would also have to
 * share every element between them, because the only way the buffer produces a
 * new array at all is by appending to or slicing the old one.
 *
 * An empty `previous` returns false. There is nothing to extend, and the
 * caller's "start from scratch" path is the same code either way.
 */
export function packetsExtend(packets: Packet[], previous: Packet[]): boolean {
  return (
    previous.length > 0 &&
    packets.length >= previous.length &&
    packets[0] === previous[0] &&
    packets[previous.length - 1] === previous[previous.length - 1]
  );
}

/**
 * How many packets `previous` lost from its HEAD, if `packets` is otherwise
 * still the same buffer grown - or `null` when it is not.
 *
 * `packetsExtend` answers the same question for the case where nothing was
 * dropped, and returns false the instant the head moves. That is correct and
 * it is expensive: `planBufferTrim` moves the head every time the buffer
 * passes its budget by `BUDGET_SLACK`, and *every* consumer keyed on
 * `packetsExtend` then rebuilds from scratch, synchronously, in one render.
 * With a display filter applied at a 700,000-frame buffer that is a full pass
 * measured in hundreds of milliseconds - a hard freeze rather than a slow
 * operation, on a schedule nobody asked for.
 *
 * A trim is a shift, and a shift is recoverable: everything from index `k` of
 * `previous` is still there, still decided, still in order.
 *
 * **Finding `k` is `indexOfFrame`'s arithmetic, for `indexOfFrame`'s reason.**
 * Frame ids are assigned by the Worker in arrival order and the buffer is
 * id-ordered, so the drop count is usually just the difference of the two
 * leading ids; the binary search is the fallback for a buffer whose ids are
 * not contiguous. That function is not imported because it lives in
 * `pcapParser.ts` and pulling the whole dissector into the filter path to
 * borrow ten lines is the worse trade - the duplication is deliberate and this
 * comment is the link.
 *
 * **Being wrong here may only ever cost time.** Every answer is confirmed by
 * two identity checks before it is returned - the same two `packetsExtend`
 * makes, shifted by `k` - so a wrong guess about ids returns `null` and the
 * caller does the full pass it would have done anyway. It can never return a
 * `k` that describes a relationship the arrays do not have.
 */
export function prefixShift(packets: Packet[], previous: Packet[]): number | null {
  if (previous.length === 0) return null;
  if (packets.length === 0) return null;

  // Nothing dropped: the common case, and the one `packetsExtend` covers.
  if (packetsExtend(packets, previous)) return 0;

  // Where `packets[0]` sits in `previous`. The guess first, as `indexOfFrame`
  // does, because on a contiguous buffer it is exact and costs one subtraction.
  const first = packets[0];
  let k = first.id - previous[0].id;
  if (!(k > 0 && k < previous.length && previous[k] === first)) {
    k = -1;
    let lo = 0;
    let hi = previous.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = previous[mid].id;
      if (at === first.id) { k = mid; break; }
      if (at < first.id) lo = mid + 1;
      else hi = mid - 1;
    }
    if (k <= 0 || previous[k] !== first) return null;
  }

  // The retained part of `previous` is `k..end`, which must still sit at the
  // front of `packets` - so `previous`'s last element is at `length - 1 - k`.
  // This is `packetsExtend`'s second check, shifted, and it is what catches a
  // wholesale replacement whose ids happen to line up.
  const retained = previous.length - k;
  if (packets.length < retained) return null;
  if (packets[retained - 1] !== previous[previous.length - 1]) return null;
  return k;
}
