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
