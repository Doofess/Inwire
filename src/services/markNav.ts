/**
 * What the app does with the marks beyond holding them (ADR 0067): where
 * "next marked" lands, whether a filter depends on them, and the tree's
 * `frame.marked` row. Pure, so a script can reach what `App.tsx` cannot.
 */
import type { Packet, ProtocolField } from '../types/packet';
import { nextMarked, type Marks } from './marks';

/** The index of frame `id` in an id-ordered list, or -1. */
function indexOfId(list: readonly Packet[], id: number): number {
  let lo = 0;
  let hi = list.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = list[mid].id;
    if (at === id) return mid;
    if (at < id) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * The marked frame Next / Previous should select, or null when there is none.
 *
 * A mark is eligible only if the list could show it: at or above the ring's
 * floor (a frame the ring expired is gone, whatever the marks file still says)
 * and present in `shown`, the buffer after the display filter. `shown` is the
 * buffer itself when no filter is applied, so one rule covers both. A mark on a
 * frame that is only on disk is skipped too, because selection is by buffered
 * packet; the list's own scrolling reaches those.
 */
export function markTarget(
  marks: Marks,
  from: number | null,
  dir: 1 | -1,
  shown: readonly Packet[],
  floorId: number,
): number | null {
  if (marks.size === 0) return null;
  const sorted = [...marks].sort((a, b) => a - b);
  return nextMarked(sorted, from, dir, (id) => id >= floorId && indexOfId(shown, id) !== -1);
}

/**
 * Whether a display filter reads the marks. Only then does a change of the set
 * change what the filter shows, so only then is the cache dropped and the disk
 * scan run again; marking a frame under `tcp` costs the list nothing.
 */
export function filterNamesMarked(expression: string): boolean {
  return /\bframe\.marked\b/.test(expression);
}

/**
 * The packet with its tree's `frame.marked` row reading True.
 *
 * The dissector writes `False` for every frame because it cannot know: a mark
 * is made after the frame was stored (`pcapParser.ts`). The renderer knows, so
 * it patches the one row on the way to the panes. The same packet is returned
 * when the frame is not marked or has no such row, so a memo on it holds.
 */
export function withMarkedRow(packet: Packet | null, marked: boolean): Packet | null {
  if (packet === null || !marked) return packet;
  let changed = false;
  const patch = (fields: ProtocolField[]): ProtocolField[] => fields.map((field) => {
    const children = field.children ? patch(field.children) : undefined;
    if (field.abbrev === 'frame.marked' && field.value !== 'True') {
      changed = true;
      return { ...field, value: 'True', ...(children ? { children } : {}) };
    }
    return children && children !== field.children ? { ...field, children } : field;
  });
  const layers = (packet.layers ?? []).map((layer) => {
    const fields = patch(layer.fields);
    return fields.some((f, i) => f !== layer.fields[i]) ? { ...layer, fields } : layer;
  });
  return changed ? { ...packet, layers } : packet;
}
