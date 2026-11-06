import type { Packet } from '../types/packet';

/**
 * Rows a finished import hands the list per task.
 *
 * A whole import in one `setPackets` made every incremental aggregate (the name
 * map, the expert log, the colour index) fold the whole buffer in one render:
 * 700-760 ms at 2.26M rows, profiled, `learnFromPacket` alone ~500 ms. Grown at
 * the tail, the buffer is a plain extension to `prefixShift`, so each render
 * folds only the slice it added. Restore does the same, by chunk.
 *
 * 150,000 because a 250,000-row slice's task measured 148-193 ms with the
 * minimap held (`PacketListMinimap`'s `hold`), too near the gate's 200; the
 * fold is proportional to the slice, so this is ~110 ms.
 */
export const ADOPT_SLICE_ROWS = 150_000;

/** Where each slice ends: `sliceRows` apart, the last at `total`; `[0]` for none. */
export function adoptSliceEnds(total: number, sliceRows: number = ADOPT_SLICE_ROWS): number[] {
  const ends: number[] = [];
  for (let end = Math.min(sliceRows, total); ; end = Math.min(end + sliceRows, total)) {
    ends.push(end);
    if (end >= total) return ends;
  }
}

/**
 * Shows `rows` a growing prefix at a time: the first at once (it is the
 * adoption itself, in the caller's task), then one per `nextTask`. The last is
 * `rows` itself. `show` answering false stops it (the buffer was replaced
 * meanwhile); the answer is whether every slice was shown.
 */
export async function adoptInSlices(
  rows: Packet[],
  sliceRows: number,
  show: (prefix: Packet[], first: boolean) => boolean,
  nextTask: () => Promise<void>,
): Promise<boolean> {
  const ends = adoptSliceEnds(rows.length, sliceRows);
  for (let i = 0; i < ends.length; i++) {
    if (i > 0) await nextTask();
    const prefix = ends[i] >= rows.length ? rows : rows.slice(0, ends[i]);
    if (!show(prefix, i === 0)) return false;
  }
  return true;
}
