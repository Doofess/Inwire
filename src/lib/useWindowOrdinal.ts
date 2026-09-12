/**
 * Where the RAM window sits in the capture.
 *
 * One number, and everything about addressing the capture rather than the
 * buffer depends on it: it is how many rows precede the window, so it is the
 * list's row count, the offset every row index is shifted by, and the answer
 * to whether there is anything on disk worth filtering at all.
 *
 * ## Asked of the store, not derived
 *
 * The tempting derivation is `droppedBuffer` - the frames the buffer evicted -
 * and it is wrong in the case that actually happens. A restored session's
 * window is the **tail** of a capture it never dropped anything from, so its
 * `droppedBuffer` is zero and there are still millions of rows underneath. The
 * store knows where the window's first frame is because it wrote it.
 *
 * ## Positions, not ids
 *
 * Ids have holes - a frame that fails to dissect burns one - so `id - firstId`
 * is not a position and never was. `scripts/session/frame-index.ts` documents
 * that trap for the buffer; this is the same trap with more places to fall
 * into.
 *
 * Zero until the store answers, and zero for a frame it cannot place: still
 * staged behind the patch horizon, or in a hole. "The window is the whole
 * capture" is the honest reading of both, and it is what the list did before
 * any of this existed.
 *
 * Split out of `useCaptureRows` because a second caller appeared: a filter
 * scan over the disk is worth running only when there is disk below the
 * window, and asking the store twice for the same number would be two answers
 * that can disagree.
 */
import { useEffect, useState } from 'react';
import { captureStore } from '../services/capture/captureClient';
import type { Packet } from '../types/packet';

export function useWindowOrdinal(packets: readonly Packet[]): number {
  const [below, setBelow] = useState(0);
  const firstId = packets.length > 0 ? packets[0].id : -1;

  // Re-asked when the window's first frame changes, which is once per trim -
  // about once a second at full rate, and never on a buffer that is not full.
  useEffect(() => {
    if (firstId < 0) { setBelow(0); return; }
    let cancelled = false;
    void captureStore.ordinalOf(firstId).then((ordinal) => {
      if (cancelled) return;
      setBelow(ordinal < 0 ? 0 : ordinal);
    });
    return () => { cancelled = true; };
  }, [firstId]);

  return below;
}
