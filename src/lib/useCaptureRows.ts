/**
 * A `RowSource` over the whole capture: the RAM window, and the disk under it.
 *
 * ## The row space
 *
 * Rows are **positions in the capture**, oldest first, and the RAM window is
 * the suffix. Row `i` is `packets[i - below]` when `i >= below`, and a read
 * from the capture store otherwise, where `below` is how many frames precede
 * the window's first frame.
 *
 * Positions rather than ids, throughout. Ids have holes - a frame that fails
 * to dissect burns one - so `id - firstId` is not a position and never was;
 * `scripts/session/frame-index.ts` already documents that trap for the buffer
 * and it is the same trap here with more places to fall into.
 *
 * `below` is asked of the capture store rather than derived from
 * `droppedBuffer`, and the difference matters in the case that actually
 * happens: a restored session's window is the *tail* of a capture it never
 * dropped anything from, so its `droppedBuffer` is zero and there are still
 * millions of rows under it. The store knows where the window's first frame
 * sits because it wrote it. Until it answers, `below` is 0 and the list shows
 * the window alone - exactly what it did before any of this.
 *
 * ## The cache is a third pool, and it is small
 *
 * `bufferBudget.ts` names two pools that sit outside the 512 MB summary
 * budget - raw frame bytes and tracker state - and this is the third. A chunk
 * is 4,096 frames at ~663 B, so `ROW_CACHE_CHUNKS` of them is about **21 MB**.
 * It is capped by chunk count rather than by bytes because a chunk is a fixed
 * number of frames and the frames are already summaries; the thing that varies
 * wildly (raw bytes) is not in here.
 *
 * ## Why `rowAt` can answer `loading` and the list is fine with it
 *
 * `rowAt` runs inside render, forty times a frame, and cannot await. A miss
 * returns `loading` and schedules a fetch; the fetch fills the cache and bumps
 * a version, which re-renders, and the second render hits. The rows are on a
 * local disk behind one inflate, so that round trip is a frame or two - which
 * is why the placeholder is a dim bar rather than a spinner.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Packet } from '../types/packet';
import { captureStore } from '../services/capture/captureClient';
import { arrayRowSource, type Row, type RowSource } from './rowSource';

/**
 * Decoded chunks kept in memory. ~21 MB, outside the summary budget.
 *
 * Eight rather than four because the reader who scrolls back into the disk is
 * usually reading, not seeking: eight chunks is 32,768 rows around wherever
 * they stopped, so a scroll up and back down inflates nothing.
 */
export const ROW_CACHE_CHUNKS = 8;

/**
 * The most rows the list can address before the scroll canvas runs out.
 *
 * Chrome caps an element's height at about 33.5 million pixels, and the
 * virtualiser's spacers are `rows * rowHeight` tall - so at 21 px a row the
 * canvas can express **1,597,830 rows** and no more. Past that a spacer is
 * silently clamped by the browser and every row below the clamp becomes
 * unreachable: the list would look complete and simply stop scrolling.
 *
 * So the source refuses to claim more than this, and the list says what it is
 * not showing. Lifting it needs the scroll position to map *proportionally*
 * onto a frame number rather than one row to one row-height, which changes how
 * every scroll interaction works and is its own step.
 */
export const MAX_ADDRESSABLE_ROWS = 1_500_000;

interface CaptureRows {
  /** What the list renders from. */
  source: RowSource;
  /** Rows of the capture that sit below the RAM window. */
  below: number;
  /**
   * Rows the capture holds that the scroll canvas cannot address.
   *
   * Zero almost always. Non-zero is a fact the list has to state rather than
   * a limit it can quietly enforce.
   */
  unaddressable: number;
}

/**
 * The capture as rows, given the window currently in memory.
 *
 * `enabled` is false whenever the list is showing something other than the
 * capture in order - a display filter, a quick-find search, a sort by any
 * other column. Those all run over the window and only the window, and a
 * source claiming the whole capture underneath one of them would put
 * unfiltered rows in a filtered list. Whole-capture filtering is its own
 * mechanism and its own step.
 */
export function useCaptureRows(packets: readonly Packet[], enabled: boolean): CaptureRows {
  const [below, setBelow] = useState(0);
  /** Bumped when a fetch lands, to re-render the rows that were loading. */
  const [version, setVersion] = useState(0);
  const cache = useRef(new Map<number, Packet[]>()).current;
  /** Chunk starts already asked for, so a miss is not requested forty times. */
  const inFlight = useRef(new Set<number>()).current;

  const firstId = packets.length > 0 ? packets[0].id : -1;

  // Where the window sits in the capture. Re-asked when its first frame
  // changes, which is once per trim - about once a second at full rate, and
  // never on a buffer that is not full.
  useEffect(() => {
    if (!enabled || firstId < 0) { setBelow(0); return; }
    let cancelled = false;
    void captureStore.ordinalOf(firstId).then((ordinal) => {
      if (cancelled) return;
      // -1 is "not addressable yet" - the frame is still staged behind the
      // patch horizon, or in a hole. Zero rows below is the honest answer and
      // the one the list handled before this hook existed.
      setBelow(ordinal < 0 ? 0 : ordinal);
    });
    return () => { cancelled = true; };
  }, [enabled, firstId]);

  // A capture that was discarded, or a window that outran what is on disk.
  useEffect(() => {
    if (below === 0) { cache.clear(); inFlight.clear(); }
  }, [below, cache, inFlight]);

  const fetchAround = useCallback((from: number, to: number) => {
    if (from >= to) return;
    // One request for the range; the worker answers in whole chunks and may
    // answer with several. `inFlight` is keyed on the requested start rather
    // than on chunk starts, which the main thread does not know - it is a
    // duplicate-suppressor, not a ledger.
    if (inFlight.has(from)) return;
    inFlight.add(from);
    void captureStore.readRowsAt(from, to).then((blocks) => {
      inFlight.delete(from);
      if (blocks.length === 0) return;
      for (const block of blocks) {
        if (block.packets.length === 0) continue;
        cache.set(block.firstOrdinal, block.packets);
      }
      while (cache.size > ROW_CACHE_CHUNKS) {
        const oldest = cache.keys().next();
        if (oldest.done) break;
        cache.delete(oldest.value);
      }
      setVersion((n) => n + 1);
    });
  }, [cache, inFlight]);

  const windowSource = useMemo(() => arrayRowSource(packets), [packets]);

  return useMemo(() => {
    if (!enabled || below === 0) {
      return { source: windowSource, below: 0, unaddressable: 0 };
    }

    const total = below + packets.length;
    const count = Math.min(total, MAX_ADDRESSABLE_ROWS);
    // Trimmed from the FRONT when it does not fit: the newest rows are the
    // ones on screen and the ones a live capture is adding to, and a list that
    // silently stopped at row 1,500,000 while frames arrived at the far end
    // would be showing the wrong million and a half.
    const skipped = total - count;

    return {
      below,
      unaddressable: skipped,
      source: {
        count,
        rowAt(index: number): Row {
          const ordinal = index + skipped;
          if (ordinal < 0 || ordinal >= total) return { state: 'unavailable', ordinal };
          if (ordinal >= below) {
            const packet = packets[ordinal - below];
            return packet === undefined
              ? { state: 'unavailable', ordinal }
              : { state: 'ready', packet };
          }
          // `version` is read so this closure is rebuilt when a fetch lands;
          // without it React would hand the list the identical source object
          // and never re-render the rows that were loading.
          void version;
          for (const [start, rows] of cache) {
            if (ordinal >= start && ordinal < start + rows.length) {
              return { state: 'ready', packet: rows[ordinal - start] };
            }
          }
          return { state: 'loading', ordinal };
        },
        indexOfId(id: number): number {
          // The window first, because the selected frame is almost always in
          // it - it is what the reader has been looking at - and the window is
          // the half that can be scanned.
          const inWindow = packets.findIndex((p) => p.id === id);
          if (inWindow >= 0) return below + inWindow - skipped;
          for (const [start, rows] of cache) {
            const at = rows.findIndex((p) => p.id === id);
            if (at >= 0) return start + at - skipped;
          }
          return -1;
        },
        request(from: number, to: number): void {
          const start = Math.max(0, from + skipped);
          const end = Math.min(below, to + skipped);
          if (start >= end) return;
          // Only the part below the window: everything above it is already in
          // memory and asking for it would decode chunks to rebuild rows the
          // caller is holding.
          let missing = -1;
          for (let ordinal = start; ordinal < end; ordinal++) {
            let held = false;
            for (const [chunkStart, rows] of cache) {
              if (ordinal >= chunkStart && ordinal < chunkStart + rows.length) { held = true; break; }
            }
            if (!held) { missing = ordinal; break; }
          }
          if (missing < 0) return;
          fetchAround(missing, end);
        },
      },
    };
  }, [enabled, below, packets, windowSource, cache, fetchAround, version]);
}
