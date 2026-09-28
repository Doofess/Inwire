/**
 * A `RowSource` over the whole capture: the RAM window, and the disk under it.
 *
 * ## The row space
 *
 * Rows are **positions in the capture**, oldest first, and the RAM window is
 * the suffix. Row `i` is `packets[i - below]` when `i >= below`, and a read
 * from the capture store otherwise, where `below` is how many frames precede
 * the window's first frame - `useWindowOrdinal.ts`.
 *
 * Positions rather than ids, throughout. Ids have holes, so `id - firstId` is
 * not a position and never was.
 *
 * ## Filtered, the row space is the matches
 *
 * With a filter applied the list's rows are the frames that matched, and they
 * come from two places that must not overlap:
 *
 * ```
 *   rows 0 .. matchesBelow      the scan's bitmap, read off disk
 *   rows matchesBelow ..        `filter.window`, filtered in memory
 * ```
 *
 * The split is at `below`, not at the scan's end, and that is what keeps the
 * two from double-counting: the frames in the RAM window are on disk **as
 * well**, so a scan covers them too. `rank(below)` is the number of matches
 * strictly before the window, which is exactly the ones the window cannot
 * supply. Everything from `below` up is answered by the in-memory filter,
 * which is the same filter and the more current of the two.
 *
 * `rank` and `ordinalAt` are why the bitmap is shipped here rather than kept
 * in the store: both are called from render, once per visible row, and neither
 * can be a message.
 *
 * ## The cache is a third pool, and it is small
 *
 * `bufferBudget.ts` names two pools outside the 512 MB summary budget - raw
 * frame bytes and tracker state - and this is the third. `ROW_CACHE_ROWS` at
 * ~663 B a row is about **21 MB**. Keyed by ordinal rather than by chunk
 * because a filtered read is scattered: fifty visible rows of `dns` can come
 * from fifty different chunks, and there is no block to key on.
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
import type { MatchSet } from '../services/capture/matchSet';
import { captureStore } from '../services/capture/captureClient';
import { arrayRowSource, type Row, type RowSource } from './rowSource';
import { addressRow, rowOfOrdinal, rowSpace } from './captureRowSpace';

export { MAX_ADDRESSABLE_ROWS, matchesBeforeWindow } from './captureRowSpace';

/**
 * Rows kept decoded in memory. ~21 MB, outside the summary budget.
 *
 * Eight chunks' worth, because the reader who scrolls back into the disk is
 * usually reading rather than seeking: 32,768 rows around wherever they
 * stopped means a scroll up and back down inflates nothing.
 */
export const ROW_CACHE_ROWS = 8 * 4096;

/** What the list needs to address a filtered capture. */
export interface CaptureFilterView {
  /** Which capture ordinals matched, over `[0, matches.frameCount)`. */
  matches: MatchSet;
  /** The filtered RAM window, in capture order. */
  window: readonly Packet[];
}

interface CaptureRows {
  /** What the list renders from. */
  source: RowSource;
  /**
   * Rows the list holds that come from disk, before the window's own.
   *
   * Unfiltered that is `below`. Filtered it is how many MATCHES precede the
   * window, which is the smaller number and the one anything drawing the
   * window's position in the list needs - the minimap draws the window and has
   * to know what it is offset by.
   */
  leadingRows: number;
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
 * @param packets  The **unfiltered** RAM window, in capture order. It is what
 *                 `below` was measured against, so a filtered array here would
 *                 shift every row by the number of frames the filter hid.
 * @param below    Rows of the capture beneath the window.
 * @param enabled  False whenever the list is showing something other than the
 *                 capture in order - a quick-find search, or a sort by any
 *                 other column. Those run over the window and only the window,
 *                 and a source claiming the whole capture underneath one would
 *                 put unsorted rows in a sorted list. A display filter is no
 *                 longer one of these; that is what `filter` is for.
 * @param filter   The scan's answer, or null to address the capture whole.
 * @param floor    The capture's first ordinal still held - above 0 once the
 *                 agent's ring has deleted files (ADR 0052). The list starts
 *                 there; see `captureRowSpace.ts`.
 */
export function useCaptureRows(
  packets: readonly Packet[],
  below: number,
  enabled: boolean,
  filter: CaptureFilterView | null = null,
  floor = 0,
): CaptureRows {
  /** Bumped when a fetch lands, to re-render the rows that were loading. */
  const [version, setVersion] = useState(0);
  /** Decoded rows by capture ordinal. Insertion-ordered, so eviction is FIFO. */
  const cache = useRef(new Map<number, Packet>()).current;
  /** Reads already asked for, so a miss is not requested forty times. */
  const inFlight = useRef(new Set<string>()).current;

  // A capture that was discarded, or a window that outran what is on disk.
  useEffect(() => {
    if (below === 0) { cache.clear(); inFlight.clear(); }
  }, [below, cache, inFlight]);

  const remember = useCallback((rows: Iterable<[number, Packet]>) => {
    let added = 0;
    for (const [ordinal, packet] of rows) { cache.set(ordinal, packet); added++; }
    if (added === 0) return;
    while (cache.size > ROW_CACHE_ROWS) {
      const oldest = cache.keys().next();
      if (oldest.done) break;
      cache.delete(oldest.value);
    }
    setVersion((n) => n + 1);
  }, [cache]);

  /** A run of the capture, answered in whole chunks. The unfiltered path. */
  const fetchRange = useCallback((from: number, to: number) => {
    if (from >= to) return;
    const key = `r${from}`;
    if (inFlight.has(key)) return;
    inFlight.add(key);
    void captureStore.readRowsAt(from, to).then((blocks) => {
      inFlight.delete(key);
      const rows: [number, Packet][] = [];
      for (const block of blocks) {
        for (let i = 0; i < block.packets.length; i++) {
          rows.push([block.firstOrdinal + i, block.packets[i]]);
        }
      }
      remember(rows);
    });
  }, [inFlight, remember]);

  /** Scattered positions, which is what a filtered list needs. */
  const fetchOrdinals = useCallback((ordinals: number[]) => {
    if (ordinals.length === 0) return;
    const key = `o${ordinals[0]}:${ordinals.length}`;
    if (inFlight.has(key)) return;
    inFlight.add(key);
    void captureStore.readRowsFor(ordinals).then((rows) => {
      inFlight.delete(key);
      // Positions the capture could not place stay missing, and the row keeps
      // saying `loading` - which is honest: a torn tail's rows are not coming.
      remember(rows);
    });
  }, [inFlight, remember]);

  const windowSource = useMemo(
    () => arrayRowSource(filter === null ? packets : filter.window),
    [packets, filter],
  );

  return useMemo(() => {
    const inWindow = filter === null ? packets : filter.window;
    // Nothing below the window, or the list is not addressing the capture:
    // the window IS the answer, and this is the path every capture that fits
    // in memory takes.
    if (!enabled || below <= floor) {
      return { source: windowSource, leadingRows: 0, unaddressable: 0 };
    }

    // Every number about the row space comes from one place, and that place
    // has no React in it - `captureRowSpace.ts`. What is left here is the
    // cache, the fetching and the three-state answer.
    const matches = filter === null ? null : filter.matches;
    const space = rowSpace(below, inWindow.length, matches, floor);

    return {
      leadingRows: space.fromDisk - space.skipped,
      unaddressable: space.skipped,
      source: {
        count: space.count,
        rowAt(index: number): Row {
          const at = addressRow(space, matches, index);
          if (at.where === 'none') return { state: 'unavailable', ordinal: -1 };
          if (at.where === 'window') {
            const packet = inWindow[at.at];
            return packet === undefined
              ? { state: 'unavailable', ordinal: -1 }
              : { state: 'ready', packet };
          }
          // `version` is read so this closure is rebuilt when a fetch lands;
          // without it React would hand the list the identical source object
          // and never re-render the rows that were loading.
          void version;
          const cached = cache.get(at.ordinal);
          return cached === undefined
            ? { state: 'loading', ordinal: at.ordinal }
            : { state: 'ready', packet: cached };
        },
        indexOfId(id: number): number {
          // The window first, because the selected frame is almost always in
          // it - it is what the reader has been looking at - and the window is
          // the half that can be scanned cheaply.
          const at = inWindow.findIndex((p) => p.id === id);
          if (at >= 0) return space.fromDisk + at - space.skipped;
          for (const [ordinal, packet] of cache) {
            if (packet.id === id) return rowOfOrdinal(space, matches, ordinal);
          }
          return -1;
        },
        request(from: number, to: number): void {
          // Only the disk half: everything above it is already in memory, and
          // asking for it would decode chunks to rebuild rows the caller is
          // holding.
          const start = Math.max(0, from + space.skipped);
          const end = Math.min(space.fromDisk, to + space.skipped);
          if (start >= end) return;

          if (matches === null) {
            // Rows to ordinals: the same run, `base` further on.
            let missing = -1;
            for (let row = start; row < end; row++) {
              if (!cache.has(space.base + row)) { missing = space.base + row; break; }
            }
            if (missing < 0) return;
            fetchRange(missing, space.base + end);
            return;
          }

          // Filtered: the positions themselves, and only the ones not held.
          // A range would be useless here - the rows between two matches of a
          // sparse filter are not rows this list has.
          const wanted: number[] = [];
          for (let row = start; row < end; row++) {
            const ordinal = matches.ordinalAt(space.base + row);
            if (ordinal >= 0 && !cache.has(ordinal)) wanted.push(ordinal);
          }
          fetchOrdinals(wanted);
        },
      },
    };
  }, [
    enabled, below, floor, packets, filter, windowSource,
    cache, fetchRange, fetchOrdinals, version,
  ]);
}
