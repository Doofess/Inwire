/**
 * What row *i* of the packet list actually is.
 *
 * The list scrolls rows. A row is one of three things - a frame in the RAM
 * window, a position in the capture on disk, or nothing - and which one it is
 * comes out of four numbers and a bitmap. That arithmetic is the whole of the
 * disk-backed list, and getting it wrong does not fail: it shows the wrong
 * frame, confidently, at the right row height.
 *
 * So it lives here rather than inside `useCaptureRows`'s memo, and
 * `scripts/session/capture-row-space.ts` drives it under plain Node.
 *
 * ## Unfiltered
 *
 * ```
 *   rows 0 .. below          on disk, and row i IS capture ordinal i
 *   rows below .. total      the window, at packets[i - below]
 * ```
 *
 * ## Filtered
 *
 * ```
 *   rows 0 .. fromDisk       the scan's matches, row k at ordinalAt(k)
 *   rows fromDisk .. total   the filtered window, at window[i - fromDisk]
 * ```
 *
 * `fromDisk` is `rank(below)` - the matches strictly before the window - and
 * the boundary is at `below` rather than at the end of the scan **because the
 * window's frames are on disk as well**. A scan covers them; the window
 * filters them; counting both would list every frame in the window twice. The
 * window wins because it is the more current of the two answers.
 *
 * ## Two clamps, both load-bearing
 *
 * `rank` is clamped to what the scan covered. A capture that grew after the
 * scan started has ordinals the bitmap does not describe, and asking `rank`
 * about them counts them as **misses** rather than as unknown - a filter
 * quietly under-reporting on exactly the frames a live capture is producing.
 * What the scan did not reach is reported separately (`uncoveredRows`), not
 * folded into a number that looks whole.
 *
 * `count` is clamped to what the scroll canvas can express, and the trim comes
 * off the **front**: the newest rows are the ones on screen and the ones a
 * live capture is adding to. A list that silently stopped at row 1,500,000
 * while frames arrived at the far end would be showing the wrong million and
 * a half.
 */
import type { MatchSet } from '../services/capture/matchSet';

/**
 * The most rows the list can address before the scroll canvas runs out.
 *
 * Chrome caps an element's height at about 33.5 million pixels, and the
 * virtualiser's spacers are `rows * rowHeight` tall - so at 21 px a row the
 * canvas can express **1,597,830 rows** and no more. Past that a spacer is
 * silently clamped by the browser and every row below the clamp becomes
 * unreachable: the list would look complete and simply stop scrolling.
 *
 * Lifting it needs the scroll position to map *proportionally* onto a frame
 * number rather than one row to one row-height, which changes how every scroll
 * interaction works and is its own step.
 */
export const MAX_ADDRESSABLE_ROWS = 1_500_000;

export interface RowSpace {
  /** Rows the list may scroll through, after the canvas clamp. */
  count: number;
  /** Rows dropped off the front by that clamp. Zero almost always. */
  skipped: number;
  /** Rows answered from disk, before the window's. `below`, or its matches. */
  fromDisk: number;
  /** Rows before the clamp. `count + skipped`. */
  total: number;
}

/**
 * Matches that sit strictly before the RAM window - the disk half's row count.
 *
 * Exported because the filter bar needs the same number to say how many frames
 * the filter found, and two copies of this clamp would eventually disagree.
 */
export function matchesBeforeWindow(matches: MatchSet, below: number): number {
  return matches.rank(Math.min(below, matches.frameCount));
}

/**
 * @param below       Capture rows beneath the RAM window.
 * @param windowRows  Rows the window supplies - filtered, when filtering.
 * @param matches     The scan's bitmap, or null to address the capture whole.
 */
export function rowSpace(
  below: number, windowRows: number, matches: MatchSet | null,
): RowSpace {
  const fromDisk = matches === null ? below : matchesBeforeWindow(matches, below);
  const total = fromDisk + windowRows;
  const count = Math.min(total, MAX_ADDRESSABLE_ROWS);
  return { count, skipped: total - count, fromDisk, total };
}

export type RowAddress =
  /** `window[at]`. */
  | { where: 'window'; at: number }
  /** Capture ordinal `ordinal`, to be read from the store. */
  | { where: 'disk'; ordinal: number }
  /**
   * Nothing. Out of range, or a match the bitmap can no longer place.
   *
   * Distinct from a row that is merely not fetched yet: this one is never
   * going to arrive, and a placeholder that spins for ever is a worse answer
   * than a row that says so.
   */
  | { where: 'none' };

const NOWHERE: RowAddress = { where: 'none' };

/** Where list row `index` reads from. Cheap: this runs inside render. */
export function addressRow(
  space: RowSpace, matches: MatchSet | null, index: number,
): RowAddress {
  const row = index + space.skipped;
  if (row < 0 || row >= space.total) return NOWHERE;
  if (row >= space.fromDisk) return { where: 'window', at: row - space.fromDisk };
  if (matches === null) return { where: 'disk', ordinal: row };
  const ordinal = matches.ordinalAt(row);
  return ordinal < 0 ? NOWHERE : { where: 'disk', ordinal };
}

/**
 * The list row a capture ordinal sits at, or -1.
 *
 * The inverse of the disk half of `addressRow`, for keeping the selected frame
 * in view when a filter is applied. Unfiltered the two are the same number;
 * filtered, the row is how many matches precede the ordinal.
 */
export function rowOfOrdinal(
  space: RowSpace, matches: MatchSet | null, ordinal: number,
): number {
  if (ordinal < 0) return -1;
  const row = matches === null ? ordinal : matches.rank(ordinal);
  if (row < space.skipped || row >= space.fromDisk) return -1;
  return row - space.skipped;
}
