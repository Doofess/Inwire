/**
 * Which rows of a virtualised list to actually render.
 *
 * Pure, and in `lib` rather than inside the component, for the same reason
 * `packetColumns.ts` is: this is arithmetic that fails **invisibly**. A sort
 * fallback that picks a hidden column leaves the list ordered by something the
 * reader cannot see; a slice computed past the end leaves the list empty with
 * no error anywhere.
 *
 * ## The failure this was extracted for
 *
 * `scrollTop` is React state fed by the scroll event, so when the row count
 * shrinks underneath it - a filter applied while the list is scrolled deep -
 * it holds an offset that is no longer reachable.
 *
 * Unclamped, that gives a `startIndex` past `endIndex`, so the slice is empty
 * and the only thing rendered is a top spacer the height of the **old** list.
 * Measured on a real capture: 157,117 pixels of nothing, for a list of 1,362
 * rows that should have been 27,000.
 *
 * And that spacer is what made it stick. It kept `scrollHeight` large enough
 * that the browser saw no reason to clamp `scrollTop`, which kept `startIndex`
 * past the end, which kept the spacer. A closed loop: the list stayed blank
 * until something unrelated re-rendered it, and scrolling did not help because
 * there was nothing to scroll to.
 *
 * Clamping the offset against what the list can actually show fixes it at the
 * source, and is right whatever caused the mismatch.
 */

export interface VirtualWindow {
  /** First row to render, inclusive. */
  startIndex: number;
  /** One past the last row to render. */
  endIndex: number;
  /** Pixels of filler above the rendered rows. */
  topSpacerHeight: number;
  /** Pixels of filler below them. */
  bottomSpacerHeight: number;
}

/**
 * The rows to render, given where the list is scrolled to.
 *
 * `overscan` rows are drawn beyond each edge so a fast scroll does not expose
 * blank space before React catches up.
 */
export function virtualWindow(
  totalRows: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  overscan: number,
): VirtualWindow {
  // A row height of zero would divide by zero on every line below. It happens
  // before the first row has been measured.
  if (totalRows <= 0 || rowHeight <= 0) {
    return { startIndex: 0, endIndex: 0, topSpacerHeight: 0, bottomSpacerHeight: 0 };
  }

  // The whole fix. Never trust the offset past what the content can reach.
  const maxScrollTop = Math.max(0, totalRows * rowHeight - viewportHeight);
  const offset = Math.min(Math.max(scrollTop, 0), maxScrollTop);

  const startIndex = Math.max(0, Math.floor(offset / rowHeight) - overscan);
  const endIndex = Math.min(
    totalRows, Math.ceil((offset + viewportHeight) / rowHeight) + overscan,
  );

  return {
    startIndex,
    endIndex,
    topSpacerHeight: startIndex * rowHeight,
    bottomSpacerHeight: (totalRows - endIndex) * rowHeight,
  };
}
