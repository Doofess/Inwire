import { useSyncExternalStore } from 'react';
// `import type` only: erased at compile time, so this pulls no hook and no
// React into a module `scripts/` imports under plain tsx.
import type { CaptureFilterState } from '../lib/useCaptureFilter';

/**
 * What the packet counter says, published from App and read by one widget.
 *
 * ## Why this is a store and not a field on `DashboardWidgetContext`
 *
 * Because it would undo the application's only `React.memo` boundary.
 *
 * `Dock` is memoised - it is the one thing standing between `App` re-rendering
 * about ten times a second during a capture and six widgets each doing a full
 * pass over the buffer. The memo holds because `dashboardContext` is itself
 * memoised on inputs that change rarely: the packet array identity, the theme,
 * three stable callbacks. Putting a frame count in there would change its
 * identity on **every flush**, which is exactly the rate the memo exists to
 * absorb, and all six widgets would re-render for a number one of them shows.
 * That regression has already shipped once (`b0ce1fc`); this is the shape that
 * cannot cause it again.
 *
 * So the counter subscribes for itself. Only the component that calls
 * `usePacketCounts` re-renders when these change, and the dock around it does
 * not. It is the same pattern `lib/windowChrome.ts` uses for maximized/focused,
 * and for the same reason: a fact that changes on its own schedule, read by one
 * place, does not belong in a context every other consumer is memoised against.
 *
 * ## Why it is here rather than in the widget's own file
 *
 * `src/services/` imports no React components and no Electron, which is what
 * lets an assertion script import it under plain `tsx`. The arithmetic - what
 * percentage to show, and whether a percentage means anything yet - is the part
 * worth asserting, so it lives on this side of that line.
 */
export interface PacketCounts {
  /** Rows the display filter selected, over the whole capture. */
  filtered: number;
  /** Rows in the capture, on disk and in the window together. */
  total: number;
  /** The whole-capture scan's state, or null when no filter is running. */
  scan: CaptureFilterState | null;
  /** Stored frames that arrived after the scan started. */
  uncovered: number;
  /** Runs the scan again. Undefined when there is nothing to re-run. */
  onRescan?: () => void;
}

export const EMPTY_COUNTS: PacketCounts = { filtered: 0, total: 0, scan: null, uncovered: 0 };

let current: PacketCounts = EMPTY_COUNTS;
const listeners = new Set<() => void>();

/**
 * Publishes the counts. Called from App on every flush.
 *
 * Compared field by field before notifying, because the caller rebuilds the
 * object each render and the identity always differs - so without this, every
 * flush would wake the subscriber even when nothing it shows had changed. The
 * same argument `createPreferenceStore.set` makes for its deep comparison, and
 * the same consequence if it is dropped: a re-render per flush for no change.
 */
export function publishPacketCounts(next: PacketCounts): void {
  if (
    next.filtered === current.filtered
    && next.total === current.total
    && next.scan === current.scan
    && next.uncovered === current.uncovered
    && next.onRescan === current.onRescan
  ) {
    return;
  }
  current = next;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function usePacketCounts(): PacketCounts {
  return useSyncExternalStore(subscribe, () => current, () => EMPTY_COUNTS);
}

/**
 * What share of the capture the filter selected, as a whole percent.
 *
 * **100 when nothing is filtered, and 0 when nothing is captured.** Those are
 * the two ends a naive `filtered / total` gets wrong: an empty capture divides
 * by zero, and a capture with no filter should read 100% rather than being a
 * ratio that happens to equal one.
 */
export function filterPercentage({ filtered, total }: PacketCounts): number {
  if (total <= 0) return 0;
  return Math.round((filtered / total) * 100);
}

/**
 * How far a whole-capture scan has got, or null while that is unknowable.
 *
 * Null until the store reports a frame count, which is 150,000 frames in. A
 * percentage of an unknown total is a number, and a wrong one - so the card
 * says "scanning" with no figure rather than "0%" for the first few seconds of
 * every scan over a large capture.
 */
export function scanPercentage(scan: CaptureFilterState | null): number | null {
  if (scan === null || scan.status !== 'scanning' || scan.frameCount <= 0) return null;
  return Math.floor((scan.framesDone / scan.frameCount) * 100);
}
