import { useSyncExternalStore } from 'react';
// `import type` only: erased at compile time, so this pulls no hook and no
// React into a module `scripts/` imports under plain tsx.
import type { CaptureFilterState } from '../lib/useCaptureFilter';

/**
 * What the packet counter says, published from App and read by the title row.
 *
 * ## Why this is a store and not a prop threaded down from `App`
 *
 * Because threading it down is the regression that shipped once already
 * (`b0ce1fc`), and the reason it is still a regression has changed.
 *
 * The original argument was a memo boundary: `Dock` was the application's only
 * `React.memo`, it held because `DashboardWidgetContext` was memoised on inputs
 * that changed rarely, and putting a ten-times-a-second number into that context
 * would have broken it. **That boundary no longer exists** - the dock is
 * deleted, and `React.memo` appears nowhere in `src/`.
 *
 * What replaced it is stronger, which is why this store stays. Every surface
 * that reads the buffer is now unmounted unless its view is active, so there is
 * nothing to memoise: the cost is not paid at all rather than paid and then
 * skipped. The counter is the one exception - it lives in the title row, which
 * is on screen in every view - so it is the one thing that must update ten
 * times a second without re-rendering anything else. A prop from `App` would
 * re-render the whole tree to move one number; a store re-renders its one
 * subscriber.
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
 * percentage of an unknown total is a number, and a wrong one - so the readout
 * says "scanning" with no figure rather than "0%" for the first few seconds of
 * every scan over a large capture.
 */
export function scanPercentage(scan: CaptureFilterState | null): number | null {
  if (scan === null || scan.status !== 'scanning' || scan.frameCount <= 0) return null;
  return Math.floor((scan.framesDone / scan.frameCount) * 100);
}
