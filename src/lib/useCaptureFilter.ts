/**
 * A display filter run over the whole capture, not just the part in memory.
 *
 * ## What was wrong before this
 *
 * A display filter has always run over `packets`, which is the RAM window. On
 * a capture larger than memory that means the filter answers a question nobody
 * asked - "which of the frames that happen to still be in RAM match" - and it
 * answers it without saying so. `dns` on a 5 GB capture would show the last
 * few minutes of DNS and look complete.
 *
 * The store can answer the real question, because it has the frames. This hook
 * asks it: one `scan` per applied filter, and what comes back is a bitmap over
 * capture ordinals that `useCaptureRows` addresses rows through.
 *
 * ## The scan is a snapshot, and that is stated rather than hidden
 *
 * `scanned` is how far the capture reached when the scan started. A capture
 * still running has grown since, and those frames are simply not in the
 * answer - so the state carries the number and the list says what it is not
 * showing. The alternative was re-scanning as the capture grows, which on a
 * live capture at full rate is a whole-capture pass about once a second.
 *
 * `rescan()` is how that gets settled, and it is deliberately something the
 * reader asks for: the natural workflow is to stop the capture and then narrow
 * it, and a scan that re-ran itself would spend the store process on frames
 * arriving faster than it can read them.
 *
 * ## Cancellation is not an edge case here
 *
 * It is the normal path. Every keystroke that applies a new filter supersedes
 * the scan before it, and React's StrictMode runs the effect twice on mount -
 * so the first thing a new scan does is cancel one. The store settles the
 * abandoned one as `cancelled`, which lands here as "a scan I no longer care
 * about" and is dropped: the generation counter, not the message, decides
 * whose answer is current.
 */
import { useCallback, useEffect, useState } from 'react';
import { captureStore } from '../services/capture/captureClient';
import type { MatchSet } from '../services/capture/matchSet';

export type CaptureFilterState =
  /** No filter applied, or nothing below the window to filter. */
  | { status: 'off' }
  | {
      status: 'scanning';
      framesDone: number;
      /** Zero until the first progress message; the bar shows indeterminate. */
      frameCount: number;
      matches: number;
    }
  | {
      status: 'ready';
      matches: MatchSet;
      /** Ordinals the scan covered. The capture may be longer by now. */
      scanned: number;
    }
  | { status: 'failed'; message: string };

export interface CaptureFilterScan {
  state: CaptureFilterState;
  /**
   * Runs it again, for a capture that has grown past what the last one saw.
   *
   * Stable across renders, so it can be handed to a button without making the
   * button's props change every flush.
   */
  rescan: () => void;
}

const OFF: CaptureFilterState = { status: 'off' };

/**
 * @param filter    The applied expression. Empty means no filter.
 * @param enabled   False when there is nothing on disk the window does not
 *                  already hold - the in-memory filter is then the whole
 *                  answer and a scan would be a pass over frames the caller
 *                  has in hand.
 */
export function useCaptureFilter(filter: string, enabled: boolean): CaptureFilterScan {
  const [state, setState] = useState<CaptureFilterState>(OFF);
  const [generation, setGeneration] = useState(0);

  const rescan = useCallback(() => setGeneration((n) => n + 1), []);

  useEffect(() => {
    if (!enabled || filter.trim() === '') {
      setState(OFF);
      return;
    }

    // Current until this effect is torn down. A late message from a scan that
    // has been superseded finds this false and is dropped - which matters
    // because the store answers the abandoned scan too, and it answers it
    // FIRST.
    let live = true;
    setState({ status: 'scanning', framesDone: 0, frameCount: 0, matches: 0 });

    const handle = captureStore.scanCapture(filter, (progress) => {
      if (!live) return;
      setState({ status: 'scanning', ...progress });
    });

    void handle.result.then((outcome) => {
      if (!live) return;
      switch (outcome.status) {
        case 'done':
          setState({ status: 'ready', matches: outcome.matches, scanned: outcome.frameCount });
          break;
        case 'failed':
          setState({ status: 'failed', message: outcome.message });
          break;
        case 'cancelled':
          // Only reachable when something cancelled the scan without tearing
          // this effect down, which nothing does today. Left as scanning would
          // be a bar that never finishes, so it says so instead.
          setState({ status: 'failed', message: 'the scan was cancelled' });
          break;
      }
    });

    return () => {
      live = false;
      handle.cancel();
    };
  }, [filter, enabled, generation]);

  return { state, rescan };
}

/**
 * How many rows below the window a scan did not reach.
 *
 * Non-zero means the capture grew after the scan started, which on a live
 * capture it always does. The list states it; `rescan()` settles it.
 */
export function uncoveredRows(state: CaptureFilterState, below: number): number {
  if (state.status !== 'ready') return 0;
  return Math.max(0, below - state.scanned);
}
