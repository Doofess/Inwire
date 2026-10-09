import { useSyncExternalStore } from 'react';

/**
 * How far the live view is behind the agent, published once a second from the
 * pipeline client and read by one status item (ADR 0053).
 *
 * A store for the reason `packetCounts.ts` gives: a prop from `App` would
 * re-render the whole tree to move one number, and this one is read by a
 * single cell in the status bar.
 */
export interface LiveLag {
  /** Frames main posted to the Worker that it has not dissected yet. */
  behindFrames: number;
  /** How long ago the oldest of them arrived from the agent, in ms. */
  behindMs: number;
  /** Frames the live stream never delivered - in the capture file, not the view. */
  skippedFrames: number;
  /** Main is shedding batches right now. */
  shedding: boolean;
  /** The store's backlog is holding frames back. */
  storeBehind: boolean;
  /**
   * The view is reading what the stream skipped back out of the capture file
   * (ADR 0053 phase 4); `behindFrames` and `behindMs` are then how far that
   * reading is from the newest live frame.
   */
  catchingUp: boolean;
}

export const NO_LAG: LiveLag = {
  behindFrames: 0, behindMs: 0, skippedFrames: 0, shedding: false, storeBehind: false, catchingUp: false,
};

/**
 * Below this the view is "live": the ordering window alone holds frames for a
 * fraction of a second by design, and a readout that flickered on every flush
 * would be reporting the window, not a backlog.
 */
export const BEHIND_SHOWN_MS = 1500;

let current: LiveLag = NO_LAG;
const listeners = new Set<() => void>();

export function publishLiveLag(next: LiveLag): void {
  if (
    next.behindFrames === current.behindFrames && next.behindMs === current.behindMs
    && next.skippedFrames === current.skippedFrames && next.shedding === current.shedding
    && next.storeBehind === current.storeBehind && next.catchingUp === current.catchingUp
  ) return;
  current = next;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function useLiveLag(): LiveLag {
  return useSyncExternalStore(subscribe, () => current, () => NO_LAG);
}

/**
 * What the status item says, or null when there is nothing to say - the
 * status bar's rule that an item renders nothing when its subject is absent.
 * Pure, so `scripts/session/live-lag.ts` can hold the wording.
 */
export function liveLagLabel(lag: LiveLag): { text: string; title: string } | null {
  if (lag.catchingUp) {
    // Said as what it is: behind, and getting there, with nothing lost - the
    // frames the stream skipped are being read back out of the capture file.
    const seconds = Math.round(lag.behindMs / 1000);
    const frames = lag.behindFrames.toLocaleString('en-US');
    const text = ['catching up', seconds > 0 ? `behind live ${seconds} s` : '', `${frames} to go`]
      .concat(lag.skippedFrames > 0 ? [`${lag.skippedFrames.toLocaleString('en-US')} skipped`] : [])
      .filter(Boolean).join(' · ');
    const title = [
      `Behind live by ${seconds} s, ${frames} frames to go, nothing lost: the live stream ran faster than the view, `
        + 'and the frames it skipped are being read back from the capture file, in order.',
      lag.skippedFrames > 0 ? `${lag.skippedFrames.toLocaleString('en-US')} frames could not be read back and are marked where they were skipped; they are in the capture file.` : '',
    ].filter(Boolean).join(' ');
    return { text, title };
  }
  const behind = lag.behindMs >= BEHIND_SHOWN_MS && lag.behindFrames > 0;
  if (!behind && lag.skippedFrames === 0) return null;
  const parts: string[] = [];
  if (behind) parts.push(`behind live ${Math.round(lag.behindMs / 1000)} s`);
  if (lag.skippedFrames > 0) parts.push(`${lag.skippedFrames.toLocaleString('en-US')} skipped`);
  const why = lag.storeBehind ? 'the capture store is catching up'
    : lag.shedding ? 'arriving faster than it can be dissected'
      : behind ? 'still dissecting what has arrived' : '';
  const title = [
    behind ? `The view is ${Math.round(lag.behindMs / 1000)} s behind the capture: ${lag.behindFrames.toLocaleString('en-US')} frames to go.` : '',
    lag.skippedFrames > 0 ? `${lag.skippedFrames.toLocaleString('en-US')} frames were skipped by the live view to keep up; they are in the capture file, and nothing was lost.` : '',
    why ? `Cause: ${why}.` : '',
  ].filter(Boolean).join(' ');
  return { text: parts.join(' · '), title };
}
