import { useSyncExternalStore } from 'react';

/**
 * Whether a Start is in progress, kept outside React, and the one decision
 * that reads it.
 *
 * `handleStartCapture` awaits twice (`cancelExportForChange`, `clearSession`)
 * before it opens its capture on the store. An import pressed in those awaits
 * passed every check, because Start had not opened or begun anything yet, and
 * the two capture-changing paths then interleaved on the one store. The first
 * of the two to begin now wins: Start refuses while an import runs
 * (`importJob.ts`), and an import is refused while a Start runs, here.
 *
 * Module scope for the reason `importJob.ts` gives: the handlers that must
 * refuse read it LIVE, and a value a render old is exactly the gap. A COUNT
 * rather than a flag, so two Starts in flight (a double press, a schedule
 * firing under a press) do not clear it for each other.
 *
 * Pure: no Electron, no `node:*`.
 */

/** Why the import is shut while a Start runs. */
export const CAPTURE_STARTING_REASON = 'Not while a capture is starting.';

let starting = 0;
const listeners = new Set<() => void>();

function publish(next: number): void {
  const was = starting > 0;
  starting = next;
  if ((next > 0) !== was) for (const listener of listeners) listener();
}

export function isCaptureStarting(): boolean {
  return starting > 0;
}

export function subscribeCaptureStarting(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/**
 * A Start begins. Pair it with `endCaptureStart` in a `finally`, so a throw
 * cannot leave imports shut for good.
 */
export function beginCaptureStart(): void {
  publish(starting + 1);
}

export function endCaptureStart(): void {
  if (starting > 0) publish(starting - 1);
}

export function useCaptureStarting(): boolean {
  return useSyncExternalStore(subscribeCaptureStarting, isCaptureStarting);
}

/** What an import's entry point must know to decide whether it may begin. */
export interface ImportGateInput {
  /** Whether a file is being imported - read live from `importJob.ts`. */
  importRunning: boolean;
  /** Whether a Start is in progress - read live from here. */
  captureStarting: boolean;
  /** The reason the panel was handed to shut it (an export, a reopen), or null. */
  blockedBy: string | null;
}

/**
 * Why an import may not begin now, or null when it may. The first reason that
 * applies wins; a running import is the panel's own and is never shown.
 */
export function importRefusal({ importRunning, captureStarting, blockedBy }: ImportGateInput): string | null {
  if (importRunning) return 'A file is already being imported.';
  if (blockedBy !== null) return blockedBy;
  if (captureStarting) return CAPTURE_STARTING_REASON;
  return null;
}
