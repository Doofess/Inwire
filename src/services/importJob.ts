import { useSyncExternalStore } from 'react';

/**
 * The file import in progress, kept outside React.
 *
 * An import of a large file now reads it a window at a time, so the renderer
 * runs between windows. Two things follow, and both need an answer that does
 * not live in a component: a second import, or a Start, Reopen, Clear View,
 * Discard or export, must not interleave with it; and the side bar can be
 * closed and reopened mid-import, which unmounts `ImportPanel` and would take
 * its own flag with it. So the job lives here, at module scope, and the panel
 * and App only read it.
 *
 * The shape of `export/exportJob.ts`: a value, a set of listeners, and
 * `useSyncExternalStore` on the other side. Every published state is a NEW
 * object, because that hook compares snapshots by identity.
 */

export type ImportJobState =
  | { status: 'idle' }
  | { status: 'running'; fileName: string; readBytes: number; totalBytes: number };

/** Why a control is shut while a file is being imported. */
export const IMPORT_RUNNING_REASON = 'Not while a file is being imported.';
/** Start's own wording: it waits, it is not refused. */
export const IMPORT_RUNNING_START = 'Importing a file - Start waits for it.';

const IDLE: ImportJobState = { status: 'idle' };

let state: ImportJobState = IDLE;
const listeners = new Set<() => void>();

function publish(next: ImportJobState): void {
  state = next;
  for (const listener of listeners) listener();
}

export function getImportJob(): ImportJobState {
  return state;
}

export function subscribeImportJob(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Starts the job, or answers false when one is already running. */
export function beginImportJob(fileName: string, totalBytes: number): boolean {
  if (state.status === 'running') return false;
  publish({ status: 'running', fileName, readBytes: 0, totalBytes });
  return true;
}

/** Bytes of the file read so far. Ignored when no import is running. */
export function importJobProgress(readBytes: number): void {
  if (state.status !== 'running') return;
  publish({ ...state, readBytes });
}

export function endImportJob(): void {
  if (state.status === 'running') publish(IDLE);
}

export function useImportJob(): ImportJobState {
  return useSyncExternalStore(subscribeImportJob, getImportJob);
}
