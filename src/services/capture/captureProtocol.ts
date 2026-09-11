/**
 * The messages between the app and the capture worker.
 *
 * A closed set, in its own module, the way `services/pipeline/protocol.ts` is
 * for the dissection worker: both ends import these types, so a message that
 * one side sends and the other does not handle fails to compile rather than
 * being dropped at runtime.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from '../dissect/types';
import type { WriterStats } from './captureWriter';

export type ToCapture =
  /** Opens (or creates) a capture directory and starts writing into it. */
  | { type: 'open'; captureId: string }
  /**
   * Frames to store. Bytes are written at once; rows wait behind the patch
   * horizon - see `captureWriter.ts`.
   */
  | { type: 'append'; packets: Packet[] }
  /** Patches produced by this flush, for rows that are still staged. */
  | { type: 'patches'; patches: InfoPatch[] }
  /** Seals the staging ring and flushes. Pause, stop, and page hide. */
  | { type: 'finish' }
  /** Deletes the capture's directory outright. */
  | { type: 'discard'; captureId: string }
  | { type: 'stats' };

export type FromCapture =
  | { type: 'ready'; captureId: string; persisted: boolean; quotaBytes: number | null }
  | { type: 'stats'; stats: WriterStats; stagedCount: number; bytesOnDisk: number }
  /**
   * The capture worker could not do something, and said so.
   *
   * Never silent: a storage layer that fails quietly is the failure
   * `sessionStore`'s own budget comment was written to prevent - "on a full
   * drive the large case would start failing writes - silently, since every
   * write here is best-effort".
   */
  | { type: 'failure'; message: string; fatal: boolean };

/** What the app shows about the capture on disk. */
export interface CaptureStorageState {
  captureId: string | null;
  framesWritten: number;
  bytesOnDisk: number;
  stagedCount: number;
  patchesMissed: number;
  /** Null until asked, then whatever `navigator.storage.estimate()` said. */
  quotaBytes: number | null;
  /** False is the ordinary answer in Chrome, not an error. See the worker. */
  persisted: boolean;
  error: string | null;
}

export function freshCaptureStorageState(): CaptureStorageState {
  return {
    captureId: null, framesWritten: 0, bytesOnDisk: 0, stagedCount: 0,
    patchesMissed: 0, quotaBytes: null, persisted: false, error: null,
  };
}
