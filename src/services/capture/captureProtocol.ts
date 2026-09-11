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
  /**
   * Opens (or creates) a capture directory and starts writing into it.
   *
   * The same message reopens a capture from a previous run - recovery, the
   * index and the writer's resume are the same three steps either way, and a
   * second message that did two of them would be a second thing to keep in
   * step. `requestId` is set only when the caller is waiting for the answer,
   * which is the restore; a fresh Start sends none.
   */
  | { type: 'open'; captureId: string; requestId?: number }
  /** One chunk's rows, for a restore. Answered with `rows`. */
  | { type: 'chunk'; requestId: number; chunk: number }
  /**
   * Deletes every capture directory except these.
   *
   * This is the whole of retention: exactly one capture on disk, the one the
   * stored session names (`docs/decisions/0026`). `keep` is a list rather than
   * a single id because the shape costs nothing and a segmented capture - v2,
   * where one capture is several directories - needs it.
   */
  | { type: 'prune'; keep: string[] }
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
  /**
   * The raw bytes of specific frames.
   *
   * Answered with a `bytes` message carrying the same `requestId`. Ids the
   * capture does not hold are simply absent from the answer - the contract
   * `sessionStore.readFrameBytes` had, kept deliberately, because
   * `packetBytes.ts` is written against it and this step is supposed to change
   * nothing above that seam.
   */
  | { type: 'read'; requestId: number; ids: number[] }
  | { type: 'stats' };

export type FromCapture =
  | {
      type: 'ready';
      captureId: string;
      persisted: boolean;
      quotaBytes: number | null;
      /** What was already on disk: zero for a capture that has just started. */
      frameCount: number;
      chunkCount: number;
      /** The highest id stored, so numbering resumes past it. Zero when empty. */
      lastId: number;
      requestId?: number;
    }
  /**
   * A chunk's rows, decoded.
   *
   * Without `rawBytes` - see `CaptureReader.readRows`. Empty when the chunk
   * could not be read, which is a torn tail and not an error.
   */
  | { type: 'rows'; requestId: number; packets: Packet[] }
  | {
      type: 'stats';
      stats: WriterStats;
      stagedCount: number;
      bytesOnDisk: number;
      /**
       * The ids the capture can supply bytes for, or null.
       *
       * Mirrored on the main thread so `bytesAreRecoverable` stays synchronous
       * - it is asked while rendering, and an async answer would mean a frame
       * with no bytes could not say WHY until a promise settled.
       */
      storedRange: { first: number; last: number } | null;
    }
  /** Frames asked for by a `read`. Absent ids are frames the capture lacks. */
  | { type: 'bytes'; requestId: number; frames: [number, Uint8Array][] }
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
  /** The span of frame ids whose bytes are readable, or null. */
  storedRange: { first: number; last: number } | null;
  /** Null until asked, then whatever `navigator.storage.estimate()` said. */
  quotaBytes: number | null;
  /** False is the ordinary answer in Chrome, not an error. See the worker. */
  persisted: boolean;
  error: string | null;
}

export function freshCaptureStorageState(): CaptureStorageState {
  return {
    captureId: null, framesWritten: 0, bytesOnDisk: 0, stagedCount: 0,
    patchesMissed: 0, storedRange: null, quotaBytes: null, persisted: false,
    error: null,
  };
}
