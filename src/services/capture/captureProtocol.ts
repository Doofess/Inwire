/**
 * The messages between the app and the capture store process.
 *
 * A closed set, in its own module, the way `services/pipeline/protocol.ts` is
 * for the dissection worker: both ends import these types, so a message that
 * one side sends and the other does not handle fails to compile rather than
 * being dropped at runtime.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from '../dissect/types';
import type { RawFrame, WriterStats } from './captureWriter';

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
   * The rows covering capture positions `[from, to)`. Answered with `blocks`.
   *
   * Positions, not ids: the list scrolls positions, and ids have holes. Whole
   * chunks come back, because a chunk is one inflate whichever part of it was
   * asked for and the caller caches what it gets.
   */
  | { type: 'rowsAt'; requestId: number; from: number; to: number }
  /**
   * The rows at scattered positions. Answered with `rowsByOrdinal`.
   *
   * `rowsAt` is a range and returns whole chunks, which is right for a list
   * scrolling the capture in order and wrong for a filtered one: the matches
   * of `dns` in a browsing capture put fifty visible rows across fifty
   * thousand ordinals, and whole chunks would be megabytes of rows to show
   * fifty of them - then stop at `MAX_ROW_CHUNKS`.
   */
  | { type: 'rowsForOrdinals'; requestId: number; ordinals: number[] }
  /**
   * Where a frame sits in the capture. Answered with `located`.
   *
   * Asked of the RAM window's first frame, which is what says how much of the
   * capture is below the window and therefore how many rows the list has.
   */
  | { type: 'locate'; requestId: number; id: number }
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
  /**
   * Frames as they arrived, before anything dissected them.
   *
   * **The capture path's write, and the reason it no longer waits for a
   * dissector** (ADR 0038). `append` above carries bytes AND a row together,
   * which is right for an import - the file is read and dissected in one pass,
   * so there is nothing to decouple. A live capture has two arrivals: the bytes
   * exist the moment the agent sends them, and the row exists when the
   * dissector gets to it.
   *
   * The two are matched by frame id inside `captureWriter.ts`, in either order.
   *
   * **There is deliberately no `attachRows` beside this.** Rows keep arriving
   * as `append`, and the writer answers "do I already have this frame's bytes?"
   * itself - so the app never has to know whether the ingest port exists, and a
   * build without one writes bytes and rows together exactly as it always did.
   */
  | { type: 'appendBytes'; frames: RawFrame[] }
  /** Patches produced by this flush, for rows that are still staged. */
  | { type: 'patches'; patches: InfoPatch[] }
  /** Seals the staging ring and flushes. Pause, stop, and page hide. */
  | { type: 'finish' }
  /** Deletes the capture's directory outright. */
  | { type: 'discard'; captureId: string }
  /**
   * Runs a display filter over the whole capture. Answered with `scanDone`.
   *
   * The **expression**, not a predicate: a compiled filter is a closure and a
   * closure does not cross a process boundary. So the store compiles it with
   * the same `filter/compile.ts` the renderer uses, which is what keeps one
   * filter from having two answers - see `captureScan.ts`.
   *
   * At most one runs at a time. A second `scan` cancels the first, because the
   * only caller is a filter bar and the filter it typed a moment ago is not
   * an answer anybody wants.
   */
  | { type: 'scan'; requestId: number; filter: string }
  /**
   * Abandons a scan. Answered with `scanDone`, like every request here.
   *
   * Carries the `requestId` it means, and is ignored when that is not the scan
   * currently running - a cancel arriving after its own scan finished must not
   * abandon the next one.
   */
  | { type: 'scanCancel'; requestId: number }
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
      /**
       * Free space on the volume the captures are on, or null.
       *
       * Replaces `quotaBytes`, and is a better number than the one it
       * replaces. `estimate().quota` was roughly a share of *total* disk - an
       * upper bound and never a promise - and it capped this app at a measured
       * 10.8 GB. This is what is actually available.
       *
       * `persisted` went with it and has no replacement, because it has no
       * meaning any more: it existed because a browser could evict the whole
       * origin under disk pressure, and nothing evicts a file.
       */
      freeBytes: number | null;
      /** Where the captures are, so the panel can show it and open it. */
      captureDir: string;
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
      freeBytes: number | null;
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
   * Decoded chunks answering a `rowsAt`, each with where it starts and
   * whether its rows carry their own link type (`RowBlock.linkTypesStored`).
   */
  | {
      type: 'blocks';
      requestId: number;
      blocks: { firstOrdinal: number; packets: Packet[]; linkTypesStored?: boolean }[];
    }
  /**
   * The rows a `rowsForOrdinals` asked for, each paired with its position.
   *
   * Positions the capture cannot place are simply absent, the same contract
   * `bytes` has: a row that is gone is a thing to render, not an error.
   */
  | { type: 'rowsByOrdinal'; requestId: number; rows: [number, Packet][] }
  /** Where a `locate`'s frame sits, or -1 when it is not addressable yet. */
  | { type: 'located'; requestId: number; ordinal: number }
  /**
   * How far a scan has got. Sent every `SCAN_PROGRESS_FRAMES`, not per slice.
   *
   * A slice is 12 ms, so a per-slice message would be 83 a second carrying a
   * number a person reads twice.
   */
  | {
      type: 'scanProgress';
      requestId: number;
      framesDone: number;
      frameCount: number;
      matches: number;
    }
  /**
   * A scan finished, was cancelled, or could not run. Always exactly one.
   *
   * `bits` is the sealed bitmap, one bit per capture ordinal, which the caller
   * rebuilds with `MatchSet.fromBytes(frameCount, bits)`. Null for a scan that
   * did not complete: a half-built `MatchSet` answers `count()` and refuses
   * `ordinalAt`, so handing one over would give a confidently wrong row.
   *
   * `frameCount` is the **snapshot** the scan covered, fixed when it started.
   * A capture still running has grown since, and the caller has to say so
   * rather than present a prefix as the whole answer.
   */
  | {
      type: 'scanDone';
      requestId: number;
      frameCount: number;
      bits: Uint8Array | null;
      cancelled: boolean;
      /** Why it could not run - a filter that does not compile, or no capture. */
      message: string | null;
    }
  /**
   * The capture store could not do something, and said so.
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
  /** Free space where the captures live. Null when it cannot be read. */
  freeBytes: number | null;
  /** The capture directory, shown in Settings and openable from there. */
  captureDir: string;
  error: string | null;
}

export function freshCaptureStorageState(): CaptureStorageState {
  return {
    captureId: null, framesWritten: 0, bytesOnDisk: 0, stagedCount: 0,
    patchesMissed: 0, storedRange: null, freeBytes: null, captureDir: '',
    error: null,
  };
}
