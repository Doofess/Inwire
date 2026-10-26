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
import type { WriterStats } from './captureWriter';
import type { FrameSlab } from './frameSlab';
import type { StreamSummary } from '../conversation/streamDigest';
import type { PackedRows } from '../pipeline/rowPack';

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
   *
   * `bytesSent` is the pipeline Worker saying that it sent every one of these
   * frames' bytes itself, ahead of this, on this same port - so these are rows
   * and nothing else, and their `rawBytes` are empty rather than a second copy
   * (ADR 0053). Only a sender that wrote the bytes may say it; the app never
   * does, for the reason `appendBytes` below gives.
   */
  | { type: 'append'; packets: Packet[]; bytesSent?: true }
  /**
   * The same rows as `append`, in the pipeline Worker's order, with a shard's
   * rows as the pack the shard encoded (`services/pipeline/rowPack.ts`).
   *
   * Only the Worker sends it. `sent` is `bytesSent` said row by row, in the
   * rows' order: 1 for a row whose bytes the Worker wrote ahead of it on this
   * port, which is attached; 0 for one that goes as an `append` would, with
   * whatever bytes it carries. Said rather than read off an empty `rawBytes`,
   * because an agent's metadata-only frame has none either and was never sent
   * ahead. The host reads every message, even with no capture open, because
   * its cache of half-read packs must count every row it was sent.
   */
  | { type: 'appendPacked'; rows: PackedRows; sent: Uint8Array }
  /**
   * Frames as they arrived, before anything dissected them, as one columnar
   * `FrameSlab` (#17): five buffers cross the port, not an object a frame.
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
   * The one sender that does know is the Worker, which wrote the bytes: its
   * rows say so (`bytesSent`), and travel without them.
   */
  | {
      type: 'appendBytes';
      slab: FrameSlab;
      /**
       * Answered with `bytesTaken` once the writer has this slab's frames, on the
       * port that sent them - the pipeline Worker's (ADR 0053). Its count of
       * unanswered appends is the store's backlog, and past a budget it stops
       * sending. Absent from a sender that keeps no count.
       */
      ack?: number;
    }
  /**
   * Frame records from the pipeline Worker, on its own port, one-way
   * (ADR 0049): what each frame's first dissection learned from the frames
   * before it. Matched to their frames by id, like rows, in either order.
   */
  | { type: 'appendRecords'; frames: { id: number; record: Uint8Array }[] }
  /**
   * Everything a revisit of frame `id` needs - its record, its row, its bytes
   * and the bytes of every frame its record names. Answered with `revisitKit`
   * on the port that asked, which for the pipeline Worker is its own.
   */
  | { type: 'revisitKit'; requestId: number; id: number }
  /** Patches produced by this flush, for rows that are still staged. */
  | { type: 'patches'; patches: InfoPatch[] }
  /**
   * The agent's ring deleted a file (ADR 0052): the segments holding only
   * frames up to `lastSeq` of run `epoch` may go, and do once they can -
   * `segments.ts` decides. From the pipeline Worker, which files every frame.
   */
  | { type: 'ringDeleted'; epoch: number; lastSeq: number }
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
   * Which stored frames the open capture's marks name (ADR 0067). Answered with
   * `markMatches`, even when no capture is open, because the caller holds a
   * promise.
   *
   * **Not a scan**, on purpose: a second `scan` cancels the list's filter scan,
   * and exporting the marked packets must not abandon the filter the user is
   * looking at. It reads the index only (`ordinalOf` per mark), so it neither
   * waits for nor disturbs a running scan.
   */
  | { type: 'markMatches'; requestId: number }
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
  /**
   * The TCP streams whose summaries changed after digest version `since`
   * (ADR 0055). Answered with `streamDigest`, even when no capture is open,
   * because the caller holds a promise. `since: 0` asks for every stream.
   */
  | { type: 'streamDigest'; requestId: number; since: number }
  /**
   * The positions of stream `streamId`'s frames, ids `[fromId, toId]`, from
   * chunk `startChunk` onward. Answered with `streamOrdinals`, a page of
   * chunks at a time, even when no capture is open, because the caller holds
   * a promise. Read from the prefix blocks, never from rows, so it neither
   * waits for nor cancels a running scan.
   */
  | {
      type: 'streamOrdinals';
      requestId: number;
      streamId: number;
      fromId: number;
      toId: number;
      startChunk: number;
    }
  /**
   * Replaces the open capture's whole set of marked frame ids and persists it
   * (ADR 0067). One-way: the renderer holds the live set and the store keeps
   * the file, so there is nothing to answer. Ignored when `captureId` is not
   * the open capture, so a message that outlives a Clear View or a Reopen
   * cannot write one capture's marks into the next.
   */
  | { type: 'marks'; captureId: string; ids: number[] }
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
      /**
       * The end of the capture's ordinal space: zero for a capture that has
       * just started. Not how many frames it holds - see `floorOrdinal`.
       */
      frameCount: number;
      chunkCount: number;
      /** The ordinal of its first frame still held; above 0 once a ring has deleted some. */
      floorOrdinal: number;
      /** Every frame id below this has gone; 0 when none has. */
      floorId: number;
      /** The ids it can supply, or null - as `stats` carries them. */
      storedRange: { first: number; last: number } | null;
      /** The highest id stored, so numbering resumes past it. Zero when empty. */
      lastId: number;
      /**
       * The frame ids the user marked, ascending: the capture's own, from
       * `marks.iwmrk`. Empty for a new capture and for a file that is missing
       * or torn, which never fails the open (ADR 0067).
       */
      marks: number[];
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
  /**
   * The capture's floor moved: a ring deleted a file, and the frames below
   * `floorOrdinal` left the capture with it (ADR 0052). Every position below
   * it now answers as a hole, and the list starts there.
   */
  | {
      type: 'floor';
      floorOrdinal: number;
      /** Every frame id below this has gone. See `CaptureStorageState.floorId`. */
      floorId: number;
      storedRange: { first: number; last: number } | null;
    }
  /** Frames asked for by a `read`. Absent ids are frames the capture lacks. */
  | { type: 'bytes'; requestId: number; frames: [number, Uint8Array][] }
  /**
   * What a `revisitKit` asked for. `record` is null for a frame with none - a
   * capture written before records existed, or one sealed before its record
   * arrived - and `row` null for a frame this capture does not hold.
   */
  | {
      type: 'revisitKit';
      requestId: number;
      record: Uint8Array | null;
      row: Packet | null;
      frames: [number, Uint8Array][];
    }
  /**
   * The writer has taken an `appendBytes` - or dropped it, with no capture
   * open, or failed it, which is reported on the client port as every failure
   * is. Answered either way: the Worker counts unanswered appends as the
   * store's backlog, and an answer that never came would stop the live view
   * for good.
   */
  | { type: 'bytesTaken'; ack: number }
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
   * The summaries a `streamDigest` asked for, and the digest's version to ask
   * from next time.
   *
   * `captureId` is the capture the digest belongs to, null when none is open:
   * a version means nothing across captures, so the caller starts again from
   * 0 when it changes. `rebuilding` is non-null while the store is folding
   * the digest again from the capture's rows - a snapshot that was missing or
   * stale (ADR 0055) - and the summaries until then are a partial answer.
   */
  | {
      type: 'streamDigest';
      requestId: number;
      captureId: string | null;
      version: number;
      summaries: StreamSummary[];
      rebuilding: { done: number; total: number } | null;
      /** A rebuild dropped rows: the summaries are not the whole capture, and no snapshot will be written. */
      partial: boolean;
    }
  /**
   * One page of a `streamOrdinals`. `nextChunk` is where to ask from next,
   * or null when the capture, or the stream's id range, has been read to its
   * end. Empty and null when the read failed, which is reported separately.
   */
  | { type: 'streamOrdinals'; requestId: number; ordinals: number[]; nextChunk: number | null }
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
   * The marked frames the capture holds, in `scanDone`'s encoding: `bits` is
   * one bit per capture ordinal, rebuilt with `MatchSet.fromBytes(frameCount,
   * bits)`. `frameCount` is the capture's size when it was asked, because the
   * bitmap cannot say how many ordinals its last block covers.
   *
   * `count` is the marks that are stored, which can be fewer than the marks
   * there are: an id the ring has expired, or one never stored, is left out.
   */
  | { type: 'markMatches'; requestId: number; frameCount: number; bits: Uint8Array; count: number }
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
  /**
   * The ordinal of the capture's first frame still held. Zero unless the
   * capture follows a ring that has deleted files (ADR 0052), and then every
   * position below it has gone.
   */
  floorOrdinal: number;
  /**
   * Every frame id below this has gone with the ring - one past the newest id
   * the deleted segments held, and 0 when none has. What the RAM window drops
   * by, because a frame still staged behind the patch horizon is in no range
   * the store can state yet and must not be taken for one that has gone.
   */
  floorId: number;
  /** Free space where the captures live. Null when it cannot be read. */
  freeBytes: number | null;
  /** The capture directory, shown in Settings and openable from there. */
  captureDir: string;
  error: string | null;
}

export function freshCaptureStorageState(): CaptureStorageState {
  return {
    captureId: null, framesWritten: 0, bytesOnDisk: 0, stagedCount: 0,
    patchesMissed: 0, storedRange: null, floorOrdinal: 0, floorId: 0, freeBytes: null, captureDir: '',
    error: null,
  };
}
