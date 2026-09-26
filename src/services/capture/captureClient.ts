/**
 * The app's handle on the capture store.
 *
 * Shaped like `services/pipelineClient.ts` - one object, callbacks assigned
 * rather than an event emitter, the connection made lazily on first use -
 * because a second thing that talks to another context should not invent a
 * second way of doing it. What is on the far side is not a Worker but the store
 * `utilityProcess` (`electron/store/`), reached over a `MessagePort` the
 * preload hands into the page; `captureHost.ts` is the code it runs.
 *
 * ## This is the read path, not a shadow of one
 *
 * It was a shadow write once - frames were persisted here while IndexedDB
 * remained the thing a restore read back - and that is over. Every row below
 * the RAM window comes through `readRowsAt`/`readRowsFor`, every byte a frame
 * has dropped comes through `readBytes`, a restore comes through `reopen` and
 * `readRows`, and the whole-capture display filter is `scanCapture`. IndexedDB
 * holds the session's **metadata** and nothing else (`services/sessionStore.ts`).
 *
 * The boundary this crosses has been measured rather than estimated:
 * `scripts/perf/store-boundary.ts` puts the serialize + `MessagePort` hop at
 * **5.26 us a frame** against the writer's own 26.68 us - 16% of the cost, and
 * 31,308 frames a second for the two together. That number is what ADR 0028 was
 * waiting for, and it says moving the store back in-process would buy the 16%
 * and nothing else, so the crossing is not the thing to optimise.
 *
 * One property of it is load-bearing and easy to undo: **a message is a
 * snapshot**. `plainForStore` flattens each frame at this boundary because a
 * structured clone drops prototypes, and `FieldBlock` is a class - see
 * `storePacket.ts`, and the bug that hid the whole disk path.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from '../dissect/types';
import type { ToCapture, FromCapture, CaptureStorageState } from './captureProtocol';
import { freshCaptureStorageState } from './captureProtocol';
import { MatchSet } from './matchSet';
import { plainForStore } from './storePacket';

/** One decoded chunk, and where it starts in the capture. */
export interface RowBlock {
  firstOrdinal: number;
  packets: Packet[];
  /**
   * True when the chunk recorded each row's `linkType`, so an absent one
   * means Ethernet. False or absent for a chunk written before it did, where
   * absent means "not recorded" and only the session's adapter table can say
   * (`export/exportFrames.ts`).
   */
  linkTypesStored?: boolean;
}

/** How far a scan has got, for the progress the filter bar shows. */
export interface ScanProgressUpdate {
  framesDone: number;
  frameCount: number;
  matches: number;
}

/**
 * How a scan ended. Exactly one of these, always.
 *
 * `cancelled` and `failed` are separate because they mean different things to
 * the caller: one is the user's own doing - a newer filter, or Escape - and
 * the other is something to say out loud.
 */
export type ScanOutcome =
  | {
      status: 'done';
      matches: MatchSet;
      /**
       * The ordinals the scan covered, fixed when it started.
       *
       * A live capture has grown since, and the frames past this are simply
       * not in the answer. The caller states that rather than presenting a
       * prefix as the whole of it.
       */
      frameCount: number;
    }
  | { status: 'cancelled' }
  | { status: 'failed'; message: string };

/** A scan in flight. `cancel` is safe at any point, including twice. */
export interface ScanHandle {
  readonly result: Promise<ScanOutcome>;
  cancel(): void;
}

/** What a reopened capture turned out to hold. */
export interface StoredCapture {
  captureId: string;
  frameCount: number;
  chunkCount: number;
  /** The highest stored id, so `packetGenerator` resumes past it. */
  lastId: number;
}

/**
 * True when a capture store can be reached at all.
 *
 * It was `opfsAvailable()`, testing for `navigator.storage.getDirectory`. The
 * question is the same one - is there somewhere to put a capture - and the
 * answer now comes from the preload bridge, which is absent in every one of
 * the assertion scripts and must therefore be optional rather than assumed.
 */
function captureStoreAvailable(): boolean {
  return typeof window !== 'undefined' && window.inwire?.isDesktop === true;
}

/**
 * The window message the preload uses to hand the store's port into the page.
 *
 * It has to arrive this way: `contextBridge` cannot pass a `MessagePort`, so
 * there is no version of this where the bridge simply returns one.
 */
const CAPTURE_PORT_MESSAGE = 'inwire:capture-port';

/** How long to wait for main to answer before giving up on the store. */
const PORT_TIMEOUT_MS = 15_000;

function requestStorePort(): Promise<MessagePort> {
  return new Promise((resolve, reject) => {
    const onMessage = (event: MessageEvent) => {
      // `event.source === window` is the check that makes `'*'` safe on the
      // preload's side: only this window can post to itself.
      if (event.source !== window) return;
      if ((event.data as { channel?: string } | null)?.channel !== CAPTURE_PORT_MESSAGE) return;
      const [port] = event.ports;
      if (!port) return;
      window.removeEventListener('message', onMessage);
      clearTimeout(timer);
      resolve(port);
    };
    const timer = setTimeout(() => {
      window.removeEventListener('message', onMessage);
      reject(new Error('the capture store did not answer'));
    }, PORT_TIMEOUT_MS);
    window.addEventListener('message', onMessage);
    window.inwire?.requestCaptureStorePort?.();
  });
}

/** Bytes a request could not be answered with. Shared, never written to. */
const NONE = new Map<number, Uint8Array>();
/** The same, for rows. */
const NO_ROWS = new Map<number, Packet>();

class CaptureClient {
  /**
   * The channel to the store process, once main has handed it over.
   *
   * A promise, and every method awaits it - which is not a style choice. The
   * port arrives asynchronously where `new Worker(...)` returned an object
   * synchronously, and `App.tsx`'s startup is
   * `reopen(...)` followed immediately by
   * `prune(stored === null ? [] : [stored.captureId])`. A `reopen` that
   * answered `null` for "no transport yet" would therefore **delete every
   * capture on disk** on a slow start. Null means the store said no; it never
   * means "not connected".
   */
  private connection: Promise<MessagePort | null> | null = null;
  private state: CaptureStorageState = freshCaptureStorageState();
  /** Set once a failure makes the store unusable, so nothing keeps trying. */
  private disabled = false;
  /** In-flight byte reads, by request id. The store always answers. */
  private readonly pending = new Map<number, (frames: Map<number, Uint8Array>) => void>();
  /** In-flight row reads and reopens, same rule. */
  private readonly pendingRows = new Map<number, (packets: Packet[]) => void>();
  private readonly pendingOpen = new Map<number, (ready: StoredCapture | null) => void>();
  private readonly pendingBlocks = new Map<number, (blocks: RowBlock[]) => void>();
  private readonly pendingScattered = new Map<number, (rows: Map<number, Packet>) => void>();
  private readonly pendingLocate = new Map<number, (ordinal: number) => void>();
  /** The scan in flight. At most one - the store enforces the same. */
  private readonly pendingScan = new Map<number, {
    onProgress?: (progress: ScanProgressUpdate) => void;
    settle: (outcome: ScanOutcome) => void;
  }>();
  private nextRequest = 1;

  onState: (state: CaptureStorageState) => void = () => {};

  private ensurePort(): Promise<MessagePort | null> {
    if (this.connection) return this.connection;
    if (this.disabled || !captureStoreAvailable()) return Promise.resolve(null);

    this.connection = (async () => {
      try {
        const port = await requestStorePort();
        port.onmessage = (event: MessageEvent<FromCapture>) => this.receive(event.data);
        // A `MessagePort` obtained this way delivers nothing until it is
        // started. Assigning `onmessage` starts it implicitly in the DOM, but
        // saying so is cheaper than remembering which of the two port types
        // this is.
        port.start();
        // The store is a separate process, and a `MessagePort` has no error
        // event and no reliable close event - so when it dies the port simply
        // goes quiet and every pending read would hang for the life of the
        // window. Main watches the process and tells us over its own channel.
        window.inwire!.onCaptureStoreExit?.((reason) => this.die(reason));
        return port;
      } catch (error) {
        this.die(error instanceof Error ? error.message : String(error));
        return null;
      }
    })();
    return this.connection;
  }

  /** The store is gone. Nothing waits on it, and nothing tries again. */
  private die(reason: string): void {
    this.disabled = true;
    this.connection = Promise.resolve(null);
    this.update({ error: reason || 'the capture store stopped' });
    // Whoever was waiting gets an empty answer rather than a promise that
    // never settles: a frame whose bytes cannot be fetched is a thing to
    // render, and the hex viewer already knows how to say so.
    this.settleAll();
  }

  private send(message: ToCapture): void {
    void this.ensurePort().then((port) => port?.postMessage(message));
  }

  private update(patch: Partial<CaptureStorageState>): void {
    this.state = { ...this.state, ...patch };
    this.onState(this.state);
  }

  private receive(message: FromCapture): void {
    switch (message.type) {
      case 'ready': {
        this.update({
          captureId: message.captureId,
          freeBytes: message.freeBytes,
          captureDir: message.captureDir,
          error: null,
        });
        if (message.requestId !== undefined) {
          const settle = this.pendingOpen.get(message.requestId);
          this.pendingOpen.delete(message.requestId);
          settle?.({
            captureId: message.captureId,
            frameCount: message.frameCount,
            chunkCount: message.chunkCount,
            lastId: message.lastId,
          });
        }
        break;
      }
      case 'stats':
        this.update({
          framesWritten: message.stats.framesWritten,
          patchesMissed: message.stats.patchesMissed,
          bytesOnDisk: message.bytesOnDisk,
          stagedCount: message.stagedCount,
          freeBytes: message.freeBytes,
          storedRange: message.storedRange,
        });
        break;
      case 'bytes': {
        const settle = this.pending.get(message.requestId);
        if (settle === undefined) break;
        this.pending.delete(message.requestId);
        settle(new Map(message.frames));
        break;
      }
      case 'rows': {
        const settle = this.pendingRows.get(message.requestId);
        if (settle === undefined) break;
        this.pendingRows.delete(message.requestId);
        settle(message.packets);
        break;
      }
      case 'blocks': {
        const settle = this.pendingBlocks.get(message.requestId);
        if (settle === undefined) break;
        this.pendingBlocks.delete(message.requestId);
        settle(message.blocks);
        break;
      }
      case 'rowsByOrdinal': {
        const settle = this.pendingScattered.get(message.requestId);
        if (settle === undefined) break;
        this.pendingScattered.delete(message.requestId);
        settle(new Map(message.rows));
        break;
      }
      case 'located': {
        const settle = this.pendingLocate.get(message.requestId);
        if (settle === undefined) break;
        this.pendingLocate.delete(message.requestId);
        settle(message.ordinal);
        break;
      }
      case 'scanProgress': {
        this.pendingScan.get(message.requestId)?.onProgress?.({
          framesDone: message.framesDone,
          frameCount: message.frameCount,
          matches: message.matches,
        });
        break;
      }
      case 'scanDone': {
        const waiting = this.pendingScan.get(message.requestId);
        if (waiting === undefined) break;
        this.pendingScan.delete(message.requestId);
        if (message.cancelled) { waiting.settle({ status: 'cancelled' }); break; }
        if (message.message !== null || message.bits === null) {
          waiting.settle({
            status: 'failed',
            message: message.message ?? 'the scan produced no result',
          });
          break;
        }
        // `fromBytes` seals, and throws if the bitmap is the wrong size for
        // the frame count - which would be the two ends disagreeing about the
        // layout rather than anything the user did.
        try {
          waiting.settle({
            status: 'done',
            matches: MatchSet.fromBytes(message.frameCount, message.bits),
            frameCount: message.frameCount,
          });
        } catch (error) {
          waiting.settle({
            status: 'failed',
            message: error instanceof Error ? error.message : String(error),
          });
        }
        break;
      }
      case 'failure':
        if (message.fatal) {
          this.disabled = true;
          // A store that will never work must not leave a restore waiting on
          // it. Everything in flight is answered with nothing, which every
          // caller here already treats as "this capture holds none of that".
          this.settleAll();
        }
        this.update({ error: message.message });
        break;
    }
  }

  /**
   * Bumped every time the store is pointed at a different capture - `begin`,
   * `reopen`, `discard`. Something that reads the store across many requests
   * (an export) remembers it and stops if it moves, because every answer after
   * that is about another capture (`export/exportFrames.guardedReader`).
   */
  private openGeneration = 0;

  get generation(): number {
    return this.openGeneration;
  }

  /** Starts a capture. One Start->Stop cycle is one capture directory. */
  begin(captureId: string): void {
    this.openGeneration++;
    if (!captureStoreAvailable()) return;
    this.settleAll();
    this.state = freshCaptureStorageState();
    this.send({ type: 'open', captureId });
  }

  /**
   * Hands a flush's frames over.
   *
   * Called from `prepareBatch`'s persist effect, which runs exactly once per
   * flush even under StrictMode's double invoke - the reason that half of the
   * flush is split out at all.
   */
  append(packets: readonly Packet[]): void {
    if (packets.length === 0) return;
    // Flattened here, at the boundary, and not before: the buffer wants its
    // dense columns and the store cannot have them, because a class instance
    // does not survive a structured clone. `storePacket.ts` says what that
    // cost when it was not done.
    this.send({ type: 'append', packets: packets.map(plainForStore) });
  }

  /**
   * Hands over frame records for frames about to be appended (ADR 0049) - an
   * import's, which dissects on this thread. A live capture's go straight from
   * the pipeline Worker on its own port and never pass through here.
   */
  appendRecords(records: readonly { id: number; record: Uint8Array }[]): void {
    if (records.length === 0) return;
    // The record and the id, and nothing else a caller's entry carries: an
    // import's entries hold its decrypted answers too, which are never
    // written anywhere (ADR 0049), and a message clones every field it is given.
    this.send({ type: 'appendRecords', frames: records.map(({ id, record }) => ({ id, record })) });
  }

  /**
   * Hands over the patches this flush produced.
   *
   * Sent separately from the frames and immediately after them, because a
   * patch usually targets a frame from an EARLIER flush - the writer's staging
   * ring is what holds those rows back long enough to receive it.
   */
  patch(patches: readonly InfoPatch[]): void {
    if (patches.length === 0) return;
    this.send({ type: 'patches', patches: patches as InfoPatch[] });
  }

  /**
   * Sends a request and waits for the answer the store always sends.
   *
   * `settle` is registered **before** the message goes out, so an answer that
   * arrives in the same turn cannot find an empty map. `fallback` is what the
   * caller gets when there is no store at all - never when there is one that
   * has not connected yet, because every path here awaits the port first.
   */
  private async request<T>(
    pendingMap: Map<number, (value: never) => void>,
    build: (requestId: number) => ToCapture,
    fallback: T,
  ): Promise<T> {
    const port = await this.ensurePort();
    if (port === null) return fallback;
    const requestId = this.nextRequest++;
    return new Promise<T>((resolve) => {
      (pendingMap as Map<number, (value: T) => void>).set(requestId, resolve);
      port.postMessage(build(requestId));
    });
  }

  /**
   * The raw bytes of specific frames, keyed by id.
   *
   * The same contract `sessionStore.readFrameBytes` had, so `packetBytes.ts`
   * changes its import and nothing else: ids the capture does not hold are
   * absent from the map rather than an error.
   */
  readBytes(ids: readonly number[]): Promise<Map<number, Uint8Array>> {
    if (ids.length === 0) return Promise.resolve(NONE);
    return this.request(
      this.pending as never,
      (requestId) => ({ type: 'read', requestId, ids: [...ids] }),
      NONE,
    );
  }

  /**
   * The ids whose bytes are readable, or null.
   *
   * Synchronous on purpose. `bytesAreRecoverable` is asked while rendering a
   * frame that has no bytes, to say whether they are gone or merely elsewhere,
   * and an answer that arrived a promise later would make that a third state
   * the detail pane has to draw. The store pushes the range with its stats and
   * this is the last one it sent, which lags a poll behind the truth in the
   * safe direction: a frame just sealed keeps its bytes in RAM for another
   * couple of seconds, and no frame is ever dropped before it is readable.
   */
  get storedRange(): { first: number; last: number } | null { return this.state.storedRange; }

  /**
   * Opens a capture that already exists and says what is in it.
   *
   * The same `open` a fresh Start sends: recovery runs, a torn tail is
   * truncated, and the writer resumes past what survived - so a reopened
   * capture is immediately appendable as well as readable, and there is one
   * code path rather than two that have to agree.
   *
   * Null when the store is unavailable or the open failed, which the caller
   * reads as "there is nothing to restore".
   */
  reopen(captureId: string): Promise<StoredCapture | null> {
    this.openGeneration++;
    this.state = freshCaptureStorageState();
    return this.request(
      this.pendingOpen as never,
      (requestId) => ({ type: 'open', captureId, requestId }),
      null,
    );
  }

  /**
   * One chunk's rows, for a restore.
   *
   * Without `rawBytes`: a restored frame is inside the stored range, so
   * `packetBytes()` reads them back when something wants them. See
   * `CaptureReader.readRows`.
   */
  readRows(chunk: number): Promise<Packet[]> {
    return this.request(
      this.pendingRows as never,
      (requestId) => ({ type: 'chunk', requestId, chunk }),
      [] as Packet[],
    );
  }

  /**
   * The rows covering capture positions `[from, to)`.
   *
   * Whole chunks come back, so a caller that asks for forty rows is handed the
   * four thousand around them and should cache what it gets - which is what
   * `useCaptureRows` does.
   */
  readRowsAt(from: number, to: number): Promise<RowBlock[]> {
    if (to <= from) return Promise.resolve([]);
    return this.request(
      this.pendingBlocks as never,
      (requestId) => ({ type: 'rowsAt', requestId, from, to }),
      [] as RowBlock[],
    );
  }

  /**
   * The rows at scattered positions, keyed by position.
   *
   * What a **filtered** list reads. `readRowsAt` walks forward returning whole
   * chunks, which is the wrong shape once the rows on screen are the matches
   * of a filter rather than a run of the capture - see the protocol's
   * `rowsForOrdinals`.
   *
   * Positions the capture cannot place are absent from the map rather than an
   * error, the same contract `readBytes` has.
   */
  readRowsFor(ordinals: readonly number[]): Promise<Map<number, Packet>> {
    if (ordinals.length === 0) return Promise.resolve(NO_ROWS);
    return this.request(
      this.pendingScattered as never,
      (requestId) => ({ type: 'rowsForOrdinals', requestId, ordinals: [...ordinals] }),
      NO_ROWS,
    );
  }

  /**
   * Where a frame sits in the capture, or -1.
   *
   * -1 means "not addressable yet" - a frame in a hole, one still staged
   * behind the patch horizon, or no capture open - and every caller reads it
   * as "show the RAM window alone", which is what the list did before any of
   * this existed.
   */
  ordinalOf(id: number): Promise<number> {
    return this.request(
      this.pendingLocate as never,
      (requestId) => ({ type: 'locate', requestId, id }),
      -1,
    );
  }

  /**
   * Runs a display filter over the whole capture on disk.
   *
   * The expression travels, not a predicate - a compiled filter is a closure.
   * The store compiles it with the same `filter/compile.ts` this process would
   * have used, which is the whole reason there is one answer rather than two.
   *
   * Returns immediately with a handle. `cancel()` is safe before the port has
   * even resolved: the scan is simply never started, and `result` settles
   * `cancelled`.
   */
  scanCapture(
    filter: string,
    onProgress?: (progress: ScanProgressUpdate) => void,
  ): ScanHandle {
    let cancelled = false;
    let requestId: number | null = null;

    const result = (async (): Promise<ScanOutcome> => {
      const port = await this.ensurePort();
      if (port === null) {
        return { status: 'failed', message: 'there is no capture store to scan' };
      }
      // Checked after the await as well as before sending: a cancel that
      // arrived while the port was still coming has nothing to cancel, and
      // starting the scan anyway would leave it running with no reader.
      if (cancelled) return { status: 'cancelled' };
      const id = this.nextRequest++;
      requestId = id;
      return new Promise<ScanOutcome>((settle) => {
        this.pendingScan.set(id, { onProgress, settle });
        port.postMessage({ type: 'scan', requestId: id, filter });
      });
    })();

    return {
      result,
      cancel: () => {
        if (cancelled) return;
        cancelled = true;
        if (requestId !== null) this.send({ type: 'scanCancel', requestId });
      },
    };
  }

  /** Deletes every capture directory but these. See the protocol's `prune`. */
  prune(keep: readonly string[]): void { this.send({ type: 'prune', keep: [...keep] }); }

  /** Seals the staging ring and flushes. Pause, stop, and page hide. */
  finish(): void { this.send({ type: 'finish' }); }

  askForStats(): void { this.send({ type: 'stats' }); }

  discard(captureId: string): void {
    this.openGeneration++;
    this.send({ type: 'discard', captureId });
    this.settleAll();
    this.state = freshCaptureStorageState();
    this.onState(this.state);
  }

  private settleAll(): void {
    for (const settle of this.pending.values()) settle(NONE);
    this.pending.clear();
    for (const settle of this.pendingRows.values()) settle([]);
    this.pendingRows.clear();
    for (const settle of this.pendingOpen.values()) settle(null);
    this.pendingOpen.clear();
    for (const settle of this.pendingBlocks.values()) settle([]);
    this.pendingBlocks.clear();
    for (const settle of this.pendingScattered.values()) settle(NO_ROWS);
    this.pendingScattered.clear();
    for (const settle of this.pendingLocate.values()) settle(-1);
    this.pendingLocate.clear();
    // `failed` rather than `cancelled`: the store went away, which is not the
    // user's doing and is worth saying.
    for (const waiting of this.pendingScan.values()) {
      waiting.settle({ status: 'failed', message: 'the capture store stopped' });
    }
    this.pendingScan.clear();
  }

  get snapshot(): CaptureStorageState { return this.state; }
}

/**
 * One per page, like `pipelineClient`.
 *
 * A module singleton rather than something threaded through props: the flush
 * calls it from inside `prepareBatch`'s effect, which is deliberately not a
 * React-shaped place.
 */
export const captureStore = new CaptureClient();

/**
 * Re-exported from `captureDirectory.ts`, which is where it now lives.
 *
 * The generator moved to sit beside the pattern that validates it: `prune`
 * refuses to delete a directory whose name this app did not choose, and a
 * guard that can drift from the generator is not a guard.
 */
export { newCaptureId } from './captureDirectory';
