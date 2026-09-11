/**
 * The app's handle on the capture worker.
 *
 * Shaped like `services/pipelineClient.ts` - one object, callbacks assigned
 * rather than an event emitter, the worker built lazily on first use - because
 * a second thing that talks to a worker should not invent a second way of
 * doing it.
 *
 * ## Shadow write
 *
 * Nothing reads from OPFS yet. This runs **beside** the IndexedDB store, so a
 * refresh still restores the way it always has and the new path can be watched
 * on a real capture before anything depends on it. IndexedDB goes when the read
 * path arrives, not before.
 *
 * The cost of that overlap is honest and worth naming: every frame is
 * structured-cloned once more, on the main thread, to reach this worker. ADR
 * 0007 measured a `Packet` clone at 5.1 us, so at 35,000 frames a second that
 * is around 178 ms of main-thread time per second of capture. The main thread
 * already pays a per-frame serialisation for IndexedDB today and that one goes
 * away in the same step this one stops being a shadow, so the overlap is
 * temporary in both directions - but it is the number to measure on a real
 * capture before deciding whether the pipeline worker should hand frames over
 * directly instead.
 */
import type { Packet } from '../../types/packet';
import type { InfoPatch } from '../dissect/types';
import type { ToCapture, FromCapture, CaptureStorageState } from './captureProtocol';
import { freshCaptureStorageState } from './captureProtocol';

/** What a reopened capture turned out to hold. */
export interface StoredCapture {
  captureId: string;
  frameCount: number;
  chunkCount: number;
  /** The highest stored id, so `packetGenerator` resumes past it. */
  lastId: number;
}

/** True when this browser can host the capture store at all. */
export function opfsAvailable(): boolean {
  return typeof navigator !== 'undefined'
    && typeof navigator.storage?.getDirectory === 'function'
    && typeof Worker !== 'undefined';
}

/** Bytes a request could not be answered with. Shared, never written to. */
const NONE = new Map<number, Uint8Array>();

class CaptureClient {
  private worker: Worker | null = null;
  private state: CaptureStorageState = freshCaptureStorageState();
  /** Set once a failure makes the store unusable, so nothing keeps trying. */
  private disabled = false;
  /** In-flight byte reads, by request id. The worker always answers. */
  private readonly pending = new Map<number, (frames: Map<number, Uint8Array>) => void>();
  /** In-flight row reads and reopens, same rule. */
  private readonly pendingRows = new Map<number, (packets: Packet[]) => void>();
  private readonly pendingOpen = new Map<number, (ready: StoredCapture | null) => void>();
  private nextRequest = 1;

  onState: (state: CaptureStorageState) => void = () => {};

  private ensureWorker(): Worker | null {
    if (this.disabled || !opfsAvailable()) return null;
    if (this.worker) return this.worker;
    const worker = new Worker(new URL('../../workers/capture.worker.ts', import.meta.url), {
      type: 'module',
      name: 'inwire-capture',
    });
    worker.onmessage = (event: MessageEvent<FromCapture>) => this.receive(event.data);
    worker.onerror = (event) => {
      // A worker that failed to start is not a reason to stop capturing - the
      // in-memory buffer and IndexedDB are both untouched by this - so it
      // disables itself and says so rather than throwing into the flush.
      this.disabled = true;
      this.update({ error: event.message || 'the capture store failed to start' });
      // Whoever was waiting on a read gets an empty answer rather than a
      // promise that never settles: a frame whose bytes cannot be fetched is a
      // thing to render, and the hex viewer already knows how to say so.
      this.settleAll();
    };
    this.worker = worker;
    return worker;
  }

  private send(message: ToCapture): void {
    this.ensureWorker()?.postMessage(message);
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
          persisted: message.persisted,
          quotaBytes: message.quotaBytes,
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

  /** Starts a capture. One Start->Stop cycle is one capture directory. */
  begin(captureId: string): void {
    if (!opfsAvailable()) return;
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
    this.send({ type: 'append', packets: packets as Packet[] });
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
   * The raw bytes of specific frames, keyed by id.
   *
   * The same contract `sessionStore.readFrameBytes` had, so `packetBytes.ts`
   * changes its import and nothing else: ids the capture does not hold are
   * absent from the map rather than an error.
   */
  readBytes(ids: readonly number[]): Promise<Map<number, Uint8Array>> {
    if (ids.length === 0) return Promise.resolve(NONE);
    const worker = this.ensureWorker();
    if (worker === null) return Promise.resolve(NONE);
    const requestId = this.nextRequest++;
    return new Promise((resolve) => {
      this.pending.set(requestId, resolve);
      worker.postMessage({ type: 'read', requestId, ids: [...ids] } satisfies ToCapture);
    });
  }

  /**
   * The ids whose bytes are readable, or null.
   *
   * Synchronous on purpose. `bytesAreRecoverable` is asked while rendering a
   * frame that has no bytes, to say whether they are gone or merely elsewhere,
   * and an answer that arrived a promise later would make that a third state
   * the detail pane has to draw. The worker pushes the range with its stats and
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
    const worker = this.ensureWorker();
    if (worker === null) return Promise.resolve(null);
    this.state = freshCaptureStorageState();
    const requestId = this.nextRequest++;
    return new Promise((resolve) => {
      this.pendingOpen.set(requestId, resolve);
      worker.postMessage({ type: 'open', captureId, requestId } satisfies ToCapture);
    });
  }

  /**
   * One chunk's rows, for a restore.
   *
   * Without `rawBytes`: a restored frame is inside the stored range, so
   * `packetBytes()` reads them back when something wants them. See
   * `CaptureReader.readRows`.
   */
  readRows(chunk: number): Promise<Packet[]> {
    const worker = this.ensureWorker();
    if (worker === null) return Promise.resolve([]);
    const requestId = this.nextRequest++;
    return new Promise((resolve) => {
      this.pendingRows.set(requestId, resolve);
      worker.postMessage({ type: 'chunk', requestId, chunk } satisfies ToCapture);
    });
  }

  /** Deletes every capture directory but these. See the protocol's `prune`. */
  prune(keep: readonly string[]): void { this.send({ type: 'prune', keep: [...keep] }); }

  /** Seals the staging ring and flushes. Pause, stop, and page hide. */
  finish(): void { this.send({ type: 'finish' }); }

  askForStats(): void { this.send({ type: 'stats' }); }

  discard(captureId: string): void {
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

/** A capture's directory name: sortable, unique, and readable in a listing. */
export function newCaptureId(at: Date = new Date()): string {
  const pad = (n: number, width = 2) => String(n).padStart(width, '0');
  const stamp = `${at.getFullYear()}${pad(at.getMonth() + 1)}${pad(at.getDate())}`
    + `-${pad(at.getHours())}${pad(at.getMinutes())}${pad(at.getSeconds())}`;
  const suffix = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0');
  return `cap-${stamp}-${suffix}`;
}
