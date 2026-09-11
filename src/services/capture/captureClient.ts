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

/** True when this browser can host the capture store at all. */
export function opfsAvailable(): boolean {
  return typeof navigator !== 'undefined'
    && typeof navigator.storage?.getDirectory === 'function'
    && typeof Worker !== 'undefined';
}

class CaptureClient {
  private worker: Worker | null = null;
  private state: CaptureStorageState = freshCaptureStorageState();
  /** Set once a failure makes the store unusable, so nothing keeps trying. */
  private disabled = false;

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
      case 'ready':
        this.update({
          captureId: message.captureId,
          persisted: message.persisted,
          quotaBytes: message.quotaBytes,
          error: null,
        });
        break;
      case 'stats':
        this.update({
          framesWritten: message.stats.framesWritten,
          patchesMissed: message.stats.patchesMissed,
          bytesOnDisk: message.bytesOnDisk,
          stagedCount: message.stagedCount,
        });
        break;
      case 'failure':
        if (message.fatal) this.disabled = true;
        this.update({ error: message.message });
        break;
    }
  }

  /** Starts a capture. One Start->Stop cycle is one capture directory. */
  begin(captureId: string): void {
    if (!opfsAvailable()) return;
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

  /** Seals the staging ring and flushes. Pause, stop, and page hide. */
  finish(): void { this.send({ type: 'finish' }); }

  askForStats(): void { this.send({ type: 'stats' }); }

  discard(captureId: string): void { this.send({ type: 'discard', captureId }); }

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
