/**
 * The capture store's message routing, with no idea where it is running.
 *
 * ## Why this is not in the process that hosts it
 *
 * It used to be `src/workers/capture.worker.ts`, whose header set the rule
 * this file inherits: *"As little as possible. Everything with a decision in
 * it - the chunk codec, the index, the recovery rule, the patch horizon -
 * lives in `services/capture/` and is driven from Node against a
 * `MemoryBlockFile`… If something here starts deciding anything, it belongs
 * below."*
 *
 * The routing turned out to be one of those things. It decides when a capture
 * is closed, what happens to an append that arrives with no capture open,
 * whether a failed read still answers its request, and which directories a
 * prune is allowed to touch - and every one of those has a silent failure
 * behind it. `scripts/electron/store-protocol.ts` drives the whole message
 * union through this class under plain Node.
 *
 * So `electron/store/entry.ts` is the adapter: it supplies a `CaptureVolume`
 * over `node:fs` and a `post` that writes to a `MessagePort`, and holds no
 * logic of its own.
 *
 * ## Everything here is synchronous now
 *
 * OPFS made `open` deeply asynchronous - a directory handle, four file
 * handles, four `createSyncAccessHandle()` calls - and that asynchrony cost
 * 500 frames on a real capture before `serialQueue` was written, because an
 * `append` overtook the `open` it depended on. Opening files is a synchronous
 * call now, so the race is gone.
 *
 * The queue stays anyway, and deliberately: the guarantee should not rest on
 * every handler *remaining* synchronous for ever. It costs one promise per
 * message and it is the difference between an ordering rule and a habit.
 */
import { CaptureWriter, type CaptureFiles } from './captureWriter';
import { CaptureReader } from './captureReader';
import { recoverIndex } from './captureIndex';
import { planPrune } from './captureDirectory';
import { serialQueue } from './serialQueue';
import { inflateSync } from 'fflate';
import type { FromCapture, ToCapture } from './captureProtocol';
import type { Packet } from '../../types/packet';

/** A capture's four files, and the handles behind them. */
export interface OpenVolume extends CaptureFiles {
  close(): void;
}

/**
 * Where captures live, and what can be done to them.
 *
 * The whole of the host's contact with a filesystem. A test supplies one over
 * `MemoryBlockFile` and a `Map`; `electron/store/entry.ts` supplies one over
 * `node:fs`.
 */
export interface CaptureVolume {
  /** The directory holding every capture, for the panel to show. */
  readonly directory: string;
  /** Opens (creating if absent) one capture's four files. */
  open(captureId: string): OpenVolume;
  /** Every entry currently in the capture directory, capture or not. */
  list(): string[];
  /** Removes one capture directory and everything in it. */
  remove(captureId: string): void;
  /** Free space on the volume, or null when it cannot be read. */
  freeBytes(): number | null;
}

interface OpenCapture {
  id: string;
  volume: OpenVolume;
  writer: CaptureWriter;
  reader: CaptureReader;
}

export class CaptureHost {
  private open: OpenCapture | null = null;
  /** Said once, so a wiring error is reported without becoming a stream. */
  private orphanedAppend = false;
  private readonly queue = serialQueue((error) => this.fail(describe(error), false));

  constructor(
    private readonly volume: CaptureVolume,
    private readonly post: (message: FromCapture) => void,
  ) {}

  /** Queues a message. Handling is serialised; see the module header. */
  receive(message: ToCapture): void {
    this.queue.run(() => this.handle(message));
  }

  /** Resolves once every queued message has been handled. For tests. */
  drain(): Promise<void> {
    return this.queue.drain();
  }

  /** Seals and releases whatever is open. For shutdown. */
  close(): void {
    this.closeOpen();
  }

  private fail(message: string, fatal: boolean): void {
    // Never silent. A storage layer that fails quietly is exactly the failure
    // `sessionStore`'s budget comment existed to prevent, and the thing that
    // fails here is usually the disk filling.
    this.post({ type: 'failure', message, fatal });
  }

  private closeOpen(): void {
    if (this.open === null) return;
    try { this.open.writer.finish(); } catch { /* a failed finish must not leak handles */ }
    try { this.open.volume.close(); } catch { /* already gone */ }
    this.open = null;
  }

  private bytesOnDisk(capture: OpenCapture): number {
    return capture.volume.index.size() + capture.volume.pfx.size()
      + capture.volume.sum.size() + capture.volume.byt.size();
  }

  private reportStats(): void {
    if (this.open === null) return;
    this.post({
      type: 'stats',
      stats: { ...this.open.writer.stats },
      stagedCount: this.open.writer.stagedCount,
      bytesOnDisk: this.bytesOnDisk(this.open),
      freeBytes: this.volume.freeBytes(),
      storedRange: this.open.writer.index.idRange(),
    });
  }

  private handle(message: ToCapture): void {
    try {
      switch (message.type) {
        case 'open': return this.onOpen(message);
        case 'append': return this.onAppend(message);
        case 'patches': {
          this.open?.writer.applyPatches(message.patches);
          return;
        }
        case 'finish': {
          if (this.open === null) return;
          this.open.writer.finish();
          this.reportStats();
          return;
        }
        case 'read': return this.onRead(message);
        case 'chunk': return this.onChunk(message);
        case 'rowsAt': return this.onRowsAt(message);
        case 'locate': return this.onLocate(message);
        case 'prune': return this.onPrune(message);
        case 'discard': return this.onDiscard(message);
        case 'stats': return this.reportStats();
      }
    } catch (error) {
      this.fail(describe(error), message.type === 'open');
    }
  }

  private onOpen(message: Extract<ToCapture, { type: 'open' }>): void {
    this.closeOpen();
    this.orphanedAppend = false;

    const volume = this.volume.open(message.captureId);
    // Recovery before the writer, not after. A crash can leave data past the
    // last index record, and a writer that appended to it would put its chunk
    // where nothing can find it and every offset after it wrong.
    const { records, plan } = recoverIndex(volume.index, volume.pfx, volume.sum, volume.byt);
    volume.pfx.truncate(plan.pfxLength);
    volume.sum.truncate(plan.sumLength);
    volume.byt.truncate(plan.bytLength);
    volume.index.truncate(plan.indexLength);

    const writer = new CaptureWriter(volume, { resumeFrom: records.slice(0, plan.keepRecords) });
    // The reader shares the writer's index, so a chunk is readable the moment
    // its record is appended rather than only after the file is re-read.
    const reader = new CaptureReader(volume, writer.index, inflateSync);
    this.open = { id: message.captureId, volume, writer, reader };

    if (plan.framesLost > 0) {
      this.fail(`${plan.framesLost} frames were lost to a torn tail and have been discarded`, false);
    }

    const range = writer.index.idRange();
    this.post({
      type: 'ready',
      captureId: message.captureId,
      freeBytes: this.volume.freeBytes(),
      captureDir: this.volume.directory,
      frameCount: writer.index.frameCount,
      chunkCount: writer.index.chunkCount,
      lastId: range === null ? 0 : range.last,
      ...(message.requestId === undefined ? {} : { requestId: message.requestId }),
    });
  }

  private onAppend(message: Extract<ToCapture, { type: 'append' }>): void {
    if (this.open === null) {
      // Ordering is guaranteed by the queue, so this can only mean the app
      // appended without starting - a wiring error rather than a race. It was
      // silent once and cost 500 frames; it does not get to be silent again.
      if (!this.orphanedAppend) {
        this.orphanedAppend = true;
        this.fail(`${message.packets.length} frames arrived before a capture was opened`, false);
      }
      return;
    }
    this.open.writer.append(message.packets);
  }

  /**
   * Every request-shaped message answers, even when it fails.
   *
   * The caller holds a promise per request. A silent drop leaves the hex
   * viewer spinning for the life of the window, which is worse than an empty
   * answer in every case.
   */
  private onRead(message: Extract<ToCapture, { type: 'read' }>): void {
    let frames: [number, Uint8Array][] = [];
    try {
      if (this.open !== null) frames = [...this.open.reader.readBytes(message.ids)];
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'bytes', requestId: message.requestId, frames });
  }

  private onChunk(message: Extract<ToCapture, { type: 'chunk' }>): void {
    let packets: Packet[] = [];
    try {
      if (this.open !== null) packets = this.open.reader.readRows(message.chunk);
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'rows', requestId: message.requestId, packets });
  }

  private onRowsAt(message: Extract<ToCapture, { type: 'rowsAt' }>): void {
    let blocks: { firstOrdinal: number; packets: Packet[] }[] = [];
    try {
      if (this.open !== null) blocks = this.open.reader.readRowsAt(message.from, message.to);
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'blocks', requestId: message.requestId, blocks });
  }

  private onLocate(message: Extract<ToCapture, { type: 'locate' }>): void {
    let ordinal = -1;
    try {
      if (this.open !== null) ordinal = this.open.reader.ordinalOf(message.id);
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'located', requestId: message.requestId, ordinal });
  }

  /**
   * Removes every capture but the ones named.
   *
   * `planPrune` decides, and refuses anything this app did not name. On a real
   * filesystem this is a recursive delete of a directory a person can open,
   * and it runs at startup with an **empty** keep list whenever the stored
   * session names no capture - see `captureDirectory.ts`.
   */
  private onPrune(message: Extract<ToCapture, { type: 'prune' }>): void {
    const plan = planPrune(this.volume.list(), message.keep);
    for (const name of plan.remove) {
      if (this.open?.id === name) this.closeOpen();
      try {
        this.volume.remove(name);
      } catch (error) {
        // Windows refuses to remove a directory with an open handle in it, and
        // an antivirus scanner will hold one occasionally. Reported and left
        // for the next launch rather than aborting the rest of the prune.
        this.fail(`could not remove ${name}: ${describe(error)}`, false);
      }
    }
    if (plan.foreign.length > 0) {
      this.fail(
        `${plan.foreign.length} entries in the capture directory are not captures `
        + 'and were left alone',
        false,
      );
    }
  }

  private onDiscard(message: Extract<ToCapture, { type: 'discard' }>): void {
    if (this.open?.id === message.captureId) this.closeOpen();
    this.volume.remove(message.captureId);
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
