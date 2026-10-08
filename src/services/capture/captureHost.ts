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
 * behind it. `scripts/capture/store-protocol.ts` drives the whole message
 * union through this class under plain Node.
 *
 * ## The scan is the one long-running message
 *
 * Everything else here is one request and one reply. A `scan` runs for
 * seconds, in slices, so that the byte reads and row reads the reader is still
 * issuing get served in between - see `captureScan.ts` for why the slice is a
 * whole chunk. The state that makes that safe is `running`, and the rule it
 * enforces is that a scan settles exactly once: superseded, cancelled, its
 * capture closed underneath it, or finished.
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
import { CaptureWriter, dataFilesOf, type CaptureFiles } from './captureWriter';
import { CaptureReader } from './captureReader';
import { recoverCapture, type CaptureIndex } from './captureIndex';
import { planPrune } from './captureDirectory';
import { serialQueue } from './serialQueue';
import { CaptureScan, DEFAULT_SLICE_MS } from './captureScan';
import { compile } from '../filter/compile';
import { inflateSync } from 'fflate';
import type { FromCapture, ToCapture } from './captureProtocol';
import type { Packet } from '../../types/packet';
import { recordRefs } from '../dissect/recordHeader';

/** A capture's files - its index, its data, its segments - and the handles behind them. */
export interface OpenVolume extends CaptureFiles {
  /** Closes every handle, the segments' included. */
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
  /** The floor the app was last told of. */
  floorChunk: number;
}

/**
 * Frames between progress messages.
 *
 * A slice is 12 ms, so reporting per slice is 83 messages a second describing
 * a bar nobody can read at that rate. A chunk is 4,096 frames and the scan
 * runs at ~0.6M frames a second, so this is roughly four a second.
 */
export const SCAN_PROGRESS_FRAMES = 150_000;

interface RunningScan {
  requestId: number;
  scan: CaptureScan;
  /**
   * Which capture it is scanning.
   *
   * Checked before every slice. A scan holds a `CaptureReader` over files the
   * host may close underneath it - a prune, a discard, or simply starting the
   * next capture - and a slice that ran afterwards would read a closed handle.
   */
  captureId: string;
  /** `framesDone` when progress was last posted. */
  reported: number;
}

export interface CaptureHostOptions {
  scanSliceMs?: number;
  /**
   * How a sealed chunk is compressed, and read back. Raw DEFLATE either way,
   * so a capture written with one reads with the other.
   *
   * Injected because this module imports no `node:*` (`node-safe.ts`), and
   * the store's process is the one place the native zlib is there to be had:
   * `electron/store/entry.ts` passes it. It is not a nicety - compressing the
   * chunk was 57% of the writer's time in `fflate`'s JavaScript, and the store
   * falling behind a 36,000 frame-a-second burst is what filled its heap
   * (`scripts/perf/store-boundary.ts` has the numbers).
   */
  deflate?: (bytes: Uint8Array) => Uint8Array;
  inflate?: (bytes: Uint8Array) => Uint8Array;
}

export class CaptureHost {
  private open: OpenCapture | null = null;
  /** Said once, so a wiring error is reported without becoming a stream. */
  private orphanedAppend = false;
  private running: RunningScan | null = null;
  private readonly queue = serialQueue((error) => this.fail(describe(error), false));

  /**
   * How long one scan slice may run. `0` is one chunk a slice.
   *
   * Settable for the same reason `CaptureWriter` takes `horizonUs`: the
   * interleaving this exists to provide - a read answered while a scan is
   * still going - is only assertable when the slices are countable. On a
   * synthetic capture a default slice swallows the whole scan and the test
   * would pass whether or not the yield happened.
   */
  private readonly scanSliceMs: number;
  private readonly deflate: ((bytes: Uint8Array) => Uint8Array) | undefined;
  private readonly inflate: (bytes: Uint8Array) => Uint8Array;

  constructor(
    private readonly volume: CaptureVolume,
    private readonly post: (message: FromCapture) => void,
    options: CaptureHostOptions = {},
  ) {
    this.scanSliceMs = options.scanSliceMs ?? DEFAULT_SLICE_MS;
    this.deflate = options.deflate;
    this.inflate = options.inflate ?? inflateSync;
  }

  /**
   * Queues a message. Handling is serialised; see the module header.
   *
   * `reply` is where an answer to THIS message goes, when it is not the client
   * port - the pipeline Worker asks for revisit kits on its own port, and the
   * answer must come back down that one. Failures still go to `post`, which is
   * the channel the app watches for them.
   */
  receive(message: ToCapture, reply?: (message: FromCapture) => void): void {
    this.queue.run(() => {
      this.handle(message, reply ?? this.post);
      this.reportFloor();
    });
  }

  /**
   * Tells the app the capture's floor moved - a ring deleted a file and the
   * segments holding its frames went with it (ADR 0052). Asked after every
   * message rather than only after `ringDeleted`, because a segment waiting
   * for its last chunk to seal goes when that chunk does, on whichever message
   * sealed it.
   */
  private reportFloor(): void {
    const open = this.open;
    if (open === null || open.writer.index.floorChunk === open.floorChunk) return;
    open.floorChunk = open.writer.index.floorChunk;
    this.post({
      type: 'floor',
      floorOrdinal: open.writer.index.floorOrdinal,
      floorId: floorIdOf(open.writer.index),
      storedRange: open.writer.index.idRange(),
    });
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
    // Before the handles go, not after: a scan slice scheduled behind this
    // would otherwise read from a closed file - and when the SAME capture is
    // reopened, the slice loop's id check sees a match and carries on.
    this.abandonScan();
    if (this.open === null) return;
    try { this.open.writer.finish(); } catch { /* a failed finish must not leak handles */ }
    try { this.open.volume.close(); } catch { /* already gone */ }
    this.open = null;
  }

  private bytesOnDisk(capture: OpenCapture): number {
    const { volume } = capture;
    let total = volume.index.size();
    for (const segment of [0, ...(volume.segments?.list() ?? [])]) {
      const data = dataFilesOf(volume, segment);
      if (data !== null) total += data.pfx.size() + data.sum.size() + data.byt.size() + data.rec.size();
    }
    return total;
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

  private handle(message: ToCapture, reply: (message: FromCapture) => void): void {
    try {
      switch (message.type) {
        case 'open': return this.onOpen(message);
        case 'append': return this.onAppend(message);
        case 'appendBytes': return this.onAppendBytes(message, reply);
        case 'appendRecords': {
          this.open?.writer.attachRecords(message.frames);
          return;
        }
        case 'revisitKit': return this.onRevisitKit(message, reply);
        case 'patches': {
          this.open?.writer.applyPatches(message.patches);
          return;
        }
        case 'ringDeleted': {
          this.open?.writer.ringDeleted(message.epoch, message.lastSeq);
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
        case 'rowsForOrdinals': return this.onRowsForOrdinals(message);
        case 'locate': return this.onLocate(message);
        case 'scan': return this.onScan(message);
        case 'scanCancel': return this.onScanCancel(message);
        case 'prune': return this.onPrune(message);
        case 'discard': return this.onDiscard(message);
        case 'stats': return this.reportStats();
      }
    } catch (error) {
      // The stack goes to stderr as well as the message to the app, and that
      // is not belt and braces - it is the difference between an afternoon and
      // five minutes. `encodeChunk` threw on every `append` for the life of
      // every capture, and all anyone could see was `state.error` reading
      // "block.read is not a function" in a panel nobody had open. Main pipes
      // this into a log a person can be asked for.
      console.error(`[inwire] the capture store failed to handle ${message.type}: `
        + `${error instanceof Error ? `${error.message}\n${error.stack}` : String(error)}`);
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
    const { records, plan } = recoverCapture(volume.index, (n) => dataFilesOf(volume, n));
    for (const [segment, sizes] of plan.truncate) {
      const data = dataFilesOf(volume, segment);
      if (data === null) continue;
      data.pfx.truncate(sizes.pfx);
      data.sum.truncate(sizes.sum);
      data.byt.truncate(sizes.byt);
      data.rec.truncate(sizes.rec);
    }
    // A segment no kept chunk is in: below the floor, which a crash kept from
    // being deleted after the floor was written, or past the torn tail.
    for (const segment of volume.segments?.list() ?? []) {
      if (!plan.truncate.has(segment)) volume.segments!.remove(segment);
    }
    volume.index.truncate(plan.indexLength);

    const writer = new CaptureWriter(volume, {
      resumeFrom: records.slice(0, plan.keepRecords),
      floorChunk: plan.floorChunk,
      ...(this.deflate !== undefined ? { deflate: this.deflate } : {}),
    });
    // The reader shares the writer's index, so a chunk is readable the moment
    // its record is appended rather than only after the file is re-read.
    const reader = new CaptureReader(volume, writer.index, this.inflate);
    this.open = { id: message.captureId, volume, writer, reader, floorChunk: writer.index.floorChunk };

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
      floorOrdinal: writer.index.floorOrdinal,
      floorId: floorIdOf(writer.index),
      storedRange: range,
      // The newest chunk's, held or not: numbering resumes past every id the
      // capture ever used, even when a ring has taken all of them.
      lastId: writer.index.chunkCount === 0 ? 0 : writer.index.record(writer.index.chunkCount - 1).lastId,
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
   * Frame bytes, straight off the capture path.
   *
   * **Silently ignored when no capture is open, unlike `append` above**, and
   * the difference is which side is wrong. `append` comes from the app, which
   * knows whether it started a capture, so an orphan there is a wiring error
   * worth shouting about - it was silent once and cost 500 frames. These come
   * from the agent's own stream, which keeps arriving for a beat after a stop
   * because the pipe is in flight; treating that as a fault would fire the
   * alarm on every single capture that ends.
   */
  private onAppendBytes(
    message: Extract<ToCapture, { type: 'appendBytes' }>,
    reply: (message: FromCapture) => void,
  ): void {
    try {
      if (this.open !== null) this.open.writer.appendBytes(message.frames);
    } finally {
      // In a `finally`: a throw is reported by `handle` on the client port,
      // and the Worker must still hear that the append is no longer owed.
      if (message.ack !== undefined) reply({ type: 'bytesTaken', ack: message.ack });
    }
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

  /**
   * One frame's revisit kit (ADR 0049): its record, its row, and the bytes of
   * it and of every frame its record names - in one answer, because a revisit
   * that had to come back for each referenced frame would pay a round trip per
   * TLS segment a record spans.
   *
   * A frame still staged is answered from the writer, which holds the newest
   * `horizonFrames` of them; everything else from the reader. Answers like
   * every request here, even when it fails: an empty kit, which the Worker
   * reads as "build this tree another way".
   */
  private onRevisitKit(
    message: Extract<ToCapture, { type: 'revisitKit' }>,
    reply: (message: FromCapture) => void,
  ): void {
    let record: Uint8Array | null = null;
    let row: Packet | null = null;
    const frames = new Map<number, Uint8Array>();
    try {
      const open = this.open;
      if (open !== null) {
        const staged = open.writer.stagedFrame(message.id);
        if (staged !== null) {
          record = staged.record;
          row = staged.packet;
        } else {
          record = open.reader.readRecord(message.id);
          const ordinal = open.reader.ordinalOf(message.id);
          if (ordinal >= 0) row = open.reader.readRowsFor([ordinal]).get(ordinal) ?? null;
        }
        const wanted = [message.id, ...(record === null ? [] : recordRefs(record))];
        const sealed: number[] = [];
        for (const id of wanted) {
          const bytes = open.writer.stagedFrame(id)?.bytes ?? null;
          if (bytes !== null) frames.set(id, bytes);
          else sealed.push(id);
        }
        for (const [id, bytes] of open.reader.readBytes(sealed)) frames.set(id, bytes);
      }
    } catch (error) {
      this.fail(describe(error), false);
      record = null;
      row = null;
      frames.clear();
    }
    reply({ type: 'revisitKit', requestId: message.requestId, record, row, frames: [...frames] });
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
    let blocks: { firstOrdinal: number; packets: Packet[]; linkTypesStored: boolean }[] = [];
    try {
      if (this.open !== null) blocks = this.open.reader.readRowsAt(message.from, message.to);
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'blocks', requestId: message.requestId, blocks });
  }

  private onRowsForOrdinals(
    message: Extract<ToCapture, { type: 'rowsForOrdinals' }>,
  ): void {
    let rows: [number, Packet][] = [];
    try {
      if (this.open !== null) {
        rows = [...this.open.reader.readRowsFor(message.ordinals)];
      }
    } catch (error) {
      this.fail(describe(error), false);
    }
    this.post({ type: 'rowsByOrdinal', requestId: message.requestId, rows });
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
   * Starts a filter scan over the whole capture.
   *
   * The expression is compiled **here**, with the renderer's own compiler, for
   * the reason `captureScan.ts` opens with: a second evaluator would be a
   * second answer, silently disagreeing on exactly the frames nobody can see
   * to check.
   *
   * Every exit answers. A filter that does not compile, a capture that is not
   * open, a read that throws mid-scan - each posts `scanDone` with a message,
   * because the caller is holding a promise and a filter bar that spins
   * forever is worse than one that says why.
   */
  private onScan(message: Extract<ToCapture, { type: 'scan' }>): void {
    // A newer filter supersedes the one in flight. Answered as cancelled, so
    // its caller settles rather than waiting on a scan nobody wants.
    this.abandonScan();

    if (this.open === null) {
      this.endScan(message.requestId, 0, null, false, 'no capture is open');
      return;
    }

    let predicate;
    try {
      predicate = compile(message.filter);
    } catch (error) {
      this.endScan(message.requestId, 0, null, false, describe(error));
      return;
    }

    // The writer's index, not one re-read from the file: a chunk is scannable
    // the moment its record is appended, which is the same sharing the reader
    // relies on.
    const scan = new CaptureScan(this.open.reader, this.open.writer.index, predicate);
    this.running = {
      requestId: message.requestId, scan, captureId: this.open.id, reported: 0,
    };
    this.stepScan();
  }

  private onScanCancel(message: Extract<ToCapture, { type: 'scanCancel' }>): void {
    // Only the scan it names. A cancel that arrives after its own scan
    // finished must not abandon the one that replaced it.
    if (this.running?.requestId !== message.requestId) return;
    this.abandonScan();
  }

  /**
   * One slice, then back through the queue.
   *
   * `setTimeout` rather than a loop, and the queue rather than a direct call:
   * between two slices the store serves the byte reads and row reads the
   * reader is still asking for. A scan that ran to completion in one message
   * would freeze the detail pane and the scrollback for as long as it took.
   *
   * Not `requestAnimationFrame`, which `redirect.ts` measured firing **zero**
   * times over 3.8 s in a background tab - and this process has no frames at
   * all.
   */
  private stepScan(): void {
    const running = this.running;
    if (running === null) return;

    // The capture closed or was replaced while this slice was queued.
    if (this.open === null || this.open.id !== running.captureId) {
      this.abandonScan();
      return;
    }

    let more: boolean;
    try {
      more = running.scan.step(this.scanSliceMs);
    } catch (error) {
      this.running = null;
      this.endScan(running.requestId, running.scan.frameCount, null, false, describe(error));
      return;
    }

    const progress = running.scan.progress;
    if (more) {
      if (progress.framesDone - running.reported >= SCAN_PROGRESS_FRAMES) {
        running.reported = progress.framesDone;
        this.post({
          type: 'scanProgress',
          requestId: running.requestId,
          framesDone: progress.framesDone,
          frameCount: progress.frameCount,
          matches: progress.matches,
        });
      }
      setTimeout(() => this.queue.run(() => this.stepScan()), 0);
      return;
    }

    const matches = running.scan.matches;
    this.running = null;
    this.endScan(
      running.requestId, running.scan.frameCount,
      matches === null ? null : matches.toBytes(),
      progress.cancelled, null,
    );
  }

  /** Stops whatever is running and answers its caller. Safe when nothing is. */
  private abandonScan(): void {
    const running = this.running;
    if (running === null) return;
    this.running = null;
    running.scan.cancel();
    this.endScan(running.requestId, running.scan.frameCount, null, true, null);
  }

  private endScan(
    requestId: number, frameCount: number, bits: Uint8Array | null,
    cancelled: boolean, message: string | null,
  ): void {
    this.post({ type: 'scanDone', requestId, frameCount, bits, cancelled, message });
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

/** One past the newest id below the floor: every id under it has gone. 0 when none has. */
function floorIdOf(index: CaptureIndex): number {
  return index.floorChunk === 0 ? 0 : index.record(index.floorChunk - 1).lastId + 1;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
