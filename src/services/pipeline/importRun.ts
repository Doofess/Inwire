/**
 * One capture-file import, as the import Worker runs it (`workers/importRole.ts`
 * is only the connection to `postMessage`). Everything here is plain: the one
 * thing it is given is `io.post`, so `scripts/capture/import-worker-equivalence.ts`
 * can run it in a Node thread and hold it to the in-process route.
 *
 * What it does is what `readStreamedCapture` and App's import sinks did on the
 * page, moved: the walk (`streamCaptureFile`), the store messages of each batch
 * on the ingest port, the RAM tail, and the decrypted answers (`DerivedStore`).
 * What comes back is the little the page must act on (`importProtocol.ts`).
 *
 * - **The store is written to directly, and only when it is open.** The first
 *   batch asks the page to open the capture (`opening`); messages queue until
 *   `storeOpen` names it, and every one is tagged with it, so a straggler that
 *   outlives a cancelled import is dropped by the host rather than written into
 *   the next capture. Nothing posted to the store carries a transfer list.
 * - **Credit.** Each batch is followed by an empty acked `appendBytes`; the walk
 *   pauses while more than `IMPORT_CREDIT_FRAMES` are unanswered. It is queued
 *   behind the batch's messages, so frames waiting for the open count too. Only
 *   empty slabs are ever sent: an `appendBytes` with frames has no tag.
 * - **Secrets.** A Decryption Secrets Block goes to the page, the one writer of
 *   the key log, and the walk waits for its `secretsTaken` before it reads
 *   another frame; frames after the block decrypt, as they do in-process.
 * - **The end.** A final empty acked `appendBytes` is the barrier: `done` is
 *   posted only after the store has taken everything before it, so the page's
 *   seal cannot overtake a row. The tail goes back first, in chunks, one in
 *   flight (`tailTaken`), each chunk's rows dropped as it is posted.
 */
import { PcapService } from '../pcapParser';
import { ImportTail } from '../importTail';
import { storeMessagesFor } from '../capture/storePacket';
import type { ToCapture } from '../capture/captureProtocol';
import { packFrames } from '../capture/frameSlab';
import { CHUNK_FRAMES } from '../capture/chunkCodec';
import { estimateSummaryBytes } from '../bufferBudget';
import { keyLog, type KeyLogShared } from '../tls/keyLog';
import type { Packet } from '../../types/packet';
import { DerivedStore } from './derivedStore';
import { PackSender, PackedFlush, packRows, type PackedRows } from './rowPack';
import {
  IMPORT_CREDIT_FRAMES, TAIL_CHUNK_ROWS,
  type FromImport, type ImportRunOptions, type ToImport,
} from './importProtocol';

export interface ImportIo {
  post(message: FromImport, transfer?: Transferable[]): void;
}

/**
 * The buffers of `values` that can be transferred: a view that is the whole of
 * its buffer. A view into a larger buffer is left to be cloned, since
 * transferring it would take bytes that belong to something else.
 */
function transferListOf(values: Iterable<ArrayBufferView>): Transferable[] {
  const buffers = new Set<ArrayBuffer>();
  for (const view of values) {
    const { buffer } = view;
    if (buffer instanceof ArrayBuffer && view.byteOffset === 0 && view.byteLength === buffer.byteLength) {
      buffers.add(buffer);
    }
  }
  return [...buffers];
}

function packedRowsViews(rows: PackedRows): ArrayBufferView[] {
  const views: ArrayBufferView[] = [rows.bytes, rows.order, rows.ends];
  for (const pack of rows.packs) views.push(pack.prefix, pack.summary);
  return views;
}

/**
 * One tail chunk as it goes to the page: the rows packed (a pack is at most
 * `CHUNK_FRAMES` rows, the codec's bound, so a message is several of them and one
 * flush). `firstKey` numbers the packs; the next free key is returned.
 */
export function packTailChunk(
  sender: PackSender, chunk: readonly Packet[], firstKey: number,
): { packed: PackedRows; nextKey: number } {
  const flush = new PackedFlush();
  let key = firstKey;
  for (let from = 0; from < chunk.length; from += CHUNK_FRAMES) {
    const part = chunk.slice(from, from + CHUNK_FRAMES);
    const pack = packRows(key++, part, part.map((row) => row.rawBytes.length));
    part.forEach((row, i) => flush.packed(pack, i, row.rawBytes, null));
  }
  return { packed: sender.seal(flush), nextKey: key };
}

export function createImportRun(io: ImportIo): (message: ToImport, ports: readonly MessagePort[]) => void {
  let started = false;
  let storePort: MessagePort | null = null;
  // Messages for the store, waiting for the page to say which capture is open.
  let queue: ToCapture[] | null = [];
  let captureId: string | null = null;
  let openingPosted = false;
  // The credit: each ack id and the frames it stands for, and their sum.
  let nextAck = 1;
  const owed = new Map<number, number>();
  let owedFrames = 0;
  let creditFrames = IMPORT_CREDIT_FRAMES;
  let resume: (() => void) | null = null;
  let barrier: (() => void) | null = null;
  let barrierAck = -1;
  let secretSeq = 0;
  const waitingSecrets = new Map<number, () => void>();
  let storedThrough = 0;
  // Set while a posted tail chunk waits for the page's `tailTaken`.
  let tailAck: (() => void) | null = null;
  let derived: DerivedStore | null = null;
  let tail: ImportTail | null = null;

  const toStore = (message: ToCapture): void => {
    if (queue !== null) queue.push(message);
    else storePort?.postMessage(message);
  };

  const owe = (frames: number): number => {
    const ack = nextAck++;
    owed.set(ack, frames);
    owedFrames += frames;
    toStore({ type: 'appendBytes', slab: packFrames([]), ack });
    return ack;
  };

  const taken = (ack: number): void => {
    const frames = owed.get(ack);
    if (frames === undefined) return;
    owed.delete(ack);
    owedFrames -= frames;
    if (ack === barrierAck) { barrier?.(); barrier = null; }
    if (resume !== null && owedFrames <= creditFrames) {
      const go = resume;
      resume = null;
      go();
    }
  };

  /**
   * A snapshot of the page's key log, adopted: this context only ever reads it.
   * One that clears it empties the decrypted answers too - they were read with
   * keys the user has just said to forget, and the live Worker does the same.
   * What the page's tree cache does for the live Worker has no counterpart
   * here: an import keeps no trees.
   */
  let adoptedBuffer: unknown = null;
  const adoptKeyLog = (snapshot: KeyLogShared): void => {
    keyLog.adopt(snapshot);
    // `cleared` stays set on every snapshot of a cleared buffer until it is next
    // replaced, and the page acks each Decryption Secrets Block with one: only a
    // snapshot that is a new buffer is the clear itself.
    if (snapshot.cleared && snapshot.buffer !== adoptedBuffer) derived?.clear();
    adoptedBuffer = snapshot.buffer;
  };

  const run = async (file: Blob, options: ImportRunOptions): Promise<void> => {
    creditFrames = options.creditFrames ?? IMPORT_CREDIT_FRAMES;
    derived = new DerivedStore(options.derivedBudget);
    const importTail = new ImportTail({ residentBytes: options.residentBytes, maxFrames: options.maxFrames });
    tail = importTail;
    // `streamCaptureFile` reads only `size` and `slice`, which a Blob has; the
    // file's name is the page's to report, not the walk's.
    const outcome = await PcapService.streamCaptureFile(file as File, (batch: Packet[], records) => {
      if (!openingPosted) {
        openingPosted = true;
        io.post({ type: 'opening' });
      }
      // Until the page has opened the capture the messages wait, untagged; the
      // open tags them. Rows are copies (`plainForStore`), as the client posts.
      for (const message of storeMessagesFor(batch, records, captureId ?? undefined)) toStore(message);
      owe(batch.length);
      if (records !== undefined) {
        for (const { id, derived: answers } of records) if (answers) derived?.set(id, answers);
      }
      importTail.push(batch);
      importTail.releaseBytesThrough(storedThrough);
    }, {
      record: options.record,
      ...(options.patchWindow === undefined ? {} : { patchWindow: options.patchWindow }),
      ...(options.batchFrames === undefined ? {} : { batchFrames: options.batchFrames }),
      ...(options.windowBytes === undefined ? {} : { windowBytes: options.windowBytes }),
      onProgress: (readBytes, totalBytes) => io.post({ type: 'progress', readBytes, totalBytes }),
      onSecrets: (text) => {
        const seq = ++secretSeq;
        return new Promise<void>((resolve) => {
          waitingSecrets.set(seq, resolve);
          io.post({ type: 'secrets', seq, text });        });
      },
      pace: () => (owedFrames > creditFrames
        ? new Promise<void>((resolve) => { resume = resolve; })
        : undefined),
    });

    // The barrier: everything before it on the port has been taken. With no
    // batch there was nothing to open and the host answers it with no capture.
    if (!openingPosted) queue = null;
    const ack = owe(0);
    barrierAck = ack;
    if (owed.has(ack)) await new Promise<void>((resolve) => { barrier = resolve; });

    // The tail, oldest first, one chunk in flight: the page decodes a chunk in a
    // task of its own and says `tailTaken`, and only then is the next packed. A
    // chunk's rows leave the tail as it is posted, so the Worker never holds the
    // whole tail while the page is building its own copy of it.
    const chunkRows = options.tailChunkRows ?? TAIL_CHUNK_ROWS;
    const sender = new PackSender();
    let key = 0;
    while (importTail.length > 0) {
      const chunk = importTail.take(chunkRows);
      // Estimated now, on the finished rows: a late patch can change a row's size
      // after it was pushed, and the page's accounting has always been taken from
      // the rows as they end up (`adoptAccounting`).
      const estimates = chunk.map(estimateSummaryBytes);
      const { packed, nextKey } = packTailChunk(sender, chunk, key);
      key = nextKey;
      io.post({ type: 'tail', pack: packed, estimates }, transferListOf(packedRowsViews(packed)));
      await new Promise<void>((resolve) => { tailAck = resolve; });
    }

    const entries = derived.entries();
    io.post({
      type: 'done',
      totalFrames: outcome.totalFrames,
      built: outcome.built,
      missedPatches: outcome.missedPatches,
      facts: outcome.facts,
      derived: entries,
    }, transferListOf(entries.map(([, bytes]) => bytes)));
  };

  return (message, ports) => {
    switch (message.type) {
      case 'start': {
        if (started) return;
        started = true;
        const port = ports[0];
        storePort = port ?? null;
        if (port === undefined) {
          io.post({ type: 'failed', message: 'import: no store port' });
          return;
        }
        port.onmessage = (event: MessageEvent<{ type: string; ack?: number }>) => {
          if (event.data.type === 'bytesTaken' && event.data.ack !== undefined) taken(event.data.ack);
        };
        run(message.file, message.options).catch((error: unknown) => {
          io.post({ type: 'failed', message: error instanceof Error ? error.message : String(error) });
        }).finally(() => { port.close(); });
        return;
      }
      case 'keylog-shared':
        adoptKeyLog(message.snapshot);
        return;
      case 'secretsTaken': {
        if (message.snapshot !== undefined) adoptKeyLog(message.snapshot);
        const resolve = waitingSecrets.get(message.seq);
        if (resolve !== undefined) {
          waitingSecrets.delete(message.seq);
          resolve();
        }
        return;
      }
      case 'storeOpen': {
        captureId = message.captureId;
        const waiting = queue;
        queue = null;
        for (const queued of waiting ?? []) {
          if (queued.type === 'append' || queued.type === 'appendRecords') queued.captureId = captureId;
          storePort?.postMessage(queued);
        }
        return;
      }
      case 'storedThrough':
        storedThrough = Math.max(storedThrough, message.id);
        tail?.releaseBytesThrough(storedThrough);
        return;
      case 'tailTaken': {
        const ack = tailAck;
        tailAck = null;
        ack?.();
        return;
      }
    }
  };
}
