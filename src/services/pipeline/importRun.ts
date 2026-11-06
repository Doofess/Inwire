/**
 * One capture-file import, as the import Worker runs it (`workers/importRole.ts`
 * is only the connection to `postMessage`). Everything here is plain: the one
 * thing it is given is `io.post`, so `scripts/capture/import-worker-equivalence.ts`
 * can run it in a Node thread and hold it to the in-process route.
 *
 * What it does is what `readStreamedCapture` and App's import sinks did on the
 * page, moved: the walk (`streamCaptureFile`), the store messages of each batch
 * on the ingest port, and the decrypted answers (`DerivedStore`). What comes back
 * is the little the page must act on (`importProtocol.ts`): each batch's rows,
 * for the tail the page keeps.
 *
 * - **Packed once.** Each batch is packed once (`packRows`, a `PackedFlush` that
 *   carries every row's bytes in its slab) and that one pack goes to both
 *   receivers: to the store as `appendPacked` (cloned, `sent` all 0: the rows
 *   bring their bytes), then to the page as `rows` (transferred). Packing every
 *   batch costs a fraction of what `plainForStore` copies, their clone and the
 *   tail's repacking after the walk did. The flush is sealed with a map of its own
 *   and no `PackSender`: every pack is read whole inside its message, so neither
 *   receiver keeps pack state and no `packsReset` is ever sent (the store host's one
 *   `PackReader` is shared with the live Worker, and a reset would clear its
 *   packs). Pack keys start at `IMPORT_PACK_KEY_BASE`, clear of the live Worker's.
 *   Batches are final where they are packed: the batcher drains a frame only after
 *   its patch window closed (`pcapParser.ts`).
 * - **The store is written to directly, and only when it is open.** The first
 *   batch asks the page to open the capture (`opening`); messages queue until
 *   `storeOpen` names it, and every one is tagged with it, so a straggler that
 *   outlives a cancelled import is dropped by the host rather than written into
 *   the next capture. Nothing posted to the store carries a transfer list (a
 *   transfer list into the store's process drops the message), so a message that
 *   waits in the queue is a copy of its own: the page's `rows` transfers the
 *   same buffers right after.
 * - **Credit.** Each batch is followed by an empty acked `appendBytes`; the walk
 *   pauses while more than `IMPORT_CREDIT_FRAMES` are unanswered. It is queued
 *   behind the batch's messages, so frames waiting for the open count too. Only
 *   empty slabs are ever sent: an `appendBytes` with frames has no tag.
 * - **Secrets.** A Decryption Secrets Block goes to the page, the one writer of
 *   the key log, and the walk waits for its `secretsTaken` before it reads
 *   another frame; frames after the block decrypt, as they do in-process.
 * - **The end.** A final empty acked `appendBytes` is the barrier: `done` is
 *   posted only after the store has taken everything before it, so the page's
 *   seal cannot overtake a row. Every `rows` message was posted before it.
 */
import { PcapService } from '../pcapParser';
import { recordsMessageFor } from '../capture/storePacket';
import type { ToCapture } from '../capture/captureProtocol';
import { packFrames } from '../capture/frameSlab';
import { estimateSummaryBytes } from '../bufferBudget';
import { keyLog, type KeyLogShared } from '../tls/keyLog';
import type { Packet } from '../../types/packet';
import { DerivedStore } from './derivedStore';
import { PackedFlush, packRows, type PackedRows } from './rowPack';
import {
  IMPORT_CREDIT_FRAMES, IMPORT_PACK_KEY_BASE,
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
  let derived: DerivedStore | null = null;
  let packKey = IMPORT_PACK_KEY_BASE;

  const toStore = (message: ToCapture): void => {
    // A queued rows message outlives this call, and the page's `rows` transfers
    // the buffers it shares with it: it holds a copy of its own.
    if (queue !== null) queue.push(message.type === 'appendPacked' ? structuredClone(message) : message);
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
    // `streamCaptureFile` reads only `size` and `slice`, which a Blob has; the
    // file's name is the page's to report, not the walk's.
    const outcome = await PcapService.streamCaptureFile(file as File, (batch: Packet[], records) => {
      if (!openingPosted) {
        openingPosted = true;
        io.post({ type: 'opening' });
      }
      // Until the page has opened the capture the messages wait, untagged; the
      // open tags them.
      const tag = captureId ?? undefined;
      const recordsMessage = recordsMessageFor(records, tag);
      if (recordsMessage !== null) toStore(recordsMessage);
      if (batch.length > 0) {
        // Measured now, on the final rows: what `ImportTail.push` would estimate.
        const sizes = batch.map(estimateSummaryBytes);
        const pack = packRows(packKey++, batch, batch.map((row) => row.rawBytes.length));
        const flush = new PackedFlush();
        batch.forEach((row, i) => flush.packed(pack, i, row.rawBytes, null));
        const rows = flush.seal(new Map());
        // The store first, the page after: the store's post is a clone, which a
        // transfer would leave detached.
        toStore({
          type: 'appendPacked', rows, sent: new Uint8Array(batch.length),
          ...(tag === undefined ? {} : { captureId: tag }),
        });
        owe(batch.length);
        io.post({ type: 'rows', pack: rows, sizes }, transferListOf(packedRowsViews(rows)));
      } else {
        owe(0);
      }
      if (records !== undefined) {
        for (const { id, derived: answers } of records) if (answers) derived?.set(id, answers);
      }
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
          io.post({ type: 'secrets', seq, text });
        });
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
          if (queued.type === 'append' || queued.type === 'appendRecords' || queued.type === 'appendPacked') {
            queued.captureId = captureId;
          }
          storePort?.postMessage(queued);
        }
        return;
      }
    }
  };
}
