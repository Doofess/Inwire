/**
 * The page's end of a capture-file import in a Worker (`docs/superpowers/specs/
 * 2026-11-05-import-worker-design.md`; the Worker's end is
 * `pipeline/importRun.ts`).
 *
 * The Worker dissects and writes the rows to the capture store over a port of its
 * own; each batch is packed once and the same pack goes to the store and here, so
 * the page keeps the RAM tail (`ImportTail`) and the Worker none. What the Worker
 * sends the page is what only the page can act on, and this answers each:
 *
 * - `secrets`: the page is the one writer of the key log. Add, then ack with the
 *   seq and a fresh snapshot (a page without shared memory has no other way to
 *   hand the keys over); the Worker reads no further until it has.
 * - `opening`: open the capture (awaited, by `deps.onOpening`), then `storeOpen`.
 * - `rows`: decode the batch, push it on the tail with the Worker's sizes, then
 *   say `rowsTaken`. A batch is a few hundred rows, so the decode is a short
 *   task; the answer is the Worker's credit (`importCredit.ts`): it holds back
 *   its `rows` past `IMPORT_ROWS_IN_FLIGHT` unanswered, so a Worker that outruns
 *   the page does not pile its batches up in the page's message queue.
 * - `progress`: report it. The tail lets go of the bytes the store can supply
 *   (`deps.storedThrough`) here and after each `rows`, once the capture is open.
 * - `done` / `failed` / the Worker's `onerror`: the run is over.
 * - the store lost (`deps.onStoreLost`): the run is over, as a failure. The Worker
 *   would wait for ever on credit or the barrier of a store that is gone.
 *
 * Every exit - success, failure, a Worker that dies, a lost store, Cancel - settles
 * `result` exactly once, terminates the Worker and ends the key-log and store
 * subscriptions; after
 * it every message from that Worker is ignored (the run is its own token), so a
 * second import started at once is independent of the first.
 *
 * Everything the run touches arrives in `deps`, so a script can drive it with a
 * scripted Worker and no browser.
 */
import { ImportTail } from './importTail';
import { FieldBlockWriter } from './dissect/fieldSplit';
import { PackReader } from './pipeline/rowPack';
import { IMPORT_NAME, type FromImport, type ImportRunOptions, type ToImport } from './pipeline/importProtocol';
import { addKeyLogText, type KeyLogStore } from './tls/keyLog';
import type { ImportOutcome, ImportRunHandle } from './tabularImport';
import type { RowsTaken } from './importCredit';

export { IMPORT_NAME };

/** The part of a `Worker` the client uses; a scripted one stands in under test. */
export interface WorkerLike {
  postMessage(message: ToImport | RowsTaken, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<FromImport>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
}

export interface ImportClientDeps {
  spawn(): WorkerLike;
  /** A fresh port to the store's ingest side; the Worker owns it from `start`. */
  ingestPort(): Promise<MessagePort>;
  keyLog: Pick<KeyLogStore, 'share' | 'add' | 'reserve' | 'onSnapshot'>;
  /** Runs the lifecycle's open of the capture, awaited; answers the capture's id. */
  onOpening(): Promise<string>;
  /** The highest frame id the store can supply bytes for (0 = none). */
  storedThrough(): number;
  /**
   * Hears when the capture store is gone or has failed for good, until the
   * returned function is called. The Worker's only link to the store is a port
   * that goes quiet when the store dies, so it would wait for ever on credit or
   * the barrier: only the page is told, and the run must end then.
   */
  onStoreLost(listener: (message: string) => void): () => void;
  onProgress(readBytes: number, totalBytes: number): void;
  options: ImportRunOptions;
}

const unreadable = (message: string): ImportOutcome => ({ ok: false, failure: { kind: 'unreadable', message } });

/**
 * The decrypted answers as the page will hand them on (`keepDerived` transfers
 * each entry's buffer): every entry its own whole buffer. A view into a shared
 * one, or a repeat of a buffer, would make that transfer list invalid.
 */
function ownBuffers(entries: [number, Uint8Array][]): [number, Uint8Array][] {
  const seen = new Set<ArrayBufferLike>();
  return entries.map(([id, bytes]) => {
    const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
    if (whole && !seen.has(bytes.buffer)) {
      seen.add(bytes.buffer);
      return [id, bytes];
    }
    return [id, bytes.slice()];
  });
}

export function runWorkerImport(file: File, deps: ImportClientDeps): ImportRunHandle {
  let settle: (outcome: ImportOutcome) => void = () => {};
  const result = new Promise<ImportOutcome>((resolve) => { settle = resolve; });

  let over = false;
  let worker: WorkerLike | null = null;
  let unsubscribe: (() => void) | null = null;
  let unlisten: (() => void) | null = null;
  let storeOpened = false;
  // Not before the capture is open: until then `storedRange` is the PREVIOUS
  // capture's (this one's `ready` has not arrived), so a stale high answer would
  // release bytes the store never got. Rows are in id order and the tail releases
  // only the ones the answer covers, so it is safe to ask again at any time.
  const release = (): void => {
    if (storeOpened) tail.releaseBytesThrough(deps.storedThrough());
  };
  const reader = new PackReader(new FieldBlockWriter());
  const tail = new ImportTail({ residentBytes: deps.options.residentBytes, maxFrames: deps.options.maxFrames });

  const finish = (outcome: ImportOutcome): void => {
    if (over) return;
    over = true;
    unsubscribe?.();
    unsubscribe = null;
    unlisten?.();
    unlisten = null;
    if (worker !== null) {
      worker.onmessage = null;
      worker.onerror = null;
      worker.onmessageerror = null;
      try { worker.terminate(); } catch { /* already gone */ }
    }
    settle(outcome);
  };

  const post = (message: ToImport | RowsTaken): void => {
    if (!over) worker?.postMessage(message);
  };

  const handle = (message: FromImport): void => {
    if (over) return;
    switch (message.type) {
      case 'progress': {
        deps.onProgress(message.readBytes, message.totalBytes);
        release();
        return;
      }
      case 'secrets':
        addKeyLogText(deps.keyLog, message.text);
        post({ type: 'secretsTaken', seq: message.seq, snapshot: deps.keyLog.share() });
        return;
      case 'opening':
        deps.onOpening().then(
          (captureId) => {
            storeOpened = true;
            post({ type: 'storeOpen', captureId });
          },
          (error: unknown) => finish(unreadable(error instanceof Error ? error.message : String(error))),
        );
        return;
      case 'rows':
        try {
          tail.push(reader.read(message.pack), message.sizes);
        } catch (error) {
          finish(unreadable(error instanceof Error ? error.message : String(error)));
          return;
        }
        release();
        // After the decode, never before: the credit is for rows the page has taken.
        post({ type: 'rowsTaken' });
        return;
      case 'done':
        finish({
          ok: true, packets: tail.rows(), notes: [], facts: message.facts, estimates: tail.estimates(),
          derived: ownBuffers(message.derived), totalFrames: message.totalFrames, stored: message.built,
        });
        return;
      case 'failed':
        finish(unreadable(message.message));
        return;
    }
  };

  // From the start, not from the Worker's: the store can die while the port is on
  // its way, and the run must not outlive it.
  unlisten = deps.onStoreLost((message) => finish(unreadable(message || 'The capture store stopped.')));

  void (async () => {
    let port: MessagePort | null = null;
    try {
      port = await deps.ingestPort();
      if (over) {
        // Cancelled while the port was on its way: nobody will use it.
        port.close();
        return;
      }
      const spawned = deps.spawn();
      worker = spawned;
      spawned.onmessage = (event) => {
        // A throw here would leave the Worker waiting for an answer for ever.
        try {
          handle(event.data);
        } catch (error) {
          finish(unreadable(error instanceof Error ? error.message : String(error)));
        }
      };
      spawned.onerror = (event) => {
        event.preventDefault?.();
        finish(unreadable(event.message || 'The import stopped unexpectedly.'));
      };
      spawned.onmessageerror = () => finish(unreadable('The import sent a message the page could not read.'));
      unsubscribe = deps.keyLog.onSnapshot((snapshot) => post({ type: 'keylog-shared', snapshot }));
      // The Worker's first message, ahead of `start`: the key log it reads from now on.
      spawned.postMessage({ type: 'keylog-shared', snapshot: deps.keyLog.share() });
      spawned.postMessage(
        { type: 'start', file, fileName: file.name, options: deps.options },
        [port],
      );
    } catch (error) {
      // A port not yet handed to the Worker would stay open on the store's side.
      port?.close();
      finish(unreadable(error instanceof Error ? error.message : String(error)));
    }
  })();

  return {
    result,
    cancel: () => finish({ ok: false, failure: { kind: 'cancelled', message: 'The import was cancelled.' } }),
  };
}
