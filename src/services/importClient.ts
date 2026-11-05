/**
 * The page's end of a capture-file import in a Worker (`docs/superpowers/specs/
 * 2026-11-05-import-worker-design.md`; the Worker's end is
 * `pipeline/importRun.ts`).
 *
 * The Worker dissects, writes the rows to the capture store over a port of its
 * own and keeps the RAM tail; what it sends the page is what only the page can
 * act on, and this answers each:
 *
 * - `secrets`: the page is the one writer of the key log. Add, then ack with the
 *   seq and a fresh snapshot (a page without shared memory has no other way to
 *   hand the keys over); the Worker reads no further until it has.
 * - `opening`: open the capture (awaited, by `deps.onOpening`), then `storeOpen`.
 * - `progress`: report it, and tell the Worker how far the store can supply bytes
 *   (`deps.storedThrough`), so its tail lets go of the rows' own.
 * - `tail`: decode the chunk in this task, yield a task, then `tailTaken`. The
 *   Worker posts the next chunk only after that, so the renderer holds at most
 *   one chunk's bytes twice at the handover, and no task decodes more than one.
 * - `done` / `failed` / the Worker's `onerror`: the run is over.
 *
 * Every exit - success, failure, a Worker that dies, Cancel - settles `result`
 * exactly once, terminates the Worker and ends the key-log subscription; after
 * it every message from that Worker is ignored (the run is its own token), so a
 * second import started at once is independent of the first.
 *
 * Everything the run touches arrives in `deps`, so a script can drive it with a
 * scripted Worker and no browser.
 */
import type { Packet } from '../types/packet';
import { FieldBlockWriter } from './dissect/fieldSplit';
import { PackReader } from './pipeline/rowPack';
import { IMPORT_NAME, type FromImport, type ImportRunOptions, type ToImport } from './pipeline/importProtocol';
import type { KeyLogStore } from './tls/keyLog';
import type { ImportOutcome, ImportRunHandle } from './tabularImport';

export { IMPORT_NAME };

/** The part of a `Worker` the client uses; a scripted one stands in under test. */
export interface WorkerLike {
  postMessage(message: ToImport, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<FromImport>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  onmessageerror: ((event: MessageEvent) => void) | null;
}

export interface ImportClientDeps {
  spawn(): WorkerLike;
  /** A fresh port to the store's ingest side; the Worker owns it from `start`. */
  ingestPort(): Promise<MessagePort>;
  keyLog: Pick<KeyLogStore, 'share' | 'add' | 'onSnapshot'>;
  /** Runs the lifecycle's open of the capture, awaited; answers the capture's id. */
  onOpening(): Promise<string>;
  /** The highest frame id the store can supply bytes for (0 = none). */
  storedThrough(): number;
  onProgress(readBytes: number, totalBytes: number): void;
  options: ImportRunOptions;
}

const unreadable = (message: string): ImportOutcome => ({ ok: false, failure: { kind: 'unreadable', message } });

/**
 * A task of its own for whatever comes next, so the page can paint and answer
 * input between two tail chunks. A message event is already a task; this is the
 * one after the decode.
 */
const nextTask = (): Promise<void> => new Promise((resolve) => { setTimeout(resolve, 0); });

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
  let sentStoredThrough = 0;
  let storeOpened = false;
  const reader = new PackReader(new FieldBlockWriter());
  const packets: Packet[] = [];
  const estimates: number[] = [];

  const finish = (outcome: ImportOutcome): void => {
    if (over) return;
    over = true;
    unsubscribe?.();
    unsubscribe = null;
    if (worker !== null) {
      worker.onmessage = null;
      worker.onerror = null;
      worker.onmessageerror = null;
      try { worker.terminate(); } catch { /* already gone */ }
    }
    settle(outcome);
  };

  const post = (message: ToImport): void => {
    if (!over) worker?.postMessage(message);
  };

  const handle = (message: FromImport): void => {
    if (over) return;
    switch (message.type) {
      case 'progress': {
        deps.onProgress(message.readBytes, message.totalBytes);
        // Not before the capture is open: until then `storedRange` is the PREVIOUS
        // capture's (this one's `ready` has not arrived), and the Worker keeps the
        // highest it is told, so a stale 2M would release bytes the store never got.
        if (!storeOpened) return;
        const through = deps.storedThrough();
        if (through > sentStoredThrough) {
          sentStoredThrough = through;
          post({ type: 'storedThrough', id: through });
        }
        return;
      }
      case 'secrets':
        deps.keyLog.add(message.text);
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
      case 'tail': {
        try {
          for (const row of reader.read(message.pack)) packets.push(row);
          for (const estimate of message.estimates) estimates.push(estimate);
        } catch (error) {
          finish(unreadable(error instanceof Error ? error.message : String(error)));
          return;
        }
        void nextTask().then(() => post({ type: 'tailTaken' }));
        return;
      }
      case 'done':
        finish({
          ok: true, packets, notes: [], facts: message.facts, estimates,
          derived: ownBuffers(message.derived), totalFrames: message.totalFrames, stored: message.built,
        });
        return;
      case 'failed':
        finish(unreadable(message.message));
        return;
    }
  };

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
