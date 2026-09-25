/**
 * Somewhere to write an export a piece at a time.
 *
 * `saveGeneratedFile` takes the whole file as one `Uint8Array`, which means an
 * export has to exist in full in the renderer's heap before the first byte
 * reaches disk. For a capture larger than the RAM window that is the thing
 * that cannot happen. A `ByteSink` is the other shape: the writer produces
 * pages, each page is written, and nothing holds more than a page.
 *
 * `openSaveSink` is the real one, over the preload's streaming save (the dialog
 * first, then `<path>.partial`, renamed on commit - `electron/saveSession.ts`).
 * `MemorySink` is the same contract in memory, for the assertion scripts.
 * `zipSink` wraps either and compresses as it goes.
 */
import { Zip, ZipDeflate } from 'fflate';
import { dialogRequestFor, narrowSaveResult, type SaveOutcome } from './saveFile';

export interface ByteSink {
  /**
   * Appends `chunk`. The sink copies what it keeps, so the caller may reuse
   * the buffer as soon as the promise resolves - and, for ordering, calls may
   * be issued without awaiting each one: they land in call order.
   */
  write(chunk: Uint8Array): Promise<void>;
  /** Finishes the file. After a failed write this reports that failure. */
  close(): Promise<SaveOutcome>;
  /** Abandons the file; nothing is left with the chosen name. */
  abort(): Promise<void>;
}

export type OpenSinkResult = ByteSink | { canceled: true } | { error: string };

export function isByteSink(value: OpenSinkResult): value is ByteSink {
  return 'write' in value;
}

/**
 * How much is gathered before one IPC message.
 *
 * Writers emit per packet - tens of bytes to a few kilobytes - and an `invoke`
 * per packet would spend the export on round trips. A couple of megabytes is
 * a few milliseconds of disk and a copy main can hold without noticing.
 */
export const COALESCE_BYTES = 2 * 1024 * 1024;

interface StreamBridge {
  openSaveStream(request: ReturnType<typeof dialogRequestFor>): Promise<unknown>;
  writeSaveStream(token: string, bytes: Uint8Array): Promise<unknown>;
  closeSaveStream(token: string, commit: boolean): Promise<unknown>;
}

function bridge(): StreamBridge | null {
  // `typeof`, because the assertion scripts import this module under plain
  // tsx, where `window` is not a name at all.
  const inwire = typeof window === 'undefined' ? undefined : window.inwire;
  if (!inwire?.openSaveStream || !inwire.writeSaveStream || !inwire.closeSaveStream) return null;
  return inwire as StreamBridge;
}

function recordOf(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' ? value as Record<string, unknown> : null;
}

/** Shows the save dialog. The file is not created until the person chooses. */
export async function openSaveSink(suggestedName: string): Promise<OpenSinkResult> {
  const desktop = bridge();
  if (!desktop) return { error: 'no desktop bridge to save through' };
  const answer = recordOf(await desktop.openSaveStream(dialogRequestFor(suggestedName)));
  if (answer?.canceled === true) return { canceled: true };
  if (answer && typeof answer.token === 'string') return new BridgeSink(desktop, answer.token);
  return { error: typeof answer?.error === 'string' ? answer.error : 'the file could not be created' };
}

class BridgeSink implements ByteSink {
  private pending = new Uint8Array(COALESCE_BYTES);
  private filled = 0;
  /** Every IPC call, in order. A rejection here is the sink's failure. */
  private chain: Promise<void> = Promise.resolve();
  private failure: string | null = null;
  private done = false;

  constructor(private readonly desktop: StreamBridge, private readonly token: string) {}

  write(chunk: Uint8Array): Promise<void> {
    if (this.done) return Promise.reject(new Error('the save is already closed'));
    if (this.failure) return Promise.reject(new Error(this.failure));
    // The copy happens now, synchronously, which is what makes unawaited calls
    // land in order and what lets the caller reuse its buffer.
    let offset = 0;
    while (offset < chunk.byteLength) {
      const take = Math.min(chunk.byteLength - offset, COALESCE_BYTES - this.filled);
      this.pending.set(chunk.subarray(offset, offset + take), this.filled);
      this.filled += take;
      offset += take;
      if (this.filled === COALESCE_BYTES) this.flush();
    }
    return this.chain;
  }

  async close(): Promise<SaveOutcome> {
    if (this.done) return { saved: false, canceled: false, error: 'the save is already closed' };
    this.done = true;
    this.flush();
    try {
      await this.chain;
    } catch {
      await this.desktop.closeSaveStream(this.token, false).catch(() => undefined);
      return { saved: false, canceled: false, error: this.failure ?? 'the file could not be written' };
    }
    try {
      return narrowSaveResult(await this.desktop.closeSaveStream(this.token, true));
    } catch (error) {
      // The commit itself threw - the IPC call, not the rename it asks for.
      // Main may still hold the session and its `.partial`, so it is told to
      // drop both; a second failure here has nothing left to report to.
      await this.desktop.closeSaveStream(this.token, false).catch(() => undefined);
      return {
        saved: false, canceled: false,
        error: error instanceof Error ? error.message : 'the file could not be committed',
      };
    }
  }

  async abort(): Promise<void> {
    if (this.done) return;
    this.done = true;
    this.filled = 0;
    await this.chain.catch(() => undefined);
    await this.desktop.closeSaveStream(this.token, false).catch(() => undefined);
  }

  private flush(): void {
    if (this.filled === 0) return;
    const bytes = this.pending.subarray(0, this.filled);
    // A fresh buffer rather than reuse: the one just handed off is read by the
    // IPC clone at some later microtask, not now.
    this.pending = new Uint8Array(COALESCE_BYTES);
    this.filled = 0;
    this.chain = this.chain.then(async () => {
      if (this.failure) throw new Error(this.failure);
      const answer = recordOf(await this.desktop.writeSaveStream(this.token, bytes));
      if (answer?.ok !== true) {
        this.failure = typeof answer?.error === 'string' ? answer.error : 'the file could not be written';
        throw new Error(this.failure);
      }
    });
    // Nobody may be awaiting this link; the failure is kept in `failure` and
    // reported by the next write or by close.
    this.chain.catch(() => undefined);
  }
}

/** The contract in memory, for tests. `bytes()` is everything written. */
export class MemorySink implements ByteSink {
  private readonly chunks: Uint8Array[] = [];
  private length = 0;
  closed = false;
  aborted = false;

  async write(chunk: Uint8Array): Promise<void> {
    if (this.closed || this.aborted) throw new Error('the save is already closed');
    this.chunks.push(chunk.slice());
    this.length += chunk.byteLength;
  }

  async close(): Promise<SaveOutcome> {
    if (this.closed || this.aborted) {
      return { saved: false, canceled: false, error: 'the save is already closed' };
    }
    this.closed = true;
    return { saved: true, path: 'memory' };
  }

  async abort(): Promise<void> {
    this.aborted = true;
  }

  get byteLength(): number {
    return this.length;
  }

  bytes(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  }
}

/**
 * fflate writes no ZIP64 records, so an entry or an archive past 4 GiB would
 * come out with wrapped sizes and offsets - a zip that lists fine and extracts
 * garbage. Refused instead, while the export can still say why.
 */
const ZIP32_LIMIT = 0xffffffff;

/**
 * Wraps `inner` so what is written becomes one deflated entry, `entryName`,
 * in a zip written to `inner` as it is produced.
 *
 * The synchronous `ZipDeflate`, not `AsyncZipDeflate`: with it, a write
 * resolves only once its compressed bytes have been handed to `inner`, which is
 * the backpressure that keeps a whole-capture export from outrunning the disk.
 * The async one returns at once and queues input in a Worker without bound.
 */
export function zipSink(inner: ByteSink, entryName: string): ByteSink {
  const produced: Uint8Array[] = [];
  let zipError: Error | null = null;
  let ended = false;
  let inputBytes = 0;
  let outputBytes = 0;
  let done = false;

  const zip = new Zip((error, chunk, final) => {
    if (error) {
      zipError = error;
      return;
    }
    produced.push(chunk);
    outputBytes += chunk.byteLength;
    if (final) ended = true;
  });
  const entry = new ZipDeflate(entryName, { level: 6 });
  zip.add(entry);

  async function drain(): Promise<void> {
    if (zipError) throw zipError;
    if (outputBytes > ZIP32_LIMIT) throw new Error('the zip would pass 4 GiB, which this writer cannot record');
    while (produced.length > 0) await inner.write(produced.shift()!);
  }

  return {
    async write(chunk: Uint8Array): Promise<void> {
      if (done) throw new Error('the save is already closed');
      inputBytes += chunk.byteLength;
      if (inputBytes > ZIP32_LIMIT) throw new Error('the zipped file would pass 4 GiB, which this writer cannot record');
      entry.push(chunk);
      await drain();
    },
    async close(): Promise<SaveOutcome> {
      if (done) return { saved: false, canceled: false, error: 'the save is already closed' };
      done = true;
      try {
        entry.push(new Uint8Array(0), true);
        zip.end();
        await drain();
        if (!ended) throw new Error('the zip did not finish');
      } catch (error) {
        await inner.abort();
        return { saved: false, canceled: false, error: error instanceof Error ? error.message : String(error) };
      }
      return inner.close();
    },
    async abort(): Promise<void> {
      if (done) return;
      done = true;
      zip.terminate();
      produced.length = 0;
      await inner.abort();
    },
  };
}
