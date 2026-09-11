/**
 * The capture store's worker: the only place that touches OPFS.
 *
 * ## Why a second worker
 *
 * `pipeline.worker.ts` is a saturated core. Measured, it dissects at 35,007
 * frames a second, which is 28.6 us a frame with nothing left over; encoding a
 * summary costs **8.91 us** (`scripts/perf/summary-codec.ts`), so doing the
 * storage there would take a 31% bite out of the capture ceiling. In its own
 * worker the encoder runs at ~112,000 f/s - three times the dissection rate -
 * and is never the bottleneck.
 *
 * There is a second, harder reason: `createSyncAccessHandle()` exists **only
 * inside a worker**. The synchronous file API is what makes `captureWriter`
 * testable as a pure function over `BlockFile`, and it is unavailable on the
 * main thread at any price.
 *
 * ## What this file is allowed to contain
 *
 * As little as possible. Everything with a decision in it - the chunk codec,
 * the index, the recovery rule, the patch horizon - lives in
 * `services/capture/` and is driven from Node against a `MemoryBlockFile`,
 * because **OPFS does not exist in Node** and a browser cannot be crashed on
 * demand. This file opens handles, routes messages, and holds no logic worth
 * testing. If something here starts deciding anything, it belongs below.
 *
 * ## Storage that the browser may take away
 *
 * `navigator.storage.persist()` is requested once, and **`false` is the
 * ordinary answer**: Chrome grants it on engagement heuristics and usually
 * declines on a plain page. It is reported rather than retried, because it
 * matters - without it the origin's data is best-effort and the browser may
 * evict **the whole origin** under disk pressure, not the oldest capture. And
 * `estimate().quota` is roughly a share of *total* disk, not free space, so it
 * is an upper bound and never a promise.
 */
/// <reference lib="webworker" />

import { inflateSync } from 'fflate';
import { CaptureWriter, type CaptureFiles } from '../services/capture/captureWriter';
import { CaptureReader } from '../services/capture/captureReader';
import { recoverIndex } from '../services/capture/captureIndex';
import { serialQueue } from '../services/capture/serialQueue';
import { SyncAccessBlockFile, type BlockFile, type SyncAccessHandleLike } from '../services/capture/blockFile';
import type { ToCapture, FromCapture } from '../services/capture/captureProtocol';
import type { Packet } from '../types/packet';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

/** Where every capture lives, under the origin's private file system. */
const ROOT_DIRECTORY = 'inwire';

interface OpenCapture {
  id: string;
  files: CaptureFiles;
  handles: SyncAccessHandleLike[];
  writer: CaptureWriter;
  reader: CaptureReader;
}

let open: OpenCapture | null = null;

function post(message: FromCapture): void {
  ctx.postMessage(message);
}

function fail(message: string, fatal: boolean): void {
  post({ type: 'failure', message, fatal });
}

/**
 * Opens the four files a capture is made of.
 *
 * `readwrite-unsafe` is asked for first and the plain mode is the fallback, and
 * **measured in Chrome that choice is load-bearing rather than defensive**:
 *
 *   - a second plain handle on a file already open: refused;
 *   - a `readwrite-unsafe` handle beside a plain one: also refused;
 *   - **two `readwrite-unsafe` handles on the same file: allowed.**
 *
 * So a reader can only hold its own handle while the capture is running if the
 * WRITER opened in that mode too. Falling back to the plain mode is therefore a
 * real degradation and not a formality - it means every read has to be routed
 * through this worker - which is why the fallback is worth noticing rather than
 * silently accepting.
 *
 * Also measured on the same machine: sequential writes ran at **1,686 MB/s**,
 * some thirty times what a 35,000 f/s capture needs, so the throughput this
 * design worried about is not a constraint. The quota was **10.8 GB**, which is
 * the number that actually binds - it comfortably holds the 5 GB target and
 * would not hold 50 GB, which is why v1 targets the former.
 */
async function openFiles(captureId: string): Promise<OpenCapture> {
  const root = await navigator.storage.getDirectory();
  const inwire = await root.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
  const dir = await inwire.getDirectoryHandle(captureId, { create: true });

  const handles: SyncAccessHandleLike[] = [];
  const openOne = async (name: string): Promise<BlockFile> => {
    const handle = await dir.getFileHandle(name, { create: true });
    let access: SyncAccessHandleLike;
    try {
      access = await (handle as unknown as {
        createSyncAccessHandle(o?: { mode?: string }): Promise<SyncAccessHandleLike>;
      }).createSyncAccessHandle({ mode: 'readwrite-unsafe' });
    } catch {
      access = await (handle as unknown as {
        createSyncAccessHandle(): Promise<SyncAccessHandleLike>;
      }).createSyncAccessHandle();
    }
    handles.push(access);
    return new SyncAccessBlockFile(access);
  };

  const files: CaptureFiles = {
    index: await openOne('index.iwidx'),
    pfx: await openOne('prefix.iwpfx'),
    sum: await openOne('summary.iwsum'),
    byt: await openOne('frames.iwbyt'),
  };

  // Recovery before the writer, not after. A crash can leave data past the
  // last index record, and a writer that appended to it would put the new
  // chunk's bytes where nothing can find them and every offset after it wrong.
  // `planRecovery` is the rule; this is the four lines that apply it.
  const { records, plan } = recoverIndex(files.index, files.pfx, files.sum, files.byt);
  files.pfx.truncate(plan.pfxLength);
  files.sum.truncate(plan.sumLength);
  files.byt.truncate(plan.bytLength);
  files.index.truncate(plan.indexLength);

  const writer = new CaptureWriter(files, { resumeFrom: records.slice(0, plan.keepRecords) });
  // The reader shares the writer's index, so a chunk is readable the moment
  // its record is appended rather than only after the file is re-read.
  const reader = new CaptureReader(files, writer.index, inflateSync);
  return { id: captureId, files, handles, writer, reader };
}

function closeOpen(): void {
  if (open === null) return;
  try { open.writer.finish(); } catch { /* a failed finish must not leak handles */ }
  for (const handle of open.handles) {
    try { handle.close(); } catch { /* already gone */ }
  }
  open = null;
}

function bytesOnDisk(capture: OpenCapture): number {
  return capture.files.index.size() + capture.files.pfx.size()
    + capture.files.sum.size() + capture.files.byt.size();
}

function reportStats(): void {
  if (open === null) return;
  post({
    type: 'stats',
    stats: { ...open.writer.stats },
    stagedCount: open.writer.stagedCount,
    bytesOnDisk: bytesOnDisk(open),
    storedRange: open.writer.index.idRange(),
  });
}

/**
 * Messages are handled one at a time, in order - see `serialQueue.ts` for the
 * 500 frames that bought that rule. An `append` must not overtake the `open`
 * it depends on.
 */
const queue = serialQueue((error) => {
  fail(error instanceof Error ? error.message : String(error), false);
});

ctx.onmessage = (event: MessageEvent<ToCapture>) => {
  const message = event.data;
  queue.run(() => handle(message));
};

/**
 * Set once an append has arrived with no capture open, so it is said once.
 *
 * With the queue above this can only mean the app appended without starting,
 * which is a wiring error rather than a race - but it was silent before and
 * cost 500 frames, so it does not get to be silent again.
 */
let orphanedAppend = false;

async function handle(message: ToCapture): Promise<void> {
  try {
    switch (message.type) {
      case 'open': {
        closeOpen();
        orphanedAppend = false;
        if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) {
          fail('this browser has no origin private file system', true);
          return;
        }
        open = await openFiles(message.captureId);
        // Asked once per capture, and a refusal is normal. Persistence stops
        // the browser evicting the origin under disk pressure; it does not
        // raise the quota by a single byte, and the two are often confused.
        let persisted = false;
        try { persisted = await navigator.storage.persist(); } catch { persisted = false; }
        let quotaBytes: number | null = null;
        try { quotaBytes = (await navigator.storage.estimate()).quota ?? null; } catch { /* unavailable */ }
        const range = open.writer.index.idRange();
        post({
          type: 'ready',
          captureId: message.captureId,
          persisted,
          quotaBytes,
          frameCount: open.writer.index.frameCount,
          chunkCount: open.writer.index.chunkCount,
          lastId: range === null ? 0 : range.last,
          ...(message.requestId === undefined ? {} : { requestId: message.requestId }),
        });
        return;
      }

      case 'append': {
        if (open === null) {
          if (!orphanedAppend) {
            orphanedAppend = true;
            fail(`${message.packets.length} frames arrived before a capture was opened`, false);
          }
          return;
        }
        open.writer.append(message.packets);
        return;
      }

      case 'patches': {
        if (open === null) return;
        open.writer.applyPatches(message.patches);
        return;
      }

      case 'finish': {
        if (open === null) return;
        open.writer.finish();
        reportStats();
        return;
      }

      case 'read': {
        // An answer always goes back, empty or not: the main thread holds a
        // promise per request and a silent drop would leave the hex viewer
        // spinning for the life of the page.
        let found = new Map<number, Uint8Array>();
        try {
          if (open !== null) found = open.reader.readBytes(message.ids);
        } catch (error) {
          // Reported, and the request still answered. Letting this reach the
          // handler's own catch would post a failure and no `bytes`, and the
          // caller would wait for ever for frames that are never coming.
          fail(error instanceof Error ? error.message : String(error), false);
        }
        post({ type: 'bytes', requestId: message.requestId, frames: [...found] });
        return;
      }

      case 'chunk': {
        // Like `read`, always answered. A restore walks chunks one at a time
        // and would stall on the first one that went unanswered.
        let packets: Packet[] = [];
        try {
          if (open !== null) packets = open.reader.readRows(message.chunk);
        } catch (error) {
          fail(error instanceof Error ? error.message : String(error), false);
        }
        post({ type: 'rows', requestId: message.requestId, packets });
        return;
      }

      case 'rowsAt': {
        let blocks: { firstOrdinal: number; packets: Packet[] }[] = [];
        try {
          if (open !== null) blocks = open.reader.readRowsAt(message.from, message.to);
        } catch (error) {
          fail(error instanceof Error ? error.message : String(error), false);
        }
        post({ type: 'blocks', requestId: message.requestId, blocks });
        return;
      }

      case 'locate': {
        let ordinal = -1;
        try {
          if (open !== null) ordinal = open.reader.ordinalOf(message.id);
        } catch (error) {
          fail(error instanceof Error ? error.message : String(error), false);
        }
        post({ type: 'located', requestId: message.requestId, ordinal });
        return;
      }

      case 'prune': {
        const root = await navigator.storage.getDirectory();
        const inwire = await root.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
        const keep = new Set(message.keep);
        // Names collected before anything is removed: mutating a directory
        // while iterating it is not something the spec promises anything
        // about, and a half-enumerated prune would leave arbitrary captures.
        const names: string[] = [];
        for await (const name of (inwire as unknown as { keys(): AsyncIterable<string> }).keys()) {
          if (!keep.has(name)) names.push(name);
        }
        for (const name of names) {
          try { await inwire.removeEntry(name, { recursive: true }); } catch { /* held open elsewhere */ }
        }
        return;
      }

      case 'stats': {
        reportStats();
        return;
      }

      case 'discard': {
        if (open?.id === message.captureId) closeOpen();
        const root = await navigator.storage.getDirectory();
        const inwire = await root.getDirectoryHandle(ROOT_DIRECTORY, { create: true });
        // `recursive` because a capture is a directory of four files, and
        // removing them one at a time would leave a half-deleted capture if it
        // failed in the middle.
        await inwire.removeEntry(message.captureId, { recursive: true });
        return;
      }
    }
  } catch (error) {
    // Never silent. A storage layer that fails quietly is exactly the failure
    // `sessionStore`'s budget comment exists to prevent, and at 5 GB the thing
    // that fails is usually the disk filling - which the reader has to be told
    // about rather than discovering as missing frames.
    fail(error instanceof Error ? error.message : String(error), message.type === 'open');
  }
}
