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

import { CaptureWriter, type CaptureFiles } from '../services/capture/captureWriter';
import { SyncAccessBlockFile, type BlockFile, type SyncAccessHandleLike } from '../services/capture/blockFile';
import type { ToCapture, FromCapture } from '../services/capture/captureProtocol';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

/** Where every capture lives, under the origin's private file system. */
const ROOT_DIRECTORY = 'inwire';

interface OpenCapture {
  id: string;
  files: CaptureFiles;
  handles: SyncAccessHandleLike[];
  writer: CaptureWriter;
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
  return { id: captureId, files, handles, writer: new CaptureWriter(files) };
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
  });
}

ctx.onmessage = (event: MessageEvent<ToCapture>) => {
  const message = event.data;
  void handle(message);
};

async function handle(message: ToCapture): Promise<void> {
  try {
    switch (message.type) {
      case 'open': {
        closeOpen();
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
        post({ type: 'ready', captureId: message.captureId, persisted, quotaBytes });
        return;
      }

      case 'append': {
        if (open === null) return;
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
