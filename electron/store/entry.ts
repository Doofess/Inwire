/**
 * The capture store, as an Electron `utilityProcess`.
 *
 * ## Why a process and not a Worker
 *
 * The store needs synchronous file I/O - that is what `BlockFile`'s whole
 * interface is shaped for, and it is why the store was a Worker in the browser
 * at all. A Web Worker in Electron has no `node:fs` unless
 * `nodeIntegrationInWorker` is set, and that flag is **renderer-wide**: it
 * would hand `node:fs` and `child_process` not to this code but to
 * `pipeline.worker.ts`, whose entire job is parsing bytes an attacker put on
 * the wire. It also requires `nodeIntegration: true`, is incompatible with
 * `sandbox: true`, and does not work with the `type: 'module'` workers this
 * app uses.
 *
 * A `utilityProcess` is a Node child with none of a renderer's privileges. The
 * sync seam survives untouched, and the store gets its own crash domain: an
 * `ENOSPC` or a corrupt index kills this process and leaves the window alive,
 * which `CaptureClient` already knows how to degrade to.
 *
 * ## What this file is allowed to contain
 *
 * As little as possible, which is the rule `capture.worker.ts` set for itself
 * and this inherits. The routing is `services/capture/captureHost.ts` and the
 * filesystem is `./volume.ts`; both are driven from plain Node by
 * `scripts/electron/store-protocol.ts`. Nothing here decides anything.
 */
import { CaptureHost } from '../../src/services/capture/captureHost';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import { captureVolume } from './volume';
import { HEAP_SAMPLE_MS, judgeHeap } from './heapGuard';
import { getHeapStatistics } from 'node:v8';
import { deflateRawSync, inflateRawSync } from 'node:zlib';

/** Where captures live. Passed in by main, which owns every path decision. */
const directory = process.argv[2];
if (!directory) {
  console.error('[inwire] capture store started with no directory');
  process.exit(1);
}

/**
 * Node's own zlib, at level 1. `fflate`'s level 6 cost 25.8 us of the writer's
 * frame and this costs 9.0, for output within 1% of the size - measured by
 * `scripts/perf/store-boundary.ts`, which is what a 36,000 frame-a-second
 * burst needs: at the old rate the store fell behind, its queue filled its
 * heap, and the guard stopped it 51 seconds in.
 */
/**
 * A `Buffer` may be a window onto a larger pooled allocation, and a view
 * posted across a port clones its whole backing buffer - so one that does not
 * own its buffer is copied, once, here.
 */
const owned = (out: Buffer): Uint8Array =>
  out.byteOffset === 0 && out.byteLength === out.buffer.byteLength
    ? new Uint8Array(out.buffer)
    : new Uint8Array(out);
const deflate = (bytes: Uint8Array): Uint8Array => owned(deflateRawSync(bytes, { level: 1 }));
const inflate = (bytes: Uint8Array): Uint8Array => owned(inflateRawSync(bytes));

const host = new CaptureHost(captureVolume(directory), (message) => {
  port?.postMessage(message);
}, { deflate, inflate });

/**
 * The app's channel. **Every reply goes here and nowhere else.**
 *
 * There is a second port now (see below), and it is one-way. A reply posted to
 * whichever port happened to arrive last is a read the hex viewer waits on for
 * the life of the window.
 */
let port: Electron.MessagePortMain | null = null;

/**
 * Main sends one message per channel, and the message says which channel it is.
 *
 * **The role is load-bearing.** This used to take `event.ports[0]` from any
 * parent message and assign it to `port` unconditionally, so the second channel
 * silently replaced the first - the store would keep working, keep writing, and
 * answer every request down a port nothing was reading. A failure with no error
 * anywhere and a hung UI, which is the shape this file's own header warns about
 * one line lower.
 */
process.parentPort.on('message', (event) => {
  const [incoming] = event.ports;
  if (!incoming) return;
  const role = (event.data as { role?: string } | null)?.role ?? 'client';
  if (role === 'ingest') {
    // The pipeline Worker's port. Frames and records in; and the one kind of
    // answer that belongs here, a revisit kit (ADR 0049), which goes back down
    // THIS port because the Worker asked for it. The answer travels with the
    // message rather than this port ever becoming `port`, so nothing meant for
    // the renderer can be answered here - failures included, which `host`
    // still reports on the client port the app watches.
    const reply = (answer: FromCapture) => incoming.postMessage(answer);
    incoming.on('message', (message) => host.receive(message.data as ToCapture, reply));
    incoming.start();
    return;
  }
  port = incoming;
  port.on('message', (message) => host.receive(message.data as ToCapture));
  // Required, and easy to miss: a `MessagePortMain` delivers nothing until it
  // is started. A DOM `MessagePort` starts itself when `onmessage` is
  // assigned; this one does not, and the symptom is a store that connects and
  // then ignores every message in silence.
  port.start();
});

// The memory ceiling, which V8 refuses to apply from `execArgv` - see
// `heapGuard.ts`. Sampled here rather than in `CaptureHost` because it is a
// fact about the process, not about the protocol; the decision it feeds is a
// pure function over there.
let heapWarned = false;
const heapTimer = setInterval(() => {
  const heap = getHeapStatistics();
  const verdict = judgeHeap(heap.used_heap_size, heap.heap_size_limit, heapWarned);
  if (verdict.level === 'ok') return;
  if (verdict.level === 'warn') {
    heapWarned = true;
    port?.postMessage({ type: 'failure', message: verdict.message, fatal: false });
    return;
  }
  // Sealed before exiting, so the chunk being staged is not lost to a ceiling
  // this process chose to hit.
  clearInterval(heapTimer);
  port?.postMessage({ type: 'failure', message: verdict.message, fatal: true });
  console.error(`[inwire] ${verdict.message}`);
  host.close();
  process.exit(1);
}, HEAP_SAMPLE_MS);
// Nothing here should hold the process open on its own.
heapTimer.unref();

// A clean exit seals whatever is open, so the next launch does not have to
// recover a tail that nothing actually tore.
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { host.close(); process.exit(0); });
}
process.on('exit', () => host.close());
