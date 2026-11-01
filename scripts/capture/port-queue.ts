/**
 * The store client posts in call order, and at once when it can (#19).
 *
 *   npx tsx scripts/capture/port-queue.ts
 *
 * ## Why it exists
 *
 * `captureClient.send` posted from inside `ensurePort().then(...)`, a microtask
 * after the call. An import dissects in one synchronous pass of a minute or
 * more, so no microtask ran until it ended: every batch's rows and records, the
 * whole file, sat in the renderer as queued callbacks, and the store only saw
 * them at the end. A 2.4M-frame import took the renderer to 7.3 GB private and
 * out of memory. `PortQueue` posts in the same turn once the port is in hand,
 * so the message leaves while the pass runs.
 *
 * ## What is pinned
 *
 * - Before the connection resolves, calls wait and then run in call order.
 * - After it, a call with nothing waiting ahead runs synchronously - the
 *   property the import needs, checked inside one synchronous block.
 * - A call made while earlier ones still wait goes behind them, never ahead:
 *   an `open` must not overtake a read issued before it.
 * - Once dropped, nothing runs against the old port; calls get `null` at once.
 */
import { PortQueue } from '../../src/services/capture/portQueue';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      expected ${JSON.stringify(expected)}\n      actual   ${JSON.stringify(actual)}`}`);
}

const PORT = 'port';
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

{
  let open!: (port: string | null) => void;
  const connection = new Promise<string | null>((resolve) => { open = resolve; });
  const queue = new PortQueue<string>(() => connection);
  const order: string[] = [];
  queue.run(() => order.push('a'));
  queue.run(() => order.push('b'));
  check('before the connection nothing runs', order, []);
  open(PORT);
  // Called after resolve but before its callbacks ran: still behind a and b.
  queue.run(() => order.push('c'));
  await flush();
  check('queued calls run in call order once connected', order, ['a', 'b', 'c']);

  // One synchronous block, as an import's pass is: each call has run before
  // the next statement, with no turn of the event loop between.
  const seen: number[] = [];
  for (let i = 0; i < 3; i++) {
    queue.run(() => seen.push(i));
    seen.push(100 + i);
  }
  check('connected and nothing waiting: a call runs in the same turn', seen, [0, 100, 1, 101, 2, 102]);
}

{
  // The store died: the client drops the port, and its connection now
  // answers null. Nothing may reach the old port after that.
  let alive = true;
  const queue = new PortQueue<string>(() => Promise.resolve(alive ? PORT : null));
  const seen: (string | null)[] = [];
  queue.run((port) => seen.push(port));
  await flush();
  alive = false;
  queue.drop();
  // A call after the drop answers null in its own turn. Queued, each would
  // hold its message until the caller yields, and an import's pass never
  // does: a big import after a store death would fill the renderer as #19 did.
  queue.run((port) => seen.push(port));
  queue.run((port) => seen.push(port));
  check('dropped: later calls get null in the same turn, in order', seen, [PORT, null, null]);
}

// --- a post that throws, through the real client ------------------------------
//
// `captureClient` runs its uses inside `PortQueue`, and a use queued behind the
// connection runs inside a `.then` nobody holds. A `postMessage` that throws
// there (a DataCloneError - a real port throws it for a function) left the
// request's pending entry registered and its promise unsettled until the store
// died, and became an unhandled rejection. The caller is answered at once now.
{
  console.log('\n--- the client: a postMessage that throws ---\n');
  const { port1, port2 } = new MessageChannel();
  port2.onmessage = () => {};
  let onMessage: ((event: unknown) => void) | null = null;
  const fakeWindow = {
    addEventListener: (_type: string, listener: (event: unknown) => void) => { onMessage = listener; },
    removeEventListener: () => { onMessage = null; },
    inwire: {
      isDesktop: true,
      requestCaptureStorePort: () => {
        onMessage?.({ source: fakeWindow, data: { channel: 'inwire:capture-port' }, ports: [port1] });
      },
      onCaptureStoreExit: () => {},
    },
  };
  (globalThis as { window?: unknown }).window = fakeWindow;

  const unhandled: string[] = [];
  process.on('unhandledRejection', (reason) => { unhandled.push(String(reason)); });
  const warnings: string[] = [];
  const realWarn = console.warn;
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(' ')); };

  const { captureStore } = await import('../../src/services/capture/captureClient');
  const internals = captureStore as unknown as { pending: Map<number, unknown>; pendingScan: Map<number, unknown> };
  /** A function does not survive a structured clone: the port throws on it. */
  const unclonable = (() => 0) as unknown as number;
  const slow = Symbol('did not settle');
  const within = <T>(promise: Promise<T>) =>
    Promise.race([promise, new Promise<typeof slow>((resolve) => setTimeout(() => resolve(slow), 300))]);

  // All three are made in one synchronous block, before the connection has
  // resolved: every use below is queued, and runs inside the queue's `.then`.
  const queuedRead = captureStore.readBytes([unclonable]);
  const queuedScan = captureStore.scanCapture(unclonable as unknown as string);
  captureStore.prune([unclonable as unknown as string]);

  const read = await within(queuedRead);
  check('queued: a request whose post throws settles with its fallback', read === slow ? 'unsettled' : (read as Map<number, unknown>).size, 0);
  check('queued: ...and leaves no pending entry behind', internals.pending.size, 0);
  const scan = await within(queuedScan.result);
  check('queued: a scan whose post throws settles failed, with a message',
    scan === slow ? 'unsettled' : { status: scan.status, hasMessage: typeof (scan as { message?: unknown }).message === 'string' },
    { status: 'failed', hasMessage: true });
  check('queued: ...and leaves no pending scan behind', internals.pendingScan.size, 0);
  await new Promise((resolve) => setTimeout(resolve, 20));
  check('queued: a send whose post throws is not an unhandled rejection', unhandled, []);
  const pruneWarnings = () => warnings.filter((w) => w.includes("'prune'")).length;
  check('queued: ...it is warned about instead', pruneWarnings(), 1);

  // The port is in hand and nothing waits: the use runs in the caller's turn.
  const directRead = await within(captureStore.readBytes([unclonable]));
  check('direct: a request whose post throws settles with its fallback', directRead === slow ? 'unsettled' : (directRead as Map<number, unknown>).size, 0);
  check('direct: ...and leaves no pending entry behind', internals.pending.size, 0);
  const directScan = await within(captureStore.scanCapture(unclonable as unknown as string).result);
  check('direct: a scan whose post throws settles failed', directScan === slow ? 'unsettled' : directScan.status, 'failed');
  captureStore.prune([unclonable as unknown as string]);
  check('direct: a send whose post throws is warned about and does not throw', pruneWarnings(), 2);
  await new Promise((resolve) => setTimeout(resolve, 20));
  check('direct: ...and is no unhandled rejection', unhandled, []);
  console.warn = realWarn;
  port1.close();
  port2.close();
}

console.log(failures === 0 ? '\nAll port queue checks passed.' : `\n${failures} port queue check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
