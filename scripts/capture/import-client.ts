/**
 * The page's end of an import in a Worker.
 *
 *   npx tsx scripts/capture/import-client.ts
 *
 * `runWorkerImport` (src/services/importClient.ts) is driven here by two kinds of
 * Worker. A *scripted* one says exactly what a test needs it to (a crash, a
 * message after the run was cancelled). A *real* one runs `createImportRun`, the
 * import Worker's whole behaviour, in this isolate, its messages delivered a task
 * later as a Worker's are, against a fake capture store on a real `MessageChannel`
 * - so the tail it hands back, the secrets round trip, the one-chunk-at-a-time
 * handover and the release of the tail's bytes are the real ones. (Node threads
 * with the byte-for-byte comparison to the in-process route are
 * `import-worker-equivalence.ts`'s.)
 *
 * The page's key log here is a copy-mode `KeyLogStore` of its own: the real run
 * adopts snapshots into the process's `keyLog` singleton, which would otherwise be
 * the page's and the Worker's at once.
 */
import {
  runWorkerImport, type ImportClientDeps, type WorkerLike,
} from '../../src/services/importClient';
import { createImportRun } from '../../src/services/pipeline/importRun';
import type { FromImport, ImportRunOptions, ToImport } from '../../src/services/pipeline/importProtocol';
import { KeyLogStore } from '../../src/services/tls/keyLog';
import { BYTES_RESIDENT_FRAMES, estimateSummaryBytes } from '../../src/services/bufferBudget';
import type { ImportOutcome } from '../../src/services/tabularImport';
import { dnsTcpInput, tlsWithDsbInput } from './importEquivalenceRig';
import { pcapOf, udpFrame } from '../parity/synthetic';

let failures = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${JSON.stringify(detail)}`.slice(0, 400));
}

function withTimeout<T>(promise: Promise<T>, what: string, ms = 30_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: no answer in ${ms / 1000} s`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const later = (fn: () => void): void => { setTimeout(fn, 0); };

// --- the workers --------------------------------------------------------------------

class ScriptedWorker implements WorkerLike {
  onmessage: ((event: MessageEvent<FromImport>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: ((event: MessageEvent) => void) | null = null;
  terminated = false;
  readonly posted: ToImport[] = [];
  postMessage(message: ToImport): void { this.posted.push(message); }
  terminate(): void { this.terminated = true; }
  say(message: FromImport): void { this.onmessage?.({ data: message } as MessageEvent<FromImport>); }
}

/** `createImportRun` in this isolate, as a Worker would run it. */
class RealWorker implements WorkerLike {
  onmessage: ((event: MessageEvent<FromImport>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: ((event: MessageEvent) => void) | null = null;
  terminated = false;
  /** `>type` to the Worker, `<type` from it, in order. */
  readonly log: string[] = [];
  private readonly handle = createImportRun({
    post: (message) => {
      if (this.terminated) return;
      this.log.push(`<${message.type}`);
      later(() => this.onmessage?.({ data: message } as MessageEvent<FromImport>));
    },
  });

  postMessage(message: ToImport, transfer?: Transferable[]): void {
    this.log.push(`>${message.type}`);
    later(() => {
      if (!this.terminated) this.handle(message, message.type === 'start' ? (transfer ?? []) as unknown as MessagePort[] : []);
    });
  }

  terminate(): void { this.terminated = true; }
}

/** The capture store's far end of the ingest port: answers the credit, remembers the last row. */
function fakeStore() {
  const { port1, port2 } = new MessageChannel();
  const state = { lastId: 0, appended: 0, closed: false };
  port1.onmessage = (event: MessageEvent<{ type: string; ack?: number; packets?: { id: number }[] }>) => {
    const m = event.data;
    if (m.type === 'append' && m.packets !== undefined && m.packets.length > 0) {
      state.appended += m.packets.length;
      state.lastId = Math.max(state.lastId, m.packets[m.packets.length - 1].id);
    }
    if (m.type === 'appendBytes' && m.ack !== undefined) port1.postMessage({ type: 'bytesTaken', ack: m.ack });
  };
  port1.addEventListener('close', () => { state.closed = true; });
  return { port: port2 as unknown as MessagePort, state, close: () => port1.close() };
}

/** A page key log that counts who is subscribed. */
function trackedKeyLog() {
  const store = new KeyLogStore({ shared: false });
  const counts = { live: 0, peak: 0, added: 0 };
  return {
    store, counts,
    deps: {
      share: () => store.share(),
      add: (text: string) => { counts.added++; return store.add(text); },
      onSnapshot: (listener: Parameters<KeyLogStore['onSnapshot']>[0]) => {
        counts.live++;
        counts.peak = Math.max(counts.peak, counts.live);
        const off = store.onSnapshot(listener);
        return () => { counts.live--; off(); };
      },
    } satisfies ImportClientDeps['keyLog'],
  };
}

const OPTIONS: ImportRunOptions = {
  record: true, residentBytes: 256 * 1024 * 1024, maxFrames: 40, derivedBudget: 64 * 1024 * 1024,
  patchWindow: 64, batchFrames: 50, windowBytes: 64 * 1024, tailChunkRows: 15,
};

interface Rig {
  worker: ScriptedWorker | RealWorker;
  deps: ImportClientDeps;
  progress: [number, number][];
  opened: string[];
  keys: ReturnType<typeof trackedKeyLog>;
  store: ReturnType<typeof fakeStore>;
  spawned: number;
}

function rig(
  make: () => ScriptedWorker | RealWorker, options: ImportRunOptions = OPTIONS,
  overrides: Partial<ImportClientDeps> = {},
): Rig {
  const keys = trackedKeyLog();
  const store = fakeStore();
  const state: Rig = {
    worker: undefined as unknown as Rig['worker'], progress: [], opened: [], keys, store, spawned: 0,
    deps: {
      spawn: () => { state.spawned++; state.worker = make(); return state.worker; },
      ingestPort: async () => store.port,
      keyLog: keys.deps,
      onOpening: async () => { state.opened.push('capture-under-test'); return 'capture-under-test'; },
      storedThrough: () => store.state.lastId,
      onProgress: (read, total) => { state.progress.push([read, total]); },
      options,
      ...overrides,
    },
  };
  return state;
}

const fileOf = (bytes: Uint8Array, name = 'input.pcapng') => new File([bytes as unknown as BlobPart], name);

const ids = (outcome: ImportOutcome) => (outcome.ok ? outcome.packets.map((p) => p.id) : []);

// --- 1. success ---------------------------------------------------------------------

{
  const input = tlsWithDsbInput();
  const r = rig(() => new RealWorker(), { ...OPTIONS, maxFrames: input.maxFrames, tailChunkRows: input.tailChunkRows });
  const run = runWorkerImport(fileOf(input.bytes), r.deps);
  const outcome = await withTimeout(run.result, 'success');
  const worker = r.worker as RealWorker;
  check('success resolves after done with decoded tail and derived',
    outcome.ok === true && outcome.packets.length === 10 && outcome.totalFrames === 10 && outcome.stored === 10
    && (outcome.derived?.length ?? 0) > 0 && outcome.estimates?.length === 10
    && JSON.stringify(ids(outcome)) === JSON.stringify([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    && outcome.packets.every((p) => p.rawBytes.length > 0)
    && worker.terminated && worker.log.indexOf('<done') > 0 && r.opened.length === 1,
    { ok: outcome.ok, packets: outcome.ok ? outcome.packets.length : 0, log: worker.log.join(' ') });
  check('shipped estimates equal the page estimate of each decoded row',
    outcome.ok === true && outcome.estimates?.length === outcome.packets.length
    && outcome.packets.every((p, i) => outcome.estimates?.[i] === estimateSummaryBytes(p)));
  check('...the derived answers each own a whole buffer (keepDerived transfers them)',
    outcome.ok === true && (outcome.derived ?? []).every(([, b]) => b.byteOffset === 0 && b.byteLength === b.buffer.byteLength)
    && new Set((outcome.derived ?? []).map(([, b]) => b.buffer)).size === (outcome.derived ?? []).length);
  check('...the Worker was started with the key log first, then the port',
    worker.log[0] === '>keylog-shared' && worker.log[1] === '>start', worker.log.slice(0, 3));

  // 2. secrets
  const posted = worker.log;
  check('secrets are added to the page key log and acked with seq',
    r.keys.counts.added === 1 && posted.includes('<secrets') && posted.includes('>secretsTaken')
    && posted.indexOf('>secretsTaken') > posted.indexOf('<secrets')
    && r.keys.store.stats().secrets > 0,
    { added: r.keys.counts.added, stats: r.keys.store.stats() });

  // 6. one chunk in flight
  const tailEvents = posted.filter((t) => t === '<tail' || t === '>tailTaken' || t === '<done');
  check('one tail chunk is in flight at a time',
    JSON.stringify(tailEvents) === JSON.stringify(['<tail', '>tailTaken', '<tail', '>tailTaken', '<tail', '>tailTaken', '<done']),
    tailEvents);

  // 5. snapshot subscription
  check('the snapshot subscription ends with the run (success)',
    r.keys.counts.peak === 1 && r.keys.counts.live === 0, r.keys.counts);
  r.store.close();
}

// --- 3. a Worker that fails never hangs -----------------------------------------------

{
  const r = rig(() => new ScriptedWorker());
  const run = runWorkerImport(fileOf(new Uint8Array(8)), r.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  const worker = r.worker as ScriptedWorker;
  worker.onerror?.({ message: 'the Worker ran out of memory', preventDefault: () => {} } as ErrorEvent);
  const outcome = await withTimeout(run.result, 'onerror');
  check('a Worker error resolves a failure, never hangs (onerror)',
    outcome.ok === false && outcome.failure.kind === 'unreadable'
    && outcome.failure.message === 'the Worker ran out of memory' && worker.terminated,
    outcome);
  check('the snapshot subscription ends with the run (onerror)', r.keys.counts.peak === 1 && r.keys.counts.live === 0, r.keys.counts);
  r.store.close();
}
{
  const r = rig(() => new ScriptedWorker());
  const run = runWorkerImport(fileOf(new Uint8Array(8)), r.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  (r.worker as ScriptedWorker).onmessageerror?.({} as MessageEvent);
  const outcome = await withTimeout(run.result, 'onmessageerror');
  check('...and an unreadable message (onmessageerror)',
    outcome.ok === false && outcome.failure.kind === 'unreadable' && (r.worker as ScriptedWorker).terminated);
  r.store.close();
}
{
  // The real run on a file that cannot be read - the one a user truncated, moved
  // or lost the disk of mid-import: Chromium's `File` rejects the read. The walk
  // does not throw on a torn file (it ends where the tear is), so this is the
  // way the Worker's `failed` is reached for real.
  const r = rig(() => new RealWorker());
  const input = dnsTcpInput();
  let reads = 0;
  const vanishing = {
    name: 'gone.pcap', size: input.bytes.length,
    slice: (from: number, to: number) => ({
      arrayBuffer: async () => {
        if (++reads > 2) throw new Error('NotReadableError: the file could not be read');
        const part = input.bytes.slice(from, to);
        return part.buffer.slice(part.byteOffset, part.byteOffset + part.byteLength);
      },
    }),
  } as unknown as File;
  const outcome = await withTimeout(runWorkerImport(vanishing, r.deps).result, 'unreadable file');
  check('a `failed` from a file that cannot be read resolves a failure (real run)',
    outcome.ok === false && outcome.failure.kind === 'unreadable' && /could not be read/.test(outcome.failure.message)
    && (r.worker as RealWorker).terminated && r.keys.counts.live === 0
    && (r.worker as RealWorker).log.includes('<failed'),
    outcome);
  r.store.close();
}
{
  // A file cut short mid-frame: the walk ends where the tear is, never hangs.
  const input = dnsTcpInput();
  const r = rig(() => new RealWorker());
  const outcome = await withTimeout(
    runWorkerImport(fileOf(input.bytes.slice(0, Math.floor(input.bytes.length * 0.6) + 7), 'cut.pcap'), r.deps).result,
    'truncated');
  check('a file cut short mid-frame resolves, with the frames before the tear (real run)',
    outcome.ok === true && outcome.packets.length > 0 && outcome.totalFrames !== undefined && outcome.totalFrames < 362,
    outcome.ok ? { n: outcome.packets.length, total: outcome.totalFrames } : outcome);
  r.store.close();
}
{
  const r = rig(() => new ScriptedWorker(), OPTIONS, {
    onOpening: async () => { throw new Error('the store would not open'); },
  });
  const run = runWorkerImport(fileOf(new Uint8Array(8)), r.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  (r.worker as ScriptedWorker).say({ type: 'opening' });
  const outcome = await withTimeout(run.result, 'open fails');
  check('a store that will not open resolves a failure and ends the Worker',
    outcome.ok === false && outcome.failure.message === 'the store would not open' && (r.worker as ScriptedWorker).terminated);
  r.store.close();
}
{
  const r = rig(() => new ScriptedWorker(), OPTIONS, {
    ingestPort: async () => { throw new Error('the capture store did not answer'); },
  });
  const outcome = await withTimeout(runWorkerImport(fileOf(new Uint8Array(8)), r.deps).result, 'no port');
  check('no ingest port resolves a failure before any Worker exists',
    outcome.ok === false && outcome.failure.message === 'the capture store did not answer' && r.spawned === 0);
  r.store.close();
}

// --- 4. a cancelled run is over; the next is independent -------------------------------

{
  const input = dnsTcpInput();
  let cancel: () => void = () => {};
  let firstRunCalls = 0;
  const counted = (fn: () => void) => { firstRunCalls++; fn(); };
  const first = rig(() => new RealWorker(), OPTIONS, {
    onOpening: async () => {
      // The page's own open: Cancel is pressed while it is in progress.
      counted(() => cancel());
      return 'capture-first';
    },
    onProgress: () => { firstRunCalls++; },
  });
  const run1 = runWorkerImport(fileOf(input.bytes), first.deps);
  cancel = run1.cancel;
  const outcome1 = await withTimeout(run1.result, 'cancelled');
  const worker1 = first.worker as RealWorker;
  const callsAtCancel = firstRunCalls;
  const logAtCancel = worker1.log.length;
  check('cancel resolves a cancelled failure, ends the Worker and the subscription',
    outcome1.ok === false && outcome1.failure.kind === 'cancelled' && worker1.terminated && first.keys.counts.live === 0,
    outcome1);

  // A second import, started at once, with a Worker of its own.
  const second = rig(() => new RealWorker());
  const outcome2 = await withTimeout(runWorkerImport(fileOf(input.bytes), second.deps).result, 'second run');
  await withTimeout(new Promise((resolve) => setTimeout(resolve, 50)), 'settle');
  check('a second run is independent: its own Worker, its whole tail, no frame of the first',
    outcome2.ok === true && outcome2.packets.length === 40 && second.spawned === 1 && second.worker !== first.worker
    && outcome2.totalFrames === 362 && ids(outcome2)[39] === 362,
    { ok: outcome2.ok, n: outcome2.ok ? outcome2.packets.length : 0 });
  check('messages from the cancelled run are ignored after it ended',
    firstRunCalls === callsAtCancel && !worker1.log.includes('>storeOpen') && worker1.log.length === logAtCancel,
    { firstRunCalls, callsAtCancel, after: worker1.log.slice(logAtCancel) });

  // A message from a Worker that has been cancelled does nothing, even when it is
  // delivered to a handler captured before the cancel.
  const scripted = rig(() => new ScriptedWorker());
  const run3 = runWorkerImport(fileOf(new Uint8Array(8)), scripted.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  const sw = scripted.worker as ScriptedWorker;
  const stale = sw.onmessage;
  run3.cancel();
  stale?.({ data: { type: 'progress', readBytes: 1, totalBytes: 2 } } as MessageEvent<FromImport>);
  stale?.({ data: { type: 'opening' } } as MessageEvent<FromImport>);
  stale?.({ data: { type: 'secrets', seq: 1, text: 'x' } } as MessageEvent<FromImport>);
  const postedAfter = sw.posted.length;
  const out3 = await run3.result;
  check('a message that reaches a cancelled run through a handler it kept changes nothing',
    out3.ok === false && out3.failure.kind === 'cancelled' && scripted.progress.length === 0
    && scripted.opened.length === 0 && scripted.keys.counts.added === 0 && sw.posted.length === postedAfter);
  check('the snapshot subscription ends with the run (cancel)', scripted.keys.counts.peak === 1 && scripted.keys.counts.live === 0);
  // Cancel before the port arrives: no Worker is ever made.
  let release: (port: MessagePort) => void = () => {};
  const slowPort = new Promise<MessagePort>((resolve) => { release = resolve; });
  const early = rig(() => new ScriptedWorker(), OPTIONS, { ingestPort: () => slowPort });
  const run4 = runWorkerImport(fileOf(new Uint8Array(8)), early.deps);
  run4.cancel();
  release(early.store.port);
  const out4 = await run4.result;
  await withTimeout(new Promise((resolve) => setTimeout(resolve, 20)), 'settle');
  check('cancel before the port arrives never makes a Worker', out4.ok === false && out4.failure.kind === 'cancelled' && early.spawned === 0);
  for (const s of [first.store, second.store, scripted.store, early.store]) s.close();
}

// --- 7. the tail's bytes are released below what the store holds ------------------------

{
  const TOTAL = BYTES_RESIDENT_FRAMES + 2_500;
  const frames: Uint8Array[] = [];
  for (let i = 0; i < TOTAL; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const bytes = pcapOf(frames);
  const options: ImportRunOptions = {
    ...OPTIONS, maxFrames: TOTAL + 10, batchFrames: 500, windowBytes: 32 * 1024, tailChunkRows: 10_000,
    // The walk would otherwise finish before the store has said a word, and
    // there would be nothing stored to release against: held to the store's pace,
    // `progress` and `storedThrough` interleave as they do on a file that takes
    // seconds.
    creditFrames: 2_000,
  };
  const run = async (storedThrough: ((store: ReturnType<typeof fakeStore>) => number) | null) => {
    const r = rig(() => new RealWorker(), options);
    if (storedThrough !== null) r.deps.storedThrough = () => storedThrough(r.store);
    else r.deps.storedThrough = () => 0;
    const outcome = await withTimeout(runWorkerImport(fileOf(bytes, 'big.pcap'), r.deps).result, 'big import', 120_000);
    const storedAtEnd = r.store.state.lastId;
    r.store.close();
    return { outcome, storedAtEnd, worker: r.worker as RealWorker };
  };
  const { outcome, storedAtEnd } = await run((store) => store.state.lastId);
  if (outcome.ok) {
    const released = outcome.packets.filter((p) => p.rawBytes.length === 0);
    const newest = outcome.packets.slice(-BYTES_RESIDENT_FRAMES);
    // `adoptAccounting` trusts these; `planBufferTrim` later subtracts the page's own
    // estimate of the same decoded rows, so the two must agree row for row, bytes
    // released or not.
    check('shipped estimates equal the page estimate of each decoded row (27,500 rows, some released)',
      outcome.estimates?.length === outcome.packets.length
      && outcome.packets.every((p, i) => outcome.estimates?.[i] === estimateSummaryBytes(p)));
    check(`tail bytes are released below storedThrough on the Worker route (${released.length} of ${outcome.packets.length} rows)`,
      outcome.packets.length === TOTAL && released.length > 0
      && released.every((p) => p.id <= storedAtEnd && p.id <= TOTAL - BYTES_RESIDENT_FRAMES)
      && newest.every((p) => p.rawBytes.length > 0),
      { rows: outcome.packets.length, released: released.length, storedAtEnd });
  } else {
    check('tail bytes are released below storedThrough on the Worker route', false, outcome);
  }
  // With nothing known to be stored nothing may be released: a tail that lets go of
  // bytes the store does not hold has lost them.
  const nothing = await run(null);
  check('...and nothing is released while the store has reported nothing',
    nothing.outcome.ok === true && nothing.outcome.packets.every((p) => p.rawBytes.length > 0));
}

// --- 8. a stale storedThrough from the previous capture is never forwarded --------------

{
  // `progress` is posted at each window load, the first before the capture is open;
  // the page's `storedRange` is then the PREVIOUS capture's. The Worker keeps the
  // highest id it is told, so that must not be forwarded until the open resolved.
  const frames: Uint8Array[] = [];
  for (let i = 0; i < 3_000; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const bytes = pcapOf(frames);
  const options: ImportRunOptions = { ...OPTIONS, maxFrames: 3_100, batchFrames: 500, windowBytes: 8 * 1024, tailChunkRows: 1_000 };
  let open = false;
  let progressBeforeOpen = 0;
  const r = rig(() => new RealWorker(), options);
  r.deps.storedThrough = () => (open ? r.store.state.lastId : 1_000_000_000);
  r.deps.onOpening = async () => {
    progressBeforeOpen = r.progress.length;
    await new Promise<void>((resolve) => { setTimeout(resolve, 20); });
    open = true;
    return 'capture-under-test';
  };
  const outcome = await withTimeout(runWorkerImport(fileOf(bytes, 'stale.pcap'), r.deps).result, 'stale storedThrough');
  const log = (r.worker as RealWorker).log;
  const firstThrough = log.indexOf('>storedThrough');
  const staleSent = log.some((t, i) => t === '>storedThrough' && i < log.indexOf('>storeOpen'));
  check('a window load is reported before the capture is open (the case under test exists)', progressBeforeOpen > 0, progressBeforeOpen);
  check('no storedThrough reaches the Worker before storeOpen, whatever the page last held',
    !staleSent && (firstThrough === -1 || firstThrough > log.indexOf('>storeOpen')), log.slice(0, 12));
  check('...and the import is whole: every row keeps its bytes',
    outcome.ok === true && outcome.packets.length === 3_000 && outcome.packets.every((p) => p.rawBytes.length > 0));
  r.store.close();
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('The import client holds.');
process.exit(0);
