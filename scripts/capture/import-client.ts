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
 * - so the tail it hands back (built on the page from the Worker's `rows`), the
 * secrets round trip and the release of the tail's bytes are the real ones. (Node threads
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
import { createImportRole } from '../../src/workers/importRole';
import { IMPORT_ROWS_IN_FLIGHT, createRowsCredit, type RowsTaken } from '../../src/services/importCredit';
import type { FromImport, ImportRunOptions, ToImport } from '../../src/services/pipeline/importProtocol';
import { KeyLogStore } from '../../src/services/tls/keyLog';
import { BYTES_RESIDENT_FRAMES, estimateSummaryBytes } from '../../src/services/bufferBudget';
import type { ImportOutcome } from '../../src/services/tabularImport';
import { dnsTcpInput, tlsWithDsbInput } from './importEquivalenceRig';
import { pcapOf, udpFrame } from '../parity/synthetic';
import { PackReader, PackedFlush, packRows, type PackedRows } from '../../src/services/pipeline/rowPack';
import type { Packet } from '../../src/types/packet';
import { readPackedBatch } from '../../src/services/packRead';
import { writeSyntheticKeyLog } from '../electron/syntheticKeyLog';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
  readonly posted: (ToImport | RowsTaken)[] = [];
  postMessage(message: ToImport | RowsTaken): void { this.posted.push(message); }
  terminate(): void { this.terminated = true; }
  say(message: FromImport): void { this.onmessage?.({ data: message } as MessageEvent<FromImport>); }
}

/**
 * The import role (`createImportRole`: the run behind its rows credit) in this isolate, as a
 * Worker would run it. `starved` is a page that never says `rowsTaken`: the Worker is left
 * holding every `rows` batch past the credit.
 */
class RealWorker implements WorkerLike {
  starved = false;
  onmessage: ((event: MessageEvent<FromImport>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: ((event: MessageEvent) => void) | null = null;
  terminated = false;
  /** `>type` to the Worker, `<type` from it, in order. */
  readonly log: string[] = [];
  private readonly handle = createImportRole((message) => {
    if (this.terminated) return;
    this.log.push(`<${message.type}`);
    later(() => this.onmessage?.({ data: message } as MessageEvent<FromImport>));
  });

  postMessage(message: ToImport | RowsTaken, transfer?: Transferable[]): void {
    this.log.push(`>${message.type}`);
    if (this.starved && message.type === 'rowsTaken') return;
    later(() => {
      if (!this.terminated) this.handle(message, message.type === 'start' ? (transfer ?? []) as unknown as MessagePort[] : []);
    });
  }

  terminate(): void { this.terminated = true; }
}

/** The capture store's far end of the ingest port: answers the credit, remembers the last row. */
function fakeStore(options: { holdAcks?: boolean } = {}) {
  const { port1, port2 } = new MessageChannel();
  // `openId` is the capture the store has open (`CaptureHost.isForAnotherCapture`
  // drops a tagged message for any other, silently); `dropped` counts those.
  const state = {
    lastId: 0, appended: 0, closed: false, dropped: 0,
    openId: 'capture-under-test' as string | null, lastPacked: null as unknown,
  };
  // The store's own reader: the Worker sends `appendPacked`, never `append`.
  const reader = new PackReader();
  port1.onmessage = (event: MessageEvent<{ type: string; ack?: number; rows?: PackedRows; captureId?: string }>) => {
    const m = event.data;
    if (m.captureId !== undefined && m.captureId !== state.openId) { state.dropped++; return; }
    if (m.type === 'appendPacked' && m.rows !== undefined) {
      state.lastPacked = m;
      const rows = reader.read(m.rows);
      state.appended += rows.length;
      if (rows.length > 0) state.lastId = Math.max(state.lastId, rows[rows.length - 1].id);
    }
    if (m.type === 'appendBytes' && m.ack !== undefined && options.holdAcks !== true) {
      port1.postMessage({ type: 'bytesTaken', ack: m.ack });
    }
  };
  port1.addEventListener('close', () => { state.closed = true; });
  return {
    port: port2 as unknown as MessagePort, state, close: () => port1.close(),
    /**
     * A message already in flight from a Worker that has since been terminated:
     * the last `appendPacked` the store took, sent again from the Worker's end.
     */
    lateAppend: () => port2.postMessage(state.lastPacked),
  };
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
      reserve: (textBytes: number) => { store.reserve(textBytes); },
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
  patchWindow: 64, batchFrames: 50, windowBytes: 64 * 1024,
};

interface Rig {
  worker: ScriptedWorker | RealWorker;
  deps: ImportClientDeps;
  progress: [number, number][];
  opened: string[];
  keys: ReturnType<typeof trackedKeyLog>;
  store: ReturnType<typeof fakeStore>;
  spawned: number;
  /** Listeners `deps.onStoreLost` holds right now; `storeLost` is the store dying. */
  lost: Set<(message: string) => void>;
  storeLost: (message: string) => void;
}

function rig(
  make: () => ScriptedWorker | RealWorker, options: ImportRunOptions = OPTIONS,
  overrides: Partial<ImportClientDeps> = {}, storeOptions: Parameters<typeof fakeStore>[0] = {},
): Rig {
  const keys = trackedKeyLog();
  const store = fakeStore(storeOptions);
  const lost = new Set<(message: string) => void>();
  const state: Rig = {
    worker: undefined as unknown as Rig['worker'], progress: [], opened: [], keys, store, spawned: 0, lost,
    storeLost: (message) => { for (const listener of [...lost]) listener(message); },
    deps: {
      spawn: () => { state.spawned++; state.worker = make(); return state.worker; },
      ingestPort: async () => store.port,
      keyLog: keys.deps,
      onOpening: async () => { state.opened.push('capture-under-test'); return 'capture-under-test'; },
      storedThrough: () => store.state.lastId,
      onStoreLost: (listener) => { lost.add(listener); return () => { lost.delete(listener); }; },
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
  const r = rig(() => new RealWorker(), { ...OPTIONS, maxFrames: input.maxFrames });
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

  // 6. the rows arrive as they are built, and the page answers each with `rowsTaken` (the credit)
  const sentToWorker = [...new Set(posted.filter((t) => t.startsWith('>')))].sort();
  const rowsIn = posted.filter((t) => t === '<rows').length;
  check('the Worker sent its rows batch by batch before `done`, and the page answered only the key log, start, secrets, storeOpen and one rowsTaken per batch',
    rowsIn >= 1 && posted.lastIndexOf('<rows') < posted.indexOf('<done')
    && !posted.includes('<tail')
    && sentToWorker.every((t) => ['>keylog-shared', '>start', '>secretsTaken', '>storeOpen', '>rowsTaken'].includes(t))
    && posted.filter((t) => t === '>rowsTaken').length === rowsIn,
    { sentToWorker, rows: rowsIn });
  check('the store was sent every row packed (appendPacked): the Worker keeps no copy of its own',
    r.store.state.appended === 10, r.store.state);

  // 5. snapshot subscription
  check('the snapshot subscription ends with the run (success)',
    r.keys.counts.peak === 1 && r.keys.counts.live === 0, r.keys.counts);
  r.store.close();
}

// --- 2b. a large secrets text moves the page's key log buffer once --------------------------
//
// The page's store is the live (shared) kind here: a snapshot is posted only when the
// buffer is replaced. A key log's worth of text added piece by piece grew it at every
// overflow, each leaving an old buffer in every reader; the page reserves for the text first.

{
  const dir = mkdtempSync(join(tmpdir(), 'inwire-import-client-'));
  let text = '';
  try {
    const file = join(dir, 'keylog.txt');
    await writeSyntheticKeyLog(file, 20_000);
    text = readFileSync(file, 'latin1');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const live = new KeyLogStore({ shared: true });
  const emitted: SharedArrayBuffer[] = [];
  live.onSnapshot((snapshot) => { emitted.push(snapshot.buffer as SharedArrayBuffer); });
  const r = rig(() => new ScriptedWorker(), OPTIONS, { keyLog: live });
  const run = runWorkerImport(fileOf(new Uint8Array(8)), r.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  const worker = r.worker as ScriptedWorker;
  worker.say({ type: 'secrets', seq: 7, text });
  const ack = worker.posted.find((m) => m.type === 'secretsTaken');
  check('a large secrets text (20,000 connections) is held whole by the live page key log',
    live.stats().connections === 20_000 && live.stats().secrets > 100_000 && live.stats().dropped === 0, live.stats());
  check('...and moves the buffer exactly once: one snapshot, the reserve', emitted.length === 1, emitted.length);
  check('...the ack carries seq and the reserved buffer, which is the current one',
    ack?.type === 'secretsTaken' && ack.seq === 7 && ack.snapshot !== undefined
    && ack.snapshot.buffer === emitted[0] && ack.snapshot.buffer === live.share().buffer
    && ack.snapshot.live, ack);
  run.cancel();
  await run.result;
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

// --- 4b. Cancel mid-import, and a store that dies mid-import ----------------------------
//
// The store never answers the Worker's credit here, so the Worker is parked on it,
// as it is when the store is slow or gone: the one state in which only the page can
// end the run.

async function stalledRun(name: string) {
  const frames: Uint8Array[] = [];
  for (let i = 0; i < 6_000; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const r = rig(() => new RealWorker(), {
    ...OPTIONS, maxFrames: 6_100, batchFrames: 500, windowBytes: 32 * 1024, creditFrames: 1_000,
  }, {}, { holdAcks: true });
  const run = runWorkerImport(fileOf(pcapOf(frames), name), r.deps);
  for (let waited = 0; r.store.state.appended === 0 && waited < 200; waited++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  // Long enough for the Worker to have read on until the credit stopped it.
  await new Promise((resolve) => setTimeout(resolve, 100));
  return { r, run, worker: r.worker as RealWorker };
}

{
  const { r, run, worker } = await stalledRun('cancel.pcap');
  const atCancel = { appended: r.store.state.appended, log: worker.log.length };
  check('the Worker is parked on credit, having written some rows, when Cancel is pressed',
    atCancel.appended > 0 && atCancel.appended < 6_000 && !worker.terminated, atCancel);
  run.cancel();
  const outcome = await withTimeout(run.result, 'cancel mid-import', 5_000);
  // The lifecycle's `fail()` discards the capture: the store has no open capture.
  r.store.state.openId = null;
  r.store.lateAppend();
  await new Promise((resolve) => setTimeout(resolve, 50));
  check('cancel mid-import discards it and a late tagged append is dropped',
    outcome.ok === false && outcome.failure.kind === 'cancelled' && worker.terminated
    && r.keys.counts.live === 0 && r.lost.size === 0
    && r.store.state.appended === atCancel.appended && r.store.state.dropped === 1 && worker.log.length === atCancel.log,
    { kind: outcome.ok ? 'ok' : outcome.failure.kind, now: r.store.state.appended, dropped: r.store.state.dropped });
  r.store.close();
}
{
  const { r, run, worker } = await stalledRun('lost.pcap');
  check('the page is listening for the store while the Worker waits', r.lost.size === 1, r.lost.size);
  r.storeLost('the capture store stopped');
  let outcome: ImportOutcome | null = null;
  try { outcome = await withTimeout(run.result, 'store death', 3_000); } catch { /* hung: checked below */ }
  check('store death mid-import ends the run as a failure',
    outcome !== null && outcome.ok === false && outcome.failure.kind === 'unreadable'
    && outcome.failure.message === 'the capture store stopped' && worker.terminated
    && r.lost.size === 0 && r.keys.counts.live === 0,
    { settled: outcome !== null, terminated: worker.terminated, listeners: r.lost.size });
  r.storeLost('again');
  check('...and a second report from the store changes nothing', r.lost.size === 0);
  if (outcome === null) run.cancel();
  r.store.close();
}
{
  // Every other exit lets go of the store listener too.
  const done = rig(() => new RealWorker());
  const input = dnsTcpInput();
  const outcome = await withTimeout(runWorkerImport(fileOf(input.bytes), done.deps).result, 'listener on success');
  check('the store listener ends with the run (success)', outcome.ok === true && done.lost.size === 0, done.lost.size);
  const failing = rig(() => new ScriptedWorker());
  const run = runWorkerImport(fileOf(new Uint8Array(8)), failing.deps);
  await withTimeout(new Promise((resolve) => later(() => resolve(undefined))), 'start');
  const during = failing.lost.size;
  run.cancel();
  await run.result;
  check('...and the listener is held for the run only: one while it runs, none after Cancel', during === 1 && failing.lost.size === 0, [during, failing.lost.size]);
  done.store.close();
  failing.store.close();
}

// --- 7. the tail's bytes are released below what the store holds ------------------------

{
  const TOTAL = BYTES_RESIDENT_FRAMES + 2_500;
  const frames: Uint8Array[] = [];
  for (let i = 0; i < TOTAL; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const bytes = pcapOf(frames);
  const options: ImportRunOptions = {
    ...OPTIONS, maxFrames: TOTAL + 10, batchFrames: 500, windowBytes: 32 * 1024,
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

// --- 8. a scripted Worker sends `rows`; the page keeps the tail and releases its bytes ---

{
  // The Worker says opening, rows (packed with the real `packRows` and
  // `PackedFlush`, a fresh map each, as `importRun` does), progress and done, and
  // the page builds the tail. What it must do: keep the tail by the sizes the
  // Worker gave; let go of the bytes below `storedThrough()` only once the capture
  // is open (before that `storedRange` is the PREVIOUS capture's, and a stale high
  // answer would release bytes this store never got); and send the Worker nothing
  // in answer to a `progress`.
  const TOTAL = BYTES_RESIDENT_FRAMES + 500;
  const BATCH = 500;
  const row = (id: number): Packet => ({
    id, source: '10.0.0.4', destination: '93.184.216.34', protocol: 'TCP', info: `frame ${id}`, status: 'ok',
    length: 100, tsUs: 1_788_000_000_000_000 + id * 1000, relativeTime: id / 1000, timeDelta: 0.001,
    interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array([id & 0xff, (id >> 8) & 0xff, 0, 0, 0, 0, 0, 0]),
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'], sourcePort: 50000, destPort: 443, fields: { 'tcp.seq': id },
  } as Packet);
  /** The message for rows `from`..`to` (ids): one pack of its own, sizes of `size` each. */
  const rowsMessage = (from: number, to: number, size: number): FromImport => {
    const batch: Packet[] = [];
    for (let id = from; id <= to; id++) batch.push(row(id));
    const pack = packRows(from, batch, batch.map((p) => p.rawBytes.length));
    const flush = new PackedFlush();
    batch.forEach((p, i) => flush.packed(pack, i, p.rawBytes, null));
    return { type: 'rows', pack: flush.seal(new Map()), sizes: batch.map(() => size) };
  };
  const tick = () => new Promise<void>((resolve) => { setTimeout(resolve, 5); });
  const progress: FromImport = { type: 'progress', readBytes: 1, totalBytes: 2 };
  const done: FromImport = {
    type: 'done', totalFrames: TOTAL, built: TOTAL, missedPatches: 0, facts: {} as never, derived: [],
  };

  /**
   * One run: `openFirst` has the capture open before any row; otherwise the rows
   * and two progress reports come first and the open is never answered.
   */
  const play = async (options: ImportRunOptions, storedThrough: number, openFirst: boolean, size = 100) => {
    const r = rig(() => new ScriptedWorker(), options);
    let release: (id: string) => void = () => {};
    r.deps.storedThrough = () => storedThrough;
    r.deps.onOpening = () => new Promise<string>((resolve) => { release = resolve; });
    const run = runWorkerImport(fileOf(new Uint8Array(8), 'scripted.pcap'), r.deps);
    await tick();
    const worker = r.worker as ScriptedWorker;
    worker.say({ type: 'opening' });
    if (openFirst) {
      release('capture-under-test');
      await tick();
    }
    for (let from = 1; from <= TOTAL; from += BATCH) {
      worker.say(rowsMessage(from, Math.min(TOTAL, from + BATCH - 1), size));
      worker.say(progress);
    }
    const postedBeforeProgress = worker.posted.length;
    worker.say(progress);
    const answered = worker.posted.length - postedBeforeProgress;
    worker.say(done);
    const outcome = await withTimeout(run.result, 'scripted');
    r.store.close();
    return { outcome, worker, answered };
  };
  const base: ImportRunOptions = { ...OPTIONS, maxFrames: TOTAL + 10, residentBytes: Number.MAX_SAFE_INTEGER };

  // Before the open: a store that answers high must release nothing.
  const early = await play(base, 1_000_000_000, false);
  check('a progress before storeOpen releases nothing, even when storedThrough() answers high',
    early.outcome.ok === true && early.outcome.packets.length === TOTAL
    && early.outcome.packets.every((p) => p.rawBytes.length > 0),
    early.outcome.ok ? { n: early.outcome.packets.length } : early.outcome);
  check('...and the Worker is sent only the key log, the start and a rowsTaken per batch, never a storedThrough',
    early.worker.posted.map((m) => m.type).every((t) => t === 'keylog-shared' || t === 'start' || t === 'rowsTaken'),
    early.worker.posted.map((m) => m.type));

  // After it: bytes go below storedThrough, never the newest BYTES_RESIDENT_FRAMES.
  const high = await play(base, 1_000_000_000, true);
  if (high.outcome.ok) {
    const releasedIds = high.outcome.packets.filter((p) => p.rawBytes.length === 0).map((p) => p.id);
    check('after storeOpen the oldest rows let go of their bytes, and the newest BYTES_RESIDENT_FRAMES keep theirs',
      releasedIds.length === TOTAL - BYTES_RESIDENT_FRAMES && releasedIds[0] === 1
      && releasedIds[releasedIds.length - 1] === TOTAL - BYTES_RESIDENT_FRAMES
      && high.outcome.packets.slice(-BYTES_RESIDENT_FRAMES).every((p) => p.rawBytes.length > 0),
      { released: releasedIds.length });
    check('...no message is posted to the Worker in answer to a progress',
      high.answered === 0 && high.worker.posted.map((m) => m.type).every((t) => ['keylog-shared', 'start', 'storeOpen', 'rowsTaken'].includes(t)),
      { answered: high.answered, types: high.worker.posted.map((m) => m.type) });
  } else {
    check('after storeOpen the oldest rows let go of their bytes', false, high.outcome);
  }
  const low = await play(base, 100, true);
  check('...and only as far as storedThrough() says (ids 1-100)',
    low.outcome.ok === true
    && low.outcome.packets.filter((p) => p.rawBytes.length === 0).map((p) => p.id).join() === Array.from({ length: 100 }, (_, i) => i + 1).join());

  // The tail is trimmed by the sizes the Worker gave, not by the page's own estimate.
  const trimmed = await play({ ...base, residentBytes: 100 * (TOTAL - 50) }, 0, true, 100);
  check('the tail is the newest rows the Worker\'s sizes allow, and its estimates are those sizes',
    trimmed.outcome.ok === true && trimmed.outcome.packets.length === TOTAL - 50
    && trimmed.outcome.packets[0].id === 51 && trimmed.outcome.packets.at(-1)?.id === TOTAL
    && trimmed.outcome.estimates?.length === TOTAL - 50 && trimmed.outcome.estimates.every((e) => e === 100)
    && trimmed.outcome.packets.every((p) => estimateSummaryBytes(p) !== 100),
    trimmed.outcome.ok ? { n: trimmed.outcome.packets.length, first: trimmed.outcome.packets[0]?.id } : trimmed.outcome);
}

// --- 10. the Worker's rows credit (1.3) ----------------------------------------------------
//
// The Worker used to post every `rows` batch as it was built; a Worker faster than the page
// piled them in the page's message queue. Now at most IMPORT_ROWS_IN_FLIGHT are on their way
// unanswered, and the page's `rowsTaken` (after each decode) releases one.

{
  type Out = { type: 'rows' | 'progress' | 'done'; n?: number };
  const posted: Out[] = [];
  const credit = createRowsCredit<Out>((message) => { posted.push(message); });
  const rowsOut = () => posted.filter((m) => m.type === 'rows').length;
  for (let n = 0; n < 20; n++) credit.send({ type: 'rows', n });
  check('with a page that answers nothing, the Worker posts exactly the credit and waits',
    rowsOut() === IMPORT_ROWS_IN_FLIGHT && IMPORT_ROWS_IN_FLIGHT === 8, rowsOut());
  credit.taken();
  check('one rowsTaken releases exactly one more, in order',
    rowsOut() === 9 && posted[8].n === 8, { rows: rowsOut(), last: posted.at(-1) });
  credit.send({ type: 'progress' });
  credit.send({ type: 'progress' });
  credit.send({ type: 'progress' });
  credit.send({ type: 'done' });
  check('progress and done wait behind the rows still held, so done cannot overtake a row',
    !posted.some((m) => m.type === 'progress' || m.type === 'done'));
  for (let i = 0; i < 11; i++) credit.taken();
  const order = posted.map((m) => m.type === 'rows' ? 'r' : m.type === 'progress' ? 'p' : 'd').join('');
  check('...and go out in order once the rows are through, the held progress reports as one',
    order === 'r'.repeat(20) + 'pd', order);
  for (let i = 0; i < 30; i++) credit.taken();
  const fresh: Out[] = [];
  const again = createRowsCredit<Out>((message) => { fresh.push(message); });
  for (let i = 0; i < 5; i++) again.taken();
  for (let n = 0; n < 20; n++) again.send({ type: 'rows', n });
  check('spurious acknowledgements do not raise the credit above the bound', fresh.length === IMPORT_ROWS_IN_FLIGHT, fresh.length);
}

async function starvedRun(name: string) {
  const frames: Uint8Array[] = [];
  for (let i = 0; i < 6_000; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const r = rig(() => { const w = new RealWorker(); w.starved = true; return w; }, {
    ...OPTIONS, maxFrames: 6_100, batchFrames: 500, windowBytes: 32 * 1024,
  });
  const run = runWorkerImport(fileOf(pcapOf(frames), name), r.deps);
  // The walk is not parked by the credit, so it reads on and finishes; what is held is the page's side.
  for (let waited = 0; r.store.state.appended < 6_000 && waited < 400; waited++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
  return { r, run, worker: r.worker as RealWorker };
}

{
  // The same file, a page that answers: every batch gets through (12 of them).
  const frames: Uint8Array[] = [];
  for (let i = 0; i < 6_000; i++) frames.push(udpFrame(5000 + (i % 100), 9999, Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  const r = rig(() => new RealWorker(), { ...OPTIONS, maxFrames: 6_100, batchFrames: 500, windowBytes: 32 * 1024 });
  const outcome = await withTimeout(runWorkerImport(fileOf(pcapOf(frames), 'acked.pcap'), r.deps).result, 'acked');
  const log = (r.worker as RealWorker).log;
  const rowsIn = log.filter((t) => t === '<rows').length;
  check('a page that answers gets every batch: all rows, one rowsTaken each',
    outcome.ok === true && outcome.packets.length === 6_000 && rowsIn > IMPORT_ROWS_IN_FLIGHT
    && log.filter((t) => t === '>rowsTaken').length === rowsIn && log.indexOf('<done') > log.lastIndexOf('<rows'),
    { ok: outcome.ok, rowsIn, acks: log.filter((t) => t === '>rowsTaken').length });
  r.store.close();
}
{
  const { r, run, worker } = await starvedRun('starved-cancel.pcap');
  const rowsPosted = worker.log.filter((t) => t === '<rows').length;
  check('a page that never answers is sent exactly the credit, and not the done behind it',
    rowsPosted === IMPORT_ROWS_IN_FLIGHT && !worker.log.includes('<done') && !worker.terminated, { rowsPosted, log: worker.log.length });
  run.cancel();
  let outcome: ImportOutcome | null = null;
  try { outcome = await withTimeout(run.result, 'cancel while credit-blocked', 3_000); } catch { /* hung: checked below */ }
  check('Cancel ends the import while the Worker is blocked on a rowsTaken: no new hang',
    outcome !== null && outcome.ok === false && outcome.failure.kind === 'cancelled' && worker.terminated
    && r.lost.size === 0 && r.keys.counts.live === 0, { settled: outcome !== null });
  r.store.close();
}
{
  const { r, run, worker } = await starvedRun('starved-lost.pcap');
  const blocked = worker.log.filter((t) => t === '<rows').length === IMPORT_ROWS_IN_FLIGHT && !worker.log.includes('<done');
  r.storeLost('the capture store stopped');
  let outcome: ImportOutcome | null = null;
  try { outcome = await withTimeout(run.result, 'store failure while credit-blocked', 3_000); } catch { /* hung: checked below */ }
  check('a store failure ends the import while the Worker is blocked on a rowsTaken: no new hang',
    blocked && outcome !== null && outcome.ok === false && outcome.failure.kind === 'unreadable'
    && outcome.failure.message === 'the capture store stopped' && worker.terminated && r.lost.size === 0,
    { blocked, settled: outcome !== null });
  if (outcome === null) run.cancel();
  r.store.close();
}

// --- 9. the live pipeline's pack that cannot be read still clears its flow debt (1.7) -------
//
// `PipelineClient.receive` reads each `frames` message's pack; the Worker counts those rows
// as owed until the page says `rowsTaken` (`flow.rowsPosted`). A pack that throws (one the
// Worker never sent) must still be acknowledged, or the debt never clears and the live
// flow stalls for good; and the reader is reset, so a half-consumed pack map does not make
// the next batch fail too.

{
  const mk = (from: number, count: number): PackedRows => {
    const batch: Packet[] = [];
    for (let id = from; id < from + count; id++) {
      batch.push({
        id, source: '10.0.0.4', destination: '93.184.216.34', protocol: 'TCP', info: `frame ${id}`, status: 'ok',
        length: 60, tsUs: 1_788_000_000_000_000 + id, relativeTime: 0, timeDelta: 0, interfaceName: 'eth0', layers: [],
        rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]), frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
        sourcePort: 50000, destPort: 443, fields: { 'tcp.seq': id },
      } as Packet);
    }
    const pack = packRows(from, batch, batch.map((p) => p.rawBytes.length));
    const flush = new PackedFlush();
    batch.forEach((p, i) => flush.packed(pack, i, p.rawBytes, null));
    return flush.seal(new Map());
  };
  const good = mk(1, 4);
  // A batch whose rows name a pack this reader was never sent: it throws on its first row.
  const bad = mk(100, 3);
  bad.packs = [];
  const reader = new PackReader();
  const acked: number[] = [];
  const first = readPackedBatch(reader, bad, (count) => { acked.push(count); });
  const second = readPackedBatch(reader, good, (count) => { acked.push(count); });
  check('a pack that cannot be read is a failure with the reader\'s own message',
    !first.ok && /no pack 100/.test(first.message), first);
  check('...and its rows are acknowledged, so the Worker\'s debt for them clears',
    acked[0] === 3, acked);
  check('...and the next good batch decodes, and is left for its own acknowledgement (the buffer\'s)',
    second.ok && second.packets.length === 4 && second.packets[3].id === 4 && acked.length === 1, { second: second.ok, acked });

  // A flush that fails part-way leaves the reader holding the pack its first row came from
  // (two rows, one read); the reset lets go of it.
  const half = mk(200, 2);
  half.order = Int32Array.from([200, 0, 999, 0]);
  const live = new PackReader();
  readPackedBatch(live, half, () => {});
  check('...and the reader is reset: the pack a half-read flush was holding is gone',
    live.held === 0, live.held);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('The import client holds.');
process.exit(0);
