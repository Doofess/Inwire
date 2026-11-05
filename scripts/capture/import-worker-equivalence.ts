/**
 * An import in the Worker is the same import.
 *
 *   npx tsx scripts/capture/import-worker-equivalence.ts
 *
 * The import Worker (`importRole.ts`, all of it in `pipeline/importRun.ts`) moves
 * the walk, the batcher, the store writes and the RAM tail off the page. What must
 * not change is anything a person or the store can see: the messages the store is
 * sent, the rows the buffer is left holding, the totals, and the decrypted
 * answers. So each input goes through both routes and they are compared.
 *
 * ## Spike (Task 4, step 1): worker_threads with tsx works
 *
 * A `node:worker_threads` Worker started with `execArgv: ['--import', 'tsx']`
 * imports `src/services/pcapParser.ts` and runs `createImportRun` as it is; a
 * in-memory `Blob` posts to it and reads back (`slice().arrayBuffer()`); a
 * file-backed `fs.openAsBlob(path)` does NOT clone across threads (so the input
 * is read into a Blob here). No child-process fallback was needed. Transferred
 * ports arrive inside the message value, not `ports`.
 *
 * ## The routes
 *
 * Each runs in a thread of its own (`importEquivalenceThread.ts`), because the
 * key log and the trackers are singletons and one isolate cannot hold two.
 *
 * - in-process: `streamCaptureFile` with the default `onSecrets`, the way
 *   `readStreamedCapture` and App run it; the store messages of each batch are
 *   recorded and the derived answers set from the records.
 * - Worker: `createImportRun` in the thread, this process playing the page (the
 *   one writer of a fresh key log, acking each secrets message with a snapshot;
 *   `storeOpen` after `opening`; `storedThrough` as the store takes rows) and the
 *   store (answering every `bytesTaken`, recording every message).
 *
 * Compared: the store messages after a structured clone (the store's process
 * boundary), as `canonical` text (every key, prototype names, typed arrays with
 * their buffer's size; `v8.serialize` itself tells an integral double from an
 * integer after a trip through a port, which no one can see), without `captureId`
 * or the empty `appendBytes` only the Worker sends; the tail's rows (every scalar and field; the bytes where
 * both routes still hold them); totals, facts, missed patches; the derived entries.
 * Small `patchWindow`, `batchFrames` and `windowBytes` put the edges in reach of
 * a small file.
 */
import { MessageChannel, Worker, type TransferListItem } from 'node:worker_threads';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PackReader } from '../../src/services/pipeline/rowPack';
import { FieldBlockWriter } from '../../src/services/dissect/fieldSplit';
import { SCORING_FRAMES } from '../../src/services/hostIdentity';
import { keyLog, KeyLogStore } from '../../src/services/tls/keyLog';
import type { FromImport, ImportRunOptions } from '../../src/services/pipeline/importProtocol';
import {
  canonicalRow, derivedHex, dnsTcpInput, normalizeStoreMessage, tlsWithDsbInput,
  type CanonicalRow, type RouteResult, type SyntheticInput, type ThreadCommand,
} from './importEquivalenceRig';

let failures = 0;
function pass(name: string, ok: boolean, detail?: unknown): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${JSON.stringify(detail)}`.slice(0, 500));
}

const ROUTE_TIMEOUT_MS = 180_000;
const spawnThread = () => new Worker(new URL('./importEquivalenceThread.ts', import.meta.url), {
  execArgv: ['--import', 'tsx'],
});

function withTimeout<T>(promise: Promise<T>, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: no answer in ${ROUTE_TIMEOUT_MS / 1000} s`)), ROUTE_TIMEOUT_MS);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function inProcessRoute(blob: Blob, options: ImportRunOptions): Promise<RouteResult> {
  const thread = spawnThread();
  try {
    return await withTimeout(new Promise<RouteResult>((resolve, reject) => {
      thread.on('message', (m: { kind: string; result?: RouteResult; message?: string }) => {
        if (m.kind === 'result') resolve(m.result as RouteResult);
        else reject(new Error(m.message));
      });
      thread.on('error', reject);
      thread.postMessage({ kind: 'inprocess', blob, options } satisfies ThreadCommand);
    }), 'in-process route');
  } finally {
    await thread.terminate();
  }
}

interface WorkerRouteResult extends RouteResult {
  /** Appends received untagged or for another capture: none is allowed. */
  untagged: number;
  /** Slabs with frames in them: only empty ones may go to the store. */
  nonEmptySlabs: number;
  appendBytesSeen: number;
  secretsSeen: number;
  /** The most frames the store held received and unanswered at once. */
  peakOutstanding: number;
  /** The most tail chunks the page held un-acked at once: one is the rule. */
  tailPeak: number;
  /** `done` arrivals while a tail chunk was still un-acked. */
  doneBeforeLastTailTaken: number;
}

/** `ackDelayMs`: how long the fake store sits on each answer, to let a pause show. */
async function workerRoute(
  blob: Blob, options: ImportRunOptions, ackDelayMs = 0, copyMode = false,
): Promise<WorkerRouteResult> {
  const thread = spawnThread();
  const { port1, port2 } = new MessageChannel();
  // This process is the page: a fresh key log, the only writer.
  // `copyMode`: a page that cannot share memory (a dev run without
  // SharedArrayBuffer), whose every snapshot is a copy the Worker must adopt.
  const page = copyMode ? new KeyLogStore({ shared: false }) : keyLog;
  if (!copyMode) keyLog.clear();
  const send = (msg: ThreadCommand, transfer: TransferListItem[] = []) => thread.postMessage(msg, transfer);
  const unsubscribe = page.onSnapshot((snapshot) => send({ kind: 'msg', msg: { type: 'keylog-shared', snapshot } }));

  const stored: string[] = [];
  const out = {
    untagged: 0, nonEmptySlabs: 0, appendBytesSeen: 0, secretsSeen: 0, peakOutstanding: 0,
    tailPeak: 0, doneBeforeLastTailTaken: 0,
  };
  const CAPTURE = 'capture-under-test';
  let tailOpen = 0;
  let outstanding = 0;
  let sinceAnswer = 0;
  port1.on('message', (m: { type: string; ack?: number; packets?: { id: number }[]; slab?: { ids: Float64Array }; captureId?: string }) => {
    const normal = normalizeStoreMessage(m);
    if (normal !== null) stored.push(normal);
    if ((m.type === 'append' || m.type === 'appendRecords') && m.captureId !== CAPTURE) out.untagged++;
    if (m.type === 'appendBytes') {
      out.appendBytesSeen++;
      if (m.slab !== undefined && m.slab.ids.length > 0) out.nonEmptySlabs++;
      if (m.ack !== undefined) {
        const { ack } = m;
        const frames = sinceAnswer;
        sinceAnswer = 0;
        setTimeout(() => {
          outstanding -= frames;
          port1.postMessage({ type: 'bytesTaken', ack });
        }, ackDelayMs);
      }
    }
    if (m.type === 'append' && m.packets !== undefined && m.packets.length > 0) {
      outstanding += m.packets.length;
      sinceAnswer += m.packets.length;
      out.peakOutstanding = Math.max(out.peakOutstanding, outstanding);
      send({ kind: 'msg', msg: { type: 'storedThrough', id: m.packets[m.packets.length - 1].id } });
    }
  });

  const reader = new PackReader(new FieldBlockWriter());
  const rows: CanonicalRow[] = [];
  const estimates: number[] = [];
  try {
    const done = await withTimeout(new Promise<Extract<FromImport, { type: 'done' }>>((resolve, reject) => {
      thread.on('error', reject);
      thread.on('message', (m: { kind: string; msg: FromImport }) => {
        if (m.kind !== 'from') return;
        const msg = m.msg;
        switch (msg.type) {
          case 'secrets':
            out.secretsSeen++;
            // A page that is busy: the Worker must wait for it, not race it. A
            // Worker that read on would dissect the frames after the block with
            // no keys in the table, and this delay is what lets that show.
            setTimeout(() => {
              page.add(msg.text);
              send({ kind: 'msg', msg: { type: 'secretsTaken', seq: msg.seq, snapshot: page.share() } });
            }, 50);
            return;
          case 'opening':
            send({ kind: 'msg', msg: { type: 'storeOpen', captureId: CAPTURE } });
            return;
          case 'tail':
            tailOpen++;
            out.tailPeak = Math.max(out.tailPeak, tailOpen);
            for (const row of reader.read(msg.pack)) rows.push(canonicalRow(row));
            estimates.push(...msg.estimates);
            // The page is a little slow to take it: a Worker that posts the next
            // chunk without waiting would have two in flight by now.
            setTimeout(() => {
              tailOpen--;
              send({ kind: 'msg', msg: { type: 'tailTaken' } });
            }, 5);
            return;
          case 'done':
            if (tailOpen > 0) out.doneBeforeLastTailTaken++;
            resolve(msg);
            return;
          case 'failed': reject(new Error(`the Worker failed: ${msg.message}`)); return;
          case 'progress': return;
        }
      });
      send({ kind: 'msg', msg: { type: 'keylog-shared', snapshot: page.share() } });
      send({ kind: 'msg', msg: { type: 'start', file: blob, fileName: 'input', options }, port: port2 }, [port2]);
    }), 'Worker route');
    return {
      messages: stored, rows, estimates,
      totalFrames: done.totalFrames, built: done.built, missedPatches: done.missedPatches,
      facts: JSON.stringify(done.facts), derived: derivedHex(done.derived),
      ...out,
    };
  } finally {
    unsubscribe();
    port1.close();
    await thread.terminate();
  }
}

/** Both routes on one file, compared. */
async function compare(
  label: string, file: string, shape: Pick<SyntheticInput, 'maxFrames' | 'tailChunkRows' | 'opaqueId' | 'decryptedId'>,
  requireDerived: boolean, copyMode = false,
): Promise<void> {
  const blob = new Blob([readFileSync(file)]);
  const options: ImportRunOptions = {
    record: true,
    residentBytes: 256 * 1024 * 1024,
    maxFrames: shape.maxFrames,
    derivedBudget: 64 * 1024 * 1024,
    patchWindow: 64,
    batchFrames: 50,
    windowBytes: 64 * 1024,
    tailChunkRows: shape.tailChunkRows,
  };
  const base = await inProcessRoute(blob, options);
  if (requireDerived) {
    pass(`${label}: the in-process route decrypts frames (derived answers kept)`, base.derived.length > 0, { derived: base.derived.length });
    if (base.derived.length === 0) return;
  }
  if (shape.opaqueId !== undefined && shape.decryptedId !== undefined) {
    // What the secrets block is for: a record before it stays opaque and one after
    // it is read. Held in the in-process rows; equality carries it to the Worker's.
    const rowOf = (id: number) => base.rows.find((row) => (JSON.parse(row.scalars) as { id: number }).id === id);
    const opaque = rowOf(shape.opaqueId);
    const decrypted = rowOf(shape.decryptedId);
    pass(`${label}: a record before the block is opaque and one after it is decrypted`,
      opaque !== undefined && decrypted !== undefined
      && !opaque.fields.includes('inwire.tls.decrypted') && decrypted.fields.includes('inwire.tls.decrypted'),
      { opaque: opaque !== undefined && !opaque.fields.includes('inwire.tls.decrypted'), decrypted: decrypted?.fields.includes('inwire.tls.decrypted') });
  }
  const worker = await workerRoute(blob, options, 0, copyMode);

  const firstMessageDifference = base.messages.findIndex((m, i) => m !== worker.messages[i]);
  pass(`${label}: store messages equal (${base.messages.length})`,
    base.messages.length === worker.messages.length && firstMessageDifference === -1,
    { inProcess: base.messages.length, worker: worker.messages.length, firstDifference: firstMessageDifference });
  pass(`${label}: every append is tagged with the open capture, and only empty slabs are sent`,
    worker.untagged === 0 && worker.nonEmptySlabs === 0 && worker.appendBytesSeen > 0,
    { untagged: worker.untagged, nonEmptySlabs: worker.nonEmptySlabs, appendBytesSeen: worker.appendBytesSeen });

  let rowsEqual = base.rows.length === worker.rows.length && base.rows.length > 0;
  let firstDifference: unknown;
  let bothHeldBytes = 0;
  for (let i = 0; rowsEqual && i < base.rows.length; i++) {
    const a = base.rows[i];
    const b = worker.rows[i];
    const bytesCompared = a.raw.length > 0 && b.raw.length > 0;
    if (bytesCompared) bothHeldBytes++;
    if (a.scalars !== b.scalars || a.fields !== b.fields || (bytesCompared && a.raw !== b.raw)) {
      rowsEqual = false;
      // Names of the keys that differ, never values: a private capture's rows hold addresses.
      const keysOf = (json: string) => JSON.parse(json) as Record<string, unknown>;
      const [sa, sb] = [keysOf(a.scalars), keysOf(b.scalars)];
      firstDifference = {
        row: i, raw: a.raw === b.raw,
        scalarKeys: [...new Set([...Object.keys(sa), ...Object.keys(sb)])]
          .filter((k) => JSON.stringify(sa[k]) !== JSON.stringify(sb[k])),
        fieldsEqual: a.fields === b.fields,
      };
    }
  }
  pass(`${label}: tail rows equal (${base.rows.length} rows, bytes compared on ${bothHeldBytes})`, rowsEqual && bothHeldBytes > 0,
    firstDifference ?? { inProcess: base.rows.length, worker: worker.rows.length });
  pass(`${label}: tail estimates equal`,
    JSON.stringify(base.estimates) === JSON.stringify(worker.estimates));
  pass(`${label}: totals/facts/missedPatches equal (${base.totalFrames} frames, ${base.missedPatches} missed)`,
    base.totalFrames === worker.totalFrames && base.built === worker.built
    && base.missedPatches === worker.missedPatches && base.facts === worker.facts && base.totalFrames > 0,
    { base: [base.totalFrames, base.built, base.missedPatches], worker: [worker.totalFrames, worker.built, worker.missedPatches] });
  pass(`${label}: one tail chunk in flight at a time, and done after the last is taken`,
    worker.tailPeak === 1 && worker.doneBeforeLastTailTaken === 0,
    { tailPeak: worker.tailPeak, doneBeforeLastTailTaken: worker.doneBeforeLastTailTaken });
  pass(`${label}: derived equal (${base.derived.length} entries)`,
    JSON.stringify(base.derived) === JSON.stringify(worker.derived));
  if (label.startsWith('tls')) {
    pass(`${label}: the secrets block reached the page once`, worker.secretsSeen === 1, { secretsSeen: worker.secretsSeen });
  }
}

const scratch = mkdtempSync(join(tmpdir(), 'inwire-import-equivalence-'));
try {
  const synthetic: [string, SyntheticInput, string, boolean, boolean][] = [
    ['tls', tlsWithDsbInput(), 'tls.pcapng', true, false],
    // Past the prefix host inference reads, so the main pass meets the block.
    ['tls (main pass)', tlsWithDsbInput(SCORING_FRAMES + 5), 'tls-big.pcapng', true, false],
    // A page without shared memory: the ack's snapshot is the only way keys arrive.
    ['tls (copy mode)', tlsWithDsbInput(), 'tls-copy.pcapng', true, true],
    ['dns', dnsTcpInput(), 'dns.pcap', false, false],
  ];
  for (const [label, input, name, requireDerived, copyMode] of synthetic) {
    const file = join(scratch, name);
    writeFileSync(file, input.bytes);
    console.log(`  ${label}: ${input.name}`);
    await compare(label, file, input, requireDerived, copyMode);
  }

  // Credit: a store that is slow to answer holds the Worker at its bound. 362
  // frames, a bound of 60, batches of 50 and a patch window of 64 (the last flush
  // lets go of the window's frames at once): without the pause every frame is at
  // the store before the first answer, and the peak is the whole file.
  {
    const input = dnsTcpInput();
    const file = join(scratch, 'pacing.pcap');
    writeFileSync(file, input.bytes);
    const options: ImportRunOptions = {
      record: true, residentBytes: 256 * 1024 * 1024, maxFrames: 40, derivedBudget: 64 * 1024 * 1024,
      patchWindow: 64, batchFrames: 50, windowBytes: 64 * 1024, creditFrames: 60,
    };
    const paced = await workerRoute(new Blob([readFileSync(file)]), options, 5);
    pass(`credit: the walk pauses past the bound (peak ${paced.peakOutstanding} frames outstanding, bound 60 + batch + window = 174)`,
      paced.peakOutstanding >= 50 && paced.peakOutstanding <= 60 + 50 + 64 && paced.totalFrames === 362,
      { peak: paced.peakOutstanding, totalFrames: paced.totalFrames });
  }

  // The owner's captures, when they are here. Nothing of them is printed but names of checks.
  // `test/` is untracked, so a worktree has none: INWIRE_FIXTURES names a directory.
  const wanted = (f: string) => /^(bulk|inwire)_capture_.*\.pcap$/.test(f);
  const dir = process.env.INWIRE_FIXTURES ?? fileURLToPath(new URL('../../test/fixtures/', import.meta.url));
  const found = existsSync(dir) ? readdirSync(dir).filter(wanted).sort() : [];
  if (found.length === 0) console.log('SKIP  private fixtures: none under test/fixtures/');
  for (const [i, name] of found.entries()) {
    await compare(`fixture ${i + 1}`, join(dir, name), { maxFrames: 30_000, tailChunkRows: 7_000 }, false);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('The import Worker is the in-process import, on every input.');
process.exit(0);
