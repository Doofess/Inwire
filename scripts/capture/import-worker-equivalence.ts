/**
 * An import in the Worker is the same import.
 *
 *   npx tsx scripts/capture/import-worker-equivalence.ts
 *
 * The import Worker (`importRole.ts`, all of it in `pipeline/importRun.ts`) moves
 * the walk, the batcher and the store writes off the page, and packs each batch
 * once for the store and the page. What must not change is anything a person or
 * the store can see: the rows and records the store is sent, the rows the buffer
 * is left holding, the totals, and the decrypted answers. So each input goes
 * through both routes and they are compared.
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
 *   `storeOpen` after `opening`; the `rows` messages decoded into an `ImportTail`
 *   with the Worker's sizes, its bytes released through what the store holds once
 *   the capture is open) and the store (answering every `bytesTaken`, decoding every
 *   `appendPacked` with the store's own `PackReader`, recording the records).
 *
 * Compared: the rows the store is sent, decoded, against the in-process route's
 * `append` rows, id by id with every scalar, field and byte (`canonicalRow`); the
 * records, as `canonical` text (every key, prototype names, typed arrays with
 * their buffer's size; `v8.serialize` itself tells an integral double from an
 * integer after a trip through a port, which no one can see), without `captureId`;
 * the page's tail (every scalar and field; the bytes where both routes still
 * hold them) and its estimates; totals, facts, missed patches; the derived entries.
 * Small `patchWindow`, `batchFrames` and `windowBytes` put the edges in reach of
 * a small file.
 */
import { MessageChannel, Worker, type TransferListItem } from 'node:worker_threads';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PackReader, type PackedRows } from '../../src/services/pipeline/rowPack';
import { ImportTail } from '../../src/services/importTail';
import { FieldBlockWriter } from '../../src/services/dissect/fieldSplit';
import { SCORING_FRAMES } from '../../src/services/hostIdentity';
import { keyLog, KeyLogStore } from '../../src/services/tls/keyLog';
import type { FromImport, ImportRunOptions } from '../../src/services/pipeline/importProtocol';
import {
  bigFramesInput, canonicalRow, derivedHex, dnsTcpInput, normalizeStoreMessage, rowDifference, tlsWithDsbInput,
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
  /** Row and record messages received untagged or for another capture: none is allowed. */
  untagged: number;
  /** `append` messages: the Worker packs, so none is allowed. */
  plainAppends: number;
  /** `appendPacked` messages with a `sent` flag set, or with a pack reset: none is allowed. */
  badPacked: number;
  /** Slabs with frames in them: only empty ones may go to the store. */
  nonEmptySlabs: number;
  appendBytesSeen: number;
  secretsSeen: number;
  /** The most frames the store held received and unanswered at once. */
  peakOutstanding: number;
  /** The most bytes of those frames, as the store holds them. */
  peakOutstandingBytes: number;
  /** Acks of a secrets message whose snapshot said `cleared`. */
  acksCleared: number;
  /** Every type of message the page sent the Worker. */
  sentTypes: string[];
  /** `rows` messages that reached the page. */
  rowsMessages: number;
  /** Rows the store had been sent when `done` arrived: all of them, or the barrier is broken. */
  storeRowsAtDone: number;
}

/**
 * `ackDelayMs`: how long the fake store sits on each answer, to let a pause show.
 * `clearOnSecret`: the page clears its key log (a Settings Clear) as it takes the
 * Decryption Secrets Block with this `seq`, before the ack.
 */
async function workerRoute(
  blob: Blob, options: ImportRunOptions, ackDelayMs = 0, copyMode = false, clearOnSecret = 0,
): Promise<WorkerRouteResult> {
  const thread = spawnThread();
  const { port1, port2 } = new MessageChannel();
  // This process is the page: a fresh key log, the only writer.
  // `copyMode`: a page that cannot share memory (a dev run without
  // SharedArrayBuffer), whose every snapshot is a copy the Worker must adopt.
  const page = copyMode ? new KeyLogStore({ shared: false }) : keyLog;
  if (!copyMode) keyLog.clear();
  const sentTypes = new Set<string>();
  const send = (msg: ThreadCommand, transfer: TransferListItem[] = []) => {
    if (msg.kind === 'msg') sentTypes.add(msg.msg.type);
    thread.postMessage(msg, transfer);
  };
  const unsubscribe = page.onSnapshot((snapshot) => send({ kind: 'msg', msg: { type: 'keylog-shared', snapshot } }));

  const stored: string[] = [];
  const storeRows: CanonicalRow[] = [];
  const out = {
    untagged: 0, plainAppends: 0, badPacked: 0, nonEmptySlabs: 0, appendBytesSeen: 0, secretsSeen: 0,
    peakOutstanding: 0, peakOutstandingBytes: 0, acksCleared: 0, rowsMessages: 0,
  };
  let outstandingBytes = 0;
  let sinceAnswerBytes = 0;
  const CAPTURE = 'capture-under-test';
  let outstanding = 0;
  let sinceAnswer = 0;
  // The store's one `PackReader`, with no split: its rows are never buffered.
  const storeReader = new PackReader();
  // What the store has taken, as the page learns it (`deps.storedThrough`).
  let storedThrough = 0;
  let storeOpened = false;
  let storeRowsAtDone = -1;
  // The page's end: the rows as the client decodes them, into the tail.
  const reader = new PackReader(new FieldBlockWriter());
  const pageTail = new ImportTail({ residentBytes: options.residentBytes, maxFrames: options.maxFrames });
  port1.on('message', (m: {
    type: string; ack?: number; rows?: PackedRows; sent?: Uint8Array; slab?: { ids: Float64Array }; captureId?: string;
  }) => {
    const normal = normalizeStoreMessage(m);
    if (normal !== null) stored.push(normal);
    if ((m.type === 'append' || m.type === 'appendPacked' || m.type === 'appendRecords') && m.captureId !== CAPTURE) out.untagged++;
    if (m.type === 'append') out.plainAppends++;
    if (m.type === 'appendPacked' && m.rows !== undefined && m.sent !== undefined) {
      if (m.sent.some((flag) => flag !== 0) || m.rows.packsReset !== undefined) out.badPacked++;
      const decoded = storeReader.read(m.rows);
      for (const row of decoded) storeRows.push(canonicalRow(row));
      const bytes = decoded.reduce((n, row) => n + row.rawBytes.length, 0);
      outstanding += decoded.length;
      sinceAnswer += decoded.length;
      outstandingBytes += bytes;
      sinceAnswerBytes += bytes;
      out.peakOutstanding = Math.max(out.peakOutstanding, outstanding);
      out.peakOutstandingBytes = Math.max(out.peakOutstandingBytes, outstandingBytes);
      storedThrough = Math.max(storedThrough, decoded[decoded.length - 1].id);
    }
    if (m.type === 'appendBytes') {
      out.appendBytesSeen++;
      if (m.slab !== undefined && m.slab.ids.length > 0) out.nonEmptySlabs++;
      if (m.ack !== undefined) {
        const { ack } = m;
        const frames = sinceAnswer;
        const answeredBytes = sinceAnswerBytes;
        sinceAnswer = 0;
        sinceAnswerBytes = 0;
        setTimeout(() => {
          outstanding -= frames;
          outstandingBytes -= answeredBytes;
          port1.postMessage({ type: 'bytesTaken', ack });
        }, ackDelayMs);
      }
    }
  });

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
              if (msg.seq === clearOnSecret) page.clear();
              page.add(msg.text);
              const snapshot = page.share();
              if (snapshot.cleared) out.acksCleared++;
              send({ kind: 'msg', msg: { type: 'secretsTaken', seq: msg.seq, snapshot } });
            }, 50);
            return;
          case 'opening':
            storeOpened = true;
            send({ kind: 'msg', msg: { type: 'storeOpen', captureId: CAPTURE } });
            return;
          case 'rows':
            // The client's own steps: decode, push with the Worker's sizes, and let
            // go of the bytes the store holds - only once the capture is open.
            out.rowsMessages++;
            pageTail.push(reader.read(msg.pack), msg.sizes);
            if (storeOpened) pageTail.releaseBytesThrough(storedThrough);
            return;
          case 'progress':
            if (storeOpened) pageTail.releaseBytesThrough(storedThrough);
            return;
          case 'done':
            storeRowsAtDone = storeRows.length;
            resolve(msg);
            return;
          case 'failed': reject(new Error(`the Worker failed: ${msg.message}`)); return;
        }
      });
      send({ kind: 'msg', msg: { type: 'keylog-shared', snapshot: page.share() } });
      send({ kind: 'msg', msg: { type: 'start', file: blob, fileName: 'input', options }, port: port2 }, [port2]);
    }), 'Worker route');
    return {
      messages: stored, storeRows, rows: pageTail.rows().map(canonicalRow), estimates: [...pageTail.estimates()],
      totalFrames: done.totalFrames, built: done.built, missedPatches: done.missedPatches,
      facts: JSON.stringify(done.facts), derived: derivedHex(done.derived),
      storeRowsAtDone, sentTypes: [...sentTypes].sort(),
      ...out,
    };
  } finally {
    unsubscribe();
    port1.close();
    await thread.terminate();
  }
}

/**
 * Two lists of rows, row by row. With `strictBytes` both must hold each row's
 * bytes (the store's rows); without, bytes are compared only where both still do
 * (a tail lets go of old rows' bytes as the store takes them).
 */
function sameRows(a: CanonicalRow[], b: CanonicalRow[], strictBytes: boolean) {
  let equal = a.length === b.length;
  let firstDifference: unknown;
  let bytesCompared = 0;
  for (let i = 0; equal && i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    const both = x.raw.length > 0 && y.raw.length > 0;
    if (both) bytesCompared++;
    if (x.scalars !== y.scalars || x.fields !== y.fields || ((both || strictBytes) && x.raw !== y.raw)) {
      equal = false;
      // Names of the keys that differ, never values: a private capture's rows hold addresses.
      const { raw, scalarKeys } = rowDifference(x, y);
      firstDifference = { row: i, raw, scalarKeys, fieldsEqual: x.fields === y.fields };
    }
  }
  return { equal, firstDifference, bytesCompared };
}

/** Both routes on one file, compared. */
async function compare(
  label: string, file: string, shape: Pick<SyntheticInput, 'maxFrames' | 'opaqueId' | 'decryptedId'>,
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

  // The store is sent the same records, and the same rows: the Worker packs them
  // (`appendPacked`), the in-process route sends `append`, so the Worker's are
  // decoded here with the store's own reader and compared id by id, bytes included.
  const firstMessageDifference = base.messages.findIndex((m, i) => m !== worker.messages[i]);
  pass(`${label}: store records equal (${base.messages.length} messages)`,
    base.messages.length === worker.messages.length && firstMessageDifference === -1,
    { inProcess: base.messages.length, worker: worker.messages.length, firstDifference: firstMessageDifference });
  pass(`${label}: every row and record message is tagged, rows are packed with their own bytes, and only empty slabs are sent`,
    worker.untagged === 0 && worker.plainAppends === 0 && worker.badPacked === 0
    && worker.nonEmptySlabs === 0 && worker.appendBytesSeen > 0,
    {
      untagged: worker.untagged, plainAppends: worker.plainAppends, badPacked: worker.badPacked,
      nonEmptySlabs: worker.nonEmptySlabs, appendBytesSeen: worker.appendBytesSeen,
    });
  const stored = sameRows(base.storeRows, worker.storeRows, true);
  pass(`${label}: the rows the store is sent are equal, id by id, bytes included (${base.storeRows.length} rows)`,
    stored.equal && base.storeRows.length > 0 && stored.bytesCompared === base.storeRows.length,
    stored.firstDifference ?? { inProcess: base.storeRows.length, worker: worker.storeRows.length });
  pass(`${label}: every row was at the store when \`done\` arrived (the barrier)`,
    worker.storeRowsAtDone === base.totalFrames, { atDone: worker.storeRowsAtDone, total: base.totalFrames });

  // The page's tail, built from the `rows` messages as the client builds it.
  const tail = sameRows(base.rows, worker.rows, false);
  pass(`${label}: tail rows equal (${base.rows.length} rows, bytes compared on ${tail.bytesCompared})`,
    tail.equal && base.rows.length > 0 && tail.bytesCompared > 0,
    tail.firstDifference ?? { inProcess: base.rows.length, worker: worker.rows.length });
  pass(`${label}: tail estimates equal`,
    JSON.stringify(base.estimates) === JSON.stringify(worker.estimates));
  pass(`${label}: totals/facts/missedPatches equal (${base.totalFrames} frames, ${base.missedPatches} missed)`,
    base.totalFrames === worker.totalFrames && base.built === worker.built
    && base.missedPatches === worker.missedPatches && base.facts === worker.facts && base.totalFrames > 0,
    { base: [base.totalFrames, base.built, base.missedPatches], worker: [worker.totalFrames, worker.built, worker.missedPatches] });
  pass(`${label}: the page sent the Worker only the key log, the start, secrets acks and storeOpen`,
    worker.sentTypes.every((type) => ['keylog-shared', 'start', 'secretsTaken', 'storeOpen'].includes(type))
    && worker.sentTypes.includes('storeOpen') && worker.rowsMessages > 0,
    worker.sentTypes);
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

  // Credit is bytes as well as frames: 64 KB segments (large send offload) put a
  // few hundred thousand frames' worth of memory in flight under a frame bound that
  // is never reached. 400 frames of 1242 bytes, a byte bound of 64 KiB, and a frame
  // bound (the default, 50,000) that is nowhere near: the walk must stop on the bytes.
  {
    const input = bigFramesInput(400, 1200);
    const frameBytes = (input.bytes.length - 24) / 400 - 16;
    const options: ImportRunOptions = {
      record: true, residentBytes: 256 * 1024 * 1024, maxFrames: 40, derivedBudget: 64 * 1024 * 1024,
      patchWindow: 8, batchFrames: 20, windowBytes: 64 * 1024,
    };
    const blob = new Blob([input.bytes]);
    const unbounded = await workerRoute(blob, options, 5);
    const bounded = await workerRoute(blob, { ...options, creditBytes: 64 * 1024 }, 5);
    const ceiling = 64 * 1024 + (20 + 8) * frameBytes;
    pass(`import credit is bounded by bytes as well as frames (peak ${bounded.peakOutstandingBytes} B in ${bounded.peakOutstanding} frames outstanding, bound ${ceiling} B; unbounded run ${unbounded.peakOutstandingBytes} B)`,
      bounded.peakOutstandingBytes > 64 * 1024 && bounded.peakOutstandingBytes <= ceiling
      && bounded.peakOutstanding < 400 && unbounded.peakOutstandingBytes > 2 * ceiling,
      { bounded: bounded.peakOutstandingBytes, unbounded: unbounded.peakOutstandingBytes, ceiling });
    const same = sameRows(unbounded.storeRows, bounded.storeRows, true);
    pass('the byte-bounded run completes and equals the unbounded run',
      bounded.totalFrames === 400 && unbounded.totalFrames === 400 && same.equal && bounded.storeRows.length === 400
      && bounded.storeRowsAtDone === 400 && JSON.stringify(bounded.estimates) === JSON.stringify(unbounded.estimates),
      { total: bounded.totalFrames, atDone: bounded.storeRowsAtDone, rows: bounded.storeRows.length });
  }

  // A cleared key log and a second Decryption Secrets Block. The page acks each
  // block with a snapshot, and `cleared` stays set on every snapshot of a cleared
  // log until its table next grows: an ack is never a clear, or each block would
  // empty the answers of frames already decrypted. (`workerRoute` clears the page's
  // key log first, and a real `postMessage` hands the Worker a new buffer object
  // every time; the route runs in a thread, so this one does too.)
  {
    const input = tlsWithDsbInput(SCORING_FRAMES + 5, true);
    const file = join(scratch, 'tls-two-blocks.pcapng');
    writeFileSync(file, input.bytes);
    const options: ImportRunOptions = {
      record: true, residentBytes: 256 * 1024 * 1024, maxFrames: input.maxFrames, derivedBudget: 64 * 1024 * 1024,
      patchWindow: 64, batchFrames: 50, windowBytes: 64 * 1024,
    };
    const blob = new Blob([readFileSync(file)]);
    const base = await inProcessRoute(blob, options);
    const before = base.derived.filter(([id]) => id < base.totalFrames);
    const worker = await workerRoute(blob, options);
    pass('a secrets ack after a Clear keeps the answers already decrypted',
      worker.acksCleared === 2 && worker.secretsSeen === 2 && before.length >= 2
      && JSON.stringify(worker.derived) === JSON.stringify(base.derived),
      { acksCleared: worker.acksCleared, secretsSeen: worker.secretsSeen, before: before.length, base: base.derived.length, worker: worker.derived.length });
    // The other half: a Clear that arrives as a `keylog-shared` is the one that
    // empties them, as in the live Worker. The page clears as it takes block 2.
    const cleared = await workerRoute(blob, options, 0, false, 2);
    pass('a keylog-shared clear empties the decrypted answers',
      cleared.secretsSeen === 2 && cleared.derived.length === 0 && base.derived.length > 0,
      { derived: cleared.derived.length, base: base.derived.length });
  }

  // The owner's captures, when they are here. Nothing of them is printed but names of checks.
  // `test/` is untracked, so a worktree has none: INWIRE_FIXTURES names a directory.
  const wanted = (f: string) => /^(bulk|inwire)_capture_.*\.pcap$/.test(f);
  const dir = process.env.INWIRE_FIXTURES ?? fileURLToPath(new URL('../../test/fixtures/', import.meta.url));
  const found = existsSync(dir) ? readdirSync(dir).filter(wanted).sort() : [];
  if (found.length === 0) console.log('SKIP  private fixtures: none under test/fixtures/');
  for (const [i, name] of found.entries()) {
    await compare(`fixture ${i + 1}`, join(dir, name), { maxFrames: 30_000 }, false);
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
