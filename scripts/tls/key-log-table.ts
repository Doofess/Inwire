/**
 * Assertion tests for the compact, shareable key log store (ADR 0073).
 *
 *   npx tsx scripts/tls/key-log-table.ts
 *
 * `KeyLogTable` packs the log into one buffer that the page writes and every
 * Worker reads in place. What can go wrong is silent: a secret that is found
 * with the wrong bytes decrypts to noise; a table that grows while a reader is
 * mid-lookup answers torn. So this checks, in order:
 *
 * - **Equivalence with the Map-of-Maps store it replaced** (`legacyKeyLog.ts`)
 *   over the awkward lines: CRLF, comments, uppercase hex, odd-length and
 *   non-hex secrets, short randoms, unknown labels, repeats and resumed labels.
 * - **Growth, retirement, a clear**, and the bound.
 * - **Copy mode**, where there is no shared memory (`npm run dev`).
 * - **Memory**: bytes of buffer a line costs, and the JS heap the store holds.
 * - **Across threads**: a real `worker_threads` reader against a writer that is
 *   still appending and growing.
 */
import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { setFlagsFromString } from 'node:v8';
import { Worker } from 'node:worker_threads';
import { KeyLogStore, type KeyLogShared } from '../../src/services/tls/keyLog';
import { LegacyKeyLogStore } from './legacyKeyLog';
import {
  connection, connectionText, hexOf, THREAD_LABELS,
  type ReaderReport, type ToReader,
} from './key-log-table-reader';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
const throws = (fn: () => unknown): boolean => { try { fn(); return false; } catch { return true; } };
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const latin1 = (b: Uint8Array) => new TextDecoder('latin1').decode(b);
const byteVal = (b: number) => b.toString(16).padStart(2, '0');
const R = (b: number) => byteVal(b).repeat(32);
const S = (b: number, bytes = 32) => byteVal(b).repeat(bytes);
const randomOf = (b: number) => new Uint8Array(32).fill(b);
const entries = (m: Map<string, Uint8Array> | undefined) =>
  m === undefined ? null : [...m].map(([k, v]) => [k, hexOf(v)]);
const pick = <T extends object>(o: T, keys: string[]) =>
  Object.fromEntries(keys.map((k) => [k, (o as Record<string, unknown>)[k]]));

async function main() {
  console.log('\n--- the same answers as the store it replaced ---\n');

  const corpus = [
    `CLIENT_TRAFFIC_SECRET_0 ${R(0xa1)} ${S(0xc3)}\r\n`,
    `SERVER_TRAFFIC_SECRET_0\t${R(0xa1)}\t${S(0xd4)}\n`,
    '# a comment\n',
    '\n',
    '   \r\n',
    `CLIENT_TRAFFIC_SECRET_0 ${R(0xbb).toUpperCase()} ${S(0xee).toUpperCase()}\n`,
    `CLIENT_RANDOM ${R(0xc3)} 0a1\n`,
    `CLIENT_RANDOM ${R(0xc3).slice(2)} ${S(0x11)}\n`,
    `FOO_SECRET ${R(0xa1)} ${S(0x22)}\n`,
    `CLIENT_TRAFFIC_SECRET_0 ${R(0xa1)} ${S(0xc3)}\n`,
    `CLIENT_TRAFFIC_SECRET_0 ${R(0xa1)} ${S(0xf6)}\n`,
    `CLIENT_RANDOM ${R(0xd4)} ${S(0x33, 48)}\n`,
    `EXPORTER_SECRET ${R(0xd4)} ${S(0x44)}\n`,
    `CLIENT_RANDOM ${R(0xd4)} zz${S(0x44).slice(2)}\n`,
    `CLIENT_RANDOM ${R(0xd4)} ${S(0x55)} extra\n`,
    `CLIENT_RANDOM ${R(0xd4)}\n`,
    `EARLY_EXPORTER_SECRET ${R(0xd4)} ${S(0x66, 255)}\n`,
  ].join('');
  const corpusRandoms = [0xa1, 0xbb, 0xc3, 0xd4, 0xe5, 0x77].map(randomOf);

  const store = new KeyLogStore();
  const legacy = new LegacyKeyLogStore();
  store.add(corpus);
  legacy.add(corpus);
  const keys = ['connections', 'secrets', 'ignored'];
  check('stats match the old store', pick(store.stats(), keys), pick(legacy.stats(), keys));
  for (const random of corpusRandoms) {
    check(`secretsFor ${hexOf(random).slice(0, 2)}.. matches`, entries(store.secretsFor(random)), entries(legacy.secretsFor(random)));
  }
  check('serialise matches, byte for byte', latin1(store.serialise()), legacy.serialise());
  check('a resumed label answers with the later secret',
    hexOf(store.secretsFor(randomOf(0xa1))!.get('CLIENT_TRAFFIC_SECRET_0')!), S(0xf6));
  checkTrue('secretsFor answers copies, not views',
    !(store.secretsFor(randomOf(0xa1))!.get('CLIENT_TRAFFIC_SECRET_0')!.buffer instanceof SharedArrayBuffer));
  checkTrue('...a copy that does not write through', (() => {
    store.secretsFor(randomOf(0xa1))!.get('CLIENT_TRAFFIC_SECRET_0')!.fill(0);
    return hexOf(store.secretsFor(randomOf(0xa1))!.get('CLIENT_TRAFFIC_SECRET_0')!) === S(0xf6);
  })());
  check('the same lines again change nothing', (() => {
    const twice = new KeyLogStore();
    const text = `CLIENT_RANDOM ${R(1)} ${S(2)}\nSERVER_TRAFFIC_SECRET_0 ${R(1)} ${S(3)}\n`;
    twice.add(text);
    const before = latin1(twice.serialise());
    const g = twice.generation;
    twice.add(text);
    return [before === latin1(twice.serialise()), g === twice.generation, twice.stats().secrets];
  })(), [true, true, 2]);
  // The one deliberate difference from the old store: it had no limit on a secret's length.
  // No real label exceeds 48 bytes; 255 is held, 256 is ignored.
  check('a 256-byte secret is ignored and a 255-byte one is held', (() => {
    const limits = new KeyLogStore();
    limits.add(`CLIENT_RANDOM ${R(1)} ${S(2, 256)}\nCLIENT_RANDOM ${R(2)} ${S(2, 255)}\n`);
    return [limits.stats().secrets, limits.stats().ignored];
  })(), [1, 1]);
  check('a random of the wrong width has no answer', store.secretsFor(new Uint8Array(31)), undefined);

  console.log('\n--- growth: the buffer is replaced, and a retired one stays whole ---\n');

  const writer = new KeyLogStore();
  const snapshots: KeyLogShared[] = [];
  writer.onSnapshot((s) => snapshots.push(s));
  const PER_CONN = 5;
  const CONNS = 50_000;
  const growLabels = THREAD_LABELS;
  const growRandom = (i: number) => { const b = new Uint8Array(32); for (let k = 0; k < 4; k++) new DataView(b.buffer).setUint32(k * 8, (i * 2654435761 + k * 40503) >>> 0, true); b[31] = i & 255; return b; };
  const growSecret = (i: number, k: number) => { const b = new Uint8Array(32); b.fill((i + k * 7) & 255); b[0] = k; b[1] = i & 255; b[2] = (i >> 8) & 255; b[3] = (i >> 16) & 255; return b; };
  const growLine = (i: number, k: number) => `${growLabels[k]} ${hexOf(growRandom(i))} ${hexOf(growSecret(i, k))}\n`;
  let chunk = '';
  let early: KeyLogShared | undefined;
  let readerOnOld: KeyLogStore | undefined;
  let retiredSum = '';
  const sum = (b: ArrayBuffer | SharedArrayBuffer) => createHash('sha1').update(new Uint8Array(b)).digest('hex');
  const EARLY = 100;
  for (let i = 0; i < CONNS; i++) {
    for (let k = 0; k < PER_CONN; k++) chunk += growLine(i, k);
    if (i === EARLY - 1) {
      // The first connections sit in the first buffer. Keep a reader on it.
      writer.add(chunk);
      chunk = '';
      early = writer.share();
      readerOnOld = new KeyLogStore();
      readerOnOld.adopt(early);
    } else if (chunk.length >= 1_000_000 || i === CONNS - 1) {
      const before = snapshots.length;
      writer.add(chunk);
      chunk = '';
      // The first replacement retires the buffer the early reader holds: fingerprint it now.
      if (retiredSum === '' && snapshots.length > before) retiredSum = sum(early!.buffer);
    }
  }
  checkTrue('the buffer was replaced at least once', snapshots.length >= 1);
  checkTrue('...and a retired buffer is never written again', retiredSum !== '' && sum(early!.buffer) === retiredSum);
  check('50,000 connections held', writer.stats().connections, CONNS);
  check('...and every line', writer.stats().secrets, CONNS * PER_CONN);
  let wrongAfterGrowth = 0;
  for (let i = 0; i < CONNS; i += 7) {
    const got = writer.secretsFor(growRandom(i));
    for (let k = 0; k < PER_CONN; k++) if (got?.get(growLabels[k]) === undefined || hexOf(got.get(growLabels[k])!) !== hexOf(growSecret(i, k))) wrongAfterGrowth++;
  }
  check('...every sampled secret correct after growth', wrongAfterGrowth, 0);
  const replica = new KeyLogStore();
  replica.adopt(snapshots[snapshots.length - 1]);
  check('a reader on the latest snapshot sees the same', pick(replica.stats(), keys), pick(writer.stats(), keys));
  checkTrue('a reader on a retired buffer still answers from it',
    readerOnOld!.secretsFor(growRandom(3))?.size === PER_CONN);
  checkTrue('...and knows nothing written after it was retired', readerOnOld!.secretsFor(growRandom(CONNS - 1)) === undefined);
  checkTrue('...whose generation did not move', readerOnOld!.generation < writer.generation);

  // One add that fills the buffer part-way through: the lines before the
  // growth land in the buffer being retired. A reader still on it can see them,
  // so its generation must say so - a TLS conversation that derived from half
  // a connection's lines re-derives only when the generation moves.
  {
    const w = new KeyLogStore();
    w.add(growLine(0, 0));
    const r = new KeyLogStore();
    r.adopt(w.share());
    const g0 = r.generation;
    let text = '';
    for (let i = 1; i <= 600; i++) text += growLine(i, 0);
    w.add(text);
    checkTrue('a growth mid-add leaves lines in the retired buffer', r.secretsFor(growRandom(1)) !== undefined);
    checkTrue('...and moves that buffer\'s generation with them', r.generation > g0);
    checkTrue('...while the new buffer\'s generation is higher still', w.generation > r.generation);
  }

  console.log('\n--- a reader in this thread sees later appends with no new snapshot ---\n');

  const live = new KeyLogStore();
  const seen: KeyLogShared[] = [];
  live.onSnapshot((s) => seen.push(s));
  live.add(`CLIENT_TRAFFIC_SECRET_0 ${R(0x01)} ${S(0x02)}\n`);
  const sharer = new KeyLogStore();
  const first = live.share();
  checkTrue('share() is live where memory can be shared', first.live === true && first.buffer instanceof SharedArrayBuffer);
  sharer.adopt(first);
  const fresh = randomOf(0x09);
  checkTrue('...the reader does not know a connection that is not there yet', sharer.secretsFor(fresh) === undefined);
  const g0 = sharer.generation;
  live.add(`SERVER_TRAFFIC_SECRET_0 ${R(0x09)} ${S(0x0a)}\n`);
  checkTrue('a shared reader sees a later add with no new snapshot',
    sharer.secretsFor(fresh) !== undefined && sharer.generation === live.generation && sharer.generation > g0 && seen.length === 0);
  check('...and its counts', pick(sharer.stats(), keys), pick(live.stats(), keys));
  checkTrue('a reader refuses add', throws(() => sharer.add(`CLIENT_RANDOM ${R(1)} ${S(1)}`)));
  checkTrue('...and clear', throws(() => sharer.clear()));
  checkTrue('adopting your own buffer is a no-op', (() => {
    live.adopt(live.share());
    live.add(`CLIENT_RANDOM ${R(0x0b)} ${S(0x0c)}\n`);
    return live.secretsFor(randomOf(0x0b)) !== undefined;
  })());
  checkTrue('adopting a buffer that is not a key log throws', throws(() => sharer.adopt({ buffer: new ArrayBuffer(512), live: false, cleared: false })));

  console.log('\n--- clear ---\n');

  const cleared = new KeyLogStore();
  const clearedSnaps: KeyLogShared[] = [];
  cleared.onSnapshot((s) => clearedSnaps.push(s));
  cleared.add(corpus);
  const genBefore = cleared.generation;
  const oldReader = new KeyLogStore();
  oldReader.adopt(cleared.share());
  cleared.clear();
  check('clear empties every count', cleared.stats(), { connections: 0, secrets: 0, ignored: 0, dropped: 0 });
  checkTrue('...and the store is empty', cleared.isEmpty && cleared.secretsFor(randomOf(0xa1)) === undefined);
  checkTrue('clear posts a cleared snapshot', clearedSnaps.length === 1 && clearedSnaps[0].cleared === true);
  checkTrue('the cleared generation is higher than before', cleared.generation > genBefore);
  checkTrue('a reader on the old buffer is stale, not torn', oldReader.secretsFor(randomOf(0xa1)) !== undefined);
  const afterClear = new KeyLogStore();
  afterClear.adopt(clearedSnaps[0]);
  check('a reader that adopts the cleared snapshot is empty', afterClear.stats(), { connections: 0, secrets: 0, ignored: 0, dropped: 0 });
  cleared.add(`CLIENT_RANDOM ${R(0x21)} ${S(0x22)}\n`);
  checkTrue('...and sees what is added after the clear without another snapshot', afterClear.secretsFor(randomOf(0x21)) !== undefined && clearedSnaps.length === 1);
  checkTrue('a clear with ignored lines forgets the count', (() => {
    cleared.add('NOT_A_LABEL x y\n');
    cleared.clear();
    return cleared.stats().ignored === 0;
  })());

  console.log('\n--- the bound ---\n');

  const small = new KeyLogStore({ maxSecrets: 100 });
  let boundText = '';
  for (let i = 0; i < 120; i++) boundText += `CLIENT_RANDOM ${R(i + 1)} ${S(i + 1)}\n`;
  small.add(boundText);
  check('lines past the bound are dropped and counted', small.stats().dropped, 20);
  check('...and not stored', small.stats().secrets, 100);
  checkTrue('...and the first 100 are the ones kept', small.secretsFor(randomOf(100)) !== undefined && small.secretsFor(randomOf(101)) === undefined);
  checkTrue('...a held line repeated at the bound is not dropped', (() => {
    small.add(`CLIENT_RANDOM ${R(1)} ${S(1)}\n`);
    return small.stats().dropped === 20;
  })());

  console.log('\n--- copy mode, where memory cannot be shared ---\n');

  const copy = new KeyLogStore({ shared: false });
  const copySnaps: KeyLogShared[] = [];
  copy.onSnapshot((s) => copySnaps.push(s));
  let copyText = '';
  for (let i = 0; i < 50; i++) copyText += `CLIENT_RANDOM ${R(i + 1)} ${S(i + 1)}\n`;
  for (const part of copyText.split('\n').filter(Boolean)) copy.add(`${part}\n`);
  const lastAdd = Date.now();
  check('nothing is posted in the turn of the adds', copySnaps.length, 0);
  await sleep(300);
  const copyLatencyMs = copySnaps.length > 0 ? Date.now() - lastAdd : -1;
  check('copy mode coalesces 50 adds in one turn into one snapshot', copySnaps.length, 1);
  const copyReader = new KeyLogStore();
  if (copySnaps.length > 0) copyReader.adopt(copySnaps[0]);
  checkTrue('copy mode posts a frozen ArrayBuffer',
    copySnaps.length > 0 && !(copySnaps[0].buffer instanceof SharedArrayBuffer) && copySnaps[0].live === false);
  checkTrue('...which arrives within 300 ms of the last add, holding all 50',
    copyLatencyMs >= 0 && copyLatencyMs <= 320 && copyReader.stats().secrets === 50);
  copy.add(`CLIENT_RANDOM ${R(0xf1)} ${S(0xf1)}\n`);
  checkTrue('a copy is frozen: a later add does not reach it', copyReader.secretsFor(randomOf(0xf1)) === undefined);
  await sleep(300);
  check('...a new snapshot carries it', copySnaps.length, 2);
  copy.add(`CLIENT_RANDOM ${R(0xf2)} ${S(0xf2)}\n`);
  copy.clear();
  await sleep(300);
  check('clear posts at once and cancels the pending copy', copySnaps.map((s) => s.cleared), [false, false, true]);
  const copyClean = new KeyLogStore();
  copyClean.adopt(copySnaps[2]);
  checkTrue('...the cleared copy is empty', copyClean.isEmpty && copyClean.generation > copyReader.generation);

  console.log('\n--- memory ---\n');

  const gc: (() => void) | undefined = (globalThis as { gc?: () => void }).gc
    ?? (() => { setFlagsFromString('--expose-gc'); return runInNewContext('gc') as () => void; })();
  const heapNow = () => { gc!(); gc!(); return process.memoryUsage().heapUsed; };
  const LINES_TARGET = 400_000;
  const heap0 = heapNow();
  const mem = new KeyLogStore();
  let memText = '';
  for (let i = 0; i < LINES_TARGET / 5; i++) {
    memText += connectionText(i);
    if (memText.length >= 1_000_000) { mem.add(memText); memText = ''; }
  }
  mem.add(memText);
  memText = '';
  const heap1 = heapNow();
  const bufferBytes = mem.share().buffer.byteLength;
  const heapDelta = heap1 - heap0;
  check('400,000 lines held', mem.stats().secrets, LINES_TARGET);
  console.log(`      ${(bufferBytes / LINES_TARGET).toFixed(1)} buffer bytes a line (${(bufferBytes / 1048576).toFixed(1)} MiB); JS heap delta ${(heapDelta / 1048576).toFixed(2)} MiB`);
  checkTrue('<= 128 buffer bytes per accepted line', bufferBytes / LINES_TARGET <= 128);
  checkTrue('<= 16 MiB of JS heap for the store', heapDelta <= 16 * 1024 * 1024);
  checkTrue('...and the store still answers', (() => {
    const c = connection(77_777);
    const got = mem.secretsFor(c.random);
    return got !== undefined && got.size === 5 && hexOf(got.get(THREAD_LABELS[4])!) === hexOf(c.secrets[4]);
  })());

  console.log('\n--- across threads ---\n');

  const STEP = 2_000;
  const THREAD_CONNS = 200_000;
  const tw = new KeyLogStore();
  const reader = new Worker(new URL('./key-log-table-reader.ts', import.meta.url), { execArgv: ['--import', 'tsx'] });
  const report = new Promise<ReaderReport>((resolve, reject) => {
    reader.once('message', (m: ReaderReport) => resolve(m));
    reader.once('error', reject);
    reader.once('exit', (code) => { if (code !== 0) reject(new Error(`the reader exited with ${code}`)); });
  });
  const send = (m: ToReader) => reader.postMessage(m);
  let posted = 0;
  tw.onSnapshot((snapshot) => { posted++; send({ type: 'snapshot', snapshot }); });
  send({ type: 'snapshot', snapshot: tw.share() });
  const started = Date.now();
  for (let from = 0; from < THREAD_CONNS; from += STEP) {
    let text = '';
    for (let i = from; i < from + STEP; i++) text += connectionText(i);
    tw.add(text);
    send({ type: 'step', from, to: from + STEP });
  }
  send({ type: 'done' });
  const readerReport = await report;
  await reader.terminate();
  console.log(`      writer: ${tw.stats().secrets} lines in ${Date.now() - started} ms; ${posted} replacement snapshots; reader: ${JSON.stringify(readerReport)}`);
  check('the writer held every connection', tw.stats().connections, THREAD_CONNS);
  check('the reader found every announced connection, whole and correct', readerReport.wrong, 0);
  check('...and checked all of them', readerReport.checked, THREAD_CONNS);
  check('...and never saw a torn one', readerReport.torn, 0);
  check('...nor a connection that was never written', readerReport.phantom, 0);
  checkTrue('...and adopted at least one replaced buffer', readerReport.adopted >= 2);

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All key log table checks passed.');
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
