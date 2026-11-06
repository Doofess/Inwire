/**
 * Loading a key log file through the Decryption panel (ADR 0073).
 *
 * `file.text()` was the whole read. At the cap that is a 512 MiB string, which
 * is longer than V8's longest (2^29 - 24 characters), and well before the cap
 * it is hundreds of megabytes on the page's heap at once. `readKeyLogFile`
 * reads in chunks and hands the store whole lines, from the file's newest
 * `cap` bytes, the way main's follower does.
 */
import { loadKeyLogFile, readKeyLogFile } from '../../src/lib/keyLogFile';
import { KeyLogStore, addKeyLogText } from '../../src/services/tls/keyLog';
import { writeSyntheticKeyLog } from '../electron/syntheticKeyLog';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}

async function read(text: string | Uint8Array, options: Parameters<typeof readKeyLogFile>[2] = {}) {
  const adds: string[] = [];
  const result = await readKeyLogFile(new Blob([text as BlobPart]), (t) => { adds.push(t); }, options);
  return { adds, joined: adds.join(''), ...result };
}

const lines = Array.from({ length: 40 }, (_, i) => `CLIENT_RANDOM ${String(i).padStart(64, '0')} ${'ab'.repeat(48)}\n`);
const log = lines.join('');

console.log('\n--- under the cap ---\n');
{
  const whole = await read(log);
  check('a file under the cap is handed over whole', whole.joined, log);
  check('...with nothing skipped', whole.skippedBytes, 0);
  const chunked = await read(log, { chunkBytes: 7 });
  check('read in small chunks, the store still gets every byte', chunked.joined, log);
  check('...and every add but the last ends on a whole line', chunked.adds.slice(0, -1).every((t) => t.endsWith('\n')), true);
  check('...the last too, when the file ends with a newline', chunked.adds[chunked.adds.length - 1].endsWith('\n'), true);
  const unterminated = await read('LABEL a b\nLABEL c d', { chunkBytes: 4 });
  check('a last line with no newline is still handed over', unterminated.joined, 'LABEL a b\nLABEL c d');
  check('an empty file adds nothing', (await read('')).adds, []);
}

console.log('\n--- over the cap ---\n');
{
  const cap = lines[0].length * 10 + 5;
  const capped = await read(log, { cap, chunkBytes: 64 });
  check('a file over the cap reports size - cap as skipped', capped.skippedBytes, log.length - cap);
  check('...and starts at the first whole line after it', capped.joined, lines.slice(-10).join(''));
  const big = await read(log, { cap, chunkBytes: 1 << 20 });
  check('...the same with one chunk', big.joined, lines.slice(-10).join(''));
}

console.log('\n--- a cut that lands exactly on a line start ---\n');
{
  // The byte before `size - cap` is the previous line's newline: the cut is a
  // line start, and that line is whole, so it is kept (the follower does the same).
  const L = lines[0].length;
  const exact = await read(log, { cap: L * 10, chunkBytes: 64 });
  check('an exact cut keeps the line it lands on', exact.joined, lines.slice(-10).join(''));
  check('...and still reports size - cap as skipped', exact.skippedBytes, log.length - L * 10);
  const exactOne = await read(log, { cap: L * 10, chunkBytes: 1 << 20 });
  check('...the same with one chunk', exactOne.joined, lines.slice(-10).join(''));
  const midLine = await read(log, { cap: L * 10 + 1, chunkBytes: 64 });
  check('a cut that lands on the newline ending the line before drops that line, not the next', midLine.joined, lines.slice(-10).join(''));
  const midLineLate = await read(log, { cap: L * 10 - 1, chunkBytes: 64 });
  check('a cut one byte into the first kept line drops it', midLineLate.joined, lines.slice(-9).join(''));
}

console.log('\n--- what a chunk boundary must not break ---\n');
{
  // 'é' is two bytes in UTF-8; a chunk of 3 splits every one of them.
  const accented = 'CLIENT_RANDOM ééé x\n# café\n';
  check('a character split across chunks decodes whole', (await read(accented, { chunkBytes: 3 })).joined, accented);
  // A file with no newline in it would make the carried line the whole file.
  const runaway = `${'x'.repeat(5000)}\n${lines[0]}`;
  const bounded = await read(runaway, { chunkBytes: 256, maxLineBytes: 1024 });
  check('a line past the bound is dropped, not carried', bounded.joined, lines[0]);
  check('...and no add is longer than a chunk plus the bound', Math.max(...bounded.adds.map((t) => t.length)) <= 256 + 1024, true);
  const tail = await read(`${lines[0]}${'y'.repeat(5000)}`, { chunkBytes: 256, maxLineBytes: 1024 });
  check('...including one that runs to the end of the file', tail.joined, lines[0]);
}

console.log('\n--- the panel\'s Load, and a Clear pressed while it runs ---\n');
{
  /** A file whose chunks arrive one at a time, when the test lets them: a Clear can land between two. */
  const gatedFile = (text: string) => {
    const bytes = new TextEncoder().encode(text);
    const waiting: (() => void)[] = [];
    let reads = 0;
    const file = {
      size: bytes.length,
      slice: (a: number, b: number) => ({
        arrayBuffer: () => new Promise<ArrayBuffer>((resolve) => {
          reads++;
          waiting.push(() => resolve(bytes.slice(a, b).buffer));
        }),
      }),
    } as unknown as Blob;
    /** Lets the oldest pending read finish, and everything it sets off. */
    const next = async () => {
      waiting.shift()?.();
      await new Promise<void>((resolve) => setImmediate(resolve));
    };
    return { file, next, reads: () => reads };
  };
  const finish = async <T>(pending: Promise<T>, next: () => Promise<void>): Promise<T> => {
    let settled = false;
    void pending.then(() => { settled = true; }, () => { settled = true; });
    while (!settled) await next();
    return pending;
  };

  const plain = new KeyLogStore();
  const whole = await loadKeyLogFile(new Blob([log]), plain, { chunkBytes: 1024 });
  check('a Load says what it added', whole, { kind: 'loaded', secrets: 40, connections: 40, skippedBytes: 0 });

  const store = new KeyLogStore();
  store.add(`CLIENT_RANDOM ${'f'.repeat(64)} ${'cd'.repeat(48)}\n`);
  const gated = gatedFile(log);
  const pending = loadKeyLogFile(gated.file, store, { chunkBytes: 1024 });
  await gated.next();
  const beforeClear = store.stats().secrets;
  store.clear();
  const result = await finish(pending, gated.next);
  check('the Load had added secrets before the Clear', beforeClear > 1, true);
  check('a Load the user clears ends as cleared, with no counts to show', result, { kind: 'cleared' });
  check('...and nothing it reads after the Clear reaches the store', store.stats().secrets, 0);
  check('...and it stops reading the file', gated.reads(), 2);

  const early = new KeyLogStore();
  early.clear();
  const afterEarlyClear = await loadKeyLogFile(new Blob([log]), early, { chunkBytes: 1024 });
  check('a Clear before a Load starts does not cancel it', afterEarlyClear.kind === 'loaded' && early.stats().secrets === 40, true);
}

console.log('\n--- the panel\'s Load reserves once ---\n');
{
  // An owner-shaped log, generated at run time and deleted at once (never committed).
  const dir = mkdtempSync(join(tmpdir(), 'inwire-keylog-file-'));
  let synth = '';
  try {
    const file = join(dir, 'keylog.txt');
    await writeSyntheticKeyLog(file, 20_000);
    synth = readFileSync(file, 'latin1');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  /** A store that records which `add` (1-based) each snapshot was posted during or after. */
  const watched = () => {
    const store = new KeyLogStore();
    let adds = 0;
    const snapshotsAt: number[] = [];
    const add = store.add.bind(store);
    store.add = (text: string) => { adds++; return add(text); };
    store.onSnapshot(() => { snapshotsAt.push(adds); });
    return { store, snapshotsAt };
  };
  const bufferBytes = (s: KeyLogStore) => s.share().buffer.byteLength;

  const { store, snapshotsAt } = watched();
  const loaded = await loadKeyLogFile(new Blob([synth]), store, { chunkBytes: 1 << 20 });
  check('a Load of an owner-shaped log (20,000 connections) is read in many chunks and keeps every secret',
    loaded.kind === 'loaded' && loaded.connections === 20_000 && loaded.secrets > 100_000
    && synth.length > 4 * (1 << 20), true);
  check('...snapshots happen only around the first chunk (its growth, then the reserve), none after',
    snapshotsAt.length > 0 && snapshotsAt.every((n) => n <= 1), true);
  const upFront = new KeyLogStore();
  upFront.reserve(synth.length);
  check('...and the table ends the size an up-front reserve for the file gives', bufferBytes(store), bufferBytes(upFront));

  const cappedWatch = watched();
  const cap = Math.floor(synth.length / 2);
  const capped = await loadKeyLogFile(new Blob([synth]), cappedWatch.store, { chunkBytes: 1 << 20, cap });
  check('a Load over the cap reserves for the cap, not the file: none after the first chunk',
    cappedWatch.snapshotsAt.length > 0 && cappedWatch.snapshotsAt.every((n) => n <= 1), true);
  const capFront = new KeyLogStore();
  capFront.reserve(cap);
  check('...and ends the size a reserve for the cap gives', bufferBytes(cappedWatch.store), bufferBytes(capFront));
  check('...and reports the bytes it skipped', capped.kind === 'loaded' && capped.skippedBytes === synth.length - cap, true);

  // A file that is not a key log (a pcap picked through "All files") sets nothing aside.
  const junkBytes = new Uint8Array(20 * (1 << 20));
  for (let i = 0; i < junkBytes.length; i++) junkBytes[i] = (i * 2654435761 >>> 24) & 0xff;
  for (let i = 0; i < junkBytes.length; i += 97) junkBytes[i] = 10;
  const junkStore = new KeyLogStore();
  const junk = await loadKeyLogFile(new Blob([junkBytes]), junkStore, { chunkBytes: 1 << 20 });
  check('a Load of 20 MB that is not a key log adds nothing', junk.kind === 'loaded' && junk.secrets, 0);
  check('...and leaves the buffer small (under 1 MiB; a reserve for 20 MB would be 11 MB)', bufferBytes(junkStore) < (1 << 20), true);

  // A file already held adds no secret, so it reserves nothing more.
  const again = watched();
  await loadKeyLogFile(new Blob([synth]), again.store, { chunkBytes: 1 << 20 });
  const sizeHeld = bufferBytes(again.store);
  const snapsHeld = again.snapshotsAt.length;
  await loadKeyLogFile(new Blob([synth]), again.store, { chunkBytes: 1 << 20 });
  check('loading the file already held posts nothing and moves nothing',
    [again.snapshotsAt.length, bufferBytes(again.store)], [snapsHeld, sizeHeld]);
}

console.log('\n--- addKeyLogText: sized once, added in whole lines ---\n');
{
  const text = Array.from({ length: 300 }, (_, i) =>
    `CLIENT_RANDOM ${String(i).padStart(64, '0')} ${'ab'.repeat(48)}\n`).join('');
  const junk = 'x'.repeat(10_000);
  const withJunk = `${text.slice(0, text.length / 2)}${junk}\n${text.slice(text.length / 2)}`;

  const store = new KeyLogStore();
  const adds: string[] = [];
  const reserves: number[] = [];
  let threw = false;
  try {
    addKeyLogText({
      reserve: (n) => { reserves.push(n); store.reserve(n); },
      add: (t) => { adds.push(t); return store.add(t); },
    }, withJunk, 4096);
  } catch {
    threw = true;
  }
  check('a log with a 10,000-character junk line adds without throwing', threw, false);
  check('...reserving its whole length first, once', reserves, [withJunk.length]);
  check('...every secret is held', store.stats().secrets, 300);
  check('...the pieces are the text, in order', adds.join(''), withJunk);
  check('...no add but the last gets text that does not end on a newline',
    adds.slice(0, -1).every((t) => t.endsWith('\n')), true);
  check('...no piece but the junk line\'s is longer than the piece size',
    adds.filter((t) => t.length > 4096).every((t) => t.includes(junk)), true);
  check('...the junk line goes in one piece', adds.filter((t) => t.includes(junk)).length, 1);
  check('...in more than one piece overall (the size bound is real)', adds.length > 5, true);

  const whole = new KeyLogStore();
  let wholeAdds = 0;
  addKeyLogText({ reserve: (n) => whole.reserve(n), add: (t) => { wholeAdds++; return whole.add(t); } }, text);
  check('a log under the piece size is one add', wholeAdds, 1);
  check('...holding all of it', whole.stats().secrets, 300);

  const noNewline = new KeyLogStore();
  const tail: string[] = [];
  addKeyLogText({ reserve: (n) => noNewline.reserve(n), add: (t) => { tail.push(t); return noNewline.add(t); } }, 'LABEL a b\nLABEL c d', 4);
  check('a last line with no newline is still added', tail.join(''), 'LABEL a b\nLABEL c d');
}

console.log('\n--- who calls it (the writers of the page key log) ---\n');
{
  const read = (path: string) => readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), 'utf8');
  const client = read('src/services/importClient.ts');
  const secretsCase = /case 'secrets':[\s\S]*?case '/.exec(client)?.[0] ?? '';
  check('importClient\'s secrets case adds through addKeyLogText(', secretsCase.includes('addKeyLogText('), true);
  check('...and not through a bare keyLog.add(', secretsCase.includes('keyLog.add('), false);
  check('...before the ack it posts', secretsCase.indexOf('addKeyLogText(') >= 0
    && secretsCase.indexOf('addKeyLogText(') < secretsCase.indexOf('secretsTaken'), true);
  const parser = read('src/services/pcapParser.ts');
  const defaultOnSecrets = /onSecrets: \(text: string\) => void \| Promise<void> = ([^\n]*)/.exec(parser)?.[1] ?? '';
  check('pcapParser\'s default onSecrets adds through addKeyLogText(', defaultOnSecrets.includes('addKeyLogText('), true);
  check('...and not through a bare keyLog.add(', defaultOnSecrets.includes('keyLog.add('), false);
  const panel = read('src/components/common/DecryptionSettingsPanel.tsx');
  check('the panel no longer tells the user to restart Inwire for the newest part',
    panel.includes('Restart Inwire to load the newest part'), false);
  check('...it says what to do instead',
    panel.includes('the key log store is full. Clear, then load or follow the file again to bring in its newest secrets.'), true);
}

console.log();
if (failures) {
  console.log(`${failures} key log file check(s) FAILED.`);
  process.exit(1);
}
console.log('All key log file checks passed.');
