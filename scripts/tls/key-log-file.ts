/**
 * Loading a key log file through the Decryption panel (ADR 0073).
 *
 * `file.text()` was the whole read. At the cap that is a 512 MiB string, which
 * is longer than V8's longest (2^29 - 24 characters), and well before the cap
 * it is hundreds of megabytes on the page's heap at once. `readKeyLogFile`
 * reads in chunks and hands the store whole lines, from the file's newest
 * `cap` bytes, the way main's follower does.
 */
import { readKeyLogFile } from '../../src/lib/keyLogFile';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}

async function read(text: string | Uint8Array, options: Parameters<typeof readKeyLogFile>[2] = {}) {
  const adds: string[] = [];
  const result = await readKeyLogFile(new Blob([text as BlobPart]), (t) => adds.push(t), options);
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

console.log();
if (failures) {
  console.log(`${failures} key log file check(s) FAILED.`);
  process.exit(1);
}
console.log('All key log file checks passed.');
