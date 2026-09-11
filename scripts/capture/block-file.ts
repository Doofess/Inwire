/**
 * One `BlockFile` contract, run against every implementation of it.
 *
 *   npx tsx scripts/capture/block-file.ts
 *
 * The seam's whole value is that the capture format is written once and works
 * over anything that can read and write bytes - so the thing worth asserting is
 * not each implementation separately but that they are **indistinguishable**.
 * Until now nothing checked that at all: `MemoryBlockFile` was exercised only
 * indirectly, through the writer and reader suites, and `SyncAccessBlockFile`
 * could not be exercised from Node at all.
 *
 * `NodeBlockFile` is what makes the file's own stated test strategy true for
 * the first time - `blockFile.ts` has promised since it was written that
 * "`scripts/` supplies a `node:fs` implementation and drives the format
 * against a real multi-gigabyte file on the local disk, killing and truncating
 * it at chosen offsets", and there was no such implementation.
 *
 * Four of the cases below are not general file-API hygiene. They are the exact
 * properties the recovery rule rests on, and each fails **silently**:
 *
 *  - a short read at the end of the file is how a reader discovers the file
 *    ended, so it must return a count and not throw;
 *  - a hole must read back as zeros, because the recovery scan reads past the
 *    last good record and has to see something deterministic;
 *  - `size()` must reflect a write that has not been flushed, or the writer's
 *    next append lands on top of the last one;
 *  - and `readExact` must throw on short, because that is what `recoverIndex`
 *    reads as a torn tail. Which is exactly why `NodeBlockFile.read` loops:
 *    `readSync` may return short for reasons that are not EOF, and a single
 *    one of those on a 5 GB `frames.iwbyt` would discard a healthy capture.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { MemoryBlockFile, append, readExact, type BlockFile } from '../../src/services/capture/blockFile';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkThrows(name: string, body: () => unknown): void {
  try { body(); check(name, 'did not throw', 'threw'); } catch { check(name, 'threw', 'threw'); }
}

const bytes = (...values: number[]) => new Uint8Array(values);
const readAll = (file: BlockFile, from: number, length: number): number[] => {
  const into = new Uint8Array(length);
  const got = file.read(from, into);
  return [...into.subarray(0, got)];
};

/** The contract, run identically against each backend. */
function contract(label: string, make: (name: string) => BlockFile): void {
  console.log(`\n--- ${label} ---\n`);

  {
    const file = make('basic');
    check(`${label}: a new file is empty`, file.size(), 0);
    file.write(0, bytes(1, 2, 3, 4));
    // Without a flush. The writer flushes every eight chunks, so every append
    // in between reads a size that no fsync has confirmed.
    check(`${label}: size reflects an unflushed write`, file.size(), 4);
    check(`${label}: the bytes read back`, readAll(file, 0, 4), [1, 2, 3, 4]);
    check(`${label}: ...and so does a slice of them`, readAll(file, 1, 2), [2, 3]);

    file.write(1, bytes(9));
    check(`${label}: a write in the middle replaces, and does not extend`,
      [readAll(file, 0, 4), file.size()], [[1, 9, 3, 4], 4]);
    file.close();
  }

  {
    const file = make('eof');
    file.write(0, bytes(1, 2, 3));
    // The property `recoverIndex` depends on: a short read is a fact, not an
    // error, and it is how the end of the file is discovered.
    check(`${label}: reading past the end returns what is there`,
      readAll(file, 0, 10), [1, 2, 3]);
    check(`${label}: reading at the end returns nothing`, readAll(file, 3, 4), []);
    check(`${label}: reading past the end returns nothing`, readAll(file, 99, 4), []);

    // And the helper above the seam turns that same fact into the torn-tail
    // signal, which is why the implementations must never report short for a
    // reason that is not EOF.
    check(`${label}: readExact is happy when the bytes are there`,
      [...readExact(file, 0, 3)], [1, 2, 3]);
    checkThrows(`${label}: readExact throws when the file is shorter`,
      () => readExact(file, 0, 4));
    file.close();
  }

  {
    const file = make('hole');
    file.write(0, bytes(7));
    file.write(8, bytes(7));
    // Both NTFS and POSIX give this, and the recovery scan reads past the last
    // good record expecting it. Asserted rather than assumed.
    check(`${label}: a hole reads back as zeros`,
      readAll(file, 0, 9), [7, 0, 0, 0, 0, 0, 0, 0, 7]);
    check(`${label}: ...and the file is as long as the far end`, file.size(), 9);
    file.close();
  }

  {
    const file = make('truncate');
    file.write(0, bytes(1, 2, 3, 4, 5));
    file.truncate(2);
    check(`${label}: truncating down discards`, [readAll(file, 0, 8), file.size()], [[1, 2], 2]);
    file.truncate(5);
    check(`${label}: truncating up zero-fills`, [readAll(file, 0, 8), file.size()],
      [[1, 2, 0, 0, 0], 5]);
    file.truncate(0);
    check(`${label}: truncating to nothing empties it`, [readAll(file, 0, 4), file.size()], [[], 0]);
    file.close();
  }

  {
    const file = make('append');
    check(`${label}: the first append lands at zero`, append(file, bytes(1, 2)), 0);
    check(`${label}: the next one follows it`, append(file, bytes(3)), 2);
    check(`${label}: ...and the one after that`, append(file, bytes(4, 5, 6)), 3);
    check(`${label}: the file is the sum of them`,
      [readAll(file, 0, 6), file.size()], [[1, 2, 3, 4, 5, 6], 6]);
    file.close();
  }

  {
    // Big enough that a real filesystem can answer a read or a write in more
    // than one go, which is the case `NodeBlockFile`'s loops exist for.
    const file = make('large');
    const size = 8 * 1024 * 1024;
    const source = new Uint8Array(size);
    for (let i = 0; i < size; i++) source[i] = (i * 31) & 0xff;
    file.write(0, source);
    const back = new Uint8Array(size);
    const got = file.read(0, back);
    let identical = got === size;
    if (identical) {
      for (let i = 0; i < size; i++) {
        if (back[i] !== source[i]) { identical = false; break; }
      }
    }
    check(`${label}: 8 MB round-trips in one call, whole`, [got, identical], [size, true]);
    file.close();
  }

  {
    const file = make('refusals');
    checkThrows(`${label}: a negative read offset is refused`, () => file.read(-1, bytes(0)));
    checkThrows(`${label}: a negative write offset is refused`, () => file.write(-1, bytes(0)));
    checkThrows(`${label}: a negative truncate is refused`, () => file.truncate(-1));
    file.close();
  }
}

const directory = mkdtempSync(path.join(tmpdir(), 'inwire-blockfile-'));
try {
  contract('MemoryBlockFile', () => new MemoryBlockFile());
  contract('NodeBlockFile', (name) => NodeBlockFile.open(path.join(directory, `${name}.bin`)));

  console.log('\n--- what only a real file can be asked ---\n');
  {
    const file = NodeBlockFile.open(path.join(directory, 'reopen.bin'));
    file.write(0, bytes(1, 2, 3));
    file.flush();
    file.close();
    // The property a restart depends on, and the one `MemoryBlockFile` cannot
    // have: the bytes are still there when the process that wrote them is not.
    const again = NodeBlockFile.open(path.join(directory, 'reopen.bin'));
    check('a closed file reopens with its bytes and its length',
      [readAll(again, 0, 3), again.size()], [[1, 2, 3], 3]);
    again.close();

    checkThrows('a closed file refuses to be read', () => again.read(0, bytes(0)));
    checkThrows('...and refuses to be written', () => again.write(0, bytes(0)));
    // Closing twice is what a failed open leads to on the way out, and it must
    // not throw over an fd that is already gone.
    again.close();
    check('closing twice is harmless', true, true);
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
}

console.log(failures === 0
  ? '\nAll block file checks passed.'
  : `\n${failures} block file check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
