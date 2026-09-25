/**
 * The streaming save: tokens, partial files, and the sinks over them.
 *
 *   npx tsx scripts/export/save-stream.ts
 *
 * `electron/saveSession.ts` is driven against a real temporary directory,
 * because what it promises is about files: that the chosen name appears only
 * on commit, that nothing is left behind by an abort, a second close, a window
 * that went away or a quit, that a read-only target is refused before any
 * export is spent on it, that a commit whose rename fails keeps the finished
 * partial and names it, and that no file this app did not create is touched. The dialog and the IPC are `saveStream.ts` and are
 * not here - it imports `electron`.
 *
 * `src/lib/saveSink.ts` is then driven twice: `zipSink` over a `MemorySink`,
 * and the real `openSaveSink` over a stand-in bridge that routes into a real
 * `SaveSessions` - so the coalescing, the commit and the zip are one path to
 * a real file. The bytes are a real capture, streamed in uneven chunks.
 */
import {
  chmodSync, closeSync, existsSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { open as openFile, rename as renameFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { unzipSync } from 'fflate';
import { SaveSessions, type CloseResult, type OpenResult } from '../../electron/saveSession';
import { COALESCE_BYTES, isByteSink, MemorySink, openSaveSink, zipSink, type ByteSink } from '../../src/lib/saveSink';

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

function tokenOf(result: OpenResult): string {
  if ('error' in result) throw new Error(`open failed: ${result.error}`);
  return result.token;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.byteLength === b.byteLength && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

/** Every partial beside `target` - the names are random, so they are found, not built. */
function partialsOf(target: string): string[] {
  const base = `${path.basename(target)}.`;
  return readdirSync(path.dirname(target))
    .filter((name) => name.startsWith(base) && name.endsWith('.partial'))
    .map((name) => path.join(path.dirname(target), name));
}
const hasPartial = (target: string): boolean => partialsOf(target).length > 0;

/** 1 byte, then primes, then a big one - so no chunk boundary is a round number. */
async function streamUnevenly(sink: ByteSink, bytes: Uint8Array): Promise<number> {
  const sizes = [1, 7, 13, 4096, 65_537, 3 * 1024 * 1024 + 11, 997];
  let offset = 0;
  let calls = 0;
  while (offset < bytes.byteLength) {
    const size = sizes[calls % sizes.length];
    await sink.write(bytes.subarray(offset, offset + size));
    offset += size;
    calls++;
  }
  return calls;
}

const dir = mkdtempSync(path.join(tmpdir(), 'inwire-save-stream-'));
const WINDOW_A = 1;
const WINDOW_B = 2;

try {
  console.log('--- saveSession: the chosen name appears only on commit ---\n');

  {
    const sessions = new SaveSessions();
    const target = path.join(dir, 'commit.pcapng');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    check('open creates the partial, not the target',
      [hasPartial(target), existsSync(target)], [true, false]);
    const partial = sessions.partialOf(token) ?? '';
    check('the partial is <path>.<random>.partial',
      /^commit\.pcapng\.[0-9a-f]{12}\.partial$/.test(path.basename(partial)), true);

    await sessions.write(WINDOW_A, token, new Uint8Array([1, 2, 3]));
    await sessions.write(WINDOW_A, token, new Uint8Array([4, 5]));

    // A second window holding the token must not be able to do anything with it.
    check('a write from another window is refused',
      await sessions.write(WINDOW_B, token, new Uint8Array([9])), { error: 'no such save in progress' });
    check('a close from another window is refused',
      await sessions.close(WINDOW_B, token, false),
      { saved: false, canceled: false, error: 'no such save in progress' });
    check('...and the refused abort deleted nothing', hasPartial(target), true);

    check('commit reports the chosen path',
      await sessions.close(WINDOW_A, token, true), { saved: true, path: target });
    check('commit leaves the target and no partial',
      [existsSync(target), hasPartial(target)], [true, false]);
    check('the target holds exactly what was written, in order',
      [...readFileSync(target)], [1, 2, 3, 4, 5]);

    // The committed file must survive a double click on "save".
    const again: CloseResult = await sessions.close(WINDOW_A, token, false);
    check('a second close is refused rather than acted on', again.saved, false);
    check('...and did not delete the committed file', existsSync(target), true);
    check('a write after close is refused',
      await sessions.write(WINDOW_A, token, new Uint8Array([6])), { error: 'no such save in progress' });
    check('no session is left open', sessions.openCount, 0);
  }

  console.log('\n--- saveSession: abort, bad input, and a window that went away ---\n');

  {
    const sessions = new SaveSessions();
    const target = path.join(dir, 'abort.pcap');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    await sessions.write(WINDOW_A, token, new Uint8Array(1000));
    check('abort answers as a cancel',
      await sessions.close(WINDOW_A, token, false), { saved: false, canceled: true });
    check('abort leaves neither the target nor the partial',
      [existsSync(target), hasPartial(target)], [false, false]);

    check('a token that was never issued is refused',
      await sessions.write(WINDOW_A, 'not-a-token', new Uint8Array(1)), { error: 'no such save in progress' });
    const typed = tokenOf(await sessions.open(WINDOW_A, path.join(dir, 'typed.bin')));
    check('a chunk that is not bytes is refused',
      await sessions.write(WINDOW_A, typed, 'hello'), { error: 'a save chunk must be bytes' });
    await sessions.close(WINDOW_A, typed, false);
  }

  {
    // The limit is per process, and a renderer that never closes must hit it.
    const sessions = new SaveSessions(2);
    const first = tokenOf(await sessions.open(WINDOW_A, path.join(dir, 'l1.bin')));
    tokenOf(await sessions.open(WINDOW_A, path.join(dir, 'l2.bin')));
    const third = await sessions.open(WINDOW_A, path.join(dir, 'l3.bin'));
    check('opens past the limit are refused', 'error' in third, true);
    check('...and create no file', hasPartial(path.join(dir, 'l3.bin')), false);
    await sessions.close(WINDOW_A, first, false);
    const fourth = await sessions.open(WINDOW_A, path.join(dir, 'l4.bin'));
    check('closing one frees a slot', 'token' in fourth, true);
    await sessions.dropSender(WINDOW_A);
  }

  {
    const sessions = new SaveSessions();
    const mine = path.join(dir, 'gone-a.pcapng');
    const theirs = path.join(dir, 'kept-b.pcapng');
    const tokenA = tokenOf(await sessions.open(WINDOW_A, mine));
    const tokenB = tokenOf(await sessions.open(WINDOW_B, theirs));
    await sessions.write(WINDOW_A, tokenA, new Uint8Array(10));
    await sessions.write(WINDOW_B, tokenB, new Uint8Array([7]));

    await sessions.dropSender(WINDOW_A);
    check('a destroyed window\'s partial is deleted', hasPartial(mine), false);
    check('...and its target never appears', existsSync(mine), false);
    check('...and its token is dead',
      await sessions.write(WINDOW_A, tokenA, new Uint8Array(1)), { error: 'no such save in progress' });
    check('another window\'s save is untouched',
      await sessions.close(WINDOW_B, tokenB, true), { saved: true, path: theirs });
    check('dropping a window with nothing open is harmless',
      await sessions.dropSender(WINDOW_A).then(() => 'ok'), 'ok');
  }

  {
    // Writes issued without awaiting each one - what an IPC handler sees when
    // several invokes are in flight - must land in the order they were sent.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'ordered.bin');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    const writes = Array.from({ length: 50 }, (_, i) =>
      sessions.write(WINDOW_A, token, new Uint8Array([i])));
    const closing = sessions.close(WINDOW_A, token, true);
    await Promise.all(writes);
    await closing;
    check('unawaited writes land in order, and close waits for them',
      [...readFileSync(target)], Array.from({ length: 50 }, (_, i) => i));
  }

  console.log('\n--- saveSession: an existing target, a locked one, and names nobody else has ---\n');

  {
    const sessions = new SaveSessions();
    const target = path.join(dir, 'existing.pcap');
    writeFileSync(target, 'an older export');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    check('opening over an existing file leaves it alone until commit',
      readFileSync(target, 'utf8'), 'an older export');
    await sessions.write(WINDOW_A, token, new Uint8Array([1, 2, 3]));
    check('commit over an existing file replaces it',
      [await sessions.close(WINDOW_A, token, true), [...readFileSync(target)]],
      [{ saved: true, path: target }, [1, 2, 3]]);
  }

  {
    // A read-only target: refused at open, before any export is spent on it.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'readonly.pcap');
    writeFileSync(target, 'keep me');
    chmodSync(target, 0o444);
    let writable = false;
    try { closeSync(openSync(target, 'r+')); writable = true; } catch { /* read-only, as intended */ }
    if (writable) {
      // Root on a POSIX runner writes through a 0444 mode; there is nothing to refuse.
      console.log('SKIP  a read-only target: this account can write through the read-only bit');
    } else {
      const opened = await sessions.open(WINDOW_A, target);
      const error = 'error' in opened ? opened.error : '';
      check('a read-only target is refused at open', 'error' in opened, true);
      check('...naming the file and why, in words', [error.includes(target), error.includes('read-only')], [true, true]);
      check('...having created no partial', hasPartial(target), false);
      check('...and left the file as it was', readFileSync(target, 'utf8'), 'keep me');
    }
    chmodSync(target, 0o644);
  }

  {
    // The rename fails at commit - a target that another program holds open.
    // Injected, so it is the same failure on every platform: Linux renames
    // over an open file without complaint.
    const failing = new SaveSessions(4, {
      open: openFile,
      rename: async () => {
        throw Object.assign(new Error("EPERM: operation not permitted, rename"), { code: 'EPERM' });
      },
    });
    const target = path.join(dir, 'locked.pcapng');
    const token = tokenOf(await failing.open(WINDOW_A, target));
    const partial = failing.partialOf(token) ?? '';
    await failing.write(WINDOW_A, token, new Uint8Array([4, 5, 6]));
    const result = await failing.close(WINDOW_A, token, true);
    const error = 'error' in result ? result.error : '';
    check('a failed rename is an error, not a save', result.saved, false);
    check('...that names the target and where the export was kept',
      [error.includes(target), error.includes(partial)], [true, true]);
    check('...and the partial is kept, whole', existsSync(partial) ? [...readFileSync(partial)] : null, [4, 5, 6]);
    rmSync(partial, { force: true });
  }

  if (process.platform === 'win32') {
    // The same failure for real. Measured on this machine: a plain Node read
    // handle on the target - no exclusive lock, delete sharing and all - is
    // enough for `rename` onto it to answer EPERM. The `r+` probe passes it,
    // which is exactly the case the kept partial is for.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'open-elsewhere.pcapng');
    writeFileSync(target, 'held open');
    const held = openSync(target, 'r');
    try {
      const token = tokenOf(await sessions.open(WINDOW_A, target));
      const partial = sessions.partialOf(token) ?? '';
      await sessions.write(WINDOW_A, token, new Uint8Array([7, 8]));
      const result = await sessions.close(WINDOW_A, token, true);
      const error = 'error' in result ? result.error : '';
      check('win32: committing over a file held open elsewhere fails', result.saved, false);
      check('...naming the kept partial', error.includes(partial), true);
      check('...which holds the export', existsSync(partial) ? [...readFileSync(partial)] : null, [7, 8]);
      check('...and the held file is untouched', readFileSync(target, 'utf8'), 'held open');
      closeSync(held);
      // What the person does next: close the other program and rename.
      await renameFile(partial, target);
      check('...and once released, the kept partial is the export', [...readFileSync(target)], [7, 8]);
    } finally {
      try { closeSync(held); } catch { /* closed above */ }
    }
  }

  {
    // A `<target>.partial` that is somebody else's must survive a save.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'theirs.pcap');
    const foreign = `${target}.partial`;
    writeFileSync(foreign, 'not ours');
    const first = tokenOf(await sessions.open(WINDOW_A, target));
    const second = tokenOf(await sessions.open(WINDOW_A, target));
    check('two saves of one name write two different partials',
      sessions.partialOf(first) !== sessions.partialOf(second), true);
    await sessions.close(WINDOW_A, first, false);
    await sessions.close(WINDOW_A, second, false);
    check('a pre-existing <target>.partial is neither truncated nor deleted',
      existsSync(foreign) ? readFileSync(foreign, 'utf8') : null, 'not ours');
    rmSync(foreign);
  }

  {
    // Opens arriving together must not both slip under the limit.
    const sessions = new SaveSessions(1);
    const both = await Promise.all([
      sessions.open(WINDOW_A, path.join(dir, 'race-1.bin')),
      sessions.open(WINDOW_A, path.join(dir, 'race-2.bin')),
    ]);
    check('two concurrent opens under a limit of one: exactly one is let in',
      both.map((r) => 'token' in r), [true, false]);
    await sessions.dropSender(WINDOW_A);
  }

  {
    // Writes nobody awaited, past what main will hold for one session.
    const sessions = new SaveSessions(4, undefined, 10);
    const target = path.join(dir, 'flood.bin');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    const first = sessions.write(WINDOW_A, token, new Uint8Array(8));
    const second = sessions.write(WINDOW_A, token, new Uint8Array(8));
    const answers = await Promise.all([first, second]);
    check('a write past the pending bound is refused', 'error' in answers[1], true);
    const closed = await sessions.close(WINDOW_A, token, true);
    check('...and the session cannot commit a file with a hole in it',
      [closed.saved, existsSync(target), hasPartial(target)], [false, false, false]);
  }

  {
    // Quit mid-export: synchronous, so it finishes before the process does.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'quitting.pcapng');
    const token = tokenOf(await sessions.open(WINDOW_A, target));
    await sessions.write(WINDOW_A, token, new Uint8Array(100));
    sessions.abandonAllSync();
    check('abandonAllSync deletes the partial before it returns', hasPartial(target), false);
    check('...and the token is dead',
      await sessions.write(WINDOW_A, token, new Uint8Array(1)), { error: 'no such save in progress' });
  }

  console.log('\n--- saveSink: the sinks, over a real capture ---\n');

  {
    const memory = new MemorySink();
    await memory.write(new Uint8Array([1, 2]));
    const reused = new Uint8Array([3, 4]);
    await memory.write(reused);
    reused[0] = 99;
    check('MemorySink keeps a copy, not the caller\'s buffer', [...memory.bytes()], [1, 2, 3, 4]);
    check('MemorySink closes once', [
      (await memory.close()).saved, (await memory.close()).saved,
    ], [true, false]);
  }

  const capturePath = path.join('test', 'fixtures', 'inwire_capture_1788478187989.pcap');
  if (!existsSync(capturePath)) {
    console.log(`SKIP  the zip and bridge sinks: ${capturePath} is absent (untracked, ADR 0004)`);
  } else {
    const capture = new Uint8Array(readFileSync(capturePath));
    console.log(`      ${capturePath}: ${capture.byteLength} bytes\n`);

    const memory = new MemorySink();
    const zipped = zipSink(memory, 'capture.pcap');
    const calls = await streamUnevenly(zipped, capture);
    const outcome = await zipped.close();
    check('the zip sink closes as saved', outcome.saved, true);
    const entries = unzipSync(memory.bytes());
    check('the zip holds exactly one entry, under the given name', Object.keys(entries), ['capture.pcap']);
    check(`it unzips to exactly the capture's bytes (${calls} uneven writes)`,
      sameBytes(entries['capture.pcap'] ?? new Uint8Array(), capture), true);
    check('...and it is actually compressed', memory.byteLength < capture.byteLength, true);

    const abandoned = new MemorySink();
    const abandonedZip = zipSink(abandoned, 'x.pcap');
    await abandonedZip.write(capture.subarray(0, 1000));
    await abandonedZip.abort();
    check('aborting the zip aborts what it wraps', abandoned.aborted, true);

    // The real `openSaveSink`, with the preload's three calls routed straight
    // into a `SaveSessions`. Counting the writes is the coalescing check.
    const sessions = new SaveSessions();
    const target = path.join(dir, 'bridged.pcap.zip');
    let ipcWrites = 0;
    let largest = 0;
    (globalThis as { window?: unknown }).window = {
      inwire: {
        openSaveStream: async () => sessions.open(WINDOW_A, target),
        writeSaveStream: async (token: string, bytes: Uint8Array) => {
          ipcWrites++;
          largest = Math.max(largest, bytes.byteLength);
          // A structured clone, as IPC would make it.
          return sessions.write(WINDOW_A, token, bytes.slice());
        },
        closeSaveStream: async (token: string, commit: boolean) =>
          sessions.close(WINDOW_A, token, commit),
      },
    };
    const opened = await openSaveSink('bridged.pcap.zip');
    if (!isByteSink(opened)) throw new Error(`openSaveSink: ${JSON.stringify(opened)}`);
    const bridged = zipSink(opened, 'capture.pcap');
    await streamUnevenly(bridged, capture);
    check('the bridged save commits to the chosen path',
      await bridged.close(), { saved: true, path: target });
    check('...and leaves no partial', hasPartial(target), false);
    check('the file on disk unzips to the capture',
      sameBytes(unzipSync(new Uint8Array(readFileSync(target)))['capture.pcap'] ?? new Uint8Array(), capture),
      true);
    const expectedWrites = Math.ceil(readFileSync(target).byteLength / COALESCE_BYTES);
    check(`small writes are coalesced into ${COALESCE_BYTES}-byte messages`,
      [ipcWrites, largest <= COALESCE_BYTES], [expectedWrites, true]);

    const opened2 = await openSaveSink('bridged.pcap.zip');
    if (!isByteSink(opened2)) throw new Error('second open failed');
    await opened2.write(capture.subarray(0, COALESCE_BYTES + 5));
    await opened2.abort();
    // Same name as the save above: the abort must remove its own partial and
    // leave the earlier committed file alone.
    check('an aborted bridged save leaves no partial, and the earlier commit stands',
      [existsSync(target), hasPartial(target)], [true, false]);

    delete (globalThis as { window?: unknown }).window;
    check('with no bridge, opening says so rather than pretending',
      await openSaveSink('x.pcap'), { error: 'no desktop bridge to save through' });
  }

  check('nothing is left in the directory but committed files',
    readdirSync(dir).filter((name) => name.endsWith('.partial')), []);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
