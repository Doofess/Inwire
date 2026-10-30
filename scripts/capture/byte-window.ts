/**
 * ByteWindow: one resident window of a file, loaded on demand.
 *
 *   npx tsx scripts/capture/byte-window.ts
 *
 * ## Why it exists
 *
 * The parser used to call `file.arrayBuffer()`, which cannot hold a file past
 * about 2 GB (#20). The frame walk now reads through a `ByteWindow`: a record is
 * read from the resident window, and the next window is fetched only when a
 * record is not in it.
 *
 * ## What is pinned
 *
 * - A `whole` window answers every in-range span and never reads.
 * - `over` reads `[at, at + max(length, windowBytes))`, clamped to the file, and
 *   grows past the window size for one record that is longer than it. The slice
 *   count is the check: a window that read exactly what was asked would pass every
 *   value check below and still read the file in a thousand small pieces.
 * - Reads address the file by absolute offset, whatever the window's base.
 * - `copy` is an own buffer, never a view of the window.
 */
import { ByteWindow, READ_WINDOW_BYTES, type BlobLike } from '../../src/services/byteWindow';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}

/** A blob of bytes 0..size-1 (mod 256) that records every slice asked of it. */
function spyBlob(size: number): { blob: BlobLike; reads: Array<[number, number]> } {
  const reads: Array<[number, number]> = [];
  const blob: BlobLike = {
    size,
    slice: (start = 0, end = size) => {
      reads.push([start, end]);
      return {
        arrayBuffer: async () => {
          const out = new Uint8Array(end - start);
          for (let i = 0; i < out.length; i++) out[i] = (start + i) & 0xff;
          return out.buffer;
        },
      };
    },
  };
  return { blob, reads };
}

check('the window is 64 MiB', READ_WINDOW_BYTES, 64 * 1024 * 1024);

// --- whole -------------------------------------------------------------------

{
  const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
  const w = ByteWindow.whole(buffer);
  check('whole: size', w.size, 8);
  check('whole: has the whole span', [w.has(0, 8), w.has(3, 5), w.has(7, 1)], [true, true, true]);
  check('whole: has nothing past the end', [w.has(5, 4), w.has(8, 1)], [false, false]);
  await w.load(2, 3);
  check('whole: load is a no-op', [w.has(0, 8), w.u8(0)], [true, 1]);
  check('whole: u16 and u32 by absolute offset',
    [w.u16(1, true), w.u16(1, false), w.u32(2, true), w.u32(2, false)],
    [0x0302, 0x0203, 0x06050403, 0x03040506]);
  check('whole: bytes is a view of the span', [...w.bytes(2, 3)], [3, 4, 5]);
  const copied = w.copy(2, 3);
  check('whole: copy holds the span', [...new Uint8Array(copied)], [3, 4, 5]);
  check('whole: copy is not the window\'s buffer', copied === buffer, false);
  new Uint8Array(copied)[0] = 99;
  check('whole: writing the copy leaves the window alone', w.u8(2), 3);
}

// --- over ----------------------------------------------------------------------

{
  const { blob, reads } = spyBlob(25);
  const seen: Array<[number, number]> = [];
  const w = ByteWindow.over(blob, 10, (end, size) => seen.push([end, size]));
  check('over: size is the blob\'s', w.size, 25);
  check('over: nothing is resident before a load', [w.has(0, 1), reads.length], [false, 0]);

  await w.load(0, 4);
  check('over: load(0, 4) reads a whole window', reads.at(-1), [0, 10]);
  check('over: the window answers inside it', [w.has(0, 10), w.has(9, 1), w.has(9, 2)], [true, true, false]);
  check('over: u8 by absolute offset', [w.u8(0), w.u8(9)], [0, 9]);

  await w.load(8, 4);
  check('over: load(8, 4) reads from the record', reads.at(-1), [8, 18]);
  check('over: the old start is gone', [w.has(0, 1), w.has(8, 10)], [false, true]);
  // The window's base is now 8, so an offset of 9 is index 1 of its buffer.
  check('over: u32 little endian at an absolute offset past the base', w.u32(9, true), 0x0c0b0a09);
  check('over: u32 big endian at an absolute offset past the base', w.u32(9, false), 0x090a0b0c);
  check('over: u16 at an absolute offset past the base', [w.u16(9, true), w.u16(9, false)], [0x0a09, 0x090a]);

  await w.load(20, 9);
  check('over: load(20, 9) is clamped to the file', reads.at(-1), [20, 25]);

  await w.load(3, 15);
  check('over: load(3, 15) grows to hold the record', reads.at(-1), [3, 18]);
  check('over: the grown window holds the record', w.has(3, 15), true);
  check('over: copy is the span, absolute', [...new Uint8Array(w.copy(5, 3))], [5, 6, 7]);
  check('over: bytes is the span, absolute', [...w.bytes(16, 2)], [16, 17]);

  check('over: onLoad reports the end and the size of each load',
    seen, [[10, 25], [18, 25], [25, 25], [18, 25]]);
  check('over: one slice per load', reads.length, 4);
}

// --- a load that is not needed is not made --------------------------------------

{
  const { blob, reads } = spyBlob(100);
  const w = ByteWindow.over(blob, 40);
  await w.load(0, 8);
  for (let at = 0; at + 8 <= 40; at += 8) {
    if (!w.has(at, 8)) await w.load(at, 8);
  }
  check('over: records inside the window cost no further read', reads.length, 1);
  if (!w.has(40, 8)) await w.load(40, 8);
  check('over: the first record past it costs one', reads, [[0, 40], [40, 80]]);
}

// --- offsets past 2^32 ------------------------------------------------------------

{
  // A blob that claims 5 GiB and synthesises only the slice asked for.
  const size = 5 * 2 ** 30;
  const reads: Array<[number, number]> = [];
  const blob: BlobLike = {
    size,
    slice: (start = 0, end = size) => {
      reads.push([start, end]);
      return { arrayBuffer: async () => new Uint8Array(end - start).fill(0xab).buffer };
    },
  };
  const w = ByteWindow.over(blob, 64);
  const at = 4 * 2 ** 30 + 12;
  await w.load(at, 8);
  check('over: a load at 4 GiB + 12 reads exactly that range', reads, [[at, at + 64]]);
  check('over: a read at 4 GiB + 12 is in the window and decodes', [w.has(at, 8), w.u32(at, true)], [true, 0xabababab]);
  check('over: the end of a 5 GiB file clamps', (await w.load(size - 4, 8), reads.at(-1)), [size - 4, size]);
}

console.log(failures === 0
  ? '\nAll byte window checks passed.'
  : `\n${failures} byte window check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
