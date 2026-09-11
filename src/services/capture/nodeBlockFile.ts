/**
 * A `BlockFile` over a real file.
 *
 * The third implementation of the seam, and the one it was built for.
 * `blockFile.ts` has claimed since it was written that `scripts/` would
 * "supply a `node:fs` implementation and drive the format against a real
 * multi-gigabyte file on the local disk, killing and truncating it at chosen
 * offsets" - and that has never been possible, because no such implementation
 * existed. Everything above the seam (`chunkCodec`, `captureIndex`,
 * `captureWriter`, `captureReader`, `captureScan`) is unchanged by this file
 * arriving, which is the whole point of the seam.
 *
 * ## Imports `node:fs` and nothing else
 *
 * Deliberately, and it is a rule rather than an accident: this module is
 * imported by the capture-store process **and** by the assertion scripts, and
 * it must never become reachable from `src/main.tsx` or Vite would try to
 * bundle `node:fs` into the renderer.
 *
 * ## Short counts are the whole reason this file is careful
 *
 * `readSync` and `writeSync` may return fewer bytes than asked for, for
 * reasons that are not end-of-file. Neither `MemoryBlockFile` nor the OPFS
 * handle ever did, so nothing above the seam expects it - and `readExact`
 * throws on a short read, which `recoverIndex` reads as **a torn tail and
 * truncates**. One short read on a 5 GB `frames.iwbyt` would therefore discard
 * a perfectly healthy capture back to its last chunk boundary.
 *
 * So both loop. `read` stops only on a genuine zero-byte return, which is the
 * one thing that does mean end-of-file, and returns what it accumulated -
 * because a short read at the end of the file is not an error, it is how the
 * recovery scan discovers where the file ends.
 */
import {
  closeSync, fstatSync, fsyncSync, ftruncateSync, mkdirSync, openSync, readSync, writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import type { BlockFile } from './blockFile';

export class NodeBlockFile implements BlockFile {
  private readonly fd: number;
  /**
   * The file's length, tracked rather than asked for.
   *
   * `append()` calls `size()` on every write and the stats tick calls it four
   * times a second across four files; `fstatSync` is a syscall and the OPFS
   * `getSize()` it replaces was not. The value is exact because every path
   * that can change the length goes through this class.
   */
  private length: number;
  private closed = false;

  constructor(readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
    // 'a+' would force every write to the end, which is wrong: the recovery
    // rule rewrites the index header at offset 0.
    this.fd = openSync(path, 'r+', 0o600);
    this.length = fstatSync(this.fd).size;
  }

  /**
   * Opens the file, creating it if it is not there.
   *
   * Separate from the constructor because 'r+' refuses to create, and a
   * capture's four files are created exactly once - so the create is the
   * unusual path and is written as such rather than hidden in a flag.
   */
  static open(path: string): NodeBlockFile {
    mkdirSync(dirname(path), { recursive: true });
    // 'a' creates without truncating and without disturbing an existing file.
    try {
      closeSync(openSync(path, 'a', 0o600));
    } catch {
      // Already there, or the directory is not writable - the constructor
      // below will fail with the real reason.
    }
    return new NodeBlockFile(path);
  }

  read(offset: number, into: Uint8Array): number {
    this.assertOpen();
    if (offset < 0) throw new RangeError(`read at negative offset ${offset}`);
    let read = 0;
    while (read < into.length) {
      const got = readSync(this.fd, into, read, into.length - read, offset + read);
      // Zero is end of file. Anything else short is a partial read to retry,
      // and treating it as EOF is what would truncate a healthy capture.
      if (got === 0) break;
      read += got;
    }
    return read;
  }

  write(offset: number, from: Uint8Array): void {
    this.assertOpen();
    if (offset < 0) throw new RangeError(`write at negative offset ${offset}`);
    let written = 0;
    while (written < from.length) {
      written += writeSync(this.fd, from, written, from.length - written, offset + written);
    }
    // A write past the end leaves a hole, and both NTFS and POSIX read a hole
    // back as zeros - which the recovery scan depends on, since it reads past
    // the last good record and must see something deterministic.
    // `scripts/capture/block-file.ts` asserts it rather than trusting it.
    this.length = Math.max(this.length, offset + from.length);
  }

  truncate(length: number): void {
    this.assertOpen();
    if (length < 0) throw new RangeError(`truncate to negative length ${length}`);
    ftruncateSync(this.fd, length);
    this.length = length;
  }

  /**
   * Rarely, and on purpose.
   *
   * A `writeSync` that has returned is in the operating system's cache and
   * survives the process dying; `fsync` defends only against power loss.
   * `captureWriter` flushes every eight chunks for exactly that reason, and
   * `scripts/perf/throughput.ts` records what flushing per batch costs.
   */
  flush(): void {
    this.assertOpen();
    fsyncSync(this.fd);
  }

  size(): number {
    return this.length;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    closeSync(this.fd);
  }

  private assertOpen(): void {
    if (this.closed) throw new Error(`NodeBlockFile: ${this.path} is closed`);
  }
}
