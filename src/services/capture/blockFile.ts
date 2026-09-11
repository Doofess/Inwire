/**
 * A random-access byte file, behind an interface thin enough to have two
 * implementations.
 *
 * ## Why this exists at all
 *
 * The capture format's hardest parts are its **recovery rule** and its offset
 * arithmetic - what a reader does when a crash left the index describing bytes
 * the data file does not have. Those are exactly the parts that cannot be
 * tested through the real backend, because **OPFS does not exist in Node**, and
 * a browser cannot be crashed on demand from a test.
 *
 * So nothing above this line knows what it is writing to. `scripts/` supplies a
 * `node:fs` implementation and drives the format against a real multi-gigabyte
 * file on the local disk, killing and truncating it at chosen offsets; the app
 * supplies an OPFS `FileSystemSyncAccessHandle`. Only the thin adapter needs a
 * browser to exercise, and the adapter is the part with no logic in it.
 *
 * The shape is deliberately the sync-access-handle's own - `read(into, {at})`
 * flattened to `read(at, into)` - so the OPFS implementation is a forwarding
 * call and cannot drift from the thing it wraps.
 *
 * ## Sync, and why that is not a problem here
 *
 * Every method is synchronous. That is what `createSyncAccessHandle()` gives,
 * and it is available **only inside a Worker** - which is where the capture
 * writer lives, for the separate and measured reason that encoding a summary
 * costs 8.91 us against the dissection Worker's whole 28.6 us budget
 * (`scripts/perf/summary-codec.ts`). A storage Worker doing synchronous I/O
 * blocks nothing anyone is looking at.
 */

export interface BlockFile {
  /**
   * Reads into `into` starting at `offset`, returning how many bytes were read.
   *
   * A short read at the end of the file is not an error - it is how a reader
   * discovers the file ended, which the recovery rule depends on.
   */
  read(offset: number, into: Uint8Array): number;
  /** Writes `from` at `offset`, extending the file if it ends before it. */
  write(offset: number, from: Uint8Array): void;
  /** Sets the file's length, discarding anything past it. */
  truncate(length: number): void;
  /**
   * Pushes writes to durable storage.
   *
   * Rarely, and on purpose. A `write()` that has returned already survives a
   * tab crash or a refresh - it is in the browser's file layer, not in this
   * page. `flush()` defends only against power loss, so calling it per batch
   * would buy 30 durability barriers a second against the one failure nobody
   * in this design is worried about.
   */
  flush(): void;
  /** The file's current length in bytes. */
  size(): number;
  close(): void;
}

/**
 * A `BlockFile` held in memory, for tests and for a browser with no OPFS.
 *
 * Grows geometrically rather than to the exact size asked for: the writer
 * appends in 4 MB blocks and a precise `set` per write would copy the whole
 * file each time.
 */
export class MemoryBlockFile implements BlockFile {
  private buf: Uint8Array;
  private length = 0;
  /** Counted so a test can assert the writer is not flushing per batch. */
  flushes = 0;

  constructor(initialCapacity = 1 << 16) {
    this.buf = new Uint8Array(initialCapacity);
  }

  private reserve(end: number): void {
    if (end <= this.buf.length) return;
    let size = Math.max(this.buf.length * 2, 1 << 16);
    while (size < end) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.length));
    this.buf = next;
  }

  read(offset: number, into: Uint8Array): number {
    if (offset < 0) throw new RangeError(`read at negative offset ${offset}`);
    const available = Math.max(0, Math.min(into.length, this.length - offset));
    if (available > 0) into.set(this.buf.subarray(offset, offset + available));
    return available;
  }

  write(offset: number, from: Uint8Array): void {
    if (offset < 0) throw new RangeError(`write at negative offset ${offset}`);
    this.reserve(offset + from.length);
    // A write past the end leaves a hole, and a hole must read as zeros rather
    // than as whatever the growth left behind - the recovery scan reads past
    // the last good record and has to see something deterministic.
    if (offset > this.length) this.buf.fill(0, this.length, offset);
    this.buf.set(from, offset);
    this.length = Math.max(this.length, offset + from.length);
  }

  truncate(length: number): void {
    if (length < 0) throw new RangeError(`truncate to negative length ${length}`);
    if (length > this.length) {
      this.reserve(length);
      this.buf.fill(0, this.length, length);
    }
    this.length = length;
  }

  flush(): void { this.flushes += 1; }
  size(): number { return this.length; }
  close(): void { /* nothing to release */ }

  /** The bytes as written, for a test that wants to inspect or corrupt them. */
  snapshot(): Uint8Array { return this.buf.slice(0, this.length); }
}

/**
 * Wraps an OPFS `FileSystemSyncAccessHandle`.
 *
 * Typed structurally rather than against `FileSystemSyncAccessHandle`, because
 * that type is not in every TypeScript lib this project builds against and a
 * missing DOM type should not decide whether the storage layer compiles.
 */
export interface SyncAccessHandleLike {
  read(into: BufferSource, options?: { at?: number }): number;
  write(from: BufferSource, options?: { at?: number }): number;
  truncate(size: number): void;
  flush(): void;
  getSize(): number;
  close(): void;
}

export class SyncAccessBlockFile implements BlockFile {
  constructor(private readonly handle: SyncAccessHandleLike) {}

  read(offset: number, into: Uint8Array): number { return this.handle.read(into, { at: offset }); }
  write(offset: number, from: Uint8Array): void { this.handle.write(from, { at: offset }); }
  truncate(length: number): void { this.handle.truncate(length); }
  flush(): void { this.handle.flush(); }
  size(): number { return this.handle.getSize(); }
  close(): void { this.handle.close(); }
}

/**
 * Reads exactly `length` bytes at `offset`, or throws.
 *
 * The common case for a reader that has an index record and therefore knows how
 * long the thing it wants is. A short read here means the file is shorter than
 * the index claims - a torn tail - and that is a fact the caller must handle
 * rather than a buffer it can half-use.
 */
export function readExact(file: BlockFile, offset: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  const got = file.read(offset, out);
  if (got !== length) {
    throw new Error(`readExact: wanted ${length} bytes at ${offset}, got ${got} (file is ${file.size()})`);
  }
  return out;
}

/** Appends to the end of the file and returns where it landed. */
export function append(file: BlockFile, bytes: Uint8Array): number {
  const at = file.size();
  file.write(at, bytes);
  return at;
}
