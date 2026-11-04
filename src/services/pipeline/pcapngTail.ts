/**
 * Reads the agent's own pcapng a piece at a time, as it is being written
 * (ADR 0053 phase 4).
 *
 * The importer's reader (`pcapParser.ts`) takes a whole file in one buffer.
 * Catching the live view up needs the opposite: a file that is still growing,
 * read in chunks main hands over as they are asked for, from wherever the last
 * catch-up stopped - so this keeps what it has not consumed, and gives frames
 * back one at a time, so a caller can stop at an exact frame and resume from
 * it later without re-reading the file.
 *
 * Only what the agent writes is understood: SHB, IDB (its `if_name` and
 * `if_tsresol`), EPB. Every other block is skipped by its length. A block
 * that is not all here yet waits for the next chunk.
 */

export interface TailFrame {
  /** The EPB's interface: an IDB index in this file, not the agent's adapter id. */
  idb: number;
  /** Capture time, epoch microseconds, and the nanoseconds past it - as the live stream carries it. */
  tsUs: number;
  tsNsRem: number;
  origLen: number;
  /** The captured bytes. Empty when the frame was skipped rather than read. */
  bytes: Uint8Array;
  /** The frame's captured length, also when its bytes were not copied. */
  capLen: number;
}

/** Bytes of carry past which consumed space is reclaimed rather than kept. */
const COMPACT_AT = 1 << 20;
/**
 * Reads of a block that does not close before it is called corrupt - at the
 * catch-up's 150 ms between reads of a file with nothing new, about ten
 * seconds, against a writer that flushes once a second.
 */
export const STALL_LIMIT = 64;

export class PcapngTail {
  private buf: Uint8Array = new Uint8Array(0);
  private at = 0;
  /** File offset of `buf[0]`. */
  private base: number;
  private little = true;
  /** Nanoseconds per tick, per IDB of the current section. */
  private nsPerTick: number[] = [];
  /** `if_name` per IDB, null where none was written. */
  readonly idbNames: (string | null)[] = [];
  /**
   * Times in a row the block at the read position did not close: bytes not
   * written yet, read again later. Past `STALL_LIMIT` the file is corrupt.
   */
  stalled = 0;
  /** File offset of the block `next` last gave back. */
  blockAt = 0;

  constructor(startOffset = 0) {
    this.base = startOffset;
  }

  /** The file offset of the next block to be read: everything before it is consumed. */
  get position(): number {
    return this.base + this.at;
  }

  /**
   * Go on reading from `offset`, a block boundary somewhere ahead, with what
   * the section's header and IDBs said kept - which is why a seek reads them
   * first (#17). Whatever is held is let go; nothing checks the offset, so a
   * caller checks what it finds there.
   */
  jump(offset: number): void {
    this.base = offset;
    this.buf = new Uint8Array(0);
    this.at = 0;
    this.stalled = 0;
  }

  /** The file offset the next chunk must be read from. */
  get readOffset(): number {
    return this.base + this.buf.length;
  }

  /** Bytes held and not yet consumed. */
  get pending(): number {
    return this.buf.length - this.at;
  }

  /** The type and length of the block at the read position, once eight bytes of it are here. */
  blockHead(): { type: number; length: number } | null {
    if (this.buf.length - this.at < 8) return null;
    const view = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, 8);
    return { type: view.getUint32(0, this.little), length: view.getUint32(4, this.little) };
  }

  /** A chunk read from `readOffset` on. */
  push(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    const keep = this.buf.length - this.at;
    if (keep === 0) {
      this.base += this.buf.length;
      this.buf = chunk.slice();
      this.at = 0;
      return;
    }
    const next = new Uint8Array(keep + chunk.length);
    next.set(this.buf.subarray(this.at), 0);
    next.set(chunk, keep);
    this.base += this.at;
    this.buf = next;
    this.at = 0;
  }

  /**
   * The next packet in the file, or null when the next block is not all here.
   * `copy` false skips the bytes - the frame is counted, not read.
   */
  next(copy = true): TailFrame | null {
    for (;;) {
      if (this.buf.length - this.at < 12) {
        this.buf = this.buf.subarray(0, this.at);
        return null;
      }
      const view = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, this.buf.length - this.at);
      const type = view.getUint32(0, this.little);
      // A section header carries its own byte order, after the length.
      if (type === 0x0a0d0d0a) {
        this.little = view.getUint32(8, true) === 0x1a2b3c4d;
      }
      const length = view.getUint32(4, this.little);
      // A block is trusted only whole, from one read, and closed by its
      // trailing copy of the length. A file being written can be read past
      // what its writer has put in it - Windows extends a file before it
      // fills it, and the gap reads as zeros - but never with zeros BEFORE
      // bytes that were written, so a block whose last four bytes are right
      // was all written when it was read. A block that is not all here, or
      // does not close, is dropped and read again from where it starts:
      // keeping its first part would keep whatever zeros were in it.
      const malformed = length < 12 || length % 4 !== 0;
      if (!malformed && length > view.byteLength) {
        this.buf = this.buf.subarray(0, this.at);
        return null;
      }
      if (malformed || view.getUint32(length - 4, this.little) !== length) {
        if (++this.stalled > STALL_LIMIT) throw new Error(`pcapng block of length ${length} at offset ${this.base + this.at}`);
        this.buf = this.buf.subarray(0, this.at);
        return null;
      }
      this.stalled = 0;
      this.blockAt = this.base + this.at;
      this.at += length;
      if (type === 0x0a0d0d0a) {
        this.nsPerTick = [];
        this.idbNames.length = 0;
      } else if (type === 0x00000001) {
        this.readIdb(view, length);
      } else if (type === 0x00000006) {
        const idb = view.getUint32(8, this.little);
        const high = view.getUint32(12, this.little);
        const low = view.getUint32(16, this.little);
        const capLen = view.getUint32(20, this.little);
        const origLen = view.getUint32(24, this.little);
        if (28 + capLen > length) throw new Error(`pcapng packet longer than its block at offset ${this.base + this.at - length}`);
        const ns = ((BigInt(high) << 32n) | BigInt(low)) * BigInt(this.nsPerTick[idb] ?? 1000);
        const start = this.buf.byteOffset + this.at - length + 28;
        const frame: TailFrame = {
          idb,
          tsUs: Number(ns / 1000n),
          tsNsRem: Number(ns % 1000n),
          origLen,
          capLen,
          bytes: copy ? new Uint8Array(this.buf.buffer.slice(start, start + capLen)) : EMPTY,
        };
        this.compact();
        return frame;
      }
      this.compact();
    }
  }

  private readIdb(view: DataView, length: number): void {
    let nsPerTick = 1000; // if_tsresol's default: microseconds
    let name: string | null = null;
    for (let at = 16; at + 4 <= length - 4;) {
      const code = view.getUint16(at, this.little);
      const len = view.getUint16(at + 2, this.little);
      if (code === 0 || at + 4 + len > length - 4) break;
      if (code === 9 && len >= 1) {
        const raw = view.getUint8(at + 4);
        const exponent = raw & 0x7f;
        // Only whole nanoseconds per tick are kept exact; a power-of-two
        // resolution, which the agent never writes, rounds.
        nsPerTick = (raw & 0x80) !== 0 ? Math.max(1, Math.round(1e9 / 2 ** exponent)) : Math.max(1, Math.round(10 ** (9 - exponent)));
      }
      if (code === 2) {
        name = UTF8.decode(new Uint8Array(view.buffer, view.byteOffset + at + 4, len)).replace(/\0+$/, '');
      }
      at += 4 + len + ((4 - (len % 4)) % 4);
    }
    this.nsPerTick.push(nsPerTick);
    this.idbNames.push(name);
  }

  private compact(): void {
    if (this.at < COMPACT_AT) return;
    this.base += this.at;
    this.buf = this.buf.slice(this.at);
    this.at = 0;
  }
}

const EMPTY = new Uint8Array(0);
const UTF8 = new TextDecoder();
