/**
 * One resident window of a file, loaded on demand.
 *
 * A capture file past about 2 GB cannot be one `ArrayBuffer` (#20), so the frame
 * walk reads through this instead: a record is read from the window when it is
 * resident, and `load` fetches the window that holds the next one when it is
 * not. Every offset a caller passes is an **absolute file offset**; the window
 * subtracts its own base, over numbers (file offsets are far below 2^53) and
 * over a `DataView` that spans only its own buffer, so nothing wraps at 2^32.
 *
 * Pure: no `node:*`, no Electron. A `File` is a `BlobLike`, and so is a stub.
 */

/** What a `File` offers that the window needs; a script can supply a stub. */
export interface BlobLike {
  readonly size: number;
  slice(start?: number, end?: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

/**
 * How much of a file is read at a time. A record longer than this is loaded
 * whole: the window grows to fit it for that one load.
 */
export const READ_WINDOW_BYTES = 64 * 1024 * 1024;

export class ByteWindow {
  /** The file offset of `buffer[0]`. */
  private base = 0;
  private buffer: ArrayBuffer;
  private view: DataView;

  private constructor(
    readonly size: number,
    buffer: ArrayBuffer,
    private readonly blob: BlobLike | null,
    private readonly windowBytes: number,
    private readonly onLoad: ((end: number, size: number) => void) | undefined,
  ) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
  }

  /** A file already in memory: everything is resident and `load` does nothing. */
  static whole(buffer: ArrayBuffer): ByteWindow {
    return new ByteWindow(buffer.byteLength, buffer, null, 0, undefined);
  }

  /**
   * A file read in pieces of `windowBytes`. Nothing is resident until the first
   * `load`. `onLoad` hears the file offset each load reached and the file's size.
   */
  static over(
    blob: BlobLike,
    windowBytes: number = READ_WINDOW_BYTES,
    onLoad?: (end: number, size: number) => void,
  ): ByteWindow {
    return new ByteWindow(blob.size, new ArrayBuffer(0), blob, windowBytes, onLoad);
  }

  /** Whether `[at, at + length)` is resident. */
  has(at: number, length: number): boolean {
    return at >= this.base && at + length <= this.base + this.buffer.byteLength;
  }

  /**
   * Replaces the window with the file from `at`: `max(length, windowBytes)`
   * bytes, clamped to the file's end. The caller has checked the record lies
   * inside the file; a span the file cannot hold stays unresident.
   */
  async load(at: number, length: number): Promise<void> {
    if (this.blob === null) return;
    const end = Math.min(this.size, at + Math.max(length, this.windowBytes));
    this.buffer = await this.blob.slice(at, end).arrayBuffer();
    this.view = new DataView(this.buffer);
    this.base = at;
    this.onLoad?.(end, this.size);
  }

  u8(at: number): number {
    return this.view.getUint8(at - this.base);
  }

  u16(at: number, littleEndian: boolean): number {
    return this.view.getUint16(at - this.base, littleEndian);
  }

  u32(at: number, littleEndian: boolean): number {
    return this.view.getUint32(at - this.base, littleEndian);
  }

  /** The span as its own buffer: it does not pin the window. */
  copy(at: number, length: number): ArrayBuffer {
    return this.buffer.slice(at - this.base, at - this.base + length);
  }

  /** The span as a view of the window, for decoding in place; do not keep it. */
  bytes(at: number, length: number): Uint8Array {
    return new Uint8Array(this.buffer, at - this.base, length);
  }
}
