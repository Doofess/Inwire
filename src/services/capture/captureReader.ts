/**
 * Reading a capture back: frame bytes today, rows in the step after this.
 *
 * ## What this replaces, and why it had to be replaced
 *
 * `packetBytes.ts` has always been able to drop a frame's bytes and read them
 * back, and its header says why that was safe: *"They are already on disk."*
 * They were - in IndexedDB, written by `toStoredFrame`, bounded by a 512 MB
 * budget that **evicts the oldest frames**. That budget is what makes the old
 * arrangement wrong now rather than merely redundant.
 *
 * `evictOldBytes` only drops the bytes of a frame the store can supply again,
 * so once the IndexedDB budget has evicted the beginning of a capture, every
 * frame it evicted keeps its bytes **in RAM, for ever** - the two ends of the
 * buffer squeeze from opposite directions and the frames in between are stuck.
 * At a 512 MB summary budget that is up to another 760 MB of raw frames sitting
 * on top of it. The capture store evicts nothing, so its range only ever grows
 * and eviction can always proceed.
 *
 * ## One read per chunk, not one per frame
 *
 * Callers ask in bulk - Follow Stream wants a conversation, export wants a
 * capture - so ids are grouped by chunk and each chunk answered with **one**
 * read of the span between the first and last byte wanted. A conversation's
 * frames are scattered through a chunk, so that span is usually most of the
 * chunk anyway, and one 4 MB read beats four hundred small ones. `MAX_SPAN` is
 * what stops that reasoning running away on a chunk where two frames are wanted
 * from opposite ends.
 *
 * ## The directory cache
 *
 * Finding a frame inside a chunk needs the chunk's byte directory, which is
 * inflated with the prefix block. That inflate is ~300 kB of work, so the last
 * `DIRECTORY_CACHE` chunks are kept - enough that scrolling through a stream,
 * or exporting chunk by chunk, inflates each one once. It is small and bounded
 * and lives in the storage Worker, outside the main thread's byte budget
 * entirely.
 */
import { ChunkDirectory, prefixBlockBytes } from './chunkCodec';
import type { CaptureIndex } from './captureIndex';
import { readExact, type BlockFile } from './blockFile';
import type { CaptureFiles } from './captureWriter';

/**
 * The most bytes one read may cover to satisfy the frames wanted from a chunk.
 *
 * A chunk is ~4.5 MB of frames at a 1,100-byte mean, so in practice this never
 * binds; it binds on a chunk of segmentation-offload frames, where 4,096 frames
 * can be tens of megabytes and reading the span between two of them would be a
 * far worse trade than reading the two.
 */
const MAX_SPAN = 8 * 1024 * 1024;

/** Chunks whose directory is kept inflated. ~48 kB each. */
const DIRECTORY_CACHE = 32;

export class CaptureReader {
  private readonly directories = new Map<number, ChunkDirectory>();

  constructor(
    private readonly files: CaptureFiles,
    private readonly index: CaptureIndex,
    private readonly inflate: (bytes: Uint8Array) => Uint8Array,
  ) {}

  /** Forgets every cached directory. For a capture that was discarded. */
  clear(): void { this.directories.clear(); }

  /**
   * The bytes of specific frames, keyed by id.
   *
   * Ids the capture does not hold are simply absent from the result, which is
   * the same contract `sessionStore.readFrameBytes` had: a frame whose bytes
   * are gone is a thing to render, not an error to handle.
   */
  readBytes(ids: readonly number[]): Map<number, Uint8Array> {
    const out = new Map<number, Uint8Array>();
    if (ids.length === 0) return out;

    // Grouped by chunk first, so each chunk's directory is inflated once and
    // each chunk's bytes are read once however the caller ordered its ids.
    const byChunk = new Map<number, number[]>();
    for (const id of new Set(ids)) {
      const chunk = this.index.chunkForId(id);
      if (chunk < 0) continue;
      const list = byChunk.get(chunk);
      if (list === undefined) byChunk.set(chunk, [id]);
      else list.push(id);
    }

    for (const [chunk, wanted] of byChunk) this.readFromChunk(chunk, wanted, out);
    return out;
  }

  private readFromChunk(chunk: number, wanted: number[], out: Map<number, Uint8Array>): void {
    const directory = this.directory(chunk);
    if (directory === null) return;
    const record = this.index.record(chunk);

    // Positions first: an id in a hole between two frames has no position, and
    // deciding the span before knowing that would read bytes for a frame that
    // is not there.
    const found: { id: number; at: number; length: number }[] = [];
    for (const id of wanted) {
      const i = directory.indexOfId(id);
      if (i < 0) continue;
      const length = directory.capLength(i);
      if (length === 0) continue;              // a frame the agent sent without bytes
      found.push({ id, at: directory.offset(i), length });
    }
    if (found.length === 0) return;

    found.sort((a, b) => a.at - b.at);
    const from = found[0].at;
    const to = found[found.length - 1].at + found[found.length - 1].length;

    if (to - from <= MAX_SPAN) {
      const span = this.readClamped(this.files.byt, record.bytOffset + from, to - from);
      if (span === null) return;
      for (const f of found) {
        const start = f.at - from;
        if (start + f.length > span.length) continue;   // a torn tail; say nothing rather than half a frame
        // `slice`, not `subarray`. These cross a worker boundary, and
        // structured clone copies a view's WHOLE underlying buffer - four
        // hundred views into one 4 MB span would post 1.6 GB.
        out.set(f.id, span.slice(start, start + f.length));
      }
      return;
    }

    for (const f of found) {
      const bytes = this.readClamped(this.files.byt, record.bytOffset + f.at, f.length);
      if (bytes !== null) out.set(f.id, bytes);
    }
  }

  /**
   * A read that returns null instead of throwing when the file is short.
   *
   * A short read here means the index describes bytes the data file does not
   * have, which the recovery pass should have removed - but a running capture
   * is being appended to while this reads, and refusing to hand back the
   * frames that ARE there because one is not would turn a torn tail into a
   * failed export.
   */
  private readClamped(file: BlockFile, offset: number, length: number): Uint8Array | null {
    if (offset + length > file.size()) return null;
    return readExact(file, offset, length);
  }

  /** The chunk's byte directory, inflated and cached, or null if unreadable. */
  private directory(chunk: number): ChunkDirectory | null {
    const cached = this.directories.get(chunk);
    if (cached !== undefined) {
      // Re-inserted so the eviction below is least-recently-used rather than
      // insertion order, which for a scan is the exact opposite of what helps.
      this.directories.delete(chunk);
      this.directories.set(chunk, cached);
      return cached;
    }

    const record = this.index.record(chunk);
    const packed = this.readClamped(this.files.pfx, record.pfxOffset, record.pfxLength);
    if (packed === null) return null;
    const block = this.inflate(packed);
    if (block.length !== prefixBlockBytes(record.frameCount)) return null;

    const directory = new ChunkDirectory(block, record.frameCount);
    this.directories.set(chunk, directory);
    if (this.directories.size > DIRECTORY_CACHE) {
      const oldest = this.directories.keys().next();
      if (!oldest.done) this.directories.delete(oldest.value);
    }
    return directory;
  }
}
