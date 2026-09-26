/**
 * Reading a capture back: a chunk's rows, and any frame's bytes.
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
import { ChunkDirectory, applyPrefixes, chunkStoresLinkType, decodeChunk, prefixBlockBytes } from './chunkCodec';
import type { CaptureIndex } from './captureIndex';
import { readExact, type BlockFile } from './blockFile';
import type { CaptureFiles } from './captureWriter';
import type { Packet } from '../../types/packet';
import { decodeRecordBlock } from './recordBlock';

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

/**
 * How many chunks' inflated records are kept. A revisit reads one frame's
 * record, and the next one is usually a neighbour - arrowing down the list -
 * so a few chunks are enough; each is 4,096 records, ~1 MB raw at worst.
 */
const RECORD_CACHE = 8;

/**
 * Chunks one `readRowsAt` may decode.
 *
 * The caller asks for what a viewport needs - forty rows plus overscan - so
 * one chunk answers it and two answer a request straddling a boundary. This is
 * the bound that stops a caller with a bad range decoding the whole capture
 * into a single structured clone.
 */
const MAX_ROW_CHUNKS = 4;

/**
 * Positions one `readRowsFor` may answer.
 *
 * The caller is a viewport plus overscan - forty rows and change - so this is
 * several times what anything asks for, and it is a bound on the ANSWER
 * rather than on the work: a maximally sparse filter can put every one of
 * these in a different chunk, and inflating that many is the honest cost of
 * showing them. What it stops is a caller passing an unbounded list.
 */
const MAX_SCATTERED_ROWS = 256;

export class CaptureReader {
  private readonly directories = new Map<number, ChunkDirectory>();
  private readonly recordBlocks = new Map<number, (Uint8Array | null)[]>();

  constructor(
    private readonly files: CaptureFiles,
    private readonly index: CaptureIndex,
    private readonly inflate: (bytes: Uint8Array) => Uint8Array,
  ) {}

  /** Forgets every cached directory. For a capture that was discarded. */
  clear(): void {
    this.directories.clear();
    this.recordBlocks.clear();
  }

  /**
   * One frame's record (ADR 0049), or null when it has none: a chunk sealed
   * without one, a capture written before records existed, or an id this
   * capture does not hold.
   */
  readRecord(id: number): Uint8Array | null {
    const chunk = this.index.chunkForId(id);
    if (chunk < 0) return null;
    const record = this.index.record(chunk);
    if (record.recLength === 0) return null;
    const directory = this.directory(chunk);
    if (directory === null) return null;
    const within = directory.indexOfId(id);
    if (within < 0) return null;

    let block = this.recordBlocks.get(chunk);
    if (block === undefined) {
      const packed = this.readClamped(this.files.rec, record.recOffset, record.recLength);
      if (packed === null) return null;
      block = decodeRecordBlock(this.inflate(packed));
      this.recordBlocks.set(chunk, block);
      if (this.recordBlocks.size > RECORD_CACHE) {
        const oldest = this.recordBlocks.keys().next();
        if (!oldest.done) this.recordBlocks.delete(oldest.value);
      }
    } else {
      this.recordBlocks.delete(chunk);
      this.recordBlocks.set(chunk, block);
    }
    return block[within] ?? null;
  }

  /**
   * One chunk's rows, exactly as they were written.
   *
   * This is what a restore reads, and it is why the summary is on disk at all:
   * `sessionStore` persisted bytes alone and re-dissected them, and a frame's
   * row is not a function of its own bytes - the TCP sequence base, the TLS
   * record cursor, the DNS pairing are all state the frames before it built.
   * Re-dissecting one from the middle of a capture produces a **different**
   * Info line, not merely a slower one. These rows are the ones the reader saw,
   * cross-references and all.
   *
   * No `rawBytes`: a restored frame reads them back through `packetBytes()`
   * when something actually wants them, which is what that seam is for. Sending
   * them would put ~770 MB of payload through a structured clone to fill a
   * buffer that would drop it again on the first flush.
   *
   * Empty when the chunk cannot be read, which is a torn tail rather than an
   * error - the caller has the rest of the capture and should show it.
   */
  readRows(chunk: number): Packet[] {
    return this.readChunkRows(chunk).packets;
  }

  /**
   * `readRows`, and whether the chunk recorded each row's link type
   * (`chunkStoresLinkType`) - false for a chunk written before it did, whose
   * rows' absent `linkType` means "not recorded" rather than Ethernet.
   */
  private readChunkRows(chunk: number): { packets: Packet[]; linkTypesStored: boolean } {
    if (chunk < 0 || chunk >= this.index.chunkCount) return { packets: [], linkTypesStored: false };
    const record = this.index.record(chunk);
    const summaryRaw = this.readClamped(this.files.sum, record.sumOffset, record.sumLength);
    const prefixRaw = this.readClamped(this.files.pfx, record.pfxOffset, record.pfxLength);
    if (summaryRaw === null || prefixRaw === null) return { packets: [], linkTypesStored: false };
    const summary = this.inflate(summaryRaw);
    const packets = decodeChunk(summary);
    applyPrefixes(packets, this.inflate(prefixRaw));
    return { packets, linkTypesStored: chunkStoresLinkType(summary) };
  }

  /**
   * Where a frame sits in the capture, or -1.
   *
   * A **position**, not an id: ids have holes and positions do not, and the
   * list scrolls positions. This is what tells the app how much of the capture
   * sits below the RAM window - the window's first frame is at this ordinal,
   * so everything before it is a row the list can reach and memory cannot.
   *
   * -1 for a frame in a hole between chunks, and for one still staged behind
   * the patch horizon. Both mean "not addressable yet", and the caller reads
   * that as "show the window alone", which is what it did before any of this.
   */
  ordinalOf(id: number): number {
    const chunk = this.index.chunkForId(id);
    if (chunk < 0) return -1;
    const directory = this.directory(chunk);
    if (directory === null) return -1;
    const within = directory.indexOfId(id);
    return within < 0 ? -1 : this.index.record(chunk).firstOrdinal + within;
  }

  /**
   * The rows covering capture positions `[from, to)`, chunk by chunk.
   *
   * Whole chunks, not the exact range: a chunk is one inflate and one decode
   * whichever part of it was asked for, and the caller caches what comes back,
   * so trimming it to the viewport would throw away the rows it is about to
   * scroll into.
   */
  readRowsAt(from: number, to: number): { firstOrdinal: number; packets: Packet[]; linkTypesStored: boolean }[] {
    const out: { firstOrdinal: number; packets: Packet[]; linkTypesStored: boolean }[] = [];
    let at = Math.max(0, from);
    while (at < to && out.length < MAX_ROW_CHUNKS) {
      const chunk = this.index.chunkForOrdinal(at);
      if (chunk < 0) break;
      const record = this.index.record(chunk);
      out.push({ firstOrdinal: record.firstOrdinal, ...this.readChunkRows(chunk) });
      at = record.firstOrdinal + record.frameCount;
    }
    return out;
  }

  /**
   * The rows at specific positions, keyed by position.
   *
   * `readRowsAt` is the wrong shape for a filtered list. It walks forward from
   * `from` returning whole chunks, which is right when the rows wanted are
   * contiguous and wrong when they are the matches of `dns` in a browsing
   * capture: fifty visible rows can span fifty thousand ordinals, and whole
   * chunks would be fifty megabytes of rows to show fifty of them - and
   * `MAX_ROW_CHUNKS` would cut it off after four, so the list would simply
   * stop.
   *
   * So this takes the positions themselves, groups them by chunk the way
   * `readBytes` groups ids, and inflates each chunk once. The answer carries
   * only the rows asked for.
   *
   * Positions the capture cannot place are absent rather than an error - a
   * torn tail, or a scan whose bitmap outlived the chunk it names.
   */
  readRowsFor(ordinals: readonly number[]): Map<number, Packet> {
    const out = new Map<number, Packet>();
    if (ordinals.length === 0) return out;

    const byChunk = new Map<number, number[]>();
    // Capped at the caller's viewport rather than at a chunk count. A cap on
    // chunks would silently drop rows a sparse filter genuinely needs, and a
    // row that never arrives is a placeholder that never resolves.
    for (const ordinal of new Set(ordinals.slice(0, MAX_SCATTERED_ROWS))) {
      const chunk = this.index.chunkForOrdinal(ordinal);
      if (chunk < 0) continue;
      const list = byChunk.get(chunk);
      if (list === undefined) byChunk.set(chunk, [ordinal]);
      else list.push(ordinal);
    }

    for (const [chunk, wanted] of byChunk) {
      const packets = this.readRows(chunk);
      if (packets.length === 0) continue;      // a torn tail
      const first = this.index.record(chunk).firstOrdinal;
      for (const ordinal of wanted) {
        const packet = packets[ordinal - first];
        if (packet !== undefined) out.set(ordinal, packet);
      }
    }
    return out;
  }

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
