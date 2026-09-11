/**
 * The chunk directory: where every frame is, and what a reader does when a
 * crash left the files disagreeing.
 *
 * ## One record per CHUNK, not per frame
 *
 * A per-frame index would be the obvious thing and it is the wrong size. At
 * 32 B a frame and 47M frames it is **1.23 GB** - 2.4% of the capture, a third
 * file to keep consistent, and it would itself have to be paged, so the "O(1)
 * seek" it was built for becomes two reads instead of one.
 *
 * One record per 4,096-frame chunk is `INDEX_RECORD_BYTES` = 64 bytes for 4,096
 * frames: **0.016 B/frame**, or 736 kB for a 47M-frame capture, read whole at
 * open and held in typed arrays for the life of the capture. Finding a frame is
 * a binary search over ~11,500 records - a handful of comparisons - then one
 * read of the chunk that holds it.
 *
 * ## Offsets are f64, never u64
 *
 * A f64 is exact for every integer to 2^53, which is 9 petabytes. `BigInt`
 * would be exact too and is far slower to read, and these are read once per
 * lookup on a path that a filter walks tens of millions of times.
 *
 * ## Ordinals and ids are different numbers
 *
 * A frame's **ordinal** is its position in the capture, 0-based and gapless. Its
 * **id** is `packetGenerator`'s number, and ids have holes: a frame that fails
 * to dissect burns one. So `chunkForId` binary-searches and never computes
 * `firstId + n`. `scripts/session/frame-index.ts` already documents that trap
 * for the in-RAM buffer; it is the same trap here with more places to fall into.
 *
 * ## The recovery rule
 *
 * Writes go: chunk bytes to the data files, `flush()`, **then** the index
 * record. So a crash leaves at most one thing wrong, and always in the same
 * direction - data with no index record describing it, never an index record
 * pointing past the data.
 *
 * `planRecovery` is that rule as a pure function, so it can be tested against a
 * real truncated file rather than reasoned about. It walks the records and
 * stops at the first one whose extents run past any of the three files, and the
 * caller truncates all four back to that boundary. What is lost is the last
 * partial chunk - under 4,096 frames - which is the append-only contract and is
 * worth stating out loud rather than discovering.
 */
import type { BlockFile } from './blockFile';

export const INDEX_MAGIC = 0x31584449;          // 'IDX1'
export const INDEX_VERSION = 1;
/** A fixed header so a reader can refuse a file it does not understand. */
export const INDEX_HEADER_BYTES = 16;
/** One record per chunk. See the module header for why 64 B is cheap. */
export const INDEX_RECORD_BYTES = 64;

const OFF_FIRST_ID = 0;        // u32
const OFF_FRAME_COUNT = 4;     // u32
const OFF_FIRST_ORDINAL = 8;   // f64 - a capture can exceed 2^32 frames
const OFF_PFX_OFFSET = 16;     // f64
const OFF_SUM_OFFSET = 24;     // f64
const OFF_BYT_OFFSET = 32;     // f64
const OFF_PFX_LENGTH = 40;     // u32
const OFF_SUM_LENGTH = 44;     // u32
const OFF_BYT_LENGTH = 48;     // u32
const OFF_LAST_ID = 52;        // u32
const OFF_FIRST_TS = 56;       // f64 - only the low half fits; see below
// 56..63 holds firstTsUs as a f64. lastTsUs is NOT stored: the next record's
// firstTsUs bounds this chunk for a time seek, and the final chunk's end is the
// capture's end, which meta already carries. Eight bytes a chunk is nothing,
// but a field that can disagree with its neighbour is worth not having.

export interface ChunkRecord {
  firstId: number;
  lastId: number;
  frameCount: number;
  /** Position of this chunk's first frame in the capture, 0-based. */
  firstOrdinal: number;
  pfxOffset: number;
  pfxLength: number;
  sumOffset: number;
  sumLength: number;
  bytOffset: number;
  bytLength: number;
  firstTsUs: number;
}

export function encodeChunkRecord(record: ChunkRecord, into: Uint8Array, at: number): void {
  const view = new DataView(into.buffer, into.byteOffset + at, INDEX_RECORD_BYTES);
  view.setUint32(OFF_FIRST_ID, record.firstId >>> 0, true);
  view.setUint32(OFF_FRAME_COUNT, record.frameCount >>> 0, true);
  view.setFloat64(OFF_FIRST_ORDINAL, record.firstOrdinal, true);
  view.setFloat64(OFF_PFX_OFFSET, record.pfxOffset, true);
  view.setFloat64(OFF_SUM_OFFSET, record.sumOffset, true);
  view.setFloat64(OFF_BYT_OFFSET, record.bytOffset, true);
  view.setUint32(OFF_PFX_LENGTH, record.pfxLength >>> 0, true);
  view.setUint32(OFF_SUM_LENGTH, record.sumLength >>> 0, true);
  view.setUint32(OFF_BYT_LENGTH, record.bytLength >>> 0, true);
  view.setUint32(OFF_LAST_ID, record.lastId >>> 0, true);
  view.setFloat64(OFF_FIRST_TS, record.firstTsUs, true);
}

export function decodeChunkRecord(from: Uint8Array, at: number): ChunkRecord {
  const view = new DataView(from.buffer, from.byteOffset + at, INDEX_RECORD_BYTES);
  return {
    firstId: view.getUint32(OFF_FIRST_ID, true),
    frameCount: view.getUint32(OFF_FRAME_COUNT, true),
    firstOrdinal: view.getFloat64(OFF_FIRST_ORDINAL, true),
    pfxOffset: view.getFloat64(OFF_PFX_OFFSET, true),
    sumOffset: view.getFloat64(OFF_SUM_OFFSET, true),
    bytOffset: view.getFloat64(OFF_BYT_OFFSET, true),
    pfxLength: view.getUint32(OFF_PFX_LENGTH, true),
    sumLength: view.getUint32(OFF_SUM_LENGTH, true),
    bytLength: view.getUint32(OFF_BYT_LENGTH, true),
    lastId: view.getUint32(OFF_LAST_ID, true),
    firstTsUs: view.getFloat64(OFF_FIRST_TS, true),
  };
}

export function writeIndexHeader(into: Uint8Array): void {
  const view = new DataView(into.buffer, into.byteOffset, INDEX_HEADER_BYTES);
  view.setUint32(0, INDEX_MAGIC, true);
  view.setUint16(4, INDEX_VERSION, true);
  view.setUint16(6, INDEX_RECORD_BYTES, true);
  view.setFloat64(8, 0, true);                   // reserved: v2's segment ordinal
}

/** How many whole records a file of this size holds after its header. */
export function recordsIn(fileSize: number): number {
  if (fileSize < INDEX_HEADER_BYTES) return 0;
  return Math.floor((fileSize - INDEX_HEADER_BYTES) / INDEX_RECORD_BYTES);
}

/**
 * The chunk directory in memory: parallel typed arrays, not an array of objects.
 *
 * 11,500 objects would be perfectly affordable; the arrays are here because the
 * searches below run on the path a whole-capture filter walks, and a binary
 * search over a `Float64Array` touches one cache line per step where an array
 * of objects touches two and chases a pointer.
 */
export class CaptureIndex {
  private firstId: Uint32Array;
  private lastId: Uint32Array;
  private counts: Uint32Array;
  private firstOrdinal: Float64Array;
  private pfxOffset: Float64Array;
  private sumOffset: Float64Array;
  private bytOffset: Float64Array;
  private pfxLength: Uint32Array;
  private sumLength: Uint32Array;
  private bytLength: Uint32Array;
  private firstTs: Float64Array;

  private n = 0;
  private frames = 0;

  /**
   * The index **grows**, because a running capture is the main thing that
   * reads it.
   *
   * A reader that could only be built from a finished file would mean either
   * rebuilding eleven typed arrays every time a chunk is sealed, or a second
   * index type for the live case that has to answer the same three questions
   * the same way. Appending doubles the arrays geometrically, so a whole
   * capture's growth costs a handful of copies in total.
   */
  constructor(records: readonly ChunkRecord[] = []) {
    const capacity = Math.max(64, records.length);
    this.firstId = new Uint32Array(capacity);
    this.lastId = new Uint32Array(capacity);
    this.counts = new Uint32Array(capacity);
    this.firstOrdinal = new Float64Array(capacity);
    this.pfxOffset = new Float64Array(capacity);
    this.sumOffset = new Float64Array(capacity);
    this.bytOffset = new Float64Array(capacity);
    this.pfxLength = new Uint32Array(capacity);
    this.sumLength = new Uint32Array(capacity);
    this.bytLength = new Uint32Array(capacity);
    this.firstTs = new Float64Array(capacity);
    for (const r of records) this.append(r);
  }

  get chunkCount(): number { return this.n; }
  get frameCount(): number { return this.frames; }

  /** Adds a sealed chunk. Records arrive in order and are never revised. */
  append(r: ChunkRecord): void {
    if (this.n === this.firstId.length) this.grow();
    const i = this.n;
    this.firstId[i] = r.firstId;
    this.lastId[i] = r.lastId;
    this.counts[i] = r.frameCount;
    this.firstOrdinal[i] = r.firstOrdinal;
    this.pfxOffset[i] = r.pfxOffset;
    this.sumOffset[i] = r.sumOffset;
    this.bytOffset[i] = r.bytOffset;
    this.pfxLength[i] = r.pfxLength;
    this.sumLength[i] = r.sumLength;
    this.bytLength[i] = r.bytLength;
    this.firstTs[i] = r.firstTsUs;
    this.n += 1;
    this.frames += r.frameCount;
  }

  private grow(): void {
    const size = this.firstId.length * 2;
    const u32 = (a: Uint32Array): Uint32Array => { const n = new Uint32Array(size); n.set(a); return n; };
    const f64 = (a: Float64Array): Float64Array => { const n = new Float64Array(size); n.set(a); return n; };
    this.firstId = u32(this.firstId);
    this.lastId = u32(this.lastId);
    this.counts = u32(this.counts);
    this.pfxLength = u32(this.pfxLength);
    this.sumLength = u32(this.sumLength);
    this.bytLength = u32(this.bytLength);
    this.firstOrdinal = f64(this.firstOrdinal);
    this.pfxOffset = f64(this.pfxOffset);
    this.sumOffset = f64(this.sumOffset);
    this.bytOffset = f64(this.bytOffset);
    this.firstTs = f64(this.firstTs);
  }

  /** Parses a whole `index.iwidx`, refusing a header it does not know. */
  static parse(bytes: Uint8Array): CaptureIndex {
    if (bytes.length < INDEX_HEADER_BYTES) return new CaptureIndex([]);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = view.getUint32(0, true);
    if (magic !== INDEX_MAGIC) throw new Error(`captureIndex: bad magic 0x${magic.toString(16)}`);
    const version = view.getUint16(4, true);
    if (version !== INDEX_VERSION) {
      throw new Error(`captureIndex: version ${version} is not one this build reads`);
    }
    const stride = view.getUint16(6, true);
    if (stride !== INDEX_RECORD_BYTES) {
      throw new Error(`captureIndex: record stride ${stride}, expected ${INDEX_RECORD_BYTES}`);
    }
    const count = recordsIn(bytes.length);
    const records: ChunkRecord[] = new Array(count);
    for (let i = 0; i < count; i++) {
      records[i] = decodeChunkRecord(bytes, INDEX_HEADER_BYTES + i * INDEX_RECORD_BYTES);
    }
    return new CaptureIndex(records);
  }

  record(chunk: number): ChunkRecord {
    if (chunk < 0 || chunk >= this.chunkCount) throw new RangeError(`chunk ${chunk} out of range`);
    return {
      firstId: this.firstId[chunk],
      lastId: this.lastId[chunk],
      frameCount: this.counts[chunk],
      firstOrdinal: this.firstOrdinal[chunk],
      pfxOffset: this.pfxOffset[chunk],
      pfxLength: this.pfxLength[chunk],
      sumOffset: this.sumOffset[chunk],
      sumLength: this.sumLength[chunk],
      bytOffset: this.bytOffset[chunk],
      bytLength: this.bytLength[chunk],
      firstTsUs: this.firstTs[chunk],
    };
  }

  /**
   * Which chunk holds the frame at this position, or -1.
   *
   * Chunks are uniform except the last, so the answer is almost always
   * `ordinal / CHUNK_FRAMES` - but "almost always" is not a contract, and a
   * capture that resumed after a restore has a short chunk in the middle of it.
   * The guess is checked and falls back to a search.
   */
  chunkForOrdinal(ordinal: number): number {
    if (this.chunkCount === 0 || ordinal < 0 || ordinal >= this.frameCount) return -1;
    const guess = Math.min(this.chunkCount - 1, Math.floor(ordinal / this.counts[0]));
    if (this.holdsOrdinal(guess, ordinal)) return guess;
    let lo = 0, hi = this.chunkCount - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (ordinal < this.firstOrdinal[mid]) hi = mid - 1;
      else if (ordinal >= this.firstOrdinal[mid] + this.counts[mid]) lo = mid + 1;
      else return mid;
    }
    return -1;
  }

  private holdsOrdinal(chunk: number, ordinal: number): boolean {
    return ordinal >= this.firstOrdinal[chunk]
      && ordinal < this.firstOrdinal[chunk] + this.counts[chunk];
  }

  /**
   * Which chunk holds this frame id, or -1.
   *
   * Never `firstId + n`: ids have holes, so the only sound answer is a search
   * on the recorded first and last id of each chunk. An id that falls in a hole
   * BETWEEN two chunks returns -1 rather than the neighbour, because "the frame
   * you asked for does not exist" and "here is a different frame" are not the
   * same answer.
   */
  chunkForId(id: number): number {
    let lo = 0, hi = this.chunkCount - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (id < this.firstId[mid]) hi = mid - 1;
      else if (id > this.lastId[mid]) lo = mid + 1;
      else return mid;
    }
    return -1;
  }

  /**
   * The first chunk that could contain a frame at or after `tsUs`.
   *
   * Free, because the record already carries `firstTsUs` for the boundary the
   * recovery rule wants - and it is what makes "go to this time" and
   * "statistics over this window" cheap on a capture too large to scan.
   */
  chunkForTime(tsUs: number): number {
    if (this.chunkCount === 0) return -1;
    // The LAST chunk that starts at or before the target. Phrased this way
    // round on purpose: the first-at-or-after form needs a `- 1` to step back
    // into the chunk that straddles the target, and that `- 1` is wrong on the
    // boundary itself - a frame whose time is exactly a chunk's `firstTsUs` is
    // in that chunk, not the one before. The test caught it.
    //
    // Capture time is monotonic per interface but not across two of them, so
    // the chunk is a starting point and the frames inside it are the answer.
    let lo = 0, hi = this.chunkCount - 1, answer = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.firstTs[mid] <= tsUs) { answer = mid; lo = mid + 1; } else hi = mid - 1;
    }
    return answer;
  }

  /**
   * The ids this capture can supply, or null when it holds nothing.
   *
   * The direct replacement for `sessionStore.ledgerRange`, deliberately the same
   * shape and the same null-when-empty rule, so `storedIdRange()` and therefore
   * `packetBytes.bytesAreRecoverable` keep working unchanged at their call
   * sites. That module's header promised this day would need no changes to it.
   */
  idRange(): { first: number; last: number } | null {
    if (this.chunkCount === 0) return null;
    return { first: this.firstId[0], last: this.lastId[this.chunkCount - 1] };
  }
}

export interface RecoveryPlan {
  /** How many index records describe data that is actually present. */
  keepRecords: number;
  /** Truncate the three data files to these lengths. */
  pfxLength: number;
  sumLength: number;
  bytLength: number;
  /** Truncate the index itself to this length. */
  indexLength: number;
  /** Frames the torn tail cost. Zero when nothing was lost. */
  framesLost: number;
}

/**
 * What to truncate after a crash, given the index and the three data sizes.
 *
 * Pure, and exported for that reason: this is the one function in the capture
 * store that decides a user's frames are gone, and it should be testable
 * directly rather than only by killing a browser. `planBudgetEviction` is
 * exported for exactly the same reason and says so.
 *
 * The rule is one-directional because the write order is. Data is written and
 * flushed before its index record, so the only inconsistency a crash can
 * produce is **data past the last index record**, which is discarded, or an
 * index record whose extents run past a data file, which means the flush did
 * not land and the record is discarded with the chunk it describes.
 */
export function planRecovery(
  records: readonly ChunkRecord[],
  pfxSize: number,
  sumSize: number,
  bytSize: number,
): RecoveryPlan {
  let keep = 0;
  for (const r of records) {
    const complete = r.pfxOffset + r.pfxLength <= pfxSize
      && r.sumOffset + r.sumLength <= sumSize
      && r.bytOffset + r.bytLength <= bytSize;
    if (!complete) break;
    keep += 1;
  }

  let framesLost = 0;
  for (let i = keep; i < records.length; i++) framesLost += records[i].frameCount;

  const last = keep > 0 ? records[keep - 1] : null;
  return {
    keepRecords: keep,
    // Truncate the data back to the end of the last chunk an index record
    // describes. Bytes past it were written by a chunk whose record never
    // landed, so nothing can find them and leaving them would make every
    // subsequent offset wrong.
    pfxLength: last === null ? 0 : last.pfxOffset + last.pfxLength,
    sumLength: last === null ? 0 : last.sumOffset + last.sumLength,
    bytLength: last === null ? 0 : last.bytOffset + last.bytLength,
    indexLength: INDEX_HEADER_BYTES + keep * INDEX_RECORD_BYTES,
    framesLost,
  };
}

/** Reads an index file and plans its recovery in one step. */
export function recoverIndex(
  index: BlockFile, pfx: BlockFile, sum: BlockFile, byt: BlockFile,
): { records: ChunkRecord[]; plan: RecoveryPlan } {
  const size = index.size();
  const count = recordsIn(size);
  const bytes = new Uint8Array(INDEX_HEADER_BYTES + count * INDEX_RECORD_BYTES);
  index.read(0, bytes);
  const records: ChunkRecord[] = new Array(count);
  for (let i = 0; i < count; i++) {
    records[i] = decodeChunkRecord(bytes, INDEX_HEADER_BYTES + i * INDEX_RECORD_BYTES);
  }
  return { records, plan: planRecovery(records, pfx.size(), sum.size(), byt.size()) };
}
