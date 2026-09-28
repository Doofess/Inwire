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
 * caller truncates all five back to that boundary. What is lost is the last
 * partial chunk - under 4,096 frames - which is the append-only contract and is
 * worth stating out loud rather than discovering.
 *
 * ## Version 2: a fifth file
 *
 * Version 2 adds `records.iwrec`, each chunk's frame records (ADR 0049), and
 * sixteen bytes to every index record to find them: an 80-byte stride where
 * version 1 had 64. A version 1 capture still opens - its chunks simply have no
 * records, which is what `recLength === 0` means - and a writer continuing one
 * keeps writing version 1, because a file's stride is set by its header and
 * cannot change half way down it.
 *
 * ## Version 3: segments, and a floor
 *
 * A capture whose agent writes a ring of pcapng files follows the ring
 * (ADR 0052): when the agent deletes a file, the frames it held leave the
 * capture too. Deleting the front of four append-only files is not something a
 * file system offers, so version 3 puts a capture's data in **segments** -
 * segment 0 is the four files beside the index, as it always was, and segment
 * *n* is `seg-NNNNNN/` holding four more - and each chunk says which segment it
 * is in, in the four bytes version 2 reserved at 76. The index stays one file.
 *
 * What left is recorded as a **floor**: the first chunk still held, in the
 * header's reserved eight bytes. Chunks below it keep their index records -
 * the file is append-only and their ordinals stay what they were - and every
 * lookup here answers as if they were not there. The floor is written before a
 * segment is deleted, so a crash between the two leaves a segment nothing
 * reads rather than a chunk whose data is gone. `segments.ts` is what decides
 * a segment may go.
 */
import type { BlockFile } from './blockFile';

export const INDEX_MAGIC = 0x31584449;          // 'IDX1'
/** The version this build writes. It reads 1, 2 and 3. */
export const INDEX_VERSION = 3;
/** A fixed header so a reader can refuse a file it does not understand. */
export const INDEX_HEADER_BYTES = 16;
/** One record per chunk. See the module header for why 80 B is cheap. */
export const INDEX_RECORD_BYTES = 80;
/** Version 1's stride: everything up to and including `firstTsUs`. */
export const INDEX_RECORD_BYTES_V1 = 64;

/** The stride of each version this build reads. */
export function strideOf(version: number): number {
  if (version === 1) return INDEX_RECORD_BYTES_V1;
  if (version === 2 || version === 3) return INDEX_RECORD_BYTES;
  throw new Error(`captureIndex: version ${version} is not one this build reads`);
}

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
const OFF_REC_OFFSET = 64;     // f64 - version 2
const OFF_REC_LENGTH = 72;     // u32 - version 2
const OFF_SEGMENT = 76;        // u32 - version 3; reserved (zero) in version 2
/** Where version 3's header keeps the floor: the first chunk still held. */
const OFF_HEADER_FLOOR = 8;    // f64

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
  /**
   * This chunk's frame records in `records.iwrec`. Both 0 when the chunk has
   * none - every chunk of a version 1 capture.
   */
  recOffset: number;
  recLength: number;
  /**
   * Which segment holds the chunk's data (version 3): 0 is the files beside
   * the index, *n* is `seg-NNNNNN/`. Always 0 before version 3.
   */
  segment: number;
}

export function encodeChunkRecord(
  record: ChunkRecord, into: Uint8Array, at: number, stride = INDEX_RECORD_BYTES,
): void {
  const view = new DataView(into.buffer, into.byteOffset + at, stride);
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
  if (stride >= INDEX_RECORD_BYTES) {
    view.setFloat64(OFF_REC_OFFSET, record.recOffset, true);
    view.setUint32(OFF_REC_LENGTH, record.recLength >>> 0, true);
    view.setUint32(OFF_SEGMENT, record.segment >>> 0, true);
  }
}

export function decodeChunkRecord(
  from: Uint8Array, at: number, stride = INDEX_RECORD_BYTES,
): ChunkRecord {
  const view = new DataView(from.buffer, from.byteOffset + at, stride);
  const records = stride >= INDEX_RECORD_BYTES;
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
    recOffset: records ? view.getFloat64(OFF_REC_OFFSET, true) : 0,
    recLength: records ? view.getUint32(OFF_REC_LENGTH, true) : 0,
    segment: records ? view.getUint32(OFF_SEGMENT, true) : 0,
  };
}

export function writeIndexHeader(into: Uint8Array, version = INDEX_VERSION): void {
  const view = new DataView(into.buffer, into.byteOffset, INDEX_HEADER_BYTES);
  view.setUint32(0, INDEX_MAGIC, true);
  view.setUint16(4, version, true);
  view.setUint16(6, strideOf(version), true);
  view.setFloat64(OFF_HEADER_FLOOR, 0, true);    // v3's floor; reserved before
}

/** Version 3's floor as it sits in the header: the first chunk still held. */
export function encodeIndexFloor(floorChunk: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setFloat64(0, floorChunk, true);
  return bytes;
}

/** Where `encodeIndexFloor`'s bytes go in the index file. */
export const INDEX_FLOOR_OFFSET = OFF_HEADER_FLOOR;

/**
 * The floor a header records, or 0 before version 3 - whose header held zeros
 * there, and whose chunks are all still held.
 */
export function indexFloorOf(header: Uint8Array): number {
  if (header.length < INDEX_HEADER_BYTES || indexVersionOf(header) < 3) return 0;
  const floor = new DataView(header.buffer, header.byteOffset, header.byteLength)
    .getFloat64(OFF_HEADER_FLOOR, true);
  return Number.isInteger(floor) && floor >= 0 ? floor : 0;
}

/** How many whole records a file of this size holds after its header. */
export function recordsIn(fileSize: number, stride = INDEX_RECORD_BYTES): number {
  if (fileSize < INDEX_HEADER_BYTES) return 0;
  return Math.floor((fileSize - INDEX_HEADER_BYTES) / stride);
}

/**
 * The version an index file's header declares, or `INDEX_VERSION` for a file
 * too short to have one - a new capture, which is written at this version.
 */
export function indexVersionOf(header: Uint8Array): number {
  if (header.length < INDEX_HEADER_BYTES) return INDEX_VERSION;
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const magic = view.getUint32(0, true);
  if (magic !== INDEX_MAGIC) throw new Error(`captureIndex: bad magic 0x${magic.toString(16)}`);
  const version = view.getUint16(4, true);
  const stride = view.getUint16(6, true);
  if (stride !== strideOf(version)) {
    throw new Error(`captureIndex: record stride ${stride}, expected ${strideOf(version)}`);
  }
  return version;
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
  private recOffset: Float64Array;
  private recLength: Uint32Array;
  private segments: Uint32Array;

  private n = 0;
  private frames = 0;
  /** The first chunk still held. See "Version 3" in the module header. */
  private floor = 0;

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
  constructor(
    records: readonly ChunkRecord[] = [],
    /** The index file's version, which decides its stride and whether chunks have records. */
    readonly version: number = INDEX_VERSION,
    /** The first chunk still held - version 3's floor. */
    floorChunk = 0,
  ) {
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
    this.recOffset = new Float64Array(capacity);
    this.recLength = new Uint32Array(capacity);
    this.segments = new Uint32Array(capacity);
    for (const r of records) this.append(r);
    this.floor = Math.min(floorChunk, this.n);
  }

  get chunkCount(): number { return this.n; }
  /** Whether this capture's chunks carry frame records at all. */
  get storesRecords(): boolean { return this.version >= 2; }
  /** Bytes each record takes in the file. */
  get stride(): number { return strideOf(this.version); }
  /**
   * The end of the capture's ordinal space: one past its newest frame. Not how
   * many frames it holds - a floor above 0 means the first `floorOrdinal` of
   * them have gone - and never reduced, because ordinals never move.
   */
  get frameCount(): number { return this.frames; }
  /** Whether chunks may live outside the files beside the index. */
  get segmented(): boolean { return this.version >= 3; }
  /** The first chunk still held. */
  get floorChunk(): number { return this.floor; }
  /** The ordinal of the first frame still held; `frameCount` when none is. */
  get floorOrdinal(): number {
    return this.floor < this.n ? this.firstOrdinal[this.floor] : this.frames;
  }
  /** Which segment holds a chunk's data. */
  segmentOf(chunk: number): number { return this.segments[chunk]; }

  /**
   * Raises the floor: every chunk below `chunk` has gone. It never falls - a
   * chunk that has left cannot come back.
   */
  setFloor(chunk: number): void {
    this.floor = Math.max(this.floor, Math.min(chunk, this.n));
  }

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
    this.recOffset[i] = r.recOffset;
    this.recLength[i] = r.recLength;
    this.segments[i] = r.segment;
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
    this.recLength = u32(this.recLength);
    this.segments = u32(this.segments);
    this.firstOrdinal = f64(this.firstOrdinal);
    this.pfxOffset = f64(this.pfxOffset);
    this.sumOffset = f64(this.sumOffset);
    this.bytOffset = f64(this.bytOffset);
    this.firstTs = f64(this.firstTs);
    this.recOffset = f64(this.recOffset);
  }

  /** Parses a whole `index.iwidx`, refusing a header it does not know. */
  static parse(bytes: Uint8Array): CaptureIndex {
    if (bytes.length < INDEX_HEADER_BYTES) return new CaptureIndex([]);
    const version = indexVersionOf(bytes);
    const stride = strideOf(version);
    const count = recordsIn(bytes.length, stride);
    const records: ChunkRecord[] = new Array(count);
    for (let i = 0; i < count; i++) {
      records[i] = decodeChunkRecord(bytes, INDEX_HEADER_BYTES + i * stride, stride);
    }
    return new CaptureIndex(records, version, indexFloorOf(bytes));
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
      recOffset: this.recOffset[chunk],
      recLength: this.recLength[chunk],
      segment: this.segments[chunk],
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
    if (this.chunkCount === 0 || ordinal < this.floorOrdinal || ordinal >= this.frameCount) return -1;
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
    // Below the floor is gone, and answered as a hole rather than as a chunk
    // whose data is not there.
    let lo = this.floor, hi = this.chunkCount - 1;
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
    if (this.chunkCount <= this.floor) return -1;
    // The LAST chunk that starts at or before the target. Phrased this way
    // round on purpose: the first-at-or-after form needs a `- 1` to step back
    // into the chunk that straddles the target, and that `- 1` is wrong on the
    // boundary itself - a frame whose time is exactly a chunk's `firstTsUs` is
    // in that chunk, not the one before. The test caught it.
    //
    // Capture time is monotonic per interface but not across two of them, so
    // the chunk is a starting point and the frames inside it are the answer.
    let lo = this.floor, hi = this.chunkCount - 1, answer = this.floor;
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
    if (this.chunkCount <= this.floor) return null;
    return { first: this.firstId[this.floor], last: this.lastId[this.chunkCount - 1] };
  }
}

export interface RecoveryPlan {
  /** How many index records describe data that is actually present. */
  keepRecords: number;
  /** Truncate the four data files to these lengths. */
  pfxLength: number;
  sumLength: number;
  bytLength: number;
  recLength: number;
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
 * directly rather than only by killing the process mid-write.
 * `scripts/capture/recovery-on-disk.ts` is what drives it, against a real file
 * truncated at chosen offsets. The disk budget's `planBudgetEviction` was
 * exported for exactly the same reason, and went with the budget it enforced.
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
  /** `records.iwrec`'s size; a version 1 capture has none, and no record reaches into it. */
  recSize = 0,
  stride = INDEX_RECORD_BYTES,
): RecoveryPlan {
  // One segment, the files beside the index, and no floor: every capture
  // before version 3, and every version 3 capture that never followed a ring.
  const sizes = { pfx: pfxSize, sum: sumSize, byt: bytSize, rec: recSize };
  const plan = planSegmentedRecovery(records, 0, (segment) => (segment === 0 ? sizes : null), stride);
  const kept = plan.truncate.get(0) ?? NOTHING;
  return {
    keepRecords: plan.keepRecords,
    pfxLength: kept.pfx,
    sumLength: kept.sum,
    bytLength: kept.byt,
    recLength: kept.rec,
    indexLength: plan.indexLength,
    framesLost: plan.framesLost,
  };
}

/** Four data files' lengths - one segment's. */
export interface SegmentSizes {
  pfx: number;
  sum: number;
  byt: number;
  rec: number;
}

const NOTHING: SegmentSizes = { pfx: 0, sum: 0, byt: 0, rec: 0 };

export interface SegmentedRecoveryPlan {
  /** How many index records to keep: those below the floor, and the whole chunks above it. */
  keepRecords: number;
  /** The floor the header records, clamped to the records there are. */
  floorChunk: number;
  indexLength: number;
  framesLost: number;
  /**
   * Each segment still holding a kept chunk, and the lengths to cut its four
   * files back to - with segment 0 always among them. **A segment not named
   * here is removed**: it holds only chunks below the floor, or only data no
   * kept record describes.
   */
  truncate: Map<number, SegmentSizes>;
}

/**
 * `planRecovery` for a capture in segments (version 3), above a floor.
 *
 * The same one-directional rule, per segment: a chunk is kept while its
 * segment exists and holds every byte its record names, and the walk stops at
 * the first that does not. Chunks below the floor are not walked - their
 * segments were deleted on purpose, after the floor that says so was written -
 * and they cost nothing: their records stay, so ordinals never move.
 *
 * Each kept segment is cut back to the end of its last kept chunk, which is
 * the torn tail in the last one and a no-op in every one before it. Segment 0
 * is named even when it holds nothing, and cut to nothing, as the files beside
 * the index always were.
 */
export function planSegmentedRecovery(
  records: readonly ChunkRecord[],
  floorChunk: number,
  sizesOf: (segment: number) => SegmentSizes | null,
  stride = INDEX_RECORD_BYTES,
): SegmentedRecoveryPlan {
  const floor = Math.min(Math.max(0, floorChunk), records.length);
  let keep = floor;
  for (let i = floor; i < records.length; i++) {
    const r = records[i];
    const sizes = sizesOf(r.segment);
    const complete = sizes !== null
      && r.pfxOffset + r.pfxLength <= sizes.pfx
      && r.sumOffset + r.sumLength <= sizes.sum
      && r.bytOffset + r.bytLength <= sizes.byt
      && (r.recLength === 0 || r.recOffset + r.recLength <= sizes.rec);
    if (!complete) break;
    keep += 1;
  }

  let framesLost = 0;
  for (let i = keep; i < records.length; i++) framesLost += records[i].frameCount;

  // Truncate each segment's data back to the end of the last chunk an index
  // record describes. Bytes past it were written by a chunk whose record never
  // landed, so nothing can find them and leaving them would make every
  // subsequent offset in that segment wrong. Records within a segment are in
  // write order, so the last kept one ends furthest - except in the records
  // file, which ends where the last kept chunk that HAS records ends: a chunk
  // sealed without them writes nothing there.
  const truncate = new Map<number, SegmentSizes>([[0, { ...NOTHING }]]);
  for (let i = floor; i < keep; i++) {
    const r = records[i];
    const ends = truncate.get(r.segment) ?? { ...NOTHING };
    ends.pfx = r.pfxOffset + r.pfxLength;
    ends.sum = r.sumOffset + r.sumLength;
    ends.byt = r.bytOffset + r.bytLength;
    if (r.recLength > 0) ends.rec = r.recOffset + r.recLength;
    truncate.set(r.segment, ends);
  }
  return {
    keepRecords: keep,
    floorChunk: floor,
    indexLength: INDEX_HEADER_BYTES + keep * stride,
    framesLost,
    truncate,
  };
}

/** Reads an index file and plans its recovery in one step. */
export function recoverIndex(
  index: BlockFile, pfx: BlockFile, sum: BlockFile, byt: BlockFile, rec?: BlockFile,
): { records: ChunkRecord[]; plan: RecoveryPlan; version: number } {
  const size = index.size();
  const header = new Uint8Array(Math.min(size, INDEX_HEADER_BYTES));
  if (header.length > 0) index.read(0, header);
  const version = indexVersionOf(header);
  const stride = strideOf(version);
  const count = recordsIn(size, stride);
  const bytes = new Uint8Array(INDEX_HEADER_BYTES + count * stride);
  if (count > 0) index.read(0, bytes);
  const records: ChunkRecord[] = new Array(count);
  for (let i = 0; i < count; i++) {
    records[i] = decodeChunkRecord(bytes, INDEX_HEADER_BYTES + i * stride, stride);
  }
  return {
    records,
    plan: planRecovery(records, pfx.size(), sum.size(), byt.size(), rec?.size() ?? 0, stride),
    version,
  };
}

/** One segment's four files, as `recoverCapture` measures them. */
export interface SegmentFileSizes {
  pfx: BlockFile;
  sum: BlockFile;
  byt: BlockFile;
  rec: BlockFile;
}

/**
 * Reads an index file, its floor and every segment it names, and plans its
 * recovery - `recoverIndex` for a capture that may be in segments.
 *
 * `segment(n)` is segment *n*'s files when they exist, and null when they do
 * not; 0 is the files beside the index.
 */
export function recoverCapture(
  index: BlockFile,
  segment: (n: number) => SegmentFileSizes | null,
): { records: ChunkRecord[]; plan: SegmentedRecoveryPlan; version: number } {
  const size = index.size();
  const header = new Uint8Array(Math.min(size, INDEX_HEADER_BYTES));
  if (header.length > 0) index.read(0, header);
  const version = indexVersionOf(header);
  const stride = strideOf(version);
  const count = recordsIn(size, stride);
  const bytes = new Uint8Array(INDEX_HEADER_BYTES + count * stride);
  if (count > 0) index.read(0, bytes);
  const records: ChunkRecord[] = new Array(count);
  for (let i = 0; i < count; i++) {
    records[i] = decodeChunkRecord(bytes, INDEX_HEADER_BYTES + i * stride, stride);
  }
  const sizesOf = (n: number): SegmentSizes | null => {
    const files = segment(n);
    return files === null
      ? null
      : { pfx: files.pfx.size(), sum: files.sum.size(), byt: files.byt.size(), rec: files.rec.size() };
  };
  return {
    records,
    plan: planSegmentedRecovery(records, indexFloorOf(header), sizesOf, stride),
    version,
  };
}
