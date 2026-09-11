/**
 * Writing a capture to disk: bytes at once, rows behind a patch horizon.
 *
 * ## The problem this exists to solve
 *
 * Write-through looks simple - a frame arrives, it goes to disk - and it is
 * wrong, because **a frame's row is not final when the frame arrives**. Four
 * mechanisms in this codebase amend an already-emitted frame:
 *
 *  - `[TCP PDU reassembled in N]` on every segment of a multi-segment PDU
 *    (`dissectors/networkLayer.ts`), reaching back a dozen frames routinely and
 *    much further across a stalled or retransmitting stream;
 *  - `[Reassembled in N]` for IPv4 and IPv6 fragments;
 *  - `dns.response_in`, written onto the query by the frame that answers it;
 *  - ICMP `(reply in N)`, where the round trip can be seconds - at 35,000
 *    frames a second that is a frame **140,000 frames back**.
 *
 * `dissect/types.ts` states the rule plainly: *"Single-pass dissection cannot
 * see the future, so the frame that learns the fact hands it back and the
 * caller patches the list."* A row written the instant it was dissected would
 * be missing every one of those cross-references, silently, for ever.
 *
 * ## The fix, and why it costs almost nothing
 *
 * **Frame bytes are immutable, so they go to disk immediately.** Only the rows
 * wait, in a staging ring, until no open patch can still reach them. A row is
 * ~390 bytes uncompressed against a frame's ~1,100, so a two-second horizon at
 * 35,000 frames a second stages roughly 27 MB - in the storage Worker, off the
 * main thread's budget entirely.
 *
 * That ordering also happens to be what the write path wants anyway: rows leave
 * the ring a whole chunk at a time, so the deflate and the write are one large
 * sequential operation instead of 4,096 small ones.
 *
 * The horizon is bounded two ways, and both matter. **Time** is the real rule -
 * a patch chases a protocol event, not a frame count - but a quiet adapter
 * would hold a handful of frames for ever waiting for time to pass, so a
 * **frame count** forces them out. Whichever fires first wins.
 *
 * ## What escapes, and what happens to it
 *
 * A patch aimed at a frame that has already left the ring cannot be applied,
 * because a written chunk is deflated and sealed and rewriting it would undo
 * the append-only property the recovery rule depends on. Those are counted, not
 * ignored: `missedPatches` collects them for the overlay journal a reader
 * applies at decode time, and `stats.patchesMissed` is what says whether the
 * horizon is long enough. On the fixtures it is zero.
 */
import { deflateSync } from 'fflate';
import type { Packet } from '../../types/packet';
import type { InfoPatch } from '../dissect/types';
import { applyInfoPatch } from '../pcapParser';
import { encodeChunk, CHUNK_FRAMES } from './chunkCodec';
import {
  encodeChunkRecord, writeIndexHeader, CaptureIndex, INDEX_HEADER_BYTES, INDEX_RECORD_BYTES,
  type ChunkRecord,
} from './captureIndex';
import { append, type BlockFile } from './blockFile';

export interface CaptureFiles {
  index: BlockFile;
  /** Fixed-width filter records, deflated per chunk. */
  pfx: BlockFile;
  /** Interned summaries, deflated per chunk. */
  sum: BlockFile;
  /** Raw frame bytes, never compressed. */
  byt: BlockFile;
}

export interface WriterOptions {
  /**
   * How long a row waits before it is sealed, in microseconds of capture time.
   *
   * Two seconds by default, which covers an ICMP round trip and a slow DNS
   * answer - the two patches that reach furthest back.
   */
  horizonUs?: number;
  /**
   * How many rows may wait, whatever the clock says.
   *
   * A quiet adapter produces frames minutes apart, and without this the last
   * few would sit in memory until the capture stopped. It is also the memory
   * bound: 100,000 rows is roughly 39 MB staged.
   */
  horizonFrames?: number;
  /**
   * How many chunks between `flush()` calls.
   *
   * Rarely, on purpose. A `write()` that has returned already survives a tab
   * crash or a refresh - it is in the browser's file layer, not in this page.
   * `flush()` defends only against power loss, and `scripts/perf/throughput.ts`
   * records what flushing per batch costs: *"flush() is synchronous, so it is
   * the tail that overruns the 100 ms budget and starves ws.onmessage, which is
   * what makes the agent's queue overflow."*
   */
  flushEveryChunks?: number;
  /** Injected so the module stays synchronous and testable outside a browser. */
  deflate?: (bytes: Uint8Array) => Uint8Array;
  /**
   * Chunks already on disk, from a capture this writer is continuing.
   *
   * The recovery pass runs before the writer is built - it may truncate the
   * files, and a writer that had already read their sizes would be describing
   * bytes that are no longer there - so what survived is handed in rather than
   * discovered here.
   */
  resumeFrom?: readonly ChunkRecord[];
}

const DEFAULT_HORIZON_US = 2_000_000;
const DEFAULT_HORIZON_FRAMES = 100_000;
const DEFAULT_FLUSH_EVERY_CHUNKS = 8;

/** Raw DEFLATE, the same format `node:zlib`'s `deflateRawSync` produces. */
const defaultDeflate = (bytes: Uint8Array): Uint8Array => deflateSync(bytes, { level: 6 });

interface Staged {
  packet: Packet;
  /** Where this frame's bytes already are. Written before the row waits. */
  bytOffset: number;
  bytLength: number;
}

export interface WriterStats {
  framesStaged: number;
  framesWritten: number;
  chunksWritten: number;
  bytesWritten: number;
  patchesApplied: number;
  /** Patches whose target had already been sealed. See the module header. */
  patchesMissed: number;
  flushes: number;
}

export class CaptureWriter {
  private readonly horizonUs: number;
  private readonly horizonFrames: number;
  private readonly flushEveryChunks: number;
  private readonly deflate: (bytes: Uint8Array) => Uint8Array;

  private readonly staged: Staged[] = [];
  /** Frame id to its position in `staged`, so a patch is a lookup not a scan. */
  private readonly stagedAt = new Map<number, number>();
  /** How many entries have been shifted off the front of `staged`. */
  private drained = 0;
  private newestTsUs = 0;
  private ordinal = 0;
  private chunksSinceFlush = 0;

  /**
   * Patches that arrived after their target was sealed.
   *
   * Kept rather than dropped: they are what a `patch.dat` overlay journals, and
   * their count is the only honest signal that the horizon is too short.
   */
  readonly missedPatches: InfoPatch[] = [];

  private readonly counters: WriterStats = {
    framesStaged: 0, framesWritten: 0, chunksWritten: 0, bytesWritten: 0,
    patchesApplied: 0, patchesMissed: 0, flushes: 0,
  };

  /**
   * The chunks this writer has sealed, searchable.
   *
   * Shared rather than copied: the reader beside this writer answers "where is
   * frame N" from the same object, so a chunk becomes readable the instant its
   * index record is appended and never a flush later.
   */
  readonly index: CaptureIndex;

  constructor(private readonly files: CaptureFiles, options: WriterOptions = {}) {
    this.horizonUs = options.horizonUs ?? DEFAULT_HORIZON_US;
    this.horizonFrames = options.horizonFrames ?? DEFAULT_HORIZON_FRAMES;
    this.flushEveryChunks = options.flushEveryChunks ?? DEFAULT_FLUSH_EVERY_CHUNKS;
    this.deflate = options.deflate ?? defaultDeflate;
    this.index = new CaptureIndex(options.resumeFrom ?? []);
    this.ordinal = this.index.frameCount;
    if (files.index.size() === 0) {
      const header = new Uint8Array(INDEX_HEADER_BYTES);
      writeIndexHeader(header);
      files.index.write(0, header);
    }
  }

  get stats(): Readonly<WriterStats> { return this.counters; }
  /** Rows waiting for the horizon. Bounded by `horizonFrames`. */
  get stagedCount(): number { return this.staged.length - this.drained; }

  /**
   * Takes a batch of freshly dissected frames.
   *
   * Bytes go to disk here and now; the row waits. Frames must arrive in
   * ascending id order, which is what the ordering window already guarantees.
   */
  append(packets: readonly Packet[]): void {
    for (const packet of packets) {
      const bytes = packet.rawBytes;
      const at = append(this.files.byt, bytes);
      this.counters.bytesWritten += bytes.length;
      this.stagedAt.set(packet.id, this.staged.length);
      this.staged.push({ packet, bytOffset: at, bytLength: bytes.length });
      this.counters.framesStaged += 1;
      if (packet.tsUs > this.newestTsUs) this.newestTsUs = packet.tsUs;
    }
    this.drainReady();
  }

  /**
   * Applies patches to rows that have not been sealed yet.
   *
   * The staged packet is **replaced**, not mutated, following
   * `applyInfoPatchesInPlace`'s own precedent - which the plan briefly and
   * wrongly forbade. Nothing here is in the main thread's buffer, so no
   * identity-keyed cache is watching, but copying keeps this consistent with
   * the one other place that does the same job.
   */
  applyPatches(patches: readonly InfoPatch[]): void {
    for (const patch of patches) {
      const index = this.stagedAt.get(patch.frameId);
      if (index === undefined || index < this.drained) {
        this.counters.patchesMissed += 1;
        this.missedPatches.push(patch);
        continue;
      }
      const entry = this.staged[index];
      const copy = { ...entry.packet };
      applyInfoPatch(copy, patch);
      entry.packet = copy;
      this.counters.patchesApplied += 1;
    }
  }

  /**
   * Seals every row a patch can no longer reach.
   *
   * Only ever in whole chunks, so a chunk is one deflate and one write. A
   * partial tail waits for `finish()`.
   */
  private drainReady(): void {
    for (;;) {
      const available = this.staged.length - this.drained;
      if (available < CHUNK_FRAMES) return;
      // The chunk's newest frame decides. Sealing on the OLDEST would let a
      // chunk go out while its last frames are still inside the horizon.
      const newestInChunk = this.staged[this.drained + CHUNK_FRAMES - 1];
      const agedOut = this.newestTsUs - newestInChunk.packet.tsUs >= this.horizonUs;
      const tooMany = available > this.horizonFrames;
      if (!agedOut && !tooMany) return;
      this.sealChunk(CHUNK_FRAMES);
    }
  }

  /** Writes everything still staged, however new. For pause and for stop. */
  finish(): void {
    while (this.staged.length - this.drained > 0) {
      this.sealChunk(Math.min(CHUNK_FRAMES, this.staged.length - this.drained));
    }
    this.flushAll();
    // The ring is empty, so the id map describes nothing. Released here rather
    // than left to grow for the life of a capture.
    this.stagedAt.clear();
    this.staged.length = 0;
    this.drained = 0;
  }

  private sealChunk(count: number): void {
    const entries = this.staged.slice(this.drained, this.drained + count);
    const packets = entries.map((e) => e.packet);
    // The lengths recorded when the bytes were appended, not the lengths the
    // packets report now - `evictOldBytes` may have emptied `rawBytes` in
    // place on any frame already sealed, and nothing stops it reaching one
    // still staged if the horizon ever outgrows the resident window.
    const encoded = encodeChunk(packets, entries.map((e) => e.bytLength));

    const pfxBytes = this.deflate(encoded.prefix);
    const sumBytes = this.deflate(encoded.summary);
    const pfxOffset = append(this.files.pfx, pfxBytes);
    const sumOffset = append(this.files.sum, sumBytes);

    // The bytes are already down, and contiguously: frames were appended in
    // order, so this chunk's byte extent is its first frame's offset to its
    // last frame's end. That is the whole reason bytes can be written early
    // without the index losing track of them.
    const first = entries[0];
    const last = entries[entries.length - 1];

    // The directory the codec wrote must describe exactly the bytes this
    // writer appended. They come from the same numbers, so a mismatch means
    // the frames were not contiguous - which would make every byte read in
    // this chunk slice the wrong frame, silently.
    let directoryBytes = 0;
    for (const e of entries) directoryBytes += e.bytLength;
    const extent = last.bytOffset + last.bytLength - first.bytOffset;
    if (directoryBytes !== extent) {
      throw new Error(`captureWriter: chunk directory covers ${directoryBytes} bytes, extent is ${extent}`);
    }

    const record: ChunkRecord = {
      firstId: encoded.firstId,
      lastId: encoded.lastId,
      frameCount: encoded.frameCount,
      firstOrdinal: this.ordinal,
      pfxOffset, pfxLength: pfxBytes.length,
      sumOffset, sumLength: sumBytes.length,
      bytOffset: first.bytOffset,
      bytLength: last.bytOffset + last.bytLength - first.bytOffset,
      firstTsUs: encoded.firstTsUs,
    };

    // Data first, then flush, THEN the index record. The recovery rule rests
    // entirely on this order: a crash can leave data no record describes, and
    // never a record pointing past its data.
    this.chunksSinceFlush += 1;
    if (this.chunksSinceFlush >= this.flushEveryChunks) this.flushData();

    const recordBytes = new Uint8Array(INDEX_RECORD_BYTES);
    encodeChunkRecord(record, recordBytes, 0);
    append(this.files.index, recordBytes);
    this.index.append(record);

    this.ordinal += count;
    this.counters.framesWritten += count;
    this.counters.chunksWritten += 1;

    // Release the sealed entries. `drained` counts rather than splicing,
    // because splicing 4,096 entries off the front of a 100,000-entry array
    // once a chunk is O(n) work for nothing.
    for (const e of entries) this.stagedAt.delete(e.packet.id);
    this.drained += count;
    if (this.drained > CHUNK_FRAMES * 4) this.compactStaging();
  }

  /** Drops the drained prefix and rebuilds the id map's indices. */
  private compactStaging(): void {
    this.staged.splice(0, this.drained);
    this.drained = 0;
    this.stagedAt.clear();
    for (let i = 0; i < this.staged.length; i++) this.stagedAt.set(this.staged[i].packet.id, i);
  }

  private flushData(): void {
    this.files.byt.flush();
    this.files.pfx.flush();
    this.files.sum.flush();
    this.chunksSinceFlush = 0;
    this.counters.flushes += 1;
  }

  private flushAll(): void {
    this.flushData();
    this.files.index.flush();
  }
}
