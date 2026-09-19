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
import { applyInfoPatch } from '../dissect/infoPatch';
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
   * Rarely, on purpose, and the reason is stated once on `BlockFile.flush` -
   * a returned `write()` is already in the OS page cache, so `flush()` defends
   * only against power loss. What belongs here is the cost:
   * `scripts/perf/throughput.ts` records what flushing per batch bought, in the
   * terms of the transport of the day - *"flush() is synchronous, so it is the
   * tail that overruns the 100 ms budget and starves the socket handler, which
   * is what makes the agent's queue overflow."* The transport is a named pipe
   * now and the arithmetic is unchanged: a synchronous barrier 30 times a
   * second is paid out of the same 100 ms budget.
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
  /** Known when the bytes arrive, which may be long before the row does. */
  id: number;
  /**
   * The frame's capture time, taken at byte-append time.
   *
   * The horizon is measured against this rather than against `packet.tsUs`,
   * because a slot may not have a packet yet - and a chunk whose ageing
   * depended on a row arriving would never age out at all while dissection was
   * behind, which is the exact stall this split exists to remove.
   */
  tsUs: number;
  /**
   * The dissected row, or `null` while dissection is still behind.
   *
   * **This being nullable is the whole of the change.** Bytes and rows are two
   * arrivals now: the bytes are immutable and go down the instant they exist,
   * and the row catches up when the dissector gets to it. A slot still holding
   * `null` when its chunk seals is written as a placeholder rather than
   * holding the chunk back - see `placeholderRow`.
   */
  packet: Packet | null;
  /** Where this frame's bytes already are. Written before the row waits. */
  bytOffset: number;
  bytLength: number;
}

/**
 * One frame as it arrives, before anything has looked at it.
 *
 * Deliberately three fields. Anything more would be something a dissector
 * decided, and the point of this path is that nothing has dissected yet.
 */
export interface RawFrame {
  id: number;
  tsUs: number;
  bytes: Uint8Array;
}

/**
 * A row for a frame whose dissection never arrived.
 *
 * Built here rather than with `buildFallbackPacket`, which lives in
 * `sessionRestore.ts` and imports `pcapParser` - the whole dissector, into the
 * store process, to fill in ten fields. The store must stay small and must not
 * gain a reason to import the thing it exists to be independent of.
 *
 * **The frame is not lost and this is not a hole.** Its bytes are on disk,
 * exactly and completely, and `frames.iwbyt` is the source of truth that a
 * re-read reconstructs from; what the placeholder stands in for is the derived
 * accelerator row. The Info column says so, because a row reading `TCP` with
 * no explanation would be a confident wrong answer about a frame nobody
 * dissected.
 */
function placeholderRow(id: number, tsUs: number, length: number): Packet {
  return {
    id,
    tsUs,
    timeDelta: 0,
    relativeTime: 0,
    source: '0.0.0.0',
    destination: '0.0.0.0',
    protocol: 'TCP' as Packet['protocol'],
    length,
    info: 'Not dissected - frame bytes are on disk',
    status: 'normal' as Packet['status'],
    // Empty rather than absent: the tree is rebuilt by replaying the frame's
    // conversation from the bytes on disk, never read back from here.
    layers: [],
    // The bytes themselves are NOT carried. They are already written, and
    // `sealChunk` passes the length it recorded at append time rather than
    // reading this - see the note on `encodeChunk`'s `capLengths`.
    rawBytes: new Uint8Array(0),
    interfaceName: 'Live Agent',
  };
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
  /** Rows matched to a frame whose bytes were already down. */
  rowsAttached: number;
  /**
   * Rows that arrived too late to be written, and rows abandoned at the end of
   * a capture.
   *
   * The number that says whether splitting bytes from rows is costing
   * anything. Its frames are **not** lost - their bytes are on disk and their
   * slot holds a placeholder - so this counts degraded rows, never lost
   * frames, and it must not be added to a frames-lost total.
   */
  rowsMissed: number;
  /** Slots sealed with a placeholder because no row ever arrived. */
  framesSealedWithoutRow: number;
}

export class CaptureWriter {
  private readonly horizonUs: number;
  private readonly horizonFrames: number;
  private readonly flushEveryChunks: number;
  private readonly deflate: (bytes: Uint8Array) => Uint8Array;

  private readonly staged: Staged[] = [];
  /** Frame id to its position in `staged`, so a patch is a lookup not a scan. */
  private readonly stagedAt = new Map<number, number>();
  /**
   * Rows that arrived before their frame's bytes did.
   *
   * See `attachRows`. Normally empty - bytes lead rows by a flush interval -
   * but two channels into one process have no ordering guarantee between them,
   * and holding is the only answer that cannot lose a row.
   */
  private readonly orphanRows = new Map<number, Packet>();
  /**
   * The highest frame id whose bytes this writer has staged.
   *
   * **This is what tells an EARLY row from a LATE one**, and nothing else can:
   * `sealChunk` deletes a sealed slot from `stagedAt`, so a miss in that map
   * means either "the bytes have not arrived" or "the slot is already on disk",
   * and those want opposite answers. Ids ascend, so the comparison is exact.
   */
  private highestStagedId = -1;
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
    rowsAttached: 0, rowsMissed: 0, framesSealedWithoutRow: 0,
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
    // Seeded from what survived, not started at zero. These counters are what
    // the panel reports as "N frames stored on disk", and a reopened capture
    // that said 1 while holding 9,001 would be the storage layer lying about
    // the one number a reader uses to decide whether it is working.
    this.counters.framesWritten = this.index.frameCount;
    this.counters.chunksWritten = this.index.chunkCount;
    if (this.index.chunkCount > 0) {
      const last = this.index.record(this.index.chunkCount - 1);
      this.counters.bytesWritten = last.bytOffset + last.bytLength;
    }
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
    // **The writer decides whether these bytes are already down, and that is
    // what keeps the app out of it entirely.**
    //
    // A live capture sends bytes ahead of rows, from the Worker, over a
    // separate port (ADR 0038). An import has both at once and no reason to
    // split them. A build whose preload predates the ingest port has no bytes
    // coming at all. The app would otherwise have to know which case it is in
    // and choose a message - three states, two of them invisible from the
    // renderer, and getting it wrong writes every frame's bytes twice or not
    // at all. Here it is one question with a local answer: do I have a slot?
    const fresh = packets.filter((packet) => !this.hasSlot(packet.id));
    if (fresh.length > 0) {
      // **Staged without draining, then the rows attached, then drained once.**
      // Calling `appendBytes` here instead would drain with no rows attached
      // yet, and at a short horizon that seals the whole batch as placeholders
      // - a row arriving in the same call would already be too late. Caught by
      // `scripts/capture/writer.ts`, which had asserted the patched row reaches
      // disk since before the split existed.
      this.stageBytes(fresh.map((packet) => ({
        id: packet.id,
        tsUs: packet.tsUs,
        bytes: packet.rawBytes,
      })));
    }
    this.attachRows(packets);
  }

  /**
   * Whether this writer has already written this frame's bytes.
   *
   * True for a slot still staged AND for one already sealed - a sealed frame's
   * bytes are emphatically on disk, and writing them again would append a
   * second copy that nothing indexes and that breaks the contiguity `sealChunk`
   * checks for every chunk after it.
   */
  private hasSlot(id: number): boolean {
    return this.stagedAt.has(id) || id <= this.highestStagedId;
  }

  /**
   * Takes frames that have arrived and nothing more.
   *
   * **This is the capture path's write, and it does not wait for a dissector.**
   * Bytes are immutable, so they go down the instant they exist; the row is a
   * derived accelerator and catches up through `attachRows`. A dissector that
   * falls behind therefore costs latency in the packet list and **cannot cost
   * a frame**, which is the property this split exists to buy.
   *
   * Frames must arrive in ascending id order. That is what the ordering window
   * already guarantees, and it is what makes a chunk's byte extent contiguous -
   * the invariant `sealChunk` checks rather than assumes.
   */
  appendBytes(frames: readonly RawFrame[]): void {
    this.stageBytes(frames);
    this.drainReady();
  }

  /** Writes the bytes and opens a slot for each, without sealing anything. */
  private stageBytes(frames: readonly RawFrame[]): void {
    for (const frame of frames) {
      const at = append(this.files.byt, frame.bytes);
      this.counters.bytesWritten += frame.bytes.length;
      this.stagedAt.set(frame.id, this.staged.length);
      // A row that overtook its bytes is already waiting. Claimed here rather
      // than left in the map, so the map holds only what is genuinely early.
      const early = this.orphanRows.get(frame.id) ?? null;
      if (early !== null) this.orphanRows.delete(frame.id);
      if (frame.id > this.highestStagedId) this.highestStagedId = frame.id;
      this.staged.push({
        id: frame.id,
        tsUs: frame.tsUs,
        packet: early,
        bytOffset: at,
        bytLength: frame.bytes.length,
      });
      this.counters.framesStaged += 1;
      if (frame.tsUs > this.newestTsUs) this.newestTsUs = frame.tsUs;
    }
  }

  /**
   * Fills in the rows for frames whose bytes are already down.
   *
   * **A row for a frame this writer has not seen bytes for is held, not
   * dropped.** The two arrivals come from different places - bytes from the
   * capture path, rows from the dissector - and nothing orders two channels
   * into one process against each other. In practice bytes always win by a
   * flush interval; "in practice" is not a guarantee, and the failure it would
   * produce is a silently missing row rather than an error.
   *
   * The held rows are bounded by the same thing the staging ring is: a row
   * whose bytes never arrive is a frame that never arrived, and
   * `clearOrphans()` is called when a capture ends.
   */
  attachRows(packets: readonly Packet[]): void {
    for (const packet of packets) {
      const index = this.stagedAt.get(packet.id);
      const sealed = index !== undefined
        ? index < this.drained
        // Not in the map. Either its slot was sealed and removed, or its bytes
        // have not arrived - and `highestStagedId` is the only thing that can
        // tell those apart, because ids ascend.
        : packet.id <= this.highestStagedId;
      if (sealed) {
        // Too late to be written: a sealed chunk is deflated and appended, and
        // rewriting it would undo the append-only property recovery depends on.
        this.counters.rowsMissed += 1;
        continue;
      }
      if (index === undefined) {
        this.orphanRows.set(packet.id, packet);
        continue;
      }
      this.staged[index].packet = packet;
      this.counters.rowsAttached += 1;
    }
    // Attaching a row can make a chunk sealable that was not before, because
    // `drainReady` only needs the slots - but a chunk held only by the horizon
    // is unaffected, so this is cheap and never premature.
    this.drainReady();
  }

  /** Rows waiting for bytes that have not arrived. Dropped when a capture ends. */
  clearOrphans(): void {
    this.counters.rowsMissed += this.orphanRows.size;
    this.orphanRows.clear();
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
      // A patch for a slot whose row has not arrived cannot be applied to
      // nothing. Counted as missed rather than dropped silently - and it is
      // genuinely missed, because the row will arrive already patched or not
      // at all: the dissector applies its own patches before emitting.
      if (entry.packet === null) {
        this.counters.patchesMissed += 1;
        this.missedPatches.push(patch);
        continue;
      }
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
      // The SLOT's timestamp, not its packet's. A slot may have no packet yet,
      // and a horizon that depended on a row arriving would never age out
      // while the dissector was behind - which is the stall this split removes.
      const agedOut = this.newestTsUs - newestInChunk.tsUs >= this.horizonUs;
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
    this.clearOrphans();
  }

  private sealChunk(count: number): void {
    const entries = this.staged.slice(this.drained, this.drained + count);
    // A slot with no row is written as a placeholder rather than holding the
    // chunk back. Holding it back would make a slow dissector stall the
    // capture's write path, which is the coupling being removed; the frame's
    // bytes are on disk either way and are the source of truth.
    const packets = entries.map((e) => {
      if (e.packet !== null) return e.packet;
      this.counters.framesSealedWithoutRow += 1;
      return placeholderRow(e.id, e.tsUs, e.bytLength);
    });
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
    // Keyed off the SLOT's id, which exists whether or not a row ever did.
    for (const e of entries) this.stagedAt.delete(e.id);
    this.drained += count;
    if (this.drained > CHUNK_FRAMES * 4) this.compactStaging();
  }

  /** Drops the drained prefix and rebuilds the id map's indices. */
  private compactStaging(): void {
    this.staged.splice(0, this.drained);
    this.drained = 0;
    this.stagedAt.clear();
    for (let i = 0; i < this.staged.length; i++) this.stagedAt.set(this.staged[i].id, i);
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
