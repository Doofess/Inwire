/**
 * Running a filter over a capture that is not in memory.
 *
 * ## One evaluator, not two
 *
 * The tempting design is to evaluate against the **prefix block** - the
 * fixed-width record `chunkCodec.ts` writes beside every chunk, holding the
 * timestamp, both addresses in binary, both ports, the length, the status and
 * two bitmaps. A `DataView` scan over that is tens of nanoseconds a row where
 * decoding the summary is a couple of microseconds, and the plan this work
 * follows costed it at 0.19 s against 11.8 s for a 5 GB capture.
 *
 * It is not what this does, and the reason is not effort. A second evaluator
 * is a **second answer**: `filter/compile.ts` is a hundred operators, four
 * comparison semantics, multi-value fields, CIDR containment and the
 * dense/sparse split, and a filter that answered differently depending on
 * whether the frame happened to be in RAM would be worse than a slow one -
 * silently, and only on the frames nobody can see to check. `==` meaning
 * "contains" is the bug this codebase already fixed once.
 *
 * So the scan decodes the row and runs the **same compiled predicate the
 * in-memory filter runs** - and then the cost was measured rather than
 * assumed, which is the part that settles it.
 *
 * `scripts/capture/scan.ts`, over both fixtures: **1.61 and 1.64 us a frame**,
 * decode and predicate together. That is 0.61M frames a second, so a 5 GB
 * capture - 4.3M frames - filters in about **7 seconds**, against the 11.8 s
 * the plan costed for this route and with a progress bar and a cancel in front
 * of it. The accelerator is worth 7 seconds, not the second answer it would
 * cost, so it is not being built.
 *
 * If it ever is, the rule for it is already clear: it may **exclude** a row
 * from decoding and may never include one, so the answer stays this
 * evaluator's answer.
 *
 * ## Sliced, because the store has other work
 *
 * The store process also serves byte reads and row reads while a scan runs -
 * the reader is scrolling, and the detail pane is fetching. A scan that ran to
 * completion in one call would block both for as long as it took. `step()`
 * does whole chunks until a time budget is spent and returns whether there is
 * more, so the caller can yield between slices. A chunk is the smallest slice
 * because a chunk is one inflate and one decode; splitting inside it would
 * mean holding a decoded chunk across a yield for nothing.
 *
 * `redirect.ts` establishes the shape and the trap that goes with it: the
 * yield must not be `requestAnimationFrame`, which `redirect.ts` measured
 * firing **zero** times over 3.8 s in a backgrounded renderer - and which does
 * not exist at all in the store process, where this actually runs
 * (`captureHost.stepScan` yields on `setTimeout` through the serial queue). A
 * scan someone left running while they looked at something else would simply
 * stop.
 *
 * ## The result is a snapshot
 *
 * A `CaptureScan` covers the chunks that were sealed when it started, and says
 * so: `frameCount` is fixed at construction. A capture still running grows
 * underneath it, and the honest presentation of that is an ordered **prefix**
 * of the true answer rather than a number pretending to be final.
 */
import { MatchSet, MATCH_BLOCK_FRAMES, MATCH_BLOCK_WORDS } from './matchSet';
import type { CaptureIndex } from './captureIndex';
import type { CaptureReader } from './captureReader';
import type { Packet } from '../../types/packet';

export interface ScanProgress {
  chunksDone: number;
  chunkCount: number;
  framesDone: number;
  /** Frames the scan will cover. Fixed when it started. */
  frameCount: number;
  matches: number;
  /** True once every chunk has been visited, or the scan was cancelled. */
  done: boolean;
  cancelled: boolean;
}

/** How long one `step()` may run before handing the thread back. */
export const DEFAULT_SLICE_MS = 12;

export class CaptureScan {
  private readonly set: MatchSet;
  private chunk = 0;
  private framesDone = 0;
  private stopped = false;
  private sealed = false;

  readonly chunkCount: number;
  readonly frameCount: number;

  constructor(
    private readonly reader: CaptureReader,
    private readonly index: CaptureIndex,
    private readonly predicate: (packet: Packet) => boolean,
  ) {
    // The snapshot. Read once, here, so a chunk sealed while the scan runs
    // cannot move the denominator underneath the progress bar or leave the
    // bitmap a chunk short of the index it is indexed by.
    this.chunkCount = index.chunkCount;
    this.frameCount = index.frameCount;
    this.set = new MatchSet(this.frameCount);
    // From the floor: what a ring has deleted is not scanned, and counts as
    // done, so the bar measures the capture that is left (ADR 0052). A chunk
    // the floor passes while the scan runs reads as nothing, like a torn tail.
    this.chunk = index.floorChunk;
    this.framesDone = index.floorOrdinal;
  }

  /** Stops at the end of the current chunk. The partial result is discarded. */
  cancel(): void { this.stopped = true; }

  get progress(): ScanProgress {
    return {
      chunksDone: this.chunk,
      chunkCount: this.chunkCount,
      framesDone: this.framesDone,
      frameCount: this.frameCount,
      matches: this.set.count(),
      done: this.sealed || this.stopped,
      cancelled: this.stopped,
    };
  }

  /**
   * The matches, once the scan has finished.
   *
   * Null while it is still running or if it was cancelled: a half-built
   * `MatchSet` answers `count()` and refuses `ordinalAt`, and handing one out
   * would give a caller a confidently wrong row rather than an error.
   */
  get matches(): MatchSet | null { return this.sealed ? this.set : null; }

  /**
   * Scans whole chunks for up to `budgetMs`, and says whether more remains.
   *
   * The budget is checked **between** chunks, so one slice always does at
   * least one chunk - a budget smaller than a chunk takes longer overall
   * rather than making no progress, which is the failure a per-row check
   * would have.
   */
  step(budgetMs: number = DEFAULT_SLICE_MS): boolean {
    if (this.stopped || this.sealed) return false;
    const until = Date.now() + budgetMs;
    do {
      if (this.chunk >= this.chunkCount) {
        this.set.seal();
        this.sealed = true;
        return false;
      }
      this.scanChunk(this.chunk);
      this.chunk += 1;
    } while (Date.now() < until);
    // The last chunk may have finished the capture exactly on the budget.
    if (this.chunk >= this.chunkCount) {
      this.set.seal();
      this.sealed = true;
      return false;
    }
    return true;
  }

  /** Runs to completion. For a caller with nothing else to do - and tests. */
  runToCompletion(): MatchSet | null {
    while (this.step(Number.POSITIVE_INFINITY)) { /* one slice is the lot */ }
    return this.matches;
  }

  /**
   * Reused across chunks. Allocating 512 bytes per chunk would be nothing at
   * 4,096 frames and 1.4 MB of garbage over a 5 GB capture, for no reason.
   */
  private readonly bits = new Uint32Array(MATCH_BLOCK_WORDS);

  private scanChunk(chunk: number): void {
    const record = this.index.record(chunk);
    const packets = this.reader.readRows(chunk);
    // A chunk that cannot be read is a torn tail. Its bits stay clear, which
    // reads as "no frame here matched" - the same answer the reader gets from
    // a row it cannot show, and better than refusing the whole filter over
    // frames the capture genuinely lost.
    const first = record.firstOrdinal;

    // A `MatchSet` is blocked in fixed 4,096-frame units of the ORDINAL space,
    // and a capture's chunks are usually but not always the same thing: a
    // capture that was paused and resumed has a short chunk in the middle of
    // it, and every chunk after that one starts off the block boundary. So the
    // bulk path is taken only when this chunk IS a whole aligned block, and
    // the general path sets ordinals. Getting this wrong would not fail - it
    // would mark the wrong frames, in a filter nobody can check by eye.
    if (first % MATCH_BLOCK_FRAMES === 0 && packets.length === MATCH_BLOCK_FRAMES) {
      this.bits.fill(0);
      for (let i = 0; i < packets.length; i++) {
        if (this.predicate(packets[i])) this.bits[i >>> 5] |= 1 << (i & 31);
      }
      this.set.setChunk(first / MATCH_BLOCK_FRAMES, this.bits);
    } else {
      for (let i = 0; i < packets.length; i++) {
        if (this.predicate(packets[i])) this.set.set(first + i);
      }
    }
    this.framesDone += packets.length;
  }
}
