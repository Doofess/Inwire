import { BYTES_RESIDENT_FRAMES, estimateSummaryBytes } from './bufferBudget';
import type { Packet } from '../types/packet';

/**
 * What a tail row holds once its bytes have gone: empty, which is all
 * `hasBytes` in `packetBytes.ts` asks. Not imported from there, so this module
 * does not pull the store client in.
 */
const RELEASED_BYTES = new Uint8Array(0);

/**
 * The RAM tail of a streamed import: the newest frames, bounded as it goes.
 *
 * The tail rather than the head, which is the opposite of what the cap used to
 * keep and is the right way round now. With the rest on disk the buffer is a
 * **window**, and the window a reader wants first is the end of the capture,
 * the same one a live capture leaves them at.
 *
 * Lifted out of `readStreamedCapture` so an import Worker keeps the same tail
 * by the same rules.
 */
export class ImportTail {
  private readonly tail: Packet[] = [];
  // Each tail row's estimate, parallel to `tail`, so dropping a row subtracts
  // what it added without estimating it again.
  private readonly sizes: number[] = [];
  private tailBytes = 0;
  // How many of the tail's oldest rows have let their bytes go. The budget does
  // not count raw bytes; they stay for the newest BYTES_RESIDENT_FRAMES only, as
  // in the live buffer, and older frames read theirs from the store. Kept on
  // every row, a tail of full-size frames held a 2.7 GB file's bytes (#20).
  private released = 0;

  constructor(private readonly limits: { residentBytes: number; maxFrames: number }) {}

  /**
   * Adds a batch and trims. Trimmed as it goes, not at the end: holding the
   * whole capture to slice the last slab off it is the memory this route exists
   * to avoid. Both bounds hold, one frame always stays, and the head goes in one
   * splice. `sizes`, when given, is one entry per row and is used instead of
   * estimating.
   */
  push(batch: Packet[], sizes?: readonly number[]): void {
    for (let i = 0; i < batch.length; i++) {
      const packet = batch[i];
      // `sizes`: what the sender measured where the row was dissected (an import
      // Worker's); the page holds the decoded row, which is not measured again.
      const size = sizes === undefined ? estimateSummaryBytes(packet) : sizes[i];
      this.tail.push(packet);
      this.sizes.push(size);
      this.tailBytes += size;
    }
    let drop = 0;
    while (
      this.tail.length - drop > 1
      && (this.tailBytes > this.limits.residentBytes || this.tail.length - drop > this.limits.maxFrames)
    ) {
      this.tailBytes -= this.sizes[drop];
      drop++;
    }
    if (drop > 0) {
      this.tail.splice(0, drop);
      this.sizes.splice(0, drop);
      this.released = Math.max(0, this.released - drop);
    }
  }

  /**
   * Lets go of the bytes of the oldest rows the store can now supply, through
   * frame id `id`. Called after the batch reached the store: its append copies
   * the packet object there and then, so this reaches only the tail's. Rows are
   * in id order, so the first one not yet stored ends the pass and the next call
   * tries again. Never called, nothing is released - a tail that keeps every
   * byte is safe, one that lets go of bytes held nowhere is not.
   */
  releaseBytesThrough(id: number): void {
    const { tail } = this;
    for (
      ;
      this.released < tail.length - BYTES_RESIDENT_FRAMES && tail[this.released].id <= id;
      this.released++
    ) {
      tail[this.released].rawBytes = RELEASED_BYTES;
    }
  }

  /** The tail's rows, oldest first: the live array, not a copy. */
  rows(): Packet[] { return this.tail; }

  /** How many rows the tail holds. */
  get length(): number { return this.tail.length; }

  /** Each row's `estimateSummaryBytes`, parallel to `rows()`. */
  estimates(): number[] { return this.sizes; }
}
