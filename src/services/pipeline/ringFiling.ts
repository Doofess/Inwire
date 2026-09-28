/**
 * Which of the agent's ring files each live frame is in (ADR 0052).
 *
 * The agent tells its owner where every file begins - `capture_boundary`,
 * "frames from `firstSeq` on are in file `index`" - before the first frame in
 * it, so a frame can be filed the moment it arrives, by its sequence number.
 * The capture store starts a segment per file and deletes segments when the
 * agent deletes files (`services/capture/segments.ts`); this is the half that
 * says which file a frame belongs to.
 *
 * **By sequence number, at arrival, and never by arrival order.** Frames reach
 * the store in capture-time order, out of the ordering window, and two
 * adapters' frames cross there - so "the frames after the boundary message"
 * is not a set this could ever name. A sequence number is.
 *
 * **An epoch per run of the agent's capture.** The agent numbers files from 1
 * and sequence numbers from 0 each time a capture starts, including when the
 * app starts one again after the agent restarted - so "file 3" and "seq 5,000"
 * mean nothing without saying which run. A file 1 starts a new epoch.
 */
import type { RingPart } from '../capture/segments';

export class RingFiling {
  private epochNow = 0;
  /** This run's files, oldest first: where each begins. */
  private starts: { index: number; firstSeq: number }[] = [];

  /** The run a `capture_file` report from the agent is about: the newest. */
  get epoch(): number { return this.epochNow; }

  /** A `capture_boundary`: frames from `firstSeq` on are in file `index`. */
  boundary(index: number, firstSeq: number): void {
    const last = this.starts[this.starts.length - 1];
    // File 1 is a new run. So is a file numbered at or below the last - which
    // an agent that restarted between two boundaries would send.
    if (index === 1 || last === undefined || index <= last.index) {
      this.epochNow += 1;
      this.starts = [];
    }
    this.starts.push({ index, firstSeq });
  }

  /**
   * The file a frame with this sequence number is in, or undefined when no
   * boundary has said - an agent that writes no ring, or a frame from before
   * this run's first file.
   */
  partOf(seq: number): RingPart | undefined {
    // From the newest: almost every frame is in the file being written, and
    // the rest in the one before it.
    for (let i = this.starts.length - 1; i >= 0; i--) {
      const start = this.starts[i];
      if (seq >= start.firstSeq) return { epoch: this.epochNow, file: start.index, seq };
    }
    return undefined;
  }
}
