/**
 * The frames' sizes through one of the agent's files, as they pass on to be
 * dissected, so a catch-up can jump to its hole instead of counting every
 * frame before it (#17). A frame's place is the file's first EPB plus the
 * EPBs before it.
 *
 * Frames pass in runs. A gap the stream never fills ends one: a clear while
 * catching up, a few frames the agent's queue shed, a catch-up that stopped
 * short. A run after a gap knows its own lengths but not where it starts,
 * until a read of the file counts across the gap and finds it (`learn`). A
 * gap is only ever crossed, never guessed across.
 */

/** Runs kept per file; past it the oldest after the first goes, which only makes a jump land earlier. */
export const RUNS_MAX = 64;

interface Run {
  /** The first frame of the run, and one past its last. */
  from: number;
  next: number;
  /** Where `from` starts, in bytes past the file's first EPB, once known. */
  rel: number | null;
  /** The run's EPB bytes, and the length of its last. */
  sum: number;
  lastLen: number;
}

/** A frame's place in its file: `rel` bytes past the first EPB. */
export interface SizedPoint {
  seq: number;
  rel: number;
}

export class FrameSizes {
  private readonly runs: Run[] = [];

  constructor(readonly index: number, readonly firstSeq: number) {}

  /** Frame `seq` passed, an EPB of `len` bytes. In order, or near it: two adapters' skew. */
  add(seq: number, len: number): void {
    const runs = this.runs;
    const last = runs[runs.length - 1];
    if (last !== undefined && seq === last.next) {
      last.next++;
      last.sum += len;
      last.lastLen = len;
      return;
    }
    if (seq < this.firstSeq) return;
    let at = runs.length;
    while (at > 0 && runs[at - 1].from > seq) at--;
    const before = runs[at - 1];
    if (before !== undefined && seq < before.next) return;
    let run: Run;
    if (before !== undefined && before.next === seq) {
      run = before;
      run.next++;
      run.sum += len;
      run.lastLen = len;
      at--;
    } else {
      run = { from: seq, next: seq + 1, rel: seq === this.firstSeq ? 0 : null, sum: len, lastLen: len };
      runs.splice(at, 0, run);
    }
    const after = runs[at + 1];
    if (after !== undefined && after.from === run.next) {
      if (run.rel === null && after.rel !== null) run.rel = after.rel - run.sum;
      run.sum += after.sum;
      run.next = after.next;
      run.lastLen = after.lastLen;
      runs.splice(at + 1, 1);
    }
    if (runs.length > RUNS_MAX) runs.splice(1, 1);
  }

  /**
   * Where to read from to reach `anchorSeq`: the anchor's own place, or the
   * end of the last run before it whose place is known - a gap to count
   * across from there. Null when no run before it is placed.
   */
  point(anchorSeq: number): SizedPoint | null {
    for (let k = this.runs.length - 1; k >= 0; k--) {
      const run = this.runs[k];
      if (run.rel === null || run.from > anchorSeq) continue;
      if (anchorSeq === run.next - 1) return { seq: anchorSeq, rel: run.rel + run.sum - run.lastLen };
      if (anchorSeq >= run.next) return { seq: run.next, rel: run.rel + run.sum };
      return { seq: run.from, rel: run.rel };
    }
    return null;
  }

  /** The first run from `seq` up to `anchorSeq` whose place is not known: where a count crossing a gap learns it. */
  unplacedFrom(seq: number, anchorSeq: number): number | null {
    for (const run of this.runs) {
      if (run.from >= seq && run.from <= anchorSeq && run.rel === null) return run.from;
    }
    return null;
  }

  /** A read of the file found frame `seq`, the first of a run, at `rel`. */
  learn(seq: number, rel: number): void {
    const run = this.runs.find((r) => r.from === seq);
    if (run !== undefined && run.rel === null) run.rel = rel;
  }
}
