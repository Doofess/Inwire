/**
 * What the pipeline Worker owes, and is owed, on the live path - ADR 0053's
 * bounds, as arithmetic the Worker asks and a script can drive.
 *
 * Three ledgers, each the answer to a queue that used to grow without limit:
 *
 * 1. **Main's batches.** Each batch main posts carries an id
 *    (`electron/pipeCredit.ts`). Once every frame in it has been dissected -
 *    or the batch was dropped unread - its id goes back in `drained`, and
 *    main's credit for it returns. Frames from one batch can leave the
 *    ordering window across several flushes, so a batch is counted down
 *    frame by frame rather than acknowledged on arrival.
 * 2. **The store's appends.** Each `appendBytes` carries an id the store
 *    answers when the writer has taken the frames (`bytesTaken`). Past a
 *    budget the Worker stops releasing from its ordering window, so frames
 *    wait there - bounded, because main's credit stops with them - instead of
 *    in the store's inbound queue, which nothing bounded and which a real
 *    burst grew to the store's 2 GB heap guard.
 * 3. **The agent's sequence numbers.** The agent numbers every frame it puts
 *    in the capture's pcapng (ADR 0052), so a number the live stream never
 *    delivers is a frame that is in the file and not in the view. That is
 *    counted exactly, and a jump large enough to be a shed batch is marked
 *    on the first frame after it.
 */

/**
 * Frames the store may owe an answer for before the Worker stops releasing.
 *
 * 50,000 frames is about 55 MB of bytes at 1.1 kB a frame, against the
 * store's 2 GB heap guard, and under a second of its work at the 67,000
 * frames a second it was measured to take - so it never delays a store that
 * keeps up, and stops one that does not long before its heap is in danger.
 */
export const STORE_BACKLOG_FRAMES = 50_000;

/**
 * Rows the app may not yet have committed before the Worker stops releasing:
 * about two seconds of what its main thread was measured to take at the top
 * rate (ADR 0053 phase 3), and under 100 MB of rows.
 */
export const RENDERER_BACKLOG_FRAMES = 60_000;

/**
 * The smallest jump in sequence numbers marked as a hole on a frame.
 *
 * Not 1, because the agent pushes a frame onto its live queue after it lets
 * go of the lock that numbered it (`agent-rs/src/runtime.rs`), so two
 * adapters' frames can arrive a few places out of order and the late one
 * fills the gap a moment later. Shedding drops whole batches - main's and the
 * agent's both - and a batch is hundreds of frames when anything is shed at
 * all, so 16 tells the two apart. The COUNT of skipped frames is exact either
 * way; only the per-frame note waits for a gap this large.
 */
export const HOLE_MIN_FRAMES = 16;

/**
 * How far below the next number a skew gap is remembered, waiting for the
 * late frame that fills it. A frame later than this is not two adapters'
 * race, and its gap is only counted, as before (#18).
 */
export const LATE_WINDOW = 64;

export class LiveFlow {
  /** Main's batch id to the frames in it not yet dissected. */
  private readonly remaining = new Map<number, number>();
  private completed: number[] = [];

  private firstSeq: number | null = null;
  /** One past the highest sequence number seen. */
  private nextSeq = 0;
  private received = 0;
  /** Frames known skipped since the last frame delivered, waiting to be marked on the next. */
  private unmarked = 0;
  /**
   * Numbers below `nextSeq` a skew gap left and no frame has filled yet. The
   * late frame usually comes; at the edge of a shed batch it was in it (#18).
   */
  private readonly late = new Set<number>();

  private storeOwed = 0;
  private readonly storeAcks = new Map<number, number>();
  private nextAck = 1;
  /**
   * Whether this store answers at all. A store from before `bytesTaken`
   * never would, and gating on it would stop the live view for ever - so the
   * gate engages only once an answer has been seen.
   */
  private storeAnswers = false;

  // -- main's batches ---------------------------------------------------------

  /** A batch arrived with `frames` frames headed for the ordering window. */
  batchArrived(batch: number | undefined, frames: number): void {
    if (batch === undefined) return;
    if (frames <= 0) { this.completed.push(batch); return; }
    this.remaining.set(batch, (this.remaining.get(batch) ?? 0) + frames);
  }

  /** A batch that will never be dissected: not capturing, or unreadable. */
  batchDropped(batch: number | undefined): void {
    if (batch === undefined) return;
    this.remaining.delete(batch);
    this.completed.push(batch);
  }

  /** One frame of `batch` has been dissected, or dropped from the window. */
  frameDone(batch: number | undefined): void {
    if (batch === undefined) return;
    const left = this.remaining.get(batch);
    if (left === undefined) return;
    if (left <= 1) {
      this.remaining.delete(batch);
      this.completed.push(batch);
    } else {
      this.remaining.set(batch, left - 1);
    }
  }

  /** The batches completed since the last call, for main. */
  takeCompleted(): number[] {
    const out = this.completed;
    this.completed = [];
    return out;
  }

  /**
   * Every batch still owed is given up - the ordering window was cleared, so
   * its frames will never be dissected and main must not wait for them.
   */
  abandonBatches(): void {
    for (const batch of this.remaining.keys()) this.completed.push(batch);
    this.remaining.clear();
  }

  // -- the agent's sequence numbers --------------------------------------------

  /**
   * A frame's sequence number, in the order frames arrived. Returns the size
   * of the hole just before it when that is large enough to mark, else 0.
   */
  seqArrived(seq: number): number {
    if (this.firstSeq === null || seq < this.firstSeq) {
      // The first frame of a capture, or a numbering that started again (a
      // restarted agent): a new run, with nothing skipped yet.
      this.firstSeq = seq;
      this.nextSeq = seq + 1;
      this.received = 1;
      this.unmarked = 0;
      this.late.clear();
      return 0;
    }
    this.received++;
    const skew = Math.max(0, seq - this.nextSeq);
    if (skew > 0 && skew < HOLE_MIN_FRAMES) for (let n = this.nextSeq; n < seq; n++) this.late.add(n);
    else if (skew === 0 && this.late.size > 0) this.late.delete(seq);
    // A known loss is marked however small; only a skew gap waits to be filled.
    const known = this.unmarked;
    const gap = skew + known;
    this.unmarked = 0;
    if (seq + 1 > this.nextSeq) this.nextSeq = seq + 1;
    if (this.late.size > 0) for (const n of this.late) if (n < this.nextSeq - LATE_WINDOW) this.late.delete(n);
    return gap >= HOLE_MIN_FRAMES || known > 0 ? gap : 0;
  }

  /**
   * The numbers in [`from`, `below`) a skew gap left and no frame has filled,
   * given up here: a catch-up reads them from the file, or the shed batch
   * held them and the caller marks them (`noteLost`).
   */
  takeLate(from: number, below: number): number[] {
    const out: number[] = [];
    for (const n of this.late) if (n >= from && n < below) out.push(n);
    for (const n of out) this.late.delete(n);
    return out.sort((a, b) => a - b);
  }

  /**
   * Frames already counted as skipped that are now known lost: marked on the
   * next frame delivered, however few.
   */
  noteLost(frames: number): void {
    if (frames > 0) this.unmarked += frames;
  }

  /**
   * Main shed a batch of `frames` frames starting at `firstSeq`. Counted now -
   * a gap the numbering would only reveal when a later frame arrived, and at
   * the end of a burst none may - and marked on the next frame that does.
   */
  noteShed(firstSeq: number, frames: number): void {
    if (frames <= 0) return;
    if (this.firstSeq === null) {
      // Shed before anything arrived: the run starts at what was shed.
      this.firstSeq = firstSeq;
      this.nextSeq = firstSeq;
      this.received = 0;
    }
    const end = firstSeq + frames;
    if (end > this.nextSeq) {
      this.unmarked += end - Math.max(firstSeq, this.nextSeq);
      this.nextSeq = end;
    }
  }

  /**
   * The agent's first `capture_boundary` of a capture: where its numbering
   * begins. The agent sends it ahead of any frame in the file, so frames
   * missing at the start - dropped before the Worker kept any - are a hole
   * like any other, not a run that began later. Until a frame has arrived it
   * is only a seed, and the agent's own boundary replaces one left from
   * before; after, a higher one says nothing new and a lower one is a
   * restarted agent's new run, as in `seqArrived`.
   */
  captureBegins(firstSeq: number): void {
    if (this.firstSeq !== null && this.received > 0 && firstSeq >= this.firstSeq) return;
    this.firstSeq = firstSeq;
    this.nextSeq = firstSeq;
    this.received = 0;
    this.unmarked = 0;
    this.late.clear();
  }

  /**
   * The next sequence number the stream owes, or null before the first frame
   * of a capture. A frame numbered well past it is the far side of a hole.
   */
  get expectedSeq(): number | null {
    return this.firstSeq === null ? null : this.nextSeq;
  }

  /** Frames the agent numbered and the live stream has not delivered. */
  get skippedFrames(): number {
    if (this.firstSeq === null) return 0;
    return Math.max(0, this.nextSeq - this.firstSeq - this.received);
  }

  /** A new capture: its numbering starts again. */
  startCapture(): void {
    this.firstSeq = null;
    this.nextSeq = 0;
    this.received = 0;
    this.unmarked = 0;
    this.late.clear();
  }

  // -- the store ----------------------------------------------------------------

  /** An `appendBytes` of `frames` frames is about to go: the id it carries. */
  storeSent(frames: number): number {
    const id = this.nextAck++;
    this.storeAcks.set(id, frames);
    this.storeOwed += frames;
    return id;
  }

  /** The store's `bytesTaken` for an append. */
  storeTaken(id: number): void {
    this.storeAnswers = true;
    const frames = this.storeAcks.get(id);
    if (frames === undefined) return;
    this.storeAcks.delete(id);
    this.storeOwed -= frames;
  }

  /** Whether the Worker must hold frames in its window until the store catches up. */
  get storeBehind(): boolean {
    return this.storeAnswers && this.storeOwed >= STORE_BACKLOG_FRAMES;
  }

  /** Frames the store has not answered for, for a readout. */
  get storeOwedFrames(): number {
    return this.storeOwed;
  }

  /**
   * A new store port, or a capture closed: nothing it owed will be answered
   * on this ledger. Whether the store answers is kept - it is the same store.
   */
  forgetStore(): void {
    this.storeAcks.clear();
    this.storeOwed = 0;
  }

  // -- the renderer -------------------------------------------------------------

  private rowsOwed = 0;
  /** As `storeAnswers`: the gate engages only once the renderer has answered. */
  private rendererAnswers = false;

  /** A flush of `frames` rows was posted to the app. */
  rowsPosted(frames: number): void {
    this.rowsOwed += frames;
  }

  /** The app committed `frames` of them to its buffer. */
  rowsTaken(frames: number): void {
    this.rendererAnswers = true;
    this.rowsOwed = Math.max(0, this.rowsOwed - frames);
  }

  /**
   * Whether the Worker must hold frames until the window catches up.
   *
   * The queue phase 1 left unbounded, because nothing could fill it then: the
   * single Worker was slower than the window. With shards it is faster, and at
   * 60,000 frames a second the main thread fell 400,000 rows behind in 16 s
   * with nothing shed - rows waiting in its message queue and its arrival
   * queue, in its heap. Held here instead, the Worker falls behind, main
   * sheds, and the status bar counts what was skipped.
   */
  get rendererBehind(): boolean {
    return this.rendererAnswers && this.rowsOwed >= RENDERER_BACKLOG_FRAMES;
  }

  /** A cleared buffer: rows posted before it are not owed. */
  forgetRenderer(): void {
    this.rowsOwed = 0;
  }
}
