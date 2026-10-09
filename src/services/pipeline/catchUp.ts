/**
 * Catching the live view up from the agent's pcapng, so a burst that outruns
 * the app leaves no hole in it (ADR 0053 phase 4).
 *
 * The live stream is best-effort and the file is the truth: the agent numbers
 * every frame and writes it into the capture's pcapng before it puts it on the
 * pipe, under one lock, so **a frame is in the file exactly when it has a
 * sequence number** (`agent-rs/src/runtime.rs`). When the stream skips -
 * main shed batches the Worker owed it too much for, or the agent's own queue
 * shed them - the frames from the first one missing are read back out of the
 * file instead, dissected in order through the same path, and the view
 * rejoins the live stream once the file has reached it.
 *
 * ## How a file frame gets its sequence number
 *
 * The file's EPBs carry none (dumpcap writes none, and the agent writes what
 * dumpcap writes). What the app has is `capture_boundary`: "frames from
 * `firstSeq` on are in file `index`". Within a file the frames are in sequence
 * order with none missing, so **the k-th packet of a file is `firstSeq + k`**.
 *
 * That holds unless the agent's file writer refused a frame because the disk
 * fell behind (`droppedWriter`, reported, never silent there) - then every
 * frame after it is numbered one too low. So the counting is checked, twice,
 * against frames the live stream DID deliver: the last frame before the hole
 * must be the file's frame of that number (`Anchor`), and the first live frame
 * the view rejoins at must be the file's frame of that number. A first check
 * that fails means nothing was read from the file at all - the hole is marked
 * as it was before this existed. A second that fails is counted
 * (`misaligned`) and catch-up is off for the rest of the capture.
 *
 * ## Rejoining
 *
 * While catching up, live frames from the hole on are dropped - the file has
 * them, and dropping them answers main's credit, so main stops shedding. Once
 * the file is within `REJOIN_WITHIN` frames of the newest live frame, live
 * frames are held instead, from the next one on (`holdFrom`), and when the
 * file reaches `holdFrom` the held frames are handed back and the view is live
 * again. The file lags the stream by up to about a second (the agent flushes
 * it once a second), which is what the hold covers; held frames are bounded,
 * and past the bound they are dropped and the hold starts again later.
 *
 * Pure: the Worker does the reading and the dissecting, and
 * `scripts/pipeline/catch-up.ts` drives every path here with no Worker.
 */
import { PcapngTail, type TailFrame } from './pcapngTail';

/** Within this many frames of live, live frames are held for the rejoin. */
export const REJOIN_WITHIN = 20_000;
/** The most live frames held while the file catches up to them. */
export const HOLD_MAX_FRAMES = 100_000;
/** ...and the most bytes, which main's credit also counts (256 MB). */
export const HOLD_MAX_BYTES = 96 * 1024 * 1024;
/** One read of the file. */
export const READ_BYTES = 4 * 1024 * 1024;
/** How long to wait before reading a file again that had nothing new. */
export const RETRY_MS = 150;

/** What catch-up needs of a live frame. */
export interface SeqFrame {
  seq: number;
  tsUs: number;
  tsNsRem: number;
  origLen: number;
  bytes: Uint8Array;
}

/** The last frame before a hole, which the file's frame of that number must be. */
export interface Anchor {
  seq: number;
  tsUs: number;
  tsNsRem: number;
  origLen: number;
  capLen: number;
}

export function anchorOf(frame: SeqFrame): Anchor {
  return { seq: frame.seq, tsUs: frame.tsUs, tsNsRem: frame.tsNsRem, origLen: frame.origLen, capLen: frame.bytes.length };
}

/** A frame read from the file, numbered. */
export interface FileFrame extends TailFrame {
  seq: number;
}

// --- the agent's files ------------------------------------------------------

interface FileFacts {
  index: number;
  name: string | null;
  firstSeq: number | null;
  closed: boolean;
  deleted: boolean;
}

/**
 * What the agent has said about this capture's files: where each begins
 * (`capture_boundary`), what it is called and whether it is finished or gone
 * (`capture_file`). One run of the agent's capture at a time, the rule
 * `ringFiling.ts` keeps: a file 1, or a number at or below the last, starts
 * again.
 */
export class CaptureFiles {
  private files = new Map<number, FileFacts>();
  private highest = 0;

  reset(): void {
    this.files.clear();
    this.highest = 0;
  }

  private facts(index: number): FileFacts {
    let facts = this.files.get(index);
    if (facts === undefined) {
      facts = { index, name: null, firstSeq: null, closed: false, deleted: false };
      this.files.set(index, facts);
      if (index > this.highest) this.highest = index;
    }
    return facts;
  }

  boundary(index: number, firstSeq: number): void {
    const known = this.files.get(index);
    if (index === 1 && known?.firstSeq !== null && known?.firstSeq !== undefined) this.reset();
    else if (index < this.highest && known === undefined) this.reset();
    this.facts(index).firstSeq = firstSeq;
  }

  file(index: number, name: string, state: 'open' | 'closed' | 'deleted', firstSeq: number | null): void {
    // An `open` for file 1 after file 1 already held frames is a new run.
    const known = this.files.get(index);
    if (state === 'open' && index === 1 && known !== undefined && known.firstSeq !== null) this.reset();
    const facts = this.facts(index);
    facts.name = name;
    if (firstSeq !== null && facts.firstSeq === null) facts.firstSeq = firstSeq;
    if (state === 'closed') facts.closed = true;
    if (state === 'deleted') { facts.closed = true; facts.deleted = true; }
  }

  /** A read found the file gone before the agent said so. */
  gone(index: number): void {
    const facts = this.files.get(index);
    if (facts !== undefined) { facts.closed = true; facts.deleted = true; }
  }

  /** The file a frame of this number is in: the newest that starts at or before it. */
  holding(seq: number): FileFacts | undefined {
    let best: FileFacts | undefined;
    for (const facts of this.files.values()) {
      if (facts.firstSeq === null || facts.firstSeq > seq) continue;
      if (best === undefined || facts.index > best.index) best = facts;
    }
    return best;
  }

  /** The file after this one, once the agent has said where it begins. */
  after(index: number): FileFacts | undefined {
    const next = this.files.get(index + 1);
    return next !== undefined && next.firstSeq !== null ? next : undefined;
  }

  get(index: number): FileFacts | undefined {
    return this.files.get(index);
  }
}

// --- catching up --------------------------------------------------------------

export type LiveVerdict = 'take' | 'hold' | 'drop';

/** Why catch-up stopped without rejoining. */
export type CatchUpEnd = 'noFile' | 'anchorMismatch' | 'misaligned' | 'unreadable';

export interface ReadRequest {
  /** The file's name, as the agent gave it - never a path. */
  name: string;
  offset: number;
  length: number;
}

export interface ReadResult<F> {
  /** Frames to dissect, in file order. */
  frames: FileFrame[];
  /** The view is live again: these held frames go next, after `frames`. */
  rejoin: F[] | null;
  /** Catch-up gave up: what it held goes back to the live path, and the hole is marked there. */
  ended: { why: CatchUpEnd; held: F[] } | null;
  /** Nothing new in the file: ask again after this long. */
  retryMs?: number;
}

/** Where reading a file had got to, kept between catch-ups. */
interface Cursor {
  index: number;
  name: string;
  tail: PcapngTail;
  /** The number of the next packet `tail` will give. */
  next: number;
}

export class CatchUp<F extends SeqFrame> {
  private on = false;
  private disabled: CatchUpEnd | null = null;
  private cursor: Cursor | null = null;
  private anchor: Anchor | null = null;
  /** The first frame number the file must deliver. */
  private from = 0;
  /** Where this catch-up's hole began: live frames before it are still dissected live. */
  private sessionFrom = 0;
  private inFlight = false;
  /** One past the newest live frame seen while catching up, and its time. */
  private edge = 0;
  private edgeUs = 0;
  private lastFileUs = 0;
  private held: F[] = [];
  private heldBytes = 0;
  private holdFrom: number | null = null;
  /** Held frames given up when the hold overflowed: the caller returns their credit. */
  private dropped: F[] = [];
  /** Frames numbered before this were read from the file; a late live copy is a duplicate. */
  private coveredBelow = 0;
  private coveredFrom = 0;

  /** Counts, for a readout and the tests. */
  readonly stats = { started: 0, rejoined: 0, framesRead: 0, ended: 0, misaligned: 0, holdOverflows: 0 };

  constructor(private readonly files: CaptureFiles) {}

  get active(): boolean {
    return this.on;
  }

  /** Why catch-up is off for the rest of this capture, if it is. */
  get off(): CatchUpEnd | null {
    return this.disabled;
  }

  /** A new capture: numbering, files and the cursor start again. */
  reset(): void {
    this.on = false;
    this.disabled = null;
    this.cursor = null;
    this.anchor = null;
    this.inFlight = false;
    this.held = [];
    this.heldBytes = 0;
    this.holdFrom = null;
    this.dropped = [];
    this.coveredBelow = 0;
    this.coveredFrom = 0;
  }

  /**
   * The live stream skipped from `fromSeq` on. True when catch-up started;
   * false when it cannot - no file says it holds those frames, or catch-up was
   * turned off for this capture - and the caller marks the hole instead.
   */
  start(fromSeq: number, anchor: Anchor | null): boolean {
    if (this.on) return true;
    if (this.disabled !== null) return false;
    let want = anchor !== null && anchor.seq === fromSeq - 1 ? anchor.seq : fromSeq;
    let file = this.files.holding(want);
    // A ring file deleted already: its frames are lost to the view, and the
    // catch-up begins with the next file the agent still has - the hole up
    // to it is marked on its first frame.
    let skipped = false;
    while (file !== undefined && file.deleted) {
      file = this.files.after(file.index);
      skipped = true;
    }
    if (file === undefined || file.name === null) return false;
    if (skipped) { want = file.firstSeq!; anchor = null; }
    // A cursor left exactly where this hole begins - the last catch-up rejoined
    // at the frame before it, which it checked - is carried on with no anchor.
    const resume = this.cursor !== null && this.cursor.index === file.index && this.cursor.next === fromSeq;
    if (!resume && (this.cursor === null || this.cursor.index !== file.index || this.cursor.next > want)) {
      this.cursor = { index: file.index, name: file.name, tail: new PcapngTail(0), next: file.firstSeq! };
    }
    this.on = true;
    this.from = fromSeq;
    this.sessionFrom = fromSeq;
    this.anchor = !resume && anchor !== null && anchor.seq === fromSeq - 1 ? anchor : null;
    this.edge = fromSeq;
    this.edgeUs = anchor?.tsUs ?? 0;
    this.lastFileUs = anchor?.tsUs ?? 0;
    this.stats.started++;
    return true;
  }

  /**
   * A live frame, while catching up: dissect it (`take`, a frame from before
   * the hole arriving late), keep it for the rejoin (`hold`), or drop it -
   * the file has it.
   */
  live(frame: F): LiveVerdict {
    if (!this.on) {
      // Live, but a late copy of a frame the file already delivered.
      return frame.seq >= this.coveredFrom && frame.seq < this.coveredBelow ? 'drop' : 'take';
    }
    if (frame.seq < this.sessionFrom) return 'take';
    if (frame.seq + 1 > this.edge) {
      this.edge = frame.seq + 1;
      this.edgeUs = frame.tsUs;
    }
    if (this.holdFrom === null) {
      // Not from a frame the file has already delivered - a live stream
      // running behind its own file - or the rejoin would wait for it for ever.
      if (this.edge - this.from > REJOIN_WITHIN || frame.seq < this.from) return 'drop';
      this.holdFrom = frame.seq;
    }
    if (frame.seq < this.holdFrom) return 'drop';
    if (this.held.length >= HOLD_MAX_FRAMES || this.heldBytes + frame.bytes.length > HOLD_MAX_BYTES) {
      // The file is not catching up to the hold fast enough: let it go and
      // start again later. Every frame in it is in the file.
      this.stats.holdOverflows++;
      for (const f of this.held) this.dropped.push(f);
      this.held = [];
      this.heldBytes = 0;
      this.holdFrom = null;
      return 'drop';
    }
    this.held.push(frame);
    this.heldBytes += frame.bytes.length;
    return 'hold';
  }

  /** Held frames given up since the last call, whose credit the caller returns. */
  takeDropped(): F[] {
    const out = this.dropped;
    this.dropped = [];
    return out;
  }

  /** The next read to ask main for, or null while one is out or there is nothing to read. */
  wantRead(): ReadRequest | null {
    if (!this.on || this.inFlight || this.cursor === null) return null;
    this.inFlight = true;
    return { name: this.cursor.name, offset: this.cursor.tail.readOffset, length: READ_BYTES };
  }

  /**
   * Main's answer to the last read: the bytes, or that the file is gone, or
   * that it could not be read at all.
   */
  readDone(result: { bytes: Uint8Array | null; gone: boolean; error?: string }): ReadResult<F> {
    this.inFlight = false;
    const out: ReadResult<F> = { frames: [], rejoin: null, ended: null };
    if (!this.on || this.cursor === null) return out;
    const cursor = this.cursor;
    if (result.error !== undefined) return this.end('unreadable', out);
    if (result.gone) {
      // The ring deleted it under us: its frames are lost to the view, and
      // the hole they leave is marked where the next file's frames begin.
      this.files.gone(cursor.index);
      const next = this.files.after(cursor.index);
      if (next === undefined || next.name === null) return this.end('noFile', out);
      this.cursor = { index: next.index, name: next.name, tail: new PcapngTail(0), next: next.firstSeq! };
      out.retryMs = 0;
      return out;
    }
    const bytes = result.bytes ?? new Uint8Array(0);
    cursor.tail.push(bytes);
    let frame;
    try {
      while ((frame = cursor.tail.next(cursor.next >= this.from - 1)) !== null) {
        const seq = cursor.next++;
        if (this.anchor !== null && seq === this.anchor.seq) {
          if (!sameFrame(frame, this.anchor)) return this.end('anchorMismatch', out);
          this.anchor = null;
          continue;
        }
        if (seq < this.from) continue;
        // The file has reached the live frames held for it: rejoin there.
        //
        // Found by content as well as by number. A frame the agent's writer
        // refused leaves every later one numbered too low, so the first held
        // frame turns up at a number below `holdFrom` - and rejoining there,
        // rather than at the number, is what keeps it from being dissected
        // twice. Anything else is a file that cannot be counted.
        const first = this.held[0];
        const isFirst = first !== undefined && sameBytes(frame, first);
        if (!isFirst && this.holdFrom !== null && seq >= this.holdFrom) {
          this.stats.misaligned++;
          return this.end('misaligned', out);
        }
        if (isFirst) {
          if (seq !== first.seq) {
            this.stats.misaligned++;
            this.disabled = 'misaligned';
          }
          this.coveredFrom = this.sessionFrom;
          this.coveredBelow = first.seq;
          out.rejoin = this.held;
          this.held = [];
          this.heldBytes = 0;
          this.holdFrom = null;
          this.on = false;
          this.stats.rejoined++;
          return out;
        }
        this.lastFileUs = frame.tsUs;
        this.stats.framesRead++;
        out.frames.push({ ...frame, seq });
        this.from = seq + 1;
      }
    } catch {
      return this.end('unreadable', out);
    }
    if (out.frames.length === 0 && bytes.length === 0) {
      // Nothing new: the end of a file the agent has finished moves on to the
      // next one, and the end of the one it is writing waits for its next
      // flush.
      const facts = this.files.get(cursor.index);
      const next = this.files.after(cursor.index);
      if (facts?.closed && next !== undefined && next.name !== null && cursor.tail.pending === 0) {
        if (next.firstSeq !== cursor.next) {
          // The finished file did not hold every frame up to where the next
          // begins - it stopped early, or a frame was refused - so counting
          // into the next would be off; a hole is marked rather than guessed.
          return this.end('misaligned', out);
        }
        this.cursor = { index: next.index, name: next.name, tail: new PcapngTail(0), next: next.firstSeq };
        out.retryMs = 0;
      } else {
        out.retryMs = RETRY_MS;
      }
    }
    return out;
  }

  /**
   * Stop now - the capture stopped. What was held goes back to the live path,
   * where the frames between are counted and marked as skipped.
   */
  abort(): F[] {
    if (!this.on) return [];
    const held = this.held;
    this.on = false;
    this.inFlight = false;
    this.held = [];
    this.heldBytes = 0;
    this.holdFrom = null;
    this.anchor = null;
    return held;
  }

  /** How far the view is behind live, in frames and capture time. */
  status(): { toGo: number; behindMs: number } {
    if (!this.on || this.cursor === null) return { toGo: 0, behindMs: 0 };
    return {
      toGo: Math.max(0, this.edge - this.from),
      behindMs: Math.max(0, Math.round((this.edgeUs - this.lastFileUs) / 1000)),
    };
  }

  private end(why: CatchUpEnd, out: ReadResult<F>): ReadResult<F> {
    const held = this.abort();
    // Counting is not to be trusted for the rest of this capture.
    if (why === 'anchorMismatch' || why === 'misaligned' || why === 'unreadable') this.disabled = why;
    this.cursor = null;
    this.stats.ended++;
    out.ended = { why, held };
    return out;
  }
}

function sameFrame(frame: TailFrame, anchor: Anchor): boolean {
  return frame.tsUs === anchor.tsUs && frame.tsNsRem === anchor.tsNsRem
    && frame.origLen === anchor.origLen && frame.capLen === anchor.capLen;
}

function sameBytes(frame: TailFrame, live: SeqFrame): boolean {
  if (frame.tsUs !== live.tsUs || frame.tsNsRem !== live.tsNsRem || frame.origLen !== live.origLen) return false;
  const a = frame.bytes;
  const b = live.bytes;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- the live path's front door -----------------------------------------------

/**
 * Where every live frame and every file frame meets the live path, so the
 * Worker and `scripts/pipeline/catch-up.ts` run one piece of logic.
 *
 * `deliver` hands a frame on to be dissected, with the hole before it that is
 * still to be marked (`liveFlow.ts`); `release` says a live frame will never
 * be dissected - the file has it - so its batch's credit can go back to main.
 * Every live frame that arrives meets exactly one of the two, once.
 */
export class CatchUpRouter<F extends SeqFrame> {
  /** The newest frame delivered, which the file's frame of that number must match. */
  private anchor: Anchor | null = null;
  private enabled = false;

  constructor(
    private readonly flow: {
      readonly expectedSeq: number | null;
      seqArrived(seq: number): number;
      noteShed(firstSeq: number, frames: number): void;
    },
    readonly catchUp: CatchUp<F>,
    private readonly fromFile: (frame: FileFrame) => F,
    private readonly deliver: (frame: F, holeBefore: number) => void,
    private readonly release: (frame: F) => void,
    /** The smallest jump in numbering that is a hole rather than two adapters' skew. */
    private readonly holeMin: number,
  ) {}

  /** Whether this capture has a file to catch up from. */
  enable(on: boolean): void {
    this.enabled = on;
  }

  /** A new capture. */
  reset(): void {
    this.anchor = null;
    this.catchUp.reset();
  }

  /** A live frame off the pipe, or one handed back from a hold. */
  arrive(frame: F): void {
    if (!this.catchUp.active) {
      if (this.catchUp.live(frame) === 'drop') { this.release(frame); return; }
      const expected = this.flow.expectedSeq;
      const hole = expected !== null && frame.seq - expected >= this.holeMin;
      if (!(hole && this.enabled && this.catchUp.start(expected, this.anchor))) {
        this.pass(frame);
        return;
      }
    }
    switch (this.catchUp.live(frame)) {
      case 'take': this.pass(frame); break;
      case 'hold': break;
      case 'drop': this.release(frame); break;
    }
    for (const given of this.catchUp.takeDropped()) this.release(given);
  }

  /**
   * Main shed a batch. Caught up from the file when it can be; otherwise
   * counted, to be marked on the next frame, as before.
   */
  shed(firstSeq: number, frames: number): void {
    if (this.catchUp.active) return;
    const expected = this.flow.expectedSeq;
    if (this.enabled && expected !== null && expected <= firstSeq && this.catchUp.start(expected, this.anchor)) return;
    this.flow.noteShed(firstSeq, frames);
  }

  /** Main's answer to a read. */
  read(result: { bytes: Uint8Array | null; gone: boolean; error?: string }): { retryMs?: number; ended?: CatchUpEnd } {
    const out = this.catchUp.readDone(result);
    for (const frame of out.frames) this.pass(this.fromFile(frame));
    if (out.rejoin !== null) for (const frame of out.rejoin) this.arrive(frame);
    if (out.ended !== null) for (const frame of out.ended.held) this.arrive(frame);
    return { retryMs: out.retryMs, ended: out.ended?.why };
  }

  /** The capture stopped: whatever was held goes on live, holes and all. */
  stop(): void {
    for (const frame of this.catchUp.abort()) this.arrive(frame);
  }

  private pass(frame: F): void {
    const hole = this.flow.seqArrived(frame.seq);
    if (this.anchor === null || frame.seq > this.anchor.seq) this.anchor = anchorOf(frame);
    this.deliver(frame, hole);
  }
}
