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
 * ## Finding the hole (#17)
 *
 * Counting from the start of the file reads every frame before the hole, and
 * a capture with no ring has one file: a hole 2.0M frames in read 2.2 GB to
 * reach it, at a fifth of the speed live had. So every frame passed on to be
 * dissected, live or read back, adds its EPB's length to a running sum per
 * file (`passed`, `frameSizes.ts`), and a catch-up with an anchor jumps there
 * - after one read of the file's header, whose IDBs the frames need - instead
 * of counting. A gap the stream never filled leaves the frames after it
 * unplaced: the jump lands before the gap, counts across it, learns where the
 * next run starts and jumps on (`gapEnd`). A clear keeps the cursor and the
 * sizes, because the agent's numbering and files go on.
 * The sum is exact only for what the agent writes: an EPB with no options
 * and no other block between them. A landing is not trusted: the block there
 * must be an EPB, the anchor's length when it landed on the anchor, and the
 * anchor itself must match. A landing that fails either is a `seekMiss`:
 * counted from the start as before, and no seek again in this capture.
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
import { FrameSizes, type SizedPoint } from './frameSizes';
import { PcapngTail, type TailFrame } from './pcapngTail';
import { LATE_WINDOW } from './liveFlow';

/**
 * The longest frame the agent writes: `MAX_SNAPLEN` in `../captureOptions`,
 * repeated rather than imported, because that module builds its preference
 * store at load and would bring it into the Worker. `catch-up.ts` holds the
 * two equal.
 */
export const MAX_CAPLEN = 262144;

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
/**
 * The first read of a file a seek will jump into: its section header and
 * IDBs, which say the byte order, the clock and the adapters' names (#17).
 */
export const HEADER_READ = 64 * 1024;
/** Reads of zeros where a seek landed - a block not written yet - before the landing is called wrong. */
const LANDING_TRIES = 20;

/**
 * An EPB's length for a frame of `capLen` bytes, as the agent writes it: no
 * options (`agent-rs/src/pcapng.rs`). An agent that wrote any would make a
 * seek land wrong, which the landing's check catches.
 */
export function epbBytes(capLen: number): number {
  return 32 + capLen + ((4 - (capLen % 4)) % 4);
}

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
    // An `open` for file 1 after file 1 was already open is a new run. Not
    // after its boundary alone: the agent's capture thread sends that and its
    // writer thread the open, so the boundary can come first - and taking its
    // open for a new run forgot where file 1 begins, and no hole in it could
    // be caught up.
    const known = this.files.get(index);
    if (state === 'open' && index === 1 && known !== undefined && known.name !== null) this.reset();
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

/**
 * What a catch-up that stopped short leaves behind: the live frames it held,
 * and the numbers `[from, to)` it was still to deliver - of which only the
 * held ones will be, live; the rest are counted and marked as skipped.
 */
export interface Abandoned<F> {
  held: F[];
  from: number;
  to: number;
  /** Late frames from below the hole (#18) the file never delivered: lost, and marked. */
  late: number;
}

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
  ended: ({ why: CatchUpEnd } & Abandoned<F>) | null;
  /** Nothing new in the file: ask again after this long. */
  retryMs?: number;
  /** Late frames from below the hole the file turned out not to hold: lost, and marked. */
  lost?: number;
}

/** Where reading a file had got to, kept between catch-ups. */
interface Cursor {
  index: number;
  name: string;
  tail: PcapngTail;
  /** The number of the next packet `tail` will give. */
  next: number;
  /** Where the file's first EPB is, once its header has been read. */
  headerEnd: number | null;
  /** Where to jump once the header has been read, by the frames' sizes. */
  seek: SizedPoint | null;
  /**
   * A jump the anchor has not proved yet: where it landed, and how often a
   * read found zeros there, and the EPB length it must find when it landed on
   * the anchor itself. A landing the anchor disproves is counted again from
   * the start of the file.
   */
  landing: { at: number; zeros: number; length: number | null } | null;
}

function freshCursor(index: number, name: string, firstSeq: number): Cursor {
  return { index, name, tail: new PcapngTail(0), next: firstSeq, headerEnd: null, seek: null, landing: null };
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
  /** The frames' sizes through the file they are in. */
  private sizes: FrameSizes | null = null;
  /** A seek landed wrong once: this capture's files are not what the sizes say, so count. */
  private seekOff = false;
  /** The first frame the cursor will count whose place the sizes do not know: on to the anchor from there. */
  private gapEnd: number | null = null;
  /**
   * Numbers below `from` the live stream never delivered - two adapters'
   * skew left them at the edge of the hole, in the batch that was shed - read
   * from the file with the rest (#18). Ascending.
   */
  private late: number[] = [];
  /** Late frames read before the anchor proved the count: delivered once it does. */
  private lateRead: FileFrame[] = [];
  /** Late frames the file delivered: a live copy after them is a duplicate. */
  private readonly lateTaken = new Set<number>();

  /** Counts, for a readout and the tests. */
  readonly stats = {
    started: 0, rejoined: 0, framesRead: 0, ended: 0, misaligned: 0, holdOverflows: 0, seeks: 0, seekMisses: 0, lateRead: 0,
  };

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
    this.sizes = null;
    this.seekOff = false;
    this.gapEnd = null;
    this.late = [];
    this.lateRead = [];
    this.lateTaken.clear();
  }

  /**
   * The view was cleared while catching up. As `reset`, but the agent's
   * numbering goes on in the same files, so where reading them had got to and
   * their sizes are kept: the next hole is sought, not counted from the start.
   * A jump the anchor had not proved yet is let go.
   */
  clear(): void {
    const cursor = this.cursor;
    const sizes = this.sizes;
    const seekOff = this.seekOff;
    this.reset();
    this.cursor = cursor !== null && cursor.seek === null && cursor.landing === null ? cursor : null;
    this.sizes = sizes;
    this.seekOff = seekOff;
  }

  /**
   * A frame on its way to be dissected, live or read back: the sum of the
   * sizes is where the next one sits in its file (#17). A frame of a later
   * file starts that file's sizes - also past a file none of whose frames
   * passed, which a ring deleted.
   */
  passed(seq: number, capLen: number): void {
    let sizes = this.sizes;
    if (sizes === null || this.files.get(sizes.index)?.firstSeq !== sizes.firstSeq) {
      const file = this.files.holding(seq);
      if (file === undefined || file.firstSeq === null) return;
      sizes = this.sizes = new FrameSizes(file.index, file.firstSeq);
    }
    for (let after = this.files.after(sizes.index); after?.firstSeq != null && seq >= after.firstSeq; after = this.files.after(sizes.index)) {
      sizes = this.sizes = new FrameSizes(after.index, after.firstSeq);
    }
    sizes.add(seq, epbBytes(capLen));
  }

  /**
   * Where to read from for a hole whose anchor is frame `anchorSeq` of
   * `file`: the anchor's own place, or the end of the last run of frames
   * placed before it - counted on from there. Null when the sizes know
   * nothing of that file.
   */
  private seekPoint(file: FileFacts, anchorSeq: number): SizedPoint | null {
    const sizes = this.sizes;
    if (this.seekOff || sizes === null || sizes.index !== file.index || sizes.firstSeq !== file.firstSeq) return null;
    return sizes.point(anchorSeq);
  }

  /** The first frame a seek must not pass: the anchor, or a late frame before it. */
  private target(): number | null {
    if (this.anchor === null) return null;
    return this.late.length > 0 ? Math.min(this.late[0], this.anchor.seq) : this.anchor.seq;
  }

  /** Where the cursor, counting on, will learn a run's place on its way to the anchor. */
  private findGapEnd(cursor: Cursor): void {
    const sizes = this.sizes;
    const target = this.target();
    this.gapEnd = target === null || this.seekOff || sizes === null || sizes.index !== cursor.index
      ? null : sizes.unplacedFrom(cursor.next, target);
  }

  /** Read on from `point`: at once when the header is read, else after it. */
  private aim(cursor: Cursor, point: SizedPoint): void {
    this.stats.seeks++;
    if (cursor.headerEnd === null) { cursor.seek = point; return; }
    this.land(cursor, cursor.headerEnd + point.rel, point.seq);
  }

  private land(cursor: Cursor, at: number, seq: number): void {
    cursor.tail.jump(at);
    cursor.next = seq;
    cursor.seek = null;
    const anchor = this.anchor;
    cursor.landing = { at, zeros: 0, length: anchor !== null && anchor.seq === seq ? epbBytes(anchor.capLen) : null };
    this.findGapEnd(cursor);
  }

  /**
   * Whether the bytes where a seek landed start an EPB, as far as eight bytes
   * say: 'zeros' for a block not written yet, which is read again. A landing
   * in the middle of a block can read as one longer than anything here, which
   * would wait for ever, so it is judged by its head, not by whether it closes.
   */
  private landingHead(cursor: Cursor): 'ok' | 'zeros' | 'wrong' | 'short' {
    const head = cursor.tail.blockHead();
    if (head === null) return 'short';
    if (head.type === 0 && head.length === 0) return 'zeros';
    const length = cursor.landing!.length;
    const fits = length !== null ? head.length === length : head.length >= 32 && head.length <= epbBytes(MAX_CAPLEN) && head.length % 4 === 0;
    return head.type === 6 && fits ? 'ok' : 'wrong';
  }

  /**
   * The seek landed somewhere the anchor is not: the sizes do not describe
   * this file. Counted again from its start, as before seeking existed, and
   * not sought again this capture.
   */
  private missed(cursor: Cursor, out: ReadResult<F>): ReadResult<F> {
    this.stats.seekMisses++;
    this.seekOff = true;
    const facts = this.files.get(cursor.index);
    this.cursor = freshCursor(cursor.index, cursor.name, facts?.firstSeq ?? cursor.next);
    // Read again from the start, with the rest.
    if (this.lateRead.length > 0) {
      this.late = [...this.late, ...this.lateRead.map((f) => f.seq)].sort((a, b) => a - b);
      this.lateRead = [];
    }
    out.retryMs = 0;
    return out;
  }

  /**
   * The live stream skipped from `fromSeq` on. True when catch-up started;
   * false when it cannot - no file says it holds those frames, or catch-up was
   * turned off for this capture - and the caller marks the hole instead.
   */
  start(fromSeq: number, anchor: Anchor | null, late: readonly number[] = []): boolean {
    if (this.on) return true;
    if (this.disabled !== null) return false;
    late = late.filter((n) => n < fromSeq);
    let want = anchor !== null && anchor.seq === fromSeq - 1 ? anchor.seq : fromSeq;
    if (late.length > 0) want = Math.min(want, ...late);
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
    if (skipped) { want = file.firstSeq!; anchor = null; late = []; }
    // A cursor left exactly where this hole begins - the last catch-up rejoined
    // at the frame before it, which it checked - is carried on with no anchor.
    const resume = late.length === 0 && this.cursor !== null && this.cursor.index === file.index && this.cursor.next === fromSeq;
    if (!resume && (this.cursor === null || this.cursor.index !== file.index || this.cursor.next > want)) {
      this.cursor = freshCursor(file.index, file.name, file.firstSeq!);
    }
    this.on = true;
    this.from = fromSeq;
    this.sessionFrom = fromSeq;
    this.anchor = !resume && anchor !== null && anchor.seq === fromSeq - 1 ? anchor : null;
    this.late = late.slice().sort((a, b) => a - b);
    this.lateRead = [];
    // Rather than count every frame from where the cursor is - the start of
    // the file, the first time - go to where the sizes put the anchor, which
    // then proves the landing. Only with an anchor: nothing else could.
    // (A cursor is there now: carried on, or made just above.)
    const cursor = this.cursor!;
    if (this.anchor !== null && cursor.seek === null && cursor.landing === null) {
      const point = this.seekPoint(file, this.target()!);
      if (point !== null && point.seq > cursor.next) this.aim(cursor, point);
    }
    this.findGapEnd(cursor);
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
    if (this.lateTaken.size > 0 && this.lateTaken.delete(frame.seq)) return 'drop';
    if (this.late.length > 0 || this.lateRead.length > 0) {
      // A late frame came live after all: the file need not deliver it.
      const i = this.late.indexOf(frame.seq);
      if (i >= 0) this.late.splice(i, 1);
      const j = this.lateRead.findIndex((f) => f.seq === frame.seq);
      if (j >= 0) this.lateRead.splice(j, 1);
    }
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

  /**
   * Main shed frames while catching up: nothing to do with them - the file
   * has them - except to know the stream reached that far, so a catch-up
   * that ends counts them among what it never delivered.
   */
  shedSeen(firstSeq: number, frames: number): void {
    if (this.on && firstSeq + frames > this.edge) this.edge = firstSeq + frames;
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
    const length = this.cursor.seek !== null && this.cursor.headerEnd === null ? HEADER_READ : READ_BYTES;
    return { name: this.cursor.name, offset: this.cursor.tail.readOffset, length };
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
      this.cursor = freshCursor(next.index, next.name, next.firstSeq!);
      out.retryMs = 0;
      return out;
    }
    const bytes = result.bytes ?? new Uint8Array(0);
    const before = cursor.tail.readOffset;
    cursor.tail.push(bytes);
    const landing = cursor.landing;
    if (landing !== null && cursor.tail.position === landing.at) {
      // Where the seek landed must be an EPB - the anchor's, by its length,
      // when it landed on the anchor. Zeros are one not written yet, if no
      // more than so often; anything else is the middle of a block.
      const head = this.landingHead(cursor);
      if (head === 'wrong' || (head === 'zeros' && ++landing.zeros > LANDING_TRIES)) return this.missed(cursor, out);
    }
    let frame;
    try {
      while ((frame = cursor.tail.next(cursor.seek === null && cursor.next >= (this.late.length > 0 ? Math.min(this.late[0], this.from) : this.from) - 1)) !== null) {
        if (cursor.headerEnd === null) cursor.headerEnd = cursor.tail.blockAt;
        if (cursor.seek !== null) {
          // The header is read: on to where the sizes say.
          this.land(cursor, cursor.headerEnd + cursor.seek.rel, cursor.seek.seq);
          continue;
        }
        const seq = cursor.next++;
        if (seq === this.gapEnd && cursor.headerEnd !== null && this.sizes?.index === cursor.index) {
          // Counted across a gap in the sizes: the run after it is placed
          // now, and from there, often, the anchor.
          this.sizes.learn(seq, cursor.tail.blockAt - cursor.headerEnd);
          const facts = this.files.get(cursor.index);
          const target = this.target();
          const point = facts !== undefined && target !== null ? this.seekPoint(facts, target) : null;
          if (point !== null && point.seq > cursor.next) { this.aim(cursor, point); continue; }
          this.findGapEnd(cursor);
        }
        if (this.anchor !== null && seq === this.anchor.seq) {
          if (!sameFrame(frame, this.anchor)) {
            return cursor.landing !== null ? this.missed(cursor, out) : this.end('anchorMismatch', out);
          }
          cursor.landing = null;
          this.anchor = null;
          for (const late of this.lateRead) this.takeLate(late, out);
          this.lateRead = [];
          continue;
        }
        if (seq < this.from) {
          const i = this.late.length > 0 ? this.late.indexOf(seq) : -1;
          if (i >= 0) {
            this.late.splice(i, 1);
            // Before the anchor proves the count, it may be wrong: held until it does.
            if (this.anchor !== null) this.lateRead.push({ ...frame, seq });
            else this.takeLate({ ...frame, seq }, out);
          }
          continue;
        }
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
          out.lost = this.dropLate();
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
    if (this.from >= this.edge && this.held.length === 0) {
      // The file has delivered everything the stream got to, and no live
      // frame has come since to rejoin at - the stream went quiet. Level:
      // live again, and the next live frame carries on from here.
      this.coveredFrom = this.sessionFrom;
      this.coveredBelow = this.from;
      this.holdFrom = null;
      this.on = false;
      this.stats.rejoined++;
      out.rejoin = [];
      out.lost = this.dropLate();
      return out;
    }
    if (cursor.tail.readOffset <= before) {
      // Nothing new - no bytes, or only the start of a block still being
      // written: the end of a file the agent has finished moves on to the
      // next one, and the end of the one it is writing waits for its next
      // flush.
      const facts = this.files.get(cursor.index);
      const next = this.files.after(cursor.index);
      if (facts?.closed && bytes.length === 0 && next !== undefined && next.name !== null) {
        if (next.firstSeq !== cursor.next) {
          // The finished file did not hold every frame up to where the next
          // begins - it stopped early, or a frame was refused - so counting
          // into the next would be off; a hole is marked rather than guessed.
          return this.end('misaligned', out);
        }
        this.cursor = freshCursor(next.index, next.name, next.firstSeq);
        out.retryMs = 0;
      } else {
        out.retryMs = RETRY_MS;
      }
    }
    return out;
  }

  /**
   * Stop now - the capture stopped, or the file let catch-up down. What was
   * held goes back to the live path; `skipped` is the frames between where
   * the file got to and the first of them (or the newest live frame, with
   * none held), which nothing will deliver now and the caller counts and
   * marks - or they would be missing with nothing saying so.
   */
  abort(): Abandoned<F> {
    if (!this.on) return { held: [], from: 0, to: 0, late: 0 };
    const held = this.held;
    const from = this.from;
    const to = this.edge;
    const late = this.dropLate();
    this.on = false;
    this.inFlight = false;
    this.held = [];
    this.heldBytes = 0;
    this.holdFrom = null;
    this.anchor = null;
    return { held, from, to, late };
  }

  /** A late frame read back: delivered, and its live copy, should one come, dropped. */
  private takeLate(frame: FileFrame, out: ReadResult<F>): void {
    this.lateTaken.add(frame.seq);
    this.stats.lateRead++;
    out.frames.push(frame);
  }

  /** The late frames this catch-up will not deliver now, given up: how many. */
  private dropLate(): number {
    const lost = this.late.length + this.lateRead.length;
    this.late = [];
    this.lateRead = [];
    return lost;
  }

  /** The device name an IDB of the file being read gives, if it gives one. */
  idbName(idb: number): string | null {
    return this.cursor?.tail.idbNames[idb] ?? null;
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
    const abandoned = this.abort();
    // Counting is not to be trusted for the rest of this capture.
    if (why === 'anchorMismatch' || why === 'misaligned' || why === 'unreadable') this.disabled = why;
    this.cursor = null;
    this.stats.ended++;
    out.ended = { why, ...abandoned };
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
  /** Where file 1's boundary said this capture begins, until a `reset` uses it or the capture stops. */
  private begins: number | null = null;

  constructor(
    private readonly flow: {
      readonly expectedSeq: number | null;
      seqArrived(seq: number): number;
      noteShed(firstSeq: number, frames: number): void;
      takeLate(from: number, below: number): number[];
      noteLost(frames: number): void;
      captureBegins(firstSeq: number): void;
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
    if (this.begins !== null) this.flow.captureBegins(this.begins);
    this.begins = null;
  }

  /** The view cleared while catching up: the numbering starts again, the files and where they were read go on. */
  clear(): void {
    this.anchor = null;
    this.catchUp.clear();
  }

  /**
   * A `capture_boundary` from the agent: file 1's says where the capture's
   * numbering begins. Kept until the capture stops, because it can arrive
   * before the Worker hears it is capturing - whose `reset` starts the
   * numbering again, and puts this back.
   */
  boundary(index: number, firstSeq: number): void {
    if (index !== 1) return;
    this.begins = firstSeq;
    this.flow.captureBegins(firstSeq);
  }

  /** A live frame off the pipe, or one handed back from a hold. */
  arrive(frame: F): void {
    if (!this.catchUp.active) {
      if (this.catchUp.live(frame) === 'drop') { this.release(frame); return; }
      const expected = this.flow.expectedSeq;
      // Before the capture's first frame is delivered, from where its first
      // boundary says it begins, any jump is a hole: frames the Worker dropped
      // before it was capturing are rarely the dozen skew is told apart by.
      // A late first frame from the other adapter is the file's copy's twin,
      // and the first to arrive is kept.
      const min = this.anchor === null ? 1 : this.holeMin;
      const hole = expected !== null && frame.seq - expected >= min;
      if (!(hole && this.enabled && this.catchUp.start(expected, this.anchor, this.flow.takeLate(expected - LATE_WINDOW, expected)))) {
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
    if (this.catchUp.active) { this.catchUp.shedSeen(firstSeq, frames); return; }
    const expected = this.flow.expectedSeq;
    // Numbers below the next one owed that never came - two adapters' skew at
    // the batch's edge: the shed batch held them, so they come from the file
    // with the rest, or are marked with it (#18).
    let late: number[] = [];
    // A file read faster than main's word of what it shed can level before
    // a later batch's notice arrives: the part the file delivered is not a
    // hole, and the rest is one to catch up from where the file stopped.
    if (expected !== null && firstSeq < expected) {
      late = this.flow.takeLate(firstSeq, expected);
      frames -= expected - firstSeq;
      firstSeq = expected;
      if (frames <= 0) { this.flow.noteLost(late.length); return; }
    }
    if (this.enabled && expected !== null && expected <= firstSeq && this.catchUp.start(expected, this.anchor, late)) {
      this.catchUp.shedSeen(firstSeq, frames);
      return;
    }
    this.flow.noteLost(late.length);
    this.flow.noteShed(firstSeq, frames);
  }

  /** Main's answer to a read. */
  read(result: { bytes: Uint8Array | null; gone: boolean; error?: string }): { retryMs?: number; ended?: CatchUpEnd } {
    const out = this.catchUp.readDone(result);
    for (const frame of out.frames) this.pass(this.fromFile(frame));
    if (out.lost !== undefined) this.flow.noteLost(out.lost);
    if (out.rejoin !== null) for (const frame of out.rejoin) this.arrive(frame);
    if (out.ended !== null) this.giveBack(out.ended);
    return { retryMs: out.retryMs, ended: out.ended?.why };
  }

  /**
   * What an ended catch-up leaves: the frames nothing will deliver now are
   * counted and marked on the next frame, as main's shed batches were before
   * catch-up existed; what was held goes on live.
   */
  private giveBack({ held, from, to, late }: Abandoned<F>): void {
    this.flow.noteLost(late);
    // Up to the first held frame, then past the last: the held ones arrive
    // live between, and mark the first gap themselves.
    const first = held.reduce((min, f) => Math.min(min, f.seq), to);
    if (first > from) this.flow.noteShed(from, first - from);
    for (const frame of held) this.arrive(frame);
    const after = held.reduce((max, f) => Math.max(max, f.seq + 1), from);
    if (held.length > 0 && to > after) this.flow.noteShed(after, to - after);
  }

  /**
   * The capture stopped: whatever was held goes on live, holes and all - and
   * a hole among them is marked, not caught up, because there is nothing
   * left to catch up for.
   */
  stop(): void {
    this.begins = null;
    const enabled = this.enabled;
    this.enabled = false;
    this.giveBack(this.catchUp.abort());
    this.enabled = enabled;
  }

  private pass(frame: F): void {
    const hole = this.flow.seqArrived(frame.seq);
    if (this.anchor === null || frame.seq > this.anchor.seq) this.anchor = anchorOf(frame);
    if (this.enabled) this.catchUp.passed(frame.seq, frame.bytes.length);
    this.deliver(frame, hole);
  }
}
