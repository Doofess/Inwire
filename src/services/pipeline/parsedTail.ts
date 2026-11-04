/**
 * What `CatchUp` reads a file through when the catch-up reader parses it
 * (ADR 0053, "Catch-up past the ceiling, 2026-11-04"): `PcapngTail`'s members,
 * over the parses the reader sends back rather than over bytes.
 *
 * The reader holds nothing between reads, so this is where the tail's state
 * lives: `nextRead()` is what the next read is parsed from, and a parse is
 * taken only if it began exactly there. Frames come out one at a time, as
 * `PcapngTail` gives them, so `CatchUp` can stop at an exact frame and go on
 * from it later; those it has not been given wait, in front of any later
 * parse's.
 *
 * Two differences from `PcapngTail`, both accepted: the reader parses a whole
 * read at once, so after an early return that left frames waiting in front of a
 * block that does not close yet, that block's failed read is already counted
 * (a corrupt file is called so one read sooner), and the next read starts at
 * the start of that block rather than at the end of the bytes held.
 */
import { startState, type TailFrame, type TailSection, type TailState } from './pcapngTail';
import type { ReadParse } from './readParse';

function copySection(s: TailSection): TailSection {
  return { little: s.little, nsPerTick: s.nsPerTick.slice(), idbNames: s.idbNames.slice() };
}

function copyState(s: TailState): TailState {
  return { offset: s.offset, ...copySection(s), stalled: s.stalled };
}

export class ParsedTail {
  /** Where the next read is parsed from: the last parse taken's end. */
  private end: TailState;
  /** Parses with frames not given yet; `index` is the next frame of the first. */
  private queue: ReadParse[] = [];
  private index = 0;
  /** The end of what `next` has given; the end of the last parse once it has said there is no more. */
  private pos: number;
  /** The section the frame at `pos` was read by. */
  private current: TailSection;
  private lastBlockAt = 0;
  /** The last parse's first block, and where that parse began. */
  private head: { type: number; length: number } | null = null;
  private headAt = -1;
  /** The last parse found the file corrupt: thrown once its frames are given. */
  private error: string | null = null;

  constructor(state: TailState = startState()) {
    this.end = copyState(state);
    this.pos = state.offset;
    this.current = copySection(state);
  }

  /** The file offset of the next block `next` reads: everything before it is consumed. */
  get position(): number {
    return this.pos;
  }

  /** The file offset the next read must start at. */
  get readOffset(): number {
    return this.end.offset;
  }

  /** File offset of the EPB `next` last gave back. */
  get blockAt(): number {
    return this.lastBlockAt;
  }

  /** `if_name` per IDB as of the last frame given, or as of the last parse's end once none wait. */
  get idbNames(): readonly (string | null)[] {
    return this.current.idbNames;
  }

  /**
   * The type and length of the block at the read position, once eight bytes
   * of it are here - known only where the last parse began, which is the only
   * place `CatchUp` asks: where a seek landed.
   */
  blockHead(): { type: number; length: number } | null {
    return this.pos === this.headAt ? this.head : null;
  }

  /**
   * A parse of the read `nextRead()` asked for. Refused, changing nothing,
   * when it did not begin where the next read does - it was asked for before a
   * jump or a clear.
   *
   * Once a parse has found the file corrupt, that is where the tail ends:
   * nothing after it is taken, and the answer is yes all the same, so the
   * caller reads on through what waits to the error, as `PcapngTail` reads on
   * to the corrupt block. A refusal is read again at once - here, for ever.
   */
  take(parse: ReadParse): boolean {
    if (this.error !== null) return true;
    if (parse.start !== this.end.offset) return false;
    if (parse.count > 0) this.queue.push(parse);
    this.end = parse.end;
    this.head = parse.head;
    this.headAt = parse.start;
    this.error = parse.error;
    return true;
  }

  /**
   * The next packet, or null when every frame taken has been given. Its bytes
   * are a view of the parse's slab, whatever `_copy` asks: the slab is sized to
   * its frames, so a view keeps no more alive than its neighbours.
   */
  next(_copy?: boolean): TailFrame | null {
    while (this.queue.length > 0) {
      const p = this.queue[0];
      if (this.index < p.count) {
        const i = this.index++;
        this.lastBlockAt = p.blockAt[i];
        this.pos = p.blockAt[i] + p.blockLen[i];
        this.current = p.sections[p.section[i]];
        return {
          idb: p.idb[i],
          tsUs: p.tsUs[i],
          tsNsRem: p.tsNsRem[i],
          origLen: p.origLen[i],
          capLen: p.capLen[i],
          bytes: new Uint8Array(p.slabs[p.slab[i]], p.slabAt[i], p.capLen[i]),
        };
      }
      this.queue.shift();
      this.index = 0;
    }
    if (this.error !== null) throw new Error(this.error);
    this.pos = this.end.offset;
    this.current = this.end;
    return null;
  }

  /**
   * Go on reading from `offset`, a block boundary somewhere ahead, with the
   * section kept. Whatever was waiting is let go, and so is a parse's error.
   */
  jump(offset: number): void {
    this.queue = [];
    this.index = 0;
    this.end = { offset, ...copySection(this.current), stalled: 0 };
    this.pos = offset;
    this.current = this.end;
    this.head = null;
    this.headAt = -1;
    this.error = null;
  }

  /** The state the next read is parsed from. */
  nextRead(): TailState {
    return copyState(this.end);
  }

  /**
   * The tail as it is at `position`, with copies: what a `PcapngTail` restored
   * from it, or this restored from it, reads on from. With frames waiting,
   * they are read again; the stall count starts again with them.
   */
  save(): TailState {
    if (this.waiting()) return { offset: this.pos, ...copySection(this.current), stalled: 0 };
    return copyState(this.end);
  }

  private waiting(): boolean {
    return this.queue.length > 0 && (this.queue.length > 1 || this.index < this.queue[0].count);
  }
}
