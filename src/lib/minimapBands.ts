import type { Packet } from '../types/packet';
import { prefixShift } from '../services/packetPrefix';

/**
 * Every buffered frame's minimap colour, indexed so a pixel row's average is
 * a few lookups rather than a walk of its band.
 *
 * The strip averages the colour of every frame a 1px row covers, and it used
 * to recompute every row from the frames on every repaint - so each repaint
 * touched the whole buffer, twice a second. At a 1.3 GB buffer that was the
 * one long task left in a 20,000 frame-a-second capture
 * (`scripts/perf/ui-burst-drive.ts`: `colorRules.cachedSlot` on top).
 *
 * So the colours are kept, packed, one `u32` a frame, with running RGBA
 * totals every `BLOCK` frames. A row's sum is whole blocks from the totals
 * plus at most two partial blocks at its ends: O(rows x BLOCK) a repaint,
 * whatever the buffer holds. ~4.5 bytes a frame.
 *
 * **It extends the way the buffer does**, proven the way every incremental
 * cache here proves it (`prefixShift`): frames appended are coloured once, a
 * trim moves an offset. Anything else starts again - which costs exactly the
 * one full pass every repaint used to cost.
 *
 * **It only indexes colours that are already decided.** A frame no rule has
 * been asked about (after a rule edit every frame is one) has no colour yet,
 * and deciding a million of them synchronously is the 1.7 s freeze the strip's
 * progressive fill exists to avoid. So a rebuild that meets one gives up and
 * says so, and the caller paints the old way until the fill has decided them.
 * Appended frames are few, so those are decided as they are indexed.
 */
export const BLOCK = 64;

/** A frame's colour, packed `r << 24 | g << 16 | b << 8 | a`; undefined while undecided. */
export type ColourOf = (packet: Packet, decide: boolean) => number | undefined;

export class MinimapBands {
  private source: Packet[] = [];
  /** Index in `colours` of the buffer's first frame: a trim moves it forward. */
  private offset = 0;
  private count = 0;
  private colours = new Uint32Array(1024);
  /** Running RGBA totals at each block boundary: entry b covers frames [0, b * BLOCK). */
  private totals = new Float64Array(4 * (1024 / BLOCK + 1));

  /** Drops everything: a new colour chain, a new theme. */
  reset(): void {
    this.source = [];
    this.offset = 0;
    this.count = 0;
  }

  /**
   * Brings the index up to `packets`, or returns false when it cannot without
   * deciding frames nobody has asked about yet.
   */
  sync(packets: Packet[], colourOf: ColourOf): boolean {
    const shift = this.count > 0 ? prefixShift(packets, this.source) : null;
    let from: number;
    if (shift === null) {
      this.offset = 0;
      this.count = 0;
      from = 0;
    } else {
      this.offset += shift;
      from = this.source.length - shift;
    }
    // A rebuild must not decide; an append may, because it is only the new.
    const decide = shift !== null;
    if (this.offset > 0 && this.offset > this.count - this.offset) this.compact();
    for (let i = from; i < packets.length; i++) {
      const colour = colourOf(packets[i], decide);
      if (colour === undefined) {
        this.reset();
        return false;
      }
      this.push(colour);
    }
    this.source = packets;
    return true;
  }

  /**
   * The summed RGBA of buffer frames [from, to), as four totals; the caller
   * divides by the frame count it asked for.
   */
  sum(from: number, to: number, into: Float64Array): void {
    into.fill(0);
    const a = this.offset + from;
    const b = this.offset + to;
    if (b <= a) return;
    const firstWhole = Math.ceil(a / BLOCK);
    const lastWhole = Math.floor(b / BLOCK);
    if (firstWhole >= lastWhole) {
      this.addRange(a, b, into);
      return;
    }
    this.addRange(a, firstWhole * BLOCK, into);
    for (let c = 0; c < 4; c++) into[c] += this.totals[lastWhole * 4 + c] - this.totals[firstWhole * 4 + c];
    this.addRange(lastWhole * BLOCK, b, into);
  }

  /** Frames indexed, for a check. */
  get length(): number {
    return this.count - this.offset;
  }

  private addRange(a: number, b: number, into: Float64Array): void {
    for (let i = a; i < b; i++) {
      const c = this.colours[i];
      into[0] += c >>> 24;
      into[1] += (c >>> 16) & 0xff;
      into[2] += (c >>> 8) & 0xff;
      into[3] += c & 0xff;
    }
  }

  private push(colour: number): void {
    if (this.count === this.colours.length) {
      const grown = new Uint32Array(this.colours.length * 2);
      grown.set(this.colours);
      this.colours = grown;
      const totals = new Float64Array(4 * (grown.length / BLOCK + 1));
      totals.set(this.totals);
      this.totals = totals;
    }
    this.colours[this.count++] = colour;
    if (this.count % BLOCK === 0) {
      const block = this.count / BLOCK;
      const start = this.count - BLOCK;
      for (let c = 0; c < 4; c++) this.totals[block * 4 + c] = this.totals[(block - 1) * 4 + c];
      for (let i = start; i < this.count; i++) {
        const v = this.colours[i];
        this.totals[block * 4] += v >>> 24;
        this.totals[block * 4 + 1] += (v >>> 16) & 0xff;
        this.totals[block * 4 + 2] += (v >>> 8) & 0xff;
        this.totals[block * 4 + 3] += v & 0xff;
      }
    }
  }

  /**
   * Drops the trimmed prefix, by whole blocks so every total stays aligned to
   * a block boundary. The totals are differences, so they need no rebasing.
   */
  private compact(): void {
    const drop = Math.floor(this.offset / BLOCK) * BLOCK;
    if (drop === 0) return;
    this.colours.copyWithin(0, drop, this.count);
    const blocks = drop / BLOCK;
    const lastBlock = Math.floor(this.count / BLOCK);
    this.totals.copyWithin(0, blocks * 4, (lastBlock + 1) * 4);
    this.count -= drop;
    this.offset -= drop;
  }
}
