import { FieldBlock } from './fieldBlock';
import { DENSE_FIELDS } from './denseFields';
import type { Packet } from '../../types/packet';

/**
 * How many frames share one block.
 *
 * A block's fixed cost is one typed array per column - 33 of them, a few
 * kilobytes - so a block of ten frames would cost more per frame than the
 * properties it replaces. 4,096 puts that overhead under a byte a frame while
 * keeping a block small enough that trimming releases memory promptly: the
 * collector can only free a block once its **last** frame has left the buffer.
 */
const BLOCK_ROWS = 4096;

/** A Set, because `absorb` asks it once per field of every frame. */
const DENSE_ABBREVS = new Set(DENSE_FIELDS.map((k) => k.abbrev));

/**
 * Moves each frame's dense fields out of its bag and into a shared block.
 *
 * Called where frames join the buffer, which is after dissection and not during
 * it. **The dissector is deliberately untouched**: `Packet.fields` is assembled
 * by scattered assignment across some two hundred lines of `pcapParser.ts` and
 * by `Object.assign` from every sub-dissector, so there is no single write to
 * intercept - but there is a single moment when a finished frame is handed to a
 * buffer, and that is here.
 *
 * The bag is still built per frame and then dropped, which costs nothing new:
 * it was being built anyway, and what changes is that it stops being retained.
 *
 * One writer lives for a capture, not for a flush. A writer per batch would
 * mean a block per batch, and a slow capture's batches are small enough that
 * the per-block overhead would exceed what the columns save.
 */
export class FieldBlockWriter {
  private block: FieldBlock;

  constructor(private readonly rowsPerBlock: number = BLOCK_ROWS) {
    this.block = new FieldBlock(DENSE_FIELDS, this.rowsPerBlock);
  }

  absorb(packets: readonly Packet[]): void {
    for (const packet of packets) {
      const bag = packet.fields;
      if (bag === undefined) continue;
      // Already split. A frame absorbed twice would move nothing the second
      // time round but would take a row it does not need.
      if (packet.cols !== undefined) continue;

      let row = this.block.claimRow();
      if (row === -1) {
        // The full block is simply let go of: the frames already pointing at it
        // keep it alive for exactly as long as they are in the buffer.
        this.block = new FieldBlock(DENSE_FIELDS, this.rowsPerBlock);
        row = this.block.claimRow();
      }

      // One pass over the frame's OWN keys - 24.7 of them on average, against
      // 33 declared - building the sparse remainder as it goes. Rebuilt rather
      // than deleted from: `delete` leaves V8's dictionary carrying the removed
      // slots, which is most of what this is trying to give back.
      const sparse: Record<string, string | number> = {};
      for (const abbrev of Object.keys(bag)) {
        if (DENSE_ABBREVS.has(abbrev)) this.block.write(row, abbrev, bag[abbrev]);
        else sparse[abbrev] = bag[abbrev];
      }

      packet.fields = sparse;
      packet.cols = this.block;
      packet.row = row;
    }
  }
}
