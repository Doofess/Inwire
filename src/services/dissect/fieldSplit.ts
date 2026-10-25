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
 * Live rows are the exception: they arrive as shard packs, and the window's
 * reader splits them as it decodes (`claim`, `decodeChunk`), so no bag of dense
 * keys is ever built and `absorb` passes them by (#16). The merge's overlay is
 * applied after that and writes its dense keys into the row's column
 * (`applyOverlay`).
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

  /**
   * A row for one frame, in the block `current` names after the call. For a
   * reader that splits as it decodes (`decodeChunk`), and for `absorb`.
   */
  claim(): number {
    let row = this.block.claimRow();
    if (row === -1) {
      // The full block is simply let go of: the frames already pointing at it
      // keep it alive for exactly as long as they are in the buffer.
      this.block = new FieldBlock(DENSE_FIELDS, this.rowsPerBlock);
      row = this.block.claimRow();
    }
    return row;
  }

  get current(): FieldBlock {
    return this.block;
  }

  absorb(packets: readonly Packet[]): void {
    for (const packet of packets) {
      const bag = packet.fields;
      if (bag === undefined) continue;
      // Already split. A frame absorbed twice would move nothing the second
      // time round but would take a row it does not need.
      if (packet.cols !== undefined) continue;

      const row = this.claim();

      // One pass over the frame's OWN keys - 24.7 of them on average, against
      // 33 declared - building the sparse remainder as it goes. Rebuilt rather
      // than deleted from: `delete` leaves V8's dictionary carrying the removed
      // slots, which is most of what this is trying to give back.
      //
      // `for...in` rather than `Object.keys`, which built an array per frame
      // to walk once; a bag is a plain object off a structured clone, with
      // nothing enumerable on its prototype. And one lookup per field: the
      // block answers whether it holds the key as it writes it.
      const sparse: Record<string, string | number> = {};
      const block = this.block;
      for (const abbrev in bag) {
        const value = bag[abbrev];
        if (!block.tryWrite(row, abbrev, value)) sparse[abbrev] = value;
      }

      packet.fields = sparse;
      packet.cols = this.block;
      packet.row = row;
    }
  }
}
