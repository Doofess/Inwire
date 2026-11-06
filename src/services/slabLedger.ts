import type { Packet } from '../types/packet';

/**
 * What a live buffer's raw frame bytes pin, counted the way the heap holds them.
 *
 * A live row's `rawBytes` is a view into its flush's slab (#17), so the slab
 * is held in full while any one row of it still has bytes: evicting half a
 * flush's rows frees nothing, and the last row's eviction frees the whole slab.
 * Counting each row's own length - what `evictOldBytes` returned - reported
 * memory freed that was not, and left the pinned total at about 29 MB when a
 * slab was half out.
 *
 * The ledger counts a slab once, when its first row is pinned, and gives it
 * back when its last row's bytes go. Pure and keyed by the `ArrayBuffer`, so
 * a row with a buffer of its own is a slab of one.
 *
 * It is not part of the budget's running total: `estimateSummaryBytes` sums
 * stay what `scripts/session/ingest.ts` recomputes (`bufferBudget.ts` says why
 * raw bytes are not in it). A gauge beside it, for the figure the user sees.
 */
export class SlabLedger {
  /** Rows of each buffer that still hold their bytes. Weak: a freed slab leaves no entry. */
  private readonly rows = new WeakMap<ArrayBufferLike, number>();
  private pinned = 0;

  /** Bytes of every slab with at least one row still holding it. */
  get pinnedBytes(): number {
    return this.pinned;
  }

  /** A row joined the buffer with its bytes. Once per row: the flush's `prepareBatch`. */
  pin(packet: Pick<Packet, 'rawBytes'>): void {
    const bytes = packet.rawBytes;
    if (bytes.byteLength === 0) return;
    const held = this.rows.get(bytes.buffer);
    this.rows.set(bytes.buffer, (held ?? 0) + 1);
    if (held === undefined) this.pinned += bytes.buffer.byteLength;
  }

  /**
   * A row is about to lose its bytes (evicted, trimmed or dropped with the
   * ring). Answers the memory that frees: the slab's size when this was its
   * last row, else 0. A row that was never pinned, or has no bytes, frees 0.
   */
  release(packet: Pick<Packet, 'rawBytes'>): number {
    const bytes = packet.rawBytes;
    if (bytes.byteLength === 0) return 0;
    const held = this.rows.get(bytes.buffer);
    if (held === undefined) return 0;
    if (held > 1) {
      this.rows.set(bytes.buffer, held - 1);
      return 0;
    }
    this.rows.delete(bytes.buffer);
    this.pinned -= bytes.buffer.byteLength;
    return bytes.buffer.byteLength;
  }
}
