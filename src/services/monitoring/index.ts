/**
 * A sparse entry-id to file-offset index over the journal.
 *
 * Not a barrel, whatever the name suggests: it exports the one class. It is
 * what lets `readEvidence` and `readPage` seek, so a page near the end of a
 * week of evidence does not walk the week.
 *
 * **There is no on-disk index in this milestone, and the index is therefore
 * always rebuilt.** The plan's "missing or stale derived index is rebuilt"
 * has no stale case to detect: the open scan, which already reads every entry
 * to check its CRC (1.5 s for a day, measured), builds this as a by-product.
 * An index file would add a second thing that can disagree with the journal
 * in exchange for a scan the journal pays anyway.
 *
 * A checkpoint is kept for entry 1 and every `INDEX_STRIDE` after it, so a
 * seek walks at most `INDEX_STRIDE - 1` headers. Each checkpoint carries the
 * session open *before* its entry, because a datagram's session is not in its
 * body: it is the nearest `start` before it, and a seek that lands mid-journal
 * would otherwise have no way to know it.
 *
 * ## The time index
 *
 * Each stride also keeps the smallest and largest `receivedMs` of every entry
 * in it, boundaries included, so a time range can be turned into the strides
 * that might hold it without reading them. The test is overlap - `min < toMs &&
 * max >= fromMs` - and not "the first and last entry bracket the range",
 * because receipt time is the utility's wall clock, which can step back: a
 * stride whose first entry is later than its last is still found. A stride the
 * overlap test admits may hold nothing in range (the min and max are bounds,
 * not contents); the reader checks each entry it reads. One it rejects holds
 * nothing in range, always.
 */
export const INDEX_STRIDE = 256;

export interface Checkpoint {
  entryId: number;
  offset: number;
  /** The session open before this entry was applied, or null if none was. */
  openSession: string | null;
}

export class EntryIndex {
  private offsets: number[] = [];
  private sessions: (string | null)[] = [];
  private minMs: number[] = [];
  private maxMs: number[] = [];
  private lastId = 0;

  get checkpoints(): number { return this.offsets.length; }

  /** Called for every entry, in id order, before the entry changes the session. */
  note(entryId: number, offset: number, openSession: string | null, receivedMs: number): void {
    const slot = Math.floor((entryId - 1) / INDEX_STRIDE);
    if ((entryId - 1) % INDEX_STRIDE === 0) {
      this.offsets[slot] = offset;
      this.sessions[slot] = openSession;
      this.minMs[slot] = receivedMs;
      this.maxMs[slot] = receivedMs;
    } else if (slot < this.minMs.length) {
      // The open tail stride is updated on every append.
      if (receivedMs < this.minMs[slot]) this.minMs[slot] = receivedMs;
      if (receivedMs > this.maxMs[slot]) this.maxMs[slot] = receivedMs;
    }
    this.lastId = entryId;
  }

  /**
   * The id ranges, merged and ascending, of the strides whose receipt times
   * overlap `[fromMs, toMs)`, no later than `throughId`.
   */
  strideRanges(fromMs: number, toMs: number, throughId: number): { fromId: number; toId: number }[] {
    const out: { fromId: number; toId: number }[] = [];
    const last = Math.min(throughId, this.lastId);
    for (let slot = 0; slot < this.minMs.length; slot++) {
      const fromId = slot * INDEX_STRIDE + 1;
      if (fromId > last) break;
      if (!(this.minMs[slot] < toMs && this.maxMs[slot] >= fromMs)) continue;
      const toId = Math.min(fromId + INDEX_STRIDE - 1, last);
      const tail = out[out.length - 1];
      if (tail !== undefined && tail.toId + 1 === fromId) tail.toId = toId;
      else out.push({ fromId, toId });
    }
    return out;
  }

  /** The nearest checkpoint at or before `entryId`, or null with nothing noted. */
  seek(entryId: number): Checkpoint | null {
    if (this.offsets.length === 0 || entryId < 1) return null;
    const slot = Math.min(Math.floor((entryId - 1) / INDEX_STRIDE), this.offsets.length - 1);
    return { entryId: slot * INDEX_STRIDE + 1, offset: this.offsets[slot], openSession: this.sessions[slot] };
  }
}
