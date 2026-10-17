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

  get checkpoints(): number { return this.offsets.length; }

  /** Called for every entry, in id order, before the entry changes the session. */
  note(entryId: number, offset: number, openSession: string | null): void {
    if ((entryId - 1) % INDEX_STRIDE !== 0) return;
    const slot = (entryId - 1) / INDEX_STRIDE;
    this.offsets[slot] = offset;
    this.sessions[slot] = openSession;
  }

  /** The nearest checkpoint at or before `entryId`, or null with nothing noted. */
  seek(entryId: number): Checkpoint | null {
    if (this.offsets.length === 0 || entryId < 1) return null;
    const slot = Math.min(Math.floor((entryId - 1) / INDEX_STRIDE), this.offsets.length - 1);
    return { entryId: slot * INDEX_STRIDE + 1, offset: this.offsets[slot], openSession: this.sessions[slot] };
  }
}
