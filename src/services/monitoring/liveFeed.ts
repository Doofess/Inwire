/**
 * Live delivery from the utility to the Worker as a credit-bounded cursor over
 * the journal (ADR 0059).
 *
 * The utility never pushes a datagram it has just received. It pushes entries
 * the journal has *written*, read back with `readPage`, so what the Worker is
 * told is exactly what a later query will find - a datagram that was shed, or
 * refused at the storage limit, is in no push. That also makes the push
 * optional: a Worker that is absent, busy or reloading loses nothing, because
 * the journal is the authority and the Worker re-reads from its own position.
 *
 * Three rules keep a fast exporter from queueing without bound behind a slow
 * Worker:
 *
 * - **Credit.** At most `LIMITS.liveCreditBatches` pushes are unacknowledged at
 *   once. A push is a batch of at most `liveBatchDatagrams` entries and about
 *   `liveBatchBytes`; the Worker's acknowledgement (`runtimeRpc.ts`'s
 *   `live-ack`) returns one credit. With none left, entries accumulate in the
 *   journal and the cursor waits.
 * - **The cursor only moves past what was pushed.** A push that throws leaves
 *   it where it was, so the next pump sends the same entries again.
 * - **Attach resets it.** A new attach starts at the journal's current end. The
 *   Worker's connect rebuilds everything up to its own snapshot from the
 *   journal; live covers what comes after, and anything in the overlap is
 *   skipped by the Worker, which knows how far it has fed.
 *
 * Pure: the journal, the push and the failure report are all injected.
 */
import { LIMITS, type Evidence, type EvidencePage, type JournalSnapshot, type Snapshot } from './types';

export interface LiveFeedSource {
  /** The journal as it stands now, or null while no dataset is open. */
  snapshot(): JournalSnapshot | null;
  readPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): EvidencePage;
  /** Sends one batch to the attached Worker. May throw where the port is gone. */
  push(entries: Evidence[]): void;
  /** A read or a push failed; the cursor has not moved. */
  onError?(e: unknown): void;
}

export class LiveFeed {
  private attached = false;
  private pushedThrough = 0;
  private unacked = 0;

  constructor(private readonly source: LiveFeedSource) {}

  get isAttached(): boolean { return this.attached; }
  /** Pushes sent and not yet acknowledged. */
  get inFlight(): number { return this.unacked; }
  /** The id of the last entry pushed (or the one the cursor was set to on attach). */
  get cursor(): number { return this.pushedThrough; }

  /** A Worker's port is now the one to feed; `throughEntryId` is the journal's end at that moment. */
  attach(throughEntryId: number): void {
    this.attached = true;
    this.pushedThrough = throughEntryId;
    this.unacked = 0;
  }

  /** The Worker is gone. Nothing is pushed until the next `attach`, which resets the cursor. */
  detach(): void {
    this.attached = false;
    this.unacked = 0;
  }

  /** The journal has grown. */
  notify(): void {
    this.pump();
  }

  /** The Worker has consumed one push. */
  ack(): void {
    if (this.unacked > 0) this.unacked--;
    this.pump();
  }

  private pump(): void {
    while (this.attached && this.unacked < LIMITS.liveCreditBatches) {
      const snapshot = this.source.snapshot();
      if (snapshot === null || this.pushedThrough >= snapshot.throughEntryId) return;
      let page: EvidencePage;
      try {
        page = this.source.readPage(snapshot, this.pushedThrough, LIMITS.liveBatchDatagrams, LIMITS.liveBatchBytes);
      } catch (e) {
        this.source.onError?.(e);
        return;
      }
      if (page.entries.length === 0) return;
      try {
        this.source.push(page.entries);
      } catch (e) {
        this.source.onError?.(e);
        return;
      }
      this.unacked++;
      this.pushedThrough = page.entries[page.entries.length - 1].ref.entryId;
    }
  }
}
