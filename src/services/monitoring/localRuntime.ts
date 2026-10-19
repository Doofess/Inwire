/**
 * The runtime in process: `MonitoringJournal` and `RollupStore` behind the
 * interfaces the Worker is written against (ADR 0059).
 *
 * Tests use it directly and the utility process (Task 5) serves the same object
 * over a port with `runtimeRpc.ts`, so what the Worker is tested against is what
 * it will be given, minus the port. Every method is `async` for that reason and
 * not because any of them waits: a Worker that only ever saw synchronous
 * answers would be untested against the one thing a real port does.
 *
 * Live appends are *announced*, not polled: `publishLive` hands the entries a
 * caller has just appended to the journal to whoever subscribed, which is how
 * the Worker's rollups follow it. A subscriber that misses one (a port that
 * closed, a Worker that was busy) loses nothing, because the journal is the
 * authority and the Worker re-reads from its own position.
 */
import type { MonitoringJournal } from './journal';
import type { MinuteInput, RollupOpenStatus, RollupStore } from './rollupStore';
import type { ArchiveCut, ArchivedMinute, ArchiveStore } from './archive';
import { RuntimeUnavailableError, type ArchiveSource, type DatasetMeta, type HostRuntime } from './runtime';
import {
  LIMITS, type BoundaryEvidence, type BundleSlice, type Evidence, type EvidencePage, type EvidenceRef, type JournalSnapshot, type RawPage,
  type RollupWatermark, type Snapshot,
} from './types';

/** The archive behind `ArchiveSource`: answers in process, async for the same reason the rest of the runtime is. */
export class LocalArchiveSource implements ArchiveSource {
  constructor(private readonly store: ArchiveStore) {}

  async read(sourceKey: string, fromMs: number, toMs: number, maxBytes: number): Promise<ArchivedMinute[] | 'history-lost' | 'range-too-large'> {
    return this.store.read(sourceKey, fromMs, toMs, maxBytes);
  }

  async coveredThroughMs(): Promise<number | null> { return this.store.coveredThroughMs(); }

  async lastCut(): Promise<ArchiveCut | null> { return this.store.lastCut(); }

  async sources(): Promise<string[]> { return this.store.sources(); }

  async cuts(): Promise<ArchiveCut[]> { return this.store.cuts(); }

  async summary(fromMs: number, toMs: number): Promise<{ minutes: number; policies: number[] } | 'history-lost'> {
    return this.store.summary(fromMs, toMs);
  }
}

export class LocalRuntime implements HostRuntime {
  private handlers: ((entries: Evidence[]) => void)[] = [];
  private opened: { status: RollupOpenStatus; reason?: string };

  constructor(
    private readonly journal: MonitoringJournal,
    private readonly rollups: RollupStore,
    opened: { status: RollupOpenStatus; reason?: string } = { status: 'ok' },
    readonly archive?: ArchiveSource,
    private readonly meta?: DatasetMeta,
  ) {
    this.opened = { ...opened };
  }

  async snapshot(): Promise<JournalSnapshot> { return this.journal.snapshot(); }

  async readPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<EvidencePage> {
    return this.journal.readPage(snapshot, afterId, maxEntries, maxBytes);
  }

  async readRawPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<RawPage> {
    return this.journal.readRawPage(snapshot, afterId, maxEntries, maxBytes);
  }

  async bundleSlice(snapshot: Snapshot, fromMs: number, throughMs: number): Promise<BundleSlice | null> {
    return this.journal.bundleSlice(snapshot, fromMs, throughMs);
  }

  async readEvidence(ref: EvidenceRef): Promise<Evidence | null> { return this.journal.readEvidence(ref); }

  async locate(snapshot: Snapshot, fromMs: number, toMs: number): Promise<{ fromId: number; toId: number }[]> {
    return this.journal.locate(snapshot, fromMs, toMs);
  }

  async readBoundaries(
    snapshot: Snapshot, afterId: number, maxEntries: number,
  ): Promise<{ entries: BoundaryEvidence[]; nextAfterId: number; done: boolean }> {
    return this.journal.readBoundaries(snapshot, afterId, maxEntries);
  }

  async watermark(): Promise<RollupWatermark | null> { return this.rollups.watermark(); }

  async readMinutes(
    sourceKey: string, fromMinuteMs: number, toMinuteMs: number, maxBytes: number,
  ): Promise<{ minuteMs: number; throughEntryId: number; bytes: Uint8Array }[]> {
    return this.rollups.readMinutes(sourceKey, fromMinuteMs, toMinuteMs, maxBytes);
  }

  async sources(): Promise<string[]> { return this.rollups.sources(); }

  /**
   * The Worker's one write, so it is bounded here where both files are known: a
   * watermark no further than the journal's end, and a batch that leaves the
   * journal and the sidecar together inside the limit less the closing reserve,
   * which the journal's `stop` relies on. A refusal rejects (`RangeError`) and
   * `runtimeRpc` answers it as an error reply; nothing is written.
   */
  async appendMinutes(minutes: MinuteInput[], watermark: RollupWatermark, afterEntryId: number): Promise<void> {
    const snapshot = this.journal.snapshot();
    this.rollups.appendMinutes(minutes, watermark, afterEntryId, {
      journalThroughEntryId: snapshot.throughEntryId,
      maxBatchBytes: this.journal.limitBytes - LIMITS.closingReserveBytes - snapshot.writtenBytes - this.rollups.size(),
    });
  }

  /** What the caller opened the runtime with: a dataset's identity is a file's, and there is nothing here to invent one from. */
  async dataset(): Promise<DatasetMeta> {
    if (this.meta === undefined) throw new RuntimeUnavailableError('this runtime was opened without a dataset identity');
    return { ...this.meta };
  }

  async rollupStatus(): Promise<{ status: RollupOpenStatus; reason?: string }> { return this.opened; }

  /** The sidecar starts over from the journal's first retained entry: what expired is the archive's, never the cache's. */
  async resetRollups(): Promise<void> {
    this.rollups.reset(this.journal.snapshot().firstEntryId - 1);
    this.opened = { status: 'empty' };
  }

  onLive(handler: (entries: Evidence[]) => void): void { this.handlers.push(handler); }

  /** Announces entries the caller has already appended to the journal. */
  publishLive(entries: Evidence[]): void {
    for (const h of this.handlers) h(entries);
  }
}
