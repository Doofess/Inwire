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
import type { HostRuntime } from './runtime';
import type { BoundaryEvidence, Evidence, EvidencePage, EvidenceRef, JournalSnapshot, RollupWatermark, Snapshot } from './types';

export class LocalRuntime implements HostRuntime {
  private handlers: ((entries: Evidence[]) => void)[] = [];
  private opened: { status: RollupOpenStatus; reason?: string };

  constructor(
    private readonly journal: MonitoringJournal,
    private readonly rollups: RollupStore,
    opened: { status: RollupOpenStatus; reason?: string } = { status: 'ok' },
  ) {
    this.opened = { ...opened };
  }

  async snapshot(): Promise<JournalSnapshot> { return this.journal.snapshot(); }

  async readPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<EvidencePage> {
    return this.journal.readPage(snapshot, afterId, maxEntries, maxBytes);
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

  async appendMinutes(minutes: MinuteInput[], watermark: RollupWatermark): Promise<void> {
    this.rollups.appendMinutes(minutes, watermark);
  }

  async rollupStatus(): Promise<{ status: RollupOpenStatus; reason?: string }> { return this.opened; }

  async resetRollups(): Promise<void> {
    this.rollups.reset();
    this.opened = { status: 'empty' };
  }

  onLive(handler: (entries: Evidence[]) => void): void { this.handlers.push(handler); }

  /** Announces entries the caller has already appended to the journal. */
  publishLive(entries: Evidence[]): void {
    for (const h of this.handlers) h(entries);
  }
}
