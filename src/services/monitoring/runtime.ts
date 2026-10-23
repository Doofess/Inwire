/**
 * The boundary between the monitoring Worker and whatever holds the files
 * (ADR 0059). The utility process owns the journal and the sidecar; the Worker
 * owns decoding, rollups and queries, and reaches the files only through these
 * interfaces. Every method is async because over a real port every one is a
 * round trip, and the Worker is written for that: `localRuntime.ts` answers in
 * process (tests, and what Task 5's utility serves), `runtimeRpc.ts` carries
 * the same calls across a `MessagePort`.
 *
 * Nothing here imports Node or Electron, so the Worker, the tests and the
 * utility all share it.
 */
import type {
  BoundaryEvidence, BundleSlice, CheckpointInfo, Evidence, EvidencePage, EvidenceRef, JournalSnapshot, RawPage, RollupWatermark,
  SegmentGeometry, Snapshot, StoredCheckpoint,
} from './types';
import type { DatasetFile } from './datasetPlan';
import type { MinuteInput, RollupOpenStatus } from './rollupStore';
import type { ArchiveCut, ArchivedMinute } from './archive';

/** The journal's side: read-only, and always against a snapshot the caller froze. */
export interface EvidenceReader {
  snapshot(): Promise<JournalSnapshot>;
  readPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<EvidencePage>;
  /** `readPage`'s entries as the file holds them (their original bodies), for the evidence bundle (ADR 0063). */
  readRawPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<RawPage>;
  /** The ids a bundle over `[fromMs, throughMs]` covers, and the session open before them; null for none. */
  bundleSlice(snapshot: Snapshot, fromMs: number, throughMs: number): Promise<BundleSlice | null>;
  readEvidence(ref: EvidenceRef): Promise<Evidence | null>;
  /** The merged id ranges whose strides might hold a datagram received in `[fromMs, toMs)`. */
  locate(snapshot: Snapshot, fromMs: number, toMs: number): Promise<{ fromId: number; toId: number }[]>;
  /** Boundaries after `afterId`, from memory; `done` once the snapshot's end is reached. */
  readBoundaries(
    snapshot: Snapshot, afterId: number, maxEntries: number,
  ): Promise<{ entries: BoundaryEvidence[]; nextAfterId: number; done: boolean }>;
  /** The retained segments the snapshot reaches, oldest first: ids, bytes and policy, for a replay's start and bound (ADR 0066). */
  segmentGeometry(snapshot: Snapshot): Promise<SegmentGeometry[]>;
}

export interface RollupReader {
  /** Null while the sidecar has not yet vouched for anything. */
  watermark(): Promise<RollupWatermark | null>;
  /** Every fragment of every minute in `[fromMinuteMs, toMinuteMs)`; over `maxBytes` is a `RangeError`, never clipped. */
  readMinutes(
    sourceKey: string, fromMinuteMs: number, toMinuteMs: number, maxBytes: number,
  ): Promise<{ minuteMs: number; throughEntryId: number; bytes: Uint8Array }[]>;
  /** Every source key the sidecar holds a minute for, sorted: the engines already admitted. */
  sources(): Promise<string[]>;
  /** The template checkpoints the sidecar holds (ADR 0066), in entry order, without their bytes. */
  checkpoints(): Promise<CheckpointInfo[]>;
  /** The deflated checkpoint through `throughEntryId`, or null for none; `DecodeState.fromCheckpoint` checks what it holds. */
  readCheckpoint(throughEntryId: number): Promise<Uint8Array | null>;
}

export interface RollupWriter {
  /** One batch, its minutes and then its watermark, in one write; `afterEntryId` is where its aggregation began, and the sidecar refuses a batch that does not continue it. */
  appendMinutes(minutes: MinuteInput[], watermark: RollupWatermark, afterEntryId: number, checkpoints?: StoredCheckpoint[]): Promise<void>;
}

/**
 * The sealed archive's read side (ADR 0062): the minutes of what expired. Optional on a runtime, because
 * one that never expired anything has none, and a query without it answers only from the journal.
 */
export interface ArchiveSource {
  /** `history-lost` when the archive is damaged or unreadable; `range-too-large` past `maxBytes`. */
  read(
    sourceKey: string, fromMs: number, toMs: number, maxBytes: number,
  ): Promise<ArchivedMinute[] | 'history-lost' | 'range-too-large'>;
  /** The receipt time through which the archive holds the minutes of what expired; null before any cut. */
  coveredThroughMs(): Promise<number | null>;
  lastCut(): Promise<ArchiveCut | null>;
  /** Every source key the archive holds a minute for, sorted: the engines the expired entries admitted. */
  sources(): Promise<string[]>;
  /** Every cut, oldest first; a bundle keeps those that overlap its range. */
  cuts(): Promise<ArchiveCut[]>;
  /**
   * The minutes of every source in `[floor(fromMs / 60000) * 60000, toMs)` and the policies they were written
   * under, counted from the index without reading a byte; `history-lost` where `read` would say it. Minutes
   * folded from entries at or past `firstRetainedEntryId` are left out: the journal still holds those.
   */
  summary(fromMs: number, toMs: number, firstRetainedEntryId: number): Promise<{ minutes: number; policies: number[] } | 'history-lost'>;
}

/** What a runtime without an archive answers: nothing held, nothing covered. */
export const NO_ARCHIVE: ArchiveSource = {
  read: async () => [],
  coveredThroughMs: async () => null,
  lastCut: async () => null,
  sources: async () => [],
  cuts: async () => [],
  summary: async () => ({ minutes: 0, policies: [] }),
};

/** The archive that would answer is not there to ask, and the journal says it was needed. A bundle maps it to `history-lost`. */
export class HistoryLostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HistoryLostError';
  }
}

/**
 * What a runtime answers when it has no archive to serve but its journal has already expired something: the
 * archive was refused (corrupt, failed, another generation, a read-only open), so what it held is unknown,
 * never empty. `lastCut`, `coveredThroughMs` and `sources` answer as before the archive existed (null, null,
 * none), which is what a runtime with `archive === undefined` always answered those with; the calls that
 * could say "nothing here" say `history-lost` instead, and `cuts` rejects so it cannot be read as no cuts.
 */
export const REFUSED_ARCHIVE: ArchiveSource = {
  read: async () => 'history-lost',
  coveredThroughMs: async () => null,
  lastCut: async () => null,
  sources: async () => [],
  cuts: async () => { throw new HistoryLostError('the sealed archive is not available, and the journal has expired entries it held'); },
  summary: async () => 'history-lost',
};

/**
 * The archive a runtime answers its archive calls from: its own, else `REFUSED_ARCHIVE` when the journal's
 * first retained entry is past 1 (a cut was made, so something expired, whether or not its segments are gone
 * yet), else `NO_ARCHIVE` for a dataset that never expired anything.
 */
export async function archiveOf(runtime: Pick<MonitoringRuntime, 'archive' | 'snapshot'>): Promise<ArchiveSource> {
  if (runtime.archive !== undefined) return runtime.archive;
  return (await runtime.snapshot()).firstEntryId > 1 ? REFUSED_ARCHIVE : NO_ARCHIVE;
}

/** What identifies the open dataset: `dataset.json`'s generation, creation time and what a discard replaced (ADR 0061). */
export interface DatasetMeta {
  /** 32 lowercase hex digits; the journal's generation. */
  generation: string;
  createdMs: number;
  replaced: DatasetFile['replaced'];
}

export interface MonitoringRuntime extends EvidenceReader, RollupReader, RollupWriter {
  /** How the sidecar opened; `rebuild-required` is answered with `resetRollups()`. */
  rollupStatus(): Promise<{ status: RollupOpenStatus; reason?: string }>;
  resetRollups(): Promise<void>;
  /** The open dataset's identity; rejects `RuntimeUnavailableError` where the runtime has none to give. */
  dataset(): Promise<DatasetMeta>;
  /** Absent until the runtime has an archive to serve. */
  readonly archive?: ArchiveSource;
}

/**
 * Where the runtime pushes the entries it has just appended, so the Worker's
 * rollups follow the journal. A handler may return a promise: the transport
 * acknowledges a push once it settles, and that acknowledgement is the credit
 * that lets the next one be sent.
 */
export interface LiveSource {
  onLive(handler: (entries: Evidence[]) => unknown): void;
  /**
   * Called when the runtime's dataset was closed and another opened under the same port (a relocation,
   * a whole discard), before any live push of the new one. What the Worker learned at connect (the
   * generation, the rollup watermark, the admitted engines) is then about a dataset that is gone, and it
   * must adopt the new one again; a generation comparison is not enough, because a relocation to a copy
   * of the same dataset keeps the generation. Optional: an in-process runtime never reopens.
   */
  onReopened?(handler: () => void): void;
}

export type HostRuntime = MonitoringRuntime & LiveSource;

/** The wire shape of a live push (ruling 23); the utility sends it, `runtimeRpc.ts` handles it and answers `{ type: 'live-ack' }`. */
export interface LiveMessage { type: 'live'; entries: Evidence[] }

/** The wire shape of the reopen notice: the utility sends it after a successful reopen, before the new dataset's live feed attaches. */
export interface ReopenedMessage { type: 'reopened' }

/**
 * A stored minute that fails its checksum or is shorter than the index says.
 * A reader sends the minutes it covers to the journal; it does not fail the
 * query, because the sidecar is a cache and the journal is the authority.
 */
export class CorruptRollupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CorruptRollupError';
  }
}

/** The runtime did not answer in time, or its port closed. A query maps it to `runtime-unavailable`. */
export class RuntimeUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuntimeUnavailableError';
  }
}
