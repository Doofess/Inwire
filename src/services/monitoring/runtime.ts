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
  BoundaryEvidence, Evidence, EvidencePage, EvidenceRef, JournalSnapshot, RollupWatermark, Snapshot,
} from './types';
import type { MinuteInput, RollupOpenStatus } from './rollupStore';

/** The journal's side: read-only, and always against a snapshot the caller froze. */
export interface EvidenceReader {
  snapshot(): Promise<JournalSnapshot>;
  readPage(snapshot: Snapshot, afterId: number, maxEntries: number, maxBytes: number): Promise<EvidencePage>;
  readEvidence(ref: EvidenceRef): Promise<Evidence | null>;
  /** The merged id ranges whose strides might hold a datagram received in `[fromMs, toMs)`. */
  locate(snapshot: Snapshot, fromMs: number, toMs: number): Promise<{ fromId: number; toId: number }[]>;
  /** Boundaries after `afterId`, from memory; `done` once the snapshot's end is reached. */
  readBoundaries(
    snapshot: Snapshot, afterId: number, maxEntries: number,
  ): Promise<{ entries: BoundaryEvidence[]; nextAfterId: number; done: boolean }>;
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
}

export interface RollupWriter {
  /** One batch, its minutes and then its watermark, in one write. */
  appendMinutes(minutes: MinuteInput[], watermark: RollupWatermark): Promise<void>;
}

export interface MonitoringRuntime extends EvidenceReader, RollupReader, RollupWriter {
  /** How the sidecar opened; `rebuild-required` is answered with `resetRollups()`. */
  rollupStatus(): Promise<{ status: RollupOpenStatus; reason?: string }>;
  resetRollups(): Promise<void>;
}

/** Where the runtime pushes the entries it has just appended, so the Worker's rollups follow the journal. */
export interface LiveSource {
  onLive(handler: (entries: Evidence[]) => void): void;
}

export type HostRuntime = MonitoringRuntime & LiveSource;

/** The wire shape of a live push (ruling 23); Task 5's utility sends it, `runtimeRpc.ts` handles it. */
export interface LiveMessage { type: 'live'; entries: Evidence[] }

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
