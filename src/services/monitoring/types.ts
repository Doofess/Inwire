/**
 * The shared vocabulary of NetFlow v5 monitoring (ADRs 0058-0060).
 *
 * A utility process receives datagrams from one configured exporter and
 * writes them, with the boundaries around them, to a journal that is the only
 * authority. A sandboxed Worker decodes them, rolls them up by receipt-time
 * minute, and answers history queries; the rollups are a cache it can always
 * rebuild from the journal. Everything here is plain data, so it crosses a
 * `postMessage` unchanged and runs under plain `tsx`.
 *
 * Counters are `bigint`: a day of 32-bit octet counters passes 2^53. They
 * become decimal strings only at the JSON and CSV boundaries.
 *
 * Time ranges are half-open, `[fromMs, toMs)`, throughout.
 */

// --- versions and limits ------------------------------------------------------

/** The journal's and the sidecar's format version (ADR 0059's header, offset 8). */
export const FORMAT_VERSION = 1;

/**
 * How datagrams are read into records. A journal written under another policy
 * is preserved and refused, never reinterpreted (ADR 0059).
 */
export const DECODER_POLICY_VERSION = 1;

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

/** Every bound ADRs 0058 and 0059 set, in one place. */
export const LIMITS = {
  /** The owner's 8 GiB, over the plan's 1 GiB (ADR 0059). */
  defaultStorageBytes: 8 * GiB,
  minStorageBytes: 16 * MiB,
  /** Kept back inside the limit for the closing and health records. */
  closingReserveBytes: 64 * KiB,
  /** The IPv4 UDP maximum; a datagram body is this plus 24 bytes of metadata. */
  maxPayloadBytes: 65_507,
  maxBodyBytes: 65_531,
  /** Endpoints and conversations together, per source and minute. */
  minuteKeyBudget: 16_384,
  enginesPerExporter: 16,
  rejectedSenders: 16,
  inboxDatagrams: 1_024,
  inboxBytes: 8 * MiB,
  liveCreditBatches: 4,
  liveBatchDatagrams: 64,
  liveBatchBytes: 256 * KiB,
  pageEntries: 256,
  pageBytes: 1 * MiB,
  rawQueryDatagrams: 100_000,
  rawQueryKeys: 50_000,
  /** Per table: a table past it comes back refused while the totals stay exact. */
  tableKeys: 50_000,
  buckets: 120,
  topRows: 20,
  focusedReferences: 100,
  concurrentQueries: 2,
  handshakeMs: 15_000,
  requestMs: 15_000,
  drainMs: 5_000,
  staleMs: 60_000,
  flushMs: 1_000,
} as const;

// --- configuration --------------------------------------------------------------

/** One exporter, one specific local address, one port (ADR 0058). */
export interface SourceConfig {
  exporterIPv4: string;
  /** A literal local address; `0.0.0.0` is refused. */
  bindIPv4: string;
  port: number;
  storageLimitBytes: number;
}

// --- evidence: what the journal holds --------------------------------------------

/** 32 lowercase hex digits: the journal header's 16 random bytes. */
export type Generation = string;

export interface EvidenceRef { generation: Generation; entryId: number }

export interface DatagramEvidence {
  kind: 'datagram';
  ref: EvidenceRef;
  /** The session the nearest `start` boundary before it opened. */
  sessionId: string;
  /** The utility's wall clock at receipt. */
  receivedMs: number;
  /** Arrival order; it is the entry id, so it never depends on the clock. */
  receiveOrdinal: number;
  localIPv4: string;
  localPort: number;
  remoteIPv4: string;
  remotePort: number;
  bytes: Uint8Array;
}

export type BoundaryAction = 'start' | 'stop' | 'suspend' | 'resume' | 'interrupted' | 'gap';

export interface BoundaryEvidence {
  kind: 'boundary';
  ref: EvidenceRef;
  sessionId: string;
  receivedMs: number;
  action: BoundaryAction;
  reason: string;
  /** Shed locally before append; null where nothing was counted. Kernel drops are never known. */
  droppedDatagrams: number | null;
}

export type Evidence = DatagramEvidence | BoundaryEvidence;

/** A frozen view of the journal: a query answers against this and nothing later. */
export interface Snapshot { generation: Generation; throughEntryId: number }

export interface JournalSnapshot extends Snapshot {
  writtenBytes: number;
  /** Flushed to the OS's disk by the one-second timer or a Stop; not power-loss durable. */
  syncedThroughEntryId: number;
}

export interface EvidencePage { entries: Evidence[]; nextAfterId: number; done: boolean }

// --- decoding --------------------------------------------------------------------

export type Sampling = { kind: 'unknown' } | { kind: 'reported'; mode: number; interval: number };

/** One v5 record, as reported, filed under its datagram's receipt time. */
export interface NormalizedV5 {
  ref: EvidenceRef;
  recordIndex: number;
  sourceKey: string;
  receivedMs: number;
  /** The record's own flow times, kept for detail; they never move it to another bucket. */
  startMs: number;
  endMs: number;
  srcAddr: string;
  dstAddr: string;
  srcPort: number;
  dstPort: number;
  protocol: number;
  inputIf: number;
  outputIf: number;
  reportedOctets: bigint;
  reportedPackets: bigint;
  sampling: Sampling;
}

export type DecodeResult =
  | { kind: 'valid'; engineType: number; engineId: number; sequence: number; uptimeMs: number; flows: NormalizedV5[] }
  | { kind: 'unsupported' | 'malformed'; reason: string };

// --- rollups ---------------------------------------------------------------------

export interface EndpointTotals { address: string; sentOctets: bigint; receivedOctets: bigint }

/** A conversation is the directional address pair; ports and protocol are a raw drill-down (ADR 0059). */
export interface ConversationTotals { srcAddr: string; dstAddr: string; reportedOctets: bigint; reportedPackets: bigint }

/**
 * One source's receipt-time minute. Over `LIMITS.minuteKeyBudget` keys it is
 * stored incomplete: totals exact, both maps empty, answered raw.
 */
export interface MinuteRollup {
  sourceKey: string;
  minuteMs: number;
  complete: boolean;
  records: number;
  reportedOctets: bigint;
  reportedPackets: bigint;
  endpoints: EndpointTotals[];
  conversations: ConversationTotals[];
  malformed: number;
  unsupported: number;
}

/** What the sidecar covers. Any disagreement with the journal means rebuild, never trust. */
export interface RollupWatermark { generation: Generation; throughEntryId: number; policyVersion: number }

// --- history queries ----------------------------------------------------------------

export type QueryFocus =
  | { kind: 'endpoint'; address: string }
  | { kind: 'conversation'; srcAddr: string; dstAddr: string };

export interface QuerySpec {
  sourceKey: string;
  fromMs: number;
  toMs: number;
  bucketCount: number;
  focus?: QueryFocus;
}

export type BucketCoverage = 'observed-records' | 'no-records' | 'collection-gap';

export interface HistoryBucket {
  fromMs: number;
  toMs: number;
  /** Null where nothing was recorded: a gap is never drawn as zero traffic. */
  reportedOctets: bigint | null;
  reportedPackets: bigint | null;
  records: number;
  coverage: BucketCoverage;
}

/** Each table is bounded on its own, so a table past its bound never refuses the totals (ADR 0059). */
export type HistoryTable<Row> =
  | { status: 'ok'; rows: Row[] }
  | { status: 'range-too-large'; message: string };

export interface HistoryResult {
  snapshot: Snapshot;
  query: QuerySpec;
  buckets: HistoryBucket[];
  gaps: { fromMs: number; toMs: number; reason: string }[];
  endpoints: HistoryTable<EndpointTotals>;
  conversations: HistoryTable<ConversationTotals>;
  malformed: number;
  unsupported: number;
  samplingKnown: boolean;
  matchingRecords: number;
  answeredFrom: { rollupMinutes: number; rawMinutes: number };
  /** A focused query's first `LIMITS.focusedReferences` supporting records, in journal order. */
  evidence: { ref: EvidenceRef; recordIndex: number }[];
}

export type HistoryReply =
  | { ok: true; value: HistoryResult }
  | {
    ok: false;
    code: 'range-too-large' | 'cancelled' | 'stale-generation' | 'runtime-unavailable' | 'storage-failed';
    message: string;
  };
