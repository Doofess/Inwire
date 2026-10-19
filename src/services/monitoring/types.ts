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

/**
 * The decoder policies this build reads (ADR 0062). Each segment records the
 * policy it was written under; one outside this set is refused as
 * `refused-version` and left untouched. A new segment is written under the
 * newest of them.
 */
export const ACCEPTED_POLICIES: readonly number[] = [1];

/** The policy a rollup, a segment or an archived minute is written under: the newest accepted. */
export const WRITE_POLICY_VERSION: number = Math.max(...ACCEPTED_POLICIES);

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
  /** One `readMinutes` answer; `readMinutes` refuses past it rather than clipping, so it is the queries' chunk as well. */
  rollupReadBytes: 8 * MiB,
  /** One archive read; past it the read is refused rather than clipped (ADR 0062). */
  archiveReadBytes: 8 * MiB,
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
  /**
   * The slowest rate an `open` is allowed to scan the journal at. Open CRCs
   * every entry synchronously - 18.7 s for a full 8 GiB measured in memory -
   * so its deadline grows with the limit: `requestMs` plus the limit at this
   * rate, about 2.4 minutes at the default.
   */
  openScanBytesPerSecond: 64 * MiB,
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

/** The configuration a session was started with: where it listened and for whom (ADR 0062). */
export interface SegmentSource { exporterIPv4: string; bindIPv4: string; port: number }

/** What an `expired` boundary says left the journal: whole segments, by entry id and by receipt time. */
export interface ExpiredRange { fromEntryId: number; throughEntryId: number; fromMs: number; throughMs: number }

export type BoundaryAction = 'start' | 'stop' | 'suspend' | 'resume' | 'interrupted' | 'gap' | 'expired';

export interface BoundaryEvidence {
  kind: 'boundary';
  ref: EvidenceRef;
  sessionId: string;
  receivedMs: number;
  action: BoundaryAction;
  /** For `expired`: `age`, `limit` or `user-before`. */
  reason: string;
  /** Shed locally before append; null where nothing was counted. Kernel drops are never known. */
  droppedDatagrams: number | null;
  /** A `start`'s recorded source, and the newest one an `expired` boundary carries; absent where none was written. */
  source?: SegmentSource | null;
  /** Present on an `expired` boundary. It does not change the open session. */
  expired?: ExpiredRange | null;
}

export type Evidence = DatagramEvidence | BoundaryEvidence;

/** A frozen view of the journal: a query answers against this and nothing later. */
export interface Snapshot { generation: Generation; throughEntryId: number }

export interface JournalSnapshot extends Snapshot {
  /** The oldest entry id still on disk; ids below it expired (ADR 0062). */
  firstEntryId: number;
  /** Every retained segment's bytes. */
  writtenBytes: number;
  /** Flushed to the OS's disk by the one-second timer or a Stop; not power-loss durable. */
  syncedThroughEntryId: number;
}

export interface EvidencePage { entries: Evidence[]; nextAfterId: number; done: boolean }

/**
 * One journal entry as it lies in the file: the body bytes, not a decoded `Evidence`. A boundary re-encoded from
 * its evidence is not byte-identical (the reader ignores keys it does not know), so the evidence bundle
 * (ADR 0063) carries what the journal holds. `policy` is the decoder policy of the entry's segment.
 */
export interface RawEntry { entryId: number; kind: 1 | 2; policy: number; receivedMs: number; body: Uint8Array }

export interface RawPage { entries: RawEntry[]; nextAfterId: number; done: boolean }

/**
 * The ids an evidence bundle's range covers (ADR 0063): every entry from the first with `receivedMs >= fromMs`
 * through the last with `receivedMs <= throughMs`, whatever their own times, so a clock that stepped back cannot
 * leave a hole. `sessionAtStart` is the session open before the first entry, which a datagram's session is not
 * in its body to say; `startEntryId` is null once the journal no longer holds that session's `start`.
 */
export interface BundleSlice {
  firstEntryId: number;
  throughEntryId: number;
  /** The distinct decoder policies of the segments the slice crosses, ascending. */
  policies: number[];
  sessionAtStart: { sessionId: string; source: SegmentSource | null; startEntryId: number | null } | null;
}

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
  /**
   * Records whose datagram said nothing about sampling. A bucket's sampling is
   * known only if none of its records are in this count.
   */
  unknownSamplingRecords: number;
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

/**
 * `aggregate-only`: the minutes came, wholly or partly, from the archive after
 * their raw datagrams expired. `history-lost`: the archive could not give them
 * back, so the bucket is unknown, never zero.
 */
export type BucketCoverage = 'observed-records' | 'no-records' | 'collection-gap' | 'aggregate-only' | 'history-lost';

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
  | { status: 'range-too-large'; message: string }
  /** The minute's raw datagrams expired and its tables were never archived whole; totals are still exact. */
  | { status: 'evidence-expired'; expiredMs: number };

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
  /**
   * A focused query's first `LIMITS.focusedReferences` (100) supporting
   * records, in journal order. `matchingRecords` still counts every match, so a
   * caller can say "100 of 4,213": the list is a detail limit, never the count.
   */
  evidence: { ref: EvidenceRef; recordIndex: number }[];
}

export type HistoryReply =
  | { ok: true; value: HistoryResult }
  | {
    ok: false;
    code: 'range-too-large' | 'invalid-query' | 'cancelled' | 'stale-generation' | 'runtime-unavailable' | 'storage-failed' | 'evidence-expired';
    message: string;
    /** For `evidence-expired`: the receipt time up to which raw evidence is gone. */
    expiredMs?: number;
  };

/**
 * What a replay of expiring entries needs to know of the world before them:
 * the sources already admitted (admission freezes at a cap, so the set decides
 * who is admitted next) and the session and source open at the first entry.
 */
export interface SessionContext {
  knownSources: readonly string[];
  sessionId?: string | null;
  source?: SegmentSource | null;
}
