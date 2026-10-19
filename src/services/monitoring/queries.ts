/**
 * History queries (ADR 0059): one frozen view of the journal and the sidecar,
 * answered from rollups where a minute can be and from the journal where it
 * cannot, with the same number either way.
 *
 * **That last clause is the property.** A rollup is a cache of a journal prefix,
 * so the rollup answer and the all-raw answer (`forceRaw`) are `deepEqual`
 * except for `answeredFrom`, and `scripts/monitoring/queries.ts` checks it
 * over journals built to break it. Everything below that looks like a special
 * case is a place where the two could part and a rule keeps them together:
 *
 * - **Both views freeze at the start.** The sidecar's watermark `W` is read
 *   first and the journal snapshot `S` second, so `W <= S`. Only fragments
 *   posted at or below `W` are used - a later batch covers entries above `W`,
 *   which are in the tail - and entries in `(W, S]` are read raw and *added to*
 *   the rollup minutes they fall in. A live append or a sidecar post during the
 *   query changes nothing in its answer.
 * - **A minute is answered from rollups only if** it lies wholly inside the
 *   range and wholly inside one bucket, the query is unfocused, and its merged
 *   fragments plus tail are complete with their key union within
 *   `LIMITS.minuteKeyBudget`. Every other minute is read from the journal. The
 *   UI (Task 6) is expected to choose minute-aligned ranges and bucket counts so
 *   that nearly every minute qualifies; a range that is not is correct, only
 *   slower, and it is refused rather than approximated when it is too slow.
 * - **The only whole-query refusal is the raw datagram budget**, counted over
 *   every datagram received inside a raw window or the tail. Each table is
 *   bounded on its own and a table past its bound is refused alone: the totals,
 *   the buckets and the other table stay exact.
 * - **Time is the receipt time**, never a flow's own start or end, and a bucket
 *   is half-open, so a datagram at a bucket's edge is in exactly one.
 *
 * Gaps are never zeros. Coverage comes from the journal's boundaries, so a
 * bucket with no records is `no-records` only where the collector was running;
 * a counter is `null`, never 0, where there are no records.
 */
import { ExpiredRangeError, StaleGenerationError } from './journal';
import { decodeMinuteRollup, type Inflate } from './rollupCodec';
import { MINUTE_MS, EngineAdmission, MinuteAccumulator, ipv4Number, minuteOf } from './rollup';
import { CorruptRollupError, RuntimeUnavailableError, type ArchiveSource, type EvidenceReader, type RollupReader } from './runtime';
import {
  DECODER_POLICY_VERSION, LIMITS, type BoundaryEvidence, type ConversationTotals, type DatagramEvidence, type EndpointTotals, type Evidence,
  type EvidenceRef, type HistoryBucket, type HistoryReply, type HistoryResult, type HistoryTable, type MinuteRollup,
  type NormalizedV5, type QueryFocus, type QuerySpec, type SegmentSource, type Snapshot,
} from './types';
import { decodeV5, exporterKey, exporterOf, isEngineSourceKey, sourceKey } from './v5';

export interface QueryOptions {
  /** Bounded: the codec's own `maxOutput` is passed to it. */
  inflate: Inflate;
  /** Reads every minute from the journal. Same answer, different `answeredFrom`: the test oracle. */
  forceRaw?: boolean;
  /** The wall clock a still-open session is covered up to. Read once, when the query starts. */
  nowMs?: number | (() => number);
  /** One cache per generation, shared by the queries of a host; a query makes its own when none is given. */
  boundaries?: BoundaryCache;
  /** Called between units of work: the host throws here on a cancel and yields here every ~8 ms. */
  checkpoint?: () => Promise<void>;
  /** What to add to a budget refusal while the host is still rebuilding the rollups. */
  rebuildNote?: () => string | null;
  /**
   * Why the sidecar is not to be used at all, when the host already knows (its
   * rollup phase is `failed`): the query then answers from the journal alone,
   * as it does when the sidecar turns out to be unusable by itself.
   */
  rollupsUnavailable?: string;
  /**
   * The sealed archive (ADR 0062): the minutes of what expired. Without it, a range that reaches
   * into expired time answers `history-lost` for it - an unknown, never a zero.
   */
  archive?: ArchiveSource;
}

/** A refusal the query decided on, as opposed to a failure it suffered. */
class Refusal extends Error {
  constructor(readonly code: 'range-too-large' | 'invalid-query' | 'stale-generation' | 'evidence-expired', message: string, readonly expiredMs?: number) {
    super(message);
    this.name = 'Refusal';
  }
}

/**
 * An expiry ran while the query did: whatever it had read describes the journal as it was. Never a reply;
 * `runHistoryQuery` plans again against the journal and the archive as they are now.
 */
class RestartQuery extends Error {
  constructor(readonly expiredMs = 0) {
    super('the journal expired while the query ran');
    this.name = 'RestartQuery';
  }
}

/** How many times a query plans again after an expiry overtook it, before it says so. */
const MAX_RESTARTS = 3;

/**
 * The rollup side cannot be trusted: it threw, or it describes another journal.
 * Never a reply; `runHistoryQuery` answers again from the journal alone.
 */
class RollupUnusable extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RollupUnusable';
  }
}

class QueryCancelled extends Error {
  constructor() {
    super('the query was cancelled');
    this.name = 'AbortError';
  }
}

// --- validation and buckets ---------------------------------------------------------------------------

const DOTTED_QUAD = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** The reason a spec is refused, or null. Untrusted: the UI's numbers arrive over a port. */
export function validateQuery(spec: QuerySpec): string | null {
  if (typeof spec !== 'object' || spec === null) return 'a query is an object';
  const { fromMs, toMs, bucketCount } = spec;
  // The bare exporter key exists to hold the malformed and unsupported counts
  // and is not a source: only what `sourceKey` produces can be asked for.
  if (typeof spec.sourceKey !== 'string' || !isEngineSourceKey(spec.sourceKey)) {
    return 'a query names a source as exporter/engine type/engine id, like 192.0.2.1/0/0';
  }
  if (!Number.isSafeInteger(fromMs) || !Number.isSafeInteger(toMs)) return 'the range is a pair of whole milliseconds';
  if (fromMs < 0 || fromMs >= toMs) return 'the range must satisfy 0 <= fromMs < toMs';
  if (!Number.isInteger(bucketCount) || bucketCount < 1 || bucketCount > LIMITS.buckets) {
    return `bucketCount is a whole number from 1 to ${LIMITS.buckets}`;
  }
  const span = toMs - fromMs;
  if (span < bucketCount) return 'the range is shorter than its bucket count';
  // Bucket edges are i * span / n. Past 2^53 the product stops being exact and
  // an edge would land a millisecond off; no real range comes near it.
  if (!Number.isSafeInteger(span * bucketCount)) return 'the range is too long for its bucket count';
  const f = spec.focus;
  if (f !== undefined) {
    if (typeof f !== 'object' || f === null) return 'a focus is an object';
    if (f.kind === 'endpoint') {
      if (typeof f.address !== 'string' || !DOTTED_QUAD.test(f.address)) return 'a focus address is a dotted IPv4 address';
    } else if (f.kind === 'conversation') {
      if (typeof f.srcAddr !== 'string' || !DOTTED_QUAD.test(f.srcAddr) || typeof f.dstAddr !== 'string' || !DOTTED_QUAD.test(f.dstAddr)) {
        return 'a focus address is a dotted IPv4 address';
      }
    } else return 'a focus is an endpoint or a conversation';
  }
  return null;
}

/** floor(a / b) for whole numbers, exact: a double division can round a quotient up to the next integer. */
function floorDiv(a: number, b: number): number {
  return (a - (a % b)) / b;
}

/** Bucket `i` is `[bounds[i], bounds[i + 1])`; the last edge is `toMs`. */
export function bucketBounds(fromMs: number, toMs: number, bucketCount: number): number[] {
  const span = toMs - fromMs;
  const bounds: number[] = [];
  for (let i = 0; i <= bucketCount; i++) bounds.push(fromMs + floorDiv(i * span, bucketCount));
  return bounds;
}

/** The bucket holding `t`, for `bounds[0] <= t < bounds[n]`. */
function bucketIndex(bounds: number[], t: number): number {
  let lo = 0;
  let hi = bounds.length - 2;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if (bounds[mid] <= t) lo = mid; else hi = mid - 1;
  }
  return lo;
}

// --- boundaries --------------------------------------------------------------------------------------

/**
 * The generation's boundaries, read once and extended as the journal grows.
 * Coverage needs every boundary from the start, and a boundary is a handful of
 * entries per session, so this stays small while the journal does not.
 */
export class BoundaryCache {
  private generation: string | null = null;
  private list: BoundaryEvidence[] = [];
  private through = 0;
  private chain: Promise<void> = Promise.resolve();

  /**
   * Every boundary of the snapshot's generation up to its end that is still on disk. `firstEntryId` is
   * the journal's oldest retained entry: boundaries before it went with their segments, and a read from
   * before it is an `ExpiredRangeError`, so the cache starts from its predecessor and forgets the rest.
   */
  async upTo(reader: EvidenceReader, snapshot: Snapshot, firstEntryId = 1): Promise<BoundaryEvidence[]> {
    // Serialised, so two queries extending the cache cannot both append the same page.
    const run = this.chain.then(() => this.extend(reader, snapshot, firstEntryId));
    this.chain = run.then(() => undefined, () => undefined);
    await run;
    let end = this.list.length;
    while (end > 0 && this.list[end - 1].ref.entryId > snapshot.throughEntryId) end--;
    return this.list.slice(0, end);
  }

  private async extend(reader: EvidenceReader, snapshot: Snapshot, firstEntryId: number): Promise<void> {
    if (this.generation !== snapshot.generation) {
      this.generation = snapshot.generation;
      this.list = [];
      this.through = 0;
    }
    const floor = Math.max(0, firstEntryId - 1);
    if (this.list.length > 0 && this.list[0].ref.entryId <= floor) this.list = this.list.filter((b) => b.ref.entryId > floor);
    this.through = Math.max(this.through, floor);
    while (this.through < snapshot.throughEntryId) {
      const page = await reader.readBoundaries(snapshot, this.through, LIMITS.pageEntries);
      this.list.push(...page.entries);
      this.through = Math.max(this.through, page.nextAfterId);
      if (page.done) break;
    }
  }
}

interface Interval { lo: number; hi: number; reason: string }
interface Hole { lo: number; hi: number; reason: string }

/**
 * The time a collector was running, as intervals, and where it was not.
 *
 * `start` and `resume` open, `stop`, `suspend` and `interrupted` close, in
 * entry order. An interval whose close is earlier than its open - a clock that
 * stepped back - covers `[min, max)` of the two, so a stepped clock can never
 * make a gap read as observed beyond that span. A session still open is still
 * recording, so it covers the rest of the range: the History asks to the close of
 * the minute `nowMs` is in, and the part of it still to come is not a period that
 * was not collected. Time after a session that closed stays a gap, future or not.
 */
function coverage(boundaries: BoundaryEvidence[], nowMs: number, horizon: number | null): Interval[] {
  const out: Interval[] = [];
  let openAt: number | null = null;
  if (horizon !== null) {
    // The `start` that opened a session may have expired with its segment. The first thing the retained
    // boundaries say decides whether the collector was already running where they begin: a close means
    // it was (it is running from the horizon), an open means it was not. With no edge left at all, the
    // expired boundary's own session says what was open when the segments went.
    const edge = boundaries.find((b) => b.action === 'start' || b.action === 'resume' || b.action === 'stop' || b.action === 'suspend' || b.action === 'interrupted');
    if (edge !== undefined) {
      if (edge.action !== 'start' && edge.action !== 'resume') openAt = horizon;
    } else {
      const lastExpired = [...boundaries].reverse().find((b) => b.action === 'expired');
      if (lastExpired !== undefined && lastExpired.sessionId !== '') openAt = horizon;
    }
  }
  for (const b of boundaries) {
    if (b.action === 'start' || b.action === 'resume') {
      if (openAt === null) openAt = b.receivedMs;
    } else if (b.action === 'stop' || b.action === 'suspend' || b.action === 'interrupted') {
      if (openAt === null) continue;
      const reason = b.action === 'suspend' ? 'suspended'
        : b.action === 'interrupted' ? 'interrupted'
        : b.reason === 'storage-limit' ? 'storage-limit' : 'stopped';
      out.push({ lo: Math.min(openAt, b.receivedMs), hi: Math.max(openAt, b.receivedMs), reason });
      openAt = null;
    }
  }
  if (openAt !== null) out.push({ lo: Math.min(openAt, nowMs), hi: Infinity, reason: 'not-recording' });
  return out;
}

/** The receipt time through which raw evidence has expired, from the journal's own `expired` boundaries; null when none has. */
export function expiredHorizon(boundaries: BoundaryEvidence[]): number | null {
  let h: number | null = null;
  for (const b of boundaries) {
    if (b.action === 'expired' && b.expired !== undefined && b.expired !== null && (h === null || b.expired.throughMs > h)) h = b.expired.throughMs;
  }
  return h;
}

/**
 * The newest source a `start` or an `expired` boundary recorded: the exporter a history is scoped to.
 * An expiry that took the only `start` with it still answers, because the `expired` boundary carries
 * the source that was recorded when the segments went.
 */
export function recordedSource(boundaries: BoundaryEvidence[]): SegmentSource | null {
  let found: SegmentSource | null = null;
  for (const b of boundaries) {
    if ((b.action === 'start' || b.action === 'expired') && b.source !== undefined && b.source !== null) found = b.source;
  }
  return found;
}

/** The complement of the union of `intervals` within `[from, to)`; each hole carries why the interval before it ended. */
function holesWithin(intervals: Interval[], from: number, to: number): Hole[] {
  const sorted = intervals.filter((i) => i.hi > i.lo).sort((a, b) => a.lo - b.lo || a.hi - b.hi);
  const holes: Hole[] = [];
  const push = (lo: number, hi: number, reason: string): void => {
    const a = Math.max(lo, from);
    const b = Math.min(hi, to);
    if (b > a) holes.push({ lo: a, hi: b, reason });
  };
  let reach = -Infinity;
  let reason = 'not-recording';
  for (const i of sorted) {
    if (i.lo > reach) push(reach, i.lo, reason);
    if (i.hi > reach) { reach = i.hi; reason = i.reason; }
  }
  push(reach, Infinity, reason);
  return holes;
}

function shedText(dropped: (number | null)[]): string {
  const known = dropped.reduce<number>((n, d) => n + (d ?? 0), 0);
  if (dropped.every((d) => d === null)) return 'shed an unknown number of datagrams';
  if (dropped.some((d) => d === null)) return `shed at least ${known} datagrams`;
  return `shed ${known} datagrams`;
}

// --- tables ------------------------------------------------------------------------------------------

/** A table that stops accumulating at its bound: memory stays bounded and the refusal is that table's alone. */
class KeyTable<V> {
  readonly rows = new Map<string, V>();
  tooLarge = false;

  upsert(key: string, make: () => V): V | null {
    if (this.tooLarge) return null;
    let v = this.rows.get(key);
    if (v === undefined) {
      if (this.rows.size >= LIMITS.tableKeys) {
        this.tooLarge = true;
        this.rows.clear();
        return null;
      }
      v = make();
      this.rows.set(key, v);
    }
    return v;
  }
}

interface EndpointAcc { sent: bigint; received: bigint }
interface ConversationAcc { src: string; dst: string; octets: bigint; packets: bigint }

const byAddress = (a: string, b: string): number => ipv4Number(a) - ipv4Number(b);

function bigintDescending(a: bigint, b: bigint): number {
  return a === b ? 0 : a > b ? -1 : 1;
}

function endpointTable(t: KeyTable<EndpointAcc>): HistoryTable<EndpointTotals> {
  if (t.tooLarge) {
    return {
      status: 'range-too-large',
      message: `The range holds more than ${LIMITS.tableKeys} distinct addresses, so this table is not shown. The totals are exact; narrow the range.`,
    };
  }
  const rows = [...t.rows].map(([address, e]) => ({ address, sentOctets: e.sent, receivedOctets: e.received }));
  rows.sort((a, b) => bigintDescending(a.sentOctets + a.receivedOctets, b.sentOctets + b.receivedOctets) || byAddress(a.address, b.address));
  return { status: 'ok', rows: rows.slice(0, LIMITS.topRows) };
}

function conversationTable(t: KeyTable<ConversationAcc>): HistoryTable<ConversationTotals> {
  if (t.tooLarge) {
    return {
      status: 'range-too-large',
      message: `The range holds more than ${LIMITS.tableKeys} distinct conversations, so this table is not shown. The totals are exact; narrow the range.`,
    };
  }
  const rows = [...t.rows.values()].map((c) => ({ srcAddr: c.src, dstAddr: c.dst, reportedOctets: c.octets, reportedPackets: c.packets }));
  rows.sort((a, b) => bigintDescending(a.reportedOctets, b.reportedOctets) || byAddress(a.srcAddr, b.srcAddr) || byAddress(a.dstAddr, b.dstAddr));
  return { status: 'ok', rows: rows.slice(0, LIMITS.topRows) };
}

// --- the query ----------------------------------------------------------------------------------------

interface Window { from: number; to: number }
interface TailMinute { acc: MinuteAccumulator }
interface Range { fromId: number; toId: number }

/** Fragments are read this many minutes at a time, and no more than `LIMITS.rollupReadBytes` at once. */
const CHUNK_MINUTES = 60;
/** Past this many raw windows each `locate` covers a cluster of them, so a pathological range costs a bounded number of calls. */
const MAX_LOCATES = 256;

export async function runHistoryQuery(
  reader: EvidenceReader, rollups: RollupReader, spec: QuerySpec, signal: AbortSignal, options: QueryOptions,
): Promise<HistoryReply> {
  const invalid = validateQuery(spec);
  if (invalid !== null) return { ok: false, code: 'invalid-query', message: invalid };
  try {
    // An expiry that overtakes the query leaves it holding pages of the journal as it was; it plans
    // again from the start (never mixing the two) and says `evidence-expired` if that keeps happening.
    let expiredMs = 0;
    for (let attempt = 1; ; attempt++) {
      try {
        return { ok: true, value: await answer(reader, rollups, spec, signal, options) };
      } catch (e) {
        if (!(e instanceof RestartQuery) && !(e instanceof ExpiredRangeError)) throw e;
        if (e instanceof RestartQuery) expiredMs = Math.max(expiredMs, e.expiredMs);
        if (signal.aborted) throw new QueryCancelled();
        if (attempt >= MAX_RESTARTS) {
          return {
            ok: false, code: 'evidence-expired', expiredMs,
            message: 'The journal expired while this query ran, more than once. Ask again.',
          };
        }
      }
    }
  } catch (e) {
    if (signal.aborted || (e instanceof Error && e.name === 'AbortError')) return { ok: false, code: 'cancelled', message: 'the query was cancelled' };
    if (e instanceof Refusal) {
      return e.expiredMs === undefined ? { ok: false, code: e.code, message: e.message } : { ok: false, code: e.code, message: e.message, expiredMs: e.expiredMs };
    }
    if (e instanceof StaleGenerationError) return { ok: false, code: 'stale-generation', message: e.message };
    if (e instanceof RuntimeUnavailableError) return { ok: false, code: 'runtime-unavailable', message: e.message };
    return { ok: false, code: 'storage-failed', message: e instanceof Error ? e.message : String(e) };
  }
}

async function answer(
  reader: EvidenceReader, rollups: RollupReader, spec: QuerySpec, signal: AbortSignal, options: QueryOptions,
): Promise<HistoryResult> {
  // The sidecar is a cache: when it cannot be used the journal answers alone,
  // exactly, and only the raw budget can refuse. A fault of the journal is
  // not caught here - it is `stale-generation` or `storage-failed` in the caller.
  let unusable = options.rollupsUnavailable ?? null;
  if (unusable === null) {
    try {
      return await new Query(reader, rollups, spec, signal, options, null).run();
    } catch (e) {
      if (!(e instanceof RollupUnusable)) throw e;
      unusable = e.message;
    }
  }
  return await new Query(reader, rollups, spec, signal, options, unusable).run();
}

class Query {
  private readonly from: number;
  private readonly to: number;
  private readonly bounds: number[];
  private readonly exporter: string;
  private readonly focused: boolean;
  private readonly rawOnly: boolean;
  private readonly buckets: { records: number; octets: bigint; packets: bigint }[];
  private readonly endpoints = new KeyTable<EndpointAcc>();
  private readonly conversations = new KeyTable<ConversationAcc>();
  private readonly evidence: { ref: EvidenceRef; recordIndex: number }[] = [];
  private malformed = 0;
  private unsupported = 0;
  private matching = 0;
  private unknownSampling = 0;
  private read = 0;
  private snapshot!: Snapshot;
  private watermark = 0;
  private admission!: EngineAdmission;
  private admitted = false;
  /** The journal's oldest retained entry: everything before it expired. */
  private firstEntryId = 1;
  /** Where the raw tail begins: after the sidecar's watermark, and never inside expired ids. */
  private tailAfter = 0;
  /** The expired cuts the journal's boundaries record, and the receipt time through which raw evidence is gone. */
  private cuts: { fromMs: number; throughMs: number }[] = [];
  private horizon: number | null = null;
  /** Time the query cannot answer: expired minutes the archive could not give back, or only gives whole. */
  private readonly lost: Window[] = [];
  /** Buckets that drew on the archive. */
  private readonly archived = new Set<number>();
  /** A table that is missing minutes whose evidence expired. */
  private tablesExpired = false;
  /** The archive's last cut when the query began: a different one at the end means an expiry overtook it. */
  private cutAtStart: number | null = null;

  constructor(
    private readonly reader: EvidenceReader, private readonly rollups: RollupReader, private readonly spec: QuerySpec,
    private readonly signal: AbortSignal, private readonly options: QueryOptions,
    /** Why the rollups are not used, or null: W is 0, no fragment is read and the journal admits the engines. */
    private readonly unusable: string | null,
  ) {
    this.from = spec.fromMs;
    this.to = spec.toMs;
    this.bounds = bucketBounds(spec.fromMs, spec.toMs, spec.bucketCount);
    this.exporter = exporterOf(spec.sourceKey);
    this.focused = spec.focus !== undefined;
    // Rollups hold no references and no per-record focus, so a focused query,
    // like a forced one, reads every minute from the journal.
    this.rawOnly = this.focused || options.forceRaw === true || unusable !== null;
    this.buckets = Array.from({ length: spec.bucketCount }, () => ({ records: 0, octets: 0n, packets: 0n }));
  }

  private async tick(): Promise<void> {
    if (this.signal.aborted) throw new QueryCancelled();
    if (this.options.checkpoint !== undefined) await this.options.checkpoint();
    if (this.signal.aborted) throw new QueryCancelled();
  }

  /**
   * What a failed sidecar call means: the sidecar is unusable, unless the
   * failure is the query's own cancel or the runtime itself being gone, which
   * no journal fallback can answer either. A stale generation raised by a
   * sidecar call is the sidecar's fault; the journal's own is raised by calls
   * that never pass through here.
   */
  private rollupFailure(e: unknown): unknown {
    if (this.signal.aborted || e instanceof RuntimeUnavailableError) return e;
    if (e instanceof Error && e.name === 'AbortError') return e;
    return new RollupUnusable(e instanceof Error ? e.message : String(e));
  }

  private async rollupCall<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (e) {
      throw this.rollupFailure(e);
    }
  }

  private tooLarge(what: string): Refusal {
    const note = this.unusable !== null
      ? `The rollups are unavailable (${this.unusable}), so every minute of the range is read from the journal.`
      : this.options.rebuildNote?.() ?? null;
    return new Refusal(
      'range-too-large',
      `${what} more than ${LIMITS.rawQueryDatagrams} datagrams have to be read from the journal for this range; narrow it.${note === null ? '' : ` ${note}`}`,
    );
  }

  async run(): Promise<HistoryResult> {
    const clock = this.options.nowMs;
    const nowMs = typeof clock === 'function' ? clock() : clock ?? Date.now();

    // Watermark first, journal second: the sidecar can only cover what the
    // journal already held, so W <= S and the tail (W, S] is well defined.
    const mark = this.unusable === null ? await this.rollupCall(() => this.rollups.watermark()) : null;
    const snap = await this.reader.snapshot();
    this.snapshot = { generation: snap.generation, throughEntryId: snap.throughEntryId };
    this.firstEntryId = snap.firstEntryId;
    this.cutAtStart = await this.archiveCut();
    if (mark !== null) {
      // A sidecar of another journal, another decoder or the future vouches for
      // nothing here; it is not the journal's fault, so it is not `stale-generation`.
      if (mark.generation !== snap.generation) {
        throw new RollupUnusable(`the rollups belong to generation ${mark.generation}, the journal is generation ${snap.generation}`);
      }
      if (mark.policyVersion !== DECODER_POLICY_VERSION) {
        throw new RollupUnusable(`the rollups were made by decoder policy ${mark.policyVersion}, this build is ${DECODER_POLICY_VERSION}`);
      }
      if (mark.throughEntryId > snap.throughEntryId) {
        throw new RollupUnusable(`the rollups claim entry ${mark.throughEntryId}, the journal ends at ${snap.throughEntryId}`);
      }
      // A sidecar that stops short of the oldest retained entry describes entries that no longer exist.
      if (mark.throughEntryId < this.firstEntryId - 1) {
        throw new RollupUnusable(`the rollups end at entry ${mark.throughEntryId}, and the journal begins at ${this.firstEntryId}`);
      }
      this.watermark = mark.throughEntryId;
    }
    this.tailAfter = Math.max(this.watermark, this.firstEntryId - 1);
    await this.tick();

    const boundaries = await (this.options.boundaries ?? new BoundaryCache()).upTo(this.reader, this.snapshot, this.firstEntryId);
    this.horizon = expiredHorizon(boundaries);
    this.cuts = boundaries.flatMap((b) => (b.action === 'expired' && b.expired ? [{ fromMs: b.expired.fromMs, throughMs: b.expired.throughMs }] : []));
    this.refuseFocusedOverExpired();
    await this.tick();
    await this.admit();

    const lastAligned = this.alignedRange();
    const raw: Window[] = [];
    let rollupMinutes = 0;
    if (this.rawOnly) {
      this.rawOrLost(this.from, this.to, raw);
    } else {
      const tail = await this.scanTail(lastAligned);
      rollupMinutes = await this.foldRollups(lastAligned, tail, raw);
      await this.addEdgeWindows(lastAligned, raw);
    }
    const windows = mergeWindows(raw);
    await this.scanRaw(windows);

    // An expiry that ran meanwhile reset the sidecar and moved the journal's start under what was read.
    if (await this.archiveCut() !== this.cutAtStart) throw new RestartQuery(this.horizon ?? 0);

    return this.result(boundaries, nowMs, rollupMinutes, windows);
  }

  // --- expired time -------------------------------------------------------------------------------------

  private async archiveCut(): Promise<number | null> {
    const archive = this.options.archive;
    if (archive === undefined) return null;
    try {
      return (await archive.lastCut())?.throughEntryId ?? null;
    } catch (e) {
      if (this.signal.aborted || e instanceof RuntimeUnavailableError || (e instanceof Error && e.name === 'AbortError')) throw e;
      return null;
    }
  }

  /** Whether any of `[from, to)` can lie in time whose raw evidence has expired. */
  private touchesExpired(from: number): boolean {
    return this.horizon !== null && from <= this.horizon;
  }

  /** A focus names records, and records are raw evidence: a focused range that reaches expired time cannot be answered. */
  private refuseFocusedOverExpired(): void {
    if (!this.focused || !this.touchesExpired(this.from)) return;
    const hits = this.cuts.filter((c) => c.fromMs < this.to && this.from <= c.throughMs);
    const expiredMs = hits.length > 0 ? Math.max(...hits.map((c) => c.throughMs)) : this.horizon!;
    throw new Refusal(
      'evidence-expired',
      'The raw records for part of this range have expired, so the records behind a conversation or an address are no longer here. The totals of the range are still available without a focus.',
      expiredMs,
    );
  }

  private markLost(from: number, to: number): void {
    const last = this.lost[this.lost.length - 1];
    if (last !== undefined && from <= last.to && from >= last.from) last.to = Math.max(last.to, to);
    else this.lost.push({ from, to });
  }

  /** A raw window, with whatever part of it is expired time set aside as lost: the journal cannot read it. */
  private rawOrLost(from: number, to: number, raw: Window[]): void {
    if (!this.touchesExpired(from)) { raw.push({ from, to }); return; }
    const end = Math.min(to, this.horizon! + 1);
    this.markLost(from, end);
    if (end < to) raw.push({ from: end, to });
  }

  /**
   * One archived key over `[a, hi)` into `out`, minute by minute. An archive that is absent, damaged or
   * unreadable, or a minute that does not decode, makes those minutes lost; a range over the byte cap is
   * halved down to a single minute first.
   */
  private async archiveFragments(key: string, a: number, hi: number, out: Map<number, MinuteRollup[]>, lostMinutes: Set<number>): Promise<void> {
    const stack: [number, number][] = [[a, hi]];
    while (stack.length > 0) {
      await this.tick();
      const [lo, h] = stack.pop()!;
      let res: Awaited<ReturnType<ArchiveSource['read']>> = 'history-lost';
      const archive = this.options.archive;
      if (archive !== undefined) {
        try {
          res = await archive.read(key, lo, h, LIMITS.archiveReadBytes);
        } catch (e) {
          if (this.signal.aborted || e instanceof RuntimeUnavailableError || (e instanceof Error && e.name === 'AbortError')) throw e;
        }
      }
      if (res === 'history-lost') { for (let m = lo; m < h; m += MINUTE_MS) lostMinutes.add(m); continue; }
      if (res === 'range-too-large') {
        if (h - lo <= MINUTE_MS) { lostMinutes.add(lo); continue; }
        const mid = lo + Math.ceil((h - lo) / MINUTE_MS / 2) * MINUTE_MS;
        stack.push([mid, h], [lo, mid]);
        continue;
      }
      for (const row of res) {
        // A fragment from an expiry this snapshot has not seen is still in the journal, and counted there.
        if (row.throughEntryId >= this.firstEntryId) continue;
        try {
          const rollup = decodeMinuteRollup(row.bytes, this.options.inflate);
          if (rollup.minuteMs !== row.minuteMs || rollup.sourceKey !== key) throw new Error('an archived minute is filed under another key');
          const list = out.get(row.minuteMs);
          if (list === undefined) out.set(row.minuteMs, [rollup]); else list.push(rollup);
        } catch {
          lostMinutes.add(row.minuteMs);
        }
      }
    }
  }

  /** Whether the archive holds anything of this source for one minute: `none` (the raw journal is exact), `some`, or `lost`. */
  private async archiveHolds(m: number): Promise<'none' | 'some' | 'lost'> {
    const found = new Map<number, MinuteRollup[]>();
    const lostMinutes = new Set<number>();
    if (this.admitted) await this.archiveFragments(this.spec.sourceKey, m, m + MINUTE_MS, found, lostMinutes);
    await this.archiveFragments(exporterKey(this.exporter), m, m + MINUTE_MS, found, lostMinutes);
    return lostMinutes.size > 0 ? 'lost' : found.size > 0 ? 'some' : 'none';
  }

  /** The minutes wholly inside the range: `[a, b)` with both on minute edges, or empty. */
  private alignedRange(): { a: number; b: number } {
    const a = Math.ceil(this.from / MINUTE_MS) * MINUTE_MS;
    const b = minuteOf(this.to);
    return { a, b };
  }

  /** The leading and trailing partial minutes, which are never answered from a rollup. */
  private async addEdgeWindows(r: { a: number; b: number }, raw: Window[]): Promise<void> {
    if (r.a >= r.b) { await this.edgeWindow(this.from, this.to, raw); return; }
    if (this.from < r.a) await this.edgeWindow(this.from, r.a, raw);
    if (r.b < this.to) await this.edgeWindow(r.b, this.to, raw);
  }

  /**
   * A partial minute, which only the journal can answer. Where the minute lies in time that has
   * expired, the journal holds only its retained part: it is exact if the archive holds nothing of the
   * minute for this source, and lost otherwise - a part of a minute cannot be taken from a whole one.
   */
  private async edgeWindow(from: number, to: number, raw: Window[]): Promise<void> {
    if (!this.touchesExpired(from)) { raw.push({ from, to }); return; }
    for (let m = minuteOf(from); m < to; m += MINUTE_MS) {
      if (m > this.horizon!) break;
      if (await this.archiveHolds(m) !== 'none') { this.markLost(from, to); return; }
    }
    raw.push({ from, to });
  }

  // --- admission -------------------------------------------------------------------------------------

  /**
   * Whether the source has a row at all: the first 16 engines of an exporter,
   * in journal order. The sidecar's sources are the ones already admitted; the
   * entries above the watermark are scanned in order for the rest. Learned from
   * the sidecar even where it ran past `S`, the set only ever grows and freezes
   * at the cap, so it is right for every entry the snapshot holds. With no
   * usable sidecar the set starts empty and W is 0, so the scan covers the
   * journal from its first entry.
   *
   * The scan stops as soon as the answer is decided: the source is admitted, or
   * its exporter already has its 16 engines without it, which is "not admitted"
   * (records 0 everywhere). Only the exporter's own datagrams can change that
   * exporter's admission, so only they are decoded and only they count against
   * the cap - another exporter's traffic, however much of it comes first, cannot
   * strand a source.
   */
  private async admit(): Promise<void> {
    const known = this.unusable === null ? [...await this.rollupCall(() => this.rollups.sources())] : [];
    // The engines the expired entries admitted are in the archive; admission freezes at its cap, so they decide who is next.
    const archive = this.options.archive;
    if (this.horizon !== null && archive !== undefined) {
      try {
        known.push(...await archive.sources());
      } catch (e) {
        if (this.signal.aborted || e instanceof RuntimeUnavailableError || (e instanceof Error && e.name === 'AbortError')) throw e;
      }
    }
    this.admission = new EngineAdmission(known);
    const key = this.spec.sourceKey;
    this.admitted = this.admission.has(key);
    if (this.admitted || this.admission.full(this.exporter)) return;
    let datagrams = 0;
    await this.scan([{ fromId: this.tailAfter + 1, toId: this.snapshot.throughEntryId }], (e) => {
      if (e.kind !== 'datagram' || e.remoteIPv4 !== this.exporter) return false;
      if (++datagrams > LIMITS.rawQueryDatagrams) throw this.admissionRefusal();
      const d = decodeV5(e, e.remoteIPv4);
      if (d.kind === 'valid') this.admission.admit(sourceKey(e.remoteIPv4, d.engineType, d.engineId));
      if (this.admission.has(key)) { this.admitted = true; return true; }
      return this.admission.full(this.exporter);
    });
  }

  /**
   * Admission could not be decided inside its cap. It looks for the source's
   * first datagram, not for the range's, so narrowing the range cannot help and
   * this does not say it can: it says what is actually limiting.
   */
  private admissionRefusal(): Refusal {
    const lead = this.unusable !== null
      ? `The rollups are unavailable (${this.unusable}), and the source's first datagram could not be found within the first ${LIMITS.rawQueryDatagrams} datagrams of its exporter in the journal.`
      : `The source has no rollups yet, and its first datagram could not be found within the first ${LIMITS.rawQueryDatagrams} datagrams of its exporter after the last rollup.`;
    const note = this.unusable === null ? this.options.rebuildNote?.() ?? null : null;
    return new Refusal('range-too-large', `${lead} Whether it has any history could not be decided; a narrower range does not change that.${note === null ? '' : ` ${note}`}`);
  }

  // --- the tail ---------------------------------------------------------------------------------------

  /**
   * The entries above the watermark that fall in the range, counted against the
   * budget once and, for the minutes that could be rollups, accumulated: the
   * tail is added to what the fragments hold. Edge minutes are counted but not
   * accumulated - they will be read raw - and the accumulators together keep at
   * most `LIMITS.tableKeys` keys; a minute that would pass it is abandoned, which
   * only sends it to the journal.
   */
  private async scanTail(r: { a: number; b: number }): Promise<Map<number, TailMinute>> {
    const tail = new Map<number, TailMinute>();
    if (this.tailAfter >= this.snapshot.throughEntryId) return tail;
    const ranges = (await this.reader.locate(this.snapshot, this.from, this.to))
      .map((x) => ({ fromId: Math.max(x.fromId, this.tailAfter + 1), toId: x.toId }))
      .filter((x) => x.fromId <= x.toId);
    let keys = 0;
    await this.scan(ranges, (e) => {
      if (e.kind !== 'datagram' || e.receivedMs < this.from || e.receivedMs >= this.to) return false;
      if (++this.read > LIMITS.rawQueryDatagrams) throw this.tooLarge('Counting the entries after the last rollup,');
      const m = minuteOf(e.receivedMs);
      if (m < r.a || m >= r.b) return false;
      const d = decodeV5(e, e.remoteIPv4);
      let t = tail.get(m);
      const minute = (): TailMinute => {
        if (t === undefined) { t = { acc: new MinuteAccumulator(this.spec.sourceKey, m) }; tail.set(m, t); }
        return t;
      };
      if (d.kind !== 'valid') {
        if (e.remoteIPv4 === this.exporter) {
          if (d.kind === 'malformed') minute().acc.malformed++; else minute().acc.unsupported++;
        }
        return false;
      }
      if (!this.admitted || sourceKey(e.remoteIPv4, d.engineType, d.engineId) !== this.spec.sourceKey) return false;
      const acc = minute().acc;
      if (d.flows.length === 0) return false;
      for (const flow of d.flows) {
        const before = acc.keyCount;
        acc.addFlow(flow);
        keys += acc.keyCount - before;
        if (keys > LIMITS.tableKeys) { keys -= acc.keyCount; acc.abandon(); }
      }
      return false;
    });
    return tail;
  }

  // --- rollups -----------------------------------------------------------------------------------------

  /**
   * Walks the whole minutes of the range a chunk at a time, merges each
   * minute's fragments with its tail, and folds the ones that qualify into the
   * buckets and tables. The ones that do not become raw windows. Returns the
   * number answered from rollups.
   */
  private async foldRollups(r: { a: number; b: number }, tail: Map<number, TailMinute>, raw: Window[]): Promise<number> {
    let answered = 0;
    const source = this.spec.sourceKey;
    const exporter = exporterKey(this.exporter);
    // Minutes below this may hold entries that expired, and their rollups are in the archive.
    const expiredBelow = this.horizon === null ? 0 : minuteOf(this.horizon) + MINUTE_MS;
    for (let a = r.a; a < r.b; a += CHUNK_MINUTES * MINUTE_MS) {
      await this.tick();
      const b = Math.min(r.b, a + CHUNK_MINUTES * MINUTE_MS);
      const unreadable = new Set<number>();
      const fromSource = this.admitted ? await this.fragments(source, a, b, unreadable) : new Map<number, MinuteRollup[]>();
      const fromExporter = await this.fragments(exporter, a, b, unreadable);
      const archivedSource = new Map<number, MinuteRollup[]>();
      const archivedExporter = new Map<number, MinuteRollup[]>();
      const lostMinutes = new Set<number>();
      if (expiredBelow > a) {
        const hi = Math.min(b, expiredBelow);
        if (this.admitted) await this.archiveFragments(source, a, hi, archivedSource, lostMinutes);
        await this.archiveFragments(exporter, a, hi, archivedExporter, lostMinutes);
      }
      const minutes = new Set<number>([...fromSource.keys(), ...fromExporter.keys(), ...unreadable, ...archivedSource.keys(), ...archivedExporter.keys(), ...lostMinutes]);
      for (const m of tail.keys()) if (m >= a && m < b) minutes.add(m);
      for (const m of [...minutes].sort((x, y) => x - y)) {
        if (lostMinutes.has(m)) { this.markLost(m, m + MINUTE_MS); continue; }
        const merged = new MinuteAccumulator(source, m);
        for (const f of fromSource.get(m) ?? []) merged.absorb(f);
        for (const f of fromExporter.get(m) ?? []) merged.absorb(f);
        const drewArchive = archivedSource.has(m) || archivedExporter.has(m);
        for (const f of archivedSource.get(m) ?? []) merged.absorb(f);
        for (const f of archivedExporter.get(m) ?? []) merged.absorb(f);
        const t = tail.get(m);
        if (t !== undefined) merged.absorb(t.acc.toRollup());
        const whole = this.bucketOf(m) === this.bucketOf(m + MINUTE_MS - 1);
        if (drewArchive) {
          // The journal no longer holds this minute's expired part, so it cannot be read again to split
          // it between buckets or to repair a part that does not decode: only the whole sum answers.
          if (!whole || unreadable.has(m)) { this.markLost(m, m + MINUTE_MS); continue; }
          if (merged.records > 0) this.archived.add(this.bucketOf(m));
          this.foldMinute(merged, merged.complete);
          // Totals are exact whatever happened to the keys; an abandoned minute has no table rows to give.
          if (!merged.complete) this.tablesExpired = true;
          answered++;
          continue;
        }
        if (!whole || !merged.complete || unreadable.has(m)) {
          raw.push({ from: m, to: m + MINUTE_MS });
          continue;
        }
        this.foldMinute(merged, true);
        answered++;
      }
      for (const m of [...tail.keys()]) if (m < b) tail.delete(m);
    }
    return answered;
  }

  /**
   * The decoded fragments of one key over `[a, b)`, only those posted at or
   * below the watermark. A range over the byte cap, or one holding a minute
   * that fails its checksum, is halved; one minute still over the cap or still
   * corrupt, or one that does not decode to the minute it is filed under, is
   * reported in `unreadable` and answered raw - a rollup is a cache, never a
   * reason to fail a query the journal can answer. Any other fault of the
   * sidecar makes the whole query start again without it (`RollupUnusable`).
   */
  private async fragments(key: string, a: number, b: number, unreadable: Set<number>): Promise<Map<number, MinuteRollup[]>> {
    const out = new Map<number, MinuteRollup[]>();
    const stack: [number, number][] = [[a, b]];
    while (stack.length > 0) {
      await this.tick();
      const [lo, hi] = stack.pop()!;
      let rows: { minuteMs: number; throughEntryId: number; bytes: Uint8Array }[];
      try {
        rows = await this.rollups.readMinutes(key, lo, hi, LIMITS.rollupReadBytes);
      } catch (e) {
        if (!(e instanceof RangeError) && !(e instanceof CorruptRollupError)) throw this.rollupFailure(e);
        if (hi - lo <= MINUTE_MS) { for (let m = lo; m < hi; m += MINUTE_MS) unreadable.add(m); continue; }
        const mid = lo + Math.ceil((hi - lo) / MINUTE_MS / 2) * MINUTE_MS;
        stack.push([mid, hi], [lo, mid]);
        continue;
      }
      for (const row of rows) {
        if (row.throughEntryId > this.watermark) continue;
        try {
          const rollup = decodeMinuteRollup(row.bytes, this.options.inflate);
          if (rollup.minuteMs !== row.minuteMs || rollup.sourceKey !== key) throw new Error('a stored minute is filed under another key');
          const list = out.get(row.minuteMs);
          if (list === undefined) out.set(row.minuteMs, [rollup]); else list.push(rollup);
        } catch {
          unreadable.add(row.minuteMs);
        }
      }
    }
    return out;
  }

  private bucketOf(t: number): number {
    return bucketIndex(this.bounds, t);
  }

  private foldMinute(m: MinuteAccumulator, withTables: boolean): void {
    this.malformed += m.malformed;
    this.unsupported += m.unsupported;
    if (m.records === 0) return;
    const bucket = this.buckets[this.bucketOf(m.minuteMs)];
    bucket.records += m.records;
    bucket.octets += m.reportedOctets;
    bucket.packets += m.reportedPackets;
    this.matching += m.records;
    this.unknownSampling += m.unknownSamplingRecords;
    if (!withTables) return;
    for (const [address, e] of m.endpoints) {
      const row = this.endpoints.upsert(address, () => ({ sent: 0n, received: 0n }));
      if (row !== null) { row.sent += e.sent; row.received += e.received; }
    }
    for (const [key, c] of m.conversations) {
      const row = this.conversations.upsert(key, () => ({ src: c.src, dst: c.dst, octets: 0n, packets: 0n }));
      if (row !== null) { row.octets += c.octets; row.packets += c.packets; }
    }
  }

  // --- the raw pass -------------------------------------------------------------------------------------

  /**
   * Reads the union of the windows' id ranges once, in id order, and takes
   * from each entry only what falls inside a window. An entry is read once
   * whatever the clock did, and a minute answered from a rollup is never inside
   * a window, so nothing is counted twice.
   */
  private async scanRaw(windows: Window[]): Promise<void> {
    if (windows.length === 0) return;
    const ranges = await this.locateAll(windows);
    const starts = windows.map((w) => w.from);
    const inWindow = (t: number): boolean => {
      let lo = 0;
      let hi = starts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >>> 1;
        if (starts[mid] <= t) lo = mid; else hi = mid - 1;
      }
      return starts[lo] <= t && t < windows[lo].to;
    };
    await this.scan(ranges, (e) => {
      if (e.kind !== 'datagram' || !inWindow(e.receivedMs)) return false;
      // Tail entries were counted when the tail was scanned.
      if (this.rawOnly || e.ref.entryId <= this.watermark) {
        if (++this.read > LIMITS.rawQueryDatagrams) throw this.tooLarge('At least');
      }
      this.foldDatagram(e);
      return false;
    });
  }

  private async locateAll(windows: Window[]): Promise<Range[]> {
    let groups: Window[] = windows;
    if (windows.length > MAX_LOCATES) {
      groups = [];
      const per = Math.ceil(windows.length / MAX_LOCATES);
      for (let i = 0; i < windows.length; i += per) groups.push({ from: windows[i].from, to: windows[Math.min(windows.length, i + per) - 1].to });
    }
    const all: Range[] = [];
    for (const g of groups) {
      await this.tick();
      all.push(...await this.reader.locate(this.snapshot, g.from, g.to));
    }
    all.sort((x, y) => x.fromId - y.fromId);
    const merged: Range[] = [];
    for (const r of all) {
      const last = merged[merged.length - 1];
      if (last !== undefined && r.fromId <= last.toId + 1) last.toId = Math.max(last.toId, r.toId);
      else merged.push({ ...r });
    }
    return merged;
  }

  private foldDatagram(e: DatagramEvidence): void {
    const d = decodeV5(e, e.remoteIPv4);
    if (d.kind !== 'valid') {
      // Malformed and unsupported datagrams belong to the exporter, whatever
      // the source asked for or the focus chose: they are counted by receipt.
      if (e.remoteIPv4 === this.exporter) { if (d.kind === 'malformed') this.malformed++; else this.unsupported++; }
      return;
    }
    if (!this.admitted || sourceKey(e.remoteIPv4, d.engineType, d.engineId) !== this.spec.sourceKey) return;
    for (const flow of d.flows) if (this.matches(flow)) this.foldFlow(flow);
  }

  private matches(flow: NormalizedV5): boolean {
    const f: QueryFocus | undefined = this.spec.focus;
    if (f === undefined) return true;
    return f.kind === 'endpoint'
      ? flow.srcAddr === f.address || flow.dstAddr === f.address
      : flow.srcAddr === f.srcAddr && flow.dstAddr === f.dstAddr;
  }

  private foldFlow(flow: NormalizedV5): void {
    const bucket = this.buckets[this.bucketOf(flow.receivedMs)];
    bucket.records++;
    bucket.octets += flow.reportedOctets;
    bucket.packets += flow.reportedPackets;
    this.matching++;
    if (flow.sampling.kind === 'unknown') this.unknownSampling++;
    if (this.focused && this.evidence.length < LIMITS.focusedReferences) {
      this.evidence.push({ ref: flow.ref, recordIndex: flow.recordIndex });
    }
    const s = this.endpoints.upsert(flow.srcAddr, () => ({ sent: 0n, received: 0n }));
    if (s !== null) s.sent += flow.reportedOctets;
    const d = this.endpoints.upsert(flow.dstAddr, () => ({ sent: 0n, received: 0n }));
    if (d !== null) d.received += flow.reportedOctets;
    const c = this.conversations.upsert(`${flow.srcAddr}>${flow.dstAddr}`, () => ({ src: flow.srcAddr, dst: flow.dstAddr, octets: 0n, packets: 0n }));
    if (c !== null) { c.octets += flow.reportedOctets; c.packets += flow.reportedPackets; }
  }

  /** Pages through `ranges` in id order; `visit` returns true to stop early. */
  private async scan(ranges: Range[], visit: (e: Evidence) => boolean): Promise<void> {
    for (const r of ranges) {
      if (r.fromId > r.toId) continue;
      let after = r.fromId - 1;
      paging: for (;;) {
        await this.tick();
        const page = await this.reader.readPage(this.snapshot, after, LIMITS.pageEntries, LIMITS.pageBytes);
        for (const e of page.entries) {
          // A page can run past the range's end; the next range picks up from its own start.
          if (e.ref.entryId > r.toId) break paging;
          if (visit(e)) return;
        }
        if (page.done || page.entries.length === 0) break;
        after = page.nextAfterId;
      }
    }
  }

  // --- the answer ---------------------------------------------------------------------------------------

  private result(boundaries: BoundaryEvidence[], nowMs: number, rollupMinutes: number, windows: Window[]): HistoryResult {
    // Where the raw evidence has expired the boundaries that said whether anything was running went with
    // it: that time is not a collection gap, it is time the archive answers for (or has lost).
    const horizon = this.horizon;
    const holes = holesWithin(coverage(boundaries, nowMs, horizon), this.from, this.to)
      .map((h) => (horizon === null ? h : { ...h, lo: Math.max(h.lo, horizon) }))
      .filter((h) => h.hi > h.lo);
    const lostBuckets = new Set<number>();
    for (const w of this.lost) {
      const lo = Math.max(w.from, this.from);
      const hi = Math.min(w.to, this.to);
      if (hi <= lo) continue;
      for (let i = this.bucketOf(lo), end = this.bucketOf(hi - 1); i <= end; i++) lostBuckets.add(i);
    }
    const shed: { t: number; dropped: number | null }[] = [];
    for (const b of boundaries) if (b.action === 'gap' && b.receivedMs >= this.from && b.receivedMs < this.to) shed.push({ t: b.receivedMs, dropped: b.droppedDatagrams });

    const shedByBucket = new Map<number, { t: number; dropped: (number | null)[] }>();
    for (const s of shed) {
      const i = this.bucketOf(s.t);
      const entry = shedByBucket.get(i);
      if (entry === undefined) shedByBucket.set(i, { t: s.t, dropped: [s.dropped] }); else entry.dropped.push(s.dropped);
    }

    const buckets: HistoryBucket[] = this.buckets.map((b, i) => {
      const fromMs = this.bounds[i];
      const toMs = this.bounds[i + 1];
      const hasGap = shedByBucket.has(i) || holes.some((h) => h.lo < toMs && h.hi > fromMs);
      // history-lost > collection-gap > aggregate-only > observed-records > no-records
      if (lostBuckets.has(i)) {
        // Part of the bucket is unknown, so none of it is claimed: a partial sum would read as the whole.
        return { fromMs, toMs, records: 0, coverage: 'history-lost', reportedOctets: null, reportedPackets: null };
      }
      const coverageKind = hasGap ? 'collection-gap'
        : this.archived.has(i) ? 'aggregate-only'
        : b.records > 0 ? 'observed-records' : 'no-records';
      return {
        fromMs, toMs, records: b.records, coverage: coverageKind,
        // Null where nothing was recorded: a gap is never drawn as zero traffic.
        reportedOctets: b.records > 0 ? b.octets : null,
        reportedPackets: b.records > 0 ? b.packets : null,
      };
    });
    const unavailable = this.tablesExpired || this.lost.length > 0;
    const expiredTable = <Row>():HistoryTable<Row> => ({ status: 'evidence-expired', expiredMs: this.horizon ?? 0 });

    const gaps = [
      ...holes.map((h) => ({ fromMs: h.lo, toMs: h.hi, reason: h.reason })),
      ...[...shedByBucket.values()].map((s) => ({ fromMs: s.t, toMs: s.t, reason: shedText(s.dropped) })),
    ].sort((x, y) => x.fromMs - y.fromMs || x.toMs - y.toMs);

    let rawMinutes = 0;
    for (const w of windows) rawMinutes += (minuteOf(w.to - 1) - minuteOf(w.from)) / MINUTE_MS + 1;

    return {
      snapshot: this.snapshot,
      query: { ...this.spec },
      buckets,
      gaps,
      endpoints: unavailable ? expiredTable() : endpointTable(this.endpoints),
      conversations: unavailable ? expiredTable() : conversationTable(this.conversations),
      malformed: this.malformed,
      unsupported: this.unsupported,
      samplingKnown: this.matching > 0 && this.unknownSampling === 0,
      matchingRecords: this.matching,
      answeredFrom: { rollupMinutes, rawMinutes },
      evidence: this.focused ? this.evidence : [],
    };
  }
}

/** Sorted, disjoint windows: touching ones are joined, because a window per minute would be a `locate` per minute. */
function mergeWindows(windows: Window[]): Window[] {
  const sorted = windows.filter((w) => w.to > w.from).sort((a, b) => a.from - b.from);
  const out: Window[] = [];
  for (const w of sorted) {
    const last = out[out.length - 1];
    if (last !== undefined && w.from <= last.to) last.to = Math.max(last.to, w.to);
    else out.push({ ...w });
  }
  return out;
}

