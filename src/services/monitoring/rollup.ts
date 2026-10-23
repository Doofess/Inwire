/**
 * Minute rollups: what the Worker derives from the journal so a history query
 * does not have to read it all (ADR 0059).
 *
 * A rollup is a **cache of a journal prefix**, never a second dataset. Three
 * rules make that true and each is here because a plausible alternative gives
 * a wrong number rather than an error:
 *
 * - **One open minute per source.** A flow whose minute differs from its
 *   source's open one seals the open one as a *fragment* and opens a new one.
 *   A clock that steps back therefore makes a second fragment for a minute
 *   already sealed, and a reader sums fragments; keeping every minute open
 *   until the end would be unbounded state, and merging into a sealed one would
 *   rewrite the sidecar.
 * - **A minute over `LIMITS.minuteKeyBudget` keys keeps its totals and drops
 *   its maps**, endpoints and conversations counted together. It is stored
 *   incomplete and answered from the journal, because the alternative - keep the
 *   largest keys - is an approximation, and a rollup answer must equal a raw one.
 * - **The watermark is a promise about the journal.** Every entry with an id at
 *   or below it is in exactly one posted fragment; no entry above it is in any.
 *   `drain` is the only place that promise is made, and it computes the
 *   watermark from what is *not* posted - an open minute, or a sealed fragment
 *   held back because an earlier-starting one is still open - never from what
 *   is.
 *
 * Live and rebuild feed the same class in the same order, so a replay of the
 * same journal produces the same fragments to the byte (`sortedRollup`).
 */
import {
  LIMITS, SAMPLING_MIXED, WRITE_POLICY_VERSION, type ConversationTotals, type DecodeResult, type EndpointTotals, type Evidence,
  type MinuteClock, type MinuteRollup, type NormalizedV5,
} from './types';
import { exporterKey, exporterOf, isEngineSourceKey } from './v5';
import type { DecodeState, DecodeStep, RecordSampling } from './decodeState';
import type { FlowDecode } from './flowDecode';
import { addressBytes, compareAddresses } from './rollupCodec';

export const MINUTE_MS = 60_000;

/** The receipt-time minute a timestamp belongs to. */
export function minuteOf(timeMs: number): number {
  return Math.floor(timeMs / MINUTE_MS) * MINUTE_MS;
}

/** A dotted quad as the unsigned number it is, for ordering: `10.0.0.9` before `10.0.0.10`. */
export function ipv4Number(address: string): number {
  const p = address.split('.');
  return ((Number(p[0]) * 256 + Number(p[1])) * 256 + Number(p[2])) * 256 + Number(p[3]);
}

/** Addresses in the order a table is stored and a tie is broken: IPv4 before IPv6, each by its bytes. */
export function byAddress(a: string, b: string): number {
  if (a.includes(':') || b.includes(':')) return compareAddresses(a, b);
  return ipv4Number(a) - ipv4Number(b);
}

/** One address as a sort key, parsed once: IPv4 as its number, IPv6 as its 16 bytes. IPv4 sorts before IPv6. */
export type AddressKey = number | Uint8Array;

export function addressKey(address: string): AddressKey {
  return address.includes(':') ? addressBytes(address) : ipv4Number(address);
}

/** The order of `byAddress`, between two keys already made. */
export function compareAddressKeys(a: AddressKey, b: AddressKey): number {
  if (typeof a === 'number') return typeof b === 'number' ? a - b : -1;
  if (typeof b === 'number') return 1;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * Sorts `rows` in place by `primary` and then by each of their addresses in turn, every address parsed once per
 * row (decorate, sort, undecorate) and not twice per comparison. The order is exactly that of `byAddress`.
 */
export function sortByAddresses<T>(rows: T[], addressesOf: (row: T) => readonly string[], primary?: (a: T, b: T) => number): void {
  const decorated = rows.map((row) => ({ row, keys: addressesOf(row).map(addressKey) }));
  decorated.sort((a, b) => {
    const p = primary === undefined ? 0 : primary(a.row, b.row);
    if (p !== 0) return p;
    for (let i = 0; i < a.keys.length; i++) {
      const c = compareAddressKeys(a.keys[i], b.keys[i]);
      if (c !== 0) return c;
    }
    return 0;
  });
  for (let i = 0; i < rows.length; i++) rows[i] = decorated[i].row;
}

/** Two samplings of one minute folded into one: none yet, the same rate, or `SAMPLING_MIXED` (ADR 0066). */
export function foldSampling(a: number, b: number): number {
  if (a === 0) return b;
  if (b === 0) return a;
  return a === b ? a : SAMPLING_MIXED;
}

// --- one datagram's records, as every reader folds them -------------------------------------------------

/** One direction of a record: who sent how much to whom. A record has a forward leg and, in a biflow, a reverse one. */
export interface FlowLeg { src: string; dst: string; octets: bigint; packets: bigint }

export interface RecordFold {
  recordIndex: number;
  /** What the record adds to the bucket: forward plus reverse, whether or not it has addresses. */
  octets: bigint;
  packets: bigint;
  /** Empty for a record without both addresses: it is in the totals and in no table. */
  legs: FlowLeg[];
  sampling: RecordSampling;
}

/** A valid datagram as the rollups and the raw scans count it; one definition, so they cannot disagree. */
export interface DatagramFold {
  sourceKey: string;
  records: RecordFold[];
  /** Records of templates with no octet count: counted, never totalled. */
  unsupportedTemplateRecords: number;
  awaitingSets: number;
  awaitingBytes: number;
  /** Export time less receipt time; null for v5. */
  skewMs: number | null;
}

type DatagramStep = Extract<DecodeStep, { kind: 'datagram' }>;

/**
 * A datagram's fold, or null where it did not decode (it is then malformed or unsupported and counted as such).
 * A biflow record's reverse counts are a second leg, dst to src, only where they are not both zero: a
 * reverse of nothing is not a conversation. The forward leg is always there, zero or not, as v5's is.
 */
export function foldOf(step: DatagramStep): DatagramFold | null {
  const d = step.decoded;
  if (d.kind !== 'valid') return null;
  const records = d.flows.map((f, i): RecordFold => {
    const legs: FlowLeg[] = [];
    const revOctets = f.reverseOctets ?? 0n;
    const revPackets = f.reversePackets ?? 0n;
    if (f.srcAddr !== '' && f.dstAddr !== '') {
      legs.push({ src: f.srcAddr, dst: f.dstAddr, octets: f.reportedOctets, packets: f.reportedPackets });
      if (revOctets !== 0n || revPackets !== 0n) legs.push({ src: f.dstAddr, dst: f.srcAddr, octets: revOctets, packets: revPackets });
    }
    return {
      recordIndex: f.recordIndex, octets: f.reportedOctets + revOctets, packets: f.reportedPackets + revPackets, legs,
      sampling: step.sampling[i] ?? { kind: 'unknown' },
    };
  });
  let awaitingSets = 0;
  let awaitingBytes = 0;
  for (const a of [...d.awaiting, ...d.refused]) { awaitingSets += a.sets; awaitingBytes += a.bytes; }
  return {
    sourceKey: d.sourceKey, records, unsupportedTemplateRecords: d.dataRecords - d.flows.length, awaitingSets, awaitingBytes,
    skewMs: step.skewMs,
  };
}

/**
 * One source's one minute, growing. The same arithmetic backs the aggregator,
 * a query's merge of fragments and the tail's records, so "the union of keys
 * passes the budget" means the same thing in all three.
 */
export class MinuteAccumulator {
  records = 0;
  reportedOctets = 0n;
  reportedPackets = 0n;
  malformed = 0;
  unsupported = 0;
  unknownSamplingRecords = 0;
  awaitingSets = 0;
  awaitingBytes = 0;
  unsupportedTemplateRecords = 0;
  unsupportedSamplingRecords = 0;
  samplingInterval = 0;
  clock: MinuteClock | null = null;
  complete = true;
  readonly endpoints = new Map<string, { sent: bigint; received: bigint }>();
  readonly conversations = new Map<string, { src: string; dst: string; octets: bigint; packets: bigint }>();

  /** `policy` is the decoder policy of the segment the minute's entries came from (ADR 0066). */
  constructor(readonly sourceKey: string, readonly minuteMs: number, readonly policy: number) {}

  get keyCount(): number { return this.endpoints.size + this.conversations.size; }

  /** Marks the minute incomplete and lets go of its keys: the totals stay exact. */
  abandon(): void {
    this.complete = false;
    this.endpoints.clear();
    this.conversations.clear();
  }

  private endpoint(address: string): { sent: bigint; received: bigint } | null {
    let e = this.endpoints.get(address);
    if (e === undefined) {
      if (this.keyCount >= LIMITS.minuteKeyBudget) { this.abandon(); return null; }
      e = { sent: 0n, received: 0n };
      this.endpoints.set(address, e);
    }
    return e;
  }

  private conversation(src: string, dst: string): { src: string; dst: string; octets: bigint; packets: bigint } | null {
    const key = `${src}>${dst}`;
    let c = this.conversations.get(key);
    if (c === undefined) {
      if (this.keyCount >= LIMITS.minuteKeyBudget) { this.abandon(); return null; }
      c = { src, dst, octets: 0n, packets: 0n };
      this.conversations.set(key, c);
    }
    return c;
  }

  /** A v5 record on its own, for a caller that has not decoded through a `DecodeState`: its sampling is its header's. */
  addFlow(flow: NormalizedV5, sampling?: RecordSampling): void {
    this.addRecord({
      recordIndex: flow.recordIndex, octets: flow.reportedOctets, packets: flow.reportedPackets,
      legs: [{ src: flow.srcAddr, dst: flow.dstAddr, octets: flow.reportedOctets, packets: flow.reportedPackets }],
      sampling: sampling ?? (flow.sampling.kind === 'reported'
        ? { kind: 'known', interval: Math.max(1, flow.sampling.interval) } : { kind: 'unknown' }),
    }, this.policy);
  }

  /**
   * A whole valid datagram. `entryPolicy` is the policy of the entry it came from: a rate is folded into
   * the minute only from a policy-2 entry, because a policy-1 minute has no field to keep it in.
   */
  addDatagram(fold: DatagramFold, entryPolicy: number = this.policy): void {
    this.awaitingSets += fold.awaitingSets;
    this.awaitingBytes += fold.awaitingBytes;
    this.records += fold.unsupportedTemplateRecords;
    this.unsupportedTemplateRecords += fold.unsupportedTemplateRecords;
    if (fold.skewMs !== null) this.noteSkew(fold.skewMs);
    for (const r of fold.records) this.addRecord(r, entryPolicy);
  }

  private noteSkew(skewMs: number): void {
    const c = this.clock;
    this.clock = c === null
      ? { minSkewMs: skewMs, maxSkewMs: skewMs, lastSkewMs: skewMs }
      : { minSkewMs: Math.min(c.minSkewMs, skewMs), maxSkewMs: Math.max(c.maxSkewMs, skewMs), lastSkewMs: skewMs };
  }

  private addRecord(r: RecordFold, entryPolicy: number): void {
    this.records++;
    this.reportedOctets += r.octets;
    this.reportedPackets += r.packets;
    if (r.sampling.kind === 'unknown') this.unknownSamplingRecords++;
    else if (r.sampling.kind === 'unsupported') this.unsupportedSamplingRecords++;
    else if (entryPolicy >= 2) this.samplingInterval = foldSampling(this.samplingInterval, r.sampling.interval);
    for (const leg of r.legs) {
      if (!this.complete) return;
      // A leg with the same source and destination is both a sender and a
      // receiver of its own octets, once each: the table has one row for it.
      const s = this.endpoint(leg.src);
      if (s === null) return;
      s.sent += leg.octets;
      const d = this.endpoint(leg.dst);
      if (d === null) return;
      d.received += leg.octets;
      const c = this.conversation(leg.src, leg.dst);
      if (c === null) return;
      c.octets += leg.octets;
      c.packets += leg.packets;
    }
  }

  /**
   * Adds a stored fragment (or another accumulator's rollup). Incomplete input
   * makes the sum incomplete, and so does a union of keys past the budget -
   * the re-check a reader must make, because each fragment alone was within it.
   */
  absorb(other: MinuteRollup): void {
    this.records += other.records;
    this.reportedOctets += other.reportedOctets;
    this.reportedPackets += other.reportedPackets;
    this.malformed += other.malformed;
    this.unsupported += other.unsupported;
    this.unknownSamplingRecords += other.unknownSamplingRecords;
    this.awaitingSets += other.awaitingSets;
    this.awaitingBytes += other.awaitingBytes;
    this.unsupportedTemplateRecords += other.unsupportedTemplateRecords;
    this.unsupportedSamplingRecords += other.unsupportedSamplingRecords;
    this.samplingInterval = foldSampling(this.samplingInterval, other.samplingInterval);
    // The later fragment's last skew is the minute's: callers absorb in entry order.
    if (other.clock !== null) {
      const c = this.clock;
      this.clock = c === null ? { ...other.clock } : {
        minSkewMs: Math.min(c.minSkewMs, other.clock.minSkewMs), maxSkewMs: Math.max(c.maxSkewMs, other.clock.maxSkewMs),
        lastSkewMs: other.clock.lastSkewMs,
      };
    }
    if (!other.complete) this.abandon();
    if (!this.complete) return;
    for (const e of other.endpoints) {
      const mine = this.endpoint(e.address);
      if (mine === null) return;
      mine.sent += e.sentOctets;
      mine.received += e.receivedOctets;
    }
    for (const c of other.conversations) {
      const mine = this.conversation(c.srcAddr, c.dstAddr);
      if (mine === null) return;
      mine.octets += c.reportedOctets;
      mine.packets += c.reportedPackets;
    }
  }

  /** The rollup, its keys in a fixed order: the same journal always encodes to the same bytes. */
  toRollup(): MinuteRollup {
    const endpoints: EndpointTotals[] = [...this.endpoints]
      .map(([address, e]) => ({ address, sentOctets: e.sent, receivedOctets: e.received }));
    sortByAddresses(endpoints, (e) => [e.address]);
    const conversations: ConversationTotals[] = [...this.conversations.values()]
      .map((c) => ({ srcAddr: c.src, dstAddr: c.dst, reportedOctets: c.octets, reportedPackets: c.packets }));
    sortByAddresses(conversations, (c) => [c.srcAddr, c.dstAddr]);
    return {
      sourceKey: this.sourceKey, minuteMs: this.minuteMs, complete: this.complete, records: this.records,
      reportedOctets: this.reportedOctets, reportedPackets: this.reportedPackets, endpoints, conversations,
      malformed: this.malformed, unsupported: this.unsupported, unknownSamplingRecords: this.unknownSamplingRecords,
      policy: this.policy, awaitingSets: this.awaitingSets, awaitingBytes: this.awaitingBytes,
      unsupportedTemplateRecords: this.unsupportedTemplateRecords, unsupportedSamplingRecords: this.unsupportedSamplingRecords,
      samplingInterval: this.samplingInterval, clock: this.clock === null ? null : { ...this.clock },
    };
  }
}

/**
 * Which engines get a row. The first `LIMITS.enginesPerExporter` distinct
 * `(type, id)` per exporter *in journal order* are admitted and the rest are
 * never rolled up - the same rule as `canAdmitEngine`, which the utility
 * applies to its health. The set only grows and freezes at the cap, so the set
 * at any point in the journal is right for every entry before it, and the
 * Worker can learn it from the sidecar's source keys and extend it from the
 * entries after.
 */
export class EngineAdmission {
  private readonly keys = new Set<string>();
  private readonly perExporter = new Map<string, number>();

  /** `known` is a list of source keys; an exporter-level key is not an engine and is skipped. */
  constructor(known: Iterable<string> = []) {
    for (const k of known) if (isEngineSourceKey(k)) this.add(k);
  }

  private add(key: string): void {
    if (this.keys.has(key)) return;
    this.keys.add(key);
    const exporter = exporterOf(key);
    this.perExporter.set(exporter, (this.perExporter.get(exporter) ?? 0) + 1);
  }

  has(key: string): boolean { return this.keys.has(key); }

  /** True when the exporter already has its full set of engines: nothing new is admitted for it, ever. */
  full(exporter: string): boolean { return (this.perExporter.get(exporter) ?? 0) >= LIMITS.enginesPerExporter; }

  /** True when `key` is admitted, admitting it now if it is new and there is room. */
  admit(key: string): boolean {
    if (this.keys.has(key)) return true;
    if ((this.perExporter.get(exporterOf(key)) ?? 0) >= LIMITS.enginesPerExporter) return false;
    this.add(key);
    return true;
  }
}

/** A sealed minute and the journal entries it was made from. */
export interface Fragment { rollup: MinuteRollup; firstId: number; lastId: number }

interface OpenMinute { acc: MinuteAccumulator; firstId: number; lastId: number }

export class MinuteAggregator {
  private readonly open = new Map<string, OpenMinute>();
  private held: Fragment[] = [];
  private lastFed: number;
  /** The policy of the entries being fed; a change seals every open minute (ADR 0066). */
  private policy = WRITE_POLICY_VERSION;
  /** The watermark of the last batch drained, or the one this aggregator began after: where the next batch continues from. */
  private drainedThrough: number;

  /** `afterEntryId` is the watermark the sidecar already holds: the first entry fed is the one after it. */
  constructor(afterEntryId = 0) {
    this.lastFed = afterEntryId;
    this.drainedThrough = afterEntryId;
  }

  /** The highest entry id fed so far. */
  get fedThrough(): number { return this.lastFed; }

  /**
   * The policy of the entry about to be fed. A minute is encoded under its segment's policy, so a change
   * seals every open minute, as a `stop` does; in practice it comes at a `start`, after one.
   */
  enterPolicy(policy: number): void {
    if (policy === this.policy) return;
    this.seal(Infinity);
    this.policy = policy;
  }

  /** Notes an entry that rolled up nothing - a boundary, a datagram of an engine not admitted. */
  fed(entryId: number): void {
    if (entryId > this.lastFed) this.lastFed = entryId;
  }

  private minute(key: string, receivedMs: number, entryId: number): MinuteAccumulator {
    this.fed(entryId);
    const minuteMs = minuteOf(receivedMs);
    let o = this.open.get(key);
    if (o !== undefined && o.acc.minuteMs !== minuteMs) {
      this.retire(key, o);
      o = undefined;
    }
    if (o === undefined) {
      o = { acc: new MinuteAccumulator(key, minuteMs, this.policy), firstId: entryId, lastId: entryId };
      this.open.set(key, o);
    }
    o.lastId = entryId;
    return o.acc;
  }

  private retire(key: string, o: OpenMinute): void {
    this.open.delete(key);
    this.held.push({ rollup: o.acc.toRollup(), firstId: o.firstId, lastId: o.lastId });
  }

  /** One record of a valid export, filed under its source and its datagram's receipt minute. */
  add(flow: NormalizedV5): void {
    this.minute(flow.sourceKey, flow.receivedMs, flow.ref.entryId).addFlow(flow);
  }

  /** A valid export with no records still makes its minute: the exporter spoke, and the query must see it. */
  touch(sourceKey: string, receivedMs: number, entryId: number): void {
    this.minute(sourceKey, receivedMs, entryId);
  }

  /** A whole valid datagram of any protocol, filed under its source and its receipt minute; the entry's policy is the aggregator's. */
  addDatagram(fold: DatagramFold, receivedMs: number, entryId: number): void {
    this.minute(fold.sourceKey, receivedMs, entryId).addDatagram(fold, this.policy);
  }

  addMalformed(exporterIPv4: string, receivedMs: number, entryId: number): void {
    this.minute(exporterKey(exporterIPv4), receivedMs, entryId).malformed++;
  }

  addUnsupported(exporterIPv4: string, receivedMs: number, entryId: number): void {
    this.minute(exporterKey(exporterIPv4), receivedMs, entryId).unsupported++;
  }

  /** Seals every open minute before `beforeMinuteMs`; `Infinity` seals them all. Returns what it sealed, in entry order. */
  seal(beforeMinuteMs: number): MinuteRollup[] {
    const before = this.held.length;
    for (const [key, o] of [...this.open]) if (o.acc.minuteMs < beforeMinuteMs) this.retire(key, o);
    const sealed = this.held.slice(before).sort((a, b) => a.firstId - b.firstId);
    this.held.splice(before, sealed.length, ...sealed);
    return sealed.map((f) => f.rollup);
  }

  /**
   * The fragments that can be posted now, with the watermark to post them at -
   * or null when none can.
   *
   * `afterEntryId` is the watermark of the batch before (or the one this aggregator began after): the
   * sidecar takes a batch only if it continues from its own.
   *
   * `alsoWhen` lets a caller with something else to post (a checkpoint) take a batch with no minute: it is asked
   * with the watermark that batch would carry, and a yes returns it with an empty list.
   *
   * The watermark is "everything before the earliest entry not in a posted
   * fragment": the first entry of any open minute and of any sealed fragment
   * not posted with this batch, minus one. A fragment may be posted only if its
   * *last* entry is at or below that, so a minute that began early and ended
   * late waits for the one that began before it, instead of the sidecar
   * claiming entries it does not hold. Dropping a fragment from the batch moves
   * the watermark back, which can drop another, so this settles by iteration; it
   * only ever shrinks, so it ends.
   */
  drain(alsoWhen?: (watermark: number) => boolean): { fragments: Fragment[]; watermark: number; afterEntryId: number } | null {
    let post = this.held.slice();
    let posted = new Set(post);
    let watermark = this.lastFed;
    for (;;) {
      let earliest = Infinity;
      for (const o of this.open.values()) earliest = Math.min(earliest, o.firstId);
      for (const f of this.held) if (!posted.has(f)) earliest = Math.min(earliest, f.firstId);
      watermark = earliest === Infinity ? this.lastFed : earliest - 1;
      const next = post.filter((f) => f.lastId <= watermark);
      if (next.length === post.length) break;
      post = next;
      posted = new Set(post);
    }
    // A batch with no minute is posted only when the caller has something to carry at this watermark (a checkpoint).
    if (post.length === 0 && (alsoWhen === undefined || watermark < this.drainedThrough || !alsoWhen(watermark))) return null;
    this.held = this.held.filter((f) => !posted.has(f));
    const afterEntryId = this.drainedThrough;
    this.drainedThrough = watermark;
    return { fragments: post, watermark, afterEntryId };
  }
}

/** A decode as v5's own result, for what reads only v5: a v9 or IPFIX export is not rolled up by it. */
export function v5View(d: FlowDecode): DecodeResult {
  if (d.kind !== 'valid') return d;
  if (d.protocol === 'v5' && d.v5 !== undefined) return d.v5;
  return { kind: 'unsupported', reason: `NetFlow ${d.protocol} is not rolled up here` };
}

/**
 * One journal entry into the decode state and the aggregator, in strict id order. The state steps
 * every entry; an id the aggregator already fed is then ignored and returns null, which is how a
 * catch-up from a checkpoint at or below the watermark replays state alone. A boundary returns null.
 * The live feed, the rebuild and the expiry's replay all go through this, so the archive's minutes are
 * made by the same code as the cache's (ADR 0062). A datagram returns its decode step and whether its
 * engine was admitted, which the live feed's health and source list need and a replay does not.
 */
export function feedEntry(
  agg: MinuteAggregator, admission: EngineAdmission, state: DecodeState, e: Evidence,
): { step: Extract<DecodeStep, { kind: 'datagram' }>; admitted: boolean } | null {
  const id = e.ref.entryId;
  const step = state.step(e);
  if (id <= agg.fedThrough) return null;
  if (step === null) throw new Error(`entry ${id} is already in the decode state but not in the aggregator`);
  agg.enterPolicy(e.policy);
  if (e.kind === 'boundary') {
    agg.fed(id);
    // A stop, a suspend and a reopen after a crash all end the collector's
    // run: the minutes it was building are done, whatever the clock says.
    if (e.action === 'stop' || e.action === 'suspend' || e.action === 'interrupted') agg.seal(Infinity);
    return null;
  }
  if (step.kind !== 'datagram') throw new Error(`entry ${id} is a datagram the decode state stepped as a boundary`);
  const decoded = step.decoded;
  const fold = foldOf(step);
  const admitted = fold !== null && admission.admit(fold.sourceKey);
  if (fold !== null) {
    // A valid datagram with nothing in it still makes its minute: the exporter spoke.
    if (!admitted) agg.fed(id);
    else agg.addDatagram(fold, e.receivedMs, id);
  } else if (decoded.kind === 'malformed') {
    agg.addMalformed(e.remoteIPv4, e.receivedMs, id);
  } else {
    agg.addUnsupported(e.remoteIPv4, e.receivedMs, id);
  }
  // Receipt time has passed every earlier minute; the watermark, not the
  // wall clock, is what makes it safe to post them.
  agg.seal(minuteOf(e.receivedMs));
  return { step, admitted };
}
