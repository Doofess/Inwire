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
import { LIMITS, type ConversationTotals, type EndpointTotals, type MinuteRollup, type NormalizedV5 } from './types';
import { exporterKey, exporterOf, isEngineSourceKey } from './v5';

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

const byAddress = (a: string, b: string): number => ipv4Number(a) - ipv4Number(b);

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
  complete = true;
  readonly endpoints = new Map<string, { sent: bigint; received: bigint }>();
  readonly conversations = new Map<string, { src: string; dst: string; octets: bigint; packets: bigint }>();

  constructor(readonly sourceKey: string, readonly minuteMs: number) {}

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

  addFlow(flow: NormalizedV5): void {
    this.records++;
    this.reportedOctets += flow.reportedOctets;
    this.reportedPackets += flow.reportedPackets;
    if (flow.sampling.kind === 'unknown') this.unknownSamplingRecords++;
    if (!this.complete) return;
    // A flow with the same source and destination is both a sender and a
    // receiver of its own octets, once each: the table has one row for it.
    const s = this.endpoint(flow.srcAddr);
    if (s === null) return;
    s.sent += flow.reportedOctets;
    const d = this.endpoint(flow.dstAddr);
    if (d === null) return;
    d.received += flow.reportedOctets;
    const c = this.conversation(flow.srcAddr, flow.dstAddr);
    if (c === null) return;
    c.octets += flow.reportedOctets;
    c.packets += flow.reportedPackets;
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
      .map(([address, e]) => ({ address, sentOctets: e.sent, receivedOctets: e.received }))
      .sort((a, b) => byAddress(a.address, b.address));
    const conversations: ConversationTotals[] = [...this.conversations.values()]
      .map((c) => ({ srcAddr: c.src, dstAddr: c.dst, reportedOctets: c.octets, reportedPackets: c.packets }))
      .sort((a, b) => byAddress(a.srcAddr, b.srcAddr) || byAddress(a.dstAddr, b.dstAddr));
    return {
      sourceKey: this.sourceKey, minuteMs: this.minuteMs, complete: this.complete, records: this.records,
      reportedOctets: this.reportedOctets, reportedPackets: this.reportedPackets, endpoints, conversations,
      malformed: this.malformed, unsupported: this.unsupported, unknownSamplingRecords: this.unknownSamplingRecords,
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

  /** `afterEntryId` is the watermark the sidecar already holds: the first entry fed is the one after it. */
  constructor(afterEntryId = 0) {
    this.lastFed = afterEntryId;
  }

  /** The highest entry id fed so far. */
  get fedThrough(): number { return this.lastFed; }

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
      o = { acc: new MinuteAccumulator(key, minuteMs), firstId: entryId, lastId: entryId };
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
   * The watermark is "everything before the earliest entry not in a posted
   * fragment": the first entry of any open minute and of any sealed fragment
   * not posted with this batch, minus one. A fragment may be posted only if its
   * *last* entry is at or below that, so a minute that began early and ended
   * late waits for the one that began before it, instead of the sidecar
   * claiming entries it does not hold. Dropping a fragment from the batch moves
   * the watermark back, which can drop another, so this settles by iteration; it
   * only ever shrinks, so it ends.
   */
  drain(): { fragments: Fragment[]; watermark: number } | null {
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
    if (post.length === 0) return null;
    this.held = this.held.filter((f) => !posted.has(f));
    return { fragments: post, watermark };
  }
}
