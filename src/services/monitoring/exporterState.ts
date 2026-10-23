/**
 * What the collector learns about an exporter across datagrams (ADRs 0064,
 * 0065): its sampling rate, the skew of its clock, restarts, and whether
 * export packets or records went missing.
 *
 * Template state is `templates.ts`'s. This state is as derived as that one and
 * is checkpointed beside it (`checkpoint.ts`): `SourceSnapshot` is the
 * checkpoint's shape. The gap and reorder counters, the clock and the reason
 * an unsupported rate is unsupported are not durable.
 *
 * **Sequence numbers.** Exporters disagree. RFC 3954 counts v9 packets; RFC
 * 7011 counts IPFIX data records sent *before* the message; softflowd's IPFIX
 * counts the message's own flow records, against the RFC. Assuming one would
 * report a false gap at every change in record count, so a source learns its
 * convention from its first eight *discriminating* message pairs and counts
 * nothing before that.
 *
 * Pure: no `node:*`, no Electron, like everything under `src/services/`.
 */
import { parseSourceKey } from './sourceKeys';
import { LIMITS, type ClockStatus, type DatagramEvidence } from './types';
import type { FlowDecode, OptionsReport } from './flowDecode';

export type SamplingStatus =
  | { kind: 'absent' }
  | { kind: 'known'; interval: number; sinceEntryId: number }
  | { kind: 'unsupported'; reason: string };

export type { ClockStatus };

export interface SequenceStatus { mode: 'learning' | 'rfc' | 'own-records' | 'unrecognized'; suspectedGap: number; reordered: number }

export type ExporterEvent =
  | { kind: 'source-restart'; sourceKey: string; entryId: number }
  | { kind: 'clock-skew'; sourceKey: string; entryId: number; skewMs: number }
  | { kind: 'sampling-changed'; sourceKey: string; entryId: number; status: SamplingStatus }
  | { kind: 'export-gap'; sourceKey: string; entryId: number; missing: number }
  | { kind: 'awaiting-template'; sourceKey: string; entryId: number; templateId: number };

export interface SamplerEntry {
  id: number;
  /** v9 IE 49, IPFIX IE 304. */
  algorithm: number;
  /** v9 IE 50, IPFIX IE 305. */
  interval: number;
  /** IPFIX IE 306; 0 for v9. */
  space: number;
}

export type SequenceMode = SequenceStatus['mode'];

/** A source's sequence state as the checkpoint holds it. */
export interface SequenceSnapshot {
  mode: SequenceMode;
  /** A sequence number has been seen and is the reference for the next. */
  seen: boolean;
  last: number;
  /** Data records in that message, options records included (RFC 7011 section 3.1). */
  lastRecords: number;
  pairs: number;
  fitRfc: number;
  fitOwn: number;
}

export interface SourceSnapshot {
  key: string;
  sampling: SamplingStatus;
  sequence: SequenceSnapshot;
  samplers: SamplerEntry[];
}

interface SequenceState extends SequenceSnapshot {
  /** Options data records in the last message: RFC mode accepts a number with or without them. */
  lastOptions: number;
  /** Restored from a checkpoint, which does not keep `lastOptions`: the next RFC comparison is skipped, not guessed. */
  optionsUnknown: boolean;
  suspectedGap: number;
  reordered: number;
}

interface SourceState {
  protocol: 'v9' | 'ipfix';
  sampling: SamplingStatus;
  samplers: Map<number, SamplerEntry>;
  /** A 17th sampler was refused: the source's sampling stays unsupported. */
  samplersRefused: boolean;
  sequence: SequenceState;
  clock: ClockStatus;
}

const MOD = 2 ** 32;
const HALF = 2 ** 31;
const MAX_RATE = 2 ** 32 - 1;

const freshSequence = (): SequenceState => ({
  mode: 'learning', seen: false, last: 0, lastRecords: 0, pairs: 0, fitRfc: 0, fitOwn: 0, lastOptions: 0, optionsUnknown: false, suspectedGap: 0, reordered: 0,
});

/**
 * The rate a sampler states: v9 gives it directly, an IPFIX selector as (interval + space) / interval; null where it is not a
 * whole number, or is past 2^32 - 1, which is the widest rate a checkpoint holds (a selector of 1 and 0xFFFFFFFF would be 2^32).
 */
function samplerRate(protocol: 'v9' | 'ipfix', s: SamplerEntry): number | null {
  if (protocol === 'v9') return s.interval >= 1 ? s.interval : null;
  if (s.algorithm !== 1 || s.interval < 1 || (s.interval + s.space) % s.interval !== 0) return null;
  const rate = (s.interval + s.space) / s.interval;
  return rate > MAX_RATE ? null : rate;
}

export class ExporterState {
  private readonly sources = new Map<string, SourceState>();

  private source(key: string, protocol: 'v9' | 'ipfix'): SourceState {
    let st = this.sources.get(key);
    if (st === undefined) {
      st = {
        protocol, sampling: { kind: 'absent' }, samplers: new Map(), samplersRefused: false, sequence: freshSequence(),
        clock: { latestSkewMs: null, minSkewMs: null, maxSkewMs: null, flagged: false },
      };
      this.sources.set(key, st);
    }
    return st;
  }

  /** Takes one decode (its datagram's evidence beside it) and returns the health events it raises. v5 is `sourceHealth.ts`'s. */
  observe(d: FlowDecode, e: DatagramEvidence): ExporterEvent[] {
    if (d.kind !== 'valid' || d.protocol === 'v5') return [];
    const key = d.sourceKey;
    const entryId = e.ref.entryId;
    const src = this.source(key, d.protocol);
    const events: ExporterEvent[] = [];

    if (d.restart) {
      src.sequence = { ...freshSequence(), suspectedGap: src.sequence.suspectedGap, reordered: src.sequence.reordered };
      events.push({ kind: 'source-restart', sourceKey: key, entryId });
    }

    const skew = d.exportMs - e.receivedMs;
    const c = src.clock;
    const wasFlagged = c.flagged;
    c.latestSkewMs = skew;
    c.minSkewMs = c.minSkewMs === null ? skew : Math.min(c.minSkewMs, skew);
    c.maxSkewMs = c.maxSkewMs === null ? skew : Math.max(c.maxSkewMs, skew);
    c.flagged = Math.abs(skew) > LIMITS.clockFlagMs;
    if (c.flagged && !wasFlagged) events.push({ kind: 'clock-skew', sourceKey: key, entryId, skewMs: skew });

    this.observeSampling(key, src, d, entryId, events);
    this.observeSequence(key, src, d, entryId, events);

    for (const a of d.awaiting) events.push({ kind: 'awaiting-template', sourceKey: key, entryId, templateId: a.templateId });
    return events;
  }

  // --- sampling -----------------------------------------------------------------------------------------------

  private addSampler(src: SourceState, s: SamplerEntry): void {
    // IE 302 may be 8 bytes, but a checkpoint keeps a 32-bit id: a wider one is not filed, so nothing cites it.
    if (s.id > 0xffffffff) return;
    if (!src.samplers.has(s.id) && src.samplers.size >= LIMITS.samplersPerSource) { src.samplersRefused = true; return; }
    src.samplers.set(s.id, s);
  }

  private observeSampling(key: string, src: SourceState, d: Extract<FlowDecode, { kind: 'valid' }>, entryId: number, events: ExporterEvent[]): void {
    const states: SamplingStatus[] = [];
    const known = (interval: number): SamplingStatus => ({ kind: 'known', interval, sinceEntryId: entryId });
    for (const r of d.options) {
      const stated = this.statement(src, r, known);
      if (stated !== null) states.push(stated);
    }
    // Data records that name their rate, or a sampler.
    const rates = new Set<number>();
    for (const f of d.flows) {
      if (f.samplingInterval !== null && f.samplingInterval >= 1) { rates.add(f.samplingInterval); continue; }
      const sampler = f.samplerId === null ? undefined : src.samplers.get(f.samplerId);
      const rate = sampler === undefined ? null : samplerRate(src.protocol, sampler);
      if (rate !== null) rates.add(rate);
    }
    if (rates.size === 1) states.push(known([...rates][0]));
    else if (rates.size > 1) states.push({ kind: 'unsupported', reason: 'several sampling rates in one datagram' });

    if (src.samplersRefused) states.push({ kind: 'unsupported', reason: `more than ${LIMITS.samplersPerSource} samplers` });
    for (const next of states) {
      const prev = src.sampling;
      const same = next.kind === prev.kind && (next.kind !== 'known' || (prev.kind === 'known' && prev.interval === next.interval));
      if (same) continue;
      src.sampling = next;
      events.push({ kind: 'sampling-changed', sourceKey: key, entryId, status: next });
    }
  }

  /** What one options record says about the source's sampling, or null if nothing. It also files sampler table entries. */
  private statement(src: SourceState, r: OptionsReport, known: (interval: number) => SamplingStatus): SamplingStatus | null {
    if (r.samplingInterval !== undefined || r.samplingAlgorithm !== undefined) {
      // v9 IE 34 / 35, which an IPFIX exporter may send too.
      if (r.samplingInterval !== undefined && r.samplingInterval >= 1) return known(r.samplingInterval);
      if (r.samplingAlgorithm !== undefined) return { kind: 'unsupported', reason: `sampling algorithm ${r.samplingAlgorithm} with no interval` };
      return null;
    }
    if (r.selectorAlgorithm !== undefined) {
      const entry: SamplerEntry = { id: r.samplerId ?? 0, algorithm: r.selectorAlgorithm, interval: r.packetInterval ?? 0, space: r.packetSpace ?? 0 };
      this.addSampler(src, entry);
      if (r.selectorAlgorithm !== 1) return { kind: 'unsupported', reason: `selector algorithm ${r.selectorAlgorithm} is not count-based systematic sampling` };
      const rate = samplerRate('ipfix', entry);
      return rate === null ? { kind: 'unsupported', reason: 'the selector does not state a whole sampling rate' } : known(rate);
    }
    if (r.samplerId !== undefined && (r.samplerInterval !== undefined || r.samplerMode !== undefined)) {
      // A v9 sampler table: it names no rate for the source until a data record cites the sampler.
      this.addSampler(src, { id: r.samplerId, algorithm: r.samplerMode ?? 0, interval: r.samplerInterval ?? 0, space: 0 });
    }
    return null;
  }

  // --- sequence numbers -----------------------------------------------------------------------------------------

  private observeSequence(key: string, src: SourceState, d: Extract<FlowDecode, { kind: 'valid' }>, entryId: number, events: ExporterEvent[]): void {
    const q = src.sequence;
    const v9 = d.protocol === 'v9';
    const s = d.sequence >>> 0;
    const all = d.dataRecords + d.optionsRecords;
    // A message whose data was awaiting its template held an unknown number of records: it cannot anchor the next IPFIX number.
    const unknown = !v9 && (d.awaiting.length > 0 || d.refused.length > 0);
    const accept = () => {
      q.last = s;
      q.lastRecords = v9 ? 0 : all;
      q.lastOptions = v9 ? 0 : d.optionsRecords;
      q.optionsUnknown = false;
      q.seen = !unknown;
    };
    if (!q.seen) { accept(); return; }

    const expectRfc = v9 ? (q.last + 1) % MOD : (q.last + q.lastRecords) % MOD;
    const expectOwn = v9 ? expectRfc : (q.last + d.dataRecords) % MOD;
    if (q.mode === 'learning' || q.mode === 'unrecognized') {
      // Only a pair the two readings disagree about teaches anything.
      if (v9 || expectRfc !== expectOwn) {
        q.pairs++;
        if (s === expectRfc) q.fitRfc++;
        if (s === expectOwn) q.fitOwn++;
        if (q.pairs >= LIMITS.sequenceLearningPairs) {
          if (q.fitRfc === q.pairs) q.mode = 'rfc';
          else if (q.fitOwn === q.pairs) q.mode = 'own-records';
          else { q.mode = 'unrecognized'; q.pairs = 0; q.fitRfc = 0; q.fitOwn = 0; }
        }
      }
      accept();
      return;
    }

    const accepted = q.mode === 'own-records' ? [expectOwn] : [expectRfc];
    // No measured exporter shows whether an RFC exporter counts options records: after a message that carried
    // some, either number is expected, and neither is a gap.
    if (q.mode === 'rfc' && !v9 && q.lastOptions > 0) accepted.push((q.last + q.lastRecords - q.lastOptions) % MOD);
    if (q.mode === 'rfc' && !v9 && q.optionsUnknown) { accept(); return; }
    if (accepted.includes(s)) { accept(); return; }
    const ahead = (s - accepted[0] + MOD) % MOD;
    if (ahead > 0 && ahead < HALF) {
      q.suspectedGap += ahead;
      events.push({ kind: 'export-gap', sourceKey: key, entryId, missing: ahead });
      accept();
    } else {
      q.reordered++;
    }
  }

  /** Drops every source that is not `exporter`'s: a start boundary naming another exporter (the owner changed it). */
  retainExporter(exporter: string): void {
    for (const key of [...this.sources.keys()]) if (parseSourceKey(key)?.exporter !== exporter) this.sources.delete(key);
  }

  /** A start, resume or gap boundary: the next message of each source is the new reference, whatever its number. The mode is kept. */
  gapEnded(): void {
    for (const st of this.sources.values()) st.sequence.seen = false;
  }

  sampling(sourceKey: string): SamplingStatus {
    return this.sources.get(sourceKey)?.sampling ?? { kind: 'absent' };
  }

  clock(sourceKey: string): ClockStatus {
    const c = this.sources.get(sourceKey)?.clock;
    return c === undefined ? { latestSkewMs: null, minSkewMs: null, maxSkewMs: null, flagged: false } : { ...c };
  }

  /** A sampler's whole rate, or null where the source has no such sampler or it states none: a record that cites it is sampled at this. */
  samplerRate(sourceKey: string, samplerId: number): number | null {
    const st = this.sources.get(sourceKey);
    const s = st?.samplers.get(samplerId);
    return st === undefined || s === undefined ? null : samplerRate(st.protocol, s);
  }

  sequence(sourceKey: string): SequenceStatus {
    const q = this.sources.get(sourceKey)?.sequence;
    return q === undefined ? { mode: 'learning', suspectedGap: 0, reordered: 0 } : { mode: q.mode, suspectedGap: q.suspectedGap, reordered: q.reordered };
  }

  /** Every source in the checkpoint's order: by key. */
  exportSources(): SourceSnapshot[] {
    return [...this.sources.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, st]) => ({
        key,
        sampling: st.sampling,
        sequence: { mode: st.sequence.mode, seen: st.sequence.seen, last: st.sequence.last, lastRecords: st.sequence.lastRecords, pairs: st.sequence.pairs, fitRfc: st.sequence.fitRfc, fitOwn: st.sequence.fitOwn },
        samplers: [...st.samplers.values()].sort((a, b) => a.id - b.id),
      }));
  }

  /** A state holding exactly these sources. */
  static fromSources(sources: SourceSnapshot[]): ExporterState {
    const state = new ExporterState();
    for (const snap of sources) {
      const protocol = snap.key.startsWith('v9:') ? 'v9' : 'ipfix';
      const st = state.source(snap.key, protocol);
      st.sampling = snap.sampling;
      for (const s of snap.samplers) st.samplers.set(s.id, s);
      st.sequence = { ...freshSequence(), ...snap.sequence, optionsUnknown: protocol === 'ipfix' && snap.sequence.mode === 'rfc' };
    }
    return state;
  }
}
