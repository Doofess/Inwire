/**
 * The one way a journal reader turns entries into decodes (ADRs 0064-0066).
 *
 * NetFlow v9 and IPFIX cannot be decoded an entry at a time: a datagram's
 * meaning depends on the templates, samplers and gaps before it. Every reader
 * of the journal - the live feed, a rebuild, the expiry's replay, a raw scan,
 * a detail - therefore carries a `DecodeState` and feeds it every entry in id
 * order, boundaries included, from a checkpoint or from empty state. That is
 * what makes the raw-scan definition one definition: they all run this.
 *
 * - A boundary that ends a collection gap (`start`, `resume`, `gap`) marks
 *   every scope and template as across a gap (ADR 0065) and resets sequence
 *   anchors.
 * - A datagram is decoded under its segment's policy. A policy-1 v9 datagram
 *   is unsupported and touches no state.
 * - Each record's sampling is resolved here, against the state as it stands
 *   after its datagram, so a rollup and a raw scan count it alike.
 *
 * The state is as of `throughEntryId`; `checkpoint()` encodes exactly that.
 * Pure: no `node:*`, no Electron.
 */
import { decodeCheckpoint, encodeCheckpoint } from './checkpoint';
import { ExporterState, type ExporterEvent } from './exporterState';
import { decodeDatagram, type FlowDecode } from './flowDecode';
import { CollectorTemplateStore } from './templates';
import type { Evidence } from './types';

/** One record's sampling as a rollup counts it (ADR 0066). */
export type RecordSampling = { kind: 'known'; interval: number } | { kind: 'unknown' } | { kind: 'unsupported' };

export type DecodeStep =
  | { kind: 'boundary' }
  | {
    kind: 'datagram';
    decoded: FlowDecode;
    /** What the datagram raised, for the live health; a replay ignores them. */
    events: ExporterEvent[];
    /** Per record of `decoded.flows` (v9, IPFIX) or `decoded.v5.flows` (v5), in order; empty otherwise. */
    sampling: RecordSampling[];
    /** v9 and IPFIX export time less receipt time; null for v5 and anything not decoded. */
    skewMs: number | null;
  };

export class DecodeState {
  private constructor(
    readonly store: CollectorTemplateStore,
    readonly exporter: ExporterState,
    private through: number,
    private throughAtMs: number,
  ) {}

  /** No templates, no sources: the state before entry `afterEntryId + 1` when nothing earlier is known. */
  static empty(afterEntryId = 0, afterMs = 0): DecodeState {
    return new DecodeState(new CollectorTemplateStore(), new ExporterState(), afterEntryId, afterMs);
  }

  /** The state a checkpoint holds, or null if the bytes are not one: such a checkpoint is skipped, never trusted. */
  static fromCheckpoint(bytes: Uint8Array): DecodeState | null {
    const c = decodeCheckpoint(bytes);
    return c === null ? null : new DecodeState(c.store, c.state, c.throughEntryId, c.throughMs);
  }

  /** The last entry this state has taken (or the checkpoint's), and its receipt time. */
  get throughEntryId(): number { return this.through; }
  get throughMs(): number { return this.throughAtMs; }

  /** The state as of `throughEntryId`, encoded deterministically: live and rebuilt states give the same bytes. */
  checkpoint(): Uint8Array {
    return encodeCheckpoint(this.store, this.exporter, this.through, this.throughAtMs);
  }

  /** One entry, in id order. An entry at or below `throughEntryId` is already in the state and returns null. */
  step(e: Evidence): DecodeStep | null {
    if (e.ref.entryId <= this.through) return null;
    this.through = e.ref.entryId;
    this.throughAtMs = e.receivedMs;
    if (e.kind === 'boundary') {
      if (e.action === 'start' || e.action === 'resume' || e.action === 'gap') {
        this.store.gapEnded();
        this.exporter.gapEnded();
      }
      return { kind: 'boundary' };
    }
    const decoded = decodeDatagram(e, e.remoteIPv4, e.policy, this.store);
    const events = this.exporter.observe(decoded, e);
    if (decoded.kind !== 'valid') return { kind: 'datagram', decoded, events, sampling: [], skewMs: null };
    if (decoded.protocol === 'v5') {
      const flows = decoded.v5 !== undefined && decoded.v5.kind === 'valid' ? decoded.v5.flows : [];
      const sampling = flows.map((f): RecordSampling => (
        f.sampling.kind === 'reported' ? { kind: 'known', interval: Math.max(1, f.sampling.interval) } : { kind: 'unknown' }
      ));
      return { kind: 'datagram', decoded, events, sampling, skewMs: null };
    }
    const key = decoded.sourceKey;
    const status = this.exporter.sampling(key);
    const fallback: RecordSampling = status.kind === 'known'
      ? { kind: 'known', interval: status.interval }
      : status.kind === 'unsupported' ? { kind: 'unsupported' } : { kind: 'unknown' };
    const sampling = decoded.flows.map((f): RecordSampling => {
      if (f.samplingInterval !== null && f.samplingInterval >= 1) return { kind: 'known', interval: f.samplingInterval };
      const rate = f.samplerId === null ? null : this.exporter.samplerRate(key, f.samplerId);
      return rate === null ? fallback : { kind: 'known', interval: rate };
    });
    return { kind: 'datagram', decoded, events, sampling, skewMs: decoded.exportMs - e.receivedMs };
  }
}
