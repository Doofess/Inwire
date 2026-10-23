/**
 * What the sheet can honestly say about the one source (ADRs 0058, 0059).
 *
 * A reducer over events, with both clocks handed in. **Staleness uses the
 * monotonic `elapsedMs` and nothing else**: a wall clock stepped back by NTP,
 * a DST fix or a VM resume would otherwise make a silent source look fresh,
 * or a fresh one look as if it had gone quiet an hour ago. The wall time is
 * kept for display only ("last export 14:02") and is never compared. And no
 * event deletes anything: a datagram stamped before the one preceding it is
 * counted like any other.
 *
 * **What is not here is as deliberate as what is.** Transport loss is the
 * literal `'unknown'`, never a number: the kernel drops datagrams without
 * telling anyone (ADR 0058), and a measured-looking zero would be a claim
 * nobody measured. What the app shed itself is a separate count, because that
 * one *is* known. Sequence anomalies are counts per engine, derived only from
 * what arrived, and no estimate of lost flows is offered beyond the summed
 * forward jumps the sequence numbers show (`jumpedFlows`, which is not a loss
 * count: see there).
 *
 * **How a sequence number is read.** Per engine, `expected` is the last
 * datagram's sequence plus its record count, all in u32 arithmetic. A datagram
 * `s` with `n` records:
 *
 *  1. A step back still *pending* is resolved first. If `s` is the pending
 *     datagram's own successor (`pending.next`, and not also `expected`), the
 *     step back was the exporter restarting its counter: `resets++`, the new
 *     chain is adopted and the datagram is done. Otherwise this datagram
 *     settles it: `s === expected` means it was a late arrival (`reordered++`),
 *     anything else means nothing proved it (`unresolved++`). It is cleared
 *     either way and the datagram goes on to 2.
 *  2. `s === expected`: in sequence.
 *  3. `s` equals the previous datagram's sequence and that one held records:
 *     `duplicates++`; `expected` does not move. (An export with no records may
 *     legitimately repeat a sequence.)
 *  4. `s` is ahead of `expected` (forward distance under 2^31): `gaps++`,
 *     `jumpedFlows` grows by the distance, the chain continues from `s + n`.
 *  5. Otherwise `s` is behind: it becomes the one pending step back, with
 *     `pending.next = s + n`, and `expected` does not move.
 *
 * A step back is classified by what the *next* datagram proves, never by how
 * far back it went. Distance cannot tell the readings apart: an exporter that
 * restarts at a small number looks like a short step back, and a datagram the
 * network held up for a long time looks like a long one. Labelling by distance
 * reported a restart as four reordered datagrams and invented lost flows, none
 * of them true. Only one step back is held at a time; if the exporter then
 * goes quiet it stays pending, visible as such.
 *
 * **NetFlow v9 and IPFIX sources** (ADRs 0064, 0066) get rows of their own,
 * `templateSources`, because they have no engine and their sequence numbers
 * follow other rules: `ExporterState` reads those and raises the events this
 * folds (`source-restart`, `export-gap`, `clock-skew`, `sampling-changed`,
 * `awaiting-template`). Engines and template sources share the sixteen rows an
 * exporter gets, as the Worker's admission does.
 *
 * Everything is plain data - arrays and numbers, no Map or class - because a
 * `SourceHealth` crosses `postMessage`.
 */
import type { ClockStatus, SamplingStatus, SequenceStatus } from './exporterState';
import type { TemplateInventory } from './templates';
import { LIMITS } from './types';
import { sourceKey } from './v5';

export type ListenerState = 'stopped' | 'starting' | 'listening' | 'failed';
export type StorageState = 'ok' | 'failed';
/** `never`: no valid datagram yet. `stale`: none for `LIMITS.staleMs`, or the listener was stopped. */
export type Freshness = 'never' | 'fresh' | 'stale';

export interface EngineHealth {
  engineType: number;
  engineId: number;
  sourceKey: string;
  /** Valid datagrams. */
  accepted: number;
  /** Flow records in them. */
  flows: number;
  lastValidWallMs: number;
  /** The last valid datagram's own sequence number, to tell a repeat from a late arrival. */
  lastSequence: number | null;
  /** The sequence the next datagram should carry: the last one's plus its record count. */
  expectedSequence: number | null;
  /** The last valid datagram's record count: an export with none may repeat a sequence. */
  lastFlowCount: number | null;
  /**
   * The summed distance of the forward sequence jumps, in flows. A late
   * datagram may later fill part of that distance, so this is **not** a count
   * of lost flows, and there is deliberately no such count: transport loss
   * stays `'unknown'`.
   */
  jumpedFlows: number;
  gaps: number;
  duplicates: number;
  reordered: number;
  resets: number;
  /** Step backs that no later datagram proved to be either a restart or a late arrival. */
  unresolved: number;
  /** The one step back not yet classified, as the sequence its successor would carry; null when none waits. */
  pending: { next: number } | null;
}

/** A NetFlow v9 or IPFIX source: what arrived from it and what `ExporterState` said about it. */
export interface TemplateSourceHealth {
  sourceKey: string;
  protocol: 'v9' | 'ipfix';
  /** Valid datagrams. */
  accepted: number;
  /** Data records decoded in them. */
  flows: number;
  lastValidWallMs: number;
  /** Data sets whose template was not in scope or was refused by the bounds, and their bytes: records unknown. */
  awaitingSets: number;
  awaitingBytes: number;
  /** The template id the last such set named; null before one. */
  lastAwaitingTemplateId: number | null;
  restarts: number;
  /** Suspected export gaps by the source's sequence convention, and the sequence distance they skipped. Not loss. */
  exportGaps: number;
  missingSequence: number;
  /** How many times the export clock went past `LIMITS.clockFlagMs` from receipt time, and by how much the last time. */
  clockFlags: number;
  lastFlaggedSkewMs: number | null;
  /** The last sampling status the source changed to; null until it states one. */
  sampling: SamplingStatus | null;
}

/**
 * The live state of one v9 or IPFIX source, pushed beside the health (ADR 0066): its templates in force
 * (with the elements it does not interpret), and its sampling, clock and sequence status as
 * `ExporterState` holds them now. Live only: none of it is part of a history answer.
 */
export interface ExporterSnapshot {
  sourceKey: string;
  protocol: 'v9' | 'ipfix';
  templates: TemplateInventory[];
  sampling: SamplingStatus;
  clock: ClockStatus;
  sequence: SequenceStatus;
}

export interface RejectedSender { address: string; count: number }

export interface SourceHealth {
  exporterIPv4: string;
  listener: { state: ListenerState; error: string | null };
  storage: { state: StorageState; error: string | null };
  freshness: Freshness;
  lastValidWallMs: number | null;
  lastValidElapsedMs: number | null;
  lastValidEntryId: number | null;
  /** The highest monotonic time any event has reported; a smaller one is ignored. */
  elapsedMs: number;
  engines: EngineHealth[];
  templateSources: TemplateSourceHealth[];
  accepted: number;
  malformed: number;
  unsupported: number;
  /** Valid datagrams from a seventeenth engine: kept in the journal, given no row. */
  engineLimitRejected: number;
  rejectedSenders: RejectedSender[];
  /** Datagrams from addresses past the sixteenth. */
  rejectedOverflow: number;
  /** Datagrams the utility shed before append, counted by it. */
  shedDatagrams: number;
  analyzedThroughEntryId: number | null;
  rolledUpThroughEntryId: number | null;
  /** The kernel's drops are never reported to the app, so this is never a number. */
  transportLoss: 'unknown';
}

interface Timed { elapsedMs: number; wallMs: number }

export type HealthEvent =
  | (Timed & { kind: 'listener'; state: ListenerState; error?: string })
  | (Timed & { kind: 'storage'; state: StorageState; error?: string })
  | (Timed & {
    kind: 'datagram'; outcome: 'valid'; engineType: number; engineId: number;
    sequence: number; flowCount: number; entryId: number;
    /**
     * False when the Worker's own admission refused this engine (it knows engines from the
     * sidecar that this health, which starts at connect, never saw). Absent means admitted.
     */
    admitted?: boolean;
  })
  | (Timed & {
    kind: 'datagram'; outcome: 'valid-template'; protocol: 'v9' | 'ipfix'; sourceKey: string; flowCount: number; entryId: number;
    awaitingSets: number; awaitingBytes: number;
    /** As for v5: false when the Worker's admission refused this source. */
    admitted?: boolean;
  })
  | (Timed & { kind: 'source-restart'; sourceKey: string; entryId: number })
  | (Timed & { kind: 'export-gap'; sourceKey: string; entryId: number; missing: number })
  | (Timed & { kind: 'clock-skew'; sourceKey: string; entryId: number; skewMs: number })
  | (Timed & { kind: 'sampling-changed'; sourceKey: string; entryId: number; status: SamplingStatus })
  | (Timed & { kind: 'awaiting-template'; sourceKey: string; entryId: number; templateId: number })
  | (Timed & { kind: 'datagram'; outcome: 'malformed'; entryId: number })
  | (Timed & { kind: 'datagram'; outcome: 'unsupported'; entryId: number })
  | (Timed & { kind: 'rejected-sender'; address: string })
  | (Timed & { kind: 'tick' })
  | (Timed & { kind: 'shed'; count: number })
  | (Timed & { kind: 'watermark'; which: 'analyzed' | 'rolled-up'; throughEntryId: number });

/**
 * `elapsedMs` is a high-water mark, so a stray smaller value cannot un-stale
 * anything. The price is that it cannot follow a clock that starts over: a new
 * process, or a restarted monotonic clock, must begin from a fresh
 * `SourceHealth` rather than carry an old one across.
 */
export function initialSourceHealth(exporterIPv4: string): SourceHealth {
  return {
    exporterIPv4,
    listener: { state: 'stopped', error: null },
    storage: { state: 'ok', error: null },
    freshness: 'never',
    lastValidWallMs: null,
    lastValidElapsedMs: null,
    lastValidEntryId: null,
    elapsedMs: 0,
    engines: [],
    templateSources: [],
    accepted: 0,
    malformed: 0,
    unsupported: 0,
    engineLimitRejected: 0,
    rejectedSenders: [],
    rejectedOverflow: 0,
    shedDatagrams: 0,
    analyzedThroughEntryId: null,
    rolledUpThroughEntryId: null,
    transportLoss: 'unknown',
  };
}

/** Rows an exporter has used: v5 engines and v9/IPFIX sources share `LIMITS.enginesPerExporter`. */
const rowsUsed = (health: SourceHealth): number => health.engines.length + health.templateSources.length;

/** Whether a valid datagram from this engine would get a row: a known engine, or room for a new one. */
export function canAdmitEngine(health: SourceHealth, engineType: number, engineId: number): boolean {
  return rowsUsed(health) < LIMITS.enginesPerExporter
    || health.engines.some((e) => e.engineType === engineType && e.engineId === engineId);
}

/** A valid datagram's effect on freshness and the last-valid fields, v5 or not. */
function markValid(h: SourceHealth, elapsedMs: number, event: Timed & { entryId: number }): void {
  h.accepted++;
  // The datagram's own time, not the clock's high-water mark: one fed late
  // (a rebuild reading entries that arrived during it) is as old as it is.
  const lastValid = Math.max(h.lastValidElapsedMs ?? event.elapsedMs, event.elapsedMs);
  h.freshness = elapsedMs - lastValid >= LIMITS.staleMs ? 'stale' : 'fresh';
  h.lastValidWallMs = event.wallMs;
  h.lastValidElapsedMs = lastValid;
  h.lastValidEntryId = event.entryId;
}

/** An exporter event on the row it names; a source with no row (not admitted) changes nothing. */
function onTemplateSource(h: SourceHealth, key: string, change: (row: TemplateSourceHealth) => TemplateSourceHealth): SourceHealth {
  const at = h.templateSources.findIndex((r) => r.sourceKey === key);
  if (at >= 0) h.templateSources = h.templateSources.map((r, i) => (i === at ? change(r) : r));
  return h;
}

const u32 = (n: number) => n >>> 0;

/** One valid datagram's effect on its engine's sequence bookkeeping; the rules are in the file header. */
function advanceSequence(engine: EngineHealth, sequence: number, flowCount: number, wallMs: number): EngineHealth {
  const next: EngineHealth = {
    ...engine, accepted: engine.accepted + 1, flows: engine.flows + flowCount, lastValidWallMs: wallMs,
    lastSequence: sequence, lastFlowCount: flowCount,
  };
  const after = u32(sequence + flowCount);
  const expected = engine.expectedSequence;
  if (expected === null) {
    next.expectedSequence = after;
    return next;
  }

  if (engine.pending !== null) {
    next.pending = null;
    // The step back's own successor means a restart. When that number is also
    // the one expected, the step back ended exactly where the chain stands
    // and is read as the late arrival it plainly is.
    if (sequence === engine.pending.next && sequence !== expected) {
      next.resets++;
      next.expectedSequence = after;
      return next;
    }
    if (sequence === expected) next.reordered++;
    else next.unresolved++;
  }

  if (sequence === expected) {
    next.expectedSequence = after;
    return next;
  }
  if (sequence === engine.lastSequence && engine.lastFlowCount !== 0) {
    next.duplicates++;
    return next;
  }
  const forward = u32(sequence - expected);
  if (forward < 2 ** 31) {
    next.gaps++;
    next.jumpedFlows += forward;
    next.expectedSequence = after;
    return next;
  }
  next.pending = { next: after };
  return next;
}

export function reduceSourceHealth(previous: SourceHealth, event: HealthEvent): SourceHealth {
  const elapsedMs = Math.max(previous.elapsedMs, event.elapsedMs);
  const h: SourceHealth = { ...previous, elapsedMs };

  // Stale is decided on every event, from elapsed time alone.
  if (h.freshness === 'fresh' && h.lastValidElapsedMs !== null && elapsedMs - h.lastValidElapsedMs >= LIMITS.staleMs) {
    h.freshness = 'stale';
  }

  switch (event.kind) {
    case 'listener':
      h.listener = { state: event.state, error: event.state === 'failed' ? event.error ?? 'failed' : null };
      if (event.state === 'stopped' && h.lastValidElapsedMs !== null) h.freshness = 'stale';
      return h;
    case 'storage':
      h.storage = { state: event.state, error: event.state === 'failed' ? event.error ?? 'failed' : null };
      return h;
    case 'tick':
      return h;
    case 'shed':
      h.shedDatagrams += Math.max(0, Math.trunc(event.count));
      return h;
    case 'watermark': {
      const key = event.which === 'analyzed' ? 'analyzedThroughEntryId' : 'rolledUpThroughEntryId';
      const current = h[key];
      h[key] = current === null ? event.throughEntryId : Math.max(current, event.throughEntryId);
      return h;
    }
    case 'rejected-sender': {
      const at = h.rejectedSenders.findIndex((r) => r.address === event.address);
      if (at >= 0) {
        h.rejectedSenders = h.rejectedSenders.map((r, i) => (i === at ? { ...r, count: r.count + 1 } : r));
      } else if (h.rejectedSenders.length < LIMITS.rejectedSenders) {
        h.rejectedSenders = [...h.rejectedSenders, { address: event.address, count: 1 }];
      } else {
        h.rejectedOverflow++;
      }
      return h;
    }
    case 'source-restart':
      return onTemplateSource(h, event.sourceKey, (r) => ({ ...r, restarts: r.restarts + 1 }));
    case 'export-gap':
      return onTemplateSource(h, event.sourceKey, (r) => ({ ...r, exportGaps: r.exportGaps + 1, missingSequence: r.missingSequence + event.missing }));
    case 'clock-skew':
      return onTemplateSource(h, event.sourceKey, (r) => ({ ...r, clockFlags: r.clockFlags + 1, lastFlaggedSkewMs: event.skewMs }));
    case 'sampling-changed':
      return onTemplateSource(h, event.sourceKey, (r) => ({ ...r, sampling: event.status }));
    case 'awaiting-template':
      return onTemplateSource(h, event.sourceKey, (r) => ({ ...r, lastAwaitingTemplateId: event.templateId }));
    case 'datagram': {
      if (event.outcome === 'malformed') { h.malformed++; return h; }
      if (event.outcome === 'unsupported') { h.unsupported++; return h; }
      if (event.outcome === 'valid-template') {
        const at = h.templateSources.findIndex((r) => r.sourceKey === event.sourceKey);
        if (event.admitted === false || (at < 0 && rowsUsed(h) >= LIMITS.enginesPerExporter)) {
          h.engineLimitRejected++;
          return h;
        }
        const row: TemplateSourceHealth = at >= 0 ? h.templateSources[at] : {
          sourceKey: event.sourceKey, protocol: event.protocol, accepted: 0, flows: 0, lastValidWallMs: event.wallMs,
          awaitingSets: 0, awaitingBytes: 0, lastAwaitingTemplateId: null, restarts: 0, exportGaps: 0, missingSequence: 0,
          clockFlags: 0, lastFlaggedSkewMs: null, sampling: null,
        };
        const next: TemplateSourceHealth = {
          ...row, accepted: row.accepted + 1, flows: row.flows + event.flowCount, lastValidWallMs: event.wallMs,
          awaitingSets: row.awaitingSets + event.awaitingSets, awaitingBytes: row.awaitingBytes + event.awaitingBytes,
        };
        h.templateSources = at >= 0 ? h.templateSources.map((r, i) => (i === at ? next : r)) : [...h.templateSources, next];
        markValid(h, elapsedMs, event);
        return h;
      }
      const at = h.engines.findIndex((e) => e.engineType === event.engineType && e.engineId === event.engineId);
      if (event.admitted === false || (at < 0 && rowsUsed(h) >= LIMITS.enginesPerExporter)) {
        // Only an admitted engine's datagrams are analyzed, so this one gets
        // no row and does not make the source fresh; the sheet shows the count.
        h.engineLimitRejected++;
        return h;
      }
      const engine: EngineHealth = at >= 0 ? h.engines[at] : {
        engineType: event.engineType,
        engineId: event.engineId,
        sourceKey: sourceKey(h.exporterIPv4, event.engineType, event.engineId),
        accepted: 0, flows: 0, lastValidWallMs: event.wallMs, lastSequence: null, expectedSequence: null,
        lastFlowCount: null, jumpedFlows: 0, gaps: 0, duplicates: 0, reordered: 0, resets: 0,
        unresolved: 0, pending: null,
      };
      const advanced = advanceSequence(engine, event.sequence, event.flowCount, event.wallMs);
      h.engines = at >= 0 ? h.engines.map((e, i) => (i === at ? advanced : e)) : [...h.engines, advanced];
      markValid(h, elapsedMs, event);
      return h;
    }
  }
}
