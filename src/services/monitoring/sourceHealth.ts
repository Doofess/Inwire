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
 * Everything is plain data - arrays and numbers, no Map or class - because a
 * `SourceHealth` crosses `postMessage`.
 */
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
  })
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

/** Whether a valid datagram from this engine would get a row: a known engine, or room for a new one. */
export function canAdmitEngine(health: SourceHealth, engineType: number, engineId: number): boolean {
  return health.engines.length < LIMITS.enginesPerExporter
    || health.engines.some((e) => e.engineType === engineType && e.engineId === engineId);
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
    case 'datagram': {
      if (event.outcome === 'malformed') { h.malformed++; return h; }
      if (event.outcome === 'unsupported') { h.unsupported++; return h; }
      const at = h.engines.findIndex((e) => e.engineType === event.engineType && e.engineId === event.engineId);
      if (at < 0 && h.engines.length >= LIMITS.enginesPerExporter) {
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
      h.accepted++;
      h.freshness = 'fresh';
      h.lastValidWallMs = event.wallMs;
      h.lastValidElapsedMs = elapsedMs;
      h.lastValidEntryId = event.entryId;
      return h;
    }
  }
}
