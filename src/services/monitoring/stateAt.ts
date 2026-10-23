/**
 * The decode state as of an entry (ADR 0066): the newest usable checkpoint at or below it, then a replay.
 *
 * NetFlow v9 and IPFIX cannot be read from the entry alone, so every reader that must decode a stretch of
 * the journal - a raw query scan, the expiry's replay, a detail - first asks for the state just before its
 * first entry. The starting points, newest first:
 *
 * - every template checkpoint (sidecar kind 3) at or below the entry, none below the oldest retained entry;
 * - the archive's last cut, whose checkpoint is the state through the entry the expiry took out;
 * - where the retained journal begins with policy-1 segments and then a policy-2 one: empty state as of the
 *   entry before the policy-2 segment, which is exact because a policy-1 entry changes neither the
 *   template store nor the exporter state (a v5 datagram is read by policy 1 and 2 alike and a v9 one is
 *   unsupported under policy 1), and a gap boundary on empty state is a no-op;
 * - failing those, empty state before the oldest retained entry.
 *
 * A starting point that cannot be used (unreadable, corrupt, not a checkpoint, a state through another
 * entry than it says) is skipped for the next older one; the replay then costs more bytes, never gives a
 * different state. A runtime that is gone or a cancelled query is not skipped.
 *
 * Pure: no `node:*`, no Electron.
 */
import { DecodeState } from './decodeState';
import type { Inflate } from './rollupCodec';
import { RuntimeUnavailableError, type ArchiveSource, type HostRuntime } from './runtime';
import { LIMITS, type CheckpointInfo, type SegmentGeometry, type Snapshot } from './types';

export type StateSource = Pick<HostRuntime, 'segmentGeometry' | 'checkpoints' | 'readCheckpoint' | 'readPage' | 'readEvidence'> & { archive?: ArchiveSource };

/** The bytes a replayed entry is charged: its datagram and a fixed overhead for its header. */
const ENTRY_OVERHEAD_BYTES = 24;

type Candidate =
  | { kind: 'checkpoint'; throughEntryId: number }
  | { kind: 'cut'; throughEntryId: number }
  | { kind: 'boundary'; throughEntryId: number };

/** The kinds in the order they win a tie on the entry they stand at: the same state, the cheapest to be sure of last. */
const RANK = { checkpoint: 0, cut: 1, boundary: 2 } as const;

/** A failure that must reach the caller: the runtime is gone, or the query was cancelled. */
function isFatal(e: unknown): boolean {
  return e instanceof RuntimeUnavailableError || (e instanceof Error && e.name === 'AbortError');
}

/** `fn`'s result, or `fallback` for a failure that only means "this starting point is not there". */
async function tolerant<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (isFatal(e)) throw e;
    return fallback;
  }
}

/**
 * The state after entry `beforeEntryId - 1` (or after the snapshot's last entry where that is earlier), or
 * `'range-too-large'` when reaching it replays more than `maxReplayBytes`. An empty retained journal has
 * nothing to replay: the state is empty as of the entry asked for, which is what a reader of no entries needs.
 */
export async function decodeStateBefore(
  source: StateSource, snapshot: Snapshot, beforeEntryId: number, inflate: Inflate,
  maxReplayBytes: number = LIMITS.replayBytes,
): Promise<DecodeState | 'range-too-large'> {
  const target = Math.max(0, Math.min(beforeEntryId - 1, snapshot.throughEntryId));
  const limited: Snapshot = { generation: snapshot.generation, throughEntryId: target };
  const geometry: SegmentGeometry[] = await source.segmentGeometry(snapshot);
  if (geometry.length === 0) return DecodeState.empty(target);
  const firstRetained = geometry[0].firstEntryId;
  const floor = firstRetained - 1;

  const candidates: Candidate[] = [];
  const infos: CheckpointInfo[] = await tolerant(() => source.checkpoints(), []);
  for (const c of infos) {
    if (c.throughEntryId <= target && c.throughEntryId >= floor) candidates.push({ kind: 'checkpoint', throughEntryId: c.throughEntryId });
  }
  const cut = source.archive === undefined ? null : await tolerant(() => source.archive!.lastCut(), null);
  if (cut !== null && cut.throughEntryId <= target) candidates.push({ kind: 'cut', throughEntryId: cut.throughEntryId });
  // Policy-1 segments followed by the first policy-2 one: empty state as of the entry before that one is exact.
  const firstPolicy2 = geometry.findIndex((g) => g.policy >= 2);
  if (firstPolicy2 > 0 && geometry.slice(0, firstPolicy2).every((g) => g.policy === 1)) {
    const through = geometry[firstPolicy2].firstEntryId - 1;
    if (through <= target) candidates.push({ kind: 'boundary', throughEntryId: through });
  }
  candidates.sort((a, b) => b.throughEntryId - a.throughEntryId || RANK[a.kind] - RANK[b.kind]);

  let state: DecodeState | null = null;
  for (const c of candidates) {
    state = await tolerant(() => open(source, limited, c, cut, inflate), null);
    if (state !== null) break;
  }
  if (state === null) state = DecodeState.empty(Math.min(floor, target));

  let bytes = 0;
  while (state.throughEntryId < target) {
    const page = await source.readPage(limited, state.throughEntryId, LIMITS.pageEntries, LIMITS.pageBytes);
    if (page.entries.length === 0) {
      throw new Error(`the journal holds no entry after ${state.throughEntryId}, and the state was asked for through ${target}`);
    }
    for (const e of page.entries) {
      if (e.ref.entryId > target) break;
      bytes += (e.kind === 'datagram' ? e.bytes.length : 0) + ENTRY_OVERHEAD_BYTES;
      if (bytes > maxReplayBytes) return 'range-too-large';
      state.step(e);
    }
    if (page.done) break;
  }
  if (state.throughEntryId < target) {
    throw new Error(`the journal ends at ${state.throughEntryId}, and the state was asked for through ${target}`);
  }
  return state;
}

/** One starting point as a state, or null when it cannot be used. */
async function open(
  source: StateSource, limited: Snapshot, c: Candidate, cut: { throughEntryId: number; throughMs: number; checkpoint: Uint8Array } | null,
  inflate: Inflate,
): Promise<DecodeState | null> {
  let state: DecodeState | null;
  if (c.kind === 'checkpoint') {
    const deflated = await source.readCheckpoint(c.throughEntryId);
    if (deflated === null) return null;
    const raw = inflate(deflated, LIMITS.checkpointBytes);
    if (raw.length > LIMITS.checkpointBytes) return null;
    state = DecodeState.fromCheckpoint(raw);
  } else if (c.kind === 'cut') {
    if (cut === null) return null;
    // An expiry that had no state to keep stored nothing: the state through the cut is the empty one.
    state = cut.checkpoint.length === 0 ? DecodeState.empty(cut.throughEntryId, cut.throughMs) : DecodeState.fromCheckpoint(cut.checkpoint);
  } else {
    // The checkpoint of a state this empty carries the receipt time of its entry, so that entry is read.
    const e = await source.readEvidence({ generation: limited.generation, entryId: c.throughEntryId });
    if (e === null || e.ref.entryId !== c.throughEntryId) return null;
    state = DecodeState.empty(c.throughEntryId, e.receivedMs);
  }
  return state !== null && state.throughEntryId === c.throughEntryId ? state : null;
}
