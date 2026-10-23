/**
 * Which template checkpoints the Worker writes to the sidecar, and when (ADRs 0064, 0066).
 *
 * The Worker captures a candidate at every segment start (role 1: the state through the entry before
 * it) and at every `stop` (role 2: the state through the stop). Most are not written. This decides,
 * batch by batch, from the retained journal alone, so a rebuild writes what the live feed did:
 *
 * - **Role 1** is written at a segment start when the retained segments since the last role-1
 *   checkpoint (or since the base) hold at least `spacingBytes`. At the default limit every segment
 *   start qualifies; at a smaller one they are spaced out.
 * - **Role 2** is written at a stop when `stopMs` of receipt time have passed since the latest kind-3
 *   entry of either role, or since the base.
 * - A candidate past the batch's watermark waits for a later batch (a checkpoint never leads the
 *   minutes). One at or below the newest checkpoint already held is dropped: a stop that ends a segment
 *   and the next segment's start name the same entry, and the state is the same.
 * - A checkpoint whose deflated body does not fit one sidecar entry is skipped, never posted: the
 *   sidecar would refuse the whole batch, and a replay would make the same one again. A reader falls
 *   back to the checkpoint before it.
 *
 * Pure: no `node:*`, no Electron.
 */
import type { Deflate } from './rollupCodec';
import type { SegmentGeometry, StoredCheckpoint } from './types';

/** A checkpoint the Worker captured; `raw` is `DecodeState.checkpoint()`, not yet deflated. */
export interface CheckpointCandidate { role: 1 | 2; throughEntryId: number; throughMs: number; raw: Uint8Array }

export interface CheckpointSpacing {
  /** The last role-1 checkpoint's through entry, or the base's (the entry before the first retained). */
  role1Through: number;
  /** The latest kind-3 entry's receipt time, or the base's. */
  latestMs: number;
  /** The newest checkpoint the sidecar holds; 0 for none. */
  storedThrough: number;
}

export interface CheckpointPlanOptions {
  spacingBytes: number;
  stopMs: number;
  /** The sidecar's entry body limit (`ROLLUP_FRAMING.maxBodyBytes`). */
  maxBodyBytes: number;
  /** `LIMITS.checkpointsPerAppend`. */
  maxPerBatch: number;
}

/** role, three reserved bytes, the length, the through entry and its time: the kind-3 body before the checkpoint. */
const KIND3_FIXED_BYTES = 24;

/**
 * `pending` in entry order; `geometry` is needed only when a role-1 candidate is at or below
 * `watermark` (the caller fetches it then), and may be null otherwise. The returned spacing is what
 * holds once `write` is in the sidecar: the caller keeps it only if the post succeeds.
 */
export function planCheckpoints(
  pending: CheckpointCandidate[], watermark: number, geometry: SegmentGeometry[] | null, spacing: CheckpointSpacing,
  deflate: Deflate, options: CheckpointPlanOptions,
): { write: StoredCheckpoint[]; pending: CheckpointCandidate[]; spacing: CheckpointSpacing } {
  const write: StoredCheckpoint[] = [];
  let next = { ...spacing };
  let at = 0;
  for (; at < pending.length; at++) {
    const c = pending[at];
    if (c.throughEntryId > watermark || write.length >= options.maxPerBatch) break;
    if (c.throughEntryId <= next.storedThrough) continue;
    if (c.role === 1) {
      if (geometry === null) throw new Error('a role-1 candidate is decided against the segment geometry');
      let bytes = 0;
      for (const g of geometry) if (g.firstEntryId > next.role1Through && g.firstEntryId <= c.throughEntryId) bytes += g.bytes;
      if (bytes < options.spacingBytes) continue;
    } else if (c.throughMs - next.latestMs < options.stopMs) {
      continue;
    }
    const bytes = deflate(c.raw);
    if (KIND3_FIXED_BYTES + bytes.length > options.maxBodyBytes) continue;
    write.push({ role: c.role, throughEntryId: c.throughEntryId, throughMs: c.throughMs, bytes });
    next = {
      role1Through: c.role === 1 ? c.throughEntryId : next.role1Through,
      latestMs: Math.max(next.latestMs, c.throughMs),
      storedThrough: c.throughEntryId,
    };
  }
  return { write, pending: pending.slice(at), spacing: next };
}
