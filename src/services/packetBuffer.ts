/**
 * Committing one batch of frames to the packet buffer.
 *
 * This is the body of `App.tsx`'s flush, moved out so it can be **called**
 * rather than only rendered. Nothing about it changed in the move.
 *
 * ## Why it is split in two
 *
 * React may invoke a state updater more than once with the same `prev`, and in
 * development `StrictMode` always does - `main.tsx` turns it on. So the work
 * divides by whether running it twice is harmless:
 *
 * - `prepareBatch` is everything that must happen **exactly once**: writing to
 *   the session store, claiming a dense-field row per frame, and adding the
 *   batch's bytes to the running total. It runs outside the updater.
 * - `commitBatch` is the updater itself, and it must be **safe to run twice on
 *   the same `prev`**. It is not pure - it moves the accounting and it trims
 *   the store - so every impure step inside it is guarded by the head id, which
 *   both invocations compute identically.
 *
 * That guard is the subtlest thing here and each failure it prevents actually
 * happened. The drop counter came out "roughly double"; subtracting the freed
 * bytes twice walked the running total down until the buffer stopped trimming
 * at all. Neither is a crash - both are quiet miscounts in the numbers the
 * feature exists to report - which is why `scripts/session/ingest.ts` runs
 * every commit twice on purpose and checks the arithmetic rather than the
 * rendering.
 */
import type { Packet } from '../types/packet';
import type { InfoPatch } from './dissect/types';
import { AUTO_PAUSE_AT, estimateSummaryBytes, planBufferTrim } from './bufferBudget';
import { evictOldBytes } from './packetBytes';
import { applyIcmpRepliesInPlace } from './sessionRestore';
import { applyInfoPatchesInPlace } from './pcapParser';

/**
 * The state a flush carries between invocations - what App.tsx holds in refs.
 *
 * Mutated in place rather than returned, because that is what a ref does and
 * the double-invocation guards only make sense against state that persists
 * across both runs. A test drives it by passing the same object twice.
 */
export interface BufferAccounting {
  /** Summary bytes held by the live buffer, as counted rather than measured. */
  residentBytes: number;
  /** Frames pushed out of the buffer since the capture began. */
  droppedTotal: number;
  /**
   * The buffer's head id at the last trim.
   *
   * The whole StrictMode guard. Both invocations of an updater see the same
   * `prev` and so compute the same head, which makes the second one a no-op.
   */
  droppedHeadId: number;
  /** The newest frame id already written to the session store. */
  persistedThroughId: number;
}

export function freshAccounting(): BufferAccounting {
  return { residentBytes: 0, droppedTotal: 0, droppedHeadId: -1, persistedThroughId: -1 };
}

export interface PrepareEffects {
  /** Fire-and-forget: the flush cadence never waits on IndexedDB. */
  persist(frames: readonly Packet[]): void;
  /** Moves the dense fields into shared columns as a frame joins the buffer. */
  absorb(frames: readonly Packet[]): void;
}

/**
 * The half that must happen exactly once per flush.
 *
 * Outside the updater precisely because none of it is repeatable: a second
 * `persist` writes the batch to disk twice, and a second `absorb` claims a
 * second block row per frame and wastes it.
 */
export function prepareBatch(
  incoming: readonly Packet[],
  accounting: BufferAccounting,
  effects: PrepareEffects,
): void {
  if (incoming.length > 0) {
    const newest = incoming[incoming.length - 1].id;
    if (newest > accounting.persistedThroughId) {
      accounting.persistedThroughId = newest;
      effects.persist(incoming);
    }
  }
  effects.absorb(incoming);
  for (const packet of incoming) accounting.residentBytes += estimateSummaryBytes(packet);
}

export interface CommitEffects {
  /** The stored session mirrors the live buffer, including its forgetting. */
  trimFramesBelow(id: number): void;
  storedIdRange(): { first: number; last: number } | null;
  /** The new running total of frames the buffer has pushed out. */
  reportDropped(total: number): void;
  /** The buffer reached `AUTO_PAUSE_AT` of its budget. */
  autoPause(): void;
}

export interface CommitOptions {
  budgetBytes: number;
  capturing: boolean;
  /** Frames whose bytes stay resident; the rest are evicted once stored. */
  residentFrames: number;
  /**
   * `accounting.residentBytes` as it stood when the flush began, snapshotted by
   * the caller and NOT read from the accounting here.
   *
   * This is what makes the head-id guard below actually work, and getting it
   * wrong is a defect this file was extracted to find. The guard assumes both
   * invocations of the updater compute the same head - but the head comes from
   * the trim plan, the plan is computed from the resident byte total, and the
   * guard's own body subtracts from that total. So the second invocation saw a
   * smaller number, planned a smaller trim (usually none), computed a different
   * head, and sailed straight past the guard.
   *
   * The visible result was the opposite of a double count: the second run
   * returned the **untrimmed** buffer, so under `StrictMode` the buffer did not
   * trim at all while its byte total drifted below the truth - which is exactly
   * the failure the code's own comment claimed to have fixed.
   *
   * A snapshot cannot move between invocations, so both plan identically, both
   * compute the same head, and only the first gets past the guard. With a
   * single invocation it equals the accounting, so nothing about production
   * behaviour changes.
   */
  residentBytesAtEntry: number;
}

/**
 * The state updater: `prev` plus this batch, trimmed to budget.
 *
 * **Safe to call twice with the same `prev`**, which is the property the whole
 * design turns on and the one `scripts/session/ingest.ts` checks. The concat
 * happens first so a patch can target a frame in this very batch - a record
 * that began and ended within one flush - and both patch passes then write into
 * an array nobody else has seen, so they can go by index instead of rebuilding
 * the buffer around them.
 */
export function commitBatch(
  prev: readonly Packet[],
  incoming: readonly Packet[],
  replies: { requestFrameId: number; replyId: number }[],
  patches: InfoPatch[],
  accounting: BufferAccounting,
  options: CommitOptions,
  effects: CommitEffects,
): Packet[] {
  let next = prev.concat(incoming);
  if (replies.length > 0) applyIcmpRepliesInPlace(next, replies);
  if (patches.length > 0) applyInfoPatchesInPlace(next, patches);

  const plan = planBufferTrim(next, options.residentBytesAtEntry, options.budgetBytes);
  const trimmed = plan.dropCount > 0 ? next.slice(plan.dropCount) : next;
  if (trimmed !== next) {
    const forgotten = next.length - trimmed.length;
    const headId = trimmed[0].id;
    // Everything impure sits inside this guard. Both invocations see the same
    // `prev`, so both compute the same head and only the first gets past it.
    if (headId !== accounting.droppedHeadId) {
      accounting.droppedTotal += forgotten;
      accounting.droppedHeadId = headId;
      effects.reportDropped(accounting.droppedTotal);
      accounting.residentBytes -= plan.freedBytes;
    }
    next = trimmed;
    effects.trimFramesBelow(next[0].id);
  }

  // Idempotent, so running it twice does the work once, and it changes no
  // packet's identity - which is why it is allowed inside an updater at all.
  evictOldBytes(next, options.residentFrames, effects.storedIdRange());

  if (options.capturing && accounting.residentBytes >= options.budgetBytes * AUTO_PAUSE_AT) {
    effects.autoPause();
  }
  return next;
}
