import type { Packet } from '../types/packet';

/**
 * How much memory the packet buffer may use, and which frames to drop when it
 * is over.
 *
 * The buffer used to be capped by a frame count the user chose from a list. That
 * number was picked when a frame cost 2,342 B and a full buffer was gigabytes; a
 * frame costs **663 B** now (`docs/decisions/0018`), so the largest option was
 * about 66 MB and the cap was leaving most of the machine unused. What a user
 * actually wants to say is how much memory the capture may have.
 *
 * This is the same shape as the disk budget that already exists -
 * `STORAGE_BUDGET_BYTES` and `planBudgetEviction` in `sessionStore.ts` - and
 * deliberately so: one idea, expressed twice, rather than two.
 *
 * **What the budget governs, and what it does not.** Summaries are the dominant
 * term and the only unbounded one, so they are what it counts. Two other pools
 * sit beside it and neither grows with it:
 *
 *   - **raw frame bytes**, kept only for the newest `BYTES_RESIDENT_FRAMES`
 *     (25,000) frames whatever the budget is - about 29 MB, constant;
 *   - **tracker state**, capped at roughly 28 MB (`docs/decisions/0014`).
 *
 * Excluding raw bytes is not only about double-counting. A frame absorbed while
 * its bytes were resident and trimmed after they had been evicted would
 * subtract less than it added, and the running total would drift upward for the
 * length of a capture until the buffer trimmed itself to nothing.
 */

/** Memory the summaries may use. The default; the user picks from `BUDGET_CHOICES`. */
export const DEFAULT_BUFFER_BUDGET_BYTES = 512 * 1024 * 1024;

/** What the settings panel offers, in bytes. */
export const BUDGET_CHOICES = [
  128 * 1024 * 1024,
  256 * 1024 * 1024,
  512 * 1024 * 1024,
  1024 * 1024 * 1024,
] as const;

/**
 * How far over budget the buffer is allowed to go before anything is dropped.
 *
 * Carried over from `TRIM_SLACK` in `App.tsx`, and load-bearing for the same
 * reason its comment gives: moving the head of the buffer invalidates every
 * identity-based cache - `packetsExtend`, the display-filter cache, each
 * `useIncrementalAggregate` - so all of them fall back to a full pass. Without
 * slack that happened ten times a second forever. A budget that trimmed the
 * instant it was exceeded would do the same thing at a buffer size where the
 * full pass costs far more.
 */
export const BUDGET_SLACK = 0.05;

/**
 * The parts of a frame that vary from frame to frame.
 *
 * `BASE` is everything that does not: the object, its slots, its numbers, its
 * row in the column block, and the strings it shares through the address and
 * token pools rather than owning. Calibrated against a real measurement rather
 * than reasoned about - `scripts/perf/buffer-budget.ts` sums this estimator
 * over both fixtures, compares it with the heap those frames actually occupy,
 * and fails if it is out by more than 15%.
 *
 * That script is the only reason these numbers are trustworthy. An estimate
 * behind a limit the user believes is worth exactly as much as its error bar,
 * and this work has produced several convincing wrong numbers already. As set
 * here it lands within 0.1% over 27,640 frames, against a measured 740 B each.
 *
 * 740 rather than the 663 in ADR 0018 because the two hold frames differently:
 * 0018 strips one component at a time and reads the difference, so what it
 * reports is what each component uniquely owns, while a buffer holds the whole
 * object. Neither is wrong; a budget wants the second. **Re-run the script
 * rather than reconciling the two by arithmetic.**
 */
const BASE = 546;
/** A key in the sparse bag: the entry, and its share of the object's table. */
const PER_SPARSE_KEY = 30;
/** One expert finding or anomaly. Pooled, so this is the reference and not the object. */
const PER_FINDING = 12;

/**
 * What one frame's summary costs, in bytes.
 *
 * A pure function of fields that do not change after dissection, so the same
 * packet always estimates the same - which is what lets the running total add
 * on the way in and subtract on the way out without drifting.
 */
export function estimateSummaryBytes(packet: Packet): number {
  let bytes = BASE;
  // UTF-16, and the largest varying part: `info` is 125 B of the average 663
  // and differs several-fold between a capture of DNS and one of bare ACKs.
  // It is unique per frame, so unlike the addresses it is never shared.
  bytes += (packet.info?.length ?? 0) * 2;
  // Only the sparse remainder is here; the dense fields live in the column
  // block and are counted in BASE, because every frame has exactly one row.
  if (packet.fields !== undefined) {
    bytes += Object.keys(packet.fields).length * PER_SPARSE_KEY;
  }
  bytes += (packet.expert?.length ?? 0) * PER_FINDING;
  bytes += (packet.anomalies?.length ?? 0) * PER_FINDING;
  return bytes;
}

/**
 * How many of the oldest frames to drop to get back under the budget.
 *
 * Pure, and separate from the buffer it describes, so the policy can be tested
 * without building one - the same reason `planBudgetEviction` is exported.
 *
 * Nothing is dropped until the buffer is over budget by more than the slack,
 * and then it drops to the budget rather than to the edge of the slack, so the
 * next flush is not immediately over again. The buffer therefore sits between
 * 95% and 105% of what the user asked for rather than exactly at it.
 */
export function planBufferTrim(
  packets: readonly Packet[],
  residentBytes: number,
  budgetBytes: number,
): { dropCount: number; freedBytes: number } {
  if (residentBytes <= budgetBytes * (1 + BUDGET_SLACK)) {
    return { dropCount: 0, freedBytes: 0 };
  }

  let freedBytes = 0;
  let dropCount = 0;
  // Never empties the buffer. A budget smaller than a single frame is a
  // setting nobody meant, and answering it with a blank screen would be a
  // worse reading of the user's intent than holding one frame too many.
  while (dropCount < packets.length - 1 && residentBytes - freedBytes > budgetBytes) {
    freedBytes += estimateSummaryBytes(packets[dropCount]);
    dropCount++;
  }
  return { dropCount, freedBytes };
}

/**
 * What a frame costs on average, measured over both fixtures.
 *
 * For the two places that need a frame count before there is a capture to
 * average: the settings panel, which shows what a budget is worth in packets,
 * and the importer, which caps by count rather than by bytes. Neither is a
 * limit - the buffer is trimmed by the real estimate either way - so an average
 * is the right precision for both.
 *
 * Kept beside the constants it comes from, and re-measured by the same script:
 * `node --expose-gc --import tsx scripts/perf/buffer-budget.ts`.
 */
export const AVERAGE_FRAME_BYTES = 740;

/**
 * Frames a budget holds, at the average a capture is running at.
 *
 * For the settings panel, which shows both numbers so the choice reads as a
 * quantity of packets as well as a quantity of memory, and for the importer,
 * which needs a count rather than a budget.
 */
export function framesForBudget(budgetBytes: number, averageBytesPerFrame: number): number {
  const perFrame = averageBytesPerFrame > 0 ? averageBytesPerFrame : BASE;
  return Math.max(1, Math.floor(budgetBytes / perFrame));
}
