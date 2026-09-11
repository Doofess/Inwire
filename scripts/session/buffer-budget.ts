/**
 * Assertion tests for the packet buffer's memory budget.
 *
 *   npx tsx scripts/session/buffer-budget.ts
 *
 * The buffer is limited by memory rather than by a frame count
 * (`services/bufferBudget.ts`), and `planBufferTrim` is the part that decides
 * what to drop. It is pure and exported because it removes a user's frames
 * without being asked, so it is worth testing directly rather than only through
 * a running buffer - and it is the only thing left in the app that does. The
 * disk budget that used to sit beside it, and its `planBudgetEviction`, went
 * with the IndexedDB session.
 *
 * The property that costs the most if it is wrong is not the arithmetic, it is
 * the **hysteresis**. Trimming moves the head of the buffer, and that
 * invalidates every identity-based cache in the app - `packetsExtend`, the
 * display-filter cache, each `useIncrementalAggregate`. A planner that trimmed
 * whenever it was a byte over would make all of them fall back to a full pass
 * on every flush, ten times a second, which is the exact failure `TRIM_SLACK`
 * was introduced to fix at a tenth of this buffer size.
 *
 * So: nothing until over budget by more than the slack, and then back to the
 * budget rather than to the edge of it, so the next flush is not over again.
 */
import {
  BUDGET_SLACK, estimateSummaryBytes, framesForBudget, planBufferTrim,
  DISK_RESERVE_BYTES, shouldStopForDisk,
} from '../../src/services/bufferBudget';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** A frame carrying nothing that varies, so its estimate is the base alone. */
function plain(id: number): Packet {
  return { id, info: '', fields: {} } as unknown as Packet;
}

const ONE = estimateSummaryBytes(plain(1));
const buffer = (n: number) => Array.from({ length: n }, (_, i) => plain(i + 1));

// --- What a frame costs -------------------------------------------------------
{
  checkTrue('a frame estimates to something positive', ONE > 0);

  // The varying parts have to actually vary, or the budget is a frame count
  // wearing a different unit - which is the thing it was chosen over.
  const chatty = { id: 1, info: 'x'.repeat(200), fields: {} } as unknown as Packet;
  checkTrue('a long Info line costs more than a short one',
    estimateSummaryBytes(chatty) > ONE + 300);

  const wide = { id: 1, info: '', fields: Object.fromEntries(
    Array.from({ length: 20 }, (_, i) => ['k' + i, i])) } as unknown as Packet;
  checkTrue('a frame with more sparse fields costs more', estimateSummaryBytes(wide) > ONE);

  // Deterministic, which is what lets the running total add on the way in and
  // subtract on the way out without drifting over a long capture.
  check('the same frame always estimates the same',
    estimateSummaryBytes(plain(7)), estimateSummaryBytes(plain(7)));

  // Raw bytes are bounded separately, at 25,000 frames, so the budget must not
  // see them - and a frame whose bytes were evicted must estimate the same as
  // it did when it still had them, or the total drifts.
  const withBytes = { ...plain(1), rawBytes: new Uint8Array(1500) } as unknown as Packet;
  const evicted = { ...plain(1), rawBytes: new Uint8Array(0) } as unknown as Packet;
  check('raw bytes are not counted, so eviction does not change the estimate',
    estimateSummaryBytes(withBytes), estimateSummaryBytes(evicted));
}

// --- Nothing is dropped until the slack is used up -------------------------------
{
  const packets = buffer(1000);
  const budget = ONE * 500;

  check('well under budget drops nothing',
    planBufferTrim(packets, budget / 2, budget).dropCount, 0);
  check('exactly at budget drops nothing',
    planBufferTrim(packets, budget, budget).dropCount, 0);

  // This is the case that matters: over budget, but inside the slack.
  const insideSlack = budget * (1 + BUDGET_SLACK * 0.5);
  check('over budget but inside the slack drops nothing',
    planBufferTrim(packets, insideSlack, budget).dropCount, 0);

  const atSlackEdge = budget * (1 + BUDGET_SLACK);
  check('at the edge of the slack still drops nothing',
    planBufferTrim(packets, atSlackEdge, budget).dropCount, 0);
}

// --- Past the slack, it drops back to the budget rather than to the edge ---------
{
  const packets = buffer(1000);
  const budget = ONE * 500;
  const over = budget * (1 + BUDGET_SLACK * 2);

  const plan = planBufferTrim(packets, over, budget);
  checkTrue('past the slack it drops something', plan.dropCount > 0);
  checkTrue('...and lands under the budget', over - plan.freedBytes <= budget);

  // Back to the budget, not to the edge of the slack: landing on the edge would
  // put the next flush straight back over it, which is the whole point of
  // having hysteresis rather than a threshold.
  const after = over - plan.freedBytes;
  checkTrue('...with room before the next trim', after <= budget);
  check('a second pass on the trimmed total drops nothing more',
    planBufferTrim(packets.slice(plan.dropCount), after, budget).dropCount, 0);

  // Oldest first, because the recent frames are the ones on screen. Checked by
  // the bytes rather than by the count: freeing exactly what the FIRST
  // `dropCount` frames were estimated at is what says it took them from the
  // front, where a count alone would pass whichever end it took.
  check('it frees exactly what the oldest frames were estimated at',
    plan.freedBytes,
    packets.slice(0, plan.dropCount).reduce((a, p) => a + estimateSummaryBytes(p), 0));
}

// --- It never empties the buffer ---------------------------------------------------
//
// A budget smaller than a single frame is a setting nobody meant. Answering it
// with a blank screen would be a worse reading of the intent than holding one
// frame too many.
{
  const packets = buffer(10);
  const plan = planBufferTrim(packets, ONE * 10, 1);
  check('an impossible budget still leaves one frame', packets.length - plan.dropCount, 1);

  const single = buffer(1);
  check('a buffer of one is never trimmed to nothing',
    planBufferTrim(single, ONE, 1).dropCount, 0);

  check('an empty buffer is handled', planBufferTrim([], 0, 1024).dropCount, 0);
}

// --- Frames a budget holds ----------------------------------------------------------
{
  check('the frame count follows the average',
    framesForBudget(1000, 100), 10);
  checkTrue('a budget smaller than a frame still reports one',
    framesForBudget(10, 1000) === 1);
  // A capture that has not started yet has no average; the answer must still be
  // a usable number rather than Infinity.
  checkTrue('no average yet still gives a finite count',
    Number.isFinite(framesForBudget(512 * 1024 * 1024, 0)));
}

console.log('\n--- when a capture stops itself ---\n');

{
  // It used to stop at 99% of the MEMORY budget, and `planBufferTrim` only
  // acts above 105% - so the capture always stopped before the trim had ever
  // run, the window's head never moved, and every row on disk was unreachable
  // during a live capture. The rule watches the disk now, because a full
  // window loses nothing and a full disk does.
  check('a roomy disk does not stop a capture',
    shouldStopForDisk(DISK_RESERVE_BYTES * 4), false);
  check('exactly at the reserve is still fine', shouldStopForDisk(DISK_RESERVE_BYTES), false);
  check('below it stops', shouldStopForDisk(DISK_RESERVE_BYTES - 1), true);
  check('an empty disk stops', shouldStopForDisk(0), true);
  // Unknown is not a reason to stop. Some filesystems do not answer `statfs`,
  // and the honest fallback is the store reporting an ENOSPC that the panel
  // shows - not refusing to capture on a volume that simply stays quiet.
  check('an unknown figure does not stop anything', shouldStopForDisk(null), false);
  // Named in seconds rather than bytes: at the measured 1,156 B a frame and
  // 35,000 frames a second, the reserve is the warning time it buys.
  check('the reserve is about fifty seconds at full rate',
    Math.round(DISK_RESERVE_BYTES / (1156 * 35000)), 53);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All buffer-budget checks passed.');
process.exit(0);
