/**
 * The live path's bounds (ADR 0053), as arithmetic and as a simulated burst.
 *
 *   npx tsx scripts/pipeline/live-flow.ts
 *
 * The first half drives `LiveFlow` directly: batches counted down frame by
 * frame, holes in the agent's numbering found and sized, a few frames out of
 * order across adapters NOT read as a hole, and the store's gate engaging only
 * on a store that answers. The second half is the whole chain on a clock -
 * main's credit (`electron/pipeCredit.ts`), the Worker's ledgers, a dissector
 * slower than arrival and a store slower than both - and holds what the bound
 * is for: nothing grows without limit, every frame shed is counted as
 * skipped, every hole is marked on a frame, and when the burst ends
 * everything drains with nothing left owed.
 */
import { HOLE_MIN_FRAMES, LiveFlow, STORE_BACKLOG_FRAMES } from '../../src/services/pipeline/liveFlow';
import { PipeCredit } from '../../electron/pipeCredit';
import { addLiveGapRow, markLiveGap } from '../../src/services/dissect/liveGapFields';
import { liveLagLabel, NO_LAG } from '../../src/services/liveLag';
import type { Packet, ProtocolLayer } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

console.log('--- the ledgers ---\n');
{
  const flow = new LiveFlow();
  flow.batchArrived(1, 3);
  flow.batchArrived(2, 0);
  check('an empty batch is answered at once', JSON.stringify(flow.takeCompleted()) === '[2]');
  flow.frameDone(1); flow.frameDone(1);
  check('a batch is not answered while frames of it wait', flow.takeCompleted().length === 0);
  flow.frameDone(1);
  check('...and is once its last frame is dissected', JSON.stringify(flow.takeCompleted()) === '[1]');
  flow.batchArrived(3, 5);
  flow.batchDropped(4);
  flow.abandonBatches();
  check('a dropped batch and a cleared window are both answered', JSON.stringify(flow.takeCompleted().sort()) === '[3,4]');
}
{
  const flow = new LiveFlow();
  const holes = [10, 11, 12, 40, 41].map((seq) => flow.seqArrived(seq));
  check('the first frame and consecutive ones make no hole', holes.slice(0, 3).every((h) => h === 0));
  check(`a jump of ${40 - 13} is a hole of that size, on the frame after it`, holes[3] === 27 && holes[4] === 0);
  check('...and the skipped count is exact', flow.skippedFrames === 27);
  const small = new LiveFlow();
  for (const seq of [1, 2, 3, 5, 4, 6, 9, 7, 8, 10]) small.seqArrived(seq);
  check('two adapters\' frames a few places out of order are neither a hole nor skipped',
    small.skippedFrames === 0);
  const tiny = new LiveFlow();
  tiny.seqArrived(1);
  const mark = tiny.seqArrived(1 + HOLE_MIN_FRAMES - 1);
  check(`a jump under ${HOLE_MIN_FRAMES} is counted but not marked`, mark === 0 && tiny.skippedFrames === HOLE_MIN_FRAMES - 2);
  const tail = new LiveFlow();
  tail.seqArrived(0);
  tail.noteShed(1, 300);
  check('a batch main shed is counted at once, even with nothing after it', tail.skippedFrames === 300);
  check('...and marked on the next frame that does arrive', tail.seqArrived(301) === 300 && tail.skippedFrames === 300);
  const restarted = new LiveFlow();
  restarted.seqArrived(5000);
  check('a numbering that starts again is a new run, not a hole', restarted.seqArrived(1) === 0 && restarted.skippedFrames === 0);
}
{
  const flow = new LiveFlow();
  const ack = flow.storeSent(STORE_BACKLOG_FRAMES + 10);
  check('a store that has never answered never holds the Worker back', !flow.storeBehind);
  const first = flow.storeSent(1);
  flow.storeTaken(first);
  check('once it answers, a backlog past the budget does', flow.storeBehind);
  flow.storeTaken(ack);
  check('...until it is answered', !flow.storeBehind && flow.storeOwedFrames === 0);
}

console.log('\n--- the note on the frame ---\n');
{
  const frameLayer = (): ProtocolLayer[] => [{ name: 'Frame', summary: 'Frame', fields: [] }];
  const packet = { id: 9, layers: frameLayer(), fields: {} } as unknown as Packet;
  markLiveGap(packet, 300);
  const row = packet.layers[0].fields[0];
  check('the frame after a hole carries the count as a field', packet.fields?.['inwire.live.skipped'] === 300);
  check('...an expert finding filed as a capture gap, never as loss',
    packet.expert?.[0]?.category === 'CaptureGap' && /in the capture file/.test(packet.expert[0].message));
  check('...and a row on its Frame layer', row?.abbrev === 'inwire.live.skipped' && row.expertInfo?.category === 'CaptureGap');
  const rebuilt = frameLayer();
  addLiveGapRow(rebuilt, packet.fields?.['inwire.live.skipped']);
  check('a rebuilt tree gets the same row back from the stored field', JSON.stringify(rebuilt[0].fields) === JSON.stringify(packet.layers[0].fields));
  const none = frameLayer();
  addLiveGapRow(none, undefined);
  check('a frame with no hole before it gets nothing', none[0].fields.length === 0);
}

console.log('\n--- what the status bar says ---\n');
{
  check('live: nothing', liveLagLabel(NO_LAG) === null);
  check('the ordering window\'s fraction of a second is not "behind"', liveLagLabel({ ...NO_LAG, behindFrames: 900, behindMs: 300 }) === null);
  const behind = liveLagLabel({ ...NO_LAG, behindFrames: 410_000, behindMs: 12_200 });
  check('behind: seconds in the cell, the frames to go in the title',
    behind?.text === 'behind live 12 s' && /410,000 frames to go/.test(behind.title));
  const skipped = liveLagLabel({ ...NO_LAG, skippedFrames: 18_000, shedding: true });
  check('skipped: said as not lost, and in the capture file',
    skipped?.text === '18,000 skipped' && /nothing was lost/.test(skipped.title) && /capture file/.test(skipped.title));
}

console.log('\n--- a burst, end to end ---\n');
{
  // Ten simulated seconds at 60,000 frames/s arriving, a dissector that takes
  // 25,000/s and a store that takes 20,000/s, then quiet until both catch up.
  const TICK_MS = 10;
  const ARRIVE = 60_000, DISSECT = 25_000, STORE = 20_000;
  const BATCH = 300, FRAME_BYTES = 1100;
  const BUDGET_BYTES = 40_000 * FRAME_BYTES; // a small budget, so the test sheds
  let clock = 0;
  const credit = new PipeCredit(BUDGET_BYTES, () => clock);
  const flow = new LiveFlow();
  /** The Worker's port queue and window together: frames received, not dissected. */
  const waiting: { seq: number; batch: number; hole: number }[] = [];
  const storeQueue: { ack: number; frames: number }[] = [];
  let seq = 0, carry = 0, dissectCarry = 0, storeCarry = 0;
  let maxOwedBytes = 0, maxStoreOwed = 0, maxWaiting = 0, marked = 0;
  /** Frames shed after the last batch that got through: no frame follows them to carry a note. */
  let tailShed = 0;
  for (let t = 0; t < 2000; t++) {
    clock += TICK_MS;
    // The agent: batches of 300, every frame numbered.
    if (t < 1000) {
      carry += (ARRIVE * TICK_MS) / 1000;
      while (carry >= BATCH) {
        carry -= BATCH;
        const first = seq;
        seq += BATCH;
        const id = credit.admit(BATCH * FRAME_BYTES, BATCH);
        if (id === null) {
          // Shed by main, which says so in the batch's place.
          flow.noteShed(first, BATCH);
          tailShed += BATCH;
          continue;
        }
        tailShed = 0;
        flow.batchArrived(id, BATCH);
        for (let s = first; s < first + BATCH; s++) waiting.push({ seq: s, batch: id, hole: flow.seqArrived(s) });
      }
    }
    // The Worker: a slice of dissection, gated by the store.
    dissectCarry += (DISSECT * TICK_MS) / 1000;
    let slice = Math.floor(dissectCarry);
    dissectCarry -= slice;
    if (flow.storeBehind) slice = 0;
    slice = Math.min(slice, waiting.length);
    if (slice > 0) {
      const done = waiting.splice(0, slice);
      storeQueue.push({ ack: flow.storeSent(done.length), frames: done.length });
      for (const frame of done) {
        if (frame.hole > 0) marked += frame.hole;
        flow.frameDone(frame.batch);
      }
      credit.drained(flow.takeCompleted());
    }
    // The store, slower still, answering every append it finishes.
    storeCarry += (STORE * TICK_MS) / 1000;
    while (storeQueue.length > 0 && storeCarry >= storeQueue[0].frames) {
      storeCarry -= storeQueue[0].frames;
      flow.storeTaken(storeQueue.shift()!.ack);
    }
    if (storeQueue.length === 0) storeCarry = Math.min(storeCarry, 1000);
    maxOwedBytes = Math.max(maxOwedBytes, credit.backlog().bytes);
    maxStoreOwed = Math.max(maxStoreOwed, flow.storeOwedFrames);
    maxWaiting = Math.max(maxWaiting, waiting.length);
  }
  const lag = credit.backlog();
  check('main never let the Worker owe more than its budget and one batch',
    maxOwedBytes <= BUDGET_BYTES + BATCH * FRAME_BYTES, `${maxOwedBytes} > ${BUDGET_BYTES}`);
  check('the Worker\'s waiting frames stayed bounded by the same', maxWaiting <= BUDGET_BYTES / FRAME_BYTES + BATCH, String(maxWaiting));
  check('the store never owed much past its budget', maxStoreOwed <= STORE_BACKLOG_FRAMES + DISSECT, String(maxStoreOwed));
  check('main shed frames - the burst was more than the chain could take', lag.shedFrames > 0, String(lag.shedFrames));
  check('every frame main shed is counted as skipped, from the numbering alone',
    flow.skippedFrames === lag.shedFrames, `${flow.skippedFrames} vs ${lag.shedFrames}`);
  check('...and every one is marked on the frame after its hole - all but those shed after the last frame to arrive, which no frame follows',
    marked === lag.shedFrames - tailShed, `${marked} vs ${lag.shedFrames} - ${tailShed}`);
  check('after the burst everything drained: nothing owed to main or by the store',
    lag.frames === 0 && waiting.length === 0 && flow.storeOwedFrames === 0,
    `main ${lag.frames}, waiting ${waiting.length}, store ${flow.storeOwedFrames}`);
}

console.log(failures === 0 ? '\nAll live-flow checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
