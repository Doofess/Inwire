/**
 * Assertion tests for the coordinator's queue of frames not yet routed
 * (`src/services/pipeline/heldQueue.ts`).
 *
 *   npx tsx scripts/pipeline/held-queue.ts
 *
 * Each held item carries the in-flight cost taken when it was dispatched: a
 * frame waiting behind a barrier can have had its buffer transferred away by
 * the time it is routed, so the cost is never read from it again. Item and cost
 * used to be two arrays the coordinator kept in step by hand, compaction
 * included; a slip there leaves `heldCost` above zero for good.
 */
import { HeldQueue } from '../../src/services/pipeline/heldQueue';

let failures = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === undefined ? '' : `\n        ${JSON.stringify(detail)}`}`);
}

{
  const queue = new HeldQueue<{ id: number }>();
  check('a new queue is empty', queue.size === 0 && queue.shift() === undefined);
  for (let id = 0; id < 5_000; id++) queue.push({ id }, id * 3);
  check('size counts what was pushed', queue.size === 5_000);
  check('peek reads ahead without taking', queue.peek(0)?.id === 0 && queue.peek(10)?.id === 10 && queue.peek(5_000) === undefined && queue.size === 5_000);

  // Past the point where the queue compacts its arrays (4,096 taken), and on.
  let aligned = true;
  for (let id = 0; id < 4_500; id++) {
    const item = queue.shift();
    if (item?.id !== id || queue.shiftedCost !== id * 3) { aligned = false; break; }
  }
  check('each item comes out with its own cost, through compaction', aligned);
  check('...and peek counts from the front after it', queue.size === 500 && queue.peek(0)?.id === 4_500);
  for (let id = 5_000; id < 5_010; id++) queue.push({ id }, id * 3);
  let rest = true;
  for (let id = 4_500; id < 5_010; id++) {
    const item = queue.shift();
    if (item?.id !== id || queue.shiftedCost !== id * 3) { rest = false; break; }
  }
  check('items pushed after a compaction keep their costs too', rest && queue.size === 0);
  queue.push({ id: 1 }, 7);
  queue.clear();
  check('clear empties it', queue.size === 0 && queue.shift() === undefined);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All held-queue checks passed.');
process.exit(0);
