/**
 * Assertion tests for the live-capture ordering window.
 *
 *   npx tsx scripts/dissect/ordering-window.ts
 *
 * The property that matters: two frames captured within the hold of each
 * other come out in capture order regardless of which interface thread won
 * the race to the socket. The cases below are the ones that were wrong in
 * the exported fixtures - inversions of a few milliseconds between adapters.
 */
import { OrderingWindow, type Orderable } from '../../src/services/dissect/orderingWindow';

type Tagged = Orderable & { tag: string };

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

const frame = (tsUs: number, seq: number, arrivedAt: number, tag = ''): Tagged => ({ tsUs, seq, arrivedAt, tag });
const tags = (fs: Tagged[]) => fs.map((f) => f.tag);

// --- the inversion the window exists for -------------------------------------

{
  const w = new OrderingWindow<Tagged>(100);
  // Adapter A's frame captured at t=1005 arrives first; adapter B's frame
  // captured at t=1000 arrives 3 ms later.
  w.push(frame(1005, 0, 0, 'A'));
  w.push(frame(1000, 1, 3, 'B'));
  check('nothing leaves before the hold has elapsed', w.drain(50), []);
  check('...and both wait', w.size, 2);
  check('after the hold, capture order wins over arrival order', tags(w.drain(200)), ['B', 'A']);
  check('the window is empty afterwards', w.size, 0);
  check('nothing was late - they were within the hold', w.lateCount, 0);
}

// --- ties resolve by sequence number ------------------------------------------

{
  const w = new OrderingWindow<Tagged>(100);
  w.push(frame(1000, 5, 0, 'second'));
  w.push(frame(1000, 4, 1, 'first'));
  check('equal timestamps order by seq', tags(w.drain(500)), ['first', 'second']);
}

// --- only frames that have waited long enough leave --------------------------

{
  const w = new OrderingWindow<Tagged>(100);
  w.push(frame(10, 0, 0, 'old'));
  w.push(frame(20, 1, 150, 'young'));
  check('a drain releases the old frame and keeps the young one', tags(w.drain(160)), ['old']);
  check('...which leaves on a later drain', tags(w.drain(260)), ['young']);
}

// --- a genuinely late frame still leaves, and is counted ------------------

{
  const w = new OrderingWindow<Tagged>(100);
  w.push(frame(2000, 0, 0, 'a'));
  w.drain(200);
  w.push(frame(1000, 1, 300, 'late'));
  check('a frame older than what already left is still emitted', tags(w.drain(500)), ['late']);
  check('...and counted as late', w.lateCount, 1);
}

// --- flush and clear -----------------------------------------------------------

{
  const w = new OrderingWindow<Tagged>(100);
  w.push(frame(30, 2, 0, 'c'));
  w.push(frame(10, 0, 1, 'a'));
  w.push(frame(20, 1, 2, 'b'));
  check('flush releases everything, sorted, ignoring the hold', tags(w.flush()), ['a', 'b', 'c']);
  w.push(frame(5, 3, 3, 'x'));
  w.clear();
  check('clear drops held frames', w.flush(), []);
  check('...and forgets what was released', w.lateCount, 0);
}

// --- sort stability: equal keys keep arrival order ---------------------------

{
  const w = new OrderingWindow<Tagged>(0);
  for (let i = 0; i < 5; i++) w.push(frame(1, 1, i, `f${i}`));
  check('fully equal keys keep arrival order', tags(w.drain(10)), ['f0', 'f1', 'f2', 'f3', 'f4']);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All ordering-window checks passed.');
process.exit(0);
