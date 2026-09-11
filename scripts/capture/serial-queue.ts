/**
 * One message at a time, in order.
 *
 *   npx tsx scripts/capture/serial-queue.ts
 *
 * This exists because the capture worker dispatched with `void handle(msg)`
 * and lost frames for it. `open` is deeply asynchronous - four
 * `createSyncAccessHandle()` calls among other things - and on a cold start it
 * outlasts the app's 100 ms flush, so the first `append` after Start ran while
 * `open` was still awaiting, found no capture, and returned **silently**.
 * Measured in Chrome: a 6,000-frame capture stored 5,500, id range starting at
 * 501.
 *
 * OPFS does not exist in Node, so the worker itself cannot be driven from a
 * script. The ordering rule can, and it is the half with the bug in it.
 */
import { serialQueue } from '../../src/services/capture/serialQueue';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

/** Resolves after `ticks` microtask turns, standing in for an awaited API. */
const slow = async (ticks: number): Promise<void> => {
  for (let i = 0; i < ticks; i++) await Promise.resolve();
};

async function main(): Promise<void> {
  console.log('--- a slow task does not let a later one overtake it ---\n');
  {
    const order: string[] = [];
    const q = serialQueue();
    // The exact shape of the bug: `open` awaits eleven times, `append` awaits
    // nothing, and `append` was posted second.
    q.run(async () => { await slow(11); order.push('open'); });
    q.run(() => { order.push('append 1'); });
    q.run(async () => { await slow(3); order.push('append 2'); });
    q.run(() => { order.push('finish'); });
    await q.drain();
    check('every task ran in the order it was queued',
      order, ['open', 'append 1', 'append 2', 'finish']);
  }

  console.log('\n--- and the same thing without a queue, which is the defect ---\n');
  {
    // Kept as a check rather than a comment, because it is the thing that
    // makes the one above worth having: the same four tasks dispatched the way
    // the worker used to dispatch them come out in the wrong order.
    const order: string[] = [];
    void (async () => { await slow(11); order.push('open'); })();
    void (async () => { order.push('append 1'); })();
    void (async () => { await slow(3); order.push('append 2'); })();
    void (async () => { order.push('finish'); })();
    await slow(30);
    check('unqueued, the appends beat the open they depend on',
      order, ['append 1', 'finish', 'append 2', 'open']);
  }

  console.log('\n--- a task that throws must not stop the queue ---\n');
  {
    const order: string[] = [];
    const errors: string[] = [];
    const q = serialQueue((e) => errors.push(String(e)));
    q.run(() => { order.push('first'); });
    q.run(async () => { await slow(2); throw new Error('a bad read'); });
    q.run(() => { order.push('after the throw'); });
    q.run(() => { throw new Error('a sync throw'); });
    q.run(() => { order.push('after that one too'); });
    await q.drain();
    // A queue that stopped here would turn one bad read into a store that
    // accepts and discards everything after it - the same class of silent
    // loss one layer up.
    check('the tasks after a rejection still run',
      order, ['first', 'after the throw', 'after that one too']);
    check('...and both failures were reported rather than swallowed',
      errors, ['Error: a bad read', 'Error: a sync throw']);
  }

  console.log('\n--- drain is honest about what is still outstanding ---\n');
  {
    const q = serialQueue();
    let done = false;
    q.run(async () => { await slow(5); done = true; });
    check('a task is not finished the moment it is queued', done, false);
    await q.drain();
    check('...and drain waits for it', done, true);
    // Nothing queued at all is a resolved promise, not a hang.
    await serialQueue().drain();
    check('draining an empty queue resolves', true, true);
  }

  console.log(failures === 0
    ? '\nAll serial queue checks passed.'
    : `\n${failures} serial queue check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
