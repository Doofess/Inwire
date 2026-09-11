/**
 * One message at a time, in the order they arrived.
 *
 * ## What this cost before it existed
 *
 * `capture.worker.ts` dispatched with `void handle(message)`, so handlers ran
 * concurrently. `open` is deeply asynchronous - a directory handle, four file
 * handles, four `createSyncAccessHandle()` calls, then `persist()` and
 * `estimate()` - and on a cold start that takes longer than the app's 100 ms
 * flush. So the first `append` after Start arrived while `open` was still
 * awaiting, found no capture open, and **returned silently**.
 *
 * Measured on a real run in Chrome: a 6,000-frame capture stored **5,500**,
 * and the store's own id range said `first: 501`. The first batch, gone, with
 * nothing anywhere saying so - which is precisely the failure
 * `sessionStore`'s budget comment was written to prevent, arriving by a
 * different door.
 *
 * ## Why it is here rather than in the worker
 *
 * The worker's own header says it should hold "no logic worth testing", and
 * ordering is logic worth testing - a promise chain is three lines and two of
 * them can be wrong in ways that only show up under a timing that a browser
 * produces and a reviewer does not imagine. **OPFS does not exist in Node, so
 * the worker cannot be driven from a script; this can.**
 *
 * ## The rule
 *
 * A task starts only after the previous one has settled, **including when it
 * rejects**. A queue that stopped on the first failure would turn one bad read
 * into a store that silently accepts and discards everything after it, which
 * is the same class of bug one layer up.
 */

export interface SerialQueue {
  /** Queues `task`; it starts after everything queued before it has settled. */
  run(task: () => void | Promise<void>): void;
  /** Resolves when everything queued so far has settled. For tests. */
  drain(): Promise<void>;
}

export function serialQueue(onError?: (error: unknown) => void): SerialQueue {
  let tail: Promise<void> = Promise.resolve();

  const chain = (task: () => void | Promise<void>): Promise<void> =>
    tail.then(task).catch((error: unknown) => {
      // Swallowed on purpose, and reported. An unhandled rejection here would
      // become the tail, and every task after it would be chained onto a
      // rejected promise and never run.
      onError?.(error);
    });

  return {
    run(task) { tail = chain(task); },
    drain() { return tail; },
  };
}
