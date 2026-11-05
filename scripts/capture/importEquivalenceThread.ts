/**
 * Helper, not a test: the entry of the thread each route of
 * `import-worker-equivalence.ts` runs in. A fresh isolate, so each route has a
 * key log, trackers and caches of its own.
 */
import { parentPort } from 'node:worker_threads';
import { threadMain } from './importEquivalenceRig';

if (parentPort === null) throw new Error('importEquivalenceThread is a worker_threads entry');
threadMain(parentPort);
