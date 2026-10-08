/**
 * A TCP shard on a `worker_threads` thread, for `parallel-threads.ts` - the
 * Node twin of `src/workers/shardRole.ts`. Not an assertion script.
 *
 * Answers one message of its own, `stats`: how busy it was, and how long it
 * spent in its own work against receiving and sending.
 */
import { parentPort } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import { Shard } from '../../src/services/pipeline/shard';
import type { ToShard } from '../../src/services/pipeline/shardProtocol';

let shard: Shard | null = null;
let handleMs = 0;
let postMs = 0;
let frames = 0;
let elu0 = performance.eventLoopUtilization();
parentPort!.on('message', (message: ToShard | { type: 'stats' }) => {
  if (message.type === 'stats') {
    // Since the last time it was asked, and from now on afresh.
    parentPort!.postMessage({
      type: 'stats', handleMs, postMs, frames, utilization: performance.eventLoopUtilization(elu0).utilization,
    });
    handleMs = 0;
    postMs = 0;
    frames = 0;
    elu0 = performance.eventLoopUtilization();
    return;
  }
  if (message.type === 'init') {
    shard = new Shard((out, transfer) => {
      const p0 = performance.now();
      parentPort!.postMessage(out, transfer as ArrayBuffer[]);
      postMs += performance.now() - p0;
    }, { shards: message.shards, cacheFrames: message.cacheFrames });
    return;
  }
  const h0 = performance.now();
  if (message.type === 'batch' && message.ops !== null) frames += message.ops.bytes.length;
  shard!.handle(message);
  handleMs += performance.now() - h0;
});
