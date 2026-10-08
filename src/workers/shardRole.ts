/**
 * The pipeline Worker's second role: a TCP shard (ADR 0053 phase 3).
 *
 * A shard is the same script as the pipeline Worker, started by it with
 * `new Worker(self.location.href, { name: 'inwire-shard-N' })` - so it is
 * served from the same origin with the same COEP and CSP headers, needs no
 * bundle of its own, and dissects with exactly the code the coordinator's own
 * lane does. Its name is how it knows which role it is in; a shard never
 * starts the pipeline's timers or listens for the app.
 *
 * Everything it does is `services/pipeline/shard.ts`; this only connects that
 * to `postMessage`.
 */
/// <reference lib="webworker" />
import { Shard } from '../services/pipeline/shard';
import type { ToShard } from '../services/pipeline/shardProtocol';

/** The name the coordinator gives each shard it starts. */
export const SHARD_NAME = 'inwire-shard-';

export function isShardRole(scope: { name?: string }): boolean {
  return typeof scope.name === 'string' && scope.name.startsWith(SHARD_NAME);
}

export function runShard(ctx: DedicatedWorkerGlobalScope): void {
  let shard: Shard | null = null;
  const pending: ToShard[] = [];
  ctx.onmessage = (event: MessageEvent<ToShard>) => {
    const message = event.data;
    if (message.type === 'init') {
      shard = new Shard((out, transfer) => ctx.postMessage(out, transfer), {
        shards: message.shards, cacheFrames: message.cacheFrames,
      });
      for (const early of pending.splice(0)) shard.handle(early);
      return;
    }
    if (shard === null) pending.push(message);
    else {
      try {
        shard.handle(message);
      } catch (err) {
        ctx.postMessage({ type: 'failure', message: `a dissection shard failed: ${String(err)}` });
      }
    }
  };
}
