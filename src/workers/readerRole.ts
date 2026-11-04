/**
 * The pipeline Worker's third role: catch-up's file reader (ADR 0053,
 * "Catch-up past the ceiling, 2026-11-04").
 *
 * Started beside the coordinator, with the shards, as the same script by its
 * own URL - `new Worker(self.location.href, { name: 'inwire-reader' })` - so it
 * has the same origin, COEP and CSP and no bundle of its own. It turns each read
 * main answers into frames: slabs of bytes and columns of fields, transferred
 * back. It holds nothing between reads; numbering, the seek, the checks against
 * live frames and the rejoin stay on the coordinator.
 *
 * Everything it does is `services/pipeline/readParse.ts`; this only connects
 * that to `postMessage`.
 */
/// <reference lib="webworker" />
import { answerParse, type ToReader } from '../services/pipeline/readParse';

/** The name the coordinator gives its reader. Not a shard's (`SHARD_NAME`). */
export const READER_NAME = 'inwire-reader';

export function isReaderRole(scope: { name?: string }): boolean {
  return scope.name === READER_NAME;
}

export function runReader(ctx: DedicatedWorkerGlobalScope): void {
  ctx.onmessage = (event: MessageEvent<ToReader>) => {
    const { reply, transfer } = answerParse(event.data);
    ctx.postMessage(reply, transfer);
  };
}
