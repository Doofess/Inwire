/**
 * The monitoring Worker: NetFlow v5 history, off the main thread and out of the
 * process that holds the files (ADR 0058, ADR 0059).
 *
 * It holds no file. The journal and the rollup sidecar belong to the utility
 * process, which hands this Worker a `MessagePort` in its `connect` message;
 * every read and every post goes over that port, with a deadline, through
 * `runtimeRpc.ts`. What runs here is the part that parses bytes the network
 * chose - the datagram decoder, the rollups, the queries - which is the reason
 * it is a sandboxed Worker and not a function in the utility.
 *
 * Everything with a rule in it is in `services/monitoring/workerHost.ts`, so
 * that `scripts/monitoring/` can drive it with a fake clock and node's zlib.
 * This file is only the wiring that cannot be tested there: the real port, the
 * real clock, fflate, and a yield that is a message rather than a timer.
 *
 * `yieldNow` posts on a `MessageChannel` instead of `setTimeout(0)`. A timer
 * can be clamped to 4 ms or throttled in a background Worker; a message is a
 * task like any other and runs as soon as the ones queued before it have, which
 * is what lets a cancel that arrived mid-query be handled before the query
 * goes on.
 */
/// <reference lib="webworker" />

import { deflateSync } from 'fflate';
import { boundedInflate } from '../services/monitoring/boundedInflate';
import { createRuntimeClient, domPort } from '../services/monitoring/runtimeRpc';
import { MonitoringWorkerHost } from '../services/monitoring/workerHost';
import { LIMITS } from '../services/monitoring/types';

const yieldChannel = new MessageChannel();
const yieldWaiters: (() => void)[] = [];
yieldChannel.port1.onmessage = () => {
  yieldWaiters.shift()?.();
};

const host = new MonitoringWorkerHost({
  post: (message) => self.postMessage(message),
  openRuntime: (port) => createRuntimeClient(domPort(port as MessagePort), {
    requestMs: LIMITS.requestMs,
    setTimer: (fn, ms) => {
      const id = setTimeout(fn, ms);
      return () => clearTimeout(id);
    },
  }),
  now: () => performance.now(),
  yieldNow: () => new Promise<void>((resolve) => {
    yieldWaiters.push(resolve);
    yieldChannel.port2.postMessage(0);
  }),
  wallNow: () => Date.now(),
  // Level 1, as the capture store does: a rollup is written once per minute per
  // source and read rarely, so the fast level is the right trade.
  deflate: (bytes) => deflateSync(bytes, { level: 1 }),
  inflate: boundedInflate,
});

self.onmessage = (event: MessageEvent) => host.handle(event.data);
