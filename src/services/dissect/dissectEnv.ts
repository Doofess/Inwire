/**
 * The facts a dissection reads that belong to no conversation at all.
 *
 * Two things a frame's tree depends on are not in the frame and not in any
 * tracker: **the time the tree was built** (a certificate is "expired" against
 * `new Date()`), and **how much of HTTP/1's shared body budget is left** (a
 * body is truncated when every connection in flight together holds 32 MB,
 * which is the one piece of dissection state shared ACROSS connections).
 *
 * Both used to be reached directly - `new Date()` in `tls.ts` and a module
 * counter in `http1.ts` - which made a frame's tree depend on whatever else
 * happened to be in flight, or on the wall clock, when it was built. That is
 * invisible while a tree is only ever built once. It stops being invisible the
 * moment a tree is rebuilt later from the frame alone (ADR 0049): the rebuild
 * would read a different clock and a different budget and quietly disagree
 * with what arrival showed.
 *
 * So both go through this one door. Arrival uses `LIVE_ENV`, which is exactly
 * the old behaviour. A revisit installs an env that answers from what arrival
 * recorded, for the length of one synchronous dissection (`withDissectEnv`).
 *
 * **The key log is the one fact here a revisit does not take from the record.**
 * A record never holds key material, so a revisit asks the key log it has now -
 * and what arrival recorded is only whether there WAS an answer. When the two
 * disagree the revisit misses rather than drawing a connection opened, or shut,
 * differently from arrival.
 */
import { keyLog } from '../tls/keyLog';

/** Everything in flight together may hold this much HTTP/1 body. */
export const MAX_TOTAL_BODY_BYTES = 32 * 1024 * 1024;

export interface DissectEnv {
  /** The moment a certificate's validity is judged against. */
  now(): Date;
  /** How many more HTTP/1 body bytes the shared budget will admit. */
  sharedBodyRoom(): number;
  /** `n` body bytes were kept. */
  takeBodyBytes(n: number): void;
  /** `n` body bytes were given back - finished, replaced or evicted. */
  releaseBodyBytes(n: number): void;
  /**
   * Which way a frame went, as decided against the host identity known now.
   * Identity at arrival; a revisit answers with what arrival decided, because
   * a live capture learns this machine's identity part way through.
   */
  direction(decided: number): number;
  /**
   * The key log's secrets for a TLS connection, looked up when its ServerHello
   * is read. Recorded only as whether there were any.
   */
  keyLogSecrets(clientRandom: Uint8Array): Map<string, Uint8Array> | undefined;
  /** Whether any key log is loaded, which decides if "no entry" is worth saying. */
  keyLogEmpty(): boolean;
}

/**
 * Bytes held by every body currently being collected.
 *
 * Module-level, which makes it per-pipeline-Worker and therefore per-capture.
 * **It is only correct because every path that stops collecting gives its
 * bytes back**: a completed body in `finishBody`, a replaced one in
 * `startBody`, and an evicted connection through `releaseHttp1Body`, which
 * `tcpStreamTracker.ts` calls from `evictPastCap`. A path that forgets costs a
 * permanent slice of the budget, and enough of them stop body collection for
 * the rest of the capture with nothing saying why.
 */
let liveBodyBytes = 0;

/** The environment of a frame dissected as it arrives. */
export const LIVE_ENV: DissectEnv = {
  now: () => new Date(),
  sharedBodyRoom: () => MAX_TOTAL_BODY_BYTES - liveBodyBytes,
  takeBodyBytes: (n) => { liveBodyBytes += n; },
  releaseBodyBytes: (n) => {
    liveBodyBytes -= n;
    if (liveBodyBytes < 0) liveBodyBytes = 0;
  },
  direction: (decided) => decided,
  keyLogSecrets: (clientRandom) => keyLog.secretsFor(clientRandom),
  keyLogEmpty: () => keyLog.isEmpty,
};

let current: DissectEnv = LIVE_ENV;

/** The environment the dissection running now should read. */
export function dissectEnv(): DissectEnv {
  return current;
}

/**
 * Runs `fn` - one synchronous dissection - under `env`, and puts the previous
 * environment back however `fn` ends. Dissection never awaits, so nothing else
 * can observe the swap.
 */
export function withDissectEnv<T>(env: DissectEnv, fn: () => T): T {
  const previous = current;
  current = env;
  try {
    return fn();
  } finally {
    current = previous;
  }
}

/** For an assertion script, which needs to see the counter return to zero. */
export function liveHttp1BodyBytes(): number {
  return liveBodyBytes;
}
