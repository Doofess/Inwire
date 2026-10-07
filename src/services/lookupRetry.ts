/**
 * When the public-identity lookup tries again by itself, and when it stops.
 *
 * It used to ask once: a lookup made while the machine was between networks,
 * or while a VPN was coming up, failed and stayed failed until the panel was
 * closed and opened again. Now a failure that another attempt could fix is
 * retried - when the connection comes back if the machine is offline, and
 * otherwise after a delay that grows - and one that another attempt cannot fix
 * is not retried at all.
 *
 * **Bounded, because consent is about how many as well as whether** (the root
 * CLAUDE.md's Direction section, on reverse DNS): every attempt is a request to
 * ipapi.co that shows in the user's own capture, so a lookup that cannot
 * succeed must not keep knocking. Three retries over about two and a half
 * minutes, then it waits for the panel to be opened again.
 */

/** Why an attempt failed, as far as the caller can tell. */
export type LookupFailure =
  /** The machine says it has no connection (`navigator.onLine` is false). */
  | 'offline'
  /** The request never got an answer: no route, DNS, a reset, a timeout. */
  | 'network'
  /** The service answered with a 5xx: its problem, and usually brief. */
  | 'server'
  /**
   * The service answered and said no - a 4xx, a rate limit, or `error` in the
   * body. Asking again sooner is exactly what a rate limit asks you not to do.
   */
  | 'refused';

/** The delay before each retry, in order. Its length is the retry budget. */
export const RETRY_DELAYS_MS: readonly number[] = [5_000, 30_000, 120_000];

export type RetryStep =
  | { kind: 'after'; ms: number }
  /** Wait for the `online` event, however long that takes; it costs nothing. */
  | { kind: 'when-online' }
  | { kind: 'stop' };

/**
 * What to do after the `retriesSoFar`-th retry failed with `failure`; 0 is the
 * first attempt. Waiting for the connection does not spend the budget, since
 * it sends nothing: what is counted is requests.
 */
export function nextRetry(failure: LookupFailure, retriesSoFar: number): RetryStep {
  if (failure === 'refused') return { kind: 'stop' };
  if (failure === 'offline') return { kind: 'when-online' };
  const ms = RETRY_DELAYS_MS[retriesSoFar];
  return ms === undefined ? { kind: 'stop' } : { kind: 'after', ms };
}

/** Sorts an HTTP status into a failure, or null for a success. */
export function failureForStatus(status: number): LookupFailure | null {
  if (status >= 200 && status < 300) return null;
  return status >= 500 ? 'server' : 'refused';
}
