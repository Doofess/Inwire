/**
 * What `will-quit` does about monitoring (ADRs 0058, 0059), as a decision with
 * no import at all so a script can run it under plain `tsx`.
 *
 * The order of the questions is the rule. `drained` first: the drain is over
 * and the second pass through `will-quit` must let the app go. `draining`
 * before `running`: the utility says `stopped` part-way through a drain, and
 * `running` going false must not let a second quit through before the drain has
 * resolved - it would kill the process mid-flush.
 */
export interface QuitState {
  /** A listener is starting or listening. */
  running: boolean;
  /** A drain has been started and has not settled. */
  draining: boolean;
  /** A drain has settled; quit may go ahead. */
  drained: boolean;
}

/** `quit` lets the app go (releasing the host), `drain` starts the one drain, `wait` holds the quit for the drain in flight. */
export function planQuitDrain(state: QuitState): 'quit' | 'drain' | 'wait' {
  if (state.drained) return 'quit';
  if (state.draining) return 'wait';
  if (state.running) return 'drain';
  return 'quit';
}

/**
 * Runs the one drain and ALWAYS calls `settled` afterwards - a result, a
 * rejection or a synchronous throw alike. `settled` is what marks the drain
 * done and quits again, so a drain that failed to answer must not leave the
 * quit held for ever behind `wait`: a windowless process holding the
 * single-instance lock. A failure is reported, never rethrown.
 */
export function runQuitDrain<R>(
  drain: () => Promise<R>,
  report: (result: R) => void,
  fail: (error: unknown) => void,
  settled: () => void,
): Promise<void> {
  return Promise.resolve()
    .then(drain)
    .then(report)
    .catch(fail)
    .finally(settled);
}
