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
