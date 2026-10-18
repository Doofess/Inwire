/**
 * The History's "ask again every few seconds", without cancelling itself.
 *
 * The client keeps one query per view id and a new one supersedes the old, so a
 * tick that always asked again meant a query slower than the interval was
 * cancelled by every tick and never answered: the chart sat on "Reading" for
 * as long as the answer took more than five seconds. So a tick does nothing
 * while a query is pending, and the next tick after the reply asks again.
 *
 * A change the user made (the range, the source) is `restart`: it supersedes
 * whatever is pending, and the reply of the superseded query is dropped here as
 * well as by the client. `stop` drops whatever is pending for good, which is
 * what an unmount or a change that leaves nothing to ask is.
 *
 * Pure so the component's one hook body is not where this is tested.
 */
export interface QueryRefresher {
  /** The interval fired: asks, unless an earlier ask has not answered yet. */
  tick(): void;
  /** The thing being asked about changed: asks now, superseding a pending ask. */
  restart(): void;
  /** Ignores any reply still to come. */
  stop(): void;
}

export function createQueryRefresher<R>(options: {
  ask(): Promise<R>;
  /** A reply to the ask that is still the current one. */
  apply(reply: R): void;
  /** Whether an ask is pending, for the spinner. */
  busy?(busy: boolean): void;
}): QueryRefresher {
  let current = 0;
  let pending = false;

  const run = (): void => {
    const mine = ++current;
    pending = true;
    options.busy?.(true);
    const settle = (): boolean => {
      if (mine !== current) return false; // superseded or stopped: its answer is for a question nobody asks now
      pending = false;
      options.busy?.(false);
      return true;
    };
    // A client call always settles; a rejection is treated as no answer so a tick can ask again.
    void options.ask().then((reply) => { if (settle()) options.apply(reply); }, () => { settle(); });
  };

  return {
    tick: () => { if (!pending) run(); },
    restart: run,
    stop: () => { current++; pending = false; },
  };
}
