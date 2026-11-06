import type { ImportFailure } from './exportSchema';
import type { ImportOutcome, ImportSuccess } from './tabularImport';

/**
 * The order one file import runs its phases in, and what Cancel does in each.
 *
 * `ImportPanel.handleFile` is React and a script cannot mount it, so the ordering
 * is here with every effect injected, as `importLifecycle.ts` does for the store.
 *
 *   begin      the live capture is sealed (awaited). A Cancel pressed meanwhile has
 *              no run to stop: it is seen when `begin` resolves, before the file is
 *              touched. No store is open, so `failed` discards nothing and offers
 *              the previous capture.
 *   read       the Worker run, or an in-process format. A Worker run stops itself
 *              (`cancel` was registered with the job) and answers `cancelled`; an
 *              in-process one has no handle, so the request is seen when it returns
 *              and its rows are dropped. Those are small.
 *   lock       past this the import is sealed and the previous capture pruned,
 *              so there is nothing to give back: Cancel is no longer offered.
 *   adopt      the rows go to the list; awaited, so the job stays running until
 *              the last slice is in.
 *
 * `failed` is the lifecycle's `fail()`: it discards what the import wrote and
 * offers the previous capture. It runs BEFORE the flow returns, so the job (ended
 * by the caller) stays running across it. Never throws: every exit is a value.
 */
export interface ImportFlowDeps {
  /** Stops a live capture and empties the view; absent when the caller has no lifecycle. */
  begin?: () => Promise<void>;
  /** Undoes what `begin` did and the import wrote. Called at most once per exit. */
  failed?: () => void;
  cancelRequested(): boolean;
  /** Cancel is over: the import is about to be adopted. */
  lockCancel(): void;
  read(): Promise<ImportOutcome>;
  adopt(outcome: ImportSuccess): Promise<void>;
}

export type ImportFlowResult =
  | { status: 'done'; outcome: ImportSuccess }
  /** The user stopped it. Not an error: nothing to show but a quiet line. */
  | { status: 'cancelled' }
  | { status: 'failed'; failure: ImportFailure };

export async function runImportFlow(deps: ImportFlowDeps): Promise<ImportFlowResult> {
  // Whether `begin` resolved: only then is there anything to undo.
  let begun = false;
  const cancelled = (): ImportFlowResult => {
    deps.failed?.();
    return { status: 'cancelled' };
  };
  try {
    await deps.begin?.();
    begun = true;
    if (deps.cancelRequested()) return cancelled();

    const outcome = await deps.read();
    if (outcome.ok === false) {
      // A request wins over the failure it raced: the user stopped it.
      if (outcome.failure.kind === 'cancelled' || deps.cancelRequested()) return cancelled();
      deps.failed?.();
      return { status: 'failed', failure: outcome.failure };
    }
    if (deps.cancelRequested()) return cancelled();

    // Checked and locked in one task: no press can land between the two.
    deps.lockCancel();
    await deps.adopt(outcome);
    return { status: 'done', outcome };
  } catch (err) {
    if (begun) deps.failed?.();
    return {
      status: 'failed',
      failure: {
        kind: 'unreadable',
        message: err instanceof Error ? err.message : 'This file could not be imported.',
      },
    };
  }
}
