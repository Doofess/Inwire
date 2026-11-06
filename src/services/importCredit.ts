/**
 * The page's credit to an import Worker for `rows` messages (the page's end is
 * `importClient.ts`, the Worker's `workers/importRole.ts`).
 *
 * Each `rows` message is a decoded batch of a few hundred rows that the page
 * must decode in a task of its own. A Worker that dissects faster than the page
 * decodes would pile them in the page's message queue, so the Worker keeps at
 * most `IMPORT_ROWS_IN_FLIGHT` of them unanswered, and the page answers each
 * (`rowsTaken`) after it has decoded it, as `secretsTaken` answers a `secrets`.
 *
 * The messages after a held `rows` wait behind it, in order, whatever they are:
 * `done` carries the tail's last word and must not overtake a row. Progress
 * reports that pile up behind a held batch are only the newest one's worth, so
 * a new one replaces every one held, wherever it sits, and waits at the back.
 *
 * The walk waits too (`clear`, the run's `pace`), from the moment the credit is
 * spent: held messages are memory in the renderer process as surely as the
 * page's queue was (#19), so a page that is slow to decode slows the file's
 * reading rather than piling its rows here.
 *
 * Nothing here can hang a run. The credit only ever holds messages for a page
 * that is alive to answer them; Cancel and a lost store end the run on the page
 * (`importClient.ts`), which terminates the Worker, held messages and all.
 */

/** Unacknowledged `rows` batches the Worker may have posted at once. */
export const IMPORT_ROWS_IN_FLIGHT = 8;

/** The page's answer to one `rows` message, sent once its batch is decoded. */
export interface RowsTaken { type: 'rowsTaken' }

export interface RowsCredit<M extends { type: string }> {
  send(message: M, transfer?: Transferable[]): void;
  /** One `rowsTaken` arrived: one batch fewer in flight, and what waited on it goes out. */
  taken(): void;
  /**
   * Nothing held and room for another `rows`: undefined. Otherwise a promise
   * settled once every held message has gone out and a batch more may.
   */
  clear(): Promise<void> | undefined;
}

export function createRowsCredit<M extends { type: string }>(
  post: (message: M, transfer?: Transferable[]) => void,
  limit: number = IMPORT_ROWS_IN_FLIGHT,
): RowsCredit<M> {
  let inFlight = 0;
  const held: { message: M; transfer: Transferable[] | undefined }[] = [];
  let cleared: (() => void)[] = [];

  const release = (): void => {
    while (held.length > 0) {
      const next = held[0];
      if (next.message.type === 'rows') {
        if (inFlight >= limit) return;
        inFlight++;
      }
      held.shift();
      post(next.message, next.transfer);
    }
    if (inFlight >= limit) return;
    const waiting = cleared;
    cleared = [];
    for (const resolve of waiting) resolve();
  };

  return {
    send(message, transfer) {
      if (held.length > 0) {
        // Only the newest report is worth anything: earlier held ones go, wherever
        // they sit, and this one waits behind every row sent before it.
        if (message.type === 'progress') {
          for (let i = held.length - 1; i >= 0; i--) if (held[i].message.type === 'progress') held.splice(i, 1);
        }
        held.push({ message, transfer });
        return;
      }
      if (message.type === 'rows') {
        if (inFlight >= limit) {
          held.push({ message, transfer });
          return;
        }
        inFlight++;
      }
      post(message, transfer);
    },
    taken() {
      if (inFlight > 0) inFlight--;
      release();
    },
    clear() {
      // Waits with the credit spent too, not only with messages held: otherwise
      // the walk builds one batch more than the credit only to hold it.
      if (held.length === 0 && inFlight < limit) return undefined;
      return new Promise<void>((resolve) => { cleared.push(resolve); });
    },
  };
}
