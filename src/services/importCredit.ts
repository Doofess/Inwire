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
 * they are merged rather than queued.
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
}

export function createRowsCredit<M extends { type: string }>(
  post: (message: M, transfer?: Transferable[]) => void,
  limit: number = IMPORT_ROWS_IN_FLIGHT,
): RowsCredit<M> {
  let inFlight = 0;
  const held: { message: M; transfer: Transferable[] | undefined }[] = [];

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
  };

  return {
    send(message, transfer) {
      if (held.length > 0) {
        const last = held[held.length - 1];
        if (message.type === 'progress' && last.message.type === 'progress') last.message = message;
        else held.push({ message, transfer });
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
  };
}
