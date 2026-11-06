/**
 * The pipeline script's fourth role: one capture-file import, off the main
 * thread (`docs/superpowers/specs/2026-11-05-import-worker-design.md`).
 *
 * Spawned by the page, one per import, as the same script under its own name,
 * so it has the same origin, COEP and CSP and no bundle of its own. The
 * capture store's ingest port arrives with `start`; the rest is
 * `services/pipeline/importRun.ts`, which this only connects to `postMessage`.
 */
/// <reference lib="webworker" />
import { createImportRun } from '../services/pipeline/importRun';
import { IMPORT_NAME, type FromImport, type ToImport } from '../services/pipeline/importProtocol';
import { createRowsCredit, type RowsTaken } from '../services/importCredit';

// Defined in the protocol so the page can name the Worker without importing the
// role (and with it the whole walk) into its own chunk.
export { IMPORT_NAME };

export function isImportRole(scope: { name?: string }): boolean {
  return scope.name === IMPORT_NAME;
}

/**
 * What the role hears: the run's own messages, and the page's credit for `rows`
 * (`rowsTaken`), which only this layer knows about.
 */
export type ToImportRole = ToImport | RowsTaken;

/**
 * The role's whole behaviour, given only where its messages go (`scripts/capture/
 * import-client.ts` runs it in-process). The run posts through the rows credit:
 * at most `IMPORT_ROWS_IN_FLIGHT` `rows` batches are on their way to the page
 * unanswered, and everything after the first held one waits behind it, in order -
 * `done` and `progress` too, or `done` would overtake rows still held - and the
 * walk waits while any are held, so the held are never more than a batch or two.
 */
export function createImportRole(
  post: (message: FromImport, transfer?: Transferable[]) => void,
): (message: ToImportRole, ports: readonly MessagePort[]) => void {
  const credit = createRowsCredit<FromImport>(post);
  const handle = createImportRun({ post: credit.send, pace: credit.clear });
  return (message, ports) => {
    if (message.type === 'rowsTaken') credit.taken();
    else handle(message, ports);
  };
}

export function runImport(ctx: DedicatedWorkerGlobalScope): void {
  const handle = createImportRole((message, transfer) => ctx.postMessage(message, transfer ?? []));
  ctx.onmessage = (event: MessageEvent<ToImportRole>) => handle(event.data, event.ports);
}
