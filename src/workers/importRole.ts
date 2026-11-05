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
import type { ToImport } from '../services/pipeline/importProtocol';

/** The name the page gives an import Worker. Not a shard's or the reader's. */
export const IMPORT_NAME = 'inwire-import';

export function isImportRole(scope: { name?: string }): boolean {
  return scope.name === IMPORT_NAME;
}

export function runImport(ctx: DedicatedWorkerGlobalScope): void {
  const handle = createImportRun({
    post: (message, transfer) => ctx.postMessage(message, transfer ?? []),
  });
  ctx.onmessage = (event: MessageEvent<ToImport>) => handle(event.data, event.ports);
}
