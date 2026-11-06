/**
 * The import Worker's open of its capture, as the page waits for it
 * (`App.handleImportOpening` binds it).
 */

export interface ImportOpenWait {
  /** The id the lifecycle opened the store on, or null if `onBatch` opened none. */
  captureId: string | null;
  /** The store's pending answer to that open, or null when no open was started. */
  opened: Promise<void> | null;
  /** Whether the lifecycle still holds this import's store open on `captureId`. */
  owns(captureId: string): boolean;
  /** Deletes a capture the store opened. Safe to repeat: the store ignores an id it no longer has. */
  discard(captureId: string): void;
}

export async function awaitImportOpen(wait: ImportOpenWait): Promise<string> {
  const { captureId, opened } = wait;
  if (captureId === null || opened === null) throw new Error('The import could not open its capture.');
  await opened;
  // A Cancel (or any failure) that ran while the open was pending has already
  // taken the import's store from the lifecycle and discarded the id - but a
  // `ready` already on its way can still settle this open successfully, and the
  // store would then hold a capture nobody owns, open under the import's id while
  // the session still names the previous one. Discard it again (idempotent) and
  // fail the wait, so a Worker that is somehow still listening gets no `storeOpen`.
  if (!wait.owns(captureId)) {
    wait.discard(captureId);
    throw new Error('The import was stopped while its capture opened.');
  }
  return captureId;
}
