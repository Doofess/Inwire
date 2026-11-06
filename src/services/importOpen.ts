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
  // taken the import's store from the lifecycle and discarded the id. With the
  // real client this line is not reached then: the discard settles the pending
  // open with nothing (`CaptureClient.settleAll`), so `opened` rejects, and the
  // late `ready` is ignored. What keeps the store from holding a capture nobody
  // owns is the host's order - the `open` and then the `discard` on one port,
  // taken in turn (`serialQueue.ts`), so the discard closes what the open made.
  // This is the fallback for a client that settles an abandoned open as opened:
  // discard again (idempotent) and fail the wait, so no Worker gets `storeOpen`.
  if (!wait.owns(captureId)) {
    wait.discard(captureId);
    throw new Error('The import was stopped while its capture opened.');
  }
  return captureId;
}
