/**
 * The order a file import does its things in, and what a failed one leaves.
 *
 * An import reads its file a window at a time, so the renderer runs between
 * windows: the agent's stop notice, a late frame, a press on a row all land
 * mid-import. What keeps them from reaching the import's capture is the ORDER
 * the import sets itself up in, and that order was spread over `App.tsx`'s
 * callbacks, which a script cannot reach. It lives here instead, with every
 * effect injected, and App binds the real ones.
 *
 *   begin      stop and SEAL a live capture (awaited), keep the offer the view
 *              was holding, empty the view. No store is opened yet: a file
 *              that is not a capture must not leave a directory behind.
 *   onBatch    the first batch opens the import's store.
 *   succeed    seal the import, prune everything else. Offers nothing: the
 *              imported frames are on screen.
 *   fail       discard the import's directory if one was opened, forget its
 *              id, and give the previous capture back.
 *
 * Pure: no React, no Electron, no `node:*`.
 */

export interface ImportEffects<Offer> {
  /** A live capture is running. */
  capturing(): boolean;
  /**
   * Does what the Stop button does and resolves once the Worker has drained and
   * the store has been told to finish. Resolves at once when already sealed.
   */
  stopAndSeal(): Promise<void>;
  /** The capture the view holds, as Reopen would offer it; read AFTER the seal. */
  currentOffer(): Offer | null;
  /** Empties the view and withholds any offer for the import's duration. */
  clearView(): void;
  newCaptureId(): string;
  /** Points the store at a new capture for the import's frames. */
  openStore(captureId: string): void;
  /** Deletes the import's directory. */
  discardStore(captureId: string): void;
  /** Persists the import's last frames and makes it the session's capture. */
  sealStore(captureId: string): void;
  /** Deletes every capture directory but this one. */
  pruneOthers(captureId: string): void;
  /** Offers the previous capture again (and records it for a relaunch). */
  offer(kept: Offer): void;
}

export interface ImportLifecycle {
  /** False, with nothing done, when an import is already running. */
  begin(): Promise<boolean>;
  /** One batch of frames is about to be written. Opens the store the first time. */
  onBatch(): void;
  /** The import's capture id while its store is open. */
  storeId(): string | null;
  running(): boolean;
  /** The import finished; answers the capture id it wrote, or null if it wrote none. */
  succeed(): string | null;
  /** The import failed. A no-op when none is running. */
  fail(): void;
}

/**
 * `getEffects` is asked on every call, so a caller whose effects close over
 * render state can hand back the newest ones; the lifecycle's own state
 * (running, id, kept offer) is the only thing that persists.
 */
export function createImportLifecycle<Offer>(getEffects: () => ImportEffects<Offer>): ImportLifecycle {
  let running = false;
  let storeId: string | null = null;
  let kept: Offer | null = null;

  return {
    async begin() {
      if (running) return false;
      running = true;
      storeId = null;
      kept = null;
      try {
        // Sealed first: the agent's stop notice arrives between the file's
        // windows, and with the live capture unsealed it would seal the store
        // the import has re-opened, part-way.
        if (getEffects().capturing()) await getEffects().stopAndSeal();
        kept = getEffects().currentOffer();
        getEffects().clearView();
      } catch (err) {
        running = false;
        kept = null;
        throw err;
      }
      return true;
    },

    onBatch() {
      if (storeId !== null) return;
      const effects = getEffects();
      storeId = effects.newCaptureId();
      effects.openStore(storeId);
    },

    storeId: () => storeId,
    running: () => running,

    succeed() {
      if (!running) return null;
      const id = storeId;
      if (id !== null) {
        const effects = getEffects();
        effects.sealStore(id);
        effects.pruneOthers(id);
      }
      running = false;
      storeId = null;
      kept = null;
      return id;
    },

    fail() {
      if (!running) return;
      const effects = getEffects();
      if (storeId !== null) effects.discardStore(storeId);
      const offer = kept;
      running = false;
      storeId = null;
      kept = null;
      if (offer !== null) effects.offer(offer);
    },
  };
}
