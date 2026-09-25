/**
 * The export in progress, kept outside React.
 *
 * `TransferPanel` is unmounted whenever the side bar shows a different panel,
 * and a whole-capture export takes long enough for somebody to go and look at
 * Interfaces while it runs. Held in the panel's own state, the progress bar,
 * the Cancel button and the "Saved to" line would all go with it - and the
 * export would carry on writing with nothing on screen able to stop it. So the
 * job lives here, at module scope, and the panel is only a view of it: mount it
 * again and it shows whatever is current.
 *
 * One job at a time. A second press while one is running is refused rather
 * than queued: two exports would share the store's read path and each run at
 * half speed, and a queue is a thing somebody has to be told about.
 *
 * Deliberately tiny, the shape of `services/packetCounts.ts`: a value, a set of
 * listeners, and `useSyncExternalStore` on the other side
 * (`lib/useExportJob.ts`). Every published state is a NEW object, because that
 * hook compares snapshots by identity.
 */

export type ExportFormat = 'pcap' | 'pcapng' | 'csv' | 'json' | 'xlsx' | 'pdf';

/**
 * Where a running export has got to.
 *
 * `choosing` is the save dialog: nothing has been read yet, and a cancel there
 * is the person's decision rather than a failure. `surveying` is the pass that
 * counts the frames and collects the columns before the first byte can be
 * written; `writing` streams them; `finishing` is the writer's trailer and the
 * file being committed.
 */
export type ExportPhase = 'choosing' | 'surveying' | 'writing' | 'finishing';

export interface ExportProgress {
  phase: ExportPhase;
  /** Frames accounted for in this phase. */
  done: number;
  /** Frames the phase covers; 0 while not yet known. */
  total: number;
}

/** How an export ended. */
export type ExportResult =
  | {
    outcome: 'saved';
    path: string;
    frames: number;
    unreadable: number;
    /**
     * Frames written without their bytes - the store could not supply them.
     * Written rather than refused (a capture record of zero length is legal,
     * and the rest of the file is still worth having), and said loudly.
     */
    withoutBytes: number;
  }
  /** The save dialog was dismissed, or the export was cancelled. Nothing was written. */
  | { outcome: 'canceled' }
  | { outcome: 'failed'; error: string };

export type ExportJobState =
  | { status: 'idle' }
  | ({ status: 'running'; format: ExportFormat } & ExportProgress)
  | {
    status: 'saved'; format: ExportFormat; path: string; frames: number; unreadable: number; withoutBytes: number;
  }
  /**
   * `reason` is set when the app cancelled it rather than the person - a new
   * capture or an import replaced the frames it was reading - so the panel
   * can say why a file they asked for does not exist.
   */
  | { status: 'canceled'; format: ExportFormat; reason: string | null }
  | { status: 'failed'; format: ExportFormat; error: string };

/** What the code running an export holds. */
export interface ExportJobHandle {
  signal: AbortSignal;
  progress(progress: ExportProgress): void;
  settle(result: ExportResult): void;
}

const IDLE: ExportJobState = { status: 'idle' };

/**
 * How often a running job republishes. Progress arrives once a page - every
 * 4,096 frames, dozens of times a second on a fast disk - and each publish
 * re-renders the panel; a bar needs a tenth of that.
 */
const PROGRESS_MS = 100;

let state: ExportJobState = IDLE;
let controller: AbortController | null = null;
let cancelReason: string | null = null;
/** Resolves when the running job settles. */
let settledPromise: Promise<void> | null = null;
const listeners = new Set<() => void>();

function publish(next: ExportJobState): void {
  state = next;
  for (const listener of listeners) listener();
}

export function getExportJob(): ExportJobState {
  return state;
}

export function subscribeExportJob(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/**
 * Starts a job, or answers null when one is already running.
 *
 * The handle's calls are ignored once it has settled, so a late progress
 * report from a job that was cancelled cannot resurrect its bar.
 */
export function beginExportJob(format: ExportFormat): ExportJobHandle | null {
  if (state.status === 'running') return null;
  const own = new AbortController();
  controller = own;
  cancelReason = null;
  let settled = false;
  let markSettled: () => void = () => {};
  settledPromise = new Promise<void>((resolve) => { markSettled = resolve; });
  let lastAt = 0;
  let lastShare = -1;
  publish({ status: 'running', format, phase: 'choosing', done: 0, total: 0 });
  return {
    signal: own.signal,
    progress(progress) {
      if (settled) return;
      // Throttled, except where it changes what the bar says: a new phase,
      // the end of one, or a whole percent.
      const current = state.status === 'running' ? state : null;
      const now = Date.now();
      const share = progress.total > 0 ? Math.floor((progress.done / progress.total) * 100) : -1;
      const due = current === null || current.phase !== progress.phase
        || progress.done === progress.total || now - lastAt >= PROGRESS_MS || share !== lastShare;
      if (!due) return;
      lastAt = now;
      lastShare = share;
      publish({ status: 'running', format, ...progress });
    },
    settle(result) {
      if (settled) return;
      settled = true;
      if (controller === own) controller = null;
      switch (result.outcome) {
        case 'saved':
          publish({
            status: 'saved', format, path: result.path, frames: result.frames,
            unreadable: result.unreadable, withoutBytes: result.withoutBytes,
          });
          break;
        case 'canceled':
          publish({ status: 'canceled', format, reason: cancelReason });
          break;
        case 'failed':
          // A job the app cancelled can end in a read that failed first; the
          // reason is still the truth about why there is no file.
          publish(cancelReason !== null
            ? { status: 'canceled', format, reason: cancelReason }
            : { status: 'failed', format, error: result.error });
          break;
      }
      markSettled();
    },
  };
}

/**
 * Stops the running export. Its file is removed, not left half-written.
 * `reason` is for the app's own cancellations; a person's Cancel has none.
 */
export function cancelExportJob(reason: string | null = null): void {
  if (controller === null) return;
  cancelReason = reason;
  controller.abort();
}

/**
 * Cancels the running export and waits until it has let go of its file.
 *
 * For whatever is about to change the capture under it - Start, an import, a
 * discard. The capture store is the export's source, and a store re-opened on
 * a new capture mid-export would hand the rest of the file the NEW capture's
 * frames, under ids that can repeat the old one's. So the export ends first,
 * and says why.
 */
export async function cancelExportForChange(reason: string): Promise<void> {
  if (state.status !== 'running') return;
  const waiting = settledPromise;
  cancelExportJob(reason);
  await waiting;
}

/** Clears a finished job's line. A running job is not touched. */
export function dismissExportJob(): void {
  if (state.status !== 'running') publish(IDLE);
}
