import React, { useRef, useState } from 'react';
import { Check, Info, LoaderCircle, Upload } from 'lucide-react';

import { Packet } from '../../types/packet';
import { ImportFailure } from '../../services/exportSchema';
import { importAnyFile, IMPORT_ACCEPT, type WorkerImportRoute } from '../../services/tabularImport';
import { performanceStore } from '../../services/interfacePrefs';
import { usePreferenceValue } from '../../services/preferenceStore';
import { AVERAGE_FRAME_BYTES, currentBufferBudget, framesForBudget } from '../../services/bufferBudget';
import type { CaptureFileFacts } from '../../services/captureFileFacts';
import {
  beginImportJob, cancelImportJob, endImportJob, getImportJob, importCancelRequested, importJobProgress,
  lockImportCancel, setImportJobCancel, useImportJob, type ImportResult,
} from '../../services/importJob';
import { runImportFlow } from '../../services/importFlow';
import { importProgressPercent, importProgressSizes } from '../../lib/importProgress';
import { importRefusal, isCaptureStarting } from '../../services/captureStarting';

/**
 * The Import half of the Import/Export centre.
 *
 * Every format goes through `importAnyFile`, which either returns packets or
 * names a reason. This component never decides on its own whether a file is
 * valid - it only decides how to show the answer, which is an inline note for
 * a success with caveats and a dialog for a refusal.
 */

/** What an import hands the app beside its frames. */
export interface ImportedInfo {
  filename: string;
  facts?: CaptureFileFacts;
  /** From the import Worker: each frame's `estimateSummaryBytes`, for the buffer's accounting. */
  estimates?: number[];
  /** From the import Worker: the decrypted answers its walk kept, by frame id. */
  derived?: [number, Uint8Array][];
}

interface ImportPanelProps {
  /**
   * The frames to put in the buffer: everything for a small file, the newest
   * `maxFrames` when the import streamed to disk.
   */
  onImportPackets: (packets: Packet[], info: ImportedInfo) => void | Promise<void>;
  /**
   * How a capture file is imported: in a Worker, which writes every frame to the
   * store and hands back the newest ones for the buffer (`importClient.ts`).
   *
   * With it, a capture file is imported whole and the buffer size stops being
   * a ceiling on what the file may contribute. Without it - which is what a
   * test or a caller with no store gets - the old cap applies and the note
   * below says so.
   */
  onImportWorker?: WorkerImportRoute;
  /**
   * Called before the file is read, and awaited: a live capture is stopped and
   * sealed and the view emptied here, so nothing the renderer does between the
   * file's windows can reach the capture the import is writing
   * (`importLifecycle.ts`). Rejects when that cannot be done.
   */
  onImportBegin?: () => Promise<void>;
  /**
   * The import failed after `onImportBegin` resolved: discard what it wrote
   * and give the previous capture back. Called before `onFailure`.
   */
  onImportFailed?: () => void;
  onFailure: (filename: string, failure: ImportFailure) => void;
  /** Set when the error dialog's "Choose another file" reopens the picker. */
  retryToken: number;
  /**
   * Why an import cannot start right now, or null. An import re-opens the
   * capture store on a new capture, which is the one thing a running export
   * cannot survive - so while one runs, the picker and the drop zone are shut
   * and say so.
   */
  blockedBy?: string | null;
}

export const ImportPanel: React.FC<ImportPanelProps> = ({
  onImportPackets,
  onImportWorker,
  onImportBegin,
  onImportFailed,
  onFailure,
  retryToken,
  blockedBy = null,
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  // Whether an import is running is `importJob.ts`'s, not this panel's: the side
  // bar can be closed and reopened mid-import, and a remounted panel must still
  // refuse a second one and still show where the first has got to. So is the
  // last result, for the same reason: it can arrive while the panel is closed.
  const job = useImportJob();
  const busy = job.status === 'running';
  const percent = job.status === 'running' ? importProgressPercent(job.readBytes, job.totalBytes) : 0;
  const status = job.status === 'idle' ? job.result?.message ?? null : null;
  const cancelled = job.status === 'idle' && job.result?.cancelled === true;
  const notes = job.status === 'idle' ? job.result?.notes ?? [] : [];
  const [dragging, setDragging] = useState(false);
  // The import may not outgrow the buffer the app is set to hold.
  const [perf] = usePreferenceValue(performanceStore);

  // Reopened by the error dialog. A ref-driven click rather than lifting the
  // whole picker into the parent, so the dialog stays a presentation concern.
  React.useEffect(() => {
    if (retryToken > 0 && blockedBy === null) inputRef.current?.click();
  }, [retryToken]);

  const handleFile = async (file: File | undefined) => {
    // Read from the stores, not from the render's copy: this closure can be old,
    // and a Start that has not opened its capture yet is exactly the gap that
    // left it so (`captureStarting.ts`). `blockedBy` is the panel's, a render old.
    if (!file || importRefusal({
      importRunning: getImportJob().status === 'running',
      captureStarting: isCaptureStarting(),
      blockedBy,
    }) !== null) return;

    beginImportJob(file.name, file.size);
    let result: ImportResult | undefined;

    try {
      // The order of the phases, and what Cancel does in each, is `importFlow.ts`'s.
      const flow = await runImportFlow({
        begin: onImportBegin,
        failed: onImportFailed,
        cancelRequested: importCancelRequested,
        lockCancel: lockImportCancel,
        // With a sink the file is imported whole and the rest is on disk, so the
        // budget's BYTES bound what stays resident (`residentBytes`, measured per
        // row); the frame count is only a ceiling beside it. Without a sink
        // (other formats) the count, from the measured average, is still a cap on
        // the import, and `importAnyFile` says so in a note.
        read: () => {
          const budget = currentBufferBudget(perf.packetBufferBytes);
          return importAnyFile(file, {
            maxFrames: framesForBudget(budget, AVERAGE_FRAME_BYTES),
            residentBytes: budget,
            worker: onImportWorker,
            onProgress: importJobProgress,
            onCancelHandle: setImportJobCancel,
          });
        },
        // The name travels with the frames: it is the capture's source in
        // everything exported from them.
        // Awaited: App hands the rows to the list a slice a task, and the job stays
        // running (every capture-changing action refused) until the last is in.
        adopt: async (outcome) => {
          await onImportPackets(outcome.packets, {
            filename: file.name, facts: outcome.facts, estimates: outcome.estimates, derived: outcome.derived,
          });
        },
      });
      if (flow.status === 'failed') {
        onFailure(file.name, flow.failure);
      } else if (flow.status === 'cancelled') {
        // Pressed by the user: no dialog, and no success line either.
        result = { message: 'Import cancelled', notes: [], cancelled: true };
      } else {
        result = {
          message: `Imported ${flow.outcome.packets.length.toLocaleString()} packets from ${file.name}`,
          notes: flow.outcome.notes,
        };
      }
    } finally {
      endImportJob(result);
    }
  };

  const onInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    // Cleared before awaiting the import, not after. The input keeps its value
    // otherwise, and picking the SAME file again fires no change event at all -
    // so a user who fixes their spreadsheet and re-selects it sees nothing
    // happen, which reads as the app having hung.
    e.target.value = '';
    await handleFile(file);
  };

  return (
    <div className="space-y-4 text-xs">
      <div>
        <div className="font-bold text-foreground/80 text-sm mb-2">Import a capture</div>

        <label
          onDragOver={e => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={e => {
            // The label has invited a drop since long before anything listened
            // for one. It does now.
            e.preventDefault();
            setDragging(false);
            void handleFile(e.dataTransfer.files?.[0]);
          }}
          aria-disabled={blockedBy !== null}
          className={`block border-2 border-dashed rounded-lg px-3 py-6 transition-colors ${
            busy ? 'cursor-wait' : blockedBy !== null ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'
          } ${dragging ? 'border-primary bg-primary/10' : busy ? 'border-border bg-muted/30' : 'border-border hover:border-sky-500 bg-muted/30'}`}
        >
          {/* Both bodies share one grid cell and the one not showing is
              `invisible`, so the zone is as tall as the taller of the two at
              every width: the idle text wraps in a narrow side bar and the busy
              rows do not, and the cards below must not jump when an import
              starts or ends. `invisible` also keeps the hidden body out of the
              accessibility tree and out of `innerText`. */}
          <div className="grid w-full grid-cols-[minmax(0,1fr)]">
            <div className={`col-start-1 row-start-1 flex flex-col items-center justify-center ${busy ? 'invisible' : ''}`}>
              <Upload className="w-8 h-8 text-foreground mb-2" />
              <span className="font-semibold text-foreground text-center">
                {dragging ? 'Drop to import' : 'Click to upload, or drag & drop'}
              </span>
              <span className="text-[11px] text-muted-foreground mt-1 text-center">
                .pcap .pcapng .cap · .csv .tsv · .xlsx · .json · .zip
              </span>
              {blockedBy !== null && (
                <span className="text-[11px] text-warning mt-1 text-center">{blockedBy}</span>
              )}
            </div>
            {/* The progress is the zone's: nothing here invites a second file. */}
            <div className={`col-start-1 row-start-1 flex flex-col items-center justify-center ${busy ? '' : 'invisible'}`}>
              <LoaderCircle className="w-8 h-8 text-foreground mb-2 animate-spin" />
              <span className="flex max-w-full gap-1 font-semibold text-foreground" title={job.status === 'running' ? job.fileName : undefined}>
                <span className="shrink-0">Importing</span>
                <span className="min-w-0 truncate">{job.status === 'running' ? job.fileName : ' '}</span>
              </span>
              <div
                role={busy ? 'progressbar' : undefined}
                aria-label={job.status === 'running' ? `Importing ${job.fileName}` : undefined}
                aria-valuemin={busy ? 0 : undefined}
                aria-valuemax={busy ? 100 : undefined}
                aria-valuenow={busy ? percent : undefined}
                className="mt-2.5 h-1 w-full overflow-hidden rounded-full bg-muted"
              >
                <div
                  className="h-full rounded-full bg-primary transition-[width] duration-300"
                  style={{ width: `${percent}%` }}
                />
              </div>
              <span className="mt-1.5 text-[11px] text-muted-foreground text-center tabular-nums">
                {job.status === 'running' ? importProgressSizes(job.readBytes, job.totalBytes) : ' '}
              </span>
            </div>
          </div>
          <input
            ref={inputRef}
            type="file"
            accept={IMPORT_ACCEPT}
            onChange={onInputChange}
            disabled={busy || blockedBy !== null}
            className="hidden"
          />
        </label>

        {/* Outside the label: a button inside it would open the file picker. The
            row is kept for as long as the import runs, with or without the
            button, so the cards below move once when an import starts and once
            when it ends, and not when Cancel stops being offered. */}
        {busy && (
          <div className="mt-2 flex h-7 items-center justify-center">
            {job.status === 'running' && job.cancellable && (
              <button
                type="button"
                aria-label={job.cancelRequested ? 'Cancelling import…' : 'Cancel import'}
                onClick={() => cancelImportJob()}
                disabled={job.cancelRequested}
                className="rounded border border-border px-2 py-1 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground
                  focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring
                  disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {job.cancelRequested ? 'Cancelling…' : 'Cancel'}
              </button>
            )}
          </div>
        )}
      </div>

      {/* The outcome sits directly under the zone it came from, above the help
          card: while an import runs the zone shows the progress, and the line
          that replaces it should not land below paragraphs of explanation.
          A cancelled import is the user's own act, so its line is quiet. */}
      {status && cancelled && (
        <div className="text-muted-foreground flex items-start gap-1.5">
          <span>{status}</span>
        </div>
      )}
      {status && !cancelled && (
        <div className="text-success-muted flex items-start gap-1.5 font-medium">
          <Check className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{status}</span>
        </div>
      )}

      {/* What was lost. Stated at import time rather than left for the user to
          discover by clicking a packet and finding an empty hex pane. */}
      {notes.length > 0 && (
        <ul className="space-y-1.5">
          {notes.map((note, i) => (
            <li key={i} className="flex items-start gap-1.5 text-amber-600 dark:text-amber-400">
              <Info className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="leading-relaxed">{note}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="rounded-lg border border-border bg-muted/30 p-3 text-[11px] text-muted-foreground leading-relaxed space-y-1.5">
        <p>
          Spreadsheets and tables are checked before anything is imported: a file whose columns are not
          packet data is refused rather than turned into frames that were never captured.
        </p>
        <p>
          A row carries no wire bytes unless it was exported with{' '}
          <span className="font-semibold text-foreground/80">Include raw packet bytes</span>. Without
          them a re-imported packet has no hex dump and no protocol tree.
        </p>
      </div>
    </div>
  );
};
