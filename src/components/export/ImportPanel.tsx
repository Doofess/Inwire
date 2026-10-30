import React, { useRef, useState } from 'react';
import { Check, Info, LoaderCircle, Upload } from 'lucide-react';

import { Packet } from '../../types/packet';
import { ImportFailure } from '../../services/exportSchema';
import { importAnyFile, IMPORT_ACCEPT, type ImportBatchSink } from '../../services/tabularImport';
import { performanceStore } from '../../services/interfacePrefs';
import { usePreferenceValue } from '../../services/preferenceStore';
import { AVERAGE_FRAME_BYTES, currentBufferBudget, framesForBudget } from '../../services/bufferBudget';
import type { CaptureFileFacts } from '../../services/captureFileFacts';
import {
  beginImportJob, endImportJob, getImportJob, importJobProgress, useImportJob,
} from '../../services/importJob';
import { importProgressText } from '../../lib/importProgress';

/**
 * The Import half of the Import/Export centre.
 *
 * Every format goes through `importAnyFile`, which either returns packets or
 * names a reason. This component never decides on its own whether a file is
 * valid - it only decides how to show the answer, which is an inline note for
 * a success with caveats and a dialog for a refusal.
 */

interface ImportPanelProps {
  /**
   * The frames to put in the buffer: everything for a small file, the newest
   * `maxFrames` when the import streamed to disk.
   */
  onImportPackets: (packets: Packet[], info: { filename: string; facts?: CaptureFileFacts }) => void;
  /**
   * Where every frame goes as it is dissected, if anywhere.
   *
   * With it, a capture file is imported whole and the buffer size stops being
   * a ceiling on what the file may contribute. Without it - which is what a
   * test or a caller with no store gets - the old cap applies and the note
   * below says so.
   */
  onImportBatch?: ImportBatchSink;
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
  onImportBatch,
  onFailure,
  retryToken,
  blockedBy = null,
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  // Whether an import is running is `importJob.ts`'s, not this panel's: the side
  // bar can be closed and reopened mid-import, and a remounted panel must still
  // refuse a second one and still show where the first has got to.
  const job = useImportJob();
  const busy = job.status === 'running';
  const [dragging, setDragging] = useState(false);
  // The import may not outgrow the buffer the app is set to hold.
  const [perf] = usePreferenceValue(performanceStore);

  // Reopened by the error dialog. A ref-driven click rather than lifting the
  // whole picker into the parent, so the dialog stays a presentation concern.
  React.useEffect(() => {
    if (retryToken > 0 && blockedBy === null) inputRef.current?.click();
  }, [retryToken]);

  const handleFile = async (file: File | undefined) => {
    // Read from the store, not from the render's copy: this closure can be old.
    if (!file || getImportJob().status === 'running' || blockedBy !== null) return;

    beginImportJob(file.name, file.size);
    setStatus(null);
    setNotes([]);

    try {
      // With a sink the file is imported whole and the rest is on disk, so the
      // budget's BYTES bound what stays resident (`residentBytes`, measured per
      // row); the frame count is only a ceiling beside it. Without a sink
      // (other formats) the count, from the measured average, is still a cap on
      // the import, and `importAnyFile` says so in a note.
      const budget = currentBufferBudget(perf.packetBufferBytes);
      const outcome = await importAnyFile(file, {
        maxFrames: framesForBudget(budget, AVERAGE_FRAME_BYTES),
        residentBytes: budget,
        onBatch: onImportBatch,
        onProgress: importJobProgress,
      });
      if (outcome.ok === false) {
        setStatus(null);
        onFailure(file.name, outcome.failure);
        return;
      }
      // The name travels with the frames: it is the capture's source in
      // everything exported from them.
      onImportPackets(outcome.packets, { filename: file.name, facts: outcome.facts });
      setStatus(`Imported ${outcome.packets.length.toLocaleString()} packets from ${file.name}`);
      setNotes(outcome.notes);
    } catch (err) {
      setStatus(null);
      onFailure(file.name, {
        kind: 'unreadable',
        message: err instanceof Error ? err.message : 'This file could not be imported.',
      });
    } finally {
      endImportJob();
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
          className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center transition-colors ${
            busy ? 'cursor-wait opacity-70' : blockedBy !== null ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'
          } ${dragging ? 'border-primary bg-primary/10' : 'border-border hover:border-sky-500 bg-muted/30'}`}
        >
          {busy ? (
            <LoaderCircle className="w-8 h-8 text-foreground mb-2 animate-spin" />
          ) : (
            <Upload className="w-8 h-8 text-foreground mb-2" />
          )}
          <span className="font-semibold text-foreground">
            {dragging ? 'Drop to import' : 'Click to upload, or drag & drop'}
          </span>
          <span className="text-[11px] text-muted-foreground mt-1 text-center">
            .pcap .pcapng .cap · .csv .tsv · .xlsx · .json · .zip
          </span>
          {blockedBy !== null && (
            <span className="text-[11px] text-warning mt-1 text-center">{blockedBy}</span>
          )}
          <input
            ref={inputRef}
            type="file"
            accept={IMPORT_ACCEPT}
            onChange={onInputChange}
            disabled={busy || blockedBy !== null}
            className="hidden"
          />
        </label>
      </div>

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

      {job.status === 'running' ? (
        <div className="text-muted-foreground font-medium" role="status">
          {importProgressText(job.fileName, job.readBytes, job.totalBytes)}
        </div>
      ) : status && (
        <div className="text-emerald-500 flex items-start gap-1.5 font-medium">
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
    </div>
  );
};
