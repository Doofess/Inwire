import React, { useRef, useState } from 'react';
import { TbCheck, TbInfoCircle, TbLoader2, TbUpload } from 'react-icons/tb';

import { Packet } from '../../types/packet';
import { ImportFailure } from '../../services/exportSchema';
import { importAnyFile, IMPORT_ACCEPT } from '../../services/tabularImport';
import { performanceStore } from '../../services/interfacePrefs';
import { usePreferenceValue } from '../../services/preferenceStore';

/**
 * The Import half of the Import/Export centre.
 *
 * Every format goes through `importAnyFile`, which either returns packets or
 * names a reason. This component never decides on its own whether a file is
 * valid - it only decides how to show the answer, which is an inline note for
 * a success with caveats and a dialog for a refusal.
 */

interface ImportPanelProps {
  onImportPackets: (packets: Packet[]) => void;
  onFailure: (filename: string, failure: ImportFailure) => void;
  /** Set when the error dialog's "Choose another file" reopens the picker. */
  retryToken: number;
}

export const ImportPanel: React.FC<ImportPanelProps> = ({
  onImportPackets,
  onFailure,
  retryToken,
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  // The import may not outgrow the buffer the app is set to hold.
  const [perf] = usePreferenceValue(performanceStore);

  // Reopened by the error dialog. A ref-driven click rather than lifting the
  // whole picker into the parent, so the dialog stays a presentation concern.
  React.useEffect(() => {
    if (retryToken > 0) inputRef.current?.click();
  }, [retryToken]);

  const handleFile = async (file: File | undefined) => {
    if (!file || busy) return;

    setBusy(true);
    setStatus(`Reading ${file.name}...`);
    setNotes([]);

    try {
      const outcome = await importAnyFile(file, { maxFrames: perf.packetBufferCap });
      if (outcome.ok === false) {
        setStatus(null);
        onFailure(file.name, outcome.failure);
        return;
      }
      onImportPackets(outcome.packets);
      setStatus(`Imported ${outcome.packets.length.toLocaleString()} packets from ${file.name}`);
      setNotes(outcome.notes);
    } catch (err) {
      setStatus(null);
      onFailure(file.name, {
        kind: 'unreadable',
        message: err instanceof Error ? err.message : 'This file could not be imported.',
      });
    } finally {
      setBusy(false);
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
          className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center transition-colors ${
            busy ? 'cursor-wait opacity-70' : 'cursor-pointer'
          } ${dragging ? 'border-primary bg-primary/10' : 'border-border hover:border-sky-500 bg-muted/30'}`}
        >
          {busy ? (
            <TbLoader2 className="w-8 h-8 text-foreground mb-2 animate-spin" />
          ) : (
            <TbUpload className="w-8 h-8 text-foreground mb-2" />
          )}
          <span className="font-semibold text-foreground">
            {dragging ? 'Drop to import' : 'Click to upload, or drag & drop'}
          </span>
          <span className="text-[11px] text-muted-foreground mt-1 font-mono text-center">
            .pcap .pcapng .cap · .csv .tsv · .xlsx · .pdf · .json · .zip
          </span>
          <input
            ref={inputRef}
            type="file"
            accept={IMPORT_ACCEPT}
            onChange={onInputChange}
            disabled={busy}
            className="hidden"
          />
        </label>
      </div>

      <div className="rounded-lg border border-border bg-muted/30 p-3 text-[11px] text-muted-foreground leading-relaxed space-y-1.5">
        <p>
          Spreadsheets and PDFs are checked before anything is imported: a file whose columns are not
          packet data is refused rather than turned into frames that were never captured.
        </p>
        <p>
          A row carries no wire bytes unless it was exported with{' '}
          <span className="font-semibold text-foreground/80">Include raw packet bytes</span>. Without
          them a re-imported packet has no hex dump and no protocol tree.
        </p>
      </div>

      {status && (
        <div className="text-emerald-500 flex items-start gap-1.5 font-medium">
          <TbCheck className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{status}</span>
        </div>
      )}

      {/* What was lost. Stated at import time rather than left for the user to
          discover by clicking a packet and finding an empty hex pane. */}
      {notes.length > 0 && (
        <ul className="space-y-1.5">
          {notes.map((note, i) => (
            <li key={i} className="flex items-start gap-1.5 text-amber-600 dark:text-amber-400">
              <TbInfoCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="leading-relaxed">{note}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
