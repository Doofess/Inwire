import React, { useEffect, useState } from 'react';
import {
  Check, CircleAlert, Download, FileCode, FileSpreadsheet, FileText,
  Image as ImageIcon, LoaderCircle, RefreshCw, X,
} from 'lucide-react';

import { Section } from '../network/rows';
import { Switch } from '../ui/switch';
import { ImportPanel } from '../export/ImportPanel';
import { ImportErrorDialog } from '../export/ImportErrorDialog';
import { useRovingFocus } from '../common/useRovingFocus';
import { FilterEngine } from '../../services/filterEngine';
import { keyLog } from '../../services/tls/keyLog';
import { captureStore } from '../../services/capture/captureClient';
import { saveCaptured, type SaveOutcome } from '../../lib/saveFile';
import { markedExportCount } from '../../lib/captureRowSpace';
import {
  beginExportJob, cancelExportJob, dismissExportJob, type ExportFormat, type ExportJobState, type ExportPhase,
} from '../../services/export/exportJob';
import { useExportJob } from '../../lib/useExportJob';
import type { CaptureFilterState } from '../../lib/useCaptureFilter';
import type { AgentInterface, CaptureDropStats } from '../../services/agentProtocol';
import type { Capabilities, Packet } from '../../types/packet';
import type { ImportFailure } from '../../services/exportSchema';
import type { CaptureSource } from '../../services/export/captureMeta';
import type { Marks } from '../../services/marks';
import type { MatchSet } from '../../services/capture/matchSet';
import type { CaptureFileFacts } from '../../services/captureFileFacts';
import type { ImportBatchSink } from '../../services/tabularImport';

/**
 * Export and Import, as one column read top to bottom.
 *
 * This was a `max-w-3xl` modal with a 70% scrim, a tab strip, and a
 * `grid-cols-1 sm:grid-cols-2 lg:grid-cols-3` of six format cards. A modal was
 * always the wrong home for it: an export is a SEQUENCE - what gets written,
 * what travels with it, in which format - and a column is the shape of a
 * sequence, where a three-column grid scrambled the last step into a reading
 * path nobody follows.
 *
 * ## An export is the whole capture, and none of the work happens here
 *
 * Every format writes the capture - the frames on disk below the RAM window as
 * well as the window - or what the display filter selects from all of it. The
 * work is `services/export/runExport.ts`, fetched with `await import` when a
 * format is pressed: the writers, the anonymiser, exceljs and jsPDF are none
 * of them needed to show a packet, and this panel is reached from the entry
 * chunk. Nothing expensive runs on render either - this panel sits beside a
 * live capture and re-renders on every flush, so hydrating or anonymising
 * anything here would do it ten times a second, for a preview.
 *
 * **The job outlives the panel.** Switching the side bar to Interfaces
 * unmounts this component, and an export that took its progress and its
 * Cancel button with it would carry on writing with nothing able to stop it.
 * So the job is a module store (`services/export/exportJob.ts`) and this is a
 * view of it: come back and the bar is where the export has got to.
 *
 * ## Both counts are the list's own
 *
 * "The whole capture" is the title row's total and "what the filter selects"
 * is its match count, from the same scan (`useCaptureFilter`). The export runs
 * no scan of its own - the store runs one at a time, and a second would cancel
 * the list's - so until that scan has covered every frame on disk the filtered
 * choice is unavailable and says why, rather than writing the window's matches
 * and calling them the filter's answer.
 *
 * ## There is no filter field here any more
 *
 * The modal embedded a whole `FilterBar`, because a 70% scrim covered the one
 * in the title row. There is no scrim: that field is 32px above this column and
 * always reachable. What is left is the CHOICE the embedded copy really
 * offered - the capture, or what the filter selects - which is two buttons and
 * no second expression anywhere in the window.
 */
export interface TransferPanelProps {
  /** The RAM window: the capture's newest frames. The rest is read off disk. */
  packets: Packet[];
  /** The expression applied in the title row, which this panel only reads. */
  appliedFilter: string;
  permissions: Capabilities;
  /**
   * What the driver, the agent and the pipe dropped. A file that does not say
   * it is incomplete reads as complete - and a count nobody reported is null
   * here and null in the file, never a zero.
   */
  captureStats?: CaptureDropStats | null;
  /** Capture ordinals below the window (`useWindowOrdinal`). */
  belowWindow: number;
  /** The capture's first ordinal still held (0 unless a ring deleted some): `belowWindow` is counted from it. */
  captureFloor: number;
  /** Frames in the whole capture: `belowWindow + packets.length`. */
  captureRowCount: number;
  /** Frames the display filter selects over the whole capture, once the scan is in. */
  filteredRowCount: number;
  /** The scan that answers the filter below the window. */
  filterScan: CaptureFilterState;
  /** Rows below the window the scan did not reach (`uncoveredRows`). */
  filterUncovered: number;
  onRescan: () => void;
  /** The agent's adapters, which carry each one's link type. */
  agentInterfaces: AgentInterface[];
  /** Where these frames came from, for the metadata every format prints. */
  captureSource: CaptureSource;
  onImportPackets: (packets: Packet[], info: { filename: string; facts?: CaptureFileFacts }) => void;
  onImportBatch?: ImportBatchSink;
  /** The capture on disk, whose own files "As captured" copies. */
  captureId: string | null;
  /** How many pcapng files the agent wrote for it and still keeps. 0 hides the row. */
  capturedFileCount: number;
  /** A capture running: its files are still being written. */
  capturing: boolean;
  /** Why an import cannot start for a reason the app knows, beside a running export. */
  importBlockedBy?: string | null;
  /**
   * A request to open the import file picker, from outside the panel (the
   * welcome's "Open a capture file…"). Each increase asks once; 0 is no request.
   */
  pickRequest?: number;
  /** The packets the user marked (ADR 0067); a new set each time one is toggled. */
  marks: Marks;
}

type Scope = 'capture' | 'filter' | 'marked';

const ROW = 'w-full text-left px-3 py-2 cursor-pointer transition-colors '
  + 'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring '
  + 'focus-visible:ring-inset disabled:opacity-40 disabled:cursor-not-allowed';

const COUNT = new Intl.NumberFormat();

/**
 * Whether the filtered choice can be written, and what its row says.
 *
 * With nothing on disk below the window the in-memory filter is the whole
 * answer and there is no scan to wait for. With something there, only a scan
 * that finished AND reached the end of the disk half will do: a scan still
 * running has no answer yet, and one that started before the capture grew
 * does not cover the frames that arrived since - exporting then would quietly
 * leave them out.
 */
function filterAvailability(
  hasFilter: boolean, below: number, scan: CaptureFilterState, uncovered: number, matches: number,
): { ready: boolean; detail: string; rescan: boolean } {
  if (!hasFilter) return { ready: false, detail: 'no filter applied', rescan: false };
  const frames = `${COUNT.format(matches)} frames`;
  if (below === 0) return { ready: true, detail: frames, rescan: false };
  switch (scan.status) {
    case 'ready':
      return uncovered > 0
        ? {
          ready: false,
          detail: `${COUNT.format(uncovered)} frames arrived after the scan; rescan to include them`,
          rescan: true,
        }
        : { ready: true, detail: frames, rescan: false };
    case 'scanning': {
      const percent = scan.frameCount > 0 ? Math.floor((scan.framesDone / scan.frameCount) * 100) : 0;
      return { ready: false, detail: `scanning ${percent}%`, rescan: false };
    }
    case 'failed':
      return { ready: false, detail: `the scan failed: ${scan.message}`, rescan: true };
    case 'off':
      return { ready: false, detail: 'waiting for the scan', rescan: false };
  }
}

const PHASE_LABEL: Record<ExportPhase, string> = {
  choosing: 'Choosing where to save',
  surveying: 'Counting frames and columns',
  writing: 'Writing',
  finishing: 'Finishing the file',
};

export const TransferPanel: React.FC<TransferPanelProps> = ({
  packets, appliedFilter, permissions, captureStats, belowWindow, captureFloor, captureRowCount, filteredRowCount,
  filterScan, filterUncovered, onRescan, agentInterfaces, captureSource, onImportPackets, onImportBatch,
  captureId, capturedFileCount, capturing, importBlockedBy = null, pickRequest = 0, marks,
}) => {
  const [scope, setScope] = useState<Scope>('capture');
  /**
   * The marked frames the store holds, asked again whenever the set changes,
   * and once more when the window has moved past what the answer covered.
   * `marks` can name frames the store does not have (the ring expired them), so
   * the count shown is not `marks.size`; it is `markedExportCount`'s, this set
   * below the window and the window's own marks above it, because frames still
   * staged during a capture are in no answer the store can give. Null until
   * the first answer.
   */
  const [heldMarks, setHeldMarks] = useState<MatchSet | null>(null);
  const windowOrdinal = captureFloor + belowWindow;
  const heldBehind = heldMarks !== null && heldMarks.frameCount < windowOrdinal;
  useEffect(() => {
    if (marks.size === 0) {
      setHeldMarks(null);
      // Nothing left to narrow by: choose the capture again rather than
      // leaving a hidden choice that every format would then be refused by.
      setScope((s) => (s === 'marked' ? 'capture' : s));
      return;
    }
    // A toggle during the round trip makes this answer about an older set.
    let stale = false;
    void captureStore.markMatches().then((held) => { if (!stale) setHeldMarks(held); });
    return () => { stale = true; };
  }, [marks, heldBehind]);
  const [includeRawBytes, setIncludeRawBytes] = useState(true);
  const [compress, setCompress] = useState(false);
  const [anonymise, setAnonymise] = useState(false);
  const [attachSecrets, setAttachSecrets] = useState(false);
  const job = useExportJob();
  /**
   * A refused file, and the token that reopens the picker for it.
   *
   * `ImportErrorDialog` stays a MODAL, which is the one thing in this
   * conversion that does not become a panel: a refusal that has to be
   * acknowledged is a detour by every test this repo applies, and squeezing a
   * parse error into 288px would put the one message that must be read in the
   * narrowest place on screen.
   */
  const [rejected, setRejected] = useState<{ filename: string; failure: ImportFailure } | null>(null);
  const [retryToken, setRetryToken] = useState(0);
  // The same token the retry button bumps, so `ImportPanel`'s one effect opens
  // the picker for both. Runs on mount too: the welcome shows the panel and asks
  // in one batch, so the panel can arrive with the request already made.
  useEffect(() => {
    if (pickRequest > 0) setRetryToken((n) => n + 1);
  }, [pickRequest]);
  const onKeyDown = useRovingFocus('vertical');
  /** What the last "As captured" save came to, said under its row. */
  const [captured, setCaptured] = useState<SaveOutcome | null>(null);
  const saveAsCaptured = async () => {
    if (captureId === null) return;
    setCaptured(await saveCaptured(captureId));
  };

  const hasFilter = appliedFilter.trim().length > 0;
  /**
   * An invalid expression exports NOTHING, and every format says so.
   *
   * `FilterEngine.filterPackets` never throws: given an expression it cannot
   * compile it quietly falls back to a substring search over a handful of
   * fields. Reasonable for a live list, where the result is on screen
   * immediately - and wrong for a file, which would match a filter nobody
   * wrote and carry no sign of it.
   */
  const filterValid = !hasFilter || FilterEngine.validateFilter(appliedFilter).isValid;
  const filtered = filterAvailability(hasFilter, belowWindow, filterScan, filterUncovered, filteredRowCount);
  // A filter cleared after choosing it leaves nothing to narrow by: the scope
  // falls back to the capture rather than disabling every format.
  const effectiveScope: Scope = scope === 'marked' && marks.size > 0 ? 'marked'
    : scope === 'filter' && hasFilter ? 'filter' : 'capture';
  const markedCount = heldMarks === null ? null
    : markedExportCount(heldMarks, windowOrdinal, captureFloor, packets, marks);
  const marked = marks.size === 0
    ? { ready: false, detail: 'No packets are marked.' }
    : markedCount === null
      ? { ready: false, detail: 'counting' }
      : markedCount === 0
        ? { ready: false, detail: 'None of the marked packets are kept.' }
        : { ready: true, detail: `${COUNT.format(markedCount)} frames` };
  const busy = job.status === 'running';
  const canExport = captureRowCount > 0 && filterValid && !busy
    && (effectiveScope === 'capture'
      || (effectiveScope === 'filter' && filtered.ready)
      || (effectiveScope === 'marked' && marked.ready));

  /**
   * Hands the job to `runExport`, fetched now rather than at startup.
   *
   * Everything it needs is read here, at the press, and handed over as values:
   * the window as it is now, the scan's bitmap, the counters. A live capture
   * keeps growing while the file is written; the file is the capture as of
   * this moment, which is the only moment anybody chose.
   */
  const start = async (format: ExportFormat) => {
    if (!canExport) return;
    const handle = beginExportJob(format);
    if (handle === null) return;
    try {
      const { runExport } = await import('../../services/export/runExport');
      // Asked again at the press: a live capture has stored frames since the
      // answer the row shows, and the file is the capture as of this moment.
      const markedMatches = effectiveScope === 'marked' ? await captureStore.markMatches() : null;
      const result = await runExport({
        format,
        scope: {
          window: packets,
          filter: effectiveScope === 'filter'
            ? { expression: appliedFilter, matches: filterScan.status === 'ready' ? filterScan.matches : null }
            : null,
          marked: markedMatches === null ? null : { ids: marks, matches: markedMatches },
          marks,
        },
        reader: captureStore,
        // Every read fails if the store is re-opened under the export. The
        // app cancels first (`cancelExportForChange`); this catches a path
        // that forgot to.
        captureIdentity: () => captureStore.generation,
        interfaces: agentInterfaces,
        includeRawBytes,
        compress,
        anonymise,
        secrets: attachSecrets && !anonymise ? keyLog.serialise() : undefined,
        source: captureSource,
        // Each count as the agent reported it. `droppedKernel` is null when
        // the driver's counters could not be read, and `droppedPipe` when the
        // agent did not say; folding either to 0 would print a complete
        // capture that nobody measured.
        drops: {
          kernel: captureStats ? captureStats.droppedKernel : null,
          agent: captureStats ? captureStats.droppedAgent : null,
          pipe: captureStats ? captureStats.droppedPipe : null,
        },
        received: captureStats ? captureStats.received : null,
        // The capturing machine's OS, from the preload - read here rather than
        // inside a writer, which is a service and never sees `window`.
        os: window.inwire?.osDescription ?? null,
        // The count this panel shows, so an Excel export too large for a
        // workbook is refused before the save dialog rather than after it.
        expectedFrames: effectiveScope === 'filter' ? filteredRowCount
          : effectiveScope === 'marked' ? markedCount ?? 0 : captureRowCount,
      }, { signal: handle.signal, onProgress: handle.progress });
      handle.settle(result);
    } catch (err) {
      // The chunk itself failed to load, or something outside `runExport`'s
      // own net threw. Its sink, if it opened one, has already been aborted.
      handle.settle({ outcome: 'failed', error: err instanceof Error ? err.message : 'The export failed.' });
    }
  };

  const formats: {
    id: ExportFormat; title: string; note?: string; icon: React.ReactNode;
    disabled?: boolean; group: 'capture' | 'report';
  }[] = [
    {
      id: 'pcapng',
      title: 'pcapng',
      group: 'capture',
      icon: <Download className="w-3.5 h-3.5" />,
      disabled: !permissions.canExportPcap,
    },
    {
      id: 'pcap',
      title: 'Libpcap (.pcap)',
      // The only capture row carrying a line, and it carries a LOSS - the
      // things pcapng keeps that this cannot. Stating them here rather than as
      // pcapng's keeps is the same fact said once instead of twice, and said
      // where it changes a decision.
      note: 'Loses the adapter name, nanosecond timestamps, the resolved names, '
        + 'what the capture dropped and the capture\'s metadata.',
      group: 'capture',
      icon: <Download className="w-3.5 h-3.5" />,
      disabled: !permissions.canExportPcap,
    },
    {
      id: 'xlsx',
      title: 'Excel Workbook',
      group: 'report',
      icon: <FileSpreadsheet className="w-3.5 h-3.5" />,
    },
    {
      id: 'csv',
      title: 'Spreadsheet CSV',
      group: 'report',
      icon: <FileText className="w-3.5 h-3.5" />,
    },
    {
      id: 'json',
      title: 'JSON Telemetry',
      group: 'report',
      icon: <FileCode className="w-3.5 h-3.5" />,
    },
    {
      id: 'pdf',
      title: 'PDF Report',
      note: 'Statistics and findings for the capture.',
      group: 'report',
      icon: <ImageIcon className="w-3.5 h-3.5" />,
    },
  ];

  const switches: { label: string; on: boolean; set: (v: boolean) => void; note?: string }[] = [
    {
      label: 'Include raw packet bytes',
      on: includeRawBytes,
      set: setIncludeRawBytes,
      // Kept in full. It is the consequence nobody can discover by looking:
      // the file opens, the rows are all there, and the hex pane is empty.
      note: 'Without them a re-imported file has frames with no hex dump and no '
        + 'protocol tree.',
    },
    {
      label: 'Compress downloads (.zip)',
      on: compress,
      set: setCompress,
      // No line. It restates its own label, which is the rule this cut follows:
      // prose that describes a mechanism the name already gives is cut, prose
      // that warns of a consequence stays.
    },
    {
      label: 'Anonymise addresses',
      on: anonymise,
      set: setAnonymise,
      note: 'Prefix-preserving, so subnets survive and a MAC keeps its vendor '
        + 'half. Payload, adapter names and processes are dropped.',
    },
    ...(keyLog.isEmpty ? [] : [{
      label: 'Attach decryption secrets',
      on: attachSecrets,
      set: setAttachSecrets,
      note: 'The file can then be decrypted by anyone who opens it. Never '
        + 'written alongside anonymisation.',
    }]),
  ];

  const formatRow = (f: typeof formats[number]) => (
    <button
      key={f.id}
      type="button"
      onClick={() => { void start(f.id); }}
      disabled={!canExport || f.disabled}
      title={f.disabled ? 'Exporting raw captures is restricted for this role' : undefined}
      className={`${ROW} hover:bg-accent`}
    >
      <span className="flex items-center gap-2">
        <span className="shrink-0 text-muted-foreground">
          {busy && job.format === f.id ? <LoaderCircle className="w-3.5 h-3.5 animate-spin" /> : f.icon}
        </span>
        <span className="text-xs font-semibold">{f.title}</span>
      </span>
      {f.note !== undefined && (
        <span className="mt-0.5 block text-[10px] leading-tight text-muted-foreground">
          {f.note}
        </span>
      )}
    </button>
  );

  return (
    <div className="p-2 space-y-2" onKeyDown={onKeyDown}>
      <Section title="What gets written">
        {/* Two buttons and no second expression. The embedded `FilterBar` that
            stood here existed because a scrim covered the title row's; without
            one, this is the CHOICE that field really offered. */}
        {([
          {
            id: 'capture' as const,
            label: 'The whole capture',
            detail: `${COUNT.format(captureRowCount)} frames`,
            unavailable: false,
          },
          {
            id: 'filter' as const,
            label: 'What the display filter selects',
            detail: filtered.detail,
            unavailable: !filtered.ready,
          },
          {
            id: 'marked' as const,
            label: 'Marked packets only',
            detail: marked.detail,
            unavailable: !marked.ready,
          },
        ]).map((option) => {
          const active = effectiveScope === option.id;
          return (
            <button
              key={option.id}
              type="button"
              disabled={option.unavailable}
              aria-pressed={active}
              onClick={() => setScope(option.id)}
              className={`${ROW} ${active
                ? 'bg-primary/15 text-foreground font-semibold'
                : 'hover:bg-accent/60 dark:hover:bg-foreground/5'}`}
            >
              <span className="block text-xs">{option.label}</span>
              <span className="mt-0.5 block text-[10px] truncate
                text-muted-foreground" title={option.detail}>
                {option.detail}
              </span>
            </button>
          );
        })}
        {/* The one way to settle a scan that is behind or failed, offered
            where the choice it blocks is - the same act as the counter's
            "+N UNSEARCHED" in the status bar. */}
        {filtered.rescan && (
          <button
            type="button"
            onClick={onRescan}
            className={`${ROW} hover:bg-accent flex items-center gap-2 text-xs`}
          >
            <RefreshCw className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
            Rescan the capture
          </button>
        )}
        {!filterValid && (
          <p className="px-3 py-2 text-[10px] leading-tight text-destructive">
            The applied filter does not compile, so nothing can be exported. An
            expression that cannot be read would otherwise write a file matching
            a filter nobody wrote.
          </p>
        )}
      </Section>

      {captureRowCount > 0 && (
        <Section title="What travels with it">
          {switches.map((row) => (
            /* **The row is inverted, and that is the redesign.** The modal put
               a three-line paragraph in a ~200px column beside a floating
               switch. Here the name and the switch share line one and the
               consequence takes the full width beneath - which is what a
               column is for, and what let the paragraphs be cut to one line
               each rather than deleted. */
            <div key={row.label} className="px-3 py-2">
              <label className="flex items-center justify-between gap-2 cursor-pointer">
                <span className="text-xs">{row.label}</span>
                <Switch checked={row.on} onCheckedChange={row.set} aria-label={row.label} />
              </label>
              {row.note !== undefined && (
                <p className="mt-0.5 text-[10px] leading-tight text-muted-foreground">
                  {row.note}
                </p>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* pcapng leads, and the ordering is the argument: a column can rank
          where a three-column grid made six formats equal siblings. */}
      <Section title="Capture formats">
        {/* The agent's own file, first: the capture as captured, block for
            block as dumpcap would have written it, copied rather than rebuilt
            (ADR 0052). The whole capture only - a filter or anonymising is an
            export's to do, and the rows below do it. */}
        {captureId !== null && capturedFileCount > 0 && (
          <>
            <button
              type="button"
              onClick={() => { void saveAsCaptured(); }}
              disabled={capturing}
              className={`${ROW} hover:bg-accent`}
            >
              <span className="flex items-center gap-2">
                <span className="shrink-0 text-muted-foreground"><Download className="w-3.5 h-3.5" /></span>
                <span className="text-xs font-semibold">pcapng, as captured</span>
              </span>
              <span className="mt-0.5 block text-[10px] leading-tight text-muted-foreground">
                {capturing
                  ? 'Available once the capture stops.'
                  : capturedFileCount === 1
                    ? 'The agent\'s own file, copied as written.'
                    : `The ${capturedFileCount} files the ring kept, copied as written into a new folder.`}
              </span>
            </button>
            {captured !== null && !(captured.saved === false && captured.canceled) && (
              <p className={`px-3 pb-2 text-[10px] leading-tight ${captured.saved ? 'text-muted-foreground' : 'text-destructive'}`}
                role="status">
                {captured.saved ? `Saved to ${captured.path}` : captured.error}
              </p>
            )}
          </>
        )}
        {formats.filter((f) => f.group === 'capture').map(formatRow)}
      </Section>

      <Section
        title="Reports and tables"
        // The caveat these four share, said once at the head of the group it
        // applies to rather than repeated on every row. It was previously
        // half on the raw-bytes switch, half in the import prose, and half
        // nowhere.
        note="A row per packet, not a capture. Re-importing one gives frames with no hex dump."
      >
        {formats.filter((f) => f.group === 'report').map(formatRow)}
      </Section>

      <JobStatus job={job} />

      <Section title="Import">
        {/* **The consequence is stated ABOVE the target, not after it**, and it
            matters in a way it did not before: the modal had to be OPENED to
            arm a drop zone, and this panel is persisted - so the target sits
            armed beside a running capture for as long as the panel is left on.
            `handleImportPackets` stops the capture, prunes the previous capture
            directory, resets the pipeline's id counter and adopts the new
            frames. None of that is discoverable from a dashed rectangle. */}
        <p className="px-3 py-2 text-[11px] leading-tight text-warning">
          An import stops the capture and replaces everything in the buffer.
        </p>
        <div className="px-3 py-2">
          <ImportPanel
            onImportPackets={onImportPackets}
            onImportBatch={onImportBatch}
            onFailure={(filename, failure) => setRejected({ filename, failure })}
            retryToken={retryToken}
            blockedBy={busy ? 'Not while an export is running - an import would replace the frames it is reading.' : importBlockedBy}
          />
        </div>
      </Section>

      {rejected !== null && (
        <ImportErrorDialog
          filename={rejected.filename}
          failure={rejected.failure}
          onClose={() => setRejected(null)}
          onRetry={() => { setRejected(null); setRetryToken((n) => n + 1); }}
        />
      )}
    </div>
  );
};

/**
 * The running export's bar and Cancel, or how the last one ended.
 *
 * A cancelled one shows nothing: somebody who pressed Cancel - in the dialog
 * or here - meant to, and a line about it would be the app arguing with a
 * decision it just asked them to make.
 */
const JobStatus: React.FC<{ job: ExportJobState }> = ({ job }) => {
  switch (job.status) {
    case 'idle':
      return null;
    case 'canceled':
      // A person's own Cancel says nothing; one the app made has to say why
      // the file they asked for does not exist.
      return job.reason === null ? null : (
        <Finished tone="text-warning">
          <span className="flex items-start gap-1.5">
            <CircleAlert className="w-3.5 h-3.5 shrink-0 mt-px" />
            <span>Export cancelled: {job.reason}. Nothing was saved.</span>
          </span>
        </Finished>
      );
    case 'running': {
      const known = job.total > 0 && (job.phase === 'surveying' || job.phase === 'writing');
      const share = known ? Math.min(1, job.done / job.total) : 0;
      return (
        <div className="px-1 space-y-1" role="status" aria-live="polite">
          {/* **Two lines, and neither truncates.** The phase and the count
              shared one `truncate` line beside Cancel, which at the side
              bar's 170px floor - and well above it - read "Writing - 268,114
              of 439,858 fr…": the one number the row exists for, cut. The
              phase keeps the line with the spinner and Cancel and may wrap;
              the count gets the full width of the line below, in the compact
              "done / total" form, and wraps at its spaces if even that is
              too narrow. */}
          <div className="flex items-start gap-2 text-[11px]">
            <LoaderCircle className="w-3.5 h-3.5 shrink-0 mt-px animate-spin text-muted-foreground" />
            <span className="flex-1 min-w-0 leading-tight">
              {PHASE_LABEL[job.phase]}
            </span>
            <button
              type="button"
              onClick={() => cancelExportJob()}
              className="shrink-0 flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] hover:bg-accent
                focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <X className="w-3 h-3" />
              Cancel
            </button>
          </div>
          {known && (
            <div className="text-[10px] leading-tight text-muted-foreground">
              {COUNT.format(job.done)} / {COUNT.format(job.total)} frames
            </div>
          )}
          {/* Indeterminate while the dialog is up or the file is closing,
              which have no frame count to show. */}
          <div className="h-1 rounded bg-secondary overflow-hidden">
            <div
              className={`h-full bg-primary ${known ? '' : 'w-full opacity-40 animate-pulse'}`}
              style={known ? { width: `${(share * 100).toFixed(1)}%` } : undefined}
            />
          </div>
        </div>
      );
    }
    case 'failed':
      return (
        <Finished tone="text-destructive">
          <span className="flex items-start gap-1.5">
            <CircleAlert className="w-3.5 h-3.5 shrink-0 mt-px" />
            <span>{job.error}</span>
          </span>
        </Finished>
      );
    case 'saved': {
      // Frames written without their bytes are a file that is not what it
      // looks like - a capture whose records are empty - so the line stops
      // being a plain success.
      const partial = job.withoutBytes > 0 || job.unreadable > 0;
      return (
        <Finished tone={partial ? 'text-warning' : 'text-success-muted'}>
          <span className="flex items-center gap-1.5">
            {partial
              ? <CircleAlert className="w-3.5 h-3.5 shrink-0" />
              : <Check className="w-3.5 h-3.5 shrink-0" />}
            Saved {COUNT.format(job.frames)} frames
            {job.withoutBytes > 0 && ` - ${COUNT.format(job.withoutBytes)} without their bytes`}
            {' '}to
          </span>
          {/* Ellipsised at the FRONT, which is the half nobody needs - the
              filename is what identifies the file. */}
          <span dir="rtl" className="mt-0.5 block font-mono truncate text-muted-foreground" title={job.path}>
            {job.path}
          </span>
          {job.unreadable > 0 && (
            <span className="mt-0.5 block text-warning">
              {COUNT.format(job.unreadable)} frames could not be read back from disk and are not in the file.
            </span>
          )}
        </Finished>
      );
    }
  }
};

/**
 * How a finished export's line is framed: its text, and a dismiss. A new
 * export replaces the line on its own; this is for putting it away sooner.
 */
const Finished: React.FC<{ tone: string; children: React.ReactNode }> = ({ tone, children }) => (
  <div className={`flex items-start gap-1 px-1 text-[11px] ${tone}`}>
    <div className="flex-1 min-w-0">{children}</div>
    <button
      type="button"
      onClick={dismissExportJob}
      aria-label="Dismiss"
      title="Dismiss"
      className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-accent
        focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
    >
      <X className="w-3 h-3" />
    </button>
  </div>
);
