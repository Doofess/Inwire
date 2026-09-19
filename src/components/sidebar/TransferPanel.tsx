import React, { useState } from 'react';
import {
  Check, CircleAlert, Download, FileCode, FileSpreadsheet, FileText,
  Image as ImageIcon, LoaderCircle,
} from 'lucide-react';

import { Section } from '../network/rows';
import { Switch } from '../ui/switch';
import { ImportPanel } from '../export/ImportPanel';
import { ImportErrorDialog } from '../export/ImportErrorDialog';
import { buildPdfReport } from '../export/pdfReport';
import { useRovingFocus } from '../common/useRovingFocus';
import { FilterEngine } from '../../services/filterEngine';
import { PcapService } from '../../services/pcapParser';
import { generatePcapNg, type PcapngInterface } from '../../services/pcapngWriter';
import { anonymiseCapture } from '../../services/anonymise';
import { keyLog } from '../../services/tls/keyLog';
import { buildNameMap } from '../../services/nameResolution';
import { buildCsv, buildXlsx, zipSingleFile } from '../../services/tabularWriters';
import { saveGeneratedBlob, exportStem } from '../../lib/saveFile';
import { packetsBytes } from '../../services/packetBytes';
import type { CaptureDropStats } from '../../services/agentProtocol';
import type { Capabilities, Packet } from '../../types/packet';
import type { ImportFailure } from '../../services/exportSchema';

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
 * ## The heavy work moved off the render path, and that is not a tidy-up
 *
 * `ExportPanel` computed `useHydratedBytes(exportPackets)` on RENDER, then
 * anonymised the result, then built a name map from it, then estimated its
 * size - all as memos over the whole buffer, to drive live previews. Inside a
 * modal opened for a few seconds that is a one-off cost nobody notices.
 *
 * This panel is persistent and sits beside a live capture, where `packets`
 * changes ten times a second. Those memos would re-hydrate and re-anonymise
 * the entire buffer at that rate, for a preview. So every one of them happens
 * once, inside `runExport`, at the moment something is actually being written.
 *
 * **What that costs is the live previews**, and it is worth naming rather than
 * glossing: the "would rewrite N addresses" figure beside Anonymise and the
 * raw-bytes size estimate are gone. The prose they sat beside is not - the
 * consequence is what the reader cannot discover, and the number was only ever
 * its illustration.
 *
 * ## The filtered scope names an expression and not a count
 *
 * For the same reason. `FilterEngine.filterPackets` over the buffer is held to
 * a 50ms budget at 50,000 frames by `scripts/filter/engine.ts`; run on every
 * flush it is half a core, continuously, to print a number. The buffer count
 * is free (`packets.length`) and is shown; the filtered count is what the
 * saved line reports once the file exists.
 *
 * The app's own packet counter was the tempting shortcut and is the wrong
 * source: it counts over the WHOLE capture, disk included, and this writes
 * from the buffer. A panel that promised 4,231 and wrote 2,800 would be worse
 * than one that promised nothing.
 *
 * ## There is no filter field here any more
 *
 * The modal embedded a whole `FilterBar`, because a 70% scrim covered the one
 * in the title row. There is no scrim: that field is 32px above this column and
 * always reachable. What is left is the CHOICE the embedded copy really
 * offered - write the buffer, or write what the filter selects - which is two
 * buttons and no second expression anywhere in the window.
 */
export interface TransferPanelProps {
  /** The full live buffer. This panel derives its own filtered view from it. */
  packets: Packet[];
  /** The expression applied in the title row, which this panel only reads. */
  appliedFilter: string;
  permissions: Capabilities;
  /**
   * What the driver and the agent dropped, for the pcapng Interface Statistics
   * Block. A file that does not say it is incomplete reads as complete.
   */
  captureStats?: CaptureDropStats | null;
  onImportPackets: (packets: Packet[]) => void;
  onImportBatch?: (batch: Packet[]) => void;
}

type FormatId = 'pcap' | 'pcapng' | 'json' | 'csv' | 'xlsx' | 'pdf';
type Scope = 'buffer' | 'filter';

const ROW = 'w-full text-left px-3 py-2 cursor-pointer transition-colors '
  + 'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring '
  + 'focus-visible:ring-inset disabled:opacity-40 disabled:cursor-not-allowed';

export const TransferPanel: React.FC<TransferPanelProps> = ({
  packets, appliedFilter, permissions, captureStats, onImportPackets, onImportBatch,
}) => {
  const [scope, setScope] = useState<Scope>('buffer');
  const [includeRawBytes, setIncludeRawBytes] = useState(true);
  const [compress, setCompress] = useState(false);
  const [anonymise, setAnonymise] = useState(false);
  const [attachSecrets, setAttachSecrets] = useState(false);
  const [busy, setBusy] = useState<FormatId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedTo, setSavedTo] = useState<{ path: string; frames: number } | null>(null);
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
  const onKeyDown = useRovingFocus('vertical');

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
  const canExport = packets.length > 0 && filterValid && busy === null;

  /**
   * Everything expensive, once, at the moment something is written.
   *
   * Hydrated FIRST, because a buffer large enough to have stopped holding raw
   * frames would otherwise write a capture of empty ones - and anonymisation
   * rewrites those bytes, so it has to happen after they are back (ADR 0013).
   *
   * This does mean the whole capture's bytes are resident for the length of an
   * export. At the present cap that is ~117 MB and unremarkable; if the cap
   * ever rises to a million frames it is 1.17 GB, and the writers will have to
   * produce a Blob from parts as they go rather than one contiguous buffer.
   * Noted here because that is the moment this stops being adequate.
   */
  const prepare = async (): Promise<{ outgoing: Packet[]; interfaces: PcapngInterface[] }> => {
    const chosen = scope === 'filter' && hasFilter
      ? FilterEngine.filterPackets(packets, appliedFilter)
      : packets;
    const bytesById = await packetsBytes(chosen);
    const hydrated = chosen.map((p) => {
      const bytes = bytesById.get(p.id);
      return bytes === undefined ? p : { ...p, rawBytes: bytes };
    });
    const outgoing = anonymise ? anonymiseCapture(hydrated).packets : hydrated;

    // One IDB per adapter the export actually contains. Classic pcap has one
    // link type and no interface field, so a multi-adapter capture came out as
    // one undifferentiated stream; pcapng can say it, so it does.
    const names = [...new Set(outgoing.map((p) => p.interfaceName).filter(Boolean))] as string[];
    const interfaces: PcapngInterface[] = names.length === 0
      ? [{ name: 'unknown', description: 'Inwire capture' }]
      : names.map((name) => ({
        name,
        description: 'Inwire capture',
        // A nanosecond capture stays nanosecond: pcapng records the
        // resolution per interface, which is the thing classic pcap could
        // only express through the whole file's magic number.
        tsPrecision: outgoing.find((p) => p.interfaceName === name)?.tsPrecision ?? 6,
        // The counters describe the whole capture rather than this adapter's
        // share, so they are only written when there is exactly one adapter
        // to attribute them to.
        ...(names.length === 1 && captureStats
          ? {
            received: captureStats.received,
            dropped: (captureStats.droppedKernel ?? 0) + captureStats.droppedAgent,
          }
          : {}),
      }));
    return { outgoing, interfaces };
  };

  /**
   * One path for every format: build a blob, optionally zip it, save it.
   *
   * The zip toggle is why this is centralised - wrapping happens after the file
   * exists and before it is handed over, so a format only has to know how to
   * produce its own bytes.
   */
  const runExport = async (
    id: FormatId,
    extension: string,
    produce: (ready: { outgoing: Packet[]; interfaces: PcapngInterface[] }) => Blob | Promise<Blob>,
    stemPrefix = 'inwire_capture',
  ) => {
    if (!canExport) return;
    setBusy(id);
    setError(null);
    setSavedTo(null);
    try {
      const ready = await prepare();
      const stem = exportStem(stemPrefix);
      const filename = `${stem}.${extension}`;
      const blob = await produce(ready);
      const outcome = compress
        ? await saveGeneratedBlob(await zipSingleFile(blob, filename), `${stem}.zip`)
        : await saveGeneratedBlob(blob, filename);
      // Three outcomes, and cancelled is not one of the other two. Somebody who
      // pressed Cancel meant to, and showing them an error for it would be the
      // app arguing with a decision it just asked them to make.
      if (outcome.saved) setSavedTo({ path: outcome.path, frames: ready.outgoing.length });
      else if (!outcome.canceled) setError(outcome.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The export failed.');
    } finally {
      setBusy(null);
    }
  };

  const formats: {
    id: FormatId; title: string; note?: string; icon: React.ReactNode;
    disabled?: boolean; group: 'capture' | 'report'; onClick: () => void;
  }[] = [
    {
      id: 'pcapng',
      title: 'pcapng',
      group: 'capture',
      icon: <Download className="w-3.5 h-3.5" />,
      disabled: !permissions.canExportPcap,
      onClick: () => runExport('pcapng', 'pcapng', ({ outgoing, interfaces }) => generatePcapNg(
        outgoing,
        {
          interfaces,
          // Only when the addresses are real. An anonymised file must not carry
          // a table mapping the addresses it just rewrote back to host names.
          names: anonymise ? undefined : buildNameMap(outgoing).entries()
            .filter((e) => e.address.includes('.') || e.address.includes(':'))
            .map((e) => ({ address: e.address, names: [e.name] })),
          // Never alongside anonymisation: the secrets would open the payload
          // that was just removed, and the two together are a contradiction
          // rather than a choice.
          secrets: attachSecrets && !anonymise ? keyLog.serialise() : undefined,
          comment: hasFilter && scope === 'filter'
            ? `Exported from Inwire with the display filter: ${appliedFilter}`
            : 'Exported from Inwire',
        },
      )),
    },
    {
      id: 'pcap',
      title: 'Libpcap (.pcap)',
      // The only format row carrying a line, and it carries a LOSS - the four
      // things pcapng keeps that this cannot. Stating them here rather than as
      // pcapng's four keeps is the same fact said once instead of twice, and
      // said where it changes a decision.
      note: 'Loses the adapter name, nanosecond timestamps, the resolved names '
        + 'and what the capture dropped.',
      group: 'capture',
      icon: <Download className="w-3.5 h-3.5" />,
      disabled: !permissions.canExportPcap,
      onClick: () => runExport('pcap', 'pcap',
        ({ outgoing }) => PcapService.generatePcapBinary(outgoing)),
    },
    {
      id: 'xlsx',
      title: 'Excel Workbook',
      group: 'report',
      icon: <FileSpreadsheet className="w-3.5 h-3.5" />,
      onClick: () => runExport('xlsx', 'xlsx',
        ({ outgoing }) => buildXlsx(outgoing, { includeRawBytes, filter: appliedFilter })),
    },
    {
      id: 'csv',
      title: 'Spreadsheet CSV',
      group: 'report',
      icon: <FileText className="w-3.5 h-3.5" />,
      onClick: () => runExport('csv', 'csv',
        ({ outgoing }) => buildCsv(outgoing, includeRawBytes)),
    },
    {
      id: 'json',
      title: 'JSON Telemetry',
      group: 'report',
      icon: <FileCode className="w-3.5 h-3.5" />,
      onClick: () => runExport('json', 'json', ({ outgoing }) => new Blob(
        [PcapService.exportToJson(outgoing, includeRawBytes)],
        { type: 'application/json;charset=utf-8' },
      )),
    },
    {
      id: 'pdf',
      title: 'PDF Report',
      note: 'Stats, alerts and the most recent 100 packets.',
      group: 'report',
      icon: <ImageIcon className="w-3.5 h-3.5" />,
      onClick: () => runExport('pdf', 'pdf',
        ({ outgoing }) => buildPdfReport(outgoing, appliedFilter), 'inwire_report'),
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
        + 'half. Payload is dropped.',
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
      onClick={f.onClick}
      disabled={!canExport || f.disabled}
      title={f.disabled ? 'Exporting raw captures is restricted for this role' : undefined}
      className={`${ROW} hover:bg-accent`}
    >
      <span className="flex items-center gap-2">
        <span className="shrink-0 text-muted-foreground">
          {busy === f.id ? <LoaderCircle className="w-3.5 h-3.5 animate-spin" /> : f.icon}
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
          { id: 'buffer' as const, label: 'Everything in the buffer', detail: `${packets.length.toLocaleString()} frames` },
          {
            id: 'filter' as const,
            label: 'What the display filter selects',
            // No count, and deliberately: see the header. The expression is the
            // identity of the set; the number arrives with the file.
            detail: hasFilter ? appliedFilter : 'no filter applied',
          },
        ]).map((option) => {
          const active = scope === option.id;
          const unavailable = option.id === 'filter' && !hasFilter;
          return (
            <button
              key={option.id}
              type="button"
              disabled={unavailable}
              aria-pressed={active}
              onClick={() => setScope(option.id)}
              className={`${ROW} ${active
                ? 'bg-primary/20 text-foreground font-semibold'
                : 'hover:bg-accent/60'}`}
            >
              <span className="block text-xs">{option.label}</span>
              <span className="mt-0.5 block text-[10px] font-mono truncate
                text-muted-foreground" title={option.detail}>
                {option.detail}
              </span>
            </button>
          );
        })}
        {!filterValid && (
          <p className="px-3 py-2 text-[10px] leading-tight text-destructive">
            The applied filter does not compile, so nothing can be exported. An
            expression that cannot be read would otherwise write a file matching
            a filter nobody wrote.
          </p>
        )}
      </Section>

      {packets.length > 0 && (
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

      {error !== null && (
        <p className="flex items-start gap-1.5 px-1 text-[11px] text-destructive">
          <CircleAlert className="w-3.5 h-3.5 shrink-0 mt-px" />
          <span>{error}</span>
        </p>
      )}
      {savedTo !== null && (
        <p className="px-1 text-[11px] text-success-muted">
          <span className="flex items-center gap-1.5">
            <Check className="w-3.5 h-3.5 shrink-0" />
            {savedTo.frames.toLocaleString()} frames written
          </span>
          {/* Ellipsised at the FRONT, which is the half nobody needs - the
              filename is what identifies the file. More right at 256px than it
              was at 768. */}
          <span dir="rtl" className="mt-0.5 block font-mono truncate text-muted-foreground">
            {savedTo.path}
          </span>
        </p>
      )}

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
