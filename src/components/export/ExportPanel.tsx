import React, { useMemo, useState } from 'react';
import {
  TbAlertCircle, TbCheck,
  TbDownload,
  TbFileCode,
  TbFileSpreadsheet,
  TbFileText,
  TbLoader2,
  TbPhoto,
  TbShield,
} from 'react-icons/tb';

import { FilterPresetLibrary, Packet, Capabilities } from '../../types/packet';
import { FilterEngine } from '../../services/filterEngine';
import { estimateRawBytesSize } from '../../services/exportSchema';
import { PcapService } from '../../services/pcapParser';
import { generatePcapNg } from '../../services/pcapngWriter';
import { anonymiseCapture } from '../../services/anonymise';
import { keyLog } from '../../services/tls/keyLog';
import { buildNameMap } from '../../services/nameResolution';
import type { CaptureDropStats } from '../../services/agentProtocol';
import type { PcapngInterface } from '../../services/pcapngWriter';
import { buildCsv, buildXlsx, zipSingleFile } from '../../services/tabularWriters';
import { saveGeneratedBlob, exportStem } from '../../lib/saveFile';
import { FilterBar } from '../common/FilterBar';
import { Switch } from '../ui/switch';
import { buildPdfReport } from './pdfReport';
import { useHydratedBytes } from '../../lib/useHydratedBytes';
import { formatBytes } from '../../lib/formatBytes';

/**
 * The Export half of the Import/Export centre.
 *
 * Three things happen before a format is chosen: the packets are narrowed by a
 * display filter, the user decides whether wire bytes travel with them, and the
 * user decides whether the result is zipped. All three apply to every format,
 * which is why they sit above the cards rather than inside them.
 */

interface ExportPanelProps {
  /** The full live buffer. This panel derives its own filtered view from it. */
  packets: Packet[];
  /** The filter active in the main window, used as the starting point. */
  initialFilter: string;
  filterPresetLibrary: FilterPresetLibrary;
  permissions: Capabilities;
  isDark: boolean;
  /**
   * What the driver and the agent dropped during this capture, for the
   * pcapng file's Interface Statistics Block. A file that does not say it is
   * incomplete reads as complete, and this app already knows better - it shows
   * the number beside the capture button.
   */
  captureStats?: CaptureDropStats | null;
}

type FormatId = 'pcap' | 'pcapng' | 'json' | 'csv' | 'xlsx' | 'pdf';

export const ExportPanel: React.FC<ExportPanelProps> = ({
  packets,
  initialFilter,
  filterPresetLibrary,
  permissions,
  isDark,
  captureStats,
}) => {
  // Typed vs applied, the same split App.tsx keeps (`filterText` /
  // `appliedFilter`). Filtering runs over the whole buffer - up to 50,000
  // packets - so it happens on Enter and on preset selection, not on keystroke.
  const [filterText, setFilterText] = useState(initialFilter);
  const [appliedFilter, setAppliedFilter] = useState(initialFilter);

  const [includeRawBytes, setIncludeRawBytes] = useState(false);
  const [compress, setCompress] = useState(false);
  /**
   * Off by default, and deliberately so: an export that quietly rewrote the
   * addresses would be worse than one that did not offer to. This is a thing
   * the user asks for at the moment they decide who the file is going to.
   */
  const [anonymise, setAnonymise] = useState(false);
  /**
   * Off by default and only offered when a key log is actually loaded. A
   * pcapng that carries its secrets decrypts itself for whoever opens it -
   * which is the point when the file is going to a colleague who has to see
   * the same thing, and a disaster when it is going anywhere else.
   */
  const [attachSecrets, setAttachSecrets] = useState(false);
  const keyLogStats = keyLog.stats();
  const [busy, setBusy] = useState<FormatId | null>(null);
  const [error, setError] = useState<string | null>(null);
  /**
   * Where the last export went.
   *
   * Worth its own state because it is the whole point of the save dialog:
   * a download could only say "done", and "done" is what somebody stares at
   * while wondering which folder to look in.
   */
  const [savedTo, setSavedTo] = useState<string | null>(null);

  const validation = useMemo(() => FilterEngine.validateFilter(appliedFilter), [appliedFilter]);

  /**
   * `FilterEngine.filterPackets` never throws: given an expression it cannot
   * compile it quietly falls back to a substring search over a handful of
   * fields. That is reasonable for a live list, where the user sees the result
   * immediately - and wrong for an export, where it would silently hand over a
   * file matching a filter nobody wrote. So an invalid expression exports
   * nothing at all, and every card below is disabled until it is fixed.
   */
  const exportPackets = useMemo(() => {
    if (!validation.isValid) return [];
    return FilterEngine.filterPackets(packets, appliedFilter);
  }, [packets, appliedFilter, validation.isValid]);

  /**
   * What every format actually writes.
   *
   * Derived once, above the formats, for the same reason the filter is: a
   * toggle that only some exports honoured would be the worst possible
   * version of this feature. The summary is shown so the user can see what
   * was taken out rather than take it on trust.
   */
  //
  // Hydrated first, because a buffer large enough to have stopped holding raw
  // frames would otherwise write a capture of empty ones - and anonymisation
  // rewrites those bytes, so it has to happen after they are back
  // (docs/decisions/0013). A pass-through while the buffer still holds them,
  // which is every capture up to the current cap.
  //
  // This does mean the whole capture's bytes are resident for the length of an
  // export. At the present cap that is ~117 MB and unremarkable; if the cap
  // ever rises to a million frames it is 1.17 GB, and the writers will have to
  // produce a Blob from parts as they go rather than one contiguous buffer.
  // Noted here because that is the moment this stops being adequate.
  const { packets: hydratedPackets, hydrating } = useHydratedBytes(exportPackets);

  const { packets: outgoing, summary: anonymised } = useMemo(() => {
    // Cast, not copy: the hook hands back a readonly view because it must not
    // invite anyone to write into the buffer's own frames, and the writers below
    // only ever read. Copying a million-frame array to satisfy a modifier would
    // be the wrong answer to it.
    if (!anonymise) return { packets: hydratedPackets as Packet[], summary: null };
    const result = anonymiseCapture(hydratedPackets as Packet[]);
    return { packets: result.packets, summary: result.summary };
  }, [anonymise, hydratedPackets]);

  /**
   * One IDB per adapter the export actually contains.
   *
   * Classic pcap has one link type and no interface field, so a multi-adapter
   * capture came out as one undifferentiated stream and the adapter each frame
   * came from was simply lost. pcapng can say it, so it does.
   */
  const pcapngInterfaces = useMemo<PcapngInterface[]>(() => {
    const names = [...new Set(outgoing.map((p) => p.interfaceName).filter(Boolean))] as string[];
    if (names.length === 0) return [{ name: 'unknown', description: 'Inwire capture' }];
    return names.map((name) => ({
      name,
      description: 'Inwire capture',
      // A nanosecond capture stays nanosecond: pcapng records the resolution
      // per interface, which is the thing classic pcap could only express
      // through the whole file's magic number.
      tsPrecision: outgoing.find((p) => p.interfaceName === name)?.tsPrecision ?? 6,
      // The counters describe the whole capture rather than this adapter's
      // share of it, so they are only written when there is exactly one
      // adapter to attribute them to.
      ...(names.length === 1 && captureStats
        ? {
          received: captureStats.received,
          dropped: (captureStats.droppedKernel ?? 0) + captureStats.droppedAgent,
        }
        : {}),
    }));
  }, [outgoing, captureStats]);

  /**
   * The names this capture taught us, for the file's Name Resolution Block.
   *
   * Worth writing precisely because the map is passive: every one of these came
   * out of a DNS answer, a TLS server name or a DHCP lease *in this capture*,
   * so the file carries its own resolution and whoever opens it later gets the
   * same names without a single lookup.
   */
  const resolvedNames = useMemo(() => {
    if (anonymise) return undefined;
    return buildNameMap(outgoing).entries()
      .filter((entry) => entry.address.includes('.') || entry.address.includes(':'))
      .map((entry) => ({ address: entry.address, names: [entry.name] }));
  }, [outgoing, anonymise]);

  const rawBytesSize = useMemo(
    () => (includeRawBytes ? estimateRawBytesSize(outgoing) : 0),
    [includeRawBytes, outgoing],
  );

  // `hydrating` gates the buttons: writing a file from frames whose bytes have
  // not arrived yet would produce a valid-looking capture full of nothing.
  const canExport = validation.isValid && exportPackets.length > 0 && !hydrating;
  const isFiltered = appliedFilter.trim().length > 0;

  /**
   * One path for every format: build a blob, optionally zip it, download it.
   *
   * The zip toggle is the reason this is centralised. Wrapping happens after
   * the file exists and before it is handed over, so a format only has to know
   * how to produce its own bytes.
   */
  const runExport = async (
    id: FormatId,
    extension: string,
    produce: () => Blob | Promise<Blob>,
    stemPrefix = 'inwire_capture',
  ) => {
    if (!canExport || busy) return;
    setBusy(id);
    setError(null);
    setSavedTo(null);
    try {
      const stem = exportStem(stemPrefix);
      const filename = `${stem}.${extension}`;
      const blob = await produce();
      const outcome = compress
        ? await saveGeneratedBlob(await zipSingleFile(blob, filename), `${stem}.zip`)
        : await saveGeneratedBlob(blob, filename);
      // Three outcomes, and cancelled is not one of the other two. Somebody who
      // pressed Cancel meant to, and showing them an error for it would be the
      // app arguing with a decision it just asked them to make.
      if (outcome.saved) setSavedTo(outcome.path);
      else if (!outcome.canceled) setError(outcome.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The export failed.');
    } finally {
      setBusy(null);
    }
  };

  const cards: {
    id: FormatId;
    title: string;
    body: string;
    icon: React.ReactNode;
    accent: string;
    disabled?: boolean;
    onClick: () => void;
  }[] = [
    {
      id: 'pcap',
      title: 'Libpcap (.pcap)',
      body: 'Standard binary libpcap 2.4 file, readable by tcpdump and any standard capture tool',
      icon: <TbDownload className="w-4 h-4" />,
      accent: isDark
        ? 'bg-sky-950/30 border-sky-600/50 hover:bg-sky-900/40 text-sky-200'
        : 'bg-sky-50 border-sky-300 hover:bg-sky-100 text-sky-900',
      disabled: !permissions.canExportPcap,
      onClick: () => runExport('pcap', 'pcap', () => PcapService.generatePcapBinary(outgoing)),
    },
    {
      id: 'pcapng',
      title: 'pcapng (.pcapng)',
      body: 'The modern capture format: keeps which adapter each frame came from, nanosecond timestamps, the names this capture taught us, and what it dropped',
      icon: <TbDownload className="w-4 h-4" />,
      accent: isDark
        ? 'bg-indigo-950/30 border-indigo-600/50 hover:bg-indigo-900/40 text-indigo-200'
        : 'bg-indigo-50 border-indigo-300 hover:bg-indigo-100 text-indigo-900',
      disabled: !permissions.canExportPcap,
      onClick: () => runExport('pcapng', 'pcapng', () => generatePcapNg(outgoing, {
        interfaces: pcapngInterfaces,
        // Only when the addresses are real. An anonymised file must not carry
        // a table mapping the addresses it just rewrote back to host names.
        names: anonymise ? undefined : resolvedNames,
        // Never alongside anonymisation: the secrets would open the payload
        // that was just removed, and the two together are a contradiction
        // rather than a choice.
        secrets: attachSecrets && !anonymise ? keyLog.serialise() : undefined,
        comment: appliedFilter.trim().length > 0
          ? `Exported from Inwire with the display filter: ${appliedFilter}`
          : 'Exported from Inwire',
      })),
    },
    {
      id: 'xlsx',
      title: 'Excel Workbook',
      body: 'Packets, protocol hierarchy and alerts as four sheets, with a frozen header row',
      icon: <TbFileSpreadsheet className="w-4 h-4" />,
      accent: isDark
        ? 'bg-emerald-950/30 border-emerald-700/50 hover:bg-emerald-900/40 text-emerald-200'
        : 'bg-emerald-50 border-emerald-300 hover:bg-emerald-100 text-emerald-900',
      onClick: () =>
        runExport('xlsx', 'xlsx', () =>
          buildXlsx(outgoing, { includeRawBytes, filter: appliedFilter }),
        ),
    },
    {
      id: 'csv',
      title: 'Spreadsheet CSV',
      body: 'Tabular packet summary for reports, Excel, and SIEM pipelines',
      icon: <TbFileText className="w-4 h-4" />,
      accent: 'bg-muted border-border hover:bg-accent text-foreground',
      onClick: () => runExport('csv', 'csv', () => buildCsv(outgoing, includeRawBytes)),
    },
    {
      id: 'json',
      title: 'JSON Telemetry',
      body: 'Structured packet metadata with decoded protocol layer fields',
      icon: <TbFileCode className="w-4 h-4" />,
      accent: 'bg-muted border-border hover:bg-accent text-foreground',
      onClick: () =>
        runExport('json', 'json', () =>
          new Blob([PcapService.exportToJson(outgoing, includeRawBytes)], {
            type: 'application/json;charset=utf-8',
          }),
        ),
    },
    {
      id: 'pdf',
      title: 'PDF Report',
      body: 'Formatted document with stats, alerts, and the most recent 100 packets',
      icon: <TbPhoto className="w-4 h-4" />,
      accent: isDark
        ? 'bg-red-950/30 border-red-900/50 hover:bg-red-900/40 text-red-200'
        : 'bg-red-50 border-red-300 hover:bg-red-100 text-red-900',
      onClick: () =>
        runExport(
          'pdf',
          'pdf',
          () => buildPdfReport(exportPackets, appliedFilter),
          'inwire_report',
        ),
    },
  ];

  return (
    <div className="space-y-5 text-xs">
      {!permissions.canExportPcap && (
        <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 flex items-center gap-2">
          <TbShield className="w-4 h-4 shrink-0" />
          <span>Exporting raw captures is restricted for the Auditor / Guest role.</span>
        </div>
      )}

      {/* Filter */}
      <div className="space-y-2">
        <div className="font-bold text-foreground/80 text-sm">Narrow what gets exported</div>
        <FilterBar
          variant="compact"
          filterText={filterText}
          onFilterChange={setFilterText}
          onApplyFilter={next => setAppliedFilter(next !== undefined ? next : filterText)}
          filterPresetLibrary={filterPresetLibrary}
        />
        {/* The invalid case is pushed clear of FilterBar's own validation
            banner, which floats absolutely just under the field. In the app
            header that banner hangs over the packet list and needs no room
            reserved; here it would land on top of this line. */}
        <div
          className={`flex items-center gap-2 text-[11px] font-mono text-muted-foreground ${
            validation.isValid ? 'pt-1' : 'pt-9'
          }`}
        >
          {validation.isValid ? (
            <>
              <span>
                Exporting{' '}
                <span className="font-bold text-primary">{exportPackets.length.toLocaleString()}</span> of{' '}
                {packets.length.toLocaleString()} packets
              </span>
              {isFiltered && exportPackets.length === 0 && (
                <span className="text-amber-600 dark:text-amber-400">- nothing matches this filter</span>
              )}
            </>
          ) : (
            // Deliberately not restating the parse error - the banner above
            // already names the offending field. This says what it means for
            // the export, which the banner does not.
            <span className="text-rose-500">
              Export is blocked while the filter is invalid: an expression that will not compile falls
              back to a plain text search, which would hand you a file you did not ask for.
            </span>
          )}
        </div>
      </div>

      {/* Options */}
      <div className="rounded-lg border border-border bg-muted/30 divide-y divide-border">
        <label className="flex items-start justify-between gap-4 p-3 cursor-pointer">
          <div className="min-w-0">
            <div className="font-semibold text-foreground">Compress downloads (.zip)</div>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Wraps the exported file in a zip archive. Inwire can import these back again.
            </p>
          </div>
          <Switch checked={compress} onCheckedChange={setCompress} aria-label="Compress downloads" />
        </label>

        <label
          className={`flex items-start justify-between gap-4 p-3 ${
            permissions.canExportPcap ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'
          }`}
        >
          <div className="min-w-0">
            <div className="font-semibold text-foreground">Include raw packet bytes</div>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Adds a base64 column to CSV, Excel and JSON. Without it a re-imported file has no hex
              dump and no protocol tree, because a spreadsheet row carries no wire data.
              {rawBytesSize > 0 && (
                <span className="text-foreground/70"> Adds about {formatBytes(rawBytesSize)}.</span>
              )}
            </p>
          </div>
          <Switch
            checked={includeRawBytes}
            onCheckedChange={setIncludeRawBytes}
            // Gated on the same permission as the .pcap card: this column IS
            // the capture, in a different container.
            disabled={!permissions.canExportPcap}
            aria-label="Include raw packet bytes"
          />
        </label>

        <label className="flex items-start justify-between gap-4 p-3 cursor-pointer">
          <div className="min-w-0">
            <div className="font-semibold text-foreground">Anonymise</div>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              Rewrites every address and removes everything above the transport header, so the
              file can be shared. Subnets survive - two hosts on one /24 still look like it - and
              a MAC keeps the half that names its manufacturer, so the capture is still a network.
              {anonymised && (
                <span className="text-foreground/70">
                  {' '}Would rewrite {anonymised.addresses} address
                  {anonymised.addresses === 1 ? '' : 'es'} and {anonymised.macs} MAC
                  {anonymised.macs === 1 ? '' : 's'}, and drop{' '}
                  {formatBytes(anonymised.bytesStripped)} of payload from{' '}
                  {anonymised.payloadsStripped} frame
                  {anonymised.payloadsStripped === 1 ? '' : 's'}.
                </span>
              )}
            </p>
          </div>
          <Switch checked={anonymise} onCheckedChange={setAnonymise} aria-label="Anonymise" />
        </label>

        {keyLogStats.connections > 0 && (
          <label className="flex items-start justify-between gap-4 p-3 cursor-pointer">
            <div className="min-w-0">
              <div className="font-semibold text-foreground">Attach decryption secrets</div>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Writes the loaded key log into the pcapng as a Decryption Secrets Block, so the
                file opens its own TLS for whoever receives it - no second file, nothing to set
                up. It also means the file has no confidentiality left:{' '}
                {keyLogStats.connections.toLocaleString()} connection
                {keyLogStats.connections === 1 ? '' : 's'} would travel with it in the clear.
                {anonymise && <span className="text-foreground/70"> Ignored while Anonymise is on.</span>}
              </p>
            </div>
            <Switch
              checked={attachSecrets && !anonymise}
              onCheckedChange={setAttachSecrets}
              disabled={anonymise}
              aria-label="Attach decryption secrets"
            />
          </label>
        )}
      </div>

      {/* Formats */}
      <div>
        <div className="font-bold text-foreground/80 text-sm mb-2">Export as</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {cards.map(card => {
            const enabled = canExport && !card.disabled && !busy;
            return (
              <button
                key={card.id}
                onClick={card.onClick}
                disabled={!enabled}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between gap-2 ${
                  enabled ? card.accent : 'opacity-40 cursor-not-allowed border-border'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-xs">{card.title}</span>
                  {busy === card.id ? (
                    <TbLoader2 className="w-4 h-4 animate-spin shrink-0" />
                  ) : (
                    <span className="shrink-0">{card.icon}</span>
                  )}
                </div>
                <p className="text-[11px] text-muted-foreground">{card.body}</p>
              </button>
            );
          })}
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-1.5 text-rose-500 font-medium">
          <TbAlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {savedTo && !error && (
        // `dir="rtl"` with the text reversed back by `unicode-bidi` is the
        // usual trick for ellipsising a path at the FRONT, which is the half
        // nobody needs - the filename is what identifies the file.
        <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium min-w-0">
          <TbCheck className="w-4 h-4 shrink-0" />
          <span className="truncate" dir="rtl" title={savedTo}>{savedTo}</span>
        </div>
      )}
    </div>
  );
};
