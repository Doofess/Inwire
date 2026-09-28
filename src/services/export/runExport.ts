/**
 * One export, from the save dialog to the committed file.
 *
 * Everything the Export panel used to do inside the component - choose the
 * frames, hydrate them, anonymise them, build a Blob, save it - happens here,
 * and it happens over the WHOLE capture: the disk below the RAM window as well
 * as the window itself (`exportFrames.ts`), a page at a time, into a
 * `ByteSink` that writes as it goes (`lib/saveSink.ts`).
 *
 * **Fetched when a format is pressed, never at startup.** `TransferPanel`
 * reaches this module through `await import(...)`, and this module is the only
 * thing that reaches the writers, `pcapngWriter`'s block builder, the
 * anonymiser, exceljs and jsPDF. None of them is needed to show a packet, and
 * all of them were in the entry chunk while the panel imported them directly.
 *
 * ## The order is the design
 *
 *   0. **An Excel export that cannot fit, refused before the dialog.** Its
 *      frame count is known at the press (`expectedFrames`), and the standard
 *      columns alone decide whether a workbook can hold that many rows - so a
 *      person is not asked for a folder and a name for a file that will be
 *      refused. Whether the field columns fit is the survey's question, and
 *      stays after it.
 *   1. **The save dialog, first.** A person who presses Cancel there has asked
 *      for nothing, so nothing is read: a survey of a five-million-frame
 *      capture is seconds of store IO to throw away.
 *   2. **A survey, when the format needs one.** CSV and Excel write every
 *      dissected field as a column, and a column set has to be fixed before
 *      the first row - so one pass over the rows, without bytes, folds the
 *      union of field keys. The same pass counts the frames and finds the
 *      first and last timestamps, which is what the metadata every format
 *      prints needs before its first line, and collects the names the capture
 *      taught for pcapng's Name Resolution Block. pcap prints no metadata and
 *      the PDF computes its own from the analysis, so neither surveys.
 *   3. **The frames, page by page**, in time order for the two capture
 *      formats (`orderByTime.ts`). Per page: the colour rule each frame
 *      matched, taken from the real frame; THEN the anonymiser; then the
 *      writer; then the sink.
 *   4. **The trailer, and the commit.** On any failure or abort the sink is
 *      aborted instead, which removes `<name>.partial` - a cancelled export
 *      never leaves a truncated file behind that looks complete.
 *
 * ## One anonymiser for the whole job
 *
 * Constructed once, before the first page, and used for every page, the
 * metadata and the report. Prefix-preserving anonymisation is keyed: two
 * anonymisers map one address to two pseudonyms, so a job that built one per
 * page would write a file in which one host is a different host on every
 * page - the conversation tables of anything reading it would fall apart
 * silently. `scripts/session/side-bar.ts` holds this file to exactly one
 * `new Anonymiser(`, outside the page loop.
 *
 * Everything that must see the REAL frame sees it before the anonymiser
 * does: the colour rule (an anonymised frame has no field bag and matches
 * nothing), the field survey, the names and the PDF's analysis. What those
 * produce is then redacted with the same anonymiser, never recomputed from the
 * anonymised copy.
 */
import { Anonymiser } from '../anonymise';
import { NameResolutionMap } from '../nameResolution';
import { exportStem } from '../../lib/saveFile';
import { isByteSink, openSaveSink, zipSink, type ByteSink, type OpenSinkResult } from '../../lib/saveSink';
import { APP_NAME, appVersion } from '../../lib/appVersion';
import type { ColorRule, Packet } from '../../types/packet';
import {
  exportFrames, guardedReader, linkTypeTable, windowOrdinal,
  type CaptureRowReader, type ExportFramesOptions, type ExportPage, type FrameScope, type LocateRetry,
} from './exportFrames';
import { orderByTime } from './orderByTime';
import { FieldSurvey } from './fieldColumns';
import { RuleMatcher } from './ruleMatcher';
import type { CaptureMeta, CaptureSource, DropCounts } from './captureMeta';
import type { ExportFormat, ExportProgress, ExportResult } from './exportJob';
import type { ExportWriter } from './writers/writer';
import { PcapWriter } from './writers/pcap';
import { PcapngWriter, type PcapngInterface } from './writers/pcapng';
import { CsvWriter } from './writers/csv';
import { JsonWriter } from './writers/json';
import { createXlsxWriter, xlsxRefusal, type XlsxBudget } from './writers/xlsx';
import { redactMeta } from '../report/redact';
import { wholeCaptureFacts } from '../captureFileFacts';

export interface ExportRequest {
  format: ExportFormat;
  /** The window as it was when Export was pressed, and the filter if any. */
  scope: FrameScope;
  /** The capture store, or a test's reader over one. */
  reader: CaptureRowReader;
  /**
   * What identifies the capture the reader is open on - `captureStore.generation`
   * in the app. Every read fails once it changes (`guardedReader`).
   */
  captureIdentity?: () => unknown;
  /** The agent's adapters, for `linkTypeTable`. */
  interfaces: readonly { label: string; linkType?: number }[];
  /** CSV, JSON and Excel: append each frame's bytes. The capture formats always carry them. */
  includeRawBytes: boolean;
  /** Write the file as a one-entry zip. */
  compress: boolean;
  anonymise: boolean;
  /** An NSS key log to attach to a pcapng. Never written alongside anonymisation. */
  secrets?: string;
  source: CaptureSource;
  /** What the capture lost. `null` counts stay null, everywhere. */
  drops: DropCounts;
  /** Frames the agent saw, for pcapng's statistics block; null when not a live capture. */
  received: number | null;
  /** The OS this export is made on, as the caller describes it. */
  os: string | null;
  /**
   * Frames the export will write, as the panel shows them - the title row's
   * total, or the filter's match count. Read for one thing: an Excel export
   * that is over its budget on this count alone is refused before the save
   * dialog opens (`xlsxRefusal`). Absent, that refusal waits for the survey.
   */
  expectedFrames?: number;
}

export interface ExportRuntime {
  signal?: AbortSignal;
  onProgress?: (progress: ExportProgress) => void;
  /** The save dialog. `openSaveSink` in the app; a test hands back a `MemorySink`. */
  openSink?: (suggestedName: string) => Promise<OpenSinkResult>;
  /** Frames per window page; `EXPORT_PAGE_FRAMES` when absent. */
  pageSize?: number;
  locate?: LocateRetry;
  /** Epoch ms; `Date.now` when absent. */
  now?: () => number;
  /** For tests: Excel's budget, `XLSX_BUDGET` when absent. */
  xlsxBudget?: XlsxBudget;
}

const EXTENSION: Record<ExportFormat, string> = {
  pcap: 'pcap', pcapng: 'pcapng', csv: 'csv', json: 'json', xlsx: 'xlsx', pdf: 'pdf',
};

/** Which formats write a row per frame, and so take colour rules and field columns. */
const TABULAR: ReadonlySet<ExportFormat> = new Set(['csv', 'json', 'xlsx']);

/** What the survey pass learns before the first byte is written. */
interface Survey {
  frames: number;
  unreadable: number;
  firstUs: number | null;
  lastUs: number | null;
  fields: FieldSurvey | null;
  names: NameResolutionMap | null;
  /** Adapters in order of first appearance. */
  adapters: string[];
}

function isAbort(error: unknown, signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true
    || (error instanceof Error && error.name === 'AbortError');
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'The export failed.';
}

/**
 * Runs one export. Never throws: every ending is an `ExportResult`, and every
 * ending other than `saved` has left no file behind.
 */
/**
 * What the capture dropped, as the metadata and an ISB report it: the live
 * capture's counts as the agent gave them, or an imported file's own - the
 * `isb_ifdrop` its ISBs carry, which is the driver's. A file that states none
 * reports none, never zero.
 */
function dropsOf(request: ExportRequest): DropCounts {
  if (request.source.kind !== 'import' || request.source.facts === undefined) return request.drops;
  return { kernel: wholeCaptureFacts(request.source.facts).dropped, agent: null, pipe: null };
}

export async function runExport(request: ExportRequest, runtime: ExportRuntime = {}): Promise<ExportResult> {
  const { format, scope } = request;
  const reader = request.captureIdentity
    ? guardedReader(request.reader, request.captureIdentity)
    : request.reader;
  const { signal } = runtime;
  const now = runtime.now ?? Date.now;
  const report = runtime.onProgress ?? (() => {});

  // ---- 0. a workbook that cannot be built, refused before anything is asked
  if (format === 'xlsx' && request.expectedFrames !== undefined) {
    const refusal = xlsxRefusal(request.expectedFrames, request.includeRawBytes, runtime.xlsxBudget);
    if (refusal !== null) return { outcome: 'failed', error: refusal };
  }

  // ---- 1. the dialog -------------------------------------------------------
  report({ phase: 'choosing', done: 0, total: 0 });
  const stem = exportStem(format === 'pdf' ? 'inwire_report' : 'inwire_capture');
  const fileName = `${stem}.${EXTENSION[format]}`;
  const opened = await (runtime.openSink ?? openSaveSink)(request.compress ? `${stem}.zip` : fileName);
  if (!isByteSink(opened)) {
    return 'canceled' in opened ? { outcome: 'canceled' } : { outcome: 'failed', error: opened.error };
  }
  const sink: ByteSink = request.compress ? zipSink(opened, fileName) : opened;

  try {
    // Asked once, of the store, and never of the caller's copy - the same
    // reasoning as `exportFrames`'s own `below`.
    if (signal?.aborted) throw signal.reason;
    const inCapture = await windowOrdinal(scope.window, reader, runtime.locate) + scope.window.length;
    const linkTypes = linkTypeTable(request.interfaces, scope.window);
    const pagesOf = (hydrateBytes: boolean): AsyncGenerator<ExportPage> => {
      const options: ExportFramesOptions = {
        hydrateBytes, linkTypes, signal, pageSize: runtime.pageSize, locate: runtime.locate,
      };
      return exportFrames(scope, reader, options);
    };

    // The job's one anonymiser. See the header: never per page.
    const anonymiser = request.anonymise ? new Anonymiser() : null;

    const metaFor = (frames: number, firstUs: number | null, lastUs: number | null, unreadable: number): CaptureMeta => {
      const tabular = TABULAR.has(format);
      const meta: CaptureMeta = {
        app: APP_NAME,
        version: appVersion(),
        os: request.os,
        generatedAt: now(),
        source: request.source,
        firstUs,
        lastUs,
        frames: { exported: frames, inCapture, unreadable },
        drops: dropsOf(request),
        scope: scope.filter === null ? 'capture' : 'filtered',
        filter: scope.filter?.expression ?? '',
        flags: {
          anonymised: anonymiser !== null,
          rawBytes: format === 'pcap' || format === 'pcapng' || (tabular && request.includeRawBytes),
          fields: tabular && anonymiser === null,
          secrets: format === 'pcapng' && anonymiser === null && !!request.secrets,
        },
      };
      return meta;
    };

    // ---- the PDF: an analysis, no bytes, no writer -------------------------
    if (format === 'pdf') {
      const [{ CaptureAnalyzer }, { buildPdfReport }] = await Promise.all([
        import('../report/analysis'),
        import('../../components/export/pdfReport'),
      ]);
      const analyzer = new CaptureAnalyzer();
      let unreadable = 0;
      for await (const page of pagesOf(false)) {
        analyzer.addPage(page.packets);
        unreadable = page.unreadable;
        report({ phase: 'writing', done: page.done, total: page.total });
      }
      report({ phase: 'finishing', done: 0, total: 0 });
      const analysis = analyzer.finish();
      const meta = metaFor(analysis.frames, analysis.firstUs, analysis.lastUs, unreadable);
      // The REAL analysis and metadata, and the job's anonymiser: the report
      // redacts both with it, so a host keeps one pseudonym across them.
      const blob = buildPdfReport(analysis, meta, {
        now: meta.generatedAt, compress: true, anonymiser: anonymiser ?? undefined,
      });
      signal?.throwIfAborted();
      await sink.write(new Uint8Array(await blob.arrayBuffer()));
      return settle(await sink.close(), analysis.frames, unreadable, 0);
    }

    // ---- 2. the survey -------------------------------------------------------
    const survey = format === 'pcap' ? null : await surveyOf(pagesOf(false), format, anonymiser !== null, report);
    const realMeta = survey === null
      ? null
      : metaFor(survey.frames, survey.firstUs, survey.lastUs, survey.unreadable);
    // What the file prints: redacted with the same anonymiser the frames get.
    const meta = realMeta !== null && anonymiser !== null ? redactMeta(realMeta, anonymiser) : realMeta;

    // The writers label adapters and redact colour-rule filters through the
    // job's anonymiser too, numbering adapters in the order the REAL metadata
    // listed them - which is how `redactMeta` numbered them above.
    const adapters = request.source.kind === 'live' ? request.source.adapters : [];
    const writer = await writerFor(request, survey, meta, anonymiser, adapters, now, runtime.xlsxBudget);

    // ---- 3. the frames -------------------------------------------------------
    const tabular = TABULAR.has(format);
    const hydrate = !tabular || request.includeRawBytes;
    const matcher = tabular ? new RuleMatcher() : null;
    const source = tabular ? pagesOf(hydrate) : orderByTime(pagesOf(hydrate));
    let frames = 0;
    // The survey's count until a page says otherwise: an export whose every
    // disk chunk was unreadable yields no page to carry the number.
    let unreadable = survey?.unreadable ?? 0;
    let withoutBytes = 0;
    for await (const page of source) {
      // Taken from the real frames, before the anonymiser strips what the
      // rules test.
      const rules: (ColorRule | null)[] | undefined = matcher === null
        ? undefined
        : page.packets.map((p) => matcher.match(p));
      const outgoing: readonly Packet[] = anonymiser === null
        ? page.packets
        : page.packets.map((p) => anonymiser.packet(p));
      // Checked per chunk, not only per page: a page can be thousands of
      // records, and a Cancel - or a new capture waiting on this one to let
      // go - should not wait for all of them to reach the disk.
      for (const chunk of writer.write(outgoing, rules)) {
        signal?.throwIfAborted();
        await sink.write(chunk);
      }
      frames += outgoing.length;
      unreadable = page.unreadable;
      withoutBytes = page.bytesMissing;
      report({ phase: 'writing', done: page.done, total: page.total });
    }

    // Measured only now, so it reaches the formats that print their metadata
    // after the frames - Excel's Capture sheet - and the result, which the
    // panel says aloud. The frames are written anyway: a zero-length record
    // is legal, and the rest of the capture is still worth having.
    if (hydrate) {
      if (meta !== null) meta.frames.withoutBytes = withoutBytes;
      if (realMeta !== null && realMeta !== meta) realMeta.frames.withoutBytes = withoutBytes;
    }

    // ---- 4. the trailer, and the commit ------------------------------------
    report({ phase: 'finishing', done: 0, total: 0 });
    for (const chunk of await writer.finish()) await sink.write(chunk);
    signal?.throwIfAborted();
    return settle(await sink.close(), frames, unreadable, withoutBytes);
  } catch (error) {
    await sink.abort();
    if (isAbort(error, signal)) return { outcome: 'canceled' };
    return { outcome: 'failed', error: messageOf(error) };
  }
}

function settle(
  outcome: Awaited<ReturnType<ByteSink['close']>>, frames: number, unreadable: number, withoutBytes: number,
): ExportResult {
  if (outcome.saved) return { outcome: 'saved', path: outcome.path, frames, unreadable, withoutBytes };
  return outcome.canceled ? { outcome: 'canceled' } : { outcome: 'failed', error: outcome.error };
}

/**
 * The pass that runs before anything is written. Reads rows only: no format's
 * survey needs a byte.
 */
async function surveyOf(
  pages: AsyncIterable<ExportPage>,
  format: ExportFormat,
  anonymised: boolean,
  report: (progress: ExportProgress) => void,
): Promise<Survey> {
  const survey: Survey = {
    frames: 0,
    unreadable: 0,
    firstUs: null,
    lastUs: null,
    // JSON writes each frame's own fields and needs no column set; an
    // anonymised export writes no fields at all (`writers/tabular.ts`).
    fields: (format === 'csv' || format === 'xlsx') && !anonymised ? new FieldSurvey() : null,
    // Never gathered for an anonymised file: a table mapping the addresses
    // it just rewrote back to host names is the one thing it must not carry.
    names: format === 'pcapng' && !anonymised ? new NameResolutionMap() : null,
    adapters: [],
  };
  const seen = new Set<string>();
  report({ phase: 'surveying', done: 0, total: 0 });
  for await (const page of pages) {
    for (const p of page.packets) {
      survey.frames += 1;
      if (survey.firstUs === null || p.tsUs < survey.firstUs) survey.firstUs = p.tsUs;
      if (survey.lastUs === null || p.tsUs > survey.lastUs) survey.lastUs = p.tsUs;
      const adapter = p.interfaceName || 'unknown';
      if (!seen.has(adapter)) {
        seen.add(adapter);
        survey.adapters.push(adapter);
      }
      survey.fields?.add(p);
      survey.names?.learnFromPacket(p);
    }
    survey.unreadable = page.unreadable;
    report({ phase: 'surveying', done: page.done, total: page.total });
  }
  return survey;
}

async function writerFor(
  request: ExportRequest,
  survey: Survey | null,
  meta: CaptureMeta | null,
  anonymiser: Anonymiser | null,
  adapters: readonly string[],
  now: () => number,
  xlsxBudget: XlsxBudget | undefined,
): Promise<ExportWriter> {
  const anonymised = anonymiser !== null;
  const tabular = {
    includeRawBytes: request.includeRawBytes,
    meta: meta ?? undefined,
    anonymiser: anonymiser ?? undefined,
    adapters,
  };
  switch (request.format) {
    case 'pcap':
      return new PcapWriter();
    case 'pcapng': {
      // The capture's filter and snaplen were applied to every adapter alike.
      // An imported file's are its own IDBs' - carried back out when they agree,
      // so a file round-trips with the filter and snaplen it came in with.
      const live = request.source.kind === 'live' ? request.source : null;
      const imported = request.source.kind === 'import' && request.source.facts !== undefined
        ? wholeCaptureFacts(request.source.facts)
        : null;
      const interfaces: PcapngInterface[] = (survey?.adapters ?? [])
        .map((name) => ({
          name, description: 'Inwire capture',
          ...(live !== null ? { filter: live.filter ?? null, snaplen: live.snaplen ?? null } : {}),
          ...(imported !== null && imported.filter !== undefined ? { filter: imported.filter } : {}),
          ...(imported !== null && imported.snaplen !== undefined ? { snaplen: imported.snaplen } : {}),
        }));
      return new PcapngWriter({
        interfaces,
        meta: meta ?? undefined,
        os: request.os,
        names: survey?.names
          ? survey.names.entries()
            .filter((e) => e.address.includes('.') || e.address.includes(':'))
            .map((e) => ({ address: e.address, names: [e.name] }))
          : undefined,
        // The counters describe the whole capture, so the writer attaches
        // them only when the file holds exactly one adapter.
        statistics: request.source.kind === 'live'
          ? { received: request.received, drops: request.drops }
          : imported !== null
            ? { received: imported.received, drops: dropsOf(request) }
            : undefined,
        // Never alongside anonymisation: the secrets would open the payload
        // that was just removed.
        secrets: anonymised ? undefined : request.secrets,
        anonymiser: anonymiser ?? undefined,
        adapters,
      });
    }
    case 'csv':
      return new CsvWriter({ ...tabular, fields: survey?.fields?.columns() });
    case 'json':
      return new JsonWriter(tabular);
    case 'xlsx':
      return createXlsxWriter({
        ...tabular,
        fields: survey?.fields?.columns(),
        expectedFrames: survey?.frames ?? 0,
        expectedFieldCells: survey?.fields?.cells ?? 0,
        now: new Date(now()),
        budget: xlsxBudget,
      });
    case 'pdf':
      throw new Error('the PDF has no frame writer');
  }
}
