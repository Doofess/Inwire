/**
 * The history CSV (Task 7A, rulings R7.6 and R7.7): one UTF-8 file, no BOM,
 * CRLF line ends, a `# key: value` preamble and three sections.
 *
 * Counters are written from the bigint, never through `Number`. A bucket with
 * no records is an empty cell: a gap is not zero traffic. Nothing is scaled
 * by a sampling interval; the preamble says what the exporter reported.
 *
 * `exportHistory` owns the sink's end: `close()` on success, `abort()` on a
 * cancel or a failed write, never both.
 */
import type { SaveOutcome } from '../../lib/saveFile';
import type { ByteSink } from '../../lib/saveSink';
import { csvCell } from '../export/writers/csv';
import type { HistoryResult, HistoryTable, QueryFocus } from './types';

export interface ExportOptions { signal?: AbortSignal }

/** Thrown when the signal aborts; the UI tells it apart from a failure. */
export class ExportCancelled extends Error {
  constructor() {
    super('Export cancelled');
    this.name = 'ExportCancelled';
  }
}

const EOL = '\r\n';
/** Rows per `write`; the signal is checked between writes. */
const ROWS_PER_WRITE = 300;
const encoder = new TextEncoder();

const iso = (ms: number): string => new Date(ms).toISOString();

/** A preamble value cannot start a new line. */
const oneLine = (text: string): string => text.replace(/[\r\n\u2028\u2029\u0085]+/g, ' ');

/** Always quoted, like the capture CSV's preamble: the line stays in column A whatever it holds. */
const quotedLine = (text: string): string => `"${text.replace(/"/g, '""')}"`;

const safePart = (text: string): string => text.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');

function focusText(focus: QueryFocus | undefined): string {
  if (!focus) return 'none';
  return focus.kind === 'endpoint'
    ? `endpoint ${oneLine(focus.address)}`
    : `conversation ${oneLine(focus.srcAddr)} -> ${oneLine(focus.dstAddr)}`;
}

/** A file name for the result: no character Windows refuses. */
export function historyCsvName(result: HistoryResult): string {
  const stamp = (ms: number): string => iso(ms).replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const exporter = safePart(result.query.sourceKey) || 'exporter';
  const focus = result.query.focus;
  const suffix = !focus ? ''
    : focus.kind === 'endpoint' ? `-endpoint-${safePart(focus.address) || 'x'}`
      : `-conv-${safePart(focus.srcAddr) || 'x'}-${safePart(focus.dstAddr) || 'x'}`;
  return `inwire-flows-${exporter}-${stamp(result.query.fromMs)}-${stamp(result.query.toMs)}${suffix}.csv`;
}

function preamble(result: HistoryResult): string {
  const lines = [
    `# source: ${result.query.sourceKey}`,
    `# focus: ${focusText(result.query.focus)}`,
    `# from: ${iso(result.query.fromMs)}`,
    `# to: ${iso(result.query.toMs)}`,
    '# time basis: receipt time at this collector (when Inwire received each export), not flow start or end',
    '# counters: as reported by the exporter; not measured on any link',
    result.samplingKnown
      ? '# sampling: the exporter reported its sampling for every record; counters are not scaled by it'
      : '# sampling: unknown for some or all records (the exporter did not say); counters are not scaled',
    `# snapshot: generation ${result.snapshot.generation} through entry ${result.snapshot.throughEntryId}`,
    `# matching records: ${result.matchingRecords}`,
    `# malformed datagrams: ${result.malformed}`,
    `# unsupported datagrams: ${result.unsupported}`,
    `# answered from: ${result.answeredFrom.rollupMinutes} rollup minutes, ${result.answeredFrom.rawMinutes} raw minutes`,
    ...result.gaps.map((g) => `# gap: ${iso(g.fromMs)} - ${iso(g.toMs)}: ${g.reason}`),
  ];
  return lines.map((line) => quotedLine(oneLine(line))).join(EOL) + EOL;
}

/** The rows of a section, as chunks of text; the first carries the heading. */
function* sectionChunks<Row>(
  name: string,
  header: string[],
  rows: readonly Row[],
  cells: (row: Row) => string[],
  unavailable?: string,
): Generator<string> {
  const head = `${EOL}# section: ${name}${EOL}`;
  if (unavailable !== undefined) {
    yield `${head}# not available: ${oneLine(unavailable)}${EOL}`;
    return;
  }
  let text = head + header.join(',') + EOL;
  if (rows.length === 0) yield text;
  for (let at = 0; at < rows.length; at += ROWS_PER_WRITE) {
    for (const row of rows.slice(at, at + ROWS_PER_WRITE)) text += cells(row).map(csvCell).join(',') + EOL;
    yield text;
    text = '';
  }
}

function tableRows<Row>(table: HistoryTable<Row>): { rows: readonly Row[]; unavailable?: string } {
  if (table.status === 'ok') return { rows: table.rows };
  if (table.status === 'evidence-expired') {
    return { rows: [], unavailable: `the evidence for this range expired through ${iso(table.expiredMs)}; totals are kept, the tables are not` };
  }
  return { rows: [], unavailable: table.message };
}

export async function exportHistory(
  result: HistoryResult,
  sink: ByteSink,
  options: ExportOptions = {},
): Promise<SaveOutcome> {
  const endpoints = tableRows(result.endpoints);
  const conversations = tableRows(result.conversations);

  function* chunks(): Generator<string> {
    yield preamble(result);
    yield* sectionChunks('buckets',
      ['from_utc', 'to_utc', 'coverage', 'records', 'reported_octets', 'reported_packets'], result.buckets,
      (b) => [iso(b.fromMs), iso(b.toMs), b.coverage, String(b.records),
        b.reportedOctets === null ? '' : b.reportedOctets.toString(),
        b.reportedPackets === null ? '' : b.reportedPackets.toString()]);
    yield* sectionChunks('endpoints', ['address', 'sent_octets', 'received_octets'], endpoints.rows,
      (e) => [e.address, e.sentOctets.toString(), e.receivedOctets.toString()], endpoints.unavailable);
    yield* sectionChunks('conversations', ['src_addr', 'dst_addr', 'reported_octets', 'reported_packets'], conversations.rows,
      (c) => [c.srcAddr, c.dstAddr, c.reportedOctets.toString(), c.reportedPackets.toString()], conversations.unavailable);
  }

  try {
    for (const text of chunks()) {
      if (options.signal?.aborted) throw new ExportCancelled();
      await sink.write(encoder.encode(text));
    }
    if (options.signal?.aborted) throw new ExportCancelled();
  } catch (error) {
    // A failed abort must not hide the error that caused it.
    await sink.abort().catch(() => undefined);
    throw error;
  }
  return sink.close();
}
