import type { ColorRule, Packet, ProtocolType, PacketStatus } from '../types/packet';
import type { StoredFrame } from './sessionRestore';
import { expertItemsFor } from './expertInfo';
import { DIRECTION_LABEL, Direction, directionOf } from './direction';
import { isoMicros } from './export/captureMeta';
import { LAYERS, fieldDef } from './dissect/fieldRegistry';

/**
 * The one description of Inwire's tabular packet format.
 *
 * CSV, Excel and the importer all read this file, which is the point: a column
 * added to a writer but missed by the reader is the failure mode a shared
 * schema exists to make impossible. The PDF report is deliberately NOT built
 * from it - a report is a document of statistics, not a table of frames.
 *
 * What a row cannot give back is the dissection. An export now writes every
 * dissected field as a column of its own (`export/fieldColumns.ts`), for the
 * reader - but the importer does not read them back, because a field bag
 * rebuilt from cells would be a second dissector that disagrees with the
 * first. `Packet.layers`, `fields` and the findings come out of the wire
 * bytes, so a row either carries those bytes - the opt-in `RawBytes` column -
 * or it imports as a summary with an honestly empty hex pane. See
 * `rowsToFrames`.
 */

/**
 * The columns the importer recognises. Every other column in a file - ours or
 * anyone's - is carried past without being read.
 */
export type ColumnKey =
  | 'no'
  | 'time'
  | 'epoch'
  | 'source'
  | 'destination'
  | 'protocol'
  | 'length'
  | 'info'
  | 'status'
  | 'expert'
  | 'rawBytes';

/** Every standard column an export writes: the importable ones and seven more. */
export type ExportColumnKey =
  | ColumnKey
  | 'arrival'
  | 'interface'
  | 'direction'
  | 'stream'
  | 'stack'
  | 'colourRule'
  | 'analysisFlags';

/**
 * What a column holds, which decides how each format writes it.
 *
 * CSV and JSON are text, and every kind has one text form. Excel is not: a
 * time written as the string `"0.250000"` sorts as text, sums to nothing and
 * cannot be charted, which is what the old workbook did. So a kind carries the
 * number format Excel shows it in, and the cell holds the number.
 */
export type ColumnKind =
  /** A whole number: frame number, length, stream. */
  | 'integer'
  /** Seconds since the capture began. */
  | 'seconds'
  /** Epoch milliseconds, fractional to the microsecond. */
  | 'epochMs'
  /** Epoch microseconds, shown as a UTC date and time. */
  | 'datetime'
  | 'text'
  /** Frame bytes, base64. */
  | 'base64';

export interface ColumnSpec {
  key: ExportColumnKey;
  header: string;
  /** Character width, used for Excel column sizing. */
  width: number;
  kind: ColumnKind;
}

/**
 * Column order, shared by CSV and Excel.
 *
 * The first ten are the order this format has always had, so a reader who
 * knows the file finds the same thing in the same place. The rest are what the
 * packet list knows about a frame beyond its summary.
 *
 * `Epoch (ms)` is here because `Time(s)` alone is not enough: a relative time
 * says when a frame arrived within its capture, not when the capture happened.
 * A file carrying only relative times re-imports onto a timeline anchored at
 * the moment of import, which is a different capture wearing the same shape.
 * `Arrival (UTC)` is the same instant for a person rather than a program: a
 * date Excel can read, and ISO-8601 to the microsecond in CSV.
 */
export const EXPORT_COLUMNS: ColumnSpec[] = [
  { key: 'no', header: 'No.', width: 10, kind: 'integer' },
  { key: 'time', header: 'Time(s)', width: 12, kind: 'seconds' },
  { key: 'epoch', header: 'Epoch (ms)', width: 18, kind: 'epochMs' },
  { key: 'arrival', header: 'Arrival (UTC)', width: 24, kind: 'datetime' },
  { key: 'source', header: 'Source', width: 40, kind: 'text' },
  { key: 'destination', header: 'Destination', width: 40, kind: 'text' },
  { key: 'protocol', header: 'Protocol', width: 11, kind: 'text' },
  { key: 'length', header: 'Length', width: 9, kind: 'integer' },
  { key: 'info', header: 'Info', width: 64, kind: 'text' },
  { key: 'status', header: 'Status', width: 10, kind: 'text' },
  { key: 'expert', header: 'Expert', width: 32, kind: 'text' },
  { key: 'interface', header: 'Interface', width: 16, kind: 'text' },
  { key: 'direction', header: 'Direction', width: 12, kind: 'text' },
  { key: 'stream', header: 'Stream', width: 9, kind: 'integer' },
  { key: 'stack', header: 'Protocol stack', width: 30, kind: 'text' },
  { key: 'colourRule', header: 'Colour rule', width: 20, kind: 'text' },
  { key: 'analysisFlags', header: 'Analysis flags', width: 24, kind: 'text' },
];

/**
 * Appended only when the user opts in, after the field columns - it is the
 * widest column by far, and a reader scrolling right to the fields should not
 * have to cross it.
 */
export const RAW_BYTES_COLUMN: ColumnSpec = {
  key: 'rawBytes',
  header: 'RawBytes (Base64)',
  width: 48,
  kind: 'base64',
};

/** The standard columns, without the field columns that sit between. */
export function exportColumns(includeRawBytes: boolean): ColumnSpec[] {
  return includeRawBytes ? [...EXPORT_COLUMNS, RAW_BYTES_COLUMN] : EXPORT_COLUMNS;
}

// --- Base64 ------------------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Hand-rolled rather than `btoa`/`Buffer`.
 *
 * This module is imported by the browser app and by the assertion script under
 * `scripts/`, and the two environments disagree about which of those globals
 * exists and whether using it prints a deprecation warning. Twenty lines buys
 * one implementation that is identical in both and needs no environment test.
 */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + '==';
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '=';
  }
  return out;
}

/** Returns null for anything that is not well-formed base64. */
export function fromBase64(text: string): Uint8Array | null {
  const clean = text.replace(/\s+/g, '');
  if (clean.length === 0) return null;
  if (clean.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;

  const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((clean.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (B64.indexOf(clean[i]) << 18) |
      (B64.indexOf(clean[i + 1]) << 12) |
      ((clean[i + 2] === '=' ? 0 : B64.indexOf(clean[i + 2])) << 6) |
      (clean[i + 3] === '=' ? 0 : B64.indexOf(clean[i + 3]));
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

// --- Writing -----------------------------------------------------------------

/**
 * The Protocol cell carries what the packet list shows - `protocolLabel` when a
 * dissector set one, else the coarse `protocol`. That is the useful value for a
 * spreadsheet or a SIEM, and it is what a reader expects to see next to the
 * frame they are looking at on screen.
 *
 * It does mean a metadata-only re-import of "TLSv1.2" cannot recover the coarse
 * `TCP` underneath it - see `coerceProtocol`. Recovering that is what the
 * RawBytes column is for; with bytes present the dissector decides and this
 * cell is never read back.
 */
export function displayProtocol(p: Packet): string {
  return p.protocolLabel ?? p.protocol;
}

/**
 * Formula injection, which a packet analyzer has to take seriously.
 *
 * Excel and Sheets execute a cell beginning `=`, `+`, `-` or `@` as a formula
 * when opening a CSV, and several of our columns are not our text: `info`
 * carries DNS query names, HTTP hosts and TLS SNI values straight off the
 * wire. A hostile name of `=cmd|'/c calc'!A1` is a well-known way to turn
 * "someone exported their capture" into code execution on the analyst's
 * machine, and the untrusted-input case is exactly the one this app exists for.
 *
 * The mitigation is the standard one - a leading apostrophe, which spreadsheets
 * read as "this is text" and do not display. `unguardFormula` removes it again
 * on import, so the round-trip is lossless rather than accumulating quotes.
 */
const FORMULA_LEAD = /^[=+\-@\t\r]/;

export function guardFormula(value: string): string {
  return FORMULA_LEAD.test(value) ? `'${value}` : value;
}

export function unguardFormula(value: string): string {
  return value.startsWith("'") && FORMULA_LEAD.test(value.slice(1)) ? value.slice(1) : value;
}

/** One standard cell before a format decides how to write it. `null` is an empty cell. */
export type StandardValue = string | number | null;

/**
 * A frame's standard columns, in `exportColumns` order, as typed values.
 *
 * Numbers stay numbers - each format decides how to spell them - and text is
 * the frame's own, unguarded: JSON writes it verbatim, and the two formats a
 * spreadsheet opens guard it as they write (`standardText`, the workbook).
 * A fact the frame does not have is `null`: an empty cell, never a zero or a
 * word standing in for "none". An unattributed frame has no stream rather than
 * stream 0, and a frame nobody could place has no direction rather than
 * "Unknown".
 *
 * `rule` is the colour rule the frame matched (`export/ruleMatcher.ts`), asked
 * by the caller because an anonymised frame can no longer be matched.
 */
export function standardValues(
  p: Packet,
  rule: ColorRule | null,
  includeRawBytes: boolean,
): StandardValue[] {
  const text = (value: string | undefined): StandardValue => (value ? value : null);
  const direction = directionOf(p.direction);
  const row: StandardValue[] = [
    p.id,
    p.relativeTime,
    p.tsUs / 1000,
    p.tsUs,
    p.source,
    p.destination,
    displayProtocol(p),
    p.length,
    p.info,
    p.status,
    // Every finding on the frame, not the two hard-coded anomalies this used
    // to carry - the column is wider than it was, not narrower.
    text(expertItemsFor(p).map((i) => i.summary).join('; ')),
    text(p.interfaceName),
    direction === Direction.Unknown ? null : DIRECTION_LABEL[direction],
    p.streamId ?? null,
    text(p.frameProtocols?.join(':')),
    text(rule?.name),
    text(p.analysisFlags?.join(', ')),
  ];
  if (includeRawBytes) row.push(p.rawBytes.length > 0 ? toBase64(p.rawBytes) : null);
  return row;
}

/**
 * A standard value as text, the one spelling CSV writes and the importer reads.
 *
 * Time keeps its six places, as it always has; epoch milliseconds are the
 * shortest string that reads back as the same double, which is exact to the
 * microsecond; a date is ISO-8601 in UTC with all six digits. Text is
 * formula-guarded - base64 included, which can begin with `+`.
 */
export function standardText(kind: ColumnKind, value: StandardValue): string {
  if (value === null) return '';
  if (typeof value === 'string') return guardFormula(value);
  switch (kind) {
    case 'seconds': return value.toFixed(6);
    case 'datetime': return isoMicros(value);
    default: return String(value);
  }
}

/** Bytes the RawBytes column will add, for the size estimate in the UI. */
export function estimateRawBytesSize(packets: Packet[]): number {
  let total = 0;
  for (const p of packets) total += Math.ceil(p.rawBytes.length / 3) * 4;
  return total;
}

// --- Reading -----------------------------------------------------------------

export type ImportFailure =
  | { kind: 'unreadable'; message: string }
  | { kind: 'no-table'; message: string }
  | { kind: 'missing-columns'; message: string; found: string[]; missing: ColumnKey[] }
  | { kind: 'no-rows'; message: string; rejected: number }
  | { kind: 'too-large'; message: string; rows: number };

/**
 * Header spellings this importer accepts, by canonical key.
 *
 * Keys are normalised - lowercased with every non-alphanumeric character
 * removed - so `Time(s)`, `time_s` and `TIME S` all arrive as `times`. The list
 * is deliberately generous: the whole point of importing a foreign spreadsheet
 * is that someone else named the columns.
 */
const HEADER_SYNONYMS: Record<ColumnKey, string[]> = {
  no: ['no', 'num', 'number', 'frame', 'frameno', 'framenumber', 'id', 'packet', 'packetno', 'index', 'seq'],
  time: ['time', 'times', 'timesec', 'timeseconds', 'seconds', 'relativetime', 'reltime', 'timerelative'],
  epoch: ['epoch', 'epochms', 'epochtime', 'absolutetime', 'abstime', 'timestamp', 'datetime', 'utc'],
  source: ['source', 'src', 'srcip', 'sourceip', 'sourceaddress', 'srcaddr', 'sourceaddr', 'from'],
  destination: ['destination', 'dest', 'dst', 'dstip', 'destip', 'destinationip', 'destinationaddress', 'dstaddr', 'to'],
  protocol: ['protocol', 'proto', 'protocolname', 'prot'],
  length: ['length', 'len', 'bytes', 'size', 'framelength', 'framelen', 'packetlength', 'bytecount', 'lengthbytes'],
  info: ['info', 'information', 'summary', 'details', 'description', 'message'],
  status: ['status', 'state', 'verdict'],
  // The old spellings stay in the alias list: this column was called
  // "Anomaly" until the anomaly model was replaced by expert categories, and a
  // file exported by an earlier build has to keep importing.
  expert: ['expert', 'expertinfo', 'findings', 'finding',
    'anomaly', 'anomalies', 'alert', 'alerts', 'anomalydetails', 'alertdetails'],
  rawBytes: ['rawbytes', 'rawbytesbase64', 'raw', 'rawdata', 'bytesbase64', 'base64', 'packetbytes', 'data'],
};

function normalizeHeader(cellText: string): string {
  const trimmed = cellText.trim();
  // '#' survives no normalisation that strips punctuation, and it is a common
  // spelling of the frame-number column, so it is resolved before the strip.
  if (trimmed === '#') return 'no';
  return trimmed.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * A Wireshark field name - `frame.len`, `ip.src`, `tcp.flags.syn`.
 *
 * An export writes one column per dissected field under exactly that name, and
 * the normalisation below strips the dot: `frame.len` becomes `framelen`, which
 * is a spelling of Length, and `frame.number` becomes `framenumber`, a spelling
 * of No. First match wins, and our own standard columns come first, so our own
 * files were safe by order alone - a foreign file with the field columns first,
 * or an export by a tool that writes only fields, was not.
 *
 * A header is a field when the registry knows it, or when it is dotted and
 * its first part is a protocol layer token, lowercase as Wireshark spells
 * them - which is what catches `frame.len` and `frame.number`, neither of
 * which this build registers. A foreign `Src.IP` or `Dst.Port` is neither,
 * and is still read as the column it names.
 */
function isFieldName(header: string): boolean {
  if (fieldDef(header) !== undefined) return true;
  const dot = header.indexOf('.');
  return dot > 0 && dot < header.length - 1 && LAYER_TOKENS.has(header.slice(0, dot));
}

const LAYER_TOKENS: ReadonlySet<string> = new Set<string>(LAYERS);

/**
 * Maps a file's header cells onto column keys, first match winning.
 *
 * Returns column *indices*, not values, so a file may carry unrelated columns
 * in any order and between the ones we recognise.
 */
export function matchHeaders(header: string[]): Partial<Record<ColumnKey, number>> {
  const lookup = new Map<string, ColumnKey>();
  for (const [key, spellings] of Object.entries(HEADER_SYNONYMS) as [ColumnKey, string[]][]) {
    for (const spelling of spellings) if (!lookup.has(spelling)) lookup.set(spelling, key);
  }

  const found: Partial<Record<ColumnKey, number>> = {};
  header.forEach((headerCell, index) => {
    if (isFieldName(headerCell.trim())) return;
    const key = lookup.get(normalizeHeader(headerCell));
    if (key !== undefined && found[key] === undefined) found[key] = index;
  });
  return found;
}

/**
 * The four columns that make a table of rows a table of *packets*.
 *
 * `no` and `time` are not among them because both can be synthesised from row
 * order without inventing anything; an address, a protocol and a length cannot.
 */
export const REQUIRED_COLUMNS: ColumnKey[] = ['source', 'destination', 'protocol', 'length'];

/**
 * The ceiling on an imported table.
 *
 * Deliberately far above the 10,000-frame limit the pcap extractors use: a
 * spreadsheet exported from a full buffer must be able to come back, and a row
 * costs far less to hold than a decoded frame. It is a standalone ceiling now -
 * it used to be described as matching App's `PACKET_BUFFER_CAP`, which no
 * longer exists, because the buffer is bounded by bytes rather than frames.
 */
export const MAX_IMPORT_ROWS = 50000;

const PROTOCOL_TYPES = new Set<string>([
  'HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'TLS', 'ICMP', 'ARP', 'MQTT', 'QUIC', 'SSH', 'CUSTOM',
]);

const PACKET_STATUSES = new Set<string>(['ok', 'warning', 'alert', 'retransmit', 'dropped']);

/**
 * Splits a cell into the coarse `ProtocolType` filters match on and the free
 * label the Protocol column shows.
 *
 * An unrecognised name becomes CUSTOM rather than being cast blindly into the
 * union, which is what would otherwise put `"TLSv1.2"` into a field every color
 * rule and display filter believes is one of twelve values.
 */
function coerceProtocol(raw: string): { protocol: ProtocolType; protocolLabel?: string } {
  const text = raw.trim();
  const upper = text.toUpperCase();
  if (PROTOCOL_TYPES.has(upper)) return { protocol: upper as ProtocolType };
  return { protocol: 'CUSTOM', protocolLabel: text || undefined };
}

/** Pulls the first number out of a cell, so `1514`, `1514 bytes` and ` 1514 ` all read. */
function parseNumber(text: string | undefined): number | null {
  if (text === undefined) return null;
  // Exponents included: a JSON number below 1e-6 is written `5e-7`, and a
  // CSV Excel has re-saved writes a large epoch as `1.7588E+12` - reading the
  // mantissa alone would make those 5 and 1.7588.
  const match = /-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?/.exec(text);
  if (!match) return null;
  const value = Number(match[0]);
  return Number.isFinite(value) ? value : null;
}

export interface RowsToFramesOk {
  ok: true;
  frames: StoredFrame[];
  /** Rows that matched the header but could not be read as a packet. */
  rejected: number;
  /** True when at least one row carried decodable wire bytes. */
  hadRawBytes: boolean;
  /** Rows whose RawBytes cell was present but not valid base64. */
  badRawBytes: number;
  /** True when times were anchored at import because the file had no epoch column. */
  synthesizedEpoch: boolean;
  /** Non-empty Expert cells, which a row cannot restore. See below. */
  droppedExpert: number;
}

/**
 * A line of the metadata preamble an export writes above its header:
 * `# Frames exported: 12,858`. One cell, `#`, a key, a colon.
 *
 * A bare `#` does not match - it is a common spelling of the No. header - and
 * nor does a row with anything in its other cells, which is a header or data.
 */
const PREAMBLE_LINE = /^#\s*[^:]+:/;

function isPreambleRow(row: string[]): boolean {
  if (row.length === 0) return true;
  for (let i = 1; i < row.length; i++) if (row[i].trim() !== '') return false;
  const first = row[0].trim();
  return first === '' || PREAMBLE_LINE.test(first);
}

/**
 * The table under the preamble: leading `# key: value` lines, and any blank
 * rows among them, dropped. A file with no preamble comes back unchanged.
 */
export function stripPreamble(rows: string[][]): string[][] {
  let start = 0;
  while (start < rows.length && isPreambleRow(rows[start])) start++;
  return start === 0 ? rows : rows.slice(start);
}

/**
 * Turns a parsed table into frames the existing restore path can decode.
 *
 * `StoredFrame` is reused rather than a new intermediate type because
 * `restoreBatch` already routes frames with bytes through
 * `decodeRawEthernetPacket` and frames without through `buildFallbackPacket`.
 * That is exactly the split a tabular import needs, and going through it means
 * an imported frame is built by the same code as a live one - the rule
 * `sessionRestore.ts` states, which this module has no business restating
 * differently.
 *
 * Expert findings are counted and dropped, never rebuilt. A cell holds the
 * findings' *summaries* joined together; which category each belongs to, and
 * the tree row each was raised on, are not in the file - and a frame painted
 * Broken because the importer matched on a word would be worse than a frame
 * painted nothing. Rows carrying wire bytes get their findings back from
 * dissection, as they should.
 */
export function rowsToFrames(
  rows: string[][],
  sourceLabel: string,
): { ok: false; failure: ImportFailure } | RowsToFramesOk {
  if (rows.length === 0) {
    return {
      ok: false,
      failure: { kind: 'no-table', message: 'The file contains no table of any kind.' },
    };
  }

  const table = stripPreamble(rows);
  if (table.length === 0) {
    return {
      ok: false,
      failure: { kind: 'no-table', message: 'The file contains no table of any kind.' },
    };
  }
  const header = table[0];
  const columns = matchHeaders(header);
  const missing = REQUIRED_COLUMNS.filter(key => columns[key] === undefined);
  if (missing.length > 0) {
    return {
      ok: false,
      failure: {
        kind: 'missing-columns',
        message:
          'This table does not look like packet data. It is missing '
          + `${missing.length === 1 ? 'a required column' : 'required columns'}: `
          + `${missing.join(', ')}.`,
        found: header.map(h => h.trim()).filter(Boolean),
        missing,
      },
    };
  }

  const body = table.slice(1).filter(row => row.some(c => c.trim().length > 0));
  if (body.length === 0) {
    return {
      ok: false,
      failure: {
        kind: 'no-rows',
        message: 'The columns look right, but the file has no data rows underneath them.',
        rejected: 0,
      },
    };
  }
  if (body.length > MAX_IMPORT_ROWS) {
    return {
      ok: false,
      failure: {
        kind: 'too-large',
        message:
          `This file holds ${body.length.toLocaleString()} rows, more than the `
          + `${MAX_IMPORT_ROWS.toLocaleString()}-packet buffer can hold.`,
        rows: body.length,
      },
    };
  }

  const cellAt = (row: string[], key: ColumnKey): string | undefined => {
    const index = columns[key];
    if (index === undefined) return undefined;
    const raw = row[index];
    return raw === undefined ? undefined : unguardFormula(raw);
  };

  // Anchor for files that carry no epoch column. Relative times are preserved
  // exactly; only the absolute origin is unknown, and it is placed at import
  // rather than at 1970 so the capture reads as a recent one on every clock.
  const importedAt = Date.now();

  const frames: StoredFrame[] = [];
  let rejected = 0;
  let hadRawBytes = false;
  let badRawBytes = 0;
  let synthesizedEpoch = false;
  let droppedExpert = 0;
  let previousRelative: number | null = null;

  body.forEach((row, index) => {
    const source = (cellAt(row, 'source') ?? '').trim();
    const destination = (cellAt(row, 'destination') ?? '').trim();
    const length = parseNumber(cellAt(row, 'length'));
    const protocolCell = (cellAt(row, 'protocol') ?? '').trim();

    if (!source || !destination || !protocolCell || length === null || length < 0) {
      rejected++;
      return;
    }

    const id = parseNumber(cellAt(row, 'no')) ?? index + 1;
    const relativeTime = parseNumber(cellAt(row, 'time')) ?? index / 1000;

    const epoch = parseNumber(cellAt(row, 'epoch'));
    let timestamp: number;
    if (epoch !== null && epoch > 0) {
      timestamp = epoch;
    } else {
      timestamp = importedAt + relativeTime * 1000;
      synthesizedEpoch = true;
    }

    const timeDelta = previousRelative === null ? 0 : Math.max(0, relativeTime - previousRelative);
    previousRelative = relativeTime;

    if ((cellAt(row, 'expert') ?? '').trim()) droppedExpert++;

    const frame: StoredFrame = {
      id: Math.round(id),
      timestamp,
      tsUs: Math.round(timestamp * 1000),
      relativeTime,
      timeDelta,
      length: Math.round(length),
      interfaceName: sourceLabel,
    };

    const rawCell = (cellAt(row, 'rawBytes') ?? '').trim();
    if (rawCell) {
      const decoded = fromBase64(rawCell);
      if (decoded && decoded.length > 0) {
        frame.raw = decoded;
        hadRawBytes = true;
      } else {
        badRawBytes++;
      }
    }

    if (!frame.raw) {
      const statusCell = (cellAt(row, 'status') ?? '').trim().toLowerCase();
      frame.fallback = {
        source,
        destination,
        info: (cellAt(row, 'info') ?? '').trim() || 'Imported frame',
        status: PACKET_STATUSES.has(statusCell) ? (statusCell as PacketStatus) : undefined,
        ...coerceProtocol(protocolCell),
      };
    }

    frames.push(frame);
  });

  if (frames.length === 0) {
    return {
      ok: false,
      failure: {
        kind: 'no-rows',
        message:
          `All ${body.length.toLocaleString()} rows were rejected: none carried a source, a `
          + 'destination, a protocol and a numeric length.',
        rejected,
      },
    };
  }

  return { ok: true, frames, rejected, hadRawBytes, badRawBytes, synthesizedEpoch, droppedExpert };
}
