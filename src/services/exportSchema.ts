import { Packet, ProtocolType, PacketStatus } from '../types/packet';
import type { StoredFrame } from './sessionRestore';
import { expertItemsFor } from './expertInfo';

/**
 * The one description of Inwire's tabular packet format.
 *
 * CSV, Excel and the importer all read this file, which is the point: a column
 * added to a writer but missed by the reader is the failure mode a shared
 * schema exists to make impossible. The PDF report is deliberately NOT built
 * from it - a report is a document with its own narrower columns, and pretending
 * otherwise would drag `RawBytes` into a printed table.
 *
 * What a row cannot carry is the dissection. `Packet.layers`, `fields` and
 * `anomalies` all come back out of the wire bytes, so a row either carries
 * those bytes - the opt-in `RawBytes` column - or it imports as a summary with
 * an honestly empty hex pane. See `rowsToFrames`.
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

export interface ColumnSpec {
  key: ColumnKey;
  header: string;
  /** Character width, used for Excel column sizing. */
  width: number;
}

/**
 * Column order, shared by CSV and Excel.
 *
 * `Epoch (ms)` is here because `Time(s)` alone is not enough: a relative time
 * says when a frame arrived within its capture, not when the capture happened.
 * A file carrying only relative times re-imports onto a timeline anchored at
 * the moment of import, which is a different capture wearing the same shape.
 */
export const EXPORT_COLUMNS: ColumnSpec[] = [
  { key: 'no', header: 'No.', width: 8 },
  { key: 'time', header: 'Time(s)', width: 14 },
  { key: 'epoch', header: 'Epoch (ms)', width: 16 },
  { key: 'source', header: 'Source', width: 24 },
  { key: 'destination', header: 'Destination', width: 24 },
  { key: 'protocol', header: 'Protocol', width: 12 },
  { key: 'length', header: 'Length', width: 9 },
  { key: 'info', header: 'Info', width: 60 },
  { key: 'status', header: 'Status', width: 11 },
  { key: 'expert', header: 'Expert', width: 30 },
];

/** Appended only when the user opts in; see `packetToRow`. */
export const RAW_BYTES_COLUMN: ColumnSpec = {
  key: 'rawBytes',
  header: 'RawBytes (Base64)',
  width: 48,
};

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

export function packetToRow(p: Packet, includeRawBytes: boolean): (string | number)[] {
  const row: (string | number)[] = [
    p.id,
    p.relativeTime.toFixed(6),
    p.tsUs / 1000,
    guardFormula(p.source),
    guardFormula(p.destination),
    guardFormula(displayProtocol(p)),
    p.length,
    guardFormula(p.info),
    p.status,
    // Every finding on the frame, not the two hard-coded anomalies this used
    // to carry - the column is wider than it was, not narrower.
    guardFormula(expertItemsFor(p).map((i) => i.summary).join('; ')),
  ];
  if (includeRawBytes) row.push(p.rawBytes.length > 0 ? toBase64(p.rawBytes) : '');
  return row;
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
  const match = /-?\d+(?:\.\d+)?/.exec(text);
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

  const header = rows[0];
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

  const body = rows.slice(1).filter(row => row.some(c => c.trim().length > 0));
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
