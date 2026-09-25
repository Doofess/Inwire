import type { Worksheet } from 'exceljs';

import { Packet } from '../types/packet';
import { exportColumns, packetToRow } from './exportSchema';
import { expertItemsFor } from './expertInfo';

/**
 * Writing the tabular export formats.
 *
 * `exceljs` and `fflate` are both reached through `await import(...)`. Together
 * they are about a megabyte, and the overwhelming majority of sessions never
 * open the export panel at all - so they are paid for on the click that needs
 * them rather than on every page load.
 */

// --- CSV ---------------------------------------------------------------------

/**
 * Excel decides a CSV's encoding from its first bytes and, with nothing to go
 * on, falls back to the system codepage - which renders any non-ASCII character
 * in an `info` string as mojibake. Three bytes of BOM is what makes a UTF-8 CSV
 * open as UTF-8, and the importer strips it again.
 */
const UTF8_BOM = '﻿';

function csvCell(value: string | number): string {
  const text = String(value);
  // Quote whenever the value could otherwise change the row's shape. The old
  // implementation quoted only three columns by hand, which left `protocol` and
  // `status` bare - fine for today's values, and a broken file the first time a
  // custom dissector names a protocol with a comma in it.
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function buildCsvText(packets: Packet[], includeRawBytes: boolean): string {
  const columns = exportColumns(includeRawBytes);
  const lines = [columns.map(c => csvCell(c.header)).join(',')];
  for (const packet of packets) {
    lines.push(packetToRow(packet, includeRawBytes).map(csvCell).join(','));
  }
  // CRLF, which is what RFC 4180 specifies and what Excel on Windows expects.
  return UTF8_BOM + lines.join('\r\n') + '\r\n';
}

export function buildCsv(packets: Packet[], includeRawBytes: boolean): Blob {
  return new Blob([buildCsvText(packets, includeRawBytes)], {
    type: 'text/csv;charset=utf-8',
  });
}

// --- Summary tables ----------------------------------------------------------

/**
 * The protocol and alert breakdowns.
 *
 * Shared with the PDF report, which computed both inline before this existed.
 * Two implementations of "count the protocols" is two chances for the Excel
 * workbook and the PDF of the same capture to disagree.
 */
export function protocolBreakdown(packets: Packet[]): { protocol: string; count: number; share: string }[] {
  const counts: Record<string, number> = {};
  for (const p of packets) counts[p.protocol] = (counts[p.protocol] || 0) + 1;
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([protocol, count]) => ({
      protocol,
      count,
      share: packets.length > 0 ? `${((count / packets.length) * 100).toFixed(1)}%` : '0.0%',
    }));
}

export function alertPackets(packets: Packet[]): Packet[] {
  return packets.filter(p => p.status === 'alert' || p.status === 'warning' || p.status === 'retransmit');
}

// --- Excel -------------------------------------------------------------------

export interface XlsxOptions {
  includeRawBytes: boolean;
  /** Shown on the Packets sheet so a filtered export says what it was filtered by. */
  filter?: string;
}

/**
 * Three sheets: the packets themselves, and the protocol hierarchy and alerts
 * the PDF report also carries.
 *
 * Unlike the PDF - which carries no frames at all because it is a document -
 * the Packets sheet carries every packet it was given. A spreadsheet is the
 * format people reach for when they want all of it.
 */
export async function buildXlsx(packets: Packet[], options: XlsxOptions): Promise<Blob> {
  // exceljs resolves to a UMD bundle in the browser and to CommonJS under
  // Node (the assertion script), and the two disagree about whether the
  // namespace arrives as `default`. Accept both rather than guessing.
  const imported = await import('exceljs');
  const ExcelJS = ((imported as unknown as { default?: typeof imported }).default
    ?? imported) as typeof imported;

  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'Inwire';
  workbook.created = new Date();

  const columns = exportColumns(options.includeRawBytes);
  const sheet = workbook.addWorksheet('Packets', {
    views: [{ state: 'frozen', ySplit: 1 }],
  });
  sheet.columns = columns.map(c => ({ header: c.header, key: c.key, width: c.width }));
  for (const packet of packets) sheet.addRow(packetToRow(packet, options.includeRawBytes));
  styleHeader(sheet);
  if (packets.length > 0) {
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
  }

  const protocols = workbook.addWorksheet('Protocols');
  protocols.columns = [
    { header: 'Protocol', key: 'protocol', width: 16 },
    { header: 'Packet Count', key: 'count', width: 14 },
    { header: 'Percentage', key: 'share', width: 14 },
  ];
  for (const row of protocolBreakdown(packets)) protocols.addRow([row.protocol, row.count, row.share]);
  styleHeader(protocols);

  const alerts = workbook.addWorksheet('Alerts');
  alerts.columns = [
    { header: 'No.', key: 'no', width: 8 },
    { header: 'Protocol', key: 'protocol', width: 12 },
    { header: 'Source', key: 'source', width: 24 },
    { header: 'Destination', key: 'destination', width: 24 },
    { header: 'Alert', key: 'alert', width: 48 },
  ];
  for (const p of alertPackets(packets)) {
    alerts.addRow([p.id, p.protocol, p.source, p.destination, expertItemsFor(p)[0]?.summary ?? 'Flagged frame']);
  }
  styleHeader(alerts);

  const summary = workbook.addWorksheet('Capture');
  summary.columns = [
    { header: 'Field', key: 'field', width: 22 },
    { header: 'Value', key: 'value', width: 60 },
  ];
  summary.addRow(['Generated', new Date().toLocaleString()]);
  summary.addRow(['Packets exported', packets.length]);
  // Named outright rather than left implicit: a filtered export that does not
  // say so is indistinguishable from a capture that simply saw less traffic.
  summary.addRow(['Display filter', options.filter?.trim() || '(none - full capture)']);
  summary.addRow(['Raw bytes included', options.includeRawBytes ? 'yes' : 'no']);
  styleHeader(summary);

  const buffer = await workbook.xlsx.writeBuffer();
  return new Blob([buffer as ArrayBuffer], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
}

/** White on the same blue the PDF report's table headers use. */
function styleHeader(sheet: Worksheet): void {
  const header = sheet.getRow(1);
  header.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  header.alignment = { vertical: 'middle' };
  header.eachCell(cell => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF3B82F6' } };
  });
}

// --- Zip ---------------------------------------------------------------------

/**
 * Wraps one already-generated file in a zip container.
 *
 * `zipSync` rather than fflate's worker-backed `zip`: the data is already fully
 * in memory by the time this is called, the existing `generatePcapBinary` is
 * synchronous for the same reason, and this repo has a documented history of
 * losing an afternoon to a library's web worker meeting Vite's pre-bundler
 * (see the maplibre note in `vite.config.ts`). A second of blocked main thread
 * on an explicitly-requested download is the cheaper trade.
 */
export async function zipSingleFile(blob: Blob, filename: string): Promise<Blob> {
  const { zipSync } = await import('fflate');
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const zipped = zipSync({ [filename]: bytes }, { level: 6 });
  return new Blob([zipped as unknown as ArrayBuffer], { type: 'application/zip' });
}
