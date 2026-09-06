// The named export, not the default. jspdf's ESM default is a namespace
// object under Node, so `new jsPDF()` off the default throws "not a
// constructor" outside a bundler - which would leave the report generator
// untestable by the assertion script. The named export is a constructor in
// both environments.
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

import { Packet } from '../../types/packet';
import { alertPackets, protocolBreakdown } from '../../services/tabularWriters';
import { expertItemsFor } from '../../services/expertInfo';
import {
  PDF_INFO_LIMIT,
  PDF_PACKET_LIMIT,
  PDF_PACKET_TABLE_HEAD,
  PDF_REPORT_SUBJECT,
} from '../../services/pdfReportFormat';

/**
 * The PDF report.
 *
 * Lifted out of `ExportImportModal` unchanged in layout, for two reasons. It
 * returns a `Blob` instead of calling `doc.save()`, which is what lets the zip
 * toggle wrap it like every other format; and it stamps the document
 * properties that let `pdfTable.ts` recognise its own output on the way back
 * in, rather than having to infer it from the table headings alone.
 *
 * The protocol and alert tables now come from the same two functions the Excel
 * workbook uses, so the two exports of one capture cannot disagree.
 *
 * Still a document, not a data format: it carries the most recent 100 packets
 * with Info cut at 50 characters. That truncation is why the importer announces
 * the limit rather than presenting a re-imported report as a whole capture.
 */

export function buildPdfReport(packets: Packet[], filter: string): Blob {
  const doc = new jsPDF();
  const dateStr = new Date().toLocaleString();

  // The strong recognition signal for import. Header-text matching still works
  // as a fallback for reports written before this existed.
  doc.setProperties({
    title: 'Inwire Analysis Report',
    creator: 'Inwire',
    subject: PDF_REPORT_SUBJECT,
  });

  doc.setFontSize(20);
  doc.text('Net View Analysis Report', 14, 22);

  doc.setFontSize(10);
  doc.text(`Generated on: ${dateStr}`, 14, 30);
  doc.text(`Total Packets Captured: ${packets.length}`, 14, 35);
  // A filtered report that does not say so is indistinguishable from a quiet
  // network, which is the wrong conclusion to hand someone in a document.
  const filterText = filter.trim();
  doc.text(`Display filter: ${filterText || '(none - full capture)'}`, 14, 40);

  doc.setFontSize(14);
  doc.text('Protocol Hierarchy Statistics', 14, 50);
  autoTable(doc, {
    startY: 55,
    head: [['Protocol', 'Packet Count', 'Percentage']],
    body: protocolBreakdown(packets).map(row => [row.protocol, String(row.count), row.share]),
    theme: 'grid',
    styles: { fontSize: 10 },
    headStyles: { fillColor: [59, 130, 246] },
  });

  const alerts = alertPackets(packets);
  let currentY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 15;

  doc.setFontSize(14);
  doc.text('Active Security Alerts', 14, currentY);

  if (alerts.length > 0) {
    autoTable(doc, {
      startY: currentY + 5,
      head: [['ID', 'Proto', 'Source', 'Destination', 'Alert Details']],
      body: alerts.slice(-50).map(a => [
        a.id.toString(),
        a.protocol,
        a.source,
        a.destination,
        expertItemsFor(a)[0]?.summary || 'Flagged frame',
      ]),
      theme: 'grid',
      styles: { fontSize: 9 },
      headStyles: { fillColor: [239, 68, 68] },
    });
    currentY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 15;
  } else {
    doc.setFontSize(10);
    doc.text('No active alerts detected in this capture session.', 14, currentY + 7);
    currentY += 15;
  }

  doc.setFontSize(14);
  doc.text(`Packet List (Latest ${PDF_PACKET_LIMIT})`, 14, currentY);

  autoTable(doc, {
    startY: currentY + 5,
    // These six headings are also the importer's recognition key - see
    // PACKET_TABLE_HEADER in pdfTable.ts. Changing one means changing both.
    head: [PDF_PACKET_TABLE_HEAD],
    body: packets.slice(-PDF_PACKET_LIMIT).map(p => [
      p.id.toString(),
      p.protocol,
      p.source,
      p.destination,
      `${p.length} bytes`,
      p.info.substring(0, PDF_INFO_LIMIT) + (p.info.length > PDF_INFO_LIMIT ? '...' : ''),
    ]),
    theme: 'grid',
    styles: { fontSize: 8 },
    headStyles: { fillColor: [71, 85, 105] },
    columnStyles: { 5: { cellWidth: 60 } },
  });

  return doc.output('blob');
}
