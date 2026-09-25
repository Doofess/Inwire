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

/**
 * The PDF report.
 *
 * Returns a `Blob` instead of calling `doc.save()`, which is what lets the zip
 * toggle wrap it like every other format.
 *
 * The protocol and alert tables come from the same two functions the Excel
 * workbook uses, so the two exports of one capture cannot disagree.
 *
 * A document, not a data format: it carries no packet list, and nothing reads
 * it back in. The frames themselves belong in pcapng, CSV or JSON.
 */

export function buildPdfReport(packets: Packet[], filter: string): Blob {
  const doc = new jsPDF();
  const dateStr = new Date().toLocaleString();

  doc.setProperties({
    title: 'Inwire capture analysis',
    creator: 'Inwire',
    subject: 'Capture analysis report',
  });

  doc.setFontSize(20);
  doc.text('Inwire capture analysis', 14, 22);

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
  const currentY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 15;

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
  } else {
    doc.setFontSize(10);
    doc.text('No active alerts detected in this capture session.', 14, currentY + 7);
  }

  return doc.output('blob');
}
