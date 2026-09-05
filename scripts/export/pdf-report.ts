/**
 * Assertion tests for the PDF report round-trip.
 *
 *   npx tsx scripts/export/pdf-report.ts
 *
 * PDF import is the least reliable thing in the export feature and therefore
 * the thing most worth pinning down. A PDF has no table - it has glyphs at
 * coordinates - so reading one back is always an argument that a particular
 * arrangement of text *was* a table. This script makes that argument testable:
 * it generates a real report with jsPDF, parses it with the real pdfjs, and
 * checks that the frames come back out.
 *
 * It also checks the refusals. Reading a foreign PDF as packets would invent
 * frames that were never on a wire, so "recognises nothing here" is as much a
 * required behaviour as "reads its own output".
 */
import { buildPdfReport } from '../../src/components/export/pdfReport';
import { PDF_PACKET_LIMIT, PDF_INFO_LIMIT } from '../../src/services/pdfReportFormat';
import { Fragment, fragmentsToRows, groupIntoLines, isPacketHeader } from '../../src/services/pdfTableLayout';
import { importRows } from '../../src/services/tabularImport';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- A capture to report on --------------------------------------------------

function buildUdpFrame(seq: number, payloadLength: number): Uint8Array {
  const frame = new Uint8Array(42 + payloadLength);
  const view = new DataView(frame.buffer);
  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
  frame.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6);
  view.setUint16(12, 0x0800);
  frame[14] = 0x45;
  view.setUint16(16, 28 + payloadLength);
  frame[22] = 64;
  frame[23] = 17; // UDP
  frame.set([10, 0, 0, (seq % 250) + 1], 26);
  frame.set([8, 8, 8, 8], 30);
  view.setUint16(34, 40000 + seq);
  view.setUint16(36, 53);
  view.setUint16(38, 8 + payloadLength);
  return frame;
}

function buildCapture(count: number): Packet[] {
  const tcp = new TcpStreamTracker();
  const icmp = new IcmpEchoTracker();
  const quic = new QuicFlowTracker();
  const packets: Packet[] = [];
  for (let i = 0; i < count; i++) {
    const raw = buildUdpFrame(i, 20 + (i % 30));
    const { packet } = decodeRawEthernetPacket(
      raw, i + 1, 1_700_000_000_000 + i * 500, i * 0.5, i === 0 ? 0 : 0.5, raw.length, tcp, icmp, quic,
    );
    packets.push(packet);
  }
  return packets;
}

// --- pdfjs, under Node -------------------------------------------------------

/**
 * Extracts positioned text per page.
 *
 * Uses the `legacy` build and leaves `workerSrc` unset, which makes pdfjs fall
 * back to running the worker in-process. That is the supported way to drive it
 * from Node; the browser path sets a real worker URL in `pdfTable.ts`.
 */
async function extractFragments(bytes: Uint8Array): Promise<Fragment[][]> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
  const task = pdfjs.getDocument({ data: bytes, useSystemFonts: false });
  const doc = await task.promise;
  try {
    const pages: Fragment[][] = [];
    for (let n = 1; n <= doc.numPages; n++) {
      const content = await (await doc.getPage(n)).getTextContent();
      const fragments: Fragment[] = [];
      for (const item of content.items) {
        if (!('str' in item)) continue;
        if (!item.str.trim()) continue;
        fragments.push({ text: item.str, x: item.transform[4], y: item.transform[5] });
      }
      pages.push(fragments);
    }
    return pages;
  } finally {
    await task.destroy();
  }
}

async function main() {
  const capture = buildCapture(12);

  // --- 1. A generated report reads back --------------------------------------
  const report = await buildPdfReport(capture, 'udp').arrayBuffer();
  const pages = await extractFragments(new Uint8Array(report));

  check('report produced pages', pages.length > 0, true);

  const layout = fragmentsToRows(pages);
  check('packet table header was found', layout.sawHeader, true);
  check('header row is the schema-recognised one', layout.rows[0], [
    'id', 'proto', 'source', 'destination', 'length', 'info',
  ]);
  check('every frame came back as a row', layout.rows.length - 1, capture.length);

  const outcome = importRows(layout.rows, 'inwire_report.pdf', 'pdf');
  if (outcome.ok === false) {
    check('report imports', outcome.failure.message, '(an import)');
  } else {
    check('imported frame count', outcome.packets.length, capture.length);
    check('ids survive', outcome.packets.map(p => p.id), capture.map(p => p.id));
    check('sources survive', outcome.packets.map(p => p.source), capture.map(p => p.source));
    check('destinations survive', outcome.packets.map(p => p.destination), capture.map(p => p.destination));
    // "1514 bytes" in the cell, 1514 in the packet.
    check('lengths survive the " bytes" suffix', outcome.packets.map(p => p.length), capture.map(p => p.length));
    check('protocol survives', outcome.packets[0].protocol, capture[0].protocol);
    // A report is a document: no wire bytes, so the import must say so.
    check('report import has no wire bytes', outcome.packets[0].rawBytes.length, 0);
    check(
      'report import warns about the 100-packet limit',
      outcome.notes.some(n => n.includes('100')),
      true,
    );
  }

  // --- 2. The document is a document, and says so ----------------------------
  {
    const many = buildCapture(PDF_PACKET_LIMIT + 40);
    const big = await extractFragments(new Uint8Array(await buildPdfReport(many, '').arrayBuffer()));
    const rows = fragmentsToRows(big);
    // Truncated to the newest 100, and the table spans pages - so this also
    // covers the repeated header being treated as a boundary, not a data row.
    check('long capture is capped at the packet limit', rows.rows.length - 1, PDF_PACKET_LIMIT);
    check('the newest frames are the ones kept', rows.rows[1][0], String(many.length - PDF_PACKET_LIMIT + 1));

    const back = importRows(rows.rows, 'big.pdf', 'pdf');
    check('capped report still imports', back.ok === true ? back.packets.length : 0, PDF_PACKET_LIMIT);
  }

  // --- 3. Info is truncated, and that is not treated as corruption -----------
  {
    const wordy = buildCapture(3);
    wordy.forEach(p => {
      p.info = 'Standard query 0xabcd A a-very-long-hostname-that-will-be-cut.example.com OPT';
    });
    const rows = fragmentsToRows(
      await extractFragments(new Uint8Array(await buildPdfReport(wordy, '').arrayBuffer())),
    );
    const back = importRows(rows.rows, 'wordy.pdf', 'pdf');
    if (back.ok === false) {
      check('wordy report imports', back.failure.message, '(an import)');
    } else {
      check('all wordy frames import', back.packets.length, 3);
      check('info is the truncated form', back.packets[0].info.endsWith('...'), true);
      check('info length matches the writer limit', back.packets[0].info.length, PDF_INFO_LIMIT + 3);
    }
  }

  // --- 4. Refusals -----------------------------------------------------------
  {
    // A PDF that is not ours: no packet-table header anywhere.
    const { jsPDF } = await import('jspdf');
    const foreign = new jsPDF();
    foreign.text('Quarterly Revenue Report', 14, 22);
    foreign.text('Region       Revenue      Growth', 14, 40);
    foreign.text('North        120000       4.2%', 14, 48);
    const foreignPages = await extractFragments(new Uint8Array(foreign.output('arraybuffer')));
    const foreignLayout = fragmentsToRows(foreignPages);
    check('a foreign PDF yields no header', foreignLayout.sawHeader, false);
    check('a foreign PDF yields no rows', foreignLayout.rows.length, 0);
  }
  {
    // The Alerts table shares four of six headings with the packet table. It
    // must not be mistaken for it, or alerts import as packets.
    const alertsHeader = groupIntoLines([
      { text: 'ID', x: 14, y: 100 },
      { text: 'Proto', x: 40, y: 100 },
      { text: 'Source', x: 70, y: 100 },
      { text: 'Destination', x: 110, y: 100 },
      { text: 'Alert Details', x: 150, y: 100 },
    ])[0];
    check('the Alerts header is not the packet header', isPacketHeader(alertsHeader), false);
  }
  {
    // An empty capture: a valid report with a valid header and no data rows.
    const empty = fragmentsToRows(
      await extractFragments(new Uint8Array(await buildPdfReport([], '').arrayBuffer())),
    );
    check('an empty report finds its header', empty.sawHeader, true);
    check('an empty report yields only the header row', empty.rows.length, 1);
  }

  // --- 5. Wrapped Info cells rejoin their own row ----------------------------
  {
    // Hand-built rather than generated, because forcing a wrap out of the real
    // table generator is fragile. A continuation line has no first column.
    const rows = fragmentsToRows([[
      { text: 'ID', x: 14, y: 200 },
      { text: 'Proto', x: 40, y: 200 },
      { text: 'Source', x: 70, y: 200 },
      { text: 'Destination', x: 110, y: 200 },
      { text: 'Length', x: 150, y: 200 },
      { text: 'Info', x: 175, y: 200 },

      { text: '7', x: 14, y: 190 },
      { text: 'TCP', x: 40, y: 190 },
      { text: '10.0.0.1', x: 70, y: 190 },
      { text: '10.0.0.2', x: 110, y: 190 },
      { text: '1514 bytes', x: 150, y: 190 },
      { text: 'first half of the', x: 175, y: 190 },
      { text: 'second half', x: 175, y: 184 },
    ]]);
    check('wrapped info rejoins one row', rows.rows.length - 1, 1);
    check('wrapped info is concatenated', rows.rows[1][5], 'first half of the second half');
  }

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All PDF report assertions passed.');
  process.exit(0);
}

main().catch(err => {
  console.log(`FAIL  threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
