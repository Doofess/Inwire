/**
 * Assertion tests for the tabular export/import round-trip.
 *
 *   npx tsx scripts/export/tabular.ts
 *
 * Two things are being defended here.
 *
 * The first is the round-trip: a capture exported with raw bytes and imported
 * again must come back byte-identical, because that is the entire promise of
 * the "Include raw packet bytes" toggle. Without it a spreadsheet is a summary
 * and everyone should know it; with it, anything less than exact is a lie.
 *
 * The second is the evaluator - the thing that decides a file is NOT packet
 * data. That half has no visible success case, so it is the half that rots
 * quietly: a loosened header match or a swallowed parse error turns "this
 * spreadsheet isn't a capture" into a buffer full of invented frames. Every
 * failure kind therefore has a test that names it.
 */
import {
  fromBase64,
  matchHeaders,
  rowsToFrames,
  toBase64,
  unguardFormula,
  MAX_IMPORT_ROWS,
} from '../../src/services/exportSchema';
import { importRows } from '../../src/services/tabularImport';
import { parseDelimited } from '../../src/services/tabularReaders';
import { buildCsvText } from '../../src/services/tabularWriters';
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

// --- A capture to round-trip -------------------------------------------------

/**
 * A real Ethernet/IPv4/TCP frame, built byte by byte.
 *
 * Synthetic rather than a committed .pcap so this runs on any machine, and
 * decoded through `decodeRawEthernetPacket` - the same function live capture,
 * pcap import and session restore use - so the packets under test are the ones
 * the app actually handles rather than hand-written literals that can drift
 * from the real shape.
 */
function buildTcpFrame(seq: number, payload: string): Uint8Array {
  const body = new TextEncoder().encode(payload);
  const frame = new Uint8Array(54 + body.length);
  const view = new DataView(frame.buffer);

  frame.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0); // dst MAC
  frame.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6); // src MAC
  view.setUint16(12, 0x0800); // IPv4

  frame[14] = 0x45; // version 4, IHL 5
  view.setUint16(16, 40 + body.length); // total length
  view.setUint16(18, 0x1234); // id
  frame[22] = 64; // TTL
  frame[23] = 6; // TCP
  frame.set([192, 168, 1, 10], 26);
  frame.set([93, 184, 216, 34], 30);

  view.setUint16(34, 51000 + seq); // src port
  view.setUint16(36, 443); // dst port
  view.setUint32(38, 1000 + seq * 100); // seq
  view.setUint32(42, 2000); // ack
  frame[46] = 0x50; // data offset 5
  frame[47] = 0x18; // PSH|ACK
  view.setUint16(48, 8192); // window
  frame.set(body, 54);
  return frame;
}

function buildCapture(count: number): Packet[] {
  const trackers = {
    tcp: new TcpStreamTracker(),
    icmp: new IcmpEchoTracker(),
    quic: new QuicFlowTracker(),
  };
  const packets: Packet[] = [];
  for (let i = 0; i < count; i++) {
    const raw = buildTcpFrame(i, `payload ${i}`);
    const { packet } = decodeRawEthernetPacket(
      raw,
      i + 1,
      1_700_000_000_000 + i * 250,
      i * 0.25,
      i === 0 ? 0 : 0.25,
      raw.length,
      trackers.tcp,
      trackers.icmp,
      trackers.quic,
    );
    packets.push(packet);
  }
  return packets;
}

const capture = buildCapture(12);
check('fixture decoded as TCP', capture[0].protocol, 'TCP');
check('fixture carries wire bytes', capture[0].rawBytes.length > 0, true);

// --- Base64 ------------------------------------------------------------------
{
  // Every remainder class, since the padding branches are where a hand-rolled
  // encoder goes wrong.
  let roundTripped = true;
  for (let length = 0; length <= 16; length++) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 37 + length) & 0xff;
    const back = fromBase64(toBase64(bytes));
    if (length === 0) {
      if (back !== null) roundTripped = false;
      continue;
    }
    if (!back || back.length !== length || back.some((b, i) => b !== bytes[i])) roundTripped = false;
  }
  check('base64 round-trips every length', roundTripped, true);

  // All 256 byte values, so a sign-extension bug cannot hide in the high half.
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  const back = fromBase64(toBase64(all));
  check('base64 covers all byte values', back && back.every((b, i) => b === i), true);

  check('base64 rejects wrong length', fromBase64('abc'), null);
  check('base64 rejects illegal characters', fromBase64('ab*d'), null);
}

// --- 1. Round-trip WITH raw bytes -------------------------------------------
{
  const csv = buildCsvText(capture, true);
  const rows = parseDelimited(csv, ',');
  const outcome = importRows(rows, 'capture.csv');

  if (outcome.ok === false) {
    check('csv+bytes imports', outcome.failure.message, '(an import)');
  } else {
    check('csv+bytes frame count', outcome.packets.length, capture.length);

    const same = (field: keyof Packet) =>
      outcome.packets.every((p, i) => JSON.stringify(p[field]) === JSON.stringify(capture[i][field]));

    check('csv+bytes preserves rawBytes exactly', same('rawBytes'), true);
    check('csv+bytes preserves id', same('id'), true);
    check('csv+bytes preserves source', same('source'), true);
    check('csv+bytes preserves destination', same('destination'), true);
    check('csv+bytes preserves protocol', same('protocol'), true);
    check('csv+bytes preserves length', same('length'), true);
    check('csv+bytes preserves info', same('info'), true);
    check('csv+bytes preserves timestamp', same('tsUs'), true);
    // The whole point of carrying the bytes: dissection comes back too. The
    // protocol tree itself is rebuilt on demand rather than carried
    // (docs/decisions/0007), so what proves the re-dissection happened is the
    // layer list and the filterable fields the dissectors published - which is
    // also what every view except the detail pane actually reads.
    check('csv+bytes re-dissects the frame', same('frameProtocols'), true);
    check('...down to the fields the filters use', same('fields'), true);
    check('...and the frame carries its bytes, not a tree',
      outcome.packets[0].rawBytes.length > 0 && outcome.packets[0].layers.length === 0, true);
    check('csv+bytes reports no losses', outcome.notes.length, 0);
  }
}

// --- 2. Round-trip WITHOUT raw bytes ----------------------------------------
{
  const rows = parseDelimited(buildCsvText(capture, false), ',');
  const outcome = importRows(rows, 'summary.csv');

  if (outcome.ok === false) {
    check('csv summary imports', outcome.failure.message, '(an import)');
  } else {
    check('csv summary frame count', outcome.packets.length, capture.length);
    check('csv summary keeps addresses', outcome.packets[3].source, capture[3].source);
    check('csv summary keeps info', outcome.packets[3].info, capture[3].info);
    check('csv summary keeps absolute time', outcome.packets[3].tsUs, capture[3].tsUs);
    // Genuinely empty, not fabricated - the rule sessionRestore.ts states.
    check('csv summary has no wire bytes', outcome.packets[3].rawBytes.length, 0);
    check('csv summary says why there is no hex', outcome.notes[0].includes('no hex dump'), true);
    check('csv summary names its own origin', outcome.packets[0].interfaceName, 'summary.csv');
  }
}

// --- 3. Evaluator negatives --------------------------------------------------
{
  const unrelated = [
    ['Name', 'Email', 'Signed up'],
    ['Ada', 'ada@example.com', '2026-01-01'],
  ];
  const result = rowsToFrames(unrelated, 'contacts.csv');
  if (result.ok === true) {
    check('unrelated table is refused', 'imported', 'refused');
  } else {
    check('unrelated table kind', result.failure.kind, 'missing-columns');
    // The message has to name the headers the user can see, or it is useless.
    check(
      'unrelated table names what it found',
      result.failure.kind === 'missing-columns' ? result.failure.found : null,
      ['Name', 'Email', 'Signed up'],
    );
    check(
      'unrelated table names what it needs',
      result.failure.kind === 'missing-columns' ? result.failure.missing : null,
      ['source', 'destination', 'protocol', 'length'],
    );
  }
}
{
  const result = rowsToFrames([], 'empty.csv');
  check('empty file kind', result.ok === false ? result.failure.kind : 'imported', 'no-table');
}
{
  const headerOnly = [['No.', 'Source', 'Destination', 'Protocol', 'Length']];
  const result = rowsToFrames(headerOnly, 'header.csv');
  check('header with no rows kind', result.ok === false ? result.failure.kind : 'imported', 'no-rows');
}
{
  // Right headers, unusable rows: blank addresses and a non-numeric length.
  const garbage = [
    ['No.', 'Source', 'Destination', 'Protocol', 'Length'],
    ['1', '', '', '', ''],
    ['2', 'x', '', 'TCP', 'abc'],
    ['3', '', 'y', 'TCP', '60'],
  ];
  const result = rowsToFrames(garbage, 'garbage.csv');
  check('garbage rows kind', result.ok === false ? result.failure.kind : 'imported', 'no-rows');
  check(
    'garbage rows counts what it rejected',
    result.ok === false && result.failure.kind === 'no-rows' ? result.failure.rejected : 0,
    3,
  );
}
{
  const header = [['No.', 'Source', 'Destination', 'Protocol', 'Length']];
  const body = Array.from({ length: MAX_IMPORT_ROWS + 1 }, (_, i) => [
    String(i + 1), '10.0.0.1', '10.0.0.2', 'TCP', '60',
  ]);
  const result = rowsToFrames([...header, ...body], 'huge.csv');
  check('oversized file kind', result.ok === false ? result.failure.kind : 'imported', 'too-large');
}
{
  // A partial rejection must import the survivors rather than failing whole.
  const mixed = [
    ['No.', 'Source', 'Destination', 'Protocol', 'Length'],
    ['1', '10.0.0.1', '10.0.0.2', 'TCP', '60'],
    ['2', '', '', '', ''],
    ['3', '10.0.0.3', '10.0.0.4', 'UDP', '74'],
  ];
  const result = rowsToFrames(mixed, 'mixed.csv');
  check('partial rejection still imports', result.ok === true ? result.frames.length : 0, 2);
  check('partial rejection is counted', result.ok === true ? result.rejected : -1, 1);
}

// --- 4. Header synonyms ------------------------------------------------------
{
  const columns = matchHeaders(['#', 'Src', 'Dst', 'Proto', 'Len', 'Summary', 'Raw Bytes']);
  check('synonym #', columns.no, 0);
  check('synonym Src', columns.source, 1);
  check('synonym Dst', columns.destination, 2);
  check('synonym Proto', columns.protocol, 3);
  check('synonym Len', columns.length, 4);
  check('synonym Summary', columns.info, 5);
  check('synonym Raw Bytes', columns.rawBytes, 6);

  // Our own headers must map to themselves, or an export cannot be re-imported.
  const own = matchHeaders([
    'No.', 'Time(s)', 'Epoch (ms)', 'Source', 'Destination',
    'Protocol', 'Length', 'Info', 'Status', 'Anomaly', 'RawBytes (Base64)',
  ]);
  check('our own headers all map', Object.keys(own).length, 11);

  // A foreign spreadsheet with columns in a different order and extras between.
  const shuffled = rowsToFrames(
    [
      ['Length', 'Notes', 'Protocol', 'Destination', 'Source'],
      ['1514', 'ignored', 'UDP', '8.8.8.8', '10.0.0.9'],
    ],
    'shuffled.csv',
  );
  check('column order does not matter', shuffled.ok === true ? shuffled.frames[0].length : 0, 1514);
  check(
    'unknown columns are ignored',
    shuffled.ok === true ? shuffled.frames[0].fallback?.source : null,
    '10.0.0.9',
  );

  // The PDF report's Length cell reads "1514 bytes", not "1514".
  const suffixed = rowsToFrames(
    [['ID', 'Source', 'Destination', 'Proto', 'Length'], ['7', '1.1.1.1', '2.2.2.2', 'TCP', '1514 bytes']],
    'report.pdf',
  );
  check('length tolerates a unit suffix', suffixed.ok === true ? suffixed.frames[0].length : 0, 1514);
}

// --- 5. CSV quoting and formula guarding ------------------------------------
{
  const nasty = buildCapture(1);
  nasty[0].info = 'Standard query 0x1234 A, "quoted", comma\nand a newline';
  nasty[0].rawBytes = new Uint8Array(0);

  const rows = parseDelimited(buildCsvText(nasty, false), ',');
  check('quoted field survives commas, quotes and newlines', rows[1][7], nasty[0].info);

  // Spreadsheet formula injection: `info` carries names straight off the wire.
  const hostile = buildCapture(1);
  hostile[0].info = '=cmd|\'/c calc\'!A1';
  hostile[0].rawBytes = new Uint8Array(0);
  const hostileCsv = buildCsvText(hostile, false);
  check('formula lead is neutralised in the file', hostileCsv.includes("'=cmd|"), true);

  const back = importRows(parseDelimited(hostileCsv, ','), 'hostile.csv');
  check(
    'formula guard is removed again on import',
    back.ok === true ? back.packets[0].info : null,
    '=cmd|\'/c calc\'!A1',
  );
  check('unguard leaves ordinary text alone', unguardFormula("it's fine"), "it's fine");
}
{
  // The BOM must not end up inside the first header cell.
  const csv = buildCsvText(capture, false);
  check('csv starts with a UTF-8 BOM', csv.charCodeAt(0), 0xfeff);
  const rows = parseDelimited(csv, ',');
  check('parser strips the BOM', rows[0][0], 'No.');
}

// --- 6. Protocol coercion ----------------------------------------------------
{
  const labelled = rowsToFrames(
    [['Source', 'Destination', 'Protocol', 'Length'], ['1.1.1.1', '2.2.2.2', 'TLSv1.2', '517']],
    'labelled.csv',
  );
  // Not cast blindly into ProtocolType, which every color rule and display
  // filter believes is one of twelve values.
  check('unknown protocol becomes CUSTOM', labelled.ok === true ? labelled.frames[0].fallback?.protocol : null, 'CUSTOM');
  check(
    'unknown protocol keeps its label',
    labelled.ok === true ? labelled.frames[0].fallback?.protocolLabel : null,
    'TLSv1.2',
  );

  const known = rowsToFrames(
    [['Source', 'Destination', 'Protocol', 'Length'], ['1.1.1.1', '2.2.2.2', 'udp', '60']],
    'known.csv',
  );
  check('known protocol is normalised', known.ok === true ? known.frames[0].fallback?.protocol : null, 'UDP');
}

// --- 7. Delimited parsing edge cases ----------------------------------------
{
  check('bare row', parseDelimited('a,b,c', ','), [['a', 'b', 'c']]);
  check('crlf rows', parseDelimited('a,b\r\nc,d\r\n', ','), [['a', 'b'], ['c', 'd']]);
  check('doubled quotes', parseDelimited('"say ""hi""",b', ','), [['say "hi"', 'b']]);
  check('quoted newline', parseDelimited('"one\ntwo",b', ','), [['one\ntwo', 'b']]);
  check('empty trailing field', parseDelimited('a,', ','), [['a', '']]);
  check('tab delimited', parseDelimited('a\tb', '\t'), [['a', 'b']]);
}

// --- 8. Excel and zip, through the real libraries ---------------------------
//
// Async, so it runs last and owns the exit. These two exercise exceljs and
// fflate for real rather than mocking them: the interop shape of exceljs's
// browser bundle versus its CommonJS entry is exactly the kind of thing that
// works in Node and breaks in the browser, so at minimum one of the two
// environments is covered here.
async function binaryFormats() {
  const { buildXlsx, zipSingleFile } = await import('../../src/services/tabularWriters');
  const { readTabularFile } = await import('../../src/services/tabularReaders');

  const xlsx = await buildXlsx(capture, { includeRawBytes: true, filter: 'tcp' });
  const table = await readTabularFile(new File([xlsx], 'capture.xlsx'));

  if (table.ok === false) {
    check('xlsx reads back', table.failure.message, '(a table)');
  } else {
    const outcome = importRows(table.rows, 'capture.xlsx');
    if (outcome.ok === false) {
      check('xlsx imports', outcome.failure.message, '(an import)');
    } else {
      check('xlsx frame count', outcome.packets.length, capture.length);
      check(
        'xlsx preserves rawBytes exactly',
        outcome.packets.every((p, i) => JSON.stringify(p.rawBytes) === JSON.stringify(capture[i].rawBytes)),
        true,
      );
      check('xlsx preserves info', outcome.packets[5].info, capture[5].info);
      check('xlsx preserves absolute time', outcome.packets[5].tsUs, capture[5].tsUs);
      // The reader has to find the packet table among four sheets, not just
      // take the first one it is handed.
      check('xlsx picks the packet sheet', outcome.packets[0].source, capture[0].source);
    }
  }

  const csvBlob = new Blob([buildCsvText(capture, true)]);
  const original = new Uint8Array(await csvBlob.arrayBuffer());
  const zipped = await zipSingleFile(csvBlob, 'capture.csv');
  const { unzipSync } = await import('fflate');
  const entries = unzipSync(new Uint8Array(await zipped.arrayBuffer()));
  check('zip holds the file under its name', Object.keys(entries), ['capture.csv']);
  // Compared as bytes, not as decoded text: TextDecoder swallows the leading
  // BOM, which would make a lost BOM look like a pass.
  const restored = entries['capture.csv'];
  check(
    'zip content is byte-identical',
    restored.length === original.length && restored.every((b, i) => b === original[i]),
    true,
  );
  check('zip preserved the BOM', [restored[0], restored[1], restored[2]], [0xef, 0xbb, 0xbf]);
  check('zip actually compressed', zipped.size < csvBlob.size, true);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All tabular export/import assertions passed.');
  process.exit(0);
}

binaryFormats().catch(err => {
  console.log(`FAIL  binary formats threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
