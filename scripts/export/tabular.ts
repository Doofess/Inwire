/**
 * Assertion tests for the tabular exports - CSV, Excel, JSON - and their
 * import, driven by the two real captures.
 *
 *   npx tsx scripts/export/tabular.ts
 *
 * Three things are being defended here.
 *
 * The first is the round-trip: a capture exported with raw bytes and imported
 * again must come back byte-identical, because that is the entire promise of
 * the "Include raw packet bytes" toggle. Real traffic, both fixtures, every
 * frame - not a dozen frames a test author built to pass.
 *
 * The second is "every field": each dissected field is a column under its
 * Wireshark name, and its cells say what the dissector said - checked against
 * `fieldValue` for sampled frames, and against tshark's own `-T fields` for a
 * handful of abbreviations, so a column that is present but wrong fails too.
 *
 * The third is the evaluator - the thing that decides a file is NOT packet
 * data. That half has no visible success case, so it is the half that rots
 * quietly: a loosened header match or a swallowed parse error turns "this
 * spreadsheet isn't a capture" into a buffer full of invented frames. Those
 * checks, and the few edge cases no capture can express (an empty file, a
 * bare `#` header, a hostile formula), are literals.
 *
 * The real-capture half SKIPs cleanly without the fixtures (ADR 0004), and the
 * tshark cross-check without tshark.
 */
import {
  EXPORT_COLUMNS,
  RAW_BYTES_COLUMN,
  fromBase64,
  guardFormula,
  matchHeaders,
  rowsToFrames,
  stripPreamble,
  toBase64,
  unguardFormula,
  MAX_IMPORT_ROWS,
} from '../../src/services/exportSchema';
import { importAnyFile, importRows } from '../../src/services/tabularImport';
import { parseDelimited, readTabularFile } from '../../src/services/tabularReaders';
import { buildCsvText, buildXlsx, zipSingleFile } from '../../src/services/tabularWriters';
import { EXCEL_CELL_CHARS } from '../../src/services/export/writers/xlsx';
import { PcapService } from '../../src/services/pcapParser';
import { exportToJson } from '../../src/services/export/oneShot';
import { CsvWriter } from '../../src/services/export/writers/csv';
import { concatChunks } from '../../src/services/export/writers/writer';
import { FieldSurvey, orderedFieldEntries } from '../../src/services/export/fieldColumns';
import { metaEntries, type CaptureMeta } from '../../src/services/export/captureMeta';
import { fieldEntries, fieldValue } from '../../src/services/dissect/fieldAccess';
import { Anonymiser } from '../../src/services/anonymise';
import { TREE_LINKS } from '../../src/services/dissect/infoPatch';
import { adapterLabel } from '../../src/services/report/redact';
import { findWiresharkTool, loadRealCaptures, runTool, type RealCapture } from './realCaptures';
import type { Packet } from '../../src/types/packet';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)?.slice(0, 400)}`);
    console.log(`        actual   ${JSON.stringify(actual)?.slice(0, 400)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** The metadata an export of this capture would carry. */
function metaFor(capture: RealCapture, overrides: Partial<CaptureMeta['flags']> = {}): CaptureMeta {
  const p = capture.packets;
  return {
    app: 'Inwire', version: 'dev', os: 'Windows 11 Pro 10.0.26200', generatedAt: Date.UTC(2026, 8, 25, 12),
    source: { kind: 'import', fileName: capture.path.split(/[\\/]/).pop()! },
    firstUs: p[0].tsUs, lastUs: p[p.length - 1].tsUs,
    frames: { exported: p.length, inCapture: p.length, unreadable: 0 },
    drops: { kernel: null, agent: null, pipe: null },
    scope: 'capture', filter: '',
    flags: { anonymised: false, rawBytes: true, fields: true, secrets: false, ...overrides },
  };
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Every n-th frame, and the last - a sample that covers the whole capture. */
function sample<T>(items: readonly T[], every = 97): T[] {
  const out = items.filter((_, i) => i % every === 0);
  if (items.length > 0) out.push(items[items.length - 1]);
  return out;
}

// --- literals: the evaluator and the pure edge cases ------------------------------

function literalChecks(): void {
  // Base64 over every remainder class and every byte value - bytes, not packets.
  let roundTripped = true;
  for (let length = 0; length <= 16; length++) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 37 + length) & 0xff;
    const back = fromBase64(toBase64(bytes));
    if (length === 0) {
      if (back !== null) roundTripped = false;
      continue;
    }
    if (!back || !sameBytes(back, bytes)) roundTripped = false;
  }
  check('base64 round-trips every length', roundTripped, true);
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  check('base64 covers all byte values', fromBase64(toBase64(all))?.every((b, i) => b === i), true);
  check('base64 rejects wrong length', fromBase64('abc'), null);
  check('base64 rejects illegal characters', fromBase64('ab*d'), null);

  {
    const result = rowsToFrames([['Name', 'Email', 'Signed up'], ['Ada', 'ada@example.com', '2026-01-01']], 'contacts.csv');
    check('unrelated table kind', result.ok === false ? result.failure.kind : 'imported', 'missing-columns');
    check('unrelated table names what it found',
      result.ok === false && result.failure.kind === 'missing-columns' ? result.failure.found : null,
      ['Name', 'Email', 'Signed up']);
    check('unrelated table names what it needs',
      result.ok === false && result.failure.kind === 'missing-columns' ? result.failure.missing : null,
      ['source', 'destination', 'protocol', 'length']);
  }
  check('empty file kind', (() => { const r = rowsToFrames([], 'empty.csv'); return r.ok === false ? r.failure.kind : 'imported'; })(), 'no-table');
  check('a preamble with no table under it is no table',
    (() => { const r = rowsToFrames([['# Application: Inwire 4.0.0'], ['# Scope: the whole capture']], 'p.csv'); return r.ok === false ? r.failure.kind : 'imported'; })(),
    'no-table');
  check('header with no rows kind',
    (() => { const r = rowsToFrames([['No.', 'Source', 'Destination', 'Protocol', 'Length']], 'h.csv'); return r.ok === false ? r.failure.kind : 'imported'; })(),
    'no-rows');
  {
    const garbage = [
      ['No.', 'Source', 'Destination', 'Protocol', 'Length'],
      ['1', '', '', '', ''], ['2', 'x', '', 'TCP', 'abc'], ['3', '', 'y', 'TCP', '60'],
    ];
    const result = rowsToFrames(garbage, 'garbage.csv');
    check('garbage rows kind', result.ok === false ? result.failure.kind : 'imported', 'no-rows');
    check('garbage rows counts what it rejected',
      result.ok === false && result.failure.kind === 'no-rows' ? result.failure.rejected : 0, 3);
  }
  {
    const body = Array.from({ length: MAX_IMPORT_ROWS + 1 }, (_, i) => [String(i + 1), '10.0.0.1', '10.0.0.2', 'TCP', '60']);
    const result = rowsToFrames([['No.', 'Source', 'Destination', 'Protocol', 'Length'], ...body], 'huge.csv');
    check('oversized file kind', result.ok === false ? result.failure.kind : 'imported', 'too-large');
  }

  // Header synonyms, and our own headers mapping to themselves.
  {
    const columns = matchHeaders(['#', 'Src', 'Dst', 'Proto', 'Len', 'Summary', 'Raw Bytes']);
    check('synonyms map', [columns.no, columns.source, columns.destination, columns.protocol, columns.length, columns.info, columns.rawBytes],
      [0, 1, 2, 3, 4, 5, 6]);
    const own = matchHeaders([...EXPORT_COLUMNS.map((c) => c.header), RAW_BYTES_COLUMN.header]);
    check('our own importable headers all map', Object.keys(own).sort(),
      ['destination', 'epoch', 'expert', 'info', 'length', 'no', 'protocol', 'rawBytes', 'source', 'status', 'time']);
    // The seven new columns are carried past, not mistaken for anything.
    const extra = matchHeaders(EXPORT_COLUMNS.filter((c) => !['no', 'time', 'epoch', 'source', 'destination', 'protocol', 'length', 'info', 'status', 'expert'].includes(c.key)).map((c) => c.header));
    check('the new standard columns match nothing the importer reads', extra, {});
  }

  // A Wireshark field name normalises to a spelling of a standard column -
  // frame.len to "framelen" (Length), frame.number to "framenumber" (No.) - and
  // must never be taken for it, even when it comes first.
  {
    const hijack = matchHeaders(['frame.number', 'frame.len', 'Source', 'Destination', 'Protocol', 'Length', 'No.']);
    check('frame.len does not take Length', hijack.length, 5);
    check('frame.number does not take No.', hijack.no, 6);
    const onlyFields = matchHeaders(['frame.len', 'frame.number', 'ip.src', 'ip.dst']);
    check('a table of nothing but fields matches no standard column', onlyFields, {});
  }

  // A dotted header that is not a Wireshark field is somebody's column name.
  {
    const foreign = matchHeaders(['Src.IP', 'Dst.IP', 'Proto', 'Len']);
    check('a foreign Src.IP / Dst.IP header is still read as the address columns',
      [foreign.source, foreign.destination], [0, 1]);
  }

  // A header row is never mistaken for a preamble line.
  check('a header row whose first cell has a colon is not preamble', stripPreamble([['#: odd', 'Source'], ['x', 'y']]).length, 2);

  // Formula guarding is symmetric, and leaves ordinary text alone.
  check('guard neutralises a formula lead', guardFormula('=cmd|\'/c calc\'!A1'), '\'=cmd|\'/c calc\'!A1');
  check('unguard restores it', unguardFormula(guardFormula('=cmd|\'/c calc\'!A1')), '=cmd|\'/c calc\'!A1');
  check('unguard leaves ordinary text alone', unguardFormula("it's fine"), "it's fine");

  // Delimited parsing.
  check('bare row', parseDelimited('a,b,c', ','), [['a', 'b', 'c']]);
  check('crlf rows', parseDelimited('a,b\r\nc,d\r\n', ','), [['a', 'b'], ['c', 'd']]);
  check('doubled quotes', parseDelimited('"say ""hi""",b', ','), [['say "hi"', 'b']]);
  check('quoted newline', parseDelimited('"one\ntwo",b', ','), [['one\ntwo', 'b']]);
  check('empty trailing field', parseDelimited('a,', ','), [['a', '']]);
  check('tab delimited', parseDelimited('a\tb', '\t'), [['a', 'b']]);
}

// --- the real captures --------------------------------------------------------------

/** tshark's answer for a few abbreviations, by frame number. */
function tsharkFields(tshark: string, path: string, abbrevs: string[]): Map<number, string[]> {
  const out = new Map<number, string[]>();
  const text = runTool(tshark, ['-r', path, '-2', '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=a',
    '-e', 'frame.number', ...abbrevs.flatMap((a) => ['-e', a])]);
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const [n, ...values] = line.split('\t');
    out.set(Number(n), values);
  }
  return out;
}

/** A field value as the CSV spells it. */
const csvText = (v: string | number) => (typeof v === 'string' ? guardFormula(v) : String(v));

async function captureChecks(capture: RealCapture, tshark: string | null): Promise<void> {
  const name = capture.name;
  const packets = capture.packets;
  const meta = metaFor(capture);
  const survey = new FieldSurvey();
  survey.addPage(packets);
  const columns = survey.columns();

  // --- CSV, paged, equals the one-shot ---------------------------------------
  const oneShot = buildCsvText(packets, true, meta);
  const paged = (() => {
    const writer = new CsvWriter({ includeRawBytes: true, fields: columns, meta });
    const chunks: Uint8Array[] = [];
    for (let at = 0; at < packets.length; at += 1000) chunks.push(...writer.write(packets.slice(at, at + 1000)));
    chunks.push(...writer.finish());
    return new TextDecoder('utf-8', { ignoreBOM: true }).decode(concatChunks(chunks));
  })();
  checkTrue(`${name}: CSV written in pages is identical to the one-shot`, paged === oneShot);
  check(`${name}: CSV starts with a UTF-8 BOM`, oneShot.charCodeAt(0), 0xfeff);

  const rows = parseDelimited(oneShot, ',');
  const entries = metaEntries(meta);
  check(`${name}: the preamble is one quoted line per metadata entry`,
    rows.slice(0, entries.length).map((r) => r), entries.map(([k, v]) => [`# ${k}: ${v}`]));
  const header = rows[entries.length];
  check(`${name}: the header is the standard columns, the fields, then RawBytes`,
    header, [...EXPORT_COLUMNS.map((c) => c.header), ...columns.map((c) => c.abbrev), RAW_BYTES_COLUMN.header]);
  check(`${name}: one row per frame`, rows.length - entries.length - 1, packets.length);
  checkTrue(`${name}: every dissected field has a column (${columns.length})`,
    columns.length > 100 && new Set(header).size === header.length);

  // --- field columns say what the dissector said --------------------------------
  {
    const at = new Map(header.map((h, i) => [h, i]));
    let compared = 0;
    let wrong: string[] = [];
    let missingBag = 0;
    for (const p of sample(packets)) {
      const row = rows[entries.length + packets.indexOf(p) + 1];
      const bag = new Map(fieldEntries(p));
      for (const c of columns) {
        const cell = row[at.get(c.abbrev)!];
        const value = fieldValue(p, c.abbrev);
        const expected = value === undefined ? '' : csvText(value);
        if (cell !== expected) wrong.push(`frame ${p.id} ${c.abbrev}: ${JSON.stringify(cell)} != ${JSON.stringify(expected)}`);
        if (value !== undefined) compared++;
        if (value !== undefined && !bag.has(c.abbrev)) missingBag++;
      }
    }
    check(`${name}: sampled field cells equal fieldValue (${compared} values)`, wrong.slice(0, 5), []);
    check(`${name}: ...and fieldValue agrees with fieldEntries, dense columns included`, missingBag, 0);
    wrong = [];
  }

  // --- and what tshark says ---------------------------------------------------------
  if (tshark === null) {
    console.log(`SKIP  ${name}: tshark not found - field values not cross-checked against the reference`);
  } else {
    const abbrevs = ['eth.src', 'ip.src', 'ip.ttl', 'ipv6.dst', 'tcp.srcport', 'tcp.len', 'udp.dstport', 'dns.qry.name'];
    const theirs = tsharkFields(tshark, capture.path, abbrevs);
    const at = new Map(header.map((h, i) => [h, i]));
    for (const abbrev of abbrevs) {
      const index = at.get(abbrev);
      if (index === undefined) {
        console.log(`SKIP  ${name}: no ${abbrev} column - the capture has none`);
        continue;
      }
      let compared = 0;
      const wrong: string[] = [];
      packets.forEach((p, i) => {
        const ours = unguardFormula(rows[entries.length + i + 1][index]);
        const reference = theirs.get(p.id)?.[abbrevs.indexOf(abbrev)] ?? '';
        // Only single-valued frames: a tunnel or a multi-question query is one
        // value in our bag and several in tshark's, which is a different
        // question from whether the column is right.
        if (ours === '' || reference === '' || reference.includes(',')) return;
        compared++;
        if (ours !== reference) wrong.push(`frame ${p.id}: ours ${ours}, tshark ${reference}`);
      });
      check(`${name}: ${abbrev} column equals tshark -T fields (${compared} frames)`,
        compared > 0 ? wrong.slice(0, 3) : ['nothing compared'], []);
    }
  }

  // --- CSV round-trip, with bytes ------------------------------------------------------
  {
    const outcome = importRows(rows, `${name}.csv`);
    if (outcome.ok === false) {
      check(`${name}: CSV imports`, outcome.failure.message, '(an import)');
    } else {
      const back = outcome.packets;
      check(`${name}: CSV+bytes frame count`, back.length, packets.length);
      checkTrue(`${name}: CSV+bytes preserves every frame's bytes exactly`,
        back.every((p, i) => sameBytes(p.rawBytes, packets[i].rawBytes)));
      const same = (f: (p: Packet) => unknown) => back.every((p, i) => JSON.stringify(f(p)) === JSON.stringify(f(packets[i])));
      checkTrue(`${name}: ...and every id`, same((p) => p.id));
      checkTrue(`${name}: ...and every timestamp, to the microsecond`, same((p) => p.tsUs));
      checkTrue(`${name}: ...and every length`, same((p) => p.length));
      checkTrue(`${name}: ...and re-dissects every frame to the same protocol stack`, same((p) => p.frameProtocols));
      // Every field but three the two import ROUTES answer differently -
      // properties of the importer, not of the file, and measured rather than
      // guessed (539 of 12,858 and 58 of 14,782 frames differ, all in these):
      //   *.stream           conversation indexes, which the capture-file
      //                      importer assigns and the row importer's restore
      //                      path does not
      //   TREE_LINKS         forward references the capture importer patches
      //                      back onto an earlier frame once a later one is
      //                      seen (dns.response_in, tcp.reassembled_in, ...)
      //   *.checksum.status  "Unverified" on frames this machine sent, which
      //                      needs the host identity the capture importer
      //                      infers from the whole file and a row import has not
      const routeDependent = (k: string) => k.endsWith('.stream') || k in TREE_LINKS || k.endsWith('.checksum.status');
      const fieldsOf = (p: Packet) => orderedFieldEntries(p).filter(([k]) => !routeDependent(k));
      const differing = back.filter((p, i) => JSON.stringify(fieldsOf(p)) !== JSON.stringify(fieldsOf(packets[i])));
      check(`${name}: ...and to the same fields on every frame`, differing.slice(0, 5).map((p) => p.id), []);
      // The preamble is read past, not rejected: no row was skipped. (The one
      // note is the expert findings a row cannot rebuild, which is true.)
      check(`${name}: the preamble costs the import no rows`,
        outcome.notes.filter((n) => !n.includes('named an expert finding')), []);
    }
  }

  // --- without bytes, a summary ------------------------------------------------------------
  {
    const outcome = importRows(parseDelimited(buildCsvText(packets, false, meta), ','), 'summary.csv');
    if (outcome.ok === false) {
      check(`${name}: summary CSV imports`, outcome.failure.message, '(an import)');
    } else {
      const i = Math.floor(packets.length / 2);
      check(`${name}: summary keeps count, addresses, info and absolute time`,
        [outcome.packets.length, outcome.packets[i].source, outcome.packets[i].info, outcome.packets[i].tsUs],
        [packets.length, packets[i].source, packets[i].info, packets[i].tsUs]);
      check(`${name}: summary has no wire bytes, and says so`,
        [outcome.packets[i].rawBytes.length, outcome.notes[0]?.includes('no hex dump')], [0, true]);
    }
  }

  // --- anonymised ------------------------------------------------------------------------------
  //
  // The survey is of the REAL frames - which is what a caller has before it
  // anonymises - and the writer is handed the anonymised ones. The field
  // columns must not appear, whatever the survey found.
  {
    const anonymiser = new Anonymiser();
    const real = packets.slice(0, 500);
    const anonymised = real.map((p) => anonymiser.packet(p));
    const realSurvey = new FieldSurvey();
    realSurvey.addPage(real);
    checkTrue(`${name}: the real frames' survey has field columns to leave out`, realSurvey.columns().length > 0);
    const meta = metaFor(capture, { anonymised: true, fields: false });
    const write = (opts: { anonymiser?: Anonymiser }) => {
      const writer = new CsvWriter({ includeRawBytes: false, fields: realSurvey.columns(), meta, ...opts });
      return parseDelimited(new TextDecoder().decode(concatChunks([...writer.write(anonymised), ...writer.finish()])), ',');
    };
    const rowsA = write({ anonymiser });
    const at = rowsA.findIndex((r) => r[0] === 'No.');
    check(`${name}: an anonymised CSV carries no field columns`, rowsA[at], EXPORT_COLUMNS.map((c) => c.header));
    const iface = rowsA[at].indexOf('Interface');
    check(`${name}: ...and its Interface is the adapter label redactMeta would print`,
      rowsA[at + 1][iface], adapterLabel(0));
    checkTrue(`${name}: ...which is not the adapter's name`, rowsA[at + 1][iface] !== real[0].interfaceName);
    const withheld = write({});
    check(`${name}: with no anonymiser to map through, the adapter is withheld as "adapter 1" too`,
      withheld[withheld.findIndex((r) => r[0] === 'No.') + 1][iface], 'adapter 1');
    const json = JSON.parse(exportToJson(anonymised, false, meta)) as { packets: Record<string, unknown>[] };
    check(`${name}: ...and in JSON`, [json.packets[0].interface, 'fields' in json.packets[0]], ['adapter 1', false]);
  }

  // --- the preamble and a bare # header, on the real file ---------------------------------------
  {
    const table = stripPreamble(rows);
    check(`${name}: the preamble is stripped down to the header`, table[0], header);
    const bareHash = [['#', ...header.slice(1)], ...table.slice(1)];
    const back = rowsToFrames(bareHash, 'bare.csv');
    checkTrue(`${name}: a bare # is still the No. header`,
      back.ok === true && back.frames.length === packets.length && back.frames.every((f, i) => f.id === packets[i].id));
  }

  // --- Protocol coercion, on the capture's own labelled frames -----------------------------------
  {
    const labelled = packets.find((p) => p.protocolLabel !== undefined && p.protocolLabel !== p.protocol);
    if (labelled) {
      const back = rowsToFrames(parseDelimited(buildCsvText([labelled], false), ','), 'l.csv');
      check(`${name}: a label that is not a coarse protocol (${labelled.protocolLabel}) imports as CUSTOM with its label`,
        back.ok === true ? [back.frames[0].fallback?.protocol, back.frames[0].fallback?.protocolLabel] : null,
        ['CUSTOM', labelled.protocolLabel]);
    }
  }

  // --- Epoch (ms) keeps three decimals ----------------------------------------------------------
  //
  // It was `String(ms)`, the shortest spelling of the double, which drops
  // trailing zeros: .120 printed as .12, .000 as nothing. Compared against the
  // integer microseconds, not against `tsUs / 1000`, so the check does not
  // share the writer's arithmetic.
  {
    const epochAt = header.indexOf('Epoch (ms)');
    const data = rows.slice(entries.length + 1);
    const epochOf = (tsUs: number) => `${Math.floor(tsUs / 1000)}.${String(tsUs % 1000).padStart(3, '0')}`;
    checkTrue(`${name}: the capture has frames whose epoch ends in a zero`, packets.some((p) => p.tsUs % 10 === 0));
    check(`${name}: every CSV Epoch (ms) cell has all three decimals, exact`,
      data.map((r, i) => [r[epochAt], epochOf(packets[i].tsUs)]).filter(([a, b]) => a !== b).slice(0, 3), []);
    const back = rowsToFrames(rows, 'epoch.csv');
    checkTrue(`${name}: ...and reads back to the microsecond`,
      back.ok === true && back.frames.every((f, i) => Math.round(f.timestamp * 1000) === packets[i].tsUs));
  }

  // --- a CSV Excel has re-saved: the epoch in scientific notation --------------------------------
  {
    const epochAt = header.indexOf('Epoch (ms)');
    const resaved = rows.map((r, i) => (i > entries.length ? r.map((c, j) => (j === epochAt ? Number(c).toExponential(14).toUpperCase() : c)) : r));
    const back = rowsToFrames(resaved, 'resaved.csv');
    const worst = back.ok === true
      ? Math.max(...back.frames.map((f, i) => Math.abs(f.timestamp - packets[i].tsUs / 1000))) : Infinity;
    check(`${name}: an epoch Excel re-saved as ${resaved[entries.length + 1][epochAt]} reads as the epoch, not its mantissa`,
      worst < 1, true);
  }

  // --- a hostile Info string, on a real frame ------------------------------------------------
  {
    const hostile = { ...packets[0], info: '=cmd|\'/c calc\'!A1', rawBytes: new Uint8Array(0) };
    const text = buildCsvText([hostile], false);
    checkTrue(`${name}: a formula lead is neutralised in the file`, text.includes('\'=cmd|'));
    const back = importRows(parseDelimited(text, ','), 'hostile.csv');
    check(`${name}: ...and the guard is removed again on import`, back.ok === true ? back.packets[0].info : null, '=cmd|\'/c calc\'!A1');
  }

  // --- Excel round-trip ------------------------------------------------------------------------
  {
    const xlsx = await buildXlsx(packets, { includeRawBytes: true, meta });
    const table = await readTabularFile(new File([xlsx], `${name}.xlsx`));
    if (table.ok === false) {
      check(`${name}: xlsx reads back`, table.failure.message, '(a table)');
    } else {
      const outcome = importRows(table.rows, `${name}.xlsx`);
      if (outcome.ok === false) {
        check(`${name}: xlsx imports`, outcome.failure.message, '(an import)');
      } else {
        check(`${name}: xlsx frame count`, outcome.packets.length, packets.length);
        // A cell holds 32,767 characters, so a frame whose base64 is longer
        // travels without its bytes (the Capture sheet says so) and imports
        // as a summary; every other frame's bytes are exact.
        const tooLong = (p: Packet) => Math.ceil(p.rawBytes.length / 3) * 4 > EXCEL_CELL_CHARS;
        const long = packets.filter(tooLong).length;
        checkTrue(`${name}: xlsx preserves the bytes of every frame that fits a cell, exactly`,
          outcome.packets.every((p, i) => (tooLong(packets[i]) ? p.rawBytes.length === 0 : sameBytes(p.rawBytes, packets[i].rawBytes))));
        console.log(`        (${long} frame(s) of ${packets.length} are past the cell limit)`);
        // Epoch milliseconds are a text cell: a number keeps 15 significant
        // digits in Excel and an epoch to the microsecond has 16.
        checkTrue(`${name}: xlsx epoch values stay exact to the microsecond`,
          outcome.packets.every((p, i) => p.tsUs === packets[i].tsUs));
        check(`${name}: xlsx picks the packet sheet and keeps info`,
          [outcome.packets[7].source, outcome.packets[7].info], [packets[7].source, packets[7].info]);
      }
    }
  }

  // --- JSON ---------------------------------------------------------------------------------------
  {
    const text = exportToJson(packets, true, meta);
    const doc = JSON.parse(text) as { format: string; formatVersion: number; meta: CaptureMeta; packets: Record<string, unknown>[] };
    check(`${name}: JSON names its format and version`, [doc.format, doc.formatVersion], ['inwire-export', 2]);
    check(`${name}: JSON carries the metadata as it is`, doc.meta, meta);
    check(`${name}: JSON holds every frame`, doc.packets.length, packets.length);
    checkTrue(`${name}: JSON drops layers`, doc.packets.every((f) => !('layers' in f)));
    const wrong = sample(packets).filter((p) => {
      const f = doc.packets[packets.indexOf(p)];
      return JSON.stringify(f.fields) !== JSON.stringify(Object.fromEntries(orderedFieldEntries(p)))
        || JSON.stringify(f.protocols) !== JSON.stringify(p.frameProtocols ?? [])
        || JSON.stringify(f.analysisFlags) !== JSON.stringify(p.analysisFlags ?? []);
    });
    check(`${name}: JSON fields, protocols and analysis flags equal the frame's`, wrong.map((p) => p.id), []);

    const outcome = await importAnyFile(new File([text], `${name}.json`));
    if (outcome.ok === false) {
      check(`${name}: {meta, packets} JSON imports`, outcome.failure.message, '(an import)');
    } else {
      check(`${name}: {meta, packets} JSON imports every frame`, outcome.packets.length, packets.length);
      checkTrue(`${name}: ...with its bytes exact`, outcome.packets.every((p, i) => sameBytes(p.rawBytes, packets[i].rawBytes)));
      checkTrue(`${name}: ...and its timestamps`, outcome.packets.every((p, i) => p.tsUs === packets[i].tsUs));
    }
  }

  // --- zip ----------------------------------------------------------------------------------------
  {
    const csvBlob = new Blob([oneShot]);
    const original = new Uint8Array(await csvBlob.arrayBuffer());
    const zipped = await zipSingleFile(csvBlob, 'capture.csv');
    const { unzipSync } = await import('fflate');
    const entriesZ = unzipSync(new Uint8Array(await zipped.arrayBuffer()));
    check(`${name}: zip holds the file under its name`, Object.keys(entriesZ), ['capture.csv']);
    checkTrue(`${name}: zip content is byte-identical, BOM included`, sameBytes(entriesZ['capture.csv'], original));
    checkTrue(`${name}: zip actually compressed`, zipped.size < csvBlob.size);
  }
}

/**
 * A frame less than a microsecond after the first, from real traffic.
 *
 * Wireshark's own tools make it: a nanosecond copy of the first 300 frames of
 * a fixture, a second copy shifted by 123 ns (`editcap -t`), and the two
 * merged in time order (`mergecap`). Frame 2 then sits 1.23e-7 s into the
 * capture - a relative time JSON writes as `1.23e-7` and a workbook stores as
 * a number in the same notation, which a reader that ignores exponents takes
 * for 1.23.
 */
async function subMicrosecondChecks(capture: RealCapture): Promise<void> {
  const editcap = findWiresharkTool('editcap');
  const mergecap = findWiresharkTool('mergecap');
  if (editcap === null || mergecap === null) {
    console.log('SKIP  sub-microsecond round-trip: editcap or mergecap not found');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'inwire-tabular-'));
  try {
    const a = join(dir, 'a.pcap');
    const b = join(dir, 'b.pcap');
    const merged = join(dir, 'sub.pcap');
    runTool(editcap, ['-F', 'nsecpcap', '-r', capture.path, a, '1-300']);
    runTool(editcap, ['-F', 'nsecpcap', '-t', '0.000000123', a, b]);
    runTool(mergecap, ['-F', 'nsecpcap', '-w', merged, a, b]);
    const { packets } = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(merged))], 'sub.pcap'), Number.POSITIVE_INFINITY);
    check('the merged capture has a frame 1.23e-7 s after the first', packets[1].relativeTime, 1.23e-7);

    const json = exportToJson(packets, true);
    checkTrue('...which JSON writes in exponent notation', json.includes('"time":1.23e-7'));
    const fromJson = await importAnyFile(new File([json], 'sub.json'));
    check('...and reads back from JSON as 1.23e-7, not 1.23',
      fromJson.ok === true ? fromJson.packets.map((p) => p.relativeTime).filter((t, i) => t !== packets[i].relativeTime).length : 'import failed', 0);

    const xlsx = await buildXlsx(packets, { includeRawBytes: false });
    const table = await readTabularFile(new File([xlsx], 'sub.xlsx'));
    const fromXlsx = table.ok === true ? importRows(table.rows, 'sub.xlsx') : null;
    check('...and from the workbook\'s numeric Time cells',
      fromXlsx?.ok === true ? fromXlsx.packets.map((p) => p.relativeTime).filter((t, i) => t !== packets[i].relativeTime).length : 'import failed', 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  literalChecks();
  const captures = await loadRealCaptures();
  const tshark = captures.length > 0 ? findWiresharkTool('tshark') : null;
  for (const capture of captures) await captureChecks(capture, tshark);
  if (captures.length > 0) await subMicrosecondChecks(captures[0]);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All tabular export/import assertions passed.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
