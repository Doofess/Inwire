/**
 * Assertion tests for the PDF report.
 *
 *   npx tsx scripts/export/pdf-report.ts
 *
 * The report is an analysis of the capture, not a copy of it: statistics and
 * findings, and no packet list. This holds the shape of that - every section
 * present, the brand where it should be and the old name nowhere - and the one
 * property that matters most when it is shared: an anonymised report carries
 * none of the capture's real addresses and none of its names.
 *
 * Driven by the real captures in `test/fixtures/`, and skips cleanly without
 * them. The empty report and the character check are literal inputs, because
 * no capture on disk is empty and neither fixture has a non-Latin name in it.
 *
 * It reads the PDF's own bytes rather than parsing it. The report is written
 * uncompressed unless asked otherwise, so every string drawn is in the file as
 * a literal. The first checks pin that, because every "does not contain" below
 * would pass vacuously on a compressed file.
 */
import { buildPdfReport, SECTION_TITLES } from '../../src/components/export/pdfReport';
import { analyseCapture, type CaptureAnalysis } from '../../src/services/report/analysis';
import { Anonymiser } from '../../src/services/anonymise';
import { brandMarkPaths } from '../../src/lib/brandMark';
import type { CaptureMeta } from '../../src/services/export/captureMeta';
import { loadRealCaptures } from './realCaptures';

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

const NOW = Date.UTC(2026, 8, 25, 14, 3);

function metaFor(a: CaptureAnalysis, fileName: string, anonymised: boolean, filter = ''): CaptureMeta {
  return {
    app: 'Inwire', version: 'dev', os: null, generatedAt: NOW,
    source: { kind: 'import', fileName },
    firstUs: a.firstUs, lastUs: a.lastUs,
    frames: { exported: a.frames, inCapture: a.frames, unreadable: 0 },
    drops: { kernel: null, agent: null, pipe: null },
    scope: filter ? 'filtered' : 'capture', filter,
    flags: { anonymised, rawBytes: false, fields: false, secrets: false },
  };
}

async function reportText(a: CaptureAnalysis, meta: CaptureMeta, anonymiser?: Anonymiser): Promise<string> {
  const bytes = new Uint8Array(await buildPdfReport(a, meta, { now: NOW, anonymiser }).arrayBuffer());
  // latin1, because jsPDF's standard fonts are WinAnsi: one byte per glyph.
  return new TextDecoder('latin1').decode(bytes);
}

/**
 * A fill colour as jsPDF writes it into a content stream for `setFillColor`
 * given a hex string: `r g b rg`, two decimals, trailing zeros trimmed.
 */
function fillOperator(hex: string): string {
  const channel = (i: number) => (parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255).toFixed(2).replace(/0+$/, '');
  return `${channel(0)} ${channel(1)} ${channel(2)} rg`;
}

/**
 * Every string drawn, in drawing order, unescaped and run together.
 *
 * A table cell that wraps is drawn as one string per line, so an address split
 * across two lines is never a substring of the raw file - and a check that
 * reads only the raw file would call a wrapped leak absent. Run together, the
 * two halves meet again. Joining unrelated strings can only ADD matches, which
 * errs toward failing a "contains none" check rather than passing one.
 */
function drawnText(pdf: string): string {
  let out = '';
  for (const m of pdf.matchAll(/\(((?:\\.|[^\\)])*)\)\s*Tj/g)) {
    out += m[1].replace(/\\([()\\])/g, '$1');
  }
  return out;
}

/** A string as drawn: jsPDF escapes parentheses and backslashes inside `( )`. */
function drawn(s: string): string {
  return `(${s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')})`;
}

async function main() {
  const captures = await loadRealCaptures();
  for (const { name, path, packets } of captures) {
    const analysis = analyseCapture(packets);
    const fileName = path.split(/[\\/]/).pop()!;
    const text = await reportText(analysis, metaFor(analysis, fileName, false));

    check(`${name}: the file is a PDF`, text.startsWith('%PDF-'), true);
    check(`${name}: content streams are uncompressed`, text.includes('/FlateDecode'), false);
    check(`${name}: the title is drawn`, text.includes(drawn('Inwire capture analysis')), true);
    check(`${name}: the document properties carry the title`, text.includes('/Title (Inwire capture analysis)'), true);
    for (const title of SECTION_TITLES) {
      // Processes appears only when the capture attributed traffic to one.
      const expected = title === 'Processes' ? analysis.processes.length > 0 : true;
      check(`${name}: section "${title}" ${expected ? 'is present' : 'is absent (no processes)'}`, text.includes(drawn(title)), expected);
    }
    check(`${name}: the footer counts pages`, /\(Page 1 of \d+ \xb7 Inwire dev \xb7 generated 2026-09-25 14:03 UTC\)/.test(text), true);
    check(`${name}: it says Inwire`, text.includes('Inwire'), true);
    check(`${name}: the old name is gone`, /Net ?View/i.test(text), false);
    check(`${name}: there is no packet list`, text.includes('Packet List'), false);
    // The columns a packet list would have and no table in the report does.
    check(`${name}: no packet-list columns`, ['No.', 'Destination', 'Info'].filter((h) => text.includes(drawn(h))), []);
    check(`${name}: every plate of the mark is filled in its own colour`,
      brandMarkPaths('primary').map((p) => p.fill).filter((fill) => !text.includes(fillOperator(fill))), []);
    check(`${name}: nothing was replaced by "?"`, text.includes('shown as "?"'), false);

    // What the plain report prints, which is what gives the anonymised checks
    // below their teeth: every address in the endpoint and conversation
    // tables, and every name in the hosts table, must be in it.
    const probe = new Anonymiser();
    const personal = (x: string) => probe.text(x) !== x; // group addresses are nobody's, and stay
    const printed = [...new Set([
      ...analysis.endpoints.ipv4.rows.map((e) => e.address),
      ...analysis.endpoints.ipv6.rows.map((e) => e.address),
      ...Object.values(analysis.conversations).flatMap((r) => r.rows.flatMap((c) => [c.addressA, c.addressB])),
    ])].filter(personal);
    const hostNames = [...new Set(analysis.names.slice(0, 25).map((n) => n.name))];
    const plain = drawnText(text);
    check(`${name}: the plain report prints every table address`, printed.filter((x) => !plain.includes(x)), []);
    check(`${name}: the plain report prints every host name it lists`, hostNames.filter((n) => !plain.includes(n)), []);

    // Everything real a report could carry, printed or not.
    const addresses = [...new Set([
      ...printed,
      ...analysis.localAddresses,
      ...analysis.names.map((n) => n.address),
      ...(analysis.topRemote ? [analysis.topRemote.address] : []),
    ])].filter(personal);
    const names = [...new Set(analysis.names.map((n) => n.name))];
    const leaks = (pdf: string) => {
      const joined = drawnText(pdf);
      return {
        addresses: addresses.filter((x) => pdf.includes(x) || joined.includes(x)),
        names: names.filter((n) => pdf.includes(n) || joined.includes(n)),
      };
    };

    // The metadata is as identifying as the tables: a filter naming a real
    // host and a real name, a file named after a real address.
    const target = printed[0];
    const filter = `ip.addr == ${target} || dns.qry.name == "${names[0] ?? 'example'}"`;
    const anonImport = await reportText(analysis,
      metaFor(analysis, `capture-from-${target}.pcap`, true, filter), new Anonymiser());
    check(`${name}: the anonymised report is a PDF`, anonImport.startsWith('%PDF-'), true);
    check(`${name}: anonymised, no real address or name anywhere`, leaks(anonImport), { addresses: [], names: [] });
    check(`${name}: ...the file name is withheld`, drawnText(anonImport).includes('Imported from a file (name withheld)'), true);
    check(`${name}: ...the filter's quoted name is withheld`, drawnText(anonImport).includes('"(withheld)"'), true);
    check(`${name}: the anonymised report says it is`, anonImport.includes('Anonymised') && anonImport.includes('Crypto-PAn'), true);

    const liveMeta: CaptureMeta = {
      ...metaFor(analysis, '', true, filter),
      source: { kind: 'live', adapters: [`Ethernet ${target}`, '\\Device\\NPF_{4A1B2C3D-0000-1111-2222-333344445555}'] },
    };
    const anonLive = await reportText(analysis, liveMeta, new Anonymiser());
    check(`${name}: anonymised live capture, no real address in the adapter labels`, leaks(anonLive), { addresses: [], names: [] });
    check(`${name}: ...a device path becomes its position`,
      drawnText(anonLive).includes('adapter 2') && !anonLive.includes('NPF_'), true);

    let refused = false;
    try {
      buildPdfReport(analysis, metaFor(analysis, fileName, true), { now: NOW });
    } catch {
      refused = true;
    }
    check(`${name}: an anonymised report with no anonymiser is refused`, refused, true);
  }

  // Nothing at all.
  const empty = analyseCapture([]);
  const emptyText = await reportText(empty, metaFor(empty, 'empty.pcap', false));
  check('an empty capture still produces a report', emptyText.includes(drawn('Inwire capture analysis')), true);
  check('...with its methods note', emptyText.includes(drawn('Methods')), true);
  check('...and no section that would describe nothing',
    ['Traffic over time', 'Protocol hierarchy', 'Packet sizes', 'Top endpoints', 'Expert findings', 'Hosts seen']
      .filter((t) => emptyText.includes(drawn(t))), []);

  // A character the standard font cannot draw is replaced, and the report says so.
  const odd = await reportText(empty, metaFor(empty, 'capture-中.pcap', false, 'dns.qry.name contains "中"'));
  check('a character outside WinAnsi becomes "?"', odd.includes('capture-?.pcap'), true);
  check('...and Methods says it happened', odd.includes('shown as "?"'), true);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All PDF report assertions passed.');
  process.exit(0);
}

main().catch(err => {
  console.log(`FAIL  pdf report threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
