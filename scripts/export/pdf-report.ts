/**
 * Assertion tests for the PDF report.
 *
 *   npx tsx scripts/export/pdf-report.ts
 *
 * An interim smoke test: the report is being rebuilt as an analysis, and until
 * it is, this holds the two things already decided - it says Inwire, and it no
 * longer carries the old name or a packet list.
 *
 * Driven by the real captures in `test/fixtures/`, and skips cleanly without
 * them.
 *
 * It reads the PDF's own bytes rather than parsing it. jsPDF writes its content
 * streams uncompressed by default, so every string drawn is in the file as a
 * literal. The first check pins that default, because every "does not
 * contain" below would pass vacuously on a compressed file.
 */
import { buildPdfReport } from '../../src/components/export/pdfReport';
import { loadRealCaptures } from './realCaptures';
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

async function reportText(packets: Packet[], filter: string): Promise<string> {
  const bytes = new Uint8Array(await buildPdfReport(packets, filter).arrayBuffer());
  // latin1, because jsPDF's standard fonts are WinAnsi: one byte per glyph.
  return new TextDecoder('latin1').decode(bytes);
}

async function main() {
  const captures = await loadRealCaptures();
  for (const { name, packets } of captures) {
    const text = await reportText(packets, 'tcp');
    check(`${name}: the file is a PDF`, text.startsWith('%PDF-'), true);
    check(`${name}: content streams are uncompressed`, text.includes('/FlateDecode'), false);
    check(`${name}: it says Inwire`, text.includes('Inwire'), true);
    check(`${name}: the title is the new one`, text.includes('(Inwire capture analysis)'), true);
    check(`${name}: the document properties carry the title`, text.includes('/Title (Inwire capture analysis)'), true);
    check(`${name}: the old name is gone`, text.includes('Net View'), false);
    check(`${name}: there is no packet list`, text.includes('Packet List'), false);
    check(`${name}: the filter is still stated`, text.includes('Display filter: tcp'), true);
  }

  // The one case no real capture can be: nothing at all.
  const empty = await reportText([], '');
  check('an empty capture still produces a report', empty.includes('(Inwire capture analysis)'), true);
  check('...with no packet list either', empty.includes('Packet List'), false);

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
