/**
 * Assertion tests for the Excel workbook's presentation, on the real captures.
 *
 *   npx tsx scripts/export/xlsx-style.ts
 *
 * `tabular.ts` proves the workbook round-trips. This proves it is the
 * workbook the export promises a person: each row in its colour rule's Day
 * colours, numbers that are numbers, the header frozen and filterable, the
 * sheets named and shaped as documented - and the budget that keeps a large
 * export from taking the renderer down. Every check reads the file back with
 * exceljs, so it asserts what Excel will be handed rather than what the
 * writer meant to write.
 *
 * SKIPs cleanly without the fixtures (ADR 0004).
 */
import ExcelImport from 'exceljs';
import type { Cell, Fill, Workbook, Worksheet } from 'exceljs';
import {
  createXlsxWriter, planWorkbook, XlsxTooLargeError, XLSX_BUDGET, EXCEL_CELL_CHARS, argb, type XlsxBudget,
} from '../../src/services/export/writers/xlsx';
import { FieldSurvey } from '../../src/services/export/fieldColumns';
import { RuleMatcher } from '../../src/services/export/ruleMatcher';
import { EXPORT_COLUMNS } from '../../src/services/exportSchema';
import { getPacketThemeForApp } from '../../src/services/packetThemes';
import { DEFAULT_COLOR_RULES, resolveRuleColors } from '../../src/services/colorRules';
import { CATEGORY_LABELS, EXPERT_RULE_ID } from '../../src/services/expertInfo';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { loadRealCaptures, type RealCapture } from './realCaptures';
import type { ColorRule, ExpertCategory, Packet } from '../../src/types/packet';
import { Anonymiser } from '../../src/services/anonymise';

const ExcelJS = ((ExcelImport as unknown as { default?: typeof ExcelImport }).default ?? ExcelImport) as typeof ExcelImport;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)?.slice(0, 300)}`);
    console.log(`        actual   ${JSON.stringify(actual)?.slice(0, 300)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const THEME = getPacketThemeForApp('light');
const fillOf = (cell: Cell) => ((cell.fill as Fill & { fgColor?: { argb?: string } } | undefined)?.fgColor?.argb) ?? null;
const col = (key: string) => EXPORT_COLUMNS.findIndex((c) => c.key === key) + 1;

async function build(packets: readonly Packet[], opts: {
  fields?: boolean; budget?: XlsxBudget; rules?: (ColorRule | null)[]; raw?: boolean; chain?: ColorRule[];
} = {}): Promise<{ workbook: Workbook; writesFields: boolean }> {
  const survey = new FieldSurvey();
  survey.addPage(packets);
  const writer = await createXlsxWriter({
    includeRawBytes: opts.raw ?? false,
    fields: opts.fields === false ? [] : survey.columns(),
    expectedFrames: packets.length,
    expectedFieldCells: survey.cells,
    budget: opts.budget,
    colorRules: opts.chain,
  });
  for (let at = 0; at < packets.length; at += 4096) {
    writer.write(packets.slice(at, at + 4096), opts.rules?.slice(at, at + 4096));
  }
  const [bytes] = await writer.finish();
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  return { workbook, writesFields: writer.writesFieldColumns };
}

function headers(sheet: Worksheet): string[] {
  const out: string[] = [];
  sheet.getRow(1).eachCell({ includeEmpty: false }, (cell) => { out.push(String(cell.value)); });
  return out;
}

async function captureChecks(capture: RealCapture): Promise<void> {
  const name = capture.name;
  const packets = capture.packets;
  const slotsBefore = packets.map((p) => p.colorSlot);
  const { workbook } = await build(packets);

  check(`${name}: four sheets, Packets first and Alerts renamed Findings`,
    workbook.worksheets.map((s) => s.name), ['Packets', 'Protocols', 'Findings', 'Capture']);
  checkTrue(`${name}: the caller's frames are not touched (colorSlot unchanged)`,
    packets.every((p, i) => p.colorSlot === slotsBefore[i]));

  // --- Packets: the header ---------------------------------------------------------
  const sheet = workbook.getWorksheet('Packets')!;
  const head = headers(sheet);
  check(`${name}: the header is on row 1 and starts with the standard columns`,
    head.slice(0, EXPORT_COLUMNS.length), EXPORT_COLUMNS.map((c) => c.header));
  check(`${name}: the standard header is the brand blue, white and bold`,
    [fillOf(sheet.getCell(1, 1)), sheet.getCell(1, 1).font?.color?.argb, sheet.getCell(1, 1).font?.bold],
    ['FF0B6BCB', 'FFFFFFFF', true]);
  check(`${name}: the field header is a step down the same ramp`,
    fillOf(sheet.getCell(1, EXPORT_COLUMNS.length + 1)), 'FF0957A4');
  const view = sheet.views[0] as { state?: string; xSplit?: number; ySplit?: number };
  check(`${name}: panes frozen on the first column and the header`, [view.state, view.xSplit, view.ySplit], ['frozen', 1, 1]);
  checkTrue(`${name}: an autofilter over the whole header`, JSON.stringify(sheet.autoFilter ?? '').includes('A1'));

  // --- Packets: rows in their rule's colours ----------------------------------------
  const matcher = new RuleMatcher();
  const rowOf = (i: number) => sheet.getRow(i + 2);
  const expectedColors = (p: Packet) => {
    const rule = matcher.match(p);
    return rule ? resolveRuleColors(rule, THEME) : { background: THEME.surface.background, color: THEME.surface.foreground };
  };
  {
    const wrong: string[] = [];
    for (let i = 0; i < packets.length; i += 37) {
      const colors = expectedColors(packets[i]);
      const row = rowOf(i);
      for (let c = 1; c <= EXPORT_COLUMNS.length; c++) {
        const cell = row.getCell(c);
        if (fillOf(cell) !== argb(colors.background) || cell.font?.color?.argb !== argb(colors.color)) {
          wrong.push(`frame ${packets[i].id} col ${c}: ${fillOf(cell)} ${cell.font?.color?.argb}`);
          break;
        }
      }
    }
    check(`${name}: every standard cell of sampled rows wears its rule's Day fill and text`, wrong.slice(0, 3), []);
  }
  {
    // TCP RST, the band the reference analyzer paints loudest. In the shipped
    // chain a reset is caught first by the Expert: Reset band; with the expert
    // bands switched off - a chain a user can have - it reaches TCP RST. Both
    // are checked on the capture's own reset frames.
    const resets = packets.map((p, i) => ({ p, i })).filter(({ p }) => fieldValue(p, 'tcp.flags.reset') === 1);
    if (resets.length === 0) {
      console.log(`SKIP  ${name}: the capture has no TCP reset`);
    } else {
      const { p, i } = resets[0];
      const shipped = matcher.match(p);
      check(`${name}: a real reset row (frame ${p.id}) wears the rule the shipped chain gives it (${shipped?.name})`,
        fillOf(rowOf(i).getCell(col('info'))), argb(resolveRuleColors(shipped!, THEME).background));
      const noExpert = DEFAULT_COLOR_RULES.map((r) => (r.id.startsWith('color-expert-') ? { ...r, enabled: false } : r));
      const frames = resets.map((r) => r.p);
      const { workbook: edited } = await build(frames, { chain: noExpert, fields: false });
      const first = edited.getWorksheet('Packets')!.getRow(2);
      check(`${name}: with the expert bands off, a real TCP RST row is filled with the theme's TCP RST colour`,
        [fillOf(first.getCell(col('info'))), first.getCell(col('info')).font?.color?.argb, first.getCell(col('colourRule')).value],
        [argb(THEME.rules['color-tcp-rst'].background), argb(THEME.rules['color-tcp-rst'].color), 'TCP RST']);
    }
  }
  {
    // Fills are per cell. A row style would carry to every column of the sheet.
    const lastColumn = head.length;
    check(`${name}: nothing is painted past the last column`, fillOf(rowOf(0).getCell(lastColumn + 1)), null);
    const fieldCell = rowOf(0).getCell(EXPORT_COLUMNS.length + 1);
    check(`${name}: the field columns are not painted`, fillOf(fieldCell), null);
  }

  // --- Packets: numbers are numbers --------------------------------------------------
  {
    const i = Math.floor(packets.length / 3);
    const row = rowOf(i);
    const p = packets[i];
    check(`${name}: No., Time and Length are numbers with their formats`,
      [col('no'), col('time'), col('length')].map((c) => [typeof row.getCell(c).value, row.getCell(c).numFmt]),
      [['number', '0'], ['number', '0.000000'], ['number', '#,##0']]);
    check(`${name}: ...and hold the frame's values exactly`,
      [row.getCell(col('no')).value, row.getCell(col('time')).value, row.getCell(col('length')).value],
      [p.id, p.relativeTime, p.length]);
    // Excel keeps 15 significant digits; an epoch to the microsecond has 16.
    check(`${name}: Epoch (ms) is a text cell, exact to the microsecond`,
      [row.getCell(col('epoch')).value, row.getCell(col('epoch')).numFmt], [String(p.tsUs / 1000), '@']);
    // A string cell is never evaluated, so no apostrophe is written into it.
    const leads = packets.map((q, k) => ({ q, k })).filter(({ q }) => /^[=+\-@]/.test(q.info));
    if (leads.length > 0) {
      check(`${name}: a text cell starting with a formula character is written as the frame has it`,
        rowOf(leads[0].k).getCell(col('info')).value, leads[0].q.info);
    }
    const arrival = row.getCell(col('arrival'));
    check(`${name}: Arrival is a date, shown to the millisecond`,
      [arrival.value instanceof Date, (arrival.value as Date).getTime(), arrival.numFmt],
      [true, Math.floor(p.tsUs / 1000), 'yyyy-mm-dd hh:mm:ss.000']);
    const ttlColumn = head.indexOf('ip.ttl') + 1;
    const withTtl = packets.findIndex((q) => typeof fieldValue(q, 'ip.ttl') === 'number');
    check(`${name}: a numeric field (ip.ttl) is a number cell`,
      withTtl >= 0 && ttlColumn > 0 ? rowOf(withTtl).getCell(ttlColumn).value : 'no ip.ttl',
      withTtl >= 0 ? fieldValue(packets[withTtl], 'ip.ttl') : 'no ip.ttl');
  }

  // --- Protocols ------------------------------------------------------------------------
  {
    const protocols = workbook.getWorksheet('Protocols')!;
    check(`${name}: Protocols header`, headers(protocols), ['Protocol', 'Frames', '% of frames', 'Bytes', '% of bytes']);
    const top = protocols.getRow(2);
    check(`${name}: the root is every frame, as 100.0% - a number, not text`,
      [top.getCell(1).value, top.getCell(2).value, top.getCell(3).value, top.getCell(3).numFmt],
      ['frame', packets.length, 1, '0.0%']);
    const child = protocols.getRow(3);
    check(`${name}: a child is indented and in the outline`, [child.getCell(1).alignment?.indent, child.outlineLevel], [1, 1]);
  }

  // --- Findings -------------------------------------------------------------------------
  {
    const findings = workbook.getWorksheet('Findings')!;
    check(`${name}: Findings header`, headers(findings), ['Category', 'Finding', 'Protocol', 'Count', 'First frames', 'What it means']);
    const labelToCategory = new Map(Object.entries(CATEGORY_LABELS).map(([k, v]) => [v, k as ExpertCategory]));
    const wrong: string[] = [];
    let rows = 0;
    findings.eachRow((row, n) => {
      if (n === 1) return;
      rows++;
      const category = labelToCategory.get(String(row.getCell(1).value));
      const expected = category ? argb(THEME.rules[EXPERT_RULE_ID[category]].background) : 'unknown category';
      if (fillOf(row.getCell(2)) !== expected) wrong.push(`${row.getCell(1).value}: ${fillOf(row.getCell(2))}`);
      if (typeof row.getCell(4).value !== 'number') wrong.push(`count is ${typeof row.getCell(4).value}`);
    });
    checkTrue(`${name}: the capture has findings (${rows} groups)`, rows > 0);
    check(`${name}: each finding row wears its category's colours, with a numeric count`, wrong.slice(0, 3), []);
  }

  // --- Capture: metadata and the legend ---------------------------------------------------
  {
    const capture = workbook.getWorksheet('Capture')!;
    const cells: string[] = [];
    let legendAt = 0;
    capture.eachRow((row, n) => {
      cells.push(String(row.getCell(1).value));
      if (row.getCell(1).value === 'Colour rule') legendAt = n;
    });
    checkTrue(`${name}: the Capture sheet carries the metadata`, cells.includes('Frames exported') && cells.includes('Generated'));
    checkTrue(`${name}: ...and a colour-rule legend`, legendAt > 0);
    const chain = new RuleMatcher().enabledRules();
    let total = 0;
    const wrong: string[] = [];
    for (let n = legendAt + 1; n <= capture.rowCount; n++) {
      const row = capture.getRow(n);
      const label = String(row.getCell(1).value);
      const rule = chain.find((r) => r.name === label) ?? null;
      const colors = rule ? resolveRuleColors(rule, THEME) : { background: THEME.surface.background, color: THEME.surface.foreground };
      if (fillOf(row.getCell(1)) !== argb(colors.background)) wrong.push(label);
      total += Number(row.getCell(3).value);
    }
    check(`${name}: each legend swatch is drawn in its rule's colours`, wrong, []);
    check(`${name}: the legend's counts cover every frame`, total, packets.length);
  }
}

/**
 * RawBytes past a cell. A segmentation-offload frame is up to 64 kB, and its
 * base64 is past the 32,767 characters a cell holds; Excel "repairs" such a
 * cell by cutting it. The writer leaves it empty, counts it, and says so.
 */
async function rawLimitChecks(capture: RealCapture): Promise<void> {
  const long = capture.packets.filter((p) => Math.ceil(p.rawBytes.length / 3) * 4 > EXCEL_CELL_CHARS);
  if (long.length === 0) {
    console.log(`SKIP  ${capture.name}: no frame is past the cell limit`);
    return;
  }
  const picked = capture.packets.filter((p, i) => i < 200 || long.includes(p));
  const { workbook } = await build(picked, { raw: true, fields: false });
  const sheet = workbook.getWorksheet('Packets')!;
  const rawColumn = headers(sheet).indexOf('RawBytes (Base64)') + 1;
  let longest = 0;
  const wrong: number[] = [];
  picked.forEach((p, i) => {
    const value = sheet.getRow(i + 2).getCell(rawColumn).value;
    const text = typeof value === 'string' ? value : '';
    longest = Math.max(longest, text.length);
    const fits = Math.ceil(p.rawBytes.length / 3) * 4 <= EXCEL_CELL_CHARS;
    if (fits ? text.length === 0 && p.rawBytes.length > 0 : text !== '') wrong.push(p.id);
  });
  check(`${capture.name}: no RawBytes cell is past ${EXCEL_CELL_CHARS} characters (longest ${longest})`, longest <= EXCEL_CELL_CHARS, true);
  check(`${capture.name}: the ${long.length} frames past the limit are empty, every other frame has its bytes`, wrong.slice(0, 5), []);
  let note = '';
  workbook.getWorksheet('Capture')!.eachRow((row) => {
    if (row.getCell(1).value === 'Frame bytes included') note = String(row.getCell(2).value);
  });
  checkTrue(`${capture.name}: the Capture sheet counts them and names pcapng and CSV`,
    note.includes(`except ${long.length.toLocaleString('en-US')} frame(s)`) && note.includes('pcapng') && note.includes('CSV'));
}

/** An anonymised workbook: adapters labelled as the metadata labels them, rule filters withheld. */
async function anonymisedChecks(capture: RealCapture): Promise<void> {
  const frames = capture.packets.slice(0, 300);
  const anonymiser = new Anonymiser();
  const matcher = new RuleMatcher();
  const rules = frames.map((p) => matcher.match(p));
  const survey = new FieldSurvey();
  survey.addPage(frames);
  const writer = await createXlsxWriter({
    includeRawBytes: false, fields: survey.columns(), expectedFrames: frames.length, expectedFieldCells: survey.cells,
    meta: {
      app: 'Inwire', version: 'dev', os: null, generatedAt: 0, source: { kind: 'session' },
      firstUs: frames[0].tsUs, lastUs: frames[frames.length - 1].tsUs,
      frames: { exported: frames.length, inCapture: frames.length, unreadable: 0 },
      drops: { kernel: null, agent: null, pipe: null }, scope: 'capture', filter: '',
      flags: { anonymised: true, rawBytes: false, fields: false, secrets: false },
    },
  });
  writer.write(frames.map((p) => anonymiser.packet(p)), rules);
  const [bytes] = await writer.finish();
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  const sheet = workbook.getWorksheet('Packets')!;
  check(`${capture.name}: an anonymised workbook has no field columns, though the real frames were surveyed`,
    headers(sheet), EXPORT_COLUMNS.map((c) => c.header));
  check(`${capture.name}: ...labels the adapter "adapter 1" with no anonymiser to map it`,
    sheet.getRow(2).getCell(col('interface')).value, 'adapter 1');
  const filters: string[] = [];
  let inLegend = false;
  workbook.getWorksheet('Capture')!.eachRow((row) => {
    if (inLegend) filters.push(String(row.getCell(2).value ?? ''));
    if (row.getCell(1).value === 'Colour rule') inLegend = true;
  });
  checkTrue(`${capture.name}: ...and withholds every rule filter in the legend (${filters.length})`,
    filters.length > 0 && filters.every((f) => f === '(withheld)' || f === ''));
}

async function budgetChecks(capture: RealCapture): Promise<void> {
  // Fields asked for with no cell count: the budget assumes every frame
  // carries every field, rather than that fields are free.
  {
    const frames = capture.packets.slice(0, 1000);
    const survey = new FieldSurvey();
    survey.addPage(frames);
    const columns = survey.columns();
    const room = frames.length * EXPORT_COLUMNS.length + survey.cells;
    const writer = await createXlsxWriter({
      includeRawBytes: false, fields: columns, expectedFrames: frames.length,
      budget: { rows: 1_048_575, cells: room },
    });
    check(`${capture.name}: with no field cell count, fields that fit only on the real count are not assumed to fit`,
      writer.writesFieldColumns, frames.length * columns.length <= survey.cells);
  }

  const packets = capture.packets.slice(0, 3000);
  const survey = new FieldSurvey();
  survey.addPage(packets);
  const standard = EXPORT_COLUMNS.length;

  // The arithmetic, pure.
  check('the shipped budget allows Excel\'s row limit', XLSX_BUDGET.rows, 1_048_575);
  check('fields that fit are written', planWorkbook(100, standard, 50, true, { rows: 1000, cells: 100 * standard + 50 }),
    { fields: true, droppedBecause: null });
  checkTrue('fields past the budget are dropped, and why is said',
    planWorkbook(100, standard, 51, true, { rows: 1000, cells: 100 * standard + 50 }).droppedBecause?.includes('CSV') === true);
  let refused: unknown = null;
  try { planWorkbook(100, standard, 0, false, { rows: 1000, cells: 100 * standard - 1 }); } catch (err) { refused = err; }
  checkTrue('standard columns past the budget are refused, naming CSV',
    refused instanceof XlsxTooLargeError && refused.message.includes('CSV'));
  refused = null;
  try { planWorkbook(1001, standard, 0, false, { rows: 1000, cells: 1e9 }); } catch (err) { refused = err; }
  checkTrue('more frames than the sheet has rows are refused', refused instanceof XlsxTooLargeError);

  // And through the writer, on real frames, with a budget forced tiny.
  const tight: XlsxBudget = { rows: 1_048_575, cells: packets.length * standard + survey.cells - 1 };
  const { workbook, writesFields } = await build(packets, { budget: tight });
  check(`${capture.name}: over the cell budget, the field columns are dropped`, writesFields, false);
  check(`${capture.name}: ...so the header is the standard columns alone`,
    headers(workbook.getWorksheet('Packets')!), EXPORT_COLUMNS.map((c) => c.header));
  let note = '';
  workbook.getWorksheet('Capture')!.eachRow((row) => {
    if (row.getCell(1).value === 'Dissected fields included') note = String(row.getCell(2).value);
  });
  checkTrue(`${capture.name}: ...and the Capture sheet says so`, note.startsWith('no - left out') && note.includes('CSV'));

  refused = null;
  try {
    await build(packets, { budget: { rows: 1_048_575, cells: packets.length * standard - 1 }, fields: false });
  } catch (err) { refused = err; }
  checkTrue(`${capture.name}: past the budget even without fields, the export is refused`, refused instanceof XlsxTooLargeError);

  // Rules matched by the caller - the anonymising path - are the ones painted.
  const { workbook: plain } = await build(packets.slice(0, 50), { rules: packets.slice(0, 50).map(() => null) });
  const row = plain.getWorksheet('Packets')!.getRow(2);
  check(`${capture.name}: rules handed in with the page are the ones painted`,
    [fillOf(row.getCell(1)), row.getCell(col('colourRule')).value], [argb(THEME.surface.background), null]);
}

async function main() {
  const captures = await loadRealCaptures();
  for (const capture of captures) await captureChecks(capture);
  for (const capture of captures) await rawLimitChecks(capture);
  if (captures.length > 0) await anonymisedChecks(captures[0]);
  if (captures.length > 0) await budgetChecks(captures[0]);

  console.log();
  if (failures > 0) {
    console.log(`${failures} assertion(s) FAILED`);
    process.exit(1);
  }
  console.log('All Excel style assertions passed.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  threw: ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
