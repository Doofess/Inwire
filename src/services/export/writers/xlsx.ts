/**
 * The Excel workbook.
 *
 * Four sheets, in the order a reader wants them:
 *
 *   * **Packets** - one row per frame, painted the way the packet list paints
 *     it. Sheet 1 with its header on row 1, because the importer reads the
 *     first sheet that looks like packets and takes row 1 as the header.
 *   * **Protocols** - the protocol hierarchy, indented and collapsible, with
 *     real numbers: frames and bytes as integers, shares as percentages.
 *   * **Findings** - the expert findings, grouped the way the Expert pane
 *     groups them, each row in its category's colours.
 *   * **Capture** - the metadata every format prints, and a legend of the
 *     colour rules this capture actually matched.
 *
 * ## The colours are the app's, in its Day theme
 *
 * A row's fill and text are its colour rule's, from
 * `getPacketThemeForApp('light')` - the same values the packet list uses on a
 * light theme, so a frame looks the same on paper as on screen. Day rather
 * than Night whatever the app shows, because a spreadsheet is a white document
 * and a dark row theme printed on it is a solid block of toner.
 *
 * Fills go on cells, never on a row: exceljs's `row.fill` is a row style,
 * which Excel applies to all 16,384 columns of the sheet, painting the empty
 * width to the right of the table. And one style object per (rule, number
 * format) is built once and **assigned** to each cell - not a fresh object per
 * cell, which on a whole-capture export is millions of identical objects.
 *
 * Only the standard columns are painted. The field columns are sparse - most
 * frames carry a small fraction of them - and a fill on an empty cell costs
 * exactly what a full one does; painted, they would be most of the workbook.
 * Unpainted, they read as what they are: the dissection, beside the list.
 *
 * ## Buffered, and so budgeted
 *
 * exceljs in the browser has no streaming writer - only `Workbook`, which
 * holds every cell until `writeBuffer` - so this is the one format that holds
 * its whole output. It is refused rather than attempted past what fits:
 * Excel's own limit of 1,048,576 rows, and a cell budget measured by
 * `scripts/perf/xlsx-cost.ts` on the real captures. Over the budget the field
 * columns go first, which the Capture sheet says; still over, the export is
 * refused and names CSV, which has no limit.
 */
import type { Borders, Fill, Font, Style, Workbook, Worksheet } from 'exceljs';

import type { ColorRule, ExpertCategory, Packet } from '../../../types/packet';
import {
  EXPORT_COLUMNS, RAW_BYTES_COLUMN, type ColumnKind, type StandardValue,
} from '../../exportSchema';
import { getPacketThemeForApp, type PacketTheme } from '../../packetThemes';
import { resolveRuleColors } from '../../colorRules';
import { HierarchyFold, type HierarchyNode } from '../../statistics';
import {
  CATEGORY_HINTS, CATEGORY_LABELS, EXPERT_RULE_ID, ExpertLog,
} from '../../expertInfo';
import { MARK_ACCENT, brandMarkPaths } from '../../../lib/brandMark';
import { APP_NAME } from '../../../lib/appVersion';
import { metaEntries, type MetaEntry } from '../captureMeta';
import { fieldRow, type FieldColumn } from '../fieldColumns';
import { AdapterLabels, fieldColumnsFor, RuleSource, splitValues, type TabularOptions } from './tabular';
import type { ExportWriter } from './writer';

export const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

// --- the budget -----------------------------------------------------------------

export interface XlsxBudget {
  /** Data rows on the Packets sheet: Excel's 1,048,576 less the header. */
  rows: number;
  /** Cells written on the Packets sheet - every standard cell, and every non-empty field cell. */
  cells: number;
}

/**
 * The cell budget, from `scripts/perf/xlsx-cost.ts` on both real captures.
 *
 * A Packets-sheet cell holds ~215 B of heap once its row is built, whatever
 * the capture; `writeBuffer` then serialises the whole model while it is still
 * alive, and that is the peak. Sampled with room to spare the peak settles to
 * ~530 B a cell as the workbook grows (the small workbooks read 1-1.2 kB,
 * which is fixed cost spread over few cells). Under a constrained heap it is
 * higher - V8 collects later than it could - and the constrained figure is the
 * one that decides whether an export completes: the bulk capture written four
 * times over, 2.66 million cells, **died at a 1,600 MB heap limit and finished
 * at 2,000 MB, peaking at 704 B a cell**. So 720.
 *
 * The export may spend `XLSX_HEAP_BUDGET` of it: the renderer's heap is
 * 4,192 MB, the packet buffer may hold up to half of that
 * (`bufferBudget.ts`, ADR 0036), and the rest of the app has to keep running
 * while the file is built. 1.25 GiB at 720 B is ~1.86 million cells - about
 * 110,000 frames of the standard columns, or ~45,000 with every field (the
 * fixtures average 27 fields a frame). Past that, a spreadsheet is the wrong
 * tool anyway, and the refusal names CSV.
 */
export const XLSX_BYTES_PER_CELL = 720;
export const XLSX_HEAP_BUDGET = 1.25 * 1024 * 1024 * 1024;

export const XLSX_BUDGET: XlsxBudget = {
  rows: 1_048_575,
  cells: Math.floor(XLSX_HEAP_BUDGET / XLSX_BYTES_PER_CELL),
};

/** The export does not fit in a workbook at all. The message names the way out. */
export class XlsxTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'XlsxTooLargeError';
  }
}

export interface XlsxPlan {
  /** Whether the field columns are written. */
  fields: boolean;
  /** Why they are not, when they were asked for; null otherwise. */
  droppedBecause: string | null;
}

const COUNT = new Intl.NumberFormat('en-US');

function tooLarge(frames: number, cells: number, budget: XlsxBudget): XlsxTooLargeError {
  const why = frames > budget.rows
    ? `${COUNT.format(frames)} frames is more rows than an Excel sheet holds (${COUNT.format(budget.rows)})`
    : `${COUNT.format(frames)} frames is ${COUNT.format(cells)} cells, more than a workbook built in memory `
      + `can hold (${COUNT.format(budget.cells)})`;
  return new XlsxTooLargeError(`${why}. Export as CSV instead - it has every column and no size limit.`);
}

/**
 * Decides, before a row is written, whether this export fits and with which
 * columns. Pure, so the arithmetic is tested without building a workbook.
 *
 * @param standardColumns the standard columns, raw bytes included when asked for
 * @param fieldCells non-empty field cells the survey counted (`FieldSurvey.cells`)
 */
export function planWorkbook(
  frames: number,
  standardColumns: number,
  fieldCells: number,
  wantFields: boolean,
  budget: XlsxBudget = XLSX_BUDGET,
): XlsxPlan {
  const standardCells = frames * standardColumns;
  if (frames > budget.rows || standardCells > budget.cells) throw tooLarge(frames, standardCells, budget);
  if (!wantFields || fieldCells === 0) return { fields: wantFields, droppedBecause: null };
  if (standardCells + fieldCells <= budget.cells) return { fields: true, droppedBecause: null };
  return {
    fields: false,
    droppedBecause: `left out: with every dissected field this workbook would be `
      + `${COUNT.format(standardCells + fieldCells)} cells, past the ${COUNT.format(budget.cells)} `
      + 'a workbook built in memory can hold. Export as CSV or JSON for every field.',
  };
}

export interface XlsxOptions extends TabularOptions {
  /**
   * Frames the export will write, from the survey. Decides whether the field
   * columns fit before the first row is built; `write` refuses past it.
   */
  expectedFrames: number;
  /**
   * Non-empty field cells, from `FieldSurvey.cells`. When absent with `fields`
   * given, the budget assumes the worst - every frame carrying every field -
   * rather than assuming the fields are free.
   */
  expectedFieldCells?: number;
  /** For tests; `XLSX_BUDGET` otherwise. */
  budget?: XlsxBudget;
  /**
   * The display filter, printed on the Capture sheet when there is no `meta`
   * to carry it - the one-shot entry point's only metadata.
   */
  filter?: string;
  /** When the workbook says it was made; now when absent. */
  now?: Date;
}

// --- colours and styles ----------------------------------------------------------------

/** `#rrggbb` or `#rgb` to exceljs's `AARRGGBB`. */
export function argb(hex: string): string {
  const h = hex.trim().replace(/^#/, '');
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h.slice(0, 6);
  return /^[0-9a-f]{6}$/i.test(full) ? `FF${full.toUpperCase()}` : 'FF000000';
}

const FONT_NAME = 'Calibri';
const FONT_SIZE = 10;
const WHITE = 'FFFFFFFF';
/** `--primary`, the brand's own blue, for the header of the frame columns. */
const HEADER = argb(MARK_ACCENT);
/**
 * The next plate down the mark's ramp, for the field and byte columns: the
 * same hue a step darker, so the header says where the packet list ends and
 * the dissection begins without introducing a colour.
 */
const HEADER_FIELDS = argb(brandMarkPaths('primary')[1].fill);

const NUM_FMT: Record<ColumnKind, string | undefined> = {
  integer: '0',
  seconds: '0.000000',
  epochMs: '@',
  datetime: 'yyyy-mm-dd hh:mm:ss.000',
  text: undefined,
  base64: undefined,
};
/** Length is a quantity, so it is grouped; a frame number or a stream is a name, so it is not. */
const LENGTH_FMT = '#,##0';

function solid(color: string): Fill {
  return { type: 'pattern', pattern: 'solid', fgColor: { argb: color } };
}

function thinBorder(color: string): Partial<Borders> {
  const side = { style: 'thin' as const, color: { argb: color } };
  return { top: side, left: side, bottom: side, right: side };
}

/**
 * Every style a cell of this workbook can have, built once each.
 *
 * exceljs serialises a cell's style by value, so sharing the object changes
 * nothing in the file - it changes the heap, which is the thing the budget
 * is spent on.
 */
class Styles {
  readonly theme: PacketTheme = getPacketThemeForApp('light');
  private readonly border: Partial<Borders>;
  private readonly baseFont: Partial<Font> = { name: FONT_NAME, size: FONT_SIZE };
  private readonly cache = new Map<string, Partial<Style>>();

  constructor() {
    this.border = thinBorder(argb(this.theme.surface.border));
  }

  /** A painted cell: the rule's colours, or the list's own ground when no rule matched. */
  row(rule: ColorRule | null, numFmt: string | undefined): Partial<Style> {
    const key = `r|${rule?.id ?? ''}|${numFmt ?? ''}`;
    let style = this.cache.get(key);
    if (!style) {
      const colors = rule
        ? resolveRuleColors(rule, this.theme)
        : { background: this.theme.surface.background, color: this.theme.surface.foreground };
      style = {
        font: { ...this.baseFont, color: { argb: argb(colors.color) } },
        fill: solid(argb(colors.background)),
        border: this.border,
        ...(numFmt ? { numFmt } : {}),
      };
      this.cache.set(key, style);
    }
    return style;
  }

  /** An unpainted data cell: the field columns, and the plain sheets. */
  plain(numFmt?: string, bold = false, indent = 0): Partial<Style> {
    const key = `p|${numFmt ?? ''}|${bold}|${indent}`;
    let style = this.cache.get(key);
    if (!style) {
      style = {
        font: bold ? { ...this.baseFont, bold: true } : this.baseFont,
        border: this.border,
        ...(numFmt ? { numFmt } : {}),
        ...(indent > 0 ? { alignment: { indent } } : {}),
      };
      this.cache.set(key, style);
    }
    return style;
  }

  header(fill: string = HEADER): Partial<Style> {
    const key = `h|${fill}`;
    let style = this.cache.get(key);
    if (!style) {
      style = {
        font: { ...this.baseFont, bold: true, color: { argb: WHITE } },
        fill: solid(fill),
        border: thinBorder(fill),
        alignment: { vertical: 'middle' },
      };
      this.cache.set(key, style);
    }
    return style;
  }
}

function headerRow(sheet: Worksheet, headers: readonly string[], styles: Styles, fills?: readonly string[]): void {
  const row = sheet.getRow(1);
  headers.forEach((text, i) => {
    const cell = row.getCell(i + 1);
    cell.value = text;
    cell.style = styles.header(fills?.[i]);
  });
  row.height = 20;
}

function freezeHeader(sheet: Worksheet, xSplit: number): void {
  sheet.views = [{
    state: 'frozen', xSplit, ySplit: 1,
    topLeftCell: xSplit > 0 ? 'B2' : 'A2', activeCell: xSplit > 0 ? 'B2' : 'A2',
  }];
}

function autoFilter(sheet: Worksheet, columns: number): void {
  sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns } };
}

// --- the writer --------------------------------------------------------------------------

type ExcelModule = typeof import('exceljs');

/**
 * exceljs resolves to a UMD bundle in the browser and to CommonJS under Node
 * (the assertion scripts), and the two disagree about whether the namespace
 * arrives as `default`. Accept both rather than guessing.
 */
async function loadExcel(): Promise<ExcelModule> {
  const imported = await import('exceljs');
  return ((imported as unknown as { default?: ExcelModule }).default ?? imported) as ExcelModule;
}

/** Excel stores a date as days since 1899-12-30; exceljs converts a `Date`, in UTC. */
function arrivalDate(tsUs: number): Date {
  return new Date(Math.floor(tsUs / 1000));
}

export async function createXlsxWriter(options: XlsxOptions): Promise<XlsxWriter> {
  return new XlsxWriter(await loadExcel(), options);
}

export class XlsxWriter implements ExportWriter {
  private readonly workbook: Workbook;
  private readonly packets: Worksheet;
  private readonly styles = new Styles();
  private readonly rules: RuleSource;
  private readonly labels: AdapterLabels;
  private readonly fields: readonly FieldColumn[];
  private readonly plan: XlsxPlan;
  private readonly budget: XlsxBudget;
  private readonly kinds: ColumnKind[] = EXPORT_COLUMNS.map((c) => c.kind);
  private readonly formats: (string | undefined)[];
  private readonly lastColumn: number;

  private readonly hierarchy = new HierarchyFold();
  /** Groups only: the per-frame category map is the app's, and a whole capture would fill it. */
  private readonly expert = new ExpertLog(false);
  /** Frames whose bytes were longer than a cell holds, and so left out of RawBytes. */
  private rawSkipped = 0;
  /** Other text cells cut to the cell limit. */
  private truncated = 0;
  private readonly ruleFrames = new Map<string, number>();
  private uncoloured = 0;
  private frames = 0;
  private cells = 0;
  private finished = false;

  constructor(excel: ExcelModule, private readonly options: XlsxOptions) {
    this.budget = options.budget ?? XLSX_BUDGET;
    const wanted = fieldColumnsFor(options);
    const standardColumns = EXPORT_COLUMNS.length + (options.includeRawBytes ? 1 : 0);
    const fieldCells = options.expectedFieldCells ?? options.expectedFrames * wanted.length;
    this.plan = planWorkbook(options.expectedFrames, standardColumns, fieldCells, wanted.length > 0, this.budget);
    this.fields = this.plan.fields ? wanted : [];
    this.rules = new RuleSource(options.colorRules);
    this.labels = new AdapterLabels(options);
    this.formats = EXPORT_COLUMNS.map((c) => (c.key === 'length' ? LENGTH_FMT : NUM_FMT[c.kind]));

    this.workbook = new excel.Workbook();
    this.workbook.creator = APP_NAME;
    this.workbook.created = options.now ?? new Date();

    this.packets = this.workbook.addWorksheet('Packets', { properties: { tabColor: { argb: HEADER } } });
    const headers = [
      ...EXPORT_COLUMNS.map((c) => c.header),
      ...this.fields.map((f) => f.abbrev),
      ...(options.includeRawBytes ? [RAW_BYTES_COLUMN.header] : []),
    ];
    this.lastColumn = headers.length;
    this.packets.columns = [
      ...EXPORT_COLUMNS.map((c) => ({ width: c.width })),
      ...this.fields.map((f) => ({ width: fieldWidth(f) })),
      ...(options.includeRawBytes ? [{ width: RAW_BYTES_COLUMN.width }] : []),
    ];
    headerRow(this.packets, headers, this.styles,
      headers.map((_, i) => (i < EXPORT_COLUMNS.length ? HEADER : HEADER_FIELDS)));
    freezeHeader(this.packets, 1);
    autoFilter(this.packets, headers.length);
  }

  write(page: readonly Packet[], rules?: readonly (ColorRule | null)[]): Uint8Array[] {
    if (this.finished) throw new Error('the workbook is already finished');
    const { includeRawBytes } = this.options;
    const standardCount = EXPORT_COLUMNS.length;
    for (let i = 0; i < page.length; i++) {
      const packet = page[i];
      this.frames += 1;
      if (this.frames > this.budget.rows) throw tooLarge(this.frames, this.cells, this.budget);

      const rule = this.rules.ruleAt(page, i, rules);
      if (rule) this.ruleFrames.set(rule.id, (this.ruleFrames.get(rule.id) ?? 0) + 1);
      else this.uncoloured += 1;
      this.hierarchy.add(packet);
      this.expert.add(packet);

      const { standard, raw } = splitValues(packet, rule, includeRawBytes, standardCount, this.labels);
      const row = this.packets.getRow(this.frames + 1);
      for (let c = 0; c < standardCount; c++) {
        const cell = row.getCell(c + 1);
        const value = this.cellValue(this.kinds[c], standard[c]);
        if (value !== null) cell.value = value;
        cell.style = this.styles.row(rule, this.formats[c]);
      }
      this.cells += standardCount;

      if (this.fields.length > 0) {
        const values = fieldRow(packet, this.fields);
        const plain = this.styles.plain();
        for (let f = 0; f < values.length; f++) {
          const value = values[f];
          if (value === undefined) continue;
          const cell = row.getCell(standardCount + f + 1);
          cell.value = typeof value === 'string' ? this.text(value) : value;
          cell.style = plain;
          this.cells += 1;
        }
      }
      if (includeRawBytes) {
        const cell = row.getCell(this.lastColumn);
        // A cell holds 32,767 characters, and base64 of a 24.6 kB frame is
        // longer - a segmentation-offload frame reaches 64 kB. Excel "repairs"
        // such a cell by cutting it, which leaves bytes that decode to a
        // different frame. Left empty and counted instead; the Capture sheet
        // says how many and where to get them.
        if (typeof raw === 'string') {
          if (raw.length > EXCEL_CELL_CHARS) this.rawSkipped += 1;
          else cell.value = raw;
        }
        cell.style = this.styles.plain();
        this.cells += 1;
      }
      // The survey said how many cells there would be; a capture that grew
      // past it - a live one, still appending - is held to the same line.
      if (this.cells > this.budget.cells) throw tooLarge(this.frames, this.cells, this.budget);
    }
    return [];
  }

  /** Cells written on the Packets sheet so far, as the budget counts them. */
  get cellsWritten(): number {
    return this.cells;
  }

  /** Whether the field columns are being written - false when the budget dropped them. */
  get writesFieldColumns(): boolean {
    return this.fields.length > 0;
  }

  async finish(): Promise<Uint8Array[]> {
    if (this.finished) return [];
    this.finished = true;
    this.protocolsSheet();
    this.findingsSheet();
    this.captureSheet();
    const buffer = await this.workbook.xlsx.writeBuffer();
    return [new Uint8Array(buffer as ArrayBuffer)];
  }

  /**
   * What the importer and a formula can both read: numbers as numbers, times
   * as dates - except epoch milliseconds, which are text. Excel keeps 15
   * significant digits and an epoch to the microsecond has 16, so as a number
   * it is shown, and re-saved, a microsecond short; as text it is exact, and a
   * reader who wants arithmetic has Time and Arrival.
   *
   * Strings are not formula-guarded here: a string cell in a workbook is never
   * evaluated, and the apostrophe the CSV needs would print as part of the
   * value. The guard is CSV's (`standardText`).
   */
  private cellValue(kind: ColumnKind, value: StandardValue): string | number | Date | null {
    if (value === null) return null;
    if (kind === 'datetime' && typeof value === 'number') return arrivalDate(value);
    if (kind === 'epochMs') return String(value);
    return typeof value === 'string' ? this.text(value) : value;
  }

  /** Text as a cell can hold it: cut at the limit, and counted when cut. */
  private text(value: string): string {
    if (value.length <= EXCEL_CELL_CHARS) return value;
    this.truncated += 1;
    return value.slice(0, EXCEL_CELL_CHARS);
  }

  private protocolsSheet(): void {
    const sheet = this.workbook.addWorksheet('Protocols', {
      properties: { outlineProperties: { summaryBelow: false, summaryRight: false } },
    });
    const headers = ['Protocol', 'Frames', '% of frames', 'Bytes', '% of bytes'];
    sheet.columns = [{ width: 34 }, { width: 13 }, { width: 14 }, { width: 16 }, { width: 14 }];
    headerRow(sheet, headers, this.styles);
    freezeHeader(sheet, 0);

    const h = this.hierarchy.result();
    let at = 2;
    const walk = (nodes: readonly HierarchyNode[], depth: number) => {
      for (const node of nodes) {
        const row = sheet.getRow(at++);
        const bold = depth === 0;
        const cells: [string | number, string | undefined][] = [
          [node.token, undefined],
          [node.packets, LENGTH_FMT],
          [h.packets > 0 ? node.packets / h.packets : 0, '0.0%'],
          [node.bytes, LENGTH_FMT],
          [h.bytes > 0 ? node.bytes / h.bytes : 0, '0.0%'],
        ];
        cells.forEach(([value, fmt], i) => {
          const cell = row.getCell(i + 1);
          cell.value = value;
          cell.style = this.styles.plain(fmt, bold, i === 0 ? depth : 0);
        });
        // Excel's outline goes seven deep; a deeper stack still indents.
        row.outlineLevel = Math.min(depth, 7);
        walk(node.children, depth + 1);
      }
    };
    walk(h.roots, 0);
    if (at > 2) autoFilter(sheet, headers.length);
  }

  private findingsSheet(): void {
    const sheet = this.workbook.addWorksheet('Findings');
    const headers = ['Category', 'Finding', 'Protocol', 'Count', 'First frames', 'What it means'];
    sheet.columns = [{ width: 15 }, { width: 60 }, { width: 13 }, { width: 11 }, { width: 44 }, { width: 56 }];
    headerRow(sheet, headers, this.styles);
    freezeHeader(sheet, 0);

    const categoryRules = new Map<ExpertCategory, ColorRule>();
    const groups = this.expert.groups();
    groups.forEach((group, index) => {
      const rule = categoryRules.get(group.category) ?? this.categoryRule(group.category);
      categoryRules.set(group.category, rule);
      const row = sheet.getRow(index + 2);
      const shown = group.frames.slice(0, FIRST_FRAMES);
      const values: (string | number)[] = [
        CATEGORY_LABELS[group.category],
        this.text(group.summary),
        this.text(group.protocol),
        group.count,
        shown.join(', ') + (group.count > shown.length ? ', ...' : ''),
        CATEGORY_HINTS[group.category],
      ];
      values.forEach((value, i) => {
        const cell = row.getCell(i + 1);
        cell.value = value;
        cell.style = this.styles.row(rule, i === 3 ? LENGTH_FMT : undefined);
      });
    });
    if (groups.length > 0) autoFilter(sheet, headers.length);
  }

  /** The rule a category paints its rows with, as a stand-in rule the style cache can key on. */
  private categoryRule(category: ExpertCategory): ColorRule {
    return { id: EXPERT_RULE_ID[category], name: CATEGORY_LABELS[category], filter: '', enabled: true };
  }

  private captureSheet(): void {
    const sheet = this.workbook.addWorksheet('Capture');
    sheet.columns = [{ width: 30 }, { width: 64 }, { width: 12 }, { width: 10 }];
    headerRow(sheet, ['Capture', 'Value'], this.styles);

    let at = 2;
    for (const [key, value] of this.metadata()) {
      const row = sheet.getRow(at++);
      const k = row.getCell(1);
      k.value = key;
      k.style = this.styles.plain(undefined, true);
      const v = row.getCell(2);
      v.value = this.text(value);
      v.style = this.styles.plain();
    }

    // The legend: every rule this export's frames matched, in chain order,
    // drawn in its own colours - the key to the Packets sheet's fills.
    at += 1;
    const legendHeader = sheet.getRow(at++);
    ['Colour rule', 'Filter', 'Frames', 'Share'].forEach((text, i) => {
      const cell = legendHeader.getCell(i + 1);
      cell.value = text;
      cell.style = this.styles.header();
    });
    legendHeader.height = 20;
    const total = this.frames;
    const legendRow = (rule: ColorRule | null, name: string, filter: string, frames: number) => {
      const row = sheet.getRow(at++);
      const swatch = row.getCell(1);
      swatch.value = name;
      swatch.style = this.styles.row(rule, undefined);
      const f = row.getCell(2);
      f.value = this.text(this.labels.filter(filter));
      f.style = this.styles.plain();
      const n = row.getCell(3);
      n.value = frames;
      n.style = this.styles.plain(LENGTH_FMT);
      const s = row.getCell(4);
      s.value = total > 0 ? frames / total : 0;
      s.style = this.styles.plain('0.0%');
    };
    for (const rule of this.rules.enabledRules()) {
      const frames = this.ruleFrames.get(rule.id);
      if (frames) legendRow(rule, rule.name, rule.filter, frames);
    }
    if (this.uncoloured > 0) legendRow(null, 'No colour rule', '', this.uncoloured);
  }

  /** The Capture sheet's key/value rows: the metadata, with what the budget changed. */
  private metadata(): MetaEntry[] {
    const meta = this.options.meta;
    const entries: MetaEntry[] = meta
      ? metaEntries(meta)
      : [
        ['Application', APP_NAME],
        ['Generated', (this.options.now ?? new Date()).toISOString()],
        ['Frames exported', COUNT.format(this.frames)],
        ['Display filter', this.options.filter?.trim() || '(none - full capture)'],
        ['Frame bytes included', this.options.includeRawBytes ? 'yes' : 'no'],
      ];
    if (!meta) entries.push(['Dissected fields included', this.fields.length > 0 ? 'yes' : 'no']);
    const out = entries.map(([key, value]): MetaEntry => {
      if (key === 'Dissected fields included' && this.plan.droppedBecause !== null) {
        return [key, `no - ${this.plan.droppedBecause}`];
      }
      if (key === 'Frame bytes included' && this.rawSkipped > 0) {
        return [key, `yes - except ${COUNT.format(this.rawSkipped)} frame(s) longer than an Excel cell `
          + `holds (${COUNT.format(EXCEL_CELL_CHARS)} characters of base64), whose RawBytes cell is empty. `
          + 'Export as pcapng or CSV for every frame\'s bytes.'];
      }
      return [key, value];
    });
    if (this.truncated > 0) {
      out.push(['Cells cut short', `${COUNT.format(this.truncated)} text cell(s) were longer than the `
        + `${COUNT.format(EXCEL_CELL_CHARS)} characters a cell holds and end at that limit. CSV has them whole.`]);
    }
    return out;
  }
}

/**
 * A field column's width: wide enough for its header and its filter button,
 * and for a typical value of its type - a MAC is 17 characters whatever its
 * name, and a truncated address is a wrong one to the eye.
 */
function fieldWidth(column: FieldColumn): number {
  const byType: Partial<Record<NonNullable<FieldColumn['type']>, number>> = {
    mac: 19, ipv4: 16, ipv6: 30, string: 28, bytes: 28, time: 24,
  };
  const value = column.type ? byType[column.type] ?? 10 : 16;
  return Math.min(48, Math.max(value, column.abbrev.length + 4));
}

/** The most characters an Excel cell holds; past it, Excel repairs the file by cutting. */
export const EXCEL_CELL_CHARS = 32_767;

/** How many frame numbers a Findings row lists before "...". */
const FIRST_FRAMES = 10;
