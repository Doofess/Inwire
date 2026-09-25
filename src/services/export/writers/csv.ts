/**
 * CSV, a page at a time.
 *
 * The file is, in order:
 *
 *   1. A UTF-8 BOM. Excel decides a CSV's encoding from its first bytes and,
 *      with nothing to go on, falls back to the system codepage - which
 *      renders any non-ASCII character in an Info string as mojibake. The
 *      importer strips it again.
 *   2. The metadata, one quoted `# key: value` line per `metaEntries` entry.
 *      One cell each, so a spreadsheet shows them down column A above the
 *      table, and the importer recognises and skips them
 *      (`exportSchema.stripPreamble`) - a bare `#` is still a No. header.
 *   3. The header: the standard columns, then one per dissected field under
 *      its Wireshark name, then RawBytes when asked for.
 *   4. A row per frame.
 *
 * CRLF throughout, which is what RFC 4180 specifies and what Excel on Windows
 * expects. Every text cell is formula-guarded (`guardFormula`): Info carries
 * DNS names and HTTP hosts straight off the wire, and a CSV is exactly the
 * file a spreadsheet opens and evaluates.
 */
import type { ColorRule, Packet } from '../../../types/packet';
import { guardFormula, standardText, EXPORT_COLUMNS, RAW_BYTES_COLUMN } from '../../exportSchema';
import { metaEntries } from '../captureMeta';
import { fieldRow, type FieldColumn } from '../fieldColumns';
import { AdapterLabels, fieldColumnsFor, RuleSource, splitValues, type TabularOptions } from './tabular';
import { utf8, type ExportWriter } from './writer';

export const CSV_MIME = 'text/csv;charset=utf-8';

const BOM = '\uFEFF';
const EOL = '\r\n';

/**
 * Quoted whenever the value could otherwise change the row's shape - a comma,
 * a quote or a line break anywhere in it.
 */
export function csvCell(text: string): string {
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** Always quoted: a preamble line is prose, and one rule is simpler to read back than two. */
function quoted(text: string): string {
  return `"${text.replace(/"/g, '""')}"`;
}

export class CsvWriter implements ExportWriter {
  private started = false;
  private readonly rules: RuleSource;
  private readonly labels: AdapterLabels;
  private readonly fields: readonly FieldColumn[];
  private readonly kinds = EXPORT_COLUMNS.map((c) => c.kind);

  constructor(private readonly options: TabularOptions) {
    this.rules = new RuleSource(options.colorRules);
    this.labels = new AdapterLabels(options);
    this.fields = fieldColumnsFor(options);
  }

  write(page: readonly Packet[], rules?: readonly (ColorRule | null)[]): Uint8Array[] {
    const lines: string[] = [];
    if (!this.started) lines.push(this.head());
    const { includeRawBytes } = this.options;
    for (let i = 0; i < page.length; i++) {
      const packet = page[i];
      const { standard, raw } = splitValues(packet, this.rules.ruleAt(page, i, rules), includeRawBytes, this.kinds.length, this.labels);
      const cells = standard.map((value, c) => csvCell(standardText(this.kinds[c], value)));
      for (const value of fieldRow(packet, this.fields)) {
        cells.push(value === undefined ? '' : csvCell(typeof value === 'string' ? guardFormula(value) : String(value)));
      }
      if (includeRawBytes) cells.push(csvCell(standardText('base64', raw ?? null)));
      lines.push(cells.join(',') + EOL);
    }
    return lines.length > 0 ? [utf8(lines.join(''))] : [];
  }

  /** A capture with no frames is still a file: the preamble and the header. */
  finish(): Uint8Array[] {
    return this.started ? [] : [utf8(this.head())];
  }

  private head(): string {
    this.started = true;
    let text = BOM;
    if (this.options.meta) {
      for (const [key, value] of metaEntries(this.options.meta)) text += quoted(`# ${key}: ${value}`) + EOL;
    }
    const headers = [
      ...EXPORT_COLUMNS.map((c) => c.header),
      ...this.fields.map((f) => f.abbrev),
      ...(this.options.includeRawBytes ? [RAW_BYTES_COLUMN.header] : []),
    ];
    return text + headers.map(csvCell).join(',') + EOL;
  }
}
