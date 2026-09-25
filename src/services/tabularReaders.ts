import type { ImportFailure } from './exportSchema';
import { matchHeaders, REQUIRED_COLUMNS, stripPreamble } from './exportSchema';

/**
 * Turning a file into a table of strings.
 *
 * Everything here stops at `string[][]`; deciding whether those strings are
 * packets is `exportSchema.rowsToFrames`'s job. The split matters because the
 * evaluator then behaves identically no matter which format a table arrived in
 * - a CSV and a spreadsheet fail for the same reasons, with the same wording.
 */

export type TableResult =
  | { ok: true; rows: string[][] }
  | { ok: false; failure: ImportFailure };

/** Extensions this module can turn into a table. */
export const TABULAR_EXTENSIONS = ['.csv', '.tsv', '.xlsx', '.xlsm', '.xls'];

export function extensionOf(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot === -1 ? '' : filename.slice(dot).toLowerCase();
}

// --- CSV ---------------------------------------------------------------------

/**
 * RFC 4180, rather than `split(',')`.
 *
 * Our own `info` column routinely contains commas, and quoting it is only half
 * a format - something has to un-quote it. Embedded newlines inside a quoted
 * field are handled too: they are rare from our writer but ordinary in a
 * spreadsheet someone exported by hand, and a naive line split turns one of
 * them into two broken rows.
 */
export function parseDelimited(text: string, delimiter: string): string[][] {
  // A BOM read as data becomes part of the first header cell, which is enough
  // to stop 'No.' matching anything.
  const input = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;

  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];

    if (quoted) {
      if (char === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"' && field === '') {
      quoted = true;
    } else if (char === delimiter) {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (char !== '\r') {
      field += char;
    }
  }

  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows;
}

async function readCsv(file: File, delimiter: string): Promise<TableResult> {
  const text = await file.text();
  if (!text.trim()) {
    return { ok: false, failure: { kind: 'no-table', message: 'The file is empty.' } };
  }
  // A binary file renamed .csv - an image, a pcap - decodes to text full of
  // replacement characters. Saying so is more useful than letting it fail later
  // as "missing required columns", which invites the user to go looking for
  // columns in a JPEG.
  if (/�/.test(text.slice(0, 4096))) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message: 'This file is not text. It looks like binary data with a .csv name.',
      },
    };
  }
  return { ok: true, rows: parseDelimited(text, delimiter) };
}

// --- Excel -------------------------------------------------------------------

/**
 * A cell's displayed text.
 *
 * exceljs hands back rich text, hyperlink, formula and date objects as well as
 * primitives, and every one of them stringifies to "[object Object]" if passed
 * straight to String().
 */
function cellText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return String(value.getTime());
  if (typeof value === 'object') {
    const cell = value as {
      richText?: { text: string }[];
      text?: string;
      result?: unknown;
      hyperlink?: string;
      error?: string;
    };
    if (Array.isArray(cell.richText)) return cell.richText.map(part => part.text).join('');
    if (cell.text !== undefined) return String(cell.text);
    if (cell.result !== undefined) return cellText(cell.result);
    if (cell.error !== undefined) return String(cell.error);
    return '';
  }
  return String(value);
}

async function readXlsx(file: File): Promise<TableResult> {
  let workbook;
  try {
    const imported = await import('exceljs');
    const ExcelJS = ((imported as unknown as { default?: typeof imported }).default
      ?? imported) as typeof imported;
    workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(await file.arrayBuffer());
  } catch (err) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message:
          'This workbook could not be opened. Note that the old .xls format is not '
          + 'supported - re-save it as .xlsx. '
          + `(${err instanceof Error ? err.message : String(err)})`,
      },
    };
  }

  const sheets: string[][][] = [];
  workbook.eachSheet(worksheet => {
    const rows: string[][] = [];
    worksheet.eachRow({ includeEmpty: false }, excelRow => {
      // `values` is 1-based with a hole at index 0, which is exceljs's own
      // convention and not something to be clever about.
      const values = excelRow.values as unknown[];
      const cells: string[] = [];
      for (let i = 1; i < values.length; i++) cells.push(cellText(values[i]));
      rows.push(cells);
    });
    if (rows.length > 0) sheets.push(rows);
  });

  if (sheets.length === 0) {
    return { ok: false, failure: { kind: 'no-table', message: 'This workbook has no sheets with data in them.' } };
  }

  // Our own export puts Packets first, but a foreign workbook may keep the
  // packet table on any sheet - so pick the first sheet that actually looks
  // like packet data, and fall back to the first sheet so the failure message
  // names real headers the user can see rather than an arbitrary sheet's.
  const match = sheets.find(rows => {
    const columns = matchHeaders(stripPreamble(rows)[0] ?? []);
    return REQUIRED_COLUMNS.every(key => columns[key] !== undefined);
  });
  return { ok: true, rows: match ?? sheets[0] };
}

// --- Dispatch ----------------------------------------------------------------

export async function readTabularFile(file: File): Promise<TableResult> {
  switch (extensionOf(file.name)) {
    case '.csv':
      return readCsv(file, ',');
    case '.tsv':
      return readCsv(file, '\t');
    case '.xlsx':
    case '.xlsm':
    case '.xls':
      return readXlsx(file);
    default:
      return {
        ok: false,
        failure: {
          kind: 'unreadable',
          message: `Inwire cannot read ${extensionOf(file.name) || 'a file with no extension'} as a table.`,
        },
      };
  }
}
