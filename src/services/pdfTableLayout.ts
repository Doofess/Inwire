import { PDF_PACKET_TABLE_HEAD } from './pdfReportFormat';

/**
 * Rebuilding a table from positioned glyphs.
 *
 * Split out of `pdfTable.ts` and given no dependency on pdfjs, for a reason
 * worth stating: this is the guessy half of PDF import, and the half most
 * likely to be wrong. Keeping it pure - fragments in, rows out - is what lets
 * the assertion script drive it over a genuinely generated report instead of
 * leaving the riskiest code in the feature with no coverage at all.
 *
 * A PDF has no table. It has text at coordinates, and this file is the argument
 * that a particular arrangement of that text *was* a table.
 */

export interface Fragment {
  text: string;
  /** Left edge, in PDF user units. */
  x: number;
  /** Baseline. PDF's origin is bottom-left, so larger y is higher on the page. */
  y: number;
}

/** Text runs sharing a baseline, ordered left to right. */
export interface Line {
  y: number;
  fragments: Fragment[];
}

/** Fragments within this many PDF units of each other share a baseline. */
const LINE_TOLERANCE = 2.5;

const HEADER_CELLS = PDF_PACKET_TABLE_HEAD.map(h => h.toLowerCase());

export function groupIntoLines(fragments: Fragment[]): Line[] {
  const lines: Line[] = [];
  // Descending y: the top of the page is the largest y, so reading order is
  // the reverse of numeric order.
  for (const fragment of [...fragments].sort((a, b) => b.y - a.y || a.x - b.x)) {
    const line = lines[lines.length - 1];
    if (line && Math.abs(line.y - fragment.y) <= LINE_TOLERANCE) line.fragments.push(fragment);
    else lines.push({ y: fragment.y, fragments: [fragment] });
  }
  for (const line of lines) line.fragments.sort((a, b) => a.x - b.x);
  return lines;
}

/**
 * Whether this line is the Packet List table's header.
 *
 * Matched in full, which is what keeps this off the report's other two tables:
 * the Alerts table also begins ID/Proto/Source/Destination and diverges only at
 * the fifth column.
 */
export function isPacketHeader(line: Line): boolean {
  const cells = line.fragments.map(f => f.text.trim().toLowerCase()).filter(Boolean);
  if (cells.length !== HEADER_CELLS.length) return false;
  return cells.every((cell, i) => cell === HEADER_CELLS[i]);
}

/**
 * Column boundaries from the header row's own x positions, so this follows
 * whatever widths the table generator chose rather than assuming any. The
 * midpoint between two header x values is the boundary between their columns.
 */
function buildColumnBoundaries(header: Line): number[] {
  const xs = header.fragments.map(f => f.x);
  const bounds: number[] = [];
  for (let i = 1; i < xs.length; i++) bounds.push((xs[i - 1] + xs[i]) / 2);
  return bounds;
}

function columnOf(x: number, bounds: number[]): number {
  let column = 0;
  while (column < bounds.length && x >= bounds[column]) column++;
  return column;
}

export interface LayoutResult {
  /** Header row plus data rows, ready for `rowsToFrames`. Empty if none found. */
  rows: string[][];
  /** True once the packet table's header was seen on any page. */
  sawHeader: boolean;
}

/**
 * Walks the pages and extracts the packet table.
 *
 * @param pages one array of fragments per page, in page order.
 */
export function fragmentsToRows(pages: Fragment[][]): LayoutResult {
  const rows: string[][] = [];
  let bounds: number[] | null = null;
  let sawHeader = false;

  for (const fragments of pages) {
    const lines = groupIntoLines(fragments);
    // The table generator repeats the header on every page it continues onto,
    // so the scan runs per page and a repeat refreshes the boundaries rather
    // than being read as a data row.
    let inTable = bounds !== null;

    for (const line of lines) {
      if (isPacketHeader(line)) {
        bounds = buildColumnBoundaries(line);
        inTable = true;
        sawHeader = true;
        if (rows.length === 0) rows.push([...HEADER_CELLS]);
        continue;
      }
      if (!inTable || !bounds) continue;

      const cells: string[] = new Array(HEADER_CELLS.length).fill('');
      for (const fragment of line.fragments) {
        const column = Math.min(columnOf(fragment.x, bounds), cells.length - 1);
        cells[column] = cells[column] ? `${cells[column]} ${fragment.text}` : fragment.text;
      }

      // A row whose first column is empty is a wrapped continuation of the
      // previous row's Info cell, not a new frame. Without this the wrap
      // becomes a packet with no id, no addresses and half a sentence.
      if (!cells[0].trim() && rows.length > 1) {
        const previous = rows[rows.length - 1];
        const tail = cells.filter(Boolean).join(' ').trim();
        if (tail) previous[previous.length - 1] = `${previous[previous.length - 1]} ${tail}`.trim();
        continue;
      }

      // A section heading ("Active Security Alerts") also sits in column 0.
      // Requiring a numeric first cell keeps prose out of the packet table.
      if (!/^\d+$/.test(cells[0].trim())) {
        inTable = false;
        continue;
      }
      rows.push(cells);
    }
  }

  return { rows, sawHeader };
}
