/** The index of the row with `id` in rows sorted by id ascending, or -1. */
function bisect(rows: readonly { id: number }[], id: number): number {
  let lo = 0;
  let hi = rows.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = rows[mid].id;
    if (at === id) return mid;
    if (at < id) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * The rows of the minimap's mark ticks (ADR 0067): each marked frame's index
 * in the list as sorted, ascending. A mark on a frame the list does not hold
 * has no row and is left out.
 *
 * `idOrdered` says the rows are in the buffer's own order, id ascending, and
 * then each mark is found by bisection - a look per mark, which is what the
 * strip pays on nearly every repaint. Any other sort is one pass over the
 * rows, because the sort gives a row's id no relation to its index.
 */
export function markTickIndices(
  marks: ReadonlySet<number>, rows: readonly { id: number }[], idOrdered: boolean,
): number[] {
  if (marks.size === 0 || rows.length === 0) return [];
  const out: number[] = [];
  if (idOrdered) {
    for (const id of marks) {
      const at = bisect(rows, id);
      if (at !== -1) out.push(at);
    }
    return out.sort((a, b) => a - b);
  }
  for (let i = 0; i < rows.length; i++) if (marks.has(rows[i].id)) out.push(i);
  return out;
}

/**
 * The selected frame's row, or -1 when the list does not hold it. Bisected in
 * the buffer's own order, because the strip asks on every repaint and every
 * slice of its fill, and a finished import selects its FIRST frame; any other
 * sort is scanned from the end, where a live selection usually is.
 */
export function selectedRowIndex(rows: readonly { id: number }[], id: number, idOrdered: boolean): number {
  if (idOrdered) return bisect(rows, id);
  for (let i = rows.length - 1; i >= 0; i--) if (rows[i].id === id) return i;
  return -1;
}
