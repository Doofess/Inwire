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
      let lo = 0;
      let hi = rows.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const at = rows[mid].id;
        if (at === id) { out.push(mid); break; }
        if (at < id) lo = mid + 1;
        else hi = mid - 1;
      }
    }
    return out.sort((a, b) => a - b);
  }
  for (let i = 0; i < rows.length; i++) if (marks.has(rows[i].id)) out.push(i);
  return out;
}
