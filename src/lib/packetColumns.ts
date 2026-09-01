/**
 * Which columns the packet list shows, and what that means for sorting.
 *
 * Pure, and in `lib` rather than inside the component, so the sort-fallback
 * rule below can be asserted. It is a rule with a sharp edge and no visible
 * symptom when it goes wrong: the list would simply be ordered by something the
 * reader cannot see.
 */

/** Columns that can be hidden. `info` is not one - see below. */
export type HideableColumn =
  | 'id'
  | 'relativeTime'
  | 'source'
  | 'destination'
  | 'protocol'
  | 'length';

/**
 * Everything the list can sort by.
 *
 * `info` is in here but not in `HideableColumn`: it is the flex column that
 * absorbs whatever width the fixed ones leave, and hiding it would leave a gap
 * no other column expands into. It is also the one column that always has
 * something worth reading, which is why it is the one that always stays.
 */
export type SortField = HideableColumn | 'info';

export const HIDEABLE_COLUMNS: readonly HideableColumn[] = [
  'id',
  'relativeTime',
  'source',
  'destination',
  'protocol',
  'length',
];

export const COLUMN_LABELS: Record<HideableColumn, string> = {
  id: 'No.',
  relativeTime: 'Time',
  source: 'Source',
  destination: 'Destination',
  protocol: 'Protocol',
  length: 'Length',
};

/**
 * Columns hidden by default.
 *
 * None. Every column the list can draw is one somebody would expect to see, so
 * the menu starts from everything on and only ever subtracts. Kept as a named
 * constant rather than inlined `true`, because "which columns start hidden" is
 * the kind of thing that acquires an entry later and should have one place to
 * acquire it in.
 */
export const DEFAULT_HIDDEN: readonly HideableColumn[] = [];

export type ColumnVisibility = Record<HideableColumn, boolean>;

export function defaultColumnVisibility(): ColumnVisibility {
  return Object.fromEntries(
    HIDEABLE_COLUMNS.map((c) => [c, !DEFAULT_HIDDEN.includes(c)]),
  ) as ColumnVisibility;
}

export function normalizeColumnVisibility(raw: unknown): ColumnVisibility | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const v = raw as Record<string, unknown>;
  const out = defaultColumnVisibility();
  // Field by field: a column added in a later build simply keeps its default
  // rather than the whole stored value being thrown away.
  for (const column of HIDEABLE_COLUMNS) {
    if (typeof v[column] === 'boolean') out[column] = v[column] as boolean;
  }
  // At least one hideable column must survive. A list of nothing but the Info
  // column is not a table, and there would be no header left to right-click to
  // get the columns back.
  if (!HIDEABLE_COLUMNS.some((c) => out[c])) out.id = true;
  return out;
}

/**
 * Where the text sits inside a column.
 *
 * Applies to the columns whose content is TEXT - Source, Destination, Protocol,
 * Info. No., Time and Length keep their right edge and their tabular figures
 * whatever this says, because that edge is what makes a column of numbers
 * comparable at a glance: ragged digits have to be read one at a time. Wireshark
 * right-aligns them for the same reason.
 *
 * `left` is what the list has always shown, so nothing moves for anyone who
 * does not go looking for the setting.
 */
export type ColumnAlign = 'left' | 'center' | 'right';

export const COLUMN_ALIGNS: readonly ColumnAlign[] = ['left', 'center', 'right'];

export const COLUMN_ALIGN_LABELS: Record<ColumnAlign, string> = {
  left: 'Left',
  center: 'Centered',
  right: 'Right',
};

/** Tailwind's classes for each, for the cells and for the header buttons. */
export const COLUMN_ALIGN_CLASS: Record<ColumnAlign, string> = {
  left: 'text-left',
  center: 'text-center',
  right: 'text-right',
};

/** The header buttons are flex rows, so they need a justification, not an alignment. */
export const COLUMN_ALIGN_JUSTIFY: Record<ColumnAlign, string> = {
  left: 'justify-start',
  center: 'justify-center',
  right: 'justify-end',
};

/**
 * The field the list should actually sort by.
 *
 * A user can sort by Protocol and then hide Protocol. Left alone, the list
 * stays in an order with no visible explanation - rows that look shuffled, and
 * no header carrying a sort arrow to explain why.
 *
 * Falling back to `id` also happens to restore the list's fast path: sorting by
 * anything else copies and sorts the whole buffer on every flush, so this guard
 * is a performance fix wearing a correctness fix's clothes.
 */
export function visibleSortField(field: SortField, columns: ColumnVisibility): SortField {
  // Always present, so a sort by it is always explicable.
  if (field === 'info') return 'info';
  return columns[field] ? field : 'id';
}
