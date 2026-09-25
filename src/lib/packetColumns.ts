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
  | 'direction'
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
  // Between the number and the time, which is where it reads best: an arrow
  // is about the frame itself rather than about its contents, so it belongs
  // with the frame's identity rather than out among the addresses.
  'direction',
  'relativeTime',
  'source',
  'destination',
  'protocol',
  'length',
];

export const COLUMN_LABELS: Record<HideableColumn, string> = {
  id: 'No.',
  direction: 'Dir',
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

// ---------------------------------------------------------------------------
// Custom columns
// ---------------------------------------------------------------------------

/**
 * Columns added from the packet detail tree's "Apply as Column".
 *
 * Stored as registry abbreviations (`tls.handshake.extensions_server_name`)
 * rather than as label/accessor pairs, because the registry already holds the
 * label, the alignment and the fact that the field is offerable at all
 * (`FieldDef.column`). One name is enough to draw the column, and it is the
 * same name the filter language uses - so a column and a filter on the same
 * field can never disagree about what that field is.
 *
 * These sit between Length and Info in the list. The cap is not arbitrary: the
 * fixed columns already fill a narrow window, and past about half a dozen
 * additions the Info column - the one that always has something worth reading -
 * has no width left.
 */
export const MAX_CUSTOM_COLUMNS = 6;

export function normalizeCustomColumns(
  raw: unknown,
  /** Passed in rather than imported, so this module stays free of `services`. */
  isKnownField: (abbrev: string) => boolean,
): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') continue;
    // A column for a field the build no longer registers would draw an empty
    // cell under a header naming something that does not exist.
    if (!isKnownField(entry)) continue;
    if (out.includes(entry)) continue;
    out.push(entry);
    if (out.length === MAX_CUSTOM_COLUMNS) break;
  }
  return out;
}

/**
 * Where the text sits inside a column.
 *
 * Applies to the columns whose content is TEXT - Source, Destination, Protocol,
 * Info. No., Time and Length keep their right edge and their tabular figures
 * whatever this says, because that edge is what makes a column of numbers
 * comparable at a glance: ragged digits have to be read one at a time. The reference analyzer
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

/**
 * Where the text sits, per column.
 *
 * It used to be one setting for the whole list, and the restriction that came
 * with it: No., Time and Length were pinned right and excluded, because a
 * global "centre" would have centred the numbers too and broken the digit
 * alignment that is the entire reason those columns are right-aligned.
 *
 * Per-column removes the reason for the restriction rather than working around
 * it. Nobody sets Time to centred by accident now - they have to open that
 * column's own menu and choose it - so every column is offered, and the three
 * numeric ones simply DEFAULT to right.
 *
 * **Every column but Direction.** It holds one glyph rather than a value, so
 * it has no first letter to line up on the left and no digits to line up on
 * the right - centred is the only position that means anything, and the menu
 * offering Left and Right for it was a choice with no right answer but one.
 * It is centred, always, and its header opens no alignment menu.
 */
export type AlignableColumn = Exclude<SortField, 'direction'>;

export const ALIGNABLE_COLUMNS: readonly AlignableColumn[] = [
  ...HIDEABLE_COLUMNS.filter((c): c is Exclude<HideableColumn, 'direction'> => c !== 'direction'),
  'info',
];

export function isAlignableColumn(column: string | null | undefined): column is AlignableColumn {
  return ALIGNABLE_COLUMNS.includes(column as AlignableColumn);
}

export type ColumnAlignMap = Record<AlignableColumn, ColumnAlign>;

/**
 * Right for the three that are read as numbers, left for the rest.
 *
 * `id`, `relativeTime` and `length` are compared down the column - is this
 * frame bigger than that one, how far apart are these two timestamps - and a
 * ragged right edge makes that comparison impossible to do at a glance. The
 * address and text columns are read across instead, so they start at the left.
 */
export const DEFAULT_COLUMN_ALIGN: ColumnAlignMap = {
  id: 'right',
  relativeTime: 'right',
  length: 'right',
  source: 'left',
  destination: 'left',
  protocol: 'left',
  info: 'left',
};

export function isColumnAlign(raw: unknown): raw is ColumnAlign {
  return COLUMN_ALIGNS.includes(raw as ColumnAlign);
}

/**
 * Validates a stored alignment map, and carries the old single value across.
 *
 * The migration is the point. Before this, `align` was one string applied to
 * the text columns; discarding it would silently reset anyone who had chosen
 * centred or right, and they would have no idea why. A stored string is
 * therefore spread over exactly the columns it used to govern, with the
 * numeric three left on their own default - which reproduces what that setting
 * actually did.
 */
export function normalizeColumnAlign(raw: unknown): ColumnAlignMap {
  if (isColumnAlign(raw)) {
    return {
      ...DEFAULT_COLUMN_ALIGN,
      source: raw,
      destination: raw,
      protocol: raw,
      info: raw,
    };
  }
  if (typeof raw !== 'object' || raw === null) return { ...DEFAULT_COLUMN_ALIGN };
  const v = raw as Record<string, unknown>;
  const out = { ...DEFAULT_COLUMN_ALIGN };
  for (const column of ALIGNABLE_COLUMNS) {
    if (isColumnAlign(v[column])) out[column] = v[column] as ColumnAlign;
  }
  return out;
}

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
