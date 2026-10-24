import React, { useState, useEffect, useRef } from 'react';
import { Packet } from '../../types/packet';
import { virtualWindow } from '../../lib/virtualWindow';
import { arrayRowSource, packetAt, rowSlice } from '../../lib/rowSource';
import { useCaptureRows, type CaptureFilterView } from '../../lib/useCaptureRows';
import type { CaptureFilterState } from '../../lib/useCaptureFilter';
import {
  Direction, DirectionSignal, DIRECTION_LABEL, SIGNAL_LABEL,
  directionOf, signalOf,
} from '../../services/direction';
import { ColorRulesEngine } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';
import { SENDER_INK_ALPHA } from '../../services/packetThemes';
import { PacketListMinimap } from './PacketListMinimap';
import { PlaceholderRow } from './PlaceholderRow';
import { DirectionMark } from './DirectionMark';
import { copyText } from '../ui/CopyButton';
import {
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  MessageSquare,
  ArrowRightLeft,
  Funnel,
  FunnelX,
  SearchX,
  Radar,
  History,
  Cable,
  Copy,
} from 'lucide-react';
import { EmptyState, EmptyStateButton, Kbd } from '../common/EmptyState';
import { packetHexDump } from '../../services/pcapParser';
import { hasBytes, packetBytes } from '../../services/packetBytes';
import { fieldValue } from '../../services/dissect/fieldAccess';
import { minimapStore, packetListStore } from '../../services/interfacePrefs';
import { formatTimeColumn } from '../../lib/formatTimeColumn';
import { ColumnOptionsMenu } from './ColumnOptionsMenu';
import {
  COLUMN_ALIGNS,
  COLUMN_ALIGN_CLASS,
  COLUMN_ALIGN_LABELS,
  COLUMN_JUSTIFY_CLASS,
  COLUMN_LABELS,
  HIDEABLE_COLUMNS,
  isAlignableColumn,
  visibleSortField,
  type AlignableColumn,
  type ColumnAlign,
  type SortField as ColumnSortField,
} from '../../lib/packetColumns';
import { fieldDef } from '../../services/dissect/fieldRegistry';
import type { NameLookup } from '../../services/nameResolution';
import { targetForPacket, type StreamTarget } from '../../services/followStream';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuLabel,
  ContextMenuRadioGroup,
  ContextMenuRadioItem,
  ContextMenuTrigger,
} from '../ui/context-menu';
import { usePreferenceStore, usePreferenceValue } from '../../services/preferenceStore';
import {
  loadPreference,
  useDebouncedPreference,
  usePreferenceSync,
} from '../../services/preferences';
import { MICRO_LABEL } from '../common/typography';

interface PacketListProps {
  /**
   * The previous capture, still on disk and offered rather than loaded. The
   * empty list is where it is offered, because an empty list is what a launch
   * shows and what a reader looks at to see what is there. Null when there is
   * nothing to offer, or once the buffer holds anything.
   */
  previousCapture?: { label: string; onReopen: () => void } | null;
  /** Whether a capture is running, so an empty list can say it is waiting rather than idle. */
  capturing?: boolean;
  /** Opens the adapter panel, from the empty list's "Choose an adapter". */
  onChooseAdapter?: () => void;
  /** Clears the display filter, from the empty list's "Clear filter". */
  onClearFilter?: () => void;
  /**
   * What the capture says its addresses are called, from the passive name map.
   *
   * Display only: `packet.source` stays the address everywhere else, so a
   * filter, an export and the row the user is looking at all still agree about
   * what this frame is. Omit, or leave `resolveNames` false, and the columns
   * show addresses.
   */
  names?: NameLookup;
  resolveNames?: boolean;
  /**
   * The program that sent a frame, for the Source column, or null.
   *
   * Passed in rather than looked up here for the same reason `names` is: this
   * component renders a list and does not own what anything is called. The
   * caller answers only for frames that actually left this machine - see
   * `sendingProcessName`.
   *
   * Display only, exactly like a resolved name. `packet.source` is still the
   * address in every filter, every export and every statistics table, so the
   * row and the filter that selects it cannot disagree.
   */
  sourceProcess?: (packet: Packet) => string | null;
  /** What the list shows: the RAM window with the display filter applied. */
  packets: Packet[];
  /**
   * The same window with no filter applied - the buffer itself.
   *
   * Both are needed, and which is which matters. `below` was measured against
   * the buffer's first frame, so the capture's row space is indexed by the
   * unfiltered window; the filtered one is the rows to SHOW from `below`
   * upward. Passing one for the other shifts every row by the number of
   * frames the filter hid.
   *
   * `packets === allPackets` is how "no filter is applied" is known, which is
   * the same identity check `App.tsx`'s selection-visibility effect uses.
   */
  allPackets: Packet[];
  /**
   * Rows of the capture below the RAM window. `useWindowOrdinal.ts`.
   *
   * Passed in rather than asked for here because the filter scan is gated on
   * the same number, and two hooks asking the store the same question can
   * disagree with each other for a frame.
   */
  below: number;
  /**
   * The capture's first ordinal still held: above 0 once the agent's ring has
   * deleted files, and the list starts there (ADR 0052).
   */
  floor?: number;
  /**
   * The display filter run over the whole capture, or `off`.
   *
   * Only `ready` lets the list address the disk while a filter is applied.
   * Scanning, failed, or a capture that fits in memory all fall back to the
   * window - which is what the list did before any of this, and is still the
   * right answer for the ~700k frames the buffer holds.
   */
  filterScan: CaptureFilterState;
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  /** Double-clicking a row opens the Frame Detail view on that frame. */
  onInspectPacket?: (packet: Packet) => void;
  onFollowStream: (target: StreamTarget, view?: 'dialogue' | 'ladder') => void;
  onQuickFilter: (filter: string) => void;
  /**
   * Frames the buffer has dropped since this capture began, or 0.
   *
   * A display filter can only match what is still held, and a trimmed frame is
   * not unmatched - it is invisible. "No packets match" is then a claim about
   * the capture that the app cannot make, and is the wrong answer in the one
   * case a reader most needs the right one: a filter that finds nothing is
   * exactly when they wonder whether it is the filter or the traffic.
   */
  droppedBuffer?: number;
  colorEngine: ColorRulesEngine;
  /** Colors for the list itself. Independent of the app theme by design -
   *  see services/packetThemes. */
  packetTheme: PacketTheme;
  themeKey?: string;
}

/**
 * Aliased rather than re-declared.
 *
 * This used to be a second hand-written copy of the union in
 * `lib/packetColumns.ts`, and the two were free to drift - adding a column
 * there compiled fine and then failed here, with the local copy silently
 * deciding what the list could sort by. One definition, one place to add to.
 */
type SortField = ColumnSortField;
type SortOrder = 'asc' | 'desc';

// 'info' is deliberately excluded: it's the last column and always absorbs
// whatever width the fixed-width columns don't use, the same way VS Code's
// rightmost panel does - it never needs its own draggable handle.
type ColumnKey = 'id' | 'direction' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length';

const COLUMN_WIDTHS_STORAGE_KEY = 'inwire.packetListColumnWidths';
const SORT_STORAGE_KEY = 'inwire.packetListSort';
const DEFAULT_COLUMN_WIDTHS: Record<ColumnKey, number> = {
  id: 64,
  // One glyph and a header of three letters. Narrow on purpose: this column
  // earns its place by being scannable down the page, not by being read.
  direction: 40,
  relativeTime: 116,
  source: 280,
  destination: 280,
  protocol: 76,
  length: 68,
};

/**
 * Width of a column added from the detail tree.
 *
 * One number for all of them rather than an entry per field: the stored widths
 * above are keyed by the six built-in columns and are resized by dragging a
 * handle between them, and a column that can be added and removed at will has
 * no stable slot in that map. Wide enough for a server name or a JA4, which
 * are what these columns are usually added for.
 */
const CUSTOM_COLUMN_WIDTH = 200;

/**
 * The tooltip for one frame's direction.
 *
 * The word, and what decided it. An arrow a reader did not expect is owed a
 * reason, and "the capture adapter's MAC said so" and "the frame was too big
 * to have arrived over Ethernet" are very different amounts of confidence to
 * have in the same glyph - so both are said rather than only the first.
 */
function directionTitle(slot: number | undefined): string {
  const direction = directionOf(slot);
  if (direction === Direction.Unknown) {
    return 'Unknown - nothing identified the capturing host';
  }
  const label = DIRECTION_LABEL[direction];
  const because = SIGNAL_LABEL[signalOf(slot)];
  const inferred = signalOf(slot) === DirectionSignal.InferredHost
    ? ' (inferred, not read from an adapter)' : '';
  return `${label} - from ${because}${inferred}`;
}
/**
 * The three densities, as designed pairs.
 *
 * Padding and text size move together rather than being offered as two
 * controls. Nine combinations of the two would include several that are simply
 * unreadable - 10px text with comfortable padding reads as a bug, not a choice
 * - and the presets are the three anybody actually wants.
 *
 * Row height is not listed here because it is MEASURED, not declared. Stating
 * it would be stating it twice, and the two would drift the first time a
 * padding value changed.
 *
 * **The line height is whole pixels, never a ratio**, so that the row is. It
 * was `leading-[1.15]` at 11px - a 20.641px row - and every row's top was then
 * `index * 20.641`, a different fraction of a pixel for each one. While a
 * capture follows, the pin to the bottom moves the list by a fractional amount
 * on every flush, so each row re-snapped its text to the pixel grid a beat
 * apart from its neighbours: the whole list wobbled by a pixel as it scrolled
 * (the owner's report). Whole-pixel rows put every row on the grid at every
 * scroll position. The values are the old ratios rounded: 11, 12.65 -> 13 and
 * 17.4 -> 17.
 */
const DENSITY_CLASS: Record<'compact' | 'default' | 'comfortable', { body: string; cell: string }> = {
  compact: { body: 'font-mono text-[10px] leading-[11px]', cell: 'py-0.5' },
  default: { body: 'font-mono text-[11px] leading-[13px]', cell: 'py-1' },
  comfortable: { body: 'font-mono text-[12px] leading-[17px]', cell: 'py-1.5' },
};

const MIN_COLUMN_WIDTH = 36;
const MAX_COLUMN_WIDTH = 480;

/**
 * Validates a stored width map field by field: an unknown key is ignored, a
 * non-numeric or absent one keeps its default, and an out-of-range one is
 * clamped rather than thrown away. A hand-edited or stale value can therefore
 * cost at most the fields it actually got wrong.
 *
 * Declared at module scope, not inside the component: usePreferenceSync takes
 * it as a dependency, and a new function identity every render would
 * resubscribe the storage listener every render.
 */
function normalizeColumnWidths(raw: unknown): Record<ColumnKey, number> | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const parsed = raw as Record<string, unknown>;
  const result = { ...DEFAULT_COLUMN_WIDTHS };
  (Object.keys(DEFAULT_COLUMN_WIDTHS) as ColumnKey[]).forEach(key => {
    const value = parsed[key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      result[key] = Math.min(MAX_COLUMN_WIDTH, Math.max(MIN_COLUMN_WIDTH, value));
    }
  });
  return result;
}

/**
 * Module scope for the same reason as normalizeColumnWidths: a fresh identity
 * every render would resubscribe the storage listener every render.
 *
 * An unknown field name is rejected rather than clamped - unlike a width,
 * there is no nearest valid sort column, and sorting by a field that does not
 * exist would render an empty list with no clue why.
 */
const SORT_FIELDS: SortField[] = ['id', 'direction', 'relativeTime', 'source', 'destination', 'protocol', 'length', 'info'];

function normalizeSort(raw: unknown): { field: SortField; order: SortOrder } | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const value = raw as Record<string, unknown>;
  const field = SORT_FIELDS.find(f => f === value.field);
  if (!field) return null;
  return { field, order: value.order === 'desc' ? 'desc' : 'asc' };
}

function loadStoredColumnWidths(): Record<ColumnKey, number> {
  return loadPreference(COLUMN_WIDTHS_STORAGE_KEY, normalizeColumnWidths, {
    ...DEFAULT_COLUMN_WIDTHS,
  });
}

export const PacketList: React.FC<PacketListProps> = ({
  names,
  resolveNames = false,
  sourceProcess,
  packets,
  allPackets,
  below,
  floor = 0,
  filterScan,
  selectedPacket,
  onSelectPacket,
  onInspectPacket,
  onFollowStream,
  onQuickFilter,
  droppedBuffer = 0,
  colorEngine,
  packetTheme,
  themeKey,
  previousCapture = null,
  capturing = false,
  onChooseAdapter,
  onClearFilter,
}) => {
  // Restored from the last session, so a refresh keeps the column the user
  // was sorting by rather than snapping back to packet number.
  const storedSort = React.useMemo(
    () => loadPreference(SORT_STORAGE_KEY, normalizeSort, { field: 'id' as SortField, order: 'asc' as SortOrder }),
    [],
  );
  const [sortField, setSortField] = useState<SortField>(storedSort.field);
  const [sortOrder, setSortOrder] = useState<SortOrder>(storedSort.order);
  useDebouncedPreference(
    SORT_STORAGE_KEY,
    React.useMemo(() => ({ field: sortField, order: sortOrder }), [sortField, sortOrder]),
  );
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; packet: Packet } | null>(null);
  /** Which header cell the last right-click landed in. See the header's ContextMenu. */
  const [alignColumn, setAlignColumn] = useState<AlignableColumn | null>(null);
  const tableContainerRef = useRef<HTMLDivElement | null>(null);

  // Resizable columns
  const [columnWidths, setColumnWidths] = useState<Record<ColumnKey, number>>(loadStoredColumnWidths);
  const columnResizeRef = useRef<{ column: ColumnKey; startX: number; startWidth: number } | null>(null);

  // Debounced rather than written straight from an effect: dragging a column
  // divider changes this on every mousemove, which used to mean one
  // serialize-and-write per frame of the drag. The write still lands if the
  // tab closes mid-drag - preferences.ts flushes on pagehide.
  useDebouncedPreference(COLUMN_WIDTHS_STORAGE_KEY, columnWidths);

  // A resize in another tab lands here without a reload. Without this the two
  // tabs hold independent copies and whichever writes last silently reverts
  // the other.
  usePreferenceSync(COLUMN_WIDTHS_STORAGE_KEY, normalizeColumnWidths, setColumnWidths);

  // Columns the user has dragged; these opt out of auto-sizing for good.
  const userSizedColumnsRef = useRef<Set<ColumnKey>>(new Set());

  // Address columns auto-size to their widest value, reference-analyzer style: an IPv6
  // address is far too wide for a fixed default, and truncating it to an
  // ellipsis hides the part that distinguishes one host from another. A column
  // the user has dragged is theirs from then on and stops auto-sizing.
  const autoSizeRef = useRef({ firstPacketId: -1, lastMeasuredId: -1, source: 0, destination: 0 });
  /**
   * Widths already measured, by address. A capture's addresses repeat - a
   * download is a handful of hosts - so most frames cost a map lookup rather
   * than a `measureText`. Bounded, and cleared with the measurement.
   */
  const widthByTextRef = useRef(new Map<string, number>());
  const textMeasureRef = useRef<CanvasRenderingContext2D | null>(null);
  /** Width each address column's header needs (label, gap, sort icon, padding); see the fit effect. */
  const headerMinRef = useRef<{ source?: number; destination?: number }>({});

  useEffect(() => {
    const state = autoSizeRef.current;

    // A new capture, a cleared buffer or an import restarts the measurement,
    // and each shows as ids going BACKWARDS: frame ids rise for the life of a
    // capture, and a new one starts again from 1. A trim does not - the
    // buffer drops its oldest frames and keeps appending, so its first id
    // rises. This used to restart on any change of the first id, which a full
    // buffer trims on nearly every flush, so a long capture re-measured the
    // whole buffer ten times a second: `measureText` was 27% of the main
    // thread at 60,000 frames a second (`scripts/perf/ui-burst-drive.ts`).
    // Widths only grow between restarts; an address that left the buffer can
    // leave its column wide, which is steadier than a column that jitters.
    const firstPacketId = packets.length > 0 ? packets[0].id : -1;
    const lastId = packets.length > 0 ? packets[packets.length - 1].id : -1;
    if (packets.length === 0 || firstPacketId < state.firstPacketId || lastId < state.lastMeasuredId) {
      state.lastMeasuredId = -1;
      state.source = 0;
      state.destination = 0;
      widthByTextRef.current.clear();
    }
    state.firstPacketId = firstPacketId;
    if (packets.length === 0 || lastId <= state.lastMeasuredId) return;

    if (!textMeasureRef.current) {
      const cell = tableContainerRef.current?.querySelector('tbody td');
      const context = document.createElement('canvas').getContext('2d');
      if (!context) return;
      const style = cell ? getComputedStyle(cell) : null;
      context.font = style ? `${style.fontSize} ${style.fontFamily}` : '11px monospace';
      textMeasureRef.current = context;
    }
    const measure = textMeasureRef.current;
    const widths = widthByTextRef.current;
    const widthOf = (text: string): number => {
      let width = widths.get(text);
      if (width === undefined) {
        width = measure.measureText(text).width;
        if (widths.size >= 4096) widths.clear();
        widths.set(text, width);
      }
      return width;
    };

    // Only the frames past the last one measured, found by id: the buffer is
    // id-ordered, and a trim moved its indices but not its ids.
    let start = state.lastMeasuredId < 0 ? 0 : state.lastMeasuredId - firstPacketId + 1;
    if (start < 0 || start > packets.length || (start < packets.length && packets[start].id <= state.lastMeasuredId)) {
      start = packets.findIndex((p) => p.id > state.lastMeasuredId);
      if (start < 0) start = packets.length;
    }
    for (let i = start; i < packets.length; i++) {
      state.source = Math.max(state.source, widthOf(packets[i].source));
      state.destination = Math.max(state.destination, widthOf(packets[i].destination));
    }
    state.lastMeasuredId = lastId;

    // The fit must never go below what the column's own TITLE needs, or short
    // addresses ("1.1.1.1") leave a header narrower than its label and the
    // centred title overflows on both sides ("estinatio"). Read from the
    // header itself, so its real font, weight and size count, and
    // once per column: the label never changes, and this effect runs ten times
    // a second. A zero (header not laid out, or display:none) is not cached.
    const headerMin = headerMinRef.current;
    for (const column of ['source', 'destination'] as const) {
      if (headerMin[column]) continue;
      const th = tableContainerRef.current?.querySelector(`th[data-column="${column}"]`);
      const button = th?.querySelector('button');
      const label = button?.querySelector('span');
      const icon = button?.querySelector('svg');
      if (!th || !button || !label || !icon) continue;
      const thStyle = getComputedStyle(th);
      const gap = parseFloat(getComputedStyle(button).columnGap) || 0;
      const needed = label.scrollWidth + gap + icon.getBoundingClientRect().width
        + parseFloat(thStyle.paddingLeft) + parseFloat(thStyle.paddingRight);
      if (needed > 0) headerMin[column] = Math.ceil(needed);
    }

    const CELL_PADDING = 18; // px-2 either side, plus a little breathing room
    setColumnWidths(prev => {
      const next = { ...prev };
      let changed = false;
      for (const column of ['source', 'destination'] as const) {
        if (userSizedColumnsRef.current.has(column)) continue;
        const fitted = Math.min(
          MAX_COLUMN_WIDTH,
          Math.max(MIN_COLUMN_WIDTH, headerMin[column] ?? 0, Math.ceil(state[column] + CELL_PADDING))
        );
        if (fitted !== prev[column]) {
          next[column] = fitted;
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [packets]);

  const handleColumnResizePointerDown = (column: ColumnKey) => (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    columnResizeRef.current = { column, startX: e.clientX, startWidth: columnWidths[column] };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const handleColumnResizePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    const drag = columnResizeRef.current;
    if (!drag) return;
    userSizedColumnsRef.current.add(drag.column);
    const nextWidth = Math.min(MAX_COLUMN_WIDTH, Math.max(MIN_COLUMN_WIDTH, drag.startWidth + (e.clientX - drag.startX)));
    setColumnWidths(prev => ({ ...prev, [drag.column]: nextWidth }));
  };
  const handleColumnResizePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    columnResizeRef.current = null;
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  const renderColumnResizeHandle = (column: ColumnKey) => (
    <div
      onPointerDown={handleColumnResizePointerDown(column)}
      onPointerMove={handleColumnResizePointerMove}
      onPointerUp={handleColumnResizePointerUp}
      onClick={e => e.stopPropagation()}
      // Right-click resets THIS column rather than all of them: the handle
      // belongs to one column, and a gesture on one control that silently
      // rearranges six others is not a reset, it is a surprise.
      onContextMenu={e => {
        e.preventDefault();
        e.stopPropagation();
        setColumnWidths(prev => ({ ...prev, [column]: DEFAULT_COLUMN_WIDTHS[column] }));
      }}
      className="absolute right-0 top-0 h-full w-1.5 translate-x-1/2 cursor-col-resize hover:bg-handle-hover z-10"
      title="Drag to resize column - right-click to reset"
    />
  );

  // Sorting & Filtering
  const [listPrefs, patchListPrefs] = usePreferenceStore(packetListStore);
  const [showMinimap] = usePreferenceValue(minimapStore);
  const density = DENSITY_CLASS[listPrefs.density];
  const columns = listPrefs.columns;
  /**
   * Columns added from the detail tree's "Apply as Column", drawn between
   * Length and Info. Resolved through the registry here rather than stored
   * with a label, so a renamed field renames its column and a field that has
   * been retired takes its column with it.
   */
  /**
   * The address as the column should read it.
   *
   * A function rather than a precomputed map: the map is keyed by address and
   * the list draws forty rows at a time, so this is forty lookups per frame
   * against a Map - cheaper than building anything, and it stays correct as
   * the capture teaches the map new names mid-scroll.
   */
  const resolved = (address: string) =>
    (resolveNames ? names?.hostName(address) : undefined) ?? address;

  const customColumns = listPrefs.customColumns
    .map((abbrev) => ({ abbrev, def: fieldDef(abbrev) }))
    .filter((c): c is { abbrev: string; def: NonNullable<ReturnType<typeof fieldDef>> } => c.def !== undefined);

  /**
   * The field actually sorted by.
   *
   * A user can sort by Protocol and then hide Protocol, leaving the list in an
   * order with no visible explanation and no header carrying an arrow. Falling
   * back to `id` also restores the fast path below - sorting by anything else
   * copies and sorts the whole buffer on every flush.
   */
  const effectiveSortField = visibleSortField(sortField as ColumnSortField, columns);

  /**
   * **The quick-find search is deleted, and this is what it cost to run.**
   *
   * It lowercased four strings for every frame in the buffer on every
   * keystroke, which is why it was debounced by 150 ms and why clearing the box
   * was exempted from the debounce. The display filter answers the same
   * questions over the WHOLE capture rather than the rows in hand, so what went
   * with it is a second, weaker search box - see `ActivityRail` for the full
   * argument.
   */

  const sortedPackets = React.useMemo(() => {
    const processedPackets = packets;

    if (!effectiveSortField) return processedPackets;

    // The default sort - packet number ascending - is the order the buffer is
    // already in, since ids come from packetGenerator monotonically and nothing
    // reorders it. Copying and re-sorting it every 100ms flush to arrive back
    // at the identical order is measurable at capture volume and buys nothing,
    // so recognise it and hand the array straight back. Exact, not an
    // approximation: any other field or direction still takes the sort below.
    if (effectiveSortField === 'id' && sortOrder === 'asc') return processedPackets;

    return [...processedPackets].sort((a, b) => {
      // Direction is a PACKED number - the direction in its low bits, the
      // deciding signal above them - so comparing the field itself would
      // interleave the directions by which signal decided them. Sorting has to
      // see the direction alone. Unknown sorts as 0, which gathers the frames
      // nobody could answer for at one end rather than scattering them.
      if (effectiveSortField === 'direction') {
        const dA = directionOf(a.direction);
        const dB = directionOf(b.direction);
        return sortOrder === 'asc' ? dA - dB : dB - dA;
      }
      let valA: any = a[effectiveSortField as keyof Packet];
      let valB: any = b[effectiveSortField as keyof Packet];
      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = (valB || '').toLowerCase();
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    });
  }, [packets, effectiveSortField, sortOrder]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Virtualization: render only the rows actually scrolled into view (plus
  // a small overscan buffer), not the entire buffer, using two spacer rows
  // to preserve the table's true scroll height. Rendering every buffered
  // packet as a real <tr> is what locks up the tab under sustained
  // high-volume capture - confirmed via a Chrome performance trace showing
  // 17k+ DOM elements and 45-97ms style recalculations on every single
  // incoming packet once the buffer approached its 4000-packet cap. Fixed
  // row height is a safe assumption here: every cell uses whitespace-nowrap
  // + truncate, so no row ever wraps to a second line.
  const ROW_HEIGHT_FALLBACK = 21;
  const OVERSCAN_ROWS = 15;
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);
  const [rowHeight, setRowHeight] = useState(ROW_HEIGHT_FALLBACK);


  const hasMeasuredRowHeightRef = useRef(false);
  /** The sticky header, measured for the keyboard scroll arithmetic above. */
  const headerRef = useRef<HTMLTableSectionElement>(null);

  // getBoundingClientRect() forces a synchronous layout, so this must only
  // ever run once: the ref callback re-fires on every render where a
  // different packet lands in the first visible slot (i.e. nearly every
  // incoming packet while auto-scrolled), and doing this measurement on
  // every one of those was itself measured as the single largest forced-
  // reflow cost in the app once the earlier full-DOM freeze was fixed.
  // One more measurement, once the fonts have settled.
  //
  // The latch below deliberately measures once, and while the app shipped a
  // webfont that once was too early on a cold load: rows were laid out in the
  // fallback font, which happened to be exactly the 21px fallback, so the
  // measurement agreed with the guess and the real 20.641px height that
  // arrived with JetBrains Mono was never seen. The list then believed every
  // row was a third of a pixel taller than it is, which across a full buffer
  // put the last rows out of reach of the scroll position that should land on
  // them. The faces are system fonts now and `document.fonts.ready` resolves
  // at once, so this costs one layout and is kept: it is what makes a webfont
  // safe to bring back.
  //
  // Bumping state rather than only clearing the latch, because the ref callback
  // fires on render and an idle list is not rendering.
  const [measureEpoch, setMeasureEpoch] = useState(0);

  /**
   * The sticky header's height, so the minimap can start below it.
   *
   * Observed rather than assumed: it changes with the density preference, and
   * again when the webfont finishes loading, which is the same pair of moving
   * parts that made the row-height measurement wrong for so long.
   */
  const [headerHeight, setHeaderHeight] = useState(0);
  useEffect(() => {
    const el = headerRef.current;
    if (!el) return;
    const update = () => setHeaderHeight(el.offsetHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    let cancelled = false;
    document.fonts?.ready.then(() => {
      if (cancelled) return;
      hasMeasuredRowHeightRef.current = false;
      setMeasureEpoch((n) => n + 1);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  /**
   * Density changes the row height, so everything measured from a row has to be
   * measured again.
   *
   * All three of these latch on first use, and all three would otherwise keep
   * describing the previous density forever: the virtualizer would place rows
   * on a stale pitch (which at a full buffer puts the end of the capture out of
   * reach), and the address auto-sizing would keep measuring text in the old
   * font size.
   */
  useEffect(() => {
    hasMeasuredRowHeightRef.current = false;
    textMeasureRef.current = null;
    autoSizeRef.current.lastMeasuredId = -1;
    autoSizeRef.current.source = 0;
    autoSizeRef.current.destination = 0;
    widthByTextRef.current.clear();
    setMeasureEpoch((n) => n + 1);
  }, [listPrefs.density]);

  const measuredRowRef = (node: HTMLTableRowElement | null) => {
    if (!node || hasMeasuredRowHeightRef.current) return;
    const height = node.getBoundingClientRect().height;
    if (height > 0) {
      hasMeasuredRowHeightRef.current = true;
      // Any real difference counts, not just a large one.
      //
      // This used to require half a pixel of disagreement before accepting the
      // measurement, which sounds harmless and is not: the row is 20.641px and
      // the fallback is 21, so the measurement was discarded every time and the
      // fallback stood forever. Per row that is a third of a pixel; across a
      // 50,000-packet buffer the spacers over-claim about eighteen thousand
      // pixels, and the last rows drift out of reach of the scroll position
      // that should land on them.
      //
      // The threshold that remains is only float noise from
      // getBoundingClientRect - it exists to avoid a pointless state update,
      // not to filter out real differences.
      if (Math.abs(height - rowHeight) > 0.01) setRowHeight(height);
    }
  };

  useEffect(() => {
    const el = tableContainerRef.current;
    if (!el) return;
    const update = () => setViewportHeight(el.clientHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // The arithmetic lives in `lib/virtualWindow.ts` so it can be asserted:
  // a slice computed past the end leaves the list blank with no error
  // anywhere, which is exactly what happened here (see that file's header).
  //
  // The list renders from a `RowSource`, and which one depends on whether it is
  // showing the capture in order. Filtered, searched or sorted by any other
  // column, it shows what is in memory and says so; otherwise it addresses the
  // whole capture and reads the rows below the RAM window back from disk.
  const unfiltered = packets === allPackets;
  // The capture in order: either unsorted, or sorted the way it was captured. A
  // sort by any other column is a view of what is in memory, and a source
  // claiming the rows below it would put unsorted rows in a sorted list.
  //
  // The quick-find search was the other disqualifier here and is deleted; it
  // filtered the window without touching the rows on disk, so any search at all
  // meant this list could only honestly address what it held.
  //
  // A display filter used to disqualify it too, and no longer does - that is
  // what `filterScan` is. It still disqualifies it while the scan is running
  // or if it failed, because until the bitmap lands the only frames this list
  // can honestly show are the ones in hand.
  const capturedInOrder =
    !effectiveSortField || (effectiveSortField === 'id' && sortOrder === 'asc');
  const filterView = React.useMemo<CaptureFilterView | null>(
    () => (unfiltered || filterScan.status !== 'ready'
      ? null
      // `packets` rather than `sortedPackets`: they are the same array under
      // `capturedInOrder`, and this one is unambiguously capture order.
      : { matches: filterScan.matches, window: packets }),
    [unfiltered, filterScan, packets],
  );
  const addressingCapture = capturedInOrder && (unfiltered || filterView !== null);
  const captureRows = useCaptureRows(allPackets, below, addressingCapture, filterView, floor);
  const windowSource = React.useMemo(() => arrayRowSource(sortedPackets), [sortedPackets]);
  const rowSource = addressingCapture ? captureRows.source : windowSource;
  const totalRows = rowSource.count;
  const { startIndex, endIndex, topSpacerHeight, bottomSpacerHeight } =
    virtualWindow(totalRows, scrollTop, viewportHeight, rowHeight, OVERSCAN_ROWS);
  const visibleRows = rowSlice(rowSource, startIndex, endIndex);

  // Told from an effect, never from render: a source that fetches will set
  // state when the rows arrive, and doing that during a render of the rows it
  // is about to replace is the one thing React will not have.
  useEffect(() => {
    rowSource.request(startIndex, endIndex);
  }, [rowSource, startIndex, endIndex]);

  // Auto scroll to bottom
  const shouldAutoScrollRef = useRef(true);

  /**
   * The follow setting, in a ref.
   *
   * Read from the scroll handler and the flush effect, both of which are
   * registered once and would otherwise close over whatever the setting was
   * when the list mounted.
   */
  const followRef = useRef(listPrefs.follow);
  useEffect(() => {
    followRef.current = listPrefs.follow;
    // Choosing 'always' should take effect now rather than at the next packet,
    // and choosing 'never' should not leave a queued stick-to-bottom behind.
    if (listPrefs.follow === 'always') {
      shouldAutoScrollRef.current = true;
      const el = tableContainerRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    } else if (listPrefs.follow === 'never') {
      shouldAutoScrollRef.current = false;
    }
  }, [listPrefs.follow]);
  // A 'scroll' event only updates shouldAutoScrollRef when it was just
  // "armed" by a genuine user input gesture (wheel/touch/scrollbar drag).
  // Our own per-packet scrollTop assignment below also fires 'scroll'
  // events, and at real capture rates (hundreds of packets/sec) those
  // interleave with genuine user scrolls far too fast to reliably tell them
  // apart after the fact from the event alone - an earlier "ignore the
  // event our own assignment causes" approach still raced, because a real
  // user scroll landing in between two of our own re-assertions could get
  // silently stomped before a 'scroll' event distinct from ours was even
  // dispatched. Gating on real input events sidesteps that: only those can
  // arm it, so our own assignments can never be mistaken for one.
  const userScrollArmedRef = useRef(false);
  const armUserScroll = () => {
    userScrollArmedRef.current = true;
  };
  /**
   * A wheel turned UPWARD on a list that can scroll stops following then and
   * there, and arms nothing.
   *
   * Arming alone left the gesture a race it could lose, two ways round. A
   * flush committing between the wheel and its scroll event puts `scrollTop`
   * back at the bottom, and a scroll event this list's own assignment had
   * already queued reaches the armed handler first - either way the handler
   * measured the bottom and went on following, and the list swapped every row
   * under the pointer of somebody trying to read one (`smoke.ts` caught it,
   * one run in three). Which way the wheel turned is on the event itself, and
   * upward means "not the newest" in `reading` mode, so no scroll event gets a
   * say. Following resumes the way it always did: a gesture that ends at the
   * bottom, or End.
   */
  const handleWheel = (event: React.WheelEvent) => {
    const el = tableContainerRef.current;
    if (event.deltaY < 0 && followRef.current === 'reading' && el !== null && el.scrollHeight > el.clientHeight) {
      shouldAutoScrollRef.current = false;
      userScrollArmedRef.current = false;
      return;
    }
    armUserScroll();
  };
  const handleScroll = () => {
    if (!tableContainerRef.current) return;
    const { scrollTop: currentScrollTop, scrollHeight, clientHeight } = tableContainerRef.current;
    setScrollTop(currentScrollTop); // keep the virtualization window in sync regardless of cause
    if (!userScrollArmedRef.current) return;
    userScrollArmedRef.current = false;
    // Only 'reading' lets a gesture change the decision. 'always' and 'never'
    // have already made it, and a scroll must not overrule the setting.
    if (followRef.current !== 'reading') return;
    shouldAutoScrollRef.current = scrollHeight - (currentScrollTop + clientHeight) < 50;
  };

  // An empty list re-arms stick-to-bottom.
  //
  // "The user scrolled up" is a statement about a particular scroll position,
  // and it stops meaning anything the moment there is nothing left to scroll.
  // Without this, clearing the packet buffer while scrolled up left autoscroll
  // switched off, so the next capture filled the list from the top and simply
  // sat there - the one moment someone is most obviously expecting to watch
  // packets arrive.
  //
  // Nothing is lost by re-arming. Emptying the list collapses scrollHeight and
  // puts scrollTop back to 0 on its own, so the position the user had was
  // already gone either way; the only open question is where the next packets
  // land, and for a live capture that is the bottom.
  useEffect(() => {
    if (packets.length === 0 && followRef.current !== 'never') {
      shouldAutoScrollRef.current = true;
    }
  }, [packets.length]);

  useEffect(() => {
    // Depend on the array reference itself, not packets.length: once the
    // live-capture buffer hits its cap (4000, see App.tsx), each new packet
    // also drops the oldest one, so length stops changing even though new
    // data keeps arriving - length alone would silently stop autoscroll.
    if (followRef.current !== 'never' && shouldAutoScrollRef.current && tableContainerRef.current) {
      tableContainerRef.current.scrollTop = tableContainerRef.current.scrollHeight;
      // Update the virtualization window synchronously too, rather than
      // waiting for the resulting scroll event to do it.
      setScrollTop(tableContainerRef.current.scrollTop);
    }
  }, [packets]);

  /**
   * Moves the selection by whole rows, from the keyboard.
   *
   * Selection moves by INDEX INTO `sortedPackets`, never by walking DOM
   * siblings: the list is virtualized, so the row above the selected one may
   * not exist in the document at all. The same reason is why the caller cannot
   * rely on `scrollIntoView` and this scrolls the container arithmetically.
   *
   * Moving the selection also decides whether the list keeps following the
   * live tail, and it decides it directly rather than going through
   * `armUserScroll`. Routing it through the arming flag would hand the
   * question to `handleScroll`, which answers it from the final scroll
   * position - so the behaviour would be right by accident and only for as
   * long as nobody changed the 50px threshold it uses.
   *
   * Disarming matters at all because the autoscroll effect reasserts scrollTop
   * on every flush, about ten times a second while capturing. Without it,
   * arrowing upwards fights the capture and loses.
   */
  const moveSelection = (delta: number | 'first' | 'last') => {
    if (totalRows === 0) return;
    // Found against the ROW SOURCE, not the array. With the capture addressed,
    // row 0 is the oldest frame on disk and the array's index 0 is the oldest
    // frame in memory - they are the same row only while the window is the
    // whole capture, and using the array's index would step the selection to a
    // row `below` positions away from the one the reader is looking at.
    const current = selectedPacket ? rowSource.indexOfId(selectedPacket.id) : -1;

    let next: number;
    if (delta === 'first') next = 0;
    else if (delta === 'last') next = totalRows - 1;
    // With nothing selected, the first key press selects an end rather than
    // jumping into the middle: down starts at the top, up starts at the bottom.
    else if (current === -1) next = delta > 0 ? 0 : totalRows - 1;
    else next = current + delta;

    next = Math.max(0, Math.min(totalRows - 1, next));
    const target = packetAt(rowSource, next);
    // A row still coming off disk cannot be selected: there is no packet to
    // hand the detail pane. The row is requested by the render that follows,
    // so pressing the key again a moment later works.
    if (!target) return;

    // Jumping to the end means "show me the newest", so following resumes.
    // Any other move means the user is reading something specific, and the
    // list must hold still underneath them - unless they have said they always
    // want the tail, in which case moving the selection is not a request to
    // stop following.
    if (followRef.current === 'reading') {
      shouldAutoScrollRef.current = next === totalRows - 1;
    }
    // Left disarmed deliberately: the scroll assignment below is ours, not the
    // user's, and handleScroll must not reinterpret it as a gesture.
    userScrollArmedRef.current = false;
    onSelectPacket(target);

    // Scroll the row into view only if it is not already, which is what
    // `block: 'nearest'` would do for a real element. Anything more eager
    // makes every arrow press recentre the list under the reader.
    const el = tableContainerRef.current;
    if (!el) return;

    // The header is INSIDE the scroll container and sticky, so it both offsets
    // every row in the content and covers the top of the viewport. Omitting it
    // is invisible when scrolling up - the row lands a header's height too low,
    // which is still on screen - and puts the row exactly one header height
    // below the bottom edge when scrolling down.
    const headerHeight = headerRef.current?.offsetHeight ?? 0;
    const rowTop = next * rowHeight;
    const rowBottom = headerHeight + (next + 1) * rowHeight;

    if (rowTop < el.scrollTop) el.scrollTop = rowTop;
    else if (rowBottom > el.scrollTop + el.clientHeight) {
      el.scrollTop = rowBottom - el.clientHeight;
    }
    setScrollTop(el.scrollTop);
  };

  /**
   * The list's keyboard contract.
   *
   * Until this existed the packet list could not be reached from a keyboard at
   * all: the container had an `onKeyDown` but no `tabIndex`, so it could never
   * receive focus and the handler was dead code, and the rows were plain
   * `<tr onClick>`. Wheel, touch and a minimap drag were the only ways in.
   */
  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    // A page is a viewport of rows, less one for continuity of context - the
    // same overlap a text editor keeps when paging.
    const page = Math.max(1, Math.floor(viewportHeight / rowHeight) - 1);

    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); moveSelection(1); break;
      case 'ArrowUp': e.preventDefault(); moveSelection(-1); break;
      case 'PageDown': e.preventDefault(); moveSelection(page); break;
      case 'PageUp': e.preventDefault(); moveSelection(-page); break;
      case 'Home': e.preventDefault(); moveSelection('first'); break;
      case 'End': e.preventDefault(); moveSelection('last'); break;
      case 'Enter':
        // Matches double-click: open the frame in its own window.
        if (selectedPacket) { e.preventDefault(); onInspectPacket?.(selectedPacket); }
        break;
      case 'F10':
        // Shift+F10 is the platform gesture for "open the context menu for the
        // current item" - the keyboard equivalent of the right-click this list
        // already supports, and the only one available to someone without a
        // pointer.
        if (e.shiftKey && selectedPacket) {
          e.preventDefault();
          const rect = (e.target as HTMLElement).getBoundingClientRect();
          setContextMenu({ x: rect.left + 16, y: rect.top + 16, packet: selectedPacket });
        }
        break;
      default:
        break;
    }
  };

  // Context Menu handlers
  const handleContextMenu = (e: React.MouseEvent, packet: Packet) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, packet });
  };

  useEffect(() => {
    const closeMenu = () => setContextMenu(null);
    window.addEventListener('click', closeMenu);
    return () => window.removeEventListener('click', closeMenu);
  }, []);

  /**
   * The sort state, for assistive tech.
   *
   * Visually the sort is carried by an arrow glyph and its colour, which says
   * nothing to a screen reader. `aria-sort` on the column header is the
   * standard channel and the only one that survives with no sighted reading of
   * the icon.
   */
  const sortAttr = (field: SortField): 'ascending' | 'descending' | 'none' =>
    effectiveSortField !== field ? 'none' : sortOrder === 'asc' ? 'ascending' : 'descending';

  // Built once and dropped into the Info header, which is the only column
  // guaranteed to be there for it to live in.
  // Info is always shown and is not in the hideable set, hence the +1.
  const visibleColumnCount =
    HIDEABLE_COLUMNS.filter((c) => columns[c]).length + 1 + listPrefs.customColumns.length;

  /**
   * The header row's surface, in one place.
   *
   * The column-options button sits in the strip above the minimap, which is a
   * SIBLING of the table rather than a cell in it - so it was drawing on
   * whatever was behind it while the header row beside it drew its own ground.
   * Two surfaces that are meant to read as one bar, defined in two places, is
   * a mismatch that reappears every time either one is themed. There is one
   * definition now and both render it.
   *
   * **It is `--card`, which is what every other titled surface in the app is.**
   * It was `--secondary`, one step brighter, which made this the only column
   * header in the window that did not match the pane headers under it -
   * `PaneHeader` is `bg-card`, and so is the Frame Detail pane's own header.
   * A table's header row is the same kind of thing as a pane's title bar: the
   * strip that names what is below it.
   *
   * **The ground and the rules are split, because only one of them can be a
   * `border` here.** The `<thead>` is `position: sticky` inside a table that is
   * `border-collapse`, and a collapsed border belongs to the TABLE rather than
   * to the cell that declares it - so it is painted in the table's own layer,
   * underneath the body rows, while the sticky header's background is painted
   * above them. The line then disappears wherever a row has scrolled beneath
   * it and the row's colour shows in its place, which reads as a transparent
   * separator rather than as a missing one. `index.css` draws the header's
   * rules as `box-shadow` on the cells instead, which paints with the sticky
   * layer; `HEADER_GROUND` is what the table gets, and `HEADER_CHROME` adds the
   * ordinary `border-b` back for the empty state, which is a plain div and has
   * no table under it to be painted beneath.
   */
  const HEADER_GROUND = 'bg-card text-muted-foreground transition-colors';
  const HEADER_CHROME = `${HEADER_GROUND} border-b border-border`;

  // Where the text sits, per column. Every column is settable now - see
  // ColumnAlignMap for why the numeric three no longer have to be excluded.
  //
  // The VALUES only. Column titles are always centred, whatever a column is
  // set to: the header is a fixed row of labels read across, and letting each
  // one wander to whichever edge its values happen to use turned that row
  // ragged - a centred title also sits over both a left-aligned and a
  // right-aligned column without looking attached to the wrong one.
  const cellAlign = (column: AlignableColumn) => COLUMN_ALIGN_CLASS[listPrefs.align[column]];
  //
  // A header dragged narrower than its title truncates from the END with an
  // ellipsis. Without `min-w-0` and a truncating label, a centred flex row
  // overflows equally on both sides and clips the START of the word. The
  // arbitrary variant reaches the title span so no cell has to remember it;
  // the sort icon is an svg, which `shrink-0` keeps whole.
  const HEADER_TITLE = 'justify-center min-w-0 [&>span:first-child]:truncate [&>svg]:shrink-0';

  const columnMenuTrigger = (
    <ColumnOptionsMenu
      columns={columns}
      timeFormat={listPrefs.timeFormat}
      onColumnsChange={(next) => patchListPrefs({ columns: next })}
      customColumns={listPrefs.customColumns}
      onCustomColumnsChange={(next) => patchListPrefs({ customColumns: next })}
      onTimeFormatChange={(timeFormat) => patchListPrefs({ timeFormat })}
    />
  );

  const renderSortIcon = (field: SortField) => {
    if (effectiveSortField !== field) return <ArrowUpDown className="w-3 h-3 text-muted-foreground opacity-30 group-hover:opacity-100 transition-opacity" />;
    return sortOrder === 'asc' ? (
      <ArrowUp className="w-3 h-3 text-primary" />
    ) : (
      <ArrowDown className="w-3 h-3 text-primary" />
    );
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden select-none relative">
      {/* Rows the capture holds and this list cannot reach.

          Outside the scroll container on purpose: it describes the container
          rather than sitting in it, and a notice occupying a row would put the
          virtualiser'"'"'s `index * rowHeight` arithmetic off by one row for the
          whole capture.

          Only ever shown past ~1.5 million rows, which is where Chrome'"'"'s
          33.5-million-pixel element cap stops a spacer being tall enough to
          address the rest. The frames are stored, exportable and readable -
          they are unreachable by SCROLLING, and saying so is the difference
          between a known limit and a list that quietly stops. */}
      {captureRows.unaddressable > 0 && (
        <div className="px-3 py-1 text-[11px] text-amber-600 dark:text-amber-400 border-b border-border/60">
          Showing the newest {totalRows.toLocaleString()} frames.{" "}
          {captureRows.unaddressable.toLocaleString()} earlier frames are stored and
          exportable, but past what this list can scroll to.
        </div>
      )}
      {/* Table Container + Minimap */}
      <div className="flex-1 flex overflow-hidden min-h-0">
      <div
        ref={tableContainerRef}
        onScroll={handleScroll}
        onWheel={handleWheel}
        onTouchStart={armUserScroll}
        onMouseDown={armUserScroll}
        onKeyDown={handleKeyDown}
        // The scroll container is the focusable element and the keyboard
        // target, rather than the rows. That is deliberate: in a virtualized
        // list the focused row can be unmounted by the virtualizer at any
        // moment, which drops focus to <body> mid-scroll. `aria-activedescendant`
        // moves the ASSISTIVE cursor without moving real focus, so the DOM
        // focus never sits on something the virtualizer is entitled to remove.
        tabIndex={0}
        role="grid"
        aria-label="Captured packets"
        // Static, deliberately. The row count belongs in aria-rowcount, which
        // assistive tech reads on demand; putting a live figure in the name
        // would re-announce the label ten times a second during capture.
        aria-rowcount={totalRows}
        aria-activedescendant={selectedPacket ? `packet-row-${selectedPacket.id}` : undefined}
        className="flex-1 overflow-y-auto overflow-x-auto custom-scrollbar minimap-scroll"
        // The list paints its own ground rather than inheriting the app's.
        // Without this a packet theme would only reach the rows its rules
        // matched - the chain has no catch-all, so everything else would show
        // the app surface, and a light packet theme inside a dark app would
        // stripe light rows across a dark list.
        // `--row-bg` is what `.packet-grid` lightens to draw a column
        // separator. Set here to the list's own ground, and overridden below by
        // any row the colouring chain painted - so an unmatched row needs no
        // special case, it simply inherits.
        style={{
          backgroundColor: packetTheme.surface.background,
          color: packetTheme.surface.foreground,
          '--row-bg': packetTheme.surface.background,
        } as React.CSSProperties}
      >
        <table className="packet-grid w-full table-fixed text-left border-collapse font-mono text-xs">
          {/* The colgroup has to track visibility exactly: `table-fixed` maps
              these to cells by POSITION, so one stale <col> shifts every width
              after it onto the wrong column. */}
          <colgroup>
            {columns.id && <col style={{ width: columnWidths.id }} />}
            {columns.direction && <col style={{ width: columnWidths.direction }} />}
            {columns.relativeTime && <col style={{ width: columnWidths.relativeTime }} />}
            {columns.source && <col style={{ width: columnWidths.source }} />}
            {columns.destination && <col style={{ width: columnWidths.destination }} />}
            {columns.protocol && <col style={{ width: columnWidths.protocol }} />}
            {columns.length && <col style={{ width: columnWidths.length }} />}
            {/* A fixed width, and no resize handle: the stored widths are keyed
                by the six built-in columns, and a column the user can add and
                remove at will has no stable slot in that map. */}
            {customColumns.map((c) => <col key={c.abbrev} style={{ width: CUSTOM_COLUMN_WIDTH }} />)}
            <col />
          </colgroup>
          {/* Table Header */}
          <thead
            ref={headerRef}
            className={`sticky top-0 z-20 select-none ${HEADER_GROUND}`}
          >
            {/* One ContextMenu for the whole header row rather than one per
                cell. Radix's trigger already positions at the pointer and owns
                Escape and focus return; which COLUMN was right-clicked is the
                only thing left to work out, and the event knows that. Seven
                wrappers would have been seven copies of the same menu. */}
            <ContextMenu>
              <ContextMenuTrigger asChild>
            <tr
              aria-rowindex={1}
              onContextMenu={(e) => {
                const cell = (e.target as HTMLElement).closest('th[data-column]');
                // Only a column that HAS a position to choose. Direction is
                // always centred, and an added field's column has no slot in
                // the alignment map - so neither opens the menu.
                const column = cell?.getAttribute('data-column');
                setAlignColumn(isAlignableColumn(column) ? column : null);
              }}
              // **No `divide-x` here, and that is the fix rather than a
              // simplification.** A collapsed border on a sticky header is
              // painted by the table, under the body rows, so it showed
              // whatever packet had scrolled beneath it - see `HEADER_CHROME`.
              // The header's rules are `box-shadow` on the cells, in
              // `index.css`, which paints with the sticky layer.
              //
              // They are `--border` rather than a lightened ground, which is
              // the body rows' rule and deliberately not this one: the header
              // is CHROME, so its rules are the app's own hairline, the same
              // one `PaneHeader` and every panel edge draws. The body's rules
              // belong to a surface the colouring chain repaints per row, and
              // have to be derived from it.
              className="font-sans text-[11px] font-semibold"
            >
              {columns.id && (
              <th
                data-column="id"
                aria-sort={sortAttr('id')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('id')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>No.</span>
                    {renderSortIcon('id')}
                </button>
                {renderColumnResizeHandle('id')}
              </th>
              )}

              {columns.direction && (
              <th
                data-column="direction"
                aria-sort={sortAttr('direction')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('direction')}
                  title="Which way the frame went, relative to the capturing host"
                  className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>Dir</span>
                    {renderSortIcon('direction')}
                </button>
                {renderColumnResizeHandle('direction')}
              </th>
              )}

              {columns.relativeTime && (
              <th
                data-column="relativeTime"
                aria-sort={sortAttr('relativeTime')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('relativeTime')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>Time</span>
                    {renderSortIcon('relativeTime')}
                </button>
                {renderColumnResizeHandle('relativeTime')}
              </th>
              )}

              {columns.source && (
              <th
                data-column="source"
                aria-sort={sortAttr('source')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('source')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>Source</span>
                    {renderSortIcon('source')}
                </button>
                {renderColumnResizeHandle('source')}
              </th>
              )}

              {columns.destination && (
              <th
                data-column="destination"
                aria-sort={sortAttr('destination')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('destination')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>Destination</span>
                    {renderSortIcon('destination')}
                </button>
                {renderColumnResizeHandle('destination')}
              </th>
              )}

              {columns.protocol && (
              <th
                data-column="protocol"
                aria-sort={sortAttr('protocol')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('protocol')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>Protocol</span>
                    {renderSortIcon('protocol')}
                </button>
                {renderColumnResizeHandle('protocol')}
              </th>
              )}

              {columns.length && (
              <th
                data-column="length"
                aria-sort={sortAttr('length')}
                className={`relative px-2 py-1 group font-semibold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                {/* Centred like every other title. It used to be pinned right
                    to match the numbers below it, because the other headers
                    were left-aligned and this one's values were not - with all
                    the titles centred there is nothing left to disagree. */}
                <button
                  type="button"
                  onClick={() => handleSort('length')}
                  className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}
                >
                  <span>Length</span>
                  {renderSortIcon('length')}
                </button>
                {renderColumnResizeHandle('length')}
              </th>
              )}

              {customColumns.map((c) => (
                <th
                  key={c.abbrev}
                  data-column={c.abbrev}
                  title={c.abbrev}
                  className={`relative px-2 py-1 group font-semibold overflow-hidden hover:bg-accent text-muted-foreground`}
                >
                  <div className={`flex items-center gap-1 w-full ${HEADER_TITLE}`}>
                    <span className="truncate">{c.def.column?.label ?? c.def.label}</span>
                  </div>
                </th>
              ))}

              <th data-column="info" aria-sort={sortAttr('info')} className={`px-4 py-2.5 group font-semibold ${"hover:bg-accent text-muted-foreground"}`}><div className="flex items-center gap-1"><button type="button" onClick={() => handleSort('info')} className={`flex items-center gap-1 flex-1 min-w-0 cursor-pointer ${HEADER_TITLE}`}><span>Info</span>{renderSortIcon('info')}</button>{/* Only when the minimap is off - otherwise it lives in the strip above the map, which is not a column and so does not move when one is resized. It has to live SOMEWHERE, though: this menu is the only way to turn the hidden columns back on. */}{!showMinimap && columnMenuTrigger}</div></th>
            </tr>
              </ContextMenuTrigger>
              {alignColumn && (
                <ContextMenuContent className="w-44">
                  <ContextMenuLabel>
                    {alignColumn === 'info' ? 'Info' : COLUMN_LABELS[alignColumn]}
                  </ContextMenuLabel>
                  <ContextMenuRadioGroup
                    value={listPrefs.align[alignColumn]}
                    onValueChange={(value) =>
                      patchListPrefs({
                        align: { ...listPrefs.align, [alignColumn]: value as ColumnAlign },
                      })
                    }
                  >
                    {COLUMN_ALIGNS.map((value) => (
                      <ContextMenuRadioItem key={value} value={value}>
                        {COLUMN_ALIGN_LABELS[value]}
                      </ContextMenuRadioItem>
                    ))}
                  </ContextMenuRadioGroup>
                </ContextMenuContent>
              )}
            </ContextMenu>
          </thead>

          {/* Table Body */}
          <tbody className={density.body}>
            {totalRows === 0 ? (
              <tr>
                <td colSpan={visibleColumnCount} className="p-0">
                  {/* Centred in the space under the header, not pinned near its
                      top: the empty state IS the pane while there are no rows,
                      and one parked in the upper third read as something left
                      over (the owner's report). A min-height, so a pane shorter
                      than the message grows and scrolls rather than clipping. */}
                  <div
                    className="flex items-center justify-center py-6"
                    style={{ minHeight: Math.max(0, viewportHeight - headerHeight) }}
                  >
                  {/* Against the BUFFER, not the filtered view. `packets` is
                      empty in both cases and they are not the same case: a
                      filter that matched nothing used to report the buffer as
                      empty, which is the wrong answer in the one situation a
                      reader most needs the right one. */}
                  {allPackets.length > 0 ? (
                    <EmptyState
                      icon={SearchX}
                      title="No packets match this filter"
                      actions={onClearFilter && (
                        <EmptyStateButton icon={FunnelX} onClick={onClearFilter}>Clear filter</EmptyStateButton>
                      )}
                    >
                      {/* What was actually searched. A filter that finds
                          nothing is exactly when the reader wonders whether it
                          is the filter or the traffic, so the scope is stated
                          rather than left to be assumed. */}
                      {filterView !== null ? (
                        <>Searched the whole stored capture, {(Math.max(0, below - floor) + allPackets.length).toLocaleString()} frames.</>
                      ) : droppedBuffer > 0 ? (
                        <span className="text-warning">
                          Searched frames {allPackets[0].id.toLocaleString()}–{allPackets[allPackets.length - 1].id.toLocaleString()};{' '}
                          {droppedBuffer.toLocaleString()} earlier frames have left the buffer.
                        </span>
                      ) : (
                        <>Searched every frame in the buffer.</>
                      )}
                    </EmptyState>
                  ) : capturing ? (
                    <EmptyState icon={Radar} title="Waiting for packets" busy>
                      The capture is running. Packets appear here as the adapter sees them.
                    </EmptyState>
                  ) : previousCapture !== null ? (
                    <EmptyState
                      icon={History}
                      title="No packets yet"
                      actions={(
                        <EmptyStateButton icon={History} primary onClick={previousCapture.onReopen}>
                          Reopen the last capture
                        </EmptyStateButton>
                      )}
                      hint="Or press Start in the rail to begin a new capture, which replaces it."
                    >
                      The capture from {previousCapture.label} is still on disk.
                    </EmptyState>
                  ) : (
                    <EmptyState
                      icon={Radar}
                      title="No packets yet"
                      actions={onChooseAdapter && (
                        <EmptyStateButton icon={Cable} onClick={onChooseAdapter}>Choose an adapter</EmptyStateButton>
                      )}
                      hint={<>Start is at the top of the rail, or <Kbd>Space</Kbd> once an adapter is chosen.</>}
                    >
                      Choose an adapter and press Start, or import a capture file.
                    </EmptyState>
                  )}
                  </div>
                </td>
              </tr>
            ) : (
              <>
                {topSpacerHeight > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={visibleColumnCount} style={{ height: topSpacerHeight, padding: 0, border: 'none' }} />
                  </tr>
                )}
                {visibleRows.map((row, i) => {
                if (row.state !== 'ready') {
                  return (
                    <PlaceholderRow
                      key={`row-${startIndex + i}`}
                      row={row}
                      columnCount={visibleColumnCount}
                      rowIndex={startIndex + i}
                      height={rowHeight}
                    />
                  );
                }
                const packet = row.packet;
                const isSelected = selectedPacket?.id === packet.id;
                const style = colorEngine.getPacketStyle(packet, packetTheme);

                return (
                  <tr
                    key={packet.id}
                    id={`packet-row-${packet.id}`}
                    ref={i === 0 ? measuredRowRef : undefined}
                    data-measure-epoch={i === 0 ? measureEpoch : undefined}
                    role="row"
                    aria-selected={isSelected}
                    // The row's TRUE position in the buffer, not its position
                    // among the ~40 rows that happen to be rendered. Without
                    // this a screen reader reports "row 12 of 32" while the
                    // user is on packet 8,431 of 21,900, because the two
                    // spacer rows are all it can see of the rest. 1-based, and
                    // offset by the header row.
                    aria-rowindex={startIndex + i + 2}
                    onClick={() => onSelectPacket(packet)}
                    // Double click also fires the single-click select first,
                    // which is what we want: the row ends up selected behind
                    // the window that opens over it.
                    onDoubleClick={() => onInspectPacket?.(packet)}
                    onContextMenu={e => handleContextMenu(e, packet)}
                    // A vertical rule between every body cell, drawn by
                    // `.packet-grid` - no `divide-x` here any more. The columns
                    // had no rule at all below the header once, so where one
                    // value ended and the next began was carried entirely by
                    // the gap between them - which disappears the moment a
                    // column is narrow enough for its text to fill it.
                    //
                    // **The colour is `.packet-grid`'s too**, which
                    // takes this row's own fill and steps it in lightness -
                    // toward the light on Day, toward the dark on Night. Two
                    // earlier answers are recorded there: `divide-border/40`,
                    // the app's hairline at an alpha over whatever the rule
                    // painted, so one separator was a different colour on every
                    // row; and the row's INK, which the colouring rule does
                    // guarantee reads on the fill, but which draws a rule as
                    // strong as the text it separates.
                    className={`group cursor-pointer ${
                      isSelected
                        // A solid accent fill that overrides the colouring
                        // rule. It was a 6-22% tint of the accent with a 1px
                        // ring and bold, and over a coloured row the tint all
                        // but vanished: the ring was the only sign, and bold
                        // changed every width in the row. The pair is
                        // `registry.ts`'s per accent, 7:1 in High Contrast.
                        //
                        // `--row-bg` has to follow, or the one row painted by a
                        // CLASS rather than by the inline style would draw its
                        // separators from the list's ground instead of from
                        // itself - the single exception to the rule the grid is
                        // built on, and on Day a line lighter than both.
                        ? '[--row-bg:var(--primary)] !bg-primary !text-primary-foreground'
                        : 'hover:brightness-95 dark:hover:brightness-125'
                    }`}
                    // The matched rule's foreground applies to the whole row,
                    // including the Protocol and Length cells - that is how
                    // The reference analyzer's coloring reads at a glance. Individual cells
                    // below inherit rather than setting their own color.
                    style={
                      !isSelected
                        ? {
                            backgroundColor: style.background,
                            color: style.color,
                            // The separator is this row's own fill, stepped -
                            // up on Day, down on Night. See `.packet-grid`.
                            ...(style.background
                              ? { '--row-bg': style.background }
                              : {}),
                          } as React.CSSProperties
                        : undefined
                    }
                  >
                    {/* No. - right-aligned with tabular figures so the column
                        stays a clean edge as the number of digits grows. */}
                    {/* Just the number.

                        A severity dot and an anomaly shield used to sit here.
                        Both are gone because the row itself now carries the
                        answer: every expert category is a colouring rule, so a
                        frame with a finding is a coloured row rather than an
                        ordinary row wearing a 6px mark that had to be hovered
                        to be read. */}
                    {columns.id && (
                    <td className={`px-2 ${density.cell} font-mono whitespace-nowrap truncate tabular-nums ${cellAlign('id')}`}>
                      {packet.id}
                    </td>
                    )}

                    {/* Direction.

                        A glyph and no colour, deliberately: the row's fill is
                        already the colouring rule's answer, and a second
                        colour scheme running down the same row would compete
                        with it for the same meaning. The tooltip carries the
                        word and the signal that decided it, because an arrow
                        somebody did not expect is owed a reason - and the
                        marker on an inferred one is what keeps a guess from
                        reading like a measurement. */}
                    {columns.direction && (
                    <td className={`px-2 ${density.cell} whitespace-nowrap text-center`}
                      title={directionTitle(packet.direction)}>
                      {/* The fades lift on the selected row: 40% of the
                          accent's ink on the accent is a mark nobody can read. */}
                      <span className={`inline-flex items-center ${
                        directionOf(packet.direction) === Direction.Unknown ? 'opacity-40 group-aria-selected:opacity-100' : ''}`}>
                        <DirectionMark direction={directionOf(packet.direction)} />
                        {signalOf(packet.direction) === DirectionSignal.InferredHost && (
                          <span className="text-[9px] self-start opacity-60 group-aria-selected:opacity-100">*</span>
                        )}
                      </span>
                    </td>
                    )}

                    {/* Time.

                        `truncate`, not just `whitespace-nowrap`. Without an
                        overflow rule this cell had nothing to clip it: drag the
                        Time column narrow and its text ran straight out under
                        Source, so two columns' values sat on top of each other
                        with no visible boundary. Same fix on No. and Length,
                        which had the same gap. */}
                    {columns.relativeTime && (
                    <td className={`px-2 ${density.cell} whitespace-nowrap truncate font-mono tabular-nums ${cellAlign('relativeTime')}`}>
                      {formatTimeColumn(
                        listPrefs.timeFormat,
                        packet,
                        // The row ABOVE this one as currently filtered and
                        // sorted, not the previous packet in the buffer: a
                        // delta against a frame a filter has hidden is a number
                        // with nothing on screen to relate it to.
                        // Null when the row above is a placeholder as well
                        // as when there is none: a delta against a frame that
                        // has not arrived yet would be a number computed from
                        // nothing, and it would change under the reader when
                        // it did arrive.
                        packetAt(rowSource, startIndex + i - 1),
                      )}
                    </td>
                    )}

                    {/* Source - address only; the reference analyzer keeps ports in the Info column.
                        With name resolution on, the column shows what the CAPTURE
                        called this address and the tooltip keeps the address itself,
                        because the address is what a filter is written against. */}
                    {columns.source && (() => {
                      // Only frames this machine SENT carry a program here;
                      // the reply to one is attributed to the same local
                      // socket, and rendering it would put the browser's name
                      // on the web server that answered.
                      const sender = sourceProcess?.(packet) ?? null;
                      return (
                        <td
                          className={`px-2 ${density.cell} ${cellAlign('source')} whitespace-nowrap overflow-hidden`}
                          title={sender ? `${packet.source}  (sent by ${sender})` : packet.source}
                        >
                          {/* The ADDRESS gives way, not the program. An IPv6
                              address is already wider than this column and was
                              ellipsising before anything was appended to it, so
                              a plain `truncate` on the pair cut off the very
                              thing that had just been added. The address
                              shrinks; the program never does - it is the short
                              half, and the half that is new. */}
                          <span className={`flex items-baseline min-w-0 ${COLUMN_JUSTIFY_CLASS[listPrefs.align.source]}`}>
                            <span className="truncate">{resolved(packet.source)}</span>
                            {sender && (
                              // Dimmed, because the address is the identity and
                              // the program is the annotation. At full strength
                              // the two read as one long token and the column
                              // stops scanning as a list of addresses.
                              <span
                                className="shrink-0"
                                // The dim is a fraction of THIS ROW'S ink rather than a
                                // fixed grey. It was `text-muted-foreground` - the app
                                // theme's colour, on a row the colouring chain painted -
                                // and its worst case measured 1.06:1. See SENDER_INK_ALPHA.
                                style={{ opacity: SENDER_INK_ALPHA }}
                              >
                                {'\\'}{sender}
                              </span>
                            )}
                          </span>
                        </td>
                      );
                    })()}

                    {/* Destination */}
                    {columns.destination && (
                    <td className={`px-2 ${density.cell} ${cellAlign('destination')} whitespace-nowrap truncate`} title={packet.destination}>
                      {resolved(packet.destination)}
                    </td>
                    )}

                    {/* Protocol - plain text in the row's own color. A badge
                        would fight the coloring chain and waste width. */}
                    {columns.protocol && (
                    <td className={`px-2 ${density.cell} ${cellAlign('protocol')} whitespace-nowrap truncate`}>
                      {packet.protocolLabel ?? packet.protocol}
                    </td>
                    )}

                    {/* Length */}
                    {columns.length && (
                    <td className={`pl-2 pr-3 ${density.cell} whitespace-nowrap truncate tabular-nums ${cellAlign('length')}`}>{packet.length}</td>
                    )}

                    {customColumns.map((c) => (
                      <td
                        key={c.abbrev}
                        className={`px-2 ${density.cell} whitespace-nowrap truncate ${
                          c.def.column?.align === 'right' ? 'text-right tabular-nums' : 'text-left'
                        }`}
                        title={String(fieldValue(packet, c.abbrev) ?? '')}
                      >
                        {fieldValue(packet, c.abbrev) ?? ''}
                      </td>
                    ))}

                    {/* Info - absorbs the remaining width and clips; the reference analyzer
                        scrolls the list horizontally rather than ellipsising. */}
                    <td className={`px-4 ${density.cell} ${cellAlign('info')} whitespace-nowrap overflow-hidden`} title={packet.info}>
                      {packet.info}
                    </td>
                  </tr>
                );
                })}
                {bottomSpacerHeight > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={visibleColumnCount} style={{ height: bottomSpacerHeight, padding: 0, border: 'none' }} />
                  </tr>
                )}
              </>
            )}
          </tbody>
        </table>
      </div>

      {showMinimap && (
      <PacketListMinimap
        packets={sortedPackets}
        leadingRows={addressingCapture ? captureRows.leadingRows : 0}
        selectedPacket={selectedPacket}
        colorEngine={colorEngine}
        packetTheme={packetTheme}
        themeKey={themeKey}
        containerRef={tableContainerRef}
        topOffset={headerHeight}
        headerSlot={
          <div className={`w-full h-full flex items-center justify-center ${HEADER_CHROME}`}>
            {columnMenuTrigger}
          </div>
        }
        onUserScrollIntent={armUserScroll}
      />
      )}
      </div>

      {/* Right Click Context Menu */}
      {contextMenu && (
        <div
          className="fixed z-50 rounded-lg border p-1 shadow-2xl transition-all bg-popover border-border text-popover-foreground min-w-[240px] font-sans text-xs"
          style={{ top: Math.min(contextMenu.y, window.innerHeight - 300), left: Math.min(contextMenu.x, window.innerWidth - 260) }}
        >
          <div className={`${MICRO_LABEL} px-2 py-1 border-b border-border`}>
            Packet #{contextMenu.packet.id} Options
          </div>

          {/* Offered for UDP as well as TCP now: a stream is selected by its
              five-tuple rather than by the TCP tracker's index, so a DNS
              exchange or a QUIC connection - which have no index - can be
              followed too. */}
          {(() => {
            const target = targetForPacket(contextMenu.packet);
            if (!target) return null;
            return (
              <button
                onClick={() => onFollowStream(target)}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
              >
                <MessageSquare className="w-3.5 h-3.5 text-foreground" />
                <span>
                  Follow {target.kind.toUpperCase()} Stream
                  {target.streamId !== undefined ? ` (#${target.streamId})` : ''}
                </span>
              </button>
            );
          })()}

          {/* The same conversation, asked a different question. Following it
              is about what was said; showing it is about the shape - a request
              answered four seconds later, a side that went quiet, a burst of
              retransmissions. Two doors onto one window. */}
          {(() => {
            const target = targetForPacket(contextMenu.packet);
            if (!target) return null;
            return (
              <button
                onClick={() => onFollowStream(target, 'ladder')}
                className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
              >
                <ArrowRightLeft className="w-3.5 h-3.5 text-foreground" />
                <span>Show conversation</span>
              </button>
            );
          })()}

          <button
            onClick={() => onQuickFilter(`ip.src == "${contextMenu.packet.source}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Funnel className="w-3.5 h-3.5" />
            <span>Filter by Source ({contextMenu.packet.source})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`ip.dst == "${contextMenu.packet.destination}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Funnel className="w-3.5 h-3.5" />
            <span>Filter by Destination ({contextMenu.packet.destination})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`proto == ${contextMenu.packet.protocol.toLowerCase()}`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Funnel className="w-3.5 h-3.5" />
            <span>Filter by Protocol ({contextMenu.packet.protocol})</span>
          </button>

          <div className="my-1 border-t border-border" />

          <button
            onClick={() => {
              // Synchronous while the frame still carries its bytes, which is
              // the common case and the one that matters here: a clipboard
              // write is only reliably permitted inside the gesture that
              // triggered it, and awaiting first can put it outside on some
              // browsers. A frame whose bytes the buffer has dropped takes the
              // slow path and accepts that risk, because the alternative is
              // copying an empty string (docs/decisions/0013).
              const target = contextMenu.packet;
              if (hasBytes(target)) {
                void copyText(packetHexDump(target));
                return;
              }
              void packetBytes(target).then((rawBytes) => {
                void copyText(packetHexDump({ ...target, rawBytes }));
              });
            }}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <Copy className="w-3.5 h-3.5 text-foreground" />
            <span>Copy Raw Hex Stream</span>
          </button>
        </div>
      )}
    </div>
  );
};
