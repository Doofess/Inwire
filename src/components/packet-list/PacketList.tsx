import React, { useState, useEffect, useRef } from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';
import { PacketListMinimap } from './PacketListMinimap';
import {
  TbArrowsSort,
  TbArrowUp,
  TbArrowDown,
  TbShieldExclamation,
  TbMessage,
  TbFilter,
  TbCopy,
} from 'react-icons/tb';
import { packetHexDump } from '../../services/pcapParser';
import { hasBytes, packetBytes } from '../../services/packetBytes';
import { fieldValue } from '../../services/dissect/fieldAccess';
import { useDebouncedValue } from '../../lib/useDebouncedValue';
import { minimapStore, packetListStore } from '../../services/interfacePrefs';
import { formatTimeColumn } from '../../lib/formatTimeColumn';
import { ColumnOptionsMenu } from './ColumnOptionsMenu';
import {
  COLUMN_ALIGNS,
  COLUMN_ALIGN_CLASS,
  COLUMN_ALIGN_JUSTIFY,
  COLUMN_ALIGN_LABELS,
  COLUMN_LABELS,
  HIDEABLE_COLUMNS,
  visibleSortField,
  type AlignableColumn,
  type ColumnAlign,
  type SortField as ColumnSortField,
} from '../../lib/packetColumns';
import { fieldDef } from '../../services/dissect/fieldRegistry';
import type { NameLookup } from '../../services/nameResolution';
import type { ExpertLookup } from '../../services/expertInfo';
import { targetForPacket, type StreamTarget } from '../../services/followStream';
import { SEVERITY_DOT, SEVERITY_LABELS } from '../../services/expertInfo';
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

interface PacketListProps {
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
  /**
   * The expert log, for the severity dot in the No. column.
   *
   * A dot rather than the shield icon this column used to carry for anomalies
   * alone: the icon answered one question ("did the detector flag this") while
   * a frame can also be a bad checksum, a lost segment or an expired
   * certificate, and those had no mark in the list at all. One mark, four
   * levels, the same colours the tree and the Expert Information tab use.
   */
  expert?: ExpertLookup;
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  /** Double-clicking a row opens the full-window view of that frame. */
  onInspectPacket?: (packet: Packet) => void;
  onFollowStream: (target: StreamTarget) => void;
  onQuickFilter: (filter: string) => void;
  searchText: string;
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
  permissions: UserRolePermissions;
  /** Colors for the list itself. Independent of the app theme by design -
   *  see services/packetThemes. */
  packetTheme: PacketTheme;
  themeKey?: string;
}

type SortField = 'id' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length' | 'info';
type SortOrder = 'asc' | 'desc';

// 'info' is deliberately excluded: it's the last column and always absorbs
// whatever width the fixed-width columns don't use, the same way VS Code's
// rightmost panel does - it never needs its own draggable handle.
type ColumnKey = 'id' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length';

const COLUMN_WIDTHS_STORAGE_KEY = 'inwire.packetListColumnWidths';
const SORT_STORAGE_KEY = 'inwire.packetListSort';
const DEFAULT_COLUMN_WIDTHS: Record<ColumnKey, number> = {
  id: 64,
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
 */
const DENSITY_CLASS: Record<'compact' | 'default' | 'comfortable', { body: string; cell: string }> = {
  compact: { body: 'font-mono text-[10px] leading-[1.1]', cell: 'py-0.5' },
  default: { body: 'font-mono text-[11px] leading-[1.15]', cell: 'py-1' },
  comfortable: { body: 'font-mono text-[12px] leading-[1.45]', cell: 'py-1.5' },
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
const SORT_FIELDS: SortField[] = ['id', 'relativeTime', 'source', 'destination', 'protocol', 'length', 'info'];

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
  expert,
  packets,
  selectedPacket,
  onSelectPacket,
  onInspectPacket,
  onFollowStream,
  onQuickFilter,
  searchText,
  droppedBuffer = 0,
  colorEngine,
  permissions,
  packetTheme,
  themeKey,
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
  const autoSizeRef = useRef({ firstPacketId: -1, measuredCount: 0, source: 0, destination: 0 });
  const textMeasureRef = useRef<CanvasRenderingContext2D | null>(null);

  useEffect(() => {
    const state = autoSizeRef.current;

    // A new capture (or a cleared buffer) restarts the measurement; the live
    // buffer also drops its oldest packets once full, but always keeps
    // appending, so a *changed* first id is what identifies a genuine reset.
    const firstPacketId = packets.length > 0 ? packets[0].id : -1;
    if (packets.length < state.measuredCount || firstPacketId !== state.firstPacketId) {
      state.firstPacketId = firstPacketId;
      state.measuredCount = 0;
      state.source = 0;
      state.destination = 0;
    }
    if (packets.length === state.measuredCount) return;

    if (!textMeasureRef.current) {
      const cell = tableContainerRef.current?.querySelector('tbody td');
      const context = document.createElement('canvas').getContext('2d');
      if (!context) return;
      const style = cell ? getComputedStyle(cell) : null;
      context.font = style ? `${style.fontSize} ${style.fontFamily}` : '11px monospace';
      textMeasureRef.current = context;
    }
    const measure = textMeasureRef.current;

    // Only the packets appended since last time are measured, so sustained
    // live capture stays O(new packets) rather than re-walking the buffer.
    for (let i = state.measuredCount; i < packets.length; i++) {
      state.source = Math.max(state.source, measure.measureText(packets[i].source).width);
      state.destination = Math.max(state.destination, measure.measureText(packets[i].destination).width);
    }
    state.measuredCount = packets.length;

    const CELL_PADDING = 18; // px-2 either side, plus a little breathing room
    setColumnWidths(prev => {
      const next = { ...prev };
      let changed = false;
      for (const column of ['source', 'destination'] as const) {
        if (userSizedColumnsRef.current.has(column)) continue;
        const fitted = Math.min(
          MAX_COLUMN_WIDTH,
          Math.max(MIN_COLUMN_WIDTH, Math.ceil(state[column] + CELL_PADDING))
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
      className="absolute right-0 top-0 h-full w-1.5 translate-x-1/2 cursor-col-resize hover:bg-primary/50 z-10"
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
   * Quick-find, once typing settles.
   *
   * The scan below lowercases four strings for every frame in the buffer, and
   * it ran on every keystroke - so each intermediate prefix of what someone is
   * typing cost a full pass, for results replaced before they could be read.
   *
   * Clearing the box is exempt and lands at once. It is the one change whose
   * answer the user already knows - the whole list - and making them wait
   * 150 ms to get their list back would be the delay showing rather than
   * hiding.
   */
  const settledSearch = useDebouncedValue(searchText, 150);
  const activeSearch = searchText.trim() === '' ? '' : settledSearch;

  const sortedPackets = React.useMemo(() => {
    let processedPackets = packets;

    // Apply quick-find search (from the FilterBar's "Find packet" control)
    if (activeSearch.trim()) {
      const lowerSearch = activeSearch.toLowerCase();
      processedPackets = processedPackets.filter(
        p =>
          p.protocol.toLowerCase().includes(lowerSearch) ||
          p.source.toLowerCase().includes(lowerSearch) ||
          p.destination.toLowerCase().includes(lowerSearch) ||
          p.info.toLowerCase().includes(lowerSearch) ||
          p.id.toString().includes(lowerSearch)
      );
    }

    if (!effectiveSortField) return processedPackets;

    // The default sort - packet number ascending - is the order the buffer is
    // already in, since ids come from packetGenerator monotonically and nothing
    // reorders it. Copying and re-sorting it every 100ms flush to arrive back
    // at the identical order is measurable at capture volume and buys nothing,
    // so recognise it and hand the array straight back. Exact, not an
    // approximation: any other field or direction still takes the sort below.
    if (effectiveSortField === 'id' && sortOrder === 'asc') return processedPackets;

    return [...processedPackets].sort((a, b) => {
      let valA: any = a[effectiveSortField as keyof Packet];
      let valB: any = b[effectiveSortField as keyof Packet];
      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = (valB || '').toLowerCase();
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    });
  }, [packets, effectiveSortField, sortOrder, activeSearch]);

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
  // One more measurement, once the webfont has actually landed.
  //
  // The latch below deliberately measures once, and on a cold load that once is
  // too early: rows are laid out in the fallback font, which here happens to be
  // exactly the 21px fallback, so the measurement agrees with the guess and the
  // real 20.641px height that arrives with JetBrains Mono is never seen. The
  // list then believes every row is a third of a pixel taller than it is, which
  // across a full buffer puts the last rows out of reach of the scroll position
  // that should land on them.
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
    autoSizeRef.current.measuredCount = 0;
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

  const totalRows = sortedPackets.length;
  const startIndex = totalRows === 0 ? 0 : Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN_ROWS);
  const endIndex = totalRows === 0 ? 0 : Math.min(totalRows, Math.ceil((scrollTop + viewportHeight) / rowHeight) + OVERSCAN_ROWS);
  const visiblePackets = sortedPackets.slice(startIndex, endIndex);
  const topSpacerHeight = startIndex * rowHeight;
  const bottomSpacerHeight = (totalRows - endIndex) * rowHeight;

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
    if (sortedPackets.length === 0) return;
    const current = selectedPacket
      ? sortedPackets.findIndex(p => p.id === selectedPacket.id)
      : -1;

    let next: number;
    if (delta === 'first') next = 0;
    else if (delta === 'last') next = sortedPackets.length - 1;
    // With nothing selected, the first key press selects an end rather than
    // jumping into the middle: down starts at the top, up starts at the bottom.
    else if (current === -1) next = delta > 0 ? 0 : sortedPackets.length - 1;
    else next = current + delta;

    next = Math.max(0, Math.min(sortedPackets.length - 1, next));
    const target = sortedPackets[next];
    if (!target) return;

    // Jumping to the end means "show me the newest", so following resumes.
    // Any other move means the user is reading something specific, and the
    // list must hold still underneath them - unless they have said they always
    // want the tail, in which case moving the selection is not a request to
    // stop following.
    if (followRef.current === 'reading') {
      shouldAutoScrollRef.current = next === sortedPackets.length - 1;
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
   * whatever was behind it while the header row beside it drew `--secondary`.
   * Two surfaces that are meant to read as one bar, defined in two places, is
   * a mismatch that reappears every time either one is themed. There is one
   * definition now and both render it.
   */
  const HEADER_CHROME =
    'bg-secondary border-b border-border text-muted-foreground transition-colors';

  // Where the text sits, per column. Every column is settable now - see
  // ColumnAlignMap for why the numeric three no longer have to be excluded.
  //
  // The VALUES only. Column titles are always centred, whatever a column is
  // set to: the header is a fixed row of labels read across, and letting each
  // one wander to whichever edge its values happen to use turned that row
  // ragged - a centred title also sits over both a left-aligned and a
  // right-aligned column without looking attached to the wrong one.
  const cellAlign = (column: AlignableColumn) => COLUMN_ALIGN_CLASS[listPrefs.align[column]];
  /** For cells whose content is a flex row rather than plain text. */
  const cellJustify = (column: AlignableColumn) => COLUMN_ALIGN_JUSTIFY[listPrefs.align[column]];
  const HEADER_TITLE = 'justify-center';

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
    if (effectiveSortField !== field) return <TbArrowsSort className="w-3 h-3 text-muted-foreground opacity-30 group-hover:opacity-100 transition-opacity" />;
    return sortOrder === 'asc' ? (
      <TbArrowUp className="w-3 h-3 text-primary" />
    ) : (
      <TbArrowDown className="w-3 h-3 text-primary" />
    );
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden select-none relative">
      {/* Table Container + Minimap */}
      <div className="flex-1 flex overflow-hidden min-h-0">
      <div
        ref={tableContainerRef}
        onScroll={handleScroll}
        onWheel={armUserScroll}
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
        style={{ backgroundColor: packetTheme.surface.background, color: packetTheme.surface.foreground }}
      >
        <table className="w-full table-fixed text-left border-collapse font-mono text-xs">
          {/* The colgroup has to track visibility exactly: `table-fixed` maps
              these to cells by POSITION, so one stale <col> shifts every width
              after it onto the wrong column. */}
          <colgroup>
            {columns.id && <col style={{ width: columnWidths.id }} />}
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
            className={`sticky top-0 z-20 select-none ${HEADER_CHROME}`}
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
                setAlignColumn((cell?.getAttribute('data-column') as AlignableColumn) ?? null);
              }}
              className="text-[11px] uppercase tracking-wider divide-x divide-border"
            >
              {columns.id && (
              <th
                data-column="id"
                aria-sort={sortAttr('id')}
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <button type="button" onClick={() => handleSort('id')} className={`flex items-center gap-1 w-full cursor-pointer ${HEADER_TITLE}`}>
                    <span>No.</span>
                    {renderSortIcon('id')}
                </button>
                {renderColumnResizeHandle('id')}
              </th>
              )}

              {columns.relativeTime && (
              <th
                data-column="relativeTime"
                aria-sort={sortAttr('relativeTime')}
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
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
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
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
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
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
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
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
                className={`relative px-2 py-1 group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
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
                  className={`relative px-2 py-1 group font-bold overflow-hidden hover:bg-accent text-muted-foreground`}
                >
                  <div className={`flex items-center gap-1 w-full ${HEADER_TITLE}`}>
                    <span className="truncate">{c.def.column?.label ?? c.def.label}</span>
                  </div>
                </th>
              ))}

              <th data-column="info" aria-sort={sortAttr('info')} className={`px-4 py-2.5 group font-bold ${"hover:bg-accent text-muted-foreground"}`}><div className="flex items-center gap-1"><button type="button" onClick={() => handleSort('info')} className={`flex items-center gap-1 flex-1 min-w-0 cursor-pointer ${HEADER_TITLE}`}><span>Info</span>{renderSortIcon('info')}</button>{/* Only when the minimap is off - otherwise it lives in the strip above the map, which is not a column and so does not move when one is resized. It has to live SOMEWHERE, though: this menu is the only way to turn the hidden columns back on. */}{!showMinimap && columnMenuTrigger}</div></th>
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
            {sortedPackets.length === 0 ? (
              <tr>
                <td colSpan={visibleColumnCount} className="text-center py-16 text-muted-foreground">
                  <div className="flex flex-col items-center justify-center gap-1">
                    <TbFilter className="w-6 h-6 text-muted-foreground/70 mb-1" />
                    <span>
                      {packets.length === 0
                        ? 'The capture buffer is empty.'
                        : 'No packets match the current display filter.'}
                    </span>
                    {/* Scoped rather than absolute, and only when it is true.
                        The filter ran over what is held, and what is held is
                        not the capture once the buffer has trimmed. */}
                    {packets.length > 0 && droppedBuffer > 0 && (
                      <span className="text-[11px] font-mono text-amber-600 dark:text-amber-400 mt-0.5">
                        Searched frames {packets[0].id.toLocaleString()}–
                        {packets[packets.length - 1].id.toLocaleString()};{' '}
                        {droppedBuffer.toLocaleString()} earlier frames have left the buffer.
                      </span>
                    )}
                    <span className="text-[10px] text-muted-foreground/70">Start capture or clear filter to resume telemetry</span>
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
                {visiblePackets.map((packet, i) => {
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
                    // `divide-x` on every row, not just the header. The
                    // columns had no vertical rule at all below the header, so
                    // where one value ended and the next began was carried
                    // entirely by the gap between them - which disappears the
                    // moment a column is narrow enough for its text to fill it.
                    // Held at /40 rather than the header's full strength: this
                    // runs behind the row colours and down every row on screen,
                    // and at full strength it reads as a grid drawn over the
                    // data rather than as a separation between columns.
                    className={`cursor-pointer divide-x divide-border/40 ${
                      isSelected
                        ? '!bg-accent !text-primary dark:!text-primary ring-1 ring-inset ring-primary font-bold'
                        : 'hover:brightness-95 dark:hover:brightness-125'
                    }`}
                    // The matched rule's foreground applies to the whole row,
                    // including the Protocol and Length cells - that is how
                    // The reference analyzer's coloring reads at a glance. Individual cells
                    // below inherit rather than setting their own color.
                    style={
                      !isSelected
                        ? { backgroundColor: style.background, color: style.color }
                        : undefined
                    }
                  >
                    {/* No. - right-aligned with tabular figures so the column
                        stays a clean edge as the number of digits grows. */}
                    {columns.id && (
                    <td className={`px-2 ${density.cell} font-mono whitespace-nowrap truncate tabular-nums ${cellAlign('id')}`}>
                      <div className={`flex items-center gap-1 ${cellJustify('id')}`}>
                        {(() => {
                          const severity = expert?.severityOf(packet.id);
                          if ((packet.anomalies?.length ?? 0) > 0 || packet.status === 'alert') {
                            return <TbShieldExclamation className="w-3 h-3 text-rose-500 shrink-0" title="Flagged by the anomaly detector" />;
                          }
                          return severity ? (
                            <span
                              className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${SEVERITY_DOT[severity]}`}
                              title={`${SEVERITY_LABELS[severity]} - see Expert Information`}
                            />
                          ) : null;
                        })()}
                        <span>{packet.id}</span>
                      </div>
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
                        startIndex + i > 0 ? sortedPackets[startIndex + i - 1] : null,
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
                          <span className="flex items-baseline min-w-0">
                            <span className="truncate">{resolved(packet.source)}</span>
                            {sender && (
                              // Dimmed, because the address is the identity and
                              // the program is the annotation. At full strength
                              // the two read as one long token and the column
                              // stops scanning as a list of addresses.
                              <span className="shrink-0 text-muted-foreground">
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
          <div className="px-2 py-1 text-[10px] font-bold text-muted-foreground uppercase tracking-wider border-b border-border font-mono">
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
                <TbMessage className="w-3.5 h-3.5 text-foreground" />
                <span>
                  Follow {target.kind.toUpperCase()} Stream
                  {target.streamId !== undefined ? ` (#${target.streamId})` : ''}
                </span>
              </button>
            );
          })()}

          <button
            onClick={() => onQuickFilter(`ip.src == "${contextMenu.packet.source}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
            <span>Filter by Source ({contextMenu.packet.source})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`ip.dst == "${contextMenu.packet.destination}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
            <span>Filter by Destination ({contextMenu.packet.destination})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`proto == ${contextMenu.packet.protocol.toLowerCase()}`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
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
                void navigator.clipboard.writeText(packetHexDump(target));
                return;
              }
              void packetBytes(target).then((rawBytes) => {
                void navigator.clipboard.writeText(packetHexDump({ ...target, rawBytes }));
              });
            }}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-primary/10 hover:text-primary transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbCopy className="w-3.5 h-3.5 text-foreground" />
            <span>Copy Raw Hex Stream</span>
          </button>
        </div>
      )}
    </div>
  );
};
