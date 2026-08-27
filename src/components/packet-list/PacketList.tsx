import React, { useState, useEffect, useRef } from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
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

interface PacketListProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet) => void;
  onFollowStream: (streamId: number) => void;
  onQuickFilter: (filter: string) => void;
  searchText: string;
  colorEngine: ColorRulesEngine;
  permissions: UserRolePermissions;
  isDark: boolean;
}

type SortField = 'id' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length' | 'info';
type SortOrder = 'asc' | 'desc';

// 'info' is deliberately excluded: it's the last column and always absorbs
// whatever width the fixed-width columns don't use, the same way VS Code's
// rightmost panel does - it never needs its own draggable handle.
type ColumnKey = 'id' | 'relativeTime' | 'source' | 'destination' | 'protocol' | 'length';

const COLUMN_WIDTHS_STORAGE_KEY = 'netview.packetListColumnWidths';
const DEFAULT_COLUMN_WIDTHS: Record<ColumnKey, number> = {
  id: 64,
  relativeTime: 116,
  source: 280,
  destination: 280,
  protocol: 76,
  length: 68,
};
const MIN_COLUMN_WIDTH = 36;
const MAX_COLUMN_WIDTH = 480;

function loadStoredColumnWidths(): Record<ColumnKey, number> {
  try {
    const raw = localStorage.getItem(COLUMN_WIDTHS_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_COLUMN_WIDTHS };
    const parsed = JSON.parse(raw);
    const result = { ...DEFAULT_COLUMN_WIDTHS };
    (Object.keys(DEFAULT_COLUMN_WIDTHS) as ColumnKey[]).forEach(key => {
      const value = parsed?.[key];
      if (typeof value === 'number' && Number.isFinite(value)) {
        result[key] = Math.min(MAX_COLUMN_WIDTH, Math.max(MIN_COLUMN_WIDTH, value));
      }
    });
    return result;
  } catch {
    return { ...DEFAULT_COLUMN_WIDTHS };
  }
}

export const PacketList: React.FC<PacketListProps> = ({
  packets,
  selectedPacket,
  onSelectPacket,
  onFollowStream,
  onQuickFilter,
  searchText,
  colorEngine,
  permissions,
  isDark,
}) => {
  const [sortField, setSortField] = useState<SortField>('id');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; packet: Packet } | null>(null);
  const tableContainerRef = useRef<HTMLDivElement | null>(null);

  // Resizable columns
  const [columnWidths, setColumnWidths] = useState<Record<ColumnKey, number>>(loadStoredColumnWidths);
  const columnResizeRef = useRef<{ column: ColumnKey; startX: number; startWidth: number } | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(COLUMN_WIDTHS_STORAGE_KEY, JSON.stringify(columnWidths));
    } catch {
      // ignore write failures (private browsing, storage disabled, etc.)
    }
  }, [columnWidths]);

  // Columns the user has dragged; these opt out of auto-sizing for good.
  const userSizedColumnsRef = useRef<Set<ColumnKey>>(new Set());

  // Address columns auto-size to their widest value, Wireshark-style: an IPv6
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
      className="absolute right-0 top-0 h-full w-1.5 translate-x-1/2 cursor-col-resize hover:bg-cyan-500/50 z-10"
      title="Drag to resize column"
    />
  );

  // Sorting & Filtering
  const sortedPackets = React.useMemo(() => {
    let processedPackets = packets;

    // Apply quick-find search (from the FilterBar's "Find packet" control)
    if (searchText.trim()) {
      const lowerSearch = searchText.toLowerCase();
      processedPackets = processedPackets.filter(
        p =>
          p.protocol.toLowerCase().includes(lowerSearch) ||
          p.source.toLowerCase().includes(lowerSearch) ||
          p.destination.toLowerCase().includes(lowerSearch) ||
          p.info.toLowerCase().includes(lowerSearch) ||
          p.id.toString().includes(lowerSearch)
      );
    }

    if (!sortField) return processedPackets;

    return [...processedPackets].sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];
      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = (valB || '').toLowerCase();
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    });
  }, [packets, sortField, sortOrder, searchText]);

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

  // getBoundingClientRect() forces a synchronous layout, so this must only
  // ever run once: the ref callback re-fires on every render where a
  // different packet lands in the first visible slot (i.e. nearly every
  // incoming packet while auto-scrolled), and doing this measurement on
  // every one of those was itself measured as the single largest forced-
  // reflow cost in the app once the earlier full-DOM freeze was fixed.
  const measuredRowRef = (node: HTMLTableRowElement | null) => {
    if (!node || hasMeasuredRowHeightRef.current) return;
    const height = node.getBoundingClientRect().height;
    if (height > 0) {
      hasMeasuredRowHeightRef.current = true;
      if (Math.abs(height - rowHeight) > 0.5) setRowHeight(height);
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
    shouldAutoScrollRef.current = scrollHeight - (currentScrollTop + clientHeight) < 50;
  };

  useEffect(() => {
    // Depend on the array reference itself, not packets.length: once the
    // live-capture buffer hits its cap (4000, see App.tsx), each new packet
    // also drops the oldest one, so length stops changing even though new
    // data keeps arriving - length alone would silently stop autoscroll.
    if (shouldAutoScrollRef.current && tableContainerRef.current) {
      tableContainerRef.current.scrollTop = tableContainerRef.current.scrollHeight;
      // Update the virtualization window synchronously too, rather than
      // waiting for the resulting scroll event to do it.
      setScrollTop(tableContainerRef.current.scrollTop);
    }
  }, [packets]);

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

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) return <TbArrowsSort className="w-3 h-3 text-muted-foreground opacity-30 group-hover:opacity-100 transition-opacity" />;
    return sortOrder === 'asc' ? (
      <TbArrowUp className="w-3 h-3 text-cyan-400" />
    ) : (
      <TbArrowDown className="w-3 h-3 text-cyan-400" />
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
        onKeyDown={armUserScroll}
        className="flex-1 overflow-y-auto overflow-x-auto custom-scrollbar"
      >
        <table className="w-full table-fixed text-left border-collapse font-mono text-xs">
          <colgroup>
            <col style={{ width: columnWidths.id }} />
            <col style={{ width: columnWidths.relativeTime }} />
            <col style={{ width: columnWidths.source }} />
            <col style={{ width: columnWidths.destination }} />
            <col style={{ width: columnWidths.protocol }} />
            <col style={{ width: columnWidths.length }} />
            <col />
          </colgroup>
          {/* Table Header */}
          <thead
            className="sticky top-0 z-20 border-b transition-colors select-none bg-secondary border-border text-muted-foreground"
          >
            <tr className="text-[11px] uppercase tracking-wider divide-x divide-border/60">
              <th
                onClick={() => handleSort('id')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <div className="flex items-center gap-1">
                  <span>No.</span>
                  {renderSortIcon('id')}
                </div>
                {renderColumnResizeHandle('id')}
              </th>

              <th
                onClick={() => handleSort('relativeTime')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Time</span>
                  {renderSortIcon('relativeTime')}
                </div>
                {renderColumnResizeHandle('relativeTime')}
              </th>

              <th
                onClick={() => handleSort('source')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Source</span>
                  {renderSortIcon('source')}
                </div>
                {renderColumnResizeHandle('source')}
              </th>

              <th
                onClick={() => handleSort('destination')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Destination</span>
                  {renderSortIcon('destination')}
                </div>
                {renderColumnResizeHandle('destination')}
              </th>

              <th
                onClick={() => handleSort('protocol')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                <div className="flex items-center gap-1">
                  <span>Protocol</span>
                  {renderSortIcon('protocol')}
                </div>
                {renderColumnResizeHandle('protocol')}
              </th>

              <th
                onClick={() => handleSort('length')}
                className={`relative px-2 py-1 cursor-pointer group font-bold overflow-hidden ${"hover:bg-accent text-muted-foreground"}`}
              >
                {/* Right-aligned to match the numbers below it. With the
                    header left-aligned and the values right-aligned, resizing
                    this column dragged the two apart in opposite directions
                    and pushed the value up against the Info text. */}
                <div className="flex items-center justify-end gap-1">
                  <span>Length</span>
                  {renderSortIcon('length')}
                </div>
                {renderColumnResizeHandle('length')}
              </th>

              <th onClick={() => handleSort('info')} className={`px-4 py-2.5 cursor-pointer group font-bold ${"hover:bg-accent text-muted-foreground"}`}><div className="flex items-center gap-1"><span>Info</span>{renderSortIcon('info')}</div></th>
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="font-mono text-[11px] leading-[1.15]">
            {sortedPackets.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-16 text-muted-foreground">
                  <div className="flex flex-col items-center justify-center gap-1">
                    <TbFilter className="w-6 h-6 text-muted-foreground/70 mb-1" />
                    <span>No packets match current display filter or capture is empty.</span>
                    <span className="text-[10px] text-muted-foreground/70">Start capture or clear filter to resume telemetry</span>
                  </div>
                </td>
              </tr>
            ) : (
              <>
                {topSpacerHeight > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={7} style={{ height: topSpacerHeight, padding: 0, border: 'none' }} />
                  </tr>
                )}
                {visiblePackets.map((packet, i) => {
                const isSelected = selectedPacket?.id === packet.id;
                const style = colorEngine.getPacketStyle(packet, isDark);

                return (
                  <tr
                    key={packet.id}
                    ref={i === 0 ? measuredRowRef : undefined}
                    onClick={() => onSelectPacket(packet)}
                    onContextMenu={e => handleContextMenu(e, packet)}
                    className={`cursor-pointer ${
                      isSelected
                        ? '!bg-accent !text-cyan-800 dark:!text-cyan-200 ring-1 ring-inset ring-cyan-500 font-bold'
                        : 'hover:brightness-95 dark:hover:brightness-125'
                    }`}
                    // The matched rule's foreground applies to the whole row,
                    // including the Protocol and Length cells - that is how
                    // Wireshark's coloring reads at a glance. Individual cells
                    // below inherit rather than setting their own color.
                    style={
                      !isSelected
                        ? { backgroundColor: style.background, color: style.color }
                        : undefined
                    }
                  >
                    {/* No. - right-aligned with tabular figures so the column
                        stays a clean edge as the number of digits grows. */}
                    <td className="px-2 py-1 font-mono whitespace-nowrap text-right tabular-nums">
                      <div className="flex items-center justify-end gap-1">
                        {(packet.anomalies && packet.anomalies.length > 0) || packet.status === 'alert' ? (
                          <TbShieldExclamation className="w-3 h-3 text-rose-500 shrink-0" />
                        ) : null}
                        <span>{packet.id}</span>
                      </div>
                    </td>

                    {/* Time */}
                    <td className="px-2 py-1 whitespace-nowrap font-mono text-right tabular-nums">
                      {typeof packet.relativeTime === 'number'
                        ? packet.relativeTime.toFixed(packet.tsPrecision ?? 6)
                        : (0).toFixed(packet.tsPrecision ?? 6)}
                    </td>

                    {/* Source - address only; Wireshark keeps ports in the Info column */}
                    <td className="px-2 py-1 whitespace-nowrap truncate" title={packet.source}>
                      {packet.source}
                    </td>

                    {/* Destination */}
                    <td className="px-2 py-1 whitespace-nowrap truncate" title={packet.destination}>
                      {packet.destination}
                    </td>

                    {/* Protocol - plain text in the row's own color. A badge
                        would fight the coloring chain and waste width. */}
                    <td className="px-2 py-1 whitespace-nowrap truncate">
                      {packet.protocolLabel ?? packet.protocol}
                    </td>

                    {/* Length */}
                    <td className="pl-2 pr-3 py-1 whitespace-nowrap text-right tabular-nums">{packet.length}</td>

                    {/* Info - absorbs the remaining width and clips; Wireshark
                        scrolls the list horizontally rather than ellipsising. */}
                    <td className="px-4 py-1 whitespace-nowrap overflow-hidden" title={packet.info}>
                      {packet.info}
                    </td>
                  </tr>
                );
                })}
                {bottomSpacerHeight > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={7} style={{ height: bottomSpacerHeight, padding: 0, border: 'none' }} />
                  </tr>
                )}
              </>
            )}
          </tbody>
        </table>
      </div>

      <PacketListMinimap
        packets={sortedPackets}
        selectedPacket={selectedPacket}
        colorEngine={colorEngine}
        isDark={isDark}
        containerRef={tableContainerRef}
        onUserScrollIntent={armUserScroll}
      />
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

          {contextMenu.packet.streamId !== undefined && (
            <button
              onClick={() => onFollowStream(contextMenu.packet.streamId!)}
              className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
            >
              <TbMessage className="w-3.5 h-3.5 text-foreground" />
              <span>Follow Stream (#{contextMenu.packet.streamId})</span>
            </button>
          )}

          <button
            onClick={() => onQuickFilter(`ip.src == "${contextMenu.packet.source}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
            <span>Filter by Source ({contextMenu.packet.source})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`ip.dst == "${contextMenu.packet.destination}"`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
            <span>Filter by Destination ({contextMenu.packet.destination})</span>
          </button>

          <button
            onClick={() => onQuickFilter(`proto == ${contextMenu.packet.protocol.toLowerCase()}`)}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbFilter className="w-3.5 h-3.5" />
            <span>Filter by Protocol ({contextMenu.packet.protocol})</span>
          </button>

          <div className="my-1 border-t border-border" />

          <button
            onClick={() => {
              navigator.clipboard.writeText(packetHexDump(contextMenu.packet));
            }}
            className="w-full text-left px-2.5 py-1.5 rounded hover:bg-cyan-500/10 hover:text-cyan-400 transition-colors flex items-center gap-2 cursor-pointer"
          >
            <TbCopy className="w-3.5 h-3.5 text-foreground" />
            <span>Copy Raw Hex Stream</span>
          </button>
        </div>
      )}
    </div>
  );
};
