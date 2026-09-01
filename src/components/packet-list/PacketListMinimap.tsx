import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Packet } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import {
  loadPreference,
  useDebouncedPreference,
  usePreferenceSync,
} from '../../services/preferences';
import { useThemeToken } from '../../lib/themeColor';
import type { PacketTheme } from '../../services/packetThemes';

interface PacketListMinimapProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  colorEngine: ColorRulesEngine;
  /** Colors for the bands, which are packet data. The selection marker
   *  deliberately does NOT use this - see `accent` below. */
  packetTheme: PacketTheme;
  /** Forces this canvas to repaint when the APP theme changes, which the
   *  accent follows. A theme name cannot be inferred from a boolean - see
   *  themeColor. */
  themeKey?: string;
  containerRef: React.RefObject<HTMLDivElement | null>;
  /**
   * How far down to start, in pixels - the height of the table's header row.
   *
   * The map is a sibling of the scroll container, so it spans the whole table
   * area; the header row is sticky INSIDE that container, so without this the
   * map ran up alongside the column headings and its first few pixels of
   * packet data sat level with the word "No." rather than with row one. Pushing
   * it down by exactly the header's height lines the top of the map up with the
   * top of the data it is a map of.
   */
  topOffset?: number;
  /**
   * Rendered in the band above the map, level with the column headings.
   *
   * The column-options button lives there rather than inside the Info heading,
   * where it sat on top of a sortable header and moved every time that column
   * was resized. This strip is the one piece of header-height space in the
   * table that belongs to no column, which makes it the natural home for a
   * control that acts on all of them.
   */
  headerSlot?: React.ReactNode;
  /**
   * Called whenever a click/drag here is about to move the table's scroll
   * position, so PacketList can treat it the same as a direct wheel/touch
   * scroll on the table itself (i.e. it's allowed to disable, or re-enable,
   * stick-to-bottom auto-scroll) rather than being silently ignored as an
   * untrusted scroll event.
   */
  onUserScrollIntent?: () => void;
}

const MINIMAP_WIDTH_STORAGE_KEY = 'netview.packetListMinimapWidth';
const DEFAULT_MINIMAP_WIDTH = 16;
const MIN_MINIMAP_WIDTH = 8;
const MAX_MINIMAP_WIDTH = 120;

/**
 * Module scope, not inside the component: usePreferenceSync takes this as a
 * dependency and a fresh identity each render would resubscribe every render.
 *
 * Accepts a bare number as well as a JSON one, because this key was written
 * with `String(width)` before it moved onto the shared service - `"24"` is
 * valid JSON for 24, but `NaN` and `Infinity` are not, so both spellings land
 * on the same guard.
 */
function normalizeMinimapWidth(raw: unknown): number | null {
  const parsed = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(parsed)) return null;
  return Math.min(MAX_MINIMAP_WIDTH, Math.max(MIN_MINIMAP_WIDTH, parsed));
}

function loadStoredMinimapWidth(): number {
  return loadPreference(MINIMAP_WIDTH_STORAGE_KEY, normalizeMinimapWidth, DEFAULT_MINIMAP_WIDTH);
}

// A throwaway 1x1 canvas used purely to resolve any valid CSS color string
// (hex from custom color rules, rgba() from the built-in ones, named colors)
// into concrete RGBA bytes, so the downsampled minimap rows can be averaged
// regardless of which format a given color rule happens to use.
let colorProbeCtx: CanvasRenderingContext2D | null | undefined;

/**
 * Resolved bytes per color string, kept for the life of the page.
 *
 * This is a pure string -> RGBA function over a tiny domain: the color rules
 * are a fixed chain, so a real capture only ever produces about ten distinct
 * strings. The uncached version was measured at 143,570 getImageData readbacks
 * per 5 seconds during a live capture (443ms of pure GPU->CPU readback), since
 * the downsample loop below resolves a color for every packet in the buffer on
 * every repaint. Memoizing takes that to at most one readback per distinct
 * color, ever.
 */
const colorByteCache = new Map<string, [number, number, number, number]>();

function resolveColorBytes(color: string): [number, number, number, number] {
  const cached = colorByteCache.get(color);
  if (cached) return cached;

  if (colorProbeCtx === undefined) {
    const probe = document.createElement('canvas');
    probe.width = 1;
    probe.height = 1;
    colorProbeCtx = probe.getContext('2d', { willReadFrequently: true });
  }
  // Not cached: without a context every call returns this same constant
  // anyway, and caching it would hide a context that became available later.
  if (!colorProbeCtx) return [148, 163, 184, 90];

  colorProbeCtx.clearRect(0, 0, 1, 1);
  colorProbeCtx.fillStyle = color;
  colorProbeCtx.fillRect(0, 0, 1, 1);
  const data = colorProbeCtx.getImageData(0, 0, 1, 1).data;
  const bytes: [number, number, number, number] = [data[0], data[1], data[2], data[3]];
  colorByteCache.set(color, bytes);
  return bytes;
}

/**
 * A VS Code-style minimap for the packet list: a thin full-height strip
 * showing one colored band per packet (matching the table's own color-rule
 * colors), a viewport indicator synced to the table's scroll position, and
 * click/drag-to-scroll plus wheel-to-scroll. Downsamples by averaging bands per pixel row when
 * there are more packets than vertical pixels, the same way a real minimap
 * degrades for files much longer than the viewport.
 */
export const PacketListMinimap: React.FC<PacketListMinimapProps> = ({
  packets,
  selectedPacket,
  colorEngine,
  packetTheme,
  themeKey,
  containerRef,
  topOffset = 0,
  headerSlot,
  onUserScrollIntent,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const draggingRef = useRef(false);
  const resizingRef = useRef<{ startX: number; startWidth: number } | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [viewport, setViewport] = useState({ top: 0, height: 0 });
  const [mapWidth, setMapWidth] = useState(loadStoredMinimapWidth);
  // As state, not read during the paint: see useThemeToken. Read inline this
  // could momentarily resolve to nothing and paint the selected-packet marker
  // in the fallback accent, then keep it until the next repaint - which, with
  // capture stopped, may never come.
  // Follows the APP theme, not the packet theme: the marker is a UI
  // affordance pointing at the selected row, not packet data. Mixing the two
  // sources in one canvas is deliberate.
  const accent = useThemeToken('--primary', '#f97316');

  // Same reasoning as the packet list's column widths: dragging this divider
  // fires on every mousemove, so the write is debounced and flushed on
  // pagehide rather than run per frame.
  useDebouncedPreference(MINIMAP_WIDTH_STORAGE_KEY, mapWidth);
  usePreferenceSync(MINIMAP_WIDTH_STORAGE_KEY, normalizeMinimapWidth, setMapWidth);

  useEffect(() => {
    const el = wrapperRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const updateViewport = useCallback(() => {
    const el = containerRef.current;
    if (!el || size.height === 0) return;
    const { scrollTop, scrollHeight, clientHeight } = el;
    if (scrollHeight <= 0) {
      setViewport({ top: 0, height: size.height });
      return;
    }
    setViewport({
      top: (scrollTop / scrollHeight) * size.height,
      // Minimum height keeps the indicator grabbable even when thousands of
      // packets squeeze the proportional viewport down to a sliver.
      height: Math.max((clientHeight / scrollHeight) * size.height, 8),
    });
  }, [containerRef, size.height]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    updateViewport();
    el.addEventListener('scroll', updateViewport, { passive: true });
    return () => el.removeEventListener('scroll', updateViewport);
  }, [containerRef, updateViewport]);

  useEffect(() => {
    // Depend on the array reference, not packets.length: once the live
    // buffer hits its cap, length stops changing on new packets even
    // though the underlying data (and scroll geometry) keeps shifting.
    updateViewport();
  }, [packets, updateViewport]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.width === 0 || size.height === 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size.width * dpr;
    canvas.height = size.height * dpr;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.width, size.height);

    const total = packets.length;
    if (total === 0) return;

    // A packet matching no rule is painted with the theme's own ground.
    const fallback = packetTheme.surface.background;

    if (total <= size.height) {
      const bandHeight = size.height / total;
      packets.forEach((packet, i) => {
        const style = colorEngine.getPacketStyle(packet, packetTheme);
        ctx.fillStyle = style.background || fallback;
        ctx.fillRect(0, i * bandHeight, size.width, Math.ceil(bandHeight));
      });
    } else {
      const packetsPerRow = total / size.height;
      for (let row = 0; row < size.height; row++) {
        const startIdx = Math.floor(row * packetsPerRow);
        const endIdx = Math.max(startIdx + 1, Math.floor((row + 1) * packetsPerRow));
        let r = 0, g = 0, b = 0, a = 0, count = 0;
        for (let i = startIdx; i < endIdx && i < total; i++) {
          const style = colorEngine.getPacketStyle(packets[i], packetTheme);
          const [pr, pg, pb, pa] = resolveColorBytes(style.background || fallback);
          r += pr; g += pg; b += pb; a += pa;
          count++;
        }
        if (count === 0) continue;
        ctx.fillStyle = `rgba(${Math.round(r / count)}, ${Math.round(g / count)}, ${Math.round(b / count)}, ${(a / count / 255).toFixed(3)})`;
        ctx.fillRect(0, row, size.width, 1);
      }
    }

    if (selectedPacket) {
      const idx = packets.findIndex(p => p.id === selectedPacket.id);
      if (idx !== -1) {
        const y = (idx / total) * size.height;
        // The selected-packet marker, in the theme's accent.
        ctx.fillStyle = accent;
        ctx.fillRect(0, Math.max(0, y - 1), size.width, 2);
      }
    }
  }, [packets, colorEngine, packetTheme, themeKey, size, selectedPacket, accent]);

  const scrollToClientY = useCallback((clientY: number) => {
    const wrapper = wrapperRef.current;
    const el = containerRef.current;
    if (!wrapper || !el) return;
    const rect = wrapper.getBoundingClientRect();
    const fraction = Math.min(1, Math.max(0, (clientY - rect.top) / rect.height));
    // Arm PacketList's user-scroll detection before moving scrollTop, the
    // same way a direct wheel/touch scroll on the table itself would - a
    // click/drag here is just as much a deliberate scroll as those, and
    // should be able to disable (or re-enable) stick-to-bottom auto-scroll.
    onUserScrollIntent?.();
    el.scrollTop = fraction * (el.scrollHeight - el.clientHeight);
  }, [containerRef, onUserScrollIntent]);

  /**
   * Wheeling over the strip scrolls the list, the same as wheeling over the
   * table itself.
   *
   * This has to be explicit because the browser genuinely cannot do it. The
   * strip is a SIBLING of the table's scroller rather than a descendant, and
   * every one of its ancestors up to the app root is `overflow: hidden`, so a
   * wheel here has no scrollable chain to act on and does nothing whatsoever.
   *
   * It is the wrong element to have that problem, too: `.minimap-scroll` sets
   * the table's vertical scrollbar to zero width precisely because this strip
   * replaces it, so as far as the user is concerned they are wheeling over the
   * scrollbar.
   *
   * deltaY is forwarded 1:1 rather than scaled to the buffer, so the strip
   * scrolls at exactly the rate the table one pixel to its left would. Scaling
   * by the whole buffer would make this the only surface in the app where a
   * wheel click means something different.
   *
   * No preventDefault: React registers `wheel` passively at the root, so the
   * call would be ignored with a console warning - and there is nothing to
   * prevent, since no ancestor scrolls.
   */
  const handleWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    const el = containerRef.current;
    if (!el) return;
    // deltaY is only in pixels when deltaMode is 0. Firefox and some mice
    // report lines or pages instead, where a raw delta of 3 would otherwise
    // scroll the list by three pixels.
    const step = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? el.clientHeight : 1;
    // Same reasoning as scrollToClientY: a wheel here is as deliberate a
    // scroll as a wheel on the table, and must be allowed to disable (or
    // re-enable) stick-to-bottom auto-scroll rather than be ignored.
    onUserScrollIntent?.();
    el.scrollTop += e.deltaY * step;
  };

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    draggingRef.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    scrollToClientY(e.clientY);
  };
  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!draggingRef.current) return;
    scrollToClientY(e.clientY);
  };
  const handlePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    draggingRef.current = false;
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  // Dragging the handle on the left edge grows/shrinks the strip itself,
  // independent of the click/drag-to-scroll handlers above (which live on
  // the wrapper and would otherwise also fire on the same pointer events).
  const handleResizePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    resizingRef.current = { startX: e.clientX, startWidth: mapWidth };
    e.currentTarget.setPointerCapture(e.pointerId);
  };
  const handleResizePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    if (!resizingRef.current) return;
    const delta = resizingRef.current.startX - e.clientX;
    setMapWidth(Math.min(MAX_MINIMAP_WIDTH, Math.max(MIN_MINIMAP_WIDTH, resizingRef.current.startWidth + delta)));
  };
  const handleResizePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation();
    resizingRef.current = null;
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  return (
    <div
      ref={wrapperRef}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onWheel={handleWheel}
      className="relative shrink-0 border-l border-border bg-secondary/40 cursor-pointer select-none"
      // Margin rather than padding: the canvas is absolutely positioned to
      // `inset-0`, which padding does not move, and the element measures its
      // own box - so shrinking the box is what keeps the viewport indicator
      // mapped to the right place.
      style={{ width: mapWidth, marginTop: topOffset }}
      title="Packet map - click or drag to scroll, or scroll the wheel"
    >
      {/* Positioned into the margin above rather than rendered before the map,
          so it cannot take part in the map's own layout or its measurement.
          The map is 16px wide by default and the button is a little wider, so
          it is allowed to overhang - clipping it would be the only alternative
          and the strip has no room to give. */}
      {headerSlot && topOffset > 0 && (
        <div
          // Positioning only. The strip's SURFACE comes from the packet list,
          // which owns the header row this has to line up with - see
          // HEADER_CHROME there.
          className="absolute left-0 right-0 z-10"
          style={{ top: -topOffset, height: topOffset }}
          // The map's own pointer handlers scroll the table; a click on the
          // button must not also jump the list to that position.
          onPointerDown={(e) => e.stopPropagation()}
          onWheel={(e) => e.stopPropagation()}
        >
          {headerSlot}
        </div>
      )}
      <canvas ref={canvasRef} className="absolute inset-0 block" style={{ width: size.width, height: size.height }} />
      <div
        className="absolute left-0 w-full rounded-sm bg-foreground/15 border border-foreground/40 pointer-events-none"
        style={{ top: viewport.top, height: viewport.height }}
      />
      <div
        onPointerDown={handleResizePointerDown}
        onPointerMove={handleResizePointerMove}
        onPointerUp={handleResizePointerUp}
        onContextMenu={(e) => {
          e.preventDefault();
          // Without this the packet list's row menu opens: this handle sits on
          // top of the table, and a right-click here is aimed at the handle.
          e.stopPropagation();
          setMapWidth(DEFAULT_MINIMAP_WIDTH);
        }}
        className="absolute left-0 top-0 h-full w-1.5 -translate-x-1/2 cursor-col-resize hover:bg-primary/50 z-10"
        title="Drag to resize packet map - right-click to reset"
      />
    </div>
  );
};
