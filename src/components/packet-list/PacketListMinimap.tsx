import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Packet } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import { themeColor } from '../../lib/themeColor';

interface PacketListMinimapProps {
  packets: Packet[];
  selectedPacket: Packet | null;
  colorEngine: ColorRulesEngine;
  isDark: boolean;
  /** Forces this canvas to repaint when the theme changes. isDark cannot
   *  signal a switch between two dark themes - see themeColor. */
  themeKey?: string;
  containerRef: React.RefObject<HTMLDivElement | null>;
  /**
   * Called whenever a click/drag here is about to move the table's scroll
   * position, so PacketList can treat it the same as a direct wheel/touch
   * scroll on the table itself (i.e. it's allowed to disable, or re-enable,
   * stick-to-bottom auto-scroll) rather than being silently ignored as an
   * untrusted scroll event.
   */
  onUserScrollIntent?: () => void;
}

const FALLBACK_BAND_COLOR_DARK = 'rgba(148, 163, 184, 0.35)';
const FALLBACK_BAND_COLOR_LIGHT = 'rgba(100, 116, 139, 0.3)';

const MINIMAP_WIDTH_STORAGE_KEY = 'netview.packetListMinimapWidth';
const DEFAULT_MINIMAP_WIDTH = 16;
const MIN_MINIMAP_WIDTH = 8;
const MAX_MINIMAP_WIDTH = 120;

function loadStoredMinimapWidth(): number {
  try {
    const raw = localStorage.getItem(MINIMAP_WIDTH_STORAGE_KEY);
    const parsed = raw ? Number(raw) : NaN;
    if (Number.isFinite(parsed)) {
      return Math.min(MAX_MINIMAP_WIDTH, Math.max(MIN_MINIMAP_WIDTH, parsed));
    }
  } catch {
    // localStorage unavailable (private browsing, etc.) - fall back to the default
  }
  return DEFAULT_MINIMAP_WIDTH;
}

// A throwaway 1x1 canvas used purely to resolve any valid CSS color string
// (hex from custom color rules, rgba() from the built-in ones, named colors)
// into concrete RGBA bytes, so the downsampled minimap rows can be averaged
// regardless of which format a given color rule happens to use.
let colorProbeCtx: CanvasRenderingContext2D | null | undefined;
function resolveColorBytes(color: string): [number, number, number, number] {
  if (colorProbeCtx === undefined) {
    const probe = document.createElement('canvas');
    probe.width = 1;
    probe.height = 1;
    colorProbeCtx = probe.getContext('2d', { willReadFrequently: true });
  }
  if (!colorProbeCtx) return [148, 163, 184, 90];
  colorProbeCtx.clearRect(0, 0, 1, 1);
  colorProbeCtx.fillStyle = color;
  colorProbeCtx.fillRect(0, 0, 1, 1);
  const data = colorProbeCtx.getImageData(0, 0, 1, 1).data;
  return [data[0], data[1], data[2], data[3]];
}

/**
 * A VS Code-style minimap for the packet list: a thin full-height strip
 * showing one colored band per packet (matching the table's own color-rule
 * colors), a viewport indicator synced to the table's scroll position, and
 * click/drag-to-scroll. Downsamples by averaging bands per pixel row when
 * there are more packets than vertical pixels, the same way a real minimap
 * degrades for files much longer than the viewport.
 */
export const PacketListMinimap: React.FC<PacketListMinimapProps> = ({
  packets,
  selectedPacket,
  colorEngine,
  isDark,
  themeKey,
  containerRef,
  onUserScrollIntent,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const draggingRef = useRef(false);
  const resizingRef = useRef<{ startX: number; startWidth: number } | null>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [viewport, setViewport] = useState({ top: 0, height: 0 });
  const [mapWidth, setMapWidth] = useState(loadStoredMinimapWidth);

  useEffect(() => {
    try {
      localStorage.setItem(MINIMAP_WIDTH_STORAGE_KEY, String(mapWidth));
    } catch {
      // ignore write failures (private browsing, storage disabled, etc.)
    }
  }, [mapWidth]);

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

    const fallback = isDark ? FALLBACK_BAND_COLOR_DARK : FALLBACK_BAND_COLOR_LIGHT;

    if (total <= size.height) {
      const bandHeight = size.height / total;
      packets.forEach((packet, i) => {
        const style = colorEngine.getPacketStyle(packet, isDark);
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
          const style = colorEngine.getPacketStyle(packets[i], isDark);
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
        ctx.fillStyle = themeColor('--primary', isDark ? '#22d3ee' : '#0891b2');
        ctx.fillRect(0, Math.max(0, y - 1), size.width, 2);
      }
    }
  }, [packets, colorEngine, isDark, themeKey, size, selectedPacket]);

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
      className="relative shrink-0 border-l border-border bg-secondary/40 cursor-pointer select-none"
      style={{ width: mapWidth }}
      title="Packet map - click or drag to scroll"
    >
      <canvas ref={canvasRef} className="absolute inset-0 block" style={{ width: size.width, height: size.height }} />
      <div
        className="absolute left-0 w-full rounded-sm bg-foreground/15 border border-foreground/40 pointer-events-none"
        style={{ top: viewport.top, height: viewport.height }}
      />
      <div
        onPointerDown={handleResizePointerDown}
        onPointerMove={handleResizePointerMove}
        onPointerUp={handleResizePointerUp}
        className="absolute left-0 top-0 h-full w-1.5 -translate-x-1/2 cursor-col-resize hover:bg-primary/50 z-10"
        title="Drag to resize packet map"
      />
    </div>
  );
};
