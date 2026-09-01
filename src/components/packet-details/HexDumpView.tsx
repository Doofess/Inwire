import React, { useEffect, useRef, useState } from 'react';
import { Packet } from '../../types/packet';

/**
 * The hex/ASCII dump itself, with no surrounding chrome.
 *
 * Split out of HexViewer for the same reason as ProtocolTreeView: the
 * workspace's bottom pane wraps it in a header and a byte-inspector footer,
 * while the packet detail window arranges those parts differently. The dump
 * rows themselves are defined once.
 *
 * `hoveredByteIndex` is owned by the caller rather than held here, because
 * both presentations show the hovered byte's breakdown somewhere outside this
 * component - the pane in its own footer, the detail window in a bar spanning
 * the full width beneath both columns.
 */

/**
 * Rendered row height, in px, before the first real measurement.
 *
 * Every row is one line of fixed-width text with the same padding, so a single
 * measurement is valid for all of them.
 */
const ROW_HEIGHT_FALLBACK = 18;
const OVERSCAN_ROWS = 12;

interface HexDumpViewProps {
  packet: Packet;
  /** Bytes belonging to the field or layer currently hovered in the tree. */
  activeByteRange: [number, number] | null;
  hoveredByteIndex: number | null;
  onHoverByte: (byteIndex: number | null) => void;
  /** 16 is the conventional width; a wider window can afford more per row. */
  bytesPerRow?: number;
  /**
   * The element that actually scrolls, when the dump is part of a larger
   * scrolling document rather than a column of its own.
   *
   * Passed when the dump is stacked under the fields in one document - the
   * packet detail window below its two-column breakpoint - because there it
   * cannot own a scrollbar. It still has to virtualize, because a single
   * segmentation-offload frame is ~4,000 rows, so it works out which rows are
   * on screen from this element instead of from its own scrollTop.
   *
   * Omitted, it owns its scrolling and adds its own overflow-y-auto: what the
   * workspace pane needs, and what the detail window's dump column needs.
   *
   * The two are not interchangeable. Passing a scroller the dump is NOT inside
   * renders no rows at all rather than failing loudly.
   */
  scrollRef?: React.RefObject<HTMLElement | null>;
  className?: string;
}

export const HexDumpView: React.FC<HexDumpViewProps> = ({
  packet,
  activeByteRange,
  hoveredByteIndex,
  onHoverByte,
  bytesPerRow = 16,
  scrollRef,
  className,
}) => {
  const rawBytes = packet.rawBytes;
  const numRows = Math.ceil(rawBytes.length / bytesPerRow);
  // Split into two halves the way every hex dump does, so the eye can count
  // to eight rather than to sixteen.
  const half = Math.ceil(bytesPerRow / 2);

  /**
   * Only the rows actually scrolled into view are rendered, with spacers above
   * and below preserving the true scroll height.
   *
   * This is not premature: a single TCP segmentation-offload frame off a real
   * link is ~64KB, which is 3,997 rows at 16 bytes each. Rendering them all
   * built about 155,000 DOM nodes and made stepping to the next frame take
   * 1.4 seconds. Fixed row height is a safe assumption - every row is one line
   * of fixed-width text with identical padding.
   */
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);
  const [rowHeight, setRowHeight] = useState(ROW_HEIGHT_FALLBACK);
  const measuredRef = useRef(false);
  const external = scrollRef !== undefined;

  /**
   * Where the visible window sits within this dump.
   *
   * When the dump owns its scrolling that is simply its own scrollTop. When it
   * is embedded in a larger document it is how far the document has scrolled
   * past the top of the dump, which can be negative while the dump is still
   * below the fold - hence the clamp at zero.
   *
   * Measured against the scroller rather than tracked incrementally, and read
   * inside a rAF, so the layout it forces happens once per frame at most.
   */
  useEffect(() => {
    const scroller = external ? scrollRef?.current : containerRef.current;
    if (!scroller) return;

    let queued = false;
    const measure = () => {
      queued = false;
      const wrapper = containerRef.current;
      if (!wrapper) return;
      setViewportHeight(scroller.clientHeight);
      if (!external) {
        setScrollTop(scroller.scrollTop);
        return;
      }
      const offsetIntoDump = scroller.getBoundingClientRect().top - wrapper.getBoundingClientRect().top;
      setScrollTop(Math.max(0, offsetIntoDump));
    };

    const onScroll = () => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(measure);
    };

    measure();
    scroller.addEventListener('scroll', onScroll, { passive: true });
    const observer = new ResizeObserver(onScroll);
    observer.observe(scroller);
    return () => {
      scroller.removeEventListener('scroll', onScroll);
      observer.disconnect();
    };
  }, [external, scrollRef, packet.id]);

  // A different frame means a different dump; start back at the top rather
  // than holding a scroll position that may not exist any more.
  useEffect(() => {
    setScrollTop(0);
    const scroller = external ? scrollRef?.current : containerRef.current;
    if (scroller) scroller.scrollTop = 0;
  }, [packet.id, external, scrollRef]);

  // getBoundingClientRect forces a synchronous layout, so this runs once.
  const measureRow = (node: HTMLDivElement | null) => {
    if (!node || measuredRef.current) return;
    const h = node.getBoundingClientRect().height;
    if (h > 0) {
      measuredRef.current = true;
      if (Math.abs(h - rowHeight) > 0.5) setRowHeight(h);
    }
  };

  const startRow = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN_ROWS);
  const endRow = Math.min(numRows, Math.ceil((scrollTop + viewportHeight) / rowHeight) + OVERSCAN_ROWS);
  const topSpacer = startRow * rowHeight;
  const bottomSpacer = Math.max(0, (numRows - endRow) * rowHeight);

  const isByteInRange = (idx: number) =>
    !!activeByteRange && idx >= activeByteRange[0] && idx <= activeByteRange[1];

  const byteClass = (absIdx: number) =>
    hoveredByteIndex === absIdx
      ? 'bg-primary text-primary-foreground font-bold scale-110 shadow-sm'
      : isByteInRange(absIdx)
        ? 'bg-primary/15 dark:bg-primary/30 text-primary font-bold ring-1 ring-primary'
        : 'text-muted-foreground hover:text-primary hover:bg-accent';

  const hoverProps = (absIdx: number) => ({
    onMouseEnter: () => onHoverByte(absIdx),
    onMouseLeave: () => onHoverByte(null),
  });

  return (
    <div
      ref={containerRef}
      className={`font-mono text-[11px] ${external ? '' : 'overflow-y-auto custom-scrollbar'} ${className ?? ''}`}
    >
      {topSpacer > 0 && <div style={{ height: topSpacer }} aria-hidden="true" />}

      {Array.from({ length: Math.max(0, endRow - startRow) }).map((_, i) => {
        const rowIdx = startRow + i;
        const startOffset = rowIdx * bytesPerRow;
        const offsetHex = startOffset.toString(16).padStart(4, '0').toUpperCase();
        const rowBytes: number[] = Array.from(rawBytes.slice(startOffset, startOffset + bytesPerRow));

        return (
          <div
            key={rowIdx}
            ref={i === 0 ? measureRow : undefined}
            className="flex items-center gap-3 px-1 py-0.5 rounded transition-colors hover:bg-accent/50"
          >
            <span className="text-muted-foreground font-bold w-10 shrink-0 select-none">{offsetHex}</span>

            <div className="flex items-center gap-2 shrink-0">
              {[0, half].map(blockStart => (
                <div key={blockStart} className="flex items-center gap-1">
                  {rowBytes.slice(blockStart, blockStart + half).map((byte, bIdx) => {
                    const absIdx = startOffset + blockStart + bIdx;
                    return (
                      <span
                        key={bIdx}
                        {...hoverProps(absIdx)}
                        className={`w-4 text-center cursor-pointer transition-all rounded px-0.5 ${byteClass(absIdx)}`}
                      >
                        {byte.toString(16).padStart(2, '0').toUpperCase()}
                      </span>
                    );
                  })}
                  {/* Keeps the ASCII column aligned on a short final row. */}
                  {rowBytes.length < blockStart + half &&
                    Array.from({
                      length: Math.max(0, blockStart + half - Math.max(rowBytes.length, blockStart)),
                    }).map((_, padIdx) => <span key={`pad${padIdx}`} className="w-4" />)}
                </div>
              ))}
            </div>

            <div className="flex items-center pl-3 border-l border-border text-muted-foreground tracking-widest shrink-0">
              {rowBytes.map((byte, bIdx) => {
                const absIdx = startOffset + bIdx;
                const char = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
                return (
                  <span
                    key={bIdx}
                    {...hoverProps(absIdx)}
                    className={`cursor-pointer transition-colors ${
                      hoveredByteIndex === absIdx
                        ? 'bg-primary text-primary-foreground font-bold rounded'
                        : isByteInRange(absIdx)
                          ? 'text-primary font-bold bg-primary/15 rounded'
                          : ''
                    }`}
                  >
                    {char}
                  </span>
                );
              })}
            </div>
          </div>
        );
      })}

      {bottomSpacer > 0 && <div style={{ height: bottomSpacer }} aria-hidden="true" />}
    </div>
  );
};

/**
 * The numeric breakdown of one byte: offset, decimal, hex, bits, ASCII.
 *
 * Its own component because the two presentations put it in different places -
 * the pane's footer, the detail window's full-width status bar - but it must
 * read identically in both.
 */
export const ByteInspector: React.FC<{ packet: Packet; hoveredByteIndex: number | null }> = ({
  packet,
  hoveredByteIndex,
}) => {
  const value =
    hoveredByteIndex !== null && hoveredByteIndex < packet.rawBytes.length
      ? packet.rawBytes[hoveredByteIndex]
      : null;

  if (hoveredByteIndex === null || value === null) {
    return <span>Hover any byte to inspect raw bitwise &amp; numerical representation</span>;
  }

  return (
    <div className="flex items-center gap-3">
      <span>OFFSET: <b className="text-foreground">{hoveredByteIndex} (0x{hoveredByteIndex.toString(16).toUpperCase()})</b></span>
      <span>DEC: <b className="text-foreground">{value}</b></span>
      <span>HEX: <b className="text-primary">0x{value.toString(16).padStart(2, '0').toUpperCase()}</b></span>
      <span>BITS: <b className="text-emerald-400">0b{value.toString(2).padStart(8, '0')}</b></span>
      <span>
        ASCII: <b className="text-amber-400">{value >= 32 && value <= 126 ? `'${String.fromCharCode(value)}'` : 'N/A'}</b>
      </span>
    </div>
  );
};
