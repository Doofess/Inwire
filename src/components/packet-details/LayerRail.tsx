import React from 'react';
import { ProtocolLayer } from '../../types/packet';

/**
 * The frame's protocol stack as a navigable rail.
 *
 * This is the packet detail window's own idea, not something lifted from the
 * workspace pane: the pane presents layers as an accordion of boxes you scroll
 * through, which is the only thing that fits a 280px-tall strip. Here the stack
 * is a *map* - each layer a segment sized and placed by the bytes it actually
 * occupies - so the shape of the frame is visible before reading a single
 * field, and any layer is one click away instead of a scroll away.
 *
 * Laid out horizontally, as a single band across the top spanning both body
 * columns. A vertical rail would add a THIRD column beside the fields and the
 * dump, and would have to scroll independently of both.
 */

interface LayerRailProps {
  layers: ProtocolLayer[];
  frameLength: number;
  /** Index of the isolated layer, or null when the whole frame is shown. */
  selectedIndex: number | null;
  onSelect: (index: number | null) => void;
  onHoverRange: (range: [number, number] | null) => void;
  activeByteRange: [number, number] | null;
}

/**
 * Dissectors name layers the way the reference analyzer's detail pane does - "Internet
 * Protocol Version 4", "Transmission Control Protocol" - which is right in a
 * full-width heading and far too long for a rail. These are the same protocols
 * under the names the packet list already uses.
 */
const RAIL_NAMES: Record<string, string> = {
  'Internet Protocol Version 4': 'IPv4',
  'Internet Protocol Version 6': 'IPv6',
  'Transmission Control Protocol': 'TCP',
  'User Datagram Protocol': 'UDP',
  'Internet Control Message Protocol': 'ICMP',
  'Internet Control Message Protocol v6': 'ICMPv6',
  'Address Resolution Protocol': 'ARP',
  'Domain Name System': 'DNS',
  'Hypertext Transfer Protocol': 'HTTP',
  'Transport Layer Security': 'TLS',
  'Ethernet II': 'Ethernet',
};

/** The short name for a layer, so the rail stays narrow. */
function shortName(layer: ProtocolLayer): string {
  const name = layer.name || layer.summary.split(',')[0];
  return RAIL_NAMES[name] ?? name;
}

export const LayerRail: React.FC<LayerRailProps> = ({
  layers,
  frameLength,
  selectedIndex,
  onSelect,
  onHoverRange,
  activeByteRange,
}) => {
  const total = Math.max(1, frameLength);

  return (
    // Scrolls rather than overflowing. Segments have a 7rem floor so they stay
    // readable, which means enough layers - a tunnelled or heavily-encapsulated
    // frame - will always outrun the band eventually. Without this they simply
    // ran off the right edge with no way to reach them.
    <div className="flex items-stretch gap-1 px-5 py-2 overflow-x-auto custom-scrollbar">
      <button
        onClick={() => onSelect(null)}
        onMouseEnter={() => onHoverRange(null)}
        className={`shrink-0 px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-widest transition-colors cursor-pointer self-center ${
          selectedIndex === null
            ? 'bg-primary/15 text-primary font-bold'
            : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground'
        }`}
        title="Show every layer"
      >
        All {frameLength} B
      </button>

      <div className="w-px bg-border mx-1.5 self-stretch" />

      {/* Segments share the width evenly and the BAR inside each one carries
          the true proportion. Sizing the segments themselves by byte count was
          tried and does not survive real traffic: the Frame layer spans the
          whole frame by definition, so on a 63,942-byte segmentation-offload
          packet it took 99.9% of the band and squeezed Ethernet, IPv4 and TCP
          off the edge. Equal segments keep every layer readable and clickable
          at any frame size; the bar still says how much of the frame each
          one is. */}
      {layers.map((layer, idx) => {
        const range = layer.rawBytesRange;
        const span = range ? range[1] - range[0] + 1 : 0;
        const isSelected = selectedIndex === idx;
        const isHovered =
          !!activeByteRange && !!range &&
          activeByteRange[0] === range[0] && activeByteRange[1] === range[1];

        return (
          <button
            key={idx}
            onClick={() => onSelect(isSelected ? null : idx)}
            onMouseEnter={() => onHoverRange(range ?? null)}
            onMouseLeave={() => onHoverRange(null)}
            // Capped as well as floored. Stretching to fill left four layers
            // ~380px each in a 1600px window, which put "Frame" and its "86 B"
            // 200px apart and read as two unrelated items rather than one
            // segment. The cap keeps a segment the width of its own label.
            className={`flex-1 min-w-[7rem] max-w-[13rem] px-2 py-1 rounded text-left transition-colors cursor-pointer group border ${
              isSelected
                ? 'bg-primary/15 border-primary/60'
                : isHovered
                  ? 'bg-accent/70 border-border'
                  : 'border-transparent hover:bg-accent/60'
            }`}
            title={`${layer.summary}${range ? ` — bytes ${range[0]}-${range[1]}` : ''}`}
          >
            <div className="flex items-baseline justify-between gap-2 min-w-0">
              <span
                className={`text-[11px] font-mono truncate ${
                  isSelected ? 'text-primary font-bold' : 'text-foreground'
                }`}
              >
                {shortName(layer)}
              </span>
              {range && (
                <span className="text-[9px] font-mono text-muted-foreground shrink-0 tabular-nums">{span} B</span>
              )}
            </div>
            <div
              className={`mt-1 h-1 rounded-full transition-colors ${
                isSelected || isHovered ? 'bg-primary' : 'bg-muted-foreground/40 group-hover:bg-primary/70'
              }`}
              style={{ width: `${Math.max(6, (span / total) * 100)}%` }}
            />
          </button>
        );
      })}
    </div>
  );
};
