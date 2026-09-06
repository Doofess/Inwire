import React, { useState } from 'react';
import { Packet, Capabilities } from '../../types/packet';
import { TbStack2 } from 'react-icons/tb';
import { ProtocolTreeView } from './ProtocolTreeView';
import { ExpertFindings } from './ExpertFindings';
import { packetAccentStyle } from '../../lib/packetAccent';

interface PacketDetailsTreeProps {
  packet: Packet | null;
  /**
   * The colour the packet list painted this frame's row, at text strength.
   *
   * Retints this whole pane rather than any one element - see packetAccent.ts.
   * Optional, so a caller with no packet theme to hand gets the app's own
   * accent rather than an uncoloured pane.
   */
  accentColor?: string | null;
  onHoverByteRange: (range: [number, number] | null) => void;
  activeByteRange: [number, number] | null;
  permissions: Capabilities;
  /** Follows a cross-packet reference such as `[Response In: 11]`. */
  onSelectFrame?: (frameNumber: number) => void;
  /** Puts an expression in the filter bar; `apply` also runs it. */
  onFieldFilter?: (expression: string, apply: boolean) => void;
  /** What is in the filter bar now, so "…and Selected" can build on it. */
  currentFilter?: string;
  /** Adds a registry field as a column in the packet list. */
  onAddColumn?: (abbrev: string) => void;
}

/**
 * The workspace's bottom-left pane: a header, any anomaly banners, and the
 * dissected protocol tree.
 *
 * The tree itself lives in ProtocolTreeView and the banners in AnomalyBanners,
 * so the packet detail window can present the same content in a layout suited
 * to a full-size window without either copy drifting from the other.
 */
export const PacketDetailsTree: React.FC<PacketDetailsTreeProps> = ({
  packet,
  accentColor,
  onHoverByteRange,
  activeByteRange,
  permissions,
  onSelectFrame,
  onFieldFilter,
  currentFilter,
  onAddColumn,
}) => {
  /**
   * The filter name of the row under the pointer.
   *
   * Wireshark puts this in its status bar; this pane's header is where it
   * belongs here, because the pane is what the pointer is inside. It is the
   * only way to learn what a row is called without right-clicking it, and
   * knowing that is the difference between reading the tree and being able to
   * write a filter from it.
   */
  const [hoveredField, setHoveredField] = useState<string | null>(null);

  if (!packet) {
    return (
      <div className="h-full flex items-center justify-center p-6 text-center text-muted-foreground font-mono text-xs">
        <div className="flex flex-col items-center gap-1.5">
          <TbStack2 className="w-6 h-6 text-muted-foreground/70 mb-1" />
          <span className="uppercase tracking-wider">No packet selected</span>
          <span className="text-[10px] text-muted-foreground/70">
            Select any packet from the list above for deep protocol dissection
          </span>
        </div>
      </div>
    );
  }

  return (
    // Everything below that was drawn in the app accent is now drawn in this
    // frame's colour, down to the tree's layer headings and its
    // cross-reference links.
    <div className="h-full flex flex-col overflow-hidden select-none" style={packetAccentStyle(accentColor)}>
      <div className="px-4 py-2 border-b flex items-center justify-between transition-colors bg-card border-border text-card-foreground shadow-sm">
        <div className="flex items-center gap-2 text-xs font-mono font-bold min-w-0">
          <span className="text-muted-foreground uppercase tracking-tighter shrink-0">Packet Inspection</span>
          <span className="text-primary shrink-0">#Frame {packet.id} ({packet.length} bytes)</span>
        </div>
        {hoveredField && (
          <span className="text-[11px] font-mono text-muted-foreground truncate pl-3" title={hoveredField}>
            {hoveredField}
          </span>
        )}
      </div>

      <ExpertFindings packet={packet} className="p-3 pb-0" />

      <div className="flex-1 overflow-y-auto p-3 custom-scrollbar">
        <ProtocolTreeView
          packet={packet}
          onHoverByteRange={onHoverByteRange}
          activeByteRange={activeByteRange}
          onSelectFrame={onSelectFrame}
          onFieldFilter={onFieldFilter}
          currentFilter={currentFilter}
          onAddColumn={onAddColumn}
          onHoverField={setHoveredField}
        />
      </div>
    </div>
  );
};
