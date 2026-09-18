import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import { Layers } from 'lucide-react';
import { ProtocolTreeView } from './ProtocolTreeView';
import { ExpertFindings } from './ExpertFindings';
import { PaneHeader } from '../common/PaneHeader';

export interface PacketDetailsTreeProps {
  packet: Packet | null;
  onHoverByteRange: (range: [number, number] | null) => void;
  activeByteRange: [number, number] | null;
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
  onHoverByteRange,
  activeByteRange,
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
          <Layers className="w-6 h-6 text-muted-foreground/70 mb-1" />
          <span className="uppercase tracking-wider">No packet selected</span>
          <span className="text-[10px] text-muted-foreground/70">
            Select any packet from the list above for deep protocol dissection
          </span>
        </div>
      </div>
    );
  }

  return (
    // Every accent in here is the APP's `--primary`, the same on every frame.
    //
    // It was the matched colour rule's hue for a while, pushed down as a
    // `--primary` override on this element so the tree's layer headings, the
    // cross-reference links, the protocol chip, the layer rail's bars and the
    // hex dump's selected byte all took the colour of the row the frame was
    // selected from. That is reverted: the pane is one surface and the app has
    // one accent, and a heading that changes hue with the frame under the
    // cursor makes the accent mean "this frame" in a pane that is only ever
    // showing one frame.
    //
    // The row colouring itself is untouched - the packet list still paints by
    // rule, which is where that information belongs.
    <div className="h-full flex flex-col overflow-hidden select-none">
      {/* **The frame number, and not its length.** The length was here as
          `(N bytes)` and it is in Hex View's own header a pane away, on the
          surface whose whole subject is those bytes. Two copies of one figure
          in one row is a row that has to be checked for agreement; this pane's
          subject is the frame's STRUCTURE, so its header names which frame and
          stops. */}
      <PaneHeader
        title="Packet Inspection"
        detail={`#Frame ${packet.id}`}
      >
        {hoveredField && (
          <span className="text-[11px] font-mono text-muted-foreground truncate" title={hoveredField}>
            {hoveredField}
          </span>
        )}
      </PaneHeader>

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
