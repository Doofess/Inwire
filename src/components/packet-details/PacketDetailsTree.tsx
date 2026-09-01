import React from 'react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { TbStack2 } from 'react-icons/tb';
import { ProtocolTreeView } from './ProtocolTreeView';
import { AnomalyBanners } from './AnomalyBanners';
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
  permissions: UserRolePermissions;
  /** Follows a cross-packet reference such as `[Response In: 11]`. */
  onSelectFrame?: (frameNumber: number) => void;
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
}) => {
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
        <div className="flex items-center gap-2 text-xs font-mono font-bold">
          <span className="text-muted-foreground uppercase tracking-tighter">Packet Inspection</span>
          <span className="text-primary">#Frame {packet.id} ({packet.length} bytes)</span>
        </div>
      </div>

      <AnomalyBanners anomalies={packet.anomalies} className="p-3 pb-0" />

      <div className="flex-1 overflow-y-auto p-3 custom-scrollbar">
        <ProtocolTreeView
          packet={packet}
          onHoverByteRange={onHoverByteRange}
          activeByteRange={activeByteRange}
          onSelectFrame={onSelectFrame}
        />
      </div>
    </div>
  );
};
