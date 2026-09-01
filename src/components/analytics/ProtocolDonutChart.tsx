import React from 'react';
import { Packet } from '../../types/packet';
import { TbChartPie, TbMaximize } from 'react-icons/tb';

interface ProtocolDonutProps {
  packets: Packet[];
  onSelectProtocol: (protocol: string) => void;
  selectedProtocolFilter?: string;
  /** Opens the Statistics modal - the full version of this panel's summary. */
  onOpenStatistics: () => void;
}

interface ProtocolDatum {
  protocol: string;
  count: number;
  percentage: number;
}

/*
 * Every bar is the theme's accent, not a hue per protocol.
 *
 * A per-protocol palette was tried here and removed. This panel is a ranked
 * list - the bar lengths and the ordering carry the comparison - so a hue per
 * row adds a second encoding of something the layout already says, and eight
 * saturated bars stacked in a small card read as decoration rather than data.
 *
 * The geo map is the opposite case and keeps its per-protocol colours: there
 * the routes are scattered across a map with no ordering and no shared
 * baseline, so colour is the only thing that can distinguish them.
 */
const PROTOCOL_BAR_COLOR = 'bg-primary';
const PROTOCOL_TEXT_COLOR = 'text-primary';

export const ProtocolDonutChart: React.FC<ProtocolDonutProps> = ({
  packets,
  onSelectProtocol,
  selectedProtocolFilter,
  onOpenStatistics,
}) => {
  const data: ProtocolDatum[] = React.useMemo(() => {
    if (packets.length === 0) return [];

    // Grouped by the displayed protocol name, so the breakdown reads the way
    // the packet list does - "TLSv1.2", "QUIC", "ICMPv6" - rather than
    // collapsing everything onto the handful of coarse ProtocolType values.
    const counts: Record<string, { count: number }> = {};
    for (const p of packets) {
      const label = p.protocolLabel ?? p.protocol;
      const entry = counts[label] ?? { count: 0 };
      entry.count += 1;
      counts[label] = entry;
    }

    const total = packets.length;
    return Object.entries(counts)
      .map(([proto, { count }]) => ({
        protocol: proto,
        count,
        percentage: (count / total) * 100,
      }))
      .sort((a, b) => b.count - a.count);
  }, [packets]);

  return (
    <div className="rounded-lg border p-3.5 flex flex-col transition-colors select-none bg-card border-border text-card-foreground shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5">
          <TbChartPie className="w-3.5 h-3.5 text-foreground" />
          <span>Protocol Breakdown</span>
        </h3>
        {/* A "CLICK TO FILTER" caption used to sit here, describing what the
            rows below already do - they keep a pointer cursor and a hover
            state, so the affordance survives its removal. The expand control
            that replaced it matches the Live Geo-IP Map's exactly: this panel
            shows the top five protocols, and Statistics is the whole table. */}
        <button
          onClick={onOpenStatistics}
          className="p-1 -m-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          title="Open full protocol statistics"
        >
          <TbMaximize className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Geometric Progress Bars */}
      <div className="space-y-3">
        {data.slice(0, 5).map(item => {
          const isSelected = selectedProtocolFilter?.toLowerCase().includes(item.protocol.toLowerCase());
          return (
            <div
              key={item.protocol}
              onClick={() => onSelectProtocol(item.protocol.toLowerCase())}
              className={`space-y-1.5 p-1 rounded transition-colors cursor-pointer ${
                isSelected ? 'bg-accent' : 'hover:bg-accent/50'
              }`}
            >
              <div className="flex justify-between text-[11px] font-mono">
                <span className="font-semibold text-foreground/90">{item.protocol}</span>
                <span className={`font-bold ${PROTOCOL_TEXT_COLOR}`}>{item.percentage.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full ${PROTOCOL_BAR_COLOR} transition-all duration-300`}
                  style={{ width: `${Math.max(4, item.percentage)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
