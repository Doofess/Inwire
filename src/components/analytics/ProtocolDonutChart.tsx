import React from 'react';
import { Packet } from '../../types/packet';
import { TbChartPie } from 'react-icons/tb';

interface ProtocolDonutProps {
  packets: Packet[];
  onSelectProtocol: (protocol: string) => void;
  selectedProtocolFilter?: string;
}

interface ProtocolDatum {
  protocol: string;
  count: number;
  percentage: number;
  color: string;
  textColor: string;
}

// All protocols share the same cyan accent used broadly across the app
// (Start Capture button, active-filter states, etc.) rather than each
// getting its own hue.
const PROTOCOL_BAR_COLOR = 'bg-cyan-500';
const PROTOCOL_TEXT_COLOR = 'text-cyan-400';

export const ProtocolDonutChart: React.FC<ProtocolDonutProps> = ({
  packets,
  onSelectProtocol,
  selectedProtocolFilter,
}) => {
  const data: ProtocolDatum[] = React.useMemo(() => {
    if (packets.length === 0) return [];

    // Grouped by the displayed protocol name, so the breakdown reads the way
    // the packet list does - "TLSv1.2", "QUIC", "ICMPv6" - rather than
    // collapsing everything onto the handful of coarse ProtocolType values.
    const counts: Record<string, number> = {};
    for (const p of packets) {
      const label = p.protocolLabel ?? p.protocol;
      counts[label] = (counts[label] || 0) + 1;
    }

    const total = packets.length;
    return Object.entries(counts)
      .map(([proto, count]) => ({
        protocol: proto,
        count,
        percentage: (count / total) * 100,
        color: PROTOCOL_BAR_COLOR,
        textColor: PROTOCOL_TEXT_COLOR,
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
        <span className="text-[10px] text-muted-foreground font-mono">CLICK TO FILTER</span>
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
                <span className={`font-bold ${item.textColor}`}>{item.percentage.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full ${item.color} transition-all duration-300`}
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
