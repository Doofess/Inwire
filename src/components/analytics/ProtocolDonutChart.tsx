import React from 'react';
import { Packet } from '../../types/packet';
import { PieChart } from 'lucide-react';

interface ProtocolDonutProps {
  packets: Packet[];
  onSelectProtocol: (protocol: string) => void;
  selectedProtocolFilter?: string;
  isDark: boolean;
}

interface ProtocolDatum {
  protocol: string;
  count: number;
  percentage: number;
  color: string;
  textColor: string;
}

const PROTOCOL_CONFIG: Record<string, { bar: string; text: string }> = {
  TLS: { bar: 'bg-cyan-500', text: 'text-cyan-400' },
  HTTP: { bar: 'bg-purple-500', text: 'text-purple-400' },
  DNS: { bar: 'bg-amber-500', text: 'text-amber-400' },
  TCP: { bar: 'bg-sky-500', text: 'text-sky-400' },
  UDP: { bar: 'bg-rose-500', text: 'text-rose-400' },
  MQTT: { bar: 'bg-emerald-500', text: 'text-emerald-400' },
  CUSTOM: { bar: 'bg-teal-400', text: 'text-teal-300' },
  ICMP: { bar: 'bg-yellow-500', text: 'text-yellow-400' },
  ARP: { bar: 'bg-slate-500', text: 'text-slate-400' },
};

export const ProtocolDonutChart: React.FC<ProtocolDonutProps> = ({
  packets,
  onSelectProtocol,
  selectedProtocolFilter,
  isDark,
}) => {
  const data: ProtocolDatum[] = React.useMemo(() => {
    if (packets.length === 0) return [];

    const counts: Record<string, number> = {};
    for (const p of packets) {
      counts[p.protocol] = (counts[p.protocol] || 0) + 1;
    }

    const total = packets.length;
    return Object.entries(counts)
      .map(([proto, count]) => ({
        protocol: proto,
        count,
        percentage: (count / total) * 100,
        color: PROTOCOL_CONFIG[proto]?.bar || 'bg-slate-500',
        textColor: PROTOCOL_CONFIG[proto]?.text || 'text-slate-400',
      }))
      .sort((a, b) => b.count - a.count);
  }, [packets]);

  return (
    <div
      className={`rounded-lg border p-3.5 flex flex-col transition-colors select-none ${
        isDark ? 'bg-slate-900/90 border-slate-800 text-slate-200' : 'bg-white border-slate-200 text-slate-800'
      } shadow-sm`}
    >
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
          <PieChart className="w-3.5 h-3.5 text-purple-400" />
          <span>Protocol Breakdown</span>
        </h3>
        <span className="text-[10px] text-slate-500 font-mono">CLICK TO FILTER</span>
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
                isSelected ? 'bg-slate-800/80' : 'hover:bg-slate-800/40'
              }`}
            >
              <div className="flex justify-between text-[11px] font-mono">
                <span className="font-semibold text-slate-300">{item.protocol}</span>
                <span className={`font-bold ${item.textColor}`}>{item.percentage.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
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
