import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import { BarChart2, X, PieChart, Network, Layers, Activity, ShieldAlert } from 'lucide-react';

interface StatisticsModalProps {
  packets: Packet[];
  onClose: () => void;
  isDark: boolean;
}

export const StatisticsModal: React.FC<StatisticsModalProps> = ({ packets, onClose, isDark }) => {
  const [activeTab, setActiveTab] = useState<'hierarchy' | 'endpoints' | 'conversations' | 'sizes'>('hierarchy');

  // Compute total statistics
  const totalPackets = packets.length;
  const totalBytes = packets.reduce((acc, p) => acc + p.length, 0);

  // Protocol Hierarchy
  const protocolHierarchy = React.useMemo(() => {
    const counts: Record<string, { count: number; bytes: number }> = {};
    for (const p of packets) {
      const existing = counts[p.protocol] || { count: 0, bytes: 0 };
      existing.count += 1;
      existing.bytes += p.length;
      counts[p.protocol] = existing;
    }

    return Object.entries(counts)
      .map(([proto, val]) => ({
        protocol: proto,
        packetCount: val.count,
        packetPercent: totalPackets > 0 ? (val.count / totalPackets) * 100 : 0,
        bytes: val.bytes,
        bytesPercent: totalBytes > 0 ? (val.bytes / totalBytes) * 100 : 0,
      }))
      .sort((a, b) => b.packetCount - a.packetCount);
  }, [packets, totalPackets, totalBytes]);

  // Packet Length Distribution Histogram
  const lengthBuckets = React.useMemo(() => {
    const ranges = [
      { label: '< 64 B', min: 0, max: 64, count: 0 },
      { label: '65 - 128 B', min: 65, max: 128, count: 0 },
      { label: '129 - 256 B', min: 129, max: 256, count: 0 },
      { label: '257 - 512 B', min: 257, max: 512, count: 0 },
      { label: '513 - 1024 B', min: 513, max: 1024, count: 0 },
      { label: '1025 - 1518 B', min: 1025, max: 1518, count: 0 },
      { label: '> 1518 B (Jumbo)', min: 1519, max: Infinity, count: 0 },
    ];

    for (const p of packets) {
      for (const r of ranges) {
        if (p.length >= r.min && p.length <= r.max) {
          r.count += 1;
          break;
        }
      }
    }

    return ranges;
  }, [packets]);

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className={`w-full max-w-4xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          isDark ? 'bg-zinc-950 border-zinc-700 text-zinc-100' : 'bg-white border-zinc-300 text-zinc-900'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-purple-500/20 text-purple-400">
              <BarChart2 className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 font-bold text-base">
                <span>Capture Statistics & Network Analytics</span>
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
                  {totalPackets.toLocaleString()} Frames
                </span>
              </div>
              <p className={`text-xs ${isDark ? "text-zinc-400" : "text-slate-600"} font-mono`}>
                Total Bandwidth: {(totalBytes / 1024).toFixed(1)} KB ({(totalBytes * 8 / 1000).toFixed(1)} Kbits)
              </p>
            </div>
          </div>

          <button onClick={onClose} className={`p-1.5 rounded-md hover:bg-zinc-800 ${isDark ? "text-zinc-400" : "text-slate-600"} hover:text-zinc-200`}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-5 py-2 border-b border-zinc-800 flex items-center gap-2 text-xs">
          <button
            onClick={() => setActiveTab('hierarchy')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'hierarchy'
                ? 'bg-purple-600 text-white shadow-sm'
                : isDark
                ? 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'
                : 'text-zinc-600 hover:text-zinc-900 hover:bg-zinc-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Protocol Hierarchy</span>
          </button>

          <button
            onClick={() => setActiveTab('sizes')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'sizes'
                ? 'bg-purple-600 text-white shadow-sm'
                : isDark
                ? 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'
                : 'text-zinc-600 hover:text-zinc-900 hover:bg-zinc-100'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Packet Length Distribution</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-5 custom-scrollbar font-mono text-xs">
          {activeTab === 'hierarchy' && (
            <div className="space-y-3">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className={`border-b border-zinc-800 ${isDark ? "text-zinc-400" : "text-slate-600"} text-[11px] font-sans font-semibold`}>
                    <th className="py-2 px-3">Protocol Tree Node</th>
                    <th className="py-2 px-3 text-right">% Packets</th>
                    <th className="py-2 px-3 text-right">Packets</th>
                    <th className="py-2 px-3 text-right">% Bytes</th>
                    <th className="py-2 px-3 text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody className={`divide-y divide-zinc-800/40 ${isDark ? "text-zinc-200" : "text-slate-800"}`}>
                  {/* Base Frame & Ethernet Layers */}
                  <tr className="hover:bg-zinc-900/40">
                    <td className="py-2 px-3 font-semibold text-sky-400">▾ Frame / Ethernet II</td>
                    <td className="py-2 px-3 text-right font-mono">100.0%</td>
                    <td className="py-2 px-3 text-right font-mono">{totalPackets}</td>
                    <td className="py-2 px-3 text-right font-mono">100.0%</td>
                    <td className="py-2 px-3 text-right font-mono">{totalBytes}</td>
                  </tr>

                  {/* IPv4 Parent */}
                  <tr className="hover:bg-zinc-900/40">
                    <td className="py-2 px-3 pl-8 text-indigo-300">▾ Internet Protocol Version 4</td>
                    <td className="py-2 px-3 text-right font-mono">98.4%</td>
                    <td className="py-2 px-3 text-right font-mono">{Math.floor(totalPackets * 0.98)}</td>
                    <td className="py-2 px-3 text-right font-mono">99.1%</td>
                    <td className="py-2 px-3 text-right font-mono">{Math.floor(totalBytes * 0.99)}</td>
                  </tr>

                  {/* Individual Sub-protocols */}
                  {protocolHierarchy.map(item => (
                    <tr key={item.protocol} className="hover:bg-zinc-900/40">
                      <td className={`py-1.5 px-3 pl-14 font-semibold ${isDark ? "text-zinc-100" : "text-slate-800"} flex items-center gap-2`}>
                        <span className="w-2 h-2 rounded-full bg-purple-400" />
                        <span>{item.protocol}</span>
                      </td>
                      <td className={`py-1.5 px-3 text-right font-mono ${isDark ? "text-zinc-300" : "text-slate-700"}`}>{item.packetPercent.toFixed(1)}%</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${isDark ? "text-zinc-100" : "text-slate-800"}`}>{item.packetCount}</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${isDark ? "text-zinc-300" : "text-slate-700"}`}>{item.bytesPercent.toFixed(1)}%</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${isDark ? "text-zinc-100" : "text-slate-800"}`}>{item.bytes.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'sizes' && (
            <div className="space-y-4">
              <div className={`${isDark ? "text-zinc-400" : "text-slate-600"} font-sans text-xs`}>
                Distribution of frame lengths captured across the active network buffer.
              </div>

              <div className="space-y-2 font-mono">
                {lengthBuckets.map((b, idx) => {
                  const percent = totalPackets > 0 ? (b.count / totalPackets) * 100 : 0;
                  return (
                    <div key={idx} className="p-2 rounded bg-zinc-900 border border-zinc-800 space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className={`font-semibold ${isDark ? "text-zinc-200" : "text-slate-800"}`}>{b.label}</span>
                        <div className="flex items-center gap-3">
                          <span className={`${isDark ? "text-zinc-400" : "text-slate-600"}`}>{b.count} frames</span>
                          <span className="text-purple-400 font-bold w-12 text-right">{percent.toFixed(1)}%</span>
                        </div>
                      </div>

                      <div className={`w-full h-2 rounded-full ${isDark ? "bg-zinc-800" : "bg-slate-200"} overflow-hidden`}>
                        <div
                          className="h-full bg-gradient-to-r from-purple-500 to-sky-400 rounded-full transition-all duration-300"
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-zinc-800 flex justify-end">
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} text-xs font-medium transition-colors`}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
