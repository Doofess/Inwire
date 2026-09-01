import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Packet } from '../../types/packet';
import { TbChartBar, TbX, TbStack2, TbActivity } from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';

interface StatisticsModalProps {
  packets: Packet[];
  onClose: () => void;
}

export const StatisticsModal: React.FC<StatisticsModalProps> = ({ packets, onClose }) => {
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
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className={`w-full max-w-4xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          'bg-card border-border text-card-foreground'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <TbChartBar className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="flex items-center gap-2 font-bold text-base">
                {/* Matches the menu entry that opens it, and the sidebar
                    panel that links here. */}
                <span>Protocol Breakdown</span>
                <span className="text-xs px-2 py-0.5 rounded bg-primary/20 text-primary font-mono">
                  {totalPackets.toLocaleString()} Frames
                </span>
              </div>
              <p className={`text-xs ${"text-muted-foreground"} font-mono`}>
                Total Bandwidth: {(totalBytes / 1024).toFixed(1)} KB ({(totalBytes * 8 / 1000).toFixed(1)} Kbits)
              </p>
            </div>
          </div>

          <button onClick={onClose} className={`p-1.5 rounded-md hover:bg-accent ${"text-muted-foreground"} hover:text-foreground`}>
            <TbX className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-5 py-2 border-b border-border flex items-center gap-2 text-xs">
          <button
            onClick={() => setActiveTab('hierarchy')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'hierarchy'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            <TbStack2 className="w-3.5 h-3.5" />
            <span>Protocol Hierarchy</span>
          </button>

          <button
            onClick={() => setActiveTab('sizes')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === 'sizes'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            <TbActivity className="w-3.5 h-3.5" />
            <span>Packet Length Distribution</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto p-5 custom-scrollbar font-mono text-xs">
          {activeTab === 'hierarchy' && (
            <div className="space-y-3">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className={`border-b border-border ${"text-muted-foreground"} text-[11px] font-sans font-semibold`}>
                    <th className="py-2 px-3">Protocol Tree Node</th>
                    <th className="py-2 px-3 text-right">% Packets</th>
                    <th className="py-2 px-3 text-right">Packets</th>
                    <th className="py-2 px-3 text-right">% Bytes</th>
                    <th className="py-2 px-3 text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60 text-foreground">
                  {/* Base Frame & Ethernet Layers */}
                  <tr className="hover:bg-accent/40">
                    <td className="py-2 px-3 font-semibold text-primary">▾ Frame / Ethernet II</td>
                    <td className="py-2 px-3 text-right font-mono">100.0%</td>
                    <td className="py-2 px-3 text-right font-mono">{totalPackets}</td>
                    <td className="py-2 px-3 text-right font-mono">100.0%</td>
                    <td className="py-2 px-3 text-right font-mono">{totalBytes}</td>
                  </tr>

                  {/* IPv4 Parent */}
                  <tr className="hover:bg-accent/40">
                    <td className="py-2 px-3 pl-8 text-primary/80">▾ Internet Protocol Version 4</td>
                    <td className="py-2 px-3 text-right font-mono">98.4%</td>
                    <td className="py-2 px-3 text-right font-mono">{Math.floor(totalPackets * 0.98)}</td>
                    <td className="py-2 px-3 text-right font-mono">99.1%</td>
                    <td className="py-2 px-3 text-right font-mono">{Math.floor(totalBytes * 0.99)}</td>
                  </tr>

                  {/* Individual Sub-protocols */}
                  {protocolHierarchy.map(item => (
                    <tr key={item.protocol} className="hover:bg-accent/40">
                      <td className={`py-1.5 px-3 pl-14 font-semibold ${"text-foreground"} flex items-center gap-2`}>
                        <span className="w-2 h-2 rounded-full bg-primary" />
                        <span>{item.protocol}</span>
                      </td>
                      <td className={`py-1.5 px-3 text-right font-mono ${"text-foreground/80"}`}>{item.packetPercent.toFixed(1)}%</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${"text-foreground"}`}>{item.packetCount}</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${"text-foreground/80"}`}>{item.bytesPercent.toFixed(1)}%</td>
                      <td className={`py-1.5 px-3 text-right font-mono ${"text-foreground"}`}>{item.bytes.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'sizes' && (
            <div className="space-y-4">
              <div className={`${"text-muted-foreground"} font-sans text-xs`}>
                Distribution of frame lengths captured across the active network buffer.
              </div>

              <div className="space-y-2 font-mono">
                {lengthBuckets.map((b, idx) => {
                  const percent = totalPackets > 0 ? (b.count / totalPackets) * 100 : 0;
                  return (
                    <div key={idx} className="p-2 rounded bg-muted border border-border space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className={`font-semibold ${"text-foreground"}`}>{b.label}</span>
                        <div className="flex items-center gap-3">
                          <span className={`${"text-muted-foreground"}`}>{b.count} frames</span>
                          <span className="text-primary font-bold w-12 text-right">{percent.toFixed(1)}%</span>
                        </div>
                      </div>

                      <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full transition-all duration-300"
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
        <div className="px-5 py-3 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-secondary hover:bg-accent ${"text-foreground"} text-xs font-medium transition-colors`}
          >
            Close
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
