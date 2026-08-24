import React, { useState } from 'react';
import { Packet } from '../../types/packet';
import { Network, ArrowRightLeft, ShieldAlert } from 'lucide-react';

interface NetworkMatrixProps {
  packets: Packet[];
  onFilterHost: (ip: string) => void;
}

interface ConversationPair {
  id: string;
  hostA: string;
  hostB: string;
  packetsCount: number;
  totalBytes: number;
  protocols: Set<string>;
  hasAnomaly: boolean;
}

export const NetworkMatrix: React.FC<NetworkMatrixProps> = ({ packets, onFilterHost }) => {
  const [activeTab, setActiveTab] = useState<'conversations' | 'endpoints'>('conversations');

  // Compute conversation flows
  const conversations: ConversationPair[] = React.useMemo(() => {
    const pairMap = new Map<string, ConversationPair>();

    for (const p of packets) {
      if (!p.source || !p.destination) continue;
      const sorted = [p.source, p.destination].sort();
      const key = `${sorted[0]}<->${sorted[1]}`;

      const existing = pairMap.get(key) || {
        id: key,
        hostA: sorted[0],
        hostB: sorted[1],
        packetsCount: 0,
        totalBytes: 0,
        protocols: new Set<string>(),
        hasAnomaly: false,
      };

      existing.packetsCount += 1;
      existing.totalBytes += p.length;
      existing.protocols.add(p.protocol);
      if ((p.anomalies && p.anomalies.length > 0) || p.status === 'alert') {
        existing.hasAnomaly = true;
      }

      pairMap.set(key, existing);
    }

    return Array.from(pairMap.values()).sort((a, b) => b.totalBytes - a.totalBytes);
  }, [packets]);

  // Compute endpoint statistics
  const endpoints = React.useMemo(() => {
    const epMap = new Map<string, { ip: string; txPkts: number; rxPkts: number; bytes: number; anomalies: number }>();

    for (const p of packets) {
      const srcEp = epMap.get(p.source) || { ip: p.source, txPkts: 0, rxPkts: 0, bytes: 0, anomalies: 0 };
      srcEp.txPkts += 1;
      srcEp.bytes += p.length;
      if ((p.anomalies && p.anomalies.length > 0) || p.status === 'alert') srcEp.anomalies++;
      epMap.set(p.source, srcEp);

      const dstEp = epMap.get(p.destination) || { ip: p.destination, txPkts: 0, rxPkts: 0, bytes: 0, anomalies: 0 };
      dstEp.rxPkts += 1;
      dstEp.bytes += p.length;
      if ((p.anomalies && p.anomalies.length > 0) || p.status === 'alert') dstEp.anomalies++;
      epMap.set(p.destination, dstEp);
    }

    return Array.from(epMap.values()).sort((a, b) => b.bytes - a.bytes);
  }, [packets]);

  return (
    <div className="rounded-lg border p-3.5 flex flex-col justify-between transition-colors select-none bg-card border-border text-card-foreground shadow-sm">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5">
          <Network className="w-3.5 h-3.5 text-emerald-400" />
          <span>Top Talkers & Matrix</span>
        </h3>

        <div className="flex rounded border border-border bg-secondary p-0.5 font-mono text-[10px]">
          <button
            onClick={() => setActiveTab('conversations')}
            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${
              activeTab === 'conversations'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            FLOWS
          </button>
          <button
            onClick={() => setActiveTab('endpoints')}
            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${
              activeTab === 'endpoints'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            HOSTS
          </button>
        </div>
      </div>

      <div className="max-h-[130px] overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
        {activeTab === 'conversations' ? (
          conversations.length === 0 ? (
            <div className="text-center text-xs text-muted-foreground py-6 font-mono">No conversation flows</div>
          ) : (
            conversations.slice(0, 5).map(conv => (
              <div
                key={conv.id}
                className={`flex items-center justify-between text-xs px-2.5 py-1.5 rounded border transition-colors ${
                  conv.hasAnomaly
                    ? 'border-rose-300 dark:border-rose-500/30 bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300'
                    : 'border-border bg-secondary/60 hover:bg-accent/80'
                }`}
              >
                <div className="flex items-center gap-1.5 font-mono text-[10px] truncate">
                  {conv.hasAnomaly && <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0 animate-pulse" />}
                  <button
                    onClick={() => onFilterHost(conv.hostA)}
                    className="hover:underline hover:text-cyan-400 truncate max-w-[85px] cursor-pointer"
                    title={conv.hostA}
                  >
                    {conv.hostA}
                  </button>
                  <ArrowRightLeft className="w-3 h-3 text-muted-foreground shrink-0" />
                  <button
                    onClick={() => onFilterHost(conv.hostB)}
                    className="hover:underline hover:text-cyan-400 truncate max-w-[85px] cursor-pointer"
                    title={conv.hostB}
                  >
                    {conv.hostB}
                  </button>
                </div>

                <div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground shrink-0">
                  <span className="text-cyan-400 font-bold">
                    {conv.totalBytes >= 1024 ? `${(conv.totalBytes / 1024).toFixed(1)}K` : `${conv.totalBytes}B`}
                  </span>
                </div>
              </div>
            ))
          )
        ) : endpoints.length === 0 ? (
          <div className="text-center text-xs text-muted-foreground py-6 font-mono">No endpoints detected</div>
        ) : (
          endpoints.slice(0, 5).map(ep => (
            <div
              key={ep.ip}
              className={`flex items-center justify-between text-xs px-2.5 py-1.5 rounded border transition-colors ${
                ep.anomalies > 0
                  ? 'border-rose-300 dark:border-rose-500/30 bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300'
                  : 'border-border bg-secondary/60 hover:bg-accent/80'
              }`}
            >
              <div className="flex items-center gap-1.5 font-mono text-[10px]">
                {ep.anomalies > 0 && <ShieldAlert className="w-3.5 h-3.5 text-rose-400 shrink-0 animate-pulse" />}
                <button
                  onClick={() => onFilterHost(ep.ip)}
                  className="hover:underline hover:text-cyan-400 font-medium cursor-pointer"
                >
                  {ep.ip}
                </button>
              </div>

              <div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
                <span>{ep.txPkts + ep.rxPkts} pkts</span>
                <span className="text-cyan-400 font-bold">
                  {ep.bytes >= 1024 ? `${(ep.bytes / 1024).toFixed(1)}K` : `${ep.bytes}B`}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
