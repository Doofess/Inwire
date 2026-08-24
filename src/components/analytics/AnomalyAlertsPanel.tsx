import React from 'react';
import { Packet, AnomalyInfo } from '../../types/packet';
import { ShieldAlert, CheckCircle2, ChevronRight } from 'lucide-react';

interface AnomalyAlertsPanelProps {
  packets: Packet[];
  onInspectPacket: (packet: Packet) => void;
  onFilterAnomaly: (type: string) => void;
}

export const AnomalyAlertsPanel: React.FC<AnomalyAlertsPanelProps> = ({
  packets,
  onInspectPacket,
  onFilterAnomaly,
}) => {
  const anomalyPackets = React.useMemo(() => {
    return packets.filter(p => (p.anomalies && p.anomalies.length > 0) || p.status === 'alert').slice(-15).reverse();
  }, [packets]);

  const latestAlert = anomalyPackets[0];

  return (
    <div className="space-y-2">
      {latestAlert ? (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg select-none">
          <div className="flex items-center space-x-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span className="text-[10px] font-bold text-rose-500 uppercase tracking-wider font-mono">
              Alert Active ({anomalyPackets.length} Total)
            </span>
          </div>

          <p className="text-[11px] text-rose-900 dark:text-rose-200 leading-snug font-sans">
            {latestAlert.anomalies?.[0]?.title || latestAlert.info} from {latestAlert.source}
          </p>

          <p className="text-[10px] text-rose-700/70 dark:text-rose-300/70 font-mono mt-1 truncate">
            Target: {latestAlert.destination} • Frame #{latestAlert.id}
          </p>

          <button
            onClick={() => onInspectPacket(latestAlert)}
            className="mt-3 w-full py-2 text-[10px] font-bold bg-rose-500 hover:bg-rose-600 active:scale-95 text-white rounded uppercase tracking-wider transition-colors shadow-md shadow-rose-500/20 cursor-pointer"
          >
            Investigate Frame #{latestAlert.id}
          </button>
        </div>
      ) : (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg select-none text-center">
          <div className="flex items-center justify-center space-x-2 mb-1">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[10px] font-bold text-emerald-700 dark:text-emerald-400 uppercase tracking-wider font-mono">
              Zero Threats Active
            </span>
          </div>
          <p className="text-[11px] text-emerald-900/80 dark:text-emerald-200/80 font-sans">
            Network baseline normal. IDS heuristics monitoring live stream.
          </p>
        </div>
      )}
    </div>
  );
};
