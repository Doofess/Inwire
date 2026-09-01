import React from 'react';
import { Packet, AnomalyInfo } from '../../types/packet';

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
        // `danger` for the fill and the dot, `danger-muted` for anything that
        // has to be READ on the card behind them - the same hue moved along
        // lightness until it clears WCAG AA. The two are separate tokens
        // because a colour bright enough to be a status dot is rarely legible
        // as an 11px line of body text, which is what the fixed rose-900 /
        // rose-200 pair was working around one theme at a time.
        <div className="p-4 bg-danger/10 border border-danger/20 rounded-lg select-none">
          <div className="flex items-center space-x-2 mb-2">
            <div className="w-2 h-2 rounded-full bg-danger animate-ping" />
            <span className="text-[10px] font-bold text-danger-muted uppercase tracking-wider font-mono">
              Alert Active ({anomalyPackets.length} Total)
            </span>
          </div>

          <p className="text-[11px] text-danger-muted leading-snug font-sans">
            {latestAlert.anomalies?.[0]?.title || latestAlert.info} from {latestAlert.source}
          </p>

          <p className="text-[10px] text-danger-muted/70 font-mono mt-1 truncate">
            Target: {latestAlert.destination} • Frame #{latestAlert.id}
          </p>

          <button
            onClick={() => onInspectPacket(latestAlert)}
            className="mt-3 w-full py-2 text-[10px] font-bold bg-danger hover:bg-danger/90 active:scale-95 text-danger-foreground rounded uppercase tracking-wider transition-colors shadow-md shadow-danger/20 cursor-pointer"
          >
            Investigate Frame #{latestAlert.id}
          </button>
        </div>
      ) : (
        <div className="p-4 bg-success/10 border border-success/20 rounded-lg select-none text-center">
          <div className="flex items-center justify-center space-x-2 mb-1">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-[10px] font-bold text-success-muted uppercase tracking-wider font-mono">
              Zero Threats Active
            </span>
          </div>
          <p className="text-[11px] text-success-muted/80 font-sans">
            Network baseline normal. IDS heuristics monitoring live stream.
          </p>
        </div>
      )}
    </div>
  );
};
