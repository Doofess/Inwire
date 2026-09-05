import React from 'react';
import { Packet, AnomalyInfo } from '../../types/packet';

/**
 * The latest anomaly, and whether anything is wrong at all.
 *
 * The one widget with no expanded form and no settings: there is nothing to
 * configure about "is something wrong", and the answer is two lines long. It is
 * also the one widget that has to say something while nobody is looking at it,
 * which is why the collapsed rail draws a light for it rather than an icon that
 * opens something.
 *
 * `onFilterAnomaly` used to be a prop here and was never called - the panel was
 * given a way to filter the packet list by anomaly type and never grew a
 * control for it. Removed rather than wired up, because the Investigate button
 * below already goes somewhere better: the frame itself.
 */
interface AnomalyAlertsPanelProps {
  packets: Packet[];
  onInspectPacket: (packet: Packet) => void;
}

export const AnomalyAlertsPanel: React.FC<AnomalyAlertsPanelProps> = ({
  packets,
  onInspectPacket,
}) => {
  const anomalyPackets = React.useMemo(() => {
    // Newest first, and stop at fifteen. `filter().slice(-15)` walked the whole
    // buffer and allocated a result the size of every anomaly in it, to keep
    // fifteen; scanning back from the end stops as soon as it has them.
    const latest: Packet[] = [];
    for (let i = packets.length - 1; i >= 0 && latest.length < 15; i--) {
      const p = packets[i];
      if ((p.anomalies && p.anomalies.length > 0) || p.status === 'alert') latest.push(p);
    }
    return latest;
  }, [packets]);

  const latestAlert = anomalyPackets[0];

  /*
   * The tint fills the card rather than sitting in a rounded box inside it.
   *
   * It used to be `p-4 bg-danger/10 border border-danger/20 rounded-lg` - which
   * was right when this widget drew no card of its own, and became a card
   * inside a card the moment WidgetCard started drawing one. Two borders, two
   * radii, two insets, and the content squeezed into what was left; with a real
   * alert on screen - a long IPv6 source wrapping onto a second line - it
   * overflowed the card outright.
   *
   * Bleeding the fill to the card's own edges says the same thing more loudly
   * with no nesting at all: the whole widget goes red, rather than containing
   * something red.
   *
   * `danger` for the fill and the dot, `danger-muted` for anything that has to
   * be READ on it - the same hue moved along lightness until it clears WCAG AA.
   * Two tokens because a colour bright enough to be a status dot is rarely
   * legible as 11px body text, which is what the fixed rose-900 / rose-200 pair
   * was working around one theme at a time.
   */
  if (!latestAlert) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-1 text-center px-4 bg-success/10">
        <div className="flex items-center gap-2">
          <span aria-hidden className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-[10px] font-bold text-success-muted uppercase tracking-wider font-mono">
            Zero threats active
          </span>
        </div>
        <p className="text-[11px] text-success-muted/80 leading-snug">
          Network baseline normal. IDS heuristics monitoring live stream.
        </p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col gap-1.5 px-3.5 py-3 bg-danger/10">
      <div className="flex items-center gap-2 shrink-0">
        <span className="relative flex w-2 h-2 shrink-0">
          {/* The ring pings and a solid dot stays put underneath, so the blanket
              reduced-motion rule leaves a dot rather than nothing: `animate-ping`
              ends its cycle scaled up and fully transparent. */}
          <span aria-hidden className="absolute inline-flex w-2 h-2 rounded-full bg-danger opacity-75 animate-ping" />
          <span aria-hidden className="relative inline-flex w-2 h-2 rounded-full bg-danger" />
        </span>
        <span className="text-[10px] font-bold text-danger-muted uppercase tracking-wider font-mono">
          Alert active ({anomalyPackets.length} total)
        </span>
      </div>

      {/* Clamped rather than left to wrap. A dissector title plus an IPv6
          address is easily four lines, and a card that grows to fit its worst
          case is a card that is mostly empty the rest of the time. */}
      <p className="text-[11px] text-danger-muted leading-snug line-clamp-2 min-w-0 break-all">
        {latestAlert.anomalies?.[0]?.title || latestAlert.info}
        <span className="opacity-70"> from {latestAlert.source}</span>
      </p>

      <p className="text-[10px] text-danger-muted/70 font-mono truncate shrink-0">
        {latestAlert.destination} - frame #{latestAlert.id}
      </p>

      <button
        onClick={() => onInspectPacket(latestAlert)}
        className="mt-auto shrink-0 w-full py-1.5 text-[10px] font-bold bg-danger hover:bg-danger/90 active:scale-95 text-danger-foreground rounded uppercase tracking-wider transition-colors cursor-pointer"
      >
        Investigate frame #{latestAlert.id}
      </button>
    </div>
  );
};
