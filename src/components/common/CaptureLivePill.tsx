import React, { useEffect, useRef, useState } from 'react';
import { Square } from 'lucide-react';
import { titleWithKeys } from '../../lib/commands';
import { formatRate, packetRate } from '../../lib/packetRate';
import { usePacketCounts } from '../../services/packetCounts';
import { LIVE_DOT, elapsedLabel, useElapsed } from '../status/SessionStatus';

/**
 * The title row's answer to "is it recording?": a pulsing dot, the elapsed time,
 * the packet rate and Stop, for as long as a capture runs.
 *
 * It subscribes to `packetCounts` itself, so the ten-times-a-second total
 * re-renders this pill and not `App`. The rate is sampled once a second from a
 * ref, because a rate over a 100ms window flickers and a rate that re-rendered
 * on every publish would too. Plain sans: these are counts in chrome, not data.
 */
export const CaptureLivePill: React.FC<{ startedAt: number | null; onStop: () => void }> = ({
  startedAt, onStop,
}) => {
  const { total } = usePacketCounts();
  const elapsed = useElapsed(startedAt);
  const totalRef = useRef(total);
  totalRef.current = total;
  const [rate, setRate] = useState(0);
  const live = startedAt !== null;

  useEffect(() => {
    if (!live) return;
    setRate(0);
    let prev = { total: totalRef.current, at: Date.now() };
    const id = setInterval(() => {
      const next = { total: totalRef.current, at: Date.now() };
      setRate(packetRate(prev, next));
      prev = next;
    }, 1000);
    return () => clearInterval(id);
  }, [live]);

  if (startedAt === null) return null;

  return (
    <div
      className="app-no-drag h-6 shrink-0 inline-flex items-center gap-1.5 rounded-full
        bg-destructive/10 pl-2.5 pr-0.5 text-xs text-foreground whitespace-nowrap"
      role="status"
      aria-label={`Capturing for ${elapsedLabel(elapsed)}`}
    >
      <span className={LIVE_DOT} aria-hidden />
      <span>{elapsedLabel(elapsed)}</span>
      <span className="text-foreground/70">{formatRate(rate)}</span>
      <button
        type="button"
        onClick={onStop}
        title={titleWithKeys('capture.stop', 'Stop capture')}
        aria-label="Stop capture"
        className="w-5 h-5 shrink-0 inline-flex items-center justify-center rounded-full
          cursor-pointer transition-colors hover:bg-destructive/20
          focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <Square className="w-3 h-3 fill-current" />
      </button>
    </div>
  );
};
