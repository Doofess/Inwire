import { useEffect, useState } from 'react';
import { ChevronRight, Radio } from 'lucide-react';
import { Section } from '../network/rows';
import { useMonitoring } from '../../hooks/useMonitoring';
import { monitoringSummary } from './monitoringCopy';
import { ToneDot } from './parts';

/**
 * Monitoring's door in the Network panel, beside the speed test's: one line
 * saying where collection is, and the way into the sheet.
 *
 * It reads the client's state and never connects: main sends no status until
 * the sheet has asked for the history, so before that it says "Not started".
 * The line is re-read once a second only while listening, because the one
 * state that changes with the clock alone - nothing for a minute - is a
 * listening one.
 */
export function MonitoringSection({ onOpen }: { onOpen: () => void }) {
  const state = useMonitoring();
  const listening = state.intake?.listener === 'listening';
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!listening) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [listening]);
  const summary = monitoringSummary(state, now);
  const notStarted = state.runtime === 'idle';

  return (
    <Section title="Monitoring">
      <div className="space-y-2 px-3 py-2.5 font-sans">
        <div className="flex items-start gap-1.5 text-xs text-foreground" role="status" aria-live="polite">
          <ToneDot tone={summary.tone} className="mt-[5px]" />
          <span className="min-w-0 break-words">{summary.text}</span>
        </div>
        {notStarted && (
          <p className="text-[11px] leading-snug text-muted-foreground">
            Traffic records a router or switch exports to this PC, as NetFlow v5.
          </p>
        )}
        {notStarted ? (
          <button type="button" onClick={onOpen}
            className="flex w-full items-center justify-center gap-1.5 rounded-md border border-primary/50 bg-primary/10 px-3 py-1.5
              text-xs font-semibold text-primary transition-colors hover:bg-primary/20 cursor-pointer
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <Radio className="h-3.5 w-3.5" aria-hidden />
            Open monitoring
          </button>
        ) : (
          <button type="button" onClick={onOpen}
            className="flex items-center gap-0.5 rounded-sm text-[11px] text-muted-foreground hover:text-foreground cursor-pointer
              focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
            Open monitoring <ChevronRight className="h-3 w-3" aria-hidden />
          </button>
        )}
      </div>
    </Section>
  );
}
