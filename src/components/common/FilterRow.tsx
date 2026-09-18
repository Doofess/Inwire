import React from 'react';
import { TriangleAlert } from 'lucide-react';
import type { AgentHealth } from '../../services/agentHealth';
import { agentNeedsAttention, agentStatusLabel } from '../../services/agentHealth';

/**
 * The row below the title row: the display filter, and the state of the capture.
 *
 * This is where the old 64px header's remaining contents ended up. The capture
 * controls went into the rail, and **the schedule picker followed them there**:
 * it decides when a capture starts and when it stops, which makes it a capture
 * control rather than something that belongs above the packet list. What is
 * left here is the display filter, the restore progress, and the banner.
 *
 * It is NOT an accent bar. The header it replaces was painted in a saturated
 * `--chrome` and everything in it took `--chrome-foreground`; this row sits on
 * the app's own `--background` beside the packet list, so its text is ordinary
 * foreground. Those tokens no longer exist - see the Colourful deletion.
 *
 * ## The capturing readout is gone, and it was a third copy
 *
 * A `Capturing on Ethernet 2` prefix used to sit at the end of this row. It
 * said nothing that was not already on screen twice: the rail's glyph says a
 * capture is running, and `windowTitleFor` puts the adapter in the title row
 * as `Ethernet 2 - capturing - Inwire`, one strip above this one. That is the
 * rule the hamburger menu was deleted under - nothing that duplicates a
 * visible control survives - turned on this row. `captureAdapter` stays in
 * `App.tsx` because the title still needs it; nothing here does.
 *
 * ## What never drops under pressure
 *
 * The banner is state, not decoration. When the row is short of space the
 * restore readout goes first, because it is transient.
 */
export interface FilterRowProps {
  /** `<FilterBar/>`, passed in so this stays a layout component. */
  filterSlot: React.ReactNode;

  restoreProgress?: { done: number; total: number } | null;

  /** Why capture cannot start, if it cannot. Drives the banner. */
  agentHealth: AgentHealth;
  /** True once the link has had its chance - suppresses the banner while opening. */
  agentLinkEnabled: boolean;
  onOpenDriverInfo: () => void;
}

export const FilterRow: React.FC<FilterRowProps> = ({
  filterSlot, restoreProgress, agentHealth, agentLinkEnabled, onOpenDriverInfo,
}) => {
  /**
   * The banner appears only when capture cannot start, and says what to do.
   *
   * `diagnoseAgent` short-circuits on `connected`, and CLAUDE.md is explicit
   * that a driverless agent **is** connected - it answers, it is healthy, it has
   * nothing to listen on. So this is the link half only; the driver half is
   * `DriverInfoPanel`'s, which is what the action opens. A banner that tried to
   * diagnose both from `agentHealth` alone would be silent on exactly the state a
   * fresh install lands in.
   */
  const blocked = agentLinkEnabled && agentNeedsAttention(agentHealth)
    && agentHealth.kind !== 'connecting';

  return (
    <div className="shrink-0 border-b border-border bg-background">
      {blocked && (
        <div
          role="status"
          className="flex items-center gap-2 px-3 py-1.5 border-b border-warning/30
            bg-warning/10 text-[11px] leading-snug"
        >
          <TriangleAlert className="w-3.5 h-3.5 shrink-0 text-warning" />
          <span className="font-semibold text-foreground">{agentStatusLabel(agentHealth)}</span>
          <span className="min-w-0 truncate text-muted-foreground">
            {'summary' in agentHealth ? agentHealth.summary : 'The capture agent is not answering.'}
          </span>
          {/* One action, and it is the one that can actually fix it. A banner
              with advice and no way to act on it is a worse version of the
              tooltip this replaced. */}
          <button
            type="button"
            onClick={onOpenDriverInfo}
            className="ml-auto shrink-0 px-2 py-0.5 rounded bg-secondary hover:bg-accent
              text-foreground text-[11px] font-medium transition-colors cursor-pointer"
          >
            Driver Info
          </button>
        </div>
      )}

      <div className="h-11 px-3 flex items-center gap-3">
        {/* The filter takes the row. Its own `flex-1` does the work. */}
        {filterSlot}

        {restoreProgress && (
          <span
            className="shrink-0 flex items-center gap-1.5 text-[10px] font-mono font-bold
              uppercase tracking-wider text-muted-foreground whitespace-nowrap"
            title="Restoring the capture from your previous session"
          >
            <span aria-hidden className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />
            <span>
              Restoring {restoreProgress.done.toLocaleString()}/
              {restoreProgress.total.toLocaleString()}
            </span>
          </span>
        )}

      </div>
    </div>
  );
};
