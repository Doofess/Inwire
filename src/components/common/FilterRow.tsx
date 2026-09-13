import React from 'react';
import { TbClock, TbAlertTriangle } from 'react-icons/tb';
import type { AgentHealth } from '../../services/agentHealth';
import { agentNeedsAttention, agentSilentLabel } from '../../services/agentHealth';
import { CaptureSchedulePicker } from './CaptureSchedulePicker';
import type { CaptureSchedule, SchedulePreset } from '../../services/captureSchedule';
import { headerButtonClass } from './headerButton';

/**
 * The row below the title row: the display filter, and the state of the capture.
 *
 * This is where the old 64px header's remaining contents ended up. The capture
 * controls went into the rail; the schedule picker and the restore readout came
 * here, because they are things you read rather than things you reach for, and
 * the row already carries the packet counter.
 *
 * It is NOT the chrome accent any more. The header it replaces was `--chrome`,
 * and everything in it took `--chrome-foreground`; this row sits on the app's own
 * `--background` beside the packet list, so its text is ordinary foreground. A
 * `text-chrome-foreground` left behind in here would be white text on a white
 * ground in Day.
 *
 * ## Two things that never drop under pressure
 *
 * The capturing prefix and the banner are state, not decoration. When the row is
 * short of space the order is: the restore readout goes first (it is transient),
 * then the schedule picker becomes icon-only, then the counter loses its `%`
 * badge. Those three are `FilterBar`'s and this component's own; the two below
 * stay put.
 */
export interface FilterRowProps {
  /** `<FilterBar/>`, passed in so this stays a layout component. */
  filterSlot: React.ReactNode;

  isCapturing: boolean;
  /** The adapter's short label, for the capturing prefix. Null if none. */
  captureAdapter: string | null;

  schedule: CaptureSchedule;
  onScheduleChange: (next: CaptureSchedule) => void;
  schedulePresets: SchedulePreset[];
  onSchedulePresetsChange: (next: SchedulePreset[]) => void;
  scheduleSummary: string;
  scheduleNow: number;
  bufferedPackets: number;

  restoreProgress?: { done: number; total: number } | null;

  /** Why capture cannot start, if it cannot. Drives the banner. */
  agentHealth: AgentHealth;
  /** True once the link has had its chance - suppresses the banner while opening. */
  agentLinkEnabled: boolean;
  onOpenDriverInfo: () => void;
}

export const FilterRow: React.FC<FilterRowProps> = ({
  filterSlot, isCapturing, captureAdapter,
  schedule, onScheduleChange, schedulePresets, onSchedulePresetsChange,
  scheduleSummary, scheduleNow, bufferedPackets,
  restoreProgress, agentHealth, agentLinkEnabled, onOpenDriverInfo,
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
          <TbAlertTriangle className="w-3.5 h-3.5 shrink-0 text-warning" />
          <span className="font-semibold text-foreground">{agentSilentLabel(agentHealth)}</span>
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

        {/* Capturing, and on what. The rail's glyph says that capture is
            running; this says which adapter, which is the half an analyst with
            four windows open actually needs. No animation on the dot: a pulsing
            light beside a list that is already visibly filling is saying the same
            thing twice, and it is the kind of motion that becomes irritating in
            the sixth hour. */}
        {isCapturing && (
          <span
            className="shrink-0 flex items-center gap-1.5 text-[10px] font-mono font-bold
              uppercase tracking-wider text-success whitespace-nowrap"
            title={captureAdapter === null ? 'Capturing' : `Capturing on ${captureAdapter}`}
          >
            <span aria-hidden className="w-1.5 h-1.5 rounded-full bg-success" />
            <span>{captureAdapter === null ? 'Capturing' : `Capturing on ${captureAdapter}`}</span>
          </span>
        )}

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

        {/* Last, and deliberately: it is the only control in the row that is not
            the filter, and it is something you set before a capture rather than
            during one. */}
        <CaptureSchedulePicker
          schedule={schedule}
          onScheduleChange={onScheduleChange}
          presets={schedulePresets}
          onPresetsChange={onSchedulePresetsChange}
          bufferedPackets={bufferedPackets}
          now={scheduleNow}
          align="end"
        >
          <button
            data-tour="schedule"
            className={`${headerButtonClass} shrink-0 max-w-[12rem] active:scale-95 cursor-pointer`}
            title="Schedule when this capture starts and stops"
          >
            <TbClock className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">{scheduleSummary}</span>
          </button>
        </CaptureSchedulePicker>
      </div>
    </div>
  );
};
