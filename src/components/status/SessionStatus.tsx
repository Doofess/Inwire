import React, { useEffect, useState } from 'react';
import {
  ArrowDownToLine,
  EthernetPort,
  LoaderCircle,
  Plug,
  TriangleAlert,
} from 'lucide-react';
import { StatusItem } from './StatusItem';
import type { AgentInterface, CaptureDropStats } from '../../services/agentProtocol';
import {
  type AgentHealth,
  agentNeedsAttention,
  agentStatusLabel,
} from '../../services/agentHealth';

/**
 * The status bar's left group: is this thing working?
 *
 * Four items, in the order a capture fails in - the link before the adapter
 * before the capture before its losses - so the leftmost thing on screen is the
 * first thing to fix. Every one of them is a click into the Settings tab that
 * fixes it, which is the other half of the point: two of these states were
 * previously reachable only through a hover tooltip or a tab nobody had open,
 * and `DriverInfoPanel` exists because of exactly that gap.
 *
 * **An item renders nothing when its subject is absent**, rather than showing a
 * zero. That rule has one deliberate exception and one hard case, both below.
 */

/** The dot that says a capture is live. Its own element so the pulse is one node. */
const LIVE_DOT = 'w-1.5 h-1.5 rounded-full bg-destructive shrink-0 animate-pulse';
const GLYPH = 'w-3 h-3 shrink-0';

/**
 * Milliseconds since the capture started, ticking once a second.
 *
 * **The interval exists only while a capture does.** An idle app must not wake
 * once a second forever, which is the same rule `useCaptureSchedule` follows
 * and for the same reason - and it compares against an absolute start time
 * rather than counting its own ticks, so a throttled background tab resumes
 * with the right number instead of the number of ticks it was awake for.
 */
function useElapsed(startedAt: number | null): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (startedAt === null) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [startedAt]);

  return startedAt === null ? 0 : Math.max(0, now - startedAt);
}

/** `4:12`, and `1:04:12` once it runs past an hour. */
export function elapsedLabel(ms: number): string {
  const total = Math.floor(ms / 1000);
  const seconds = String(total % 60).padStart(2, '0');
  const minutes = Math.floor(total / 60) % 60;
  const hours = Math.floor(total / 3600);
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, '0')}:${seconds}`
    : `${minutes}:${seconds}`;
}

/**
 * The dropped-frame total, and whether every counter behind it was readable.
 *
 * **A `null` counter is not zero.** `droppedKernel` is null when the driver's
 * own counters could not be read; `droppedPipe` is null when the agent does
 * not report it at all. Folding either in as 0 would have the bar say "nothing
 * was dropped" about a number nobody obtained - the same mistake `provesAbsent`
 * made with `reg query`, where a failure to ask read as proof of absence. So
 * the unknown travels out with the total and the tooltip says so.
 *
 * There are four contributors and they are not the same kind of thing, which
 * is the open question this function inherits: `droppedBuffer` counts frames
 * that were **persisted and are still readable off disk**, trimmed from the
 * RAM window rather than lost. Adding it to frames that never arrived overstates
 * the loss. Left as it was rather than changed in passing - it is a decision
 * about what the chip means, and it belongs with the Driver Info revamp.
 */
export function droppedTotal(
  stats: CaptureDropStats | null,
  droppedBuffer: number,
): { total: number; unknown: boolean } {
  const agent = stats?.droppedAgent ?? 0;
  const kernel = stats?.droppedKernel ?? 0;
  // The pipe's own shed count, which had no number at all until the outbound
  // queue was found discarding frames silently. `null` from an agent that does
  // not report it, and it travels into `unknown` for the same reason the
  // kernel's does rather than being folded in as 0.
  const pipe = stats?.droppedPipe ?? 0;
  return {
    total: agent + kernel + pipe + droppedBuffer,
    unknown: stats !== null && (stats.droppedKernel === null || stats.droppedPipe === null),
  };
}

export interface SessionStatusProps {
  agentHealth: AgentHealth;
  interfaces: AgentInterface[];
  selectedInterfaces: string[];
  isCapturing: boolean;
  /** Epoch milliseconds, or null when nothing is running. */
  captureStartedAt: number | null;
  captureStats: CaptureDropStats | null;
  droppedBuffer: number;
  bufferAutoPaused: boolean;
  /**
   * How far the previous session's capture has got being read back, if one is.
   *
   * From `FilterRow`, which is deleted. It is session state and transient -
   * exactly what the left group is - where in that row it was the thing that
   * dropped first when space ran short, which is a strange fate for the only
   * indication that the app is busy doing something the user asked for.
   */
  restoreProgress: { done: number; total: number } | null;
}

export const SessionStatus: React.FC<SessionStatusProps> = ({
  agentHealth,
  interfaces,
  selectedInterfaces,
  isCapturing,
  captureStartedAt,
  captureStats,
  droppedBuffer,
  bufferAutoPaused,
  restoreProgress,
}) => {
  const elapsed = useElapsed(isCapturing ? captureStartedAt : null);
  const attention = agentNeedsAttention(agentHealth);
  const { total: dropped, unknown: someUncounted } = droppedTotal(captureStats, droppedBuffer);

  const selected = interfaces.filter((i) => selectedInterfaces.includes(i.name));
  const adapterLabel = selected.length === 0
    ? 'No adapter'
    : selected.length === 1
      ? (selected[0].label || selected[0].name)
      : `${selected.length} adapters`;

  return (
    <>
      {/* **The link, and it is the one item that is never absent.** Everything
          else here depends on it, and `diagnoseAgent` answers `unknown` rather
          than nothing before main has replied - so there is always a state to
          name. The labels come from `agentHealth.ts` so this cell, the rail's
          badge and the filter row's banner cannot disagree about the same
          fault. */}
      <StatusItem
        tone={attention ? 'attention' : 'normal'}
        title={
          agentHealth.kind === 'connected'
            ? 'The capture agent is connected.'
            : agentHealth.kind === 'connecting'
              ? 'Connecting to the capture agent.'
              : `${agentHealth.summary} - ${agentHealth.detail}`
        }
      >
        {/* The hue is on the glyph and not on the label - `--warning` on this
            ground is 4.06:1 in Day, under the text floor. The triangle differs
            in OUTLINE from the plug beside it, so the state reads without the
            colour at all. */}
        {agentHealth.kind === 'connecting'
          ? <LoaderCircle className={`${GLYPH} animate-spin`} aria-hidden />
          : attention
            ? <TriangleAlert className={`${GLYPH} text-warning`} aria-hidden />
            : <Plug className={GLYPH} aria-hidden />}
        <span className="truncate">{agentStatusLabel(agentHealth)}</span>
      </StatusItem>

      {/* **The adapter, and it is deliberately never hidden either** - including
          when nothing is selected. "No adapter" is the single most common
          reason a capture does nothing, and an empty slot there would be the
          app declining to say so. The rail's picker is still the richer
          control; this names the state and hands off. */}
      <StatusItem
        className="min-w-0"
        title={
          selected.length === 0
            ? 'No capture adapter is selected.'
            : `Capturing on ${selected.map((i) => i.label || i.name).join(', ')}`
        }
      >
        <EthernetPort className={GLYPH} aria-hidden />
        <span className="truncate">{adapterLabel}</span>
      </StatusItem>

      {/* The capture. Absent until one has been started, which is the honest
          state on a fresh launch: the left group is then the link and the
          adapter, which are the two things that need attention anyway. */}
      {isCapturing && (
        <StatusItem
          tone="accent"
          title={`Capturing for ${elapsedLabel(elapsed)}`}
        >
          <span className={LIVE_DOT} aria-hidden />
          <span className="tabular-nums">{elapsedLabel(elapsed)}</span>
        </StatusItem>
      )}

      {/* Restoring, which is transient and comes first while it lasts: until
          it finishes there is no capture for anything to the right of it to
          describe. */}
      {restoreProgress !== null && (
        <StatusItem
          tone="attention"
          title="Reading back the capture from your previous session"
        >
          <LoaderCircle className={`${GLYPH} animate-spin`} aria-hidden />
          <span className="tabular-nums">
            Restoring {restoreProgress.done.toLocaleString()}/
            {restoreProgress.total.toLocaleString()}
          </span>
        </StatusItem>
      )}

      {/* Losses, hidden at zero. A permanent "0 dropped" is an item crying wolf
          in reverse - it trains the eye to skip the place the warning will
          appear. `bufferAutoPaused` outranks a count, because a capture that
          stopped itself is a different problem from one that is losing frames. */}
      {(dropped > 0 || bufferAutoPaused) && (
        <StatusItem
          tone="attention"
          title={
            (bufferAutoPaused
              ? 'The capture paused itself: the buffer reached its budget. '
              : '')
            + `${dropped.toLocaleString()} frames dropped`
            + (someUncounted
              ? ', and at least one counter could not be read - the driver’s '
                + 'own, or the pipe’s - so the real total may be higher.'
              : '.')
          }
        >
          <ArrowDownToLine className={`${GLYPH} text-warning`} aria-hidden />
          <span className="tabular-nums">
            {bufferAutoPaused ? 'paused - ' : ''}
            {dropped.toLocaleString()}{someUncounted ? '+' : ''} dropped
          </span>
        </StatusItem>
      )}
    </>
  );
};
