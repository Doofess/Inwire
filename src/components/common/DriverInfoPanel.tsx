import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { AgentHealth } from '../../services/agentHealth';
import { Trash } from 'lucide-react';
import type { AgentLogEntry } from '../../services/agentProtocol';
import { describeLink, type LinkChange } from '../../services/linkContext';

interface DriverInfoPanelProps {
  /** Only for the no-adapters notice and the log's empty state - no row names it. */
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  /**
   * Frames pushed out of the app's own buffer because it filled. Not a loss:
   * these frames were captured, dissected and shown, and are still in the
   * stored session - they are just no longer in the list.
   */
  droppedBuffer?: number;
  /** Network transitions observed this session, oldest first. */
  linkChanges?: LinkChange[];
  /** Only to detect the no-adapters state; the adapter in use is in the bar. */
  agentInterfaces: { name: string; label: string }[];
  agentLog: AgentLogEntry[];
  /**
   * Why the link is down, when anything outside the pipe can say.
   *
   * A refused pipe and a missing service look identical from the pipe, so this
   * is the only thing that turns "Not reachable" into a sentence with a next
   * step in it. See `services/agentHealth.ts`.
   */
  agentHealth: AgentHealth;
  /** Raises the UAC prompt that starts the service. Offered only when it helps. */
  onStartAgentService: () => void;
  /**
   * Opens the Updates section, where the capture driver is installed.
   *
   * Offered only for the one failure `agentHealth` structurally cannot
   * describe - see `noInterfaces` below.
   */
  onShowUpdates?: () => void;
  /** The agent's most recent rejection, or null. */
  agentError: string | null;
  /**
   * What the renderer's heap guard has said, or null.
   *
   * Warn and stop both land here; the message itself says which. See
   * `services/rendererHeapGuard.ts`.
   */
  heapNotice?: string | null;
  onSubscribe: () => void;
  onUnsubscribe: () => void;
  onClearLog: () => void;
  /**
   * The capture-buffer block, rendered between the driver's own facts and its
   * log.
   *
   * A slot rather than five more props, because the buffer is not driver
   * information - it is what the app does with what the driver sends, and it
   * lives here because Settings had a whole tab holding one progress bar and a
   * button. Passed in from where its numbers already are, so this component
   * keeps knowing only about the driver.
   */
  captureSection?: React.ReactNode;
}

/**
 * **There was a second status label table here, and deleting it is the point.**
 *
 * `AGENT_STATUS_LABEL` and `AGENT_STATUS_COLOR` mapped the same four link
 * states this panel's Status row showed - while `services/agentHealth.ts`
 * already held `agentStatusLabel`, a TOTAL record, for the status bar and the
 * rail. Two tables for one fact is how they stop agreeing, which is exactly the
 * bug `agentSilentLabel` shipped: a healthy agent read "Agent not reachable" in
 * one place and "connected" in another, because one was a lookup with a
 * fallback and the other a conditional.
 *
 * The panel no longer names the link state at all. The status bar's left group
 * does, permanently, in the one place session state lives - and this tab is
 * reached by opening Settings, which is strictly more work than glancing down.
 */

function levelColor(level: string | null): string {
  switch (level) {
    case 'ERROR':
    case 'CRITICAL':
      return 'text-rose-600 dark:text-rose-400';
    case 'WARNING':
      return 'text-amber-600 dark:text-amber-400';
    case 'DEBUG':
      return 'text-muted-foreground';
    default:
      return 'text-foreground';
  }
}

/**
 * The action in this tab: Clear Buffer, in the capture section's slot.
 *
 * Pill shaped, and in the theme's accent rather than a bordered neutral. It sat
 * beside Connect, Disconnect and Restart Driver, which are gone (2026-09-26,
 * at the owner's request, with the "Frames lost" counts above them). Kept as
 * an exported constant so the next action here matches it rather than drifting.
 *
 * Fully rounded because it is an action on a status readout rather than a form
 * submit; the pill is what separates it from the panel's rows of facts without
 * needing a border to do it.
 */
export const DRIVER_ACTION_BUTTON_CLASS =
  'flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium transition-colors '
  + 'bg-primary text-primary-foreground hover:bg-primary/90 '
  + 'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-primary cursor-pointer';

/**
 * The same pill for an action that deletes: an outline in `--destructive` at
 * rest, filled on hover. Not a solid red, because it sits beside a primary
 * pill and two filled buttons of equal weight would make neither the default;
 * the red says what it costs before the pointer gets there.
 */
export const DESTRUCTIVE_ACTION_BUTTON_CLASS =
  'flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium transition-colors '
  + 'border border-destructive/60 text-destructive bg-transparent '
  + 'hover:bg-destructive hover:text-destructive-foreground hover:border-destructive '
  + 'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent '
  + 'disabled:hover:text-destructive disabled:hover:border-destructive/60 cursor-pointer';

export const DriverInfoPanel: React.FC<DriverInfoPanelProps> = ({
  agentStatus,
  droppedBuffer = 0,
  linkChanges = [],
  agentInterfaces,
  agentLog,
  agentHealth,
  onStartAgentService,
  onShowUpdates,
  agentError,
  heapNotice,
  onSubscribe,
  onUnsubscribe,
  onClearLog,
  captureSection,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Subscribe for as long as this panel is mounted, and only that long -
  // the whole point of the subscription model is that a closed panel costs
  // nothing on the wire.
  //
  // Under React StrictMode (main.tsx), this effect runs subscribe ->
  // unsubscribe -> subscribe in development, and App.tsx's setAgentLog([])
  // on each subscribe lands before either backlog arrives - so the dev-mode
  // pane can briefly show the backlog twice. StrictMode-only, harmless, and
  // absent in production.
  useEffect(() => {
    onSubscribe();
    return onUnsubscribe;
  }, [onSubscribe, onUnsubscribe]);

  // useLayoutEffect, not useEffect: scrolling after paint makes the newest
  // line visibly jump into place on every arrival.
  useLayoutEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [agentLog, autoScroll]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    // Scrolling up to read something must not be fought by the next arriving
    // line; returning to the bottom opts back in.
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setAutoScroll(atBottom);
  };

  const handleClear = () => {
    onClearLog();
    // An emptied pane renders only the short empty-state div, so
    // scrollHeight collapses to clientHeight and the element is not
    // scrollable at all - no scroll event can fire to re-arm autoScroll via
    // handleScroll. Without this, clearing while paused (scrolled up) would
    // leave the "paused" banner up with no way for the user to satisfy it
    // short of waiting for enough new lines to make the pane scrollable
    // again.
    setAutoScroll(true);
  };

  // Shown only when it says something the Status row does not. "Connected" and
  // "Connecting" are already legible; a banner repeating them would be noise
  // in the one panel somebody opens when something is wrong.
  const diagnosis = agentHealth.kind === 'connected' || agentHealth.kind === 'connecting'
    ? null
    : agentHealth;

  // The failure `agentHealth` cannot express, and the reason it cannot is
  // structural rather than an oversight: `diagnoseAgent` short-circuits on
  // `status === 'connected'`, and this IS connected. The agent answered, it
  // is healthy, and it has nothing to capture on - which on Windows means
  // Npcap almost every time.
  //
  // Until now the entire signal for it was a hover tooltip on a header
  // button. It is the state a new install lands in, so it is the one that
  // least deserves to be a tooltip.
  const noInterfaces = agentStatus === 'connected' && agentInterfaces.length === 0;

  return (
    <div className="flex flex-col gap-4 min-h-0">
      {diagnosis && (
        <div className={`rounded-md border px-3 py-2.5 text-xs ${
          diagnosis.kind === 'crashing' || diagnosis.kind === 'missing'
            ? 'border-rose-500/30 bg-rose-500/5'
            : 'border-amber-500/30 bg-amber-500/5'
        }`}>
          <div className="font-semibold text-foreground">{diagnosis.summary}</div>
          <p className="mt-1 text-muted-foreground leading-relaxed">{diagnosis.detail}</p>
          {diagnosis.canStart && (
            <button
              type="button"
              onClick={onStartAgentService}
              className="mt-2 rounded border border-border px-2 py-1 font-medium text-foreground hover:bg-muted"
            >
              Start the agent
            </button>
          )}
        </div>
      )}
      {noInterfaces && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2.5 text-xs">
          <div className="font-semibold text-foreground">No capture interfaces</div>
          <p className="mt-1 text-muted-foreground leading-relaxed">
            The agent is running and answering, and it has nothing to listen on. That almost
            always means the Npcap capture driver is missing - Windows itself does not let a
            program read raw frames.
          </p>
          {onShowUpdates && (
            <button
              type="button"
              onClick={onShowUpdates}
              className="mt-2 rounded border border-border px-2 py-1 font-medium text-foreground hover:bg-muted cursor-pointer"
            >
              Install it from Updates
            </button>
          )}
        </div>
      )}
      <div>
        {/* **Two facts that appear only when there is something to say.**

            They were the tail of a "Frames lost" block - Received, the three
            drop counts, the log file's path - removed with Connect, Disconnect
            and Restart Driver on 2026-09-26 at the owner's request. The status
            bar still carries the drop total.

            The trimmed count is worded apart from a loss on purpose: these
            frames were captured, dissected, written to disk and are still
            readable off it - they are only out of the RAM window. Gated on its
            own count because the buffer fills during an import too, when there
            is no agent to have reported anything.

            A network change is what a gap with no frames, a burst of ARP and
            DHCP, or a stream that stops dead all look like from the inside. */}
        {(droppedBuffer > 0 || linkChanges.length > 0) && (
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
            {droppedBuffer > 0 && (
              <>
                <dt className="text-muted-foreground">Trimmed from the buffer</dt>
                <dd className="">
                  {droppedBuffer.toLocaleString()}
                  <span className="text-muted-foreground"> (still on disk)</span>
                </dd>
              </>
            )}
            {linkChanges.length > 0 && (
              <>
                <dt className="text-muted-foreground">Network changed</dt>
                <dd className="text-amber-600 dark:text-amber-400">
                  {linkChanges.length}&times;
                  <span className="text-muted-foreground">
                    {' '}(last: {describeLink(linkChanges[linkChanges.length - 1].before) || 'unknown'}
                    {' → '}
                    {describeLink(linkChanges[linkChanges.length - 1].after) || 'unknown'})
                  </span>
                </dd>
              </>
            )}
          </dl>
        )}

        {/* The agent's most recent refusal. Most commands have no other visible
            outcome, so without this a declined one reads as nothing happening. */}
        {agentError && (
          <div className="mt-2 px-2.5 py-2 rounded-md text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400">
            {agentError}
          </div>
        )}

        {/* The one thing a V8 abort cannot say.
            `services/rendererHeapGuard.ts` samples the heap and stands down
            before the collector gives up - without it the window simply
            disappears, with the reason in a stderr a packaged GUI app pipes
            into a log nobody is reading. This strip is the difference between
            "Inwire crashed" and a sentence naming the ceiling and what to
            change. It lives in this tab because the ceiling is the same subject
            as the counts above it: where the frames went. */}
        {heapNotice && (
          <div className="mt-2 px-2.5 py-2 rounded-md text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400">
            {heapNotice}
          </div>
        )}
      </div>

      {captureSection}

      <div className="flex flex-col min-h-0 flex-1">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs font-semibold text-foreground">
            Log
            {!autoScroll && (
              <span className="ml-2 text-[10px] font-normal text-muted-foreground">
                paused — scroll to the bottom to follow
              </span>
            )}
          </div>
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px] font-medium text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            <Trash className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>

        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="flex-1 min-h-[14rem] max-h-[22rem] overflow-y-auto overflow-x-auto rounded-lg border border-border bg-muted/40 p-2 font-mono text-[11px] leading-relaxed"
        >
          {agentLog.length === 0 ? (
            <div className="text-muted-foreground p-2">
              {agentStatus === 'connected'
                ? 'No log lines yet.'
                : 'Waiting for the driver to connect…'}
            </div>
          ) : (
            agentLog.map((line, index) => (
              // Index keys are correct here: this is an append-only buffer
              // whose only other mutation drops entries off the front, and
              // entries carry no identity of their own - two identical lines
              // a second apart are genuinely indistinguishable.
              <div key={index} className="whitespace-pre flex gap-2">
                <span className="text-muted-foreground shrink-0">{line.time ?? ''}</span>
                <span className={`shrink-0 w-16 ${levelColor(line.level)}`}>{line.level ?? ''}</span>
                <span className={levelColor(line.level)}>{line.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
