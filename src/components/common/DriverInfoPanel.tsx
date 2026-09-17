import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { AgentHealth } from '../../services/agentHealth';
import { Trash, Plug, Unplug, RefreshCw } from 'lucide-react';
import type { AgentLogEntry, CaptureDropStats } from '../../services/agentProtocol';
import { describeLink, type LinkChange, type LinkContext } from '../../services/linkContext';

interface DriverInfoPanelProps {
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
  /** This capture's frame counts from the agent, or null before its first report. */
  captureStats?: CaptureDropStats | null;
  /**
   * Frames pushed out of the app's own buffer because it filled.
   *
   * The third of the three places a frame goes missing, and the only one the
   * app itself is responsible for. Counted and worded apart from the other two
   * because it is a different loss: these frames were captured, dissected and
   * shown, and are still in the stored session - they are just no longer in
   * the list.
   */
  droppedBuffer?: number;
  /** What the engine says about the link, or null where it says nothing. */
  linkContext?: LinkContext | null;
  /** Network transitions observed this session, oldest first. */
  linkChanges?: LinkChange[];
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  /** Whether the app is meant to be holding a link at all - see App.tsx.
   *  Distinguishes "you disconnected" from "the agent is not running", which
   *  agentStatus alone reports as the same 'disconnected'. */
  agentLinkEnabled: boolean;
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
  onConnect: () => void;
  onDisconnect: () => void;
  onRestartAgent: () => void;
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
 * What each link state is called in the UI.
 *
 * "Connected" rather than "Running", because this row reports the state of the
 * LINK, not of the service: the driver runs as a Windows service and is running
 * whether or not this page has a socket to it. Calling a closed socket "not
 * running" said something about the machine that the app cannot actually know.
 */
const AGENT_STATUS_LABEL: Record<DriverInfoPanelProps['agentStatus'], string> = {
  connected: 'Connected',
  connecting: 'Connecting',
  disconnected: 'Not reachable',
  error: 'Error',
};

const AGENT_STATUS_COLOR: Record<DriverInfoPanelProps['agentStatus'], string> = {
  connected: 'text-emerald-600 dark:text-emerald-400',
  connecting: 'text-amber-600 dark:text-amber-400',
  disconnected: 'text-muted-foreground',
  error: 'text-rose-600 dark:text-rose-400',
};

// The agent resolves this itself from %ProgramData% (config.config_dir()),
// so a machine with a relocated ProgramData would differ. Showing the
// standard path is enough to find the file; the agent is not asked for its
// real one, which would mean another protocol field for a rare case.
//
// The OS comes from the preload rather than from `navigator`. `platformDetect`
// inferred it from the user agent in order to pick an installer to download,
// and both the inference and the download are gone: the main process simply
// knows which OS it is running on.
function logFilePath(): string {
  return window.inwire?.platform === 'win32'
    ? '%ProgramData%\\Inwire\\agent.log'
    : '~/.inwire/agent.log';
}

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
 * The four actions in this tab: Connect, Disconnect, Restart Driver, Clear
 * Buffer.
 *
 * Pill shaped, and in the theme's accent rather than a bordered neutral. They
 * were three near-identical class strings here plus a fourth in SettingsModal
 * that had already drifted - a different background, a different radius - even
 * though all four are the same kind of control. One constant, exported so the
 * buffer button in the slot above can use the same one instead of a copy.
 *
 * Fully rounded because these are actions on a status readout rather than form
 * submits; the pill is what separates them from the panel's rows of facts
 * without needing a border to do it.
 */
export const DRIVER_ACTION_BUTTON_CLASS =
  'flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium transition-colors '
  + 'bg-primary text-primary-foreground hover:bg-primary/90 '
  + 'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-primary cursor-pointer';

export const DriverInfoPanel: React.FC<DriverInfoPanelProps> = ({
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  captureStats,
  droppedBuffer = 0,
  linkContext,
  linkChanges = [],
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  agentLinkEnabled,
  agentHealth,
  onStartAgentService,
  onShowUpdates,
  agentError,
  onConnect,
  onDisconnect,
  onRestartAgent,
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

  const listening = agentInterfaces.filter((i) => selectedInterfaces.includes(i.name));

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
  const noInterfaces = agentLinkEnabled
    && agentStatus === 'connected'
    && agentInterfaces.length === 0;

  return (
    <div className="flex flex-col gap-4 min-h-0">
      {agentLinkEnabled && diagnosis && (
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
        <div className="text-xs font-semibold text-foreground mb-2">Driver</div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
          <dt className="text-muted-foreground">Status</dt>
          <dd className={`font-mono font-semibold ${
            agentLinkEnabled ? AGENT_STATUS_COLOR[agentStatus] : 'text-muted-foreground'
          }`}>
            {agentLinkEnabled ? AGENT_STATUS_LABEL[agentStatus] : 'Disconnected (by you)'}
          </dd>

          <dt className="text-muted-foreground">Version</dt>
          <dd className="font-mono flex items-center gap-2">
            <span>{agentVersion ?? '—'}</span>
            {agentOutdated && (
              <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400">
                Update
              </span>
            )}
          </dd>

          <dt className="text-muted-foreground">Capture</dt>
          {/* "Not capturing" rather than "Idle": idle describes the driver,
              and the driver is never idle - it is a service that is always up.
              What this row actually reports is whether it is sniffing right
              now, so both of its values now say that. */}
          <dd className="font-mono">{agentCaptureState === 'sniffing' ? 'Sniffing' : 'Not capturing'}</dd>

          {/* Loss is reported here, in full and in one place. "Unknown" for
              the driver's count means the agent could not read pcap's
              statistics on this adapter - it is not a zero, and is never shown
              as one. */}
          {captureStats && (
            <>
              <dt className="text-muted-foreground">Received</dt>
              <dd className="font-mono">{captureStats.received.toLocaleString()}</dd>
              <dt className="text-muted-foreground">Dropped by driver</dt>
              <dd className={`font-mono ${captureStats.droppedKernel ? 'text-amber-600 dark:text-amber-400' : ''}`}>
                {captureStats.droppedKernel === null ? 'Unknown' : captureStats.droppedKernel.toLocaleString()}
              </dd>
              <dt className="text-muted-foreground">Dropped by agent</dt>
              <dd className={`font-mono ${captureStats.droppedAgent ? 'text-amber-600 dark:text-amber-400' : ''}`}>
                {captureStats.droppedAgent.toLocaleString()}
              </dd>
            </>
          )}

          {/* Gated on its own count rather than on captureStats: the buffer
              fills during an import too, when there is no agent to have
              reported anything. */}
          {droppedBuffer > 0 && (
            <>
              <dt className="text-muted-foreground">Dropped from buffer</dt>
              <dd className="font-mono text-amber-600 dark:text-amber-400">
                {droppedBuffer.toLocaleString()}
              </dd>
            </>
          )}

          {/* What the ENGINE believes about the link, kept visibly apart from
              the counts above, which the capture measured. These are estimates
              Chromium derives from its own recent requests and rounds to resist
              fingerprinting: context for reading a capture, never a measurement
              of one, which is what the label has to keep saying. The agent
              could report the adapter's negotiated speed instead, and that
              would be a measurement - it does not yet. */}
          {linkContext && describeLink(linkContext) && (
            <>
              <dt className="text-muted-foreground">Link (estimated)</dt>
              <dd className="font-mono">{describeLink(linkContext)}</dd>
            </>
          )}

          {/* The half that actually explains a capture. A machine changing
              network is what a gap with no frames, a burst of ARP and DHCP, or
              a stream that stops dead all look like from the inside. */}
          {linkChanges.length > 0 && (
            <>
              <dt className="text-muted-foreground">Network changed</dt>
              <dd className="font-mono text-amber-600 dark:text-amber-400">
                {linkChanges.length}&times;
                <span className="text-muted-foreground">
                  {' '}(last: {describeLink(linkChanges[linkChanges.length - 1].before) || 'unknown'}
                  {' → '}
                  {describeLink(linkChanges[linkChanges.length - 1].after) || 'unknown'})
                </span>
              </dd>
            </>
          )}

          <dt className="text-muted-foreground">Listening on</dt>
          <dd className="font-mono">
            {listening.length === 0 ? (
              <span className="text-muted-foreground">No interfaces selected</span>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {listening.map((i) => (
                  <li key={i.name} className="truncate" title={i.name}>{i.label}</li>
                ))}
              </ul>
            )}
          </dd>

          <dt className="text-muted-foreground">Log file</dt>
          <dd className="font-mono text-muted-foreground break-all">{logFilePath()}</dd>
        </dl>

        {/* Disabled states here are correctness, not polish. Restart is a
            command sent down the socket, so it is unreachable without one -
            offering it while disconnected would look like it did nothing. */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            onClick={onConnect}
            disabled={agentLinkEnabled}
            title={agentLinkEnabled ? 'Already connected' : 'Reconnect to the driver'}
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <Plug className="w-3.5 h-3.5" />
            <span>Connect</span>
          </button>

          <button
            onClick={onDisconnect}
            disabled={!agentLinkEnabled}
            title={
              agentLinkEnabled
                ? 'Close the link. The driver stops capturing when its last client leaves.'
                : 'Already disconnected'
            }
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <Unplug className="w-3.5 h-3.5" />
            <span>Disconnect</span>
          </button>

          <button
            onClick={onRestartAgent}
            disabled={agentStatus !== 'connected'}
            title={
              agentStatus === 'connected'
                ? 'Restart the driver service. It comes back on its own in a few seconds.'
                : 'Needs a live connection to the driver'
            }
            className={DRIVER_ACTION_BUTTON_CLASS}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Restart Driver</span>
          </button>
        </div>

        {/* A refused restart has no other visible outcome - without this the
            button reads as broken rather than as declined for a reason. */}
        {agentError && (
          <div className="mt-2 px-2.5 py-2 rounded-md text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-400">
            {agentError}
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
