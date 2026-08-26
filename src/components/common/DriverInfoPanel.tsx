import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { TbTrash } from 'react-icons/tb';
import type { AgentLogEntry } from '../../services/agentProtocol';
import { detectOS } from '../../services/platformDetect';

interface DriverInfoPanelProps {
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  onSubscribe: () => void;
  onUnsubscribe: () => void;
  onClearLog: () => void;
}

const AGENT_STATUS_LABEL: Record<DriverInfoPanelProps['agentStatus'], string> = {
  connected: 'Running',
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
function logFilePath(): string {
  return detectOS() === 'windows'
    ? '%ProgramData%\\NetView\\agent.log'
    : '~/.netview/agent.log';
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

export const DriverInfoPanel: React.FC<DriverInfoPanelProps> = ({
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  onSubscribe,
  onUnsubscribe,
  onClearLog,
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

  return (
    <div className="flex flex-col gap-4 min-h-0">
      <div>
        <div className="text-xs font-semibold text-foreground mb-2">Agent</div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
          <dt className="text-muted-foreground">Status</dt>
          <dd className={`font-mono font-semibold ${AGENT_STATUS_COLOR[agentStatus]}`}>
            {AGENT_STATUS_LABEL[agentStatus]}
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
          <dd className="font-mono">{agentCaptureState === 'sniffing' ? 'Sniffing' : 'Idle'}</dd>

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
      </div>

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
            <TbTrash className="w-3.5 h-3.5" />
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
                : 'Waiting for the agent to connect…'}
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
