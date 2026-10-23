import { useEffect, useRef, useState } from 'react';
import { ChevronRight, Loader2, RefreshCw } from 'lucide-react';
import { getMonitoringClient } from '../../services/monitoring/appClient';
import type { SourceConfig } from '../../services/monitoring/types';
import type { RuntimeExit } from '../../services/monitoring/control';
import { useMonitoring } from '../../hooks/useMonitoring';
import { PaneHeader } from '../common/PaneHeader';
import { count, monitoringSummary } from './monitoringCopy';
import { SourceForm } from './SourceForm';
import { SourceStatus } from './SourceStatus';
import { History } from './History';
import { ExporterDetail } from './ExporterDetail';
import { Onboarding } from './Onboarding';
import { Block, Note, ToneDot } from './parts';

/**
 * Monitoring's sheet (ADRs 0058-0060, 0064-0066): one exporter's received
 * traffic records, kept as a history on this PC.
 *
 * A sheet by the same rules as Settings and the speed test - the view
 * underneath is untouched, and Back, Escape or any view leaves it. Leaving
 * does not stop collection and does not reset the client: the client is the
 * module's (`getMonitoringClient`), and this only reads it. Opening it the
 * first time is what connects, because main sends no monitoring status until
 * the history has been asked for.
 */
export function MonitoringSheet({ onFilterCapture }: { onFilterCapture: (expression: string) => void }) {
  const client = getMonitoringClient();
  const state = useMonitoring();
  const [config, setConfig] = useState<SourceConfig | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const listening = state.intake?.listener === 'listening';

  useEffect(() => { void client.ensureConnected(); }, [client]);
  useEffect(() => {
    if (!listening) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [listening]);

  const summary = monitoringSummary(state, now);
  const announced = useAnnouncement(summary.text);
  const rebuild = state.rebuild;

  return (
    <div className="flex h-full flex-col bg-background font-sans motion-sheet" data-testid="monitoring-sheet">
      <PaneHeader title="Monitoring" detail={
        <span className="inline-flex items-center gap-1.5 font-sans font-semibold normal-case">
          <ToneDot tone={summary.tone} />{summary.text}
        </span>
      } />
      <div className="sr-only" role="status" aria-live="polite">{announced}</div>
      <div className="flex-1 overflow-y-auto">
        <div className="@container mx-auto flex w-full max-w-[80rem] flex-col gap-7 px-6 py-7">
          <header className="max-w-[44rem] space-y-1.5">
            <h1 className="text-lg font-semibold text-foreground">Received traffic records</h1>
            <p className="text-xs leading-relaxed text-muted-foreground">
              What one router or switch reports about the traffic it forwarded, sent to this PC as NetFlow v5, v9 or IPFIX.
              Every number here is reported by the exporter, not measured by Inwire. The history is kept on this PC,
              and collection goes on while this sheet is closed.
            </p>
          </header>

          {state.runtime === 'connecting' && (
            <Note icon={<Loader2 className="h-4 w-4 motion-safe:animate-spin" />} title="Opening the history…">
              <p>A large history can take up to a couple of minutes to open. Collection does not wait for it.</p>
            </Note>
          )}
          {state.runtime === 'unavailable' && (
            <Note tone="bad" role="alert" title="Monitoring is not available">
              <p>{state.problem ?? 'The monitoring process stopped.'}</p>
              {state.exit && <p className="text-muted-foreground">{exitText(state.exit)}</p>}
              <button type="button" onClick={() => void client.ensureConnected()}
                className="mt-1 text-xs font-semibold text-primary hover:underline cursor-pointer rounded-sm
                  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                Try again
              </button>
            </Note>
          )}
          {rebuild?.phase === 'rebuilding' && (
            <Note icon={<RefreshCw className="h-4 w-4 motion-safe:animate-spin" />} title="Rebuilding summaries — answers read more of the journal until done">
              <p className="tabular-nums text-muted-foreground">
                {count(Math.max(0, rebuild.fedThroughEntryId))} of {count(Math.max(0, rebuild.targetEntryId))} entries
              </p>
            </Note>
          )}
          {rebuild?.phase === 'failed' && (
            <Note tone="bad" role="alert" title="The summaries could not be built">
              <p>{rebuild.message ?? 'No reason was given.'} Health still updates; the history reads the journal directly.</p>
            </Note>
          )}

          <div className="grid gap-7 @4xl:grid-cols-[minmax(18rem,22rem)_1fr]">
            <Block title="Source" labelId="monitoring-source">
              <SourceForm client={client} state={state} onConfig={setConfig} />
            </Block>
            <Block title="Status" labelId="monitoring-status">
              <SourceStatus state={state} config={config} />
            </Block>
          </div>

          {state.exporters.length > 0 && (
            <Block title="Exporter" labelId="monitoring-exporter">
              <ExporterDetail exporters={state.exporters} rows={state.health?.templateSources ?? []} />
            </Block>
          )}

          <Block title="History" labelId="monitoring-history">
            {state.runtime === 'connected' || state.sources.length > 0 ? (
              <History client={client} state={state} config={config} onFilterCapture={onFilterCapture} />
            ) : (
              <p className="text-xs text-muted-foreground">The history is read once it has opened.</p>
            )}
          </Block>

          {/* The empty history carries these itself; once there is one, they fold away below it. */}
          {state.sources.length > 0 && (
            <details className="group" data-testid="monitoring-onboarding">
              <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-[13px] font-semibold text-foreground
                focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground transition-transform group-open:rotate-90" aria-hidden />
                Set up the exporter
              </summary>
              <div className="mt-2.5">
                <Onboarding address={config?.bindIPv4 ?? null} port={config?.port ?? 2055} />
              </div>
            </details>
          )}
        </div>
      </div>
    </div>
  );
}

function exitText(exit: RuntimeExit): string {
  const code = exit.code === null ? '' : ` (exit code ${exit.code})`;
  return `${exit.message}${code}.${exit.wasRunning ? ' The listener was running: press Start again.' : ''}`;
}

/**
 * The text a polite live region should hold: the summary, but only once it has
 * stayed put for a moment, so a flicker between two states is one announcement
 * and a datagram is never one at all (the summary does not change per datagram).
 */
function useAnnouncement(text: string): string {
  const [said, setSaid] = useState('');
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    const t = window.setTimeout(() => setSaid(text), 600);
    return () => window.clearTimeout(t);
  }, [text]);
  return said;
}
