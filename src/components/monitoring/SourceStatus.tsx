import { useEffect, useState } from 'react';
import { AlertTriangle, Ban, Clock } from 'lucide-react';
import { nothingArriving, type MonitoringState } from '../../services/monitoring/state';
import type { EngineHealth } from '../../services/monitoring/sourceHealth';
import type { SourceConfig } from '../../services/monitoring/types';
import { formatBytes } from '../../lib/formatBytes';
import { count, localTime, MONITORING_FOLDER, stopReasonText, type Tone } from './monitoringCopy';
import { Fact, Note, ToneDot } from './parts';

/**
 * Where collection is, as three rows that fail independently: the listener
 * (is the socket open?), the source (is the exporter sending?) and storage (is
 * the history being written?). One can be wrong while the others are fine, so
 * none of them is folded into another.
 *
 * `nothingArriving` is a pure function of the state and the clock, and the
 * state does not change while nothing arrives - so this re-reads the clock once
 * a second while listening, or the 60-second note would never appear.
 */
export function SourceStatus({ state, config }: { state: MonitoringState; config: SourceConfig | null }) {
  const intake = state.intake;
  const health = state.health;
  const listening = intake?.listener === 'listening';
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!listening) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [listening]);

  if (intake === null) {
    return <p className="text-xs text-muted-foreground">Waiting for the collector’s first status…</p>;
  }

  const source = intake.source ?? config;
  const listenerRow = listenerLine(state);
  const stale = health?.freshness === 'stale';
  const quiet = nothingArriving(state, now);
  // Listener, storage, the refused senders and the shed count are the intake's: in the
  // Worker's health those fields keep their defaults.
  const rejected = intake.rejectedSenders;
  const rejectedOverflow = intake.rejectedOverflow;

  return (
    <div className="space-y-3">
      <dl className="divide-y divide-border overflow-hidden rounded-md border border-border bg-card">
        <Row title="Listener" tone={listenerRow.tone} line={listenerRow.text}>
          {source && (
            <Fact label="Address">
              <span className="font-mono">{source.bindIPv4}:{source.port}</span>
            </Fact>
          )}
          {intake.stopReason === 'storage-limit' && (
            <p className="text-xs leading-relaxed text-muted-foreground">
              Raise the storage limit under Source, then press Start. The history already kept stays.
            </p>
          )}
        </Row>

        <Row title="Source" tone={sourceTone(state)} line={sourceLine(state)}>
          {source && <Fact label="Exporter"><span className="font-mono">{source.exporterIPv4}</span></Fact>}
          {health && (
            <>
              <Fact label="Accepted">{count(health.accepted)}</Fact>
              {health.engines.length > 0 && <Engines engines={health.engines} />}
              <Fact label="Transport loss" title="UDP drops in the network or the kernel are never reported to Inwire">
                unknown
              </Fact>
              <p className="text-[11px] leading-snug text-muted-foreground">
                Loss on the way here is not reported by Windows, so it is never counted. Sequence jumps show where the
                exporter’s numbering skipped, which a late datagram may still fill.
              </p>
              <Counters items={[
                ['Malformed', health.malformed],
                ['Data sets waiting for a template', health.templateSources.reduce((n, t) => n + t.awaitingSets, 0)],
                ['Unsupported version', health.unsupported],
                ['Past the engine limit', health.engineLimitRejected],
              ]} />
            </>
          )}
          <Counters items={[['Shed before writing', intake.shedDatagrams]]} />
        </Row>

        <Row title="Storage" tone={storageTone(state)} line={storageLine(state)}>
          <StorageMeter state={state} config={source} />
          {intake.storage === 'refused-corrupt' && (
            <p className="text-xs leading-relaxed text-muted-foreground">
              To start a new history, quit Inwire and move the folder{' '}
              <span className="font-mono text-foreground">{MONITORING_FOLDER}</span> aside. Inwire does not delete it.
            </p>
          )}
        </Row>
      </dl>

      {listening && quiet && !stale && source && (
        <Note tone="warn" icon={<Clock className="h-4 w-4" />} title="Nothing has arrived for a minute" role="note">
          <p>Two things stop exports reaching Inwire:</p>
          <ul className="list-disc space-y-1 pl-4">
            <li>
              Windows Defender Firewall is blocking Inwire. If Cancel was chosen when Windows asked, an administrator
              has to remove the block rule for Inwire there.
            </li>
            <li>
              The exporter is sending somewhere else. It has to send to{' '}
              <span className="font-mono">{source.bindIPv4}:{source.port}</span>, as NetFlow v5, v9 or IPFIX.
            </li>
          </ul>
        </Note>
      )}

      {rejected.length > 0 && source && (
        <Note tone="warn" icon={<Ban className="h-4 w-4" />} title="Refused senders" role="note">
          <p>These addresses sent exports and were refused — only <span className="font-mono">{source.exporterIPv4}</span> is accepted.</p>
          <ul className="space-y-0.5">
            {rejected.map((r) => (
              <li key={r.address} className="flex justify-between gap-3 tabular-nums">
                <span className="font-mono">{r.address}</span>
                <span className="text-muted-foreground">{count(r.count)} {r.count === 1 ? 'datagram' : 'datagrams'}</span>
              </li>
            ))}
            {rejectedOverflow > 0 && (
              <li className="text-muted-foreground">and {count(rejectedOverflow)} from further addresses</li>
            )}
          </ul>
          <p className="text-muted-foreground">If one of them is the exporter, put its address under Source.</p>
        </Note>
      )}
    </div>
  );
}

function Row({ title, tone, line, children }: {
  title: string; tone: Tone; line: string; children?: React.ReactNode;
}) {
  return (
    <div className="space-y-2 px-3.5 py-3">
      <div className="flex items-baseline gap-3">
        <dt className="w-16 shrink-0 text-xs font-semibold text-foreground">{title}</dt>
        <dd className="flex min-w-0 items-start gap-1.5 text-xs text-foreground">
          <ToneDot tone={tone} className="mt-[5px]" />
          <span className="min-w-0 break-words">{line}</span>
        </dd>
      </div>
      {children && <div className="space-y-1.5 sm:pl-[4.75rem]">{children}</div>}
    </div>
  );
}

function listenerLine(state: MonitoringState): { text: string; tone: Tone } {
  const intake = state.intake!;
  switch (intake.listener) {
    case 'starting': return { text: 'Starting…', tone: 'progress' };
    case 'listening': return { text: 'Listening', tone: 'good' };
    case 'failed': return { text: `Could not listen: ${intake.listenerError ?? 'no reason was given'}`, tone: 'bad' };
    default: {
      const text = stopReasonText(intake.stopReason, intake.listenerError ?? intake.storageError) ?? 'Not started.';
      const bad = intake.stopReason === 'socket-error' || intake.stopReason === 'storage-failed'
        || intake.stopReason === 'storage-limit';
      return { text, tone: bad ? 'bad' : 'neutral' };
    }
  }
}

/**
 * The Worker's health starts again at every connect, so after a page reload it says `never` until the
 * next datagram. The utility's own count does not reset, and `monitoringSummary` already falls back to it.
 */
function receivedBeforeHealth(state: MonitoringState): boolean {
  const h = state.health;
  return (!h || h.freshness === 'never') && (state.intake?.received ?? 0) > 0;
}

function sourceLine(state: MonitoringState): string {
  const h = state.health;
  if (receivedBeforeHealth(state)) return 'Receiving';
  if (!h || h.freshness === 'never') return 'Nothing received from the exporter yet';
  if (h.freshness === 'stale') return 'No recent export — nothing for over a minute';
  return h.lastValidWallMs === null ? 'Receiving' : `Last export ${localTime(h.lastValidWallMs)}`;
}

function sourceTone(state: MonitoringState): Tone {
  const h = state.health;
  if (receivedBeforeHealth(state)) return 'good';
  if (!h || h.freshness === 'never') return 'neutral';
  return h.freshness === 'stale' ? 'warn' : 'good';
}

function storageLine(state: MonitoringState): string {
  const intake = state.intake!;
  const s = intake.storage;
  const err = intake.storageError;
  switch (s) {
    case 'unopened': return 'Not opened yet';
    case 'open': return intake.listener === 'listening' ? 'Writing' : 'Ready';
    case 'storage-limit': return 'Full: the storage limit is reached';
    case 'refused-corrupt': return `Refused: the history is damaged${err ? ` — ${err}` : ''}`;
    case 'refused-version': return `Refused: the history was written by another version of Inwire${err ? ` — ${err}` : ''}`;
    case 'failed': return `Failed: ${err ?? 'no reason was given'}`;
    case 'closed': return 'Closed';
  }
}

function storageTone(state: MonitoringState): Tone {
  const s = state.intake!.storage;
  if (s === 'open') return state.intake!.listener === 'listening' ? 'good' : 'neutral';
  if (s === 'unopened' || s === 'closed') return 'neutral';
  return 'bad';
}

function StorageMeter({ state, config }: { state: MonitoringState; config: SourceConfig | null }) {
  const written = state.intake?.snapshot?.writtenBytes ?? null;
  const limit = config?.storageLimitBytes ?? null;
  if (written === null || limit === null) return null;
  const share = Math.min(1, written / limit);
  const pct = share * 100;
  const fill = share >= 1 ? 'bg-danger' : share >= 0.9 ? 'bg-warning' : 'bg-primary';
  return (
    <div className="space-y-1">
      <div role="meter" aria-label="History storage used" aria-valuemin={0} aria-valuemax={limit} aria-valuenow={written}
        aria-valuetext={`${formatBytes(written)} of ${formatBytes(limit)}`}
        className="h-1.5 overflow-hidden rounded-full bg-muted">
        <div className={`h-full rounded-full ${fill}`} style={{ width: `${Math.max(pct, written > 0 ? 0.75 : 0)}%` }} />
      </div>
      <p className="flex justify-between gap-3 text-[11px] tabular-nums text-muted-foreground">
        <span>{formatBytes(written)} of {formatBytes(limit)}</span>
        <span>{pct < 1 && written > 0 ? 'under 1%' : `${Math.floor(pct)}%`}</span>
      </p>
    </div>
  );
}

function Counters({ items }: { items: [string, number][] }) {
  const shown = items.filter(([, n]) => n > 0);
  if (shown.length === 0) return null;
  return (
    <div className="flex items-start gap-1.5 text-xs text-foreground">
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
      <span>{shown.map(([label, n]) => `${label}: ${count(n)}`).join('; ')}</span>
    </div>
  );
}

function Engines({ engines }: { engines: EngineHealth[] }) {
  return (
    <div className="-mx-1 overflow-x-auto">
      <table className="w-full min-w-[30rem] text-left text-[11px] tabular-nums">
        <caption className="sr-only">Engines the exporter reported</caption>
        <thead className="text-muted-foreground">
          <tr>
            <th scope="col" className="px-1 py-1 font-semibold">Engine</th>
            {['Accepted', 'Sequence jumps', 'Gaps', 'Duplicates', 'Reordered', 'Resets', 'Unresolved'].map((h) => (
              <th key={h} scope="col" className="px-1 py-1 text-right font-semibold">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="text-foreground">
          {engines.map((e) => (
            <tr key={e.sourceKey} className="border-t border-border">
              <th scope="row" className="px-1 py-1 font-mono font-normal">{e.engineType}/{e.engineId}</th>
              {[e.accepted, e.jumpedFlows, e.gaps, e.duplicates, e.reordered, e.resets, e.unresolved].map((n, i) => (
                <td key={i} className={`px-1 py-1 text-right ${n > 0 && i > 0 ? 'font-semibold text-warning' : ''}`}>
                  {count(n)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
