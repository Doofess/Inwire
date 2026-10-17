import { useEffect, useRef, useState } from 'react';
import { Download, Loader2 } from 'lucide-react';
import type { MonitoringClient } from '../../services/monitoring/client';
import type { MonitoringState } from '../../services/monitoring/state';
import { LIMITS, type HistoryResult, type HistoryTable, type QueryFocus, type QuerySpec, type SourceConfig } from '../../services/monitoring/types';
import { ExportCancelled, exportHistory, historyCsvName } from '../../services/monitoring/export';
import { isByteSink, openSaveSink } from '../../lib/saveSink';
import { formatBytes } from '../../lib/formatBytes';
import { useElementSize } from '../../lib/useElementSize';
import { count, engineLabel, localRange } from './monitoringCopy';
import { HistoryChart, type Measure } from './HistoryChart';
import { Focus } from './Focus';
import { BUTTON_SECONDARY, Note } from './parts';

const PRESETS = [
  { label: '15 min', ms: 15 * 60_000 },
  { label: '1 h', ms: 3_600_000 },
  { label: '6 h', ms: 6 * 3_600_000 },
  { label: '24 h', ms: 24 * 3_600_000 },
  { label: '7 d', ms: 7 * 24 * 3_600_000 },
] as const;

/** How often the history is asked again while the sheet is on screen. */
const REFRESH_MS = 5000;

type Saving = { kind: 'idle' } | { kind: 'saving' } | { kind: 'saved'; path: string } | { kind: 'cancelled' }
  | { kind: 'failed'; message: string };

/**
 * Received traffic records over a range: the bars, the gaps, and the top
 * endpoints and conversations, all "reported by the exporter".
 *
 * Asked again every few seconds while the document is visible, under one view
 * id so a slow answer is superseded rather than queued; a selection's focused
 * query is the second id, so at most two are ever in flight.
 */
export function History({ client, state, config, onFilterCapture }: {
  client: MonitoringClient;
  state: MonitoringState;
  config: SourceConfig | null;
  onFilterCapture: (expression: string) => void;
}) {
  const sources = state.sources;
  const [chosen, setChosen] = useState<string | null>(null);
  const sourceKey = chosen !== null && sources.includes(chosen) ? chosen : sources[0] ?? null;
  const [preset, setPreset] = useState(1);
  const [measure, setMeasure] = useState<Measure>('octets');
  const [result, setResult] = useState<HistoryResult | null>(null);
  const [failure, setFailure] = useState<{ code: string; message: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(0);
  const [focus, setFocus] = useState<{ focus: QueryFocus; spec: QuerySpec } | null>(null);
  const [saving, setSaving] = useState<Saving>({ kind: 'idle' });
  const abort = useRef<AbortController | null>(null);
  const chartBox = useRef<HTMLDivElement>(null);
  const { width } = useElementSize(chartBox);
  const bucketCount = Math.max(12, Math.min(LIMITS.buckets, Math.floor(width / 10)));
  const connected = state.runtime === 'connected';

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') setTick((t) => t + 1);
    }, REFRESH_MS);
    return () => window.clearInterval(timer);
  }, []);

  const specFor = (key: string): QuerySpec => {
    const toMs = Date.now();
    return { sourceKey: key, fromMs: toMs - PRESETS[preset].ms, toMs, bucketCount };
  };

  useEffect(() => {
    if (!connected || sourceKey === null || width <= 0) return;
    let live = true;
    setLoading(true);
    void client.query('monitoring-history', specFor(sourceKey)).then((reply) => {
      if (!live) return;
      setLoading(false);
      if (reply.ok) { setResult(reply.value); setFailure(null); return; }
      if (reply.code === 'cancelled' || reply.code === 'stale-generation') return; // the next tick asks again
      setFailure({ code: reply.code, message: reply.message });
    });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, connected, sourceKey, preset, bucketCount, tick, width > 0]);

  // A new source or range clears what the old one answered.
  useEffect(() => { setResult(null); setFailure(null); setFocus(null); }, [sourceKey, preset]);
  useEffect(() => () => abort.current?.abort(), []);

  const select = (next: QueryFocus) => {
    if (sourceKey === null) return;
    const same = focus !== null && JSON.stringify(focus.focus) === JSON.stringify(next);
    setFocus(same ? null : { focus: next, spec: specFor(sourceKey) });
  };

  const save = async () => {
    if (!result) return;
    setSaving({ kind: 'saving' });
    const sink = await openSaveSink(historyCsvName(result));
    if (!isByteSink(sink)) {
      setSaving('canceled' in sink ? { kind: 'cancelled' } : { kind: 'failed', message: sink.error });
      return;
    }
    const controller = new AbortController();
    abort.current = controller;
    try {
      const outcome = await exportHistory(result, sink, { signal: controller.signal });
      if (outcome.saved) setSaving({ kind: 'saved', path: outcome.path });
      else setSaving(outcome.canceled ? { kind: 'cancelled' } : { kind: 'failed', message: outcome.error });
    } catch (e) {
      setSaving(e instanceof ExportCancelled ? { kind: 'cancelled' } : { kind: 'failed', message: String(e) });
    } finally {
      abort.current = null;
    }
  };

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      {sources.length > 1 && (
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          Source
          <select value={sourceKey ?? ''} onChange={(e) => setChosen(e.target.value)}
            className="h-7 rounded-md border border-input bg-background px-1.5 text-xs text-foreground
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            {sources.map((s) => <option key={s} value={s}>{engineLabel(s)}</option>)}
          </select>
        </label>
      )}
      {sources.length === 1 && <span className="text-xs text-muted-foreground">{engineLabel(sources[0])}</span>}
      <Segmented label="Range" value={preset} options={PRESETS.map((p, i) => ({ value: i, label: p.label }))} onChange={setPreset} />
      <Segmented label="Measure" value={measure}
        options={[{ value: 'octets' as const, label: 'Bytes' }, { value: 'packets' as const, label: 'Packets' }]}
        onChange={setMeasure} />
    </div>
  );

  if (sources.length === 0) {
    return (
      <div className="space-y-3">
        <div ref={chartBox} className="h-0" />
        <EmptyHistory config={config} state={state} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {toolbar}
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-3.5 w-3.5 text-muted-foreground motion-safe:animate-spin" aria-label="Reading" />}
          <button type="button" className={BUTTON_SECONDARY} disabled={!result || saving.kind === 'saving'}
            onClick={() => void save()}>
            <Download className="h-3.5 w-3.5" aria-hidden />
            {saving.kind === 'saving' ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>
      <SaveLine saving={saving} />

      <div ref={chartBox} className="min-w-0">
        {failure ? (
          <Note tone={failure.code === 'range-too-large' ? 'warn' : 'bad'} role="alert"
            title={failure.code === 'range-too-large' ? 'That range is too large to read' : 'The history could not be read'}>
            <p>{failure.message}</p>
            {failure.code === 'range-too-large' && <p className="text-muted-foreground">Choose a shorter range.</p>}
          </Note>
        ) : result ? (
          <HistoryChart buckets={result.buckets} measure={measure} width={width} />
        ) : (
          <div className="flex h-[200px] items-center justify-center gap-1.5 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 motion-safe:animate-spin" aria-hidden />Reading the history…
          </div>
        )}
      </div>

      {result && !failure && (
        <>
          <Facts result={result} />
          {result.gaps.length > 0 && <Gaps gaps={result.gaps} />}
          {focus && (
            <Focus client={client} spec={focus.spec} focus={focus.focus} onClear={() => setFocus(null)}
              onFilterCapture={onFilterCapture} />
          )}
          <div className="grid gap-4 @3xl:grid-cols-2">
            <TopTable title="Top endpoints" table={result.endpoints} leftColumns={1}
              head={['Address', 'Sent', 'Received']}
              rows={(rows) => rows.map((r) => ({
                key: r.address,
                selected: focus?.focus.kind === 'endpoint' && focus.focus.address === r.address,
                onSelect: () => select({ kind: 'endpoint', address: r.address }),
                cells: [<span className="font-mono">{r.address}</span>, formatBytes(Number(r.sentOctets)), formatBytes(Number(r.receivedOctets))],
              }))} />
            <TopTable title="Top conversations" table={result.conversations} leftColumns={2}
              head={['Source', 'Destination', measure === 'octets' ? 'Bytes' : 'Packets']}
              rows={(rows) => rows.map((r) => ({
                key: `${r.srcAddr}>${r.dstAddr}`,
                selected: focus?.focus.kind === 'conversation' && focus.focus.srcAddr === r.srcAddr && focus.focus.dstAddr === r.dstAddr,
                onSelect: () => select({ kind: 'conversation', srcAddr: r.srcAddr, dstAddr: r.dstAddr }),
                cells: [<span className="font-mono">{r.srcAddr}</span>, <span className="font-mono">{r.dstAddr}</span>,
                  measure === 'octets' ? formatBytes(Number(r.reportedOctets)) : count(r.reportedPackets)],
              }))} />
          </div>
        </>
      )}
    </div>
  );
}

function Segmented<T extends string | number>({ label, value, options, onChange }: {
  label: string; value: T; options: { value: T; label: string }[]; onChange: (v: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-md border border-border bg-secondary p-0.5">
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button key={String(o.value)} type="button" role="radio" aria-checked={on} onClick={() => onChange(o.value)}
            className={`h-6 rounded-[5px] px-2 text-xs tabular-nums cursor-pointer transition-colors
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring
              ${on ? 'bg-background font-semibold text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}`}>
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function SaveLine({ saving }: { saving: Saving }) {
  if (saving.kind === 'idle' || saving.kind === 'saving') return null;
  const text = saving.kind === 'saved' ? `Saved to ${saving.path}`
    : saving.kind === 'cancelled' ? 'Export cancelled. Nothing was saved.'
      : `Not saved: ${saving.message}`;
  return (
    <p role={saving.kind === 'failed' ? 'alert' : 'status'}
      className={`-mt-2 break-all text-xs ${saving.kind === 'failed' ? 'text-danger' : 'text-muted-foreground'}`}>{text}</p>
  );
}

function Facts({ result }: { result: HistoryResult }) {
  const { rollupMinutes, rawMinutes } = result.answeredFrom;
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-1 text-[11px] tabular-nums text-muted-foreground">
      <span>{count(result.matchingRecords)} received traffic records in {localRange(result.query.fromMs, result.query.toMs)}</span>
      <span>{result.samplingKnown ? 'Sampling reported for every record; counters are not scaled'
        : 'Sampling unknown for some records; counters are not scaled'}</span>
      {result.malformed > 0 && <span className="text-warning">{count(result.malformed)} malformed</span>}
      {result.unsupported > 0 && <span className="text-warning">{count(result.unsupported)} unsupported (not v5)</span>}
      <span title="Minutes answered from the summaries, and from the journal itself">
        read from {count(rollupMinutes)} summarised and {count(rawMinutes)} raw minutes
      </span>
    </div>
  );
}

function Gaps({ gaps }: { gaps: HistoryResult['gaps'] }) {
  return (
    <details className="group rounded-md border border-border bg-card px-3.5 py-2 text-xs">
      <summary className="cursor-pointer text-foreground marker:text-muted-foreground focus-visible:outline-none
        focus-visible:ring-2 focus-visible:ring-ring rounded-sm">
        {gaps.length === 1 ? '1 period' : `${count(gaps.length)} periods`} not collected
      </summary>
      <ul className="mt-2 space-y-1 tabular-nums">
        {gaps.map((g, i) => (
          <li key={i} className="flex flex-wrap justify-between gap-x-3">
            <span>{localRange(g.fromMs, g.toMs)}</span>
            <span className="text-muted-foreground">{g.reason}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

interface RowView { key: string; selected: boolean; onSelect: () => void; cells: React.ReactNode[] }

function TopTable<Row>({ title, table, head, rows, leftColumns }: {
  title: string; table: HistoryTable<Row>; leftColumns: number;
  head: string[]; rows: (rows: Row[]) => RowView[];
}) {
  return (
    <div className="min-w-0 overflow-hidden rounded-md border border-border bg-card">
      <h3 className="border-b border-border px-3 py-2 text-xs font-semibold text-foreground">{title}</h3>
      {table.status === 'range-too-large' ? (
        <p className="px-3 py-3 text-xs text-muted-foreground">{table.message} Choose a shorter range to see this table.</p>
      ) : table.rows.length === 0 ? (
        <p className="px-3 py-3 text-xs text-muted-foreground">No records in this range.</p>
      ) : (
        <table className="w-full table-fixed text-xs tabular-nums">
          <thead className="text-[11px] text-muted-foreground">
            <tr>
              {head.map((h, i) => (
                <th key={h} scope="col" className={`px-3 py-1.5 font-semibold ${i < leftColumns ? 'text-left' : 'text-right'}`}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows(table.rows).map((r) => (
              <tr key={r.key} aria-selected={r.selected}
                className={`border-t border-border ${r.selected ? 'bg-selection' : 'hover:bg-accent/60'}`}>
                {r.cells.map((c, i) => (
                  <td key={i} className={`truncate px-3 py-1 ${i < leftColumns ? 'text-left' : 'text-right'}`}>
                    {i === 0 ? (
                      <button type="button" onClick={r.onSelect} aria-pressed={r.selected}
                        className="max-w-full truncate rounded-sm text-left text-foreground hover:underline cursor-pointer
                          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                        {c}
                      </button>
                    ) : c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function EmptyHistory({ config, state }: { config: SourceConfig | null; state: MonitoringState }) {
  const bind = config?.bindIPv4 ?? '<this PC’s address>';
  const port = config?.port ?? 2055;
  const listening = state.intake?.listener === 'listening';
  return (
    <div className="space-y-3 rounded-md border border-dashed border-border px-4 py-4">
      <p className="text-[13px] text-foreground">
        {listening ? 'No received traffic records yet.' : 'No history yet.'}
      </p>
      <p className="max-w-[38rem] text-xs leading-relaxed text-muted-foreground">
        Inwire collects NetFlow version 5 over UDP and IPv4 only. NetFlow v9, IPFIX and sFlow arrive and are counted as
        unsupported. Point the exporter at <span className="font-mono text-foreground">{bind}:{port}</span>:
      </p>
      <dl className="space-y-2 text-xs">
        <div>
          <dt className="mb-1 text-muted-foreground">From WSL on this PC</dt>
          <dd><Code>{`softflowd -i eth0 -n ${bind}:${port} -v 5`}</Code></dd>
        </div>
        <div>
          <dt className="mb-1 text-muted-foreground">On a Cisco IOS router</dt>
          <dd><Code>{`ip flow-export destination ${bind} ${port}\nip flow-export version 5`}</Code></dd>
        </div>
      </dl>
    </div>
  );
}

function Code({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded-md border border-border bg-muted px-2.5 py-1.5 font-mono text-[11px] leading-relaxed text-foreground">
      {children}
    </pre>
  );
}
