import { useEffect, useRef, useState } from 'react';
import { Filter, Loader2, RefreshCw, X } from 'lucide-react';
import type { DetailResult, MonitoringClient } from '../../services/monitoring/client';
import type { HistoryResult, QueryFocus, QuerySpec } from '../../services/monitoring/types';
import { count, evidenceExpiredText, localTime } from './monitoringCopy';
import { DatagramDetail } from './DatagramDetail';
import { BUTTON_SECONDARY } from './parts';

/** Reopens in a row before the reply's own message is shown; Refresh starts the count again. */
const MAX_STALE = 3;

/**
 * A selected endpoint or conversation: the same range asked again with a
 * focus, which answers how many records support it and the first hundred of
 * them by reference. A reference opens the datagram it came from.
 *
 * **It is a snapshot.** The history above is asked again every few seconds and
 * this is asked once, at the click, because a focused query reads the journal
 * and costs about a second under load. The line says "as of" and Refresh asks
 * again over the range as it is now.
 *
 * A detail that comes back empty means the reference is no longer in the
 * history the query read (the journal moved on); the list is read again
 * rather than left pointing at nothing.
 */
export function Focus({ client, spec, focus, asOfMs, onRefresh, onClear, onFilterCapture }: {
  client: MonitoringClient;
  /** The history's own query, unfocused. */
  spec: QuerySpec;
  focus: QueryFocus;
  /** When `spec` was taken: the answer is as of then, and Refresh is what moves it. */
  asOfMs: number;
  onRefresh: () => void;
  onClear: () => void;
  onFilterCapture: (expression: string) => void;
}) {
  const [result, setResult] = useState<HistoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState<string | null>(null);
  const [again, setAgain] = useState(0);
  const [reading, setReading] = useState(false);
  const [detail, setDetail] = useState<DetailResult | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const staleRun = useRef(0);
  const key = focus.kind === 'endpoint' ? focus.address : `${focus.srcAddr}>${focus.dstAddr}`;

  useEffect(() => {
    let live = true;
    setError(null);
    setExpired(null);
    setReading(true);
    void client.query('monitoring-focus', { ...spec, focus }).then((reply) => {
      if (!live) return;
      setReading(false);
      if (reply.ok) { staleRun.current = 0; setResult(reply.value); return; }
      // The journal moved between asking and answering: ask again, as the
      // detail path does. Neither is something to show as an error, unless it
      // keeps happening.
      if (reply.code === 'stale-generation') {
        if (++staleRun.current < MAX_STALE) { setAgain((n) => n + 1); return; }
      }
      staleRun.current = 0;
      if (reply.code === 'cancelled') return;
      // Neither note may sit under a list from an older answer.
      setResult(null);
      // Expired evidence is a fact about the range, not a failure: said in the sheet's own words.
      if (reply.code === 'evidence-expired') { setExpired(evidenceExpiredText(reply.expiry ?? null, reply.expiredMs ?? 0)); return; }
      setError(reply.message);
    });
    return () => { live = false; };
    // `spec` is rebuilt per render by its owner; its fields are the dependency.
    // `asOfMs` is one too: a Refresh inside the same minute leaves the spec as it was.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, spec.sourceKey, spec.fromMs, spec.toMs, spec.bucketCount, asOfMs, key, again]);

  // What is being opened, as `key|id`: an answer for anything else is late.
  const wanted = useRef('');
  useEffect(() => { wanted.current = ''; setDetail(null); setNote(null); setResult(null); setOpening(null); }, [key]);

  const open = async (ref: HistoryResult['evidence'][number]) => {
    if (!result) return;
    const id = `${ref.ref.entryId}:${ref.recordIndex}`;
    const mine = `${key}|${id}`;
    wanted.current = mine;
    setOpening(id);
    setNote(null);
    const answer = await client.detail(result.snapshot, ref.ref, ref.recordIndex);
    if (wanted.current !== mine) return;
    setOpening(null);
    if (answer === null) {
      setDetail(null);
      setNote('That reference could not be read; it may have left the history. The list has been read again.');
      setAgain((n) => n + 1);
      return;
    }
    setDetail(answer);
  };

  const title = focus.kind === 'endpoint'
    ? <>Host <span className="font-mono">{focus.address}</span></>
    : <>Conversation <span className="font-mono">{focus.srcAddr}</span> to <span className="font-mono">{focus.dstAddr}</span></>;

  // One button, shown beside whichever answer is up: an expired range or a
  // failure is as much a snapshot as a list.
  const refresh = (
    <button type="button" className={BUTTON_SECONDARY} disabled={reading} onClick={onRefresh}>
      <RefreshCw className={`h-3.5 w-3.5 ${reading ? 'motion-safe:animate-spin' : ''}`} aria-hidden />
      {reading ? 'Refreshing…' : 'Refresh'}
    </button>
  );

  return (
    <section aria-label="Selection" className="space-y-3 rounded-md border border-primary/40 bg-card px-3.5 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-xs font-semibold text-foreground">{title}</h3>
        <div className="flex items-center gap-2">
          {focus.kind === 'endpoint' && (
            <button type="button" className={BUTTON_SECONDARY}
              onClick={() => onFilterCapture(`ip.addr == ${focus.address}`)}>
              <Filter className="h-3.5 w-3.5" aria-hidden />Filter capture by this host
            </button>
          )}
          <button type="button" onClick={onClear} aria-label="Clear the selection"
            className="rounded-sm p-1 text-muted-foreground hover:bg-accent hover:text-foreground cursor-pointer
              focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <X className="h-3.5 w-3.5" aria-hidden />
          </button>
        </div>
      </div>
      {focus.kind === 'endpoint' && (
        <p className="text-[11px] text-muted-foreground">
          The filter applies to the open packet capture, <span className="font-mono">ip.addr == {focus.address}</span>,
          not to this history.
        </p>
      )}
      {error && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p role="alert" className="text-xs text-danger">{error}</p>
          {refresh}
        </div>
      )}
      {expired && !error && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p role="status" className="text-xs leading-relaxed text-muted-foreground">{expired}</p>
          {refresh}
        </div>
      )}
      {!error && !expired && !result && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 motion-safe:animate-spin" aria-hidden />Reading the supporting records…
        </p>
      )}
      {result && (
        <>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <p className="text-xs text-foreground" aria-live="polite">
              Supporting references: {count(result.evidence.length)} of {count(result.matchingRecords)}
              {result.evidence.length < result.matchingRecords && (
                <span className="text-muted-foreground"> (the first {count(result.evidence.length)} are listed)</span>
              )}
              <span className="tabular-nums text-muted-foreground"> · as of {localTime(asOfMs)}</span>
            </p>
            {refresh}
          </div>
          {result.evidence.length > 0 && (
            <ul className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto" aria-label="Supporting references">
              {result.evidence.map((ref) => {
                const id = `${ref.ref.entryId}:${ref.recordIndex}`;
                const current = detail !== null && detail.evidence.ref.entryId === ref.ref.entryId
                  && detail.record.recordIndex === ref.recordIndex;
                return (
                  <li key={id}>
                    <button type="button" onClick={() => void open(ref)} aria-pressed={current}
                      aria-busy={opening === id || undefined}
                      className={`rounded border px-1.5 py-0.5 font-mono text-[11px] tabular-nums cursor-pointer
                        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring
                        ${opening === id ? 'opacity-60 motion-safe:animate-pulse' : ''}
                        ${current ? 'border-primary bg-primary/15 text-foreground' : 'border-border text-muted-foreground hover:border-primary/60 hover:text-foreground'}`}>
                      {`#${ref.ref.entryId}.${ref.recordIndex + 1}`}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {result.evidence.length > 0 && !detail && (
            <p className="text-[11px] text-muted-foreground">
              Each reference is a datagram and the record in it. Open one to see what the exporter sent.
            </p>
          )}
        </>
      )}
      {note && <p role="status" className="text-xs text-muted-foreground">{note}</p>}
      {detail && <DatagramDetail detail={detail} onClose={() => setDetail(null)} />}
    </section>
  );
}
