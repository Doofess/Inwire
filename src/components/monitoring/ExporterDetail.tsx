import { AlertTriangle } from 'lucide-react';
import type { ExporterSnapshot, TemplateSourceHealth } from '../../services/monitoring/sourceHealth';
import type { TemplateInventory } from '../../services/monitoring/templates';
import { formatBytes } from '../../lib/formatBytes';
import { clockText, count, engineLabel, localTime, notInterpretedText, samplingText, sequenceText, type Tone } from './monitoringCopy';
import { ToneDot } from './parts';

/**
 * What each NetFlow v9 or IPFIX source is doing now (ADRs 0064-0066): the templates it defined, how it
 * samples, how far its clock is from this PC's, how it numbers its exports, and what arrived before its
 * template did. Live only - none of it is history - and every figure is the exporter's own or counted
 * here, never inferred.
 */
export function ExporterDetail({ exporters, rows }: { exporters: ExporterSnapshot[]; rows: TemplateSourceHealth[] }) {
  return (
    <div className="grid gap-4 @5xl:grid-cols-2">
      {exporters.map((x) => (
        <Source key={x.sourceKey} snapshot={x} row={rows.find((r) => r.sourceKey === x.sourceKey) ?? null} />
      ))}
    </div>
  );
}

function Source({ snapshot, row }: { snapshot: ExporterSnapshot; row: TemplateSourceHealth | null }) {
  const sampling = samplingText(snapshot.sampling);
  const clock = clockText(snapshot.clock);
  const gaps = snapshot.sequence.suspectedGap > 0 || snapshot.sequence.reordered > 0;
  const port = snapshot.templates.find((t) => t.scope.exporterPort !== null)?.scope.exporterPort ?? null;
  return (
    <section aria-label={engineLabel(snapshot.sourceKey)} className="min-w-0 overflow-hidden rounded-md border border-border bg-card">
      <header className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 border-b border-border px-3.5 py-2">
        <h3 className="text-xs font-semibold text-foreground">{engineLabel(snapshot.sourceKey)}</h3>
        <p className="text-[11px] text-muted-foreground">
          from <span className="font-mono text-foreground">{exporterOf(snapshot.sourceKey)}{port === null ? '' : `:${port}`}</span>
          {row && <>, {count(row.accepted)} {row.accepted === 1 ? 'export' : 'exports'} and {count(row.flows)} records</>}
        </p>
      </header>

      <dl className="space-y-1.5 px-3.5 py-3">
        <Line label="Sampling" tone={sampling.tone}>{sampling.text}</Line>
        <Line label="Clock" tone={clock.tone}>{clock.text}</Line>
        <Line label="Numbering" tone={gaps ? 'warn' : 'neutral'}>{sequenceText(snapshot.sequence)}</Line>
        {row && (
          <Line label="No template" tone={row.awaitingSets > 0 ? 'warn' : 'good'}>
            {row.awaitingSets === 0 ? 'Every data set had its template' : (
              <>
                {count(row.awaitingSets)} data {row.awaitingSets === 1 ? 'set' : 'sets'} ({formatBytes(row.awaitingBytes)}) arrived
                before {row.awaitingSets === 1 ? 'its' : 'their'} template: kept, records unknown
                {row.lastAwaitingTemplateId !== null && <>; last waited for template {row.lastAwaitingTemplateId}</>}
              </>
            )}
          </Line>
        )}
        {row && row.restarts > 0 && (
          <Line label="Restarts" tone="warn">
            {count(row.restarts)} {row.restarts === 1 ? 'restart' : 'restarts'}: its templates were dropped and learned again
          </Line>
        )}
      </dl>

      <Templates templates={snapshot.templates} />
    </section>
  );
}

function Line({ label, tone, children }: { label: string; tone: Tone; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-2 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 items-start gap-1.5 text-foreground">
        <ToneDot tone={tone} className="mt-[5px]" />
        <span className="min-w-0 break-words">{children}</span>
      </dd>
    </div>
  );
}

function Templates({ templates }: { templates: TemplateInventory[] }) {
  if (templates.length === 0) {
    return <p className="border-t border-border px-3.5 py-2.5 text-xs text-muted-foreground">No template in force: data from this source waits for one.</p>;
  }
  const sorted = [...templates].sort((a, b) => a.id - b.id);
  return (
    <div className="overflow-x-auto border-t border-border">
      <table className="w-full min-w-[28rem] text-left text-[11px] tabular-nums">
        <caption className="sr-only">Templates in force</caption>
        <thead className="text-muted-foreground">
          <tr>
            <th scope="col" className="px-3.5 py-1.5 font-semibold">Template</th>
            <th scope="col" className="px-2 py-1.5 text-right font-semibold">Fields</th>
            <th scope="col" className="px-2 py-1.5 font-semibold">Seen</th>
            <th scope="col" className="w-full px-2 py-1.5 font-semibold">Notes</th>
          </tr>
        </thead>
        <tbody className="text-foreground">
          {sorted.map((t) => (
            <tr key={t.id} className="border-t border-border align-top">
              <th scope="row" className="whitespace-nowrap px-3.5 py-1.5 font-normal">
                <span className="font-mono">{t.id}</span>
                <span className="text-muted-foreground">{t.options ? ' options' : ' data'}</span>
              </th>
              <td className="px-2 py-1.5 text-right">{t.fields.length}</td>
              <td className="whitespace-nowrap px-2 py-1.5 text-muted-foreground">{localTime(t.lastSeenMs)}</td>
              <td className="px-2 py-1.5"><Notes template={t} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Notes({ template }: { template: TemplateInventory }) {
  const notes: { text: string; warn: boolean }[] = [];
  if (template.unsupported) notes.push({ text: 'no byte count: records counted, not totalled', warn: true });
  if (template.totalCounts) notes.push({ text: 'counts are running totals, so a long flow is counted again at each export', warn: true });
  const unread = notInterpretedText(template.notInterpreted);
  if (unread !== null) notes.push({ text: unread, warn: false });
  if (notes.length === 0) return <span className="text-muted-foreground">every field read</span>;
  return (
    <ul className="space-y-0.5">
      {notes.map((n) => (
        // The warning colour carries the glyph, not the words: as text it is under the contrast floor on a card.
        <li key={n.text} className={`flex items-start gap-1 break-words ${n.warn ? 'text-foreground' : 'text-muted-foreground'}`}>
          {n.warn && <AlertTriangle className="mt-px h-3 w-3 shrink-0 text-warning" aria-hidden />}
          <span className="min-w-0">{n.text}</span>
        </li>
      ))}
    </ul>
  );
}

/** The exporter address a v9 or IPFIX source key names (`v9:ip/id`). */
function exporterOf(key: string): string {
  const colon = key.indexOf(':');
  const slash = key.lastIndexOf('/');
  return colon >= 0 && slash > colon ? key.slice(colon + 1, slash) : key;
}
