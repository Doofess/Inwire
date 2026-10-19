import { useId } from 'react';
import type { HistoryBucket } from '../../services/monitoring/types';
import { formatBytes } from '../../lib/formatBytes';
import { count, localRange, localTime } from './monitoringCopy';

export type Measure = 'octets' | 'packets';

const HEIGHT = 168;
const AXIS = 18;
const PLOT = HEIGHT - AXIS;

/**
 * The history's bars. Three kinds of bucket, three kinds of mark, because the
 * question "how much?" has three answers that must never look alike:
 *
 * - the exporter reported records: a bar, its height the reported counter;
 * - collection was running and nothing was reported: a dashed baseline, which
 *   is a real zero;
 * - collection was not running: a hatched band over the full height, which is
 *   not a zero at all - nobody was listening.
 *
 * A gap is never a zero-height bar. Drawn as SVG at the measured width, with a
 * `<title>` per bucket so the hover says the exact numbers.
 */
export function HistoryChart({ buckets, measure, width }: {
  buckets: HistoryBucket[]; measure: Measure; width: number;
}) {
  const hatch = useId().replace(/:/g, '');
  if (width <= 0 || buckets.length === 0) return <div style={{ height: HEIGHT }} />;
  const value = (b: HistoryBucket): bigint | null => (measure === 'octets' ? b.reportedOctets : b.reportedPackets);
  let max = 0n;
  for (const b of buckets) { const v = value(b); if (v !== null && v > max) max = v; }
  const slot = width / buckets.length;
  const gap = slot >= 6 ? 1.5 : slot >= 3 ? 0.75 : 0;
  const barW = Math.max(1, slot - gap);
  const scale = (v: bigint): number => (max === 0n ? 0 : Number((v * 10_000n) / max) / 10_000 * (PLOT - 6));
  const fmt = (v: bigint): string => (measure === 'octets' ? formatBytes(Number(v)) : `${count(v)} packets`);
  const label = measure === 'octets' ? 'Reported bytes' : 'Reported packets';
  const observed = buckets.filter((b) => b.coverage === 'observed-records' || b.coverage === 'aggregate-only').length;
  const gaps = buckets.filter((b) => b.coverage === 'collection-gap' || b.coverage === 'history-lost').length;
  const ticks = tickIndices(buckets.length, width);

  return (
    <figure className="m-0 space-y-1.5">
      <p className="flex justify-between gap-3 text-[11px] tabular-nums text-muted-foreground" aria-hidden>
        <span>{label} per {intervalText(buckets[0].toMs - buckets[0].fromMs)}</span>
        <span>{max > 0n ? `peak ${fmt(max)}` : 'nothing reported'}</span>
      </p>
      <svg width={width} height={HEIGHT} role="img" className="block overflow-visible text-muted-foreground"
        aria-label={`${label} per interval, ${localRange(buckets[0].fromMs, buckets[buckets.length - 1].toMs)}: ${observed} intervals with records, ${gaps} not collected. Peak ${fmt(max)}.`}>
        <defs>
          <pattern id={hatch} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <rect width="6" height="6" fill="var(--color-muted)" />
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--color-muted-foreground)" strokeOpacity="0.45" strokeWidth="2" />
          </pattern>
        </defs>
        {/* the peak line, so a bar's height has a number to read against */}
        <line x1={0} x2={width} y1={6} y2={6} stroke="var(--color-border)" strokeDasharray="2 3" />
        <line x1={0} x2={width} y1={PLOT + 0.5} y2={PLOT + 0.5} stroke="var(--color-border)" />
        {buckets.map((b, i) => {
          const x = i * slot + gap / 2;
          const span = localRange(b.fromMs, b.toMs);
          if (b.coverage === 'collection-gap' || b.coverage === 'history-lost') {
            return (
              <rect key={i} x={i * slot} y={0} width={slot} height={PLOT} fill={`url(#${hatch})`}>
                <title>{b.coverage === 'history-lost' ? `${span}: history lost` : `${span}: not collecting`}</title>
              </rect>
            );
          }
          const v = value(b);
          if (b.coverage === 'no-records' || v === null) {
            return (
              <g key={i}>
                <line x1={x} x2={x + barW} y1={PLOT - 1.5} y2={PLOT - 1.5} stroke="var(--color-muted-foreground)"
                  strokeDasharray="2 2" strokeOpacity="0.7" />
                <rect x={i * slot} y={0} width={slot} height={PLOT} fill="transparent">
                  <title>{`${span}: listening, nothing reported`}</title>
                </rect>
              </g>
            );
          }
          const h = Math.max(b.records > 0 ? 1.5 : 0, scale(v));
          return (
            <g key={i}>
              <rect x={x} y={PLOT - h} width={barW} height={h} rx={barW >= 4 ? 1 : 0} fill="var(--color-primary)" />
              <rect x={i * slot} y={0} width={slot} height={PLOT} fill="transparent">
                <title>{`${span}: ${fmt(v)} in ${count(b.records)} ${b.records === 1 ? 'record' : 'records'}`}</title>
              </rect>
            </g>
          );
        })}
        {ticks.map((i) => (
          <text key={i} x={Math.min(width - 2, Math.max(2, i * slot))} y={HEIGHT - 3} fontSize="10" fill="currentColor"
            textAnchor={i === 0 ? 'start' : i === buckets.length ? 'end' : 'middle'} className="tabular-nums">
            {localTime(i === buckets.length ? buckets[i - 1].toMs : buckets[i].fromMs, spansDays(buckets)).replace(/:\d\d$/, '')}
          </text>
        ))}
      </svg>
      <figcaption className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden className="h-2.5 w-2.5 rounded-[2px] bg-primary" />Reported by the exporter
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden className="h-0 w-3 border-t-2 border-dashed border-muted-foreground/70" />Listening, nothing reported
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg aria-hidden width="10" height="10"><rect width="10" height="10" fill={`url(#${hatch})`} /></svg>Not collecting
        </span>
      </figcaption>
    </figure>
  );
}

function intervalText(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m} min`;
  const h = Math.round(m / 60);
  return `${h} h`;
}

function spansDays(buckets: HistoryBucket[]): boolean {
  return buckets[buckets.length - 1].toMs - buckets[0].fromMs > 24 * 3_600_000;
}

/** Bucket edges for the time labels: about one per 120px, always both ends. */
function tickIndices(n: number, width: number): number[] {
  const wanted = Math.max(2, Math.floor(width / 120));
  const step = Math.max(1, Math.round(n / wanted));
  const out: number[] = [];
  for (let i = 0; i < n; i += step) out.push(i);
  if (n - out[out.length - 1] < step / 2) out.pop();
  out.push(n);
  return out;
}
