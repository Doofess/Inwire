import { bloatGrade, type BloatGrade } from '../../services/speedTest/method';
import type { Spread, SpeedPhase } from '../../services/speedTest/protocol';
import { latencyDomain, logScale } from '../../services/speedTest/stats';
import { fmtMsValue } from './Hint';

const W = 688;
const GUTTER = 90;
const FIGURE = 56;
const AXIS = W - GUTTER - FIGURE;
const TOP = 16;
const ROW = 28;
const BOX = 12;
const ROWS_END = TOP + ROW * 3;
const H = ROWS_END + 44;

/** The bands bloatGrade cuts at, as a rise over idle. */
const BANDS: { grade: BloatGrade; from: number; to: number }[] = [
  { grade: 'A+', from: -Infinity, to: 5 },
  { grade: 'A', from: 5, to: 30 },
  { grade: 'B', from: 30, to: 60 },
  { grade: 'C', from: 60, to: 200 },
  { grade: 'D', from: 200, to: 400 },
  { grade: 'F', from: 400, to: Infinity },
];

type Row = { key: 'idle' | 'download' | 'upload'; label: string; phase: SpeedPhase };
const ROWS: Row[] = [
  { key: 'idle', label: 'Idle', phase: 'latency' },
  { key: 'download', label: 'Downloading', phase: 'download' },
  { key: 'upload', label: 'Uploading', phase: 'upload' },
];
const ORDER: SpeedPhase[] = ['connecting', 'latency', 'download', 'upload'];

/**
 * Latency under load, the centrepiece (ADR 0054's amendment): one box per
 * phase on a shared LOG axis, because idle at 2 ms beside upload at 26 ms is a
 * 2px box on a linear one. The boxes are each probe's time to first byte,
 * which keeps the spread; the figures at the right are the server's own
 * round trip, which is what the grade compares, and the grade's thresholds are
 * drawn on the axis so the letter is explained where it is shown.
 */
export function LatencyBoxes({ idle, download, upload, rtt, live }: {
  idle: Spread | null;
  download: Spread | null;
  upload: Spread | null;
  rtt: { idle: number | null; download: number | null; upload: number | null };
  live: SpeedPhase | null;
}) {
  const spreads = { idle, download, upload };
  const known = [rtt.idle, rtt.download, rtt.upload].filter((v): v is number => v !== null && v > 0);
  let [lo, hi] = latencyDomain([idle, download, upload]);
  for (const v of known) {
    while (v < lo && lo > 0.5) lo /= 10;
    while (v > hi) hi *= 10;
  }
  const x = logScale(lo, hi, AXIS);
  const at = (ms: number) => GUTTER + x(ms);

  const loaded = rtt.download === null && rtt.upload === null ? null
    : Math.max(rtt.download ?? -Infinity, rtt.upload ?? -Infinity);
  const grade = rtt.idle !== null && loaded !== null ? bloatGrade(rtt.idle, loaded) : null;
  const liveAt = live === null ? ORDER.length : ORDER.indexOf(live);

  const said = (r: Row) => {
    const v = rtt[r.key] ?? spreads[r.key]?.p50 ?? null;
    return v === null ? `${r.label.toLowerCase()} no samples` : `${r.label.toLowerCase()} ${fmtMsValue(v)} ms`;
  };
  const label = known.length === 0 && !idle && !download && !upload
    ? 'Latency: no samples' : `Latency: ${ROWS.map(said).join(', ')}`;

  return (
    <figure className="w-full">
      <svg role="img" aria-label={label} viewBox={`0 0 ${W} ${H}`} className="w-full select-none overflow-visible">
        <Grid lo={lo} hi={hi} at={at} />
        {rtt.idle !== null && BANDS.map((b) => {
          const from = b.from === -Infinity ? lo : rtt.idle! + b.from;
          const to = b.to === Infinity ? hi : rtt.idle! + b.to;
          const x1 = at(Math.max(lo, from));
          const x2 = at(Math.min(hi, to));
          return (
            <g key={b.grade}>
              {b.from !== -Infinity && rtt.idle! + b.from > lo && rtt.idle! + b.from < hi && (
                <line x1={x1} x2={x1} y1={TOP - 4} y2={ROWS_END} className="stroke-muted-foreground/35" strokeDasharray="2 3" />
              )}
              {x2 - x1 >= 12 && (
                <text x={(x1 + x2) / 2} y={TOP - 6} textAnchor="middle"
                  className={`font-mono text-[10px] ${b.grade === grade ? 'fill-foreground font-bold' : 'fill-muted-foreground/60'}`}>
                  {b.grade}
                </text>
              )}
            </g>
          );
        })}
        {ROWS.map((r, i) => {
          const s = spreads[r.key];
          const y = TOP + i * ROW + ROW / 2;
          const current = live === r.phase;
          const pending = ORDER.indexOf(r.phase) > liveAt;
          const figure = rtt[r.key];
          return (
            <g key={r.key}>
              <text x={0} y={y + 4} className={`text-[12px] ${current ? 'fill-foreground font-medium' : 'fill-muted-foreground'}`}>
                {r.label}
              </text>
              {s ? (
                <g className={r.key === 'idle' ? 'text-muted-foreground' : r.key === 'download' ? 'text-speed-download' : 'text-speed-upload'}>
                  <line x1={at(s.p10)} x2={at(s.p90)} y1={y} y2={y} stroke="currentColor" strokeWidth={1} />
                  <line x1={at(s.p10)} x2={at(s.p10)} y1={y - 4} y2={y + 4} stroke="currentColor" strokeWidth={1} />
                  <line x1={at(s.p90)} x2={at(s.p90)} y1={y - 4} y2={y + 4} stroke="currentColor" strokeWidth={1} />
                  <rect x={at(s.p25)} y={y - BOX / 2} width={Math.max(2, at(s.p75) - at(s.p25))} height={BOX} rx={2}
                    fill="currentColor" fillOpacity={0.18} stroke="currentColor" strokeWidth={1} />
                  <line x1={at(s.p50)} x2={at(s.p50)} y1={y - BOX / 2 - 2} y2={y + BOX / 2 + 2} stroke="currentColor" strokeWidth={2} />
                </g>
              ) : (
                <text x={GUTTER + 6} y={y + 4} className="fill-muted-foreground/70 text-[11px] italic">
                  {pending || current ? '–' : 'no samples'}
                </text>
              )}
              <text x={W} y={y + 4} textAnchor="end"
                className={`font-mono text-[12px] ${figure === null ? 'fill-muted-foreground/50' : 'fill-foreground'}`}>
                {figure === null ? '–' : `${fmtMsValue(figure)} ms`}
              </text>
            </g>
          );
        })}
        {rtt.idle !== null && loaded !== null && loaded > rtt.idle && (
          <Bracket x1={at(rtt.idle)} x2={at(loaded)} rise={loaded - rtt.idle} />
        )}
      </svg>
      <figcaption className="mt-1 text-[11px] text-muted-foreground">
        Boxes: time to first byte. Figures: the server's round trip.
      </figcaption>
    </figure>
  );
}

/** Decades and their 2 and 5, faint; labelled below the rows. */
function Grid({ lo, hi, at }: { lo: number; hi: number; at: (ms: number) => number }) {
  const ticks: { v: number; major: boolean }[] = [];
  for (let d = lo; d <= hi * 1.0001; d *= 10) {
    for (const m of [1, 2, 5]) {
      const v = d * m;
      if (v >= lo * 0.9999 && v <= hi * 1.0001) ticks.push({ v, major: m === 1 });
    }
  }
  const last = ticks[ticks.length - 1];
  return (
    <g>
      {ticks.map((t) => (
        <g key={t.v}>
          <line x1={at(t.v)} x2={at(t.v)} y1={TOP} y2={ROWS_END}
            className={t.major ? 'stroke-border' : 'stroke-border/50'} />
          <text x={at(t.v)} y={ROWS_END + 13} textAnchor="middle" className="fill-muted-foreground font-mono text-[10px]">
            {t.v < 1 ? t.v.toFixed(1) : t.v}{t === last ? ' ms' : ''}
          </text>
        </g>
      ))}
    </g>
  );
}

/** From the idle round trip to the worse loaded one: the grade's own input. */
function Bracket({ x1, x2, rise }: { x1: number; x2: number; rise: number }) {
  const y = ROWS_END + 26;
  const text = `+${fmtMsValue(rise)} ms under load`;
  const room = W - FIGURE - x2;
  return (
    <g className="text-foreground">
      <path d={`M${x1},${y - 5} V${y} H${x2} V${y - 5}`} fill="none" stroke="currentColor" strokeWidth={1} />
      <text x={room > 130 ? x2 + 6 : x1 - 6} y={y + 4} textAnchor={room > 130 ? 'start' : 'end'}
        className="fill-foreground font-mono text-[11px]">
        {text}
      </text>
    </g>
  );
}
