import { ArrowDown, ArrowUp } from 'lucide-react';
import { formatMbps, median, SLICE_MS } from '../../services/speedTest/method';
import type { LatencySample } from '../../services/speedTest/protocol';
import type { TracePoint } from '../../services/speedTest/state';
import { latencyDomain, logScale, spread } from '../../services/speedTest/stats';

const W = 688;
const GUTTER = 90;
const RIGHT = 52;
const PLOT_W = W - GUTTER - RIGHT;
const PLOT_H = 96;
const TOP = 4;
const STRIP = 16;
const STRIP_TOP = TOP + PLOT_H + 4;

/** 1, 2, 2.5, 5 times a power of ten: the smallest at or above `v`. */
function niceCeil(v: number): number {
  if (!(v > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

/** A step path: each 100 ms slice holds its value across the slice it measured. */
function stepPath(points: readonly TracePoint[], x: (ms: number) => number, y: (mbps: number) => number): string {
  let d = '';
  for (const p of points) {
    d += d === '' ? `M${x(p.tMs - SLICE_MS)},${y(p.mbps)}` : `V${y(p.mbps)}`;
    d += `H${x(p.tMs)}`;
  }
  return d;
}

/**
 * One direction's throughput, slice by slice, on the time axis the engine
 * measured it on. The headline is the median; P90 and the mean are cursors
 * here, not figures, because ADR 0054 calibrated the median against Ookla.
 * The warm-up is drawn and labelled rather than hidden, since it is the first
 * thing anyone asks about a trace that starts low. Under it, on the same x,
 * the loaded-latency probes, so a spike lines up with the slice it hit.
 */
export function ThroughputTrace({ direction, points, durationMs, warmupMs, p90, mean, ghost, loaded, live, showTime = false }: {
  direction: 'download' | 'upload';
  points: readonly TracePoint[];
  durationMs: number;
  warmupMs: number;
  p90: number | null;
  mean: number | null;
  ghost: readonly number[] | null;
  loaded: readonly LatencySample[];
  live: boolean;
  showTime?: boolean;
}) {
  const Dir = direction === 'download' ? 'Download' : 'Upload';
  const tone = direction === 'download' ? 'text-speed-download' : 'text-speed-upload';
  const Arrow = direction === 'download' ? ArrowDown : ArrowUp;
  const H = STRIP_TOP + STRIP + (showTime ? 16 : 2);

  const ghostPoints = (ghost ?? []).map((mbps, i) => ({ tMs: (i + 1) * SLICE_MS, mbps }));
  const last = points[points.length - 1];
  const xMax = Math.max(durationMs, last?.tMs ?? 0, ghostPoints[ghostPoints.length - 1]?.tMs ?? 0);
  // The scale is set by the counted slices: a first slice that bursts while
  // the window opens would otherwise flatten the ten seconds after it. Until
  // the warm-up is over, the warm-up is all there is to scale by.
  const counted = (ps: readonly TracePoint[]) => {
    const after = ps.filter((p) => p.tMs > warmupMs);
    return (after.length > 0 ? after : ps).map((p) => p.mbps);
  };
  const empty = points.length === 0 && ghostPoints.length === 0;
  const yMax = niceCeil(Math.max(1, ...counted(points), ...counted(ghostPoints), p90 ?? 0, mean ?? 0));
  const x = (ms: number) => GUTTER + Math.max(0, Math.min(1, ms / xMax)) * PLOT_W;
  const y = (mbps: number) => TOP + PLOT_H - Math.max(0, Math.min(1, mbps / yMax)) * PLOT_H;

  const past = points.filter((p) => p.tMs > warmupMs).map((p) => p.mbps);
  const said = live ? last?.mbps : median(past) ?? last?.mbps;
  const label = said === undefined || said === null ? `${Dir} trace: no data` : `${Dir} trace: ${formatMbps(said)} Mb/s`;

  const [lo, hi] = latencyDomain([spread(loaded.map((s) => s.ttfbMs))]);
  const ly = logScale(lo, hi, STRIP - 4);

  const cursors = cursorLabels(p90, mean, y);
  const line = stepPath(points, x, y);

  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${W} ${H}`} className="w-full select-none overflow-visible">
      <g className={tone}>
        <Arrow x={0} y={TOP} width={12} height={12} aria-hidden />
      </g>
      <text x={16} y={TOP + 10} className="fill-foreground text-[12px]">{Dir}</text>
      {/* No scale before there is anything on it: "1.00" over an empty plot
          reads as a measurement. */}
      {!empty && (
        <>
          <text x={GUTTER - 6} y={TOP + 22} textAnchor="end" className="fill-muted-foreground font-mono text-[10px]">
            {formatMbps(yMax)}
          </text>
          <text x={GUTTER - 6} y={TOP + PLOT_H} textAnchor="end" className="fill-muted-foreground font-mono text-[10px]">0</text>
        </>
      )}
      <text x={GUTTER - 6} y={STRIP_TOP + 11} textAnchor="end" className="fill-muted-foreground text-[10px]">latency</text>

      <rect x={GUTTER} y={TOP} width={x(warmupMs) - GUTTER} height={PLOT_H} className="fill-muted" />
      <line x1={GUTTER} x2={GUTTER + PLOT_W} y1={TOP} y2={TOP} className="stroke-border/60" />
      <line x1={GUTTER} x2={GUTTER + PLOT_W} y1={TOP + PLOT_H} y2={TOP + PLOT_H} className="stroke-border" />
      <rect x={GUTTER} y={STRIP_TOP} width={PLOT_W} height={STRIP} rx={2} className="fill-muted/50" />

      {ghostPoints.length > 0 && (
        <path d={stepPath(ghostPoints, x, y)} fill="none" className="stroke-muted-foreground/40" strokeWidth={1} />
      )}
      {points.length > 0 && (
        <g className={tone}>
          <path d={`${line}V${TOP + PLOT_H}H${x(points[0].tMs - SLICE_MS)}Z`} fill="currentColor" fillOpacity={0.08} />
          <path d={line} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinejoin="round" />
          {live && last && <circle cx={x(last.tMs)} cy={y(last.mbps)} r={3} fill="currentColor" />}
        </g>
      )}
      {/* Drawn over the trace with a halo in the warm-up's own fill, so a
          trace running along the top does not strike it through. */}
      <text x={GUTTER + 5} y={TOP + PLOT_H - 5} className="fill-muted-foreground stroke-muted text-[10px]"
        strokeWidth={3} paintOrder="stroke" strokeLinejoin="round">
        not counted
      </text>
      {points.length === 0 && !live && (
        <text x={GUTTER + PLOT_W / 2} y={TOP + PLOT_H / 2 + 4} textAnchor="middle" className="fill-muted-foreground/70 text-[11px] italic">
          Waiting for the {direction}
        </text>
      )}

      {cursors.map((c) => (
        <g key={c.name}>
          <line x1={GUTTER} x2={GUTTER + PLOT_W} y1={c.y} y2={c.y} className="stroke-foreground/50" strokeDasharray="4 3" />
          <text x={GUTTER + PLOT_W + 4} y={c.labelY + 3.5} className="fill-muted-foreground font-mono text-[10px]">
            {c.name} {formatMbps(c.value)}
          </text>
        </g>
      ))}

      {loaded.map((s) => (
        <circle key={s.tMs} cx={x(s.tMs)} cy={STRIP_TOP + STRIP - 2 - ly(s.ttfbMs)} r={1.5}
          className="fill-muted-foreground/70" />
      ))}

      {showTime && Array.from({ length: Math.floor(xMax / 2000) + 1 }, (_, i) => i * 2000).map((ms) => (
        <text key={ms} x={x(ms)} y={H - 3} textAnchor={ms === 0 ? 'start' : 'middle'} className="fill-muted-foreground font-mono text-[10px]">
          {ms / 1000}{ms === 0 ? '' : ' s'}
        </text>
      ))}
    </svg>
  );
}

/** The two cursors' labels, pushed apart when their lines are too close to read both. */
function cursorLabels(p90: number | null, mean: number | null, y: (v: number) => number) {
  const out: { name: string; value: number; y: number; labelY: number }[] = [];
  if (p90 !== null) out.push({ name: 'P90', value: p90, y: y(p90), labelY: y(p90) });
  if (mean !== null) out.push({ name: 'mean', value: mean, y: y(mean), labelY: y(mean) });
  if (out.length === 2) {
    const [a, b] = out[0].y <= out[1].y ? [out[0], out[1]] : [out[1], out[0]];
    const gap = b.labelY - a.labelY;
    if (gap < 11) { a.labelY -= (11 - gap) / 2; b.labelY += (11 - gap) / 2; }
  }
  return out;
}
