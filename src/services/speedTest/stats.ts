/**
 * What a finished speed test summarises to, and the axis the sheet draws its
 * latencies on. Pure, so the engine builds the summary into the result (a run
 * nobody watched has it too) and the sheet draws from the same numbers.
 */
import { formatMbps, median, quantile, rpm, rpmBand, SLICE_MS, type BloatGrade } from './method';
import type { LatencySample, SpeedSummary, SpeedTransfer, Spread } from './protocol';

/** Where a set of numbers falls; null for none, so an empty phase draws "no samples" rather than a box. */
export function spread(values: readonly number[]): Spread | null {
  if (values.length === 0) return null;
  return {
    n: values.length,
    p10: quantile(values, 0.1)!,
    p25: quantile(values, 0.25)!,
    p50: quantile(values, 0.5)!,
    p75: quantile(values, 0.75)!,
    p90: quantile(values, 0.9)!,
  };
}

/**
 * The mean of the slices past warm-up - bytes over time, since every slice is
 * the same length. Too short to leave anything past warm-up, the second half,
 * the same fallback `transferFigure` takes, so the cursor and the figure are
 * read over one span.
 */
export function meanPastWarmup(trace: readonly number[], warmupMs: number, sliceMs = SLICE_MS): number | null {
  if (trace.length === 0) return null;
  let from = Math.floor(warmupMs / sliceMs);
  if (from >= trace.length) from = Math.floor(trace.length / 2);
  const kept = trace.slice(from);
  return kept.reduce((a, b) => a + b, 0) / kept.length;
}

export function summarise(
  run: { idle: readonly LatencySample[]; download: SpeedTransfer; upload: SpeedTransfer },
  warmupMs: number,
): SpeedSummary {
  const ttfb = (s: readonly LatencySample[]) => spread(s.map((x) => x.ttfbMs));
  // The worse loaded median, as the grade takes it - or the one phase that
  // has samples. Neither, and there is no responsiveness to claim.
  const loaded = [run.download.loaded, run.upload.loaded]
    .map((s) => median(s.map((x) => x.rttMs)))
    .filter((m): m is number => m !== null);
  return {
    idle: ttfb(run.idle),
    download: ttfb(run.download.loaded),
    upload: ttfb(run.upload.loaded),
    rpm: loaded.length > 0 ? rpm(Math.max(...loaded)) : null,
    downMeanMbps: meanPastWarmup(run.download.trace, warmupMs),
    upMeanMbps: meanPastWarmup(run.upload.trace, warmupMs),
  };
}

/**
 * A log10 axis from `min` to `max` over `width`, clamped into it. Logarithmic
 * because idle at 2 ms beside upload at 26 ms leaves a 2px box on a linear
 * one. Zero and below land on the left edge, never NaN.
 */
export function logScale(min: number, max: number, width: number): (value: number) => number {
  const lo = Math.log10(min);
  const span = Math.log10(max) - lo;
  return (value) => {
    if (!(value > 0) || span <= 0) return 0;
    return Math.min(width, Math.max(0, ((Math.log10(value) - lo) / span) * width));
  };
}

/**
 * Whole decades around what was measured: from the decade under the lowest
 * p10 (never under half a millisecond) to the one over the highest p90, and
 * at least a decade wide so a tight run is not drawn as a sliver. One to a
 * hundred before anything is measured.
 */
export function latencyDomain(spreads: readonly (Spread | null)[]): [number, number] {
  const seen = spreads.filter((s): s is Spread => s !== null);
  if (seen.length === 0) return [1, 100];
  const low = Math.min(...seen.map((s) => s.p10));
  const high = Math.max(...seen.map((s) => s.p90));
  const lo = Math.max(0.5, low > 0 ? 10 ** Math.floor(Math.log10(low)) : 0.5);
  let hi = 10 ** Math.ceil(Math.log10(Math.max(high, lo)));
  if (hi < lo * 10) hi = lo * 10;
  return [lo, hi];
}

/** Milliseconds as a figure: a decimal under ten, where one matters. */
const msText = (ms: number): string => (ms < 10 ? ms.toFixed(1) : Math.round(ms).toString());

/**
 * A monospace string's width in drawing units. 0.62 em is the widest of the
 * faces the mono stack can land on (Courier's 0.6 plus a hair), so a label
 * placed with it is never wider than it was told.
 */
export const monoTextWidth = (text: string, px: number): number => text.length * px * 0.62;

export interface LabelPlacement {
  x: number;
  anchor: 'start' | 'end' | 'middle';
  /** True when the label does not fit beside the bracket and drops a line under it. */
  below: boolean;
}

/**
 * Where the latency bracket's "+N ms under load" goes so that it lies wholly
 * inside `[min, max]`: to the right of the bracket if it fits, else to the
 * left, else - the bracket spans most of the axis - centred under it and
 * clamped into the drawing.
 */
export function bracketLabelPlacement(
  { x1, x2, width, min, max, gap = 6 }: { x1: number; x2: number; width: number; min: number; max: number; gap?: number },
): LabelPlacement {
  if (x2 + gap + width <= max) return { x: x2 + gap, anchor: 'start', below: false };
  if (x1 - gap - width >= min) return { x: x1 - gap, anchor: 'end', below: false };
  const half = width / 2;
  return { x: Math.min(max - half, Math.max(min + half, (x1 + x2) / 2)), anchor: 'middle', below: true };
}

/**
 * The history strip's shared track, from the smallest to the largest latency
 * of any dot drawn in the rows shown - idle and loaded alike. Min and max of
 * what is drawn rather than a percentile: a p10-p90 domain would push the
 * outlier the strip exists to show off the track. Shared by every row, so one
 * row's dots can be read against another's. At least a factor of two wide, so
 * rows that all read alike sit mid-track instead of piling on its left end.
 */
export function pingStripDomain(values: readonly number[]): [number, number] {
  const v = values.filter((x) => Number.isFinite(x) && x > 0);
  if (v.length === 0) return [1, 100];
  const lo = Math.min(...v);
  const hi = Math.max(...v);
  if (hi >= lo * 2) return [lo, hi];
  const mid = Math.sqrt(lo * hi);
  return [mid / Math.SQRT2, mid * Math.SQRT2];
}

/** A dot's x on a track `width` wide with `pad` on both ends for the dot itself; clamped, never NaN. */
export function pingStripX(value: number, domain: readonly [number, number], width = 48, pad = 4): number {
  const [lo, hi] = domain;
  const span = Math.log10(hi) - Math.log10(lo);
  if (!(value > 0) || !(span > 0)) return pad;
  const f = Math.min(1, Math.max(0, (Math.log10(value) - Math.log10(lo)) / span));
  return pad + f * (width - 2 * pad);
}

/**
 * The worse loaded median a history row kept, or null: an entry from before
 * the field existed has it undefined, and a zero is not a measurement.
 */
export function loadedOfHistory(down: number | null | undefined, up: number | null | undefined): number | null {
  const v = [down, up].filter((x): x is number => typeof x === 'number' && Number.isFinite(x) && x > 0);
  return v.length > 0 ? Math.max(...v) : null;
}

/** What a history row's strip says to a screen reader and on hover. */
export function pingStripLabel(idle: number, loaded: number | null): string {
  return loaded === null ? `Idle ${msText(idle)} ms, no loaded data` : `Idle ${msText(idle)} ms, loaded ${msText(loaded)} ms`;
}

/** The phase strip's tick: the engine raised its connection count at this moment of the transfer. */
export function rampTickLabel(ms: number): string {
  return Number.isFinite(ms) ? `More connections added at ${(ms / 1000).toFixed(1)} s` : 'More connections added';
}

/**
 * The sentence the live region says once a test is done. Responsiveness and
 * the grade only when they exist: a run with no loaded probe has neither, and
 * saying "0 RPM" or "grade undefined" would be a measurement that was not made.
 */
export function resultAnnouncement(r: {
  downMbps: number; upMbps: number; idleMs: number; rpm: number | null; grade: BloatGrade | null;
}): string {
  let s = `Test complete. Download ${formatMbps(r.downMbps)} megabits per second, upload ${formatMbps(r.upMbps)}, ping ${Math.round(r.idleMs)} milliseconds`;
  if (r.rpm !== null && r.rpm > 0) s += `, responsiveness ${r.rpm} RPM, ${rpmBand(r.rpm).toLowerCase()}`;
  if (r.grade !== null) s += `, bufferbloat grade ${r.grade}`;
  return `${s}.`;
}
