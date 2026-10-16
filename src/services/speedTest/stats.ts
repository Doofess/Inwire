/**
 * What a finished speed test summarises to, and the axis the sheet draws its
 * latencies on. Pure, so the engine builds the summary into the result (a run
 * nobody watched has it too) and the sheet draws from the same numbers.
 */
import { median, quantile, rpm, SLICE_MS } from './method';
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
