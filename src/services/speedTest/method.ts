/**
 * The speed test's arithmetic, apart from any socket (ADR 0054).
 *
 * The engine (`electron/speedTest/engine.ts`) moves bytes and reads clocks; what
 * a run of bytes and clocks MEANS is decided here, where a script can hold it
 * under plain `tsx`. The method is Cloudflare's, ported rather than shipped -
 * their library posts every result back to them - and tightened where the
 * research said to (`docs/ideas/network-monitoring-and-speed-test.md`, Part 2).
 */

/** How long each direction runs. */
export const TRANSFER_MS = 10_000;
/** Bytes counted per slice of this length. */
export const SLICE_MS = 100;
/** The first stretch of a transfer is TCP slow start and says nothing about the link. */
export const WARMUP_MS = 2_000;
/** Connections a transfer opens with, and the most it ramps to. */
export const START_CONNECTIONS = 4;
export const MAX_CONNECTIONS = 8;
/** Connections added per step, and how often a step is considered. */
export const RAMP_STEP = 2;
export const RAMP_EVERY_MS = 1_000;
/** A step is taken while the last second beat the one before by this much. */
export const RAMP_GAIN = 1.1;
/**
 * The most a test transfers, whatever the link. Cloudflare rate-limits an
 * address that pulls much more - a measured 429 after about a gigabyte in a
 * few minutes - so a cap is what keeps a second test possible. At 1 Gb/s the
 * download reaches it in about five seconds: three past warm-up, thirty
 * slices, plenty for a median. Faster than that, the figure is the cap's.
 */
export const DOWNLOAD_CAP_BYTES = 600_000_000;
export const UPLOAD_CAP_BYTES = 200_000_000;
/**
 * Per request. `__down` refuses 100,000,000 bytes and more outright, and an
 * address it is limiting is refused large requests first - measured: 1 and 5
 * MB answered 200 while 10 and 25 MB answered 429. Five megabytes keeps under
 * that, and over keep-alive with four to eight connections the gap between
 * requests costs the link nothing it would notice.
 */
export const DOWNLOAD_REQUEST_BYTES = 5_000_000;
export const UPLOAD_REQUEST_BYTES = 5_000_000;
/** Empty requests for idle latency; the first only opens the connection and is dropped. */
export const LATENCY_SAMPLES = 20;
/** Loaded latency is probed this often during a transfer, on a connection of its own. */
export const LOADED_PROBE_MS = 150;

/** The most a test could move, for the consent copy. */
export const TEST_CAP_MB = Math.round((DOWNLOAD_CAP_BYTES + UPLOAD_CAP_BYTES) / 1e6);

/** The `q`-quantile (0..1) of numbers, by linear interpolation. Null for none. */
export function quantile(values: readonly number[], q: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const at = (sorted.length - 1) * Math.min(1, Math.max(0, q));
  const lo = Math.floor(at);
  const hi = Math.ceil(at);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (at - lo);
}

export const median = (values: readonly number[]): number | null => quantile(values, 0.5);

/** Jitter: the mean absolute difference between successive samples, in their order. */
export function jitter(samples: readonly number[]): number | null {
  if (samples.length < 2) return null;
  let sum = 0;
  for (let i = 1; i < samples.length; i++) sum += Math.abs(samples[i] - samples[i - 1]);
  return sum / (samples.length - 1);
}

/** Bytes counted into fixed slices of time since a transfer began. */
export class SliceCounter {
  readonly slices: number[] = [];
  constructor(readonly sliceMs = SLICE_MS) {}
  /** `bytes` arrived `elapsedMs` after the transfer began. */
  add(elapsedMs: number, bytes: number): void {
    const i = Math.max(0, Math.floor(elapsedMs / this.sliceMs));
    while (this.slices.length <= i) this.slices.push(0);
    this.slices[i] += bytes;
  }
  /** Megabits a second over the slices covering `[fromMs, toMs)`. */
  mbpsOver(fromMs: number, toMs: number): number {
    const a = Math.max(0, Math.floor(fromMs / this.sliceMs));
    const b = Math.min(this.slices.length, Math.ceil(toMs / this.sliceMs));
    if (b <= a) return 0;
    let bytes = 0;
    for (let i = a; i < b; i++) bytes += this.slices[i];
    return toMbps(bytes, (b - a) * this.sliceMs);
  }
}

export function toMbps(bytes: number, ms: number): number {
  return ms <= 0 ? 0 : (bytes * 8) / (ms * 1000);
}

/** One direction's answer: the median slice past warm-up, with its spread. */
export interface TransferFigure {
  mbps: number;
  p10: number;
  p90: number;
  /** Slices the figure stands on. */
  slices: number;
  bytes: number;
}

/**
 * What a transfer measured.
 *
 * Each slice past warm-up is a speed; the answer is their median, because one
 * stalled or bursting slice should move a robust figure not at all. The last
 * slice is partial (the transfer stopped inside it) and is dropped. A transfer
 * too short to leave anything past warm-up - a cap reached early on a very
 * fast link - falls back to the second half of what there is.
 */
export function transferFigure(counter: SliceCounter, warmupMs = WARMUP_MS, elapsedMs?: number): TransferFigure | null {
  const whole = counter.slices.slice(0, Math.max(0, counter.slices.length - 1));
  const total = counter.slices.reduce((a, b) => a + b, 0);
  if (whole.length === 0) {
    // Over inside one slice - a cap reached at once on a link far faster than
    // the cap was sized for. No slice to take a median of, so the whole: bytes
    // over the time they took.
    if (total === 0 || !elapsedMs) return null;
    const mbps = toMbps(total, elapsedMs);
    return { mbps, p10: mbps, p90: mbps, slices: 0, bytes: total };
  }
  let from = Math.floor(warmupMs / counter.sliceMs);
  if (from >= whole.length) from = Math.floor(whole.length / 2);
  const kept = whole.slice(from).map((b) => toMbps(b, counter.sliceMs));
  if (kept.length === 0) return null;
  return {
    mbps: median(kept)!,
    p10: quantile(kept, 0.1)!,
    p90: quantile(kept, 0.9)!,
    slices: kept.length,
    bytes: total,
  };
}

/**
 * Whether to open more connections: while the last second beat the one before
 * it by `RAMP_GAIN`, two at a time up to `MAX_CONNECTIONS`, never in warm-up's
 * first second (everything rises then).
 */
export function shouldRamp(connections: number, lastSecondMbps: number, secondBeforeMbps: number): boolean {
  if (connections >= MAX_CONNECTIONS) return false;
  if (secondBeforeMbps <= 0) return false;
  // A hair of tolerance: 100 * 1.1 is 110.00000000000001 in a double.
  return lastSecondMbps >= secondBeforeMbps * RAMP_GAIN - 1e-9;
}

export type BloatGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/** Bufferbloat, from how much latency rose under load. The bands in common use. */
export function bloatGrade(idleMs: number, loadedMs: number): BloatGrade {
  const rise = Math.max(0, loadedMs - idleMs);
  if (rise < 5) return 'A+';
  if (rise < 30) return 'A';
  if (rise < 60) return 'B';
  if (rise < 200) return 'C';
  if (rise < 400) return 'D';
  return 'F';
}

/** Responsiveness in round trips per minute, as Apple's `networkQuality` reports it. */
export const rpm = (latencyMs: number): number => (latencyMs > 0 ? Math.round(60_000 / latencyMs) : 0);

/**
 * The gauge's marks: Ookla's non-linear scale, each mark an equal step of arc,
 * so 5 Mb/s and 500 Mb/s are both readable on one dial.
 */
export const GAUGE_MARKS = [0, 5, 10, 50, 100, 250, 500, 750, 1000] as const;

/** Where `mbps` sits on the dial, 0..1, interpolated linearly between marks and pinned past the last. */
export function gaugeFraction(mbps: number): number {
  if (!(mbps > 0)) return 0;
  const steps = GAUGE_MARKS.length - 1;
  for (let i = 1; i < GAUGE_MARKS.length; i++) {
    if (mbps <= GAUGE_MARKS[i]) {
      const lo = GAUGE_MARKS[i - 1];
      const hi = GAUGE_MARKS[i];
      return (i - 1 + (mbps - lo) / (hi - lo)) / steps;
    }
  }
  return 1;
}

/** A speed as the dial and the tiles print it: three significant figures, never an exponent. */
export function formatMbps(mbps: number): string {
  if (!(mbps > 0)) return '0';
  if (mbps >= 100) return mbps.toFixed(0);
  if (mbps >= 10) return mbps.toFixed(1);
  return mbps.toFixed(2);
}

/**
 * Round-trip time for one empty request.
 *
 * **The server's own measurement of the TCP round trip, when it sends one.**
 * Cloudflare reports its kernel's smoothed RTT for the connection in
 * `Server-Timing: cfL4;desc="?...&rtt=<us>&..."`, and measured against it the
 * client-side figure - time to first byte, net of the `cfSpeedEdge` and
 * `cfSpeedWorker` durations - was still 5-15 ms over a 3 ms round trip: the
 * server spends time it does not report. Idle and loaded latency both use the
 * same measure, so the bufferbloat grade compares like with like.
 *
 * Without that header (another server, the tests' local one): time to first
 * byte net of the server time it reports. Never below a tenth of a
 * millisecond: a server time that outran the client's clock is skew, not a
 * negative trip.
 */
export function netLatency(elapsedMs: number, serverTiming: string | undefined): number {
  const rttUs = serverTiming ? /cfL4;[^,]*?[?&]rtt=([0-9]+)/.exec(serverTiming)?.[1] : undefined;
  if (rttUs !== undefined) return Math.max(0.1, Number(rttUs) / 1000);
  return Math.max(0.1, elapsedMs - serverTimeMs(serverTiming));
}

/**
 * The server's measure of how much the round trip varies, in ms: the kernel's
 * `rtt_var` from `cfL4` (RFC 6298's RTTVAR, a smoothed mean deviation).
 *
 * **Jitter comes from here when it is sent, not from successive samples.** The
 * `rtt` beside it is SMOOTHED - each sample moves it an eighth of the way - so
 * the differences between successive values read about an eighth of the real
 * variation, and the first real test reported 0.0 ms. Null without the header.
 */
export function serverRttVarMs(serverTiming: string | undefined): number | null {
  const us = serverTiming ? /cfL4;[^,]*?[?&]rtt_var=([0-9]+)/.exec(serverTiming)?.[1] : undefined;
  return us === undefined ? null : Number(us) / 1000;
}

/** The server's time out of a `Server-Timing` header: what this server reports spending. */
export function serverTimeMs(header: string | undefined): number {
  if (!header) return 0;
  const dur = (name: string): number | null => {
    const m = new RegExp(`${name};dur=([0-9.]+)`).exec(header);
    return m ? Number(m[1]) : null;
  };
  const request = dur('cfRequestDuration');
  if (request !== null) return request;
  return (dur('cfSpeedEdge') ?? 0) + (dur('cfSpeedWorker') ?? 0);
}
