/**
 * What the speed-test engine says while it runs (ADR 0054).
 *
 * The engine runs in its own `utilityProcess`; main relays these to the window
 * unread. The renderer only ever asks to start or cancel - it never names a
 * host, a URL or a size - and folds these events into what it draws
 * (`state.ts`).
 */
import type { BloatGrade, TransferFigure } from './method';

export type SpeedPhase = 'connecting' | 'latency' | 'download' | 'upload';

export interface SpeedServer {
  /** Cloudflare's data-centre code and city - what the test actually reached. */
  colo: string | null;
  coloCity: string | null;
  /**
   * Where that data centre is: from `/meta`, or the colo code resolved against
   * the bundled table (`colos.ts`) by the engine. Null when neither knew - the
   * globe then shows no pin and the results say so.
   */
  coloLat: number | null;
  coloLon: number | null;
  /** The network the test ran from, as Cloudflare saw it. */
  isp: string | null;
  asn: number | null;
  /** This machine's public address as the server saw it. Shown, never stored remotely. */
  ip: string | null;
  city: string | null;
}

/**
 * One latency probe: when it ran (from its phase's start), the server's
 * round trip for it (`netLatency`: Cloudflare's smoothed kernel RTT when sent),
 * and the client's own time to first byte net of the server's time. The first
 * is what the figures and the grade compare; the second is what the boxes
 * draw, because a smoothed RTT moves an eighth of the way per sample and so
 * hides most of the spread.
 */
export interface LatencySample { tMs: number; rttMs: number; ttfbMs: number }

/** Where a set of latencies falls: the box and whiskers the sheet draws. */
export interface Spread { n: number; p10: number; p25: number; p50: number; p75: number; p90: number }

/** One direction, as the engine finished it. */
export type SpeedTransfer = TransferFigure & {
  loadedLatencyMs: number | null;
  connections: number;
  /** Mb/s in each 100 ms slice from the start, warm-up included, the partial last slice dropped. */
  trace: number[];
  /** The loaded-latency probes, in order. */
  loaded: LatencySample[];
  /** When the ramp added connections, ms from the start. */
  rampsAtMs: number[];
};

/** What the sheet prints beside the figures, built by the engine so a run nobody watched has it too. */
export interface SpeedSummary {
  /** Spreads of time to first byte, per phase; null where no probe answered. */
  idle: Spread | null;
  download: Spread | null;
  upload: Spread | null;
  /** Round trips a minute at the worse loaded median - approximate, see `rpm`. */
  rpm: number | null;
  /** Bytes over time past warm-up: the cursor beside the median. */
  downMeanMbps: number | null;
  upMeanMbps: number | null;
}

export interface SpeedResult {
  /** Epoch ms the test finished. */
  at: number;
  server: SpeedServer;
  latency: { idleMs: number; jitterMs: number; samples: number; idle: LatencySample[] };
  download: SpeedTransfer;
  upload: SpeedTransfer;
  /** Null when no loaded probe answered in either phase: nothing to grade. */
  grade: BloatGrade | null;
  summary: SpeedSummary;
  /** Every byte both directions moved, for the "transfers up to" promise. */
  bytesMoved: number;
}

export type SpeedEvent =
  | { type: 'phase'; phase: SpeedPhase }
  | { type: 'server'; server: SpeedServer }
  /** One idle-latency sample, in order, with the jitter estimate so far. */
  | { type: 'latency'; ms: number; jitterMs: number | null; ttfbMs: number; tMs: number }
  /**
   * A transfer's running speed: `mbps` over the last second, for the figure,
   * and `sliceMbps` over the last 100 ms alone, for the trace.
   */
  | { type: 'progress'; phase: 'download' | 'upload'; mbps: number; sliceMbps: number; elapsedMs: number; connections: number }
  /** One loaded-latency probe during a transfer; `ms` is its round trip. */
  | { type: 'loaded'; phase: 'download' | 'upload'; ms: number; ttfbMs: number; tMs: number }
  /** A phase finished; its figure is final. */
  | { type: 'figure'; phase: 'download' | 'upload'; figure: TransferFigure }
  | { type: 'done'; result: SpeedResult }
  /** Nothing more will come. `rateLimited` when Cloudflare answered 429. */
  | { type: 'failed'; phase: SpeedPhase; message: string; rateLimited?: boolean }
  | { type: 'cancelled' };

/** Narrowing a message from main, which the renderer never trusts blindly. */
export function isSpeedEvent(value: unknown): value is SpeedEvent {
  if (typeof value !== 'object' || value === null) return false;
  const type = (value as { type?: unknown }).type;
  return type === 'phase' || type === 'server' || type === 'latency' || type === 'progress'
    || type === 'loaded' || type === 'figure' || type === 'done' || type === 'failed' || type === 'cancelled';
}
