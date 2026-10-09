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

export interface SpeedResult {
  /** Epoch ms the test finished. */
  at: number;
  server: SpeedServer;
  latency: { idleMs: number; jitterMs: number; samples: number };
  download: TransferFigure & { loadedLatencyMs: number | null; connections: number };
  upload: TransferFigure & { loadedLatencyMs: number | null; connections: number };
  grade: BloatGrade;
  /** Every byte both directions moved, for the "transfers up to" promise. */
  bytesMoved: number;
}

export type SpeedEvent =
  | { type: 'phase'; phase: SpeedPhase }
  | { type: 'server'; server: SpeedServer }
  /** One idle-latency sample, in order, with the jitter estimate so far. */
  | { type: 'latency'; ms: number; jitterMs: number | null }
  /** A transfer's running speed: the last second, sampled every slice-ish. */
  | { type: 'progress'; phase: 'download' | 'upload'; mbps: number; elapsedMs: number; connections: number }
  /** One loaded-latency probe during a transfer. */
  | { type: 'loaded'; phase: 'download' | 'upload'; ms: number }
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
