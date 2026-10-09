/**
 * What the speed-test surfaces draw, folded from the engine's events.
 *
 * A module-level store rather than App state, for the reason `byteRange.ts`
 * is one: the Network panel's section and the workspace sheet both read it, a
 * test keeps running when the sheet is closed, and progress arrives ten times a
 * second - App re-rendering at that rate for a dial nobody may be looking at is
 * the regression `packetCounts.ts` exists to prevent. The reducer is pure so
 * `scripts/speed-test/state.ts` can drive it.
 */
import { useSyncExternalStore } from 'react';
import { median } from './method';
import { isSpeedEvent, type SpeedEvent, type SpeedPhase, type SpeedResult, type SpeedServer } from './protocol';
import { recordResult } from './history';

export type SpeedStatus = 'idle' | 'running' | 'done' | 'failed' | 'cancelled';

export interface SpeedState {
  status: SpeedStatus;
  phase: SpeedPhase | null;
  server: SpeedServer | null;
  /** Idle-latency samples so far, for the live ping tile, and the engine's jitter estimate. */
  latencySamples: number[];
  liveJitterMs: number | null;
  /** The dial's live value and the sparkline under it, for the transfer running. */
  liveMbps: number;
  spark: number[];
  connections: number;
  downloadMbps: number | null;
  uploadMbps: number | null;
  result: SpeedResult | null;
  error: { phase: SpeedPhase; message: string; rateLimited: boolean } | null;
}

export const IDLE: SpeedState = {
  status: 'idle', phase: null, server: null, latencySamples: [], liveJitterMs: null, liveMbps: 0, spark: [],
  connections: 0, downloadMbps: null, uploadMbps: null, result: null, error: null,
};

/** The state a fresh run starts from. */
export const STARTING: SpeedState = { ...IDLE, status: 'running', phase: 'connecting' };

/** The sparkline keeps this many points - about the last ten seconds. */
const SPARK_POINTS = 100;

export function reduceSpeed(state: SpeedState, event: SpeedEvent): SpeedState {
  switch (event.type) {
    case 'phase':
      return {
        ...state, status: 'running', phase: event.phase,
        // A new transfer starts its dial and sparkline from nothing.
        ...(event.phase === 'download' || event.phase === 'upload' ? { liveMbps: 0, spark: [], connections: 0 } : {}),
      };
    case 'server':
      return { ...state, server: event.server };
    case 'latency':
      return { ...state, latencySamples: [...state.latencySamples, event.ms], liveJitterMs: event.jitterMs };
    case 'progress':
      return {
        ...state,
        liveMbps: event.mbps,
        connections: event.connections,
        spark: [...state.spark, event.mbps].slice(-SPARK_POINTS),
      };
    case 'loaded':
      return state;
    case 'figure':
      return event.phase === 'download'
        ? { ...state, downloadMbps: event.figure.mbps, liveMbps: event.figure.mbps }
        : { ...state, uploadMbps: event.figure.mbps, liveMbps: event.figure.mbps };
    case 'done':
      return { ...state, status: 'done', phase: null, result: event.result };
    case 'failed':
      return {
        ...state, status: 'failed',
        error: { phase: event.phase, message: event.message, rateLimited: event.rateLimited === true },
      };
    case 'cancelled':
      return { ...state, status: 'cancelled', phase: null };
  }
}

/** The ping the tile shows while samples arrive: their median so far. */
export function livePing(state: SpeedState): number | null {
  return state.result?.latency.idleMs ?? median(state.latencySamples);
}

// --- the store -----------------------------------------------------------------

let current: SpeedState = IDLE;
const listeners = new Set<() => void>();
let bridgeSubscribed = false;

function set(next: SpeedState): void {
  current = next;
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function useSpeedTest(): SpeedState {
  return useSyncExternalStore(subscribe, () => current, () => current);
}

/** Whether this build can run a test at all: the desktop bridge is there. */
export function speedTestAvailable(): boolean {
  return typeof window !== 'undefined' && typeof window.inwire?.startSpeedTest === 'function';
}

/**
 * Starts a test. One at a time; a second press while one runs does nothing.
 * The click IS the consent - there is no test the reader did not start.
 */
export function startSpeedTest(): void {
  const bridge = typeof window === 'undefined' ? undefined : window.inwire;
  if (!bridge?.startSpeedTest || current.status === 'running') return;
  if (!bridgeSubscribed && bridge.onSpeedTestEvent) {
    bridgeSubscribed = true;
    // Once, for the life of the window: the store outlives every surface.
    bridge.onSpeedTestEvent((raw) => {
      if (!isSpeedEvent(raw)) return;
      if (raw.type === 'done') recordResult(raw.result);
      set(reduceSpeed(current, raw));
    });
  }
  set(STARTING);
  void bridge.startSpeedTest().catch((error: unknown) => {
    set({
      ...current, status: 'failed',
      error: { phase: 'connecting', message: error instanceof Error ? error.message : String(error), rateLimited: false },
    });
  });
}

export function cancelSpeedTest(): void {
  if (current.status !== 'running') return;
  void window.inwire?.cancelSpeedTest?.();
}
