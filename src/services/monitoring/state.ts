/**
 * What the UI knows about monitoring, as one value (ADR 0059).
 *
 * Three independent sources feed it - the utility's `IntakeStatus` relayed by
 * main, the Worker's `rebuild` progress, and the facts about the link itself
 * (connecting, connected, gone) - and they arrive in no fixed order. A pure
 * reducer keeps them from contradicting each other: the runtime being
 * unavailable wins over a late rebuild message, and a dead utility cannot
 * leave the last status saying it is still listening.
 *
 * Plain data in, plain data out, so `scripts/monitoring/runtime-host.ts`
 * drives every transition without React.
 */
import type { IntakeStatus, RuntimeExit } from './control';
import type { SourceHealth } from './sourceHealth';
import { LIMITS } from './types';
import type { RebuildPhase } from './workerHost';

/** `idle` before the first connect, `unavailable` once the utility or the Worker is gone. */
export type RuntimeState = 'idle' | 'connecting' | 'connected' | 'unavailable';

export interface RebuildProgress {
  phase: RebuildPhase;
  fedThroughEntryId: number;
  targetEntryId: number;
  message: string | null;
}

export interface MonitoringState {
  runtime: RuntimeState;
  /** The last status main relayed; kept, but corrected, after an exit. */
  intake: IntakeStatus | null;
  rebuild: RebuildProgress | null;
  /** Why the runtime is unavailable, in words, or null. */
  problem: string | null;
  /** The exit that made it so, when it was the utility's. */
  exit: RuntimeExit | null;
  /**
   * The Worker's last word on the source: null until a datagram that arrived after the connect
   * names an exporter, and again whenever the Worker is gone. Listener, storage and the
   * rejected and shed counts are `intake`'s, not this.
   * In the Worker those four `SourceHealth` fields keep the reducer's defaults (`stopped`, `ok`, empty, 0): `state.intake` is authoritative for them.
   */
  health: SourceHealth | null;
  /** The engine-form source keys the Worker knows, sorted. */
  sources: string[];
  /**
   * The renderer's clock at the first status that said `listening`, kept while it stays so and
   * null otherwise: when "nothing has arrived for a minute" starts counting (`nothingArriving`).
   */
  listeningSinceMs: number | null;
}

export type MonitoringEvent =
  | { type: 'connecting' }
  | { type: 'connected'; phase: RebuildPhase; watermark: number }
  /** `atMs` is the client's clock when the status arrived, so the reducer stays pure. */
  | { type: 'status'; status: IntakeStatus; atMs: number }
  | { type: 'health'; health: SourceHealth | null; sources: string[] }
  | { type: 'rebuild'; progress: RebuildProgress }
  | { type: 'exit'; exit: RuntimeExit }
  /** The Worker failed or never connected: not the utility's exit, but just as final for this client. */
  | { type: 'unavailable'; message: string }
  | { type: 'reset' };

export const initialMonitoringState: MonitoringState = {
  runtime: 'idle', intake: null, rebuild: null, problem: null, exit: null, health: null, sources: [], listeningSinceMs: null,
};

/**
 * Whether to show the firewall / wrong-target hint: listening for `LIMITS.staleMs` and not one
 * datagram from the exporter since. `IntakeStatus.received` counts this session and starts over
 * with the collector, and so does `listeningSinceMs`, so zero is "nothing since this listening began".
 */
export function nothingArriving(state: MonitoringState, nowMs: number): boolean {
  return state.intake !== null && state.intake.listener === 'listening'
    && state.listeningSinceMs !== null && nowMs - state.listeningSinceMs >= LIMITS.staleMs
    && state.intake.received === 0;
}

export function reduceMonitoring(state: MonitoringState, event: MonitoringEvent): MonitoringState {
  switch (event.type) {
    case 'connecting':
      return { ...state, runtime: 'connecting', rebuild: null, problem: null, exit: null, health: null, sources: [] };
    case 'connected':
      return {
        ...state, runtime: 'connected', problem: null, exit: null,
        rebuild: { phase: event.phase, fedThroughEntryId: event.watermark, targetEntryId: event.watermark, message: null },
      };
    case 'status':
      // Status is the utility's own word and does not depend on the Worker,
      // so it is taken while only the Worker is gone; after the utility's
      // exit it has no more to say and whatever arrives is a straggler.
      if (state.exit !== null) return state;
      return {
        ...state, intake: event.status,
        listeningSinceMs: event.status.listener === 'listening' ? state.listeningSinceMs ?? event.atMs : null,
      };
    case 'health':
      return state.runtime === 'unavailable' || state.runtime === 'idle' ? state : { ...state, health: event.health, sources: event.sources };
    case 'rebuild':
      return state.runtime === 'unavailable' || state.runtime === 'idle' ? state : { ...state, rebuild: event.progress };
    case 'exit':
      return {
        ...state, runtime: 'unavailable', rebuild: null, problem: event.exit.message, exit: event.exit,
        health: null, sources: [], listeningSinceMs: null,
        // The process is gone, so nothing is listening and nothing is attached.
        intake: state.intake === null ? null : { ...state.intake, listener: 'stopped', sessionId: null, workerAttached: false },
      };
    case 'unavailable':
      return { ...state, runtime: 'unavailable', rebuild: null, problem: event.message, exit: null, health: null, sources: [] };
    case 'reset':
      return initialMonitoringState;
  }
}
