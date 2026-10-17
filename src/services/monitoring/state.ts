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
}

export type MonitoringEvent =
  | { type: 'connecting' }
  | { type: 'connected'; phase: RebuildPhase; watermark: number }
  | { type: 'status'; status: IntakeStatus }
  | { type: 'rebuild'; progress: RebuildProgress }
  | { type: 'exit'; exit: RuntimeExit }
  /** The Worker failed or never connected: not the utility's exit, but just as final for this client. */
  | { type: 'unavailable'; message: string }
  | { type: 'reset' };

export const initialMonitoringState: MonitoringState = {
  runtime: 'idle', intake: null, rebuild: null, problem: null, exit: null,
};

export function reduceMonitoring(state: MonitoringState, event: MonitoringEvent): MonitoringState {
  switch (event.type) {
    case 'connecting':
      return { ...state, runtime: 'connecting', rebuild: null, problem: null, exit: null };
    case 'connected':
      return {
        ...state, runtime: 'connected', problem: null, exit: null,
        rebuild: { phase: event.phase, fedThroughEntryId: event.watermark, targetEntryId: event.watermark, message: null },
      };
    case 'status':
      // Status is the utility's own word and does not depend on the Worker,
      // so it is taken while only the Worker is gone; after the utility's
      // exit it has no more to say and whatever arrives is a straggler.
      return state.exit !== null ? state : { ...state, intake: event.status };
    case 'rebuild':
      return state.runtime === 'unavailable' || state.runtime === 'idle' ? state : { ...state, rebuild: event.progress };
    case 'exit':
      return {
        ...state, runtime: 'unavailable', rebuild: null, problem: event.exit.message, exit: event.exit,
        // The process is gone, so nothing is listening and nothing is attached.
        intake: state.intake === null ? null : { ...state.intake, listener: 'stopped', sessionId: null, workerAttached: false },
      };
    case 'unavailable':
      return { ...state, runtime: 'unavailable', rebuild: null, problem: event.message, exit: null };
    case 'reset':
      return initialMonitoringState;
  }
}
