/**
 * The one monitoring client of this page (ADRs 0059, 0060).
 *
 * The sheet, the status bar and anything else that shows monitoring read the same
 * `MonitoringClient`, so the Worker, the port main ferries and the state they fold
 * exist once. It is built the first time something asks, and **asking does not
 * connect**: the client registers for main's status and exit pushes (cheap, and
 * the status bar wants them before any sheet is opened) but the Worker and the
 * journal behind it start only at `ensureConnected()`, which the sheet calls when
 * it opens. A page that never opens monitoring never starts a Worker.
 *
 * Real dependencies, so nothing under `scripts/` imports this: they build a
 * `MonitoringClient` with fakes.
 */
import { MonitoringClient, type MonitoringBridge, type MessageTarget, type WorkerLike } from './client';

let instance: MonitoringClient | null = null;

function createWorker(): WorkerLike {
  // A module worker through the bundler, as the packet pipeline's is.
  return new Worker(new URL('../../workers/monitoring.worker.ts', import.meta.url), {
    type: 'module',
    name: 'inwire-monitoring',
  });
}

/** The page's client; constructed on first use and never connected by being constructed. */
export function getMonitoringClient(): MonitoringClient {
  if (instance === null) {
    instance = new MonitoringClient({
      // Absent outside the desktop shell: every method is optional and the client says so.
      bridge: (window.inwire ?? {}) as MonitoringBridge,
      createWorker,
      window: window as unknown as MessageTarget,
      timers: {
        setTimeout: (fn, ms) => window.setTimeout(fn, ms),
        clearTimeout: (handle) => window.clearTimeout(handle as number),
      },
      now: () => Date.now(),
    });
  }
  return instance;
}
