/**
 * The renderer's side of monitoring (ADRs 0058, 0059): one Worker for history,
 * one port ferried to it, and the control calls that go to main.
 *
 * Nothing live passes through here. The port main sends arrives as a window
 * message, is transferred straight into the Worker without being read, and
 * from then on the Worker talks to the utility itself; this class sees only
 * queries, details and the Worker's rebuild progress. Start, Stop and the
 * saved source go to main over the bridge, and the utility's status and exit
 * come back the same way, because control never travels on the runtime port.
 *
 * Four rules, each there because a plausible alternative hangs or lies:
 *
 * - **A port is taken only from this window, on the literal channel.** The
 *   preload posts to `'*'`, so the `source === window` check is what makes
 *   that safe, and the channel is a string here because the renderer cannot
 *   import `electron/`.
 * - **Every call settles.** A runtime exit, a Worker error or a dispose
 *   fails each pending query (`runtime-unavailable`), detail (`null`) and
 *   connect, then terminates the Worker. A pending promise that outlives its
 *   runtime is a spinner that never stops.
 * - **A dead runtime is replaced, not repaired.** The next `connect` makes a
 *   new Worker and asks for a new port; the old one is never reused.
 * - **Everything from main and the Worker is `unknown` until read** with the
 *   readers in `control.ts`.
 *
 * Imports no Electron and no `node:*`, and takes the bridge, the Worker
 * factory, the window and the timers as parameters, so a script drives it
 * with fakes.
 */
import { readSourceConfig } from './config';
import {
  readIntakeStatus, readRuntimeExit, readStartResult, readStopResult,
  type StartResult, type StopResult,
} from './control';
import {
  initialMonitoringState, reduceMonitoring, type MonitoringEvent, type MonitoringState,
} from './state';
import type {
  DatagramEvidence, EvidenceRef, HistoryReply, NormalizedV5, QuerySpec, Snapshot, SourceConfig,
} from './types';
import { LIMITS } from './types';
import type { FromMonitoringWorker, RebuildPhase, ToMonitoringWorker } from './workerHost';

/** The window message main's port arrives on (`MONITORING_PORT_CHANNEL`, which the renderer cannot import). */
export const MONITORING_PORT_MESSAGE = 'inwire:monitoring-port';

// --- what is injected ---------------------------------------------------------------------------------------

/** The methods of `window.inwire` this class uses; each optional, like the rest of the bridge. */
export interface MonitoringBridge {
  requestMonitoringPort?(): Promise<unknown>;
  getMonitoringConfig?(): Promise<unknown>;
  saveMonitoringConfig?(config: unknown): Promise<unknown>;
  startMonitoring?(config: unknown): Promise<unknown>;
  stopMonitoring?(): Promise<unknown>;
  onMonitoringRuntimeExit?(listener: (exit: unknown) => void): () => void;
  onMonitoringStatus?(listener: (status: unknown) => void): () => void;
}

export interface PortMessageEvent {
  source: unknown;
  data: unknown;
  ports: readonly unknown[];
}

/** `window`, as far as this class goes. */
export interface MessageTarget {
  addEventListener(type: 'message', listener: (event: PortMessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: PortMessageEvent) => void): void;
}

/** A `Worker`, as far as this class goes. */
export interface WorkerLike {
  postMessage(message: unknown, transfer?: unknown[]): void;
  terminate(): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'error', listener: (event: { message?: string }) => void): void;
}

export interface ClientTimers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ClientDeps {
  bridge: MonitoringBridge;
  createWorker(): WorkerLike;
  window: MessageTarget;
  timers: ClientTimers;
  /** How long to wait for main's port after it has answered; `LIMITS.handshakeMs` by default. */
  portWaitMs?: number;
}

// --- results ------------------------------------------------------------------------------------------------------

export type ConnectResult =
  | { ok: true; phase: RebuildPhase; watermark: number }
  | { ok: false; message: string };

/** A datagram and the record decoded from it (the Worker answers both; the UI needs both). */
export interface DetailResult { evidence: DatagramEvidence; record: NormalizedV5 }

export type ConfigReadReply = { ok: true; config: SourceConfig | null } | { ok: false; message: string };
export type ConfigSaveReply = { ok: true; config: SourceConfig } | { ok: false; message: string };

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const describe = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const UNREADABLE = 'main answered with something this build cannot read';
const UNAVAILABLE = 'monitoring is not available in this build';
const REBUILD_PHASES: ReadonlySet<string> = new Set<RebuildPhase>(['idle', 'rebuilding', 'live', 'failed']);

/** A refusal main gives instead of a port: `{ ok: false, message }`. Anything else means "wait for the port". */
function readRefusal(v: unknown): string | null {
  return isObject(v) && v.ok === false && typeof v.message === 'string' ? v.message : null;
}

export function readConfigReply(v: unknown): ConfigReadReply {
  if (!isObject(v)) return { ok: false, message: UNREADABLE };
  if (v.ok === false && typeof v.message === 'string') return { ok: false, message: v.message };
  if (v.ok !== true) return { ok: false, message: UNREADABLE };
  if (v.config === null) return { ok: true, config: null };
  const config = readSourceConfig(v.config);
  return config === null ? { ok: false, message: UNREADABLE } : { ok: true, config };
}

export function readSaveReply(v: unknown): ConfigSaveReply {
  const read = readConfigReply(v);
  if (!read.ok) return read;
  return read.config === null ? { ok: false, message: UNREADABLE } : { ok: true, config: read.config };
}

// --- the client ----------------------------------------------------------------------------------------------------

type CallResult = { reply: FromMonitoringWorker } | { failure: string };

interface Pending {
  /** The reply type that answers it. */
  accepts: FromMonitoringWorker['type'];
  settle(result: CallResult): void;
}

interface PortWait {
  promise: Promise<unknown>;
  abort(reason: string): void;
}

export class MonitoringClient {
  private snapshot: MonitoringState = initialMonitoringState;
  private readonly listeners = new Set<(state: MonitoringState) => void>();
  private worker: WorkerLike | null = null;
  private readonly pending = new Map<number, Pending>();
  private portWait: PortWait | null = null;
  private connecting: Promise<ConnectResult> | null = null;
  private lastId = 0;
  private disposed = false;
  private readonly unsubscribers: (() => void)[] = [];

  constructor(private readonly deps: ClientDeps) {
    const { bridge } = deps;
    const offExit = bridge.onMonitoringRuntimeExit?.((raw) => this.onRuntimeExit(raw));
    const offStatus = bridge.onMonitoringStatus?.((raw) => {
      const status = readIntakeStatus(raw);
      if (status !== null) this.dispatch({ type: 'status', status });
    });
    for (const off of [offExit, offStatus]) if (off !== undefined) this.unsubscribers.push(off);
  }

  get state(): MonitoringState { return this.snapshot; }

  /** Calls `listener` with each new state; returns the unsubscribe. */
  subscribe(listener: (state: MonitoringState) => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  private dispatch(event: MonitoringEvent): void {
    const next = reduceMonitoring(this.snapshot, event);
    if (next === this.snapshot) return;
    this.snapshot = next;
    for (const listener of [...this.listeners]) listener(next);
  }

  // --- connect ---------------------------------------------------------------------------------------------------

  /**
   * Opens the history: asks main for a port (which opens the dataset and
   * never binds a socket), transfers it into a new Worker, and waits for the
   * Worker to say it holds a runtime. One attempt at a time; connecting when
   * already connected answers from the state.
   */
  connect(): Promise<ConnectResult> {
    if (this.disposed) return Promise.resolve({ ok: false, message: 'monitoring was shut down' });
    if (this.connecting !== null) return this.connecting;
    if (this.worker !== null && this.snapshot.runtime === 'connected') {
      const rebuild = this.snapshot.rebuild;
      return Promise.resolve({ ok: true, phase: rebuild?.phase ?? 'idle', watermark: rebuild?.fedThroughEntryId ?? 0 });
    }
    const attempt = this.attach().finally(() => {
      if (this.connecting === attempt) this.connecting = null;
    });
    this.connecting = attempt;
    return attempt;
  }

  private async attach(): Promise<ConnectResult> {
    const { bridge } = this.deps;
    if (bridge.requestMonitoringPort === undefined) {
      this.dispatch({ type: 'unavailable', message: UNAVAILABLE });
      return { ok: false, message: UNAVAILABLE };
    }
    this.dispatch({ type: 'connecting' });
    let worker: WorkerLike;
    try {
      worker = this.deps.createWorker();
    } catch (e) {
      return this.failConnect(null, `the monitoring Worker could not start (${describe(e)})`);
    }
    this.adopt(worker);
    // Listening before asking: the port may be posted before the answer returns.
    const wait = this.waitForPort();
    this.portWait = wait;
    try {
      const refused = readRefusal(await bridge.requestMonitoringPort());
      if (refused !== null) {
        wait.abort(refused);
        await wait.promise.catch(() => undefined);
        return this.failConnect(worker, refused);
      }
    } catch (e) {
      wait.abort(`main could not open monitoring (${describe(e)})`);
    }
    let port: unknown;
    try {
      port = await wait.promise;
    } catch (e) {
      return this.failConnect(worker, describe(e));
    } finally {
      if (this.portWait === wait) this.portWait = null;
    }
    if (this.worker !== worker) return { ok: false, message: 'the connection was cancelled' };
    const result = await this.call(worker, 'connect-reply', (requestId) => ({ type: 'connect', requestId, port }), [port]);
    if ('failure' in result) return this.failConnect(worker, result.failure);
    const reply = result.reply;
    if (reply.type !== 'connect-reply') return this.failConnect(worker, UNREADABLE);
    if (!reply.ok) return this.failConnect(worker, reply.message);
    this.dispatch({ type: 'connected', phase: reply.phase, watermark: reply.watermark });
    return { ok: true, phase: reply.phase, watermark: reply.watermark };
  }

  /** Ends this attempt's Worker, unless something else already ended it, and says why. */
  private failConnect(worker: WorkerLike | null, message: string): ConnectResult {
    if (worker === null || this.worker === worker) {
      this.teardown(message);
      this.dispatch({ type: 'unavailable', message });
    }
    return { ok: false, message };
  }

  private waitForPort(): PortWait {
    const { window, timers } = this.deps;
    let abort!: (reason: string) => void;
    const promise = new Promise<unknown>((resolve, reject) => {
      const onMessage = (event: PortMessageEvent): void => {
        if (event.source !== window) return;
        if (!isObject(event.data) || event.data.channel !== MONITORING_PORT_MESSAGE) return;
        const [port] = event.ports;
        if (port === undefined) return;
        finish();
        resolve(port);
      };
      const timer = timers.setTimeout(() => {
        finish();
        reject(new Error('main did not send a monitoring port'));
      }, this.deps.portWaitMs ?? LIMITS.handshakeMs);
      const finish = (): void => {
        window.removeEventListener('message', onMessage);
        timers.clearTimeout(timer);
      };
      abort = (reason) => {
        finish();
        reject(new Error(reason));
      };
      window.addEventListener('message', onMessage);
    });
    return { promise, abort };
  }

  // --- the Worker ------------------------------------------------------------------------------------------------

  private adopt(worker: WorkerLike): void {
    this.worker = worker;
    worker.addEventListener('message', (event) => {
      if (this.worker === worker) this.onWorkerMessage(event.data);
    });
    worker.addEventListener('error', (event) => {
      if (this.worker !== worker) return;
      const message = `the monitoring Worker failed${event.message ? ` (${event.message})` : ''}`;
      this.teardown(message);
      this.dispatch({ type: 'unavailable', message });
    });
  }

  private onWorkerMessage(data: unknown): void {
    if (!isObject(data) || typeof data.type !== 'string') return;
    if (data.type === 'rebuild') {
      const { phase, fedThroughEntryId, targetEntryId, message } = data;
      if (typeof phase !== 'string' || !REBUILD_PHASES.has(phase)) return;
      if (typeof fedThroughEntryId !== 'number' || typeof targetEntryId !== 'number') return;
      this.dispatch({
        type: 'rebuild',
        progress: { phase: phase as RebuildPhase, fedThroughEntryId, targetEntryId, message: typeof message === 'string' ? message : null },
      });
      return;
    }
    if (typeof data.requestId !== 'number') return;
    const pending = this.pending.get(data.requestId);
    if (pending === undefined) return;
    if (data.type === 'error-reply') {
      pending.settle({ failure: typeof data.message === 'string' ? data.message : UNREADABLE });
    } else if (data.type === pending.accepts) {
      pending.settle({ reply: data as unknown as FromMonitoringWorker });
    }
  }

  /** Posts one request and waits for the reply that answers it, or for the runtime to go. */
  private call(
    worker: WorkerLike, accepts: Pending['accepts'], build: (requestId: number) => ToMonitoringWorker, transfer?: unknown[],
  ): Promise<CallResult> {
    return new Promise<CallResult>((resolve) => {
      const requestId = ++this.lastId;
      this.pending.set(requestId, {
        accepts,
        settle: (result) => {
          this.pending.delete(requestId);
          resolve(result);
        },
      });
      try {
        worker.postMessage(build(requestId), transfer);
      } catch (e) {
        this.pending.get(requestId)?.settle({ failure: `the monitoring Worker could not be reached (${describe(e)})` });
      }
    });
  }

  /** Terminates the Worker and fails everything waiting on it or on its port. */
  private teardown(reason: string): void {
    const worker = this.worker;
    this.worker = null;
    this.portWait?.abort(reason);
    this.portWait = null;
    for (const pending of [...this.pending.values()]) pending.settle({ failure: reason });
    try { worker?.terminate(); } catch { /* already gone */ }
  }

  private onRuntimeExit(raw: unknown): void {
    const exit = readRuntimeExit(raw);
    if (exit === null) return;
    this.teardown(exit.message);
    this.dispatch({ type: 'exit', exit });
  }

  // --- history ---------------------------------------------------------------------------------------------------

  async query(viewId: string, spec: QuerySpec): Promise<HistoryReply> {
    const worker = this.worker;
    if (worker === null || this.snapshot.runtime !== 'connected') {
      return { ok: false, code: 'runtime-unavailable', message: 'monitoring is not connected' };
    }
    const result = await this.call(worker, 'query-reply', (requestId) => ({ type: 'query', requestId, viewId, spec }));
    if ('failure' in result) return { ok: false, code: 'runtime-unavailable', message: result.failure };
    const reply = result.reply;
    if (reply.type !== 'query-reply' || !isObject(reply.reply) || typeof reply.reply.ok !== 'boolean') {
      return { ok: false, code: 'storage-failed', message: UNREADABLE };
    }
    return reply.reply;
  }

  /** One datagram and its decoded record, or null for any failure (stale, missing, runtime gone). */
  async detail(snapshot: Snapshot, ref: EvidenceRef, recordIndex: number): Promise<DetailResult | null> {
    const worker = this.worker;
    if (worker === null || this.snapshot.runtime !== 'connected') return null;
    const result = await this.call(worker, 'detail-reply', (requestId) => ({ type: 'detail', requestId, snapshot, ref, recordIndex }));
    if ('failure' in result) return null;
    const reply = result.reply;
    if (reply.type !== 'detail-reply' || !reply.ok) return null;
    if (!isObject(reply.evidence) || !isObject(reply.record)) return null;
    return { evidence: reply.evidence, record: reply.record };
  }

  // --- control ---------------------------------------------------------------------------------------------------

  async start(config: SourceConfig): Promise<StartResult> {
    const start = this.deps.bridge.startMonitoring;
    if (start === undefined) return { ok: false, message: UNAVAILABLE };
    try {
      return readStartResult(await start.call(this.deps.bridge, config));
    } catch (e) {
      return { ok: false, message: `Start could not reach monitoring (${describe(e)})` };
    }
  }

  async stop(): Promise<StopResult> {
    const stop = this.deps.bridge.stopMonitoring;
    if (stop === undefined) return { ok: false, message: UNAVAILABLE, clean: false, snapshot: null };
    try {
      return readStopResult(await stop.call(this.deps.bridge));
    } catch (e) {
      return { ok: false, message: `Stop could not reach monitoring (${describe(e)})`, clean: false, snapshot: null };
    }
  }

  async getConfig(): Promise<ConfigReadReply> {
    const get = this.deps.bridge.getMonitoringConfig;
    if (get === undefined) return { ok: false, message: UNAVAILABLE };
    try {
      return readConfigReply(await get.call(this.deps.bridge));
    } catch (e) {
      return { ok: false, message: `The saved source could not be read (${describe(e)})` };
    }
  }

  async saveConfig(config: SourceConfig): Promise<ConfigSaveReply> {
    const save = this.deps.bridge.saveMonitoringConfig;
    if (save === undefined) return { ok: false, message: UNAVAILABLE };
    try {
      return readSaveReply(await save.call(this.deps.bridge, config));
    } catch (e) {
      return { ok: false, message: `The source could not be saved (${describe(e)})` };
    }
  }

  /** Detaches from main, fails everything pending and ends the Worker. */
  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    for (const off of this.unsubscribers.splice(0)) off();
    this.teardown('monitoring was shut down');
    this.listeners.clear();
  }
}
