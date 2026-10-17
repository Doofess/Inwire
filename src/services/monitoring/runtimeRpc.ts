/**
 * `MonitoringRuntime` across a `MessagePort` (ADR 0059): `serveRuntime` is the
 * utility process's half and `createRuntimeClient` the Worker's.
 *
 * The port is the only thing either half knows about the other, so it is the
 * smallest thing that can be faked or replaced: `RpcPort` is a post, a message
 * handler and optionally a close. `domPort` adapts a `MessagePort`; the tests
 * use the same adapter over node's, which has the same `onmessage`.
 *
 * Four rules, each from a way a request/reply layer hangs a UI:
 *
 * - **Every call has a deadline.** A utility process that is busy, wedged or
 *   gone must not leave a query pending for ever, so a call that is not
 *   answered in `requestMs` is `RuntimeUnavailableError` - and a reply that
 *   arrives after that is dropped, never delivered to a caller who has already
 *   been told no.
 * - **A closed port fails everything at once**, pending and future, with the
 *   same error.
 * - **Errors cross by name.** An `Error` does not survive structured clone with
 *   its class, and the query maps `StaleGenerationError`, `RangeError`,
 *   `CorruptRollupError` and `RuntimeUnavailableError` to different answers, so
 *   the server sends `{name, message}` plus the two generation strings and the
 *   client rebuilds the class.
 * - **Live evidence is acknowledged, and a server is bounded.** The client
 *   answers every `live` push with `live-ack` once its handlers have settled,
 *   which is the credit the utility's feed spends (`liveFeed.ts`); and a server
 *   with `maxInFlight` requests unanswered refuses the next one at once, so a
 *   Worker that fires reads faster than the journal answers them is told the
 *   runtime is busy rather than queueing them without bound.
 */
import { StaleGenerationError } from './journal';
import { CorruptRollupError, RuntimeUnavailableError, type HostRuntime, type LiveMessage } from './runtime';
import type { Evidence } from './types';

export interface RpcPort {
  postMessage(message: unknown): void;
  onMessage(handler: (message: unknown) => void): void;
  onClose?(handler: () => void): void;
  close?(): void;
}

/** The subset of a DOM `MessagePort` (and of node's) this layer uses. */
interface PortLike {
  postMessage(message: unknown): void;
  // `any`: the DOM and node ports name different event types, and only `data` is read.
  onmessage: ((event: any) => unknown) | null;
  addEventListener?(type: string, listener: () => void): void;
  start?(): void;
  close(): void;
}

export function domPort(port: PortLike): RpcPort {
  return {
    postMessage: (m) => port.postMessage(m),
    onMessage: (handler) => {
      port.onmessage = (event: { data: unknown }) => handler(event.data);
      port.start?.();
    },
    onClose: (handler) => port.addEventListener?.('close', handler),
    close: () => port.close(),
  };
}

type Method =
  | 'snapshot' | 'readPage' | 'readEvidence' | 'locate' | 'readBoundaries' | 'watermark' | 'readMinutes'
  | 'sources' | 'appendMinutes' | 'rollupStatus' | 'resetRollups';

const METHODS: ReadonlySet<string> = new Set<Method>([
  'snapshot', 'readPage', 'readEvidence', 'locate', 'readBoundaries', 'watermark', 'readMinutes',
  'sources', 'appendMinutes', 'rollupStatus', 'resetRollups',
]);

interface Request { type: 'req'; id: number; method: string; args: unknown[] }
interface ErrorBody { name: string; message: string; wanted?: string; actual?: string }
type Reply = { type: 'res'; id: number; ok: true; value: unknown } | { type: 'res'; id: number; ok: false; error: ErrorBody };

function errorBody(e: unknown): ErrorBody {
  if (e instanceof StaleGenerationError) return { name: e.name, message: e.message, wanted: e.wanted, actual: e.actual };
  if (e instanceof Error) return { name: e.name, message: e.message };
  return { name: 'Error', message: String(e) };
}

function errorFrom(body: ErrorBody): Error {
  if (body.name === 'StaleGenerationError') return new StaleGenerationError(body.wanted ?? '', body.actual ?? '');
  if (body.name === 'RangeError') return new RangeError(body.message);
  if (body.name === 'CorruptRollupError') return new CorruptRollupError(body.message);
  if (body.name === 'RuntimeUnavailableError') return new RuntimeUnavailableError(body.message);
  const e = new Error(body.message);
  e.name = body.name;
  return e;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

// --- the serving half -------------------------------------------------------------------------------

export interface RuntimeServer {
  /** Sends entries the journal has just appended to the client, in order. */
  pushLive(entries: Evidence[]): void;
}

export interface ServeOptions {
  /** Called once per `live-ack` the client posts: the utility's credit coming back. */
  onLiveAck?: () => void;
  /** Requests unanswered at once, past which the next is refused as busy. Default 16. */
  maxInFlight?: number;
}

export const DEFAULT_MAX_IN_FLIGHT = 16;

export function serveRuntime(port: RpcPort, runtime: Omit<HostRuntime, 'onLive'>, options: ServeOptions = {}): RuntimeServer {
  const maxInFlight = options.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT;
  let inFlight = 0;
  port.onMessage((message) => {
    if (isObject(message) && message.type === 'live-ack') {
      options.onLiveAck?.();
      return;
    }
    if (!isObject(message) || message.type !== 'req' || typeof message.id !== 'number') return;
    const req = message as unknown as Request;
    // A port that closed under a reply has nobody to tell; it must not become an unhandled rejection.
    const reply = (r: Reply): void => {
      try { port.postMessage(r); } catch { /* the client is gone */ }
    };
    if (typeof req.method !== 'string' || !METHODS.has(req.method) || !Array.isArray(req.args)) {
      reply({ type: 'res', id: req.id, ok: false, error: { name: 'TypeError', message: `unknown runtime call ${String(req.method)}` } });
      return;
    }
    if (inFlight >= maxInFlight) {
      reply({
        type: 'res', id: req.id, ok: false,
        error: errorBody(new RuntimeUnavailableError(`the monitoring runtime is busy: ${maxInFlight} requests are already waiting`)),
      });
      return;
    }
    inFlight++;
    // The call is looked up in the table above, never by an arbitrary name from the port.
    const call = (runtime as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[req.method];
    Promise.resolve()
      .then(() => call.apply(runtime, req.args))
      .then(
        (value) => { inFlight--; reply({ type: 'res', id: req.id, ok: true, value }); },
        (e) => { inFlight--; reply({ type: 'res', id: req.id, ok: false, error: errorBody(e) }); },
      );
  });
  return {
    pushLive(entries) {
      const m: LiveMessage = { type: 'live', entries };
      port.postMessage(m);
    },
  };
}

// --- the calling half ---------------------------------------------------------------------------------

export interface ClientOptions {
  requestMs: number;
  /** Starts a timer and returns what cancels it: the Worker passes `setTimeout`, a test passes a fake. */
  setTimer(fn: () => void, ms: number): () => void;
}

export function createRuntimeClient(port: RpcPort, options: ClientOptions): HostRuntime {
  let nextId = 1;
  let closed = false;
  const pending = new Map<number, { resolve(v: unknown): void; reject(e: Error): void; cancel(): void }>();
  const live: ((entries: Evidence[]) => unknown)[] = [];

  const failAll = (): void => {
    closed = true;
    for (const [, p] of [...pending]) { p.cancel(); p.reject(new RuntimeUnavailableError('the monitoring runtime closed its port')); }
    pending.clear();
  };

  port.onMessage((message) => {
    if (!isObject(message)) return;
    if (message.type === 'live' && Array.isArray(message.entries)) {
      const entries = message.entries as Evidence[];
      // Called now and in order, as before; a handler that throws has settled.
      const settled = live.map((h) => {
        try { return Promise.resolve(h(entries)); } catch (e) { return Promise.reject(e); }
      });
      // The ack is the utility's credit: returned when the Worker has consumed
      // the push, not when it arrived.
      void Promise.allSettled(settled).then(() => {
        try { port.postMessage({ type: 'live-ack' }); } catch { /* the port closed under it */ }
      });
      return;
    }
    if (message.type !== 'res' || typeof message.id !== 'number') return;
    const p = pending.get(message.id);
    // No entry: the caller was already told the runtime was unavailable.
    if (p === undefined) return;
    pending.delete(message.id);
    p.cancel();
    const reply = message as unknown as Reply;
    if (reply.ok) p.resolve(reply.value); else p.reject(errorFrom(reply.error));
  });
  port.onClose?.(failAll);

  const call = <T>(method: Method, ...args: unknown[]): Promise<T> => {
    if (closed) return Promise.reject(new RuntimeUnavailableError('the monitoring runtime closed its port'));
    const id = nextId++;
    return new Promise<T>((resolve, reject) => {
      const cancel = options.setTimer(() => {
        if (pending.delete(id)) reject(new RuntimeUnavailableError(`the monitoring runtime did not answer ${method} in ${options.requestMs} ms`));
      }, options.requestMs);
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject, cancel });
      try {
        const req: Request = { type: 'req', id, method, args };
        port.postMessage(req);
      } catch (e) {
        pending.delete(id);
        cancel();
        reject(new RuntimeUnavailableError(`the monitoring runtime could not be reached: ${e instanceof Error ? e.message : String(e)}`));
      }
    });
  };

  return {
    snapshot: () => call('snapshot'),
    readPage: (snapshot, afterId, maxEntries, maxBytes) => call('readPage', snapshot, afterId, maxEntries, maxBytes),
    readEvidence: (ref) => call('readEvidence', ref),
    locate: (snapshot, fromMs, toMs) => call('locate', snapshot, fromMs, toMs),
    readBoundaries: (snapshot, afterId, maxEntries) => call('readBoundaries', snapshot, afterId, maxEntries),
    watermark: () => call('watermark'),
    readMinutes: (sourceKey, from, to, maxBytes) => call('readMinutes', sourceKey, from, to, maxBytes),
    sources: () => call('sources'),
    appendMinutes: (minutes, watermark) => call('appendMinutes', minutes, watermark),
    rollupStatus: () => call('rollupStatus'),
    resetRollups: () => call('resetRollups'),
    onLive: (handler) => { live.push(handler); },
  };
}
