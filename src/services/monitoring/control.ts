/**
 * The control vocabulary of monitoring (ADRs 0058, 0059): what main says to
 * the utility process over its `parentPort`, what the utility answers, and
 * what main relays to the renderer over IPC.
 *
 * Control is a separate path from the Worker's runtime port on purpose. That
 * port carries bulk reads and live evidence, and a Start, a Stop or a status
 * report queued behind a megabyte page is a button that does nothing for a
 * second. So nothing here ever travels on it, and nothing on it is control.
 *
 * Every message arrives as `unknown` at the process that owns its meaning,
 * which is why each type has a reader beside it. A reader returns a clean
 * value or a stated failure, never a half-trusted object: a Start result that
 * does not parse is a failed Start the user is told about, not a success.
 *
 * Plain data throughout, because every one of these crosses a structured
 * clone.
 */
import { readSourceConfig } from './config';
import type { JournalState } from './journal';
import type { ListenerState, RejectedSender } from './sourceHealth';
import { LIMITS, type JournalSnapshot, type SourceConfig } from './types';

// --- results ------------------------------------------------------------------------------

export type StartResult = { ok: true } | { ok: false; message: string };

/**
 * `clean` is false when the final boundary or the flush did not happen - a
 * drain past its deadline, a journal that refused the write. The journal is
 * then left for the next open's recovery, which writes `interrupted`.
 */
export type StopResult =
  | { ok: true; clean: boolean; snapshot: JournalSnapshot | null }
  | { ok: false; message: string; clean: false; snapshot: JournalSnapshot | null };

/** Why intake stopped. `suspend` is `powerMonitor`'s, `quit` the drain's, `user` the Stop button's. */
export type StopReason = 'user' | 'quit' | 'suspend';
const STOP_REASONS: ReadonlySet<string> = new Set<StopReason>(['user', 'quit', 'suspend']);

// --- status ---------------------------------------------------------------------------------

/**
 * What the utility knows about intake, posted to main whenever it changes and
 * coalesced while datagrams are arriving. It is not `SourceHealth`: freshness,
 * engines and the malformed counts come from decoding, which is the Worker's
 * (Task 7 folds the two). What is here is what only the socket and the journal
 * can say.
 */
export interface IntakeStatus {
  listener: ListenerState;
  /** The bind or socket error in Node's words (`EADDRINUSE` ...), or null. */
  listenerError: string | null;
  /** `unopened` before the first port request opens the dataset. */
  storage: 'unopened' | JournalState;
  storageError: string | null;
  /** The source the listener was last started with; null before the first Start. */
  source: SourceConfig | null;
  /** The open session, or null while stopped. */
  sessionId: string | null;
  /** Datagrams from the configured exporter journalled this session. */
  received: number;
  /** Other senders, at most `LIMITS.rejectedSenders` of them, the rest in `rejectedOverflow`. */
  rejectedSenders: RejectedSender[];
  rejectedOverflow: number;
  /** Datagrams this app dropped before append because the inbox was full. Known, unlike transport loss. */
  shedDatagrams: number;
  snapshot: JournalSnapshot | null;
  /** Whether a Worker's runtime port is attached; a reload detaches it until the new page asks. */
  workerAttached: boolean;
}

/** Main -> renderer when the utility process exits; every pending request has already been failed. */
export interface RuntimeExit {
  /** The process's exit code, or null where Electron gave none. */
  code: number | null;
  /** Whether a listener was running: the user has to press Start again. */
  wasRunning: boolean;
  message: string;
}

// --- main <-> utility --------------------------------------------------------------------------

/**
 * Main -> utility. `open` opens the dataset (no socket); `attach` carries the
 * Worker's runtime port as `ports[0]` and replaces any port attached before
 * it; `dispose` stops intake with reason `quit` and closes the dataset.
 */
export type ToMonitoringUtility =
  | { type: 'open'; id: number; root: string; limitBytes: number }
  | { type: 'attach' }
  | { type: 'start'; id: number; config: SourceConfig }
  | { type: 'stop'; id: number; reason: StopReason }
  | { type: 'dispose'; id: number };

/** Utility -> main. A `reply` answers the request with its `id`: `open` and `start` with a `StartResult`, `stop` and `dispose` with a `StopResult`. */
export type FromMonitoringUtility =
  | { type: 'reply'; id: number; result: StartResult | StopResult }
  | { type: 'status'; status: IntakeStatus };

// --- readers ----------------------------------------------------------------------------------

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const isId = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const isText = (v: unknown): v is string => typeof v === 'string';
const textOrNull = (v: unknown): v is string | null => v === null || typeof v === 'string';

const LISTENER_STATES: ReadonlySet<string> = new Set<ListenerState>(['stopped', 'starting', 'listening', 'failed']);
const STORAGE_STATES: ReadonlySet<string> = new Set<IntakeStatus['storage']>([
  'unopened', 'open', 'storage-limit', 'refused-corrupt', 'refused-version', 'failed', 'closed',
]);
const GENERATION = /^[0-9a-f]{32}$/;

const UNREADABLE = 'monitoring answered with something this build cannot read';

export function readJournalSnapshot(v: unknown): JournalSnapshot | null {
  if (!isObject(v)) return null;
  const { generation, throughEntryId, writtenBytes, syncedThroughEntryId } = v;
  if (!isText(generation) || !GENERATION.test(generation)) return null;
  if (!isCount(throughEntryId) || !isCount(writtenBytes) || !isCount(syncedThroughEntryId)) return null;
  if (syncedThroughEntryId > throughEntryId) return null;
  return { generation, throughEntryId, writtenBytes, syncedThroughEntryId };
}

export function readStartResult(v: unknown): StartResult {
  if (isObject(v) && v.ok === true) return { ok: true };
  if (isObject(v) && v.ok === false && isText(v.message)) return { ok: false, message: v.message };
  return { ok: false, message: UNREADABLE };
}

export function readStopResult(v: unknown): StopResult {
  if (!isObject(v)) return { ok: false, message: UNREADABLE, clean: false, snapshot: null };
  const snapshot = v.snapshot === null ? null : readJournalSnapshot(v.snapshot);
  if (v.snapshot !== null && snapshot === null) return { ok: false, message: UNREADABLE, clean: false, snapshot: null };
  if (v.ok === true && typeof v.clean === 'boolean') return { ok: true, clean: v.clean, snapshot };
  if (v.ok === false && isText(v.message)) return { ok: false, message: v.message, clean: false, snapshot };
  return { ok: false, message: UNREADABLE, clean: false, snapshot: null };
}

export function readStopReason(v: unknown): StopReason | null {
  return typeof v === 'string' && STOP_REASONS.has(v) ? (v as StopReason) : null;
}

export function readIntakeStatus(v: unknown): IntakeStatus | null {
  if (!isObject(v)) return null;
  const {
    listener, listenerError, storage, storageError, source, sessionId, received,
    rejectedSenders, rejectedOverflow, shedDatagrams, snapshot, workerAttached,
  } = v;
  if (!isText(listener) || !LISTENER_STATES.has(listener) || !textOrNull(listenerError)) return null;
  if (!isText(storage) || !STORAGE_STATES.has(storage) || !textOrNull(storageError)) return null;
  const config = source === null ? null : readSourceConfig(source);
  if (source !== null && config === null) return null;
  if (!textOrNull(sessionId) || !isCount(received) || !isCount(rejectedOverflow) || !isCount(shedDatagrams)) return null;
  if (!Array.isArray(rejectedSenders) || rejectedSenders.length > LIMITS.rejectedSenders) return null;
  const senders: RejectedSender[] = [];
  for (const s of rejectedSenders) {
    if (!isObject(s) || !isText(s.address) || !isCount(s.count)) return null;
    senders.push({ address: s.address, count: s.count });
  }
  const snap = snapshot === null ? null : readJournalSnapshot(snapshot);
  if (snapshot !== null && snap === null) return null;
  if (typeof workerAttached !== 'boolean') return null;
  return {
    listener: listener as ListenerState, listenerError,
    storage: storage as IntakeStatus['storage'], storageError,
    source: config, sessionId, received, rejectedSenders: senders, rejectedOverflow, shedDatagrams,
    snapshot: snap, workerAttached,
  };
}

export function readRuntimeExit(v: unknown): RuntimeExit | null {
  if (!isObject(v)) return null;
  const { code, wasRunning, message } = v;
  if (!(code === null || (typeof code === 'number' && Number.isInteger(code)))) return null;
  if (typeof wasRunning !== 'boolean' || !isText(message)) return null;
  return { code, wasRunning, message };
}

/** The utility's reader for what main sends it. `attach`'s port is in the event, not the message. */
export function readToUtility(v: unknown): ToMonitoringUtility | null {
  if (!isObject(v)) return null;
  if (v.type === 'attach') return { type: 'attach' };
  if (!isId(v.id)) return null;
  const id = v.id;
  switch (v.type) {
    case 'open': {
      if (!isText(v.root) || v.root === '') return null;
      if (!isCount(v.limitBytes) || v.limitBytes < LIMITS.minStorageBytes) return null;
      return { type: 'open', id, root: v.root, limitBytes: v.limitBytes };
    }
    case 'start': {
      const config = readSourceConfig(v.config);
      return config === null ? null : { type: 'start', id, config };
    }
    case 'stop': {
      const reason = readStopReason(v.reason);
      return reason === null ? null : { type: 'stop', id, reason };
    }
    case 'dispose':
      return { type: 'dispose', id };
    default:
      return null;
  }
}

/** Main's reader for what the utility sends. A reply's result is read by the request that knows its shape. */
export function readFromUtility(v: unknown): { type: 'reply'; id: number; result: unknown } | { type: 'status'; status: IntakeStatus } | null {
  if (!isObject(v)) return null;
  if (v.type === 'reply' && isId(v.id)) return { type: 'reply', id: v.id, result: v.result };
  if (v.type === 'status') {
    const status = readIntakeStatus(v.status);
    return status === null ? null : { type: 'status', status };
  }
  return null;
}
