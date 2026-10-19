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
import { MAX_STORAGE_BYTES, readSourceConfig } from './config';
import type { JournalState } from './journal';
import { validateRetentionPolicy, type RetentionPolicy } from './retention';
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
/**
 * Why intake last stopped: a requested stop's reason, or what ended the
 * listener without one. `storage-failed` is a journal write or flush that
 * failed (`storageError` has the words), as against `storage-limit`, which is
 * the journal refusing to grow.
 */
export type IntakeStopReason = StopReason | 'socket-error' | 'storage-limit' | 'storage-failed';
const INTAKE_STOP_REASONS: ReadonlySet<string> = new Set<IntakeStopReason>([
  'user', 'quit', 'suspend', 'socket-error', 'storage-limit', 'storage-failed',
]);

export function isIntakeStopReason(v: unknown): v is IntakeStopReason {
  return typeof v === 'string' && INTAKE_STOP_REASONS.has(v);
}

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
  /**
   * Why the most recent stop in this utility's life happened; null before any
   * stop and again once a Start succeeds. `suspend` is what lets the UI say the
   * computer slept and Start is needed - no loss count is invented for the gap.
   */
  stopReason: IntakeStopReason | null;
  /**
   * The exporter the open dataset itself recorded (the newest `start` boundary's source, else the
   * newest segment header's), which is whose history it holds whatever is configured now. Null
   * while no dataset is open or nothing was ever recorded.
   */
  datasetSource: string | null;
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
  | { type: 'open'; id: number; root: string; limitBytes: number; isDefaultLocation: boolean; retention: RetentionPolicy }
  | { type: 'inspect'; id: number; root: string; isDefaultLocation: boolean }
  | { type: 'discard'; id: number; scope: DiscardScope }
  | { type: 'discard-preview'; id: number; scope: DiscardScope }
  | { type: 'retention'; id: number; policy: RetentionPolicy }
  | { type: 'attach' }
  | { type: 'start'; id: number; config: SourceConfig }
  | { type: 'stop'; id: number; reason: StopReason }
  | { type: 'dispose'; id: number };

/** Utility -> main. A `reply` answers the request with its `id`: `open` and `start` with a `StartResult`, `stop` and `dispose` with a `StopResult`, `inspect` with an `InspectResult`, `discard` with a `DiscardResult`, `discard-preview` with a `DiscardPreviewResult`, `retention` with a `RetentionResult`. */
export type FromMonitoringUtility =
  | { type: 'reply'; id: number; result: StartResult | StopResult | InspectResult | DiscardResult | DiscardPreviewResult | RetentionResult }
  | { type: 'status'; status: IntakeStatus };

// --- location and discard (ADR 0061) -----------------------------------------------------------

/** What a discard removes: the whole dataset, or the sealed prefix that ends before a date. */
export type DiscardScope = { scope: 'all' } | { scope: 'before'; beforeMs: number };

/**
 * What a folder would be if it were adopted, read without writing anything. `adopt-read-only` means
 * Start is disabled and nothing is written; `problem` says why. `exporterIPv4` is the exporter the
 * dataset itself recorded, the one its history is about.
 */
export type InspectResult =
  | { ok: true; kind: 'new' | 'adopt' | 'adopt-read-only'; truncatedTailBytes: number | null; problem: string | null; exporterIPv4: string | null }
  | { ok: false; reason: 'refused-version' | 'foreign-files' | 'failed'; message: string; names?: string[] };

/**
 * `cancelled` is main's own: the dialog it opened was declined, and nothing was sent to the utility. The
 * utility itself only ever answers `busy` or `failed`.
 */
export type DiscardResult =
  | { ok: true; removedSegments: number }
  | { ok: false; reason: 'busy' | 'failed' | 'cancelled'; message: string };

/**
 * What a discard would do, read from the same selection the discard runs and writing nothing: the figures
 * main's confirmation dialog states. `segments` is how many journal segments go. For `before`, `fromMs` is
 * the first removed segment's first received time and `cutMs` the last removed segment's last: the cut
 * that actually happens, which is at or before the date asked for because evidence goes in whole segments.
 * For `all`, `fromMs` and `throughMs` are the dataset's recorded range, and `cutMs` is null. A time the
 * dataset cannot give is null.
 */
export type DiscardPreviewResult =
  | { ok: true; scope: 'all' | 'before'; segments: number; fromMs: number | null; throughMs: number | null; cutMs: number | null }
  | { ok: false; reason: 'busy' | 'failed'; message: string };

/** A retention policy is changed only while stopped, like the location and a discard. */
export type RetentionResult = { ok: true } | { ok: false; reason: 'busy' | 'failed'; message: string };

// --- main -> renderer: location and retention (ADR 0061) ---------------------------------------

/**
 * What choosing a dataset folder answers. The renderer never sends a path: main shows the dialog,
 * decides the folder and answers with what it chose (`displayPath`) and what the folder holds.
 */
export type LocationReply =
  | { ok: true; displayPath: string; isDefaultLocation: boolean; inspect: Extract<InspectResult, { ok: true }> }
  | {
    ok: false;
    reason: 'cancelled' | 'busy' | 'refused' | 'refused-version' | 'foreign-files' | 'failed';
    message: string;
    names?: string[];
  };

/** What saving a retention policy answers: the policy now in force, or why it is not. */
export type RetentionSaveReply =
  | { ok: true; retention: RetentionPolicy }
  | { ok: false; reason: 'busy' | 'failed'; message: string };

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
  const { generation, throughEntryId, firstEntryId, writtenBytes, syncedThroughEntryId } = v;
  if (!isText(generation) || !GENERATION.test(generation)) return null;
  if (!isCount(throughEntryId) || !isCount(writtenBytes) || !isCount(syncedThroughEntryId)) return null;
  if (syncedThroughEntryId > throughEntryId) return null;
  if (!isId(firstEntryId) || firstEntryId > throughEntryId + 1) return null;
  return { generation, throughEntryId, firstEntryId, writtenBytes, syncedThroughEntryId };
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

export function readDiscardScope(v: unknown): DiscardScope | null {
  if (!isObject(v)) return null;
  if (v.scope === 'all') return { scope: 'all' };
  if (v.scope === 'before' && isCount(v.beforeMs)) return { scope: 'before', beforeMs: v.beforeMs };
  return null;
}

export function readDiscardResult(v: unknown): DiscardResult {
  if (isObject(v) && v.ok === true && isCount(v.removedSegments)) return { ok: true, removedSegments: v.removedSegments };
  if (isObject(v) && v.ok === false && (v.reason === 'busy' || v.reason === 'failed' || v.reason === 'cancelled') && isText(v.message)) {
    return { ok: false, reason: v.reason, message: v.message };
  }
  return { ok: false, reason: 'failed', message: UNREADABLE };
}

const timeOrNull = (v: unknown): v is number | null => v === null || isCount(v);

export function readDiscardPreviewResult(v: unknown): DiscardPreviewResult {
  if (isObject(v) && v.ok === true) {
    const { scope, segments, fromMs, throughMs, cutMs } = v;
    if ((scope === 'all' || scope === 'before') && isCount(segments) && timeOrNull(fromMs) && timeOrNull(throughMs) && timeOrNull(cutMs)) {
      return { ok: true, scope, segments, fromMs, throughMs, cutMs };
    }
  } else if (isObject(v) && v.ok === false && (v.reason === 'busy' || v.reason === 'failed') && isText(v.message)) {
    return { ok: false, reason: v.reason, message: v.message };
  }
  return { ok: false, reason: 'failed', message: UNREADABLE };
}

const INSPECT_KINDS: ReadonlySet<unknown> = new Set(['new', 'adopt', 'adopt-read-only']);
const INSPECT_REFUSALS: ReadonlySet<unknown> = new Set(['refused-version', 'foreign-files', 'failed']);

export function readInspectResult(v: unknown): InspectResult {
  const bad: InspectResult = { ok: false, reason: 'failed', message: UNREADABLE };
  if (!isObject(v)) return bad;
  if (v.ok === true) {
    const { kind, truncatedTailBytes, problem, exporterIPv4 } = v;
    if (!INSPECT_KINDS.has(kind) || !(truncatedTailBytes === null || isCount(truncatedTailBytes))) return bad;
    if (!textOrNull(problem) || !textOrNull(exporterIPv4)) return bad;
    return { ok: true, kind: kind as 'new' | 'adopt' | 'adopt-read-only', truncatedTailBytes, problem, exporterIPv4 };
  }
  if (v.ok === false && INSPECT_REFUSALS.has(v.reason) && isText(v.message)) {
    const names = Array.isArray(v.names) && v.names.every(isText) ? (v.names as string[]) : undefined;
    return { ok: false, reason: v.reason as 'refused-version' | 'foreign-files' | 'failed', message: v.message, ...(names === undefined ? {} : { names }) };
  }
  return bad;
}

export function readRetentionResult(v: unknown): RetentionResult {
  if (isObject(v) && v.ok === true) return { ok: true };
  if (isObject(v) && v.ok === false && (v.reason === 'busy' || v.reason === 'failed') && isText(v.message)) {
    return { ok: false, reason: v.reason, message: v.message };
  }
  return { ok: false, reason: 'failed', message: UNREADABLE };
}

const LOCATION_REFUSALS: ReadonlySet<unknown> = new Set(['cancelled', 'busy', 'refused', 'refused-version', 'foreign-files', 'failed']);

export function readLocationReply(v: unknown): LocationReply {
  const bad: LocationReply = { ok: false, reason: 'failed', message: UNREADABLE };
  if (!isObject(v)) return bad;
  if (v.ok === true) {
    if (!isText(v.displayPath) || typeof v.isDefaultLocation !== 'boolean') return bad;
    const inspect = readInspectResult(v.inspect);
    if (!inspect.ok) return bad;
    return { ok: true, displayPath: v.displayPath, isDefaultLocation: v.isDefaultLocation, inspect };
  }
  if (v.ok === false && LOCATION_REFUSALS.has(v.reason) && isText(v.message)) {
    const names = Array.isArray(v.names) && v.names.every(isText) ? (v.names as string[]) : undefined;
    return {
      ok: false, reason: v.reason as Extract<LocationReply, { ok: false }>['reason'], message: v.message,
      ...(names === undefined ? {} : { names }),
    };
  }
  return bad;
}

export function readRetentionSaveReply(v: unknown): RetentionSaveReply {
  if (isObject(v) && v.ok === true) {
    const retention = validateRetentionPolicy(v.retention);
    if (retention !== null) return { ok: true, retention };
  } else if (isObject(v) && v.ok === false && (v.reason === 'busy' || v.reason === 'failed') && isText(v.message)) {
    return { ok: false, reason: v.reason, message: v.message };
  }
  return { ok: false, reason: 'failed', message: UNREADABLE };
}

export function readStopReason(v: unknown): StopReason | null {
  return typeof v === 'string' && STOP_REASONS.has(v) ? (v as StopReason) : null;
}

export function readIntakeStatus(v: unknown): IntakeStatus | null {
  if (!isObject(v)) return null;
  const {
    listener, listenerError, storage, storageError, source, sessionId, received,
    rejectedSenders, rejectedOverflow, shedDatagrams, snapshot, workerAttached, stopReason, datasetSource,
  } = v;
  if (!textOrNull(datasetSource)) return null;
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
  if (stopReason !== null && !(isText(stopReason) && INTAKE_STOP_REASONS.has(stopReason))) return null;
  return {
    listener: listener as ListenerState, listenerError,
    storage: storage as IntakeStatus['storage'], storageError,
    source: config, sessionId, received, rejectedSenders: senders, rejectedOverflow, shedDatagrams,
    snapshot: snap, workerAttached, stopReason: stopReason as IntakeStopReason | null, datasetSource,
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
      if (!isCount(v.limitBytes) || v.limitBytes < LIMITS.minStorageBytes || v.limitBytes > MAX_STORAGE_BYTES) return null;
      if (typeof v.isDefaultLocation !== 'boolean') return null;
      const retention = validateRetentionPolicy(v.retention);
      if (retention === null) return null;
      return { type: 'open', id, root: v.root, limitBytes: v.limitBytes, isDefaultLocation: v.isDefaultLocation, retention };
    }
    case 'inspect': {
      if (!isText(v.root) || v.root === '' || typeof v.isDefaultLocation !== 'boolean') return null;
      return { type: 'inspect', id, root: v.root, isDefaultLocation: v.isDefaultLocation };
    }
    case 'discard': {
      const scope = readDiscardScope(v.scope);
      return scope === null ? null : { type: 'discard', id, scope };
    }
    case 'discard-preview': {
      const scope = readDiscardScope(v.scope);
      return scope === null ? null : { type: 'discard-preview', id, scope };
    }
    case 'retention': {
      const policy = validateRetentionPolicy(v.policy);
      return policy === null ? null : { type: 'retention', id, policy };
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
