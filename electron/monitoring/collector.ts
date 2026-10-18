/**
 * The monitoring utility's whole decision-making (ADRs 0058, 0059): the UDP
 * intake rules, the journal and the sidecar it owns, the sessions around them,
 * and the live feed to the Worker.
 *
 * Imports no Electron and no `node:` module. Every effect is handed in through
 * `CollectorEnv` - the socket, the volume opener, the clock, timers, the next
 * tick, randomness, and where status goes - so `scripts/monitoring/runtime.ts`
 * drives all of it under plain `tsx` with a fake socket, a fake clock and the
 * memory `BlockFile` the journal tests use. `entry.ts` is the process and
 * `udp.ts` the `dgram` adapter; neither holds a rule.
 *
 * ## The rules that are easy to undo
 *
 * - **Bytes are copied at the `message` event.** Node reuses nothing today,
 *   but a view onto a socket's buffer is a promise nobody here made; the inbox
 *   holds its own `Uint8Array`.
 * - **Only the configured exporter is evidence.** Anything else is counted
 *   (the first `LIMITS.rejectedSenders` addresses by arrival, then one
 *   overflow count) and never reaches the journal - a stray host on the
 *   segment must not be able to grow the dataset.
 * - **The inbox is bounded and shedding is stated.** Past `inboxDatagrams` or
 *   `inboxBytes` a datagram is dropped and counted, and the next drain opens
 *   with a `gap` boundary (`intake-shed`) carrying the count, so a history
 *   query shows the hole as a hole. This is the one loss the app knows the
 *   size of; the kernel's drops it cannot.
 * - **Operations do not interleave.** Start, Stop, open and dispose run one at
 *   a time on a chain. A drain is one synchronous `journal.append`, so it cannot
 *   interleave with a step that is synchronous either; the only await inside an
 *   operation is Start's wait and bind, and the drain does nothing until a
 *   session is open.
 * - **A Start that is waiting can be cancelled.** Start waits up to
 *   `LIMITS.handshakeMs` for the dataset and a Worker; a Stop or a dispose in
 *   that time ends the wait rather than queueing behind it, so no promise is
 *   left pending behind a button the user has already pressed again.
 * - **Nothing is ever deleted.** A journal this build will not write to
 *   (damaged, another version, failed) is reported and left alone.
 */
import type { BlockFile } from '../../src/services/capture/blockFile';
import { readSourceConfig } from '../../src/services/monitoring/config';
import { isIntakeStopReason, type IntakeStatus, type IntakeStopReason, type StartResult, type StopReason, type StopResult } from '../../src/services/monitoring/control';
import { MonitoringJournal, type EvidenceInput, type JournalState } from '../../src/services/monitoring/journal';
import { LiveFeed } from '../../src/services/monitoring/liveFeed';
import { LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { RuntimeUnavailableError, type HostRuntime } from '../../src/services/monitoring/runtime';
import { serveRuntime, type RpcPort, type RuntimeServer } from '../../src/services/monitoring/runtimeRpc';
import type { ListenerState } from '../../src/services/monitoring/sourceHealth';
import { DECODER_POLICY_VERSION, LIMITS, type SourceConfig } from '../../src/services/monitoring/types';

// --- what is injected -------------------------------------------------------------------------

export interface UdpError { code?: string; message: string }

/** One UDP socket. `udp.ts` is the real one; the tests' is a fake that emits what they say. */
export interface UdpSocket {
  onMessage(handler: (data: Uint8Array, from: { address: string; port: number }) => void): void;
  /** Errors after a successful bind. A failed bind rejects `bind` and is not reported here. */
  onError(handler: (error: UdpError) => void): void;
  bind(address: string, port: number): Promise<void>;
  close(): void;
}

/** The two files of the monitoring directory; `electron/monitoring/volume.ts` opens the real ones. */
export interface CollectorVolume { journal: BlockFile; rollups: BlockFile; close(): void }

export interface CollectorEnv {
  openVolume(root: string): CollectorVolume;
  createSocket(): UdpSocket;
  now(): number;
  randomBytes(n: number): Uint8Array;
  /** One-shot timer; returns what cancels it. */
  setTimer(fn: () => void, ms: number): () => void;
  /** Runs `fn` soon, after the current event; the real one is `setImmediate`. */
  defer(fn: () => void): void;
  postStatus(status: IntakeStatus): void;
  /** Where a failure nobody can be told about goes (the live feed's); optional. */
  log?(message: string): void;
}

// --- small rules, exported for the tests -------------------------------------------------------------

/** Counter-only changes are reported at most this often; a listener or storage change goes at once. */
export const STATUS_COALESCE_MS = 250;

/** The user-facing words for a bind or socket error (ADR 0058). Node's own message for anything else. */
export function describeListenError(error: UdpError, bindIPv4: string, port: number): string {
  switch (error.code) {
    case 'EADDRINUSE': return `UDP port ${port} on ${bindIPv4} is already in use by another program`;
    case 'EADDRNOTAVAIL': return `${bindIPv4} is not an address of this computer`;
    case 'EACCES': return `Windows refused UDP port ${port} on ${bindIPv4}`;
    default: return error.message;
  }
}

function sameSource(a: SourceConfig, b: SourceConfig): boolean {
  return a.exporterIPv4 === b.exporterIPv4 && a.bindIPv4 === b.bindIPv4 && a.port === b.port
    && a.storageLimitBytes === b.storageLimitBytes;
}

function describeStorage(state: JournalState): string {
  switch (state) {
    case 'storage-limit': return 'the monitoring storage limit has been reached';
    case 'refused-corrupt': return 'the monitoring journal is damaged; it was left untouched and nothing will be written to it';
    case 'refused-version': return 'the monitoring journal was written by another version of Inwire; it was left untouched and nothing will be written to it';
    case 'failed': return 'the monitoring journal could not be written';
    case 'closed': return 'the monitoring journal is closed';
    case 'open': return 'the monitoring journal is open';
  }
}

const STOPPED_BEFORE_START = 'monitoring was stopped before it started listening';
const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GENERATION = /^[0-9a-f]{32}$/;

/** A caller's size, clamped to `cap`. NaN and a non-positive number are refused, not clamped: `Math.min(NaN, cap)` is NaN, and a NaN bound compares false against every total, so it would read without a limit at all. */
function clampSize(n: number, cap: number): number {
  if (!(n > 0)) throw new RangeError(`a read size must be a positive number (got ${n})`);
  return Math.min(n, cap);
}

// --- the collector ---------------------------------------------------------------------------------------

interface Dataset {
  root: string;
  limitBytes: number;
  volume: CollectorVolume;
  journal: MonitoringJournal;
  rollups: RollupStore;
  local: LocalRuntime;
  /** Why the journal was opened read-only, in the scan's words; null where it is writable. */
  problem: string | null;
}

interface InboxItem { bytes: Uint8Array; receivedMs: number; remoteIPv4: string; remotePort: number }

/** What a waiting Start can be told to stop doing. */
interface StartAbort { aborted: boolean; onAbort: (() => void) | null }

export class Collector {
  private disposed = false;
  private disposing: Promise<StopResult> | null = null;
  private chain: Promise<unknown> = Promise.resolve();

  private dataset: Dataset | null = null;
  /** What `storage` reads while there is no dataset: `unopened`, a refusal, or `closed`. */
  private storageWithoutDataset: IntakeStatus['storage'] = 'unopened';
  private storageProblem: string | null = null;

  private port: RpcPort | null = null;
  private portToken = 0;
  private server: RuntimeServer | null = null;
  private readonly feed: LiveFeed;

  private socket: UdpSocket | null = null;
  private session: { id: string; config: SourceConfig } | null = null;
  private source: SourceConfig | null = null;
  private listener: ListenerState = 'stopped';
  private listenerError: string | null = null;
  /** Why intake last stopped in this utility's life; cleared by a Start that succeeds. */
  private stopReason: IntakeStopReason | null = null;
  /** The reason of the latest Stop asked for, so a Start queued behind work and then aborted by it can say why. */
  private lastStopRequest: StopReason | null = null;
  /** The `stopReason` the last posted status carried, so a change nothing else posts is still posted. */
  private publishedStopReason: IntakeStopReason | null = null;
  private cancelFlush: (() => void) | null = null;

  private inbox: InboxItem[] = [];
  private inboxBytes = 0;
  private drainScheduled = false;
  private received = 0;
  private rejected = new Map<string, number>();
  private rejectedOverflow = 0;
  /** Shed this session, for the status. */
  private shed = 0;
  /** Shed since the last `gap` boundary was written: what the next one carries. */
  private shedSinceGap = 0;

  private lastStatusMs = Number.NEGATIVE_INFINITY;
  private statusTimer: (() => void) | null = null;

  private startAbort: StartAbort | null = null;
  /** Counts Stops and disposes, so a Start asked for before one knows it was cancelled even if it has not begun. */
  private stopEpoch = 0;
  private readonly readyWaiters = new Set<() => void>();

  constructor(private readonly env: CollectorEnv) {
    this.feed = new LiveFeed({
      snapshot: () => this.dataset?.journal.snapshot() ?? null,
      readPage: (snapshot, afterId, maxEntries, maxBytes) => {
        if (this.dataset === null) throw new RuntimeUnavailableError('the monitoring dataset is not open');
        return this.dataset.journal.readPage(snapshot, afterId, maxEntries, maxBytes);
      },
      push: (entries) => {
        if (this.server === null) throw new RuntimeUnavailableError('no monitoring Worker is attached');
        this.server.pushLive(entries);
      },
      onError: (e) => this.env.log?.(`monitoring live feed: ${message(e)}`),
    });
  }

  // --- the served runtime ------------------------------------------------------------------------------

  /**
   * What the Worker reads through. It names no journal: each call goes to the
   * dataset as it is *now*, so reopening for a new storage limit does not strand
   * a port that was attached to the old objects. `readPage` is clamped to the
   * page constants here as well as in the journal, because a limit that only
   * holds when the caller sends a finite number is not a limit (`Infinity`
   * survives a structured clone, and the journal rightly refuses it as a
   * range error; the clamp makes it a full page instead). `readBoundaries` and
   * `readMinutes` are clamped the same way, to `pageEntries` and
   * `rollupReadBytes`: `readMinutes` refuses past its number rather than clips,
   * so that constant is the queries' own chunk and a bigger one is never legal.
   */
  readonly runtime: Omit<HostRuntime, 'onLive'> = {
    snapshot: async () => this.local().snapshot(),
    readPage: async (snapshot, afterId, maxEntries, maxBytes) => this.local().readPage(
      snapshot, afterId, clampSize(maxEntries, LIMITS.pageEntries), clampSize(maxBytes, LIMITS.pageBytes),
    ),
    readEvidence: async (ref) => this.local().readEvidence(ref),
    // Needs no clamp: its size is the journal index's (one range per stride), not the caller's.
    locate: async (snapshot, fromMs, toMs) => this.local().locate(snapshot, fromMs, toMs),
    readBoundaries: async (snapshot, afterId, maxEntries) => this.local().readBoundaries(
      snapshot, afterId, clampSize(maxEntries, LIMITS.pageEntries),
    ),
    watermark: async () => this.local().watermark(),
    readMinutes: async (sourceKey, from, to, maxBytes) => this.local().readMinutes(
      sourceKey, from, to, clampSize(maxBytes, LIMITS.rollupReadBytes),
    ),
    sources: async () => this.local().sources(),
    appendMinutes: async (minutes, watermark) => this.local().appendMinutes(minutes, watermark),
    rollupStatus: async () => this.local().rollupStatus(),
    resetRollups: async () => this.local().resetRollups(),
  };

  private local(): LocalRuntime {
    if (this.dataset === null) throw new RuntimeUnavailableError('the monitoring dataset is not open');
    return this.dataset.local;
  }

  // --- public operations ----------------------------------------------------------------------------------

  /** Opens the dataset and binds nothing. Already open answers ok and does nothing (ruling R2). */
  open(root: string, limitBytes: number): Promise<StartResult> {
    // Not through `run()`: a Start that arrived first is waiting for exactly this
    // and holds the chain, so queueing behind it would be a deadlock that only
    // the handshake deadline ends. `openNow` is synchronous and only reached
    // with no dataset, which nothing else in flight can be using.
    try {
      if (this.disposed) return Promise.resolve({ ok: false, message: 'monitoring has shut down' });
      if (this.dataset !== null) return Promise.resolve({ ok: true });
      return Promise.resolve(this.openNow(root, limitBytes));
    } catch (e) {
      return Promise.resolve({ ok: false, message: `monitoring could not open its dataset: ${message(e)}` });
    }
  }

  /** A Worker's runtime port. It replaces any port attached before it. */
  attach(port: RpcPort): void {
    if (this.disposed) {
      try { port.close?.(); } catch { /* already gone */ }
      return;
    }
    const previous = this.port;
    const token = ++this.portToken;
    this.port = port;
    this.server = serveRuntime(port, this.runtime, {
      // An ack from a port that has since been replaced says nothing about the new one's credit.
      onLiveAck: () => { if (token === this.portToken) this.feed.ack(); },
    });
    port.onClose?.(() => { if (token === this.portToken) this.detach(); });
    this.feed.detach();
    this.attachFeedIfReady();
    if (previous !== null) {
      try { previous.close?.(); } catch { /* the old page's port may be dead already */ }
    }
    this.publish();
    this.wake();
  }

  start(config: SourceConfig): Promise<StartResult> {
    const epoch = this.stopEpoch;
    return this.run(() => this.startOp(config, epoch))
      .catch((e): StartResult => ({ ok: false, message: `monitoring could not start: ${message(e)}` }));
  }

  stop(reason: StopReason): Promise<StopResult> {
    this.stopEpoch++;
    this.lastStopRequest = reason;
    if (this.abortStart()) this.stopReason = reason;
    return this.run(() => this.stopOp(reason))
      .catch((e): StopResult => ({ ok: false, message: `monitoring could not stop cleanly: ${message(e)}`, clean: false, snapshot: null }));
  }

  /** `stop('quit')`, then the dataset closed. Idempotent: the second call is the first's answer. */
  dispose(): Promise<StopResult> {
    if (this.disposing !== null) return this.disposing;
    this.disposed = true;
    this.stopEpoch++;
    this.lastStopRequest = 'quit';
    if (this.abortStart()) this.stopReason = 'quit';
    this.disposing = this.run(() => {
      const result = this.stopOp('quit');
      this.cancelStatusTimer();
      this.feed.detach();
      this.server = null;
      const port = this.port;
      this.port = null;
      this.portToken++;
      try { port?.close?.(); } catch { /* nothing to tell */ }
      this.closeDataset('closed');
      this.publish();
      return result;
    }).catch((e): StopResult => ({ ok: false, message: `monitoring could not shut down cleanly: ${message(e)}`, clean: false, snapshot: null }));
    return this.disposing;
  }

  /** The status as it would be posted now; the tests read it, `postStatus` carries it. */
  status(): IntakeStatus {
    const journalState = this.dataset?.journal.state ?? null;
    const storage: IntakeStatus['storage'] = journalState ?? this.storageWithoutDataset;
    const storageError = journalState === 'open' ? null
      : journalState !== null ? this.dataset?.problem ?? describeStorage(journalState)
        : this.storageProblem;
    return {
      listener: this.listener,
      listenerError: this.listenerError,
      storage,
      storageError,
      source: this.source,
      sessionId: this.session?.id ?? null,
      received: this.received,
      rejectedSenders: [...this.rejected].map(([address, count]) => ({ address, count })),
      rejectedOverflow: this.rejectedOverflow,
      shedDatagrams: this.shed,
      snapshot: this.dataset?.journal.snapshot() ?? null,
      workerAttached: this.port !== null,
      stopReason: this.stopReason,
    };
  }

  // --- serialisation ---------------------------------------------------------------------------------------------

  private run<T>(fn: () => T | Promise<T>): Promise<T> {
    const next = this.chain.then(fn);
    this.chain = next.then(() => undefined, () => undefined);
    return next;
  }

  /** Whether a Start was in flight to be aborted. */
  private abortStart(): boolean {
    const abort = this.startAbort;
    if (abort === null) return false;
    abort.aborted = true;
    abort.onAbort?.();
    return true;
  }

  // --- the dataset ---------------------------------------------------------------------------------------------------

  private openNow(root: string, limitBytes: number): StartResult {
    let volume: CollectorVolume;
    try {
      volume = this.env.openVolume(root);
    } catch (e) {
      return this.openFailed('failed', `the monitoring folder could not be opened: ${message(e)}`);
    }
    const holder: { rollups: RollupStore | null } = { rollups: null };
    try {
      const { journal, recovery } = MonitoringJournal.open(volume.journal, {
        limitBytes,
        // One limit covers both files.
        otherBytes: () => holder.rollups?.size() ?? 0,
        randomBytes: this.env.randomBytes,
        nowMs: this.env.now,
      });
      const snapshot = journal.snapshot();
      // A file with no readable header has no generation to serve a query
      // against. It is left exactly as it was, and the user is told why.
      if (!GENERATION.test(snapshot.generation)) {
        volume.close();
        return this.openFailed(journal.state, recovery.problem ?? 'the monitoring journal cannot be read');
      }
      const opened = RollupStore.open(volume.rollups, {
        generation: snapshot.generation, throughEntryId: snapshot.throughEntryId, policyVersion: DECODER_POLICY_VERSION,
      }, { nowMs: this.env.now });
      holder.rollups = opened.store;
      // The last run's stop survives the relaunch in the journal's own boundary. A run that ended
      // without one leaves `interrupted` or a bare `start`, and its reason has no copy, so none is invented.
      if (this.stopReason === null && this.session === null) {
        const last = journal.lastBoundary();
        if (last !== null && last.action === 'stop' && isIntakeStopReason(last.reason)) this.stopReason = last.reason;
      }
      const local = new LocalRuntime(journal, opened.store, {
        status: opened.status, ...(opened.reason === undefined ? {} : { reason: opened.reason }),
      });
      this.dataset = {
        root, limitBytes, volume, journal, rollups: opened.store, local,
        problem: journal.state === 'open' ? null : recovery.problem ?? null,
      };
    } catch (e) {
      try { volume.close(); } catch { /* the first failure is the one to report */ }
      return this.openFailed('failed', `the monitoring dataset could not be opened: ${message(e)}`);
    }
    this.storageProblem = null;
    this.attachFeedIfReady();
    this.publish();
    this.wake();
    return { ok: true };
  }

  private openFailed(state: JournalState, why: string): StartResult {
    this.storageWithoutDataset = state;
    this.storageProblem = why;
    this.publish();
    return { ok: false, message: why };
  }

  private closeDataset(after: IntakeStatus['storage']): void {
    const dataset = this.dataset;
    if (dataset === null) return;
    this.dataset = null;
    this.storageWithoutDataset = after;
    try { dataset.journal.close(); } catch { /* the volume closes regardless */ }
    try { dataset.volume.close(); } catch { /* nothing more to do with a file that will not close */ }
  }

  private attachFeedIfReady(): void {
    if (this.port === null || this.dataset === null || this.feed.isAttached) return;
    // The Worker's connect rebuilds everything up to its own snapshot from the journal;
    // live covers what comes after.
    this.feed.attach(this.dataset.journal.snapshot().throughEntryId);
  }

  private detach(): void {
    this.port = null;
    this.server = null;
    this.feed.detach();
    this.publish();
  }

  // --- Start -------------------------------------------------------------------------------------------------------------

  private missing(): string[] {
    const out: string[] = [];
    if (this.dataset === null) out.push('the monitoring dataset has not been opened');
    if (this.port === null) out.push('no monitoring Worker is attached');
    return out;
  }

  private wake(): void {
    for (const check of [...this.readyWaiters]) check();
  }

  /** Null once the dataset is open and a Worker is attached; otherwise why not (a timeout, or a cancel). */
  private awaitReady(abort: StartAbort): Promise<string | null> {
    if (abort.aborted) return Promise.resolve(STOPPED_BEFORE_START);
    if (this.missing().length === 0) return Promise.resolve(null);
    return new Promise((resolve) => {
      let done = false;
      const finish = (result: string | null): void => {
        if (done) return;
        done = true;
        cancel();
        this.readyWaiters.delete(check);
        abort.onAbort = null;
        resolve(result);
      };
      const check = (): void => { if (this.missing().length === 0) finish(null); };
      const cancel = this.env.setTimer(
        () => finish(`monitoring was not ready after ${LIMITS.handshakeMs / 1000} s: ${this.missing().join(' and ')}`),
        LIMITS.handshakeMs,
      );
      this.readyWaiters.add(check);
      abort.onAbort = () => finish(STOPPED_BEFORE_START);
    });
  }

  private bind(socket: UdpSocket, config: SourceConfig, abort: StartAbort): Promise<'ok' | 'aborted' | 'timeout' | UdpError> {
    return new Promise((resolve) => {
      let done = false;
      const finish = (result: 'ok' | 'aborted' | 'timeout' | UdpError): void => {
        if (done) return;
        done = true;
        cancel();
        abort.onAbort = null;
        resolve(result);
      };
      const cancel = this.env.setTimer(() => finish('timeout'), LIMITS.handshakeMs);
      abort.onAbort = () => finish('aborted');
      socket.bind(config.bindIPv4, config.port).then(
        () => finish('ok'),
        (e: unknown) => {
          const code = typeof e === 'object' && e !== null && typeof (e as { code?: unknown }).code === 'string'
            ? (e as { code: string }).code : undefined;
          finish({ ...(code === undefined ? {} : { code }), message: message(e) });
        },
      );
    });
  }

  private async startOp(requested: SourceConfig, epoch: number): Promise<StartResult> {
    if (this.disposed) return { ok: false, message: 'monitoring has shut down' };
    const config = readSourceConfig(requested);
    if (config === null) return { ok: false, message: 'the monitoring source is not valid' };

    if (this.session !== null) {
      return sameSource(this.session.config, config)
        ? { ok: true }
        : { ok: false, message: 'monitoring is already listening with a different source; stop it first' };
    }

    const abort: StartAbort = { aborted: this.stopEpoch !== epoch, onAbort: null };
    if (abort.aborted && this.lastStopRequest !== null) this.stopReason = this.lastStopRequest;
    this.startAbort = abort;
    try {
      const notReady = await this.awaitReady(abort);
      if (notReady !== null) return { ok: false, message: notReady };
      if (abort.aborted) return { ok: false, message: STOPPED_BEFORE_START };

      // A changed limit is applied in place. Closing and reopening to apply it rescans every entry
      // of the journal, which a full dataset cannot do inside Start's deadline, and it would strand
      // the Worker's view of the objects. Only while stopped: this is that branch.
      if (this.dataset !== null && this.dataset.limitBytes !== config.storageLimitBytes) {
        this.dataset.journal.setLimit(config.storageLimitBytes);
        this.dataset.limitBytes = config.storageLimitBytes;
        // The journal may have stopped at the old limit; its refusal text went with that state.
        if (this.dataset.journal.state === 'open') this.dataset.problem = null;
        this.publish();
      }
      const dataset = this.dataset;
      if (dataset === null) return { ok: false, message: 'the monitoring dataset is not open' };
      if (dataset.journal.state !== 'open') {
        return { ok: false, message: dataset.problem ?? describeStorage(dataset.journal.state) };
      }

      this.source = config;
      this.listener = 'starting';
      this.listenerError = null;
      this.publish();

      // Before the socket exists, so a datagram shed or rejected from the moment it can receive is
      // counted in this session (and a shed one carried by its first gap), not zeroed after the bind.
      this.shed = 0;
      this.shedSinceGap = 0;
      this.rejected = new Map();
      this.rejectedOverflow = 0;
      const socket = this.env.createSocket();
      this.socket = socket;
      this.inbox = [];
      this.inboxBytes = 0;
      socket.onMessage((data, from) => this.onDatagram(socket, config, data, from));
      socket.onError((e) => this.onSocketError(socket, config, e));

      const bound = await this.bind(socket, config, abort);
      if (bound !== 'ok') {
        this.closeSocket();
        if (bound === 'aborted') return this.startFailed(STOPPED_BEFORE_START, false);
        if (bound === 'timeout') {
          return this.startFailed(`binding UDP port ${config.port} on ${config.bindIPv4} took longer than ${LIMITS.handshakeMs / 1000} s`, true);
        }
        // No retry: a port that is taken stays taken until the user does something about it.
        return this.startFailed(describeListenError(bound, config.bindIPv4, config.port), true);
      }

      const id = toHex(this.env.randomBytes(16));
      const appended = dataset.journal.append([{
        kind: 'boundary', sessionId: id, receivedMs: this.env.now(), action: 'start', reason: '', droppedDatagrams: null,
      }]);
      if (appended.appended !== 1) {
        this.closeSocket();
        return this.startFailed(`the journal refused the start of a session: ${describeStorage(appended.state)}`, true);
      }

      this.session = { id, config };
      this.received = 0;
      this.listener = 'listening';
      this.stopReason = null;
      this.armFlush();
      this.feed.notify();
      this.publish();
      // Anything that arrived between the bind and the `start` boundary belongs to this session.
      if (this.inbox.length > 0) this.scheduleDrain();
      return { ok: true };
    } finally {
      if (this.startAbort === abort) this.startAbort = null;
    }
  }

  private startFailed(why: string, failed: boolean): StartResult {
    this.listener = failed ? 'failed' : 'stopped';
    this.listenerError = failed ? why : null;
    this.inbox = [];
    this.inboxBytes = 0;
    this.publish();
    return { ok: false, message: why };
  }

  // --- intake ----------------------------------------------------------------------------------------------------------------

  private onDatagram(socket: UdpSocket, config: SourceConfig, data: Uint8Array, from: { address: string; port: number }): void {
    // A socket this collector has let go of (a stop, a failed start) may still have events in flight.
    if (this.socket !== socket) return;
    if (from.address !== config.exporterIPv4) {
      if (this.rejected.has(from.address)) this.rejected.set(from.address, this.rejected.get(from.address)! + 1);
      else if (this.rejected.size < LIMITS.rejectedSenders) this.rejected.set(from.address, 1);
      else this.rejectedOverflow++;
      this.markCounters();
      return;
    }
    // Impossible over UDP; refused rather than trusted, and counted as the loss it would be.
    if (data.length > LIMITS.maxPayloadBytes
      || this.inbox.length >= LIMITS.inboxDatagrams
      || this.inboxBytes + data.length > LIMITS.inboxBytes) {
      this.shed++;
      this.shedSinceGap++;
      this.markCounters();
      return;
    }
    this.inbox.push({ bytes: new Uint8Array(data), receivedMs: this.env.now(), remoteIPv4: from.address, remotePort: from.port });
    this.inboxBytes += data.length;
    this.scheduleDrain();
  }

  private scheduleDrain(): void {
    if (this.drainScheduled) return;
    this.drainScheduled = true;
    this.env.defer(() => {
      this.drainScheduled = false;
      this.drain();
    });
  }

  /**
   * The whole inbox in one `append`, behind a `gap` if anything was shed since the last one.
   * Null while the session goes on; once the append ended it, whether the end was clean.
   */
  private drain(): boolean | null {
    const session = this.session;
    const dataset = this.dataset;
    if (session === null || dataset === null) return null;
    if (this.inbox.length === 0 && this.shedSinceGap === 0) return null;
    const batch = this.inbox;
    this.inbox = [];
    this.inboxBytes = 0;
    const gap = this.shedSinceGap;
    const inputs: EvidenceInput[] = [];
    if (gap > 0) {
      inputs.push({
        kind: 'boundary', sessionId: session.id, receivedMs: this.env.now(), action: 'gap',
        reason: 'intake-shed', droppedDatagrams: gap,
      });
    }
    for (const item of batch) {
      inputs.push({
        kind: 'datagram', receivedMs: item.receivedMs, localIPv4: session.config.bindIPv4, localPort: session.config.port,
        remoteIPv4: item.remoteIPv4, remotePort: item.remotePort, bytes: item.bytes,
      });
    }
    const result = dataset.journal.append(inputs);
    if (gap > 0 && result.appended > 0) this.shedSinceGap -= gap;
    this.received += Math.max(0, result.appended - (gap > 0 ? 1 : 0));
    if (result.state !== 'open') return this.endSession(result.state);
    this.markCounters();
    this.feed.notify();
    return null;
  }

  /**
   * The journal stopped accepting: the socket closes, and the listener says why.
   * A full journal wrote its own `stop`, which is flushed here because nothing
   * else will (the flush timer is cancelled), so a crash cannot turn a session
   * that ended cleanly into an `interrupted` one. Returns whether it ended clean.
   */
  private endSession(state: JournalState): boolean {
    const dataset = this.dataset;
    let clean = false;
    if (state === 'storage-limit' && dataset !== null) {
      const snapshot = dataset.journal.flush();
      clean = dataset.journal.state === 'storage-limit' && snapshot.syncedThroughEntryId === snapshot.throughEntryId;
      if (dataset.journal.state === 'failed') state = 'failed';
    }
    this.closeSocket();
    this.cancelFlushTimer();
    this.inbox = [];
    this.inboxBytes = 0;
    this.session = null;
    if (state === 'storage-limit') {
      // Not a failure: the journal wrote its own stop, and the dataset is simply full.
      this.stopReason = 'storage-limit';
      this.listener = 'stopped';
      this.listenerError = null;
    } else {
      this.stopReason = 'storage-failed';
      this.listener = 'failed';
      this.listenerError = describeStorage(state);
    }
    this.publish();
    this.feed.notify();
    return clean;
  }

  private onSocketError(socket: UdpSocket, config: SourceConfig, error: UdpError): void {
    if (this.socket !== socket) return;
    void this.run(() => {
      if (this.socket !== socket || this.session === null) return;
      const why = describeListenError(error, config.bindIPv4, config.port);
      // Before the close, as `stopOp` does: a drain that fills the journal overwrites it.
      this.stopReason = 'socket-error';
      this.closeSession('socket-error', false);
      // The drain inside the close can end the session itself, at the storage limit or on a failure;
      // that ending has already set the truer stop reason and listener, and is not overwritten.
      if (this.session === null && this.listener === 'listening') {
        this.listener = 'failed';
        this.listenerError = why;
      }
      this.publish();
    }).catch((e) => this.env.log?.(`monitoring socket error handling: ${message(e)}`));
  }

  private closeSocket(): void {
    const socket = this.socket;
    this.socket = null;
    try { socket?.close(); } catch { /* a socket that will not close is one nothing reads from */ }
  }

  // --- the flush timer ---------------------------------------------------------------------------------------------------------------

  private armFlush(): void {
    this.cancelFlush = this.env.setTimer(() => this.flushTick(), LIMITS.flushMs);
  }

  private cancelFlushTimer(): void {
    this.cancelFlush?.();
    this.cancelFlush = null;
  }

  private flushTick(): void {
    this.cancelFlush = null;
    const dataset = this.dataset;
    if (this.session === null || dataset === null) return;
    const before = dataset.journal.snapshot().syncedThroughEntryId;
    const after = dataset.journal.flush().syncedThroughEntryId;
    if (dataset.journal.state === 'failed') {
      this.endSession('failed');
      return;
    }
    // The status carries how far the journal is flushed; an idle second changes nothing to report.
    if (after !== before) this.markCounters();
    this.armFlush();
  }

  // --- Stop ----------------------------------------------------------------------------------------------------------------------------

  private stopOp(reason: StopReason): StopResult {
    if (this.session === null) {
      // Nothing is open, so nothing is written: a second Stop is an answer, not an event.
      // Unless it aborted a Start short of the bind, which posts nothing: after a
      // suspend nothing else may post either, so the reason it recorded goes now.
      if (this.stopReason !== this.publishedStopReason) this.publish();
      return { ok: true, clean: true, snapshot: this.dataset?.journal.snapshot() ?? null };
    }
    // Before the close, because a drain that fills the journal ends the session
    // itself and overwrites this with `storage-limit`, which is the truer reason.
    this.stopReason = reason;
    const clean = this.closeSession(reason, reason === 'suspend');
    if (this.listener === 'failed' || this.dataset?.journal.state === 'failed') {
      // The close ran into a journal failure: a stop is not what happened to the listener, and the status must not say it is.
      this.stopReason = 'storage-failed';
      this.listener = 'failed';
      this.listenerError ??= describeStorage('failed');
    } else {
      this.listener = 'stopped';
      this.listenerError = null;
    }
    this.publish();
    return { ok: true, clean, snapshot: this.dataset?.journal.snapshot() ?? null };
  }

  /**
   * Closes the socket, journals what the inbox holds, writes the closing
   * boundaries and flushes. `clean` is false when a boundary was refused or the
   * flush did not take: the next open then writes `interrupted`.
   */
  private closeSession(reason: string, suspend: boolean): boolean {
    const session = this.session;
    const dataset = this.dataset;
    this.closeSocket();
    this.cancelFlushTimer();
    if (session === null || dataset === null) return false;
    // The drain itself can end the session: the journal filled, and wrote its own stop.
    const ended = this.drain();
    if (ended !== null) return ended;
    const at = this.env.now();
    const inputs: EvidenceInput[] = [];
    if (suspend) {
      inputs.push({ kind: 'boundary', sessionId: session.id, receivedMs: at, action: 'suspend', reason, droppedDatagrams: null });
    }
    inputs.push({ kind: 'boundary', sessionId: session.id, receivedMs: at, action: 'stop', reason, droppedDatagrams: null });
    const result = dataset.journal.append(inputs);
    const snapshot = dataset.journal.flush();
    this.session = null;
    this.inbox = [];
    this.inboxBytes = 0;
    this.feed.notify();
    return result.appended === inputs.length && result.refused === 0
      && dataset.journal.state !== 'failed' && snapshot.syncedThroughEntryId === snapshot.throughEntryId;
  }

  // --- status ---------------------------------------------------------------------------------------------------------------------------------

  /** Posts now: a listener or storage change, or a Worker coming or going. */
  private publish(): void {
    this.cancelStatusTimer();
    this.lastStatusMs = this.env.now();
    const status = this.status();
    this.publishedStopReason = status.stopReason;
    this.env.postStatus(status);
  }

  private cancelStatusTimer(): void {
    this.statusTimer?.();
    this.statusTimer = null;
  }

  /** A counter moved: posted at most once per `STATUS_COALESCE_MS`, with the numbers as they are then. */
  private markCounters(): void {
    if (this.statusTimer !== null) return;
    const wait = this.lastStatusMs + STATUS_COALESCE_MS - this.env.now();
    if (wait <= 0) {
      this.publish();
      return;
    }
    this.statusTimer = this.env.setTimer(() => {
      this.statusTimer = null;
      this.publish();
    }, wait);
  }
}
