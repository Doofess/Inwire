/**
 * Main's side of monitoring, with Electron taken out (ADRs 0058, 0059): the
 * rules for forking the utility process, opening its dataset, ferrying the
 * Worker's port, binding control to one window and failing every request when
 * the process dies. `host.ts` is the adapter that gives it a real
 * `utilityProcess`, a real `MessageChannelMain` and real timers; the script
 * gives it a fake child, a fake window and a fake clock.
 *
 * Four rules, each there because a plausible alternative hangs or lies:
 *
 * - **Control is bound to one window.** `start` and `stop` from any other
 *   WebContents are refused, so a second window (or a frame that is not the
 *   app's) cannot open a socket. A reload connects again and takes the
 *   binding; it never restarts the process, so a listener survives a reload.
 * - **Every request settles.** A reply, a deadline or the process dying ends
 *   it, and nothing waits on a process that is gone. Replies are read where
 *   they arrive (`control.ts`), so one that does not parse is a failed
 *   request, not a success.
 * - **A dead process is told over its own channel.** The runtime port goes
 *   quiet when the utility dies, so the bound window is sent a `RuntimeExit`
 *   on an IPC channel. The next connect forks anew; nothing restarts a
 *   listener on its own, because the user pressed Start and a restart is a
 *   second press.
 * - **A window going away does not stop intake.** Evidence is what the app is
 *   for; closing the window unbinds control and the listener runs on.
 *
 * And one lifecycle rule: **quit is final.** `drainForQuit` and `release` are
 * the two ways out, `quitDrain.ts` decides which, and once either has been
 * called nothing connects, starts, stops or forks again.
 */
import { readSourceConfig } from '../../src/services/monitoring/config';
import {
  readFromUtility, readStartResult, readStopReason, readStopResult,
  type RuntimeExit, type StartResult, type StopReason, type StopResult, type ToMonitoringUtility,
} from '../../src/services/monitoring/control';
import { LIMITS } from '../../src/services/monitoring/types';
import { MONITORING_EXIT_CHANNEL, MONITORING_PORT_CHANNEL, MONITORING_STATUS_CHANNEL } from '../channels';

// --- what is injected -------------------------------------------------------------------------------

export interface ChildLike {
  /** `ports` are the transferred ends; only `attach` carries one. */
  postMessage(message: unknown, ports?: unknown[]): void;
  onMessage(listener: (message: unknown) => void): void;
  onSpawn(listener: () => void): void;
  onExit(listener: (code: number | null) => void): void;
  kill(): void;
}

/** The part of a `WebContents` the core touches. */
export interface ContentsLike {
  readonly id: number;
  isDestroyed(): boolean;
  postMessage(channel: string, message: unknown, ports?: unknown[]): void;
  send(channel: string, ...args: unknown[]): void;
  once(event: 'destroyed', listener: () => void): unknown;
}

export interface TimersLike {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface HostDeps {
  /** The monitoring directory the utility opens its dataset under. */
  directory: string;
  fork(): ChildLike;
  createChannel(): { port1: unknown; port2: unknown };
  timers: TimersLike;
  /** The saved source's storage limit, or null when none is saved or readable. */
  savedLimitBytes(): number | null;
}

// --- the core -----------------------------------------------------------------------------------------------

const NOT_CONNECTED = 'this window is not connected to monitoring';

interface Pending {
  settle(raw: unknown): void;
  fail(message: string): void;
}

interface Session {
  child: ChildLike;
  /** Set once, by an exit, a deadline on the spawn, or a dispose. */
  ended: boolean;
  spawned: boolean;
  disposing: boolean;
  /** Whether a listener was last known to be starting or running; `RuntimeExit.wasRunning`. */
  running: boolean;
  readonly pending: Map<number, Pending>;
  spawn: Promise<void>;
  rejectSpawn(error: Error): void;
  spawnTimer: unknown;
}

const failStart = (message: string): StartResult => ({ ok: false, message });
const failStop = (message: string): StopResult => ({ ok: false, message, clean: false, snapshot: null });
const NOTHING_TO_STOP: StopResult = { ok: true, clean: true, snapshot: null };
const QUITTING = 'the app is quitting';

/**
 * How long `open` may take: the ordinary request, plus a scan of the whole
 * storage limit. Opening checks every entry of the journal before it answers,
 * so the time is the dataset's size, not a constant - a full default dataset
 * took 18.7 s to scan in memory alone, and a deadline shorter than the scan
 * fails every launch of the app that has filled its storage.
 */
export function openDeadlineMs(limitBytes: number): number {
  return LIMITS.requestMs + Math.ceil(limitBytes / LIMITS.openScanBytesPerSecond * 1000);
}

const seconds = (ms: number): string => `${Math.round(ms / 100) / 10} s`;

export class MonitoringHostCore {
  private session: Session | null = null;
  private bound: ContentsLike | null = null;
  private lastId = 0;
  /** Contents already watched for `destroyed`, so a reload does not add a listener each time. */
  private readonly watched = new WeakSet<ContentsLike>();
  /** Set by the first `drainForQuit` or `release`, and never cleared. */
  private quitting = false;
  /** The one drain, shared by every caller; its settled value is the answer to a late one. */
  private drain: Promise<StopResult> | null = null;

  constructor(private readonly deps: HostDeps) {}

  // --- connect ---------------------------------------------------------------------------------------------

  /**
   * Opens the dataset (forking the utility if there is none) and hands this
   * window the Worker's port, replacing any port and binding it had before.
   * Nothing here binds a socket. Rejects, with the reason, when the process
   * does not start or the dataset does not open.
   *
   * `nonce` is the window's own, from its request: it is echoed in the port
   * message so a port from an attempt that already gave up is told apart from
   * the one the current attempt waits for. It arrives over IPC, so it is
   * `unknown` until it is a positive safe integer.
   */
  async connect(contents: ContentsLike, nonce: unknown): Promise<void> {
    if (this.quitting) throw new Error(QUITTING);
    if (typeof nonce !== 'number' || !Number.isSafeInteger(nonce) || nonce <= 0) {
      throw new Error('that is not a monitoring port request');
    }
    const session = this.session ?? this.launch();
    await session.spawn;
    const limitBytes = this.deps.savedLimitBytes() ?? LIMITS.defaultStorageBytes;
    const opened = await this.ask(
      session, (id) => ({ type: 'open', id, root: this.deps.directory, limitBytes }),
      readStartResult, failStart, openDeadlineMs(limitBytes),
    );
    if (!opened.ok) throw new Error(opened.message);
    if (session.ended || this.session !== session) throw new Error('monitoring stopped while it was connecting');
    if (contents.isDestroyed()) return;
    const { port1, port2 } = this.deps.createChannel();
    // The role needs no tag: `attach` is the one message that carries a port,
    // and a later one replaces the earlier (`control.ts`).
    session.child.postMessage({ type: 'attach' }, [port2]);
    contents.postMessage(MONITORING_PORT_CHANNEL, { nonce }, [port1]);
    this.bind(contents);
  }

  private bind(contents: ContentsLike): void {
    this.bound = contents;
    if (this.watched.has(contents)) return;
    this.watched.add(contents);
    // Unbinds and nothing else: intake outlives the window that started it.
    contents.once('destroyed', () => {
      if (this.bound === contents) this.bound = null;
    });
  }

  // --- start and stop ---------------------------------------------------------------------------------------

  async start(sender: ContentsLike, config: unknown): Promise<StartResult> {
    if (this.quitting) return failStart(QUITTING);
    const session = this.session;
    if (session === null || !this.isBound(sender)) return failStart(NOT_CONNECTED);
    const source = readSourceConfig(config);
    if (source === null) return failStart('that is not a valid monitoring source');
    // A Start can wait out the handshake inside the utility, so its deadline
    // is that wait and then the ordinary one.
    const result = await this.ask(
      session, (id) => ({ type: 'start', id, config: source }),
      readStartResult, failStart, LIMITS.handshakeMs + LIMITS.requestMs,
    );
    if (result.ok) session.running = true;
    return result;
  }

  async stop(sender: ContentsLike, reason: unknown): Promise<StopResult> {
    if (this.quitting) return failStop(QUITTING);
    const session = this.session;
    if (session === null || !this.isBound(sender)) return failStop(NOT_CONNECTED);
    const why = readStopReason(reason);
    if (why === null) return failStop('that is not a reason monitoring can stop for');
    return this.stopSession(session, why);
  }

  /**
   * Main's own stop, for the computer going to sleep: no window is asked and
   * none need be bound. Stopped or unconnected is already what was asked for,
   * so nothing is sent. `stop` stays the only operation a window reaches.
   */
  async suspend(): Promise<StopResult> {
    if (this.quitting) return failStop(QUITTING);
    const session = this.session;
    if (session === null || session.ended || !session.running) return NOTHING_TO_STOP;
    return this.stopSession(session, 'suspend');
  }

  private async stopSession(session: Session, reason: StopReason): Promise<StopResult> {
    const result = await this.ask(
      session, (id) => ({ type: 'stop', id, reason }),
      readStopResult, failStop, LIMITS.drainMs + LIMITS.requestMs,
    );
    if (result.ok) session.running = false;
    return result;
  }

  /** Whether a listener is starting or listening in a utility that is still alive. */
  isRunning(): boolean {
    const session = this.session;
    return session !== null && !session.ended && session.running;
  }

  private isBound(sender: ContentsLike): boolean {
    return this.bound !== null && this.bound.id === sender.id && !this.bound.isDestroyed();
  }

  // --- quitting ------------------------------------------------------------------------------------------------

  /**
   * On quit with a listener running: the utility stops intake with reason
   * `quit` (which finishes the admitted journal writes, appends the final
   * boundary and flushes) and closes the dataset, and is then ended. Never
   * rejects, and every caller gets the one answer: a second call while this is
   * in flight returns the same promise, a call after it settled returns the
   * settled result and sends nothing.
   *
   * `LIMITS.drainMs` is the whole wait. A deadline, a refused write or a dead
   * child is `clean: false`, the child is killed and the journal is left for
   * the next open to recover; nothing here removes it.
   */
  drainForQuit(): Promise<StopResult> {
    if (this.drain !== null) return this.drain;
    this.quitting = true;
    const session = this.session;
    this.drain = session === null ? Promise.resolve(NOTHING_TO_STOP) : this.drainSession(session);
    return this.drain;
  }

  private async drainSession(session: Session): Promise<StopResult> {
    session.disposing = true;
    let result: StopResult = NOTHING_TO_STOP;
    try {
      // A child that never spawned has been sent nothing and holds nothing to stop.
      if (session.spawned) {
        result = await this.ask(
          session, (id) => ({ type: 'dispose', id }),
          readStopResult, failStop, LIMITS.drainMs,
        );
      }
    } finally {
      this.endSession(session, 'monitoring was shut down', null, true);
      this.bound = null;
    }
    return result;
  }

  /**
   * On quit with nothing running: the session ends at once, the child is
   * killed and nothing is sent or awaited. The journal is consistent because
   * the last stop flushed it, and anything else is the next open's recovery.
   * Idempotent; a no-op with no session.
   */
  release(): void {
    this.quitting = true;
    const session = this.session;
    if (session === null) return;
    session.disposing = true;
    this.endSession(session, 'monitoring was shut down', null, true);
    this.bound = null;
  }

  // --- the process ----------------------------------------------------------------------------------------------

  private launch(): Session {
    const child = this.deps.fork();
    let resolveSpawn!: () => void;
    let rejectSpawn!: (error: Error) => void;
    const session: Session = {
      child, ended: false, spawned: false, disposing: false, running: false,
      pending: new Map(),
      spawn: new Promise<void>((resolve, reject) => { resolveSpawn = resolve; rejectSpawn = reject; }),
      rejectSpawn: (error) => rejectSpawn(error),
      spawnTimer: null,
    };
    // A rejection nobody awaits (the process never spawned and nobody asked) is not unhandled.
    session.spawn.catch(() => undefined);
    this.session = session;
    // A message posted before `spawn` is not delivered, which is why nothing
    // is sent until it arrives and why it has a deadline.
    session.spawnTimer = this.deps.timers.setTimeout(() => {
      this.endSession(session, `monitoring did not start within ${seconds(LIMITS.handshakeMs)}`, null, true);
    }, LIMITS.handshakeMs);
    child.onSpawn(() => {
      if (session.ended) return;
      session.spawned = true;
      this.deps.timers.clearTimeout(session.spawnTimer);
      resolveSpawn();
    });
    child.onMessage((raw) => this.onMessage(session, raw));
    child.onExit((code) => {
      this.endSession(session, `monitoring stopped unexpectedly (exit ${code})`, code, false);
    });
    return session;
  }

  private onMessage(session: Session, raw: unknown): void {
    if (session.ended) return;
    const message = readFromUtility(raw);
    if (message === null) return;
    if (message.type === 'reply') {
      session.pending.get(message.id)?.settle(message.result);
      return;
    }
    const { listener } = message.status;
    session.running = listener === 'starting' || listener === 'listening';
    // Unchanged, and only to the window that holds control.
    if (this.bound !== null && !this.bound.isDestroyed()) this.bound.send(MONITORING_STATUS_CHANNEL, message.status);
  }

  /**
   * The one place a session ends: fails everything pending, forgets the
   * child and, unless the app is quitting, tells the bound window. Idempotent,
   * because an exit follows a kill.
   */
  private endSession(session: Session, message: string, code: number | null, kill: boolean): void {
    if (session.ended) return;
    session.ended = true;
    if (this.session === session) this.session = null;
    this.deps.timers.clearTimeout(session.spawnTimer);
    session.rejectSpawn(new Error(message));
    for (const pending of [...session.pending.values()]) pending.fail(message);
    session.pending.clear();
    if (kill) {
      try { session.child.kill(); } catch { /* already gone */ }
    }
    if (session.disposing) return;
    const contents = this.bound;
    this.bound = null;
    if (contents !== null && !contents.isDestroyed()) {
      const exit: RuntimeExit = { code, wasRunning: session.running, message };
      contents.send(MONITORING_EXIT_CHANNEL, exit);
    }
  }

  /** One request to the utility: settles on its reply, on the deadline, or when the session ends. */
  private ask<T>(
    session: Session, build: (id: number) => ToMonitoringUtility,
    read: (raw: unknown) => T, fail: (message: string) => T, ms: number,
  ): Promise<T> {
    if (session.ended) return Promise.resolve(fail('monitoring is not running'));
    return new Promise<T>((resolve) => {
      const id = ++this.lastId;
      const done = (value: T): void => {
        this.deps.timers.clearTimeout(timer);
        session.pending.delete(id);
        resolve(value);
      };
      const timer = this.deps.timers.setTimeout(() => done(fail(`monitoring did not answer within ${seconds(ms)}`)), ms);
      session.pending.set(id, { settle: (raw) => done(read(raw)), fail: (message) => done(fail(message)) });
      try {
        session.child.postMessage(build(id));
      } catch (e) {
        done(fail(`monitoring could not be reached (${e instanceof Error ? e.message : String(e)})`));
      }
    });
  }
}
