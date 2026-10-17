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
 */
import { readSourceConfig } from '../../src/services/monitoring/config';
import {
  readFromUtility, readStartResult, readStopReason, readStopResult,
  type RuntimeExit, type StartResult, type StopResult, type ToMonitoringUtility,
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

const seconds = (ms: number): string => `${Math.round(ms / 100) / 10} s`;

export class MonitoringHostCore {
  private session: Session | null = null;
  private bound: ContentsLike | null = null;
  private lastId = 0;
  /** Contents already watched for `destroyed`, so a reload does not add a listener each time. */
  private readonly watched = new WeakSet<ContentsLike>();

  constructor(private readonly deps: HostDeps) {}

  // --- connect ---------------------------------------------------------------------------------------------

  /**
   * Opens the dataset (forking the utility if there is none) and hands this
   * window the Worker's port, replacing any port and binding it had before.
   * Nothing here binds a socket. Rejects, with the reason, when the process
   * does not start or the dataset does not open.
   */
  async connect(contents: ContentsLike): Promise<void> {
    const session = this.session ?? this.launch();
    await session.spawn;
    const limitBytes = this.deps.savedLimitBytes() ?? LIMITS.defaultStorageBytes;
    const opened = await this.ask(
      session, (id) => ({ type: 'open', id, root: this.deps.directory, limitBytes }),
      readStartResult, failStart, LIMITS.requestMs,
    );
    if (!opened.ok) throw new Error(opened.message);
    if (session.ended || this.session !== session) throw new Error('monitoring stopped while it was connecting');
    if (contents.isDestroyed()) return;
    const { port1, port2 } = this.deps.createChannel();
    // The role needs no tag: `attach` is the one message that carries a port,
    // and a later one replaces the earlier (`control.ts`).
    session.child.postMessage({ type: 'attach' }, [port2]);
    contents.postMessage(MONITORING_PORT_CHANNEL, null, [port1]);
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
    const session = this.session;
    if (session === null || !this.isBound(sender)) return failStop(NOT_CONNECTED);
    const why = readStopReason(reason);
    if (why === null) return failStop('that is not a reason monitoring can stop for');
    const result = await this.ask(
      session, (id) => ({ type: 'stop', id, reason: why }),
      readStopResult, failStop, LIMITS.drainMs + LIMITS.requestMs,
    );
    if (result.ok) session.running = false;
    return result;
  }

  private isBound(sender: ContentsLike): boolean {
    return this.bound !== null && this.bound.id === sender.id && !this.bound.isDestroyed();
  }

  // --- dispose -------------------------------------------------------------------------------------------------

  /**
   * On quit: the utility stops intake with reason `quit`, closes the dataset
   * and is then ended. Resolves whatever happens - a process that is already
   * dead, never spawned or past its deadline does not hold the app open.
   */
  async dispose(): Promise<void> {
    const session = this.session;
    if (session === null) return;
    session.disposing = true;
    try {
      if (session.spawned) {
        await this.ask(
          session, (id) => ({ type: 'dispose', id }),
          readStopResult, failStop, LIMITS.drainMs + LIMITS.requestMs,
        );
      }
    } finally {
      this.endSession(session, 'monitoring was shut down', null, true);
      this.bound = null;
    }
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
