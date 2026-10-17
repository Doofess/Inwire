/**
 * Assertion tests for main's monitoring host, the saved source, the atomic
 * write, the renderer's client and the state reducer (ADRs 0058, 0059).
 *
 *   npx tsx scripts/monitoring/runtime-host.ts
 *
 * No Electron: `MonitoringHostCore` and `MonitoringClient` take the child
 * process, the windows, the Worker and the clock as parameters, so a fake
 * child that never spawns, a fake window that is destroyed and a clock the
 * test advances reach every branch. What this cannot show is that the real
 * `utilityProcess` delivers a message after `spawn` and not before, or that a
 * `MessagePortMain` crosses the process boundary - `host.ts` is the adapter
 * for those and the live drive is where they get watched.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeFileAtomic, partialPath } from '../../electron/atomicWrite';
import { MONITORING_EXIT_CHANNEL, MONITORING_PORT_CHANNEL, MONITORING_STATUS_CHANNEL } from '../../electron/channels';
import { MonitoringHostCore, openDeadlineMs, type ChildLike, type ContentsLike } from '../../electron/monitoring/hostCore';
import { readMonitoringSettings, saveMonitoringSettings, SETTINGS_FILE } from '../../electron/monitoring/settings';
import {
  MonitoringClient, MONITORING_PORT_MESSAGE,
  type MonitoringBridge, type PortMessageEvent, type WorkerLike,
} from '../../src/services/monitoring/client';
import type { IntakeStatus, RuntimeExit } from '../../src/services/monitoring/control';
import {
  initialMonitoringState, reduceMonitoring, type MonitoringState,
} from '../../src/services/monitoring/state';
import { LIMITS, type SourceConfig } from '../../src/services/monitoring/types';

// --- the harness --------------------------------------------------------------------------------------------

let failures = 0;
const queue: { name: string; fn: () => Promise<void> | void }[] = [];
function test(name: string, fn: () => Promise<void> | void) { queue.push({ name, fn }); }

const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/** A clock the test advances; timers fire in order, with the event loop drained after each. */
class Clock {
  now = 0;
  private next = 1;
  private readonly timers = new Map<number, { at: number; fn: () => void }>();
  setTimeout(fn: () => void, ms: number): unknown {
    const id = this.next++;
    this.timers.set(id, { at: this.now + ms, fn });
    return id;
  }
  clearTimeout(handle: unknown): void { this.timers.delete(handle as number); }
  get pendingTimers(): number { return this.timers.size; }
  async advance(ms: number): Promise<void> {
    const target = this.now + ms;
    for (;;) {
      let due: [number, { at: number; fn: () => void }] | null = null;
      for (const entry of this.timers) if (entry[1].at <= target && (due === null || entry[1].at < due[1].at)) due = entry;
      if (due === null) break;
      this.timers.delete(due[0]);
      this.now = due[1].at;
      due[1].fn();
      await flush();
    }
    this.now = target;
    await flush();
  }
}

const CONFIG: SourceConfig = { exporterIPv4: '192.0.2.10', bindIPv4: '127.0.0.1', port: 2055, storageLimitBytes: 1024 * 1024 * 1024 };

function status(over: Partial<IntakeStatus> = {}): IntakeStatus {
  return {
    listener: 'listening', listenerError: null, storage: 'open', storageError: null, source: CONFIG, sessionId: 'session-1',
    received: 0, rejectedSenders: [], rejectedOverflow: 0, shedDatagrams: 0, snapshot: null, workerAttached: true, ...over,
  };
}

// --- main's side ---------------------------------------------------------------------------------------------------

type Reply = unknown | 'none';

class FakeChild implements ChildLike {
  sent: { message: Record<string, unknown>; ports: unknown[] | undefined }[] = [];
  killed = 0;
  /** What each request type answers; `'none'` stays silent. */
  replies: Record<string, Reply> = {
    open: { ok: true }, start: { ok: true }, stop: { ok: true, clean: true, snapshot: null }, dispose: { ok: true, clean: true, snapshot: null },
  };
  private messageListeners: ((m: unknown) => void)[] = [];
  private spawnListeners: (() => void)[] = [];
  private exitListeners: ((code: number | null) => void)[] = [];
  postMessage(message: unknown, ports?: unknown[]): void {
    const m = message as Record<string, unknown>;
    this.sent.push({ message: m, ports });
    const answer = this.replies[String(m.type)];
    if (typeof m.id === 'number' && answer !== 'none' && answer !== undefined) {
      queueMicrotask(() => this.emitMessage({ type: 'reply', id: m.id, result: answer }));
    }
  }
  onMessage(l: (m: unknown) => void): void { this.messageListeners.push(l); }
  onSpawn(l: () => void): void { this.spawnListeners.push(l); }
  onExit(l: (code: number | null) => void): void { this.exitListeners.push(l); }
  kill(): void { this.killed++; }
  emitSpawn(): void { for (const l of this.spawnListeners) l(); }
  emitMessage(m: unknown): void { for (const l of this.messageListeners) l(m); }
  emitExit(code: number | null): void { for (const l of this.exitListeners) l(code); }
  types(): string[] { return this.sent.map((s) => String(s.message.type)); }
  of(type: string) { return this.sent.filter((s) => s.message.type === type); }
}

class FakeContents implements ContentsLike {
  destroyed = false;
  posts: { channel: string; message: unknown; ports: unknown[] | undefined }[] = [];
  sends: { channel: string; args: unknown[] }[] = [];
  private destroyListeners: (() => void)[] = [];
  constructor(readonly id: number) {}
  isDestroyed(): boolean { return this.destroyed; }
  postMessage(channel: string, message: unknown, ports?: unknown[]): void { this.posts.push({ channel, message, ports }); }
  send(channel: string, ...args: unknown[]): void { this.sends.push({ channel, args }); }
  once(_event: 'destroyed', listener: () => void): unknown { this.destroyListeners.push(listener); return this; }
  get listenerCount(): number { return this.destroyListeners.length; }
  destroy(): void { this.destroyed = true; for (const l of this.destroyListeners) l(); }
  sent(channel: string): unknown[][] { return this.sends.filter((s) => s.channel === channel).map((s) => s.args); }
}

function hostRig(saved: number | null = null) {
  const clock = new Clock();
  const children: FakeChild[] = [];
  const channels: { port1: { name: string }; port2: { name: string } }[] = [];
  let limit = saved;
  const core = new MonitoringHostCore({
    directory: 'monitoring-dir',
    fork: () => { const c = new FakeChild(); children.push(c); return c; },
    createChannel: () => {
      const n = channels.length + 1;
      const pair = { port1: { name: `port1-${n}` }, port2: { name: `port2-${n}` } };
      channels.push(pair);
      return pair;
    },
    timers: clock,
    savedLimitBytes: () => limit,
  });
  return { core, clock, children, channels, setLimit: (v: number | null) => { limit = v; } };
}

/** Connects `contents` to a child that spawns at once. */
async function connect(r: ReturnType<typeof hostRig>, contents: FakeContents): Promise<FakeChild> {
  const done = r.core.connect(contents, 1);
  const child = r.children[r.children.length - 1];
  child.emitSpawn();
  await done;
  return child;
}

// --- the host: connect --------------------------------------------------------------------------------------------

test('host: connect forks once and sends nothing before the child has spawned', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 1);
  await flush();
  assert.equal(r.children.length, 1);
  assert.deepEqual(r.children[0].sent, []);
  r.children[0].emitSpawn();
  await done;
  assert.equal(r.children.length, 1);
  assert.deepEqual(r.children[0].types(), ['open', 'attach']);
  // A second connect while the first is settled does not fork either.
  await connect(r, new FakeContents(2));
  assert.equal(r.children.length, 1);
});

test('host: a child that never spawns fails connect at the deadline and is killed', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 1);
  const outcome = done.then(() => 'connected', (e: Error) => e.message);
  await r.clock.advance(LIMITS.handshakeMs - 1);
  assert.equal(r.children[0].killed, 0);
  await r.clock.advance(1);
  assert.match(await outcome, /did not start within 15 s/);
  assert.equal(r.children[0].killed, 1);
  assert.deepEqual(r.children[0].sent, []);
  assert.deepEqual(c1.posts, []);
  assert.deepEqual(c1.sends, []);
});

test('host: open carries the saved storage limit, or 8 GiB when none is saved', async () => {
  const saved = hostRig(64 * 1024 * 1024);
  const a = await connect(saved, new FakeContents(1));
  assert.equal(a.of('open')[0].message.limitBytes, 64 * 1024 * 1024);
  assert.equal(a.of('open')[0].message.root, 'monitoring-dir');
  const fresh = hostRig(null);
  const b = await connect(fresh, new FakeContents(1));
  assert.equal(b.of('open')[0].message.limitBytes, LIMITS.defaultStorageBytes);
  assert.equal(LIMITS.defaultStorageBytes, 8 * 1024 * 1024 * 1024);
});

test('host: a refused open rejects connect with the reason and posts no port', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 1);
  r.children[0].replies.open = { ok: false, message: 'the journal is corrupt' };
  r.children[0].emitSpawn();
  await assert.rejects(done, /the journal is corrupt/);
  assert.deepEqual(r.children[0].of('attach'), []);
  assert.deepEqual(c1.posts, []);
});

test('host: the port goes to the child as attach and to the window on the port channel', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  const attach = child.of('attach')[0];
  assert.deepEqual(attach.ports, [r.channels[0].port2]);
  assert.equal(c1.posts.length, 1);
  assert.equal(c1.posts[0].channel, MONITORING_PORT_CHANNEL);
  assert.deepEqual(c1.posts[0].message, { nonce: 1 });
  assert.deepEqual(c1.posts[0].ports, [r.channels[0].port1]);
});

test('host: a second connect (a reload) replaces the port and the binding without forking', async () => {
  const r = hostRig();
  const first = new FakeContents(1);
  const second = new FakeContents(2);
  const child = await connect(r, first);
  await connect(r, second);
  assert.equal(r.children.length, 1);
  assert.equal(child.of('attach').length, 2);
  assert.deepEqual(child.of('attach')[1].ports, [r.channels[1].port2]);
  assert.deepEqual(second.posts[0].ports, [r.channels[1].port1]);
  // The new window holds control and the old one does not.
  assert.deepEqual((await r.core.start(second, CONFIG)).ok, true);
  const refused = await r.core.start(first, CONFIG);
  assert.equal(refused.ok, false);
});

test('host: the same window connecting again adds one destroyed listener, not one per reload', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  await connect(r, c1);
  await connect(r, c1);
  await connect(r, c1);
  assert.equal(c1.listenerCount, 1);
});

test('host: the port message echoes the request nonce, and a nonce that is not a positive safe integer is refused before anything forks', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 41);
  r.children[0].emitSpawn();
  await done;
  assert.deepEqual(c1.posts[0].message, { nonce: 41 });
  for (const bad of [undefined, null, 0, -1, 1.5, NaN, Infinity, 2 ** 53, '1', {}, [1], true]) {
    const fresh = hostRig();
    const c = new FakeContents(2);
    await assert.rejects(fresh.core.connect(c, bad), /that is not a monitoring port request/, String(bad));
    assert.equal(fresh.children.length, 0);
    assert.deepEqual(c.posts, []);
  }
});

test('host: open is allowed a scan of the whole storage limit - an answer just under its deadline connects', async () => {
  assert.equal(openDeadlineMs(LIMITS.defaultStorageBytes), LIMITS.requestMs + Math.ceil(LIMITS.defaultStorageBytes / LIMITS.openScanBytesPerSecond * 1000));
  assert.ok(openDeadlineMs(LIMITS.defaultStorageBytes) > 18_700 + LIMITS.requestMs, 'longer than the measured scan of a full default dataset');
  assert.equal(openDeadlineMs(0), LIMITS.requestMs);
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 1);
  const child = r.children[0];
  child.replies.open = 'none';
  child.emitSpawn();
  await flush();
  const deadline = openDeadlineMs(LIMITS.defaultStorageBytes);
  await r.clock.advance(deadline - 1);
  child.emitMessage({ type: 'reply', id: child.of('open')[0].message.id, result: { ok: true } });
  await done;
  assert.deepEqual(child.types(), ['open', 'attach']);
  assert.equal(c1.posts.length, 1);
  assert.equal(child.killed, 0);
});

test('host: an open the utility never answers fails at exactly its deadline, not at the ordinary one', async () => {
  const r = hostRig(64 * 1024 * 1024);
  const done = r.core.connect(new FakeContents(1), 1);
  const outcome = done.then(() => 'connected', (e: Error) => e.message);
  r.children[0].replies.open = 'none';
  r.children[0].emitSpawn();
  await flush();
  const deadline = openDeadlineMs(64 * 1024 * 1024);
  assert.equal(deadline, LIMITS.requestMs + 1000);
  await r.clock.advance(LIMITS.requestMs);
  await r.clock.advance(deadline - LIMITS.requestMs - 1);
  let settled = false;
  void outcome.then(() => { settled = true; });
  await flush();
  assert.equal(settled, false);
  await r.clock.advance(1);
  assert.match(await outcome, /did not answer within 16 s/);
});

// --- the host: start and stop ------------------------------------------------------------------------------------

test('host: start and stop from a window that is not bound are refused and reach nobody', async () => {
  const r = hostRig();
  const bound = new FakeContents(1);
  const stranger = new FakeContents(9);
  const child = await connect(r, bound);
  const start = await r.core.start(stranger, CONFIG);
  const stop = await r.core.stop(stranger, 'user');
  assert.equal(start.ok, false);
  assert.equal(stop.ok, false);
  assert.deepEqual(child.of('start'), []);
  assert.deepEqual(child.of('stop'), []);
  // And before anything is connected at all.
  const empty = hostRig();
  assert.equal((await empty.core.start(stranger, CONFIG)).ok, false);
  assert.equal((await empty.core.stop(stranger, 'user')).ok, false);
});

test('host: a bound window starts and stops, and a bad config or reason never reaches the utility', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  assert.deepEqual(await r.core.start(c1, CONFIG), { ok: true });
  assert.deepEqual(child.of('start')[0].message.config, CONFIG);
  assert.equal((await r.core.start(c1, { exporterIPv4: 'nope' })).ok, false);
  assert.equal((await r.core.stop(c1, 'whenever')).ok, false);
  assert.equal(child.of('start').length, 1);
  assert.equal(child.of('stop').length, 0);
  const stopped = await r.core.stop(c1, 'user');
  assert.deepEqual(stopped, { ok: true, clean: true, snapshot: null });
});

test('host: a reply that does not parse is a failed request, not a success', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = 'fine';
  child.replies.stop = { ok: true };
  assert.equal((await r.core.start(c1, CONFIG)).ok, false);
  assert.equal((await r.core.stop(c1, 'user')).ok, false);
});

test('host: a request the utility never answers settles at its deadline, start after the handshake and stop after the drain', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = 'none';
  child.replies.stop = 'none';
  let start = null as unknown;
  void r.core.start(c1, CONFIG).then((v) => { start = v; });
  await r.clock.advance(LIMITS.handshakeMs + LIMITS.requestMs - 1);
  assert.equal(start === null, true);
  await r.clock.advance(1);
  assert.equal((start as { ok: boolean }).ok, false);
  assert.match((start as { message: string }).message, /did not answer/);
  let stop = null as unknown;
  void r.core.stop(c1, 'user').then((v) => { stop = v; });
  await r.clock.advance(LIMITS.drainMs + LIMITS.requestMs - 1);
  assert.equal(stop === null, true);
  await r.clock.advance(1);
  assert.equal((stop as { ok: boolean }).ok, false);
  assert.equal((stop as { clean: boolean }).clean, false);
});

test('host: an answered request leaves no timer behind', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  await connect(r, c1);
  await r.core.start(c1, CONFIG);
  await r.core.stop(c1, 'user');
  assert.equal(r.clock.pendingTimers, 0);
});

// --- the host: the process dies -----------------------------------------------------------------------------------

test('host: a utility exit settles every pending request and tells the bound window', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  assert.equal((await r.core.start(c1, CONFIG)).ok, true);
  child.replies.stop = 'none';
  child.replies.start = 'none';
  let stop = null as unknown;
  void r.core.stop(c1, 'user').then((v) => { stop = v; });
  await flush();
  child.emitExit(3);
  await flush();
  assert.equal((stop as { ok: boolean }).ok, false);
  assert.match((stop as { message: string }).message, /exit 3/);
  const exits = c1.sent(MONITORING_EXIT_CHANNEL);
  assert.equal(exits.length, 1);
  const exit = exits[0][0] as RuntimeExit;
  assert.equal(exit.code, 3);
  assert.equal(exit.wasRunning, true);
  assert.match(exit.message, /exit 3/);
  assert.equal(r.clock.pendingTimers, 0);
});

test('host: after an exit the next connect forks anew, and control is unbound until then', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const first = await connect(r, c1);
  first.emitExit(1);
  await flush();
  assert.equal((await r.core.start(c1, CONFIG)).ok, false);
  const second = await connect(r, c1);
  assert.equal(r.children.length, 2);
  assert.notEqual(first, second);
  assert.equal((await r.core.start(c1, CONFIG)).ok, true);
  // A message from the dead child is nobody's.
  first.emitMessage({ type: 'status', status: status() });
  assert.equal(c1.sent(MONITORING_STATUS_CHANNEL).length, 0);
});

test('host: an exit is reported once even when it follows a kill', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const done = r.core.connect(c1, 1).catch(() => undefined);
  await r.clock.advance(LIMITS.handshakeMs);
  await done;
  r.children[0].emitExit(null);
  await flush();
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  const c2 = new FakeContents(2);
  const child = await connect(r, c2);
  child.emitExit(1);
  child.emitExit(1);
  await flush();
  assert.equal(c2.sent(MONITORING_EXIT_CHANNEL).length, 1);
});

// --- the host: status ---------------------------------------------------------------------------------------------

test('host: status goes unchanged to the bound window and only when it validates', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.emitMessage({ type: 'status', status: status({ received: 7 }) });
  child.emitMessage({ type: 'status', status: { listener: 'listening' } });
  child.emitMessage({ type: 'status', status: status({ received: -1 }) });
  child.emitMessage('status');
  const got = c1.sent(MONITORING_STATUS_CHANNEL);
  assert.equal(got.length, 1);
  assert.deepEqual(got[0][0], status({ received: 7 }));
});

test('host: status is not sent to a window that is not bound, or one that is destroyed', async () => {
  const r = hostRig();
  const first = new FakeContents(1);
  const second = new FakeContents(2);
  const child = await connect(r, first);
  await connect(r, second);
  child.emitMessage({ type: 'status', status: status() });
  assert.equal(first.sent(MONITORING_STATUS_CHANNEL).length, 0);
  assert.equal(second.sent(MONITORING_STATUS_CHANNEL).length, 1);
  second.destroyed = true;
  child.emitMessage({ type: 'status', status: status() });
  assert.equal(second.sent(MONITORING_STATUS_CHANNEL).length, 1);
});

test('host: a destroyed window unbinds control without stopping intake', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  c1.destroy();
  assert.deepEqual(child.of('stop'), []);
  assert.deepEqual(child.of('dispose'), []);
  assert.equal(child.killed, 0);
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  // Control is nobody's, and the next window to connect takes it with the same process.
  assert.equal((await r.core.stop(new FakeContents(1), 'user')).ok, false);
  const c2 = new FakeContents(2);
  await connect(r, c2);
  assert.equal(r.children.length, 1);
  assert.equal((await r.core.stop(c2, 'user')).ok, true);
});

// --- the host: dispose --------------------------------------------------------------------------------------------

test('host: dispose asks the utility to dispose, kills it and does not announce an exit', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.dispose();
  assert.equal(child.of('dispose').length, 1);
  assert.equal(child.killed, 1);
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  child.emitExit(0);
  await flush();
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
});

test('host: dispose resolves with nothing connected, with a child that never spawned and with a silent one', async () => {
  await hostRig().core.dispose();
  const never = hostRig();
  const pending = never.core.connect(new FakeContents(1), 1).catch(() => undefined);
  await never.core.dispose();
  await pending;
  assert.equal(never.children[0].killed, 1);
  assert.deepEqual(never.children[0].sent, []);
  const silent = hostRig();
  const child = await connect(silent, new FakeContents(1));
  child.replies.dispose = 'none';
  let done = false;
  void silent.core.dispose().then(() => { done = true; });
  await silent.clock.advance(LIMITS.drainMs + LIMITS.requestMs);
  assert.equal(done, true);
  assert.equal(child.killed, 1);
});

// --- the saved source ---------------------------------------------------------------------------------------------

function tempDir(): string { return mkdtempSync(path.join(os.tmpdir(), 'inwire-monitoring-settings-')); }

test('settings: a missing file reads as no source, not as a failure', () => {
  const dir = tempDir();
  try {
    assert.deepEqual(readMonitoringSettings(dir), { ok: true, config: null });
    assert.deepEqual(readMonitoringSettings(path.join(dir, 'never-created')), { ok: true, config: null });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a file that is not JSON, not an object or the wrong version is a stated failure', () => {
  const dir = tempDir();
  try {
    const file = path.join(dir, SETTINGS_FILE);
    for (const [text, pattern] of [
      ['{ not json', /not valid JSON/], ['[1]', /not a JSON object/], ['null', /not a JSON object/],
      [JSON.stringify({ version: 2, source: CONFIG }), /version 2/], [JSON.stringify({ source: CONFIG }), /version undefined/],
    ] as [string, RegExp][]) {
      writeFileSync(file, text);
      const read = readMonitoringSettings(dir);
      assert.equal(read.ok, false, text);
      assert.match((read as { message: string }).message, pattern);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a source that fails validation is a failure, never a default', () => {
  const dir = tempDir();
  try {
    const file = path.join(dir, SETTINGS_FILE);
    for (const source of [null, {}, { ...CONFIG, bindIPv4: '0.0.0.0' }, { ...CONFIG, port: 0 }, { ...CONFIG, storageLimitBytes: 5 }]) {
      writeFileSync(file, JSON.stringify({ version: 1, source }));
      const read = readMonitoringSettings(dir);
      assert.equal(read.ok, false, JSON.stringify(source));
      assert.match((read as { message: string }).message, /not a valid configuration/);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a save that does not validate is refused and writes nothing', () => {
  const dir = tempDir();
  try {
    let writes = 0;
    const result = saveMonitoringSettings(dir, { ...CONFIG, bindIPv4: '0.0.0.0' }, () => { writes++; });
    assert.equal(result.ok, false);
    assert.equal(writes, 0);
    assert.deepEqual(readdirSync(dir), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a failing write is surfaced as a failed save and leaves the previous file whole', () => {
  const dir = tempDir();
  try {
    assert.equal(saveMonitoringSettings(dir, CONFIG).ok, true);
    const before = readFileSync(path.join(dir, SETTINGS_FILE), 'utf8');
    const result = saveMonitoringSettings(dir, { ...CONFIG, port: 9995 }, () => { throw new Error('disk full'); });
    assert.equal(result.ok, false);
    assert.match((result as { message: string }).message, /could not be saved \(disk full\)/);
    assert.equal(readFileSync(path.join(dir, SETTINGS_FILE), 'utf8'), before);
    assert.deepEqual(readMonitoringSettings(dir), { ok: true, config: CONFIG });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a saved source reads back, in a directory that did not exist, with no partial left', () => {
  const dir = tempDir();
  try {
    const nested = path.join(dir, 'a', 'b');
    const saved = saveMonitoringSettings(nested, { ...CONFIG, extra: 'ignored' });
    assert.deepEqual(saved, { ok: true, config: CONFIG });
    assert.deepEqual(readMonitoringSettings(nested), { ok: true, config: CONFIG });
    assert.deepEqual(readdirSync(nested), [SETTINGS_FILE]);
    assert.deepEqual(JSON.parse(readFileSync(path.join(nested, SETTINGS_FILE), 'utf8')), { version: 1, source: CONFIG });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- the atomic write ----------------------------------------------------------------------------------------------

test('atomic write: the partial name is the target plus twelve hex digits plus .partial, new each time', () => {
  const a = partialPath('x/settings.json');
  assert.match(a, /^x\/settings\.json\.[0-9a-f]{12}\.partial$/);
  assert.notEqual(a, partialPath('x/settings.json'));
});

test('atomic write: it replaces the target whole and leaves no partial', () => {
  const dir = tempDir();
  try {
    const target = path.join(dir, 'out.json');
    writeFileAtomic(target, 'one');
    writeFileAtomic(target, new TextEncoder().encode('two'));
    assert.equal(readFileSync(target, 'utf8'), 'two');
    assert.deepEqual(readdirSync(dir), ['out.json']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('atomic write: a failure throws and leaves no partial behind', () => {
  const dir = tempDir();
  try {
    // A directory cannot be replaced by a file, so the rename fails after the partial was written.
    const target = path.join(dir, 'taken');
    mkdirSync(target);
    assert.throws(() => writeFileAtomic(target, 'data'));
    assert.deepEqual(readdirSync(dir), ['taken']);
    // And a directory that is not there fails before anything exists.
    assert.throws(() => writeFileAtomic(path.join(dir, 'missing', 'f'), 'data'));
    assert.deepEqual(readdirSync(dir), ['taken']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('atomic write: a cleanup that itself fails does not replace the error that caused it', () => {
  const dir = tempDir();
  const realRm = fs.rmSync;
  try {
    const target = path.join(dir, 'taken');
    mkdirSync(target);
    // Windows can refuse to remove a partial (EPERM, EBUSY) a moment after it was written.
    fs.rmSync = (() => { throw Object.assign(new Error('EPERM: cleanup refused'), { code: 'EPERM' }); }) as typeof fs.rmSync;
    syncBuiltinESMExports();
    let thrown: unknown;
    try { writeFileAtomic(target, 'data'); } catch (e) { thrown = e; }
    assert.ok(thrown instanceof Error);
    // The rename onto a directory is the failure; the refused cleanup must not have replaced it.
    assert.doesNotMatch((thrown as Error).message, /cleanup refused/);
    assert.match((thrown as Error).message, /rename/);
  } finally {
    fs.rmSync = realRm;
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- the renderer's client -----------------------------------------------------------------------------------------

class FakeWindow {
  listeners = new Set<(e: PortMessageEvent) => void>();
  addEventListener(_t: 'message', l: (e: PortMessageEvent) => void) { this.listeners.add(l); }
  removeEventListener(_t: 'message', l: (e: PortMessageEvent) => void) { this.listeners.delete(l); }
  post(event: PortMessageEvent) { for (const l of [...this.listeners]) l(event); }
}

class FakeWorker implements WorkerLike {
  posts: { message: Record<string, unknown>; transfer: unknown[] | undefined }[] = [];
  terminated = 0;
  /** What each request type answers; `'none'` stays silent. */
  replies: Record<string, (m: Record<string, unknown>) => unknown | 'none'> = {
    connect: (m) => ({ type: 'connect-reply', requestId: m.requestId, ok: true, phase: 'live', watermark: 5 }),
  };
  private message: ((e: { data: unknown }) => void)[] = [];
  private error: ((e: { message?: string }) => void)[] = [];
  postMessage(message: unknown, transfer?: unknown[]): void {
    const m = message as Record<string, unknown>;
    this.posts.push({ message: m, transfer });
    const answer = this.replies[String(m.type)]?.(m);
    if (answer !== undefined && answer !== 'none') queueMicrotask(() => this.emit(answer));
  }
  terminate(): void { this.terminated++; }
  addEventListener(type: 'message' | 'error', l: never): void {
    if (type === 'message') this.message.push(l); else this.error.push(l);
  }
  emit(data: unknown): void { for (const l of this.message) l({ data }); }
  fail(message?: string): void { for (const l of this.error) l({ message }); }
  of(type: string) { return this.posts.filter((p) => p.message.type === type); }
}

function clientRig(over: Partial<MonitoringBridge> & { sendPort?: boolean } = {}) {
  const clock = new Clock();
  const win = new FakeWindow();
  const workers: FakeWorker[] = [];
  const port = { name: 'runtime-port' };
  const exitListeners: ((v: unknown) => void)[] = [];
  const statusListeners: ((v: unknown) => void)[] = [];
  let portRequests = 0;
  const nonces: number[] = [];
  const { sendPort = true, ...bridgeOver } = over;
  const bridge: MonitoringBridge = {
    requestMonitoringPort: async (nonce) => {
      portRequests++;
      nonces.push(nonce);
      if (sendPort) win.post({ source: win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [port] });
      return { ok: true };
    },
    getMonitoringConfig: async () => ({ ok: true, config: CONFIG }),
    saveMonitoringConfig: async (c) => ({ ok: true, config: c }),
    startMonitoring: async () => ({ ok: true }),
    stopMonitoring: async () => ({ ok: true, clean: true, snapshot: null }),
    onMonitoringRuntimeExit: (l) => { exitListeners.push(l); return () => { exitListeners.splice(exitListeners.indexOf(l), 1); }; },
    onMonitoringStatus: (l) => { statusListeners.push(l); return () => { statusListeners.splice(statusListeners.indexOf(l), 1); }; },
    ...bridgeOver,
  };
  const client = new MonitoringClient({
    bridge, window: win, timers: clock,
    createWorker: () => { const w = new FakeWorker(); workers.push(w); return w; },
  });
  return {
    client, clock, win, workers, port, bridge, nonces, get portRequests() { return portRequests; },
    exit: (v: unknown) => { for (const l of [...exitListeners]) l(v); },
    status: (v: unknown) => { for (const l of [...statusListeners]) l(v); },
    listeners: () => exitListeners.length + statusListeners.length,
  };
}

const EXIT: RuntimeExit = { code: 1, wasRunning: true, message: 'monitoring stopped unexpectedly (exit 1)' };

test('client: connect takes the port from this window on the port channel and transfers ports[0] into the Worker', async () => {
  const r = clientRig();
  const result = await r.client.connect();
  assert.deepEqual(result, { ok: true, phase: 'live', watermark: 5 });
  assert.equal(r.workers.length, 1);
  const connect = r.workers[0].of('connect')[0];
  assert.equal(connect.message.port, r.port);
  assert.deepEqual(connect.transfer, [r.port]);
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(r.win.listeners.size, 0);
});

test('client: it ignores port messages from another source or channel, and takes the first one that is right', async () => {
  const r = clientRig({ sendPort: false });
  const stranger = { name: 'another-frame' };
  const first = { name: 'first' };
  const second = { name: 'second' };
  const done = r.client.connect();
  await flush();
  const nonce = r.nonces[0];
  r.win.post({ source: stranger, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [{ name: 'from-stranger' }] });
  r.win.post({ source: r.win, data: { channel: 'inwire:something-else', nonce }, ports: [{ name: 'wrong-channel' }] });
  r.win.post({ source: r.win, data: 'inwire:monitoring-port', ports: [{ name: 'not-an-object' }] });
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [] });
  await flush();
  assert.deepEqual(r.workers[0].posts, []);
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [first, second] });
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [{ name: 'late' }] });
  assert.equal((await done).ok, true);
  assert.equal(r.workers[0].of('connect').length, 1);
  assert.equal(r.workers[0].of('connect')[0].message.port, first);
  assert.deepEqual(r.workers[0].of('connect')[0].transfer, [first]);
});

test('client: each connect attempt asks with a fresh nonce', async () => {
  const r = clientRig();
  await r.client.connect();
  r.exit(EXIT);
  await r.client.connect();
  assert.equal(r.nonces.length, 2);
  assert.ok(r.nonces.every((n) => Number.isSafeInteger(n) && n > 0));
  assert.notEqual(r.nonces[0], r.nonces[1]);
});

test('client: a port carrying another nonce is closed and ignored, and the one with this attempt nonce is taken', async () => {
  const r = clientRig({ sendPort: false });
  const closed: string[] = [];
  const stale = { name: 'stale', close: () => { closed.push('stale'); } };
  const noNonce = { name: 'no-nonce', close: () => { closed.push('no-nonce'); } };
  const mine = { name: 'mine', close: () => { closed.push('mine'); } };
  const done = r.client.connect();
  await flush();
  const nonce = r.nonces[0];
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce: nonce + 1 }, ports: [stale] });
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE }, ports: [noNonce] });
  // A port with nothing to close is not an error.
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce: nonce + 2 }, ports: [{ name: 'unclosable' }] });
  await flush();
  assert.deepEqual(closed, ['stale', 'no-nonce']);
  assert.deepEqual(r.workers[0].posts, []);
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [mine] });
  assert.equal((await done).ok, true);
  assert.equal(r.workers[0].of('connect')[0].message.port, mine);
  assert.deepEqual(closed, ['stale', 'no-nonce']);
});

test('client: a reloaded page does not start its nonces where the last page did, so a port posted to the old one is not taken', async () => {
  const a = clientRig({ sendPort: false });
  const b = clientRig({ sendPort: false });
  void a.client.connect();
  void b.client.connect();
  await flush();
  const [na, nb] = [a.nonces[0], b.nonces[0]];
  assert.ok(Number.isSafeInteger(na) && na > 0 && Number.isSafeInteger(nb) && nb > 0, `${na} ${nb}`);
  assert.notEqual(na, nb);
  a.client.dispose();
  b.client.dispose();
});

test('client: main may take longer than the port wait to answer - the wait starts when it has', async () => {
  let answer!: () => void;
  const r = clientRig({
    sendPort: false,
    requestMonitoringPort: (nonce) => new Promise((resolve) => {
      answer = () => {
        r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [r.port] });
        resolve({ ok: true });
      };
    }),
  });
  const done = r.client.connect();
  await r.clock.advance(LIMITS.handshakeMs * 4);
  assert.equal(r.client.state.runtime, 'connecting');
  assert.equal(r.workers[0].terminated, 0);
  answer();
  const result = await done;
  assert.equal(result.ok, true);
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: the port wait is armed only once main has answered, and a port that never follows still times out', async () => {
  let answer!: () => void;
  const r = clientRig({ sendPort: false, requestMonitoringPort: () => new Promise((resolve) => { answer = () => resolve({ ok: true }); }) });
  const done = r.client.connect();
  await r.clock.advance(LIMITS.handshakeMs * 2);
  answer();
  await flush();
  await r.clock.advance(LIMITS.handshakeMs - 1);
  assert.equal(r.client.state.runtime, 'connecting');
  await r.clock.advance(1);
  const result = await done;
  assert.equal(result.ok, false);
  assert.match((result as { message: string }).message, /did not send a monitoring port/);
});

test('client: connect waits for the port and fails at the deadline when none comes', async () => {
  const r = clientRig({ sendPort: false });
  const done = r.client.connect();
  await flush();
  await r.clock.advance(LIMITS.handshakeMs - 1);
  assert.equal(r.client.state.runtime, 'connecting');
  await r.clock.advance(1);
  const result = await done;
  assert.equal(result.ok, false);
  assert.match((result as { message: string }).message, /did not send a monitoring port/);
  assert.equal(r.workers[0].terminated, 1);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.equal(r.win.listeners.size, 0);
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: a refusal from main fails connect at once with main\'s words and ends the Worker', async () => {
  const r = clientRig({ sendPort: false, requestMonitoringPort: async () => ({ ok: false, message: 'the journal is corrupt' }) });
  const result = await r.client.connect();
  assert.deepEqual(result, { ok: false, message: 'the journal is corrupt' });
  assert.equal(r.workers[0].terminated, 1);
  assert.equal(r.win.listeners.size, 0);
  assert.equal(r.client.state.problem, 'the journal is corrupt');
});

test('client: a rejected port request fails connect, a Worker that rejects the port does too', async () => {
  const a = clientRig({ sendPort: false, requestMonitoringPort: async () => { throw new Error('ipc closed'); } });
  const ra = await a.client.connect();
  assert.equal(ra.ok, false);
  assert.match((ra as { message: string }).message, /ipc closed/);
  const b = clientRig();
  b.client['deps'].createWorker = () => {
    const w = new FakeWorker();
    w.replies.connect = (m) => ({ type: 'connect-reply', requestId: m.requestId, ok: false, code: 'storage-failed', message: 'no dataset' });
    b.workers.push(w);
    return w;
  };
  const rb = await b.client.connect();
  assert.deepEqual(rb, { ok: false, message: 'no dataset' });
  assert.equal(b.workers[0].terminated, 1);
});

test('client: a bridge without monitoring is unavailable, and nothing is created', async () => {
  const r = clientRig({ requestMonitoringPort: undefined });
  const result = await r.client.connect();
  assert.equal(result.ok, false);
  assert.equal(r.workers.length, 0);
  assert.equal(r.client.state.runtime, 'unavailable');
});

test('client: a second connect while connecting shares the attempt, and while connected asks for nothing', async () => {
  const r = clientRig();
  const a = r.client.connect();
  const b = r.client.connect();
  assert.equal(a, b);
  await a;
  const c = await r.client.connect();
  assert.equal(c.ok, true);
  assert.equal(r.portRequests, 1);
  assert.equal(r.workers.length, 1);
});

test('client: a runtime exit fails every pending query, detail and connect, and terminates the Worker', async () => {
  const r = clientRig();
  await r.client.connect();
  const worker = r.workers[0];
  worker.replies.query = () => 'none';
  worker.replies.detail = () => 'none';
  const q1 = r.client.query('view-1', { kind: 'window' } as never);
  const q2 = r.client.query('view-2', { kind: 'window' } as never);
  const d = r.client.detail({ generation: 'g', throughEntryId: 1 } as never, { entryId: 1 } as never, 0);
  await flush();
  assert.equal(worker.of('query').length, 2);
  r.exit(EXIT);
  const [a, b, detail] = await Promise.all([q1, q2, d]);
  for (const reply of [a, b]) {
    assert.equal(reply.ok, false);
    assert.equal((reply as { code: string }).code, 'runtime-unavailable');
    assert.match((reply as { message: string }).message, /exit 1/);
  }
  assert.equal(detail, null);
  assert.equal(worker.terminated, 1);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.deepEqual(r.client.state.exit, EXIT);
  // With the Worker gone, new calls fail at once instead of waiting.
  assert.equal((await r.client.query('view-3', {} as never)).ok, false);
  assert.equal(await r.client.detail({} as never, {} as never, 0), null);
  assert.equal(worker.of('query').length, 2);
});

test('client: a runtime exit during connect settles that connect', async () => {
  const r = clientRig({ sendPort: false });
  const done = r.client.connect();
  await flush();
  r.exit(EXIT);
  const result = await done;
  assert.equal(result.ok, false);
  assert.match((result as { message: string }).message, /exit 1/);
  assert.equal(r.win.listeners.size, 0);
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: after an exit the next connect makes a new Worker and asks for a new port', async () => {
  const r = clientRig();
  await r.client.connect();
  r.exit(EXIT);
  assert.equal(r.client.state.runtime, 'unavailable');
  const result = await r.client.connect();
  assert.equal(result.ok, true);
  assert.equal(r.workers.length, 2);
  assert.equal(r.portRequests, 2);
  assert.equal(r.workers[1].of('connect').length, 1);
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(r.client.state.exit, null);
  // The old Worker's late messages reach nobody.
  r.workers[0].emit({ type: 'rebuild', phase: 'failed', fedThroughEntryId: 0, targetEntryId: 9 });
  assert.equal(r.client.state.rebuild?.phase, 'live');
});

test('client: a terminated Worker\'s late error does not overwrite the exit that ended it', async () => {
  const r = clientRig();
  await r.client.connect();
  r.exit(EXIT);
  r.workers[0].fail('late');
  assert.deepEqual(r.client.state.exit, EXIT);
  assert.equal(r.client.state.problem, EXIT.message);
});

test('client: an exit that is not an exit is ignored', async () => {
  const r = clientRig();
  await r.client.connect();
  r.exit({ code: 'one', wasRunning: true, message: 'x' });
  r.exit(null);
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(r.workers[0].terminated, 0);
});

test('client: a Worker error makes the runtime unavailable and fails what was pending', async () => {
  const r = clientRig();
  await r.client.connect();
  r.workers[0].replies.query = () => 'none';
  const q = r.client.query('v', {} as never);
  await flush();
  r.workers[0].fail('boom');
  const reply = await q;
  assert.equal(reply.ok, false);
  assert.match((reply as { message: string }).message, /boom/);
  assert.equal(r.workers[0].terminated, 1);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.equal((await r.client.connect()).ok, true);
  assert.equal(r.workers.length, 2);
});

test('client: queries and details are answered by the reply with their own id, and an error-reply fails only its own', async () => {
  const r = clientRig();
  await r.client.connect();
  const w = r.workers[0];
  w.replies.query = (m) => ({ type: 'query-reply', requestId: m.requestId, reply: { ok: true, marker: m.viewId } });
  w.replies.detail = (m) => (m.recordIndex === 1
    ? { type: 'error-reply', requestId: m.requestId, message: 'broke' }
    : { type: 'detail-reply', requestId: m.requestId, ok: true, evidence: { e: 1 }, record: { r: 1 } });
  const q = await r.client.query('view-7', {} as never);
  assert.equal(q.ok, true);
  assert.equal((q as unknown as { marker: string }).marker, 'view-7');
  assert.deepEqual(await r.client.detail({} as never, {} as never, 0), { evidence: { e: 1 }, record: { r: 1 } });
  assert.equal(await r.client.detail({} as never, {} as never, 1), null);
  // A reply of the wrong kind for its id is not taken as the answer.
  w.replies.query = (m) => ({ type: 'detail-reply', requestId: m.requestId, ok: true, evidence: {}, record: {} });
  let settled = false;
  void r.client.query('v', {} as never).then(() => { settled = true; });
  await flush();
  assert.equal(settled, false);
});

test('client: status is relayed through the reducer only when it validates', async () => {
  const r = clientRig();
  await r.client.connect();
  const seen: MonitoringState[] = [];
  r.client.subscribe((s) => seen.push(s));
  r.status({ listener: 'listening' });
  r.status(status({ received: 3 }));
  assert.equal(seen.length, 1);
  assert.equal(r.client.state.intake?.received, 3);
});

test('client: a Worker rebuild message moves the progress, and a malformed one does not', async () => {
  const r = clientRig();
  await r.client.connect();
  r.workers[0].emit({ type: 'rebuild', phase: 'rebuilding', fedThroughEntryId: 10, targetEntryId: 40 });
  assert.deepEqual(r.client.state.rebuild, { phase: 'rebuilding', fedThroughEntryId: 10, targetEntryId: 40, message: null });
  r.workers[0].emit({ type: 'rebuild', phase: 'bogus', fedThroughEntryId: 10, targetEntryId: 40 });
  r.workers[0].emit({ type: 'rebuild', phase: 'live', fedThroughEntryId: '10', targetEntryId: 40 });
  assert.equal(r.client.state.rebuild?.phase, 'rebuilding');
});

test('client: start and stop read what main answered, and an unreadable answer is a failure', async () => {
  const good = clientRig();
  assert.deepEqual(await good.client.start(CONFIG), { ok: true });
  assert.deepEqual(await good.client.stop(), { ok: true, clean: true, snapshot: null });
  const bad = clientRig({ startMonitoring: async () => 'fine', stopMonitoring: async () => ({ ok: true }) });
  assert.equal((await bad.client.start(CONFIG)).ok, false);
  const stopped = await bad.client.stop();
  assert.equal(stopped.ok, false);
  const thrown = clientRig({ startMonitoring: async () => { throw new Error('ipc closed'); }, stopMonitoring: async () => { throw new Error('ipc closed'); } });
  assert.match((await thrown.client.start(CONFIG) as { message: string }).message, /ipc closed/);
  assert.equal((await thrown.client.stop()).ok, false);
  const none = clientRig({ startMonitoring: undefined, stopMonitoring: undefined });
  assert.equal((await none.client.start(CONFIG)).ok, false);
  assert.equal((await none.client.stop()).ok, false);
});

test('client: the saved source is read and saved through main and validated on the way back', async () => {
  const r = clientRig();
  assert.deepEqual(await r.client.getConfig(), { ok: true, config: CONFIG });
  assert.deepEqual(await r.client.saveConfig(CONFIG), { ok: true, config: CONFIG });
  const empty = clientRig({ getMonitoringConfig: async () => ({ ok: true, config: null }) });
  assert.deepEqual(await empty.client.getConfig(), { ok: true, config: null });
  const refused = clientRig({ saveMonitoringConfig: async () => ({ ok: false, message: 'disk full' }) });
  assert.deepEqual(await refused.client.saveConfig(CONFIG), { ok: false, message: 'disk full' });
  const junk = clientRig({
    getMonitoringConfig: async () => ({ ok: true, config: { port: 1 } }),
    saveMonitoringConfig: async () => ({ ok: true, config: null }),
  });
  assert.equal((await junk.client.getConfig()).ok, false);
  assert.equal((await junk.client.saveConfig(CONFIG)).ok, false);
});

test('client: dispose unsubscribes from main, fails what is pending and ends the Worker', async () => {
  const r = clientRig();
  await r.client.connect();
  r.workers[0].replies.query = () => 'none';
  const q = r.client.query('v', {} as never);
  await flush();
  assert.equal(r.listeners(), 2);
  await r.client.dispose();
  assert.equal((await q).ok, false);
  assert.equal(r.workers[0].terminated, 1);
  assert.equal(r.listeners(), 0);
  assert.equal((await r.client.connect()).ok, false);
  assert.equal(r.workers.length, 1);
});

// --- the reducer ---------------------------------------------------------------------------------------------------

test('state: connecting, then connected, seeds the rebuild progress from the watermark', () => {
  const connecting = reduceMonitoring(initialMonitoringState, { type: 'connecting' });
  assert.equal(connecting.runtime, 'connecting');
  const connected = reduceMonitoring(connecting, { type: 'connected', phase: 'rebuilding', watermark: 12 });
  assert.equal(connected.runtime, 'connected');
  assert.deepEqual(connected.rebuild, { phase: 'rebuilding', fedThroughEntryId: 12, targetEntryId: 12, message: null });
});

test('state: a rebuild message is ignored before a connection and after the runtime is gone', () => {
  const progress = { phase: 'live' as const, fedThroughEntryId: 3, targetEntryId: 3, message: null };
  assert.equal(reduceMonitoring(initialMonitoringState, { type: 'rebuild', progress }), initialMonitoringState);
  const gone = reduceMonitoring(initialMonitoringState, { type: 'unavailable', message: 'x' });
  assert.equal(reduceMonitoring(gone, { type: 'rebuild', progress }), gone);
  const up = reduceMonitoring(reduceMonitoring(initialMonitoringState, { type: 'connecting' }), { type: 'connected', phase: 'idle', watermark: 0 });
  assert.deepEqual(reduceMonitoring(up, { type: 'rebuild', progress }).rebuild, progress);
});

test('state: an exit makes the runtime unavailable and a dead process is no longer listening', () => {
  let s = reduceMonitoring(initialMonitoringState, { type: 'connecting' });
  s = reduceMonitoring(s, { type: 'connected', phase: 'live', watermark: 4 });
  s = reduceMonitoring(s, { type: 'status', status: status() });
  assert.equal(s.intake?.listener, 'listening');
  s = reduceMonitoring(s, { type: 'exit', exit: EXIT });
  assert.equal(s.runtime, 'unavailable');
  assert.equal(s.rebuild, null);
  assert.equal(s.problem, EXIT.message);
  assert.deepEqual(s.exit, EXIT);
  assert.equal(s.intake?.listener, 'stopped');
  assert.equal(s.intake?.sessionId, null);
  assert.equal(s.intake?.workerAttached, false);
  assert.equal(s.intake?.received, 0);
});

test('state: after an exit a straggling status changes nothing, but a Worker-only failure still takes status', () => {
  const exited = reduceMonitoring(reduceMonitoring(initialMonitoringState, { type: 'status', status: status() }), { type: 'exit', exit: EXIT });
  assert.equal(reduceMonitoring(exited, { type: 'status', status: status({ received: 99 }) }), exited);
  const workerOnly = reduceMonitoring(reduceMonitoring(initialMonitoringState, { type: 'status', status: status() }), { type: 'unavailable', message: 'worker died' });
  const next = reduceMonitoring(workerOnly, { type: 'status', status: status({ received: 99 }) });
  assert.equal(next.intake?.received, 99);
  assert.equal(next.runtime, 'unavailable');
});

test('state: connecting again clears the problem and the exit, and reset returns to the start', () => {
  const exited = reduceMonitoring(initialMonitoringState, { type: 'exit', exit: EXIT });
  const again = reduceMonitoring(exited, { type: 'connecting' });
  assert.equal(again.runtime, 'connecting');
  assert.equal(again.problem, null);
  assert.equal(again.exit, null);
  assert.equal(reduceMonitoring(exited, { type: 'reset' }), initialMonitoringState);
});

test('state: an exit with no status yet leaves the intake empty rather than inventing one', () => {
  assert.equal(reduceMonitoring(initialMonitoringState, { type: 'exit', exit: EXIT }).intake, null);
});

// --- run ------------------------------------------------------------------------------------------------------------

async function main() {
  for (const { name, fn } of queue) {
    // A promise that never settles is the failure these tests exist to catch,
    // and left alone it ends the process silently with exit code 0.
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        Promise.resolve().then(fn),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('timed out after 5 s: a promise never settled')), 5000);
        }),
      ]);
      console.log(`PASS  ${name}`);
    } catch (e) {
      failures++;
      console.log(`FAIL  ${name}`);
      console.log(`        ${e instanceof Error ? e.message.split('\n').join('\n        ') : String(e)}`);
    } finally {
      clearTimeout(timer);
    }
  }
  console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}
void main();
