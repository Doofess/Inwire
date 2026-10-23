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
import { planQuitDrain } from '../../electron/monitoring/quitDrain';
import { readMonitoringSettings, saveMonitoringSettings, SETTINGS_FILE } from '../../electron/monitoring/settings';
import {
  MonitoringClient, MONITORING_PORT_MESSAGE, readHealthPush,
  type MonitoringBridge, type PortMessageEvent, type WorkerLike,
} from '../../src/services/monitoring/client';
import type { IntakeStatus, RuntimeExit, StartResult, StopResult } from '../../src/services/monitoring/control';
import { DEFAULT_RETENTION, type RetentionPolicy } from '../../src/services/monitoring/retention';
import {
  initialMonitoringState, nothingArriving, reduceMonitoring, type MonitoringState,
} from '../../src/services/monitoring/state';
import { initialSourceHealth, type ExporterSnapshot } from '../../src/services/monitoring/sourceHealth';
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
    received: 0, rejectedSenders: [], rejectedOverflow: 0, shedDatagrams: 0, snapshot: null, workerAttached: true,
    stopReason: null, datasetSource: null, ...over,
  };
}

// --- main's side ---------------------------------------------------------------------------------------------------

type Reply = unknown | 'none';

class FakeChild implements ChildLike {
  sent: { message: Record<string, unknown>; ports: unknown[] | undefined }[] = [];
  killed = 0;
  /** What each request type answers; `'none'` stays silent. */
  replies: Record<string, Reply> = {
    open: { ok: true }, inspect: { ok: true, kind: 'new', truncatedTailBytes: null, problem: null, exporterIPv4: null },
    discard: { ok: true, removedSegments: 2 },
    'discard-preview': { ok: true, scope: 'before', segments: 2, fromMs: 1_000, throughMs: null, cutMs: 5_000 },
    'retention-preview': { ok: true, segments: 0, fromMs: null, cutMs: null, cause: null },
    retention: { ok: true }, start: { ok: true }, stop: { ok: true, clean: true, snapshot: null }, dispose: { ok: true, clean: true, snapshot: null },
  };
  private messageListeners: ((m: unknown) => void)[] = [];
  private spawnListeners: (() => void)[] = [];
  private exitListeners: ((code: number | null) => void)[] = [];
  postMessage(message: unknown, ports?: unknown[]): void {
    const m = message as Record<string, unknown>;
    this.sent.push({ message: m, ports });
    const raw = this.replies[String(m.type)];
    const answer = typeof raw === 'function' ? (raw as (m: Record<string, unknown>) => unknown)(m) : raw;
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

function hostRig(saved: number | null = null, location: string | null = null, retention: RetentionPolicy = DEFAULT_RETENTION) {
  const clock = new Clock();
  const children: FakeChild[] = [];
  const channels: { port1: { name: string }; port2: { name: string } }[] = [];
  let limit = saved;
  const where = location;
  const policy = retention;
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
    settings: () => ({ limitBytes: limit, location: where, retention: policy }),
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

test('host: open carries the saved location (or the directory), whether it is the default, and the retention', async () => {
  const policy: RetentionPolicy = { keepRawDays: 14, atLimit: 'expire-oldest' };
  const moved = await connect(hostRig(null, 'D:\\evidence', policy), new FakeContents(1));
  const a = moved.of('open')[0].message;
  assert.equal(a.root, 'D:\\evidence');
  assert.equal(a.isDefaultLocation, false);
  assert.deepEqual(a.retention, policy);
  const plain = await connect(hostRig(), new FakeContents(1));
  const b = plain.of('open')[0].message;
  assert.equal(b.root, 'monitoring-dir');
  assert.equal(b.isDefaultLocation, true);
  assert.deepEqual(b.retention, DEFAULT_RETENTION);
});

// --- the host: location, discard and retention (ADR 0061) --------------------------------------------------------

const BUSY_TEXT = /Stop monitoring first/;

/** A connected, listening host: the child answers start and reports `listening`. */
async function listening(r: ReturnType<typeof hostRig>, contents = new FakeContents(1)): Promise<FakeChild> {
  const child = await connect(r, contents);
  assert.equal((await r.core.start(contents, CONFIG)).ok, true);
  child.emitMessage({ type: 'status', status: status() });
  assert.equal(r.core.isRunning(), true);
  return child;
}

test('host: discard, setRetention and relocate while running are busy and send nothing', async () => {
  const r = hostRig();
  const child = await listening(r);
  const before = child.sent.length;
  const discard = await r.core.discard({ scope: 'all' }, () => { throw new Error('asked while collecting'); });
  assert.equal(discard.ok, false);
  assert.equal((discard as { reason: string }).reason, 'busy');
  assert.match((discard as { message: string }).message, BUSY_TEXT);
  const retention = await r.core.setRetention({ keepRawDays: 7, atLimit: 'stop' });
  assert.equal((retention as { reason: string }).reason, 'busy');
  const relocate = await r.core.relocate('D:\\elsewhere', false);
  assert.equal(relocate.ok, false);
  assert.match((relocate as { message: string }).message, BUSY_TEXT);
  assert.equal(child.sent.length, before);
});

const YES = (): Promise<boolean> => Promise.resolve(true);

test('host: discard with no session launches, opens, previews, asks, then discards with an open-sized deadline', async () => {
  const r = hostRig(64 * 1024 * 1024);
  const done = r.core.discard({ scope: 'before', beforeMs: 1_000 }, YES);
  await flush();
  assert.equal(r.children.length, 1);
  assert.deepEqual(r.children[0].sent, []);
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: true, removedSegments: 2 });
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview', 'discard']);
  assert.deepEqual(r.children[0].of('discard-preview')[0].message.scope, { scope: 'before', beforeMs: 1_000 });
  assert.deepEqual(r.children[0].of('discard')[0].message.scope, { scope: 'before', beforeMs: 1_000 });
});

test('host: a declined confirmation answers cancelled and sends no discard', async () => {
  const r = hostRig();
  const asked: unknown[] = [];
  const done = r.core.discard({ scope: 'before', beforeMs: 9_000 }, (preview) => { asked.push(preview); return Promise.resolve(false); });
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: false, reason: 'cancelled', message: '' });
  assert.deepEqual(asked, [{ ok: true, scope: 'before', segments: 2, fromMs: 1_000, throughMs: null, cutMs: 5_000 }], 'the dialog is shown the utility\'s own preview');
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview']);
});

test('host: the confirmation comes after the preview and before the discard', async () => {
  const r = hostRig();
  let seenWhenAsked: string[] = [];
  const done = r.core.discard({ scope: 'all' }, () => { seenWhenAsked = r.children[0].types(); return Promise.resolve(true); });
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: true, removedSegments: 2 });
  assert.deepEqual(seenWhenAsked, ['open', 'discard-preview']);
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview', 'discard']);
});

test('host: a discard waits for the answer; it is not sent while the dialog is still open', async () => {
  const r = hostRig();
  let answer!: (v: boolean) => void;
  const done = r.core.discard({ scope: 'all' }, () => new Promise<boolean>((resolve) => { answer = resolve; }));
  r.children[0].emitSpawn();
  await flush();
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview']);
  answer(true);
  assert.deepEqual(await done, { ok: true, removedSegments: 2 });
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview', 'discard']);
});

test('host: a preview that says nothing would go neither asks nor discards', async () => {
  const r = hostRig();
  const done = r.core.discard({ scope: 'before', beforeMs: 1 }, () => { throw new Error('asked about nothing'); });
  r.children[0].replies['discard-preview'] = { ok: true, scope: 'before', segments: 0, fromMs: null, throughMs: null, cutMs: null };
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: true, removedSegments: 0 });
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview']);
});

test('host: no confirmation means no discard: refused, nothing forked or sent', async () => {
  const r = hostRig();
  const result = await r.core.discard({ scope: 'all' });
  assert.equal(result.ok, false);
  assert.equal((result as { reason: string }).reason, 'failed');
  assert.match((result as { message: string }).message, /needs a confirmation/);
  assert.equal(r.children.length, 0);
});

test('host: a preview the utility refuses is the discard\'s answer, and nothing is asked', async () => {
  const r = hostRig();
  const done = r.core.discard({ scope: 'before', beforeMs: 1 }, () => { throw new Error('asked about a refusal'); });
  r.children[0].replies['discard-preview'] = { ok: false, reason: 'failed', message: 'the monitoring dataset cannot be written' };
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: false, reason: 'failed', message: 'the monitoring dataset cannot be written' });
  assert.deepEqual(r.children[0].types(), ['open', 'discard-preview']);
  // An answer this build cannot read is a failed preview as well.
  const u = hostRig();
  const unreadable = u.core.discard({ scope: 'all' }, () => { throw new Error('asked'); });
  u.children[0].replies['discard-preview'] = { ok: 'maybe' };
  u.children[0].emitSpawn();
  assert.equal((await unreadable).ok, false);
  assert.deepEqual(u.children[0].types(), ['open', 'discard-preview']);
});

test('host: monitoring that starts while the dialog is open turns the accepted discard into busy', async () => {
  const r = hostRig();
  const contents = new FakeContents(1);
  const child = await connect(r, contents);
  const done = r.core.discard({ scope: 'all' }, async () => {
    assert.equal((await r.core.start(contents, CONFIG)).ok, true);
    child.emitMessage({ type: 'status', status: status() });
    return true;
  });
  const result = await done;
  assert.equal(result.ok, false);
  assert.equal((result as { reason: string }).reason, 'busy');
  assert.equal(child.of('discard').length, 0);
});

test('host: a discard the utility never answers fails at an open\'s deadline, not the ordinary one', async () => {
  const r = hostRig(64 * 1024 * 1024);
  const done = r.core.discard({ scope: 'all' }, YES);
  r.children[0].replies.discard = 'none';
  r.children[0].emitSpawn();
  await flush();
  const deadline = openDeadlineMs(64 * 1024 * 1024);
  assert.ok(deadline > LIMITS.requestMs);
  type Seen = { ok: boolean; reason?: string; message?: string } | null;
  let seen = null as Seen;
  const outcome = (): Seen => seen;
  void done.then((v) => { seen = v; });
  await r.clock.advance(deadline - 1);
  assert.equal(outcome(), null);
  await r.clock.advance(1);
  assert.equal(outcome()?.ok, false);
  assert.equal(outcome()?.reason, 'failed');
  assert.match(outcome()?.message ?? '', /did not answer/);
});

test('host: a discard that is not a scope is refused before anything is sent or forked', async () => {
  const r = hostRig();
  for (const bad of [{ scope: 'nope' }, undefined, null, 'all', { scope: 'before' }, { scope: 'before', beforeMs: -1 }]) {
    const result = await r.core.discard(bad);
    assert.equal(result.ok, false, JSON.stringify(bad));
    assert.match((result as { message: string }).message, /not a discard/);
  }
  assert.equal(r.children.length, 0);
});

test('host: inspect forks if needed, sends no open, and reads the reply', async () => {
  const r = hostRig();
  const done = r.core.inspect('D:\\found', false);
  await flush();
  assert.equal(r.children.length, 1);
  r.children[0].replies.inspect = { ok: true, kind: 'adopt', truncatedTailBytes: 12, problem: null, exporterIPv4: '192.0.2.10' };
  r.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: true, kind: 'adopt', truncatedTailBytes: 12, problem: null, exporterIPv4: '192.0.2.10' });
  assert.deepEqual(r.children[0].types(), ['inspect']);
  assert.equal(r.children[0].of('inspect')[0].message.root, 'D:\\found');
  assert.equal(r.children[0].of('inspect')[0].message.isDefaultLocation, false);
  // Garbage comes back as a stated failure, never as a success.
  r.children[0].replies.inspect = { ok: 'yes' };
  const bad = await r.core.inspect('D:\\found', false);
  assert.equal(bad.ok, false);
});

test('host: relocate with no session is ok and sends nothing; with one it asks open at the new root', async () => {
  const idle = hostRig();
  assert.deepEqual(await idle.core.relocate('D:\\elsewhere', false), { ok: true });
  assert.equal(idle.children.length, 0);
  const policy: RetentionPolicy = { keepRawDays: 3, atLimit: 'stop' };
  const r = hostRig(64 * 1024 * 1024, null, policy);
  const child = await connect(r, new FakeContents(1));
  assert.deepEqual(await r.core.relocate('D:\\elsewhere', false), { ok: true });
  const open = child.of('open')[1].message;
  assert.equal(open.root, 'D:\\elsewhere');
  assert.equal(open.isDefaultLocation, false);
  assert.equal(open.limitBytes, 64 * 1024 * 1024);
  assert.deepEqual(open.retention, policy);
});

test('host: setRetention with no session opens one first; with one it previews, then sends retention', async () => {
  const idle = hostRig();
  const done = idle.core.setRetention({ keepRawDays: 7, atLimit: 'stop' });
  await flush();
  assert.equal(idle.children.length, 1, 'a policy that may expire evidence is previewed, so there is a utility to ask');
  idle.children[0].emitSpawn();
  assert.deepEqual(await done, { ok: true });
  assert.deepEqual(idle.children[0].types(), ['open', 'retention-preview', 'retention']);
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  assert.deepEqual(await r.core.setRetention({ keepRawDays: 7, atLimit: 'expire-oldest' }), { ok: true });
  assert.deepEqual(child.of('retention-preview')[0].message.policy, { keepRawDays: 7, atLimit: 'expire-oldest' });
  assert.deepEqual(child.of('retention')[0].message.policy, { keepRawDays: 7, atLimit: 'expire-oldest' });
  child.replies.retention = { ok: false, reason: 'failed', message: 'disk said no' };
  const refused = await r.core.setRetention({ keepRawDays: 7, atLimit: 'stop' });
  assert.deepEqual(refused, { ok: false, reason: 'failed', message: 'disk said no' });
});

const DUE = { ok: true, segments: 3, fromMs: 1_000, cutMs: 5_000, cause: 'age' };
const POLICY: RetentionPolicy = { keepRawDays: 7, atLimit: 'stop' };

test('host: setRetention with segments due and no confirmation is refused, and sends no retention', async () => {
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  child.replies['retention-preview'] = DUE;
  const result = await r.core.setRetention(POLICY);
  assert.equal(result.ok, false);
  assert.equal((result as { reason: string }).reason, 'failed');
  assert.match((result as { message: string }).message, /needs a confirmation/);
  assert.equal(child.of('retention').length, 0);
});

test('host: a declined retention confirmation is cancelled, persists nothing and sends no retention', async () => {
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  child.replies['retention-preview'] = DUE;
  const asked: unknown[] = [];
  let applied = 0;
  const result = await r.core.setRetention(POLICY, (preview, policy) => { asked.push([preview, policy]); return Promise.resolve(false); }, () => { applied++; return null; });
  assert.deepEqual(result, { ok: false, reason: 'cancelled', message: '' });
  assert.deepEqual(asked, [[DUE, POLICY]], "the dialog is shown the utility's own preview and the candidate");
  assert.equal(child.of('retention').length, 0);
  assert.equal(applied, 0, 'nothing is persisted for a declined dialog');
});

test('host: an accepted retention confirmation persists, then sends retention, in that order', async () => {
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  child.replies['retention-preview'] = DUE;
  const order: string[] = [];
  const result = await r.core.setRetention(
    POLICY,
    () => { order.push(`ask after ${child.types().at(-1)}`); return YES(); },
    () => { order.push(`persist after ${child.types().at(-1)}`); return null; },
  );
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(order, ['ask after retention-preview', 'persist after retention-preview']);
  assert.deepEqual(child.of('retention')[0].message.policy, POLICY);
});

test('host: nothing due asks nothing, and a persist that fails refuses before retention is sent', async () => {
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  const result = await r.core.setRetention(POLICY, () => { throw new Error('asked about nothing'); });
  assert.deepEqual(result, { ok: true });
  const failed = await r.core.setRetention(POLICY, undefined, () => 'settings.json is read-only');
  assert.deepEqual(failed, { ok: false, reason: 'failed', message: 'settings.json is read-only' });
  assert.equal(child.of('retention').length, 1, 'only the first, unrefused save reached the utility');
});

test('host: a retention preview the utility refuses is the answer, and nothing is asked', async () => {
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  child.replies['retention-preview'] = { ok: false, reason: 'busy', message: 'm' };
  const result = await r.core.setRetention(POLICY, () => { throw new Error('asked about a refusal'); });
  assert.deepEqual(result, { ok: false, reason: 'busy', message: 'm' });
  assert.equal(child.of('retention').length, 0);
});

const DIFFERS = { ok: false, reason: 'source-differs', recordedExporter: '198.51.100.7', message: 'recorded from another exporter' };

/** A child that refuses a Start for a differing exporter until the message says the user agreed. */
function differing(child: FakeChild): void {
  child.replies.start = (m: Record<string, unknown>) => (m.sourceChangeConfirmed === true ? { ok: true } : DIFFERS);
}

test('host: a start refused for a differing exporter with no confirmation is the answer, and nothing second is sent', async () => {
  const r = hostRig();
  const contents = new FakeContents(1);
  const child = await connect(r, contents);
  differing(child);
  const result = await r.core.start(contents, CONFIG);
  assert.deepEqual(result, DIFFERS);
  assert.equal(child.of('start').length, 1);
  assert.equal(child.of('start')[0].message.sourceChangeConfirmed, false);
  assert.equal(r.core.isRunning(), false);
});

test('host: a declined start confirmation is cancelled and no second start is sent', async () => {
  const r = hostRig();
  const contents = new FakeContents(1);
  const child = await connect(r, contents);
  differing(child);
  const asked: unknown[] = [];
  const result = await r.core.start(contents, CONFIG, (recorded, configured) => { asked.push([recorded, configured]); return Promise.resolve(false); });
  assert.deepEqual(result, { ok: false, reason: 'cancelled', message: '' });
  assert.deepEqual(asked, [['198.51.100.7', CONFIG.exporterIPv4]]);
  assert.equal(child.of('start').length, 1);
  assert.equal(r.core.isRunning(), false);
});

test('host: an accepted start confirmation sends the second start with the flag, the dialog held outside startsOutstanding', async () => {
  const r = hostRig();
  const contents = new FakeContents(1);
  const child = await connect(r, contents);
  differing(child);
  let runningWhileAsked: boolean | null = null;
  const result = await r.core.start(contents, CONFIG, () => { runningWhileAsked = r.core.isRunning(); return YES(); });
  assert.deepEqual(result, { ok: true });
  assert.equal(runningWhileAsked, false, 'a dialog is not a listener starting: it holds no start outstanding');
  assert.deepEqual(child.of('start').map((s) => s.message.sourceChangeConfirmed), [false, true]);
  assert.equal(r.core.isRunning(), true);
});

test('host: a start whose window went away during the dialog is not sent again', async () => {
  const r = hostRig();
  const contents = new FakeContents(1);
  const child = await connect(r, contents);
  differing(child);
  const result = await r.core.start(contents, CONFIG, () => { contents.destroy(); return YES(); });
  assert.equal(result.ok, false);
  assert.equal(child.of('start').length, 1);
});

test('host: after quit, inspect, relocate, discard and setRetention are refused', async () => {
  const r = hostRig();
  r.core.release();
  assert.equal((await r.core.inspect('x', false)).ok, false);
  assert.equal((await r.core.relocate('x', false)).ok, false);
  assert.equal((await r.core.discard({ scope: 'all' })).ok, false);
  assert.equal((await r.core.setRetention({ keepRawDays: null, atLimit: 'stop' })).ok, false);
  assert.equal(r.children.length, 0);
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

// --- the host: reload ----------------------------------------------------------------------------------------------

test('host: a reload (a connect from new contents after the bound ones were destroyed) leaves a running listener running and binds the new page', async () => {
  const r = hostRig();
  const first = new FakeContents(1);
  const child = await connect(r, first);
  assert.equal((await r.core.start(first, CONFIG)).ok, true);
  assert.equal(r.core.isRunning(), true);
  first.destroy();
  const second = new FakeContents(2);
  await connect(r, second);
  assert.equal(r.children.length, 1, 'no new process');
  assert.deepEqual(child.of('stop'), [], 'nothing stopped the listener');
  assert.deepEqual(child.of('dispose'), []);
  assert.equal(child.killed, 0);
  assert.equal(r.core.isRunning(), true);
  assert.equal(first.sent(MONITORING_EXIT_CHANNEL).length, 0);
  assert.equal((await r.core.stop(second, 'user')).ok, true);
  assert.equal(child.of('stop').length, 1);
  assert.equal(r.core.isRunning(), false);
  assert.equal((await r.core.start(second, CONFIG)).ok, true, 'and the new page may start again');
});

// --- the host: quitting ------------------------------------------------------------------------------------------------

test('quit plan: drained quits; else draining waits; else running drains; else quits - all eight inputs', () => {
  const table: [boolean, boolean, boolean, 'quit' | 'drain' | 'wait'][] = [
    // running, draining, drained
    [false, false, false, 'quit'],
    [true, false, false, 'drain'],
    [false, true, false, 'wait'],
    [true, true, false, 'wait'],
    [false, false, true, 'quit'],
    [true, false, true, 'quit'],
    [false, true, true, 'quit'],
    [true, true, true, 'quit'],
  ];
  assert.equal(new Set(table.map(([a, b, c]) => `${a}${b}${c}`)).size, 8);
  for (const [running, draining, drained, expected] of table) {
    assert.equal(planQuitDrain({ running, draining, drained }), expected, JSON.stringify({ running, draining, drained }));
  }
});

test('host: isRunning follows a session that exists, has not ended and has a starting or listening listener', async () => {
  const r = hostRig();
  assert.equal(r.core.isRunning(), false);
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  assert.equal(r.core.isRunning(), false);
  await r.core.start(c1, CONFIG);
  assert.equal(r.core.isRunning(), true);
  child.emitMessage({ type: 'status', status: status({ listener: 'stopped' }) });
  assert.equal(r.core.isRunning(), false);
  child.emitMessage({ type: 'status', status: status({ listener: 'starting' }) });
  assert.equal(r.core.isRunning(), true);
  child.emitExit(1);
  assert.equal(r.core.isRunning(), false);
});

test('host: a Start still waiting for the utility counts as running, so a quit then drains rather than kills', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = 'none';
  let start = null as StartResult | null;
  void r.core.start(c1, CONFIG).then((v) => { start = v; });
  await flush();
  assert.equal(child.of('start').length, 1);
  assert.equal(r.core.isRunning(), true, 'no status has come back yet');
  assert.equal(planQuitDrain({ running: r.core.isRunning(), draining: false, drained: false }), 'drain');
  child.replies.dispose = { ok: true, clean: true, snapshot: null };
  const result = await r.core.drainForQuit();
  assert.equal(result.ok, true);
  assert.equal(child.of('dispose').length, 1, 'the utility was asked to stop, not just killed');
  assert.equal(child.killed, 1);
  await flush();
  assert.equal(start!.ok, false, 'and the waiting Start was settled');
});

test('host: a Start the utility refuses leaves isRunning false', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = { ok: false, message: 'the port is taken' };
  assert.equal((await r.core.start(c1, CONFIG)).ok, false);
  assert.equal(r.core.isRunning(), false);
});

test('host: release while stopped kills the child, sends nothing, announces no exit, and twice is fine', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  const before = child.sent.length;
  r.core.release();
  r.core.release();
  assert.equal(child.killed, 1);
  assert.equal(child.sent.length, before, 'nothing was sent');
  child.emitExit(0);
  await flush();
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  assert.equal(r.clock.pendingTimers, 0);
  assert.equal(r.core.isRunning(), false);
  // And with nothing ever connected it is a no-op.
  const empty = hostRig();
  empty.core.release();
  assert.equal(empty.children.length, 0);
});

test('host: release with a connect still waiting for the spawn ends it and kills the child', async () => {
  const r = hostRig();
  const done = r.core.connect(new FakeContents(1), 1).then(() => 'connected', (e: Error) => e.message);
  await flush();
  r.core.release();
  assert.match(await done, /shut down/);
  assert.equal(r.children[0].killed, 1);
  assert.deepEqual(r.children[0].sent, []);
  assert.equal(r.clock.pendingTimers, 0);
});

test('host: quit is final - after release a connect forks nothing, and start, stop and suspend are refused', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  r.core.release();
  const c2 = new FakeContents(2);
  await assert.rejects(r.core.connect(c2, 5), /the app is quitting/);
  assert.equal(r.children.length, 1);
  assert.deepEqual(c2.posts, []);
  assert.equal((await r.core.start(c1, CONFIG)).ok, false);
  assert.equal((await r.core.stop(c1, 'user')).ok, false);
  assert.equal((await r.core.suspend()).ok, false);
  assert.equal(child.of('start').length + child.of('stop').length, 0);
});

test('host: quit is final during a drain too - nothing connects, starts, stops or suspends while it is in flight', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.replies.dispose = 'none';
  const drain = r.core.drainForQuit();
  await flush();
  await assert.rejects(r.core.connect(new FakeContents(3), 7), /the app is quitting/);
  assert.equal((await r.core.start(c1, CONFIG)).ok, false);
  assert.equal((await r.core.stop(c1, 'user')).ok, false);
  assert.equal((await r.core.suspend()).ok, false);
  assert.equal(r.children.length, 1);
  assert.equal(child.of('stop').length, 0);
  await r.clock.advance(LIMITS.drainMs);
  await drain;
});

test('host: drainForQuit while running sends one dispose however many ask, kills the child, announces no exit, and a later call sends nothing', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  const a = r.core.drainForQuit();
  const b = r.core.drainForQuit();
  assert.equal(a, b, 'the same promise');
  const [ra, rb] = await Promise.all([a, b]);
  assert.deepEqual(ra, { ok: true, clean: true, snapshot: null });
  assert.equal(ra, rb);
  assert.equal(child.of('dispose').length, 1);
  assert.equal(child.killed, 1);
  const sent = child.sent.length;
  const c = await r.core.drainForQuit();
  assert.equal(c, ra, 'the settled result');
  assert.equal(child.sent.length, sent);
  child.emitExit(0);
  await flush();
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  assert.equal(r.clock.pendingTimers, 0);
  assert.equal(r.core.isRunning(), false);
});

test('host: drainForQuit with nothing connected answers clean without sending, and a never-spawned child is killed and not asked', async () => {
  assert.deepEqual(await hostRig().core.drainForQuit(), { ok: true, clean: true, snapshot: null });
  const never = hostRig();
  const pending = never.core.connect(new FakeContents(1), 1).catch(() => undefined);
  const result = await never.core.drainForQuit();
  await pending;
  assert.equal(result.ok, true);
  assert.equal(never.children[0].killed, 1);
  assert.deepEqual(never.children[0].sent, []);
});

test('host: drainForQuit relays an unclean answer from the utility as it is', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.replies.dispose = { ok: true, clean: false, snapshot: null };
  assert.deepEqual(await r.core.drainForQuit(), { ok: true, clean: false, snapshot: null });
  assert.equal(child.killed, 1);
});

test('host: a silent utility is waited for exactly LIMITS.drainMs - not a millisecond less, not drainMs plus the request deadline - and is then killed', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.replies.dispose = 'none';
  let result = null as StopResult | null;
  void r.core.drainForQuit().then((v) => { result = v; });
  await r.clock.advance(LIMITS.drainMs - 1);
  assert.equal(result, null);
  assert.equal(child.killed, 0);
  await r.clock.advance(1);
  assert.notEqual(result, null);
  assert.equal(result!.ok, false);
  assert.equal(result!.ok ? true : result!.clean, false);
  assert.equal(child.killed, 1);
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  assert.equal(r.clock.pendingTimers, 0);
});

test('host: a child that exits mid-drain resolves unclean and announces no exit', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.replies.dispose = 'none';
  const drain = r.core.drainForQuit();
  await flush();
  child.emitExit(9);
  const result = await drain;
  assert.equal(result.ok, false);
  assert.equal(result.ok ? true : result.clean, false);
  assert.equal(c1.sent(MONITORING_EXIT_CHANNEL).length, 0);
  assert.equal(r.clock.pendingTimers, 0);
});

test('host: a refused write to the child during the drain is unclean and still ends the session', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.postMessage = () => { throw new Error('channel closed'); };
  const result = await r.core.drainForQuit();
  assert.equal(result.ok, false);
  assert.match((result as { message: string }).message, /channel closed/);
  assert.equal(child.killed, 1);
});

// --- the host: suspend ---------------------------------------------------------------------------------------------------

test('host: suspend while running sends stop with reason suspend, and needs no bound window', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  c1.destroy();
  const result = await r.core.suspend();
  assert.deepEqual(result, { ok: true, clean: true, snapshot: null });
  assert.equal(child.of('stop').length, 1);
  assert.equal(child.of('stop')[0].message.reason, 'suspend');
  assert.equal(r.core.isRunning(), false);
  assert.equal(child.killed, 0, 'suspending is not quitting');
});

test('host: suspend while stopped, or with nothing connected, sends nothing and answers clean', async () => {
  const empty = hostRig();
  assert.deepEqual(await empty.core.suspend(), { ok: true, clean: true, snapshot: null });
  const r = hostRig();
  const child = await connect(r, new FakeContents(1));
  const sent = child.sent.length;
  assert.deepEqual(await r.core.suspend(), { ok: true, clean: true, snapshot: null });
  assert.equal(child.sent.length, sent);
});

test('host: suspend during a Start still unanswered sends stop, so the listener does not run through the sleep', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = 'none';
  void r.core.start(c1, CONFIG);
  await flush();
  assert.equal(r.core.isRunning(), true, 'no status has come back yet');
  await r.core.suspend();
  assert.equal(child.of('stop').length, 1);
  assert.equal(child.of('stop')[0].message.reason, 'suspend');
});

test('host: a suspend the utility never answers settles at the ordinary stop deadline', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  await r.core.start(c1, CONFIG);
  child.replies.stop = 'none';
  let result = null as StopResult | null;
  void r.core.suspend().then((v) => { result = v; });
  await r.clock.advance(LIMITS.drainMs + LIMITS.requestMs - 1);
  assert.equal(result, null);
  await r.clock.advance(1);
  assert.equal(result!.ok, false);
});

test('host: a pending start is settled as failed when the utility exits', async () => {
  const r = hostRig();
  const c1 = new FakeContents(1);
  const child = await connect(r, c1);
  child.replies.start = 'none';
  let start = null as StartResult | null;
  void r.core.start(c1, CONFIG).then((v) => { start = v; });
  await flush();
  child.emitExit(2);
  await flush();
  assert.equal(start!.ok, false);
  assert.match((start as unknown as { message: string }).message, /exit 2/);
});

// --- the saved source ---------------------------------------------------------------------------------------------

function tempDir(): string { return mkdtempSync(path.join(os.tmpdir(), 'inwire-monitoring-settings-')); }

test('settings: a missing file reads as no source, not as a failure', () => {
  const dir = tempDir();
  try {
    const none = { ok: true, config: null, location: null, retention: DEFAULT_RETENTION };
    assert.deepEqual(readMonitoringSettings(dir), none);
    assert.deepEqual(readMonitoringSettings(path.join(dir, 'never-created')), none);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a file that is not JSON, not an object or the wrong version is a stated failure', () => {
  const dir = tempDir();
  try {
    const file = path.join(dir, SETTINGS_FILE);
    for (const [text, pattern] of [
      ['{ not json', /not valid JSON/], ['[1]', /not a JSON object/], ['null', /not a JSON object/],
      [JSON.stringify({ version: 3, source: CONFIG }), /version 3/], [JSON.stringify({ source: CONFIG }), /version undefined/],
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
    const result = saveMonitoringSettings(dir, { ...CONFIG, bindIPv4: '0.0.0.0' }, {}, () => { writes++; });
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
    const result = saveMonitoringSettings(dir, { ...CONFIG, port: 9995 }, {}, () => { throw new Error('disk full'); });
    assert.equal(result.ok, false);
    assert.match((result as { message: string }).message, /could not be saved \(disk full\)/);
    assert.equal(readFileSync(path.join(dir, SETTINGS_FILE), 'utf8'), before);
    assert.deepEqual(readMonitoringSettings(dir), { ok: true, config: CONFIG, location: null, retention: DEFAULT_RETENTION });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a saved source reads back, in a directory that did not exist, with no partial left', () => {
  const dir = tempDir();
  try {
    const nested = path.join(dir, 'a', 'b');
    const saved = saveMonitoringSettings(nested, { ...CONFIG, extra: 'ignored' });
    const expected = { ok: true, config: CONFIG, location: null, retention: DEFAULT_RETENTION };
    assert.deepEqual(saved, expected);
    assert.deepEqual(readMonitoringSettings(nested), expected);
    assert.deepEqual(readdirSync(nested), [SETTINGS_FILE]);
    assert.deepEqual(JSON.parse(readFileSync(path.join(nested, SETTINGS_FILE), 'utf8')), { version: 2, source: CONFIG, location: null, retention: DEFAULT_RETENTION });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a version-1 file reads as the default location and policy, and a save rewrites it as version 2', () => {
  const dir = tempDir();
  try {
    writeFileSync(path.join(dir, SETTINGS_FILE), JSON.stringify({ version: 1, source: CONFIG }));
    assert.deepEqual(readMonitoringSettings(dir), { ok: true, config: CONFIG, location: null, retention: DEFAULT_RETENTION });
    assert.equal(saveMonitoringSettings(dir, undefined, { location: path.join(dir, 'elsewhere') }).ok, true);
    assert.equal(JSON.parse(readFileSync(path.join(dir, SETTINGS_FILE), 'utf8')).version, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a patch keeps the source and the other half of the patch', () => {
  const dir = tempDir();
  try {
    const place = path.join(dir, 'data');
    const policy: RetentionPolicy = { keepRawDays: 30, atLimit: 'stop' };
    assert.equal(saveMonitoringSettings(dir, CONFIG).ok, true);
    assert.deepEqual(saveMonitoringSettings(dir, undefined, { location: place }), { ok: true, config: CONFIG, location: place, retention: DEFAULT_RETENTION });
    assert.deepEqual(saveMonitoringSettings(dir, undefined, { retention: policy }), { ok: true, config: CONFIG, location: place, retention: policy });
    assert.deepEqual(readMonitoringSettings(dir), { ok: true, config: CONFIG, location: place, retention: policy });
    // null puts the location back to the default; a new source keeps the policy.
    assert.equal(saveMonitoringSettings(dir, undefined, { location: null }).ok, true);
    assert.deepEqual(saveMonitoringSettings(dir, { ...CONFIG, port: 9995 }), { ok: true, config: { ...CONFIG, port: 9995 }, location: null, retention: policy });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: a patch over an unreadable file is refused and writes nothing', () => {
  const dir = tempDir();
  try {
    writeFileSync(path.join(dir, SETTINGS_FILE), '{ not json');
    let writes = 0;
    const refused = saveMonitoringSettings(dir, undefined, { location: path.join(dir, 'x') }, () => { writes++; });
    assert.equal(refused.ok, false);
    assert.match((refused as { message: string }).message, /Nothing was saved over it/);
    assert.equal(writes, 0);
    assert.equal(readFileSync(path.join(dir, SETTINGS_FILE), 'utf8'), '{ not json');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('settings: an invalid retention policy or location is refused and writes nothing', () => {
  const dir = tempDir();
  try {
    let writes = 0;
    const write = (): void => { writes++; };
    for (const retention of [null, {}, { keepRawDays: 0, atLimit: 'stop' }, { keepRawDays: 1.5, atLimit: 'stop' }, { keepRawDays: null, atLimit: 'burn' }]) {
      const result = saveMonitoringSettings(dir, undefined, { retention }, write);
      assert.equal(result.ok, false, JSON.stringify(retention));
      assert.match((result as { message: string }).message, /retention policy/);
    }
    assert.equal(saveMonitoringSettings(dir, undefined, { location: '' }, write).ok, false);
    assert.equal(writes, 0);
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
  /** Like the real Worker, it answers a ping; a test sets this false to make it go silent. */
  answersPings = true;
  private message: ((e: { data: unknown }) => void)[] = [];
  private error: ((e: { message?: string }) => void)[] = [];
  /** Like the real Worker, it says `ready` once its script has loaded; `speaks = false` is a script that never does. */
  constructor(speaks = true) {
    if (speaks) queueMicrotask(() => this.emit({ type: 'ready' }));
  }
  postMessage(message: unknown, transfer?: unknown[]): void {
    const m = message as Record<string, unknown>;
    this.posts.push({ message: m, transfer });
    if (m.type === 'ping') {
      if (this.answersPings) queueMicrotask(() => this.emit({ type: 'pong' }));
      return;
    }
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

function clientRig(over: Partial<MonitoringBridge> & { sendPort?: boolean; workerSpeaks?: boolean } = {}) {
  const clock = new Clock();
  const win = new FakeWindow();
  const workers: FakeWorker[] = [];
  const port = { name: 'runtime-port' };
  const exitListeners: ((v: unknown) => void)[] = [];
  const statusListeners: ((v: unknown) => void)[] = [];
  let portRequests = 0;
  const nonces: number[] = [];
  const { sendPort = true, workerSpeaks = true, ...bridgeOver } = over;
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
    bridge, window: win, timers: clock, now: () => clock.now,
    createWorker: () => { const w = new FakeWorker(workerSpeaks); workers.push(w); return w; },
  });
  return {
    client, clock, win, workers, port, bridge, nonces, get portRequests() { return portRequests; },
    exit: (v: unknown) => { for (const l of [...exitListeners]) l(v); },
    status: (v: unknown) => { for (const l of [...statusListeners]) l(v); },
    listeners: () => exitListeners.length + statusListeners.length,
  };
}

const SILENT = /the monitoring Worker stopped answering/;

test('client: a Worker that goes silent is torn down within the request deadline plus a ping, every pending call settles, and a later connect works', async () => {
  const r = clientRig();
  await r.client.connect();
  const w = r.workers[0];
  w.answersPings = false;
  w.replies.query = () => 'none';
  w.replies.detail = () => 'none';
  const query = r.client.query('v', { kind: 'raw' } as never);
  const detail = r.client.detail({} as never, {} as never, 0);
  await flush();
  assert.equal(r.client.state.runtime, 'connected');
  // The last sign of life was the connect-reply at t=0; the deadline is requestMs from it, noticed at most one tick later.
  await r.clock.advance(LIMITS.requestMs - 1);
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(w.terminated, 0);
  await r.clock.advance(1);
  const reply = await query;
  assert.equal(reply.ok, false);
  assert.match((reply as { message: string }).message, SILENT);
  assert.equal(await detail, null);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.match(String(r.client.state.problem), SILENT);
  assert.equal(w.terminated, 1);
  assert.ok(w.of('ping').length >= 2, 'it kept pinging while it waited');
  assert.equal(r.clock.pendingTimers, 0);
  // Recovery is the ordinary one: a new Worker, a new port.
  const again = await r.client.connect();
  assert.equal(again.ok, true);
  assert.equal(r.workers.length, 2);
  r.client.dispose();
});

test('client: a Worker that answers pings is never torn down, however long a query takes', async () => {
  const r = clientRig();
  await r.client.connect();
  const w = r.workers[0];
  w.replies.query = () => 'none';
  const query = r.client.query('v', { kind: 'raw' } as never);
  await r.clock.advance(LIMITS.requestMs * 10);
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(w.terminated, 0);
  assert.ok(w.of('ping').length >= (LIMITS.requestMs * 10) / 5_000 - 1);
  w.emit({ type: 'query-reply', requestId: w.of('query')[0].message.requestId, reply: { ok: false, code: 'cancelled', message: 'late' } });
  await query;
  r.client.dispose();
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: any message from the Worker counts as a sign of life, not only a pong', async () => {
  const r = clientRig();
  await r.client.connect();
  const w = r.workers[0];
  w.answersPings = false;
  for (let i = 0; i < 4; i++) {
    await r.clock.advance(LIMITS.requestMs - 1);
    w.emit({ type: 'rebuild', phase: 'rebuilding', fedThroughEntryId: i, targetEntryId: 10 });
  }
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(w.terminated, 0);
  r.client.dispose();
});

test('client: the heartbeat stops with the Worker - on an error, an exit and a dispose', async () => {
  for (const end of ['error', 'exit', 'dispose'] as const) {
    const r = clientRig();
    await r.client.connect();
    if (end === 'error') r.workers[0].fail('boom'); else if (end === 'exit') r.exit(EXIT); else await r.client.dispose();
    assert.equal(r.clock.pendingTimers, 0, end);
    const pings = r.workers[0].of('ping').length;
    await r.clock.advance(LIMITS.requestMs * 3);
    assert.equal(r.workers[0].of('ping').length, pings, end);
  }
});

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
  await flush(); // the Worker's script loads and says ready, as a real one does before anything else happens
  await r.clock.advance(LIMITS.handshakeMs * 4);
  assert.equal(r.client.state.runtime, 'connecting');
  assert.equal(r.workers[0].terminated, 0);
  answer();
  const result = await done;
  assert.equal(result.ok, true);
  // The port wait left nothing behind: the two that remain are the connected Worker's heartbeat (ping and silence).
  assert.equal(r.clock.pendingTimers, 2);
  await r.client.dispose();
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: a Worker that never says it started is torn down at the load deadline, not the request deadline', async () => {
  const r = clientRig({ sendPort: false, workerSpeaks: false, requestMonitoringPort: () => new Promise(() => undefined) });
  void r.client.connect();
  await flush();
  // Past the 15 s a running Worker is held to: a cold script load on a busy machine is not a fault.
  await r.clock.advance(LIMITS.requestMs * 4 - 1);
  assert.equal(r.client.state.runtime, 'connecting');
  assert.equal(r.workers[0].terminated, 0);
  await r.clock.advance(1);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.match(String(r.client.state.problem), /the monitoring Worker did not start/);
  assert.equal(r.workers[0].terminated, 1);
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: a slow load under the deadline survives, and the request window starts at the first message', async () => {
  const r = clientRig({ sendPort: false, workerSpeaks: false, requestMonitoringPort: () => new Promise(() => undefined) });
  void r.client.connect();
  await flush();
  await r.clock.advance(40_000);
  assert.equal(r.client.state.runtime, 'connecting');
  const w = r.workers[0];
  w.answersPings = false;
  w.emit({ type: 'ready' });
  await flush();
  // The 15 s window starts now, not at the connect: 14 999 ms after `ready` it is still waited for.
  await r.clock.advance(LIMITS.requestMs - 1);
  assert.equal(r.client.state.runtime, 'connecting');
  assert.equal(w.terminated, 0);
  await r.clock.advance(1);
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.match(String(r.client.state.problem), SILENT);
  assert.equal(w.terminated, 1);
});

test('client: a port that arrives after the client was disposed is closed, not left for a Worker that is gone', async () => {
  let nonce = -1;
  const r = clientRig({ sendPort: false, requestMonitoringPort: async (n) => { nonce = n; return { ok: true }; } });
  const closed: string[] = [];
  const late = { name: 'late', close: () => { closed.push('late'); } };
  const done = r.client.connect();
  await flush();
  r.win.post({ source: r.win, data: { channel: MONITORING_PORT_MESSAGE, nonce }, ports: [late] });
  // Disposed in the same turn the port arrived: the attempt resumes into a client with no Worker.
  const disposed = r.client.dispose();
  const result = await done;
  await disposed;
  assert.equal(result.ok, false);
  assert.deepEqual(closed, ['late']);
  assert.equal(r.workers[0].of('connect').length, 0, 'the port was not handed to a Worker that was terminated');
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
  assert.deepEqual(await r.client.getConfig(), { ok: true, config: CONFIG, location: null, retention: DEFAULT_RETENTION });
  assert.deepEqual(await r.client.saveConfig(CONFIG), { ok: true, config: CONFIG });
  const empty = clientRig({ getMonitoringConfig: async () => ({ ok: true, config: null }) });
  assert.deepEqual(await empty.client.getConfig(), { ok: true, config: null, location: null, retention: DEFAULT_RETENTION });
  const refused = clientRig({ saveMonitoringConfig: async () => ({ ok: false, message: 'disk full' }) });
  assert.deepEqual(await refused.client.saveConfig(CONFIG), { ok: false, message: 'disk full' });
  const junk = clientRig({
    getMonitoringConfig: async () => ({ ok: true, config: { port: 1 } }),
    saveMonitoringConfig: async () => ({ ok: true, config: null }),
  });
  assert.equal((await junk.client.getConfig()).ok, false);
  assert.equal((await junk.client.saveConfig(CONFIG)).ok, false);
});

test('client: the config reply carries the location and the retention, read strictly', async () => {
  const policy: RetentionPolicy = { keepRawDays: 30, atLimit: 'stop' };
  const full = clientRig({ getMonitoringConfig: async () => ({ ok: true, config: CONFIG, location: 'D:\\Inwire Monitoring', retention: policy }) });
  assert.deepEqual(await full.client.getConfig(), { ok: true, config: CONFIG, location: 'D:\\Inwire Monitoring', retention: policy });
  const nulled = clientRig({ getMonitoringConfig: async () => ({ ok: true, config: CONFIG, location: null }) });
  assert.deepEqual(await nulled.client.getConfig(), { ok: true, config: CONFIG, location: null, retention: DEFAULT_RETENTION });
  const copy = (await clientRig({ getMonitoringConfig: async () => ({ ok: true, config: null }) }).client.getConfig()) as { retention: RetentionPolicy };
  assert.notEqual(copy.retention, DEFAULT_RETENTION, 'a copy, never the shared default');
  for (const bad of [{ location: 5 }, { location: {} }, { retention: { keepRawDays: 0, atLimit: 'stop' } }, { retention: 'x' }, { retention: null }]) {
    const r = clientRig({ getMonitoringConfig: async () => ({ ok: true, config: CONFIG, ...bad }) });
    assert.equal((await r.client.getConfig()).ok, false, JSON.stringify(bad));
  }
});

test('client: location, discard and retention go through main unchanged and read what it answers', async () => {
  const seen: unknown[] = [];
  const inspect = { ok: true, kind: 'new', truncatedTailBytes: null, problem: null, exporterIPv4: null };
  const policy: RetentionPolicy = { keepRawDays: 7, atLimit: 'expire-oldest' };
  const r = clientRig({
    chooseMonitoringLocation: async (i) => { seen.push(i); return { ok: true, displayPath: 'D:\\x', isDefaultLocation: false, inspect }; },
    discardMonitoring: async (s) => { seen.push(s); return { ok: true, removedSegments: 3 }; },
    saveMonitoringRetention: async (p) => { seen.push(p); return { ok: true, retention: policy }; },
  });
  assert.deepEqual(await r.client.chooseLocation('pick'), { ok: true, displayPath: 'D:\\x', isDefaultLocation: false, inspect });
  assert.deepEqual(await r.client.discard({ scope: 'before', beforeMs: 9 }), { ok: true, removedSegments: 3 });
  assert.deepEqual(await r.client.saveRetention(policy), { ok: true, retention: policy });
  assert.deepEqual(seen, ['pick', { scope: 'before', beforeMs: 9 }, policy]);
  const none = clientRig();
  const unavailable = 'monitoring is not available in this build';
  assert.deepEqual(await none.client.chooseLocation('default'), { ok: false, reason: 'failed', message: unavailable });
  assert.deepEqual(await none.client.discard({ scope: 'all' }), { ok: false, reason: 'failed', message: unavailable });
  assert.deepEqual(await none.client.saveRetention(policy), { ok: false, reason: 'failed', message: unavailable });
  const boom = async (): Promise<never> => { throw new Error('ipc closed'); };
  const thrown = clientRig({ chooseMonitoringLocation: boom, discardMonitoring: boom, saveMonitoringRetention: boom });
  assert.deepEqual(await thrown.client.chooseLocation('pick'), { ok: false, reason: 'failed', message: 'The location could not be changed (ipc closed)' });
  assert.deepEqual(await thrown.client.discard({ scope: 'all' }), { ok: false, reason: 'failed', message: 'The data could not be discarded (ipc closed)' });
  assert.deepEqual(await thrown.client.saveRetention(policy), { ok: false, reason: 'failed', message: 'The retention policy could not be saved (ipc closed)' });
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

// --- the client: every call settles ---------------------------------------------------------------------------------
// (Task 5 already covers a pending query, detail and connect on a runtime exit, and a pending query on a Worker
// error. start and stop are not the Worker's: they go to main, which fails them itself on an exit - the host tests
// above - so here they are driven by a bridge that answers the way main does, and the client must pass it on.)

/** A bridge whose start and stop stay out until the test lets them go, as main's do until the utility answers or dies. */
function heldControl() {
  const held: { start: ((v: unknown) => void)[]; stop: ((v: unknown) => void)[] } = { start: [], stop: [] };
  const bridge: Partial<MonitoringBridge> = {
    startMonitoring: () => new Promise((resolve) => { held.start.push(resolve); }),
    stopMonitoring: () => new Promise((resolve) => { held.stop.push(resolve); }),
  };
  return { bridge, held };
}

// A pending start or stop on a runtime exit is settled by main, not by the client: 'a pending start is settled as failed
// when the utility exits' and 'a utility exit settles every pending request', in the host section above, pin it.
test('client: on a runtime exit a pending query and detail settle, as failures', async () => {
  const r = clientRig(heldControl().bridge);
  await r.client.connect();
  r.workers[0].replies.query = () => 'none';
  r.workers[0].replies.detail = () => 'none';
  const q = r.client.query('v', {} as never);
  const d = r.client.detail({} as never, {} as never, 0);
  await flush();
  r.exit(EXIT);
  const [qr, dr] = await Promise.all([q, d]);
  assert.equal(qr.ok, false);
  assert.equal((qr as { code: string }).code, 'runtime-unavailable');
  assert.equal(dr, null);
});

test('client: on a Worker error a pending query and detail settle as failures and control is untouched', async () => {
  const control = heldControl();
  const r = clientRig(control.bridge);
  await r.client.connect();
  r.workers[0].replies.query = () => 'none';
  r.workers[0].replies.detail = () => 'none';
  const q = r.client.query('v', {} as never);
  const d = r.client.detail({} as never, {} as never, 0);
  const start = r.client.start(CONFIG);
  const stop = r.client.stop();
  await flush();
  r.workers[0].fail('boom');
  const [qr, dr] = await Promise.all([q, d]);
  assert.equal(qr.ok, false);
  assert.equal((qr as { code: string }).code, 'runtime-unavailable');
  assert.match((qr as { message: string }).message, /boom/);
  assert.equal(dr, null);
  // The Worker is the history's, not control's: main's answers still reach the caller.
  control.held.start[0]({ ok: true });
  control.held.stop[0]({ ok: true, clean: true, snapshot: null });
  assert.deepEqual(await start, { ok: true });
  assert.deepEqual(await stop, { ok: true, clean: true, snapshot: null });
});

test('client: after a connect that fails, queries and details answer at once and start and stop still reach main', async () => {
  const calls: string[] = [];
  const r = clientRig({
    requestMonitoringPort: async () => ({ ok: false, message: 'the dataset is corrupt' }),
    startMonitoring: async () => { calls.push('start'); return { ok: false, message: 'not connected' }; },
    stopMonitoring: async () => { calls.push('stop'); return { ok: false, message: 'not connected', clean: false, snapshot: null }; },
  });
  const connected = await r.client.connect();
  assert.equal(connected.ok, false);
  const q = await r.client.query('v', {} as never);
  assert.equal(q.ok, false);
  assert.equal((q as { code: string }).code, 'runtime-unavailable');
  assert.equal(await r.client.detail({} as never, {} as never, 0), null);
  assert.equal((await r.client.start(CONFIG)).ok, false);
  assert.equal((await r.client.stop()).ok, false);
  assert.deepEqual(calls, ['start', 'stop']);
  assert.equal(r.clock.pendingTimers, 0);
});

test('client: dispose (an unmounted sheet) never calls stopMonitoring - collection goes on without a window', async () => {
  let stops = 0;
  let starts = 0;
  const r = clientRig({
    stopMonitoring: async () => { stops++; return { ok: true, clean: true, snapshot: null }; },
    startMonitoring: async () => { starts++; return { ok: true }; },
  });
  await r.client.connect();
  await r.client.start(CONFIG);
  await r.client.dispose();
  await r.client.dispose();
  assert.equal(stops, 0);
  assert.equal(starts, 1);
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

test('state: an exit keeps why the listener stopped', () => {
  let s = reduceMonitoring(initialMonitoringState, { type: 'connecting' });
  s = reduceMonitoring(s, { type: 'connected', phase: 'live', watermark: 4 });
  s = reduceMonitoring(s, { type: 'status', atMs: 0, status: status({ listener: 'stopped', stopReason: 'suspend' }) });
  assert.equal(s.intake?.stopReason, 'suspend');
  s = reduceMonitoring(s, { type: 'exit', exit: EXIT });
  assert.equal(s.intake?.stopReason, 'suspend');
});

test('state: an exit makes the runtime unavailable and a dead process is no longer listening', () => {
  let s = reduceMonitoring(initialMonitoringState, { type: 'connecting' });
  s = reduceMonitoring(s, { type: 'connected', phase: 'live', watermark: 4 });
  s = reduceMonitoring(s, { type: 'status', atMs: 0, status: status() });
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
  const exited = reduceMonitoring(reduceMonitoring(initialMonitoringState, { type: 'status', atMs: 0, status: status() }), { type: 'exit', exit: EXIT });
  assert.equal(reduceMonitoring(exited, { type: 'status', atMs: 0, status: status({ received: 99 }) }), exited);
  const workerOnly = reduceMonitoring(reduceMonitoring(initialMonitoringState, { type: 'status', atMs: 0, status: status() }), { type: 'unavailable', message: 'worker died' });
  const next = reduceMonitoring(workerOnly, { type: 'status', atMs: 0, status: status({ received: 99 }) });
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

// --- health, sources and the time listening began (Task 7B) ------------------------------------------------------

const HEALTH = initialSourceHealth('192.0.2.1');
const SNAPSHOT: ExporterSnapshot = {
  sourceKey: 'v9:192.0.2.1/1', protocol: 'v9', templates: [], sampling: { kind: 'absent' },
  clock: { latestSkewMs: 40, minSkewMs: 40, maxSkewMs: 40, flagged: false }, sequence: { mode: 'learning', suspectedGap: 0, reordered: 0 },
};
const connectedState = (): MonitoringState => reduceMonitoring(
  reduceMonitoring(initialMonitoringState, { type: 'connecting' }), { type: 'connected', phase: 'live', watermark: 1 },
);

test('state: a health push is folded with its sources once the runtime is up, and not before or after', () => {
  const push = { type: 'health' as const, health: HEALTH, sources: ['192.0.2.1/0/0'], exporters: [SNAPSHOT] };
  assert.equal(reduceMonitoring(initialMonitoringState, push), initialMonitoringState);
  const up = reduceMonitoring(connectedState(), push);
  assert.equal(up.health, HEALTH);
  assert.deepEqual(up.sources, ['192.0.2.1/0/0']);
  assert.deepEqual(up.exporters, [SNAPSHOT]);
  const gone = reduceMonitoring(up, { type: 'unavailable', message: 'worker died' });
  assert.equal(gone.health, null);
  assert.deepEqual(gone.sources, []);
  assert.deepEqual(gone.exporters, []);
  assert.equal(reduceMonitoring(gone, push), gone);
});

test('state: health and sources are cleared by an exit, by connecting again and by reset', () => {
  const up = reduceMonitoring(connectedState(), { type: 'health', health: HEALTH, sources: ['a'], exporters: [SNAPSHOT] });
  for (const event of [{ type: 'exit' as const, exit: EXIT }, { type: 'connecting' as const }, { type: 'reset' as const }]) {
    const s = reduceMonitoring(up, event);
    assert.equal(s.health, null, event.type);
    assert.deepEqual(s.sources, [], event.type);
    assert.deepEqual(s.exporters, [], event.type);
  }
});

test('client: a health push carries the exporter snapshots, tolerates a Worker that sends none, and drops a malformed one', () => {
  const health = { ...HEALTH };
  const read = readHealthPush({ type: 'health', health, sources: ['v9:192.0.2.1/1'], exporters: [SNAPSHOT] });
  assert.ok(read !== null);
  assert.deepEqual(read.exporters, [SNAPSHOT]);
  assert.deepEqual(read.health?.templateSources, []);
  assert.deepEqual(readHealthPush({ type: 'health', health: null, sources: [] })?.exporters, [], 'none sent is none');
  assert.equal(readHealthPush({ type: 'health', health: null, sources: [], exporters: [{ sourceKey: 1 }] }), null);
  assert.equal(readHealthPush({ type: 'health', health: null, sources: [], exporters: 'x' }), null);
});

test('state: listeningSinceMs is set at the first listening status, kept while it stays, and cleared otherwise', () => {
  let s = connectedState();
  assert.equal(s.listeningSinceMs, null);
  s = reduceMonitoring(s, { type: 'status', atMs: 1000, status: status({ listener: 'starting' }) });
  assert.equal(s.listeningSinceMs, null);
  s = reduceMonitoring(s, { type: 'status', atMs: 2000, status: status() });
  assert.equal(s.listeningSinceMs, 2000);
  s = reduceMonitoring(s, { type: 'status', atMs: 9000, status: status({ received: 4 }) });
  assert.equal(s.listeningSinceMs, 2000, 'a later status while listening does not restart the wait');
  s = reduceMonitoring(s, { type: 'status', atMs: 10_000, status: status({ listener: 'stopped' }) });
  assert.equal(s.listeningSinceMs, null);
  s = reduceMonitoring(s, { type: 'status', atMs: 11_000, status: status() });
  assert.equal(s.listeningSinceMs, 11_000);
  assert.equal(reduceMonitoring(s, { type: 'status', atMs: 12_000, status: status({ listener: 'failed', listenerError: 'bind' }) }).listeningSinceMs, null);
  assert.equal(reduceMonitoring(s, { type: 'exit', exit: EXIT }).listeningSinceMs, null);
  assert.equal(reduceMonitoring(s, { type: 'reset' }).listeningSinceMs, null);
});

test('nothingArriving: false before staleMs of listening, true at it, and false once anything has arrived', () => {
  const since = 5000;
  const s = reduceMonitoring(connectedState(), { type: 'status', atMs: since, status: status() });
  assert.equal(nothingArriving(s, since + LIMITS.staleMs - 100), false, '59.9 s');
  assert.equal(nothingArriving(s, since + LIMITS.staleMs), true, '60 s');
  const arrived = reduceMonitoring(s, { type: 'status', atMs: since + 30_000, status: status({ received: 1 }) });
  assert.equal(nothingArriving(arrived, since + LIMITS.staleMs + 1), false, 'after a datagram');
  const stopped = reduceMonitoring(s, { type: 'status', atMs: since + 1, status: status({ listener: 'stopped' }) });
  assert.equal(nothingArriving(stopped, since + LIMITS.staleMs * 2), false, 'not listening');
  assert.equal(nothingArriving(initialMonitoringState, 1e12), false, 'no status at all');
});

test('client: a status is stamped with the injected clock, and a later one keeps the first listening time', async () => {
  const r = clientRig();
  r.clock.now = 5000;
  r.status(status());
  assert.equal(r.client.state.listeningSinceMs, 5000);
  r.clock.now = 9000;
  r.status(status({ received: 2 }));
  assert.equal(r.client.state.listeningSinceMs, 5000);
  r.status(status({ listener: 'stopped' }));
  assert.equal(r.client.state.listeningSinceMs, null);
});

test('client: the Worker\'s health push lands in the state, a malformed one is ignored, and the state is stable between changes', async () => {
  const r = clientRig();
  await r.client.connect();
  const seen: MonitoringState[] = [];
  r.client.subscribe((s) => seen.push(s));
  const before = r.client.state;
  r.workers[0].emit({ type: 'health', health: HEALTH, sources: ['192.0.2.1/0/0'] });
  assert.equal(r.client.state.health, HEALTH);
  assert.deepEqual(r.client.state.sources, ['192.0.2.1/0/0']);
  assert.notEqual(r.client.state, before);
  const after = r.client.state;
  assert.equal(r.client.state, after, 'the same reference until something changes');
  for (const bad of [
    { type: 'health', health: 'x', sources: [] },
    { type: 'health', health: HEALTH, sources: 'x' },
    { type: 'health', health: HEALTH, sources: [1] },
    { type: 'health', health: { exporterIPv4: 1 }, sources: [] },
    { type: 'health', sources: [] },
  ]) r.workers[0].emit(bad);
  assert.equal(r.client.state, after);
  assert.equal(seen.length, 1);
  r.workers[0].emit({ type: 'health', health: null, sources: [] });
  assert.equal(r.client.state.health, null);
});

test('client: the listener shown is the status main relayed, never inferred from Start\'s answer (m10)', async () => {
  const r = clientRig({ startMonitoring: async () => ({ ok: false, message: 'Start did not finish in time' }) });
  await r.client.connect();
  r.status(status({ listener: 'starting' }));
  const started = await r.client.start(CONFIG);
  assert.equal(started.ok, false);
  assert.equal(r.client.state.intake?.listener, 'starting', 'a refused or late Start changes nothing');
  r.status(status());
  assert.equal(r.client.state.intake?.listener, 'listening');
  const ok = clientRig();
  await ok.client.connect();
  await ok.client.start(CONFIG);
  assert.equal(ok.client.state.intake, null, 'and a successful Start does not invent one');
});

test('client: ensureConnected is single-flight, answers from the state when connected, and connects again after an exit', async () => {
  const r = clientRig();
  const [a, b] = [r.client.ensureConnected(), r.client.ensureConnected()];
  assert.equal(a, b, 'the same promise while one is in flight');
  assert.deepEqual(await a, { ok: true, phase: 'live', watermark: 5 });
  assert.equal(r.workers.length, 1);
  assert.equal(r.portRequests, 1);
  await r.client.ensureConnected();
  assert.equal(r.workers.length, 1, 'connected: nothing new');
  r.exit(EXIT);
  assert.equal(r.client.state.runtime, 'unavailable');
  const again = await r.client.ensureConnected();
  assert.equal(again.ok, true);
  assert.equal(r.workers.length, 2, 'a dead runtime is replaced');
  assert.equal(r.client.state.runtime, 'connected');
  assert.equal(r.client.state.exit, null);
});

test('client: ensureConnected connects again after the Worker alone failed', async () => {
  const r = clientRig();
  await r.client.ensureConnected();
  r.workers[0].fail('boom');
  assert.equal(r.client.state.runtime, 'unavailable');
  assert.equal(r.client.state.health, null);
  await r.client.ensureConnected();
  assert.equal(r.workers.length, 2);
  assert.equal(r.client.state.runtime, 'connected');
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
