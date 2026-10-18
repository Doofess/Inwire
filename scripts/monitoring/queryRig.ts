/**
 * The shared rig for `rollup.ts` and `queries.ts`: a journal, a sidecar and a
 * runtime in memory, a `MonitoringWorkerHost` on a fake clock, and node's zlib
 * behind the host's `inflate` and `deflate`. Not a test (it is in `check.ts`'s
 * NOT_TESTS) and it must never end the process itself.
 *
 * Everything here is the *harness*; every rule it exercises lives in
 * `src/services/monitoring/`. The one thing the harness itself holds is the
 * generator: datagrams are authored from the v5 layout in `fixtures.ts`, never
 * by the encoder under test.
 */
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { MonitoringJournal, type AppendResult, type EvidenceInput } from '../../src/services/monitoring/journal';
import { LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { runHistoryQuery, type QueryOptions } from '../../src/services/monitoring/queries';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import type { HostRuntime } from '../../src/services/monitoring/runtime';
import {
  DECODER_POLICY_VERSION, LIMITS, type BoundaryAction, type Evidence, type HistoryReply, type HistoryResult, type QuerySpec,
} from '../../src/services/monitoring/types';
import { sourceKey } from '../../src/services/monitoring/v5';
import {
  MonitoringWorkerHost, type FromMonitoringWorker, type HostOptions, type ToMonitoringWorker,
} from '../../src/services/monitoring/workerHost';
import { COLLECTOR, EXPORTER, v5Payload, type FlowSpec, type HeaderSpec } from './fixtures';

export const MIN = 60_000;
/** Minute-aligned, so a test names its minutes as `BASE + n * MIN`. */
export const BASE = 1_760_000_040_000;
/** Far enough ahead that every session a test leaves open is covered through the whole fixture. */
export const NOW = BASE + 10_000 * MIN;
export const SRC = sourceKey(EXPORTER, 0, 0);
export const SRC1 = sourceKey(EXPORTER, 0, 1);

export const inflate = (b: Uint8Array, maxOutput: number): Uint8Array =>
  new Uint8Array(inflateRawSync(b, { maxOutputLength: maxOutput }));
export const deflate = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b, { level: 1 }));

/** mulberry32: small, seedable and the same on every machine. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// --- evidence ---------------------------------------------------------------------------------------

export function dgram(
  receivedMs: number, flows: Partial<FlowSpec>[], header: Partial<HeaderSpec> = {}, remoteIPv4 = EXPORTER,
): EvidenceInput {
  return {
    kind: 'datagram', receivedMs, localIPv4: COLLECTOR, localPort: 2055,
    remoteIPv4, remotePort: 40_000, bytes: v5Payload(header, flows),
  };
}

/** A datagram that is not NetFlow at all: it decodes as malformed. */
export function junk(receivedMs: number, remoteIPv4 = EXPORTER): EvidenceInput {
  return {
    kind: 'datagram', receivedMs, localIPv4: COLLECTOR, localPort: 2055,
    remoteIPv4, remotePort: 40_000, bytes: Uint8Array.from([0, 5, 0, 9, 1, 2, 3]),
  };
}

/** A NetFlow version this build does not read: it decodes as unsupported. */
export function v9(receivedMs: number, remoteIPv4 = EXPORTER): EvidenceInput {
  const bytes = new Uint8Array(24);
  bytes[1] = 9;
  return { kind: 'datagram', receivedMs, localIPv4: COLLECTOR, localPort: 2055, remoteIPv4, remotePort: 40_000, bytes };
}

export function boundary(
  action: BoundaryAction, sessionId: string, receivedMs: number, reason = '', droppedDatagrams: number | null = null,
): EvidenceInput {
  return { kind: 'boundary', sessionId, receivedMs, action, reason, droppedDatagrams };
}

export const start = (receivedMs: number, sessionId = 's1'): EvidenceInput => boundary('start', sessionId, receivedMs);
export const stop = (receivedMs: number, sessionId = 's1', reason = ''): EvidenceInput =>
  boundary('stop', sessionId, receivedMs, reason);

// --- the journal, the sidecar and the runtime ---------------------------------------------------------

export class Rig {
  jfile = new MemoryBlockFile();
  sfile = new MemoryBlockFile();
  journal!: MonitoringJournal;
  store!: RollupStore;
  runtime!: LocalRuntime;
  sidecarStatus = '';

  /** `seed` picks the generation: two rigs with different seeds are two journals. */
  constructor(readonly seed = 0xa0) {
    this.openJournal();
    this.openSidecar();
  }

  private rnd = (n: number): Uint8Array => Uint8Array.from({ length: n }, (_, i) => (this.seed + i) & 0xff);

  openJournal(): void {
    this.journal = MonitoringJournal.open(this.jfile, { limitBytes: 1 << 30, randomBytes: this.rnd, nowMs: () => NOW }).journal;
  }

  /** Opens the sidecar file as it stands against the journal as it stands, and wraps both in a runtime. */
  openSidecar(): void {
    const snap = this.journal.snapshot();
    const r = RollupStore.open(
      this.sfile,
      { generation: snap.generation, throughEntryId: snap.throughEntryId, policyVersion: DECODER_POLICY_VERSION },
      { nowMs: () => NOW },
    );
    this.sidecarStatus = r.status;
    this.store = r.store;
    this.runtime = new LocalRuntime(this.journal, r.store, r.reason === undefined ? { status: r.status } : { status: r.status, reason: r.reason });
  }

  get generation(): string { return this.journal.snapshot().generation; }
  get through(): number { return this.journal.snapshot().throughEntryId; }

  /** Appends and does not read back; for fixtures too large to want a copy. */
  append(inputs: EvidenceInput[]): AppendResult {
    const r = this.journal.append(inputs);
    if (r.refused > 0) throw new Error(`the rig's journal refused ${r.refused} of ${inputs.length} entries (state ${r.state})`);
    return r;
  }

  /** Appends and returns the entries as the journal now holds them. */
  add(...inputs: EvidenceInput[]): Evidence[] {
    const before = this.through;
    const r = this.append(inputs);
    const out: Evidence[] = [];
    let after = before;
    for (;;) {
      const page = this.journal.readPage(r.snapshot, after, 256, 1 << 20);
      out.push(...page.entries);
      after = page.nextAfterId;
      if (page.done) break;
    }
    return out;
  }

  /** A fresh process: the same files, opened again. A session left open is closed by an `interrupted` boundary. */
  reopen(): void {
    this.openJournal();
    this.openSidecar();
  }

  sidecarBytes(): Uint8Array {
    const out = new Uint8Array(this.sfile.size());
    this.sfile.read(0, out);
    return out;
  }
}

// --- the host ------------------------------------------------------------------------------------------

export function waitTick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** Timers the test fires by hand: a pending one is scheduled, `fire` runs it and forgets it. */
export class ManualTimers {
  private next = 1;
  private readonly pending = new Map<number, { fn: () => void; ms: number }>();
  /** The host's `setTimer`: returns the cancel. */
  readonly set = (fn: () => void, ms: number): (() => void) => {
    const id = this.next++;
    this.pending.set(id, { fn, ms });
    return () => { this.pending.delete(id); };
  };
  get count(): number { return this.pending.size; }
  /** The delays of the timers waiting, oldest first. */
  get delays(): number[] { return [...this.pending.values()].map((t) => t.ms); }
  /** Runs every timer waiting now (not ones they schedule). */
  fire(): void {
    const due = [...this.pending.entries()];
    for (const [id] of due) this.pending.delete(id);
    for (const [, t] of due) t.fn();
  }
}

export class HostRig {
  posts: FromMonitoringWorker[] = [];
  readonly timers = new ManualTimers();
  /** The fake monotonic clock: each `now()` advances it by `step`, so a step of 0 never yields. */
  clock = 0;
  step = 0;
  yields = 0;
  onYield: (() => void) | null = null;
  wall = NOW;
  readonly host: MonitoringWorkerHost;
  private nextId = 1;

  constructor(public runtime: HostRuntime, over: Partial<HostOptions> = {}) {
    this.host = new MonitoringWorkerHost({
      post: (m) => { this.posts.push(m); },
      openRuntime: () => this.runtime,
      now: () => (this.clock += this.step),
      yieldNow: () => {
        this.yields++;
        this.onYield?.();
        return waitTick();
      },
      wallNow: () => this.wall,
      setTimer: this.timers.set,
      inflate,
      deflate,
      ...over,
    });
  }

  send(message: DistributiveOmit<ToMonitoringWorker, 'requestId'>): number {
    const requestId = this.nextId++;
    this.host.handle({ ...message, requestId });
    return requestId;
  }

  repliesTo(requestId: number): FromMonitoringWorker[] {
    return this.posts.filter((p) => p.type !== 'rebuild' && p.type !== 'health' && p.type !== 'pong' && p.requestId === requestId);
  }

  /** Polls until `find` returns something; a hung host fails the test instead of the run. */
  async waitFor<T>(find: () => T | undefined, what: string, limitMs = 10_000): Promise<T> {
    const deadline = Date.now() + limitMs;
    for (;;) {
      const found = find();
      if (found !== undefined) return found;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
      await waitTick();
    }
  }

  /** Connects and waits for the reply only; the rebuild goes on behind it. */
  async connectOnly(): Promise<FromMonitoringWorker> {
    const id = this.send({ type: 'connect', port: {} });
    return this.waitFor(() => this.repliesTo(id)[0], 'the connect reply');
  }

  /** Connects and waits for the rebuild to finish too. */
  async connect(): Promise<FromMonitoringWorker> {
    const reply = await this.connectOnly();
    await this.host.settled();
    return reply;
  }

  queryNoWait(viewId: string, spec: QuerySpec): number {
    return this.send({ type: 'query', viewId, spec });
  }

  async query(viewId: string, spec: QuerySpec): Promise<HistoryReply> {
    const id = this.queryNoWait(viewId, spec);
    const reply = await this.waitFor(() => this.repliesTo(id).find((r) => r.type === 'query-reply'), 'a query reply');
    return (reply as Extract<FromMonitoringWorker, { type: 'query-reply' }>).reply;
  }

  /** One flush window passes: the clock moves on and the host's tick timer fires. */
  tick(ms: number = LIMITS.flushMs): void {
    this.clock += ms;
    this.timers.fire();
  }

  /** The health messages posted so far. */
  healthPosts(): Extract<FromMonitoringWorker, { type: 'health' }>[] {
    return this.posts.filter((p): p is Extract<FromMonitoringWorker, { type: 'health' }> => p.type === 'health');
  }

  phases(): string[] {
    return this.posts.filter((p) => p.type === 'rebuild').map((p) => (p as { phase: string }).phase);
  }
}

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** A host over `rig`, connected and caught up. */
export async function rollUp(rig: Rig, over: Partial<HostOptions> = {}): Promise<HostRig> {
  const host = new HostRig(rig.runtime, over);
  const reply = await host.connect();
  if (reply.type !== 'connect-reply' || !reply.ok) throw new Error(`connect failed: ${JSON.stringify(reply)}`);
  return host;
}

// --- asking ---------------------------------------------------------------------------------------------

export const spec = (fromMs: number, toMs: number, bucketCount: number, over: Partial<QuerySpec> = {}): QuerySpec =>
  ({ sourceKey: SRC, fromMs, toMs, bucketCount, ...over });

export function ask(rig: Rig, query: QuerySpec, over: Partial<QueryOptions> = {}): Promise<HistoryReply> {
  return runHistoryQuery(rig.runtime, rig.runtime, query, new AbortController().signal, { inflate, nowMs: NOW, ...over });
}

export async function askOk(rig: Rig, query: QuerySpec, over: Partial<QueryOptions> = {}): Promise<HistoryResult> {
  const reply = await ask(rig, query, over);
  if (!reply.ok) throw new Error(`query refused: ${reply.code}: ${reply.message}`);
  return reply.value;
}

/** What the equality property compares: everything but how the answer was reached. */
export function withoutProvenance(r: HistoryResult): Omit<HistoryResult, 'answeredFrom'> {
  const { answeredFrom: _answeredFrom, ...rest } = r;
  return rest;
}

/** The answer from rollups and the same question answered by reading every minute from the journal. */
export async function askBoth(rig: Rig, query: QuerySpec, over: Partial<QueryOptions> = {}): Promise<{ fast: HistoryResult; raw: HistoryResult }> {
  const fast = await askOk(rig, query, over);
  const raw = await askOk(rig, query, { ...over, forceRaw: true });
  return { fast, raw };
}

// --- a runner that can await ---------------------------------------------------------------------------

const tests: { name: string; fn: () => void | Promise<void> }[] = [];

export function test(name: string, fn: () => void | Promise<void>): void {
  tests.push({ name, fn });
}

/** Runs every registered test in order and returns the number that failed. The caller exits. */
export async function runAll(): Promise<number> {
  let failures = 0;
  for (const t of tests) {
    const started = Date.now();
    try {
      await t.fn();
      console.log(`PASS  ${t.name}${Date.now() - started > 2000 ? ` (${((Date.now() - started) / 1000).toFixed(1)} s)` : ''}`);
    } catch (e) {
      failures++;
      console.log(`FAIL  ${t.name}`);
      console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 7).join('\n        ')}`.slice(0, 1100));
    }
  }
  console.log(failures === 0 ? `\n${tests.length} passed` : `\n${failures} of ${tests.length} FAILED`);
  return failures;
}
