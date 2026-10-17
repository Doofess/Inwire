/**
 * The monitoring Worker's logic, with the Worker taken out (ADR 0059): messages
 * in through `handle`, messages out through `post`, the files behind a
 * `HostRuntime`. `src/workers/monitoring.worker.ts` is the thin wiring that
 * gives it a real port, a real clock and fflate; the tests give it a fake
 * clock, node's zlib and an in-process runtime, which is how a cancel arriving
 * halfway through a query can be tested at all.
 *
 * Four rules, each there because a plausible alternative hangs or lies:
 *
 * - **Exactly one terminal reply per request.** Every job carries a `replied`
 *   flag and every reply goes through it, so supersede, cancel, shutdown and a
 *   query finishing in the same tick cannot answer twice - and a cancelled
 *   running query still holds its slot until it actually stops, so cancelling
 *   cannot be used to run an unbounded number of queries.
 * - **Work is cut into ~8 ms slices.** An `async` function over an in-process
 *   runtime never yields to the event loop on its own, so a long query would
 *   starve the message that cancels it. The slice is measured on the injected
 *   clock and the yield is a real macrotask (`yieldNow`), not a timer.
 * - **Rollups follow the journal and never lead it.** Live entries, a rebuild
 *   from the sidecar's watermark and a hole read after a missed push all go
 *   through one `feed` in strict id order, and `MinuteAggregator.drain` decides
 *   what may be posted. A post that fails stops the rollups, not the queries:
 *   the sidecar's older watermark is still true, and the journal answers.
 * - **The Worker is not the authority.** A generation that changes under it, a
 *   policy version it does not decode, or a sidecar that disagrees with the
 *   journal is a reset or a failure, never a guess.
 */
import { StaleGenerationError } from './journal';
import { BoundaryCache, runHistoryQuery } from './queries';
import { encodeMinuteRollup, type Deflate, type Inflate } from './rollupCodec';
import { EngineAdmission, MinuteAggregator, minuteOf } from './rollup';
import { RuntimeUnavailableError, type HostRuntime } from './runtime';
import {
  DECODER_POLICY_VERSION, LIMITS, type DatagramEvidence, type Evidence, type EvidenceRef, type HistoryReply, type NormalizedV5,
  type QuerySpec, type Snapshot,
} from './types';
import { decodeV5, sourceKey } from './v5';

// --- the messages --------------------------------------------------------------------------------------

export type ToMonitoringWorker =
  | { type: 'connect'; requestId: number; port: unknown }
  | { type: 'query'; requestId: number; viewId: string; spec: QuerySpec }
  | { type: 'cancelQuery'; requestId: number; targetRequestId: number }
  | { type: 'detail'; requestId: number; snapshot: Snapshot; ref: EvidenceRef; recordIndex: number }
  | { type: 'shutdown'; requestId: number };

export type RebuildPhase = 'idle' | 'rebuilding' | 'live' | 'failed';

export type DetailFailure = 'stale-generation' | 'not-found' | 'runtime-unavailable' | 'storage-failed' | 'cancelled';

export type FromMonitoringWorker =
  | { type: 'connect-reply'; requestId: number; ok: true; phase: RebuildPhase; watermark: number }
  | { type: 'connect-reply'; requestId: number; ok: false; code: 'already-connected' | 'runtime-unavailable' | 'storage-failed' | 'cancelled'; message: string }
  | { type: 'query-reply'; requestId: number; reply: HistoryReply }
  | { type: 'cancel-reply'; requestId: number; cancelled: boolean }
  | { type: 'detail-reply'; requestId: number; ok: true; evidence: DatagramEvidence; record: NormalizedV5 }
  | { type: 'detail-reply'; requestId: number; ok: false; code: DetailFailure; message: string }
  | { type: 'shutdown-reply'; requestId: number }
  | { type: 'error-reply'; requestId: number; message: string }
  /** Not a reply: how far the rollups have got, sent as it changes. */
  | { type: 'rebuild'; phase: RebuildPhase; fedThroughEntryId: number; targetEntryId: number; message?: string };

export interface HostOptions {
  post(message: FromMonitoringWorker): void;
  /** Wraps the port a `connect` carries; the Worker file passes `createRuntimeClient`. */
  openRuntime(port: unknown): HostRuntime;
  /** A monotonic millisecond clock, for slicing only. */
  now(): number;
  /** Lets the event loop run: a macrotask, so a queued message is handled before this returns. */
  yieldNow(): Promise<void>;
  /** The wall clock a still-open session is covered up to. */
  wallNow(): number;
  inflate: Inflate;
  deflate: Deflate;
  boundaries?: BoundaryCache;
}

/** How long a loop runs before it yields. */
const SLICE_MS = 8;

interface Job {
  requestId: number;
  viewId: string;
  spec: QuerySpec;
  controller: AbortController;
  state: 'queued' | 'running' | 'done';
  replied: boolean;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

class Slicer {
  private start: number;
  constructor(private readonly now: () => number, private readonly yieldNow: () => Promise<void>) {
    this.start = now();
  }

  async checkpoint(): Promise<void> {
    if (this.now() - this.start < SLICE_MS) return;
    await this.yieldNow();
    this.start = this.now();
  }
}

export class MonitoringWorkerHost {
  private runtime: HostRuntime | null = null;
  private connecting = false;
  private shuttingDown = false;
  private readonly jobs = new Map<number, Job>();
  private queue: Job[] = [];
  private running = 0;
  private readonly boundaries: BoundaryCache;
  private readonly tasks = new Set<Promise<void>>();

  private phase: RebuildPhase = 'idle';
  private generation = '';
  private aggregator = new MinuteAggregator();
  private admission = new EngineAdmission();
  private targetEntryId = 0;
  private stopRebuild = false;
  private feedChain: Promise<void> = Promise.resolve();

  constructor(private readonly options: HostOptions) {
    this.boundaries = options.boundaries ?? new BoundaryCache();
  }

  /** Resolves when every request handled so far has been answered; for tests and orderly shutdown. */
  async settled(): Promise<void> {
    while (this.tasks.size > 0) await Promise.all([...this.tasks]);
    await this.feedChain;
  }

  get rebuildPhase(): RebuildPhase { return this.phase; }

  // --- dispatch --------------------------------------------------------------------------------------

  handle(message: unknown): void {
    if (!isObject(message) || typeof message.type !== 'string' || typeof message.requestId !== 'number') return;
    const requestId = message.requestId;
    switch (message.type) {
      case 'connect': this.track(this.connect(requestId, message.port)); return;
      case 'query': this.query(requestId, message.viewId, message.spec as QuerySpec); return;
      case 'cancelQuery': this.cancelQuery(requestId, message.targetRequestId); return;
      case 'detail': this.track(this.detail(requestId, message.snapshot as Snapshot, message.ref as EvidenceRef, message.recordIndex)); return;
      case 'shutdown': this.track(this.shutdown(requestId)); return;
      default: this.options.post({ type: 'error-reply', requestId, message: `unknown message ${message.type}` });
    }
  }

  private track(task: Promise<void>): void {
    const t = task.catch(() => undefined).then(() => { this.tasks.delete(t); });
    this.tasks.add(t);
  }

  // --- connect and the rollups ---------------------------------------------------------------------------

  private async connect(requestId: number, port: unknown): Promise<void> {
    const post = this.options.post;
    if (this.shuttingDown) return post({ type: 'connect-reply', requestId, ok: false, code: 'cancelled', message: 'the Worker is shutting down' });
    if (this.runtime !== null || this.connecting) {
      return post({ type: 'connect-reply', requestId, ok: false, code: 'already-connected', message: 'the Worker already has a runtime' });
    }
    this.connecting = true;
    let runtime: HostRuntime | null = null;
    let failure = '';
    try {
      runtime = this.options.openRuntime(port);
      const status = await runtime.rollupStatus();
      // The sidecar is a cache: a fault resetting or reading it leaves the host
      // in `failed` with nothing fed and nothing posted, and queries answer from
      // the journal. Only the journal's own faults (`snapshot`, `openRuntime`)
      // and a lost runtime fail the connect.
      let sidecarFault: unknown = null;
      let mark: Awaited<ReturnType<HostRuntime['watermark']>> = null;
      try {
        if (status.status === 'rebuild-required') await runtime.resetRollups();
        mark = await runtime.watermark();
      } catch (e) {
        if (e instanceof RuntimeUnavailableError) throw e;
        sidecarFault = e;
      }
      const snapshot = await runtime.snapshot();
      let sources: string[] = [];
      if (sidecarFault === null) {
        try {
          // The store already refuses a sidecar of another generation or policy;
          // a disagreement here is a runtime that did not, so it is wiped, not trusted.
          if (mark !== null && (mark.generation !== snapshot.generation || mark.policyVersion !== DECODER_POLICY_VERSION)) {
            await runtime.resetRollups();
            mark = await runtime.watermark();
          }
          sources = mark === null ? [] : await runtime.sources();
        } catch (e) {
          if (e instanceof RuntimeUnavailableError) throw e;
          sidecarFault = e;
        }
      }
      if (sidecarFault !== null) { mark = null; sources = []; }
      this.generation = snapshot.generation;
      this.admission = new EngineAdmission(sources);
      this.aggregator = new MinuteAggregator(mark === null ? 0 : mark.throughEntryId);
      this.runtime = runtime;
      runtime.onLive((entries) => this.onLive(entries));
      this.phase = status.status === 'failed' || sidecarFault !== null ? 'failed' : 'rebuilding';
      failure = sidecarFault === null
        ? 'the rollup sidecar could not be opened; history is answered from the journal'
        : `the rollup sidecar could not be reset or read (${sidecarFault instanceof Error ? sidecarFault.message : String(sidecarFault)}); history is answered from the journal`;
      post({ type: 'connect-reply', requestId, ok: true, phase: this.phase, watermark: this.aggregator.fedThrough });
    } catch (e) {
      this.runtime = null;
      this.connecting = false;
      const code = e instanceof RuntimeUnavailableError ? 'runtime-unavailable' : 'storage-failed';
      return post({ type: 'connect-reply', requestId, ok: false, code, message: e instanceof Error ? e.message : String(e) });
    }
    this.connecting = false;
    if (this.phase === 'failed') {
      this.announce(failure);
      return;
    }
    // The rebuild runs behind the reply: queries are answered meanwhile, from
    // the sidecar as it stands (rule 13 makes that consistent).
    this.feedChain = this.feedChain.then(() => this.rebuild());
  }

  private announce(message?: string): void {
    this.options.post({
      type: 'rebuild', phase: this.phase, fedThroughEntryId: this.aggregator.fedThrough, targetEntryId: this.targetEntryId,
      ...(message === undefined ? {} : { message }),
    });
  }

  private fail(e: unknown): void {
    this.phase = 'failed';
    this.announce(e instanceof Error ? e.message : String(e));
  }

  /** Reads `(fed, snapshot.through]` into the aggregator in slices, posting what may be posted after each page. */
  private async readThrough(runtime: HostRuntime, snapshot: Snapshot): Promise<void> {
    const slicer = new Slicer(this.options.now, this.options.yieldNow);
    while (!this.stopRebuild && this.aggregator.fedThrough < snapshot.throughEntryId) {
      await slicer.checkpoint();
      const after = this.aggregator.fedThrough;
      const page = await runtime.readPage(snapshot, after, LIMITS.pageEntries, LIMITS.pageBytes);
      for (const e of page.entries) this.feed(e);
      if (page.entries.length === 0 && this.aggregator.fedThrough <= after) {
        throw new Error(`the journal returned no entries after ${after} though it holds ${snapshot.throughEntryId}`);
      }
      await this.postDrained(runtime);
      this.announce();
    }
  }

  private async rebuild(): Promise<void> {
    const runtime = this.runtime;
    if (runtime === null || this.phase !== 'rebuilding') return;
    try {
      let snapshot: Snapshot = await runtime.snapshot();
      for (;;) {
        if (snapshot.generation !== this.generation) throw new StaleGenerationError(this.generation, snapshot.generation);
        this.targetEntryId = snapshot.throughEntryId;
        this.announce();
        await this.readThrough(runtime, snapshot);
        if (this.stopRebuild) return;
        const next = await runtime.snapshot();
        // Caught up when nothing was appended while the last pass ran. No
        // await sits between this test and `live`, so a push after it is
        // handled and a push before it is in `next`.
        if (next.generation === this.generation && next.throughEntryId <= this.aggregator.fedThrough) {
          this.phase = 'live';
          this.announce();
          return;
        }
        snapshot = next;
      }
    } catch (e) {
      this.fail(e);
    }
  }

  /**
   * The promise is the push's own: it settles when these entries have been
   * consumed, and the transport acknowledges the push then. A push that is
   * dropped settles at once - there is nothing to wait for.
   */
  private onLive(entries: Evidence[]): Promise<void> {
    // Dropped during the rebuild: its loop re-takes the snapshot until it has them.
    if (this.phase !== 'live' || this.shuttingDown) return Promise.resolve();
    const done = this.feedChain.then(() => this.consume(entries));
    this.feedChain = done;
    return done;
  }

  private async consume(entries: Evidence[]): Promise<void> {
    const runtime = this.runtime;
    if (runtime === null || this.phase !== 'live' || this.stopRebuild) return;
    try {
      for (const e of entries) {
        const id = e.ref.entryId;
        if (e.ref.generation !== this.generation) throw new StaleGenerationError(this.generation, e.ref.generation);
        if (id <= this.aggregator.fedThrough) continue;
        // A push that was missed (or dropped while rebuilding) left a hole: read it before going on.
        if (id > this.aggregator.fedThrough + 1) await this.readThrough(runtime, { generation: this.generation, throughEntryId: id - 1 });
        this.feed(e);
      }
      await this.postDrained(runtime);
      this.announce();
    } catch (e) {
      this.fail(e);
    }
  }

  /** One entry into the aggregator, in strict id order; an id already fed is ignored. */
  private feed(e: Evidence): void {
    const id = e.ref.entryId;
    const agg = this.aggregator;
    if (id <= agg.fedThrough) return;
    if (e.kind === 'boundary') {
      agg.fed(id);
      // A stop, a suspend and a reopen after a crash all end the collector's
      // run: the minutes it was building are done, whatever the clock says.
      if (e.action === 'stop' || e.action === 'suspend' || e.action === 'interrupted') agg.seal(Infinity);
      return;
    }
    const decoded = decodeV5(e, e.remoteIPv4);
    if (decoded.kind === 'valid') {
      const key = sourceKey(e.remoteIPv4, decoded.engineType, decoded.engineId);
      if (!this.admission.admit(key)) agg.fed(id);
      else if (decoded.flows.length === 0) agg.touch(key, e.receivedMs, id);
      else for (const flow of decoded.flows) agg.add(flow);
    } else if (decoded.kind === 'malformed') {
      agg.addMalformed(e.remoteIPv4, e.receivedMs, id);
    } else {
      agg.addUnsupported(e.remoteIPv4, e.receivedMs, id);
    }
    // Receipt time has passed every earlier minute; the watermark, not the
    // wall clock, is what makes it safe to post them.
    agg.seal(minuteOf(e.receivedMs));
  }

  private async postDrained(runtime: HostRuntime): Promise<void> {
    const drained = this.aggregator.drain();
    if (drained === null) return;
    const minutes = drained.fragments.map((f) => ({
      sourceKey: f.rollup.sourceKey,
      minuteMs: f.rollup.minuteMs,
      bytes: encodeMinuteRollup(f.rollup, this.options.deflate),
    }));
    await runtime.appendMinutes(minutes, { generation: this.generation, throughEntryId: drained.watermark, policyVersion: DECODER_POLICY_VERSION });
  }

  private rebuildNote(): string | null {
    if (this.phase !== 'rebuilding') return null;
    return `The rollups are still being rebuilt (through entry ${this.aggregator.fedThrough} of ${this.targetEntryId}), so more of this range has to be read from the journal than will be once they are.`;
  }

  // --- queries -----------------------------------------------------------------------------------------

  private replyQuery(job: Job, reply: HistoryReply): void {
    if (job.replied) return;
    job.replied = true;
    this.options.post({ type: 'query-reply', requestId: job.requestId, reply });
  }

  private cancelJob(job: Job): void {
    this.replyQuery(job, { ok: false, code: 'cancelled', message: 'the query was cancelled' });
    job.controller.abort();
    if (job.state === 'queued') {
      this.queue = this.queue.filter((q) => q !== job);
      job.state = 'done';
      this.jobs.delete(job.requestId);
    }
  }

  private query(requestId: number, viewId: unknown, spec: QuerySpec): void {
    const post = this.options.post;
    if (typeof viewId !== 'string') {
      post({ type: 'query-reply', requestId, reply: { ok: false, code: 'invalid-query', message: 'a query names its view' } });
      return;
    }
    if (this.shuttingDown) {
      post({ type: 'query-reply', requestId, reply: { ok: false, code: 'cancelled', message: 'the Worker is shutting down' } });
      return;
    }
    if (this.runtime === null) {
      post({ type: 'query-reply', requestId, reply: { ok: false, code: 'runtime-unavailable', message: 'the Worker has no runtime yet' } });
      return;
    }
    const job: Job = { requestId, viewId, spec, controller: new AbortController(), state: 'queued', replied: false };
    // A newer query for the same view makes the older one pointless, queued or running.
    for (const other of [...this.jobs.values()]) if (other.viewId === viewId && !other.replied) this.cancelJob(other);
    this.jobs.set(requestId, job);
    if (this.running < LIMITS.concurrentQueries) this.start(job);
    else this.queue.push(job);
    while (this.queue.length > LIMITS.concurrentQueries) this.cancelJob(this.queue[0]);
  }

  private start(job: Job): void {
    job.state = 'running';
    this.running++;
    this.track(this.run(job));
  }

  private async run(job: Job): Promise<void> {
    const runtime = this.runtime;
    try {
      if (runtime === null) throw new RuntimeUnavailableError('the Worker has no runtime');
      const slicer = new Slicer(this.options.now, this.options.yieldNow);
      const reply = await runHistoryQuery(runtime, runtime, job.spec, job.controller.signal, {
        inflate: this.options.inflate,
        nowMs: this.options.wallNow,
        boundaries: this.boundaries,
        checkpoint: () => slicer.checkpoint(),
        rebuildNote: () => this.rebuildNote(),
        // A failed rebuild leaves the sidecar behind the journal for good, and
        // a failed open leaves it unreadable: either way the journal answers.
        ...(this.phase === 'failed' ? { rollupsUnavailable: 'the rollup sidecar has failed' } : {}),
      });
      this.replyQuery(job, reply);
    } catch (e) {
      this.replyQuery(job, { ok: false, code: 'storage-failed', message: e instanceof Error ? e.message : String(e) });
    } finally {
      job.state = 'done';
      this.jobs.delete(job.requestId);
      this.running--;
      const next = this.queue.shift();
      if (next !== undefined && !this.shuttingDown) this.start(next);
    }
  }

  private cancelQuery(requestId: number, target: unknown): void {
    const job = typeof target === 'number' ? this.jobs.get(target) : undefined;
    const cancelled = job !== undefined && !job.replied;
    if (cancelled) this.cancelJob(job);
    this.options.post({ type: 'cancel-reply', requestId, cancelled });
  }

  // --- detail ----------------------------------------------------------------------------------------------

  private async detail(requestId: number, snapshot: Snapshot, ref: EvidenceRef, recordIndex: unknown): Promise<void> {
    const post = this.options.post;
    const fail = (code: DetailFailure, message: string): void => post({ type: 'detail-reply', requestId, ok: false, code, message });
    if (this.shuttingDown) return fail('cancelled', 'the Worker is shutting down');
    const runtime = this.runtime;
    if (runtime === null) return fail('runtime-unavailable', 'the Worker has no runtime yet');
    try {
      if (!isObject(snapshot) || !isObject(ref) || typeof recordIndex !== 'number') return fail('not-found', 'a detail names a snapshot, a reference and a record');
      if (ref.generation !== snapshot.generation || ref.entryId > snapshot.throughEntryId) {
        return fail('stale-generation', 'the reference is outside the snapshot it was asked against');
      }
      const current = await runtime.snapshot();
      if (current.generation !== snapshot.generation) return fail('stale-generation', `the journal is now generation ${current.generation}`);
      const evidence = await runtime.readEvidence(ref);
      if (evidence === null) return fail('not-found', `no entry ${ref.entryId} in the journal`);
      if (evidence.kind !== 'datagram') return fail('not-found', `entry ${ref.entryId} is a boundary, not a datagram`);
      const decoded = decodeV5(evidence, evidence.remoteIPv4);
      const record = decoded.kind === 'valid' ? decoded.flows[recordIndex] : undefined;
      if (record === undefined) return fail('not-found', `entry ${ref.entryId} holds no record ${recordIndex}`);
      post({ type: 'detail-reply', requestId, ok: true, evidence, record });
    } catch (e) {
      if (e instanceof StaleGenerationError) return fail('stale-generation', e.message);
      if (e instanceof RuntimeUnavailableError) return fail('runtime-unavailable', e.message);
      fail('storage-failed', e instanceof Error ? e.message : String(e));
    }
  }

  // --- shutdown ----------------------------------------------------------------------------------------------

  private async shutdown(requestId: number): Promise<void> {
    this.shuttingDown = true;
    this.stopRebuild = true;
    for (const job of [...this.jobs.values()]) this.cancelJob(job);
    // The rebuild notices the flag at its next page; wait for it so nothing
    // is still posting to the runtime after the reply.
    await this.feedChain.catch(() => undefined);
    this.options.post({ type: 'shutdown-reply', requestId });
  }
}
