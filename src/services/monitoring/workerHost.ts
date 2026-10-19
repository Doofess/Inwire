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
 *   the sidecar's older watermark is still true, and the journal answers. A
 *   runtime that was only slow or lost is retried a few times from that
 *   watermark (`rollupFault`); a fault of the sidecar itself is final.
 * - **The Worker is not the authority.** A generation that changes under it, a
 *   policy version it does not decode, or a sidecar that disagrees with the
 *   journal is a reset or a failure, never a guess.
 */
import { StaleGenerationError } from './journal';
import { BoundaryCache, runHistoryQuery } from './queries';
import { encodeMinuteRollup, type Deflate, type Inflate } from './rollupCodec';
import { EngineAdmission, MinuteAggregator, feedEntry } from './rollup';
import { RuntimeUnavailableError, type HostRuntime } from './runtime';
import { initialSourceHealth, reduceSourceHealth, type HealthEvent, type SourceHealth } from './sourceHealth';
import {
  DECODER_POLICY_VERSION, LIMITS, type DatagramEvidence, type Evidence, type EvidenceRef, type HistoryReply, type NormalizedV5,
  type JournalSnapshot, type QuerySpec, type Snapshot,
} from './types';
import { decodeV5, sourceKey } from './v5';

// --- the messages --------------------------------------------------------------------------------------

export type ToMonitoringWorker =
  | { type: 'connect'; requestId: number; port: unknown }
  | { type: 'query'; requestId: number; viewId: string; spec: QuerySpec }
  | { type: 'cancelQuery'; requestId: number; targetRequestId: number }
  | { type: 'detail'; requestId: number; snapshot: Snapshot; ref: EvidenceRef; recordIndex: number }
  | { type: 'shutdown'; requestId: number }
  /** Liveness: no request id, answered with `pong` straight from the message handler. */
  | { type: 'ping' };

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
  /** The Worker's first message, posted when its script has loaded: the client's silence deadline starts here. */
  | { type: 'ready' }
  /** The answer to `ping`; any message from the Worker counts as a sign of life, this one exists for when it has nothing else to say. */
  | { type: 'pong' }
  /** Not a reply: how far the rollups have got, sent as it changes. */
  | { type: 'rebuild'; phase: RebuildPhase; fedThroughEntryId: number; targetEntryId: number; message?: string }
  /**
   * Not a reply: what this Worker can say about the source, at most once per `LIMITS.flushMs`
   * and only when something besides the clock changed. `health` is null until the first
   * datagram that arrived after the connect names an exporter. `sources` are the engine-form
   * keys this Worker knows (the sidecar's at connect plus every one admitted since), sorted.
   */
  | { type: 'health'; health: SourceHealth | null; sources: string[] };

export interface HostOptions {
  post(message: FromMonitoringWorker): void;
  /** Wraps the port a `connect` carries; the Worker file passes `createRuntimeClient`. */
  openRuntime(port: unknown): HostRuntime;
  /**
   * Called with the port a `connect` carried when that connect fails, so the runtime made from it
   * does not stay open: the Worker file closes it. A host given none leaves it to the garbage collector.
   */
  closePort?(port: unknown): void;
  /** A monotonic millisecond clock, for slicing only. */
  now(): number;
  /** Lets the event loop run: a macrotask, so a queued message is handled before this returns. */
  yieldNow(): Promise<void>;
  /** The wall clock a still-open session is covered up to, and what ages an entry the host feeds late. */
  wallNow(): number;
  /**
   * Calls `fn` once after `ms` and returns the cancel. The health tick re-arms itself, so a
   * host given none posts the connect's health and nothing after (staleness needs time to pass).
   */
  setTimer?(fn: () => void, ms: number): () => void;
  inflate: Inflate;
  deflate: Deflate;
  boundaries?: BoundaryCache;
}

/** How long a loop runs before it yields. */
const SLICE_MS = 8;

/**
 * How many times a lost or slow runtime is retried before the rollups are `failed`, with the
 * first delay `LIMITS.flushMs` and each one double the last. Five is 31 s of trying, after which
 * the runtime is gone for longer than a hiccup and the journal answering is the honest state.
 */
const RETRY_ATTEMPTS = 5;

/**
 * The sidecar refused a post (a `RangeError` from `appendMinutes`): the watermark was past the
 * journal's end, the batch over the per-call caps, or it would pass the storage limit less the
 * reserve. It is not the runtime failing and not a fault of the sidecar's file, so it is neither
 * retried tightly nor final - see `rollupRefused`.
 */
class AppendRefused extends Error {
  constructor(message: string) { super(message); this.name = 'AppendRefused'; }
}

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

  // What is pushed as `health`. Fed only by entries above `healthFloor`, the journal's end at
  // connect: replay is history, and a stale count on a fresh connect would read as a live fault.
  // It needs `decodeV5` and not the aggregator, so a failed host keeps feeding it from the live
  // push (`feedHealthOnly`); `healthThrough` is what keeps an entry from counting twice.
  private health: SourceHealth | null = null;
  private healthFloor = 0;
  private healthThrough = 0;
  private knownSources = new Set<string>();
  private lastSignature = '';
  private analyzedThrough: number | null = null;
  private rolledUpThrough: number | null = null;
  private cancelTick: (() => void) | null = null;
  // The retry of a transient rollup fault: how many have been spent since the last push that was
  // posted, and the cancel of the one waiting. Only a posted push resets the count, so a runtime
  // that comes back and fails again at once cannot be retried for ever.
  private retries = 0;
  // Refusals are counted apart: they are never final, only slower, up to a ceiling.
  private refusals = 0;
  private cancelRetry: (() => void) | null = null;

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
    // Before everything else and synchronous: a pong that waited behind a running query would read as a dead Worker.
    if (isObject(message) && message.type === 'ping') { this.options.post({ type: 'pong' }); return; }
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

  /**
   * The watermark a rebuild may continue from, after wiping a sidecar that cannot be continued: one of
   * another generation or policy; one that ends before the journal's first retained entry (it counts
   * entries the journal no longer has); one that ends before the newest retained `expired` boundary (it
   * still counts entries the archive now holds, and a query would add the two: a crash between the
   * boundary and the reset leaves exactly this, and `resumeExpiry` is what normally closes it). An empty
   * sidecar is reset too when entries have expired, so its base is the journal's start and not entry 0.
   */
  private async settleSidecar(
    runtime: HostRuntime, mark: Awaited<ReturnType<HostRuntime['watermark']>>, snapshot: JournalSnapshot,
  ): Promise<Awaited<ReturnType<HostRuntime['watermark']>>> {
    let wipe = false;
    if (mark !== null) {
      if (mark.generation !== snapshot.generation || mark.policyVersion !== DECODER_POLICY_VERSION) wipe = true;
      else if (mark.throughEntryId < snapshot.firstEntryId - 1) wipe = true;
      else if (mark.throughEntryId < await this.newestExpiredBoundary(runtime, snapshot)) wipe = true;
    } else if (snapshot.firstEntryId > 1) {
      wipe = true;
    }
    if (!wipe) return mark;
    await runtime.resetRollups();
    return runtime.watermark();
  }

  /** The entry id of the newest `expired` boundary the journal still holds, 0 for none. */
  private async newestExpiredBoundary(runtime: HostRuntime, snapshot: JournalSnapshot): Promise<number> {
    let newest = 0;
    let after = snapshot.firstEntryId - 1;
    for (;;) {
      const page = await runtime.readBoundaries(snapshot, after, LIMITS.pageEntries);
      for (const b of page.entries) if (b.action === 'expired') newest = Math.max(newest, b.ref.entryId);
      if (page.done) return newest;
      after = page.nextAfterId;
    }
  }

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
      // The sidecar is a cache: a fault asking about, resetting or reading it
      // leaves the host in `failed` with nothing fed and nothing posted, and
      // queries answer from the journal. Only the journal's own faults
      // (`snapshot`, `openRuntime`) and a lost runtime fail the connect.
      let sidecarFault: unknown = null;
      let status: Awaited<ReturnType<HostRuntime['rollupStatus']>> = { status: 'failed' };
      let mark: Awaited<ReturnType<HostRuntime['watermark']>> = null;
      try {
        status = await runtime.rollupStatus();
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
          mark = await this.settleSidecar(runtime, mark, snapshot);
          sources = mark === null ? [] : await runtime.sources();
          // What expired is no longer in the journal to re-admit from: its engines are in the archive.
          if (snapshot.firstEntryId > 1 && runtime.archive !== undefined) {
            sources = [...new Set([...sources, ...await runtime.archive.sources()])].sort();
          }
        } catch (e) {
          if (e instanceof RuntimeUnavailableError) throw e;
          sidecarFault = e;
        }
      }
      if (sidecarFault !== null) { mark = null; sources = []; }
      this.generation = snapshot.generation;
      this.healthFloor = snapshot.throughEntryId;
      this.healthThrough = 0;
      this.health = null;
      this.knownSources = new Set(sources);
      this.analyzedThrough = null;
      this.rolledUpThrough = null;
      this.admission = new EngineAdmission(sources);
      this.aggregator = new MinuteAggregator(Math.max(mark === null ? 0 : mark.throughEntryId, snapshot.firstEntryId - 1));
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
      // The runtime, if one was made, is not going to be used: its port would otherwise stay open on every Try again.
      try { this.options.closePort?.(port); } catch { /* already closed */ }
      const code = e instanceof RuntimeUnavailableError ? 'runtime-unavailable' : 'storage-failed';
      return post({ type: 'connect-reply', requestId, ok: false, code, message: e instanceof Error ? e.message : String(e) });
    }
    this.connecting = false;
    this.postHealth(true);
    // A failed host still ticks: the exporter going quiet is true whether or not the rollups work.
    this.armTick();
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
    // The tick stays armed: only shutdown stops it (see `armTick`).
    this.phase = 'failed';
    this.announce(e instanceof Error ? e.message : String(e));
  }

  /**
   * A fault while the rollups follow the journal. A runtime that was lost or too slow is transient:
   * the rollups go back to `rebuilding` and start again after a delay, from a fresh snapshot and
   * the sidecar's own watermark, because the aggregator may hold minutes a failed post had
   * already taken out of it. A fault of the sidecar or the journal is not, and is `failed`.
   */
  private rollupFault(e: unknown): void {
    const setTimer = this.options.setTimer;
    if (e instanceof AppendRefused && setTimer !== undefined && !this.shuttingDown) {
      this.rollupRefused(e, setTimer);
      return;
    }
    if (!(e instanceof RuntimeUnavailableError) || setTimer === undefined || this.shuttingDown || this.retries >= RETRY_ATTEMPTS) {
      this.fail(e);
      return;
    }
    if (this.cancelRetry !== null) return;
    const delay = LIMITS.flushMs * 2 ** this.retries++;
    this.phase = 'rebuilding';
    this.announce();
    this.cancelRetry = setTimer(() => {
      this.cancelRetry = null;
      this.feedChain = this.feedChain.then(() => this.resume());
    }, delay);
  }

  /**
   * A post the sidecar refused. At the storage limit the right state is not `failed`: the rollups stop
   * growing, the journal keeps answering, and they resume if room comes back. The aggregator may hold
   * fewer minutes than the sidecar's watermark vouches for (the refused post's were drained), so the
   * try again is a `resume` from the sidecar's own watermark, like a lost runtime's. The delay doubles
   * to a ceiling and the attempts have no limit: each costs one pass over what the sidecar lacks.
   */
  private rollupRefused(e: AppendRefused, setTimer: NonNullable<HostOptions['setTimer']>): void {
    if (this.cancelRetry !== null) return;
    const delay = LIMITS.flushMs * 2 ** Math.min(this.refusals++, RETRY_ATTEMPTS);
    this.phase = 'rebuilding';
    this.announce(`The rollups are paused: the sidecar refused to grow (${e.message}). Queries are answered from the journal.`);
    this.cancelRetry = setTimer(() => {
      this.cancelRetry = null;
      this.feedChain = this.feedChain.then(() => this.resume());
    }, delay);
  }

  /** The retry: a new aggregator from what the sidecar holds, then the ordinary rebuild. */
  private async resume(): Promise<void> {
    const runtime = this.runtime;
    if (runtime === null || this.shuttingDown || this.phase !== 'rebuilding') return;
    try {
      const snapshot = await runtime.snapshot();
      const mark = await this.settleSidecar(runtime, await runtime.watermark(), snapshot);
      this.aggregator = new MinuteAggregator(Math.max(mark === null ? 0 : mark.throughEntryId, snapshot.firstEntryId - 1));
    } catch (e) {
      this.rollupFault(e);
      return;
    }
    await this.rebuild();
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
      this.rollupFault(e);
    }
  }

  /**
   * The promise is the push's own: it settles when these entries have been
   * consumed, and the transport acknowledges the push then. A push that is
   * dropped settles at once - there is nothing to wait for.
   */
  private onLive(entries: Evidence[]): Promise<void> {
    if (this.shuttingDown) return Promise.resolve();
    if (this.phase === 'failed') {
      this.feedHealthOnly(entries);
      return Promise.resolve();
    }
    // Dropped during the rebuild: its loop re-takes the snapshot until it has them.
    if (this.phase !== 'live') return Promise.resolve();
    const done = this.feedChain.then(() => this.consume(entries));
    this.feedChain = done;
    return done;
  }

  private async consume(entries: Evidence[]): Promise<void> {
    const runtime = this.runtime;
    if (runtime === null || this.stopRebuild) return;
    if (this.phase === 'failed') {
      // Failed between the push and this turn of the chain.
      this.feedHealthOnly(entries);
      return;
    }
    if (this.phase !== 'live') return;
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
      this.retries = 0;
      this.announce();
    } catch (e) {
      this.rollupFault(e);
      // What this push still holds arrived all the same.
      this.feedHealthOnly(entries);
    }
  }

  // --- health ---------------------------------------------------------------------------------------------

  private armTick(): void {
    const setTimer = this.options.setTimer;
    if (setTimer === undefined || this.shuttingDown || this.cancelTick !== null) return;
    this.cancelTick = setTimer(() => {
      this.cancelTick = null;
      if (this.shuttingDown) return;
      this.observe({ kind: 'tick', elapsedMs: this.options.now(), wallMs: this.options.wallNow() });
      this.postHealth(false);
      this.armTick();
    }, LIMITS.flushMs);
  }

  private disarmTick(): void {
    this.cancelTick?.();
    this.cancelTick = null;
  }

  /** One event into the one health. Nothing before the first exporter address is known: there is no source to describe. */
  private observe(event: HealthEvent): void {
    if (this.health !== null) this.health = reduceSourceHealth(this.health, event);
  }

  /** A datagram from an exporter address: a different one than the health describes starts it afresh. */
  private observeDatagram(address: string, event: HealthEvent): void {
    if (this.health === null || this.health.exporterIPv4 !== address) {
      this.health = initialSourceHealth(address);
      // The watermarks are the Worker's own and outlive the exporter.
      if (this.analyzedThrough !== null) this.observe({ kind: 'watermark', which: 'analyzed', throughEntryId: this.analyzedThrough, elapsedMs: event.elapsedMs, wallMs: event.wallMs });
      if (this.rolledUpThrough !== null) this.observe({ kind: 'watermark', which: 'rolled-up', throughEntryId: this.rolledUpThrough, elapsedMs: event.elapsedMs, wallMs: event.wallMs });
    }
    this.health = reduceSourceHealth(this.health, event);
  }

  private noteWatermark(which: 'analyzed' | 'rolled-up', throughEntryId: number): void {
    if (which === 'analyzed') this.analyzedThrough = Math.max(this.analyzedThrough ?? 0, throughEntryId);
    else this.rolledUpThrough = Math.max(this.rolledUpThrough ?? 0, throughEntryId);
    this.observe({ kind: 'watermark', which, throughEntryId, elapsedMs: this.options.now(), wallMs: this.options.wallNow() });
  }

  /** Posts when anything but the clock differs from the last post (or when forced); the tick calls it once per flush window. */
  private postHealth(force: boolean): void {
    const sources = [...this.knownSources].sort();
    const signature = JSON.stringify([this.health === null ? null : { ...this.health, elapsedMs: 0 }, sources]);
    if (!force && signature === this.lastSignature) return;
    this.lastSignature = signature;
    this.options.post({ type: 'health', health: this.health, sources });
  }

  /** One entry into the aggregator, in strict id order; an id already fed is ignored. */
  private feed(e: Evidence): void {
    // The aggregator's own steps are `feedEntry`'s, shared with the expiry's replay; the health and
    // the source list are this host's.
    const fed = feedEntry(this.aggregator, this.admission, e);
    if (fed === null || e.kind !== 'datagram') return;
    if (fed.decoded.kind === 'valid' && fed.admitted) {
      this.knownSources.add(sourceKey(e.remoteIPv4, fed.decoded.engineType, fed.decoded.engineId));
    }
    this.watch(e, fed.decoded, fed.admitted);
  }

  /** Engine admission and the source list: the Worker's own facts, replay included, and independent of the aggregator. */
  private admit(e: DatagramEvidence, decoded: ReturnType<typeof decodeV5>): boolean {
    if (decoded.kind !== 'valid') return false;
    const key = sourceKey(e.remoteIPv4, decoded.engineType, decoded.engineId);
    const admitted = this.admission.admit(key);
    if (admitted) this.knownSources.add(key);
    return admitted;
  }

  /**
   * One datagram into the health, if it arrived after the connect and has not been counted.
   * Stamped with its real age (`now()` less how long ago it was received) rather than with the
   * moment it is fed: the rebuild's later passes read entries that arrived minutes earlier, and
   * a source that went quiet meanwhile must not look fresh for another `staleMs`.
   */
  private watch(e: DatagramEvidence, decoded: ReturnType<typeof decodeV5>, admitted: boolean): void {
    const id = e.ref.entryId;
    if (id <= Math.max(this.healthFloor, this.healthThrough)) return;
    this.healthThrough = id;
    const age = Math.max(0, this.options.wallNow() - e.receivedMs);
    const timing = { elapsedMs: this.options.now() - age, wallMs: e.receivedMs };
    if (decoded.kind === 'valid') {
      this.observeDatagram(e.remoteIPv4, {
        kind: 'datagram', outcome: 'valid', engineType: decoded.engineType, engineId: decoded.engineId,
        sequence: decoded.sequence, flowCount: decoded.flows.length, entryId: id, admitted, ...timing,
      });
    } else {
      this.observeDatagram(e.remoteIPv4, { kind: 'datagram', outcome: decoded.kind, entryId: id, ...timing });
    }
  }

  /**
   * After a failure nothing is analyzed, but datagrams are still arriving and the health and the
   * source list are still true of them. Entries of another generation have ids that mean nothing
   * against this one's, so they are not counted.
   */
  private feedHealthOnly(entries: Evidence[]): void {
    if (this.shuttingDown) return;
    for (const e of entries) {
      if (e.kind !== 'datagram' || e.ref.generation !== this.generation) continue;
      const decoded = decodeV5(e, e.remoteIPv4);
      this.watch(e, decoded, this.admit(e, decoded));
    }
  }

  private async postDrained(runtime: HostRuntime): Promise<void> {
    // Whatever has been fed has been analyzed; what is rolled up is what the sidecar acknowledged.
    const live = this.aggregator.fedThrough > this.healthFloor;
    if (live) this.noteWatermark('analyzed', this.aggregator.fedThrough);
    const drained = this.aggregator.drain();
    if (drained === null) return;
    const minutes = drained.fragments.map((f) => ({
      sourceKey: f.rollup.sourceKey,
      minuteMs: f.rollup.minuteMs,
      bytes: encodeMinuteRollup(f.rollup, this.options.deflate),
    }));
    try {
      await runtime.appendMinutes(
        minutes, { generation: this.generation, throughEntryId: drained.watermark, policyVersion: DECODER_POLICY_VERSION }, drained.afterEntryId,
      );
    } catch (e) {
      // Only the sidecar's refusal; a RangeError from encoding the batch above is thrown before this.
      if (e instanceof RangeError) throw new AppendRefused(e.message);
      throw e;
    }
    this.refusals = 0;
    // Replay posts to the sidecar too, but it is history and updates nothing (R7.2).
    if (live) this.noteWatermark('rolled-up', drained.watermark);
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
        ...(runtime.archive !== undefined ? { archive: runtime.archive } : {}),
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
    // Taken before the first await, so this shutdown's own task is not in it.
    const running = [...this.tasks];
    this.shuttingDown = true;
    this.stopRebuild = true;
    this.disarmTick();
    this.cancelRetry?.();
    this.cancelRetry = null;
    for (const job of [...this.jobs.values()]) this.cancelJob(job);
    // The rebuild notices the flag at its next page, and an aborted query at its
    // next checkpoint: wait for both so that nothing is still posting to the
    // runtime after the reply. A read stuck in the runtime is not waited for
    // past a flush window - the Worker is terminated next either way.
    const settled = Promise.all([this.feedChain.catch(() => undefined), ...running]).then(() => undefined);
    const setTimer = this.options.setTimer;
    if (setTimer === undefined) await settled;
    else {
      let cancel: () => void = () => undefined;
      const bound = new Promise<void>((resolve) => { cancel = setTimer(resolve, LIMITS.flushMs); });
      await Promise.race([settled, bound]);
      cancel();
    }
    this.options.post({ type: 'shutdown-reply', requestId });
  }
}
