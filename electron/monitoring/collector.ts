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
import { deflateSync } from 'fflate';
import type { BlockFile } from '../../src/services/capture/blockFile';
import type { SegmentDirectory } from '../../src/services/monitoring/segments';
import { ArchiveStore, resumeExpiry, runExpiry, type ArchiveStatus } from '../../src/services/monitoring/archive';
import { readSourceConfig } from '../../src/services/monitoring/config';
import { isIntakeStopReason, type DiscardPreviewResult, type DiscardResult, type DiscardScope, type InspectResult, type IntakeStatus, type IntakeStopReason, type RetentionResult, type StartResult, type StopReason, type StopResult } from '../../src/services/monitoring/control';
import {
  DATASET_FILE, classifyAdoption, encodeDatasetFile, newDatasetFile, planMonitoringDiscard, readDatasetFile,
  type AdoptionResult, type DatasetFile,
} from '../../src/services/monitoring/datasetPlan';
import { MonitoringJournal, recoverJournal, type EvidenceInput, type JournalState } from '../../src/services/monitoring/journal';
import { FILE_HEADER_BYTES, generationFromHex, generationToHex } from '../../src/services/monitoring/journalCodec';
import { LiveFeed } from '../../src/services/monitoring/liveFeed';
import { LocalArchiveSource, LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { recordedSource } from '../../src/services/monitoring/queries';
import { DEFAULT_RETENTION, planExpiry, type ExpiryPlan, type RetentionPolicy } from '../../src/services/monitoring/retention';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { isSegmentFileName, type SegmentInfo } from '../../src/services/monitoring/segments';
import { RuntimeUnavailableError, archiveOf, type DatasetMeta, type HostRuntime } from '../../src/services/monitoring/runtime';
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

/**
 * The journal's segment directory, the rollup cache, the archive and the folder's names;
 * `electron/monitoring/volume.ts` opens the real ones. `removeFile`, `readText` and `writeText` work
 * by plain name and after `close()`: a discard closes every handle first, because Windows will not
 * unlink an open file.
 */
export interface CollectorVolume {
  segments: SegmentDirectory;
  rollups: BlockFile;
  archive: BlockFile;
  names(): string[];
  removeFile(name: string): void;
  readText(name: string): string | null;
  writeText(name: string, text: string): void;
  close(): void;
}

/** A folder looked at and not changed: no file is created, so a folder the user then walks away from is as it was. */
export interface CollectorFolder {
  names: string[];
  segments: SegmentDirectory;
  /** The archive file where one exists, else null. */
  archive: BlockFile | null;
  readText(name: string): string | null;
  close(): void;
}

export interface CollectorEnv {
  openVolume(root: string): CollectorVolume;
  openFolder(root: string): CollectorFolder;
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
const BUSY = 'Stop monitoring first: its data and where it is kept change only while it is stopped.';
const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GENERATION = /^[0-9a-f]{32}$/;

/** How often retention is looked at while a dataset is open; a step that expired something looks again at once. */
export const EXPIRY_CHECK_MS = 30_000;

const deflate = (bytes: Uint8Array): Uint8Array => deflateSync(bytes, { level: 1 });

/** A file a look must not change: writes and truncations go nowhere, so a scan that would repair reads as if it had. */
function unwritable(file: BlockFile): BlockFile {
  return {
    read: (offset, into) => file.read(offset, into),
    write: () => {},
    truncate: () => {},
    flush: () => {},
    size: () => file.size(),
    close: () => {},
  };
}

/** The sidecar a read-only adoption is given: `RollupStore` opened `readOnly` only asks its size, and a write here is a bug. */
const NO_SIDECAR: BlockFile = {
  read: () => 0,
  write: () => { throw new Error('a read-only dataset has no sidecar to write'); },
  truncate: () => { throw new Error('a read-only dataset has no sidecar to write'); },
  flush: () => {},
  size: () => 0,
  close: () => {},
};

/** What a folder is, and what an open may take from it, read without writing a byte. */
interface FolderLook {
  adoption: AdoptionResult;
  /** `dataset.json` where it parses, else null. */
  file: DatasetFile | null;
  /** The newest cut of an archive that belongs to this journal; 0 for any other, which is no evidence about it. */
  lastCut: number;
  /** The archive file as read, with the generation its header names; null where there is none. */
  archive: { status: ArchiveStatus; generation: string | null } | null;
}

/**
 * ADR 0061's adoption table over a folder, the one decision `inspect` and `openNow` share. It runs before
 * anything that can write is opened: `MonitoringJournal.open` unlinks, truncates and appends, and an archive
 * store truncates, so a dataset that is to be served read-only must be known to be one first.
 *
 * The journal is scanned once with no cut to learn its generation, and only an archive of that generation
 * lends its last cut: a cut from another dataset would move where the journal is thought to begin.
 */
function lookAtFolder(folder: CollectorFolder, isDefaultLocation: boolean): FolderLook {
  const early = classifyAdoption(folder.names, null, null, { isDefaultLocation });
  if (early.kind === 'refuse') return { adoption: early, file: null, lastCut: 0, archive: null };
  const hasSegments = folder.names.some(isSegmentFileName);
  const bare = hasSegments ? recoverJournal(folder.segments) : null;
  let archive: FolderLook['archive'] = null;
  let lastCut = 0;
  if (folder.archive !== null && folder.archive.size() > 0) {
    const { store, status } = ArchiveStore.open(unwritable(folder.archive), { generation: new Uint8Array(16), createdMs: 0 });
    const gen = store.generation();
    archive = { status, generation: gen === null ? null : generationToHex(gen) };
    if (archive.generation !== null && archive.generation === bare?.generation && status !== 'corrupt' && status !== 'failed') {
      lastCut = store.lastCut()?.throughEntryId ?? 0;
    }
  }
  const recovery = lastCut === 0 ? bare : recoverJournal(folder.segments, { lastCutThroughEntryId: lastCut });
  const file = readDatasetText(folder.readText(DATASET_FILE));
  const adoption = classifyAdoption(folder.names, recovery, archive, { isDefaultLocation, datasetGeneration: file?.generation ?? null });
  return { adoption, file, lastCut, archive };
}

/** `dataset.json` as a file to trust, or null where it is missing or does not parse: losing it loses a note and nothing else. */
function readDatasetText(text: string | null): DatasetFile | null {
  if (text === null) return null;
  const read = readDatasetFile(text);
  return read.ok ? read.file : null;
}

/** The exporter the journal's retained boundaries last name, paged so a long journal is not read at once. */
function recordedExporter(journal: MonitoringJournal): string | null {
  const snapshot = journal.snapshot();
  let found: string | null = null;
  let afterId = Math.max(0, snapshot.firstEntryId - 1);
  for (;;) {
    const page = journal.readBoundaries(snapshot, afterId, LIMITS.pageEntries);
    found = recordedSource(page.entries)?.exporterIPv4 ?? found;
    if (page.done || page.nextAfterId <= afterId) return found;
    afterId = page.nextAfterId;
  }
}

/** When the dataset's history starts: the archive's first cut, else the first retained entry. */
function firstRecordedMs(d: { journal: MonitoringJournal; archive: ArchiveStore | null }): number | null {
  const cut = d.archive?.cuts()[0];
  if (cut !== undefined) return cut.fromMs;
  return firstJournalMs(d.journal);
}

/** When the oldest entry the journal still holds was received; null for a journal with none. */
function firstJournalMs(journal: MonitoringJournal): number | null {
  const snapshot = journal.snapshot();
  if (snapshot.throughEntryId < snapshot.firstEntryId) return null;
  return journal.readPage(snapshot, snapshot.firstEntryId - 1, 1, LIMITS.pageBytes).entries[0]?.receivedMs ?? null;
}

/** A caller's size, clamped to `cap`. NaN and a non-positive number are refused, not clamped: `Math.min(NaN, cap)` is NaN, and a NaN bound compares false against every total, so it would read without a limit at all. */
function clampSize(n: number, cap: number): number {
  if (!(n > 0)) throw new RangeError(`a read size must be a positive number (got ${n})`);
  return Math.min(n, cap);
}

// --- the collector ---------------------------------------------------------------------------------------

interface Dataset {
  root: string;
  limitBytes: number;
  /** Null for a read-only adoption, which opens no volume: that would create files. */
  volume: CollectorVolume | null;
  /** The read handles a read-only adoption holds instead of a volume; null otherwise. */
  folder: CollectorFolder | null;
  journal: MonitoringJournal;
  rollups: RollupStore;
  /** Null only where its generation is another dataset's: then it is neither served nor written. */
  archive: ArchiveStore | null;
  local: LocalRuntime;
  /** Why the journal was opened read-only, in the scan's words; null where it is writable. */
  problem: string | null;
  /**
   * Adopted read-only (ADR 0061): the journal opened, but a file beside it belongs to another dataset or
   * cannot be read. Start is refused and nothing expires; `problem` says why.
   */
  readOnly: boolean;
  /** The exporter the dataset itself recorded; `IntakeStatus.datasetSource`. */
  recordedSource: string | null;
}

/** Where the dataset was last asked to open, so a discard can reopen it and a relocation can tell it moved. */
interface Location { root: string; limitBytes: number; isDefaultLocation: boolean }

interface InboxItem { bytes: Uint8Array; receivedMs: number; remoteIPv4: string; remotePort: number }

/** What a waiting Start can be told to stop doing. */
interface StartAbort { aborted: boolean; onAbort: (() => void) | null }

export class Collector {
  private disposed = false;
  private disposing: Promise<StopResult> | null = null;
  private chain: Promise<unknown> = Promise.resolve();

  private dataset: Dataset | null = null;
  private location: Location | null = null;
  private retention: RetentionPolicy = DEFAULT_RETENTION;
  private cancelExpiry: (() => void) | null = null;
  /** An expiry check is already due at once; a drain does not arm another. */
  private expirySoon = false;
  /** When the last check ran; a drain asks for one at most once a second. */
  private lastExpiryCheckMs = Number.NEGATIVE_INFINITY;
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
    appendMinutes: async (minutes, watermark, afterEntryId) => this.local().appendMinutes(minutes, watermark, afterEntryId),
    rollupStatus: async () => this.local().rollupStatus(),
    resetRollups: async () => this.local().resetRollups(),
    // The evidence bundle (ADR 0063): raw pages are bounded like `readPage`; the slice and the dataset's identity
    // are small; the archive's reads are bounded by `archiveReadBytes`, which refuses past it rather than clips.
    readRawPage: async (snapshot, afterId, maxEntries, maxBytes) => this.local().readRawPage(
      snapshot, afterId, clampSize(maxEntries, LIMITS.pageEntries), clampSize(maxBytes, LIMITS.pageBytes),
    ),
    bundleSlice: async (snapshot, fromMs, throughMs) => this.local().bundleSlice(snapshot, fromMs, throughMs),
    dataset: async () => this.local().dataset(),
    // No archive served over a journal that expired something is a refused archive (corrupt, failed, another
    // generation, read-only): unknown, never empty (`archiveOf`).
    archive: {
      read: async (sourceKey, from, to, maxBytes) => (await archiveOf(this.local())).read(
        sourceKey, from, to, clampSize(maxBytes, LIMITS.archiveReadBytes),
      ),
      coveredThroughMs: async () => (await archiveOf(this.local())).coveredThroughMs(),
      lastCut: async () => (await archiveOf(this.local())).lastCut(),
      sources: async () => (await archiveOf(this.local())).sources(),
      cuts: async () => (await archiveOf(this.local())).cuts(),
      summary: async (fromMs, toMs, firstRetained) => (await archiveOf(this.local())).summary(fromMs, toMs, firstRetained),
    },
  };

  private local(): LocalRuntime {
    if (this.dataset === null) throw new RuntimeUnavailableError('the monitoring dataset is not open');
    return this.dataset.local;
  }

  // --- public operations ----------------------------------------------------------------------------------

  /**
   * Opens the dataset and binds nothing. Already open at `root` answers ok and does nothing (ruling R2)
   * but takes the retention policy. Open somewhere else is a relocation: only while stopped, it closes
   * the dataset that is open and opens the one at `root`, moving nothing (ADR 0061).
   */
  open(root: string, limitBytes: number, opts: { isDefaultLocation?: boolean; retention?: RetentionPolicy } = {}): Promise<StartResult> {
    const isDefaultLocation = opts.isDefaultLocation ?? true;
    // Not through `run()`: a Start that arrived first is waiting for exactly this
    // and holds the chain, so queueing behind it would be a deadlock that only
    // the handshake deadline ends. `openNow` is synchronous and only reached
    // with no dataset, which nothing else in flight can be using.
    try {
      if (this.disposed) return Promise.resolve({ ok: false, message: 'monitoring has shut down' });
      if (opts.retention !== undefined) this.retention = opts.retention;
      if (this.dataset !== null) {
        if (this.dataset.root === root) {
          if (opts.retention !== undefined) this.armExpiry(0);
          return Promise.resolve({ ok: true });
        }
        return this.run(() => this.relocateOp(root, limitBytes, isDefaultLocation))
          .catch((e): StartResult => ({ ok: false, message: `monitoring could not open its dataset: ${message(e)}` }));
      }
      return Promise.resolve(this.openNow(root, limitBytes, isDefaultLocation));
    } catch (e) {
      return Promise.resolve({ ok: false, message: `monitoring could not open its dataset: ${message(e)}` });
    }
  }

  /**
   * What `root` would be if it were opened, read without writing a byte there (ADR 0061's adoption table).
   * The open dataset's own folder answers from the open dataset. Not on the chain: it touches nothing the
   * chain guards.
   */
  inspect(root: string, isDefaultLocation: boolean): InspectResult {
    try {
      const d = this.dataset;
      if (d !== null && d.root === root) {
        return { ok: true, kind: d.readOnly ? 'adopt-read-only' : 'adopt', truncatedTailBytes: null, problem: d.readOnly ? d.problem : null, exporterIPv4: d.recordedSource };
      }
      const folder = this.env.openFolder(root);
      try {
        const result = lookAtFolder(folder, isDefaultLocation).adoption;
        switch (result.kind) {
          case 'refuse':
            return { ok: false, reason: result.reason, message: result.message, ...(result.names === undefined ? {} : { names: result.names }) };
          case 'new':
            return { ok: true, kind: 'new', truncatedTailBytes: null, problem: null, exporterIPv4: null };
          case 'adopt':
            // Whose datagrams these are is read from the boundaries, which an open reads; the status carries it then.
            return { ok: true, kind: 'adopt', truncatedTailBytes: result.truncatedTailBytes, problem: null, exporterIPv4: null };
          case 'adopt-read-only':
            return { ok: true, kind: 'adopt-read-only', truncatedTailBytes: null, problem: result.problem, exporterIPv4: null };
        }
      } finally {
        folder.close();
      }
    } catch (e) {
      return { ok: false, reason: 'failed', message: `that folder could not be read: ${message(e)}` };
    }
  }

  /** Discards the whole dataset or its evidence before a date (ADR 0061). Only while stopped. */
  discard(scope: DiscardScope): Promise<DiscardResult> {
    return this.run(() => this.discardOp(scope))
      .catch((e): DiscardResult => ({ ok: false, reason: 'failed', message: `monitoring could not discard its data: ${message(e)}` }));
  }

  /**
   * What `discard(scope)` would do right now, from the same selection, without writing a byte: the figures
   * main's confirmation states (ADR 0061). On the chain, so it never reads a dataset a discard is changing.
   */
  discardPreview(scope: DiscardScope): Promise<DiscardPreviewResult> {
    return this.run(() => this.discardPreviewOp(scope))
      .catch((e): DiscardPreviewResult => ({ ok: false, reason: 'failed', message: `monitoring could not preview its discard: ${message(e)}` }));
  }

  /** A new retention policy, applied at once. Only while stopped, like the location and a discard. */
  setRetention(policy: RetentionPolicy): Promise<RetentionResult> {
    return this.run((): RetentionResult => {
      if (this.disposed) return { ok: false, reason: 'failed', message: 'monitoring has shut down' };
      if (this.session !== null) return { ok: false, reason: 'busy', message: BUSY };
      this.retention = policy;
      if (this.dataset !== null) this.armExpiry(0);
      return { ok: true };
    }).catch((e): RetentionResult => ({ ok: false, reason: 'failed', message: `monitoring could not change its retention: ${message(e)}` }));
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
    const readOnly = this.dataset?.readOnly === true;
    const journalState = this.dataset?.journal.state ?? null;
    // Adopted read-only is reported as the damaged journal it is to the sheet: served, never written.
    const storage: IntakeStatus['storage'] = readOnly ? 'refused-corrupt' : journalState ?? this.storageWithoutDataset;
    const storageError = readOnly ? this.dataset?.problem ?? describeStorage('refused-corrupt')
      : journalState === 'open' ? null
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
      datasetSource: this.dataset?.recordedSource ?? null,
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

  /**
   * Opens the dataset at `root` (ADR 0061's adoption table). A foreign name refuses before a file is
   * created; a discard a crash interrupted is finished first; a dataset whose files disagree opens
   * read-only, served and never written.
   */
  private openNow(root: string, limitBytes: number, isDefaultLocation: boolean): StartResult {
    this.location = { root, limitBytes, isDefaultLocation };
    // Classified before anything that can write is opened: `MonitoringJournal.open` repairs, and a dataset
    // that is to be served read-only must come out of this untouched.
    let look: FolderLook;
    try {
      look = this.lookAt(root, isDefaultLocation);
      const marker = look.adoption.kind === 'refuse' ? null : look.file?.discarding ?? null;
      if (marker !== null) {
        // A discard a crash interrupted is the one write a look leads to, and the user asked for it.
        const volume = this.env.openVolume(root);
        volume.close();
        this.finishDiscard(volume, marker, isDefaultLocation);
        look = this.lookAt(root, isDefaultLocation);
      }
    } catch (e) {
      return this.openFailed('failed', `the monitoring folder could not be read: ${message(e)}`);
    }
    const adoption = look.adoption;
    if (adoption.kind === 'refuse') return this.openFailed(adoption.reason === 'refused-version' ? 'refused-version' : 'failed', adoption.message);

    const built = adoption.kind === 'adopt-read-only'
      ? this.openReadOnly(root, limitBytes, look, adoption.problem)
      : this.openWritable(root, limitBytes, look);
    if ('ok' in built) return built;
    this.dataset = built;
    this.storageProblem = null;
    // A Worker already attached is serving the dataset that was closed: tell it before the feed re-attaches,
    // so on the one port the notice is ahead of every live push the new dataset makes. Writable and read-only
    // adoptions both come through here; no port (a first open) means nothing to tell.
    this.server?.notifyReopened();
    this.attachFeedIfReady();
    this.armExpiry(0);
    this.publish();
    this.wake();
    return { ok: true };
  }

  private lookAt(root: string, isDefaultLocation: boolean): FolderLook {
    const folder = this.env.openFolder(root);
    try { return lookAtFolder(folder, isDefaultLocation); } finally { folder.close(); }
  }

  /**
   * A new dataset or one that adopts: the volume is opened (it creates the sidecar and the archive), and
   * the journal may repair what a crash left. Only reached once `lookAtFolder` has said it may.
   */
  private openWritable(root: string, limitBytes: number, look: FolderLook): Dataset | StartResult {
    let volume: CollectorVolume;
    try {
      volume = this.env.openVolume(root);
    } catch (e) {
      return this.openFailed('failed', `the monitoring folder could not be opened: ${message(e)}`);
    }
    const holder: { rollups: RollupStore | null; archive: ArchiveStore | null } = { rollups: null, archive: null };
    try {
      // An archive with a header is read before the journal, which needs its last cut to finish an
      // interrupted drop. One without is written after it, with the journal's generation.
      let archiveStatus: ArchiveStatus = 'ok';
      if (volume.archive.size() >= FILE_HEADER_BYTES) {
        const opened = ArchiveStore.open(volume.archive, { generation: new Uint8Array(16), createdMs: this.env.now() });
        holder.archive = opened.store;
        archiveStatus = opened.status;
      }
      const { journal, recovery } = MonitoringJournal.open(volume.segments, {
        limitBytes,
        // One limit covers every file.
        otherBytes: () => (holder.rollups?.size() ?? 0) + (holder.archive?.bytes() ?? 0),
        randomBytes: this.env.randomBytes,
        nowMs: this.env.now,
        lastCutThroughEntryId: look.lastCut,
      });
      const snapshot = journal.snapshot();
      // A file with no readable header has no generation to serve a query
      // against. It is left exactly as it was, and the user is told why.
      if (!GENERATION.test(snapshot.generation)) {
        volume.close();
        return this.openFailed(journal.state, recovery.problem ?? 'the monitoring journal cannot be read');
      }
      if (holder.archive === null) {
        const opened = ArchiveStore.open(volume.archive, { generation: generationFromHex(snapshot.generation), createdMs: this.env.now() });
        holder.archive = opened.store;
        archiveStatus = opened.status;
      }
      const archiveGeneration = holder.archive.generation();
      const archiveHex = archiveGeneration === null ? null : generationToHex(archiveGeneration);
      // Another dataset's archive is neither served nor written.
      const archive = archiveHex === snapshot.generation && archiveStatus !== 'corrupt' && archiveStatus !== 'failed' ? holder.archive : null;

      const opened = RollupStore.open(volume.rollups, {
        generation: snapshot.generation, throughEntryId: snapshot.throughEntryId, policyVersion: DECODER_POLICY_VERSION,
      }, { nowMs: this.env.now, readOnly: false });
      holder.rollups = opened.store;
      const writable = journal.state === 'open';
      // An expiry a crash interrupted is finished before the cache answers anything.
      if (writable && archive !== null && resumeExpiry(journal, opened.store, archive, this.env.now()) === 'failed') {
        this.env.log?.('monitoring: an interrupted expiry could not be finished; the next check tries again');
      }
      const file = look.file;
      let meta: DatasetMeta | undefined = file !== null && file.generation === snapshot.generation
        ? { generation: file.generation, createdMs: file.createdMs, replaced: file.replaced }
        : undefined;
      if (writable && (file === null || file.generation !== snapshot.generation)) {
        const base = file ?? newDatasetFile(snapshot.generation, this.env.now());
        volume.writeText(DATASET_FILE, encodeDatasetFile({ ...base, generation: snapshot.generation, discarding: null }));
        meta = { generation: snapshot.generation, createdMs: base.createdMs, replaced: base.replaced };
      }
      return this.assemble({
        root, limitBytes, volume, folder: null, journal, rollups: opened, archive, meta,
        problem: journal.state === 'open' ? null : recovery.problem ?? null, readOnly: false,
      });
    } catch (e) {
      try { volume.close(); } catch { /* the first failure is the one to report */ }
      return this.openFailed('failed', `the monitoring dataset could not be opened: ${message(e)}`);
    }
  }

  /**
   * A dataset whose files disagree or whose journal is damaged (ADR 0061): served from read handles, with
   * nothing written. There is no volume to open, so no sidecar or archive is created; the journal does not
   * repair a torn tail, finish a drop or close a session, and the archive store sees an `unwritable` file.
   * The sidecar is a cache and is simply not served: queries answer from the journal.
   */
  private openReadOnly(root: string, limitBytes: number, look: FolderLook, problem: string): Dataset | StartResult {
    let folder: CollectorFolder;
    try {
      folder = this.env.openFolder(root);
    } catch (e) {
      return this.openFailed('failed', `the monitoring folder could not be read: ${message(e)}`);
    }
    try {
      const { journal, recovery } = MonitoringJournal.open(folder.segments, {
        limitBytes, randomBytes: this.env.randomBytes, nowMs: this.env.now, lastCutThroughEntryId: look.lastCut, readOnly: true,
      });
      const snapshot = journal.snapshot();
      if (!GENERATION.test(snapshot.generation)) {
        folder.close();
        return this.openFailed(journal.state, recovery.problem ?? 'the monitoring journal cannot be read');
      }
      // Another dataset's archive, or one that cannot be read, is not served.
      const served = look.archive !== null && look.archive.generation === snapshot.generation
        && look.archive.status !== 'corrupt' && look.archive.status !== 'failed' && folder.archive !== null;
      const archive = served
        ? ArchiveStore.open(unwritable(folder.archive!), { generation: new Uint8Array(16), createdMs: this.env.now() }).store
        : null;
      const rollups = RollupStore.open(NO_SIDECAR, {
        generation: snapshot.generation, throughEntryId: snapshot.throughEntryId, policyVersion: DECODER_POLICY_VERSION,
      }, { nowMs: this.env.now, readOnly: true });
      // Only a dataset.json that is this journal's names it; without one the bundle has no identity to write.
      const meta: DatasetMeta | undefined = look.file !== null && look.file.generation === snapshot.generation
        ? { generation: look.file.generation, createdMs: look.file.createdMs, replaced: look.file.replaced }
        : undefined;
      return this.assemble({ root, limitBytes, volume: null, folder, journal, rollups, archive, meta, problem, readOnly: true });
    } catch (e) {
      try { folder.close(); } catch { /* the first failure is the one to report */ }
      return this.openFailed('failed', `the monitoring dataset could not be opened: ${message(e)}`);
    }
  }

  /** What both opens end in: the last stop's reason, read back, and the runtime the Worker queries. */
  private assemble(p: {
    root: string; limitBytes: number; volume: CollectorVolume | null; folder: CollectorFolder | null;
    journal: MonitoringJournal; rollups: ReturnType<typeof RollupStore.open>; archive: ArchiveStore | null;
    problem: string | null; readOnly: boolean; meta?: DatasetMeta;
  }): Dataset {
    // The last run's stop survives the relaunch in the journal's own boundary. A run that ended
    // without one leaves `interrupted` or a bare `start`, and its reason has no copy, so none is invented.
    if (this.stopReason === null && this.session === null) {
      const last = p.journal.lastBoundary();
      if (last !== null && last.action === 'stop' && isIntakeStopReason(last.reason)) this.stopReason = last.reason;
    }
    const local = new LocalRuntime(p.journal, p.rollups.store, {
      status: p.rollups.status, ...(p.rollups.reason === undefined ? {} : { reason: p.rollups.reason }),
    }, p.archive === null ? undefined : new LocalArchiveSource(p.archive), p.meta);
    return {
      root: p.root, limitBytes: p.limitBytes, volume: p.volume, folder: p.folder, journal: p.journal, rollups: p.rollups.store,
      archive: p.archive, local, problem: p.problem, readOnly: p.readOnly, recordedSource: recordedExporter(p.journal),
    };
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
    this.cancelExpiryTimer();
    // The feed counted this journal's entry ids; the next one's start again.
    this.feed.detach();
    try { dataset.journal.close(); } catch { /* the volume closes regardless */ }
    try { dataset.volume?.close(); } catch { /* nothing more to do with a file that will not close */ }
    try { dataset.folder?.close(); } catch { /* nor with a handle that will not close */ }
  }

  private relocateOp(root: string, limitBytes: number, isDefaultLocation: boolean): StartResult {
    if (this.disposed) return { ok: false, message: 'monitoring has shut down' };
    if (this.dataset !== null && this.dataset.root === root) return { ok: true };
    if (this.session !== null) return { ok: false, message: BUSY };
    this.closeDataset('closed');
    return this.openNow(root, limitBytes, isDefaultLocation);
  }

  // --- discard (ADR 0061) ----------------------------------------------------------------------------------------------

  private discardOp(scope: DiscardScope): DiscardResult {
    if (this.disposed) return { ok: false, reason: 'failed', message: 'monitoring has shut down' };
    if (this.session !== null) return { ok: false, reason: 'busy', message: BUSY };
    return scope.scope === 'all' ? this.discardAll() : this.discardBefore(scope.beforeMs);
  }

  /**
   * The sealed segments that end before `beforeMs`, one at a time through the expiry a policy runs: their
   * minutes stay in the archive, and the journal records an `expired` boundary.
   */
  private discardBefore(beforeMs: number): DiscardResult {
    const refused = this.cannotExpire();
    if (refused !== null) return { ok: false, reason: 'failed', message: refused };
    let removed = 0;
    for (;;) {
      const step = this.expireStep(beforeMs);
      if (step === 'none') break;
      if (step === 'failed') {
        this.feed.notify();
        this.publish();
        return { ok: false, reason: 'failed', message: `the evidence before that date could not all be discarded; ${removed} segment(s) were` };
      }
      removed++;
    }
    this.feed.notify();
    this.publish();
    return { ok: true, removedSegments: removed };
  }

  /** Why a discard before a date cannot run (no dataset, or one served read-only), or null where it can. */
  private cannotExpire(): string | null {
    const d = this.dataset;
    if (d === null) return 'the monitoring dataset is not open';
    if (d.readOnly || d.archive === null) return d.problem ?? 'the monitoring dataset cannot be written';
    return null;
  }

  private discardPreviewOp(scope: DiscardScope): DiscardPreviewResult {
    if (this.disposed) return { ok: false, reason: 'failed', message: 'monitoring has shut down' };
    if (this.session !== null) return { ok: false, reason: 'busy', message: BUSY };
    if (scope.scope === 'all') return this.previewAll();
    const refused = this.cannotExpire();
    if (refused !== null) return { ok: false, reason: 'failed', message: refused };
    const d = this.dataset;
    // The selection `discardBefore` loops over one segment at a time, taken whole.
    const due = d === null ? null : this.dueSegments(d, scope.beforeMs);
    if (d === null || due === null) return { ok: true, scope: 'before', segments: 0, fromMs: null, throughMs: null, cutMs: null };
    return {
      ok: true, scope: 'before', segments: due.plan.segments.length,
      fromMs: firstJournalMs(d.journal), throughMs: null, cutMs: due.plan.throughMs,
    };
  }

  /** The whole discard's figures: what `planMonitoringDiscard` would remove from the folder as it is, read without opening a writer. */
  private previewAll(): DiscardPreviewResult {
    const at = this.location;
    if (at === null) return { ok: false, reason: 'failed', message: 'no monitoring folder has been opened' };
    const d = this.dataset;
    let names: string[];
    if (d?.volume != null) names = d.volume.names();
    else if (d?.folder != null) names = d.folder.names;
    else {
      const folder = this.env.openFolder(at.root);
      try { names = [...folder.names]; } finally { folder.close(); }
    }
    const segments = planMonitoringDiscard(names, { isDefaultLocation: at.isDefaultLocation }).remove.filter(isSegmentFileName).length;
    let fromMs: number | null = null;
    let throughMs: number | null = null;
    if (d !== null) {
      try {
        fromMs = firstRecordedMs(d);
        throughMs = d.journal.segments().at(-1)?.lastReceivedMs ?? null;
      } catch { /* a journal that cannot be read gives no range; the segments are still counted */ }
    }
    return { ok: true, scope: 'all', segments, fromMs, throughMs, cutMs: null };
  }

  /**
   * The whole dataset. The marker goes first, so an open after a crash part-way finishes the deletion;
   * then what `planMonitoringDiscard` names, newest segment first; then a `dataset.json` that says what
   * was replaced. Nothing it does not name is touched, and the folder itself stays.
   */
  private discardAll(): DiscardResult {
    const at = this.location;
    if (at === null) return { ok: false, reason: 'failed', message: 'no monitoring folder has been opened' };
    const d = this.dataset;
    const volume = d?.volume ?? this.env.openVolume(at.root);
    const file = readDatasetText(volume.readText(DATASET_FILE));
    const journalGeneration = d?.journal.snapshot().generation ?? '';
    const generation = GENERATION.test(journalGeneration) ? journalGeneration : file?.generation ?? toHex(this.env.randomBytes(16));
    const fromMs = (d === null ? null : firstRecordedMs(d)) ?? file?.createdMs ?? this.env.now();
    const lastMs = d?.journal.segments().at(-1)?.lastReceivedMs ?? fromMs;
    const marker = { generation, fromMs, throughMs: Math.max(fromMs, lastMs) };
    volume.writeText(DATASET_FILE, encodeDatasetFile({ ...(file ?? newDatasetFile(generation, fromMs)), generation, discarding: marker }));
    if (d !== null) this.closeDataset('closed');
    // A volume opened for this discard (none was open, or the dataset was read-only) is closed here.
    if (d?.volume == null) volume.close();
    const removed = this.finishDiscard(volume, marker, at.isDefaultLocation);
    const reopened = this.openNow(at.root, at.limitBytes, at.isDefaultLocation);
    // The data is gone either way; a reply that only said "failed" would read as nothing discarded.
    if (!reopened.ok) {
      return { ok: false, reason: 'failed', message: `the dataset was discarded (${removed} segment(s)), but its folder could not be opened again: ${reopened.message}` };
    }
    return { ok: true, removedSegments: removed };
  }

  /** Removes what a discard removes from a closed volume, then writes the note. Returns how many segments went. */
  private finishDiscard(volume: CollectorVolume, marker: NonNullable<DatasetFile['discarding']>, isDefaultLocation: boolean): number {
    let segments = 0;
    for (const name of planMonitoringDiscard(volume.names(), { isDefaultLocation }).remove) {
      // Last, and rewritten rather than removed: it is where the marker lives until the rest is gone.
      if (name === DATASET_FILE) continue;
      volume.removeFile(name);
      if (isSegmentFileName(name)) segments++;
    }
    const now = this.env.now();
    // The old generation until an open writes the new journal's; the note is what matters.
    volume.writeText(DATASET_FILE, encodeDatasetFile({
      ...newDatasetFile(marker.generation, now),
      replaced: { discardedAtMs: now, previousGeneration: marker.generation, previousFromMs: marker.fromMs, previousThroughMs: marker.throughMs },
    }));
    return segments;
  }

  // --- retention -------------------------------------------------------------------------------------------------------

  /**
   * One sealed segment through `runExpiry`, if the policy (or `beforeMs`) says the oldest is due. One at a
   * time because a run holds its segments' entries in memory: a segment is bounded, a plan's prefix is not.
   */
  private expireStep(beforeMs?: number): 'done' | 'none' | 'failed' {
    const d = this.dataset;
    if (d === null) return 'none';
    const due = this.dueSegments(d, beforeMs);
    if (due === null || d.archive === null) return 'none';
    const { plan, segments } = due;
    const first = segments[0];
    const one: ExpiryPlan = { segments: [first.name], throughEntryId: first.lastEntryId, throughMs: first.lastReceivedMs, reason: plan.reason };
    if (runExpiry(d.journal, d.rollups, d.archive, one, { nowMs: this.env.now(), deflate }) === 'failed') return 'failed';
    // A journal that stopped at its limit takes appends again once the drop made room (`setLimit`'s contract).
    if (d.journal.state === 'storage-limit') d.journal.setLimit(d.limitBytes);
    if (d.journal.state === 'open') d.problem = null;
    d.recordedSource = recordedExporter(d.journal) ?? d.recordedSource;
    return 'done';
  }

  /**
   * Which sealed segments are due, the one decision `expireStep` and a discard's preview share, so the cut a
   * dialog states is the cut that runs. Null where nothing is due or the dataset cannot expire anything
   * (read-only, or a journal that is neither open nor at its limit). `segments` is the journal's, oldest first.
   */
  private dueSegments(d: Dataset, beforeMs?: number): { plan: ExpiryPlan; segments: SegmentInfo[] } | null {
    if (d.readOnly || d.archive === null) return null;
    if (d.journal.state !== 'open' && d.journal.state !== 'storage-limit') return null;
    const segments = d.journal.segments();
    let used = d.rollups.size() + d.archive.bytes();
    for (const s of segments) used += s.bytes;
    const plan = planExpiry(segments, this.retention, this.env.now(), used, d.limitBytes, beforeMs);
    return plan === null ? null : { plan, segments };
  }

  private armExpiry(ms: number = EXPIRY_CHECK_MS): void {
    this.cancelExpiryTimer();
    // A policy that keeps everything until the limit stops intake expires nothing on its own; no timer stands for it.
    if (this.retention.keepRawDays === null && this.retention.atLimit === 'stop') return;
    this.expirySoon = ms === 0;
    this.cancelExpiry = this.env.setTimer(() => {
      this.cancelExpiry = null;
      this.expirySoon = false;
      void this.run(() => this.expiryTick()).catch((e) => this.env.log?.(`monitoring retention: ${message(e)}`));
    }, ms);
  }

  private cancelExpiryTimer(): void {
    this.cancelExpiry?.();
    this.cancelExpiry = null;
    this.expirySoon = false;
  }

  private expiryTick(): void {
    if (this.disposed || this.dataset === null) return;
    this.lastExpiryCheckMs = this.env.now();
    const step = this.expireStep();
    if (step === 'done') {
      this.feed.notify();
      this.publish();
    } else if (step === 'failed') {
      this.env.log?.('monitoring retention: an expiry step failed; the next check tries again');
    }
    if (this.dataset !== null && this.cancelExpiry === null) this.armExpiry(step === 'done' ? 0 : EXPIRY_CHECK_MS);
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
        if (this.location !== null) this.location.limitBytes = config.storageLimitBytes;
        // The journal may have stopped at the old limit; its refusal text went with that state.
        if (this.dataset.journal.state === 'open') this.dataset.problem = null;
        this.publish();
      }
      const dataset = this.dataset;
      if (dataset === null) return { ok: false, message: 'the monitoring dataset is not open' };
      if (dataset.readOnly) {
        return { ok: false, message: `this monitoring dataset can be read but not added to: ${dataset.problem ?? 'its files disagree'}` };
      }
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
        // Recorded so a segment rolled mid-session, and one that outlives its predecessors, says whose datagrams it holds (ADR 0062).
        source: { exporterIPv4: config.exporterIPv4, bindIPv4: config.bindIPv4, port: config.port },
      }]);
      if (appended.appended !== 1) {
        this.closeSocket();
        return this.startFailed(`the journal refused the start of a session: ${describeStorage(appended.state)}`, true);
      }

      this.session = { id, config };
      dataset.recordedSource = config.exporterIPv4;
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
    // Near the limit with expire-oldest, the oldest segment goes before the journal stops taking datagrams.
    if (this.retention.atLimit === 'expire-oldest' && !this.expirySoon && this.env.now() - this.lastExpiryCheckMs >= 1000) this.armExpiry(0);
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
