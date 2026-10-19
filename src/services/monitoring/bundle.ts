/**
 * The evidence bundle, `.iwmon` (ADR 0063): a range of the journal as it lies in the file, the archive's
 * minutes for what expired out of it, and the manifest that says exactly what is and is not in it.
 *
 * It is a file in the journal's own framing (`journalCodec.ts`), under the magic `INWIREMB`: a 64-byte header
 * (format 1, decoder policy 0, the dataset's generation), then entries with ids 1, 2, 3, and so on.
 *
 * - kind 1, the manifest, always entry 1 (JSON, in the key order `BundleManifest` declares);
 * - kind 2, one per journal entry in the range: a 16-byte prefix (the journal's entry id, its kind, its
 *   segment's decoder policy) and then the entry's body exactly as the journal holds it;
 * - kind 3, one per archived minute: the archive's fragment body whole;
 * - kind 4 is reserved and never written;
 * - kind 5, the end, always last: the counts a reader checks what it read against.
 *
 * `bundleStream` is the Worker's half: it reads the runtime and yields whole framed entries a page at a time,
 * so no more than a page is ever held. `exportBundle` is the renderer's: it pulls those chunks one request at a
 * time into a `ByteSink` and owns the sink's end. The range is frozen when the export opens; anything that moves
 * under it (an expiry, a cut, a reopen) fails the export `changed` rather than writing a bundle whose manifest
 * disagrees with its entries.
 *
 * No `node:*` and no Electron, like everything under `src/services/`.
 */
import { appVersion } from '../../lib/appVersion';
import type { SaveOutcome } from '../../lib/saveFile';
import type { ByteSink } from '../../lib/saveSink';
import { encodeArchiveFragmentBody, type ArchiveCut, type ArchivedMinute } from './archive';
import { ExportCancelled } from './exportCancelled';
import { ExpiredRangeError, StaleGenerationError } from './journal';
import {
  ENTRY_HEADER_BYTES, FILE_HEADER_BYTES, encodeEntry, encodeFileHeader, generationFromHex, type Framing,
} from './journalCodec';
import { NO_ARCHIVE, RuntimeUnavailableError, type DatasetMeta, type MonitoringRuntime } from './runtime';
import { LIMITS, type RawEntry, type SegmentSource } from './types';

export const BUNDLE_FRAMING: Framing = { magic: 'INWIREMB', maxBodyBytes: 1 << 20 };

export const BUNDLE_KIND_MANIFEST = 1;
export const BUNDLE_KIND_JOURNAL = 2;
export const BUNDLE_KIND_ARCHIVE = 3;
/** Reserved for a later format; never written. */
export const BUNDLE_KIND_CHECKPOINT = 4;
export const BUNDLE_KIND_END = 5;

/** A kind-2 entry's prefix: u64 journal entry id, u8 kind, u8 zero, u16 policy, u32 zero. */
export const JOURNAL_PREFIX_BYTES = 16;

const BUNDLE_FORMAT = 1;
/** The header's decoder policy: a bundle is not read under any decoder, so it names none. */
const HEADER_POLICY = 0;
const MINUTE_MS = 60_000;

const utf8 = new TextEncoder();

// --- the manifest -----------------------------------------------------------------------------------------

export interface BundleManifest {
  bundleFormat: 1;
  inwireVersion: string;
  exportedMs: number;
  dataset: { generation: string; createdMs: number; replaced: DatasetMeta['replaced'] };
  range: { fromMs: number; throughMs: number };
  journal: { firstEntryId: number; throughEntryId: number; policies: number[] } | null;
  sessionAtStart: { sessionId: string; source: SegmentSource | null; startEntryId: number | null } | null;
  archive: { minutes: number; policies: number[] };
  history: { cuts: { fromEntryId: number; throughEntryId: number; fromMs: number; throughMs: number; reason: ArchiveCut['reason'] }[] };
}

/** The manifest's bytes, built key by key: the order is part of the format, whatever order the caller's object has. */
function manifestJson(m: BundleManifest): string {
  const source = (s: SegmentSource | null) => s === null ? null : { exporterIPv4: s.exporterIPv4, bindIPv4: s.bindIPv4, port: s.port };
  return JSON.stringify({
    bundleFormat: m.bundleFormat,
    inwireVersion: m.inwireVersion,
    exportedMs: m.exportedMs,
    dataset: {
      generation: m.dataset.generation,
      createdMs: m.dataset.createdMs,
      replaced: m.dataset.replaced === null ? null : {
        discardedAtMs: m.dataset.replaced.discardedAtMs,
        previousGeneration: m.dataset.replaced.previousGeneration,
        previousFromMs: m.dataset.replaced.previousFromMs,
        previousThroughMs: m.dataset.replaced.previousThroughMs,
      },
    },
    range: { fromMs: m.range.fromMs, throughMs: m.range.throughMs },
    journal: m.journal === null ? null : {
      firstEntryId: m.journal.firstEntryId, throughEntryId: m.journal.throughEntryId, policies: m.journal.policies,
    },
    sessionAtStart: m.sessionAtStart === null ? null : {
      sessionId: m.sessionAtStart.sessionId, source: source(m.sessionAtStart.source), startEntryId: m.sessionAtStart.startEntryId,
    },
    archive: { minutes: m.archive.minutes, policies: m.archive.policies },
    history: {
      cuts: m.history.cuts.map((c) => ({
        fromEntryId: c.fromEntryId, throughEntryId: c.throughEntryId, fromMs: c.fromMs, throughMs: c.throughMs, reason: c.reason,
      })),
    },
  });
}

// --- the encoders: whole framed entries, ids supplied by the caller ------------------------------------------

function concat(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export function encodeBundleHeader(generation: Uint8Array, createdMs: number): Uint8Array {
  return encodeFileHeader(BUNDLE_FRAMING, { generation, createdMs, formatVersion: BUNDLE_FORMAT, policyVersion: HEADER_POLICY });
}

/** The manifest as bundle entry 1. */
export function encodeBundleManifest(manifest: BundleManifest): Uint8Array {
  return encodeEntry(BUNDLE_FRAMING, 1, BUNDLE_KIND_MANIFEST, utf8.encode(manifestJson(manifest)));
}

/** Journal entries as kind-2 entries with bundle ids `firstBundleId`, `firstBundleId + 1`, and so on. */
export function encodeBundleEntries(entries: RawEntry[], firstBundleId: number): Uint8Array {
  const parts: Uint8Array[] = [];
  entries.forEach((e, i) => {
    if (e.body.length > LIMITS.maxBodyBytes) throw new RangeError(`a journal body of ${e.body.length} bytes is over the ${LIMITS.maxBodyBytes} cap`);
    const body = new Uint8Array(JOURNAL_PREFIX_BYTES + e.body.length);
    const v = new DataView(body.buffer);
    v.setBigUint64(0, BigInt(e.entryId), true);
    body[8] = e.kind;
    v.setUint16(10, e.policy, true);
    body.set(e.body, JOURNAL_PREFIX_BYTES);
    parts.push(encodeEntry(BUNDLE_FRAMING, firstBundleId + i, BUNDLE_KIND_JOURNAL, body));
  });
  return concat(parts);
}

/** Archived minutes as kind-3 entries; each body is the archive's own fragment body. */
export function encodeBundleArchive(minutes: ArchivedMinute[], firstBundleId: number): Uint8Array {
  return concat(minutes.map((m, i) => encodeEntry(BUNDLE_FRAMING, firstBundleId + i, BUNDLE_KIND_ARCHIVE, encodeArchiveFragmentBody(m))));
}

export function encodeBundleEnd(counts: { journalEntries: number; archivedMinutes: number }, bundleId: number): Uint8Array {
  const body = JSON.stringify({ journalEntries: counts.journalEntries, archivedMinutes: counts.archivedMinutes });
  return encodeEntry(BUNDLE_FRAMING, bundleId, BUNDLE_KIND_END, utf8.encode(body));
}

// --- errors -------------------------------------------------------------------------------------------------

/**
 * Why an export stopped. `changed`: the dataset moved under it. `history-lost`: the archive could not give
 * its minutes back. `runtime-unavailable`: the runtime did not answer. `cancelled`: another export or the
 * user ended it. The last two are the host's own: a read that failed, and a request that was not one.
 */
export type BundleErrorCode = 'changed' | 'history-lost' | 'runtime-unavailable' | 'cancelled' | 'storage-failed' | 'invalid-request';

export class BundleError extends Error {
  constructor(readonly code: BundleErrorCode, message: string) {
    super(message);
    this.name = 'BundleError';
  }
}

/** A runtime error as the export's: an expired or replaced range is `changed`, an unreachable runtime is not. */
function asBundleError(e: unknown): unknown {
  if (e instanceof StaleGenerationError || e instanceof ExpiredRangeError) {
    return new BundleError('changed', 'the dataset changed while the bundle was being written (its history was expired or replaced)');
  }
  if (e instanceof RuntimeUnavailableError) return new BundleError('runtime-unavailable', e.message);
  return e;
}

// --- the Worker's half --------------------------------------------------------------------------------------

export interface BundleOptions { exportedMs: number; inwireVersion: string }

/**
 * Yields the bundle as whole framed entries: the header and the manifest, then a chunk per raw page of at most
 * `LIMITS.pageEntries` and `pageBytes`, then the archive's minutes a window at a time, then the end. A range is
 * `[fromMs, toMs)`; the manifest says `throughMs`, the last millisecond in it.
 */
export async function* bundleStream(
  runtime: MonitoringRuntime, range: { fromMs: number; toMs: number }, opts: BundleOptions, signal?: AbortSignal,
): AsyncGenerator<Uint8Array, void, undefined> {
  if (!Number.isSafeInteger(range.fromMs) || range.fromMs < 0 || !Number.isSafeInteger(range.toMs) || range.toMs <= range.fromMs) {
    throw new BundleError('invalid-request', 'a bundle covers a range of whole milliseconds that ends after it starts');
  }
  const throughMs = range.toMs - 1;
  const archive = runtime.archive ?? NO_ARCHIVE;
  /** Every runtime call goes through here: a cancel is seen before it, an expiry or an outage is the export's own error. */
  const ask = async <T>(call: () => Promise<T>): Promise<T> => {
    if (signal?.aborted) throw new BundleError('cancelled', 'the export was cancelled');
    try { return await call(); } catch (e) { throw asBundleError(e); }
  };
  const changed = (what: string): BundleError => new BundleError('changed', `the dataset changed while the bundle was being written (${what})`);

  // Frozen now: everything the manifest says is read here, once.
  const meta = await ask(() => runtime.dataset());
  const snapshot = await ask(() => runtime.snapshot());
  if (snapshot.generation !== meta.generation) throw changed('the journal is not the dataset it was opened as');
  const cutsAtOpen = await ask(() => archive.cuts());
  const frozen = { generation: snapshot.generation, throughEntryId: snapshot.throughEntryId };
  const slice = await ask(() => runtime.bundleSlice(frozen, range.fromMs, throughMs));
  const summary = await ask(() => archive.summary(range.fromMs, range.toMs));
  if (summary === 'history-lost') throw new BundleError('history-lost', 'the archive of expired history could not be read');

  const manifest: BundleManifest = {
    bundleFormat: BUNDLE_FORMAT,
    inwireVersion: opts.inwireVersion,
    exportedMs: opts.exportedMs,
    dataset: { generation: meta.generation, createdMs: meta.createdMs, replaced: meta.replaced },
    range: { fromMs: range.fromMs, throughMs },
    journal: slice === null ? null : { firstEntryId: slice.firstEntryId, throughEntryId: slice.throughEntryId, policies: slice.policies },
    sessionAtStart: slice === null ? null : slice.sessionAtStart,
    archive: { minutes: summary.minutes, policies: summary.policies },
    history: {
      cuts: cutsAtOpen
        .filter((c) => c.fromMs <= throughMs && c.throughMs >= range.fromMs)
        .map((c) => ({ fromEntryId: c.fromEntryId, throughEntryId: c.throughEntryId, fromMs: c.fromMs, throughMs: c.throughMs, reason: c.reason })),
    },
  };
  yield concat([encodeBundleHeader(generationFromHex(meta.generation), opts.exportedMs), encodeBundleManifest(manifest)]);

  let nextBundleId = 2;

  let journalEntries = 0;
  if (slice !== null) {
    let after = slice.firstEntryId - 1;
    const upTo = { generation: snapshot.generation, throughEntryId: slice.throughEntryId };
    for (;;) {
      const page = await ask(() => runtime.readRawPage(upTo, after, LIMITS.pageEntries, LIMITS.pageBytes));
      // Contiguous by id or not at all: a page that skips or repeats an id is not the journal this was opened over.
      page.entries.forEach((e, i) => {
        if (e.entryId !== after + 1 + i) throw changed(`entry ${after + 1 + i} was expected and ${e.entryId} came`);
      });
      if (page.entries.length === 0 && !page.done) throw changed('the journal stopped answering mid-range');
      if (page.entries.length > 0) {
        journalEntries += page.entries.length;
        yield encodeBundleEntries(page.entries, nextBundleId);
        nextBundleId += page.entries.length;
      }
      after = page.nextAfterId;
      if (page.done) break;
    }
    if (after !== slice.throughEntryId) throw changed('the journal ended before the range did');
  }

  let archivedMinutes = 0;
  const firstMinuteMs = Math.floor(range.fromMs / MINUTE_MS) * MINUTE_MS;
  for (const key of [...await ask(() => archive.sources())].sort()) {
    let lo = firstMinuteMs;
    let span = range.toMs - firstMinuteMs;
    while (lo < range.toMs) {
      const hi = Math.min(range.toMs, lo + span);
      let minutes = await ask(() => archive.read(key, lo, hi, LIMITS.pageBytes));
      if (minutes === 'range-too-large' && hi - lo > MINUTE_MS) {
        // Narrower, down to one minute; what was asked for stays the same range.
        span = Math.max(MINUTE_MS, Math.floor((hi - lo) / 2 / MINUTE_MS) * MINUTE_MS);
        continue;
      }
      // One minute over a page is still a minute: read whole and written whole, within the archive's own bound.
      if (minutes === 'range-too-large') minutes = await ask(() => archive.read(key, lo, hi, LIMITS.archiveReadBytes));
      if (minutes === 'history-lost' || minutes === 'range-too-large') {
        throw new BundleError('history-lost', 'the archive of expired history could not be read');
      }
      if (minutes.length > 0) {
        archivedMinutes += minutes.length;
        yield encodeBundleArchive(minutes, nextBundleId);
        nextBundleId += minutes.length;
      }
      lo = hi;
    }
  }

  // The end says what was written, so it is only written when that is what was promised and nothing moved.
  const meta2 = await ask(() => runtime.dataset());
  const cutsNow = await ask(() => archive.cuts());
  const snapshot2 = await ask(() => runtime.snapshot());
  if (meta2.generation !== meta.generation || snapshot2.generation !== snapshot.generation) throw changed('the dataset was replaced');
  if (cutsNow.length !== cutsAtOpen.length) throw changed('history was expired into the archive');
  if (slice !== null && snapshot2.firstEntryId > slice.firstEntryId) throw changed('entries in the range expired');
  if (slice !== null && journalEntries !== slice.throughEntryId - slice.firstEntryId + 1) throw changed('the journal entries written are not the range');
  if (archivedMinutes !== summary.minutes) throw changed('the archive\'s minutes are not the ones counted when it opened');
  yield encodeBundleEnd({ journalEntries, archivedMinutes }, nextBundleId);
}

// --- the renderer's half ------------------------------------------------------------------------------------

export type BundleOpenResult = { ok: true; exportId: number } | { ok: false; code: BundleErrorCode; message: string };
export type BundleChunkResult = { ok: true; bytes: Uint8Array; done: boolean } | { ok: false; code: BundleErrorCode; message: string };

/** What `exportBundle` needs of the monitoring client: three calls to the Worker. */
export interface BundleClient {
  bundleOpen(range: { fromMs: number; toMs: number }, exportedMs: number, inwireVersion: string): Promise<BundleOpenResult>;
  bundleNext(exportId: number): Promise<BundleChunkResult>;
  bundleCancel(exportId: number): Promise<void>;
}

export interface BundleExportResult { outcome: SaveOutcome; journalEntries: number; archivedMinutes: number }

/** The kind-2 and kind-3 entries a chunk of whole framed entries holds. */
function countEntries(bytes: Uint8Array, skip: number): { journal: number; archive: number } {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const counts = { journal: 0, archive: 0 };
  let at = skip;
  while (at < bytes.length) {
    if (at + ENTRY_HEADER_BYTES > bytes.length) throw new BundleError('runtime-unavailable', 'the Worker sent a chunk that is not whole entries');
    const kind = bytes[at + 16];
    if (kind === BUNDLE_KIND_JOURNAL) counts.journal++;
    else if (kind === BUNDLE_KIND_ARCHIVE) counts.archive++;
    at += ENTRY_HEADER_BYTES + v.getUint32(at + 4, true);
  }
  if (at !== bytes.length) throw new BundleError('runtime-unavailable', 'the Worker sent a chunk that is not whole entries');
  return counts;
}

/**
 * Pulls the bundle for `range` from the Worker into `sink`, one chunk at a time, awaiting each write before
 * asking for the next. It owns the sink's end: `close()` on success, `abort()` on a cancel, a failure or the
 * signal, and never both. An abort asks the Worker to drop the export as well.
 */
export async function exportBundle(
  client: BundleClient, range: { fromMs: number; toMs: number }, sink: ByteSink, signal: AbortSignal,
  opts: { exportedMs?: number; inwireVersion?: string } = {},
): Promise<BundleExportResult> {
  let exportId: number | null = null;
  let cancelSent = false;
  let closing = false;
  const cancel = (): void => {
    if (exportId === null || cancelSent) return;
    cancelSent = true;
    void client.bundleCancel(exportId).catch(() => undefined);
  };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    if (signal.aborted) throw new ExportCancelled();
    const opened = await client.bundleOpen(range, opts.exportedMs ?? Date.now(), opts.inwireVersion ?? appVersion());
    if (!opened.ok) throw opened.code === 'cancelled' ? new ExportCancelled() : new BundleError(opened.code, opened.message);
    exportId = opened.exportId;
    if (signal.aborted) throw new ExportCancelled();
    let journalEntries = 0;
    let archivedMinutes = 0;
    let first = true;
    for (;;) {
      if (signal.aborted) throw new ExportCancelled();
      const chunk = await client.bundleNext(exportId);
      if (!chunk.ok) throw chunk.code === 'cancelled' ? new ExportCancelled() : new BundleError(chunk.code, chunk.message);
      if (chunk.bytes.length > 0) {
        const counts = countEntries(chunk.bytes, first ? FILE_HEADER_BYTES : 0);
        first = false;
        await sink.write(chunk.bytes);
        journalEntries += counts.journal;
        archivedMinutes += counts.archive;
      }
      if (chunk.done) break;
    }
    if (signal.aborted) throw new ExportCancelled();
    closing = true;
    return { outcome: await sink.close(), journalEntries, archivedMinutes };
  } catch (error) {
    // A sink that was closed is the sink's own; any other end is an abort, and a failed abort must not hide the cause.
    if (!closing) await sink.abort().catch(() => undefined);
    // A failure the Worker reported has already ended its export; anything else (a write that failed) leaves it open.
    if (!(error instanceof BundleError) && !(error instanceof ExportCancelled)) cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
  }
}

// --- the file's name ------------------------------------------------------------------------------------------

const two = (n: number): string => String(n).padStart(2, '0');

function stamp(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}${two(d.getUTCMonth() + 1)}${two(d.getUTCDate())}-${two(d.getUTCHours())}${two(d.getUTCMinutes())}`;
}

/** `inwire-monitoring-<from>-<to>.iwmon`, both in UTC as `YYYYMMDD-HHmm`. */
export function bundleFileName(fromMs: number, toMs: number): string {
  return `inwire-monitoring-${stamp(fromMs)}-${stamp(toMs)}.iwmon`;
}
