/**
 * The monitoring evidence journal (ADRs 0059 and 0062): every datagram received
 * from the configured exporter and the lifecycle boundaries around them, in a
 * run of segment files, and **the only authority over what was received**. The
 * rollup sidecar is a cache; this is not.
 *
 * Stored-format handling only. Nothing here reads a NetFlow header: a payload
 * is bytes, and the Worker that decodes them is a different process with a
 * different policy version.
 *
 * ## Segments
 *
 * A journal is the files `SegmentDirectory` lists: an optional milestone-1
 * `journal.iwmj` (format 1, sealed, never appended to) and any number of
 * `journal-<first id>.iwmj` segments (format 2). Entry ids are one sequence
 * across all of them. The newest segment takes appends; before an append that
 * would take it past its size the journal flushes it, writes and flushes the
 * next segment's header, and only then writes the entry. A segment's header
 * names the session open when it was created, so a segment whose predecessors
 * have expired still says whose datagrams it holds. Retention removes whole
 * sealed segments through `dropSegments`, which records an `expired` boundary
 * first and syncs it before the first unlink.
 *
 * ## What a failure does to the files
 *
 * - **A torn tail** - an append that did not finish - is truncated, and only
 *   by `open`, and only on the newest segment. `recoverJournal` is the same
 *   scan without any change, so the sheet can say what it would do before
 *   anything is touched.
 * - **A torn roll** - a newest segment with an incomplete header or no whole
 *   entry, beside an older one - is the rest of a roll that did not finish. It
 *   is removed by `open` and the older segment carries on.
 * - **Anything else** - a bad entry with bytes behind it, a skipped id, a
 *   generation or session that does not carry across a segment boundary, a
 *   datagram with no session, an unknown format or policy version - leaves the
 *   files exactly as they were, refuses every append and keeps the history
 *   before it readable. Later evidence is never truncated on a guess.
 * - **A write that throws** truncates back to the last complete entry if it
 *   can, and the journal stops accepting appends. The snapshot is what it was
 *   before the failing entry, so the caller's cursor is still true.
 *
 * ## Admission is per entry
 *
 * An `append` of many entries is a loop over single admissions, never one
 * write: a failure part way leaves a journal that ends at a whole entry, and
 * `AppendResult` says how many of the batch got in. The cost is one write per
 * entry, which is 3.4 us a frame measured on the capture store and nothing at
 * monitoring's rates.
 *
 * ## Durability
 *
 * `append` is acknowledged once the OS has the bytes. It is not called
 * durable. `flush` is what moves `syncedThroughEntryId`, and the one-second
 * timer and every Stop are its callers.
 */
import type { BlockFile } from '../capture/blockFile';
import { EntryIndex } from './index';
import {
  ENTRY_HEADER_BYTES, FILE_HEADER_BYTES, JOURNAL_FRAMING, KIND_BOUNDARY, KIND_DATAGRAM,
  crc32, decodeDatagramBody, decodeFileHeader, encodeDatagramBody, encodeEntry, entryCrc,
  entryReservedProblem, generationFromHex, generationToHex, isHeaderPrefix, parseEntryHeader, scanEntries,
  type ScanOutcome,
} from './journalCodec';
import {
  LEGACY_JOURNAL_NAME, SEGMENT_FORMAT_VERSION, SEGMENT_HEADER_BYTES, decodeSegmentHeader, encodeSegmentHeader,
  segmentBytesFor, segmentName, type SegmentDirectory, type SegmentInfo,
} from './segments';
import {
  ACCEPTED_POLICIES, FORMAT_VERSION, LIMITS,
  type BoundaryAction, type BoundaryEvidence, type BundleSlice, type DatagramEvidence, type Evidence,
  type EvidencePage, type EvidenceRef, type ExpiredRange, type JournalSnapshot, type RawPage, type SegmentGeometry, type SegmentSource,
} from './types';

// --- the vocabulary ------------------------------------------------------------------------

/** What a caller hands to `append`; the journal assigns the id and the session. */
export type EvidenceInput =
  | Omit<DatagramEvidence, 'ref' | 'receiveOrdinal' | 'sessionId' | 'policy' | 'segmentFirstId'>
  | Omit<BoundaryEvidence, 'ref' | 'policy' | 'segmentFirstId'>;

export type JournalState = 'open' | 'storage-limit' | 'refused-corrupt' | 'refused-version' | 'failed' | 'closed';

export interface AppendResult {
  snapshot: JournalSnapshot;
  /** Inputs that became entries. A `stop` the journal wrote itself at the storage limit is not counted. */
  appended: number;
  refused: number;
  state: JournalState;
}

export interface JournalOptions {
  /** The whole dataset's bound: every segment plus `otherBytes()`. */
  limitBytes: number;
  /** The sidecar's size (and the archive's), so one limit covers every file. */
  otherBytes?: () => number;
  randomBytes?: (n: number) => Uint8Array;
  nowMs?: () => number;
  /**
   * The newest entry id an archive cut has already taken out of the journal
   * (ADR 0062). The oldest segment may start right after it; 0 where there is
   * no archive.
   */
  lastCutThroughEntryId?: number;
  /**
   * A read-only adoption (ADR 0061): the dataset is served and nothing is written. `open` keeps the torn roll,
   * the segments an interrupted drop left and the newest segment's torn tail exactly as found, reads only up to
   * the whole entries, and writes no `interrupted` for a session a crash left open. The journal it returns
   * reports `refused-corrupt`, so every write path fails closed.
   */
  readOnly?: boolean;
}

export interface RecoveryResult {
  /** 32 lowercase hex digits, or null where nothing has a readable header. */
  generation: string | null;
  completeEntries: number;
  lastEntryId: number;
  /** The end of the last entry that was accepted in the newest segment (or its header's, for an unknown version). */
  validBytes: number;
  /** The newest segment's torn tail, or the lone file's torn header. */
  tornTail: { fromOffset: number; bytes: number } | null;
  /**
   * `empty`: nothing complete, so nothing to lose; `ok`: every file is entries
   * and at most a torn tail; `corrupt` and `unknown-version`: preserved.
   */
  status: 'ok' | 'empty' | 'corrupt' | 'unknown-version';
  problem?: string;
  /** The segments an `open` would keep, oldest first. */
  segments: SegmentInfo[];
  /** The distinct decoder policies the headers name. */
  policies: number[];
  /** Segments an interrupted `dropSegments` left behind, which an `open` would unlink. */
  pendingUnlink: string[];
  /** A newest segment holding no whole entry beside an older one, which an `open` would unlink. */
  tornRoll: string | null;
}

/** A snapshot of another generation: the journal under it was replaced. A query maps this to `stale-generation`. */
export class StaleGenerationError extends Error {
  constructor(readonly wanted: string, readonly actual: string) {
    super(`snapshot of generation ${wanted} asked of generation ${actual}`);
    this.name = 'StaleGenerationError';
  }
}

/** The ids asked for are below the oldest one still on disk: whole segments expired (ADR 0062). */
export class ExpiredRangeError extends Error {
  constructor(readonly firstRetainedEntryId: number) {
    super(`entries before ${firstRetainedEntryId} have expired`);
    this.name = 'ExpiredRangeError';
  }
}

// --- boundaries -------------------------------------------------------------------------------

/** What a caller may write. `expired` is the journal's own, written by `dropSegments`. */
const WRITE_ACTIONS: ReadonlySet<string> = new Set<BoundaryAction>(['start', 'stop', 'suspend', 'resume', 'interrupted', 'gap']);
/** What a reader accepts. */
const READ_ACTIONS: ReadonlySet<string> = new Set<BoundaryAction>(['start', 'stop', 'suspend', 'resume', 'interrupted', 'gap', 'expired']);
const SESSION_ID = /^[0-9a-f]{32}$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

export interface BoundaryFields {
  action: BoundaryAction;
  sessionId: string;
  receivedMs: number;
  reason: string;
  droppedDatagrams: number | null;
  /** `undefined`: the body had none (or this action carries none). `null`: it had one that could not be read. */
  source?: SegmentSource | null;
  expired?: ExpiredRange | null;
}

type BoundaryParse = { ok: true; value: BoundaryFields } | { ok: false; reason: string };

function validSource(s: unknown): s is SegmentSource {
  if (typeof s !== 'object' || s === null) return false;
  const o = s as Record<string, unknown>;
  return typeof o.exporterIPv4 === 'string' && IPV4.test(o.exporterIPv4)
    && typeof o.bindIPv4 === 'string' && IPV4.test(o.bindIPv4)
    && typeof o.port === 'number' && Number.isInteger(o.port) && o.port >= 0 && o.port <= 0xffff;
}

function cleanSource(s: SegmentSource): SegmentSource {
  return { exporterIPv4: s.exporterIPv4, bindIPv4: s.bindIPv4, port: s.port };
}

const isId = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;

/**
 * A reader ignores fields it does not know. Of the known ones, `action`,
 * `sessionId` and `receivedMs` are required: without them the entry cannot
 * be placed. `reason` and `droppedDatagrams` default, and a wrong-typed one
 * defaults too rather than condemning the entry - it is a count a human reads,
 * not a thing the journal's structure depends on. A `source` that is not a
 * source reads as null for the same reason. An `expired` boundary is different:
 * its range is what tells a reader which ids are gone, so one without a whole
 * range is unreadable.
 */
function parseBoundary(body: Uint8Array): BoundaryParse {
  let json: unknown;
  try {
    json = JSON.parse(utf8Strict.decode(body));
  } catch {
    return { ok: false, reason: 'a boundary body is not JSON' };
  }
  if (typeof json !== 'object' || json === null || Array.isArray(json)) return { ok: false, reason: 'a boundary body is not an object' };
  const o = json as Record<string, unknown>;
  if (typeof o.action !== 'string' || !READ_ACTIONS.has(o.action)) return { ok: false, reason: 'a boundary has no known action' };
  if (typeof o.sessionId !== 'string') return { ok: false, reason: 'a boundary has no sessionId' };
  if (!isId(o.receivedMs)) return { ok: false, reason: 'a boundary has no receivedMs' };
  const value: BoundaryFields = {
    action: o.action as BoundaryAction,
    sessionId: o.sessionId,
    receivedMs: o.receivedMs,
    reason: typeof o.reason === 'string' ? o.reason : '',
    droppedDatagrams: typeof o.droppedDatagrams === 'number' && Number.isSafeInteger(o.droppedDatagrams) && o.droppedDatagrams >= 0
      ? o.droppedDatagrams
      : null,
  };
  if (value.action === 'start' || value.action === 'expired') {
    if ('source' in o) value.source = validSource(o.source) ? cleanSource(o.source) : null;
    else if (value.action === 'expired') value.source = null;
  }
  if (value.action === 'expired') {
    if (!isId(o.fromEntryId) || !isId(o.throughEntryId) || !isId(o.fromMs) || !isId(o.throughMs) || o.fromEntryId < 1 || o.fromEntryId > o.throughEntryId) {
      return { ok: false, reason: 'an expired boundary has no whole range' };
    }
    value.expired = { fromEntryId: o.fromEntryId, throughEntryId: o.throughEntryId, fromMs: o.fromMs, throughMs: o.throughMs };
  }
  return { ok: true, value };
}

/**
 * The bytes of a boundary's body, in the key order the format pins. A `start`
 * with a source appends it as the last key; without one the body is the old one
 * exactly. An `expired` boundary has ADR 0062's own order and no
 * `droppedDatagrams`.
 */
export function encodeBoundaryBody(b: BoundaryFields): Uint8Array {
  if (b.action === 'expired') {
    const range = b.expired;
    if (range === undefined || range === null) throw new RangeError('an expired boundary has a range');
    return utf8.encode(JSON.stringify({
      action: b.action,
      sessionId: b.sessionId,
      receivedMs: b.receivedMs,
      fromEntryId: range.fromEntryId,
      throughEntryId: range.throughEntryId,
      fromMs: range.fromMs,
      throughMs: range.throughMs,
      reason: b.reason,
      source: b.source === undefined || b.source === null ? null : cleanSource(b.source),
    }));
  }
  const base = {
    action: b.action,
    sessionId: b.sessionId,
    receivedMs: b.receivedMs,
    reason: b.reason,
    droppedDatagrams: b.droppedDatagrams,
  };
  if (b.action === 'start' && b.source !== undefined && b.source !== null) {
    return utf8.encode(JSON.stringify({ ...base, source: cleanSource(b.source) }));
  }
  return utf8.encode(JSON.stringify(base));
}

function boundaryEvidence(generation: string, entryId: number, b: BoundaryFields, policy: number, segmentFirstId: number): BoundaryEvidence {
  const e: BoundaryEvidence = {
    kind: 'boundary', ref: { generation, entryId }, sessionId: b.sessionId, receivedMs: b.receivedMs,
    action: b.action, reason: b.reason, droppedDatagrams: b.droppedDatagrams, policy, segmentFirstId,
  };
  if (b.source !== undefined) e.source = b.source;
  if (b.expired !== undefined) e.expired = b.expired;
  return e;
}

/** The session and the sources a run of entries leaves behind. */
interface Track {
  open: string | null;
  /** The open session's recorded source; null with none open or none recorded. */
  sessionSource: SegmentSource | null;
  /** The newest source any `start` or `expired` boundary recorded. */
  recordedSource: SegmentSource | null;
}

/**
 * What a boundary does to the session. `suspend` and `resume` leave it as it
 * was: a suspended session is still one that a crash must close with an
 * `interrupted`, and a datagram that arrives during one is still evidence.
 * `expired` leaves it too: it says what left the journal, not what happened to
 * the stream.
 */
function applyBoundary(t: Track, b: BoundaryFields): void {
  if (b.action === 'start') {
    t.open = b.sessionId;
    t.sessionSource = b.source ?? null;
    if (b.source) t.recordedSource = b.source;
  } else if (b.action === 'stop' || b.action === 'interrupted') {
    t.open = null;
    t.sessionSource = null;
  } else if (b.action === 'expired' && b.source) {
    t.recordedSource = b.source;
  }
}

// --- segments in memory ------------------------------------------------------------------------

interface Seg {
  name: string;
  legacy: boolean;
  file: BlockFile;
  headerBytes: number;
  firstId: number;
  /** `firstId - 1` while the segment holds no entry. */
  lastId: number;
  firstMs: number;
  lastMs: number;
  policy: number;
  /** The file's size: the header and every complete entry. */
  bytes: number;
  /** The size the segment grows to before the next one starts. */
  maxBytes: number;
  index: EntryIndex;
}

const infoOf = (s: Seg, sealed: boolean): SegmentInfo => ({
  name: s.name, firstEntryId: s.firstId, lastEntryId: s.lastId, lastReceivedMs: s.lastMs,
  policyVersion: s.policy, sealed, bytes: s.bytes,
});

/** One entry read back: the evidence, and the same entry's body, kind and time as the file holds them. */
interface ReadEntry {
  evidence: Evidence;
  entryId: number;
  kind: 1 | 2;
  body: Uint8Array;
  policy: number;
  receivedMs: number;
  nextOffset: number;
  sessionAfter: string | null;
  entryBytes: number;
}

// --- scanning ----------------------------------------------------------------------------------

interface DatasetScan {
  status: 'ok' | 'empty' | 'corrupt' | 'unknown-version';
  problem?: string;
  generation: string | null;
  /** The segments kept, oldest first; on `corrupt`, the ones read before the damage. */
  segs: Seg[];
  pendingUnlink: string[];
  tornRoll: string | null;
  /** A lone file with an incomplete header: an `open` starts the dataset over in it. */
  resetFile: string | null;
  tornTail: { fromOffset: number; bytes: number } | null;
  policies: number[];
  /** Every boundary of the kept segments, in id order: they are few, and a query needs all of them to place its gaps. */
  boundaries: BoundaryEvidence[];
  track: Track;
  createdMs: number;
  lastReceivedMs: number;
  completeEntries: number;
  lastEntryId: number;
  validBytes: number;
}

interface Probe {
  name: string;
  legacy: boolean;
  file: BlockFile;
  size: number;
  head: Uint8Array;
}

interface Decoded extends Probe {
  headerBytes: number;
  policy: number;
  generation: string;
  createdMs: number;
  firstId: number;
  /** The session the header names, as the 32 hex digits it is stored as; null with none. */
  session: string | null;
  source: SegmentSource | null;
}

function emptyScan(): DatasetScan {
  return {
    status: 'empty', generation: null, segs: [], pendingUnlink: [], tornRoll: null, resetFile: null, tornTail: null,
    policies: [], boundaries: [], track: { open: null, sessionSource: null, recordedSource: null },
    createdMs: 0, lastReceivedMs: 0, completeEntries: 0, lastEntryId: 0, validBytes: 0,
  };
}

const MAGIC_BYTES = Array.from('INWIREMJ', (c) => c.charCodeAt(0));
const hasMagic = (b: Uint8Array): boolean => b.length >= 8 && MAGIC_BYTES.every((m, i) => b[i] === m);
const u16 = (b: Uint8Array, at: number): number => b[at] | (b[at + 1] << 8);

/** A segment header's bytes that are not our magic, or whose checksum does not match: never a header anything wrote whole. */
function isUnwrittenHeader(head: Uint8Array): boolean {
  if (!hasMagic(head)) return true;
  return new DataView(head.buffer, head.byteOffset, head.byteLength).getUint32(124, true) !== crc32(head.subarray(0, 124));
}

/** Whether a legacy file holds a complete entry. It reads as far as the first and stops. */
function legacyHoldsEntries(file: BlockFile): boolean {
  let any = false;
  scanEntries(file, JOURNAL_FRAMING, FILE_HEADER_BYTES, 0, () => { any = true; return 'seen'; });
  return any;
}

/**
 * What `open` would find, read-only. Every change `open` makes is a decision
 * this reports (`tornTail`, `tornRoll`, `pendingUnlink`, `resetFile`) and does
 * not take.
 */
function scanDataset(dir: SegmentDirectory, lastCut: number, limitBytes: number): DatasetScan {
  const out = emptyScan();
  const names = dir.list();
  if (names.length === 0) return out;

  const probes: Probe[] = names.map((name) => {
    const file = dir.open(name);
    const size = file.size();
    const head = new Uint8Array(Math.min(size, SEGMENT_HEADER_BYTES));
    file.read(0, head);
    return { name, legacy: name === LEGACY_JOURNAL_NAME, file, size, head };
  });

  // Versions first, over every file: a dataset a newer build wrote is refused whole and left alone,
  // whatever else is wrong with it, and a legacy file with nothing in it is not ignored until this is settled.
  const policies = new Set<number>();
  let versionProblem: string | null = null;
  for (const p of probes) {
    if (p.size < 12 || !hasMagic(p.head)) continue;
    const format = u16(p.head, 8);
    const policy = u16(p.head, 10);
    policies.add(policy);
    const wanted = p.legacy ? FORMAT_VERSION : SEGMENT_FORMAT_VERSION;
    if (format !== wanted) {
      versionProblem ??= `${p.name}: format ${format}; this build reads format ${wanted} there`;
    } else if (!ACCEPTED_POLICIES.includes(policy)) {
      versionProblem ??= `${p.name}: policy ${policy}; this build reads policy ${ACCEPTED_POLICIES.join(', ')}`;
    }
  }
  out.policies = [...policies].sort((a, b) => a - b);
  if (versionProblem !== null) {
    const first = probes.find((p) => p.size >= (p.legacy ? FILE_HEADER_BYTES : SEGMENT_HEADER_BYTES) && hasMagic(p.head));
    if (first !== undefined) {
      if (first.legacy) {
        const h = decodeFileHeader(JOURNAL_FRAMING, first.head);
        if (h.ok) { out.generation = generationToHex(h.generation); out.validBytes = FILE_HEADER_BYTES; }
      } else {
        const h = decodeSegmentHeader(first.head);
        if (h.ok) { out.generation = generationToHex(h.value.generation); out.validBytes = SEGMENT_HEADER_BYTES; }
      }
    }
    return { ...out, status: 'unknown-version', problem: versionProblem };
  }
  const corrupt = (problem: string): DatasetScan => ({ ...out, segs: [], boundaries: [], status: 'corrupt', problem });

  // Headers.
  const decoded: Decoded[] = [];
  const tornHeaders: { name: string; size: number; idFromName: number; whole?: boolean }[] = [];
  for (const p of probes) {
    const headerBytes = p.legacy ? FILE_HEADER_BYTES : SEGMENT_HEADER_BYTES;
    if (p.size < headerBytes) {
      // Bytes that are not the start of our header are somebody else's file, and not ours to discard.
      if (!isHeaderPrefix(JOURNAL_FRAMING, p.head)) return corrupt(`${p.name} is not a monitoring journal`);
      if (p.legacy) continue;
      tornHeaders.push({ name: p.name, size: p.size, idFromName: Number(/(\d+)/.exec(p.name)![1]) });
      continue;
    }
    if (p.legacy) {
      const h = decodeFileHeader(JOURNAL_FRAMING, p.head);
      if (!h.ok) return corrupt(`${p.name}: ${h.reason}`);
      decoded.push({
        ...p, headerBytes, policy: h.policyVersion, generation: generationToHex(h.generation), createdMs: h.createdMs,
        firstId: 1, session: null, source: null,
      });
    } else {
      const h = decodeSegmentHeader(p.head);
      if (!h.ok) {
        // A roll's header that reached disk as zeros or garbage (the size was extended, the data was not): the same
        // torn roll as a partial header, if it is the newest and exactly a header long. Judged below with the others.
        // Anything else wrong with a header, a correct magic and checksum included, is something that wrote it on purpose.
        if (p.size === SEGMENT_HEADER_BYTES && isUnwrittenHeader(p.head)) {
          tornHeaders.push({ name: p.name, size: p.size, idFromName: Number(/(\d+)/.exec(p.name)![1]), whole: true });
          continue;
        }
        return corrupt(`${p.name}: ${h.reason}`);
      }
      decoded.push({
        ...p, headerBytes, policy: h.value.policyVersion, generation: generationToHex(h.value.generation),
        createdMs: h.value.createdMs, firstId: h.value.firstEntryId,
        session: h.value.openSession === null ? null : generationToHex(h.value.openSession), source: h.value.source,
      });
    }
  }
  decoded.sort((a, b) => a.firstId - b.firstId);
  for (let i = 1; i < decoded.length; i++) {
    if (decoded[i].firstId === decoded[i - 1].firstId) {
      return corrupt(`${decoded[i - 1].name} and ${decoded[i].name} both start at entry ${decoded[i].firstId}`);
    }
  }

  // An incomplete header is only ever the segment a roll was creating, so only ever the newest.
  let tornRoll: string | null = null;
  if (tornHeaders.length > 1) return corrupt('more than one segment has an incomplete header');
  if (tornHeaders.length === 1) {
    const t = tornHeaders[0];
    // A milestone-1 file with no entry is passed over below, so it is not a segment this one could have followed.
    const holding = decoded.filter((d) => !(d.legacy && !legacyHoldsEntries(d.file)));
    if (holding.length === 0) {
      // Nothing to fall back on: a partial header is a first segment's crash and starts over. A header-sized one
      // that is not a header is the same crash only beside an empty legacy file, which is how a first open begins;
      // alone, nothing says whether it held data, so it is refused.
      if (t.whole === true && decoded.length === 0) return corrupt(`${t.name}: the header is not a segment header and there is no earlier segment`);
      out.resetFile = t.name;
      out.tornTail = t.size === 0 ? null : { fromOffset: 0, bytes: t.size };
    } else if (t.idFromName > holding[holding.length - 1].firstId) {
      tornRoll = t.name;
    } else {
      return corrupt(`${t.name} has an incomplete header and is not the newest segment`);
    }
  }
  if (decoded.length === 0) return { ...out, status: 'empty' };

  const t = out.track;
  const kept: Seg[] = [];
  let prev: Seg | null = null;
  let problem: string | null = null;
  let tornTailOfNewest: { fromOffset: number; bytes: number } | null = null;

  for (let i = 0; i < decoded.length && problem === null; i++) {
    const d = decoded[i];
    const isNewest = i === decoded.length - 1;
    if (out.generation !== null && d.generation !== out.generation) {
      problem = `${d.name} is generation ${d.generation}, the others are ${out.generation}`;
      break;
    }
    if (prev !== null && d.firstId !== prev.lastId + 1) {
      problem = `${d.name} starts at entry ${d.firstId} but ${prev.name} ends at ${prev.lastId}`;
      break;
    }
    let expectInterrupted: string | null = null;
    if (prev === null) {
      // The oldest kept segment seeds the session from its own header: what came before it is gone.
      t.open = d.session;
      t.sessionSource = d.session === null ? null : d.source;
      t.recordedSource = d.source;
      out.createdMs = d.createdMs;
      out.lastReceivedMs = d.createdMs;
    } else if (d.session !== null) {
      if (d.session !== t.open) {
        problem = `${d.name}'s header names session ${d.session}, but the session open at the end of ${prev.name} is ${t.open ?? 'none'}`;
        break;
      }
    } else if (t.open !== null) {
      // A roll made to write the `interrupted` that closes a session names none: that entry is how it ends.
      expectInterrupted = t.open;
    }

    const seg: Seg = {
      name: d.name, legacy: d.legacy, file: d.file, headerBytes: d.headerBytes, firstId: d.firstId, lastId: d.firstId - 1,
      firstMs: 0, lastMs: d.createdMs, policy: d.policy, bytes: d.headerBytes, maxBytes: segmentBytesFor(limitBytes),
      index: new EntryIndex(d.firstId),
    };
    const gen = d.generation;
    let count = 0;
    const outcome: ScanOutcome = scanEntries(d.file, JOURNAL_FRAMING, d.headerBytes, d.firstId - 1, (e) => {
      const before = t.open;
      let receivedMs = 0;
      if (e.kind === KIND_DATAGRAM) {
        if (expectInterrupted !== null && count === 0) {
          return `${d.name}'s header names no session, but ${expectInterrupted} is still open and the segment does not begin with the interrupted that closes it`;
        }
        if (t.open === null) return 'a datagram with no open session';
        const dg = decodeDatagramBody(e.body);
        if (!dg.ok) return dg.reason;
        receivedMs = dg.value.receivedMs;
      } else if (e.kind === KIND_BOUNDARY) {
        const b = parseBoundary(e.body);
        if (!b.ok) return b.reason;
        if (expectInterrupted !== null && count === 0 && !(b.value.action === 'interrupted' && b.value.sessionId === expectInterrupted)) {
          return `${d.name}'s header names no session, but ${expectInterrupted} is still open and the segment does not begin with the interrupted that closes it`;
        }
        applyBoundary(t, b.value);
        receivedMs = b.value.receivedMs;
        out.boundaries.push(boundaryEvidence(gen, e.entryId, b.value, seg.policy, seg.firstId));
      } else {
        return `unknown kind ${e.kind}`;
      }
      if (count === 0) seg.firstMs = receivedMs;
      seg.lastMs = receivedMs;
      out.lastReceivedMs = receivedMs;
      seg.index.note(e.entryId, e.offset, before, receivedMs);
      count++;
      return null;
    });
    seg.bytes = outcome.validEnd;
    seg.lastId = outcome.lastEntryId;
    out.completeEntries += outcome.entries;

    if (outcome.problem !== null) {
      problem = `${d.name}: ${outcome.problem}`;
      out.generation ??= d.generation;
      kept.push(seg);
      break;
    }
    if (outcome.entries === 0 && d.legacy) {
      // A milestone-1 file that never got an entry is nothing a history could ask for: it is left where it is and passed over.
      continue;
    }
    if (outcome.entries === 0 && isNewest && prev !== null) {
      // The segment a roll was creating when it stopped: header written, entry not.
      tornRoll = d.name;
      break;
    }
    if (outcome.tornTail !== null) {
      if (!isNewest) {
        problem = `${d.name}: a torn tail on a segment that is not the newest`;
        kept.push(seg);
        break;
      }
      tornTailOfNewest = outcome.tornTail;
    }
    out.generation ??= d.generation;
    kept.push(seg);
    prev = seg;
  }

  out.tornRoll = tornRoll;
  out.segs = kept;
  const last = kept[kept.length - 1];
  out.lastEntryId = last?.lastId ?? 0;
  out.validBytes = last?.bytes ?? 0;
  out.tornTail = tornTailOfNewest;
  if (problem !== null) return { ...out, status: 'corrupt', problem };
  if (kept.length === 0) return { ...out, status: 'empty', tornRoll: null };

  // An interrupted `dropSegments`: the boundary is on disk and some of the segments it names are too.
  const expiredBoundaries = out.boundaries.filter((b) => b.action === 'expired' && b.expired);
  const pending: string[] = [];
  let pendingThrough = 0;
  for (const s of kept) {
    const covered = expiredBoundaries.some((b) => b.ref.entryId > s.lastId && b.expired!.throughEntryId >= s.lastId);
    if (!covered) break;
    pending.push(s.name);
    pendingThrough = s.lastId;
  }
  if (pending.length > 0) {
    out.pendingUnlink = pending;
    out.segs = kept.slice(pending.length);
    out.boundaries = out.boundaries.filter((b) => b.ref.entryId > pendingThrough);
    out.completeEntries = out.segs.reduce((n, s) => n + (s.lastId - s.firstId + 1), 0);
  }

  // The oldest segment starts where the history does: at the beginning, right after an archive cut,
  // or inside what an `expired` boundary says is gone.
  const oldest = out.segs[0];
  const retainedExpired = out.boundaries.filter((b) => b.action === 'expired' && b.expired);
  const starts = oldest.firstId === 1 || oldest.firstId === lastCut + 1
    || retainedExpired.some((b) => b.expired!.fromEntryId <= oldest.firstId && oldest.firstId <= b.expired!.throughEntryId + 1);
  if (!starts) {
    return {
      ...out, status: 'corrupt',
      problem: `the oldest segment ${oldest.name} starts at entry ${oldest.firstId}; the journal should start at 1 or at ${lastCut + 1}`,
    };
  }
  return { ...out, status: 'ok' };
}

function toRecovery(scan: DatasetScan): RecoveryResult {
  return {
    generation: scan.generation,
    completeEntries: scan.completeEntries,
    lastEntryId: scan.lastEntryId,
    validBytes: scan.validBytes,
    tornTail: scan.tornTail,
    status: scan.status,
    ...(scan.problem === undefined ? {} : { problem: scan.problem }),
    segments: scan.segs.map((s, i) => infoOf(s, s.legacy || i < scan.segs.length - 1)),
    policies: scan.policies,
    pendingUnlink: scan.pendingUnlink,
    tornRoll: scan.tornRoll,
  };
}

function lastCutOf(options: { lastCutThroughEntryId?: number }): number {
  const cut = options.lastCutThroughEntryId ?? 0;
  if (!Number.isSafeInteger(cut) || cut < 0) throw new RangeError(`lastCutThroughEntryId ${cut} is not a non-negative safe integer`);
  return cut;
}

/**
 * What `open` would find, without changing anything. Never truncates and never
 * unlinks: a `tornTail`, a `tornRoll` or a `pendingUnlink` here is a report.
 * The limit only sizes segments an open would keep, so a default serves.
 */
export function recoverJournal(dir: SegmentDirectory, options: { lastCutThroughEntryId?: number } = {}): RecoveryResult {
  return toRecovery(scanDataset(dir, lastCutOf(options), 0));
}

function defaultRandom(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

const NEWEST_POLICY = Math.max(...ACCEPTED_POLICIES);

const READ_ONLY_PROBLEM = 'the journal was opened read-only; nothing is written to it';

// --- the journal ----------------------------------------------------------------------------------

export class MonitoringJournal {
  private lastId: number;
  private syncedId = 0;
  private status: JournalState;
  private problemText: string | null = null;
  /** The ceiling in force: `options.limitBytes` until `setLimit` moves it. */
  private limit: number;
  /** The newest entry's own `receivedMs`, which an `interrupted` written by `setLimit` carries. */
  private lastReceivedMs: number;
  private readonly generationHex: string;
  private readonly track: Track;
  private readonly segs: Seg[];
  private readonly lastCut: number;
  /**
   * Every boundary in the retained segments, in id order, kept in memory: the
   * open scan collects them and every append adds to the list. A history query
   * needs all of them to place its gaps, and they are a few per session, not
   * per second.
   */
  private readonly boundaryList: BoundaryEvidence[];

  private constructor(
    private readonly dir: SegmentDirectory,
    private readonly options: JournalOptions,
    init: {
      generation: string; segs: Seg[]; lastId: number; state: JournalState; track: Track;
      boundaries: BoundaryEvidence[]; lastReceivedMs: number; lastCut: number; problem?: string | null;
    },
  ) {
    this.limit = options.limitBytes;
    this.lastReceivedMs = init.lastReceivedMs;
    this.generationHex = init.generation;
    this.segs = init.segs;
    this.lastId = init.lastId;
    this.status = init.state;
    this.track = init.track;
    this.boundaryList = init.boundaries;
    this.lastCut = init.lastCut;
    this.problemText = init.problem ?? null;
  }

  /**
   * The only way to get a journal. A directory with no segment gets a new one
   * with a new generation; any other dataset's generation is read and never
   * replaced. An open is the only thing that changes files: it truncates the
   * newest segment's torn tail, unlinks a torn roll and the segments an
   * interrupted drop left, and closes a session a crash left open.
   */
  static open(dir: SegmentDirectory, options: JournalOptions): { journal: MonitoringJournal; recovery: RecoveryResult } {
    const lastCut = lastCutOf(options);
    const scan = scanDataset(dir, lastCut, options.limitBytes);
    const recovery = toRecovery(scan);
    const lastOf = (segs: Seg[]): number => segs[segs.length - 1]?.lastId ?? lastCut;
    const refused = (state: JournalState): MonitoringJournal => new MonitoringJournal(dir, options, {
      generation: scan.generation ?? '', segs: scan.segs, lastId: lastOf(scan.segs), state,
      track: { open: null, sessionSource: null, recordedSource: null }, boundaries: scan.boundaries,
      lastReceivedMs: scan.lastReceivedMs, lastCut, problem: scan.problem ?? null,
    });

    if (scan.status === 'corrupt') return { journal: refused('refused-corrupt'), recovery };
    if (scan.status === 'unknown-version') return { journal: refused('refused-version'), recovery };

    if (options.readOnly === true) {
      // Nothing to read is not a dataset to create: a read-only look never makes one.
      if (scan.status === 'empty') return { journal: refused('refused-corrupt'), recovery };
      // The scan already left out the torn roll, the pending unlinks and the torn tail, so this is what
      // a repairing open would keep. `refused-corrupt` because that state refuses every write; the track
      // is the real one, so the dataset's recorded source is still read from it.
      return {
        journal: new MonitoringJournal(dir, options, {
          generation: scan.generation!, segs: scan.segs, lastId: scan.lastEntryId, state: 'refused-corrupt',
          track: scan.track, boundaries: scan.boundaries, lastReceivedMs: scan.lastReceivedMs, lastCut, problem: READ_ONLY_PROBLEM,
        }),
        recovery,
      };
    }

    if (scan.status === 'empty') {
      const bytes = (options.randomBytes ?? defaultRandom)(16);
      // A caller bug, refused before any file is touched: a generation of the
      // wrong length would otherwise be a header nobody could read back.
      if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
        throw new RangeError(`randomBytes(16) returned ${bytes instanceof Uint8Array ? `${bytes.length} bytes` : 'something that is not a Uint8Array'}; a generation is exactly 16`);
      }
      const createdMs = (options.nowMs ?? Date.now)();
      const firstId = lastCut + 1;
      const name = segmentName(firstId);
      const header = encodeSegmentHeader({
        policyVersion: NEWEST_POLICY, generation: bytes, createdMs, firstEntryId: firstId, openSession: null, source: null,
      });
      const segs: Seg[] = [];
      let state: JournalState = 'open';
      let problem: string | null = null;
      let created = false;
      try {
        let file: BlockFile;
        if (scan.resetFile === name) {
          file = dir.open(name);
          if (file.size() > 0) file.truncate(0);
        } else {
          if (scan.resetFile !== null) dir.unlink(scan.resetFile);
          file = dir.create(name);
          created = true;
        }
        file.write(0, header);
        segs.push({
          name, legacy: false, file, headerBytes: SEGMENT_HEADER_BYTES, firstId, lastId: lastCut, firstMs: 0, lastMs: createdMs,
          policy: NEWEST_POLICY, bytes: SEGMENT_HEADER_BYTES, maxBytes: segmentBytesFor(options.limitBytes), index: new EntryIndex(firstId),
        });
      } catch (e) {
        // A file without its header is something the next open has to explain; do not leave one that can go now.
        if (created) { try { dir.unlink(name); } catch { /* the next open resets it */ } }
        state = 'failed';
        problem = `the first segment could not be created: ${(e as Error).message}`;
      }
      const journal = new MonitoringJournal(dir, options, {
        generation: generationToHex(bytes), segs, lastId: lastCut, state,
        track: { open: null, sessionSource: null, recordedSource: null }, boundaries: [], lastReceivedMs: 0, lastCut, problem,
      });
      return { journal, recovery };
    }

    let state: JournalState = 'open';
    let problem: string | null = null;
    const attempt = (what: string, run: () => void): void => {
      if (state !== 'open') return;
      try {
        run();
      } catch (e) {
        state = 'failed';
        problem = `${what}: ${(e as Error).message}`;
      }
    };
    if (scan.tornRoll !== null) attempt(`could not remove the unfinished segment ${scan.tornRoll}`, () => dir.unlink(scan.tornRoll!));
    for (const name of scan.pendingUnlink) attempt(`could not finish removing ${name}`, () => dir.unlink(name));
    const newest = scan.segs[scan.segs.length - 1];
    if (scan.tornTail !== null) attempt(`could not truncate ${newest.name}'s torn tail`, () => newest.file.truncate(scan.validBytes));
    const journal = new MonitoringJournal(dir, options, {
      generation: scan.generation!, segs: scan.segs, lastId: scan.lastEntryId, state,
      track: scan.track, boundaries: scan.boundaries, lastReceivedMs: scan.lastReceivedMs, lastCut, problem,
    });
    // A session a crash left open. `receivedMs` is the last entry's own, so the
    // gap runs from the last thing seen, and no count is invented.
    if (state === 'open' && scan.track.open !== null) {
      journal.writeBoundary({
        action: 'interrupted', sessionId: scan.track.open, receivedMs: scan.lastReceivedMs,
        reason: 'the previous run ended without a stop', droppedDatagrams: null,
      });
    }
    return { journal, recovery };
  }

  get state(): JournalState { return this.status; }

  /** What went wrong, where the state is `failed` or refused; null otherwise. */
  get problem(): string | null { return this.problemText; }

  /** The whole dataset's ceiling now in force (every segment plus the other files). */
  get limitBytes(): number { return this.limit; }

  /** The retained segments, oldest first. The newest takes appends unless it is the legacy file. */
  segments(): SegmentInfo[] {
    return this.segs.map((s, i) => infoOf(s, s.legacy || i < this.segs.length - 1));
  }

  /**
   * Moves the ceiling in place. Nothing on disk depends on it, so there is no
   * rescan and every port and object holding this journal stays valid - which is
   * the point: the way back from a full dataset is a larger limit, and closing
   * and reopening the journal to apply one scans every entry under a deadline
   * shorter than the scan. Segments already created keep the size they were
   * given; later ones use the new limit.
   *
   * A journal that stopped at its old limit is open again when the new one
   * leaves room for at least the closing reserve (so is one that `dropSegments`
   * has made room in: `setLimit` with the same number is how a caller says so).
   * A session its `stop` did not fit behind is still open on disk, and gets the
   * `interrupted` an open would have written, so the next `start` is allowed.
   * Any other state is left as it is: a refused or failed journal does not
   * become writable by a number.
   */
  setLimit(limitBytes: number): void {
    if (!Number.isSafeInteger(limitBytes) || limitBytes < 1) throw new RangeError(`a limit is a positive safe integer of bytes (got ${limitBytes})`);
    this.limit = limitBytes;
    if (this.status !== 'storage-limit') return;
    if (this.totalBytes() + this.otherBytes() + LIMITS.closingReserveBytes >= limitBytes) return;
    this.status = 'open';
    if (this.track.open !== null) {
      this.writeBoundary({
        action: 'interrupted', sessionId: this.track.open, receivedMs: this.lastReceivedMs,
        reason: 'the previous run ended without a stop', droppedDatagrams: null,
      });
    }
  }

  /**
   * The newest boundary in the retained segments, or null for none. From the list the open scan already
   * built, so it costs nothing on top of it; after a crash that is the `interrupted` this open wrote.
   */
  lastBoundary(): BoundaryEvidence | null {
    return this.boundaryList[this.boundaryList.length - 1] ?? null;
  }

  snapshot(): JournalSnapshot {
    return {
      generation: this.generationHex,
      throughEntryId: this.lastId,
      firstEntryId: this.firstRetained(),
      writtenBytes: this.totalBytes(),
      syncedThroughEntryId: this.syncedId,
    };
  }

  /** The oldest entry id still on disk; with no segment, the id the next one would start at. */
  private firstRetained(): number {
    return this.segs[0]?.firstId ?? this.lastCut + 1;
  }

  private totalBytes(): number {
    let n = 0;
    for (const s of this.segs) n += s.bytes;
    return n;
  }

  // --- writing ------------------------------------------------------------------------------------

  append(inputs: EvidenceInput[]): AppendResult {
    let appended = 0;
    let refused = 0;
    for (let i = 0; i < inputs.length; i++) {
      if (this.status !== 'open') {
        refused += inputs.length - i;
        break;
      }
      if (this.appendOne(inputs[i])) appended++;
      else refused++;
    }
    return { snapshot: this.snapshot(), appended, refused, state: this.status };
  }

  private appendOne(input: EvidenceInput): boolean {
    let kind: number;
    let body: Uint8Array;
    let boundary: BoundaryFields | null = null;
    try {
      if (input.kind === 'datagram') {
        if (this.track.open === null) return false;
        kind = KIND_DATAGRAM;
        body = encodeDatagramBody({
          receivedMs: input.receivedMs, localIPv4: input.localIPv4, localPort: input.localPort,
          remoteIPv4: input.remoteIPv4, remotePort: input.remotePort, payload: input.bytes,
        });
      } else {
        kind = KIND_BOUNDARY;
        boundary = {
          action: input.action, sessionId: input.sessionId, receivedMs: input.receivedMs,
          reason: input.reason, droppedDatagrams: input.droppedDatagrams,
        };
        if (!WRITE_ACTIONS.has(boundary.action) || !Number.isSafeInteger(boundary.receivedMs) || boundary.receivedMs < 0) return false;
        if (typeof boundary.sessionId !== 'string' || !this.sessionAllows(boundary)) return false;
        if (boundary.action === 'start') {
          // A session id is the 16 random bytes a segment header can carry, as hex: anything else could not be rolled into the next segment.
          if (!SESSION_ID.test(boundary.sessionId)) return false;
          if (input.source !== undefined && input.source !== null) {
            if (!validSource(input.source)) return false;
            boundary.source = cleanSource(input.source);
          }
        }
        body = encodeBoundaryBody(boundary);
        if (body.length > JOURNAL_FRAMING.maxBodyBytes) return false;
      }
    } catch {
      return false;
    }

    // The closing reserve belongs to the entries that close a session: a `stop`
    // (the user's or the forced one) and `interrupted`. Everything else -
    // datagrams, `start`, `suspend`, `resume`, `gap` - stops short of the limit
    // by the reserve, so the `stop` that explains the end always has room to be
    // written. Refusing one of them with a session open writes that `stop`.
    const closes = boundary !== null && (boundary.action === 'stop' || boundary.action === 'interrupted');
    const ceiling = closes ? this.limit : this.limit - LIMITS.closingReserveBytes;
    const result = this.commit(kind, body, input.receivedMs, boundary, ceiling);
    if (result === 'over') {
      this.enterStorageLimit(input.receivedMs);
      return false;
    }
    return result === 'written';
  }

  /**
   * The journal's own rules for a session, applied at append so the files never
   * hold a sequence the reader would have to forgive. A `start` needs no
   * session open; `stop`, `suspend`, `resume` and `interrupted` need the open
   * one, by id. `gap` is evidence about the stream, not about a session, and
   * is held to neither. These are rules for writing: the read side accepts
   * whatever a file contains, so no existing file is made corrupt by them.
   */
  private sessionAllows(b: BoundaryFields): boolean {
    if (b.action === 'start') return this.track.open === null;
    if (b.action === 'gap') return true;
    return this.track.open !== null && b.sessionId === this.track.open;
  }

  private otherBytes(): number {
    return this.options.otherBytes?.() ?? 0;
  }

  /**
   * The journal has reached its limit (less the closing reserve, for anything
   * that does not close a session). Closing the open session on disk is the
   * one write allowed to use the reserve.
   *
   * **If even that does not fit** - `otherBytes()` grew past the reserve - it
   * is not written: the files never go over the limit. The state is still
   * `storage-limit` and the session is left open on disk, so the next `open`
   * with room for it writes the `interrupted` marker a crash would have.
   */
  private enterStorageLimit(receivedMs: number): void {
    if (this.track.open !== null) {
      this.writeBoundary({
        action: 'stop', sessionId: this.track.open, receivedMs, reason: 'storage-limit', droppedDatagrams: null,
      });
    }
    if (this.status === 'open') this.status = 'storage-limit';
  }

  /**
   * A boundary the journal writes itself: the `stop` at the storage limit and
   * the `interrupted` on open. Held to `limitBytes` - the reserve is exactly
   * what these may spend - and never past it. Returns whether it was written;
   * when it was not for want of room, the state is `storage-limit`.
   */
  private writeBoundary(b: BoundaryFields): boolean {
    const result = this.commit(KIND_BOUNDARY, encodeBoundaryBody(b), b.receivedMs, b, this.limit);
    if (result === 'over') {
      if (this.status === 'open') this.status = 'storage-limit';
      return false;
    }
    return result === 'written';
  }

  /**
   * One entry, one write, rolling to a new segment first where the newest is
   * full or is the sealed legacy file. A throw truncates back to the last
   * complete entry if the disk will let it, and the journal stops: it cannot
   * know what state the file is in, and a torn tail is what the next open
   * expects to find. `over` writes nothing: the entry (and a roll's header)
   * would take the dataset past `ceiling`.
   */
  private commit(
    kind: number, body: Uint8Array, receivedMs: number, boundary: BoundaryFields | null, ceiling: number,
  ): 'written' | 'over' | 'failed' {
    // Every caller already refuses a state that is not open; this is the byte-writing choke point, so a read-only
    // journal fails closed here too if a new caller forgets.
    if (this.options.readOnly === true) return 'failed';
    const id = this.lastId + 1;
    const bytes = encodeEntry(JOURNAL_FRAMING, id, kind, body);
    let seg = this.segs[this.segs.length - 1];
    if (seg === undefined) return 'failed';
    const roll = this.rollsFor(bytes.length);
    if (this.overCeiling(bytes.length, roll, ceiling)) return 'over';
    if (roll) {
      const next = this.roll(id, boundary !== null && boundary.action === 'interrupted');
      if (next === null) return 'failed';
      seg = next;
    }
    try {
      seg.file.write(seg.bytes, bytes);
    } catch (e) {
      try { seg.file.truncate(seg.bytes); } catch { /* a torn tail is recoverable; say nothing more */ }
      this.fail(`an entry could not be written: ${(e as Error).message}`);
      return 'failed';
    }
    seg.index.note(id, seg.bytes, this.track.open, receivedMs);
    if (seg.lastId < seg.firstId) seg.firstMs = receivedMs;
    seg.lastId = id;
    seg.lastMs = receivedMs;
    seg.bytes += bytes.length;
    this.lastReceivedMs = receivedMs;
    if (boundary !== null) this.boundaryList.push(boundaryEvidence(this.generationHex, id, boundary, seg.policy, seg.firstId));
    this.lastId = id;
    if (boundary !== null) applyBoundary(this.track, boundary);
    return 'written';
  }

  /**
   * Whether an entry of `entryBytes` starts a new segment: the newest is full, is the sealed legacy file, or
   * holds entries of an older policy than this build writes. The last is how an upgraded dataset starts
   * decoding under the new policy at its next append, the next Start, rather than when the old segment
   * fills (ADR 0066). An older-policy segment with no entry (a roll torn before its first) is written into.
   */
  private rollsFor(entryBytes: number): boolean {
    const seg = this.segs[this.segs.length - 1];
    const holds = seg.lastId >= seg.firstId;
    return seg.legacy || (holds && seg.policy !== NEWEST_POLICY) || (holds && seg.bytes + entryBytes > seg.maxBytes);
  }

  private overCeiling(entryBytes: number, roll: boolean, ceiling: number): boolean {
    return this.totalBytes() + this.otherBytes() + (roll ? SEGMENT_HEADER_BYTES : 0) + entryBytes > ceiling;
  }

  private fail(problem: string): void {
    this.status = 'failed';
    this.problemText = problem;
  }

  /**
   * Starts the segment that will hold entry `nextId`: flushes the one before
   * it, writes the new header (naming the open session and its recorded
   * source, so the segment is readable on its own once the older ones expire)
   * and flushes that, so a crash leaves a header the next open can pair with
   * the previous segment. The entry follows.
   *
   * The header of a roll made to write an `interrupted` names no session: that
   * entry is how the session ends, and it is the first thing in the segment.
   * Returns null, with the state `failed`, if any step fails.
   */
  private roll(nextId: number, closing: boolean): Seg | null {
    const prev = this.segs[this.segs.length - 1];
    const session = this.track.open;
    if (session !== null && !SESSION_ID.test(session)) {
      this.fail(`the session ${JSON.stringify(session)} is not 32 lowercase hex digits, so a new segment cannot name it`);
      return null;
    }
    const name = segmentName(nextId);
    const header = encodeSegmentHeader({
      policyVersion: NEWEST_POLICY, generation: generationFromHex(this.generationHex), createdMs: this.lastReceivedMs,
      firstEntryId: nextId, openSession: session === null || closing ? null : generationFromHex(session),
      source: session === null || closing ? null : this.track.sessionSource,
    });
    let created = false;
    try {
      prev.file.flush();
      this.syncedId = Math.max(this.syncedId, prev.lastId);
      const file = this.dir.create(name);
      created = true;
      file.write(0, header);
      file.flush();
      const seg: Seg = {
        name, legacy: false, file, headerBytes: SEGMENT_HEADER_BYTES, firstId: nextId, lastId: nextId - 1, firstMs: 0,
        lastMs: this.lastReceivedMs, policy: NEWEST_POLICY, bytes: SEGMENT_HEADER_BYTES, maxBytes: segmentBytesFor(this.limit),
        index: new EntryIndex(nextId),
      };
      this.segs.push(seg);
      return seg;
    } catch (e) {
      // A header-only newest is a torn roll the next open removes, but do not leave it for that if it can go now.
      if (created) { try { this.dir.unlink(name); } catch { /* the next open removes it */ } }
      this.fail(`could not start segment ${name}: ${(e as Error).message}`);
      return null;
    }
  }

  /**
   * Retention's one write (ADR 0062). `names` must be the oldest segments, in
   * order, all sealed. An `expired` boundary naming the ids and times that are
   * about to go is appended and synced first; only then are the files
   * unlinked, so a crash between the two leaves the boundary and segments an
   * `open` finishes removing, and never a gap nobody explained.
   *
   * Refused, with nothing written, unless the journal is `open` or at its
   * storage limit and the names are a prefix of `segments()` that is whole and
   * sealed. The boundary may use the closing reserve and never enters the
   * storage limit itself: with no room even for it, nothing is dropped. A drop
   * does not move a journal out of `storage-limit`; `setLimit` does.
   */
  dropSegments(names: string[], reason: 'age' | 'limit' | 'user-before', nowMs: number): AppendResult {
    const refuse = (): AppendResult => ({ snapshot: this.snapshot(), appended: 0, refused: 1, state: this.status });
    const boundary = this.dropBoundary(names, reason, nowMs);
    if (boundary === null) return refuse();
    // With the legacy file alone, this append is the roll that makes it something other than the newest.
    if (this.commit(KIND_BOUNDARY, encodeBoundaryBody(boundary), nowMs, boundary, this.limit) !== 'written') return refuse();
    this.flush();
    if ((this.status as JournalState) === 'failed') return { snapshot: this.snapshot(), appended: 1, refused: 0, state: this.status };
    for (let i = 0; i < names.length; i++) {
      const s = this.segs[0];
      try {
        this.dir.unlink(s.name);
      } catch (e) {
        this.fail(`could not remove ${s.name}: ${(e as Error).message}`);
        break;
      }
      this.segs.shift();
      while (this.boundaryList.length > 0 && this.boundaryList[0].ref.entryId <= s.lastId) this.boundaryList.shift();
    }
    return { snapshot: this.snapshot(), appended: 1, refused: 0, state: this.status };
  }

  /**
   * Whether `dropSegments(names, ...)` would write its boundary: the state, the names (the oldest segments,
   * in order, whole and sealed, all still listed) and the room, the closing reserve included. Retention asks
   * before it makes a cut durable, because a cut the drop then refuses is a promise nothing keeps. `reason`
   * and `nowMs` only size the boundary; the defaults are the widest it can be, so a yes holds for any real call.
   */
  canDropSegments(names: string[], reason: 'age' | 'limit' | 'user-before' = 'user-before', nowMs: number = Number.MAX_SAFE_INTEGER): boolean {
    const boundary = this.dropBoundary(names, reason, nowMs);
    if (boundary === null) return false;
    let bytes: number;
    try { bytes = encodeEntry(JOURNAL_FRAMING, this.lastId + 1, KIND_BOUNDARY, encodeBoundaryBody(boundary)).length; } catch { return false; }
    return !this.overCeiling(bytes, this.rollsFor(bytes), this.limit);
  }

  /** The `expired` boundary a drop of `names` would write, or null for a drop that is refused before any room is asked of. */
  private dropBoundary(names: string[], reason: 'age' | 'limit' | 'user-before', nowMs: number): BoundaryFields | null {
    if (this.status !== 'open' && this.status !== 'storage-limit') return null;
    if (reason !== 'age' && reason !== 'limit' && reason !== 'user-before') return null;
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) return null;
    if (!Array.isArray(names) || names.length === 0 || names.length > this.segs.length) return null;
    const listed = new Set(this.dir.list());
    for (let i = 0; i < names.length; i++) {
      const s = this.segs[i];
      if (names[i] !== s.name || !(s.legacy || i < this.segs.length - 1) || !listed.has(s.name)) return null;
    }
    const first = this.segs[0];
    const last = this.segs[names.length - 1];
    return {
      action: 'expired', sessionId: this.track.open ?? '', receivedMs: nowMs, reason, droppedDatagrams: null,
      source: this.track.recordedSource,
      expired: { fromEntryId: first.firstId, throughEntryId: last.lastId, fromMs: first.firstMs, throughMs: last.lastMs },
    };
  }

  /** Moves `syncedThroughEntryId` and nothing else. A flush that throws fails the journal and moves nothing. */
  flush(): JournalSnapshot {
    if ((this.status === 'open' || this.status === 'storage-limit') && this.syncedId < this.lastId) {
      try {
        this.segs[this.segs.length - 1].file.flush();
        this.syncedId = this.lastId;
      } catch (e) {
        this.fail(`a flush failed: ${(e as Error).message}`);
      }
    }
    return this.snapshot();
  }

  /**
   * Flushes what is unflushed and stops accepting. The files belong to the
   * directory, and are not closed here.
   */
  close(): void {
    this.flush();
    this.status = 'closed';
  }

  // --- reading --------------------------------------------------------------------------------------

  readEvidence(ref: EvidenceRef): Evidence | null {
    if (ref.generation !== this.generationHex) return null;
    if (!Number.isSafeInteger(ref.entryId) || ref.entryId < this.firstRetained() || ref.entryId > this.lastId) return null;
    const idx = this.segIndexOf(ref.entryId);
    if (idx < 0) return null;
    const seg = this.segs[idx];
    const at = this.cursorAt(seg, ref.entryId);
    return at === null ? null : this.decodeAt(seg, ref.entryId, at.offset, at.session).evidence;
  }

  /**
   * Entries after `afterId` and no later than the snapshot's own, across
   * segment boundaries. The caller's limits are capped by the page constants,
   * and one entry over `maxBytes` is still returned, alone: a page that could
   * return nothing would never advance. An `afterId` below the oldest retained
   * entry's predecessor throws `ExpiredRangeError`.
   */
  readPage(snapshot: { generation: string; throughEntryId: number }, afterId: number, maxEntries: number, maxBytes: number): EvidencePage {
    const w = this.walk(snapshot, afterId, maxEntries, maxBytes);
    return { entries: w.items.map((d) => d.evidence), nextAfterId: w.nextAfterId, done: w.done };
  }

  /**
   * `readPage`'s entries as the file holds them: the same walk, so the same checksum and reserved-byte checks,
   * the same generation and expiry errors and the same page bounds. A body is a copy.
   */
  readRawPage(snapshot: { generation: string; throughEntryId: number }, afterId: number, maxEntries: number, maxBytes: number): RawPage {
    const w = this.walk(snapshot, afterId, maxEntries, maxBytes);
    return {
      entries: w.items.map((d) => ({ entryId: d.entryId, kind: d.kind, policy: d.policy, receivedMs: d.receivedMs, body: d.body })),
      nextAfterId: w.nextAfterId,
      done: w.done,
    };
  }

  private walk(
    snapshot: { generation: string; throughEntryId: number }, afterId: number, maxEntries: number, maxBytes: number,
  ): { items: ReadEntry[]; nextAfterId: number; done: boolean } {
    // Task 5 puts this behind IPC, so the numbers are untrusted: NaN would
    // slip through every comparison below and read as "no limit".
    if (!Number.isSafeInteger(afterId) || afterId < 0) throw new RangeError(`afterId ${afterId} is not a non-negative safe integer`);
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError(`maxEntries ${maxEntries} is not a positive safe integer`);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError(`maxBytes ${maxBytes} is not a positive safe integer`);
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    if (afterId < this.firstRetained() - 1) throw new ExpiredRangeError(this.firstRetained());
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    const after = afterId;
    const first = after + 1;
    if (first > through) return { items: [], nextAfterId: Math.min(after, through), done: true };

    const entryCap = Math.max(1, Math.min(maxEntries, LIMITS.pageEntries));
    const byteCap = Math.min(maxBytes, LIMITS.pageBytes);
    let idx = this.segIndexOf(first);
    if (idx < 0) return { items: [], nextAfterId: after, done: true };
    let seg = this.segs[idx];
    const at = this.cursorAt(seg, first);
    if (at === null) return { items: [], nextAfterId: after, done: true };

    const items: ReadEntry[] = [];
    let bytes = 0;
    let offset = at.offset;
    let session = at.session;
    let id = first;
    while (id <= through && items.length < entryCap) {
      if (id > seg.lastId) {
        // The next segment begins where its header ends, with the session this one left open.
        seg = this.segs[++idx];
        if (seg === undefined) break;
        offset = seg.headerBytes;
      }
      const decoded = this.decodeAt(seg, id, offset, session);
      if (items.length > 0 && bytes + decoded.entryBytes > byteCap) break;
      items.push(decoded);
      bytes += decoded.entryBytes;
      offset = decoded.nextOffset;
      session = decoded.sessionAfter;
      id++;
    }
    const last = id - 1;
    return { items, nextAfterId: last, done: last >= through };
  }

  /**
   * The ids an evidence bundle's range covers (ADR 0063): from the lowest id of either kind received in
   * `[fromMs, throughMs]` to the highest received in it, so an entry whose clock stepped back inside the range is
   * in it, and an entry outside it never ends the slice, however far its clock stepped. Entries between the ends
   * go in whatever their time. Null where none is in the range. `locate` is strided on datagrams and cannot say
   * this: the ends are found by the strides' own smallest and largest times, and only the stride that holds each
   * end is read, so the work is a stride or two however long the range. Ids below the oldest retained one are not looked for.
   */
  bundleSlice(snapshot: { generation: string; throughEntryId: number }, fromMs: number, throughMs: number): BundleSlice | null {
    if (!Number.isSafeInteger(fromMs) || fromMs < 0) throw new RangeError(`fromMs ${fromMs} is not a non-negative safe integer`);
    if (!Number.isSafeInteger(throughMs) || throughMs < 0) throw new RangeError(`throughMs ${throughMs} is not a non-negative safe integer`);
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    let first: number | null = null;
    scanFirst: for (const seg of this.segs) {
      if (seg.firstId > through) break;
      for (let slot = 0; slot < seg.index.strides; slot++) {
        const st = seg.index.stride(slot);
        if (st.fromId > through) break scanFirst;
        if (st.maxMs < fromMs || st.minMs > throughMs) continue;
        const hit = this.scanStride(seg, st.fromId, Math.min(st.toId, through), (ms) => ms >= fromMs && ms <= throughMs, false);
        if (hit !== null) { first = hit; break scanFirst; }
      }
    }
    if (first === null) return null;
    let last: number | null = null;
    scanLast: for (let s = this.segs.length - 1; s >= 0; s--) {
      const seg = this.segs[s];
      if (seg.firstId > through) continue;
      for (let slot = seg.index.strides - 1; slot >= 0; slot--) {
        const st = seg.index.stride(slot);
        if (st.fromId > through || st.minMs > throughMs || st.maxMs < fromMs) continue;
        const hit = this.scanStride(seg, st.fromId, Math.min(st.toId, through), (ms) => ms >= fromMs && ms <= throughMs, true);
        if (hit !== null) { last = hit; break scanLast; }
      }
    }
    if (last === null) return null;

    const policies = new Set<number>();
    for (const seg of this.segs) if (seg.firstId <= last && seg.lastId >= first) policies.add(seg.policy);

    return { firstEntryId: first, throughEntryId: last, policies: [...policies].sort((a, b) => a - b), sessionAtStart: this.sessionBefore(first) };
  }

  /** The lowest (or, with `highest`, the highest) id in `[fromId, toId]` of one stride whose receipt time `wanted` accepts. */
  private scanStride(seg: Seg, fromId: number, toId: number, wanted: (ms: number) => boolean, highest: boolean): number | null {
    const at = this.cursorAt(seg, fromId);
    if (at === null) return null;
    let offset = at.offset;
    let session = at.session;
    let found: number | null = null;
    for (let id = fromId; id <= toId; id++) {
      const d = this.decodeAt(seg, id, offset, session);
      if (wanted(d.receivedMs)) {
        found = id;
        if (!highest) return id;
      }
      offset = d.nextOffset;
      session = d.sessionAfter;
    }
    return found;
  }

  /**
   * The session open before `entryId` and what it recorded, or null: the entry's segment header (which names the
   * session open when the segment was made, and its source), then the segment's own boundaries up to the entry.
   * The id of that session's `start` is the newest one the retained boundaries hold, else null: it expired.
   */
  private sessionBefore(entryId: number): { sessionId: string; source: SegmentSource | null; startEntryId: number | null } | null {
    const seg = this.segs[this.segIndexOf(entryId)];
    let session: string | null = null;
    let source: SegmentSource | null = null;
    if (!seg.legacy) {
      const header = decodeSegmentHeader(this.readBytes(seg, 0, SEGMENT_HEADER_BYTES));
      if (!header.ok) throw new Error(`journal: ${seg.name}: ${header.reason}`);
      if (header.value.openSession !== null) {
        session = generationToHex(header.value.openSession);
        source = header.value.source;
      }
    }
    for (const b of this.boundaryList) {
      if (b.ref.entryId >= entryId) break;
      if (b.ref.entryId < seg.firstId) continue;
      if (b.action === 'start') { session = b.sessionId; source = b.source ?? null; }
      else if (b.action === 'stop' || b.action === 'interrupted') { session = null; source = null; }
    }
    if (session === null) return null;
    let startEntryId: number | null = null;
    for (const b of this.boundaryList) {
      if (b.ref.entryId >= entryId) break;
      if (b.action === 'start' && b.sessionId === session) startEntryId = b.ref.entryId;
    }
    return { sessionId: session, source: source === null ? null : { ...source }, startEntryId };
  }

  /**
   * The id ranges, merged and ascending, that might hold a datagram received in
   * `[fromMs, toMs)`, no later than the snapshot. Answered from the indexes
   * alone, and by overlap of each stride's smallest and largest receipt time:
   * a clock that stepped back makes a stride's last entry earlier than its
   * first, and a test on either end would lose the entries between. A range may
   * hold entries outside the window - the reader checks each one it reads - but
   * an id outside every range holds none inside it. Expired ids are simply not
   * in any range; this never throws for them.
   */
  locate(snapshot: { generation: string; throughEntryId: number }, fromMs: number, toMs: number): { fromId: number; toId: number }[] {
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    const out: { fromId: number; toId: number }[] = [];
    for (const seg of this.segs) {
      if (seg.firstId > through) break;
      for (const r of seg.index.strideRanges(fromMs, toMs, through)) {
        const tail = out[out.length - 1];
        if (tail !== undefined && tail.toId + 1 === r.fromId) tail.toId = r.toId;
        else out.push({ ...r });
      }
    }
    return out;
  }

  /**
   * The boundaries after `afterId` and no later than the snapshot, from memory.
   * `nextAfterId` is the last id the answer is complete through - the snapshot's
   * own when `done` - so a cache that stores it knows it has seen every
   * boundary up to there, whether or not the ids in between held any. An
   * `afterId` below the oldest retained entry's predecessor throws
   * `ExpiredRangeError`: those boundaries went with their segments, bar the
   * `expired` ones that say so.
   */
  readBoundaries(
    snapshot: { generation: string; throughEntryId: number }, afterId: number, maxEntries: number,
  ): { entries: BoundaryEvidence[]; nextAfterId: number; done: boolean } {
    if (!Number.isSafeInteger(afterId) || afterId < 0) throw new RangeError(`afterId ${afterId} is not a non-negative safe integer`);
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError(`maxEntries ${maxEntries} is not a positive safe integer`);
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    if (afterId < this.firstRetained() - 1) throw new ExpiredRangeError(this.firstRetained());
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    const list = this.boundaryList;
    let lo = 0;
    let hi = list.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (list[mid].ref.entryId <= afterId) lo = mid + 1; else hi = mid;
    }
    const entries: BoundaryEvidence[] = [];
    let i = lo;
    while (i < list.length && list[i].ref.entryId <= through && entries.length < maxEntries) entries.push(list[i++]);
    const more = i < list.length && list[i].ref.entryId <= through;
    if (more) return { entries, nextAfterId: entries[entries.length - 1].ref.entryId, done: false };
    return { entries, nextAfterId: Math.max(afterId, through), done: true };
  }

  /**
   * The retained segments a snapshot reaches, oldest first, clipped to its last entry: what a reader that
   * replays decode state needs to choose a checkpoint and bound the replay (ADR 0066). A segment's bytes are
   * its size now, so the newest one may count bytes past the snapshot; a bound read from them errs high.
   */
  segmentGeometry(snapshot: { generation: string; throughEntryId: number }): SegmentGeometry[] {
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    const out: SegmentGeometry[] = [];
    for (const seg of this.segs) {
      if (seg.firstId > through || seg.lastId < seg.firstId) break;
      out.push({ firstEntryId: seg.firstId, lastEntryId: Math.min(seg.lastId, through), bytes: seg.bytes, policy: seg.policy });
    }
    return out;
  }

  /** The index in `segs` of the segment holding `entryId`, or -1: a binary search on first ids. */
  private segIndexOf(entryId: number): number {
    let lo = 0;
    let hi = this.segs.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (this.segs[mid].firstId <= entryId) { found = mid; lo = mid + 1; } else hi = mid - 1;
    }
    return found >= 0 && entryId <= this.segs[found].lastId ? found : -1;
  }

  private readBytes(seg: Seg, offset: number, n: number): Uint8Array {
    const out = new Uint8Array(n);
    const got = seg.file.read(offset, out);
    if (got !== n) throw new Error(`journal: wanted ${n} bytes at ${offset} of ${seg.name}, got ${got}`);
    return out;
  }

  /** The offset of `entryId` in `seg` and the session open before it, walking at most one stride of headers. */
  private cursorAt(seg: Seg, entryId: number): { offset: number; session: string | null } | null {
    const cp = seg.index.seek(entryId);
    if (cp === null) return null;
    let id = cp.entryId;
    let offset = cp.offset;
    let session = cp.openSession;
    while (id < entryId) {
      const header = parseEntryHeader(JOURNAL_FRAMING, this.readBytes(seg, offset, ENTRY_HEADER_BYTES));
      if (!header.ok) throw new Error(`journal: ${header.reason} at ${offset} of ${seg.name}`);
      if (header.kind === KIND_BOUNDARY) {
        const b = parseBoundary(this.readBytes(seg, offset + ENTRY_HEADER_BYTES, header.bodyLength));
        if (b.ok) session = sessionAfter(session, b.value);
      }
      offset += ENTRY_HEADER_BYTES + header.bodyLength;
      id++;
    }
    return { offset, session };
  }

  private decodeAt(seg: Seg, entryId: number, offset: number, session: string | null): ReadEntry {
    const headerBytes = this.readBytes(seg, offset, ENTRY_HEADER_BYTES);
    const header = parseEntryHeader(JOURNAL_FRAMING, headerBytes);
    if (!header.ok) throw new Error(`journal: ${header.reason} at ${offset} of ${seg.name}`);
    const body = this.readBytes(seg, offset + ENTRY_HEADER_BYTES, header.bodyLength);
    // Checked again on a read: a file can change under a journal that was
    // fine when it scanned it, and a wrong answer here is evidence that lies.
    if (entryCrc(headerBytes, body) !== header.crc || header.entryId !== entryId) {
      throw new Error(`journal: entry ${entryId} at ${offset} of ${seg.name} no longer matches its checksum`);
    }
    const reserved = entryReservedProblem(headerBytes);
    if (reserved !== null) throw new Error(`journal: entry ${entryId} at ${offset} of ${seg.name}: ${reserved}`);
    const ref: EvidenceRef = { generation: this.generationHex, entryId };
    const entryBytes = ENTRY_HEADER_BYTES + header.bodyLength;
    const nextOffset = offset + entryBytes;
    if (header.kind === KIND_DATAGRAM) {
      const d = decodeDatagramBody(body);
      if (!d.ok || session === null) throw new Error(`journal: entry ${entryId} is not a readable datagram`);
      return {
        evidence: {
          kind: 'datagram', ref, sessionId: session, receivedMs: d.value.receivedMs, receiveOrdinal: entryId,
          localIPv4: d.value.localIPv4, localPort: d.value.localPort,
          remoteIPv4: d.value.remoteIPv4, remotePort: d.value.remotePort, bytes: d.value.payload,
          policy: seg.policy, segmentFirstId: seg.firstId,
        },
        entryId, kind: 1, body, policy: seg.policy, receivedMs: d.value.receivedMs,
        nextOffset, sessionAfter: session, entryBytes,
      };
    }
    const b = parseBoundary(body);
    if (header.kind !== KIND_BOUNDARY || !b.ok) throw new Error(`journal: entry ${entryId} is not a readable boundary`);
    return {
      evidence: boundaryEvidence(this.generationHex, entryId, b.value, seg.policy, seg.firstId),
      entryId, kind: 2, body, policy: seg.policy, receivedMs: b.value.receivedMs,
      nextOffset, sessionAfter: sessionAfter(session, b.value), entryBytes,
    };
  }
}

/** `applyBoundary`'s session, for a cursor that carries only the session and not the sources. */
function sessionAfter(open: string | null, b: BoundaryFields): string | null {
  if (b.action === 'start') return b.sessionId;
  if (b.action === 'stop' || b.action === 'interrupted') return null;
  return open;
}
