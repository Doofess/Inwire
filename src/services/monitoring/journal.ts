/**
 * The monitoring evidence journal (ADR 0059): every datagram received from the
 * configured exporter and the lifecycle boundaries around them, in one file,
 * and **the only authority over what was received**. The rollup sidecar is a
 * cache; this is not.
 *
 * Stored-format handling only. Nothing here reads a NetFlow header: a payload
 * is bytes, and the Worker that decodes them is a different process with a
 * different policy version.
 *
 * ## What a failure does to the file
 *
 * - **A torn tail** - an append that did not finish - is truncated, and only
 *   by `open`. `recoverJournal` is the same scan without the truncation, so
 *   the sheet can say what it would do before anything is touched.
 * - **Anything else** - a bad entry with bytes behind it, a skipped id, a
 *   datagram with no session, an unknown format or policy version - leaves the
 *   file exactly as it was, refuses every append and keeps the history before
 *   it readable. Later evidence is never truncated on a guess.
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
  decodeDatagramBody, decodeFileHeader, encodeDatagramBody, encodeEntry, encodeFileHeader,
  entryCrc, entryReservedProblem, generationToHex, isHeaderPrefix, parseEntryHeader, scanEntries,
} from './journalCodec';
import {
  DECODER_POLICY_VERSION, FORMAT_VERSION, LIMITS,
  type BoundaryAction, type BoundaryEvidence, type DatagramEvidence, type Evidence,
  type EvidencePage, type EvidenceRef, type JournalSnapshot,
} from './types';

// --- the vocabulary ------------------------------------------------------------------------

/** What a caller hands to `append`; the journal assigns the id and the session. */
export type EvidenceInput =
  | Omit<DatagramEvidence, 'ref' | 'receiveOrdinal' | 'sessionId'>
  | Omit<BoundaryEvidence, 'ref'>;

export type JournalState = 'open' | 'storage-limit' | 'refused-corrupt' | 'refused-version' | 'failed' | 'closed';

export interface AppendResult {
  snapshot: JournalSnapshot;
  /** Inputs that became entries. A `stop` the journal wrote itself at the storage limit is not counted. */
  appended: number;
  refused: number;
  state: JournalState;
}

export interface JournalOptions {
  /** The whole dataset's bound: this file plus `otherBytes()`. */
  limitBytes: number;
  /** The sidecar's size, so one limit covers both files. */
  otherBytes?: () => number;
  randomBytes?: (n: number) => Uint8Array;
  nowMs?: () => number;
}

export interface RecoveryResult {
  /** 32 lowercase hex digits, or null where the file has no readable header. */
  generation: string | null;
  completeEntries: number;
  lastEntryId: number;
  /** The end of the last entry that was accepted (or the header's, for an unknown version). */
  validBytes: number;
  tornTail: { fromOffset: number; bytes: number } | null;
  /**
   * `empty`: no complete header, so nothing to lose; `ok`: the whole file is
   * entries and at most a torn tail; `corrupt` and `unknown-version`: preserved.
   */
  status: 'ok' | 'empty' | 'corrupt' | 'unknown-version';
  problem?: string;
}

/** A snapshot of another generation: the journal under it was replaced. A query maps this to `stale-generation`. */
export class StaleGenerationError extends Error {
  constructor(readonly wanted: string, readonly actual: string) {
    super(`snapshot of generation ${wanted} asked of generation ${actual}`);
    this.name = 'StaleGenerationError';
  }
}

// --- boundaries -------------------------------------------------------------------------------

const ACTIONS: ReadonlySet<string> = new Set<BoundaryAction>(['start', 'stop', 'suspend', 'resume', 'interrupted', 'gap']);
const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

interface BoundaryFields {
  action: BoundaryAction;
  sessionId: string;
  receivedMs: number;
  reason: string;
  droppedDatagrams: number | null;
}

type BoundaryParse = { ok: true; value: BoundaryFields } | { ok: false; reason: string };

/**
 * A reader ignores fields it does not know. Of the known ones, `action`,
 * `sessionId` and `receivedMs` are required: without them the entry cannot
 * be placed. `reason` and `droppedDatagrams` default, and a wrong-typed one
 * defaults too rather than condemning the entry - it is a count a human reads,
 * not a thing the journal's structure depends on.
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
  if (typeof o.action !== 'string' || !ACTIONS.has(o.action)) return { ok: false, reason: 'a boundary has no known action' };
  if (typeof o.sessionId !== 'string') return { ok: false, reason: 'a boundary has no sessionId' };
  if (typeof o.receivedMs !== 'number' || !Number.isSafeInteger(o.receivedMs) || o.receivedMs < 0) {
    return { ok: false, reason: 'a boundary has no receivedMs' };
  }
  return {
    ok: true,
    value: {
      action: o.action as BoundaryAction,
      sessionId: o.sessionId,
      receivedMs: o.receivedMs,
      reason: typeof o.reason === 'string' ? o.reason : '',
      droppedDatagrams: typeof o.droppedDatagrams === 'number' && Number.isSafeInteger(o.droppedDatagrams) && o.droppedDatagrams >= 0
        ? o.droppedDatagrams
        : null,
    },
  };
}

function encodeBoundary(b: BoundaryFields): Uint8Array {
  return utf8.encode(JSON.stringify({
    action: b.action,
    sessionId: b.sessionId,
    receivedMs: b.receivedMs,
    reason: b.reason,
    droppedDatagrams: b.droppedDatagrams,
  }));
}

/**
 * Which session a boundary leaves open. `suspend` and `resume` leave it as it
 * was: a suspended session is still one that a crash must close with an
 * `interrupted`, and a datagram that arrives during one is still evidence.
 */
function sessionAfter(open: string | null, b: BoundaryFields): string | null {
  if (b.action === 'start') return b.sessionId;
  if (b.action === 'stop' || b.action === 'interrupted') return null;
  return open;
}

// --- scanning ----------------------------------------------------------------------------------

interface JournalScan extends RecoveryResult {
  createdMs: number;
  openSession: string | null;
  lastReceivedMs: number;
  index: EntryIndex;
}

function scanJournal(file: BlockFile): JournalScan {
  const index = new EntryIndex();
  const base: JournalScan = {
    generation: null, completeEntries: 0, lastEntryId: 0, validBytes: 0, tornTail: null, status: 'empty',
    createdMs: 0, openSession: null, lastReceivedMs: 0, index,
  };
  const size = file.size();
  if (size === 0) return base;

  if (size < FILE_HEADER_BYTES) {
    const head = new Uint8Array(size);
    file.read(0, head);
    // Bytes that are not the start of our header are somebody else's file, and
    // not ours to discard.
    return isHeaderPrefix(JOURNAL_FRAMING, head)
      ? { ...base, tornTail: { fromOffset: 0, bytes: size } }
      : { ...base, status: 'corrupt', problem: 'the file is not a monitoring journal' };
  }

  const headerBytes = new Uint8Array(FILE_HEADER_BYTES);
  file.read(0, headerBytes);
  const header = decodeFileHeader(JOURNAL_FRAMING, headerBytes);
  if (!header.ok) return { ...base, status: 'corrupt', problem: header.reason };
  const generation = generationToHex(header.generation);
  const known = { ...base, generation, createdMs: header.createdMs, lastReceivedMs: header.createdMs, validBytes: FILE_HEADER_BYTES };
  if (header.formatVersion !== FORMAT_VERSION || header.policyVersion !== DECODER_POLICY_VERSION) {
    return {
      ...known,
      status: 'unknown-version',
      problem: `format ${header.formatVersion} policy ${header.policyVersion}; this build reads format ${FORMAT_VERSION} policy ${DECODER_POLICY_VERSION}`,
    };
  }

  let open: string | null = null;
  let lastReceivedMs = header.createdMs;
  const outcome = scanEntries(file, JOURNAL_FRAMING, FILE_HEADER_BYTES, 0, (e) => {
    const before = open;
    if (e.kind === KIND_DATAGRAM) {
      if (open === null) return 'a datagram with no open session';
      const d = decodeDatagramBody(e.body);
      if (!d.ok) return d.reason;
      lastReceivedMs = d.value.receivedMs;
    } else if (e.kind === KIND_BOUNDARY) {
      const b = parseBoundary(e.body);
      if (!b.ok) return b.reason;
      open = sessionAfter(open, b.value);
      lastReceivedMs = b.value.receivedMs;
    } else {
      return `unknown kind ${e.kind}`;
    }
    index.note(e.entryId, e.offset, before);
    return null;
  });

  return {
    ...known,
    completeEntries: outcome.entries,
    lastEntryId: outcome.lastEntryId,
    validBytes: outcome.validEnd,
    tornTail: outcome.tornTail,
    status: outcome.problem === null ? 'ok' : 'corrupt',
    ...(outcome.problem === null ? {} : { problem: outcome.problem }),
    openSession: open,
    lastReceivedMs,
  };
}

/**
 * What `open` would find, without changing anything. Never truncates: a
 * `tornTail` here is a report.
 */
export function recoverJournal(file: BlockFile): RecoveryResult {
  const s = scanJournal(file);
  return {
    generation: s.generation,
    completeEntries: s.completeEntries,
    lastEntryId: s.lastEntryId,
    validBytes: s.validBytes,
    tornTail: s.tornTail,
    status: s.status,
    ...(s.problem === undefined ? {} : { problem: s.problem }),
  };
}

function defaultRandom(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// --- the journal ----------------------------------------------------------------------------------

export class MonitoringJournal {
  private end: number;
  private lastId: number;
  private syncedId = 0;
  private status: JournalState;
  private openSession: string | null;
  private readonly index: EntryIndex;
  private readonly generationHex: string;

  private constructor(
    private readonly file: BlockFile,
    private readonly options: JournalOptions,
    init: { generation: string; end: number; lastId: number; state: JournalState; openSession: string | null; index: EntryIndex },
  ) {
    this.generationHex = init.generation;
    this.end = init.end;
    this.lastId = init.lastId;
    this.status = init.state;
    this.openSession = init.openSession;
    this.index = init.index;
  }

  /**
   * The only way to get a journal. An empty file (or one holding nothing but a
   * torn header) gets a new header and a new generation; any other file's
   * generation is read and never replaced.
   */
  static open(file: BlockFile, options: JournalOptions): { journal: MonitoringJournal; recovery: RecoveryResult } {
    const scan = scanJournal(file);
    const recovery: RecoveryResult = {
      generation: scan.generation,
      completeEntries: scan.completeEntries,
      lastEntryId: scan.lastEntryId,
      validBytes: scan.validBytes,
      tornTail: scan.tornTail,
      status: scan.status,
      ...(scan.problem === undefined ? {} : { problem: scan.problem }),
    };
    const refused = (state: JournalState): MonitoringJournal => new MonitoringJournal(file, options, {
      generation: scan.generation ?? '', end: scan.validBytes, lastId: scan.lastEntryId, state,
      openSession: null, index: scan.index,
    });

    if (scan.status === 'corrupt') return { journal: refused('refused-corrupt'), recovery };
    if (scan.status === 'unknown-version') return { journal: refused('refused-version'), recovery };

    if (scan.status === 'empty') {
      const bytes = (options.randomBytes ?? defaultRandom)(16);
      // A caller bug, refused before the file is touched: a generation of the
      // wrong length would otherwise be a header nobody could read back.
      if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
        throw new RangeError(`randomBytes(16) returned ${bytes instanceof Uint8Array ? `${bytes.length} bytes` : 'something that is not a Uint8Array'}; a generation is exactly 16`);
      }
      const header = encodeFileHeader(JOURNAL_FRAMING, { generation: bytes, createdMs: (options.nowMs ?? Date.now)() });
      let state: JournalState = 'open';
      try {
        if (file.size() > 0) file.truncate(0);
        file.write(0, header);
      } catch {
        state = 'failed';
      }
      const journal = new MonitoringJournal(file, options, {
        generation: generationToHex(bytes), end: FILE_HEADER_BYTES, lastId: 0, state,
        openSession: null, index: new EntryIndex(),
      });
      return { journal, recovery };
    }

    let state: JournalState = 'open';
    if (scan.tornTail !== null) {
      try {
        file.truncate(scan.validBytes);
      } catch {
        state = 'failed';
      }
    }
    const journal = new MonitoringJournal(file, options, {
      generation: scan.generation!, end: scan.validBytes, lastId: scan.lastEntryId, state,
      openSession: scan.openSession, index: scan.index,
    });
    // A session a crash left open. `receivedMs` is the last entry's own, so the
    // gap runs from the last thing seen, and no count is invented.
    if (state === 'open' && scan.openSession !== null) {
      journal.writeBoundary({
        action: 'interrupted', sessionId: scan.openSession, receivedMs: scan.lastReceivedMs,
        reason: 'the previous run ended without a stop', droppedDatagrams: null,
      });
    }
    return { journal, recovery };
  }

  get state(): JournalState { return this.status; }

  snapshot(): JournalSnapshot {
    return {
      generation: this.generationHex,
      throughEntryId: this.lastId,
      writtenBytes: this.end,
      syncedThroughEntryId: this.syncedId,
    };
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
        if (this.openSession === null) return false;
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
        if (!ACTIONS.has(boundary.action) || !Number.isSafeInteger(boundary.receivedMs) || boundary.receivedMs < 0) return false;
        if (typeof boundary.sessionId !== 'string' || !this.sessionAllows(boundary)) return false;
        body = encodeBoundary(boundary);
        if (body.length > JOURNAL_FRAMING.maxBodyBytes) return false;
      }
    } catch {
      return false;
    }

    const entryBytes = ENTRY_HEADER_BYTES + body.length;
    const total = this.end + this.otherBytes();
    // The closing reserve belongs to the entries that close a session: a `stop`
    // (the user's or the forced one) and `interrupted`. Everything else -
    // datagrams, `start`, `suspend`, `resume`, `gap` - stops short of the limit
    // by the reserve, so the `stop` that explains the end always has room to be
    // written. Refusing one of them with a session open writes that `stop`.
    const closes = boundary !== null && (boundary.action === 'stop' || boundary.action === 'interrupted');
    const ceiling = closes ? this.options.limitBytes : this.options.limitBytes - LIMITS.closingReserveBytes;
    if (total + entryBytes > ceiling) {
      this.enterStorageLimit(input.receivedMs);
      return false;
    }

    const written = this.writeEntry(kind, body);
    if (!written) return false;
    if (boundary !== null) this.afterBoundary(boundary);
    return true;
  }

  /**
   * The journal's own rules for a session, applied at append so the file never
   * holds a sequence the reader would have to forgive. A `start` needs no
   * session open; `stop`, `suspend`, `resume` and `interrupted` need the open
   * one, by id. `gap` is evidence about the stream, not about a session, and
   * is held to neither. These are rules for writing: the read side accepts
   * whatever a file contains, so no existing file is made corrupt by them.
   */
  private sessionAllows(b: BoundaryFields): boolean {
    if (b.action === 'start') return this.openSession === null;
    if (b.action === 'gap') return true;
    return this.openSession !== null && b.sessionId === this.openSession;
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
   * is not written: the file never goes over the limit. The state is still
   * `storage-limit` and the session is left open on disk, so the next `open`
   * with room for it writes the `interrupted` marker a crash would have.
   */
  private enterStorageLimit(receivedMs: number): void {
    if (this.openSession !== null) {
      this.writeBoundary({
        action: 'stop', sessionId: this.openSession, receivedMs, reason: 'storage-limit', droppedDatagrams: null,
      });
    }
    if (this.status === 'open') this.status = 'storage-limit';
  }

  /**
   * A boundary the journal writes itself: the `stop` at the storage limit and
   * the `interrupted` on open. Held to `limitBytes` - the reserve is exactly
   * what these may spend - and never past it. Returns whether it was written;
   * when it was not, the state is `storage-limit`.
   */
  private writeBoundary(b: BoundaryFields): boolean {
    const body = encodeBoundary(b);
    if (this.end + this.otherBytes() + ENTRY_HEADER_BYTES + body.length > this.options.limitBytes) {
      if (this.status === 'open') this.status = 'storage-limit';
      return false;
    }
    if (!this.writeEntry(KIND_BOUNDARY, body)) return false;
    this.afterBoundary(b);
    return true;
  }

  private afterBoundary(b: BoundaryFields): void {
    this.openSession = sessionAfter(this.openSession, b);
  }

  /**
   * One entry, one write. A throw truncates back to the last complete entry
   * if the disk will let it, and the journal stops: it cannot know what state
   * the file is in, and a torn tail is what the next open expects to find.
   */
  private writeEntry(kind: number, body: Uint8Array): boolean {
    const id = this.lastId + 1;
    const bytes = encodeEntry(JOURNAL_FRAMING, id, kind, body);
    try {
      this.file.write(this.end, bytes);
    } catch {
      try { this.file.truncate(this.end); } catch { /* a torn tail is recoverable; say nothing more */ }
      this.status = 'failed';
      return false;
    }
    this.index.note(id, this.end, this.openSession);
    this.end += bytes.length;
    this.lastId = id;
    return true;
  }

  /** Moves `syncedThroughEntryId` and nothing else. A flush that throws fails the journal and moves nothing. */
  flush(): JournalSnapshot {
    if ((this.status === 'open' || this.status === 'storage-limit') && this.syncedId < this.lastId) {
      try {
        this.file.flush();
        this.syncedId = this.lastId;
      } catch {
        this.status = 'failed';
      }
    }
    return this.snapshot();
  }

  /**
   * Flushes what is unflushed and stops accepting. The file belongs to whoever
   * opened it, and is not closed here.
   */
  close(): void {
    this.flush();
    this.status = 'closed';
  }

  // --- reading --------------------------------------------------------------------------------------

  readEvidence(ref: EvidenceRef): Evidence | null {
    if (ref.generation !== this.generationHex) return null;
    if (!Number.isSafeInteger(ref.entryId) || ref.entryId < 1 || ref.entryId > this.lastId) return null;
    const at = this.cursorAt(ref.entryId);
    return at === null ? null : this.decodeAt(ref.entryId, at.offset, at.session).evidence;
  }

  /**
   * Entries after `afterId` and no later than the snapshot's own. The caller's
   * limits are capped by the page constants, and one entry over `maxBytes` is
   * still returned, alone: a page that could return nothing would never advance.
   */
  readPage(snapshot: { generation: string; throughEntryId: number }, afterId: number, maxEntries: number, maxBytes: number): EvidencePage {
    // Task 5 puts this behind IPC, so the numbers are untrusted: NaN would
    // slip through every comparison below and read as "no limit".
    if (!Number.isSafeInteger(afterId) || afterId < 0) throw new RangeError(`afterId ${afterId} is not a non-negative safe integer`);
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError(`maxEntries ${maxEntries} is not a positive safe integer`);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError(`maxBytes ${maxBytes} is not a positive safe integer`);
    if (snapshot.generation !== this.generationHex) throw new StaleGenerationError(snapshot.generation, this.generationHex);
    const through = Math.min(snapshot.throughEntryId, this.lastId);
    const after = afterId;
    const first = after + 1;
    if (first > through) return { entries: [], nextAfterId: Math.min(after, through), done: true };

    const entryCap = Math.max(1, Math.min(maxEntries, LIMITS.pageEntries));
    const byteCap = Math.min(maxBytes, LIMITS.pageBytes);
    const at = this.cursorAt(first);
    if (at === null) return { entries: [], nextAfterId: after, done: true };

    const entries: Evidence[] = [];
    let bytes = 0;
    let offset = at.offset;
    let session = at.session;
    let id = first;
    while (id <= through && entries.length < entryCap) {
      const decoded = this.decodeAt(id, offset, session);
      if (entries.length > 0 && bytes + decoded.entryBytes > byteCap) break;
      entries.push(decoded.evidence);
      bytes += decoded.entryBytes;
      offset = decoded.nextOffset;
      session = decoded.sessionAfter;
      id++;
    }
    const last = id - 1;
    return { entries, nextAfterId: last, done: last >= through };
  }

  private readBytes(offset: number, n: number): Uint8Array {
    const out = new Uint8Array(n);
    const got = this.file.read(offset, out);
    if (got !== n) throw new Error(`journal: wanted ${n} bytes at ${offset}, got ${got}`);
    return out;
  }

  /** The offset of `entryId` and the session open before it, walking at most one stride of headers. */
  private cursorAt(entryId: number): { offset: number; session: string | null } | null {
    const cp = this.index.seek(entryId);
    if (cp === null) return null;
    let id = cp.entryId;
    let offset = cp.offset;
    let session = cp.openSession;
    while (id < entryId) {
      const header = parseEntryHeader(JOURNAL_FRAMING, this.readBytes(offset, ENTRY_HEADER_BYTES));
      if (!header.ok) throw new Error(`journal: ${header.reason} at ${offset}`);
      if (header.kind === KIND_BOUNDARY) {
        const b = parseBoundary(this.readBytes(offset + ENTRY_HEADER_BYTES, header.bodyLength));
        if (b.ok) session = sessionAfter(session, b.value);
      }
      offset += ENTRY_HEADER_BYTES + header.bodyLength;
      id++;
    }
    return { offset, session };
  }

  private decodeAt(entryId: number, offset: number, session: string | null): {
    evidence: Evidence; nextOffset: number; sessionAfter: string | null; entryBytes: number;
  } {
    const headerBytes = this.readBytes(offset, ENTRY_HEADER_BYTES);
    const header = parseEntryHeader(JOURNAL_FRAMING, headerBytes);
    if (!header.ok) throw new Error(`journal: ${header.reason} at ${offset}`);
    const body = this.readBytes(offset + ENTRY_HEADER_BYTES, header.bodyLength);
    // Checked again on a read: a file can change under a journal that was
    // fine when it scanned it, and a wrong answer here is evidence that lies.
    if (entryCrc(headerBytes, body) !== header.crc || header.entryId !== entryId) {
      throw new Error(`journal: entry ${entryId} at ${offset} no longer matches its checksum`);
    }
    const reserved = entryReservedProblem(headerBytes);
    if (reserved !== null) throw new Error(`journal: entry ${entryId} at ${offset}: ${reserved}`);
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
        },
        nextOffset, sessionAfter: session, entryBytes,
      };
    }
    const b = parseBoundary(body);
    if (header.kind !== KIND_BOUNDARY || !b.ok) throw new Error(`journal: entry ${entryId} is not a readable boundary`);
    return {
      evidence: {
        kind: 'boundary', ref, sessionId: b.value.sessionId, receivedMs: b.value.receivedMs,
        action: b.value.action, reason: b.value.reason, droppedDatagrams: b.value.droppedDatagrams,
      },
      nextOffset, sessionAfter: sessionAfter(session, b.value), entryBytes,
    };
  }
}
