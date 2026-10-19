/**
 * The sealed archive and the expiry that fills it (ADR 0062).
 *
 * When whole segments leave the journal their datagrams go, and what is kept
 * is what a history query can still answer from: each source's minute as a
 * rollup, written here before the segments are unlinked. The archive is a
 * file of its own, `archive.iwma`, in the same framing as the journal and the
 * sidecar (magic `INWIREMA`). Unlike the sidecar it is **not a cache**: nothing
 * can rebuild it, so it is never reset, never repaired and never rewritten.
 * A damaged one is preserved as found, refuses appends, and says
 * `history-lost` for every read.
 *
 * Two entry kinds. A *minute* (kind 1) is one source's minute from one
 * expiry; a *cut* (kind 2) closes an expiry and records the range it took out.
 * Fragments are readable only once the cut behind them is on disk, so an
 * expiry that died between the two leaves nothing a reader could trust: open
 * truncates those fragments and the expiry runs again from the journal,
 * which still holds everything.
 *
 * No `node:*` and no Electron.
 */
import {
  ENTRY_HEADER_BYTES, FILE_HEADER_BYTES, decodeFileHeader, encodeEntry, encodeFileHeader, isHeaderPrefix, scanEntries,
  type Framing,
} from './journalCodec';
import type { MonitoringJournal } from './journal';
import type { ExpiryPlan } from './retention';
import { EngineAdmission, MinuteAccumulator, MinuteAggregator, feedEntry } from './rollup';
import { encodeMinuteRollup, type Deflate } from './rollupCodec';
import type { RollupStore } from './rollupStore';
import { ACCEPTED_POLICIES, LIMITS, WRITE_POLICY_VERSION, type Evidence, type MinuteRollup, type SessionContext } from './types';

export const ARCHIVE_FRAMING: Framing = { magic: 'INWIREMA', maxBodyBytes: 1 << 20 };

const KIND_MINUTE = 1;
const KIND_CUT = 2;
/** From/through ids and times (4 x u64), the fragment count, the reason, three reserved bytes, the checkpoint length. */
const CUT_FIXED_BYTES = 44;
const REASONS: readonly ArchiveCut['reason'][] = ['age', 'limit', 'user-before'];

const utf8 = new TextEncoder();
const utf8d = new TextDecoder('utf-8', { fatal: true });

export interface ArchivedMinute {
  sourceKey: string;
  minuteMs: number;
  /** The last journal entry that contributed to this fragment. */
  throughEntryId: number;
  /** The decoder policy the rollup bytes were written under; the first two bytes of `bytes` say the same. */
  policyVersion: number;
  bytes: Uint8Array;
}

/** One finished expiry: the range that left the journal, and how many fragments of it are in the archive. */
export interface ArchiveCut {
  fromEntryId: number;
  throughEntryId: number;
  fromMs: number;
  throughMs: number;
  fragments: number;
  reason: 'age' | 'limit' | 'user-before';
  /** Reserved for the admission state a later policy may carry; empty in this one. */
  checkpoint: Uint8Array;
}

/**
 * `ok`: opened as written. `empty`: a new file got its header. `truncated-unfinished`: fragments
 * with no cut behind them were cut off. `corrupt`: damage with bytes behind it, preserved.
 * `failed`: the file could not be read or written.
 */
export type ArchiveStatus = 'ok' | 'empty' | 'truncated-unfinished' | 'corrupt' | 'failed';

interface BlockFileLike {
  read(offset: number, into: Uint8Array): number;
  write(offset: number, from: Uint8Array): void;
  truncate(length: number): void;
  flush(): void;
  size(): number;
}

interface Located { minuteMs: number; throughEntryId: number; offset: number; length: number; policy: number }

const cloneCut = (c: ArchiveCut): ArchiveCut => ({ ...c, checkpoint: c.checkpoint.slice() });

function safeU64(v: DataView, at: number): number | null {
  const n = v.getBigUint64(at, true);
  return n > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(n);
}

export class ArchiveStore {
  private state: 'ok' | 'corrupt' | 'failed' = 'ok';
  private current: ArchiveStatus = 'ok';
  private gen: Uint8Array | null = null;
  private end = FILE_HEADER_BYTES;
  private lastId = 0;
  private readonly minutes = new Map<string, Located[]>();
  private cutList: ArchiveCut[] = [];

  private constructor(private readonly file: BlockFileLike) {}

  static open(
    file: BlockFileLike, init: { generation: Uint8Array; createdMs: number },
  ): { store: ArchiveStore; status: ArchiveStatus } {
    const store = new ArchiveStore(file);
    store.openFile(init);
    return { store, status: store.current };
  }

  private fail(): void {
    this.state = 'failed';
    this.current = 'failed';
    this.minutes.clear();
    this.cutList = [];
  }

  private corrupt(): void {
    this.state = 'corrupt';
    this.current = 'corrupt';
    this.minutes.clear();
    this.cutList = [];
  }

  private fresh(init: { generation: Uint8Array; createdMs: number }): void {
    // The archive's header carries no policy: each minute names its own, so policy field 0.
    const header = encodeFileHeader(ARCHIVE_FRAMING, { generation: init.generation, createdMs: init.createdMs, policyVersion: 0 });
    this.file.write(0, header);
    this.file.flush();
    this.gen = init.generation.slice();
    this.end = FILE_HEADER_BYTES;
    this.current = 'empty';
  }

  private openFile(init: { generation: Uint8Array; createdMs: number }): void {
    try {
      const size = this.file.size();
      if (size === 0) { this.fresh(init); return; }
      if (size < FILE_HEADER_BYTES) {
        const head = new Uint8Array(size);
        this.file.read(0, head);
        // Part of our own header: the first write never finished. Anything else is someone else's file.
        if (!isHeaderPrefix(ARCHIVE_FRAMING, head)) { this.corrupt(); return; }
        this.file.truncate(0);
        this.fresh(init);
        return;
      }
      const head = new Uint8Array(FILE_HEADER_BYTES);
      this.file.read(0, head);
      const h = decodeFileHeader(ARCHIVE_FRAMING, head);
      if (!h.ok || h.formatVersion !== 1) { this.corrupt(); return; }
      this.gen = h.generation;

      const pending: [string, Located][] = [];
      let lastCut: ArchiveCut | null = null;
      let lastCutEnd = FILE_HEADER_BYTES;
      let lastCutId = 0;
      const cuts: ArchiveCut[] = [];
      const minutes = new Map<string, Located[]>();
      const scan = scanEntries(this.file, ARCHIVE_FRAMING, FILE_HEADER_BYTES, 0, (e) => {
        const b = e.body;
        const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
        if (e.kind === KIND_MINUTE) {
          if (b.length < 2) return 'a minute is cut short';
          const keyLength = v.getUint16(0, true);
          if (keyLength === 0 || b.length < 2 + keyLength + 16 + 2) return 'a minute is shorter than its fields';
          let key: string;
          try { key = utf8d.decode(b.subarray(2, 2 + keyLength)); } catch { return 'a source key is not UTF-8'; }
          const minuteMs = safeU64(v, 2 + keyLength);
          const through = safeU64(v, 2 + keyLength + 8);
          if (minuteMs === null || through === null) return 'a minute\'s time or entry id is out of range';
          const at = 2 + keyLength + 16;
          pending.push([key, {
            minuteMs, throughEntryId: through, offset: e.offset + ENTRY_HEADER_BYTES + at, length: b.length - at, policy: v.getUint16(at, true),
          }]);
          return null;
        }
        if (e.kind === KIND_CUT) {
          if (b.length < CUT_FIXED_BYTES) return 'a cut is shorter than its fields';
          const fromEntryId = safeU64(v, 0);
          const throughEntryId = safeU64(v, 8);
          const fromMs = safeU64(v, 16);
          const throughMs = safeU64(v, 24);
          if (fromEntryId === null || throughEntryId === null || fromMs === null || throughMs === null) return 'a cut\'s range is out of range';
          const fragments = v.getUint32(32, true);
          const reason = REASONS[b[36] - 1];
          if (reason === undefined) return `a cut's reason byte is ${b[36]}`;
          if (b[37] !== 0 || b[38] !== 0 || b[39] !== 0) return 'a cut\'s reserved bytes are not zero';
          const checkpointLength = v.getUint32(40, true);
          if (b.length !== CUT_FIXED_BYTES + checkpointLength) return 'a cut\'s checkpoint length disagrees with its size';
          if (fragments !== pending.length) return `a cut counts ${fragments} fragments and ${pending.length} precede it`;
          if (fromEntryId < 1 || throughEntryId < fromEntryId || throughMs < fromMs) return 'a cut\'s range runs backwards';
          if (lastCut !== null && fromEntryId <= lastCut.throughEntryId) return 'a cut starts inside the one before it';
          const cut: ArchiveCut = {
            fromEntryId, throughEntryId, fromMs, throughMs, fragments, reason, checkpoint: b.slice(CUT_FIXED_BYTES),
          };
          for (const [key, loc] of pending) {
            const list = minutes.get(key);
            if (list === undefined) minutes.set(key, [loc]); else list.push(loc);
          }
          pending.length = 0;
          cuts.push(cut);
          lastCut = cut;
          lastCutEnd = e.end;
          lastCutId = e.entryId;
          return null;
        }
        return `an unknown entry kind ${e.kind}`;
      });
      if (scan.problem !== null) { this.corrupt(); return; }

      this.status0(scan.validEnd, lastCutEnd, scan.tornTail !== null, pending.length > 0);
      if (this.state !== 'ok') return;
      for (const [k, list] of minutes) this.minutes.set(k, list);
      this.cutList = cuts;
      this.end = lastCutEnd;
      this.lastId = lastCutId;
    } catch {
      this.fail();
    }
  }

  /** The truncations an open performs, and the status it reports. Throws into `openFile`'s catch. */
  private status0(validEnd: number, lastCutEnd: number, torn: boolean, hasPending: boolean): void {
    if (hasPending || validEnd > lastCutEnd) {
      this.file.truncate(lastCutEnd);
      this.current = 'truncated-unfinished';
    } else {
      if (torn) this.file.truncate(validEnd);
      this.current = 'ok';
    }
  }

  status(): ArchiveStatus { return this.current; }

  generation(): Uint8Array | null { return this.gen === null ? null : this.gen.slice(); }

  bytes(): number {
    try { return this.file.size(); } catch { return 0; }
  }

  lastCut(): ArchiveCut | null {
    const c = this.cutList[this.cutList.length - 1];
    return c === undefined ? null : cloneCut(c);
  }

  cuts(): ArchiveCut[] { return this.cutList.map(cloneCut); }

  /** The receipt time up to which the archive holds the minutes of what expired; null before the first cut or when it cannot be trusted. */
  coveredThroughMs(): number | null {
    const c = this.cutList[this.cutList.length - 1];
    return c === undefined ? null : c.throughMs;
  }

  /** Every source key the archive holds a minute for, sorted: the engines the expired entries admitted. */
  sources(): string[] { return [...this.minutes.keys()].sort(); }

  /**
   * One source's fragments for the minutes in `[fromMs, toMs)`, in minute order. A range over `maxBytes` of
   * rollup is refused, never clipped. An archive that is damaged or unreadable, and a minute under a policy
   * this build does not accept, answer `history-lost`: the caller shows an unknown, never a zero.
   */
  read(sourceKey: string, fromMs: number, toMs: number, maxBytes: number): ArchivedMinute[] | 'history-lost' | 'range-too-large' {
    if (this.state !== 'ok') return 'history-lost';
    const hits = (this.minutes.get(sourceKey) ?? []).filter((m) => m.minuteMs >= fromMs && m.minuteMs < toMs);
    hits.sort((a, b) => a.minuteMs - b.minuteMs);
    if (hits.some((m) => !ACCEPTED_POLICIES.includes(m.policy))) return 'history-lost';
    let total = 0;
    for (const m of hits) total += m.length;
    if (total > maxBytes) return 'range-too-large';
    const out: ArchivedMinute[] = [];
    try {
      for (const m of hits) {
        const bytes = new Uint8Array(m.length);
        if (this.file.read(m.offset, bytes) !== bytes.length) return 'history-lost';
        out.push({ sourceKey, minuteMs: m.minuteMs, throughEntryId: m.throughEntryId, policyVersion: m.policy, bytes });
      }
    } catch {
      return 'history-lost';
    }
    return out;
  }

  /**
   * The fragments and then their cut, in one write and one flush. Everything is checked and encoded before
   * the file is touched, so a refusal writes nothing. A cut must start after the one before it.
   */
  append(fragments: ArchivedMinute[], cut: ArchiveCut): void {
    if (this.state !== 'ok') throw new Error(`the archive is ${this.state}; nothing can be appended`);
    if (fragments.length !== cut.fragments) throw new RangeError(`the cut counts ${cut.fragments} fragments and ${fragments.length} were given`);
    if (!REASONS.includes(cut.reason)) throw new RangeError(`a cut's reason is not one of ${REASONS.join(', ')}`);
    for (const n of [cut.fromEntryId, cut.throughEntryId, cut.fromMs, cut.throughMs]) {
      if (!Number.isSafeInteger(n) || n < 0) throw new RangeError('a cut\'s range is non-negative safe integers');
    }
    if (cut.fromEntryId < 1 || cut.throughEntryId < cut.fromEntryId || cut.throughMs < cut.fromMs) throw new RangeError('a cut\'s range runs backwards');
    const prev = this.cutList[this.cutList.length - 1];
    if (prev !== undefined && cut.fromEntryId <= prev.throughEntryId) {
      throw new RangeError(`a cut from entry ${cut.fromEntryId} starts inside the one through ${prev.throughEntryId}`);
    }

    const parts: Uint8Array[] = [];
    const placed: [string, Located][] = [];
    let id = this.lastId;
    let at = this.end;
    for (const m of fragments) {
      if (!Number.isSafeInteger(m.minuteMs) || m.minuteMs < 0 || !Number.isSafeInteger(m.throughEntryId) || m.throughEntryId < 0) {
        throw new RangeError('a minute\'s time and entry id are non-negative safe integers');
      }
      if (!ACCEPTED_POLICIES.includes(m.policyVersion)) throw new RangeError(`policy ${m.policyVersion} is not one this build reads`);
      if (m.bytes.length < 2 || (m.bytes[0] | (m.bytes[1] << 8)) !== m.policyVersion) {
        throw new RangeError('a minute\'s rollup bytes must begin with its policy version');
      }
      const key = utf8.encode(m.sourceKey);
      if (key.length === 0 || key.length > 0xffff) throw new RangeError('a source key is 1 to 65,535 bytes');
      const body = new Uint8Array(2 + key.length + 16 + m.bytes.length);
      const v = new DataView(body.buffer);
      v.setUint16(0, key.length, true);
      body.set(key, 2);
      v.setBigUint64(2 + key.length, BigInt(m.minuteMs), true);
      v.setBigUint64(2 + key.length + 8, BigInt(m.throughEntryId), true);
      body.set(m.bytes, 2 + key.length + 16);
      const entry = encodeEntry(ARCHIVE_FRAMING, ++id, KIND_MINUTE, body);
      placed.push([m.sourceKey, {
        minuteMs: m.minuteMs, throughEntryId: m.throughEntryId, offset: at + ENTRY_HEADER_BYTES + 2 + key.length + 16,
        length: m.bytes.length, policy: m.policyVersion,
      }]);
      parts.push(entry);
      at += entry.length;
    }
    const cutBody = new Uint8Array(CUT_FIXED_BYTES + cut.checkpoint.length);
    const cv = new DataView(cutBody.buffer);
    cv.setBigUint64(0, BigInt(cut.fromEntryId), true);
    cv.setBigUint64(8, BigInt(cut.throughEntryId), true);
    cv.setBigUint64(16, BigInt(cut.fromMs), true);
    cv.setBigUint64(24, BigInt(cut.throughMs), true);
    cv.setUint32(32, cut.fragments, true);
    cutBody[36] = REASONS.indexOf(cut.reason) + 1;
    cv.setUint32(40, cut.checkpoint.length, true);
    cutBody.set(cut.checkpoint, CUT_FIXED_BYTES);
    const cutEntry = encodeEntry(ARCHIVE_FRAMING, ++id, KIND_CUT, cutBody);
    parts.push(cutEntry);
    at += cutEntry.length;

    const all = new Uint8Array(at - this.end);
    let w = 0;
    for (const p of parts) { all.set(p, w); w += p.length; }
    try {
      this.file.write(this.end, all);
    } catch (e) {
      // Back to the last closed cut; a torn batch is truncated on open all the same.
      try { this.file.truncate(this.end); } catch { this.fail(); }
      throw e;
    }
    try {
      this.file.flush();
    } catch (e) {
      // Whether the cut reached the disk is unknown, so nothing further is trusted of this process's archive.
      this.fail();
      throw e;
    }
    for (const [key, loc] of placed) {
      const list = this.minutes.get(key);
      if (list === undefined) this.minutes.set(key, [loc]); else list.push(loc);
    }
    this.cutList.push(cloneCut(cut));
    this.end = at;
    this.lastId = id;
  }
}

// --- the replay ---------------------------------------------------------------------------------------

/**
 * What the archive keeps of `entries`: each (source, minute) as the rollup the cache would hold for it,
 * from the same aggregator and the same encoder, so a minute wholly inside the range is byte-identical
 * to the cache's. Where the entries cover only part of a minute, the fragment is that part and a reader
 * adds the retained fragment to it. A (source, minute) the aggregator sealed more than once - a clock
 * that stepped back - is merged into one. `deflate` is injected like everywhere else a rollup is encoded.
 */
export function expiryFragments(entries: Evidence[], session: SessionContext, deflate: Deflate): ArchivedMinute[] {
  if (entries.length === 0) return [];
  const agg = new MinuteAggregator(entries[0].ref.entryId - 1);
  const admission = new EngineAdmission(session.knownSources);
  for (const e of entries) feedEntry(agg, admission, e);
  agg.seal(Infinity);
  const drained = agg.drain();
  if (drained === null) return [];
  const groups = new Map<string, { rollups: MinuteRollup[]; lastId: number }>();
  for (const f of drained.fragments) {
    const key = `${f.rollup.minuteMs}\n${f.rollup.sourceKey}`;
    const g = groups.get(key);
    if (g === undefined) groups.set(key, { rollups: [f.rollup], lastId: f.lastId });
    else { g.rollups.push(f.rollup); g.lastId = Math.max(g.lastId, f.lastId); }
  }
  const out: ArchivedMinute[] = [];
  for (const g of groups.values()) {
    let rollup = g.rollups[0];
    if (g.rollups.length > 1) {
      const acc = new MinuteAccumulator(rollup.sourceKey, rollup.minuteMs);
      for (const r of g.rollups) acc.absorb(r);
      rollup = acc.toRollup();
    }
    out.push({
      sourceKey: rollup.sourceKey, minuteMs: rollup.minuteMs, throughEntryId: g.lastId, policyVersion: WRITE_POLICY_VERSION,
      bytes: encodeMinuteRollup(rollup, deflate),
    });
  }
  return out;
}

// --- the run -------------------------------------------------------------------------------------------

export interface RunExpiryOptions {
  /** Encodes the archived minutes; required unless `replay` makes them. */
  deflate?: Deflate;
  nowMs?: number;
  /** The seam Task 4 puts the Worker behind: entries and the world before them in, archive fragments out. */
  replay?: (entries: Evidence[], sessionAtStart: SessionContext) => ArchivedMinute[];
}

/** The newest `expired` boundary the journal still holds: its own entry id and the last entry id it took out. */
function newestExpiredBoundary(journal: MonitoringJournal): { entryId: number; throughEntryId: number } | null {
  const snap = journal.snapshot();
  let after = snap.firstEntryId - 1;
  let newest: { entryId: number; throughEntryId: number } | null = null;
  for (;;) {
    const page = journal.readBoundaries(snap, after, LIMITS.pageEntries);
    for (const b of page.entries) {
      if (b.action === 'expired' && b.expired !== undefined && b.expired !== null) newest = { entryId: b.ref.entryId, throughEntryId: b.expired.throughEntryId };
    }
    if (page.done) return newest;
    after = page.nextAfterId;
  }
}

/**
 * Finishes an expiry an earlier process began, from what is on disk and nothing else: call it on every
 * open, before anything is answered from the cache (ADR 0062's order, read from the end).
 *
 * - The archive's last cut covers segments the journal still holds and no `expired` boundary records it:
 *   the process died, or the drop was refused, between the cut and the boundary. The cut is a promise the
 *   archive has those minutes, so the boundary and unlink are done now and nothing is archived twice.
 * - The cache's watermark is below the newest retained `expired` boundary: it still holds minutes of
 *   entries that are gone and the archive holds, and a query would add the two. It is reset.
 *
 * `resumed` if either was done, `none` if there was nothing to do, `failed` if one could not be (a later
 * call repeats it; nothing was left half done that this cannot finish).
 */
export function resumeExpiry(journal: MonitoringJournal, cache: RollupStore, archive: ArchiveStore, nowMs: number = Date.now()): 'none' | 'resumed' | 'failed' {
  try {
    let did = false;
    const cut = archive.lastCut();
    if (cut !== null && cut.throughEntryId >= journal.snapshot().firstEntryId) {
      // The cut is durable and the journal still holds what it took out.
      const segs = journal.segments();
      const names: string[] = [];
      for (const s of segs) {
        if (s.lastEntryId > cut.throughEntryId) break;
        names.push(s.name);
      }
      const last = segs[names.length - 1];
      if (names.length === 0 || last === undefined || last.lastEntryId !== cut.throughEntryId || segs[0].firstEntryId !== cut.fromEntryId) return 'failed';
      const boundary = newestExpiredBoundary(journal);
      if (boundary !== null && boundary.throughEntryId >= cut.throughEntryId) return 'failed';
      if (!journal.canDropSegments(names, cut.reason, nowMs)) return 'failed';
      const r = journal.dropSegments(names, cut.reason, nowMs);
      if (r.refused > 0 || r.state === 'failed') return 'failed';
      did = true;
    }
    const boundary = newestExpiredBoundary(journal);
    const mark = cache.watermark();
    if (boundary !== null && mark !== null && mark.throughEntryId < boundary.entryId) {
      cache.reset(journal.snapshot().firstEntryId - 1);
      did = true;
    }
    return did ? 'resumed' : 'none';
  } catch {
    return 'failed';
  }
}

/**
 * Takes the planned segments out of the journal, keeping what a query needs of them (ADR 0062's order):
 * replay, archive fragments and cut and flush, the journal's `expired` boundary and unlink, then the
 * cache reset. A cut or a boundary an earlier run left is finished first (`resumeExpiry`), never redone.
 *
 * - `done`: the whole run.
 * - `resumed`: an earlier run's leftovers were finished; the plan is not run on top of them, since the
 *   next plan takes whatever else is due. A plan that an earlier run already carried out is not
 *   recognised by its numbers: its segments are gone, so it is `failed` like any plan that is not a
 *   prefix of the journal.
 * - `failed`: a refusal or a throw. Nothing a later run cannot repeat or resume was left half done.
 */
export function runExpiry(
  journal: MonitoringJournal, cache: RollupStore, archive: ArchiveStore, plan: ExpiryPlan, opts: RunExpiryOptions = {},
): 'done' | 'resumed' | 'failed' {
  try {
    const nowMs = opts.nowMs ?? Date.now();
    const resumed = resumeExpiry(journal, cache, archive, nowMs);
    if (resumed !== 'none') return resumed;

    const snap = journal.snapshot();
    const segs = journal.segments();
    if (plan.segments.length === 0 || plan.segments.length > segs.length) return 'failed';
    for (let i = 0; i < plan.segments.length; i++) {
      if (segs[i].name !== plan.segments[i] || !segs[i].sealed) return 'failed';
    }
    const first = segs[0];
    if (segs[plan.segments.length - 1].lastEntryId !== plan.throughEntryId) return 'failed';
    // A cut the journal then refuses to match is a promise nothing keeps (and a drop that can never be made
    // would wedge every later run behind it): ask first, and write nothing if the answer is no.
    if (!journal.canDropSegments(plan.segments, plan.reason, nowMs)) return 'failed';

    const entries: Evidence[] = [];
    const readThrough = { generation: snap.generation, throughEntryId: plan.throughEntryId };
    let after = first.firstEntryId - 1;
    for (;;) {
      const page = journal.readPage(readThrough, after, LIMITS.pageEntries, LIMITS.pageBytes);
      if (page.entries.length === 0 && !page.done) return 'failed';
      for (const e of page.entries) entries.push(e);
      after = page.nextAfterId;
      if (page.done) break;
    }
    if (entries.length === 0) return 'failed';

    // Everything admitted before this range is in the archive; nothing later is known yet.
    const context: SessionContext = { knownSources: archive.sources() };
    let fragments: ArchivedMinute[];
    if (opts.replay !== undefined) fragments = opts.replay(entries, context);
    else if (opts.deflate !== undefined) fragments = expiryFragments(entries, context, opts.deflate);
    else return 'failed';

    // The range the journal's `expired` boundary will record: the first entry's receipt time, the last segment's.
    archive.append(fragments, {
      fromEntryId: first.firstEntryId, throughEntryId: plan.throughEntryId, fromMs: entries[0].receivedMs, throughMs: plan.throughMs,
      fragments: fragments.length, reason: plan.reason, checkpoint: new Uint8Array(0),
    });
    const r = journal.dropSegments(plan.segments, plan.reason, nowMs);
    if (r.refused > 0 || r.state === 'failed') return 'failed';
    // The new sidecar continues from where the journal now begins, so a batch that does not is refused.
    cache.reset(journal.snapshot().firstEntryId - 1);
    return 'done';
  } catch {
    return 'failed';
  }
}
