/**
 * The rollup sidecar, `rollups.iwmr` (ADR 0059): minute rollups the Worker
 * derived from the journal, stored as opaque bytes.
 *
 * **It is a cache, and the opposite of the journal in every failure.** The
 * journal preserves what it cannot read and refuses to go on; this file, when
 * it cannot be trusted, is thrown away and recomputed. So a bad header, a CRC
 * failing anywhere, a generation or policy other than the journal's, or a
 * watermark claiming more than the journal holds does not truncate or repair
 * anything: it reports `rebuild-required`, mutates nothing, and refuses reads
 * and appends until `reset()`. Nothing is lost by that - everything in here
 * came from the journal - and nothing wrong is ever served.
 *
 * ## A batch is the unit of durability
 *
 * `appendMinutes` writes its minute entries and a closing **watermark entry**
 * in one write. The watermark is the only thing that says how far the
 * journal the sidecar covers, so minutes after the last watermark cover
 * nothing the sidecar can vouch for: on open they are a torn tail and are
 * truncated, whole batch or none. A watermark behind the journal's end is
 * fine and expected - the missing tail is computed and appended later.
 *
 * ## What is stored per entry
 *
 * Framing is `journalCodec`'s, with the magic `INWIREMR` and a 1 MiB body cap
 * (a deflated 16,384-key minute can pass the journal's 65,531). Entry kind 1
 * is a minute: `u16 keyLength, key, u64 minuteMs, u64 throughEntryId`, then
 * the rollup's own bytes, which this file never interprets. Kind 2 is the
 * watermark: `16 generation, u64 throughEntryId, u16 policyVersion`.
 *
 * The in-memory index (per source, the minutes in file order) is rebuilt on
 * open by the same scan that checks the CRCs.
 */
import type { BlockFile } from '../capture/blockFile';
import {
  ENTRY_HEADER_BYTES, FILE_HEADER_BYTES, ROLLUP_FRAMING,
  decodeFileHeader, encodeEntry, encodeFileHeader, entryCrc, generationFromHex, generationToHex,
  isHeaderPrefix, parseEntryHeader, scanEntries,
} from './journalCodec';
import { FORMAT_VERSION, type Generation, type RollupWatermark } from './types';

const KIND_MINUTE = 1;
const KIND_WATERMARK = 2;
const WATERMARK_BODY_BYTES = 16 + 8 + 2;
const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** `failed`: the file could not be given a header; the store is returned, refusing reads and appends. */
export type RollupOpenStatus = 'ok' | 'rebuild-required' | 'empty' | 'failed';

export interface RollupStoreOptions {
  nowMs?: () => number;
}

export interface MinuteInput { sourceKey: string; minuteMs: number; bytes: Uint8Array }

interface Located { minuteMs: number; offset: number; bodyLength: number; bytes: number }

/** What the open scan found, before anything is decided about it. */
interface SidecarScan {
  verdict: 'ok' | 'empty' | 'rebuild-required';
  reason?: string;
  /** Where the last closed batch ends: the file is truncated to here. */
  batchEnd: number;
  lastEntryId: number;
  watermark: RollupWatermark | null;
  minutes: Map<string, Located[]>;
}

function emptyScan(verdict: SidecarScan['verdict'], reason?: string): SidecarScan {
  return { verdict, ...(reason === undefined ? {} : { reason }), batchEnd: FILE_HEADER_BYTES, lastEntryId: 0, watermark: null, minutes: new Map() };
}

function scanSidecar(file: BlockFile, journal: { generation: Generation; throughEntryId: number; policyVersion: number }): SidecarScan {
  const size = file.size();
  if (size === 0) return emptyScan('empty');
  if (size < FILE_HEADER_BYTES) {
    const head = new Uint8Array(size);
    file.read(0, head);
    return isHeaderPrefix(ROLLUP_FRAMING, head) ? emptyScan('empty') : emptyScan('rebuild-required', 'the file is not a rollup sidecar');
  }
  const headerBytes = new Uint8Array(FILE_HEADER_BYTES);
  file.read(0, headerBytes);
  const header = decodeFileHeader(ROLLUP_FRAMING, headerBytes);
  if (!header.ok) return emptyScan('rebuild-required', header.reason);
  if (header.formatVersion !== FORMAT_VERSION) {
    return emptyScan('rebuild-required', `sidecar format ${header.formatVersion}; this build reads ${FORMAT_VERSION}`);
  }
  if (header.policyVersion !== journal.policyVersion) {
    return emptyScan('rebuild-required', `sidecar decoder policy ${header.policyVersion}, journal ${journal.policyVersion}`);
  }
  const generation = generationToHex(header.generation);
  if (generation !== journal.generation) {
    return emptyScan('rebuild-required', 'the sidecar was derived from another journal generation');
  }

  const minutes = new Map<string, Located[]>();
  let pending: [string, Located, number][] = [];
  let batchEnd = FILE_HEADER_BYTES;
  let batchLastId = 0;
  // An object, because TypeScript cannot see a closure assign a `let`.
  const seen: { watermark: RollupWatermark | null } = { watermark: null };

  const outcome = scanEntries(file, ROLLUP_FRAMING, FILE_HEADER_BYTES, 0, (e) => {
    const v = new DataView(e.body.buffer, e.body.byteOffset, e.body.byteLength);
    if (e.kind === KIND_MINUTE) {
      if (e.body.length < 2) return 'a minute entry is shorter than its key length';
      const keyLength = v.getUint16(0, true);
      if (e.body.length < 2 + keyLength + 16) return 'a minute entry is shorter than its metadata';
      let key: string;
      try {
        key = utf8Strict.decode(e.body.subarray(2, 2 + keyLength));
      } catch {
        return 'a minute entry has a source key that is not UTF-8';
      }
      const at = 2 + keyLength;
      const minuteMs = v.getBigUint64(at, true);
      if (minuteMs > BigInt(Number.MAX_SAFE_INTEGER)) return 'a minute entry has a time out of range';
      const minuteThrough = v.getBigUint64(at + 8, true);
      if (minuteThrough > BigInt(Number.MAX_SAFE_INTEGER)) return 'a minute entry has a watermark out of range';
      pending.push([key, {
        minuteMs: Number(minuteMs), offset: e.offset + ENTRY_HEADER_BYTES, bodyLength: e.body.length,
        bytes: e.body.length - (at + 16),
      }, Number(minuteThrough)]);
      return null;
    }
    if (e.kind === KIND_WATERMARK) {
      if (e.body.length !== WATERMARK_BODY_BYTES) return 'a watermark entry is the wrong length';
      if (generationToHex(e.body.subarray(0, 16)) !== generation) return 'a watermark names another generation';
      const through = v.getBigUint64(16, true);
      if (through > BigInt(Number.MAX_SAFE_INTEGER)) return 'a watermark is out of range';
      if (v.getUint16(24, true) !== header.policyVersion) return 'a watermark names another policy';
      if (seen.watermark !== null && Number(through) < seen.watermark.throughEntryId) return 'a watermark moves backwards';
      // A batch is written with one closing watermark, and every minute in it
      // says which. One that names another was not written by this code.
      for (const [, , minuteThrough] of pending) {
        if (minuteThrough !== Number(through)) {
          return `a minute entry names watermark ${minuteThrough}, but its batch closes at ${Number(through)}`;
        }
      }
      seen.watermark = { generation, throughEntryId: Number(through), policyVersion: header.policyVersion };
      for (const [key, loc] of pending) {
        const list = minutes.get(key);
        if (list === undefined) minutes.set(key, [loc]); else list.push(loc);
      }
      pending = [];
      batchEnd = e.end;
      batchLastId = e.entryId;
      return null;
    }
    return `unknown kind ${e.kind}`;
  });

  if (outcome.problem !== null) return emptyScan('rebuild-required', outcome.problem);
  const wm = seen.watermark;
  if (wm === null) return emptyScan('empty');
  if (wm.throughEntryId > journal.throughEntryId) {
    return emptyScan('rebuild-required', `the sidecar covers entry ${wm.throughEntryId}, past the journal's ${journal.throughEntryId}`);
  }
  return { verdict: 'ok', batchEnd, lastEntryId: batchLastId, watermark: wm, minutes };
}

export class RollupStore {
  private constructor(
    private readonly file: BlockFile,
    private readonly journal: { generation: Generation; throughEntryId: number; policyVersion: number },
    private readonly nowMs: () => number,
    private end: number,
    private lastId: number,
    private mark: RollupWatermark | null,
    private minutes: Map<string, Located[]>,
    private rebuildReason: string | null,
  ) {}

  static open(
    file: BlockFile,
    journal: { generation: Generation; throughEntryId: number; policyVersion: number },
    options: RollupStoreOptions = {},
  ): { store: RollupStore; status: RollupOpenStatus; reason?: string } {
    const nowMs = options.nowMs ?? Date.now;
    const scan = scanSidecar(file, journal);
    if (scan.verdict === 'rebuild-required') {
      const store = new RollupStore(file, journal, nowMs, file.size(), 0, null, new Map(), scan.reason ?? 'rebuild required');
      return { store, status: 'rebuild-required', reason: scan.reason };
    }
    if (scan.verdict === 'empty') {
      const store = new RollupStore(file, journal, nowMs, FILE_HEADER_BYTES, 0, null, new Map(), null);
      try {
        store.writeFreshHeader();
      } catch (e) {
        const reason = `the sidecar's header could not be written: ${e instanceof Error ? e.message : String(e)}`;
        store.rebuildReason = reason;
        return { store, status: 'failed', reason };
      }
      return { store, status: 'empty' };
    }
    // Minutes after the last watermark vouch for nothing: the batch was torn.
    if (file.size() > scan.batchEnd) file.truncate(scan.batchEnd);
    const store = new RollupStore(file, journal, nowMs, scan.batchEnd, scan.lastEntryId, scan.watermark, scan.minutes, null);
    return { store, status: 'ok' };
  }

  private writeFreshHeader(): void {
    this.file.truncate(0);
    this.file.write(0, encodeFileHeader(ROLLUP_FRAMING, {
      generation: generationFromHex(this.journal.generation), createdMs: this.nowMs(), policyVersion: this.journal.policyVersion,
    }));
    this.end = FILE_HEADER_BYTES;
    this.lastId = 0;
    this.mark = null;
    this.minutes = new Map();
    this.rebuildReason = null;
  }

  watermark(): RollupWatermark | null {
    return this.mark === null ? null : { ...this.mark };
  }

  size(): number { return this.end; }

  /** Throws the open's reason: a sidecar that cannot be trusted answers nothing. */
  private requireUsable(): void {
    if (this.rebuildReason !== null) throw new Error(`the rollup sidecar needs a rebuild: ${this.rebuildReason}`);
  }

  /**
   * The whole batch, its minutes and then its watermark, in one write. Every
   * entry is encoded before the file is touched, so a body over the cap
   * (`RangeError`) writes nothing.
   */
  appendMinutes(minutes: MinuteInput[], watermark: RollupWatermark): void {
    this.requireUsable();
    if (watermark.generation !== this.journal.generation || watermark.policyVersion !== this.journal.policyVersion) {
      throw new Error('a watermark must name the journal generation and policy this sidecar was opened for');
    }
    if (!Number.isSafeInteger(watermark.throughEntryId) || watermark.throughEntryId < 0) throw new RangeError('a watermark is a non-negative entry id');
    if (this.mark !== null && watermark.throughEntryId < this.mark.throughEntryId) {
      throw new RangeError(`a watermark cannot move back from ${this.mark.throughEntryId} to ${watermark.throughEntryId}`);
    }

    const encoded: Uint8Array[] = [];
    const placed: [string, Located][] = [];
    let id = this.lastId;
    let at = this.end;
    for (const m of minutes) {
      if (!Number.isSafeInteger(m.minuteMs) || m.minuteMs < 0) throw new RangeError('a minute is a non-negative safe integer of milliseconds');
      const key = utf8.encode(m.sourceKey);
      if (key.length > 0xffff) throw new RangeError('a source key is at most 65,535 bytes');
      const body = new Uint8Array(2 + key.length + 16 + m.bytes.length);
      const v = new DataView(body.buffer);
      v.setUint16(0, key.length, true);
      body.set(key, 2);
      v.setBigUint64(2 + key.length, BigInt(m.minuteMs), true);
      v.setBigUint64(2 + key.length + 8, BigInt(watermark.throughEntryId), true);
      body.set(m.bytes, 2 + key.length + 16);
      const entry = encodeEntry(ROLLUP_FRAMING, ++id, KIND_MINUTE, body);
      encoded.push(entry);
      placed.push([m.sourceKey, { minuteMs: m.minuteMs, offset: at + ENTRY_HEADER_BYTES, bodyLength: body.length, bytes: m.bytes.length }]);
      at += entry.length;
    }
    const wm = new Uint8Array(WATERMARK_BODY_BYTES);
    wm.set(generationFromHex(watermark.generation), 0);
    new DataView(wm.buffer).setBigUint64(16, BigInt(watermark.throughEntryId), true);
    new DataView(wm.buffer).setUint16(24, watermark.policyVersion, true);
    encoded.push(encodeEntry(ROLLUP_FRAMING, ++id, KIND_WATERMARK, wm));

    const all = new Uint8Array(encoded.reduce((n, e) => n + e.length, 0));
    let w = 0;
    for (const e of encoded) { all.set(e, w); w += e.length; }

    try {
      this.file.write(this.end, all);
    } catch (e) {
      // Back to the last closed batch; the open scan would do the same.
      try { this.file.truncate(this.end); } catch { /* a torn batch is truncated on open */ }
      throw e;
    }
    for (const [key, loc] of placed) {
      const list = this.minutes.get(key);
      if (list === undefined) this.minutes.set(key, [loc]); else list.push(loc);
    }
    this.end += all.length;
    this.lastId = id;
    this.mark = { generation: watermark.generation, throughEntryId: watermark.throughEntryId, policyVersion: watermark.policyVersion };
  }

  /**
   * Every fragment of every minute in `[fromMinuteMs, toMinuteMs)`, in the
   * order they were written. Several for one minute is normal after a clock
   * step back; the reader sums them. A range holding more than `maxBytes` is
   * refused, never clipped: a clipped answer is a wrong total.
   */
  readMinutes(sourceKey: string, fromMinuteMs: number, toMinuteMs: number, maxBytes: number): { minuteMs: number; bytes: Uint8Array }[] {
    this.requireUsable();
    const hits = (this.minutes.get(sourceKey) ?? []).filter((m) => m.minuteMs >= fromMinuteMs && m.minuteMs < toMinuteMs);
    const total = hits.reduce((n, m) => n + m.bytes, 0);
    if (total > maxBytes) throw new RangeError(`the range holds ${total} bytes, over the maxBytes of ${maxBytes}`);
    const keyLength = utf8.encode(sourceKey).length;
    return hits.map((m) => {
      const header = new Uint8Array(ENTRY_HEADER_BYTES);
      const body = new Uint8Array(m.bodyLength);
      if (this.file.read(m.offset - ENTRY_HEADER_BYTES, header) !== header.length || this.file.read(m.offset, body) !== body.length) {
        throw new Error('the rollup sidecar is shorter than its index');
      }
      const parsed = parseEntryHeader(ROLLUP_FRAMING, header);
      if (!parsed.ok || parsed.crc !== entryCrc(header, body)) throw new Error('a stored minute no longer matches its checksum');
      return { minuteMs: m.minuteMs, bytes: body.slice(2 + keyLength + 16) };
    });
  }

  /** Back to an empty sidecar with a fresh header: how a `rebuild-required` one recovers. */
  reset(): void {
    this.writeFreshHeader();
  }
}
