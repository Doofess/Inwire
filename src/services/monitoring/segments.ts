/**
 * The journal's segments (ADR 0062): what one file is, how it is named and
 * headed, and the directory that holds them.
 *
 * ADR 0059's single `journal.iwmj` could only be deleted whole, so a
 * retention policy had nothing to remove. A journal is now a run of segment
 * files, `journal-<first entry id>.iwmj`, each a 128-byte format-2 header
 * followed by 0059's entries unchanged. The header says where the segment
 * starts in the dataset's one id sequence, which decoder policy its datagrams
 * were written under, and - because a datagram's session is the nearest
 * `start` before it - the session that was open when it was created and the
 * source that session recorded, so a segment whose predecessors have expired
 * still says whose datagrams it holds.
 *
 * A milestone-1 `journal.iwmj` is the first segment as it lies: never renamed,
 * never appended to, expired whole. It is the only file with a 64-byte
 * format-1 header.
 *
 * This module is bytes and names only. Whether a set of segments is a valid
 * dataset is `journal.ts`'s decision; `SegmentDirectory` is the seam that lets
 * it make that decision over memory and over a folder alike.
 *
 * No `node:*` and no Electron, like everything under `src/services/`.
 */
import { MemoryBlockFile, type BlockFile } from '../capture/blockFile';
import { crc32, ipv4FromBytes, ipv4ToBytes } from './journalCodec';
import type { SegmentSource } from './types';

export type { SegmentSource };

export const LEGACY_JOURNAL_NAME = 'journal.iwmj';
export const SEGMENT_PATTERN = /^journal-(\d{12,20})\.iwmj$/;
export const SEGMENT_HEADER_BYTES = 128;
export const SEGMENT_FORMAT_VERSION = 2;

const KiB = 1024;
const MiB = 1024 * KiB;
const MIN_SEGMENT_BYTES = 1 * MiB;
const MAX_SEGMENT_BYTES = 256 * MiB;
const MAGIC = 'INWIREMJ';
const SESSION_BYTES = 16;
const GENERATION_BYTES = 16;
const FLAG_SESSION_OPEN = 1;

/** `journal-000000000001.iwmj`: the first entry id, zero-padded to 12 digits and longer if it needs to be. */
export function segmentName(firstEntryId: number): string {
  if (!Number.isSafeInteger(firstEntryId) || firstEntryId < 1) throw new RangeError(`a segment starts at a positive entry id (got ${firstEntryId})`);
  return `journal-${String(firstEntryId).padStart(12, '0')}.iwmj`;
}

/** The size a segment grows to before the next one starts: a 32nd of the dataset's limit, within 1 MiB and 256 MiB. */
export function segmentBytesFor(limitBytes: number): number {
  return Math.min(MAX_SEGMENT_BYTES, Math.max(MIN_SEGMENT_BYTES, Math.floor(limitBytes / 32)));
}

export interface SegmentHeaderFields {
  policyVersion: number;
  generation: Uint8Array;
  createdMs: number;
  firstEntryId: number;
  /** The 16 bytes of the session open when the segment was created, or null. */
  openSession: Uint8Array | null;
  /** That session's recorded source, or null. */
  source: SegmentSource | null;
}

export function encodeSegmentHeader(f: SegmentHeaderFields): Uint8Array {
  if (f.generation.length !== GENERATION_BYTES) throw new RangeError('a generation is 16 bytes');
  if (f.openSession !== null && f.openSession.length !== SESSION_BYTES) throw new RangeError('a session id is 16 bytes');
  if (!Number.isInteger(f.policyVersion) || f.policyVersion < 0 || f.policyVersion > 0xffff) throw new RangeError(`policy version ${f.policyVersion}`);
  if (!Number.isSafeInteger(f.createdMs) || f.createdMs < 0) throw new RangeError(`created ${f.createdMs}`);
  if (!Number.isSafeInteger(f.firstEntryId) || f.firstEntryId < 1) throw new RangeError(`first entry id ${f.firstEntryId}`);
  const out = new Uint8Array(SEGMENT_HEADER_BYTES);
  const v = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) out[i] = MAGIC.charCodeAt(i);
  v.setUint16(8, SEGMENT_FORMAT_VERSION, true);
  v.setUint16(10, f.policyVersion, true);
  v.setUint32(12, SEGMENT_HEADER_BYTES, true);
  out.set(f.generation, 16);
  v.setBigUint64(32, BigInt(f.createdMs), true);
  v.setBigUint64(40, BigInt(f.firstEntryId), true);
  if (f.openSession !== null) out.set(f.openSession, 48);
  if (f.source !== null) {
    if (!Number.isInteger(f.source.port) || f.source.port < 0 || f.source.port > 0xffff) throw new RangeError(`port ${f.source.port}`);
    out.set(ipv4ToBytes(f.source.exporterIPv4), 64);
    out.set(ipv4ToBytes(f.source.bindIPv4), 68);
    v.setUint16(72, f.source.port, true);
  }
  v.setUint16(74, f.openSession !== null ? FLAG_SESSION_OPEN : 0, true);
  v.setUint32(124, crc32(out.subarray(0, 124)), true);
  return out;
}

export type SegmentHeaderResult =
  | { ok: true; value: SegmentHeaderFields & { formatVersion: number } }
  | { ok: false; reason: string };

/**
 * Checks what makes the header a header - the magic, the length, the checksum,
 * zeros where it promises zeros, no flag it does not know - and returns the
 * versions rather than judging them: whether policy 3 is acceptable is the
 * journal's policy, as it is for the 64-byte header.
 */
export function decodeSegmentHeader(bytes: Uint8Array): SegmentHeaderResult {
  if (bytes.length < SEGMENT_HEADER_BYTES) return { ok: false, reason: 'the header is shorter than 128 bytes' };
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== MAGIC.charCodeAt(i)) return { ok: false, reason: `the magic is not ${MAGIC}` };
  }
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (v.getUint32(12, true) !== SEGMENT_HEADER_BYTES) return { ok: false, reason: 'the header length is not 128' };
  if (v.getUint32(124, true) !== crc32(bytes.subarray(0, 124))) return { ok: false, reason: 'the header checksum does not match' };
  for (let i = 76; i < 124; i++) {
    if (bytes[i] !== 0) return { ok: false, reason: `a reserved header byte at offset ${i} is not zero` };
  }
  const flags = v.getUint16(74, true);
  if ((flags & ~FLAG_SESSION_OPEN) !== 0) return { ok: false, reason: `the header sets flag bits this build does not know (${flags})` };
  const created = v.getBigUint64(32, true);
  if (created > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'the creation time is out of range' };
  const first = v.getBigUint64(40, true);
  if (first < 1n || first > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'the first entry id is out of range' };
  const port = v.getUint16(72, true);
  let anySource = port !== 0;
  for (let i = 64; i < 72 && !anySource; i++) if (bytes[i] !== 0) anySource = true;
  return {
    ok: true,
    value: {
      formatVersion: v.getUint16(8, true),
      policyVersion: v.getUint16(10, true),
      generation: bytes.slice(16, 16 + GENERATION_BYTES),
      createdMs: Number(created),
      firstEntryId: Number(first),
      openSession: (flags & FLAG_SESSION_OPEN) !== 0 ? bytes.slice(48, 48 + SESSION_BYTES) : null,
      source: anySource ? { exporterIPv4: ipv4FromBytes(bytes, 64), bindIPv4: ipv4FromBytes(bytes, 68), port } : null,
    },
  };
}

/** What the journal knows of one retained segment. `bytes` is the file's size. */
export interface SegmentInfo {
  name: string;
  firstEntryId: number;
  lastEntryId: number;
  lastReceivedMs: number;
  policyVersion: number;
  /** Closed to appends: every segment but the newest, and a legacy file wherever it is. */
  sealed: boolean;
  bytes: number;
}

/**
 * Where segments live. `journal.ts` sees only this: a folder through `node:fs`
 * in the app, a map of memory files in a test. The directory owns its handles -
 * `open` returns the same file for the same name, and `unlink` closes before it
 * removes, which Windows requires.
 */
export interface SegmentDirectory {
  /** Only names matching `SEGMENT_PATTERN` or `LEGACY_JOURNAL_NAME`. */
  list(): string[];
  /** An existing file; the directory owns the handle. */
  open(name: string): BlockFile;
  /** A new, empty file; throws if it exists. */
  create(name: string): BlockFile;
  /** Closes its handle first. Only names `list()` returned. */
  unlink(name: string): void;
}

export function isSegmentFileName(name: string): boolean {
  return name === LEGACY_JOURNAL_NAME || SEGMENT_PATTERN.test(name);
}

export class MemorySegmentDirectory implements SegmentDirectory {
  private readonly files = new Map<string, MemoryBlockFile>();

  constructor(seed?: Record<string, Uint8Array>) {
    for (const [name, bytes] of Object.entries(seed ?? {})) {
      const file = this.create(name);
      file.write(0, bytes);
    }
  }

  list(): string[] {
    return [...this.files.keys()].sort();
  }

  open(name: string): BlockFile {
    return this.file(name);
  }

  create(name: string): BlockFile {
    if (!isSegmentFileName(name)) throw new RangeError(`not a segment name: ${name}`);
    if (this.files.has(name)) throw new Error(`${name} already exists`);
    const file = new MemoryBlockFile();
    this.files.set(name, file);
    return file;
  }

  unlink(name: string): void {
    if (!this.files.has(name)) throw new Error(`${name} does not exist`);
    this.files.delete(name);
  }

  /** The file itself, so a test can read its bytes or damage them. */
  file(name: string): MemoryBlockFile {
    const file = this.files.get(name);
    if (file === undefined) throw new Error(`${name} does not exist`);
    return file;
  }
}
