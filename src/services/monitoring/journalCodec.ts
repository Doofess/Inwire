/**
 * The framing shared by the evidence journal and its rollup sidecar (ADR 0059).
 *
 * Both files are a 64-byte header followed by entries of a 24-byte header and a
 * body, little-endian, each entry checksummed with CRC-32/ISO-HDLC over its own
 * header and body. They differ in their magic and in how large a body may be -
 * 65,531 bytes for a datagram, 1 MiB for a deflated minute - so the framing is
 * parameterised by both and the two files cannot be mistaken for one another.
 *
 * **This module knows bytes, never meaning.** It does not decide whether an
 * entry's kind is valid, whether a datagram has a session or whether a body
 * parses; that is the journal's and the sidecar's business. It does decide
 * the one question both files share: of an entry that fails, is it a torn tail
 * (an append that did not finish, truncated on open) or damage in the interior
 * (preserved, append refused). `scanEntries` is that rule, in one place.
 *
 * No `node:*` and no Electron: it runs under plain `tsx` and in a Worker.
 */
import { LIMITS } from './types';

export const FILE_HEADER_BYTES = 64;
export const ENTRY_HEADER_BYTES = 24;
export const KIND_DATAGRAM = 1;
export const KIND_BOUNDARY = 2;
export const DATAGRAM_METADATA_BYTES = 24;

/** `0x454a5749` little-endian, which is ASCII `IWJE` on disk. */
const ENTRY_MAGIC = 0x454a5749;
const GENERATION_BYTES = 16;

export interface Framing {
  /** Eight ASCII characters. */
  magic: string;
  /** The largest body a reader will accept, checked before it allocates anything. */
  maxBodyBytes: number;
}

export const JOURNAL_FRAMING: Framing = { magic: 'INWIREMJ', maxBodyBytes: LIMITS.maxBodyBytes };

/**
 * A deflated 16,384-key minute can pass the journal's 65,531, so the sidecar
 * has its own cap. It is still a cap: a damaged length must not ask for
 * four gigabytes.
 */
export const ROLLUP_FRAMING: Framing = { magic: 'INWIREMR', maxBodyBytes: 1 << 20 };

// --- CRC-32/ISO-HDLC ----------------------------------------------------------------

const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/**
 * `seed` is a previous result, so a CRC continues over a second span: an
 * entry's checksum is the header's `[0, 20)` continued over its body.
 */
export function crc32(bytes: Uint8Array, seed = 0): number {
  let c = ~seed >>> 0;
  for (let i = 0; i < bytes.length; i++) c = TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

// --- generations --------------------------------------------------------------------

export function generationToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function generationFromHex(hex: string): Uint8Array {
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new RangeError(`not a generation: ${hex}`);
  const out = new Uint8Array(GENERATION_BYTES);
  for (let i = 0; i < GENERATION_BYTES; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// --- file header ------------------------------------------------------------------------

export interface FileHeaderFields {
  generation: Uint8Array;
  createdMs: number;
  /** Overridable so a test can write the header of a file from the future. */
  formatVersion?: number;
  policyVersion?: number;
}

export function encodeFileHeader(framing: Framing, fields: FileHeaderFields): Uint8Array {
  if (fields.generation.length !== GENERATION_BYTES) throw new RangeError('a generation is 16 bytes');
  const out = new Uint8Array(FILE_HEADER_BYTES);
  const v = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) out[i] = framing.magic.charCodeAt(i);
  v.setUint16(8, fields.formatVersion ?? 1, true);
  v.setUint16(10, fields.policyVersion ?? 1, true);
  v.setUint32(12, FILE_HEADER_BYTES, true);
  out.set(fields.generation, 16);
  v.setBigUint64(32, BigInt(fields.createdMs), true);
  v.setUint32(60, crc32(out.subarray(0, 60)), true);
  return out;
}

export type FileHeaderResult =
  | { ok: true; formatVersion: number; policyVersion: number; generation: Uint8Array; createdMs: number }
  | { ok: false; reason: string };

/**
 * Versions are returned rather than judged: whether version 2 is "unknown" is
 * the caller's policy, and the journal and the sidecar answer it differently
 * (one is preserved, the other rebuilt).
 */
export function decodeFileHeader(framing: Framing, bytes: Uint8Array): FileHeaderResult {
  if (bytes.length < FILE_HEADER_BYTES) return { ok: false, reason: 'the header is shorter than 64 bytes' };
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== framing.magic.charCodeAt(i)) return { ok: false, reason: `the magic is not ${framing.magic}` };
  }
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (v.getUint32(12, true) !== FILE_HEADER_BYTES) return { ok: false, reason: 'the header length is not 64' };
  if (v.getUint32(60, true) !== crc32(bytes.subarray(0, 60))) return { ok: false, reason: 'the header checksum does not match' };
  const created = v.getBigUint64(32, true);
  if (created > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'the creation time is out of range' };
  return {
    ok: true,
    formatVersion: v.getUint16(8, true),
    policyVersion: v.getUint16(10, true),
    generation: bytes.slice(16, 16 + GENERATION_BYTES),
    createdMs: Number(created),
  };
}

/** Whether `bytes` (fewer than a whole header) could be the start of one: a tear, not someone else's file. */
export function isHeaderPrefix(framing: Framing, bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8);
  for (let i = 0; i < n; i++) if (bytes[i] !== framing.magic.charCodeAt(i)) return false;
  return true;
}

// --- entries -------------------------------------------------------------------------------

export function encodeEntry(framing: Framing, entryId: number, kind: number, body: Uint8Array): Uint8Array {
  if (body.length > framing.maxBodyBytes) {
    throw new RangeError(`a body of ${body.length} bytes is over the ${framing.maxBodyBytes} cap`);
  }
  if (!Number.isSafeInteger(entryId) || entryId < 1) throw new RangeError(`entry id ${entryId}`);
  const out = new Uint8Array(ENTRY_HEADER_BYTES + body.length);
  const v = new DataView(out.buffer);
  v.setUint32(0, ENTRY_MAGIC, true);
  v.setUint32(4, body.length, true);
  v.setBigUint64(8, BigInt(entryId), true);
  out[16] = kind;
  out.set(body, ENTRY_HEADER_BYTES);
  v.setUint32(20, crc32(body, crc32(out.subarray(0, 20))), true);
  return out;
}

export type EntryHeaderResult =
  | { ok: true; bodyLength: number; entryId: number; kind: number; crc: number }
  | { ok: false; reason: string };

/** Refuses a declared length over the cap before anything is read or allocated for it. */
export function parseEntryHeader(framing: Framing, header: Uint8Array): EntryHeaderResult {
  if (header.length < ENTRY_HEADER_BYTES) return { ok: false, reason: 'an entry header is cut short' };
  const v = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (v.getUint32(0, true) !== ENTRY_MAGIC) return { ok: false, reason: 'the entry magic is wrong' };
  const bodyLength = v.getUint32(4, true);
  if (bodyLength > framing.maxBodyBytes) return { ok: false, reason: `a declared body of ${bodyLength} bytes is over the ${framing.maxBodyBytes} cap` };
  const id = v.getBigUint64(8, true);
  if (id < 1n || id > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'the entry id is out of range' };
  return { ok: true, bodyLength, entryId: Number(id), kind: header[16], crc: v.getUint32(20, true) };
}

export function entryCrc(header: Uint8Array, body: Uint8Array): number {
  return crc32(body, crc32(header.subarray(0, 20)));
}

// --- datagram bodies -----------------------------------------------------------------------

export interface DatagramFields {
  receivedMs: number;
  localIPv4: string;
  localPort: number;
  remoteIPv4: string;
  remotePort: number;
  payload: Uint8Array;
}

export function ipv4ToBytes(address: string): Uint8Array {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!m) throw new RangeError(`not an IPv4 address: ${address}`);
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(m[i + 1]);
    if (n > 255) throw new RangeError(`not an IPv4 address: ${address}`);
    out[i] = n;
  }
  return out;
}

export function ipv4FromBytes(b: Uint8Array, at: number): string {
  return `${b[at]}.${b[at + 1]}.${b[at + 2]}.${b[at + 3]}`;
}

function port(n: number, what: string): number {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new RangeError(`${what} ${n}`);
  return n;
}

export function encodeDatagramBody(d: DatagramFields): Uint8Array {
  if (d.payload.length > LIMITS.maxPayloadBytes) {
    throw new RangeError(`a payload of ${d.payload.length} bytes is over ${LIMITS.maxPayloadBytes}`);
  }
  if (!Number.isSafeInteger(d.receivedMs) || d.receivedMs < 0) throw new RangeError(`receivedMs ${d.receivedMs}`);
  const out = new Uint8Array(DATAGRAM_METADATA_BYTES + d.payload.length);
  const v = new DataView(out.buffer);
  v.setBigUint64(0, BigInt(d.receivedMs), true);
  out.set(ipv4ToBytes(d.localIPv4), 8);
  v.setUint16(12, port(d.localPort, 'local port'), true);
  out.set(ipv4ToBytes(d.remoteIPv4), 14);
  v.setUint16(18, port(d.remotePort, 'remote port'), true);
  out.set(d.payload, DATAGRAM_METADATA_BYTES);
  return out;
}

export type DatagramBodyResult = { ok: true; value: DatagramFields } | { ok: false; reason: string };

export function decodeDatagramBody(body: Uint8Array): DatagramBodyResult {
  if (body.length < DATAGRAM_METADATA_BYTES) return { ok: false, reason: 'a datagram body is shorter than its metadata' };
  if (body.length - DATAGRAM_METADATA_BYTES > LIMITS.maxPayloadBytes) return { ok: false, reason: 'a datagram payload is over the UDP maximum' };
  const v = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const received = v.getBigUint64(0, true);
  if (received > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'a datagram receipt time is out of range' };
  return {
    ok: true,
    value: {
      receivedMs: Number(received),
      localIPv4: ipv4FromBytes(body, 8),
      localPort: v.getUint16(12, true),
      remoteIPv4: ipv4FromBytes(body, 14),
      remotePort: v.getUint16(18, true),
      // A copy, so an evidence record never pins the 4 MB window it was read from.
      payload: body.slice(DATAGRAM_METADATA_BYTES),
    },
  };
}

// --- scanning --------------------------------------------------------------------------------

/** What a scan needs of a file; `BlockFile` satisfies it, and this module imports nothing else. */
export interface Readable {
  read(offset: number, into: Uint8Array): number;
  size(): number;
}

export interface ScannedEntry {
  entryId: number;
  kind: number;
  /** Where this entry's header starts. */
  offset: number;
  /** Where the next entry starts. */
  end: number;
  /** A view into the scan's window: valid only until the visitor returns. */
  body: Uint8Array;
}

export interface ScanOutcome {
  /** The end of the last entry the scan accepted. */
  validEnd: number;
  /** The id of the last accepted entry, or the one passed as `afterEntryId`. */
  lastEntryId: number;
  entries: number;
  /** A bad or incomplete entry with nothing valid after it. */
  tornTail: { fromOffset: number; bytes: number } | null;
  /** Damage with bytes behind it, or something the visitor rejected. The scan stops there. */
  problem: string | null;
}

const WINDOW_BYTES = 4 << 20;

/**
 * Walks entries from `startOffset`, checking every header and every CRC.
 *
 * **Torn or corrupt** is decided here. An entry whose header is cut short, or
 * whose declared extent reaches or passes the end of the file, is a tear: it is
 * what an append that did not finish leaves, and nothing valid can lie behind
 * it. An entry whose extent ends exactly at the end of the file with a failing
 * checksum is a tear for the same reason. A bad magic, an over-cap length, a
 * failing checksum with bytes behind it, a skipped or repeated id - all
 * corruption, because truncating on a guess would discard evidence that may be
 * intact behind it.
 *
 * `visit` returns `null` to accept an entry or a sentence to reject it; a
 * rejected entry is corruption even at the very end, because its checksum
 * was good, so it was written whole by something that was wrong.
 *
 * Reads go through a 4 MB window rather than two reads per entry: the
 * measured scan of a day is 1.5 s that way.
 */
export function scanEntries(
  file: Readable,
  framing: Framing,
  startOffset: number,
  afterEntryId: number,
  visit: (entry: ScannedEntry) => string | null,
): ScanOutcome {
  const size = file.size();
  const windowBytes = Math.max(framing.maxBodyBytes + ENTRY_HEADER_BYTES, Math.min(WINDOW_BYTES, Math.max(size - startOffset, 1)));
  const win = new Uint8Array(windowBytes);
  let winStart = 0;
  let winLen = 0;

  const get = (offset: number, n: number): Uint8Array | null => {
    if (offset + n > size) return null;
    if (!(offset >= winStart && offset + n <= winStart + winLen)) {
      winStart = offset;
      winLen = file.read(offset, win.subarray(0, Math.min(win.length, size - offset)));
      if (winLen < n) return null;
    }
    return win.subarray(offset - winStart, offset - winStart + n);
  };

  let offset = startOffset;
  let lastId = afterEntryId;
  let entries = 0;
  const outcome = (tornFrom: number | null, problem: string | null): ScanOutcome => ({
    validEnd: offset,
    lastEntryId: lastId,
    entries,
    tornTail: tornFrom === null ? null : { fromOffset: tornFrom, bytes: size - tornFrom },
    problem,
  });

  while (offset < size) {
    if (size - offset < ENTRY_HEADER_BYTES) return outcome(offset, null);
    const header = get(offset, ENTRY_HEADER_BYTES);
    if (!header) return outcome(offset, null);
    const h = parseEntryHeader(framing, header);
    if (!h.ok) return outcome(null, `${h.reason} at offset ${offset}`);
    const end = offset + ENTRY_HEADER_BYTES + h.bodyLength;
    if (end > size) return outcome(offset, null);
    // The header view is clobbered if the body read moves the window, so the
    // CRC of its first 20 bytes is taken first.
    const headerCrc = crc32(header.subarray(0, 20));
    const body = get(offset + ENTRY_HEADER_BYTES, h.bodyLength);
    if (!body) return outcome(offset, null);
    if (crc32(body, headerCrc) !== h.crc) {
      return end === size
        ? outcome(offset, null)
        : outcome(null, `the checksum of entry ${h.entryId} at offset ${offset} does not match`);
    }
    if (h.entryId !== lastId + 1) {
      return outcome(null, `entry id ${h.entryId} at offset ${offset} follows ${lastId}`);
    }
    const rejected = visit({ entryId: h.entryId, kind: h.kind, offset, end, body });
    if (rejected !== null) return outcome(null, `entry ${h.entryId} at offset ${offset}: ${rejected}`);
    lastId = h.entryId;
    entries++;
    offset = end;
  }
  return outcome(null, null);
}
