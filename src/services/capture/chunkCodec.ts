/**
 * A chunk of frame summaries, encoded for disk.
 *
 * The disk-backed buffer stores each frame's **summary** beside its bytes, so
 * that scrolling back to an evicted frame is a read rather than a
 * re-dissection. That is not a speed choice: a frame's row is a function of the
 * frames before it - the TCP sequence base, the TLS record cursor, the DNS
 * pairing - so re-dissecting one in the middle of a capture can produce a
 * **different** Info line, not merely a slower one. `sessionStore.toStoredFrame`
 * persists bytes alone and re-derives the rest, which was right when the disk
 * copy existed to survive a refresh and is wrong when it is where the row is
 * read back from.
 *
 * ## Two blocks, and the reason they are two
 *
 * A chunk encodes to **a prefix block and a summary block**, and they are kept
 * apart because they are read by different things:
 *
 *  - **The prefix** is fixed-width, `PREFIX_BYTES` per frame, holding what a
 *    display filter asks about most of the time - the timestamp, both addresses
 *    in binary, both ports, the length, the status, and bitmaps for the layer
 *    chain and the TCP analysis flags. A whole-capture filter reads *only* this
 *    block and evaluates it through a `DataView` at tens of nanoseconds a row.
 *  - **The summary** is variable-width and holds everything needed to rebuild
 *    the `Packet` exactly, with every string interned into a per-chunk table.
 *    It is read when a row is actually shown.
 *
 * Measured over both fixtures (`scripts/perf/summary-codec.ts`), that split is
 * free. Deflated as one blob a chunk is 27.5 B/frame and a filter must inflate
 * 388 B/frame to scan it; deflated as two blocks it is **27.2 B/frame** - the
 * same disk - and a filter inflates **64 B/frame**. Prefixes compress 19x on
 * their own because addresses and timestamps repeat inside a chunk. Six times
 * less inflate work, for nothing.
 *
 * ## What this module does NOT do
 *
 * **It does not compress.** Both blocks come out and go in uncompressed, and
 * the storage layer deflates them. That keeps this module pure and synchronous
 * - the browser's `CompressionStream` is async and Node's `zlib` is not the
 * same API - so the round-trip can be asserted directly rather than through an
 * I/O layer. It is also why the numbers above are quoted from the measurement
 * script rather than produced here.
 *
 * ## The prefix is an accelerator, never the source of truth
 *
 * `source` and `destination` appear **twice**: as exact strings in the summary,
 * and as parsed binary in the prefix. The strings are what round-trips, because
 * `Packet.source` may be a resolved name or a MAC and must come back
 * character-for-character. The binary is what `ip.addr == x` matches against
 * without decoding anything. The same relationship holds for `frameProtocols`
 * and `analysisFlags`: exact as interned lists, mirrored as bitmaps.
 *
 * That is what makes growth safe. `LAYERS` is 57 tokens today and the bitmap
 * holds 64; when it passes 64 the *accelerator* degrades for the overflow
 * tokens and the filter falls back to the list, and nothing decodes wrongly.
 * A layout that stored only the bitmap would silently lose a protocol instead.
 */
import type { Packet, PacketStatus, ProtocolType, ExpertInfo, ExpertCategory } from '../../types/packet';
import { LAYERS } from '../dissect/fieldRegistry';
import { fieldEntries } from '../dissect/fieldAccess';

export const CHUNK_MAGIC = 0x314b4349;            // 'ICK1'
export const CHUNK_VERSION = 1;

/**
 * Frames per chunk, pinned to `BLOCK_ROWS` in `dissect/fieldSplit.ts`.
 *
 * Deliberately the same number, so one decoded chunk is exactly one
 * `FieldBlock`'s worth of rows and the read path never has to re-split what the
 * write path already grouped.
 */
export const CHUNK_FRAMES = 4096;

/**
 * The fixed-width filter record. 72 bytes, laid out so every field is naturally
 * aligned: the f64 first, then the 4-byte fields, then the 16-byte addresses,
 * then the 2-byte and 1-byte tail.
 */
export const PREFIX_BYTES = 72;

const OFF_TS_US = 0;          // f64  - epoch microseconds
const OFF_LENGTH = 8;         // u32
const OFF_STREAM_ID = 12;     // u32  - 0xffffffff means "none"
const OFF_SRC_ADDR = 16;      // 16 bytes
const OFF_DST_ADDR = 32;      // 16 bytes
const OFF_LAYERS_LO = 48;     // u32  - LAYERS[0..31]
const OFF_LAYERS_HI = 52;     // u32  - LAYERS[32..63]
const OFF_ANALYSIS = 56;      // u32  - ANALYSIS_FLAGS bitmap
const OFF_SRC_PORT = 60;      // u16
const OFF_DST_PORT = 62;      // u16
const OFF_NANOS_REM = 64;     // u16  - 0..999, the sub-microsecond part
const OFF_DIRECTION = 66;     // u16  - the packed direction word
const OFF_STATUS = 68;        // u8
const OFF_ADDR_KIND = 69;     // u8   - src kind in the low nibble, dst in the high
// 70..71 reserved. Two bytes held back on purpose: a segment ordinal goes here
// when v2 splits a capture into segments, which is the one field v2 is known to
// need and the cheapest possible way to not break the format for it.

/** Status codes, ordered so the byte is stable across releases. */
const STATUS_ORDER: readonly PacketStatus[] = ['ok', 'warning', 'alert', 'retransmit', 'dropped'];

/**
 * The TCP analysis flags, in a fixed order because their bit positions are
 * stored. Appending is safe; reordering or removing is not.
 */
export const ANALYSIS_FLAGS: readonly string[] = [
  'ack_lost_segment', 'duplicate_ack', 'fast_retransmission', 'keep_alive',
  'keep_alive_ack', 'lost_segment', 'out_of_order', 'retransmission',
  'reused_ports', 'spurious_retransmission', 'window_full', 'window_update',
  'zero_window', 'zero_window_probe', 'zero_window_probe_ack',
];

const ANALYSIS_BIT = new Map<string, number>(ANALYSIS_FLAGS.map((f, i) => [f, i]));
const LAYER_BIT = new Map<string, number>(LAYERS.map((l, i) => [l, i]));

/** How an address was parsed into the prefix, so a filter knows what it holds. */
const ADDR_NONE = 0;
const ADDR_IPV4 = 1;
const ADDR_IPV6 = 2;
const ADDR_MAC = 3;
/** A name or anything else textual: the prefix holds nothing a filter can use. */
const ADDR_TEXT = 4;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Writes an address into 16 bytes and says what it wrote.
 *
 * Hoisted encoders and no allocation per call: this runs once per frame per
 * address, and `scripts/perf/hot-path-allocations.ts` fails the build on a
 * `TextEncoder` built inside a function under `src/services/`.
 */
function writeAddress(text: string, into: Uint8Array, at: number): number {
  into.fill(0, at, at + 16);
  if (text.length === 0) return ADDR_NONE;

  // IPv4: four dotted decimals and no colon.
  if (text.indexOf(':') === -1 && text.indexOf('.') !== -1) {
    const parts = text.split('.');
    if (parts.length !== 4) return ADDR_TEXT;
    for (let i = 0; i < 4; i++) {
      const v = Number(parts[i]);
      if (!Number.isInteger(v) || v < 0 || v > 255) return ADDR_TEXT;
      into[at + i] = v;
    }
    return ADDR_IPV4;
  }

  // A MAC is six hex pairs separated by colons; IPv6 groups are up to four hex
  // digits. Telling them apart by group width is exact for both forms.
  if (text.indexOf(':') !== -1) {
    const groups = text.split(':');
    const isMac = groups.length === 6 && groups.every((g) => g.length === 2);
    if (isMac) {
      for (let i = 0; i < 6; i++) {
        const v = parseInt(groups[i], 16);
        if (Number.isNaN(v)) return ADDR_TEXT;
        into[at + i] = v;
      }
      return ADDR_MAC;
    }
    return writeIpv6(text, into, at) ? ADDR_IPV6 : ADDR_TEXT;
  }

  return ADDR_TEXT;
}

/** Expands an RFC 5952 address, `::` included, into 16 bytes. */
function writeIpv6(text: string, into: Uint8Array, at: number): boolean {
  const halves = text.split('::');
  if (halves.length > 2) return false;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  if (halves.length === 1 && head.length !== 8) return false;
  if (head.length + tail.length > 8) return false;

  let out = at;
  for (const g of head) {
    const v = parseInt(g, 16);
    if (Number.isNaN(v)) return false;
    into[out++] = (v >> 8) & 0xff;
    into[out++] = v & 0xff;
  }
  out = at + 16 - tail.length * 2;
  for (const g of tail) {
    const v = parseInt(g, 16);
    if (Number.isNaN(v)) return false;
    into[out++] = (v >> 8) & 0xff;
    into[out++] = v & 0xff;
  }
  return true;
}

/** A growable little-endian byte sink. */
class Sink {
  private buf: Uint8Array;
  private view: DataView;
  private at = 0;

  constructor(initial = 1 << 16) {
    this.buf = new Uint8Array(initial);
    this.view = new DataView(this.buf.buffer);
  }

  private grow(n: number): void {
    if (this.at + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.at + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.at));
    this.buf = next;
    this.view = new DataView(next.buffer);
  }

  u8(v: number): void { this.grow(1); this.buf[this.at++] = v & 0xff; }
  u16(v: number): void { this.grow(2); this.view.setUint16(this.at, v & 0xffff, true); this.at += 2; }
  u32(v: number): void { this.grow(4); this.view.setUint32(this.at, v >>> 0, true); this.at += 4; }
  f64(v: number): void { this.grow(8); this.view.setFloat64(this.at, v, true); this.at += 8; }
  raw(b: Uint8Array): void { this.grow(b.length); this.buf.set(b, this.at); this.at += b.length; }

  bytes(): Uint8Array { return this.buf.slice(0, this.at); }
}

/** A little-endian cursor over an encoded block. */
class Source {
  private view: DataView;
  private at = 0;

  constructor(private readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  u8(): number { return this.buf[this.at++]; }
  u16(): number { const v = this.view.getUint16(this.at, true); this.at += 2; return v; }
  u32(): number { const v = this.view.getUint32(this.at, true); this.at += 4; return v; }
  f64(): number { const v = this.view.getFloat64(this.at, true); this.at += 8; return v; }
  raw(n: number): Uint8Array { const v = this.buf.subarray(this.at, this.at + n); this.at += n; return v; }
  get offset(): number { return this.at; }
}

export interface EncodedChunk {
  /** Fixed-width filter records, `PREFIX_BYTES` each. Deflate before writing. */
  prefix: Uint8Array;
  /** Everything needed to rebuild the packets exactly. Deflate before writing. */
  summary: Uint8Array;
  frameCount: number;
  firstId: number;
  lastId: number;
  firstTsUs: number;
  lastTsUs: number;
}

/**
 * Encodes up to `CHUNK_FRAMES` packets.
 *
 * `packets` must be in ascending id order and non-empty. Ids may have holes - a
 * frame that failed to dissect burns one - so the decoder never assumes
 * `firstId + n`.
 */
export function encodeChunk(packets: readonly Packet[]): EncodedChunk {
  if (packets.length === 0) throw new Error('encodeChunk: empty chunk');
  if (packets.length > CHUNK_FRAMES) {
    throw new Error(`encodeChunk: ${packets.length} frames exceeds CHUNK_FRAMES (${CHUNK_FRAMES})`);
  }

  const prefix = new Uint8Array(packets.length * PREFIX_BYTES);
  const prefixView = new DataView(prefix.buffer);

  // One string table for the chunk. This is where the compression comes from:
  // inside 4,096 frames an address, a protocol label or an expert sentence
  // recurs dozens of times, and an id costs four bytes where the text costs
  // fifteen to a hundred. Measured at 10-14x before deflate even runs.
  const table: string[] = [];
  const seen = new Map<string, number>();
  const id = (s: string): number => {
    let v = seen.get(s);
    if (v === undefined) { v = table.length; seen.set(s, v); table.push(s); }
    return v;
  };

  const body = new Sink(packets.length * 256);

  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    const at = i * PREFIX_BYTES;

    // --- the prefix: an accelerator, derived, never read back as truth -------
    prefixView.setFloat64(at + OFF_TS_US, p.tsUs, true);
    prefixView.setUint32(at + OFF_LENGTH, p.length >>> 0, true);
    prefixView.setUint32(at + OFF_STREAM_ID, p.streamId === undefined ? 0xffffffff : p.streamId >>> 0, true);
    const srcKind = writeAddress(p.source, prefix, at + OFF_SRC_ADDR);
    const dstKind = writeAddress(p.destination, prefix, at + OFF_DST_ADDR);

    let layersLo = 0, layersHi = 0;
    for (const token of p.frameProtocols ?? []) {
      const bit = LAYER_BIT.get(token);
      if (bit === undefined || bit >= 64) continue;   // overflow falls back to the list
      if (bit < 32) layersLo |= 1 << bit; else layersHi |= 1 << (bit - 32);
    }
    prefixView.setUint32(at + OFF_LAYERS_LO, layersLo >>> 0, true);
    prefixView.setUint32(at + OFF_LAYERS_HI, layersHi >>> 0, true);

    let analysis = 0;
    for (const flag of p.analysisFlags ?? []) {
      const bit = ANALYSIS_BIT.get(flag);
      if (bit !== undefined) analysis |= 1 << bit;
    }
    prefixView.setUint32(at + OFF_ANALYSIS, analysis >>> 0, true);

    prefixView.setUint16(at + OFF_SRC_PORT, (p.sourcePort ?? 0) & 0xffff, true);
    prefixView.setUint16(at + OFF_DST_PORT, (p.destPort ?? 0) & 0xffff, true);
    // The nanosecond remainder rides beside `tsUs` rather than replacing it
    // with a u64: epoch nanoseconds exceed 2^53, so a f64 cannot hold them and
    // a BigInt read per row is too slow for a 38M-row scan. Microseconds are
    // exact in a f64 for the next few centuries, and 0..999 fits a u16.
    prefixView.setUint16(at + OFF_NANOS_REM, nanosRemainderOf(p), true);
    prefixView.setUint16(at + OFF_DIRECTION, (p.direction ?? 0) & 0xffff, true);
    prefix[at + OFF_STATUS] = Math.max(0, STATUS_ORDER.indexOf(p.status));
    prefix[at + OFF_ADDR_KIND] = (srcKind & 0x0f) | ((dstKind & 0x0f) << 4);

    // --- the summary: exact, and what actually round-trips ------------------
    body.u32(p.id >>> 0);
    body.u32(id(p.source));
    body.u32(id(p.destination));
    body.u32(id(p.protocol));
    body.u32(p.protocolLabel === undefined ? 0xffffffff : id(p.protocolLabel));
    body.u32(id(p.info));
    body.u32(id(p.interfaceName));
    body.f64(p.relativeTime);
    body.f64(p.timeDelta);
    body.u32(p.sourcePort === undefined ? 0xffffffff : p.sourcePort >>> 0);
    body.u32(p.destPort === undefined ? 0xffffffff : p.destPort >>> 0);
    body.u32(p.direction === undefined ? 0xffffffff : p.direction >>> 0);
    body.u16(p.tsPrecision === undefined ? 0xffff : p.tsPrecision);
    writeNanos(body, p.tsNanos);

    // ABSENT rather than 0 for a list the frame does not have, because an
    // EMPTY list is a different fact and the dissector emits both: a TCP frame
    // with no analysis carries `analysisFlags: []`, and an ARP frame carries
    // none at all. Collapsing the two was the first thing the round-trip test
    // caught, on 7,775 of 12,858 real frames.
    const protocols = p.frameProtocols;
    body.u16(protocols === undefined ? ABSENT : protocols.length);
    for (const t of protocols ?? []) body.u32(id(t));

    const flags = p.analysisFlags;
    body.u16(flags === undefined ? ABSENT : flags.length);
    for (const f of flags ?? []) body.u32(id(f));

    const expert = p.expert ?? [];
    body.u16(p.expert === undefined ? ABSENT : expert.length);
    for (const f of expert) {
      body.u32(id(f.message));
      body.u32(f.category === undefined ? 0xffffffff : id(f.category));
    }

    const resolved = p.resolved ?? [];
    body.u16(p.resolved === undefined ? ABSENT : resolved.length);
    for (const r of resolved) {
      body.u32(id(r.name));
      body.u16(r.addresses.length);
      for (const a of r.addresses) body.u32(id(a));
    }

    // The whole field bag, dense columns and sparse remainder alike.
    // `fieldEntries` is the one function that knows a value can be in either
    // place, which is exactly why the codec asks it rather than reading
    // `packet.fields` and silently losing every dense key.
    const entries = p.fields === undefined && p.cols === undefined ? [] : fieldEntries(p);
    body.u16(p.fields === undefined && p.cols === undefined ? ABSENT : entries.length);
    for (const [key, value] of entries) {
      body.u32(id(key));
      if (typeof value === 'number') { body.u8(0); body.f64(value); }
      else { body.u8(1); body.u32(id(value)); }
    }
  }

  // Header, then the table, then the bodies. The table comes first so a reader
  // that only wants string ids resolved does not have to walk the bodies.
  const out = new Sink(body.bytes().length + 8192);
  out.u32(CHUNK_MAGIC);
  out.u16(CHUNK_VERSION);
  out.u16(0);                                  // flags, reserved
  out.u32(packets.length);
  out.u32(table.length);
  for (const s of table) {
    const encoded = textEncoder.encode(s);
    out.u32(encoded.length);
    out.raw(encoded);
  }
  out.raw(body.bytes());

  return {
    prefix,
    summary: out.bytes(),
    frameCount: packets.length,
    firstId: packets[0].id,
    lastId: packets[packets.length - 1].id,
    firstTsUs: packets[0].tsUs,
    lastTsUs: packets[packets.length - 1].tsUs,
  };
}

/**
 * `tsNanos` is a bigint of epoch nanoseconds when a capture file carried them.
 *
 * Split into two u32 lanes rather than written through a f64: 1.7e18 is well
 * past 2^53, so a numeric lane would round three digits away silently - the
 * exact precision the pcapng reader went to trouble to keep.
 */
function writeNanos(sink: Sink, value: bigint | undefined): void {
  if (value === undefined) { sink.u8(0); return; }
  sink.u8(1);
  sink.u32(Number(value & 0xffffffffn));
  sink.u32(Number((value >> 32n) & 0xffffffffn));
}

function readNanos(src: Source): bigint | undefined {
  if (src.u8() === 0) return undefined;
  const lo = BigInt(src.u32());
  const hi = BigInt(src.u32());
  return (hi << 32n) | lo;
}

/** The sub-microsecond part of a frame's timestamp, 0..999. */
function nanosRemainderOf(p: Packet): number {
  if (p.tsNanos === undefined) return 0;
  return Number(p.tsNanos % 1000n);
}

/**
 * Rebuilds the packets a chunk was encoded from.
 *
 * `rawBytes` comes back as an empty view: frame bytes live in their own stream
 * and are fetched through the existing `packetBytes()` seam, which already
 * knows how to hydrate a frame whose bytes are not resident. `layers` comes
 * back empty for the reason ADR 0007 gives - a tree is 10.6 kB against the
 * frame's own 1.2 kB, and it is rebuilt on demand.
 */
export function decodeChunk(summary: Uint8Array): Packet[] {
  const src = new Source(summary);
  const magic = src.u32();
  if (magic !== CHUNK_MAGIC) throw new Error(`decodeChunk: bad magic 0x${magic.toString(16)}`);
  const version = src.u16();
  if (version !== CHUNK_VERSION) throw new Error(`decodeChunk: version ${version} is not one this build reads`);
  src.u16();                                    // flags
  const frameCount = src.u32();
  const tableLength = src.u32();

  const table: string[] = new Array(tableLength);
  for (let i = 0; i < tableLength; i++) table[i] = textDecoder.decode(src.raw(src.u32()));
  const str = (index: number): string => {
    const s = table[index];
    if (s === undefined) throw new Error(`decodeChunk: string id ${index} past the table`);
    return s;
  };

  const packets: Packet[] = new Array(frameCount);
  for (let i = 0; i < frameCount; i++) {
    const id = src.u32();
    const source = str(src.u32());
    const destination = str(src.u32());
    const protocol = str(src.u32()) as ProtocolType;
    const labelId = src.u32();
    const info = str(src.u32());
    const interfaceName = str(src.u32());
    const relativeTime = src.f64();
    const timeDelta = src.f64();
    const sourcePort = src.u32();
    const destPort = src.u32();
    const direction = src.u32();
    const tsPrecision = src.u16();
    const tsNanos = readNanos(src);

    const protocolCount = src.u16();
    const protocols: string[] = new Array(protocolCount === ABSENT ? 0 : protocolCount);
    for (let k = 0; k < protocols.length; k++) protocols[k] = str(src.u32());

    const flagCount = src.u16();
    const flags: string[] = new Array(flagCount === ABSENT ? 0 : flagCount);
    for (let k = 0; k < flags.length; k++) flags[k] = str(src.u32());

    const expertCount = src.u16();
    const expert: ExpertInfo[] = new Array(expertCount === ABSENT ? 0 : expertCount);
    for (let k = 0; k < expert.length; k++) {
      const message = str(src.u32());
      const categoryId = src.u32();
      expert[k] = categoryId === 0xffffffff
        ? { message }
        : { message, category: str(categoryId) as ExpertCategory };
    }

    const resolvedCount = src.u16();
    const resolved: { name: string; addresses: string[] }[] =
      new Array(resolvedCount === ABSENT ? 0 : resolvedCount);
    for (let k = 0; k < resolved.length; k++) {
      const name = str(src.u32());
      const addresses: string[] = new Array(src.u16());
      for (let a = 0; a < addresses.length; a++) addresses[a] = str(src.u32());
      resolved[k] = { name, addresses };
    }

    const fields: Record<string, string | number> = {};
    const entryCount = src.u16();
    for (let k = 0; k < (entryCount === ABSENT ? 0 : entryCount); k++) {
      const key = str(src.u32());
      fields[key] = src.u8() === 0 ? src.f64() : str(src.u32());
    }

    packets[i] = {
      id,
      source,
      destination,
      protocol,
      info,
      interfaceName,
      relativeTime,
      timeDelta,
      // Filled from the prefix block by the reader, which has it to hand; the
      // summary does not repeat them.
      tsUs: 0,
      length: 0,
      status: 'ok',
      layers: [],
      rawBytes: EMPTY_BYTES,
      ...(labelId === 0xffffffff ? {} : { protocolLabel: str(labelId) }),
      ...(sourcePort === 0xffffffff ? {} : { sourcePort }),
      ...(destPort === 0xffffffff ? {} : { destPort }),
      ...(direction === 0xffffffff ? {} : { direction }),
      ...(tsPrecision === 0xffff ? {} : { tsPrecision }),
      ...(tsNanos === undefined ? {} : { tsNanos }),
      ...(protocolCount === ABSENT ? {} : { frameProtocols: protocols }),
      ...(flagCount === ABSENT ? {} : { analysisFlags: flags }),
      ...(expertCount === ABSENT ? {} : { expert }),
      ...(resolvedCount === ABSENT ? {} : { resolved }),
      ...(entryCount === ABSENT ? {} : { fields }),
    } as Packet;
  }

  if (src.offset !== summary.length) {
    throw new Error(`decodeChunk: ${summary.length - src.offset} bytes after the last frame`);
  }
  return packets;
}

const EMPTY_BYTES = new Uint8Array(0);

/**
 * The u16 count that means "this frame has no such list at all".
 *
 * Distinct from 0, which means "it has one and it is empty". `CHUNK_FRAMES` is
 * 4,096 so no real count comes near it.
 */
const ABSENT = 0xffff;

/**
 * Copies the prefix block's per-frame values onto decoded packets.
 *
 * Split out because the two blocks are read independently: a filter reads the
 * prefix alone, and only a row that is actually going to be shown pays for the
 * summary. This is what joins them when both are in hand.
 */
export function applyPrefixes(packets: Packet[], prefix: Uint8Array): void {
  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
  for (let i = 0; i < packets.length; i++) {
    const at = i * PREFIX_BYTES;
    const p = packets[i];
    p.tsUs = view.getFloat64(at + OFF_TS_US, true);
    p.length = view.getUint32(at + OFF_LENGTH, true);
    p.status = STATUS_ORDER[prefix[at + OFF_STATUS]] ?? 'ok';
    const stream = view.getUint32(at + OFF_STREAM_ID, true);
    if (stream !== 0xffffffff) p.streamId = stream;
  }
}

/** A read-only view over one chunk's prefix block, for the scan path. */
export class PrefixBlock {
  private readonly view: DataView;
  readonly frameCount: number;

  constructor(private readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    this.frameCount = Math.floor(buf.byteLength / PREFIX_BYTES);
  }

  tsUs(i: number): number { return this.view.getFloat64(i * PREFIX_BYTES + OFF_TS_US, true); }
  length(i: number): number { return this.view.getUint32(i * PREFIX_BYTES + OFF_LENGTH, true); }
  srcPort(i: number): number { return this.view.getUint16(i * PREFIX_BYTES + OFF_SRC_PORT, true); }
  dstPort(i: number): number { return this.view.getUint16(i * PREFIX_BYTES + OFF_DST_PORT, true); }
  status(i: number): PacketStatus { return STATUS_ORDER[this.buf[i * PREFIX_BYTES + OFF_STATUS]] ?? 'ok'; }
  direction(i: number): number { return this.view.getUint16(i * PREFIX_BYTES + OFF_DIRECTION, true); }
  srcKind(i: number): number { return this.buf[i * PREFIX_BYTES + OFF_ADDR_KIND] & 0x0f; }
  dstKind(i: number): number { return (this.buf[i * PREFIX_BYTES + OFF_ADDR_KIND] >> 4) & 0x0f; }

  streamId(i: number): number | undefined {
    const v = this.view.getUint32(i * PREFIX_BYTES + OFF_STREAM_ID, true);
    return v === 0xffffffff ? undefined : v;
  }

  /** True when the frame's layer chain contains `token`, for a bareword filter. */
  hasLayer(i: number, token: string): boolean {
    const bit = LAYER_BIT.get(token);
    if (bit === undefined || bit >= 64) return false;
    const at = i * PREFIX_BYTES + (bit < 32 ? OFF_LAYERS_LO : OFF_LAYERS_HI);
    return (this.view.getUint32(at, true) & (1 << (bit % 32))) !== 0;
  }

  /** True when the frame carries `flag`, for a `tcp.analysis.*` filter. */
  hasAnalysisFlag(i: number, flag: string): boolean {
    const bit = ANALYSIS_BIT.get(flag);
    if (bit === undefined) return false;
    return (this.view.getUint32(i * PREFIX_BYTES + OFF_ANALYSIS, true) & (1 << bit)) !== 0;
  }

  /** The 16 raw address bytes, for an `ip.addr` comparison without decoding. */
  address(i: number, which: 'src' | 'dst'): Uint8Array {
    const at = i * PREFIX_BYTES + (which === 'src' ? OFF_SRC_ADDR : OFF_DST_ADDR);
    return this.buf.subarray(at, at + 16);
  }
}

/** Exposed so tests and the reader can agree on what the accelerator holds. */
export const ADDRESS_KIND = {
  NONE: ADDR_NONE, IPV4: ADDR_IPV4, IPV6: ADDR_IPV6, MAC: ADDR_MAC, TEXT: ADDR_TEXT,
} as const;
