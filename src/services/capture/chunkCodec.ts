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
 * That is what makes growth safe. `LAYERS` is past 64 tokens and the bitmap
 * holds 64, in the frozen order of `LAYER_BIT_ORDER`; for every other token
 * the *accelerator* degrades and the filter falls back to the list, and
 * nothing decodes wrongly.
 * A layout that stored only the bitmap would silently lose a protocol instead.
 *
 * ## Version 3: a chunk that holds shard packs
 *
 * A shard hands the coordinator its rows already encoded as a version-2 summary
 * (`pipeline/rowPack.ts`). Decoding and encoding them again in the store is
 * most of what the store costs per frame, so a chunk that holds packed rows may
 * instead be a **container**: the packs' own summaries, whole or reduced to the
 * rows this chunk holds, as segments; one lane saying which segment each row of
 * the chunk is in; and two side sections for what the merge and later frames
 * wrote to a row after its shard was done (overlays, then info patches). Each
 * segment is a complete version-2 summary, so `decodeChunk` reads it with the
 * code it already had, and a container inside a segment is refused.
 *
 * The prefix block does not change, and neither does anything that reads only
 * it. Only chunks that hold packed rows are containers: `encodeChunk` still
 * writes version 2, so an import and the single Worker produce the files they
 * always did. An older build opens a capture holding a container and fails the
 * row reads of those chunks, one by one, with the version error below; the
 * index and the prefix and byte blocks stay readable.
 */
import type { Packet, PacketStatus, ProtocolType, ExpertInfo, ExpertCategory } from '../../types/packet';
import { fieldEntries } from '../dissect/fieldAccess';
import type { FieldBlock } from '../dissect/fieldBlock';
import type { FieldBlockWriter } from '../dissect/fieldSplit';
import { DENSE_FIELDS } from '../dissect/denseFields';
import { applyInfoPatch } from '../dissect/infoPatch';
import type { InfoPatch } from '../dissect/types';
// A type only: `rowPack.ts` imports this module as a value, and a cycle between
// the two would leave one of them half-initialised under a bundler.
import type { RowPack } from '../pipeline/rowPack';
import { applyOverlay, type RowOverlay } from '../pipeline/rowOverlay';

export const CHUNK_MAGIC = 0x314b4349;            // 'ICK1'
/**
 * The layout of a row inside a summary, which is what `encodeChunk` writes and
 * what a shard's pack is made of. Unchanged by version 3, which is a container
 * around summaries in this layout, not a new layout for a row.
 */
export const ROW_LAYOUT_VERSION = 2;
/**
 * The newest summary this build reads: 3, the container. Writers use
 * `ROW_LAYOUT_VERSION` for a flat summary and `encodePackedChunk` for a
 * container.
 *
 * Of the row layout, 2 carries each frame's `linkType`; 1 did not.
 *
 * **A version-1 chunk still decodes**, and that is a promise rather than a
 * courtesy: a capture on disk outlives the build that wrote it, and a restore
 * or an export of one written last week must not fail because this field was
 * added since. Its rows come back with no `linkType`, exactly as they always
 * did, and `chunkStoresLinkType` says so - so a reader knows the absence means
 * "not recorded" there and "Ethernet" in a version-2 chunk, which is the same
 * convention the dissector follows.
 *
 * Why it had to be stored: the only other source is a table from adapter
 * label to link type, and a label is not an adapter. Every frame of an
 * imported file is labelled alike, so an import of a multi-interface pcapng -
 * an Ethernet adapter and a Raw IP tunnel, say - read back off disk with every
 * row given whichever type the table held last, and an export of it wrote
 * the tunnel's frames under an Ethernet interface or the reverse.
 */
export const CHUNK_VERSION = 3;
/** The oldest summary layout this build reads. */
const OLDEST_CHUNK_VERSION = 1;

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

/**
 * The byte directory: which frame is where in the `byt` stream.
 *
 * Two u32 lanes per frame - the frame **id** and its **captured length** -
 * written after the prefix records in the same block, and columnar rather than
 * interleaved into the record. Both halves of that are deliberate.
 *
 * *In the same block*, because a byte read needs the directory and nothing
 * else, and a block of its own would be a fifth file, two more index fields and
 * a second thing the recovery rule has to keep consistent. The block's split is
 * arithmetic - `frameCount * PREFIX_BYTES` - and `frameCount` is in the index
 * record every reader already has.
 *
 * *Columnar*, because these two lanes are the most compressible thing in the
 * capture and interleaving them into a 72-byte stride would waste that: ids
 * ascend by one and captured lengths repeat a handful of values (1514, 66, 54)
 * thousands of times. Deflate finds that in a run of 16 kB and cannot find it
 * across a 72-byte gap.
 *
 * The id lane holds **gaps, not ids**, for the same reason. Measured on both
 * fixtures, absolute ids cost 3.1-3.5 B/frame deflated - nearly half of the
 * eight raw bytes - because an ascending u32 changes its low byte on every
 * frame and deflate sees no repeat. The gap between consecutive ids is 1 on
 * every frame that dissected, so the lane becomes one four-byte pattern
 * repeated 4,096 times and costs **0.4-0.5 B/frame** instead. The first entry
 * is the chunk's first id in full, so the lane needs nothing from outside
 * itself.
 *
 * The id lane is what makes the directory work at all. Ids have holes, so a
 * frame's position inside its chunk is not `id - firstId`; and the ids live in
 * the **summary** block, which a byte read must not have to inflate - it is
 * fourteen times the size and holds nothing this needs.
 */
export const DIRECTORY_BYTES = 8;

/** The length of a whole prefix block, records and directory together. */
export function prefixBlockBytes(frameCount: number): number {
  return frameCount * (PREFIX_BYTES + DIRECTORY_BYTES);
}

const OFF_TS_US = 0;          // f64  - epoch microseconds
const OFF_LENGTH = 8;         // u32
const OFF_STREAM_ID = 12;     // u32  - 0xffffffff means "none"
const OFF_SRC_ADDR = 16;      // 16 bytes
const OFF_DST_ADDR = 32;      // 16 bytes
const OFF_LAYERS_LO = 48;     // u32  - LAYER_BIT_ORDER[0..31]
const OFF_LAYERS_HI = 52;     // u32  - LAYER_BIT_ORDER[32..63]
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
/**
 * Each layer token's bit in the prefix's 64-bit layer bitmap, in a fixed
 * order because the bits are WRITTEN TO DISK. Appending is safe; reordering,
 * inserting or removing is not.
 *
 * It used to be `LAYERS`' own order, which is the autocomplete's and gains
 * tokens in the middle - so every protocol added below the end moved every
 * bit after it, and a capture written before the change read back as the
 * wrong layers. Nothing reads the bitmap today (`hasLayer` has no caller
 * outside this file and its test; the filter answers from the interned
 * list), which is the only reason that was never seen. This is the order the
 * last build to use `LAYERS` wrote, so its captures keep their meaning; a
 * token past 64 or not listed here is answered from the list.
 */
export const LAYER_BIT_ORDER: readonly string[] = [
  'frame', 'eth', 'vlan', 'ieee8021ad', 'ieee8021ah', 'llc', 'sll', 'null', 'arp', 'stp', 'lldp', 'ieee1905', 'cdp',
  'eapol', 'eap', 'wlan_rsna_eapol',
  'ip', 'ipv6', 'gre', 'vxlan', 'esp', 'icmp', 'icmpv6', 'igmp', 'vrrp', 'ospf', 'tcp', 'udp',
  'dns', 'nbns', 'nbdgm', 'tls', 'quic', 'ssdp', 'dhcp', 'dhcpv6', 'ntp', 'stun',
  'syslog', 'radius', 'snmp', 'sip', 'rtcp', 'udpencap', 'isakmp', 'wg', 'openvpn', 'dtls', 'nat-pmp', 'portcontrol',
  'db-lsp-disc', 'tftp', 'bfd', 'coap', 'ptp',
  'hsrp', 'rip', 'ripng', 'bgp', 'ldap', 'cldap', 'mscldap', 'smb2', 'kerberos',
];
const LAYER_BIT = new Map<string, number>(LAYER_BIT_ORDER.map((l, i) => [l, i]));

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
 * Writes one frame's 72-byte filter record at `at`. The block is zero-filled
 * by whoever allocated it, which is what keeps the two reserved bytes zero.
 *
 * Factored out of `encodeChunk` so a chunk that holds packed rows writes the
 * records of its objects and placeholders exactly as a flat chunk would; a
 * packed row's record is copied instead (`encodePackedChunk`).
 */
function writePrefixRecord(prefix: Uint8Array, prefixView: DataView, at: number, p: Packet): void {
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
  prefixView.setUint16(at + OFF_NANOS_REM, nanosRemainderOf(p.tsNanos), true);
  prefixView.setUint16(at + OFF_DIRECTION, (p.direction ?? 0) & 0xffff, true);
  prefix[at + OFF_STATUS] = Math.max(0, STATUS_ORDER.indexOf(p.status));
  prefix[at + OFF_ADDR_KIND] = (srcKind & 0x0f) | ((dstKind & 0x0f) << 4);
}

/**
 * Encodes up to `CHUNK_FRAMES` packets.
 *
 * `packets` must be in ascending id order and non-empty. Ids may have holes - a
 * frame that failed to dissect burns one - so the decoder never assumes
 * `firstId + n`.
 */
export function encodeChunk(
  packets: readonly Packet[],
  capLengths: readonly number[],
  /**
   * The layout to write. Always `ROW_LAYOUT_VERSION` in the app; 1 exists so
   * the compatibility promise above can be asserted against a real old chunk
   * rather than one described in a comment.
   */
  version: 1 | 2 = ROW_LAYOUT_VERSION,
): EncodedChunk {
  if (packets.length === 0) throw new Error('encodeChunk: empty chunk');
  if (packets.length > CHUNK_FRAMES) {
    throw new Error(`encodeChunk: ${packets.length} frames exceeds CHUNK_FRAMES (${CHUNK_FRAMES})`);
  }
  // Passed in rather than read off `packet.rawBytes`, and this is not
  // defensive. `evictOldBytes` sets `rawBytes` to an empty array **in place**
  // on frames it can read back, so a packet's own view of how long its bytes
  // are is true when the writer appended them and can be false by the time the
  // chunk is sealed. The writer recorded the real length at append time; that
  // is the only number that describes the `byt` stream.
  if (capLengths.length !== packets.length) {
    throw new Error(`encodeChunk: ${capLengths.length} lengths for ${packets.length} frames`);
  }

  const prefix = new Uint8Array(prefixBlockBytes(packets.length));
  const prefixView = new DataView(prefix.buffer);
  const directoryAt = packets.length * PREFIX_BYTES;

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

    // --- the prefix: an accelerator, derived, never read back as truth -------
    writePrefixRecord(prefix, prefixView, i * PREFIX_BYTES, p);

    // --- the byte directory: two columnar lanes, not part of the record -----
    prefixView.setUint32(directoryAt + i * 4, (i === 0 ? p.id : p.id - packets[i - 1].id) >>> 0, true);
    prefixView.setUint32(directoryAt + packets.length * 4 + i * 4, capLengths[i] >>> 0, true);

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
    // Absent stays absent, meaning Ethernet, as it does on the frame.
    if (version >= 2) body.u16(p.linkType === undefined ? 0xffff : p.linkType & 0xffff);

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
  out.u16(version);
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
function nanosRemainderOf(tsNanos: bigint | undefined): number {
  if (tsNanos === undefined) return 0;
  return Number(tsNanos % 1000n);
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
export function decodeChunk(summary: Uint8Array, split?: FieldBlockWriter): Packet[] {
  return decodeSummary(summary, true, split);
}

/** Each dense key's column, by its place in `DENSE_FIELDS`. */
const DENSE_INDEX = new Map<string, number>(DENSE_FIELDS.map((k, i) => [k.abbrev, i]));

const SHORT_TEXT = 64;
const shortCodes = new Uint16Array(SHORT_TEXT);

/**
 * One string-table entry. Nearly all are short - 97% of the burst's are 64
 * bytes or fewer - and a TextDecoder call has a fixed cost that dwarfs them:
 * 5% of the window's main thread at 60,000 rows a second (#16). Most are not
 * ASCII either, because an Info line's arrow is three bytes, so one- to
 * three-byte UTF-8 is decoded here. Anything else - longer text, a four-byte
 * character, a malformed or overlong sequence, a surrogate, a byte-order mark -
 * goes to TextDecoder, so the answer is always the one it would give.
 * Exported for `scripts/capture/chunk-codec.ts`, which holds it to that.
 */
export function decodeText(bytes: Uint8Array): string {
  const n = bytes.length;
  if (n > SHORT_TEXT || (n >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) {
    return textDecoder.decode(bytes);
  }
  let out = 0;
  for (let i = 0; i < n;) {
    const b = bytes[i];
    if (b < 0x80) {
      shortCodes[out++] = b;
      i++;
    } else if (b >= 0xc2 && b < 0xe0 && i + 1 < n && (bytes[i + 1] & 0xc0) === 0x80) {
      shortCodes[out++] = ((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f);
      i += 2;
    } else if (b >= 0xe0 && b < 0xf0 && i + 2 < n) {
      const c = bytes[i + 1];
      const d = bytes[i + 2];
      if ((c & 0xc0) !== 0x80 || (d & 0xc0) !== 0x80) return textDecoder.decode(bytes);
      if ((b === 0xe0 && c < 0xa0) || (b === 0xed && c >= 0xa0)) return textDecoder.decode(bytes);
      shortCodes[out++] = ((b & 0x0f) << 12) | ((c & 0x3f) << 6) | (d & 0x3f);
      i += 3;
    } else {
      return textDecoder.decode(bytes);
    }
  }
  return String.fromCharCode.apply(null, shortCodes.subarray(0, out) as unknown as number[]);
}

/** `container` false is a segment: it must be a flat summary, never another container. */
function decodeSummary(summary: Uint8Array, container: boolean, split?: FieldBlockWriter): Packet[] {
  const src = new Source(summary);
  const magic = src.u32();
  if (magic !== CHUNK_MAGIC) throw new Error(`decodeChunk: bad magic 0x${magic.toString(16)}`);
  const version = src.u16();
  if (version < OLDEST_CHUNK_VERSION || version > CHUNK_VERSION) {
    throw new Error(`decodeChunk: version ${version} is not one this build reads`);
  }
  src.u16();                                    // flags
  const frameCount = src.u32();
  if (version === CHUNK_VERSION) {
    if (!container) throw new Error('decodeChunk: a container inside a segment');
    return decodeContainer(src, summary, frameCount);
  }
  const tableLength = src.u32();

  const table: string[] = new Array(tableLength);
  for (let i = 0; i < tableLength; i++) table[i] = decodeText(src.raw(src.u32()));
  const str = (index: number): string => {
    const s = table[index];
    if (s === undefined) throw new Error(`decodeChunk: string id ${index} past the table`);
    return s;
  };
  // With a writer, which table entries are dense keys and which column each
  // is: settled once a pack rather than looked up once a field.
  let dense: Int16Array | null = null;
  if (split !== undefined) {
    dense = new Int16Array(tableLength);
    for (let i = 0; i < tableLength; i++) dense[i] = DENSE_INDEX.get(table[i]) ?? -1;
  }

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
    const linkType = version >= 2 ? src.u16() : 0xffff;

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

    // Split as it is read, when the window asks: the dense keys go straight
    // into its FieldBlock and the bag gets only the rest. Building a 25-key
    // bag and then walking it again in `absorb` was 3.7 us a row (#16).
    const fields: Record<string, string | number> = {};
    const entryCount = src.u16();
    let block: FieldBlock | null = null;
    let row = -1;
    if (dense !== null && entryCount !== ABSENT) {
      row = split!.claim();
      block = split!.current;
    }
    for (let k = 0; k < (entryCount === ABSENT ? 0 : entryCount); k++) {
      const keyId = src.u32();
      const value = src.u8() === 0 ? src.f64() : str(src.u32());
      const at = dense === null ? -1 : dense[keyId];
      if (at >= 0) block!.writeAt(row, at, value);
      else fields[str(keyId)] = value;
    }

    // The optional keys are assigned, not spread in: a spread builds and
    // copies a throwaway object for each of twelve keys on every row.
    const p = {
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
    } as Packet;
    if (labelId !== 0xffffffff) p.protocolLabel = str(labelId);
    if (sourcePort !== 0xffffffff) p.sourcePort = sourcePort;
    if (destPort !== 0xffffffff) p.destPort = destPort;
    if (direction !== 0xffffffff) p.direction = direction;
    if (tsPrecision !== 0xffff) p.tsPrecision = tsPrecision;
    if (tsNanos !== undefined) p.tsNanos = tsNanos;
    if (linkType !== 0xffff) p.linkType = linkType;
    if (protocolCount !== ABSENT) p.frameProtocols = protocols;
    if (flagCount !== ABSENT) p.analysisFlags = flags;
    if (expertCount !== ABSENT) p.expert = expert;
    if (resolvedCount !== ABSENT) p.resolved = resolved;
    if (entryCount !== ABSENT) p.fields = fields;
    if (block !== null) { p.cols = block; p.row = row; }
    packets[i] = p;
  }

  if (src.offset !== summary.length) {
    throw new Error(`decodeChunk: ${summary.length - src.offset} bytes after the last frame`);
  }
  return packets;
}

// --- version 3: a container of packs -------------------------------------------
//
//   MAGIC, u16 3, u16 flags, u32 frameCount, u16 segmentCount
//   segmentCount x { u8 kind, u32 length, a complete version-2 summary }
//   u16 lane[frameCount]     the segment that holds chunk row i
//   the overlay section      { u32 count, string table, count x { u16 row, overlay } }
//   the patch section        { u32 count, string table, count x { u16 row, patch } }
//
// Rows inside a segment ascend by id, as do the chunk's rows, so a row's
// position inside its segment is the number of earlier rows that name that
// segment in the lane: nothing stores it. Each section has a string table of
// its own, because the segments' tables are the packs' and are not touched.

const SEGMENT_PACK = 0;
const SEGMENT_RUN = 1;
/**
 * A pack that contributes fewer rows than this to a chunk is not carried as a
 * segment. Its few rows are decoded and join the run, because a segment costs a
 * string table of its own, and for a handful of rows that table is most of it.
 */
const SELECT_MIN_ROWS = 16;

function tableString(table: readonly string[], index: number): string {
  const s = table[index];
  if (s === undefined) throw new Error(`decodeChunk: string id ${index} past the table`);
  return s;
}

function readTable(src: Source): string[] {
  const length = src.u32();
  const table: string[] = new Array(length);
  for (let i = 0; i < length; i++) table[i] = textDecoder.decode(src.raw(src.u32()));
  return table;
}

function writeTable(out: Sink, table: readonly string[]): void {
  out.u32(table.length);
  for (const s of table) {
    const encoded = textEncoder.encode(s);
    out.u32(encoded.length);
    out.raw(encoded);
  }
}

/** First-use string ids, for the side sections; `encodeChunk` keeps its own inline for speed. */
class Interner {
  readonly table: string[] = [];
  private readonly seen = new Map<string, number>();

  id(s: string): number {
    let v = this.seen.get(s);
    if (v === undefined) { v = this.table.length; this.seen.set(s, v); this.table.push(s); }
    return v;
  }
}

function decodeContainer(src: Source, summary: Uint8Array, frameCount: number): Packet[] {
  const segmentCount = src.u16();
  const segments: Packet[][] = new Array(segmentCount);
  for (let s = 0; s < segmentCount; s++) {
    const kind = src.u8();
    if (kind !== SEGMENT_PACK && kind !== SEGMENT_RUN) throw new Error(`decodeChunk: segment kind ${kind}`);
    const length = src.u32();
    // `raw` clips silently at the end of the buffer; a length that lies must not.
    if (src.offset + length > summary.length) throw new Error('decodeChunk: a segment runs past the end of the summary');
    const bytes = src.raw(length);
    if (bytes.length < 6 || bytes[4] !== ROW_LAYOUT_VERSION || bytes[5] !== 0) {
      throw new Error('decodeChunk: a segment is not a version-2 summary');
    }
    segments[s] = decodeSummary(bytes, false);
  }

  // Gather the rows into chunk order. A wrong lane puts a row under another
  // row's ordinal, which shows as a confident wrong Info line, so everything
  // that could be inconsistent is checked here rather than trusted.
  const next = new Array<number>(segmentCount).fill(0);
  const packets: Packet[] = new Array(frameCount);
  let previousId = -1;
  for (let i = 0; i < frameCount; i++) {
    const lane = src.u16();
    if (lane >= segmentCount) throw new Error(`decodeChunk: row ${i} names segment ${lane} of ${segmentCount}`);
    const row = segments[lane][next[lane]++];
    if (row === undefined) throw new Error(`decodeChunk: segment ${lane} has fewer rows than the lane asks of it`);
    if (row.id <= previousId) throw new Error(`decodeChunk: id ${row.id} after ${previousId}`);
    previousId = row.id;
    packets[i] = row;
  }
  for (let s = 0; s < segmentCount; s++) {
    if (next[s] !== segments[s].length) throw new Error(`decodeChunk: segment ${s} has rows the lane does not place`);
  }

  // Overlays, then patches: the order the merge and the writer wrote them in.
  const overlayCount = src.u32();
  const overlayStrings = readTable(src);
  for (let k = 0; k < overlayCount; k++) {
    const row = src.u16();
    if (row >= frameCount) throw new Error(`decodeChunk: an overlay for row ${row} of ${frameCount}`);
    const overlay = readOverlay(src, overlayStrings);
    const packet = packets[row];
    applyOverlay(packet, overlay);
    // `applyOverlay` assigns undefined for a member that clears its key; a
    // flat chunk stores that as no key at all, and the two must read alike.
    if ('expert' in overlay && packet.expert === undefined) delete packet.expert;
    if ('tsPrecision' in overlay && packet.tsPrecision === undefined) delete packet.tsPrecision;
    if ('tsNanos' in overlay && packet.tsNanos === undefined) delete packet.tsNanos;
  }

  const patchCount = src.u32();
  const patchStrings = readTable(src);
  for (let k = 0; k < patchCount; k++) {
    const row = src.u16();
    if (row >= frameCount) throw new Error(`decodeChunk: a patch for row ${row} of ${frameCount}`);
    // Every row here was decoded just now and is nobody else's, so the patch
    // may write into its field bag instead of copying it.
    applyInfoPatch(packets[row], readPatch(src, patchStrings), true);
  }

  if (src.offset !== summary.length) {
    throw new Error(`decodeChunk: ${summary.length - src.offset} bytes after the last section`);
  }
  return packets;
}

const OV_FIELDS = 1, OV_EXPERT = 2, OV_PRECISION = 4, OV_NANOS = 8;

function writeOverlays(out: Sink, entries: readonly (readonly [number, RowOverlay])[]): void {
  const strings = new Interner();
  const body = new Sink(1024);
  for (const [row, overlay] of entries) {
    body.u16(row);
    // Presence, not value: a member that is present and undefined clears the key.
    let flags = 0;
    if (overlay.fields !== undefined) flags |= OV_FIELDS;
    if ('expert' in overlay) flags |= OV_EXPERT;
    if ('tsPrecision' in overlay) flags |= OV_PRECISION;
    if ('tsNanos' in overlay) flags |= OV_NANOS;
    body.u8(flags);
    if (overlay.fields !== undefined) {
      const keys = Object.keys(overlay.fields);
      body.u16(keys.length);
      for (const key of keys) {
        body.u32(strings.id(key));
        const value = overlay.fields[key];
        if (typeof value === 'number') { body.u8(0); body.f64(value); }
        else { body.u8(1); body.u32(strings.id(value)); }
      }
    }
    if (flags & OV_EXPERT) {
      const expert = overlay.expert;
      body.u16(expert === undefined ? ABSENT : expert.length);
      for (const finding of expert ?? []) {
        body.u32(strings.id(finding.message));
        body.u32(finding.category === undefined ? 0xffffffff : strings.id(finding.category));
      }
    }
    if (flags & OV_PRECISION) body.u16(overlay.tsPrecision === undefined ? 0xffff : overlay.tsPrecision);
    if (flags & OV_NANOS) writeNanos(body, overlay.tsNanos);
  }
  out.u32(entries.length);
  writeTable(out, strings.table);
  out.raw(body.bytes());
}

function readOverlay(src: Source, table: readonly string[]): RowOverlay {
  const flags = src.u8();
  const overlay: RowOverlay = {};
  if (flags & OV_FIELDS) {
    const fields: Record<string, string | number> = {};
    const count = src.u16();
    for (let k = 0; k < count; k++) {
      const key = tableString(table, src.u32());
      fields[key] = src.u8() === 0 ? src.f64() : tableString(table, src.u32());
    }
    overlay.fields = fields;
  }
  if (flags & OV_EXPERT) {
    const count = src.u16();
    if (count === ABSENT) {
      overlay.expert = undefined;
    } else {
      const expert: ExpertInfo[] = new Array(count);
      for (let k = 0; k < count; k++) {
        const message = tableString(table, src.u32());
        const categoryId = src.u32();
        expert[k] = categoryId === 0xffffffff
          ? { message }
          : { message, category: tableString(table, categoryId) as ExpertCategory };
      }
      overlay.expert = expert;
    }
  }
  if (flags & OV_PRECISION) {
    const v = src.u16();
    overlay.tsPrecision = v === 0xffff ? undefined : v;
  }
  if (flags & OV_NANOS) overlay.tsNanos = readNanos(src);
  return overlay;
}

const PT_SUFFIX = 1, PT_LABEL = 2, PT_RESPONSE = 4, PT_LINKS = 8;

function writePatches(out: Sink, entries: readonly (readonly [number, InfoPatch])[]): void {
  const strings = new Interner();
  const body = new Sink(1024);
  for (const [row, patch] of entries) {
    body.u16(row);
    body.u32(patch.frameId >>> 0);
    let flags = 0;
    if (patch.suffix !== undefined) flags |= PT_SUFFIX;
    if (patch.protocolLabel !== undefined) flags |= PT_LABEL;
    if (patch.responseInFrame !== undefined) flags |= PT_RESPONSE;
    if (patch.links !== undefined) flags |= PT_LINKS;
    body.u8(flags);
    if (patch.suffix !== undefined) body.u32(strings.id(patch.suffix));
    if (patch.protocolLabel !== undefined) body.u32(strings.id(patch.protocolLabel));
    if (patch.responseInFrame !== undefined) body.f64(patch.responseInFrame);
    if (patch.links !== undefined) {
      const keys = Object.keys(patch.links);
      body.u16(keys.length);
      for (const key of keys) { body.u32(strings.id(key)); body.f64(patch.links[key]); }
    }
  }
  out.u32(entries.length);
  writeTable(out, strings.table);
  out.raw(body.bytes());
}

function readPatch(src: Source, table: readonly string[]): InfoPatch {
  const frameId = src.u32();
  const flags = src.u8();
  const patch: InfoPatch = { frameId };
  if (flags & PT_SUFFIX) patch.suffix = tableString(table, src.u32());
  if (flags & PT_LABEL) patch.protocolLabel = tableString(table, src.u32());
  if (flags & PT_RESPONSE) patch.responseInFrame = src.f64();
  if (flags & PT_LINKS) {
    const links: Record<string, number> = {};
    const count = src.u16();
    for (let k = 0; k < count; k++) {
      const key = tableString(table, src.u32());
      links[key] = src.f64();
    }
    patch.links = links;
  }
  return patch;
}

/** A row held in a shard's pack, as the writer stages it. */
export interface PackedChunkSlot {
  pack: RowPack;
  /** The row's position in the pack. */
  index: number;
  /** What the merge wrote to the row after the shard packed it. */
  overlay: RowOverlay | null;
  /**
   * The row's frame id. Carried beside the pack rather than read out of it: the
   * directory lanes are built from the writer's own ids and its own captured
   * lengths, and copying them from a pack would let a pack's idea of either
   * into the capture's.
   */
  id: number;
}

/** One frame of a chunk: a row the writer holds, or one it holds still packed. */
export type ChunkSlot = Packet | PackedChunkSlot;

/**
 * The capture time of a packed row, from its pack's prefix record: what the
 * writer ages a frame by when the frame's bytes arrive with its row. The merge's
 * overlay never writes the timestamp, so the record is the whole answer.
 */
export function packedSlotTsUs(slot: PackedChunkSlot): number {
  const from = slot.index * PREFIX_BYTES;
  const prefix = slot.pack.prefix;
  if (!Number.isInteger(slot.index) || slot.index < 0 || from + PREFIX_BYTES > prefix.length) {
    throw new Error(`packedSlotTsUs: pack ${slot.pack.key} has no prefix record for row ${slot.index}`);
  }
  return new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getFloat64(from + OFF_TS_US, true);
}

interface PackGroup {
  pack: RowPack;
  /** The pack rows this chunk holds, ascending. */
  indices: number[];
  /** The segment carrying them, or -1 when they were demoted into the run. */
  segment: number;
  demoted: Packet[] | null;
  nextDemoted: number;
}

/**
 * Encodes a chunk that holds packed rows as a version-3 container.
 *
 * `slots` are in ascending id order. `patches[i]` are the info patches that
 * reached slot `i`, in arrival order, whatever kind of slot it is: they ride
 * in the patch section and are applied by the decoder after the overlays.
 * The returned prefix block is the one `encodeChunk` would have written for the
 * same rows with overlays and patches already applied - byte for byte, which
 * `scripts/capture/chunk-codec.ts` holds it to.
 */
export function encodePackedChunk(
  slots: readonly ChunkSlot[],
  capLengths: readonly number[],
  patches: readonly (readonly InfoPatch[] | null)[],
): EncodedChunk {
  const count = slots.length;
  if (count === 0) throw new Error('encodePackedChunk: empty chunk');
  if (count > CHUNK_FRAMES) {
    throw new Error(`encodePackedChunk: ${count} frames exceeds CHUNK_FRAMES (${CHUNK_FRAMES})`);
  }
  if (capLengths.length !== count) throw new Error(`encodePackedChunk: ${capLengths.length} lengths for ${count} frames`);
  if (patches.length !== count) throw new Error(`encodePackedChunk: ${patches.length} patch lists for ${count} frames`);

  const prefix = new Uint8Array(prefixBlockBytes(count));
  const prefixView = new DataView(prefix.buffer);
  const directoryAt = count * PREFIX_BYTES;

  const groups = new Map<number, PackGroup>();
  const groupOf: (PackGroup | null)[] = new Array(count);
  const overlays: [number, RowOverlay][] = [];
  const patchEntries: [number, InfoPatch][] = [];

  let previousId = -1;
  for (let i = 0; i < count; i++) {
    const slot = slots[i];
    const at = i * PREFIX_BYTES;
    if (slot.id <= previousId) throw new Error(`encodePackedChunk: id ${slot.id} after ${previousId}`);
    prefixView.setUint32(directoryAt + i * 4, (i === 0 ? slot.id : slot.id - previousId) >>> 0, true);
    prefixView.setUint32(directoryAt + count * 4 + i * 4, capLengths[i] >>> 0, true);
    previousId = slot.id;

    if ('pack' in slot) {
      let group = groups.get(slot.pack.key);
      if (group === undefined) {
        group = { pack: slot.pack, indices: [], segment: -1, demoted: null, nextDemoted: 0 };
        groups.set(slot.pack.key, group);
      } else if (group.pack !== slot.pack) {
        throw new Error(`encodePackedChunk: two different packs under key ${slot.pack.key}`);
      }
      const last = group.indices.length === 0 ? -1 : group.indices[group.indices.length - 1];
      if (!Number.isInteger(slot.index) || slot.index <= last || slot.index >= slot.pack.count) {
        throw new Error(`encodePackedChunk: row ${slot.index} of pack ${slot.pack.key} (${slot.pack.count} rows) after ${last}`);
      }
      group.indices.push(slot.index);
      groupOf[i] = group;

      // The pack's record is already what `encodeChunk` would write for the
      // row, except where the overlay changed something the record encodes.
      // That is the nanosecond remainder and nothing else: the record holds no
      // `tsPrecision`, no `expert`, no field, and the merge never touches the
      // timestamp, length, status or stream. A patch writes Info, the label and
      // fields, none of which are in it either.
      const from = slot.index * PREFIX_BYTES;
      if (from + PREFIX_BYTES > slot.pack.prefix.length) {
        throw new Error(`encodePackedChunk: pack ${slot.pack.key} has no prefix record for row ${slot.index}`);
      }
      prefix.set(slot.pack.prefix.subarray(from, from + PREFIX_BYTES), at);
      if (slot.overlay !== null) {
        overlays.push([i, slot.overlay]);
        if ('tsNanos' in slot.overlay) {
          prefixView.setUint16(at + OFF_NANOS_REM, nanosRemainderOf(slot.overlay.tsNanos), true);
        }
      }
    } else {
      groupOf[i] = null;
      writePrefixRecord(prefix, prefixView, at, slot);
    }

    for (const patch of patches[i] ?? []) patchEntries.push([i, patch]);
  }

  // Which packs travel as segments, and which are too thin to.
  const segments: { kind: number; bytes: Uint8Array }[] = [];
  for (const group of groups.values()) {
    if (group.indices.length === group.pack.count) {
      const bytes = group.pack.summary;
      if (bytes.length < 6 || bytes[4] !== ROW_LAYOUT_VERSION || bytes[5] !== 0) {
        throw new Error(`encodePackedChunk: pack ${group.pack.key} is not a version-2 summary`);
      }
      group.segment = segments.length;
      segments.push({ kind: SEGMENT_PACK, bytes });
    } else if (group.indices.length >= SELECT_MIN_ROWS) {
      group.segment = segments.length;
      segments.push({ kind: SEGMENT_PACK, bytes: selectRows(group.pack.summary, group.indices) });
    } else {
      group.demoted = decodeSummary(selectRows(group.pack.summary, group.indices), false);
    }
  }

  // The run: objects, placeholders and demoted rows, in id order.
  const runIndex = segments.length;
  const lane = new Uint16Array(count);
  const run: Packet[] = [];
  const runLengths: number[] = [];
  for (let i = 0; i < count; i++) {
    const slot = slots[i];
    const group = groupOf[i];
    if (group === null && !('pack' in slot)) {
      run.push(slot);
    } else if (group !== null && group.demoted !== null) {
      run.push(group.demoted[group.nextDemoted++]);
    } else if (group !== null) {
      lane[i] = group.segment;
      continue;
    } else {
      throw new Error('encodePackedChunk: a slot with no segment');
    }
    lane[i] = runIndex;
    runLengths.push(capLengths[i]);
  }
  if (run.length > 0) segments.push({ kind: SEGMENT_RUN, bytes: encodeChunk(run, runLengths).summary });

  let size = 4096 + count * 2;
  for (const s of segments) size += 5 + s.bytes.length;
  const out = new Sink(size);
  out.u32(CHUNK_MAGIC);
  out.u16(CHUNK_VERSION);
  out.u16(0);                                  // flags, reserved
  out.u32(count);
  out.u16(segments.length);
  for (const s of segments) {
    out.u8(s.kind);
    out.u32(s.bytes.length);
    out.raw(s.bytes);
  }
  for (let i = 0; i < count; i++) out.u16(lane[i]);
  writeOverlays(out, overlays);
  writePatches(out, patchEntries);

  return {
    prefix,
    summary: out.bytes(),
    frameCount: count,
    firstId: slots[0].id,
    lastId: slots[count - 1].id,
    firstTsUs: prefixView.getFloat64(OFF_TS_US, true),
    lastTsUs: prefixView.getFloat64((count - 1) * PREFIX_BYTES + OFF_TS_US, true),
  };
}

/** Moves string ids from one table to a smaller one, copying each entry as the bytes it is. */
class IdRemap {
  private readonly to: Int32Array;
  readonly kept: Uint8Array[] = [];

  constructor(private readonly entries: readonly Uint8Array[]) {
    this.to = new Int32Array(entries.length).fill(-1);
  }

  map(old: number): number {
    if (old >= this.entries.length) throw new Error(`selectRows: string id ${old} past the table`);
    let n = this.to[old];
    if (n < 0) { n = this.kept.length; this.to[old] = n; this.kept.push(this.entries[old]); }
    return n;
  }
}

/** Reads `n` bytes and, if `dst` is given, writes them. */
function copyBytes(src: Source, dst: Sink | null, n: number): void {
  const bytes = src.raw(n);
  if (bytes.length !== n) throw new Error('selectRows: the summary ends inside a row');
  if (dst !== null) dst.raw(bytes);
}

/** Reads a string id and, if `dst` is given, writes it under its new number. */
function copyId(src: Source, dst: Sink | null, ids: IdRemap): void {
  const old = src.u32();
  if (dst !== null) dst.u32(ids.map(old));
}

/** As `copyId`, for an id that may be the 0xffffffff "none". */
function copyOptionalId(src: Source, dst: Sink | null, ids: IdRemap): void {
  const old = src.u32();
  if (dst !== null) dst.u32(old === 0xffffffff ? old : ids.map(old));
}

/**
 * Walks one version-2 row, writing it to `dst` with its string ids remapped, or
 * only reading it when `dst` is null. The shape is `encodeChunk`'s, in the
 * order it writes it; a change to that layout is a change here.
 */
function copyRow(src: Source, dst: Sink | null, ids: IdRemap): void {
  copyBytes(src, dst, 4);                        // id
  copyId(src, dst, ids);                         // source
  copyId(src, dst, ids);                         // destination
  copyId(src, dst, ids);                         // protocol
  copyOptionalId(src, dst, ids);                 // protocol label
  copyId(src, dst, ids);                         // info
  copyId(src, dst, ids);                         // interface
  copyBytes(src, dst, 16);                       // relativeTime, timeDelta
  copyBytes(src, dst, 12);                       // ports, direction
  copyBytes(src, dst, 2);                        // tsPrecision
  const hasNanos = src.u8();
  if (dst !== null) dst.u8(hasNanos);
  if (hasNanos !== 0) copyBytes(src, dst, 8);
  copyBytes(src, dst, 2);                        // linkType

  for (let list = 0; list < 2; list++) {         // frameProtocols, analysisFlags
    const n = src.u16();
    if (dst !== null) dst.u16(n);
    for (let k = 0, m = n === ABSENT ? 0 : n; k < m; k++) copyId(src, dst, ids);
  }

  const expertCount = src.u16();
  if (dst !== null) dst.u16(expertCount);
  for (let k = 0, m = expertCount === ABSENT ? 0 : expertCount; k < m; k++) {
    copyId(src, dst, ids);                       // message
    copyOptionalId(src, dst, ids);               // category
  }

  const resolvedCount = src.u16();
  if (dst !== null) dst.u16(resolvedCount);
  for (let k = 0, m = resolvedCount === ABSENT ? 0 : resolvedCount; k < m; k++) {
    copyId(src, dst, ids);                       // name
    const addresses = src.u16();
    if (dst !== null) dst.u16(addresses);
    for (let a = 0; a < addresses; a++) copyId(src, dst, ids);
  }

  const entryCount = src.u16();
  if (dst !== null) dst.u16(entryCount);
  for (let k = 0, m = entryCount === ABSENT ? 0 : entryCount; k < m; k++) {
    copyId(src, dst, ids);                       // key
    const kind = src.u8();
    if (dst !== null) dst.u8(kind);
    if (kind === 0) copyBytes(src, dst, 8); else copyId(src, dst, ids);
  }
}

/**
 * A version-2 summary of just the rows at `indices` (ascending, in range).
 *
 * The rows are copied as bytes: no string is decoded and no row is built. Only
 * the string ids change, renumbered in first-use order into a table of just the
 * strings those rows use, so what comes out is the summary `encodeChunk` would
 * write for the same rows.
 */
export function selectRows(summary: Uint8Array, indices: readonly number[]): Uint8Array {
  if (indices.length === 0) throw new Error('selectRows: no rows');
  const src = new Source(summary);
  const magic = src.u32();
  if (magic !== CHUNK_MAGIC) throw new Error(`selectRows: bad magic 0x${magic.toString(16)}`);
  const version = src.u16();
  if (version !== ROW_LAYOUT_VERSION) throw new Error(`selectRows: version ${version} is not a flat version-2 summary`);
  src.u16();                                    // flags
  const frameCount = src.u32();
  let previous = -1;
  for (const index of indices) {
    if (!Number.isInteger(index) || index <= previous || index >= frameCount) {
      throw new Error(`selectRows: row ${index} of ${frameCount} after ${previous}`);
    }
    previous = index;
  }

  const tableLength = src.u32();
  const entries: Uint8Array[] = new Array(tableLength);
  for (let i = 0; i < tableLength; i++) {
    const length = src.u32();
    const bytes = src.raw(length);
    if (bytes.length !== length) throw new Error('selectRows: the string table is cut short');
    entries[i] = bytes;
  }

  const ids = new IdRemap(entries);
  const body = new Sink(indices.length * 256);
  let want = 0;
  for (let row = 0; want < indices.length; row++) {
    const keep = row === indices[want];
    copyRow(src, keep ? body : null, ids);
    if (keep) want++;
  }

  const rows = body.bytes();
  const out = new Sink(rows.length + 4096);
  out.u32(CHUNK_MAGIC);
  out.u16(ROW_LAYOUT_VERSION);
  out.u16(0);                                   // flags, reserved
  out.u32(indices.length);
  out.u32(ids.kept.length);
  for (const entry of ids.kept) { out.u32(entry.length); out.raw(entry); }
  out.raw(rows);
  return out.bytes();
}

const EMPTY_BYTES = new Uint8Array(0);

/**
 * Whether a summary's rows carry their own `linkType` - version 2 onward.
 *
 * Asked by the reader so a consumer can tell "Ethernet" from "not recorded":
 * on a version-1 row an absent link type is the second, and the only way to
 * recover it is the session's adapter table.
 */
export function chunkStoresLinkType(summary: Uint8Array): boolean {
  if (summary.byteLength < 6) return false;
  return new DataView(summary.buffer, summary.byteOffset, summary.byteLength).getUint16(4, true) >= 2;
}

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
 *
 * A block that carries the byte directory has the writer's own ids, so the
 * join checks each row against it and throws on the first that disagrees: a
 * version 3 lane that ascends but picked the wrong rows would otherwise put a
 * confident wrong Info line under another frame's ordinal.
 */
export function applyPrefixes(packets: Packet[], prefix: Uint8Array): void {
  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
  const directoryAt = prefix.byteLength === prefixBlockBytes(packets.length) ? packets.length * PREFIX_BYTES : -1;
  let id = 0;
  for (let i = 0; i < packets.length; i++) {
    const at = i * PREFIX_BYTES;
    const p = packets[i];
    if (directoryAt >= 0) {
      const gap = view.getUint32(directoryAt + i * 4, true);
      id = i === 0 ? gap : id + gap;
      if (p.id !== id) throw new Error(`applyPrefixes: row ${i} is frame ${p.id}, the directory says ${id}`);
    }
    p.tsUs = view.getFloat64(at + OFF_TS_US, true);
    p.length = view.getUint32(at + OFF_LENGTH, true);
    p.status = STATUS_ORDER[prefix[at + OFF_STATUS]] ?? 'ok';
    const stream = view.getUint32(at + OFF_STREAM_ID, true);
    if (stream !== 0xffffffff) p.streamId = stream;
  }
}

/**
 * A read-only view over one chunk's prefix records, for the scan path.
 *
 * `frameCount` is passed rather than divided out of the block's length,
 * because the block does not end where the records do - the byte directory
 * follows them. The count is in the index record every reader already holds,
 * so asking for it costs nothing and guessing it would be wrong by
 * `DIRECTORY_BYTES / PREFIX_BYTES` of a chunk.
 */
export class PrefixBlock {
  private readonly view: DataView;

  constructor(private readonly buf: Uint8Array, readonly frameCount: number) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
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

/**
 * The byte directory of one chunk: which frame is where in the `byt` stream.
 *
 * Constructed over the same inflated prefix block a filter scan reads, so a
 * reader that already has the block for one purpose pays nothing for the
 * other.
 *
 * Frame offsets are a prefix sum rather than a stored lane. The writer appends
 * every frame's bytes in order and contiguously - that is the property that
 * lets bytes go to disk immediately while their rows wait behind the patch
 * horizon - so a chunk's byte extent is exactly the sum of its captured
 * lengths, and storing the offsets as well would be four more bytes a frame
 * saying something already known.
 */
export class ChunkDirectory {
  /** Ids, summed back out of the gap lane. */
  private readonly ids: Uint32Array;
  private readonly lens: Uint32Array;
  /** Offset of each frame's bytes from the start of the chunk's byte extent. */
  private readonly offsets: Uint32Array;
  /** The chunk's whole byte extent, which the index record must agree with. */
  readonly totalBytes: number;

  /**
   * Both lanes are expanded into typed arrays here rather than read from the
   * block on demand: the gaps have to be summed to be searchable at all, and
   * the offsets are a running sum whichever way round it is done. 48 kB a
   * chunk, in the storage Worker, for the last `DIRECTORY_CACHE` chunks.
   */
  constructor(block: Uint8Array, readonly frameCount: number) {
    const at = block.byteOffset + frameCount * PREFIX_BYTES;
    const gaps = new DataView(block.buffer, at, frameCount * 4);
    const lens = new DataView(block.buffer, at + frameCount * 4, frameCount * 4);
    this.ids = new Uint32Array(frameCount);
    this.lens = new Uint32Array(frameCount);
    this.offsets = new Uint32Array(frameCount);
    let id = 0;
    let running = 0;
    for (let i = 0; i < frameCount; i++) {
      id = i === 0 ? gaps.getUint32(0, true) : id + gaps.getUint32(i * 4, true);
      this.ids[i] = id;
      const length = lens.getUint32(i * 4, true);
      this.lens[i] = length;
      this.offsets[i] = running;
      running += length;
    }
    this.totalBytes = running;
  }

  id(i: number): number { return this.ids[i]; }
  capLength(i: number): number { return this.lens[i]; }
  /** Where frame `i`'s bytes start, relative to the chunk's `bytOffset`. */
  offset(i: number): number { return this.offsets[i]; }

  /**
   * The position of a frame id inside this chunk, or -1.
   *
   * A search, never `id - firstId`: a frame that failed to dissect burns an id,
   * so the lane ascends without being contiguous. -1 for an id in one of those
   * holes, because "that frame does not exist" and "here is its neighbour" are
   * different answers and only one of them is true.
   */
  indexOfId(id: number): number {
    let lo = 0, hi = this.frameCount - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const at = this.ids[mid];
      if (id < at) hi = mid - 1;
      else if (id > at) lo = mid + 1;
      else return mid;
    }
    return -1;
  }
}

/** Exposed so tests and the reader can agree on what the accelerator holds. */
export const ADDRESS_KIND = {
  NONE: ADDR_NONE, IPV4: ADDR_IPV4, IPV6: ADDR_IPV6, MAC: ADDR_MAC, TEXT: ADDR_TEXT,
} as const;
