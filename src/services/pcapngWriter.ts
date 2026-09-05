/**
 * The pcapng writer.
 *
 * The reader has existed since the beginning; the writer has not, so a capture
 * this app took could only leave it as classic libpcap - a format that cannot
 * express several things the app already knows:
 *
 *   * **which adapter a frame came from.** A classic pcap file has one link
 *     type and no interface field, so a multi-adapter capture came out as one
 *     undifferentiated stream and `Packet.interfaceName` was simply lost.
 *   * **timestamps finer than a microsecond.** The classic header has one
 *     32-bit sub-second field whose unit is fixed by the file's magic number.
 *     pcapng's `if_tsresol` is per interface, so a nanosecond capture survives
 *     a round trip.
 *   * **the names the capture taught us** (a Name Resolution Block), and
 *     **what the capture missed** (an Interface Statistics Block). Both are
 *     things this app computes and then, on export, threw away - the drop
 *     counts especially, since a file that does not say it is incomplete reads
 *     as complete.
 *
 * Block layout is uniform: type (u32), total length (u32), body, total length
 * again (u32). The trailing copy is what lets a reader walk the file
 * backwards, and it is the field most often got wrong - it counts itself, the
 * leading length and the type, and every block is padded to a multiple of four.
 */
import type { Packet } from '../types/packet';
import { LINKTYPE } from './dissect/types';

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_NRB = 0x00000004;
const BLOCK_ISB = 0x00000005;
const BLOCK_EPB = 0x00000006;
const BLOCK_DSB = 0x0000000a;

/**
 * The one secrets type anything reads: "TLSK" as four ASCII bytes, meaning an
 * NSS key log in the file. The registry has others (WireGuard, ZigBee), none
 * of which this build produces or consumes.
 */
export const DSB_SECRETS_TYPE_TLS_KEY_LOG = 0x544c534b;

const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

/** Options are `code (u16) | length (u16) | value | padding`, ending in opt_endofopt. */
const OPT_ENDOFOPT = 0;
const OPT_COMMENT = 1;
const SHB_HARDWARE = 2;
const SHB_OS = 3;
const SHB_USERAPPL = 4;
const IF_NAME = 2;
const IF_DESCRIPTION = 3;
const IF_TSRESOL = 9;
const ISB_STARTTIME = 2;
const ISB_ENDTIME = 3;
const ISB_IFRECV = 4;
const ISB_IFDROP = 5;

/** NRB record types: an IPv4 or IPv6 address followed by NUL-separated names. */
const NRES_ENDOFRECORD = 0;
const NRES_IP4RECORD = 1;
const NRES_IP6RECORD = 2;

export interface PcapngInterface {
  /** The adapter's label, as `Packet.interfaceName` carries it. */
  name: string;
  description?: string;
  linkType?: number;
  /** Decimal places the timestamps are meaningful to; 6 (us) or 9 (ns). */
  tsPrecision?: number;
  /** From the agent's capture_stats, when this capture had any. */
  received?: number;
  dropped?: number;
}

export interface PcapngOptions {
  /** One IDB per entry, in order; a frame's interface id indexes into it. */
  interfaces?: PcapngInterface[];
  /** Address to names, for the Name Resolution Block. */
  names?: { address: string; names: string[] }[];
  /** Free text at the top of the file. */
  comment?: string;
  /** Written into the SHB so a reader knows what produced the file. */
  application?: string;
  /**
   * An NSS key log, written as a Decryption Secrets Block.
   *
   * The file then opens itself: whoever receives it sees the decrypted HTTP
   * without being sent a second file and without setting anything up. That is
   * also exactly why it is off by default and asked for explicitly - a capture
   * with its secrets attached is a capture with no confidentiality at all, and
   * the difference is invisible from the outside.
   */
  secrets?: string;
}

// --- little writer ----------------------------------------------------------

class Writer {
  private chunks: Uint8Array[] = [];
  private size = 0;

  bytes(b: Uint8Array): void {
    this.chunks.push(b);
    this.size += b.length;
  }

  u8(v: number): void { const b = new Uint8Array(1); b[0] = v & 0xff; this.bytes(b); }

  u16(v: number): void {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    this.bytes(b);
  }

  u32(v: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this.bytes(b);
  }

  u64(v: bigint): void {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v, true);
    this.bytes(b);
  }

  /** Everything in pcapng is padded to a four-byte boundary. */
  pad(): void {
    const over = this.size % 4;
    if (over !== 0) this.bytes(new Uint8Array(4 - over));
  }

  get length(): number { return this.size; }

  concat(): Uint8Array {
    const out = new Uint8Array(this.size);
    let at = 0;
    for (const c of this.chunks) { out.set(c, at); at += c.length; }
    return out;
  }
}

const utf8 = (text: string) => new TextEncoder().encode(text);

function option(w: Writer, code: number, value: Uint8Array): void {
  w.u16(code);
  w.u16(value.length);
  w.bytes(value);
  w.pad();
}

function stringOption(w: Writer, code: number, value: string): void {
  option(w, code, utf8(value));
}

/**
 * Frames a body as a block.
 *
 * The trailing length is what lets a reader walk the file backwards, and it is
 * the field most often got wrong: it counts the type, both lengths and the
 * padded body, so it cannot be computed until the body is finished.
 */
function block(type: number, body: Uint8Array): Uint8Array {
  const padded = body.length % 4 === 0 ? body : (() => {
    const out = new Uint8Array(body.length + (4 - (body.length % 4)));
    out.set(body);
    return out;
  })();
  const total = 12 + padded.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, total, true);
  out.set(padded, 8);
  view.setUint32(total - 4, total, true);
  return out;
}

// --- blocks -------------------------------------------------------------------

function sectionHeader(options: PcapngOptions): Uint8Array {
  const w = new Writer();
  w.u32(BYTE_ORDER_MAGIC);
  w.u16(1);            // major
  w.u16(0);            // minor
  // Section length: -1, "not known". Backfilling it would mean holding the
  // whole file to rewrite eight bytes, and every reader accepts the unknown
  // form because a live capture cannot know it either.
  w.u64(0xffffffffffffffffn);
  if (options.comment) stringOption(w, OPT_COMMENT, options.comment);
  stringOption(w, SHB_HARDWARE, 'Inwire');
  if (typeof navigator !== 'undefined' && navigator.userAgent) {
    stringOption(w, SHB_OS, navigator.userAgent);
  }
  stringOption(w, SHB_USERAPPL, options.application ?? 'Inwire');
  w.u16(OPT_ENDOFOPT); w.u16(0);
  return block(BLOCK_SHB, w.concat());
}

function interfaceDescription(iface: PcapngInterface): Uint8Array {
  const w = new Writer();
  w.u16(iface.linkType ?? LINKTYPE.ETHERNET);
  w.u16(0);            // reserved
  w.u32(0);            // snaplen: 0 = no limit, which is what this app captures
  stringOption(w, IF_NAME, iface.name);
  if (iface.description) stringOption(w, IF_DESCRIPTION, iface.description);
  // if_tsresol is one byte: a power of ten unless the high bit says power of
  // two. Writing it is what makes a nanosecond capture survive the round trip
  // that classic pcap could only express through its magic number.
  const resol = new Uint8Array(1);
  resol[0] = iface.tsPrecision ?? 6;
  option(w, IF_TSRESOL, resol);
  w.u16(OPT_ENDOFOPT); w.u16(0);
  return block(BLOCK_IDB, w.concat());
}

function enhancedPacket(packet: Packet, interfaceId: number, unitsPerSecond: bigint): Uint8Array {
  const w = new Writer();
  // The timestamp is one 64-bit count of if_tsresol units, split across two
  // 32-bit fields high-first. Assembling it in bigint is not fussiness: a
  // nanosecond count is ~1.8e18, well past the exact range of a double, and
  // doing this in floats quantises every timestamp in the file.
  const ticks = packet.tsNanos !== undefined && unitsPerSecond === 1_000_000_000n
    ? packet.tsNanos
    : BigInt(Math.round(packet.tsUs)) * unitsPerSecond / 1_000_000n;
  w.u32(interfaceId);
  w.u32(Number(ticks >> 32n));
  w.u32(Number(ticks & 0xffffffffn));
  w.u32(packet.rawBytes.length);
  // The wire length, which a snaplen may have truncated. Never less than what
  // was captured: a file claiming to hold more bytes than the frame had is
  // the one shape a reader cannot recover from.
  w.u32(Math.max(packet.length, packet.rawBytes.length));
  w.bytes(packet.rawBytes);
  w.pad();
  // Which program sent it, as an ordinary comment.
  //
  // A comment rather than a custom option, because the point is that somebody
  // ELSE can read it: `opt_comment` is the one per-packet option every pcapng
  // reader already shows, and Wireshark puts it in the frame tree without
  // being told anything. A private option would be a fact only this app could
  // recover, which for the one fact the file could not otherwise contain is
  // exactly backwards.
  //
  // Nothing is written when the frame was not attributed - an absent comment
  // says "not known", and an empty one would say "known to be nothing".
  const processName = packet.fields?.['inwire.process.name'];
  const processPid = packet.fields?.['inwire.process.pid'];
  if (typeof processName === 'string' && typeof processPid === 'number') {
    const path = packet.fields?.['inwire.process.path'];
    stringOption(w, OPT_COMMENT, `Process: ${processName} (pid ${processPid})`
      + (typeof path === 'string' && path ? ` - ${path}` : ''));
  }
  w.u16(OPT_ENDOFOPT); w.u16(0);
  return block(BLOCK_EPB, w.concat());
}

/**
 * Decryption Secrets Block: the type, the length, then the secrets themselves,
 * padded to a four-byte boundary like every other variable-length field in the
 * format. The length field counts the real bytes, not the padding, so a reader
 * that trusts it does not hand three NUL bytes to its key log parser.
 */
function decryptionSecrets(secrets: string): Uint8Array | null {
  const payload = utf8(secrets);
  if (payload.length === 0) return null;

  const w = new Writer();
  w.u32(DSB_SECRETS_TYPE_TLS_KEY_LOG);
  w.u32(payload.length);
  w.bytes(payload);
  w.pad();
  w.u16(OPT_ENDOFOPT);
  w.u16(0);
  return block(BLOCK_DSB, w.concat());
}

function parseIpv4(address: string): Uint8Array | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIpv6(address: string): Uint8Array | null {
  if (!address.includes(':')) return null;
  const [head, tail] = address.split('::');
  const headGroups = head === '' ? [] : head.split(':').filter((g) => g !== '');
  const tailGroups = tail === undefined ? [] : tail === '' ? [] : tail.split(':').filter((g) => g !== '');
  if (tail === undefined && headGroups.length !== 8) return null;
  if (headGroups.length + tailGroups.length > 8) return null;

  const out = new Uint8Array(16);
  const write = (groups: string[], at: number) => {
    for (let i = 0; i < groups.length; i++) {
      const v = parseInt(groups[i], 16);
      if (!Number.isInteger(v) || v < 0 || v > 0xffff) return false;
      out[at + i * 2] = v >> 8;
      out[at + i * 2 + 1] = v & 0xff;
    }
    return true;
  };
  if (!write(headGroups, 0)) return null;
  if (!write(tailGroups, 16 - tailGroups.length * 2)) return null;
  return out;
}

/**
 * The names the capture taught us, as a Name Resolution Block.
 *
 * Worth writing because the map is passive: every one of these came out of a
 * DNS answer, a TLS server name or a DHCP lease *in this capture*, so the file
 * carries its own resolution and a reader opening it later gets the same names
 * without a single lookup - which is the whole property that makes passive
 * resolution worth having.
 */
function nameResolution(entries: { address: string; names: string[] }[]): Uint8Array | null {
  const w = new Writer();
  let written = 0;
  for (const entry of entries) {
    const names = entry.names.filter((n) => n.length > 0);
    if (names.length === 0) continue;
    const v4 = parseIpv4(entry.address);
    const v6 = v4 ? null : parseIpv6(entry.address);
    const address = v4 ?? v6;
    if (!address) continue;
    // The record's value is the address followed by NUL-terminated names.
    const encoded = names.map(utf8);
    const length = address.length + encoded.reduce((a, n) => a + n.length + 1, 0);
    w.u16(v4 ? NRES_IP4RECORD : NRES_IP6RECORD);
    w.u16(length);
    w.bytes(address);
    for (const n of encoded) { w.bytes(n); w.u8(0); }
    w.pad();
    written++;
  }
  if (written === 0) return null;
  w.u16(NRES_ENDOFRECORD);
  w.u16(0);
  w.u16(OPT_ENDOFOPT); w.u16(0);
  return block(BLOCK_NRB, w.concat());
}

/**
 * What the capture missed, as an Interface Statistics Block.
 *
 * A file that does not say it is incomplete reads as complete. The app already
 * knows what the driver and the agent dropped - it shows the number beside the
 * capture button - and until now that knowledge stopped at the export.
 */
function interfaceStatistics(
  iface: PcapngInterface, interfaceId: number, firstUs: number, lastUs: number,
): Uint8Array | null {
  if (iface.received === undefined && iface.dropped === undefined) return null;
  const w = new Writer();
  w.u32(interfaceId);
  // The ISB's own timestamp is microseconds regardless of if_tsresol.
  const now = BigInt(Math.round(lastUs));
  w.u32(Number(now >> 32n));
  w.u32(Number(now & 0xffffffffn));
  const start = BigInt(Math.round(firstUs));
  const startValue = new Uint8Array(8);
  const startView = new DataView(startValue.buffer);
  startView.setUint32(0, Number(start >> 32n), true);
  startView.setUint32(4, Number(start & 0xffffffffn), true);
  option(w, ISB_STARTTIME, startValue);
  const endValue = new Uint8Array(8);
  const endView = new DataView(endValue.buffer);
  endView.setUint32(0, Number(now >> 32n), true);
  endView.setUint32(4, Number(now & 0xffffffffn), true);
  option(w, ISB_ENDTIME, endValue);
  const counter = (v: number) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(Math.max(0, Math.round(v))), true);
    return b;
  };
  if (iface.received !== undefined) option(w, ISB_IFRECV, counter(iface.received));
  if (iface.dropped !== undefined) option(w, ISB_IFDROP, counter(iface.dropped));
  w.u16(OPT_ENDOFOPT); w.u16(0);
  return block(BLOCK_ISB, w.concat());
}

// --- the file -------------------------------------------------------------------

/**
 * Writes `packets` as a pcapng file.
 *
 * Frames are sorted by capture time, as the classic writer sorts them: the
 * buffer can hold frames from several adapters that arrived out of order - the
 * ordering window only covers thread skew - and a file is forever.
 */
export function generatePcapNg(packets: Packet[], options: PcapngOptions = {}): Blob {
  const interfaces = options.interfaces && options.interfaces.length > 0
    ? options.interfaces
    : [{ name: 'unknown', description: 'Inwire capture' }];

  // A frame names its adapter by label; the file names it by index.
  const indexByName = new Map<string, number>();
  interfaces.forEach((iface, index) => indexByName.set(iface.name, index));

  const parts: Uint8Array[] = [sectionHeader(options)];
  for (const iface of interfaces) parts.push(interfaceDescription(iface));

  // Before the packets, deliberately: a reader walks the file once and in
  // order, so secrets written after the frames they open would arrive too
  // late to decrypt them.
  if (options.secrets !== undefined && options.secrets.length > 0) {
    const dsb = decryptionSecrets(options.secrets);
    if (dsb) parts.push(dsb);
  }

  // Stable, so frames sharing a timestamp keep their frame-number order.
  const ordered = [...packets].sort((a, b) => a.tsUs - b.tsUs);
  for (const packet of ordered) {
    const index = packet.interfaceName ? indexByName.get(packet.interfaceName) ?? 0 : 0;
    const precision = interfaces[index]?.tsPrecision ?? 6;
    parts.push(enhancedPacket(packet, index, 10n ** BigInt(precision)));
  }

  if (options.names && options.names.length > 0) {
    const nrb = nameResolution(options.names);
    if (nrb) parts.push(nrb);
  }

  // The ISB goes last, as a summary of what happened: readers take the newest
  // one for an interface, and writing it after the frames is what makes its
  // end time meaningful.
  const firstUs = ordered.length > 0 ? ordered[0].tsUs : 0;
  const lastUs = ordered.length > 0 ? ordered[ordered.length - 1].tsUs : 0;
  interfaces.forEach((iface, index) => {
    const isb = interfaceStatistics(iface, index, firstUs, lastUs);
    if (isb) parts.push(isb);
  });

  return new Blob(parts as BlobPart[], { type: 'application/x-pcapng' });
}
