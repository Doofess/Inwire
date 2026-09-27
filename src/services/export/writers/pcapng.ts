/**
 * The pcapng writer, a page at a time.
 *
 * pcapng can express what classic pcap cannot, and this app knows all of it:
 *
 *   * **which adapter a frame came from** - an Interface Description Block per
 *     adapter, with its own link type;
 *   * **timestamps finer than a microsecond** - `if_tsresol` is per interface;
 *   * **the capture itself** - the Section Header Block's comment carries the
 *     export's metadata (`metaEntries`), the same lines every other format
 *     prints, and `shb_userappl` / `shb_os` say what wrote it and where;
 *   * **the names the capture taught us** (a Name Resolution Block) and **what
 *     the capture missed** (an Interface Statistics Block).
 *
 * ## Block order, streamed
 *
 * A stream cannot go back and prepend, so the order is chosen so it never
 * has to:
 *
 *   1. SHB, first, from the metadata the caller hands in. A whole-capture
 *      export knows its frame count and span before the first frame is
 *      written - the survey pass counted them - so the header is complete.
 *   2. DSB, when there are secrets: before any frame, because a reader walks
 *      the file once and secrets after the frames they open arrive too late.
 *   3. An IDB immediately before the first frame of each adapter. Interfaces
 *      are numbered **in order of first appearance**, so the numbering is a
 *      property of the frames and not of how they were paged; the format asks
 *      only that an IDB precede every block that names it (RFC draft
 *      `draft-ietf-opsawg-pcapng`, section 4.2), and Wireshark reads IDBs
 *      between packets.
 *   4. The frames, as EPBs.
 *   5. At `finish`: the NRB, then an ISB per adapter that has counters - last,
 *      as a summary; a reader takes the newest ISB for an interface.
 *
 * Paging is therefore invisible in the output: the same frames in pages of
 * any size give the same bytes, which `scripts/export/pcapng.ts` asserts.
 *
 * Block layout is uniform: type (u32), total length (u32), body, total length
 * again (u32). The trailing copy is what lets a reader walk the file
 * backwards, and it is the field most often got wrong - it counts itself, the
 * leading length and the type, and every block is padded to a multiple of four.
 */
import type { Packet } from '../../../types/packet';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG, LINKTYPE } from '../../dissect/types';
import { fieldValue } from '../../dissect/fieldAccess';
import { Direction, directionOf } from '../../direction';
import { APP_NAME, appVersion } from '../../../lib/appVersion';
import { metaEntries, type CaptureMeta, type DropCounts } from '../captureMeta';
import type { ExportWriter } from './writer';
import type { Anonymiser } from '../../anonymise';
import { AdapterLabels } from './tabular';

export const PCAPNG_MIME = 'application/x-pcapng';

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_NRB = 0x00000004;
const BLOCK_ISB = 0x00000005;
const BLOCK_EPB = 0x00000006;
const BLOCK_DSB = 0x0000000a;

/** The one secrets type anything reads, an NSS key log; defined beside `LINKTYPE`. */
export { DSB_SECRETS_TYPE_TLS_KEY_LOG };

const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

// Option codes, from the pcapng specification (draft-ietf-opsawg-pcapng).
// Options are `code (u16) | length (u16) | value | padding`, ending in
// opt_endofopt.
const OPT_ENDOFOPT = 0;
/** opt_comment: valid in every block, and repeatable. */
const OPT_COMMENT = 1;
/**
 * epb_flags: a 32-bit word whose low two bits are the frame's direction.
 * 0 = not available, 1 = inbound, 2 = outbound. Transit has no encoding - the
 * two bits describe a frame relative to the capturing interface, and a frame
 * merely overheard is neither - so it is written as "not available".
 */
const EPB_FLAGS = 2;
/**
 * 2 is `shb_hardware`, deliberately not written: "the hardware used to create
 * this section", which this build does not know. An absent option says
 * nothing is known; a wrong one is read by every tool as a fact.
 */
const SHB_OS = 3;
const SHB_USERAPPL = 4;
const IF_NAME = 2;
const IF_DESCRIPTION = 3;
const IF_TSRESOL = 9;
const IF_FILTER = 11;
/** `if_filter`'s first byte: the rest is a libpcap filter string. */
const IF_FILTER_LIBPCAP = 0;
const ISB_STARTTIME = 2;
const ISB_ENDTIME = 3;
const ISB_IFRECV = 4;
/** Dropped by the interface - the driver's kernel buffer. */
const ISB_IFDROP = 5;
/** Dropped by the operating system or the capturing program - the agent and the pipe. */
const ISB_OSDROP = 7;

/** NRB record types: an IPv4 or IPv6 address followed by NUL-terminated names. */
const NRES_ENDOFRECORD = 0;
const NRES_IP4RECORD = 1;
const NRES_IP6RECORD = 2;

export interface PcapngInterface {
  /** The adapter's label, as `Packet.interfaceName` carries it. */
  name: string;
  description?: string;
  /** Used only to describe an adapter no frame was written for: a written frame's IDB takes the frame's own link type. */
  linkType?: number;
  /** Decimal places the timestamps are meaningful to; 6 (µs) or 9 (ns). When absent, the first frame's. */
  tsPrecision?: number;
  /** Frames the adapter saw; null or absent when not reported. */
  received?: number | null;
  /** `isb_ifdrop`: dropped by the driver. Null or absent when not reported - never written as 0. */
  dropped?: number | null;
  /** `isb_osdrop`: dropped past the driver. Null or absent when not reported. */
  osDropped?: number | null;
  /** The snaplen the capture kept each frame to; null or absent for whole frames. */
  snaplen?: number | null;
  /**
   * `if_filter`: the libpcap capture filter the driver applied. Never written
   * into an anonymised file - it names hosts - and absent when there was none.
   */
  filter?: string | null;
}

export interface PcapngOptions {
  /**
   * Adapters the caller can describe, by name. Only adapters with frames in the
   * file get an IDB - unless no frame is written at all, when every one given
   * is described so an empty capture still says where it was taken.
   */
  interfaces?: PcapngInterface[];
  /** Address to names, for the Name Resolution Block. Leave out when anonymising. */
  names?: { address: string; names: string[] }[];
  /** Free text, the first line of the section comment. */
  comment?: string;
  /** The export's metadata; its lines follow `comment` in the section comment. */
  meta?: CaptureMeta;
  /**
   * `shb_os`. The caller's to give - a service does not read the window - and
   * `meta.os` when absent. Omitted when neither says.
   */
  os?: string | null;
  /** `shb_userappl`; `Inwire <version>` when absent. */
  application?: string;
  /**
   * The capture's counters, written as an ISB when the file holds frames from
   * exactly one adapter - the counters describe the whole capture, so with two
   * adapters there is no one interface to attribute them to. Counts set on the
   * interface itself win over these.
   */
  statistics?: { received?: number | null; drops: DropCounts };
  /**
   * An NSS key log, written as a Decryption Secrets Block. The file then opens
   * itself - which is exactly why it is off by default and asked for
   * explicitly: a capture with its secrets attached has no confidentiality.
   */
  secrets?: string;
  /**
   * For an anonymised export (`meta.flags.anonymised`): the job's anonymiser
   * and the adapters' real labels, so `if_name` says what the metadata says -
   * see `AdapterLabels` in `tabular.ts`.
   */
  anonymiser?: Anonymiser;
  adapters?: readonly string[];
}

// --- little writer ----------------------------------------------------------

class Bytes {
  private chunks: Uint8Array[] = [];
  private size = 0;

  bytes(b: Uint8Array): void {
    this.chunks.push(b);
    this.size += b.length;
  }

  u8(v: number): void { this.bytes(Uint8Array.of(v & 0xff)); }

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

  concat(): Uint8Array {
    const out = new Uint8Array(this.size);
    let at = 0;
    for (const c of this.chunks) { out.set(c, at); at += c.length; }
    return out;
  }
}

const encoder = new TextEncoder();
const utf8 = (text: string) => encoder.encode(text);

function option(w: Bytes, code: number, value: Uint8Array): void {
  w.u16(code);
  w.u16(value.length);
  w.bytes(value);
  w.pad();
}

/**
 * An option's value is at most 65,535 bytes - its length is a u16. A longer
 * string is cut at a character boundary rather than written with a length
 * that wraps and misframes every option after it.
 */
function stringOption(w: Bytes, code: number, value: string): void {
  let bytes = utf8(value);
  if (bytes.length > 0xffff) {
    let end = 0xffff;
    while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
    bytes = bytes.subarray(0, end);
  }
  option(w, code, bytes);
}

function u32Option(w: Bytes, code: number, value: number): void {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
  option(w, code, bytes);
}

/** A 64-bit timestamp as the format stores it: upper 32 bits, then lower 32. */
function timestampValue(ticks: bigint): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setUint32(0, Number((ticks >> 32n) & 0xffffffffn), true);
  view.setUint32(4, Number(ticks & 0xffffffffn), true);
  return out;
}

function counterValue(v: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(Math.max(0, Math.round(v))), true);
  return out;
}

function endOfOptions(w: Bytes): void {
  w.u16(OPT_ENDOFOPT);
  w.u16(0);
}

/**
 * Frames a body as a block. The trailing length counts the type, both lengths
 * and the padded body, so it cannot be computed until the body is finished.
 */
function block(type: number, body: Uint8Array): Uint8Array {
  const padded = body.length % 4 === 0 ? body.length : body.length + (4 - (body.length % 4));
  const total = 12 + padded;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, total, true);
  out.set(body, 8);
  view.setUint32(total - 4, total, true);
  return out;
}

// --- blocks -------------------------------------------------------------------

/** The section comment: the caller's line, then one line per metadata entry. */
export function sectionComment(options: PcapngOptions): string {
  const lines: string[] = [];
  if (options.comment) lines.push(options.comment);
  if (options.meta) for (const [key, value] of metaEntries(options.meta)) lines.push(`${key}: ${value}`);
  return lines.join('\n');
}

function sectionHeader(options: PcapngOptions): Uint8Array {
  const w = new Bytes();
  w.u32(BYTE_ORDER_MAGIC);
  w.u16(1);            // major
  w.u16(0);            // minor
  // Section length: -1, "not known". Backfilling it would mean holding the
  // whole file to rewrite eight bytes, and every reader accepts the unknown
  // form because a live capture cannot know it either.
  w.u64(0xffffffffffffffffn);
  const comment = sectionComment(options);
  if (comment) stringOption(w, OPT_COMMENT, comment);
  // `shb_os` used to be `navigator.userAgent`, and then a read of the
  // preload's `osDescription` from inside this module. It is the caller's now:
  // a service that reaches for `window` is one the assertion scripts cannot
  // run, and Wireshark shows this under "Operating System", so it must be the
  // capturing machine's answer and not a browser's.
  const os = options.os ?? options.meta?.os;
  if (os) stringOption(w, SHB_OS, os);
  stringOption(w, SHB_USERAPPL, options.application ?? `${APP_NAME} ${appVersion()}`);
  endOfOptions(w);
  return block(BLOCK_SHB, w.concat());
}

interface OpenInterface {
  id: number;
  /** The adapter's real label: what `given` and the counters are keyed by. */
  name: string;
  /** What `if_name` says - `name`, or its anonymised label. */
  label: string;
  /** What `if_description` says: the caller's, or the generic one when anonymised. */
  description: string;
  linkType: number;
  precision: number;
  unitsPerSecond: bigint;
  given: PcapngInterface | undefined;
  firstUs: number;
  lastUs: number;
  /** The file is anonymised, so nothing that names a host is written. */
  anonymised: boolean;
}

function interfaceDescription(iface: OpenInterface): Uint8Array {
  const w = new Bytes();
  w.u16(iface.linkType);
  w.u16(0);            // reserved
  // 0 is "no limit", which is what a capture with no snaplen kept.
  w.u32(iface.given?.snaplen ?? 0);
  stringOption(w, IF_NAME, iface.label);
  stringOption(w, IF_DESCRIPTION, iface.description);
  // if_tsresol is one byte: a power of ten unless the high bit says power of
  // two. Writing it is what makes a nanosecond capture survive the round trip.
  option(w, IF_TSRESOL, Uint8Array.of(iface.precision));
  const filter = iface.given?.filter;
  if (typeof filter === 'string' && !iface.anonymised) {
    const text = encoder.encode(filter);
    option(w, IF_FILTER, Uint8Array.of(IF_FILTER_LIBPCAP, ...text));
  }
  endOfOptions(w);
  return block(BLOCK_IDB, w.concat());
}

/** Ticks of the interface's own resolution. Assembled in bigint: a nanosecond count is past a double's exact range. */
function ticksOf(packet: Packet, unitsPerSecond: bigint): bigint {
  // The nanosecond stamp whenever the frame has one, whatever the interface's
  // resolution: `tsUs` is that stamp already rounded, and scaling a rounded
  // value to a finer or coarser unit rounds twice.
  return packet.tsNanos !== undefined
    ? packet.tsNanos * unitsPerSecond / 1_000_000_000n
    : BigInt(Math.round(packet.tsUs)) * unitsPerSecond / 1_000_000n;
}

function enhancedPacket(packet: Packet, iface: OpenInterface, anonymised: boolean): Uint8Array {
  const w = new Bytes();
  const ticks = ticksOf(packet, iface.unitsPerSecond);
  w.u32(iface.id);
  w.u32(Number(ticks >> 32n));
  w.u32(Number(ticks & 0xffffffffn));
  w.u32(packet.rawBytes.length);
  // The wire length, never less than what was captured.
  w.u32(Math.max(packet.length, packet.rawBytes.length));
  w.bytes(packet.rawBytes);
  w.pad();
  // Which way it went, in the format's own field for it - written only when
  // there is an answer; the option's absence already says "not available".
  const direction = directionOf(packet.direction);
  if (direction === Direction.In) u32Option(w, EPB_FLAGS, 0b01);
  else if (direction === Direction.Out) u32Option(w, EPB_FLAGS, 0b10);

  // Which program sent it, as an ordinary comment: the one per-packet option
  // every pcapng reader already shows. Nothing when the frame was not
  // attributed - an empty comment would say "known to be nothing".
  const processName = fieldValue(packet, 'inwire.process.name');
  const processPid = fieldValue(packet, 'inwire.process.pid');
  // Never in an anonymised file, whatever the frame still carries: a process
  // and its PID are the capturing machine's, and say who was using it.
  if (!anonymised && typeof processName === 'string' && typeof processPid === 'number') {
    const path = fieldValue(packet, 'inwire.process.path');
    stringOption(w, OPT_COMMENT, `Process: ${processName} (pid ${processPid})`
      + (typeof path === 'string' && path ? ` - ${path}` : ''));
  }
  endOfOptions(w);
  return block(BLOCK_EPB, w.concat());
}

/**
 * Decryption Secrets Block. The length field counts the real bytes, not the
 * padding, so a reader that trusts it does not hand NULs to its parser.
 */
function decryptionSecrets(secrets: string): Uint8Array | null {
  const payload = utf8(secrets);
  if (payload.length === 0) return null;
  const w = new Bytes();
  w.u32(DSB_SECRETS_TYPE_TLS_KEY_LOG);
  w.u32(payload.length);
  w.bytes(payload);
  w.pad();
  endOfOptions(w);
  return block(BLOCK_DSB, w.concat());
}

function parseIpv4(address: string): Uint8Array | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!/^\d{1,3}$/.test(parts[i]) || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIpv6(address: string): Uint8Array | null {
  if (!address.includes(':')) return null;
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const [head, tail] = halves;
  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = tail === undefined || tail === '' ? [] : tail.split(':');
  if (tail === undefined && headGroups.length !== 8) return null;
  if (headGroups.length + tailGroups.length > (tail === undefined ? 8 : 7)) return null;

  const out = new Uint8Array(16);
  const put = (groups: string[], at: number) => {
    for (let i = 0; i < groups.length; i++) {
      if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return false;
      const v = parseInt(groups[i], 16);
      out[at + i * 2] = v >> 8;
      out[at + i * 2 + 1] = v & 0xff;
    }
    return true;
  };
  if (!put(headGroups, 0)) return null;
  if (!put(tailGroups, 16 - tailGroups.length * 2)) return null;
  return out;
}

/**
 * The names the capture taught us. Every one came out of a DNS answer, a TLS
 * server name or a DHCP lease in this capture, so the file carries its own
 * resolution and a reader gets the same names without a single lookup.
 */
function nameResolution(entries: { address: string; names: string[] }[]): Uint8Array | null {
  const w = new Bytes();
  let written = 0;
  for (const entry of entries) {
    const names = entry.names.filter((n) => n.length > 0);
    if (names.length === 0) continue;
    const v4 = parseIpv4(entry.address);
    const address = v4 ?? parseIpv6(entry.address);
    if (!address) continue;
    const encoded = names.map(utf8);
    const length = address.length + encoded.reduce((a, n) => a + n.length + 1, 0);
    // A record's length is a u16 too; a name list past it is not written.
    if (length > 0xffff) continue;
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
  endOfOptions(w);
  return block(BLOCK_NRB, w.concat());
}

interface Counters { received: number | null; ifDrop: number | null; osDrop: number | null }

/** Drops past the driver, when the agent and the pipe both said. A sum with an unknown half is unknown. */
function osDropOf(drops: DropCounts): number | null {
  return drops.agent !== null && drops.pipe !== null ? drops.agent + drops.pipe : null;
}

/**
 * What the capture missed. Every timestamp in the block is in the interface's
 * own `if_tsresol` units, like an EPB's - the specification defines the ISB's
 * timestamp and `isb_starttime`/`isb_endtime` as "the same format" as the EPB
 * timestamp. The writer this replaced wrote microseconds whatever the
 * interface said, which put a nanosecond adapter's statistics in 1970.
 */
function interfaceStatistics(iface: OpenInterface, counters: Counters): Uint8Array | null {
  if (counters.received === null && counters.ifDrop === null && counters.osDrop === null) return null;
  const w = new Bytes();
  const toTicks = (us: number) => BigInt(Math.round(us)) * iface.unitsPerSecond / 1_000_000n;
  const end = toTicks(iface.lastUs);
  w.u32(iface.id);
  w.u32(Number(end >> 32n));
  w.u32(Number(end & 0xffffffffn));
  option(w, ISB_STARTTIME, timestampValue(toTicks(iface.firstUs)));
  option(w, ISB_ENDTIME, timestampValue(end));
  if (counters.received !== null) option(w, ISB_IFRECV, counterValue(counters.received));
  if (counters.ifDrop !== null) option(w, ISB_IFDROP, counterValue(counters.ifDrop));
  if (counters.osDrop !== null) option(w, ISB_OSDROP, counterValue(counters.osDrop));
  endOfOptions(w);
  return block(BLOCK_ISB, w.concat());
}

// --- the writer -----------------------------------------------------------------

export class PcapngWriter implements ExportWriter {
  private started = false;
  /** By adapter AND link type - see `interfaceFor`. */
  private readonly open = new Map<string, OpenInterface>();
  private readonly given = new Map<string, PcapngInterface>();
  private readonly labels: AdapterLabels;

  constructor(private readonly options: PcapngOptions = {}) {
    // Refused outright rather than quietly dropped: a name table maps the
    // addresses the anonymiser just rewrote back to host names, and a key log
    // opens the payload it removed. A caller asking for either on an
    // anonymised file has a bug worth hearing about.
    if (options.meta?.flags.anonymised) {
      if (options.names && options.names.length > 0) {
        throw new Error('an anonymised pcapng cannot carry a name resolution table');
      }
      if (options.secrets) throw new Error('an anonymised pcapng cannot carry decryption secrets');
    }
    for (const iface of options.interfaces ?? []) {
      if (!this.given.has(iface.name)) this.given.set(iface.name, iface);
    }
    this.labels = new AdapterLabels(options);
  }

  write(page: readonly Packet[]): Uint8Array[] {
    const out: Uint8Array[] = [];
    this.start(out);
    for (const packet of page) {
      const iface = this.interfaceFor(packet, out);
      if (packet.tsUs < iface.firstUs) iface.firstUs = packet.tsUs;
      if (packet.tsUs > iface.lastUs) iface.lastUs = packet.tsUs;
      out.push(enhancedPacket(packet, iface, this.labels.anonymised));
    }
    return out;
  }

  finish(): Uint8Array[] {
    const out: Uint8Array[] = [];
    this.start(out);
    // Nothing was written: describe what the caller named, so an empty file
    // still says where it was taken. Nothing named, nothing described - a
    // section with no interfaces is legal and says exactly that.
    if (this.open.size === 0) {
      for (const iface of this.given.values()) {
        this.describe(iface.name, iface.linkType ?? LINKTYPE.ETHERNET, undefined, out);
      }
    }

    if (this.options.names && this.options.names.length > 0) {
      const nrb = nameResolution(this.options.names);
      if (nrb) out.push(nrb);
    }

    const written = [...this.open.values()].filter((i) => i.firstUs !== Number.POSITIVE_INFINITY);
    // An adapter's own counters go on its first IDB only: one adapter written
    // under two link types is still one set of counters.
    const counted = new Set<string>();
    for (const iface of written) {
      if (counted.has(iface.name)) continue;
      counted.add(iface.name);
      const counters = this.countersFor(iface, written.length === 1);
      if (!counters) continue;
      const isb = interfaceStatistics(iface, counters);
      if (isb) out.push(isb);
    }
    return out;
  }

  private start(out: Uint8Array[]): void {
    if (this.started) return;
    this.started = true;
    out.push(sectionHeader(this.options));
    if (this.options.secrets) {
      const dsb = decryptionSecrets(this.options.secrets);
      if (dsb) out.push(dsb);
    }
  }

  /**
   * The IDB a frame belongs to, keyed by adapter AND link type.
   *
   * By name alone, two sources that share a label - every frame an import
   * reads carries the same `interfaceName`, whatever interface of the file it
   * came from - collapse into one IDB with the first frame's link type, and
   * every frame of the other type is then declared, and dissected by every
   * reader, as something it is not. The frame's own link type decides, since
   * its bytes are what the EPB holds.
   */
  private interfaceFor(packet: Packet, out: Uint8Array[]): OpenInterface {
    const name = packet.interfaceName || 'unknown';
    const linkType = packet.linkType ?? LINKTYPE.ETHERNET;
    return this.open.get(`${linkType}|${name}`) ?? this.describe(name, linkType, packet, out);
  }

  private describe(name: string, linkType: number, first: Packet | undefined, out: Uint8Array[]): OpenInterface {
    const given = this.given.get(name);
    const precision = given?.tsPrecision ?? first?.tsPrecision ?? 6;
    const iface: OpenInterface = {
      id: this.open.size,
      name,
      label: this.labels.label(name),
      // A description a caller supplied can name the hardware as surely as
      // the adapter's name does, so an anonymised file carries neither.
      description: this.labels.anonymised ? 'Inwire capture' : given?.description ?? 'Inwire capture',
      linkType,
      precision,
      unitsPerSecond: 10n ** BigInt(precision),
      given,
      firstUs: Number.POSITIVE_INFINITY,
      lastUs: Number.NEGATIVE_INFINITY,
      anonymised: this.labels.anonymised,
    };
    this.open.set(`${linkType}|${name}`, iface);
    out.push(interfaceDescription(iface));
    return iface;
  }

  /**
   * Counters set on the interface, else the capture's when this is the only
   * adapter in the file. Null counts stay null: a drop count nobody reported
   * is left out of the block, never written as a zero that claims the capture
   * was complete.
   */
  private countersFor(iface: OpenInterface, only: boolean): Counters | null {
    const given = iface.given;
    const own: Counters = {
      received: given?.received ?? null,
      ifDrop: given?.dropped ?? null,
      osDrop: given?.osDropped ?? null,
    };
    const stats = only ? this.options.statistics : undefined;
    if (!stats) return own;
    return {
      received: own.received ?? stats.received ?? null,
      ifDrop: own.ifDrop ?? stats.drops.kernel,
      osDrop: own.osDrop ?? osDropOf(stats.drops),
    };
  }
}
