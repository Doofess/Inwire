/**
 * NetFlow v5, v9 and IPFIX - the reference's `cflow` - as a tree.
 *
 * Routers, switches, firewalls and hypervisors export a record per flow to a
 * collector on UDP 2055, 9996 (NetFlow) or 4739 (IPFIX), and a capture taken
 * anywhere near a collector is mostly these. The structure is read by
 * `flow/flowExport.ts`; this draws it, row for row as the reference does,
 * which `scripts/netflow/dissect.ts` holds against `tshark -T pdml`.
 *
 * v9 and IPFIX records mean nothing without the template an earlier message
 * defined, so templates are kept by the L3 tracker per exporter (both ends of
 * the datagram), domain and template id - and as in the reference, **the first
 * definition of an id stands**: a later message redefining it is drawn, and
 * not used. The sequence number is followed the same way, and a gap said.
 *
 * The ~470 standard elements are named from a table generated from the
 * reference (`cflowNames.ts`); a handful it draws as trees of their own (TCP
 * flags, the forwarding status, application ids, MPLS labels, start/end time
 * pairs) are drawn here by hand.
 *
 * Deliberate differences, each because matching would mean carrying the
 * reference's whole vendor vocabulary: an enterprise element is drawn as a
 * private entry even where the reference has a field for it (Cisco's, ntop's,
 * NetScaler's...), and an enterprise number this build does not list is
 * written `Unknown (n)` where the reference names the company. NetFlow v1, v6,
 * v7 and v8 are not read.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { LeafResult } from './dispatch';
import {
  readDataRecords, readFlowHeader, readFlowSets, readTemplateSet, readUint, setKind, v5RecordOffsets,
  type FlowHeader, type FlowSet, type FlowTemplateField, type FlowTemplateSource, type FlowValue, type ParsedTemplate,
  type StoredFlowTemplate,
} from '../flow/flowExport';
import {
  CISCO_TYPE_NAMES, CLASSIFICATION_ENGINES, CONSUME_CODES, DROP_CODES, ELEMENTS, ELEMENT_VALUES, ENGINE_TYPES,
  FORWARDING_STATUS, FORWARD_CODES, PEN_NAMES, SAMPLING_MODES, SCOPE_TYPES, TYPE_NAMES,
} from './cflowNames';
import { describeIpProtocol } from '../dissect/ipProtocolNames';
import { formatArrivalTime } from '../dissect/arrivalTime';
import { hexColons } from '../dissect/hexBytes';
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';

/** What a message needs from outside itself. */
export interface CflowContext {
  /** Both ends of the datagram, `a:p>b:p` - what templates and sequence numbers are kept under. */
  exporter: string;
  frame: number;
  templates: FlowTemplateSource;
  /** The sequence number the exporter should have sent, and the frame it last sent in; null for its first. */
  sequence(exporter: string, domain: number, next: number, frame: number): { expected: number; previousFrame: number } | null;
}

const REVERSE_PEN = 29305;
const CISCO_PEN = 9;

const u16 = (b: Uint8Array, p: number) => (b[p] << 8) | b[p + 1];
const u32 = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
const range = (from: number, length: number): [number, number] => [from, Math.max(from, from + length - 1)];
const named = (table: Readonly<Record<number, string>>, n: number) => `${table[n] ?? 'Unknown'} (${n})`;
const plural = (n: bigint | number, unit: string) => `${n} ${unit}${n === 1n || n === 1 ? '' : 's'}`;
const spacedHex = (b: Uint8Array, from: number, length: number) => hexColons(b, from, from + length).replace(/:/g, ' ');

/**
 * A duration as the reference writes one: `1 hour, 1 minute, 1.500000000
 * seconds`, `500.000000 milliseconds`, `1.000 microseconds`, `0.000000000
 * seconds`. Zero parts are left out, and a sub-second remainder with no whole
 * seconds is written in the largest unit that has it.
 */
export function relativeTime(ns: bigint): string {
  if (ns === 0n) return '0.000000000 seconds';
  if (ns < 0n) return `-${relativeTime(-ns)}`;
  const secs = ns / 1_000_000_000n;
  const frac = Number(ns % 1_000_000_000n);
  const sub = (f: number) => (f >= 1_000_000
    ? `${Math.floor(f / 1_000_000)}.${String(f % 1_000_000).padStart(6, '0')} milliseconds`
    : f >= 1000 ? `${Math.floor(f / 1000)}.${String(f % 1000).padStart(3, '0')} microseconds` : `${f} nanoseconds`);
  if (secs === 0n) return sub(frac);
  const parts: string[] = [];
  const days = secs / 86400n;
  const hours = (secs % 86400n) / 3600n;
  const minutes = (secs % 3600n) / 60n;
  const seconds = secs % 60n;
  if (days > 0n) parts.push(plural(days, 'day'));
  if (hours > 0n) parts.push(plural(hours, 'hour'));
  if (minutes > 0n) parts.push(plural(minutes, 'minute'));
  if (seconds > 0n) parts.push(frac > 0 ? `${seconds}.${String(frac).padStart(9, '0')} seconds` : plural(seconds, 'second'));
  else if (frac > 0) parts.push(sub(frac));
  return parts.join(', ');
}

/** Epoch nanoseconds as the reference's local date, or its "Not representable". */
function absoluteTime(ns: bigint): string {
  if (ns < 0n || ns > 8_640_000_000_000_000_000_000n) return 'Not representable';
  return formatArrivalTime(Number(ns / 1000n), false, Number(ns % 1000n));
}

/** An NTP timestamp (seconds since 1900 and a 32-bit fraction) as epoch nanoseconds. */
function ntpNs(b: Uint8Array, p: number): bigint {
  const secs = BigInt(u32(b, p)) - 2208988800n;
  return secs * 1_000_000_000n + ((BigInt(u32(b, p + 4)) * 1_000_000_000n) >> 32n);
}

/** C's `%g`: six significant digits, trailing zeros dropped, an exponent of two digits or more. */
function cFloat(v: number): string {
  if (!Number.isFinite(v)) return Number.isNaN(v) ? 'nan' : v > 0 ? 'inf' : '-inf';
  if (v === 0) return Object.is(v, -0) ? '-0' : '0';
  const exp = Math.floor(Math.log10(Math.abs(v)));
  const trim = (s: string) => (s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s);
  if (exp < -4 || exp >= 6) {
    const [mantissa, e] = v.toExponential(5).split('e');
    const n = Number(e);
    return `${trim(mantissa)}e${n < 0 ? '-' : '+'}${String(Math.abs(n)).padStart(2, '0')}`;
  }
  return trim(v.toFixed(Math.max(0, 5 - exp)));
}

const decoder = new TextDecoder();

/** C-style escapes for what a string element holds that is not printable. */
function escapedText(b: Uint8Array, from: number, length: number): string {
  const text = decoder.decode(b.subarray(from, from + length));
  const escapes: Record<string, string> = { '\x07': '\\a', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\v': '\\v', '\\': '\\\\' };
  return text.replace(/[\x00-\x1f\x7f\\]/g, (c) => escapes[c] ?? `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

// --- elements -------------------------------------------------------------------

/** A start/end time pair's kind, in the order the reference draws leftovers. */
const PAIRS: Record<number, { kind: number; end: boolean }> = {
  22: { kind: 0, end: false }, 21: { kind: 0, end: true },
  150: { kind: 1, end: false }, 151: { kind: 1, end: true },
  152: { kind: 2, end: false }, 153: { kind: 2, end: true },
  154: { kind: 3, end: false }, 155: { kind: 3, end: true },
  156: { kind: 4, end: false }, 157: { kind: 4, end: true },
  158: { kind: 5, end: false }, 159: { kind: 5, end: true },
};
// The last is microseconds before the export time; the reference calls the
// pair "delta milliseconds".
const PAIR_NAMES = ['switched', 'seconds', 'milliseconds', 'microseconds', 'nanoseconds', 'delta milliseconds'];

/**
 * A pair element's time, in nanoseconds - since boot for a switched time,
 * since the epoch otherwise. A delta is four bytes of microseconds before the
 * export time, and the reference reads the first four of a longer one.
 */
function pairTime(b: Uint8Array, v: FlowValue, kind: number, exportNs: bigint): bigint {
  if (kind === 0 || kind === 2) return readUint(b, v.start, Math.min(v.length, 8)) * 1_000_000n;
  if (kind === 1) return readUint(b, v.start, Math.min(v.length, 8)) * 1_000_000_000n;
  if (kind === 5) return exportNs - readUint(b, v.start, Math.min(v.length, 4)) * 1000n;
  return v.length >= 8 ? ntpNs(b, v.start) : 0n;
}

/** A pair element's own row: `StartTime: 58 minutes, 20 seconds`, or a date. */
function pairRow(b: Uint8Array, v: FlowValue, kind: number, end: boolean, exportNs: bigint): ProtocolField {
  const t = pairTime(b, v, kind, exportNs);
  return kind === 0
    ? { name: end ? 'EndTime' : 'StartTime', value: relativeTime(t), abbrev: end ? 'cflow.timeend' : 'cflow.timestart', rawBytesRange: range(v.start, v.length) }
    : { name: end ? 'EndTime' : 'StartTime', value: absoluteTime(t), abbrev: end ? 'cflow.abstimeend' : 'cflow.abstimestart', rawBytesRange: range(v.start, v.length) };
}

const TCP_FLAG_BITS: [number, string, string][] = [
  [0x100, 'ECN Nonce Sum', 'cflow.tcpflags.ns'], [0x80, 'CWR', 'cflow.tcpflags.cwr'], [0x40, 'ECN Echo', 'cflow.tcpflags.ece'],
  [0x20, 'URG', 'cflow.tcpflags.urg'], [0x10, 'ACK', 'cflow.tcpflags.ack'], [0x08, 'PSH', 'cflow.tcpflags.psh'],
  [0x04, 'RST', 'cflow.tcpflags.rst'], [0x02, 'SYN', 'cflow.tcpflags.syn'], [0x01, 'FIN', 'cflow.tcpflags.fin'],
];

/** TCP flags as v9 and IPFIX draw them: the set flags named, and a bit each. */
function tcpFlagsRow(b: Uint8Array, v: FlowValue): ProtocolField {
  const wide = v.length === 2;
  const flags = wide ? u16(b, v.start) : b[v.start];
  const bits = wide ? 16 : 8;
  // One byte is the six classic flags under two reserved bits (the
  // reference's default reading); two are RFC 7125's whole flags word.
  const shown = TCP_FLAG_BITS.filter(([bit]) => (wide ? true : bit <= 0x20));
  const set = shown.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
  const bit = (shift: number, width: number) => ({ bitOffset: bits - shift - width, bitLength: width, totalBits: bits });
  const children: ProtocolField[] = wide
    ? [
      { name: 'Zero (Header Length)', value: `0x${(flags >> 12).toString(16)}`, abbrev: 'cflow.tcpflags.zero', rawBytesRange: range(v.start, 2), bitfield: bit(12, 4) },
      { name: 'Reserved', value: `0x${((flags >> 9) & 7).toString(16)}`, abbrev: 'cflow.tcpflags.reserved', rawBytesRange: range(v.start, 2), bitfield: bit(9, 3) },
    ]
    : [{ name: 'Reserved', value: `0x${(flags >> 6).toString(16)}`, abbrev: 'cflow.tcpflags.reserved', rawBytesRange: range(v.start, 1), bitfield: bit(6, 2) }];
  for (const [mask, name, abbrev] of shown) {
    const shift = Math.log2(mask);
    children.push({ name, value: (flags & mask) !== 0 ? 'Used' : 'Not used', abbrev, rawBytesRange: range(v.start, v.length), bitfield: bit(shift, 1) });
  }
  const hex = `0x${flags.toString(16).padStart(wide ? 4 : 2, '0')}`;
  return { name: 'TCP Flags', value: set.length > 0 ? `${hex}, ${set.join(', ')}` : hex, abbrev: 'cflow.tcpflags', rawBytesRange: range(v.start, v.length), children };
}

/** The forwarding status: two bits of status, six of its reason. */
function forwardingRow(b: Uint8Array, v: FlowValue): ProtocolField {
  const byte = b[v.start];
  const status = byte >> 6;
  const code = byte & 0x3f;
  const [abbrev, name, table] = (
    [['cflow.forwarding_status_unknown_code', 'ForwardingStatusUnknown', {}],
      ['cflow.forwarding_status_forward_code', 'ForwardingStatusForwardCode', FORWARD_CODES],
      ['cflow.forwarding_status_drop_code', 'ForwardingStatusDropCode', DROP_CODES],
      ['cflow.forwarding_status_consume_code', 'ForwardingStatusConsumeCode', CONSUME_CODES]] as const
  )[status];
  const r = range(v.start, 1);
  return {
    name: 'Forwarding Status', value: '', rawBytesRange: r,
    children: [
      { name: 'ForwardingStatus', value: named(FORWARDING_STATUS, status), abbrev: 'cflow.forwarding_status', rawBytesRange: r, bitfield: { bitOffset: 0, bitLength: 2, totalBits: 8 } },
      { name, value: named(table, code), abbrev, rawBytesRange: r, bitfield: { bitOffset: 2, bitLength: 6, totalBits: 8 } },
    ],
  };
}

/** An MPLS label stack entry: label, experimental bits, bottom of stack. */
function mplsRow(b: Uint8Array, v: FlowValue, n: number): ProtocolField {
  const word = (b[v.start] << 16) | (b[v.start + 1] << 8) | b[v.start + 2];
  const label = word >> 4;
  const exp = (word >> 1) & 7;
  const bos = (word & 1) === 1;
  const r = range(v.start, 3);
  return {
    name: `MPLS-Label${n}`, value: `${label} exp-bits: ${exp}${bos ? ' bottom-of-stack' : ''}`, rawBytesRange: r,
    children: [
      { name: 'MPLS label', value: label, abbrev: 'cflow.mpls_label', rawBytesRange: r, bitfield: { bitOffset: 0, bitLength: 20, totalBits: 24 } },
      { name: 'MPLS experimental bits', value: exp, abbrev: 'cflow.mpls_exp', rawBytesRange: range(v.start + 2, 1), bitfield: { bitOffset: 4, bitLength: 3, totalBits: 8 } },
      { name: 'MPLS Bottom of Stack', value: bos ? 'Bottom-of-Stack' : 'Not Bottom-of-Stack', abbrev: 'cflow.mpls_bos', rawBytesRange: range(v.start + 2, 1), bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } },
    ],
  };
}

/** A plain element's value, by the kind the generated table gives it. */
function elementValue(b: Uint8Array, v: FlowValue, abbrev: string, kind: string): string | null {
  const { start, length } = v;
  const width = Number(kind.slice(1)) || 0;
  const n = () => readUint(b, start, Math.min(length, 8));
  switch (kind[0]) {
    case 'u': return length <= 8 ? String(n()) : null;
    case 'x': return length <= 8 ? `0x${n().toString(16).padStart(width * 2, '0')}` : null;
    case 'X': return length <= 8 ? `0x${n().toString(16).padStart(width * 2, '0')} (${n()})` : null;
    case 'P': return length <= 8 && length >= 2 ? `${n()} (${u16(b, start)})` : null;
    case 'o': { if (length > 8) return null; const o = n().toString(8); return o === '0' ? '0' : `0${o}`; }
    case 'e': return length <= 8 ? named(ELEMENT_VALUES[abbrev] ?? {}, Number(n())) : null;
    case 'p': return length <= 8 ? describeIpProtocol(Number(n())) : null;
    case 'i': return length <= 8 ? String(BigInt.asIntN(length * 8, n())) : null;
    case 'a': return length === 4 && kind === 'a4' ? formatIpv4Address(b, start) : length === 16 && kind === 'a6' ? formatIpv6Address(b, start) : null;
    case 'm': return length === 6 ? hexColons(b, start, start + 6) : null;
    case 'b': return hexColons(b, start, start + length);
    case 's': return escapedText(b, start, length);
    case 'B': return length <= 8 ? (n() !== 0n ? 'True' : 'False') : null;
    case 'f': return length === 4 ? cFloat(new DataView(b.buffer, b.byteOffset + start, 4).getFloat32(0)) : null;
    case 'F': return length === 8 ? cFloat(new DataView(b.buffer, b.byteOffset + start, 8).getFloat64(0)) : null;
    case 't': {
      const unit = kind[1];
      if (unit === 'u' || unit === 'n') return length === 8 ? absoluteTime(ntpNs(b, start)) : null;
      if (unit === 'd') return null;
      if (length > 8) return null;
      return absoluteTime(n() * (unit === 'm' ? 1_000_000n : 1_000_000_000n));
    }
    case 'r': return length <= 8 ? relativeTime(n() * (kind[1] === 'u' ? 1000n : 1_000_000n)) : null;
    default: return null;
  }
}

/** Whether a record is an IPFIX one: enterprise elements and reverse elements are IPFIX's alone. */
interface RecordState {
  ipfix: boolean;
  /** The message's export time, which a delta time counts back from. */
  exportNs: bigint;
  /** Unpaired start and end times, by pair kind, waiting for their other half. */
  starts: (FlowValue | undefined)[];
  ends: (FlowValue | undefined)[];
}

/** One element's rows - none for a time waiting for its pair. */
function elementRows(b: Uint8Array, v: FlowValue, state: RecordState): ProtocolField[] {
  const { field } = v;
  const r = range(v.start, v.length);
  if (field.pen !== undefined && field.pen !== REVERSE_PEN) {
    const name = PEN_NAMES[field.pen] ?? 'Unknown';
    return [{ name: 'Enterprise Private entry', value: `(${name}) Type ${field.type}: Value (hex bytes): ${spacedHex(b, v.start, v.length)}`, abbrev: 'cflow.enterprise_private_entry', rawBytesRange: r }];
  }
  const reverse = field.pen === REVERSE_PEN;
  const pair = PAIRS[field.type];
  if (pair !== undefined && !reverse) {
    const other = pair.end ? state.starts[pair.kind] : state.ends[pair.kind];
    if (other === undefined) {
      (pair.end ? state.ends : state.starts)[pair.kind] = v;
      return [];
    }
    const [s, e] = pair.end ? [other, v] : [v, other];
    state.starts[pair.kind] = undefined;
    state.ends[pair.kind] = undefined;
    const delta = pairTime(b, e, pair.kind, state.exportNs) - pairTime(b, s, pair.kind, state.exportNs);
    return [{
      name: 'Duration', value: `${relativeTime(delta)} (${PAIR_NAMES[pair.kind]})`, abbrev: 'cflow.timedelta', generated: true,
      children: [pairRow(b, s, pair.kind, false, state.exportNs), pairRow(b, e, pair.kind, true, state.exportNs)],
    }];
  }
  if (!reverse) {
    if (field.type === 6 && (v.length === 1 || v.length === 2)) return [tcpFlagsRow(b, v)];
    if (field.type === 89 && v.length === 1) return [forwardingRow(b, v)];
    if (field.type >= 70 && field.type <= 79 && v.length === 3) return [mplsRow(b, v, field.type - 69)];
    if (field.type === 95 && v.length >= 1) {
      return [
        { name: 'Classification Engine ID', value: named(CLASSIFICATION_ENGINES, b[v.start]), abbrev: 'cflow.appl_id.classification_engine_id', rawBytesRange: range(v.start, 1) },
        { name: 'Selector ID', value: hexColons(b, v.start + 1, v.start + v.length), abbrev: 'cflow.appl_id.selector_id', rawBytesRange: range(v.start + 1, v.length - 1) },
      ];
    }
    if (field.type === 139 && v.length === 2) {
      return [
        { name: 'IPv6 ICMP Type', value: b[v.start], abbrev: 'cflow.icmp_ipv6_type', rawBytesRange: range(v.start, 1) },
        { name: 'IPv6 ICMP Code', value: b[v.start + 1], abbrev: 'cflow.icmp_ipv6_code', rawBytesRange: range(v.start + 1, 1) },
      ];
    }
  }
  const element = ELEMENTS[field.type];
  const value = element !== undefined && element[2] !== '-' ? elementValue(b, v, element[0], element[2]) : null;
  if (element === undefined || value === null) {
    // An element this build cannot draw: its bytes, named. The reference
    // files a standard one it does not know as an enterprise entry with no
    // enterprise (IPFIX) or an unknown field type (v9).
    const typeName = TYPE_NAMES[field.type];
    if (element === undefined && !state.ipfix) {
      return [{ name: 'Unknown Field Type', value: `Type ${field.type}: Value (hex bytes): ${spacedHex(b, v.start, v.length)}`, abbrev: 'cflow.unknown_field_type', rawBytesRange: r }];
    }
    if (element === undefined) {
      return [{ name: 'Enterprise Private entry', value: `((null)) Type ${field.type}: Value (hex bytes): ${spacedHex(b, v.start, v.length)}`, abbrev: 'cflow.enterprise_private_entry', rawBytesRange: r }];
    }
    return [{ name: typeName ?? `Type ${field.type}`, value: hexColons(b, v.start, v.start + v.length), rawBytesRange: r }];
  }
  const row: ProtocolField = {
    name: element[1], value: reverse ? `${value} (Reverse Type ${field.type} ${TYPE_NAMES[field.type] ?? 'Unknown'})` : value,
    abbrev: element[0], rawBytesRange: r,
  };
  if (v.prefixAt !== undefined) {
    // A variable-length element says how long it is in a byte, or in a 255
    // and two more bytes; the reference shows both.
    row.children = [{ name: 'String_len_short', value: b[v.prefixAt], abbrev: 'cflow.string_len_short', rawBytesRange: range(v.prefixAt, 1) }];
    if (v.prefixLength === 3) row.children.push({ name: 'String_len_short', value: u16(b, v.prefixAt + 1), abbrev: 'cflow.string_len_long', rawBytesRange: range(v.prefixAt + 1, 2) });
  }
  return [row];
}

/** v9's options scopes are types of their own, not elements. */
function scopeRow(b: Uint8Array, v: FlowValue): ProtocolField {
  const r = range(v.start, v.length);
  const num = v.length <= 4 ? readUint(b, v.start, v.length) : 0n;
  switch (v.field.type) {
    case 2: return { name: 'ScopeInterface', value: v.length <= 4 ? String(num) : hexColons(b, v.start, v.start + v.length), abbrev: 'cflow.scope_interface', rawBytesRange: r };
    case 3: return { name: 'ScopeLinecard', value: v.length <= 4 ? String(num) : hexColons(b, v.start, v.start + v.length), abbrev: 'cflow.scope_linecard', rawBytesRange: r };
    case 4: return { name: 'ScopeCache', value: hexColons(b, v.start, v.start + v.length), abbrev: 'cflow.scope_cache', rawBytesRange: r };
    case 5: return { name: 'ScopeTemplate', value: hexColons(b, v.start, v.start + v.length), abbrev: 'cflow.scope_template', rawBytesRange: r };
    default: return { name: 'ScopeSystem', value: hexColons(b, v.start, v.start + v.length), abbrev: 'cflow.scope_system', rawBytesRange: r };
  }
}

/** One record's rows, in the reference's order: times wait for their pair, and what never paired comes last. */
function recordRows(b: Uint8Array, record: FlowValue[], template: StoredFlowTemplate, ipfix: boolean, exportNs: bigint): ProtocolField[] {
  const state: RecordState = { ipfix, exportNs, starts: [], ends: [] };
  const rows: ProtocolField[] = [];
  record.forEach((v, i) => {
    if (template.v9Options && i < template.scopeCount) rows.push(scopeRow(b, v));
    else rows.push(...elementRows(b, v, state));
  });
  for (let kind = 0; kind < PAIR_NAMES.length; kind++) {
    const s = state.starts[kind];
    const e = state.ends[kind];
    if (s !== undefined) rows.push(pairRow(b, s, kind, false, exportNs));
    if (e !== undefined) rows.push(pairRow(b, e, kind, true, exportNs));
  }
  return rows;
}

// --- templates ------------------------------------------------------------------

/** What a template row calls an element: `IP_SRC_ADDR`, `100 [pen: VWB Group]`, `BYTES [Reverse]`. */
function fieldTitle(field: FlowTemplateField): string {
  if (field.pen === undefined) return TYPE_NAMES[field.type] ?? `Unknown(${field.type})`;
  if (field.pen === REVERSE_PEN) return `${TYPE_NAMES[field.type] ?? `Unknown(${field.type})`} [Reverse]`;
  if (field.pen === CISCO_PEN) return CISCO_TYPE_NAMES[field.type] ?? `Unknown(${field.type})`;
  return `${field.type} [pen: ${PEN_NAMES[field.pen] ?? 'Unknown'}]`;
}

/** One template field's rows. */
function templateFieldRows(at: number, field: FlowTemplateField, ipfix: boolean, scope: boolean): ProtocolField[] {
  const lengthRow: ProtocolField = {
    name: 'Length', value: field.length === 0xffff ? '65535 [i.e.: "Variable Length"]' : field.length,
    abbrev: 'cflow.template_field_length', rawBytesRange: range(at + 2, 2),
  };
  if (!ipfix) {
    return scope
      ? [{ name: 'Scope Type', value: named(SCOPE_TYPES, field.type), abbrev: 'cflow.scope_field_type', rawBytesRange: range(at, 2) }, lengthRow]
      : [{ name: 'Type', value: named(TYPE_NAMES, field.type), abbrev: 'cflow.template_field_type', rawBytesRange: range(at, 2) }, lengthRow];
  }
  const bits = { bitOffset: 1, bitLength: 15, totalBits: 16 };
  const rows: ProtocolField[] = [{
    name: 'Pen provided', value: field.pen !== undefined ? 'Yes' : 'No', abbrev: 'cflow.template_ipfix_pen_provided',
    rawBytesRange: range(at, 2), bitfield: { bitOffset: 0, bitLength: 1, totalBits: 16 },
  }];
  if (field.pen === undefined || field.pen === REVERSE_PEN) {
    rows.push({ name: 'Type', value: `${named(TYPE_NAMES, field.type)}${field.pen === REVERSE_PEN ? ' [Reverse]' : ''}`, abbrev: 'cflow.template_ipfix_field_type', rawBytesRange: range(at, 2), bitfield: bits });
  } else if (field.pen === CISCO_PEN) {
    rows.push({ name: 'Type', value: named(CISCO_TYPE_NAMES, field.type), abbrev: 'cflow.template_cisco_field_type', rawBytesRange: range(at, 2), bitfield: bits });
  } else {
    rows.push({ name: 'Type', value: `${field.type} [pen: ${PEN_NAMES[field.pen] ?? 'Unknown'}]`, abbrev: 'cflow.template_ipfix_field_type_enterprise', rawBytesRange: range(at, 2), bitfield: bits });
  }
  rows.push(lengthRow);
  if (field.pen !== undefined) rows.push({ name: 'PEN', value: named(PEN_NAMES, field.pen), abbrev: 'cflow.template_ipfix_field_pen', rawBytesRange: range(at + 4, 4) });
  return rows;
}

/** One template's subtree. */
function templateRow(t: ParsedTemplate, ipfix: boolean, options: boolean): ProtocolField {
  const r: [number, number] = [t.start, Math.max(t.start, t.end - 1)];
  const children: ProtocolField[] = [{ name: 'Template Id', value: t.id, abbrev: 'cflow.template_id', rawBytesRange: range(t.start, 2) }];
  const scopes = t.scopeCount;
  const data = t.fields.length - scopes;
  if (!options) {
    children.push({ name: 'Field Count', value: t.fields.length, abbrev: 'cflow.template_field_count', rawBytesRange: range(t.start + 2, 2) });
  } else if (!ipfix) {
    children.push(
      { name: 'Option Scope Length', value: t.scopeLength ?? 0, abbrev: 'cflow.option_scope_length', rawBytesRange: range(t.start + 2, 2) },
      { name: 'Option Length', value: t.optionLength ?? 0, abbrev: 'cflow.option_length', rawBytesRange: range(t.start + 4, 2) },
    );
  } else {
    children.push(
      { name: 'Total Field Count', value: t.totalCount ?? 0, abbrev: 'cflow.template_ipfix_total_field_count', rawBytesRange: range(t.start + 2, 2) },
      { name: 'Scope Field Count', value: scopes, abbrev: 'cflow.template_ipfix_scope_field_count', rawBytesRange: range(t.start + 4, 2) },
    );
  }
  t.fields.forEach((field, i) => {
    const at = t.positions[i];
    const scope = options && i < scopes;
    const title = scope && !ipfix ? named(SCOPE_TYPES, field.type).replace(/ \(\d+\)$/, '') : fieldTitle(field);
    const label = scope ? `Field (${i + 1}/${scopes}) [Scope]` : `Field (${i + 1 - (options ? scopes : 0)}/${options ? data : t.fields.length})`;
    children.push({
      name: label, value: title, rawBytesRange: range(at, field.pen !== undefined ? 8 : 4),
      children: templateFieldRows(at, field, ipfix, scope),
    });
  });
  const name = options
    ? `Options Template (Id = ${t.id}) (Scope Count = ${scopes}; Data Count = ${data})`
    : `Template (Id = ${t.id}, Count = ${t.fields.length})`;
  return { name, value: '', rawBytesRange: r, children };
}

// --- the message ------------------------------------------------------------------

const SET_NAMES: Record<number, string> = {
  0: 'Data Template (V9)', 1: 'Options Template(V9)', 2: 'Data Template (V10 [IPFIX])', 3: 'Options Template (V10 [IPFIX])',
};
const setName = (id: number) => SET_NAMES[id] ?? (id >= 256 ? '(Data)' : '(Reserved)');

/**
 * An expert row: the reference's text, under a row of its own. A sequence gap
 * is records the exporter sent and this capture or the collector did not get.
 */
const expert = (message: string, abbrev: string, category: 'Broken' | 'Loss' = 'Broken'): ProtocolField => ({
  name: message, value: '', abbrev, generated: true,
  expertInfo: { category, message },
});

const pad = (n: number, width: number) => String(n).padStart(width, ' ');

/** The header's timestamp row and its parts. */
function timestampRow(h: FlowHeader, start: number): ProtocolField {
  if (h.version === 10) {
    return {
      name: 'Timestamp', value: absoluteTime(BigInt(h.unixSecs) * 1_000_000_000n), abbrev: 'cflow.timestamp', rawBytesRange: range(start + 4, 4),
      children: [{ name: 'ExportTime', value: h.unixSecs, abbrev: 'cflow.exporttime', rawBytesRange: range(start + 4, 4) }],
    };
  }
  const at = start + 8;
  const children: ProtocolField[] = [{ name: 'CurrentSecs', value: h.unixSecs, abbrev: 'cflow.unix_secs', rawBytesRange: range(at, 4) }];
  if (h.version === 5) children.push({ name: 'CurrentNSecs', value: h.unixNsecs ?? 0, abbrev: 'cflow.unix_nsecs', rawBytesRange: range(at + 4, 4) });
  const ns = BigInt(h.unixSecs) * 1_000_000_000n + BigInt(h.unixNsecs ?? 0);
  return { name: 'Timestamp', value: absoluteTime(ns), abbrev: 'cflow.timestamp', rawBytesRange: range(at, h.version === 5 ? 8 : 4), children };
}

/** A v5 record: fixed, 48 bytes. */
function v5Record(b: Uint8Array, p: number, i: number, count: number): ProtocolField {
  const ip = (o: number) => formatIpv4Address(b, p + o);
  const first = u32(b, p + 24);
  const last = u32(b, p + 28);
  const mask = (o: number, addressAt: number) => {
    const bits = b[p + o];
    const kept = bits === 0 ? 0 : (0xffffffff << (32 - Math.min(bits, 32))) >>> 0;
    const net = (u32(b, p + addressAt) & kept) >>> 0;
    return `${bits} (prefix: ${net >>> 24}.${(net >> 16) & 255}.${(net >> 8) & 255}.${net & 255}/${bits === 0 ? 32 : bits})`;
  };
  const f = (name: string, value: string | number, abbrev: string, o: number, length: number): ProtocolField =>
    ({ name, value, abbrev, rawBytesRange: range(p + o, length) });
  return {
    name: `pdu ${i + 1}/${count}`, value: '', rawBytesRange: range(p, 48),
    children: [
      f('SrcAddr', ip(0), 'cflow.srcaddr', 0, 4),
      f('DstAddr', ip(4), 'cflow.dstaddr', 4, 4),
      f('NextHop', ip(8), 'cflow.nexthop', 8, 4),
      f('InputInt', u16(b, p + 12), 'cflow.inputint', 12, 2),
      f('OutputInt', u16(b, p + 14), 'cflow.outputint', 14, 2),
      f('Packets', u32(b, p + 16), 'cflow.packets', 16, 4),
      f('Octets', u32(b, p + 20), 'cflow.octets', 20, 4),
      {
        name: 'Duration', value: relativeTime(BigInt((last - first) >>> 0) * 1_000_000n), abbrev: 'cflow.timedelta', rawBytesRange: range(p + 24, 8),
        children: [
          f('StartTime', relativeTime(BigInt(first) * 1_000_000n), 'cflow.timestart', 24, 4),
          f('EndTime', relativeTime(BigInt(last) * 1_000_000n), 'cflow.timeend', 28, 4),
        ],
      },
      f('SrcPort', u16(b, p + 32), 'cflow.srcport', 32, 2),
      f('DstPort', u16(b, p + 34), 'cflow.dstport', 34, 2),
      f('Padding', hexColons(b, p + 36, p + 37), 'cflow.padding', 36, 1),
      f('TCP Flags', `0x${b[p + 37].toString(16).padStart(2, '0')}`, 'cflow.tcpflags', 37, 1),
      f('Protocol', describeIpProtocol(b[p + 38]), 'cflow.protocol', 38, 1),
      f('IP ToS', `0x${b[p + 39].toString(16).padStart(2, '0')}`, 'cflow.tos', 39, 1),
      f('SrcAS', u16(b, p + 40), 'cflow.srcas', 40, 2),
      f('DstAS', u16(b, p + 42), 'cflow.dstas', 42, 2),
      f('SrcMask', mask(44, 0), 'cflow.srcmask', 44, 1),
      f('DstMask', mask(45, 4), 'cflow.dstmask', 45, 1),
      f('Padding', hexColons(b, p + 46, p + 48), 'cflow.padding', 46, 2),
    ],
  };
}

/** A data set: through its template, or said to have none. */
function dataSetRows(
  b: Uint8Array, set: FlowSet, template: StoredFlowTemplate | null, ipfix: boolean, exportNs: bigint,
): { rows: ProtocolField[]; records: number } {
  const contentStart = set.start + 4;
  if (template === null) {
    const length = set.end - contentStart;
    const message = `Data (${length} bytes), no template found`;
    return { rows: [{ name: message, value: '', rawBytesRange: range(contentStart, length), children: [expert(message, 'cflow.no_template_found')] }], records: 0 };
  }
  const { records, padding } = readDataRecords(b, set, template);
  const rows: ProtocolField[] = [{ name: 'Template Frame', value: template.frame, abbrev: 'cflow.template_frame', generated: true, linkToFrame: template.frame }];
  records.forEach((record, i) => {
    const first = record[0];
    const last = record[record.length - 1];
    const end = last === undefined ? contentStart : last.start + last.length;
    rows.push({
      name: `Flow ${i + 1}`, value: '', rawBytesRange: range(first?.prefixAt ?? first?.start ?? contentStart, end - (first?.prefixAt ?? first?.start ?? contentStart)),
      children: recordRows(b, record, template, ipfix, exportNs),
    });
  });
  if (padding < set.end) rows.push({ name: 'Padding', value: hexColons(b, padding, set.end), abbrev: 'cflow.padding', rawBytesRange: range(padding, set.end - padding) });
  return { rows, records: records.length };
}

/**
 * A NetFlow or IPFIX message, or null when the datagram is not one - a
 * version this build does not read, or fewer bytes than a header.
 */
export function dissectCflow(b: Uint8Array, start: number, end: number, ctx: CflowContext): LeafResult | null {
  const h = readFlowHeader(b, start, end);
  if (h === null) return null;
  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  const at = (o: number, length: number) => range(start + o, length);
  fields['cflow.version'] = h.version;
  fields['cflow.sequence'] = h.sequence;
  rows.push({ name: 'Version', value: h.version, abbrev: 'cflow.version', rawBytesRange: at(0, 2) });
  if (h.version === 10) {
    fields['cflow.len'] = h.length ?? 0;
    rows.push({ name: 'Length', value: h.length ?? 0, abbrev: 'cflow.len', rawBytesRange: at(2, 2) });
  } else {
    fields['cflow.count'] = h.count ?? 0;
    rows.push(
      { name: 'Count', value: h.count ?? 0, abbrev: 'cflow.count', rawBytesRange: at(2, 2) },
      { name: 'SysUptime', value: relativeTime(BigInt(h.sysUptimeMs ?? 0) * 1_000_000n), abbrev: 'cflow.sysuptime', rawBytesRange: at(4, 4) },
    );
  }
  rows.push(timestampRow(h, start));
  const sequenceRow: ProtocolField = { name: 'FlowSequence', value: h.sequence, abbrev: 'cflow.sequence', rawBytesRange: at(h.version === 5 ? 16 : h.version === 9 ? 12 : 8, 4) };
  rows.push(sequenceRow);
  let info: string;

  if (h.version === 5) {
    const count = h.count ?? 0;
    rows.push(
      { name: 'EngineType', value: named(ENGINE_TYPES, h.engineType ?? 0), abbrev: 'cflow.engine_type', rawBytesRange: at(20, 1) },
      { name: 'EngineId', value: h.engineId ?? 0, abbrev: 'cflow.engine_id', rawBytesRange: at(21, 1) },
      { name: 'SamplingMode', value: named(SAMPLING_MODES, h.samplingMode ?? 0), abbrev: 'cflow.samplingmode', rawBytesRange: at(22, 2), bitfield: { bitOffset: 0, bitLength: 2, totalBits: 16 } },
      { name: 'SampleRate', value: h.samplingInterval ?? 0, abbrev: 'cflow.samplerate', rawBytesRange: at(22, 2), bitfield: { bitOffset: 2, bitLength: 14, totalBits: 16 } },
    );
    if (count === 0) {
      const message = 'FlowSets impossible - PDU Count is 0';
      rows.push({ name: message, value: '', children: [expert(message, 'cflow.flowsets.impossible')] });
    }
    for (const [i, p] of v5RecordOffsets(h, end).entries()) rows.push(v5Record(b, p, i, count));
    info = `total: ${count} (v5) flow${count === 1 ? '' : 's'}`;
    return finish();
  }

  const ipfix = h.version === 10;
  const domainRow: ProtocolField = ipfix
    ? { name: 'Observation Domain Id', value: h.domain, abbrev: 'cflow.od_id', rawBytesRange: at(12, 4) }
    : { name: 'SourceId', value: h.domain, abbrev: 'cflow.source_id', rawBytesRange: at(16, 4) };
  if (ipfix) fields['cflow.od_id'] = h.domain; else fields['cflow.source_id'] = h.domain;
  rows.push(domainRow);

  // IPFIX says how long the message is; what is past that is not its.
  const declared = h.length ?? 0;
  const msgEnd = ipfix ? Math.min(end, start + Math.max(declared, 16)) : end;
  const notes: string[] = [];
  let dataRecords = 0;
  if (!ipfix && (h.count ?? 0) === 0) {
    const message = 'FlowSets impossible - PDU Count is 0';
    rows.push({ name: message, value: '', children: [expert(message, 'cflow.flowsets.impossible')] });
  } else {
    readFlowSets(b, h, msgEnd).forEach((set, i) => {
      const kind = setKind(h.version, set.id);
      const children: ProtocolField[] = [
        { name: 'FlowSet Id', value: `${setName(set.id)} (${set.id})`, abbrev: 'cflow.flowset_id', rawBytesRange: range(set.start, 2) },
        { name: 'FlowSet Length', value: set.length, abbrev: 'cflow.flowset_length', rawBytesRange: range(set.start + 2, 2) },
      ];
      let suffix = '';
      if (set.length < 4) {
        children[1].children = [expert(`Flowset Length (${set.length}) too short`, 'cflow.flowset_length.invalid')];
      } else if (kind === 'template' || kind === 'options') {
        const { templates, padding } = readTemplateSet(b, h.version, set);
        for (const t of templates) {
          children.push(templateRow(t, ipfix, kind === 'options'));
          if (!t.withdrawal) ctx.templates.define(ctx.exporter, h.domain, t.id, t, ctx.frame);
        }
        if (padding < set.end) children.push({ name: 'Padding', value: hexColons(b, padding, set.end), abbrev: 'cflow.padding', rawBytesRange: range(padding, set.end - padding) });
        const ids = templates.map((t) => t.id).join(',');
        suffix = ` (${kind === 'options' ? 'Options Template' : 'Data Template'}): ${ids}`;
        notes.push(`[${kind === 'options' ? 'Options-Template' : 'Data-Template'}:${ids}]`);
      } else if (kind === 'data') {
        const template = ctx.templates.lookup(ctx.exporter, h.domain, set.id);
        const read = dataSetRows(b, set, template, ipfix, BigInt(h.unixSecs) * 1_000_000_000n);
        children.push(...read.rows);
        dataRecords += read.records;
        if (template !== null) suffix = ` (${read.records} flows)`;
        notes.push(`[Data:${set.id}]`);
      }
      rows.push({ name: `${ipfix ? 'Set' : 'FlowSet'} ${i + 1} [id=${set.id}]${suffix}`, value: '', rawBytesRange: range(set.start, set.end - set.start), children });
    });
  }

  // v9 counts messages, IPFIX the data records sent before this one. A v9
  // message saying it holds nothing is not followed, as in the reference.
  const followed = ipfix || (h.count ?? 0) > 0;
  const next = (h.sequence + (ipfix ? dataRecords : 1)) >>> 0;
  const previous = followed ? ctx.sequence(ctx.exporter, h.domain, next, ctx.frame) : null;
  if (previous !== null && previous.expected !== h.sequence) {
    sequenceRow.value = `${h.sequence} (expected ${previous.expected})`;
    sequenceRow.children = [expert(`Unexpected flow sequence for domain ID ${h.domain} (expected ${previous.expected}, got ${h.sequence})`, 'cflow.unexpected_sequence_number', 'Loss')];
    rows.push(
      { name: 'Expected Sequence Number', value: previous.expected, abbrev: 'cflow.sequence_analysis.expected_sn', generated: true },
      { name: 'Previous Frame in Sequence', value: previous.previousFrame, abbrev: 'cflow.sequence_analysis.previous_frame', generated: true, linkToFrame: previous.previousFrame },
    );
  }
  const domain = `Obs-Domain-ID=${pad(h.domain, 5)}`;
  const tail = notes.map((n) => ` ${n}`).join('');
  if (ipfix) {
    const available = end - start;
    info = available === declared
      ? `IPFIX flow (${pad(declared, 4)} bytes) ${domain}${tail}`
      : `IPFIX partial flow (${available}/${declared} bytes) ${domain}${tail}`;
  } else {
    const count = h.count ?? 0;
    info = `total: ${count} (v9) record${count === 1 ? '' : 's'} ${domain}${tail}`;
  }
  return finish();

  function finish(): LeafResult {
    const layer: ProtocolLayer = { name: 'Cisco NetFlow/IPFIX', summary: 'Cisco NetFlow/IPFIX', rawBytesRange: [start, Math.max(start, end - 1)], fields: rows };
    return { protocolLabel: 'CFLOW', info, layer, fields };
  }
}

/** Whether a datagram's ports are NetFlow's or IPFIX's, as the reference's defaults have them. */
export function isCflowPort(srcPort: number, dstPort: number): boolean {
  const on = (p: number) => p === 2055 || p === 9996 || p === 4739;
  return on(srcPort) || on(dstPort);
}
