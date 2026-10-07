/**
 * TZSP, the TaZmen Sniffer Protocol (UDP 37008): how a router streams the
 * packets it mirrors to a collector somewhere else. MikroTik's packet sniffer
 * sends it, so does its "sniff" firewall action, and a few wireless access
 * points - which makes it the cheapest way to see a whole network's traffic
 * from one PC: the router copies every frame it forwards into a datagram to
 * this machine.
 *
 * A four-byte header - version, type, encapsulation - then a list of tagged
 * options ending in an End tag, then the mirrored frame itself. Like VXLAN and
 * GRE, the reference looks THROUGH it: a TZSP datagram carrying a TCP SYN
 * between two other hosts reports `TCP` and those two hosts in every column.
 * So this module only reads the header and the options and says where the
 * frame starts; `networkLayer.ts` (`decodeTzspFrame`) dissects the frame,
 * which is where every other tunnel's inner packet is read too.
 *
 * Shapes from `tshark -T pdml` (4.6.8) on frames built for every branch
 * (`scripts/tzsp/dissect.ts`), including the reference's own quirks:
 *
 * - **Any datagram on 37008 is TZSP**, however short; one that ends early is
 *   a malformed one, not plain UDP.
 * - **Keepalive (4) and port opener (5) carry nothing** - no options and no
 *   frame - while every other type, including transmit and configuration,
 *   reads both.
 * - **The version is not checked**: a version 2 header is read as version 1.
 * - **"FCS Error" is appended to the layer's heading with no separator**
 *   (`Tazmen Sniffer Protocol: EthernetFCS Error`) when the FCS option says
 *   the frame was damaged. Matched, because the heading is what a reader
 *   compares against Wireshark.
 * - **An encapsulation it has no dissector for** reads `UNKNOWN` in the
 *   Protocol column and `TZSP_ENCAP = n` in Info, with the frame as data -
 *   but only once the options have been read; a datagram that ends inside
 *   them is `TZSP`, `Unknown (n)`.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatMac } from '../addressFormat';
import { resolveMacVendor } from '../macVendors';
import { formatArrivalTime } from '../dissect/arrivalTime';
import { hexColons } from '../dissect/hexBytes';

export const TZSP_PORT = 37008;

/** True when a UDP datagram between these ports is TZSP. */
export function isTzspPort(srcPort: number, dstPort: number): boolean {
  return srcPort === TZSP_PORT || dstPort === TZSP_PORT;
}

const TYPES: Readonly<Record<number, string>> = {
  0: 'Received packet', 1: 'Packet for transmit', 3: 'Configuration', 4: 'Keepalive', 5: 'Port opener',
};
const TYPE_KEEPALIVE = 4;
const TYPE_PORT_OPENER = 5;

const ENCAPSULATIONS: Readonly<Record<number, string>> = {
  1: 'Ethernet', 2: 'Token Ring', 3: 'SLIP', 4: 'PPP', 5: 'FDDI', 7: 'Raw IP', 18: 'IEEE 802.11',
  119: 'IEEE 802.11 with Prism headers', 126: 'IEEE 802.11 with radiotap headers',
  127: 'IEEE 802.11 with AVS headers',
};
/**
 * The encapsulations the reference hands to a dissector of its own. Any other
 * - SLIP, named above, as much as a number nobody names - reads `UNKNOWN`
 * and `TZSP_ENCAP = n`, with the frame as data.
 */
const DISSECTED_BY_REFERENCE: ReadonlySet<number> = new Set([1, 2, 4, 5, 7, 18, 119, 126, 127]);
export const TZSP_ENCAP_ETHERNET = 1;
export const TZSP_ENCAP_RAW_IP = 7;

const TAGS: Readonly<Record<number, string>> = {
  0: 'Pad', 1: 'End', 10: 'Signal', 11: 'Silence', 12: 'Rate', 13: 'Time', 14: 'Message Type',
  15: 'Point Coordination Function', 16: 'Undecrypted', 17: 'Frame check sequence', 18: 'Channel',
  40: 'packet ID', 41: 'Original Length', 60: 'Sensor MAC', 80: 'Device Name', 81: 'Capture Location',
  82: 'Time Stamp', 83: 'Information', 84: 'Capture ID',
};
const TAG_PAD = 0;
const TAG_END = 1;

/** 802.11 rates, in the two units the options use: 100 kbit/s and 500 kbit/s. */
const RATES: Readonly<Record<number, string>> = {
  10: '1 Mbit/s', 20: '2 Mbit/s', 55: '5.5 Mbit/s', 110: '11 Mbit/s',
  2: '1 Mbit/s', 4: '2 Mbit/s', 11: '5.5 Mbit/s', 12: '6 Mbit/s', 18: '9 Mbit/s', 22: '11 Mbit/s',
  24: '12 Mbit/s', 36: '18 Mbit/s', 48: '24 Mbit/s', 72: '36 Mbit/s', 96: '48 Mbit/s', 108: '54 Mbit/s',
};
const MESSAGE_TYPES: Readonly<Record<number, string>> = {
  0: 'Normal', 1: 'RFC1042 encoded', 2: 'Bridge-tunnel encoded', 4: '802.11 management frame',
};

/**
 * A channel's name and centre frequency, for the channels the reference
 * names: all of 2.4 GHz, 5 GHz's 36-64 and 149-161, and 6 GHz.
 */
function channelName(channel: number): string | undefined {
  let mhz: number | undefined;
  if (channel >= 1 && channel <= 13) mhz = 2407 + 5 * channel;
  else if (channel === 14) mhz = 2484;
  else if ((channel >= 36 && channel <= 64 && channel % 4 === 0)
    || (channel >= 149 && channel <= 161 && channel % 4 === 1)) mhz = 5000 + 5 * channel;
  else if (channel >= 191 && channel <= 423 && (channel - 191) % 4 === 0) mhz = 5950 + 5 * (channel - 190);
  return mhz === undefined ? undefined : `${channel} (${(mhz / 1000).toFixed(3)} GHz)`;
}

const named = (table: Readonly<Record<number, string>>, value: number) => `${table[value] ?? 'Unknown'} (${value})`;
const int8 = (v: number) => (v << 24) >> 24;
const int16 = (v: number) => (v << 16) >> 16;
const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const u32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const decoder = new TextDecoder();

export interface TzspResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /**
   * The mirrored frame, when there is one: where it lies and how it is
   * encapsulated. Absent for a keepalive, a port opener, and a header the
   * datagram ended inside.
   */
  frame?: { offset: number; end: number; encapsulation: number };
  /** The datagram ended inside the header or the options. */
  malformed: boolean;
}

/** The malformed row, as every dissector here that can run out of bytes draws it. */
export function malformedRow(protocol: string): ProtocolField {
  return {
    name: `[Malformed Packet: ${protocol}]`, value: '', generated: true,
    expertInfo: { category: 'Broken', message: 'Malformed Packet (Exception occurred)' },
  };
}

/** The header and the options, and where the frame after them is. */
export function dissectTzsp(b: Uint8Array, start: number, end: number): TzspResult | null {
  if (start >= end) return null;
  const rows: ProtocolField[] = [];
  const layer: ProtocolLayer = {
    name: 'Tazmen Sniffer Protocol', summary: 'Tazmen Sniffer Protocol', fields: rows,
    rawBytesRange: [start, end - 1],
  };
  const fields: Record<string, string | number> = {};
  const result: TzspResult = { protocolLabel: 'TZSP', info: '', layer, fields, malformed: false };
  const fail = (): TzspResult => {
    result.malformed = true;
    result.info += '[Malformed Packet]';
    rows.push(malformedRow('TZSP'));
    return result;
  };

  rows.push({ name: 'Version', value: b[start], abbrev: 'tzsp.version', rawBytesRange: [start, start] });
  fields['tzsp.version'] = b[start];
  if (start + 2 > end) return fail();
  const type = b[start + 1];
  rows.push({ name: 'Type', value: named(TYPES, type), abbrev: 'tzsp.type', rawBytesRange: [start + 1, start + 1] });
  fields['tzsp.type'] = type;
  if (start + 4 > end) return fail();
  const encapsulation = u16(b, start + 2);
  const encapName = ENCAPSULATIONS[encapsulation];
  rows.push({ name: 'Encapsulation', value: named(ENCAPSULATIONS, encapsulation), abbrev: 'tzsp.encap', rawBytesRange: [start + 2, start + 3] });
  fields['tzsp.encap'] = encapsulation;
  layer.summary = `Tazmen Sniffer Protocol: ${encapName ?? `Unknown (${encapsulation})`}`;
  result.info = encapName ?? `Unknown (${encapsulation})`;
  if (type === TYPE_KEEPALIVE || type === TYPE_PORT_OPENER) return result;

  let at = start + 4;
  for (;;) {
    if (at >= end) return fail();
    const tag = b[at];
    const tagRow: ProtocolField = { name: 'Option Tag', value: named(TAGS, tag), abbrev: 'tzsp.option_tag', rawBytesRange: [at, at] };
    rows.push(tagRow);
    at++;
    if (tag === TAG_END) break;
    if (tag === TAG_PAD) continue;
    if (at >= end) return fail();
    const length = b[at];
    rows.push({ name: 'Option Length', value: length, abbrev: 'tzsp.option_length', rawBytesRange: [at, at] });
    at++;
    const value = optionRow(b, tag, at, length, end);
    if (value === null) return fail();
    rows.push(value.row);
    if (value.fcsError) layer.summary += 'FCS Error';
    at += length;
  }

  // Only once the options are read: a datagram that ends inside them keeps
  // the encapsulation's name in Info, as the reference's does.
  if (!DISSECTED_BY_REFERENCE.has(encapsulation)) {
    result.protocolLabel = 'UNKNOWN';
    result.info = `TZSP_ENCAP = ${encapsulation}`;
  }
  result.frame = { offset: at, end, encapsulation };
  return result;
}

/**
 * One option's value row, read as the reference reads it: a fixed-size field
 * at the option's start whatever its declared length - a two-byte signal is
 * its first byte - except the channel, the strings and the unknown tag, which
 * take the length. Null when the bytes are not there.
 */
function optionRow(
  b: Uint8Array, tag: number, at: number, length: number, end: number,
): { row: ProtocolField; fcsError?: boolean } | null {
  const fixed = (size: number) => (at + size <= end ? [at, at + size - 1] as [number, number] : null);
  const one = fixed(1);
  switch (tag) {
    case 10: case 11: {
      if (one === null) return null;
      return { row: { name: tag === 10 ? 'Signal' : 'Silence', value: int8(b[at]), abbrev: tag === 10 ? 'tzsp.wlan.signal' : 'tzsp.wlan.silence', rawBytesRange: one } };
    }
    case 12:
      if (one === null) return null;
      return { row: { name: 'Rate', value: named(RATES, b[at]), abbrev: 'tzsp.wlan.rate', rawBytesRange: one } };
    case 13: {
      const range = fixed(4);
      if (range === null) return null;
      return { row: { name: 'Time', value: `0x${u32(b, at).toString(16).padStart(8, '0')}`, abbrev: 'tzsp.wlan.time', rawBytesRange: range } };
    }
    case 14:
      if (one === null) return null;
      return { row: { name: 'Type', value: `${MESSAGE_TYPES[b[at]] ?? 'Unknown'} (0x${b[at].toString(16).padStart(2, '0')})`, abbrev: 'tzsp.wlan.status.msg_type', rawBytesRange: one } };
    case 15: case 16: case 17: {
      if (one === null) return null;
      const set = b[at] !== 0;
      const [name, abbrev, yes, no] = tag === 15
        ? ['PCF', 'tzsp.wlan.status.pcf', 'CF: Frame received during CF period', 'Not CF']
        : tag === 16
          ? ['Undecrypted', 'tzsp.wlan.status.undecrypted', 'Encrypted frame could not be decrypted', 'Unencrypted']
          : ['FCS', 'tzsp.wlan.status.fcs_err', 'FCS error, frame is corrupted', 'Frame is valid'];
      return { row: { name, value: set ? yes : no, abbrev, rawBytesRange: one }, fcsError: tag === 17 && set };
    }
    case 18: {
      // The one option read at its declared width: a 6 GHz channel past 255
      // needs two bytes, and the reference reads two when two are declared.
      const range = fixed(length >= 2 ? 2 : 1);
      if (range === null) return null;
      const channel = length >= 2 ? u16(b, at) : b[at];
      return { row: { name: 'Channel', value: `${channelName(channel) ?? 'Unknown'} (${channel})`, abbrev: 'tzsp.wlan.channel', rawBytesRange: range } };
    }
    case 40: case 84: {
      const range = fixed(4);
      if (range === null) return null;
      return { row: tag === 40
        ? { name: 'Packet Id', value: u32(b, at), abbrev: 'tzsp.packet_id', rawBytesRange: range }
        : { name: 'Capture Id', value: u32(b, at), abbrev: 'tzsp.device_id', rawBytesRange: range } };
    }
    case 41: {
      const range = fixed(2);
      if (range === null) return null;
      return { row: { name: 'Original Length', value: int16(u16(b, at)), abbrev: 'tzsp.original_length', rawBytesRange: range } };
    }
    case 60: {
      const range = fixed(6);
      if (range === null) return null;
      return { row: { name: 'Sensor Address', value: resolveMacVendor(formatMac(b.subarray(at, at + 6))), abbrev: 'tzsp.sensormac', rawBytesRange: range } };
    }
    case 80: case 81: case 83: {
      if (at + length > end) return null;
      const text = decoder.decode(b.subarray(at, at + length));
      const [name, abbrev] = tag === 80 ? ['Device Name', 'tzsp.device_name']
        : tag === 81 ? ['Capture Location', 'tzsp.capture_location'] : ['Capture Information', 'tzsp.device_info'];
      return { row: { name, value: text, abbrev, ...(length > 0 ? { rawBytesRange: [at, at + length - 1] as [number, number] } : {}) } };
    }
    case 82: {
      const range = fixed(4);
      if (range === null) return null;
      return { row: { name: 'Time Stamp', value: formatArrivalTime(u32(b, at) * 1_000_000), abbrev: 'tzsp.time_stamp', rawBytesRange: range } };
    }
    default:
      if (at + length > end) return null;
      return { row: { name: 'Unknown tag', value: hexColons(b, at, at + length), abbrev: 'tzsp.unknown', ...(length > 0 ? { rawBytesRange: [at, at + length - 1] as [number, number] } : {}) } };
  }
}

