/**
 * The IPv6 extension-header chain (RFC 8200 §4).
 *
 * IPv6 puts options in a linked list of headers between the fixed 40-byte
 * header and the transport one, each naming the next. Walking it is not
 * optional the moment a capture contains multicast: every MLDv2 report a
 * device sends carries a Hop-by-Hop header with a Router Alert option, so a
 * dissector that assumes the transport starts at byte 40 reads the option
 * bytes as an ICMPv6 header and reports a protocol nobody sent. Five frames
 * in one of the fixtures did exactly that.
 *
 * Lengths follow three different rules, which is the other reason this is its
 * own file: most headers are `(len + 1) * 8`, the Authentication Header is
 * `(len + 2) * 4`, and the Fragment header is a fixed 8 bytes.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { describeIpProtocol } from '../dissect/ipProtocolNames';
import { formatIpv6Address } from '../addressFormat';

export const IPV6_EXT_HEADERS: Record<number, string> = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  50: 'Encapsulating Security Payload',
  51: 'Authentication Header',
  60: 'Destination Options',
  135: 'Mobility',
  139: 'Host Identity Protocol',
  140: 'Shim6',
};

/** 59 means "nothing follows", not a protocol. */
export const NO_NEXT_HEADER = 59;

/**
 * The reference's names for each header's Next Header and Length fields, by
 * protocol number - spelled out whole, because the registry's scanner reads
 * quoted literals and a name assembled at run time is one nothing checks.
 */
const HEADER_FIELDS: Record<number, { nxt: string; len?: string; lenOct?: string }> = {
  0: { nxt: 'ipv6.hopopts.nxt', len: 'ipv6.hopopts.len', lenOct: 'ipv6.hopopts.len_oct' },
  60: { nxt: 'ipv6.dstopts.nxt', len: 'ipv6.dstopts.len', lenOct: 'ipv6.dstopts.len_oct' },
  43: { nxt: 'ipv6.routing.nxt', len: 'ipv6.routing.len', lenOct: 'ipv6.routing.len_oct' },
  44: { nxt: 'ipv6.fraghdr.nxt' },
};

/** Option names by the whole type byte - the reference's `ipv6_opt_type_vals`. */
const OPTION_NAMES: Record<number, string> = {
  0x00: 'Pad1', 0x01: 'PadN', 0x04: 'Tunnel Encapsulation Limit', 0x05: 'Router Alert', 0x07: 'CALIPSO',
  0x08: 'SMF_DPD', 0x0f: 'Performance and Diagnostic Metrics', 0x13: 'Application-Aware IPv6 Networking (APN6)',
  0x1e: 'Experimental (0x1E)', 0x23: 'RPL Option', 0x26: 'Quick-Start', 0x30: 'Path MTU Option',
  0x31: 'IOAM Option', 0x3e: 'Experimental (0x3E)', 0x41: 'Tunnel Payload Forwarding (TPF) Information',
  0x5e: 'Experimental (0x5E)', 0x63: 'RPL Option (deprecated)', 0x6d: 'MPL Option', 0x7e: 'Experimental (0x7E)',
  0x8a: 'Endpoint Identification', 0x8b: 'ILNP Nonce', 0x8c: 'Line-Identification Option',
  0x9e: 'Experimental (0x9E)', 0xbe: 'Experimental (0xBE)', 0xc2: 'Jumbo Payload', 0xc9: 'Home Address',
  0xde: 'Experimental (0xDE)', 0xee: 'IP_DFF', 0xfe: 'Experimental (0xFE)',
};

/** Routing header types - the reference's `routing_header_type`. */
const ROUTING_TYPES: Record<number, string> = {
  0: 'Source Route', 1: 'Nimrod', 2: 'Type 2 Routing', 3: 'RPL Source Route', 4: 'Segment Routing',
  5: 'Compact Routing Header 16', 6: 'Compact Routing Header 32', 253: 'Experiment 1', 254: 'Experiment 2',
};

const OPTION_ACTIONS = ['Skip and continue', 'Discard', 'Discard and send ICMP Parameter Problem', 'Discard and send ICMP if not multicast'];
const ROUTER_ALERT_VALUES = ['MLD', 'RSVP', 'Active Network'];

export interface Ipv6ExtensionChain {
  /** Layers to insert between IPv6 and the transport, outermost first. */
  layers: ProtocolLayer[];
  /** The protocol number the transport decoder should be given. */
  finalNextHeader: number;
  /** Where the transport header starts. */
  transportOffset: number;
  /** True when the chain ended in "No Next Header" or a fragment that is not the first. */
  stopsHere: boolean;
  /** Set on any fragment. Offset is in bytes, not the wire's 8-byte units. */
  fragmentOffset?: number;
  /** Whether more fragments follow. */
  moreFragments?: boolean;
  /**
   * The Fragment header's 32-bit identification.
   *
   * With the source and destination this is the whole key to a datagram -
   * RFC 8200 4.5 deliberately leaves the protocol out of it, unlike IPv4's
   * RFC 791, because the Fragment header sits above whatever the payload
   * turns out to be.
   */
  fragmentId?: number;
  /**
   * Where this fragment's share of the datagram begins - the byte after the
   * Fragment header, which is where RFC 8200's "fragmentable part" starts.
   */
  fragmentPayloadOffset?: number;
  /** Names for the [Protocols in frame] chain, e.g. ['ipv6.hopopts']. */
  protocolTokens: string[];
}

/**
 * Walks the chain from `start` (the byte after the fixed header) with
 * `firstNextHeader` from the fixed header's Next Header field.
 */
export function walkIpv6Extensions(
  b: Uint8Array, start: number, firstNextHeader: number, end: number,
): Ipv6ExtensionChain {
  const out: Ipv6ExtensionChain = {
    layers: [], finalNextHeader: firstNextHeader, transportOffset: start, stopsHere: false, protocolTokens: [],
  };
  let nextHeader = firstNextHeader;
  let p = start;
  // A chain longer than this is a denial-of-service attempt, not traffic.
  for (let guard = 0; guard < 16; guard++) {
    const name = IPV6_EXT_HEADERS[nextHeader];
    if (name === undefined) break;
    if (nextHeader === 50) { // ESP: everything after is encrypted
      out.finalNextHeader = 50;
      out.transportOffset = p;
      out.stopsHere = true;
      return out;
    }
    if (p + 2 > end) break;
    const following = b[p];
    const lenField = b[p + 1];
    const length = nextHeader === 44 ? 8 : nextHeader === 51 ? (lenField + 2) * 4 : (lenField + 1) * 8;
    if (p + length > end) break;

    // The header's own field names, as the reference spells them per header:
    // `ipv6.hopopts.nxt`, `ipv6.routing.len`, `ipv6.fraghdr.nxt`...
    const family = HEADER_FIELDS[nextHeader];
    const fields: ProtocolField[] = [
      {
        name: nextHeader === 44 ? 'Next header' : 'Next Header', value: describeIpProtocol(following), rawBytesRange: [p, p],
        ...(family ? { abbrev: family.nxt } : {}),
      },
    ];
    if (nextHeader !== 44) {
      // The length field, then what it means in bytes - two rows, as the
      // reference draws them, because the field counts 8-octet units past
      // the first and nobody reads that number directly.
      fields.push(
        { name: 'Length', value: lenField, rawBytesRange: [p + 1, p + 1], ...(family?.len ? { abbrev: family.len } : {}) },
        { name: '[Length]', value: `${length} bytes`, generated: true, ...(family?.lenOct ? { abbrev: family.lenOct } : {}) },
      );
    }

    if (nextHeader === 0 || nextHeader === 60) {
      fields.push(...tlvOptionFields(b, p + 2, p + length));
    } else if (nextHeader === 44) {
      const offsetAndFlags = (b[p + 2] << 8) | b[p + 3];
      const fragOffset = offsetAndFlags >> 3;
      const more = (offsetAndFlags & 1) === 1;
      const id = ((b[p + 4] << 24) | (b[p + 5] << 16) | (b[p + 6] << 8) | b[p + 7]) >>> 0;
      // As the reference draws them: the offset in 8-octet units and then in
      // bytes, and the two reserved fields, which a sender must zero.
      const bits16 = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 16 });
      fields.push(
        { name: 'Reserved octet', value: `0x${b[p + 1].toString(16).padStart(2, '0')}`, rawBytesRange: [p + 1, p + 1], abbrev: 'ipv6.fraghdr.reserved_octet' },
        { name: 'Offset', value: `${fragOffset} (${fragOffset * 8} bytes)`, rawBytesRange: [p + 2, p + 3], abbrev: 'ipv6.fraghdr.offset', bitfield: bits16(0, 13) },
        { name: 'Reserved bits', value: (offsetAndFlags >> 1) & 0x3, rawBytesRange: [p + 2, p + 3], abbrev: 'ipv6.fraghdr.reserved_bits', bitfield: bits16(13, 2) },
        { name: 'More Fragments', value: more ? 'Yes' : 'No', rawBytesRange: [p + 2, p + 3], abbrev: 'ipv6.fraghdr.more', bitfield: bits16(15, 1) },
        { name: 'Identification', value: `0x${id.toString(16).padStart(8, '0')}`, rawBytesRange: [p + 4, p + 7], abbrev: 'ipv6.fraghdr.ident' },
      );
      out.fragmentOffset = fragOffset * 8;
      out.moreFragments = more;
      out.fragmentId = id;
      out.fragmentPayloadOffset = p + length;
      // An "atomic fragment" - offset 0 with More Fragments clear - is not
      // fragmented at all. RFC 6946 says to process it as an ordinary packet,
      // and treating it as a one-fragment datagram to be reassembled would be
      // a pointless round trip through the tracker.
      if (fragOffset > 0 || more) {
        // The rest of this frame is the datagram's fragmentable part, not a
        // header chain to keep walking: the headers after the Fragment header
        // belong to the reassembled datagram, and in a later fragment there
        // are none at all. The caller reassembles and dissects from
        // `finalNextHeader` at `fragmentPayloadOffset`.
        out.layers.push({ name: `IPv6 ${name}`, summary: `${name} Header`, rawBytesRange: [p, p + length - 1], fields });
        out.protocolTokens.push('ipv6.fragment');
        out.finalNextHeader = following;
        out.transportOffset = p + length;
        out.stopsHere = true;
        return out;
      }
    } else if (nextHeader === 43) {
      fields.push(
        { name: 'Type', value: `${ROUTING_TYPES[b[p + 2]] ?? 'Unknown'} (${b[p + 2]})`, rawBytesRange: [p + 2, p + 2], abbrev: 'ipv6.routing.type' },
        { name: 'Segments Left', value: b[p + 3], rawBytesRange: [p + 3, p + 3], abbrev: 'ipv6.routing.segleft' },
      );
    }

    out.layers.push({ name: `IPv6 ${name}`, summary: `${name} Header`, rawBytesRange: [p, p + length - 1], fields });
    out.protocolTokens.push(tokenFor(nextHeader));
    p += length;
    nextHeader = following;
    out.finalNextHeader = nextHeader;
    out.transportOffset = p;
    if (nextHeader === NO_NEXT_HEADER) {
      out.stopsHere = true;
      return out;
    }
  }
  return out;
}

function tokenFor(n: number): string {
  switch (n) {
    case 0: return 'ipv6.hopopts';
    case 43: return 'ipv6.routing';
    case 44: return 'ipv6.fragment';
    case 51: return 'ah';
    case 60: return 'ipv6.dstopts';
    default: return 'ipv6.ext';
  }
}

/**
 * Hop-by-Hop and Destination Options carry type-length-value options, drawn
 * as packet-ipv6.c draws them: a row per option named for it (`ipv6.opt`),
 * the Type byte opened into what a node that does not know it must do and
 * whether it may change en route, then the Length and the option's own data.
 */
function tlvOptionFields(b: Uint8Array, start: number, end: number): ProtocolField[] {
  const out: ProtocolField[] = [];
  let p = start;
  while (p < end) {
    const type = b[p];
    const name = OPTION_NAMES[type] ?? `Unknown IPv6 Option (${type})`;
    const typeRow: ProtocolField = {
      name: 'Type', value: `${OPTION_NAMES[type] ?? 'Unknown'} (0x${type.toString(16).padStart(2, '0')})`,
      abbrev: 'ipv6.opt.type', rawBytesRange: [p, p],
    };
    if (type === 0) { // Pad1 has no length byte, and the reference opens no Type subtree for it
      out.push({
        name, value: '', abbrev: 'ipv6.opt', rawBytesRange: [p, p],
        children: [typeRow, { name: 'Pad1', value: '', abbrev: 'ipv6.opt.pad1', rawBytesRange: [p, p] }],
      });
      p += 1;
      continue;
    }
    if (p + 1 >= end) break;
    const len = b[p + 1];
    if (p + 2 + len > end) break;
    const bits = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 8 });
    typeRow.children = [
      { name: 'Action', value: `${OPTION_ACTIONS[type >> 6]} (${type >> 6})`, abbrev: 'ipv6.opt.type.action', rawBytesRange: [p, p], bitfield: bits(0, 2) },
      { name: 'May Change', value: type & 0x20 ? 'Yes' : 'No', abbrev: 'ipv6.opt.type.change', rawBytesRange: [p, p], bitfield: bits(2, 1) },
      { name: 'Low-Order Bits', value: `0x${(type & 0x1f).toString(16).padStart(2, '0')}`, abbrev: 'ipv6.opt.type.rest', rawBytesRange: [p, p], bitfield: bits(3, 5) },
    ];
    const children: ProtocolField[] = [
      typeRow,
      { name: 'Length', value: len, abbrev: 'ipv6.opt.length', rawBytesRange: [p + 1, p + 1] },
    ];
    const data: [number, number] = [p + 2, p + 1 + len];
    const hex = Array.from(b.subarray(p + 2, p + 2 + len), (x) => x.toString(16).padStart(2, '0')).join('');
    if (type === 0x01) {
      children.push({ name: 'PadN', value: len === 0 ? '<none>' : hex, abbrev: 'ipv6.opt.padn', ...(len > 0 ? { rawBytesRange: data } : {}) });
    } else if (type === 0x05 && len === 2) {
      const alert = (b[p + 2] << 8) | b[p + 3];
      children.push({ name: 'Router Alert', value: `${ROUTER_ALERT_VALUES[alert] ?? 'Unknown'} (${alert})`, abbrev: 'ipv6.opt.router_alert', rawBytesRange: data });
    } else if (type === 0xc2 && len === 4) {
      const jumbo = ((b[p + 2] << 24) | (b[p + 3] << 16) | (b[p + 4] << 8) | b[p + 5]) >>> 0;
      children.push({ name: 'Payload Length', value: jumbo, abbrev: 'ipv6.opt.jumbo', rawBytesRange: data });
    } else if (type === 0x04 && len === 1) {
      children.push({ name: 'Tunnel Encapsulation Limit', value: b[p + 2], abbrev: 'ipv6.opt.tel', rawBytesRange: data });
    } else if (type === 0xc9 && len === 16) {
      children.push({ name: 'MIPv6 Home Address', value: formatIpv6Address(b, p + 2), abbrev: 'ipv6.opt.mipv6.home_address', rawBytesRange: data });
    } else if (len > 0) {
      // One nobody names is the reference's own "Unknown Option Payload";
      // one it names and this build does not read is shown as bytes.
      children.push(OPTION_NAMES[type] === undefined
        ? { name: 'Unknown Option Payload', value: hex, abbrev: 'ipv6.opt.unknown', rawBytesRange: data }
        : { name: 'Data', value: hex, rawBytesRange: data });
    }
    out.push({ name, value: '', abbrev: 'ipv6.opt', rawBytesRange: [p, p + 1 + len], children });
    p += 2 + len;
  }
  return out;
}
