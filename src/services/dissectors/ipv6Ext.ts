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

const OPTION_NAMES: Record<number, string> = {
  0: 'Pad1', 1: 'PadN', 5: 'Router Alert', 6: 'Quick-Start', 7: 'CALIPSO', 8: 'SMF_DPD',
  0xc2: 'Jumbo Payload', 0x26: 'Quick-Start', 0x4d: 'Deprecated', 0x6d: 'MPL Option', 0xc9: 'Home Address',
};

const ROUTER_ALERT_VALUES: Record<number, string> = {
  0: 'MLD (0)', 1: 'RSVP (1)', 2: 'Active Networks (2)',
};

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

    const fields: ProtocolField[] = [
      { name: 'Next Header', value: `${headerName(following)} (${following})`, rawBytesRange: [p, p] },
    ];
    if (nextHeader !== 44) {
      fields.push({ name: 'Length', value: `${lenField} (${length} bytes)`, rawBytesRange: [p + 1, p + 1] });
    }

    if (nextHeader === 0 || nextHeader === 60) {
      fields.push(...tlvOptionFields(b, p + 2, p + length));
    } else if (nextHeader === 44) {
      const offsetAndFlags = (b[p + 2] << 8) | b[p + 3];
      const fragOffset = offsetAndFlags >> 3;
      const more = (offsetAndFlags & 1) === 1;
      const id = ((b[p + 4] << 24) | (b[p + 5] << 16) | (b[p + 6] << 8) | b[p + 7]) >>> 0;
      fields.push(
        { name: 'Offset', value: fragOffset * 8, rawBytesRange: [p + 2, p + 3], abbrev: 'ipv6.fraghdr.offset' },
        { name: 'More Fragments', value: more ? 'Yes' : 'No', rawBytesRange: [p + 3, p + 3], abbrev: 'ipv6.fraghdr.more' },
        { name: 'Identification', value: `0x${id.toString(16).padStart(8, '0')}`, rawBytesRange: [p + 4, p + 7] },
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
        { name: 'Routing Type', value: b[p + 2], rawBytesRange: [p + 2, p + 2] },
        { name: 'Segments Left', value: b[p + 3], rawBytesRange: [p + 3, p + 3] },
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

function headerName(n: number): string {
  if (n === NO_NEXT_HEADER) return 'No Next Header';
  return IPV6_EXT_HEADERS[n] ?? (n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 58 ? 'ICMPv6' : 'Unknown');
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

/** Hop-by-Hop and Destination Options carry type-length-value options. */
function tlvOptionFields(b: Uint8Array, start: number, end: number): ProtocolField[] {
  const out: ProtocolField[] = [];
  let p = start;
  while (p < end) {
    const type = b[p];
    if (type === 0) { // Pad1 has no length byte
      out.push({ name: 'PadN', value: 'Pad1', rawBytesRange: [p, p] });
      p += 1;
      continue;
    }
    if (p + 1 >= end) break;
    const len = b[p + 1];
    if (p + 2 + len > end) break;
    const name = OPTION_NAMES[type] ?? `Unknown (0x${type.toString(16).padStart(2, '0')})`;
    let value = `${len} bytes`;
    if (type === 5 && len === 2) {
      const alert = (b[p + 2] << 8) | b[p + 3];
      value = ROUTER_ALERT_VALUES[alert] ?? String(alert);
    } else if (type === 1) {
      value = `${len} bytes of padding`;
    }
    out.push({
      name: `IPv6 Option (${name})`, value, rawBytesRange: [p, p + 1 + len],
      ...(type === 5 ? { abbrev: 'ipv6.opt.router_alert' } : {}),
    });
    p += 2 + len;
  }
  return out;
}
