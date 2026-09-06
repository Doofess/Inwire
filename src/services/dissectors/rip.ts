/**
 * RIP (RFC 2453) on UDP 520, and RIPng (RFC 2080) on UDP 521.
 *
 *   Response
 *    Command Response, Version 1
 *
 * Old, still deployed, and the simplest possible thing that is genuinely a
 * routing protocol: a router shouts its whole table every thirty seconds. It
 * is worth reading precisely because it is unauthenticated by default and
 * trivially spoofable - an unexpected RIP Response on a network is either a
 * misconfiguration or an attempt to redirect traffic, and either way the
 * capture is where it shows up.
 *
 * The two versions share a name and almost nothing else, and this is one
 * dissector rather than two only because they share a three-byte preamble.
 * RIPng's entries are IPv6 prefixes with a prefix length; RIPv2's are an
 * address, a mask, a next hop and a route tag in the space RIPv1 left zero.
 * **The Info lines differ in a way that looks like a bug and is not**: the
 * reference analyzer writes `Response` for RIP and ` Command Response, Version
 * 1` for RIPng - a leading space, a different word order, and the version
 * spelled out. Matching it means copying both, which is why they are written
 * out separately below rather than shared.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';

export interface RipResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

const REQUEST = 1, RESPONSE = 2;

const COMMANDS: Record<number, string> = {
  [REQUEST]: 'Request',
  [RESPONSE]: 'Response',
  // The three obsolete commands, named so an old implementation is not read as
  // a corrupt modern one.
  3: 'Traceon', 4: 'Traceoff', 5: 'Sun Reserved',
};

/** RIPv2's entries are 20 bytes; so are RIPng's, for different reasons. */
const ENTRY_BYTES = 20;
const HEADER_BYTES = 4;

/** RIP's own "unreachable", which is the whole of its loop avoidance. */
const INFINITY = 16;

export function dissectRip(bytes: Uint8Array, start: number, end: number, ipv6 = false): RipResult | null {
  if (start + HEADER_BYTES > end) return null;
  const command = bytes[start];
  const version = bytes[start + 1];
  const commandName = COMMANDS[command];
  if (commandName === undefined) return null;
  // RIPv1 and v2 over IPv4; RIPng is version 1 over IPv6. Anything else is
  // not RIP, and the version check is most of what keeps this off other
  // traffic given how little structure the header has.
  if (!ipv6 && version !== 1 && version !== 2) return null;
  if (ipv6 && version !== 1) return null;
  // Bytes 2-3 are "must be zero" in every version, and are the only fixed
  // value in the header - so they are the fingerprint.
  if (bytes[start + 2] !== 0 || bytes[start + 3] !== 0) return null;

  const fields: Record<string, string | number> = {
    'rip.command': command,
    'rip.version': version,
  };
  const rows: ProtocolField[] = [
    { name: 'Command', value: `${commandName} (${command})`, abbrev: 'rip.command',
      rawBytesRange: [start, start] },
    { name: 'Version', value: `${ipv6 ? 'RIPng' : `RIPv${version}`} (${version})`,
      abbrev: 'rip.version', rawBytesRange: [start + 1, start + 1] },
  ];

  let routes = 0;
  for (let p = start + HEADER_BYTES; p + ENTRY_BYTES <= end; p += ENTRY_BYTES) {
    routes++;
    if (ipv6) {
      const prefix = formatIpv6Address(bytes, p);
      const routeTag = (bytes[p + 16] << 8) | bytes[p + 17];
      const prefixLength = bytes[p + 18];
      const metric = bytes[p + 19];
      rows.push({ name: 'IP Address', value: `${prefix}/${prefixLength}, Metric: ${metric}`,
        abbrev: 'rip.ip', rawBytesRange: [p, p + ENTRY_BYTES - 1],
        children: [
          { name: 'IPv6 Prefix', value: prefix, abbrev: 'rip.ip' },
          { name: 'Route Tag', value: routeTag, abbrev: 'rip.route_tag' },
          { name: 'Prefix length', value: prefixLength },
          { name: 'Metric', value: metric === INFINITY ? `${metric} (unreachable)` : metric,
            abbrev: 'rip.metric' },
        ] });
      if (routes === 1) { fields['rip.ip'] = prefix; fields['rip.metric'] = metric; }
    } else {
      const family = (bytes[p] << 8) | bytes[p + 1];
      const routeTag = (bytes[p + 2] << 8) | bytes[p + 3];
      const address = formatIpv4Address(bytes, p + 4);
      const mask = formatIpv4Address(bytes, p + 8);
      const nextHop = formatIpv4Address(bytes, p + 12);
      const metric = ((bytes[p + 16] << 24) | (bytes[p + 17] << 16)
        | (bytes[p + 18] << 8) | bytes[p + 19]) >>> 0;
      rows.push({ name: 'IP Address', value: `${address}, Metric: ${metric}`,
        abbrev: 'rip.ip', rawBytesRange: [p, p + ENTRY_BYTES - 1],
        children: [
          { name: 'Address Family', value: family === 2 ? 'IP (2)' : `${family}`,
            abbrev: 'rip.family' },
          { name: 'Route Tag', value: routeTag, abbrev: 'rip.route_tag' },
          { name: 'IP Address', value: address, abbrev: 'rip.ip' },
          { name: 'Netmask', value: mask, abbrev: 'rip.netmask' },
          { name: 'Next Hop', value: nextHop, abbrev: 'rip.next_hop' },
          { name: 'Metric', value: metric === INFINITY ? `${metric} (unreachable)` : metric,
            abbrev: 'rip.metric' },
        ] });
      if (routes === 1) { fields['rip.ip'] = address; fields['rip.metric'] = metric; }
    }
  }
  fields['rip.route_count'] = routes;

  return {
    protocolLabel: ipv6 ? 'RIPng' : `RIPv${version}`,
    // Two spellings, deliberately. See the header comment - the reference
    // analyzer's RIPng Info opens with a space and names the version, and its
    // RIP Info is the bare command.
    info: ipv6 ? ` Command ${commandName}, Version ${version}` : commandName,
    fields,
    layer: {
      name: ipv6 ? 'RIPng' : 'Routing Information Protocol',
      summary: ipv6 ? 'RIPng' : 'Routing Information Protocol',
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}

/**
 * RIPng, which is the same header over IPv6 entries.
 *
 * A separate entry point rather than a flag at the call site, because the two
 * arrive on different ports and the dispatch table's job is to name which
 * dissector reads which port - not to carry an argument that changes what a
 * dissector means.
 */
export function dissectRipng(bytes: Uint8Array, start: number, end: number): RipResult | null {
  return dissectRip(bytes, start, end, true);
}
