/**
 * Which subdissector reads a UDP payload, by the ports it arrived on.
 *
 * This was an `else if` chain in `pcapParser.ts` with one block per protocol,
 * each of them the same eight lines: run the dissector, and on a result copy
 * `protocolLabel`, `info`, the layer, the token and the fields into the
 * variables the caller is assembling. Six copies of it was tolerable; the
 * batch of leaf protocols that followed would have made it thirteen, and a
 * chain that long is where a missing `protocolTokens.push` hides - which is
 * exactly the bug `PROTOCOL_NAME_MAP` had for NTP and STUN.
 *
 * Only the **simple** protocols live here: the ones whose whole output is a
 * label, an Info line, one tree layer and a bag of fields. DHCP, DNS, NBNS and
 * QUIC stay where they are, because each returns something more - resolved
 * names, a matched query frame, a tracker's state - and folding them into a
 * table would mean the table's result type carried four optional members that
 * nine of thirteen entries never set.
 */
import type { ProtocolLayer } from '../../types/packet';
import { dissectSip } from './sip';
import { dissectSnmp } from './snmp';
import { dissectSyslog } from './syslog';
import { dissectRadius } from './radius';
import { dissectTftp } from './tftp';
import { dissectNbds } from './nbds';
import { dissectBfd, dissectBfdEcho } from './bfd';
import { dissectCoap } from './coap';
import { dissectPtp } from './ptp';
import { dissectHsrp, HSRP_V1_GROUP, HSRP_V2_GROUP } from './hsrp';
import { dissectRip, dissectRipng } from './rip';
import { dissectKerberosDatagram, KERBEROS_PORT } from './kerberos';

/** Everything a leaf UDP dissector produces. */
export interface SimpleUdpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

export interface UdpSubdissector {
  /** The filter token to push, which is also the `LAYERS` entry. */
  token: string;
  /**
   * Does this protocol claim a datagram between these ports?
   *
   * The destination address is here for HSRP alone, and it is not a
   * refinement - see `dissectors/hsrp.ts`.
   */
  claims(srcPort: number, dstPort: number, dstAddress: string): boolean;
  dissect(bytes: Uint8Array, start: number, end: number): SimpleUdpResult | null;
}

/** Claims a datagram with any of these ports at either end. */
const onPorts = (...ports: readonly number[]) =>
  (srcPort: number, dstPort: number): boolean =>
    ports.includes(srcPort) || ports.includes(dstPort);

/**
 * The table, in no significant order - a datagram matches at most one entry
 * because no two claim a port in common, which `scripts/dissect/udp-ports.ts`
 * asserts rather than assumes.
 */
export const UDP_SUBDISSECTORS: readonly UdpSubdissector[] = [
  { token: 'sip', claims: onPorts(5060, 5061), dissect: dissectSip },
  { token: 'snmp', claims: onPorts(161, 162), dissect: dissectSnmp },
  { token: 'syslog', claims: onPorts(514), dissect: dissectSyslog },
  // 1645/1646 are the pre-standard ports a lot of kit still ships with.
  { token: 'radius', claims: onPorts(1812, 1813, 1645, 1646), dissect: dissectRadius },
  { token: 'tftp', claims: onPorts(69), dissect: dissectTftp },
  // The KDC answers on 88 over both transports. A datagram carries exactly
  // one message and no length prefix, which is the whole difference from the
  // TCP side in `tcpTransport.ts`.
  { token: 'kerberos', claims: onPorts(KERBEROS_PORT), dissect: dissectKerberosDatagram },
  { token: 'nbdgm', claims: onPorts(138), dissect: dissectNbds },
  // 4784 is multihop and carries the same control header. 3785 does NOT - it
  // is the echo port, and an echo packet has no format at all.
  { token: 'bfd', claims: onPorts(3784, 4784), dissect: dissectBfd },
  { token: 'bfd', claims: onPorts(3785), dissect: dissectBfdEcho },
  { token: 'coap', claims: onPorts(5683, 5684), dissect: dissectCoap },
  { token: 'ptp', claims: onPorts(319, 320), dissect: dissectPtp },
  {
    token: 'hsrp',
    // The one entry that reads the destination address. A datagram on port
    // 1985 addressed to a host is not HSRP - see `dissectors/hsrp.ts`.
    claims: (srcPort, dstPort, dstAddress) =>
      (srcPort === 1985 || dstPort === 1985 || srcPort === 2029 || dstPort === 2029)
      && (dstAddress === HSRP_V1_GROUP || dstAddress === HSRP_V2_GROUP),
    dissect: dissectHsrp,
  },
  { token: 'rip', claims: onPorts(520), dissect: dissectRip },
  { token: 'ripng', claims: onPorts(521), dissect: dissectRipng },
];

/** Whichever subdissector claims these ports, or null. */
export function findUdpSubdissector(
  srcPort: number, dstPort: number, dstAddress: string,
): UdpSubdissector | null {
  for (const candidate of UDP_SUBDISSECTORS) {
    if (candidate.claims(srcPort, dstPort, dstAddress)) return candidate;
  }
  return null;
}
