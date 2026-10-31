/**
 * Which subdissector takes a UDP datagram: `dissectUdpTransport`'s precedence
 * chain, in its order, as one function.
 *
 * The chain used to be an `if / else if` ladder whose conditions were read
 * where the bodies were. The QUIC lane needs the same answer without
 * dissecting - the coordinator decides from the headers alone whether a
 * datagram will reach the QUIC branch (`frameLane`) - and two copies of a
 * precedence list would drift the first time a port was added to one. So the
 * conditions live here and `udpTransport.ts` switches on the result.
 * `scripts/pipeline/quic-lane.ts` holds the QUIC answer to the dissection.
 *
 * The order is the dissector's and is not a style choice: 443 paired with
 * 53/5353/5355/137/1900/500/4500/389/3702/4789 and the rest is claimed by the
 * other protocol, not by QUIC.
 */
import { findUdpPort } from './dispatch';
import { isCflowPort } from './cflow';
import { looksLikeLdap } from './ldap';
import { isTzspPort } from './tzsp';
import { isVxlanPort, readVxlanHeader } from './vxlan';

export type UdpBranch = 'dhcp' | 'vxlan' | 'tzsp' | 'cflow' | 'port' | 'ike' | 'natt' | 'cldap'
  | 'wsd' | 'nbns' | 'dns' | 'ssdp' | 'quic' | 'none';

/**
 * The branch of `dissectUdpTransport` that takes this datagram.
 *
 * `payloadEnd` is `Math.min(bytes.length, payloadStart + max(0, udpLength - 8))`,
 * what each branch of the dissector hands its subdissector as the end.
 */
export function udpBranch(
  bytes: Uint8Array, payloadStart: number, payloadEnd: number,
  srcPort: number, dstPort: number, dstIp: string,
): UdpBranch {
  const isDhcp = (srcPort === 67 || srcPort === 68) && (dstPort === 67 || dstPort === 68);
  const isDhcpv6 = (srcPort === 546 || srcPort === 547) && (dstPort === 546 || dstPort === 547);
  if (isDhcp || isDhcpv6) return 'dhcp';
  if (isVxlanPort(srcPort, dstPort) && readVxlanHeader(bytes, payloadStart, payloadEnd) !== null) return 'vxlan';
  if (isTzspPort(srcPort, dstPort)) return 'tzsp';
  if (isCflowPort(srcPort, dstPort)) return 'cflow';
  if (findUdpPort(srcPort, dstPort, dstIp) !== null) return 'port';
  if (srcPort === 500 || dstPort === 500) return 'ike';
  if (srcPort === 4500 || dstPort === 4500) return 'natt';
  if ((srcPort === 389 || dstPort === 389) && looksLikeLdap(bytes, payloadStart, payloadEnd)) return 'cldap';
  if (srcPort === 3702 || dstPort === 3702) return 'wsd';
  if (srcPort === 137 || dstPort === 137) return 'nbns';
  if (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353 || srcPort === 5355 || dstPort === 5355) return 'dns';
  if (srcPort === 1900 || dstPort === 1900) return 'ssdp';
  if (srcPort === 443 || dstPort === 443) return 'quic';
  return 'none';
}
