/**
 * The protocols that sit directly on IP with no ports at all.
 *
 * IGMP, VRRP and OSPF are dispatched by IP protocol number rather than by port,
 * which is what separates them from everything in `udpDispatch.ts`. They were
 * three `else if` arms inside `decodeTransportLayer`, each carrying the same
 * comment explaining that it is not port-based - and a comment repeated three
 * times is a grouping the code has not made yet.
 *
 * `proto` is `'ICMP'` for all three, and deliberately: the coarse
 * `ProtocolType` union has no member for any of them, `protocolLabel` is what
 * the Protocol column and the parity harness actually read, and ICMP is the
 * closest existing key for "sits on IP, has no ports". Changing that union is a
 * wider change than these three protocols justify.
 */
import type { TransportResult } from '../dissect/types';
import { dissectIgmp } from './igmp';
import { dissectVrrp } from './vrrp';
import { dissectOspf } from './ospf';

/** IP protocol numbers this module claims. */
export const IGMP_PROTOCOL = 2;
export const OSPF_PROTOCOL = 89;
export const VRRP_PROTOCOL = 112;

/** True when `dissectPortless` is the right decoder for this protocol number. */
export function isPortlessProtocol(ipProtocolNum: number): boolean {
  return ipProtocolNum === IGMP_PROTOCOL
    || ipProtocolNum === VRRP_PROTOCOL
    || ipProtocolNum === OSPF_PROTOCOL;
}

/**
 * Reads whichever of the three this is, or null when the bytes are not it.
 *
 * `end` comes from the network layer's declared length rather than from
 * `rawBytes.length`, because a real Ethernet frame is padded up to 60 bytes and
 * counting that padding as payload is how a short IGMP report grows a tail.
 */
export function dissectPortless(
  rawBytes: Uint8Array,
  transportOffset: number,
  ipProtocolNum: number,
  l4SegmentLen?: number,
): TransportResult | null {
  const length = l4SegmentLen ?? rawBytes.length - transportOffset;
  const read = ipProtocolNum === IGMP_PROTOCOL
    ? dissectIgmp(rawBytes, transportOffset, length)
    : ipProtocolNum === VRRP_PROTOCOL
      ? dissectVrrp(rawBytes, transportOffset, transportOffset + length)
      : dissectOspf(rawBytes, transportOffset, transportOffset + length);
  if (!read) return null;
  return {
    proto: 'ICMP',
    protocolLabel: read.protocolLabel,
    info: read.info,
    fields: read.fields,
    layer: read.layer,
  };
}
