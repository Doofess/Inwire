/**
 * VXLAN (RFC 7348), the second tunnel and the first that re-enters at layer 2.
 *
 * GRE carries an inner *network* packet, so reading it meant calling
 * `decodeNetworkLayer` again at a new offset - the one thing ADR 0023 built
 * that signature for. Skipping an inner Ethernet header is not new either:
 * GRE's Transparent Ethernet Bridging type does it. What that case does NOT do
 * is dispatch on the inner ethertype - `innerNetworkStart` in `gre.ts` reads
 * the fourteen bytes and then **declines anything that is not inner IP**.
 *
 * VXLAN cannot decline it, because an overlay's ARP is not an edge case: it is
 * how the overlay learns where anything is. So this is the first tunnel that
 * needs the ethertype dispatch, and that dispatch lives in
 * `decodeRawEthernetPacket` rather than in `decodeNetworkLayer`. Rather than
 * lift the whole chain out for one caller, the two cases that occur inside an
 * overlay go to the same functions the outer frame uses - `decodeNetworkLayer`
 * for IP, `dissectArp` for ARP.
 *
 * ## The reference looks THROUGH it, as it does through GRE
 *
 * Asked directly (tshark 4.6.8), a VXLAN frame carrying an ICMP echo between
 * 10.1.1.1 and 10.2.2.2 reports `ICMP`, those two addresses, and the echo's own
 * Info. The word VXLAN appears in no column. So a half-tunnel that names itself
 * and stops is wrong on four columns at once, two of them at 100%.
 *
 * Inner ARP is the case that makes this different from GRE, and it is the
 * common one on an overlay: the reference reports the inner **MACs** -
 * `0a:00:00:00:00:01` -> `Broadcast` - because ARP has no layer-3 addresses to
 * report. The outer frame's MACs, which `pcapParser` has already put in those
 * columns, are the wrong pair.
 *
 * ## What was measured rather than read off the RFC
 *
 *  - **Port 8472 decodes too.** Linux shipped VXLAN on it before IANA assigned
 *    4789 and the kernel still defaults to it, so a capture from a Linux host
 *    is full of it.
 *  - **Port 4790 does NOT.** That is VXLAN-GPE, whose header replaces the first
 *    reserved byte with a next-protocol field, so reading it as RFC 7348 finds
 *    the inner frame at the right offset but describes it with the wrong
 *    header. The reference declines it; so does this.
 *  - **The I flag is ignored.** RFC 7348 says a receiver MUST drop a packet
 *    with the VNI-valid bit clear, and tshark dissects it anyway. Matched,
 *    because a capture is not a receiver: a frame the network dropped is still
 *    a frame somebody needs to see.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';
import { formatMac } from '../addressFormat';
import { describeEtherType, macAddressFields } from './linkLayer';

/**
 * The ports that carry RFC 7348 VXLAN.
 *
 * 4790 is deliberately absent - see the note above.
 */
export const VXLAN_PORTS: ReadonlySet<number> = new Set([4789, 8472]);

/** True when a UDP datagram between these ports should be read as VXLAN. */
export function isVxlanPort(srcPort: number, dstPort: number): boolean {
  return VXLAN_PORTS.has(dstPort) || VXLAN_PORTS.has(srcPort);
}

/** The fixed VXLAN header, and the inner Ethernet frame's own header. */
export const VXLAN_HEADER_LENGTH = 8;
const ETHERNET_HEADER_LENGTH = 14;

export interface VxlanHeader {
  vni: number;
  flags: number;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * The eight-byte header: flags, three reserved, a 24-bit VNI, one reserved.
 *
 * Returns null only when the bytes are not there. A header whose reserved bits
 * are set is still read - the reference reads it, and a capture that hid a
 * malformed frame would be hiding the thing worth looking at.
 */
export function readVxlanHeader(
  bytes: Uint8Array, start: number, end: number,
): VxlanHeader | null {
  if (start + VXLAN_HEADER_LENGTH > end) return null;
  const flags = bytes[start];
  const vni = (bytes[start + 4] << 16) | (bytes[start + 5] << 8) | bytes[start + 6];
  const vniValid = (flags & 0x08) !== 0;

  const rows: ProtocolField[] = [
    {
      name: 'Flags',
      value: `0x${flags.toString(16).padStart(2, '0')}`,
      abbrev: 'vxlan.flags',
      rawBytesRange: [start, start],
      children: [{
        name: vniValid ? 'VXLAN Network ID (VNI): Set' : 'VXLAN Network ID (VNI): Not set',
        value: vniValid ? '1' : '0',
        abbrev: 'vxlan.flag_i',
      }],
    },
    {
      name: 'VXLAN Network Identifier (VNI)',
      value: String(vni),
      abbrev: 'vxlan.vni',
      rawBytesRange: [start + 4, start + 6],
    },
  ];

  return {
    vni,
    flags,
    fields: { 'vxlan.vni': vni, 'vxlan.flags': flags, 'vxlan.flag_i': vniValid ? 1 : 0 },
    layer: {
      name: 'Virtual eXtensible Local Area Network',
      summary: `Virtual eXtensible Local Area Network, VNI: ${vni}`,
      fields: rows,
    },
  };
}

export interface InnerEthernet {
  srcMac: string;
  dstMac: string;
  etherType: number;
  /** Where the inner network header starts. */
  l3Offset: number;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * The encapsulated Ethernet header.
 *
 * Ethernet II only, and that is the format rather than a shortcut: RFC 7348
 * defines the VXLAN payload as an Ethernet frame, and an 802.3 length field
 * inside an overlay is not a thing that occurs. `eth.src`/`eth.dst` are NOT
 * written into `filterFields` from here - the outer frame already claimed those
 * keys, and a dense column holds one value per frame, so the inner pair would
 * either overwrite the outer or be dropped depending on assignment order.
 * Both are wrong; the tree row carries them instead, which is where a reader
 * looking at a tunnel expects to find them.
 */
export function readInnerEthernet(
  bytes: Uint8Array, start: number, end: number,
): InnerEthernet | null {
  if (start + ETHERNET_HEADER_LENGTH > end) return null;
  const dstMac = formatMac(bytes.slice(start, start + 6));
  const srcMac = formatMac(bytes.slice(start + 6, start + 12));
  const etherType = (bytes[start + 12] << 8) | bytes[start + 13];

  return {
    srcMac,
    dstMac,
    etherType,
    l3Offset: start + ETHERNET_HEADER_LENGTH,
    fields: {},
    layer: {
      name: 'Ethernet II',
      summary: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
      fields: [
        {
          name: 'Destination',
          value: dstMac,
          rawBytesRange: [start, start + 5],
          children: macAddressFields(dstMac, start, true),
        },
        {
          name: 'Source',
          value: srcMac,
          rawBytesRange: [start + 6, start + 11],
          children: macAddressFields(srcMac, start + 6),
        },
        {
          name: 'Type',
          value: `${describeEtherType(etherType)} (0x${etherType.toString(16).padStart(4, '0')})`,
          rawBytesRange: [start + 12, start + 13],
        },
      ],
    },
  };
}
