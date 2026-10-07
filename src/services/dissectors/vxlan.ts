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

/** The fixed VXLAN header. */
export const VXLAN_HEADER_LENGTH = 8;

export interface VxlanHeader {
  vni: number;
  flags: number;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** The four flags the reference names, by bit, in its words and its order. */
const FLAG_NAMES: readonly [number, string][] = [
  [0x8000, 'GBP Extension'], [0x0800, 'VXLAN Network ID (VNI)'], [0x0040, "Don't Learn"], [0x0008, 'Policy Applied'],
];
/** Every bit of the flags word that is none of the four. */
const FLAGS_RESERVED = 0x77b7;

/**
 * The eight-byte header as the reference reads it: a 16-bit flags word (RFC
 * 7348's I flag, and the Group Policy extension's G, D and A), the Group
 * Policy ID, the 24-bit VNI, and a reserved byte.
 *
 * Returns null only when the bytes are not there. A header whose reserved bits
 * are set is still read - the reference reads it, and a capture that hid a
 * malformed frame would be hiding the thing worth looking at.
 */
export function readVxlanHeader(
  bytes: Uint8Array, start: number, end: number,
): VxlanHeader | null {
  if (start + VXLAN_HEADER_LENGTH > end) return null;
  const flags = (bytes[start] << 8) | bytes[start + 1];
  const gbp = (bytes[start + 2] << 8) | bytes[start + 3];
  const vni = (bytes[start + 4] << 16) | (bytes[start + 5] << 8) | bytes[start + 6];
  const set = (bit: number) => (flags & bit) !== 0;
  const hex4 = (n: number) => `0x${n.toString(16).padStart(4, '0')}`;
  const named = FLAG_NAMES.filter(([bit]) => set(bit)).map(([, name]) => name);
  const flagRange: [number, number] = [start, start + 1];

  const rows: ProtocolField[] = [
    {
      name: 'Flags',
      value: [hex4(flags), ...named].join(', '),
      abbrev: 'vxlan.flags',
      rawBytesRange: flagRange,
      children: [
        { name: 'GBP Extension', value: set(0x8000) ? 'Defined' : 'Not defined', abbrev: 'vxlan.flag_g', rawBytesRange: flagRange },
        { name: 'VXLAN Network ID (VNI)', value: set(0x0800), abbrev: 'vxlan.flag_i', rawBytesRange: flagRange },
        { name: "Don't Learn", value: set(0x0040), abbrev: 'vxlan.flag_d', rawBytesRange: flagRange },
        { name: 'Policy Applied', value: set(0x0008), abbrev: 'vxlan.flag_a', rawBytesRange: flagRange },
        { name: 'Reserved(R)', value: hex4(flags & FLAGS_RESERVED), abbrev: 'vxlan.flags_reserved', rawBytesRange: flagRange },
      ],
    },
    { name: 'Group Policy ID', value: String(gbp), abbrev: 'vxlan.gbp', rawBytesRange: [start + 2, start + 3] },
    { name: 'VXLAN Network Identifier (VNI)', value: String(vni), abbrev: 'vxlan.vni', rawBytesRange: [start + 4, start + 6] },
    { name: 'Reserved', value: String(bytes[start + 7]), abbrev: 'vxlan.reserved8', rawBytesRange: [start + 7, start + 7] },
  ];

  return {
    vni,
    flags,
    fields: { 'vxlan.vni': vni, 'vxlan.flags': flags, 'vxlan.flag_i': set(0x0800) ? 1 : 0 },
    layer: {
      name: 'Virtual eXtensible Local Area Network',
      summary: 'Virtual eXtensible Local Area Network',
      rawBytesRange: [start, start + VXLAN_HEADER_LENGTH - 1],
      fields: rows,
    },
  };
}
