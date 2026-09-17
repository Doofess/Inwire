/**
 * GRE (RFC 2784, with RFC 2890's key and sequence), and the first tunnel here.
 *
 * A tunnel is not a protocol you name - it is a protocol you look *through*.
 * Asked directly, tshark reports the **inner** packet in every column: a GRE
 * datagram from 192.0.2.1 to 192.0.2.2 carrying an ICMP echo between 10.1.1.1
 * and 10.2.2.2 shows `ICMP`, the echo's own Info, and **10.1.1.1 -> 10.2.2.2**.
 * The word "GRE" appears only when there is nothing readable inside.
 *
 * That is why a half-tunnel is worse than none: naming the frame `GRE` and
 * stopping would be wrong on Protocol, Info, Source *and* Destination at once,
 * and Source/Destination are the two columns this build holds at 100%. It is
 * also why this file only reads the header - the recursion belongs to
 * `networkLayer.ts`, which owns the addresses and can call itself.
 *
 * Every rule below was read off the oracle rather than the RFC; the RFC does
 * not say what a column should print. They are pinned in `scripts/gre/dissect.ts`.
 */
import type { ProtocolLayer, ProtocolField } from '../../types/packet';

/** GRE's IP protocol number. */
export const GRE_PROTOCOL = 47;

/** Transparent Ethernet Bridging - the payload is a whole Ethernet frame. */
const ETHERTYPE_TRANSPARENT_ETHERNET = 0x6558;

const FLAG_CHECKSUM = 0x8000;   // C, bit 0
const FLAG_KEY = 0x2000;        // K, bit 2 (RFC 2890)
const FLAG_SEQUENCE = 0x1000;   // S, bit 3 (RFC 2890)
const VERSION_MASK = 0x0007;

/**
 * How the reference names a payload it is not going to dissect.
 *
 * `Encapsulated IP` rather than `Encapsulated IPv4`, which is the sort of thing
 * only the oracle tells you, and an unknown type is rendered as its hex value
 * followed by `(unknown)`.
 */
const ENCAPSULATED_NAMES: Record<number, string> = {
  0x0800: 'IP',
  0x86dd: 'IPv6',
  [ETHERTYPE_TRANSPARENT_ETHERNET]: 'Transparent Ethernet bridging',
};

/** The Info line for a GRE frame whose payload this build will not open. */
export function encapsulatedInfo(protocolType: number): string {
  const known = ENCAPSULATED_NAMES[protocolType];
  return `Encapsulated ${known ?? `0x${protocolType.toString(16).padStart(4, '0')} (unknown)`}`;
}

export interface GreHeader {
  /** Bytes from the start of the GRE header to the start of its payload. */
  headerLength: number;
  /** The ethertype of what it carries. */
  protocolType: number;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/**
 * Reads a GRE header, or null when these bytes are not one.
 *
 * Null rather than a guess on anything malformed, and version 1 is refused:
 * that is PPTP's GRE, which has a different header shape (an acknowledgement
 * number, and a payload length where the key's upper half sits) and reading it
 * as RFC 2784 would put the payload at the wrong offset.
 */
export function readGreHeader(bytes: Uint8Array, start: number, end: number): GreHeader | null {
  if (end - start < 4) return null;
  const flags = (bytes[start] << 8) | bytes[start + 1];
  const protocolType = (bytes[start + 2] << 8) | bytes[start + 3];
  if ((flags & VERSION_MASK) !== 0) return null;

  let offset = start + 4;
  const rows: ProtocolField[] = [
    {
      name: 'Flags and Version',
      value: `0x${flags.toString(16).padStart(4, '0')}`,
      children: [
        { name: 'Checksum Bit', value: (flags & FLAG_CHECKSUM) !== 0 ? 'Set' : 'Not set' },
        { name: 'Key Bit', value: (flags & FLAG_KEY) !== 0 ? 'Set' : 'Not set' },
        { name: 'Sequence Number Bit', value: (flags & FLAG_SEQUENCE) !== 0 ? 'Set' : 'Not set' },
        { name: 'Version', value: flags & VERSION_MASK },
      ],
    },
    {
      name: 'Protocol Type',
      value: `${ENCAPSULATED_NAMES[protocolType] ?? 'Unknown'} (0x${protocolType.toString(16).padStart(4, '0')})`,
      abbrev: 'gre.proto',
    },
  ];
  const fields: Record<string, string | number> = { 'gre.proto': protocolType };

  if ((flags & FLAG_CHECKSUM) !== 0) {
    // The checksum word is followed by a reserved word, present or not - both
    // are there whenever C is set, which is the one place RFC 2784 differs from
    // the older RFC 1701 layout it replaced.
    if (end - offset < 4) return null;
    const checksum = (bytes[offset] << 8) | bytes[offset + 1];
    rows.push({ name: 'Checksum', value: `0x${checksum.toString(16).padStart(4, '0')}`, abbrev: 'gre.checksum' });
    fields['gre.checksum'] = checksum;
    offset += 4;
  }
  if ((flags & FLAG_KEY) !== 0) {
    if (end - offset < 4) return null;
    const key = ((bytes[offset] << 24) | (bytes[offset + 1] << 16)
      | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    rows.push({ name: 'Key', value: key, abbrev: 'gre.key' });
    fields['gre.key'] = key;
    offset += 4;
  }
  if ((flags & FLAG_SEQUENCE) !== 0) {
    if (end - offset < 4) return null;
    const sequence = ((bytes[offset] << 24) | (bytes[offset + 1] << 16)
      | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    rows.push({ name: 'Sequence Number', value: sequence, abbrev: 'gre.sequence_number' });
    fields['gre.sequence_number'] = sequence;
    offset += 4;
  }

  return {
    headerLength: offset - start,
    protocolType,
    fields,
    layer: {
      name: 'Generic Routing Encapsulation',
      summary: `Generic Routing Encapsulation (${ENCAPSULATED_NAMES[protocolType] ?? 'unknown'})`,
      rawBytesRange: [start, offset - 1],
      fields: rows,
    },
  };
}

/**
 * Where the inner *network* header starts, and what ethertype to read it as.
 *
 * For IPv4 and IPv6 that is the payload itself. For Transparent Ethernet
 * Bridging the payload is a whole Ethernet frame, so the inner network header
 * is 14 bytes further on and its ethertype comes from the inner frame - which
 * is why this returns both numbers rather than just an offset.
 *
 * Null when there is nothing to recurse into, which is the only case where the
 * frame reads as `GRE` at all.
 */
export function innerNetworkStart(
  bytes: Uint8Array, payloadStart: number, protocolType: number, end: number,
): { offset: number; etherType: number } | null {
  if (protocolType === 0x0800 || protocolType === 0x86dd) {
    return end - payloadStart > 0 ? { offset: payloadStart, etherType: protocolType } : null;
  }
  if (protocolType === ETHERTYPE_TRANSPARENT_ETHERNET) {
    // A minimum Ethernet header plus something after it. VLAN tags inside the
    // bridged frame are not unwrapped here - that is the link layer's job and
    // this is the network layer's - so a tagged inner frame reads as GRE rather
    // than being decoded one tag deep and reported wrongly.
    if (end - payloadStart < 15) return null;
    const innerType = (bytes[payloadStart + 12] << 8) | bytes[payloadStart + 13];
    if (innerType !== 0x0800 && innerType !== 0x86dd) return null;
    return { offset: payloadStart + 14, etherType: innerType };
  }
  return null;
}
