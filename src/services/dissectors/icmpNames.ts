/**
 * What an ICMP or ICMPv6 Type and Code are called, in the tree.
 *
 * The Type and Code rows were bare numbers - `Type: 3`, `Code: 3` - where
 * Wireshark draws `Destination unreachable (3)` and `3 (Port unreachable)`.
 * The Info column already named most of them; the tree, which is where
 * somebody reads a router's explanation of why a packet did not arrive, did
 * not.
 *
 * **The names, and the shape of each row, are the reference's own.** They were
 * read off tshark 4.6.8 by building one frame for every type and every code
 * and asking it how it draws each, and `scripts/parity/header-names.ts` does
 * that again on every run and fails on any row that differs. The shapes it
 * found, which a reasonable person would not guess:
 *
 * - **Type** is always `Name (n)`, and `Unknown (n)` for an unassigned type.
 * - **Code** is named only under the types that have a code table. Everywhere
 *   else it is the bare number, even when non-zero: an echo request with code
 *   5 is `Code: 5`.
 * - **An unlisted code under a type that has a table** reads differently in
 *   each protocol: ICMPv4 writes `7 (Unknown code: 7)`, ICMPv6 writes
 *   `11 (Unknown (11))` - and `9 (Unknown)` under Destination Unreachable
 *   alone.
 *
 * Not the Info column's names, which `icmp.ts` keeps: that column is its own
 * contract with the reference (lower-case ICMPv6 unreachable codes, padded
 * echo text) and `parity-check.ts` holds it separately.
 */

/** ICMPv4 types (`icmp.type`). */
const ICMP_TYPES: Record<number, string> = {
  0: 'Echo (ping) reply', 1: 'Reserved', 2: 'Reserved', 3: 'Destination unreachable',
  4: 'Source quench (flow control)', 5: 'Redirect', 6: 'Alternate host address',
  8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation',
  11: 'Time-to-live exceeded', 12: 'Parameter problem', 13: 'Timestamp request',
  14: 'Timestamp reply', 15: 'Information request', 16: 'Information reply',
  17: 'Address mask request', 18: 'Address mask reply', 19: 'Reserved (for security)',
  30: 'Traceroute', 31: 'Datagram Conversion Error', 32: 'Mobile Host Redirect',
  33: 'IPv6 Where-Are-You', 34: 'IPv6 I-Am-Here', 35: 'Mobile Registration Request',
  36: 'Mobile Registration Reply', 37: 'Domain Name Request', 38: 'Domain Name Reply', 39: 'SKIP',
  40: 'Photuris', 41: 'Experimental mobility protocols', 42: 'Extended Echo request',
  43: 'Extended Echo reply',
};

/** ICMPv4 codes, under the types the reference names them for. */
const ICMP_CODES: Record<number, Record<number, string>> = {
  3: {
    0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable',
    3: 'Port unreachable', 4: 'Fragmentation needed', 5: 'Source route failed',
    6: 'Destination network unknown', 7: 'Destination host unknown', 8: 'Source host isolated',
    9: 'Network administratively prohibited', 10: 'Host administratively prohibited',
    11: 'Network unreachable for TOS', 12: 'Host unreachable for TOS',
    13: 'Communication administratively filtered', 14: 'Host precedence violation',
    15: 'Precedence cutoff in effect',
  },
  5: {
    0: 'Redirect for network', 1: 'Redirect for host', 2: 'Redirect for TOS and network',
    3: 'Redirect for TOS and host',
  },
  6: {
    0: 'Alternate address for host',
  },
  9: {
    0: 'Normal router advertisement', 16: 'Does not route common traffic',
  },
  11: {
    0: 'Time to live exceeded in transit', 1: 'Fragment reassembly time exceeded',
  },
  12: {
    0: 'Pointer indicates the error', 1: 'Required option missing', 2: 'Bad length',
  },
  40: {
    0: 'Bad SPI', 1: 'Authentication Failed', 2: 'Decompression Failed', 3: 'Decryption Failed',
    4: 'Need Authentication', 5: 'Need Authorization',
  },
  42: {
    0: 'No error',
  },
  43: {
    0: 'No error', 1: 'Malformed Query', 2: 'No Such Interface', 3: 'No Such Table Entry',
    4: 'Multiple Interfaces Satisfy Query',
  },
};

/** ICMPv6 types (`icmpv6.type`). */
const ICMPV6_TYPES: Record<number, string> = {
  1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem',
  100: 'Private experimentation', 101: 'Private experimentation',
  127: 'Reserved for expansion of ICMPv6 error messages', 128: 'Echo (ping) request',
  129: 'Echo (ping) reply', 130: 'Multicast Listener Query', 131: 'Multicast Listener Report',
  132: 'Multicast Listener Done', 133: 'Router Solicitation', 134: 'Router Advertisement',
  135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect',
  138: 'Router Renumbering', 139: 'Node Information Query', 140: 'Node Information Reply',
  141: 'Inverse Neighbor Discovery Solicitation', 142: 'Inverse Neighbor Discovery Advertisement',
  143: 'Multicast Listener Report Message v2', 144: 'Home Agent Address Discovery Request',
  145: 'Home Agent Address Discovery Reply', 146: 'Mobile Prefix Solicitation',
  147: 'Mobile Prefix Advertisement', 148: 'Certification Path Solicitation',
  149: 'Certification Path Advertisement', 150: 'Experimental Mobility',
  151: 'Multicast Router Advertisement', 152: 'Multicast Router Solicitation',
  153: 'Multicast Router Termination', 154: 'FMIPv6', 155: 'RPL Control', 156: 'Locator Update',
  157: 'Duplicate Address Request', 158: 'Duplicate Address Confirmation',
  159: 'MPL Control Message', 160: 'Extended Echo request', 161: 'Extended Echo reply',
  200: 'Private experimentation', 201: 'Private experimentation',
  255: 'Reserved for expansion of ICMPv6 informational messages',
};

/** ICMPv6 codes, under the types the reference names them for. */
const ICMPV6_CODES: Record<number, Record<number, string>> = {
  1: {
    0: 'No route to destination', 1: 'Administratively prohibited',
    2: 'Beyond scope of source address', 3: 'Address unreachable', 4: 'Port unreachable',
    5: 'Source address failed ingress/egress policy', 6: 'Reject route to destination',
    7: 'Error in Source Routing Header', 8: 'Headers too long',
  },
  3: {
    0: 'Hop limit exceeded in transit', 1: 'Fragment reassembly time exceeded',
  },
  4: {
    0: 'Erroneous header field encountered', 1: 'Unrecognized Next Header type encountered',
    2: 'Unrecognized IPv6 option encountered',
    3: 'IPv6 First Fragment has incomplete IPv6 Header Chain', 4: 'SR Upper-layer Header Error',
    5: 'Unrecognized Next Header type encountered by intermediate node',
    6: 'Extension header too big', 7: 'Extension header chain too long',
    8: 'Too many extension headers', 9: 'Too many options in extension header',
    10: 'Option too big',
  },
  138: {
    0: 'Command', 1: 'Result',
  },
  139: {
    0: 'Query subject = IPv6 addresses', 1: 'Query subject = DNS name or empty',
    2: 'Query subject = IPv4 addresses',
  },
  140: {
    0: 'Successful', 1: 'Refused', 2: 'Unknown query type',
  },
  155: {
    0: 'DODAG Information Solicitation', 1: 'DODAG Information Object',
    2: 'Destination Advertisement Object', 3: 'Destination Advertisement Object Acknowledgment',
    4: 'P2P Discovery Reply Object', 5: 'P2P Discovery Reply Object Acknowledgement',
    7: 'Destination Cleanup Object', 8: 'Destination Cleanup Object Acknowledgment',
  },
  160: {
    0: 'No error',
  },
  161: {
    0: 'No error', 1: 'Malformed Query', 2: 'No Such Interface', 3: 'No Such Table Entry',
    4: 'Multiple Interfaces Satisfy Query',
  },
};

/** `Echo (ping) request (8)`; `Unknown (n)` for an unassigned type. */
export function icmpTypeValue(isIcmpv6: boolean, type: number): string {
  return `${(isIcmpv6 ? ICMPV6_TYPES : ICMP_TYPES)[type] ?? 'Unknown'} (${type})`;
}

/**
 * `3 (Port unreachable)` under a type with a code table, otherwise the bare
 * number - see the module comment for the three shapes.
 */
export function icmpCodeValue(isIcmpv6: boolean, type: number, code: number): string | number {
  const table = (isIcmpv6 ? ICMPV6_CODES : ICMP_CODES)[type];
  if (table === undefined) return code;
  const name = table[code];
  if (name !== undefined) return `${code} (${name})`;
  if (!isIcmpv6) return `${code} (Unknown code: ${code})`;
  return type === 1 ? `${code} (Unknown)` : `${code} (Unknown (${code}))`;
}
