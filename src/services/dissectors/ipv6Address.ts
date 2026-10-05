/**
 * What an IPv6 address says about itself, drawn under its row as Wireshark
 * draws it (`add_ipv6_address_detail` and its neighbours in packet-ipv6.c).
 *
 * An engineer reads an IPv6 address by its kind before its digits: link-local
 * or global, which multicast scope, whether IANA set the block aside and what
 * for, and - for an address built from a MAC (SLAAC) or a tunnel (6to4,
 * Teredo, ISATAP) - the MAC or IPv4 address inside it. The reference shows all
 * of it on every IPv6 frame; this tree showed an address space, by a rule of
 * its own that named two spaces the reference does not have.
 *
 * Every row the reference draws twice - once for the side (`ipv6.src_*`) and
 * once, hidden, for either end (`ipv6.addr_*`) - is drawn here as the side's
 * row with its either-end twin beneath the address's own `ipv6.addr` row, the
 * way `hostAliasRows` already hangs `ipv6.addr` and `ipv6.host`.
 *
 * Not ported: the NAT64 embedded-IPv4 rows, whose prefixes are a preference.
 */
import type { ProtocolField } from '../../types/packet';

interface SpecialBlock {
  prefix: readonly number[];
  bits: number;
  name: string;
  /** 1 true, 0 false, -1 not applicable - IANA's own three answers. */
  source: number; destination: number; forwardable: number; global: number; reserved: number;
}

/**
 * IANA's IPv6 Special-Purpose Address Registry, as `epan/iana-ip-data.c`
 * carries it - sorted, and looked up the same way (below), because the blocks
 * overlap (2001::/23 holds TEREDO's 2001::/32) and which one an address lands
 * in is decided by the search, not by the longest prefix.
 */
const BLOCKS: readonly SpecialBlock[] = [
  { prefix: [], bits: 128, name: 'Unspecified Address', source: 1, destination: 0, forwardable: 0, global: 0, reserved: 1 },
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], bits: 128, name: 'Loopback Address', source: 0, destination: 0, forwardable: 0, global: 0, reserved: 1 },
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], bits: 96, name: 'IPv4-mapped Address', source: 0, destination: 0, forwardable: 0, global: 0, reserved: 1 },
  { prefix: [0, 0x64, 0xff, 0x9b], bits: 96, name: 'IPv4-IPv6 Translat.', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0, 0x64, 0xff, 0x9b, 0, 1], bits: 48, name: 'IPv4-IPv6 Translat.', source: 1, destination: 1, forwardable: 1, global: 0, reserved: 0 },
  { prefix: [1], bits: 64, name: 'Discard-Only Address Block', source: 1, destination: 1, forwardable: 1, global: 0, reserved: 0 },
  { prefix: [1, 0, 0, 0, 0, 0, 0, 1], bits: 64, name: 'Dummy IPv6 Prefix', source: 1, destination: 0, forwardable: 0, global: 0, reserved: 0 },
  { prefix: [0x20, 0x01], bits: 23, name: 'IETF Protocol Assignments', source: -1, destination: -1, forwardable: -1, global: -1, reserved: 0 },
  { prefix: [0x20, 0x01], bits: 32, name: 'TEREDO', source: 1, destination: 1, forwardable: 1, global: -1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], bits: 128, name: 'Port Control Protocol Anycast', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], bits: 128, name: 'Traversal Using Relays around NAT Anycast', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3], bits: 128, name: 'DNS-SD Service Registration Protocol Anycast', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 2], bits: 48, name: 'Benchmarking', source: 1, destination: 1, forwardable: 1, global: 0, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 3], bits: 32, name: 'AMT', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 4, 1, 0x12], bits: 48, name: 'AS112-v6', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 0x20], bits: 28, name: 'ORCHIDv2', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0, 0x30], bits: 28, name: 'Drone Remote ID Protocol Entity Tags (DETs) Prefix', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x20, 0x01, 0x0d, 0xb8], bits: 32, name: 'Documentation', source: 0, destination: 0, forwardable: 0, global: 0, reserved: 0 },
  { prefix: [0x20, 0x02], bits: 16, name: '6to4', source: 1, destination: 1, forwardable: 1, global: -1, reserved: 0 },
  { prefix: [0x26, 0x20, 0, 0x4f, 0x80], bits: 48, name: 'Direct Delegation AS112 Service', source: 1, destination: 1, forwardable: 1, global: 1, reserved: 0 },
  { prefix: [0x3f, 0xff], bits: 20, name: 'Documentation', source: 0, destination: 0, forwardable: 0, global: 0, reserved: 0 },
  { prefix: [0x5f], bits: 16, name: 'Segment Routing (SRv6) SIDs', source: 1, destination: 1, forwardable: 1, global: 0, reserved: 0 },
  { prefix: [0xfc], bits: 7, name: 'Unique-Local', source: 1, destination: 1, forwardable: 1, global: -1, reserved: 0 },
  { prefix: [0xfe, 0x80], bits: 10, name: 'Link-Local Unicast', source: 1, destination: 1, forwardable: 0, global: 0, reserved: 1 },
];

const PARTIAL_MASK = [0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff];

/** `compare_ipv6_block`: the address against a block, over the block's prefix. */
function compareBlock(bytes: Uint8Array, at: number, block: SpecialBlock): number {
  let bits = block.bits;
  let pos = 0;
  while (bits >= 8) {
    const a = bytes[at + pos];
    const b = block.prefix[pos] ?? 0;
    if (a !== b) return a - b;
    bits -= 8;
    pos++;
  }
  if (bits !== 0) {
    const a = bytes[at + pos] & PARTIAL_MASK[bits];
    const b = block.prefix[pos] ?? 0;
    if (a !== b) return a - b;
  }
  return 0;
}

/**
 * The reference's `bsearch`, step for step. With overlapping blocks a binary
 * search answers by which entries it happens to visit, so the search itself is
 * part of the answer: this is the one the Windows C runtime runs, which is the
 * build `scripts/parity/ipv6-address.ts` holds it to.
 */
function lookupBlock(bytes: Uint8Array, at: number): SpecialBlock | undefined {
  let lo = 0;
  let hi = BLOCKS.length - 1;
  let num = BLOCKS.length;
  while (lo <= hi) {
    const half = num >> 1;
    if (half !== 0) {
      const mid = lo + ((num & 1) ? half : half - 1);
      const result = compareBlock(bytes, at, BLOCKS[mid]);
      if (result === 0) return BLOCKS[mid];
      if (result < 0) {
        hi = mid - 1;
        num = (num & 1) ? half : half - 1;
      } else {
        lo = mid + 1;
        num = half;
      }
    } else if (num !== 0) {
      return compareBlock(bytes, at, BLOCKS[lo]) === 0 ? BLOCKS[lo] : undefined;
    } else {
      break;
    }
  }
  return undefined;
}

/** The IANA Address Space registry, by the reference's own tests and in its order. */
export function ipv6AddressSpace(bytes: Uint8Array, at: number): string {
  const first = bytes[at];
  if (first === 0xff) return 'Multicast';
  if ((((first << 8) | bytes[at + 1]) & 0xffc0) === 0xfe80) return 'Link-Local Unicast';
  if ((first & 0x30) === 0x20) return 'Global Unicast';
  if ((first & 0xfe) === 0xfc) return 'Unique Local Unicast';
  return 'Reserved by IETF';
}

const SCOPES = [
  'Reserved', 'Interface-Local scope', 'Link-Local scope', 'Realm-Local scope', 'Admin-Local scope',
  'Site-Local scope', 'Unassigned', 'Unassigned', 'Organization-Local scope', 'Unassigned', 'Unassigned',
  'Unassigned', 'Unassigned', 'Unassigned', 'Global scope', 'Reserved',
];

const bool = (v: number) => (v ? 'True' : 'False');

/**
 * Every literal spelled out, side by side with its either-end twin, so the
 * registry's scanner can see each name (see `HOST_ALIASES` in networkLayer.ts).
 */
const NAMES = {
  Source: {
    space: 'ipv6.src_addr_space', flags: 'ipv6.src_multicast_flags', reserved: 'ipv6.src_multicast_flags.reserved',
    embedRp: 'ipv6.src_multicast_flags.embed_rp', prefix: 'ipv6.src_multicast_flags.network_prefix',
    transient: 'ipv6.src_multicast_flags.transient', scope: 'ipv6.src_multicast_scope',
    special: 'ipv6.src_special_purpose', source: 'ipv6.src_special_purpose_source',
    destination: 'ipv6.src_special_purpose_destination', forwardable: 'ipv6.src_special_purpose_forwardable',
    global: 'ipv6.src_special_purpose_global', reservedBy: 'ipv6.src_special_purpose_reserved',
  },
  Destination: {
    space: 'ipv6.dst_addr_space', flags: 'ipv6.dst_multicast_flags', reserved: 'ipv6.dst_multicast_flags.reserved',
    embedRp: 'ipv6.dst_multicast_flags.embed_rp', prefix: 'ipv6.dst_multicast_flags.network_prefix',
    transient: 'ipv6.dst_multicast_flags.transient', scope: 'ipv6.dst_multicast_scope',
    special: 'ipv6.dst_special_purpose', source: 'ipv6.dst_special_purpose_source',
    destination: 'ipv6.dst_special_purpose_destination', forwardable: 'ipv6.dst_special_purpose_forwardable',
    global: 'ipv6.dst_special_purpose_global', reservedBy: 'ipv6.dst_special_purpose_reserved',
  },
  Either: {
    space: 'ipv6.addr_space', flags: 'ipv6.multicast_flags', reserved: 'ipv6.multicast_flags.reserved',
    embedRp: 'ipv6.multicast_flags.embed_rp', prefix: 'ipv6.multicast_flags.network_prefix',
    transient: 'ipv6.multicast_flags.transient', scope: 'ipv6.multicast_scope',
    special: 'ipv6.addr_special_purpose', source: 'ipv6.addr_special_purpose_source',
    destination: 'ipv6.addr_special_purpose_destination', forwardable: 'ipv6.addr_special_purpose_forwardable',
    global: 'ipv6.addr_special_purpose_global', reservedBy: 'ipv6.addr_special_purpose_reserved',
  },
} as const;

/**
 * The detail rows of the address at `at`, for one side or for either end:
 * its space, a multicast address's flags and scope, and the special-purpose
 * block it falls in with IANA's five answers about it.
 */
export function ipv6AddressDetail(bytes: Uint8Array, at: number, side: keyof typeof NAMES): ProtocolField[] {
  const n = NAMES[side];
  const range: [number, number] = [at, at + 15];
  const rows: ProtocolField[] = [
    { name: '[Address Space]', value: ipv6AddressSpace(bytes, at), abbrev: n.space, generated: true, rawBytesRange: [at, at + 1] },
  ];
  if (bytes[at] === 0xff) {
    const word = (bytes[at] << 8) | bytes[at + 1];
    const bit = (mask: number) => (word & mask) !== 0;
    const field = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 16 });
    // A bitmask row names the flags that are set after its value, as the
    // reference's does - Reserved is a number rather than a flag, so never.
    const set = ([[0x0040, 'Rendezvous Point (RP)'], [0x0020, 'Network Prefix'], [0x0010, 'Transient']] as const)
      .filter(([mask]) => bit(mask)).map(([, name]) => `, ${name}`).join('');
    rows.push({
      name: '[Multicast Flags]', value: `0x${((word & 0x00f0) >> 4).toString(16)}${set}`, abbrev: n.flags, generated: true,
      rawBytesRange: [at, at + 1], bitfield: field(8, 4),
      children: [
        { name: 'Reserved', value: bit(0x0080) ? 1 : 0, abbrev: n.reserved, rawBytesRange: [at, at + 1], bitfield: field(8, 1) },
        { name: 'Rendezvous Point (RP)', value: bool(word & 0x0040), abbrev: n.embedRp, rawBytesRange: [at, at + 1], bitfield: field(9, 1) },
        { name: 'Network Prefix', value: bool(word & 0x0020), abbrev: n.prefix, rawBytesRange: [at, at + 1], bitfield: field(10, 1) },
        { name: 'Transient', value: bool(word & 0x0010), abbrev: n.transient, rawBytesRange: [at, at + 1], bitfield: field(11, 1) },
      ],
    });
    rows.push({
      name: '[Multicast Scope]', value: `${SCOPES[word & 0x000f]} (0x${(word & 0x000f).toString(16)})`,
      abbrev: n.scope, generated: true, rawBytesRange: [at, at + 1], bitfield: field(12, 4),
    });
  }
  const block = lookupBlock(bytes, at);
  if (block !== undefined) {
    const answers: [string, number, string][] = [
      ['Source', block.source, n.source],
      ['Destination', block.destination, n.destination],
      ['Forwardable', block.forwardable, n.forwardable],
      ['Globally Reachable', block.global, n.global],
      ['Reserved-by-Protocol', block.reserved, n.reservedBy],
    ];
    rows.push({
      name: '[Special-Purpose Allocation]', value: block.name, abbrev: n.special, generated: true, rawBytesRange: range,
      children: answers.filter(([, v]) => v >= 0)
        .map(([name, v, abbrev]) => ({ name: `[${name}]`, value: bool(v), abbrev, generated: true, rawBytesRange: range })),
    });
  }
  return rows;
}

const dotted = (bytes: Uint8Array, at: number, xor = 0) =>
  [0, 1, 2, 3].map((i) => (bytes[at + i] ^ xor) & 0xff).join('.');
const mac = (octets: number[]) => octets.map((o) => o.toString(16).padStart(2, '0')).join(':');

/**
 * What a source and a destination address carry inside them, in the
 * reference's order: 6to4's gateway, Teredo's server and client, a SLAAC
 * interface identifier's MAC, ISATAP's IPv4. Each side's row carries the
 * either-end twin beneath it.
 */
export function ipv6EmbeddedRows(bytes: Uint8Array, srcAt: number, dstAt: number): ProtocolField[] {
  const rows: ProtocolField[] = [];
  const twin = (row: ProtocolField, name: string, abbrev: string): ProtocolField =>
    ({ ...row, children: [{ ...row, name, abbrev }] });
  const sides = [['Source', srcAt, 'src'], ['Destination', dstAt, 'dst']] as const;

  for (const [label, at, side] of sides) {
    if (((bytes[at] << 8) | bytes[at + 1]) !== 0x2002) continue;
    const gw: ProtocolField = { name: `[${label} 6to4 Gateway IPv4]`, value: dotted(bytes, at + 2), abbrev: side === 'src' ? 'ipv6.src_6to4_gw_ipv4' : 'ipv6.dst_6to4_gw_ipv4', generated: true, rawBytesRange: [at + 2, at + 5] };
    const sla: ProtocolField = { name: `[${label} 6to4 SLA ID]`, value: (bytes[at + 6] << 8) | bytes[at + 7], abbrev: side === 'src' ? 'ipv6.src_6to4_sla_id' : 'ipv6.dst_6to4_sla_id', generated: true, rawBytesRange: [at + 6, at + 7] };
    rows.push(twin(gw, '[6to4 Gateway IPv4]', 'ipv6.6to4_gw_ipv4'), twin(sla, '[6to4 SLA ID]', 'ipv6.6to4_sla_id'));
  }
  for (const [label, at, side] of sides) {
    if (bytes[at] !== 0x20 || bytes[at + 1] !== 0x01 || bytes[at + 2] !== 0 || bytes[at + 3] !== 0) continue;
    const server: ProtocolField = { name: `[${label} Teredo Server IPv4]`, value: dotted(bytes, at + 4), abbrev: side === 'src' ? 'ipv6.src_ts_ipv4' : 'ipv6.dst_ts_ipv4', generated: true, rawBytesRange: [at + 4, at + 7] };
    const port: ProtocolField = { name: `[${label} Teredo Port]`, value: ((bytes[at + 10] << 8) | bytes[at + 11]) ^ 0xffff, abbrev: side === 'src' ? 'ipv6.src_tc_port' : 'ipv6.dst_tc_port', generated: true, rawBytesRange: [at + 10, at + 11] };
    const client: ProtocolField = { name: `[${label} Teredo Client IPv4]`, value: dotted(bytes, at + 12, 0xff), abbrev: side === 'src' ? 'ipv6.src_tc_ipv4' : 'ipv6.dst_tc_ipv4', generated: true, rawBytesRange: [at + 12, at + 15] };
    rows.push(twin(server, '[Teredo Server IPv4]', 'ipv6.ts_ipv4'), twin(port, '[Teredo Port]', 'ipv6.tc_port'),
      twin(client, '[Teredo Client IPv4]', 'ipv6.tc_ipv4'));
  }
  for (const [label, at, side] of sides) {
    if (!(bytes[at + 8] & 0x02) || ((bytes[at + 11] << 8) | bytes[at + 12]) !== 0xfffe) continue;
    const octets = [bytes[at + 8] & ~0x02, bytes[at + 9], bytes[at + 10], bytes[at + 13], bytes[at + 14], bytes[at + 15]];
    const row: ProtocolField = { name: `[${label} SLAAC MAC]`, value: mac(octets), abbrev: side === 'src' ? 'ipv6.src_slaac_mac' : 'ipv6.dst_slaac_mac', generated: true, rawBytesRange: [at + 8, at + 15] };
    rows.push(twin(row, '[SLAAC MAC]', 'ipv6.slaac_mac'));
  }
  for (const [label, at, side] of sides) {
    const word = ((bytes[at + 8] << 24) | (bytes[at + 9] << 16) | (bytes[at + 10] << 8) | bytes[at + 11]) >>> 0;
    if (((word & 0xfcffffff) >>> 0) !== 0x00005efe) continue;
    const row: ProtocolField = { name: `[${label} ISATAP IPv4]`, value: dotted(bytes, at + 12), abbrev: side === 'src' ? 'ipv6.src_isatap_ipv4' : 'ipv6.dst_isatap_ipv4', generated: true, rawBytesRange: [at + 12, at + 15] };
    rows.push(twin(row, '[ISATAP IPv4]', 'ipv6.isatap_ipv4'));
  }
  return rows;
}
