/**
 * OSPF (RFC 2328 for v2, RFC 5340 for v3), IP protocol 89.
 *
 *   Hello Packet
 *   DB Description
 *   LS Update
 *
 * The routing protocol most enterprise networks actually run, and the one whose
 * failures are hardest to see from anywhere else. Two routers that cannot form
 * an adjacency exchange Hellos forever and never reach Exchange; the Hello
 * carries the reason, because **a Hello lists the neighbours the sender has
 * heard from**. A router that does not see itself in its neighbour's Hello has
 * a one-way link - the packets are arriving in one direction only - and that
 * is diagnosable from a capture and very little else.
 *
 * The five packet types are read to the depth their headers allow. LSAs
 * themselves are not expanded: the link-state database is a recursive
 * structure with eleven LSA types, and it is the one part of OSPF that is not
 * a leaf. The header, the Hello's neighbour list and each LSA's identity are
 * here, which is what names the conversation; the topology inside is not.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';

export interface OspfResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 2328 §A.3.1. Wireshark's wording, which is not the RFC's. */
const PACKET_TYPES: Record<number, string> = {
  1: 'Hello Packet',
  2: 'DB Description',
  3: 'LS Request',
  4: 'LS Update',
  5: 'LS Acknowledge',
};

const AUTH_TYPES: Record<number, string> = {
  0: 'Null',
  1: 'Simple password',
  2: 'Cryptographic',
};

/** The 24-byte v2 header; v3's is 16 and is not read here. */
const HEADER_BYTES = 24;

export function dissectOspf(bytes: Uint8Array, start: number, end: number): OspfResult | null {
  if (start + HEADER_BYTES > end) return null;
  const version = bytes[start];
  // Only v2 is read. v3 carries IPv6 topology in a differently shaped header,
  // and half-reading it would put v2's field names on v3's bytes.
  if (version !== 2) return null;
  const type = bytes[start + 1];
  const typeName = PACKET_TYPES[type];
  if (typeName === undefined) return null;
  const length = (bytes[start + 2] << 8) | bytes[start + 3];
  if (length < HEADER_BYTES || start + length > end) return null;

  const routerId = formatIpv4Address(bytes, start + 4);
  const areaId = formatIpv4Address(bytes, start + 8);
  const checksum = (bytes[start + 12] << 8) | bytes[start + 13];
  const authType = (bytes[start + 14] << 8) | bytes[start + 15];

  const fields: Record<string, string | number> = {
    'ospf.version': version,
    'ospf.msg': type,
    'ospf.packet_length': length,
    'ospf.srcrouter': routerId,
    'ospf.area_id': areaId,
    'ospf.checksum': checksum,
    'ospf.auth.type': authType,
  };

  const rows: ProtocolField[] = [
    { name: 'Version', value: version, abbrev: 'ospf.version', rawBytesRange: [start, start] },
    { name: 'Message Type', value: `${typeName} (${type})`, abbrev: 'ospf.msg',
      rawBytesRange: [start + 1, start + 1] },
    { name: 'Packet Length', value: length, abbrev: 'ospf.packet_length',
      rawBytesRange: [start + 2, start + 3] },
    { name: 'Source OSPF Router', value: routerId, abbrev: 'ospf.srcrouter',
      rawBytesRange: [start + 4, start + 7] },
    { name: 'Area ID', value: areaId === '0.0.0.0' ? `${areaId} (Backbone)` : areaId,
      abbrev: 'ospf.area_id', rawBytesRange: [start + 8, start + 11] },
    { name: 'Checksum', value: `0x${checksum.toString(16).padStart(4, '0')}`,
      abbrev: 'ospf.checksum', rawBytesRange: [start + 12, start + 13] },
    { name: 'Auth Type', value: `${AUTH_TYPES[authType] ?? 'Unknown'} (${authType})`,
      abbrev: 'ospf.auth.type', rawBytesRange: [start + 14, start + 15] },
  ];

  const body = start + HEADER_BYTES;
  const bodyEnd = start + length;

  if (type === 1 && body + 20 <= bodyEnd) {
    const mask = formatIpv4Address(bytes, body);
    const helloInterval = (bytes[body + 4] << 8) | bytes[body + 5];
    const options = bytes[body + 6];
    const priority = bytes[body + 7];
    const deadInterval = ((bytes[body + 8] << 24) | (bytes[body + 9] << 16)
      | (bytes[body + 10] << 8) | bytes[body + 11]) >>> 0;
    const designated = formatIpv4Address(bytes, body + 12);
    const backup = formatIpv4Address(bytes, body + 16);
    Object.assign(fields, {
      'ospf.hello.network_mask': mask,
      'ospf.hello.hello_interval': helloInterval,
      'ospf.hello.router_priority': priority,
      'ospf.hello.router_dead_interval': deadInterval,
      'ospf.hello.designated_router': designated,
      'ospf.hello.backup_designated_router': backup,
    });
    const helloRows: ProtocolField[] = [
      { name: 'Network Mask', value: mask, abbrev: 'ospf.hello.network_mask',
        rawBytesRange: [body, body + 3] },
      { name: 'Hello Interval [sec]', value: helloInterval, abbrev: 'ospf.hello.hello_interval',
        rawBytesRange: [body + 4, body + 5] },
      { name: 'Options', value: `0x${options.toString(16).padStart(2, '0')}`,
        rawBytesRange: [body + 6, body + 6] },
      { name: 'Router Priority', value: priority, abbrev: 'ospf.hello.router_priority',
        rawBytesRange: [body + 7, body + 7] },
      { name: 'Router Dead Interval [sec]', value: deadInterval,
        abbrev: 'ospf.hello.router_dead_interval', rawBytesRange: [body + 8, body + 11] },
      { name: 'Designated Router', value: designated, abbrev: 'ospf.hello.designated_router',
        rawBytesRange: [body + 12, body + 15] },
      { name: 'Backup Designated Router', value: backup,
        abbrev: 'ospf.hello.backup_designated_router', rawBytesRange: [body + 16, body + 19] },
    ];
    // The neighbour list, which is the half of a Hello that diagnoses a
    // one-way link: a router missing from its neighbour's list is not being
    // heard, however many Hellos it sends.
    let neighbours = 0;
    for (let p = body + 20; p + 4 <= bodyEnd; p += 4) {
      helloRows.push({ name: 'Active Neighbor', value: formatIpv4Address(bytes, p),
        abbrev: 'ospf.hello.active_neighbor', rawBytesRange: [p, p + 3] });
      neighbours++;
    }
    fields['ospf.hello.neighbor_count'] = neighbours;
    rows.push({ name: 'OSPF Hello Packet', value: '', rawBytesRange: [body, bodyEnd - 1],
      children: helloRows });
  } else if (type === 2 && body + 8 <= bodyEnd) {
    const mtu = (bytes[body] << 8) | bytes[body + 1];
    const flags = bytes[body + 2 + 1];
    const sequence = ((bytes[body + 4] << 24) | (bytes[body + 5] << 16)
      | (bytes[body + 6] << 8) | bytes[body + 7]) >>> 0;
    Object.assign(fields, { 'ospf.db.interface_mtu': mtu, 'ospf.db.dd_sequence': sequence });
    rows.push({ name: 'OSPF DB Description', value: '', rawBytesRange: [body, bodyEnd - 1],
      children: [
        { name: 'Interface MTU', value: mtu, abbrev: 'ospf.db.interface_mtu',
          rawBytesRange: [body, body + 1] },
        { name: 'DB Description', value: `0x${flags.toString(16).padStart(2, '0')}`,
          rawBytesRange: [body + 3, body + 3],
          children: [
            { name: 'Init', value: (flags & 0x04) !== 0 ? 'Set' : 'Not set' },
            { name: 'More', value: (flags & 0x02) !== 0 ? 'Set' : 'Not set' },
            { name: 'Master', value: (flags & 0x01) !== 0 ? 'Set' : 'Not set' },
          ] },
        { name: 'DD Sequence', value: sequence, abbrev: 'ospf.db.dd_sequence',
          rawBytesRange: [body + 4, body + 7] },
      ] });
  } else if (type === 3) {
    // Each request names one LSA by type, id and advertising router.
    for (let p = body; p + 12 <= bodyEnd; p += 12) {
      rows.push({ name: 'Link State Request', value: '', rawBytesRange: [p, p + 11],
        children: [
          // No abbrev: the reference analyzer has no `ospf.lsa.type`, and a
          // filter name this build alone understands is worse than none.
          { name: 'LS Type', value: ((bytes[p] << 24) | (bytes[p + 1] << 16)
            | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0 },
          { name: 'Link State ID', value: formatIpv4Address(bytes, p + 4) },
          { name: 'Advertising Router', value: formatIpv4Address(bytes, p + 8) },
        ] });
    }
  } else if (type === 4 && body + 4 <= bodyEnd) {
    const count = ((bytes[body] << 24) | (bytes[body + 1] << 16)
      | (bytes[body + 2] << 8) | bytes[body + 3]) >>> 0;
    fields['ospf.ls.number_of_lsas'] = count;
    rows.push({ name: 'Number of LSAs', value: count, abbrev: 'ospf.ls.number_of_lsas',
      rawBytesRange: [body, body + 3] });
  }

  return {
    protocolLabel: 'OSPF',
    info: typeName,
    fields,
    layer: {
      name: 'Open Shortest Path First',
      summary: 'Open Shortest Path First',
      rawBytesRange: [start, start + length - 1],
      fields: rows,
    },
  };
}
