/**
 * The DCE/RPC endpoint mapper (EPM, TCP 135) - the directory a Windows client
 * asks "which port is the interface I want on?" before it connects there.
 *
 *   Map request, DRSUAPI, 32bit NDR
 *   Map response, DRSUAPI, 32bit NDR
 *
 * A Map names an interface in a protocol tower (the interface, its transfer
 * syntax, then the transport floors) and the answer is the same tower with
 * the port and address filled in - so the Map response is where the dynamic
 * port of every later RPC connection on a Windows network comes from. Only
 * Map is read; the other operations are named and drawn as stub bytes.
 *
 * Every row is the reference's, read from tshark.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';
import { INTERFACES, SYNTAXES } from './dcerpcNames';

export const EPM_UUID = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa';
const OPERATIONS = INTERFACES[EPM_UUID]?.operations ?? {};

/** `epm.tower.proto_id`, the reference's names. */
const PROTOCOL_IDS: Record<number, string> = {
  0x00: 'OSI OID', 0x02: 'DNA Session Control', 0x03: 'DNA Session Control V3', 0x04: 'DNA NSP Transport',
  0x05: 'OSI TP4', 0x06: 'OSI CLNS or DNA Routing', 0x07: 'DOD TCP', 0x08: 'DOD UDP', 0x09: 'DOD IP',
  0x0a: 'RPC connectionless protocol', 0x0b: 'RPC connection-oriented protocol', 0x0c: 'SPX?', 0x0d: 'UUID',
  0x0e: 'IPX?', 0x0f: 'Named Pipes', 0x10: 'Named Pipes', 0x11: 'NetBIOS', 0x12: 'NetBEUI', 0x13: 'Netware SPX',
  0x14: 'Netware IPX', 0x16: 'Appletalk Stream', 0x17: 'Appletalk Datagram', 0x18: 'Appletalk', 0x19: 'NetBIOS',
  0x1a: 'Vines SPP', 0x1b: 'Vines IPC', 0x1c: 'StreetTalk', 0x1f: 'RPC over HTTP', 0x20: 'Unix Domain Socket',
  0x21: 'null', 0x22: 'NetBIOS',
};

const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const le16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const hexColons = (b: Uint8Array, from: number, to: number) =>
  Array.from(b.subarray(from, to), (x) => x.toString(16).padStart(2, '0')).join(':');
const LATIN1 = new TextDecoder('latin1');

/** A DCE UUID, its first three fields little-endian. */
export function readUuid(b: Uint8Array, at: number): string {
  const h = (from: number, to: number, reverse: boolean) => {
    const part = Array.from(b.subarray(from, to), (x) => x.toString(16).padStart(2, '0'));
    return (reverse ? part.reverse() : part).join('');
  };
  return `${h(at, at + 4, true)}-${h(at + 4, at + 6, true)}-${h(at + 6, at + 8, true)}-${h(at + 8, at + 10, false)}-${h(at + 10, at + 16, false)}`;
}

/** An interface's or a transfer syntax's name, when the reference has one. */
export function uuidName(uuid: string): string | undefined {
  return INTERFACES[uuid]?.name ?? SYNTAXES[uuid];
}

interface Tower {
  rows: ProtocolField[];
  /** The first two floors' names, which is what the Info column quotes. */
  names: string[];
  end: number;
}

/** A tower behind its pointer: two lengths, then the floors. */
function readTower(b: Uint8Array, at: number, end: number): Tower | null {
  if (at + 10 > end) return null;
  const length = le32(b, at);
  const towerEnd = at + 8 + length;
  if (towerEnd > end) return null;
  const count = le16(b, at + 8);
  const rows: ProtocolField[] = [
    { name: 'Length', value: length, abbrev: 'epm.tower.len', rawBytesRange: [at, at + 3] },
    { name: 'Length', value: le32(b, at + 4), abbrev: 'epm.tower.len', rawBytesRange: [at + 4, at + 7] },
    { name: 'Number of floors', value: count, abbrev: 'epm.tower.num_floors', rawBytesRange: [at + 8, at + 9] },
  ];
  const names: string[] = [];
  let p = at + 10;
  for (let i = 1; i <= count && p + 2 <= towerEnd; i++) {
    const lhsLen = le16(b, p);
    const lhs = p + 2;
    if (lhs + lhsLen + 2 > towerEnd) return null;
    const rhsLenAt = lhs + lhsLen;
    const rhsLen = le16(b, rhsLenAt);
    const rhs = rhsLenAt + 2;
    if (rhs + rhsLen > towerEnd) return null;
    const proto = b[lhs];
    const floor: ProtocolField[] = [
      { name: 'LHS Length', value: lhsLen, abbrev: 'epm.tower.lhs.len', rawBytesRange: [p, p + 1] },
      { name: 'Protocol', value: `${PROTOCOL_IDS[proto] ?? 'Unknown'} (${hex(proto, 2)})`, abbrev: 'epm.tower.proto_id', rawBytesRange: [lhs, lhs] },
    ];
    let summary = PROTOCOL_IDS[proto] ?? 'Unknown';
    if (proto === 0x0d && lhsLen >= 19) {
      const uuid = readUuid(b, lhs + 1);
      const name = uuidName(uuid);
      names.push(name ?? uuid);
      summary = `UUID: ${name ?? uuid}`;
      floor.push(
        { name: 'UUID', value: name !== undefined ? `${name} (${uuid})` : uuid, abbrev: 'epm.uuid', rawBytesRange: [lhs + 1, lhs + 16] },
        // Two bytes the reference reads as major then minor: `4.00`.
        { name: 'Version', value: `${b[lhs + 17]}.${String(b[lhs + 18]).padStart(2, '0')}`, abbrev: 'epm.uuid_version', rawBytesRange: [lhs + 17, lhs + 18] },
      );
    }
    floor.push({ name: 'RHS Length', value: rhsLen, abbrev: 'epm.tower.rhs.len', rawBytesRange: [rhsLenAt, rhsLenAt + 1] });
    if (proto === 0x0d && rhsLen >= 2) {
      floor.push({ name: 'Version Minor', value: le16(b, rhs), abbrev: 'epm.ver_min', rawBytesRange: [rhs, rhs + 1] });
    } else if ((proto === 0x07 || proto === 0x08 || proto === 0x1f) && rhsLen >= 2) {
      const port = (b[rhs] << 8) | b[rhs + 1];
      const abbrev = proto === 0x07 ? 'epm.proto.tcp_port' : proto === 0x08 ? 'epm.proto.udp_port' : 'epm.proto.http_port';
      floor.push({ name: proto === 0x08 ? 'UDP Port' : 'TCP Port', value: port, abbrev, rawBytesRange: [rhs, rhs + 1] });
      summary = `${summary}:${port}`;
    } else if (proto === 0x09 && rhsLen >= 4) {
      const ip = formatIpv4Address(b, rhs);
      floor.push({ name: 'IP', value: ip, abbrev: 'epm.proto.ip', rawBytesRange: [rhs, rhs + 3] });
      summary = `${summary}:${ip}`;
    } else if ((proto === 0x0f || proto === 0x10 || proto === 0x11) && rhsLen > 0) {
      let stop = rhs;
      while (stop < rhs + rhsLen && b[stop] !== 0) stop++;
      const text = LATIN1.decode(b.subarray(rhs, stop));
      floor.push(proto === 0x11
        ? { name: 'NetBIOS Name', value: text, abbrev: 'epm.proto.netbios_name', rawBytesRange: [rhs, rhs + rhsLen - 1] }
        : { name: 'Named Pipe', value: text, abbrev: 'epm.proto.named_pipe', rawBytesRange: [rhs, rhs + rhsLen - 1] });
    }
    rows.push({ name: `Floor ${i}`, value: summary, rawBytesRange: [p, rhs + rhsLen - 1], children: floor });
    p = rhs + rhsLen;
  }
  return { rows, names, end: towerEnd };
}

const align4 = (start: number, p: number) => p + ((4 - ((p - start) % 4)) % 4);

export interface EpmResult {
  info: string;
  layer: ProtocolLayer;
}

/**
 * One EPM call's stub. `opnum` is the operation, which a response knows only
 * from its request; `link` is the request-or-response row the reference draws
 * here as well as in the DCE/RPC layer.
 */
export function dissectEpm(b: Uint8Array, start: number, end: number, opnum: number, isResponse: boolean,
  link: ProtocolField | null): EpmResult {
  const opName = OPERATIONS[opnum] ?? `Unknown operation ${opnum}`;
  const rows: ProtocolField[] = [
    { name: 'Operation', value: `${opName} (${opnum})`, abbrev: 'epm.opnum' },
  ];
  if (link !== null) rows.push(link);
  let info = `${opName} ${isResponse ? 'response' : 'request'}`;

  if (opnum === 3 && !isResponse) {
    // ept_map: object, map_tower, entry_handle, max_towers.
    let p = start;
    const pointer = (label: string, read: (at: number) => number): void => {
      if (p + 4 > end) return;
      const referent = le32(b, p);
      if (referent === 0) {
        rows.push({ name: 'NULL Pointer', value: label, abbrev: 'dcerpc.null_pointer', rawBytesRange: [p, p + 3] });
        p += 4;
        return;
      }
      rows.push({ name: 'Referent ID', value: hex(referent, 8), abbrev: 'dcerpc.referent_id', rawBytesRange: [p, p + 3] });
      p = read(p + 4);
    };
    pointer('UUID pointer:', (at) => {
      if (at + 16 > end) return end;
      rows.push({ name: 'UUID', value: readUuid(b, at), abbrev: 'epm.uuid', rawBytesRange: [at, at + 15] });
      return at + 16;
    });
    pointer('Tower pointer:', (at) => {
      const tower = readTower(b, at, end);
      if (tower === null) return end;
      rows.push(...tower.rows);
      if (tower.names.length > 0) info += `, ${tower.names.join(', ')}`;
      return align4(start, tower.end);
    });
    if (p + 24 <= end) {
      rows.push(
        { name: 'Handle', value: hexColons(b, p, p + 20), abbrev: 'epm.hnd', rawBytesRange: [p, p + 19] },
        { name: 'Max Towers', value: le32(b, p + 20), abbrev: 'epm.max_towers', rawBytesRange: [p + 20, p + 23] },
      );
    }
  } else if (opnum === 3 && isResponse && start + 24 <= end) {
    // entry_handle, num_towers, then a conformant varying array of tower pointers.
    let p = start;
    const count = le32(b, p + 20);
    rows.push(
      { name: 'Handle', value: hexColons(b, p, p + 20), abbrev: 'epm.hnd', rawBytesRange: [p, p + 19] },
      { name: 'Num Towers', value: count, abbrev: 'epm.num_towers', rawBytesRange: [p + 20, p + 23] },
    );
    p += 24;
    if (p + 12 <= end) {
      const actual = le32(b, p + 8);
      const array: ProtocolField[] = [
        { name: 'Max Count', value: le32(b, p), abbrev: 'dcerpc.array.max_count', rawBytesRange: [p, p + 3] },
        { name: 'Offset', value: le32(b, p + 4), abbrev: 'dcerpc.array.offset', rawBytesRange: [p + 4, p + 7] },
        { name: 'Actual Count', value: actual, abbrev: 'dcerpc.array.actual_count', rawBytesRange: [p + 8, p + 11] },
      ];
      p += 12;
      // The pointers first, then the towers they point to, in order.
      const referents: { at: number; id: number }[] = [];
      for (let i = 0; i < actual && p + 4 <= end; i++, p += 4) referents.push({ at: p, id: le32(b, p) });
      for (const [i, referent] of referents.entries()) {
        const tower: ProtocolField[] = [
          { name: 'Referent ID', value: hex(referent.id, 8), abbrev: 'dcerpc.referent_id', rawBytesRange: [referent.at, referent.at + 3] },
        ];
        if (referent.id !== 0) {
          const read = readTower(b, p, end);
          if (read === null) break;
          tower.push(...read.rows);
          if (i === 0 && read.names.length > 0) info += `, ${read.names.join(', ')}`;
          p = align4(start, read.end);
        }
        array.push({ name: 'Tower pointer', value: '', children: tower });
      }
      rows.push({ name: 'Tower pointer', value: '', children: array });
      if (p + 4 <= end) rows.push({ name: 'Return code', value: hex(le32(b, p), 8), abbrev: 'epm.rc', rawBytesRange: [p, p + 3] });
    }
  }
  return {
    info,
    layer: {
      name: 'DCE/RPC Endpoint Mapper',
      summary: `DCE/RPC Endpoint Mapper, ${opName}`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}
