/**
 * NBDS - the NetBIOS Datagram Service (RFC 1002 §4.4), UDP 138.
 *
 *   Direct_group datagram
 *   Broadcast datagram
 *
 * The third of the three NetBIOS services and the one that carries the traffic
 * a Windows LAN is actually made of: browser announcements, workgroup
 * elections, the messenger service. It shares the RFC 1001 first-level name
 * encoding with `dissectors/nbns.ts` and nothing else - the header is its own,
 * and the datagram carries **two** encoded names rather than a question
 * section.
 *
 * The user data after those names is an SMB Mailslot, which this does not
 * decode: doing so means the SMB command set, which is not a leaf and is not
 * cheap. What is here names the datagram, both endpoints and the mailslot's
 * size, which is what a reader needs to see who is announcing what.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { decodeNetbiosName } from './nbns';
import { readDnsName } from './dnsRecords';
import { formatIpv4Address } from '../addressFormat';

export interface NbdsResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 1002 §4.4.1. Wireshark's wording, which keeps the underscores. */
const MESSAGE_TYPES: Record<number, string> = {
  0x10: 'Direct_unique datagram',
  0x11: 'Direct_group datagram',
  0x12: 'Broadcast datagram',
  0x13: 'Datagram error',
  0x14: 'Datagram query request',
  0x15: 'Datagram positive query response',
  0x16: 'Datagram negative query response',
};

/** The types that carry two names and user data rather than an error code. */
const CARRIES_DATA = new Set([0x10, 0x11, 0x12]);

/**
 * One RFC 1001 encoded name, read where it sits.
 *
 * The names travel in DNS label form - a length byte, the 32 encoded
 * characters, then any scope labels and a terminator - so the labels are read
 * by the DNS reader and the first one is what carries the encoding. A name
 * that does not decode is not NetBIOS, and saying so is what lets the caller
 * decline the datagram rather than show a mangled one.
 */
function netbiosNameAt(bytes: Uint8Array, messageStart: number, offset: number, end: number):
  { display: string; after: number } | null {
  if (offset >= end) return null;
  const raw = readDnsName(bytes, messageStart, offset);
  const decoded = decodeNetbiosName(raw.name);
  if (decoded === null || raw.nextOffset > end) return null;
  return { display: decoded.display, after: raw.nextOffset };
}

export function dissectNbds(bytes: Uint8Array, start: number, end: number): NbdsResult | null {
  if (start + 10 > end) return null;
  const messageType = bytes[start];
  const typeName = MESSAGE_TYPES[messageType];
  if (typeName === undefined) return null;

  const flags = bytes[start + 1];
  const id = (bytes[start + 2] << 8) | bytes[start + 3];
  const sourceIp = formatIpv4Address(bytes, start + 4);
  const sourcePort = (bytes[start + 8] << 8) | bytes[start + 9];

  const fields: Record<string, string | number> = {
    'nbdgm.type': messageType,
    'nbdgm.dgram_id': id,
    'nbdgm.src.ip': sourceIp,
    'nbdgm.src.port': sourcePort,
  };

  const rows: ProtocolField[] = [
    { name: 'Message Type', value: `${typeName} (0x${messageType.toString(16)})`,
      abbrev: 'nbdgm.type', rawBytesRange: [start, start] },
    // The two low bits are the fragment flags; the rest is the node type,
    // which is the same B/P/M/H taxonomy NBNS registers under.
    { name: 'More fragments follow', value: (flags & 0x01) !== 0 ? 'Yes' : 'No' },
    { name: 'This is first fragment', value: (flags & 0x02) !== 0 ? 'Yes' : 'No' },
    { name: 'Node Type', value: ['B node', 'P node', 'M node', 'NBDD'][(flags >> 2) & 0x03] },
    { name: 'Datagram ID', value: `0x${id.toString(16).padStart(4, '0')}`, abbrev: 'nbdgm.dgram_id',
      rawBytesRange: [start + 2, start + 3] },
    { name: 'Source IP', value: sourceIp, abbrev: 'nbdgm.src.ip',
      rawBytesRange: [start + 4, start + 7] },
    { name: 'Source Port', value: sourcePort, abbrev: 'nbdgm.src.port',
      rawBytesRange: [start + 8, start + 9] },
  ];

  if (CARRIES_DATA.has(messageType)) {
    if (start + 14 > end) return null;
    const dataLength = (bytes[start + 10] << 8) | bytes[start + 11];
    const offset = (bytes[start + 12] << 8) | bytes[start + 13];
    rows.push(
      { name: 'Datagram length', value: `${dataLength} bytes`, abbrev: 'nbdgm.dgram_len',
        rawBytesRange: [start + 10, start + 11] },
      { name: 'Packet offset', value: `${offset} bytes`, rawBytesRange: [start + 12, start + 13] },
    );
    fields['nbdgm.dgram_len'] = dataLength;

    const sourceName = netbiosNameAt(bytes, start, start + 14, end);
    if (sourceName === null) return null;
    const destName = netbiosNameAt(bytes, start, sourceName.after, end);
    if (destName === null) return null;
    fields['nbdgm.source_name'] = sourceName.display;
    fields['nbdgm.destination_name'] = destName.display;
    rows.push(
      { name: 'Source name', value: sourceName.display, abbrev: 'nbdgm.source_name',
        rawBytesRange: [start + 14, sourceName.after - 1] },
      { name: 'Destination name', value: destName.display, abbrev: 'nbdgm.destination_name',
        rawBytesRange: [sourceName.after, destName.after - 1] },
    );

    const userDataStart = destName.after;
    if (userDataStart < end) {
      // Not decoded, and deliberately - this is an SMB Mailslot. Reporting its
      // size is honest; naming it would not be.
      rows.push({ name: 'User data', value: `${end - userDataStart} bytes`,
        rawBytesRange: [userDataStart, end - 1] });
    }
  } else if (messageType === 0x13) {
    if (start + 11 > end) return null;
    const code = bytes[start + 10];
    fields['nbdgm.error_code'] = code;
    rows.push({ name: 'Error code', value: code, abbrev: 'nbdgm.error_code',
      rawBytesRange: [start + 10, start + 10] });
  } else {
    const name = netbiosNameAt(bytes, start, start + 10, end);
    if (name === null) return null;
    fields['nbdgm.destination_name'] = name.display;
    rows.push({ name: 'Destination name', value: name.display, abbrev: 'nbdgm.destination_name',
      rawBytesRange: [start + 10, name.after - 1] });
  }

  return {
    protocolLabel: 'NBDS',
    info: typeName,
    fields,
    layer: {
      name: 'NetBIOS Datagram Service',
      summary: `NetBIOS Datagram Service (${typeName})`,
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}
