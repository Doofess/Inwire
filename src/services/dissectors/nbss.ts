/**
 * The NetBIOS Session Service (RFC 1002 §4.3) - the framing SMB rides on, on
 * TCP 139 and, as "direct hosting", on TCP 445.
 *
 *   Session request, to SERVER<20> from LAPTOP1<00>
 *   Negative session response, Called name not present
 *   Negotiate Protocol Request
 *
 * On 445 it is only a type byte and a 24-bit length in front of every SMB
 * message. On 139 it is a session protocol of its own: a client asks for a
 * session by the server's NetBIOS name before it may send SMB, and the answer
 * - yes, no and why, or "try that address instead" - is the first thing to
 * read when a connection to an old file server fails.
 *
 * A session message's payload is SMB: SMB1 is read here through
 * `dissectors/smb.ts`; SMB2 has its own stateful path in `tcpTransport.ts`,
 * which asks `nbssLayers` for the framing rows to put in front of it.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';
import { readDnsName } from './dnsRecords';
import { decodeNetbiosName, netbiosSuffixName } from './nbns';
import { dissectSmb, hasSmbMagic } from './smb';

/** The NetBIOS session port; 445 carries the same framing without the session protocol. */
export const NBSS_PORT = 139;
export const SMB_DIRECT_PORT = 445;

const TYPES: Record<number, string> = {
  0x00: 'Session message', 0x81: 'Session request', 0x82: 'Positive session response',
  0x83: 'Negative session response', 0x84: 'Retarget session response', 0x85: 'Session keep-alive',
};
const ERROR_CODES: Record<number, string> = {
  0x80: 'Not listening on called name', 0x81: 'Not listening for calling name', 0x82: 'Called name not present',
  0x83: 'Called name present, but insufficient resources', 0x8f: 'Unspecified error',
};
const hex2 = (n: number) => `0x${n.toString(16).padStart(2, '0')}`;

interface Message {
  type: number;
  /** Where the next message starts. */
  end: number;
  layer: ProtocolLayer;
  info: string;
  fields: Record<string, string | number>;
}

/**
 * The message at `at`, or null when it is not NBSS or runs past `end`. On 445
 * the length is 24 bits; on 139 it is 17, the flag byte's low bit on top.
 */
function readMessage(b: Uint8Array, at: number, end: number, directHosted: boolean): Message | null {
  if (at + 4 > end) return null;
  const type = b[at];
  const typeName = TYPES[type];
  if (typeName === undefined) return null;
  const flags = b[at + 1];
  if (!directHosted && (flags & 0xfe) !== 0) return null;
  const length = directHosted
    ? (flags << 16) | (b[at + 2] << 8) | b[at + 3]
    : ((flags & 1) << 16) | (b[at + 2] << 8) | b[at + 3];
  const bodyEnd = at + 4 + length;
  if (bodyEnd > end) return null;

  const rows: ProtocolField[] = [
    { name: 'Message Type', value: `${typeName} (${hex2(type)})`, abbrev: 'nbss.type', rawBytesRange: [at, at] },
  ];
  // A session message's flag byte is part of its length, and the reference
  // draws no flags for one.
  if (type !== 0x00) {
    rows.push({
      name: 'Flags', value: hex2(flags), abbrev: 'nbss.flags', rawBytesRange: [at + 1, at + 1],
      children: [{ name: 'Extend', value: (flags & 1) !== 0 ? 'Add 65536 to length' : 'Add 0 to length', abbrev: 'nbss.flags.e',
        rawBytesRange: [at + 1, at + 1], bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } }],
    });
  }
  rows.push({ name: 'Length', value: length, abbrev: 'nbss.length', rawBytesRange: [at + 1, at + 3] });
  const fields: Record<string, string | number> = { 'nbss.type': type, 'nbss.length': length };
  let info = typeName;
  const p = at + 4;

  if (type === 0x81) {
    const called = readDnsName(b, p, p);
    const calledName = decodeNetbiosName(called.name);
    const calling = readDnsName(b, p, called.nextOffset);
    const callingName = decodeNetbiosName(calling.name);
    if (calledName === null || callingName === null || calling.nextOffset > bodyEnd) return null;
    rows.push(
      { name: 'Called name', value: `${calledName.display} (${netbiosSuffixName(calledName.suffix)})`, abbrev: 'nbss.called_name',
        rawBytesRange: [p, called.nextOffset - 1] },
      { name: 'Calling name', value: `${callingName.display} (${netbiosSuffixName(callingName.suffix)})`, abbrev: 'nbss.calling_name',
        rawBytesRange: [called.nextOffset, calling.nextOffset - 1] },
    );
    fields['nbss.called_name'] = calledName.display;
    fields['nbss.calling_name'] = callingName.display;
    info = `${typeName}, to ${calledName.display} from ${callingName.display}`;
  } else if (type === 0x83 && length >= 1) {
    const code = b[p];
    rows.push({ name: 'Error code', value: `${ERROR_CODES[code] ?? 'Unknown'} (${hex2(code)})`, abbrev: 'nbss.error_code', rawBytesRange: [p, p] });
    fields['nbss.error_code'] = code;
    info = `${typeName}, ${ERROR_CODES[code] ?? 'Unknown'}`;
  } else if (type === 0x84 && length >= 6) {
    rows.push(
      { name: 'Retarget IP address', value: formatIpv4Address(b, p), abbrev: 'nbss.retarget_ip_address', rawBytesRange: [p, p + 3] },
      { name: 'Retarget port', value: (b[p + 4] << 8) | b[p + 5], abbrev: 'nbss.retarget_port', rawBytesRange: [p + 4, p + 5] },
    );
  }
  return {
    type, end: bodyEnd, info, fields,
    layer: { name: 'NetBIOS Session Service', summary: 'NetBIOS Session Service', rawBytesRange: [at, Math.max(at, bodyEnd - 1)], fields: rows },
  };
}

/** Whether a segment opens with an NBSS message this reads. */
export function looksLikeNbss(b: Uint8Array, start: number, end: number, directHosted: boolean): boolean {
  return readMessage(b, start, end, directHosted) !== null;
}

/** The framing layer of every message in a segment, for the SMB2 path to draw in front of its own. */
export function nbssLayers(b: Uint8Array, start: number, end: number, directHosted: boolean): ProtocolLayer[] {
  const out: ProtocolLayer[] = [];
  for (let at = start; at < end;) {
    const message = readMessage(b, at, end, directHosted);
    if (message === null) break;
    out.push(message.layer);
    at = message.end;
  }
  return out;
}

export interface NbssResult {
  protocolLabel: string;
  info: string;
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
}

/**
 * Every NBSS message in a segment, and the SMB1 each session message carries.
 * Declines a segment holding SMB2, which `dissectors/smb2.ts` reads with its
 * connection's state.
 */
export function dissectNbss(b: Uint8Array, start: number, end: number, directHosted: boolean): NbssResult | null {
  const layers: ProtocolLayer[] = [];
  const fields: Record<string, string | number> = {};
  const infos: string[] = [];
  let protocolLabel = 'NBSS';
  for (let at = start; at < end;) {
    const message = readMessage(b, at, end, directHosted);
    if (message === null) break;
    if (message.type === 0x00 && message.end > at + 4 && b[at + 4] === 0xfe) return null;
    layers.push(message.layer);
    Object.assign(fields, message.fields);
    const smb = message.type === 0x00 && hasSmbMagic(b, at + 4) ? dissectSmb(b, at + 4, message.end) : null;
    if (smb !== null) {
      layers.push(...smb.layers);
      Object.assign(fields, smb.fields);
      protocolLabel = smb.protocolLabel;
      infos.push(smb.info);
    } else {
      infos.push(message.info);
    }
    at = message.end;
  }
  if (layers.length === 0) return null;
  return { protocolLabel, info: infos.join('; '), layers, fields };
}
