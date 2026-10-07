/**
 * Remote Desktop's connection setup on TCP 3389: TPKT (RFC 1006), the X.224
 * transport header under it (COTP, ISO 8073), and RDP's own negotiation
 * (MS-RDPBCGR 2.2.1.1-2).
 *
 *   Cookie: mstshash=alice, Negotiate Request
 *   Negotiate Response
 *   Negotiate Failure, failureCode Server requires Enhanced RDP Security with CredSSP
 *
 * The first two segments of every Remote Desktop connection, and the part of
 * it a capture can still read: who is logging on (the `mstshash` cookie), the
 * security the client offers, and what the server chose - or why it refused.
 * Everything after a TLS or CredSSP choice is TLS, which the TLS dissector
 * reads from there. Port 3389 only, as the reference dispatches it.
 *
 * A data TPDU carries T.125 (MCS), which only the legacy, non-TLS RDP security
 * uses and which is not decoded here.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

export const RDP_PORT = 3389;

const COTP_TYPES: Record<number, string> = {
  0x0e: 'CR Connect Request', 0x0d: 'CC Connect Confirm', 0x08: 'DR Disconnect Request', 0x0c: 'DC Disconnect Confirm',
  0x0f: 'DT Data', 0x07: 'ER TPDU Error', 0x05: 'EA Expedited Acknowledgement', 0x06: 'AK Data Acknowledgement',
  0x01: 'ED Expedited Data', 0x02: 'RJ Reject',
};
const COTP_CAUSES: Record<number, string> = {
  0: 'Reason not specified', 1: 'Congestion at TSAP', 2: 'Session entity not attached to TSAP', 3: 'Address unknown',
  128: 'Normal Disconnect', 129: 'Remote transport entity congestion', 130: 'Connection negotiation failed',
  131: 'Duplicate source reference', 132: 'Mismatched references', 133: 'Protocol error', 135: 'Reference overflow',
  136: 'Connection request refused', 138: 'Header or parameter length invalid',
};
const NEG_TYPES: Record<number, string> = {
  1: 'RDP Negotiation Request', 2: 'RDP Negotiation Response', 3: 'RDP Negotiation Failure', 6: 'RDP Correlation Info',
};
const SELECTED_PROTOCOLS: Record<number, string> = {
  0: 'Standard RDP Security', 1: 'TLS 1.0, 1.1 or 1.2', 2: 'CredSSP', 4: 'RDSTLS protocol',
  8: 'CredSSP with Early User Authorization Result PDU', 0x10: 'RDS AAD Auth security',
};
const FAILURE_CODES: Record<number, string> = {
  1: 'TLS required by server', 2: 'TLS not allowed by server', 3: 'TLS certificate not on server', 4: 'Inconsistent flags',
  5: 'Server requires Enhanced RDP Security with CredSSP',
  6: 'Server requires Enhanced RDP Security with TLS and certificate-based client authentication',
};

/** A flag's mask, field, and its name - which is what the summary lists when it is set. */
type Flag = [mask: number, abbrev: string, name: string];
const REQUEST_FLAGS: Flag[] = [
  [0x01, 'rdp.negReq.flags.restricted_admin_mode_req', 'Restricted admin mode required'],
  [0x02, 'rdp.negReq.flags.redirected_auth_req', 'Redirected Authentication required'],
  [0x08, 'rdp.negReq.flags.correlation_info_present', 'Correlation info present'],
];
const RESPONSE_FLAGS: Flag[] = [
  [0x01, 'rdp.negRsp.flags.extended_client_data_supported', 'Extended Client Data Blocks supported'],
  [0x02, 'rdp.negRsp.flags.dynvc_gfx_protocol_supported', 'Graphics Pipeline Extension Protocol supported'],
  [0x08, 'rdp.negRsp.flags.restricted_admin_mode_supported', 'Restricted admin mode supported'],
  [0x10, 'rdp.negRsp.flags.restricted_authentication_mode_supported', 'Restricted authentication mode supported'],
];
const REQUESTED_PROTOCOLS: Flag[] = [
  [0x01, 'rdp.negReq.requestedProtocols.ssl', 'TLS security supported'],
  [0x02, 'rdp.negReq.requestedProtocols.hybrid', 'CredSSP supported'],
  [0x04, 'rdp.negReq.requestedProtocols.rdstls', 'RDSTLS supported'],
  [0x08, 'rdp.negReq.requestedProtocols.hybrid_ex', 'CredSSP with Early User Authorization Result PDU supported'],
];

const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const ascii = new TextDecoder('latin1');

/** A flag word: its value and the set flags' names, then a row per flag. */
function flagsRow(name: string, abbrev: string, word: number, digits: number, totalBits: number, at: number, flags: Flag[]): ProtocolField {
  const set = flags.filter(([mask]) => (word & mask) !== 0).map(([, , n]) => `, ${n}`).join('');
  return {
    name, value: `${hex(word, digits)}${set}`, abbrev, rawBytesRange: [at, at + totalBits / 8 - 1],
    children: flags.map(([mask, flagAbbrev, n]): ProtocolField => ({
      name: n, value: (word & mask) !== 0 ? 'True' : 'False', abbrev: flagAbbrev,
      // Little-endian on the wire, so the mask's bit counts from the far end of the first byte.
      rawBytesRange: [at, at + totalBits / 8 - 1], bitfield: { bitOffset: totalBits - 1 - Math.log2(mask), bitLength: 1, totalBits },
    })),
  };
}

export interface RdpResult {
  protocolLabel: string;
  info: string;
  layers: ProtocolLayer[];
  fields: Record<string, string | number>;
}

/** Whether a segment opens with a TPKT header that fits it. */
export function looksLikeTpkt(b: Uint8Array, start: number, end: number): boolean {
  return end - start >= 7 && b[start] === 3 && b[start + 1] === 0 && u16(b, start + 2) >= 7 && start + u16(b, start + 2) <= end;
}

/** The TPKTs of one segment, each with its COTP and - on a connect - RDP's negotiation. */
export function dissectRdpSetup(b: Uint8Array, start: number, end: number): RdpResult | null {
  if (!looksLikeTpkt(b, start, end)) return null;
  const layers: ProtocolLayer[] = [];
  const info: string[] = [];
  const fields: Record<string, string | number> = {};
  let rdpSeen = false;
  for (let p = start; looksLikeTpkt(b, p, end);) {
    const length = u16(b, p + 2);
    const stop = p + length;
    layers.push({
      name: 'TPKT', summary: `TPKT, Version: 3, Length: ${length}`, rawBytesRange: [p, stop - 1],
      fields: [
        { name: 'Version', value: 3, abbrev: 'tpkt.version', rawBytesRange: [p, p] },
        { name: 'Reserved', value: 0, abbrev: 'tpkt.reserved', rawBytesRange: [p + 1, p + 1] },
        { name: 'Length', value: length, abbrev: 'tpkt.length', rawBytesRange: [p + 2, p + 3] },
      ],
    });
    const c = p + 4;
    const li = b[c];
    // The PDU type is the high nibble; the low one is credit or flags.
    const type = b[c + 1] >> 4;
    fields['cotp.type'] = type;
    const cotp: ProtocolField[] = [
      { name: 'Length', value: li, abbrev: 'cotp.li', rawBytesRange: [c, c] },
      { name: 'PDU Type', value: `${COTP_TYPES[type] ?? 'Unknown'} (${hex(type, 2)})`, abbrev: 'cotp.type', rawBytesRange: [c + 1, c + 1] },
    ];
    // RDP's cookie and negotiation sit inside the header's length, straight
    // after its seven fixed bytes, where X.224 would put its parameters.
    const userData = c + 7;
    if (type === 0x0e || type === 0x0d || type === 0x08) {
      const destref = u16(b, c + 2);
      const srcref = u16(b, c + 4);
      cotp.push(
        { name: 'Destination reference', value: hex(destref, 4), abbrev: 'cotp.destref', rawBytesRange: [c + 2, c + 3] },
        { name: 'Source reference', value: hex(srcref, 4), abbrev: 'cotp.srcref', rawBytesRange: [c + 4, c + 5] },
      );
      const tpdu = `${COTP_TYPES[type].slice(0, 2)} TPDU src-ref: ${hex(srcref, 4)} dst-ref: ${hex(destref, 4)}`;
      if (type === 0x08) {
        const cause = b[c + 6];
        cotp.push(
          { name: 'Cause', value: `${COTP_CAUSES[cause] ?? 'Unknown'} (${cause})`, abbrev: 'cotp.cause', rawBytesRange: [c + 6, c + 6] },
          { name: 'Disconnect Request(DR)', value: `${hex(srcref, 1)} -> ${hex(destref, 1)}`, abbrev: 'cotp.disconnect_request', expertInfo: { message: 'Disconnect Request' } },
        );
        info.push(tpdu);
      } else {
        const cls = b[c + 6];
        cotp.push(
          { name: 'Class', value: cls >> 4, abbrev: 'cotp.class', rawBytesRange: [c + 6, c + 6], bitfield: { bitOffset: 0, bitLength: 4, totalBits: 8 } },
          { name: 'Extended formats', value: (cls & 0x02) !== 0 ? 'True' : 'False', abbrev: 'cotp.opts.extended_formats', rawBytesRange: [c + 6, c + 6], bitfield: { bitOffset: 6, bitLength: 1, totalBits: 8 } },
          { name: 'No explicit flow control', value: (cls & 0x01) !== 0 ? 'True' : 'False', abbrev: 'cotp.opts.no_explicit_flow_control', rawBytesRange: [c + 6, c + 6], bitfield: { bitOffset: 7, bitLength: 1, totalBits: 8 } },
        );
        const rdp = rdpNegotiation(b, userData, stop, type === 0x0e, fields);
        if (rdp !== null) {
          layers.push({ name: 'ISO 8073/X.224 COTP Connection-Oriented Transport Protocol', summary: 'ISO 8073/X.224 COTP Connection-Oriented Transport Protocol', fields: cotp });
          layers.push({ name: 'Remote Desktop Protocol', summary: 'Remote Desktop Protocol', fields: rdp.rows, rawBytesRange: [userData, stop - 1] });
          info.push(rdp.info);
          rdpSeen = true;
          p = stop;
          continue;
        }
        info.push(tpdu);
      }
    } else if (type === 0x0f) {
      cotp.push(
        { name: 'TPDU number', value: hex(b[c + 2] & 0x7f, 2), abbrev: 'cotp.tpdu-number', rawBytesRange: [c + 2, c + 2], bitfield: { bitOffset: 1, bitLength: 7, totalBits: 8 } },
        { name: 'Last data unit', value: (b[c + 2] & 0x80) !== 0 ? 'Yes' : 'No', abbrev: 'cotp.eot', rawBytesRange: [c + 2, c + 2], bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 } },
      );
      info.push(`DT TPDU (${b[c + 2] & 0x7f})`);
    }
    layers.push({ name: 'ISO 8073/X.224 COTP Connection-Oriented Transport Protocol', summary: 'ISO 8073/X.224 COTP Connection-Oriented Transport Protocol', fields: cotp, rawBytesRange: [c, stop - 1] });
    p = stop;
  }
  return { protocolLabel: rdpSeen ? 'RDP' : 'COTP', info: info.join(', '), layers, fields };
}

/** A connect's user data: the routing token or cookie, then RDP_NEG_REQ, _RSP or _FAILURE. */
function rdpNegotiation(b: Uint8Array, at: number, end: number, request: boolean, fields: Record<string, string | number>): { rows: ProtocolField[]; info: string } | null {
  if (at >= end) return null;
  const rows: ProtocolField[] = [];
  const info: string[] = [];
  let p = at;
  if (request) {
    // A routing token or cookie, up to its CR LF.
    let q = p;
    while (q + 1 < end && !(b[q] === 0x0d && b[q + 1] === 0x0a)) q++;
    if (q + 1 < end) {
      const token = ascii.decode(b.subarray(p, q));
      fields['rdp.rt_cookie'] = token;
      rows.push({ name: 'Routing Token/Cookie', value: token, abbrev: 'rdp.rt_cookie', rawBytesRange: [p, q + 1] });
      info.push(token);
      p = q + 2;
    }
  }
  if (p + 8 <= end) {
    const type = b[p];
    const flags = b[p + 1];
    const length = b[p + 2] | (b[p + 3] << 8);
    const word = le32(b, p + 4);
    fields['rdp.neg_type'] = type;
    rows.push({ name: 'Type', value: `${NEG_TYPES[type] ?? 'Unknown'} (${hex(type, 2)})`, abbrev: 'rdp.neg_type', rawBytesRange: [p, p] });
    if (type === 1) {
      rows.push(
        flagsRow('Flags', 'rdp.negReq.flags', flags, 2, 8, p + 1, REQUEST_FLAGS),
        { name: 'Length', value: length, abbrev: 'rdp.neg_length', rawBytesRange: [p + 2, p + 3] },
        flagsRow('requestedProtocols', 'rdp.negReq.requestedProtocols', word, 8, 32, p + 4, REQUESTED_PROTOCOLS),
      );
      fields['rdp.negReq.requestedProtocols'] = word;
      info.push('Negotiate Request');
    } else if (type === 2) {
      rows.push(
        flagsRow('Flags', 'rdp.negRsp.flags', flags, 2, 8, p + 1, RESPONSE_FLAGS),
        { name: 'Length', value: length, abbrev: 'rdp.neg_length', rawBytesRange: [p + 2, p + 3] },
        { name: 'selectedProtocol', value: `${SELECTED_PROTOCOLS[word] ?? 'Unknown'} (${hex(word, 8)})`, abbrev: 'rdp.negReq.selectedProtocol', rawBytesRange: [p + 4, p + 7] },
      );
      fields['rdp.negReq.selectedProtocol'] = word;
      info.push('Negotiate Response');
    } else if (type === 3) {
      rows.push(
        // The failure's flags byte, drawn bare under the request's name.
        { name: 'Flags', value: hex(flags, 2), abbrev: 'rdp.negReq.flags', rawBytesRange: [p + 1, p + 1] },
        { name: 'Length', value: length, abbrev: 'rdp.neg_length', rawBytesRange: [p + 2, p + 3] },
        { name: 'failureCode', value: `${FAILURE_CODES[word] ?? 'Unknown'} (${hex(word, 8)})`, abbrev: 'rdp.negFailure.failureCode', rawBytesRange: [p + 4, p + 7] },
      );
      fields['rdp.negFailure.failureCode'] = word;
      info.push(`Negotiate Failure, failureCode ${FAILURE_CODES[word] ?? 'Unknown'}`);
    }
  }
  return rows.length === 0 ? null : { rows, info: info.join(', ') };
}
