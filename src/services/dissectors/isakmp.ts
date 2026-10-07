/**
 * IKE - ISAKMP (RFC 2408/2409) and IKEv2 (RFC 7296) - on UDP 500 and 4500.
 *
 *   IKE_SA_INIT MID=00 Initiator Request
 *   Identity Protection (Main Mode)
 *
 * How an IPsec VPN starts: Windows' and macOS's built-in clients, strongSwan,
 * Cisco and Fortinet gateways, L2TP/IPsec. What it shows before encryption
 * takes over is the part that fails - which proposals each side offered and
 * which it chose, the key-exchange group, NAT detection, which vendor's
 * software is talking (Vendor IDs), and the notify that says why it stopped
 * (`NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`, `AUTHENTICATION_FAILED`).
 *
 * The tree is the reference's: every payload a row holding its generic header
 * and its body, proposals inside the SA, transforms inside proposals,
 * attributes inside transforms. The names are `isakmpTables.ts`, generated
 * from `tshark -G values`; the vendor IDs, which that does not print, are the
 * ones listed here, matched as the reference matches them, by prefix.
 *
 * Without the keys, an encrypted IKEv1 message is its bytes, and IKEv2's
 * Encrypted payload is a 4-byte IV and the rest - the reference's own split
 * when it has no decryption table to consult.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';
import { hexColons } from '../dissect/hexBytes';
import * as T from './isakmpTables';

const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const u32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const utf8 = new TextDecoder('utf-8', { fatal: false });
const named = (name: string | undefined, value: number) => `${name ?? 'Unknown'} (${value})`;
const range = (table: T.RangeTable, value: number) => named(T.rangeName(table, value), value);

/** Known vendor IDs, by their leading bytes: the reference names a VID whose prefix is one of these. */
const VENDOR_IDS: readonly [string, string][] = [
  ['4a131c81070358455c5728f20e95452f', 'RFC 3947 Negotiation of NAT-Traversal in the IKE'],
  ['90cb80913ebb696e086381b5ec427b1f', 'draft-ietf-ipsec-nat-t-ike-02\\n'],
  ['cd60464335df21f87cfdb2fc68b6a448', 'draft-ietf-ipsec-nat-t-ike-02'],
  ['7d9419a65310ca6f2c179d9215529d56', 'draft-ietf-ipsec-nat-t-ike-03'],
  ['4485152d18b6bbcd0be8a8469579ddcc', 'draft-ietf-ipsec-nat-t-ike-00'],
  ['16f6ca16e4a4066d83821a0f0aeaa862', 'draft-ietf-ipsec-nat-t-ike-01'],
  ['c40fee00d5d39ddb1fc762e09b7cfea7', 'Testing NAT-T RFC'],
  ['afcad71368a1f1c96b8696fc77570100', 'RFC 3706 DPD (Dead Peer Detection)'],
  ['09002689dfd6b712', 'XAUTH'],
  // Its last two bytes are a version, which the title carries (`CISCO-UNITY 1.0`).
  ['12f5f28c457168a9702d9fe274cc', 'CISCO-UNITY'],
  ['1f07f70eaa6514d3b0fa96542a500100', 'CISCO-CONCENTRATOR'],
  ['4048b7d56ebce88525e7de7f00d6c2d3', 'Cisco Fragmentation'],
  ['1e2b516905991c7d7c96fcbfb587e461', 'MS NT5 ISAKMPOAKLEY'],
  ['fb1de3cdf341b7ea16b7e5be0855f120', 'MS-Negotiation Discovery Capable'],
  ['26244d38eddb61b3172a36e3d0cfb819', 'Microsoft Vid-Initial-Contact'],
  ['e3a5966a76379fe707228231e5ce8652', 'IKE CGA Version 1'],
  ['882fe56d6fd20dbc2251613b2ebe5beb', 'strongSwan'],
  ['8299031757a36082c6a621de', 'Fortigate (Fortinet)'],
  ['4865617274426561745f4e6f74696679', 'Heartbeat Notify'],
  ['f4ed19e0c114eb516faaac0ee37daf2807b4381f', 'CryptoPro/GOST 0.1 / Check Point R65'],
];
/** What the version after `MS NT5 ISAKMPOAKLEY` is; the reference's table stops at Windows Vista. */
const MS_NT5_VERSIONS: Record<number, string> = {
  2: 'Windows 2000', 3: 'Windows XP SP1', 4: 'Windows 2003 and Windows XP SP2', 5: 'Windows Vista',
};
/** IKEv1 transform IDs under the ISAKMP protocol (RFC 2407 §4.4.2). */
const V1_ISAKMP_TRANSFORMS: Record<number, string> = { 0: 'RESERVED', 1: 'KEY_IKE' };
/** RFC 7427's hash algorithms, for SIGNATURE_HASH_ALGORITHMS. */
const SIGNATURE_HASHES: Record<number, string> = {
  0: 'Reserved', 1: 'SHA1', 2: 'SHA2-256', 3: 'SHA2-384', 4: 'SHA2-512', 5: 'Identity', 6: 'STREEBOG_256', 7: 'STREEBOG_512',
};

/** IKEv1's payload types are 1-22 and 128+; IKEv2's 33-53. */
const V1 = 1;
const V2 = 2;

function vendorName(b: Uint8Array, from: number, to: number): string {
  const hex = hexColons(b, from, to).replace(/:/g, '');
  for (const [prefix, name] of VENDOR_IDS) if (hex.startsWith(prefix)) return name;
  return 'Unknown Vendor ID';
}

const row = (name: string, value: string | number, abbrev: string, from?: number, to?: number): ProtocolField =>
  ({ name, value, abbrev, ...(from !== undefined && to !== undefined && to > from ? { rawBytesRange: [from, to - 1] as [number, number] } : {}) });
const bits = (name: string, value: string | number, abbrev: string, at: number, bitOffset: number, bitLength: number, totalBits: number): ProtocolField =>
  ({ name, value, abbrev, rawBytesRange: [at, at + totalBits / 8 - 1], bitfield: { bitOffset, bitLength, totalBits } });

/** One data attribute (RFC 2408 §3.3): TV when the top bit is set, TLV when not. */
function attribute(b: Uint8Array, at: number, end: number, version: number): { node: ProtocolField; next: number } | null {
  if (at + 4 > end) return null;
  const tv = (b[at] & 0x80) !== 0;
  const type = u16(b, at) & 0x7fff;
  const length = tv ? 2 : u16(b, at + 2);
  const valueAt = tv ? at + 2 : at + 4;
  const valueEnd = Math.min(end, valueAt + length);
  let value = 0;
  for (let i = valueAt; i < valueEnd && i < valueAt + 6; i++) value = value * 256 + b[i];
  const v2 = version === V2;
  const typeName = T.rangeName(v2 ? T.IKE2_ATTR_TYPE : T.IKE_ATTR_TYPE, type) ?? 'Unknown';
  const prefix = v2 ? 'isakmp.ike2.attr' : 'isakmp.ike.attr';
  const children: ProtocolField[] = [
    bits('Format', tv ? 'Type/Value (TV)' : 'Type/Length/Value (TLV)', v2 ? 'isakmp.ike2.attr.format' : 'isakmp.ike.attr.format', at, 0, 1, 16),
    row('Type', `${typeName} (${type})`, v2 ? 'isakmp.ike2.attr.type' : 'isakmp.ike.attr.type', at, at + 2),
  ];
  if (!tv) children.push(row('Length', length, v2 ? 'isakmp.ike2.attr.length' : 'isakmp.ike.attr.length', at + 2, at + 4));
  children.push(row('Value', hexColons(b, valueAt, valueEnd), v2 ? 'isakmp.ike2.attr.value' : 'isakmp.ike.attr.value', valueAt, valueEnd));
  // The value, read as what the type says it is.
  let shown: string = String(value);
  if (v2) {
    if (type === 14) children.push(row('Key Length', value, 'isakmp.ike2.attr.key_length', valueAt, valueEnd));
  } else {
    const decoded: Record<number, [string, string, Readonly<Record<number, string>> | null]> = {
      1: ['Encryption Algorithm', 'isakmp.ike.attr.encryption_algorithm', T.IKE_ENCRYPTION],
      2: ['HASH Algorithm', 'isakmp.ike.attr.hash_algorithm', T.IKE_HASH],
      3: ['Authentication Method', 'isakmp.ike.attr.authentication_method', T.IKE_AUTH_METHOD],
      4: ['Group Description', 'isakmp.ike.attr.group_description', T.IKE_GROUP],
      5: ['Group Type', 'isakmp.ike.attr.group_type', T.IKE_GROUP_TYPE],
      11: ['Life Type', 'isakmp.ike.attr.life_type', T.IKE_LIFE_TYPE],
      12: ['Life Duration', 'isakmp.ike.attr.life_duration', null],
      14: ['Key Length', 'isakmp.ike.attr.key_length', null],
    };
    const known = decoded[type];
    if (known !== undefined) {
      const [label, abbrev, table] = known;
      if (table !== null) shown = table[value] ?? 'Unknown';
      children.push(row(label, table !== null ? named(table[value], value) : value, abbrev, valueAt, valueEnd));
    }
  }
  return {
    node: {
      name: `${v2 ? 'Transform Attribute' : 'IKE Attribute'} (t=${type},l=${length})`, value: `${typeName}: ${shown}`,
      abbrev: prefix, rawBytesRange: [at, valueEnd - 1], children,
    },
    next: valueEnd,
  };
}

/** A transform (RFC 2408 §3.5 / RFC 7296 §3.3.2), inside a proposal. */
function transform(b: Uint8Array, at: number, end: number, version: number, protocol: number): ProtocolField[] {
  const rows: ProtocolField[] = [];
  if (version === V2) {
    if (at + 4 > end) return rows;
    const type = b[at];
    const id = u16(b, at + 2);
    const ids: Record<number, [string, string, Readonly<Record<number, string>>]> = {
      1: ['Transform ID (ENCR)', 'isakmp.tf.id.encr', T.ENCR], 2: ['Transform ID (PRF)', 'isakmp.tf.id.prf', T.PRF],
      3: ['Transform ID (INTEG)', 'isakmp.tf.id.integ', T.INTEG], 4: ['Transform ID (KE)', 'isakmp.tf.id.dh', T.KE_METHOD],
      5: ['Transform ID (ESN)', 'isakmp.tf.id.esn', T.ESN],
    };
    const known = ids[type];
    rows.push(
      row('Transform Type', range(T.TRANSFORM_TYPE, type), 'isakmp.tf.type', at, at + 1),
      row('Reserved', hexColons(b, at + 1, at + 2), 'isakmp.reserved', at + 1, at + 2),
      known !== undefined
        ? row(known[0], named(known[2][id], id), known[1], at + 2, at + 4)
        : row('Transform ID', id, 'isakmp.tf.id', at + 2, at + 4),
    );
    at += 4;
  } else {
    if (at + 4 > end) return rows;
    const id = b[at + 1];
    rows.push(
      row('Transform number', b[at], 'isakmp.trans.number', at, at + 1),
      row('Transform ID', named(protocol === 1 ? V1_ISAKMP_TRANSFORMS[id] : undefined, id), 'isakmp.trans.id', at + 1, at + 2),
      row('Reserved', hexColons(b, at + 2, at + 4), 'isakmp.reserved', at + 2, at + 4),
    );
    at += 4;
  }
  while (at < end && rows.length < 64) {
    const attr = attribute(b, at, end, version);
    if (attr === null) break;
    rows.push(attr.node);
    at = attr.next;
  }
  return rows;
}

/** A proposal and its transforms (RFC 2408 §3.4 / RFC 7296 §3.3.1). */
function proposal(b: Uint8Array, at: number, end: number, version: number): ProtocolField[] {
  if (at + 4 > end) return [];
  const protocol = b[at + 1];
  const spiSize = b[at + 2];
  const count = b[at + 3];
  const rows: ProtocolField[] = [
    row('Proposal number', b[at], 'isakmp.prop.number', at, at + 1),
    row('Protocol ID', named((version === V2 ? T.PROTOCOL_V2 : T.PROTOCOL_V1)[protocol], protocol), 'isakmp.prop.protoid', at + 1, at + 2),
    row('SPI Size', spiSize, 'isakmp.spisize', at + 2, at + 3),
    row('Proposal transforms', count, 'isakmp.prop.transforms', at + 3, at + 4),
  ];
  let p = at + 4;
  if (spiSize > 0 && p + spiSize <= end) {
    rows.push(row('SPI', hexColons(b, p, p + spiSize), 'isakmp.spi', p, p + spiSize));
    p += spiSize;
  }
  for (let i = 0; p + 4 <= end && i < 64; i++) {
    const next = b[p];
    const length = u16(b, p + 2);
    if (length < 4) break;
    const stop = Math.min(end, p + length);
    rows.push({
      name: 'Payload', value: version === V2 ? 'Transform (3)' : `Transform (3) # ${i + 1}`, abbrev: 'isakmp.typepayload',
      rawBytesRange: [p, stop - 1],
      children: [
        row('Next payload', range(T.PAYLOAD, next), 'isakmp.nextpayload', p, p + 1),
        row('Reserved', hexColons(b, p + 1, p + 2), 'isakmp.reserved', p + 1, p + 2),
        row('Payload length', length, 'isakmp.payloadlength', p + 2, p + 4),
        ...transform(b, p + 4, stop, version, protocol),
      ],
    });
    p = stop;
    if (next === 0) break;
  }
  return rows;
}

/** The body of one payload, by its type; the generic header is drawn by the caller. */
function payloadBody(
  b: Uint8Array, type: number, at: number, end: number, version: number, fields: Record<string, string | number>,
): { rows: ProtocolField[]; suffix: string } {
  const rows: ProtocolField[] = [];
  let suffix = '';
  const bytes = (name: string, abbrev: string, from: number, to: number) => row(name, hexColons(b, from, to), abbrev, from, to);
  if (type === 1 || type === 33) {
    let p = at;
    if (version === V1 && at + 8 <= end) {
      const situation = u32(b, at + 4);
      const flag = (bit: number, name: string, abbrev: string) =>
        bits(name, (situation & (1 << bit)) !== 0 ? 'True' : 'False', abbrev, at + 4, 31 - bit, 1, 32);
      rows.push(
        row('Domain of interpretation', named(T.SA_DOI[u32(b, at)], u32(b, at)), 'isakmp.sa.doi', at, at + 4),
        {
          ...row('Situation', hexColons(b, at + 4, at + 8).replace(/:/g, ''), 'isakmp.sa.situation', at + 4, at + 8),
          children: [
            flag(0, 'Identity Only', 'isakmp.sa.situation.identity_only'),
            flag(1, 'Secrecy', 'isakmp.sa.situation.secrecy'),
            flag(2, 'Integrity', 'isakmp.sa.situation.integrity'),
          ],
        },
      );
      p = at + 8;
    }
    for (let i = 0; p + 4 <= end && i < 64; i++) {
      const next = b[p];
      const length = u16(b, p + 2);
      if (length < 8) break;
      const stop = Math.min(end, p + length);
      rows.push({
        name: 'Payload', value: `Proposal (2) # ${b[p + 4]}`, abbrev: 'isakmp.typepayload', rawBytesRange: [p, stop - 1],
        children: [
          row('Next payload', range(T.PAYLOAD, next), 'isakmp.nextpayload', p, p + 1),
          row('Reserved', hexColons(b, p + 1, p + 2), 'isakmp.reserved', p + 1, p + 2),
          row('Payload length', length, 'isakmp.payloadlength', p + 2, p + 4),
          ...proposal(b, p + 4, stop, version),
        ],
      });
      p = stop;
      if (next === 0) break;
    }
    // Bytes the SA's length claims that its last proposal did not.
    if (p < end) rows.push(bytes('Extra data', 'isakmp.extradata', p, end));
  } else if (type === 4 || type === 34) {
    let p = at;
    if (version === V2 && at + 4 <= end) {
      fields['isakmp.key_exchange.dh_group'] = u16(b, at);
      rows.push(
        row('Key Exchange Method', named(T.KE_METHOD[u16(b, at)], u16(b, at)), 'isakmp.key_exchange.dh_group', at, at + 2),
        bytes('Reserved', 'isakmp.reserved', at + 2, at + 4),
      );
      p = at + 4;
    }
    if (p < end) rows.push(bytes('Key Exchange Data', 'isakmp.key_exchange.data', p, end));
  } else if (type === 10 || type === 40) {
    rows.push(bytes('Nonce DATA', 'isakmp.nonce', at, end));
  } else if (type === 13 || type === 43) {
    const vendor = vendorName(b, at, end);
    suffix = ` : ${vendor}`;
    rows.push(bytes('Vendor ID', 'isakmp.vid_bytes', at, end), row('Vendor ID', vendor, 'isakmp.vid_string', at, end));
    if (vendor === 'CISCO-UNITY' && end - at >= 16) {
      suffix += ` ${b[at + 14]}.${b[at + 15]}`;
      rows.push(
        row('CISCO-UNITY Major version', b[at + 14], 'isakmp.vid.cisco_unity.major', at + 14, at + 15),
        row('CISCO-UNITY Minor version', b[at + 15], 'isakmp.vid.cisco_unity.minor', at + 15, at + 16),
      );
    }
    if (vendor === 'MS NT5 ISAKMPOAKLEY' && end - at >= 20) {
      const v = u32(b, at + 16);
      rows.push(row('MS NT5 ISAKMPOAKLEY', named(MS_NT5_VERSIONS[v], v), 'isakmp.vid.ms_nt5_isakmpoakley', at + 16, at + 20));
    }
  } else if (type === 20 || type === 130) {
    rows.push(bytes('HASH of the address and port', 'isakmp.ike.nat_hash', at, end));
  } else if (type === 8) {
    rows.push(bytes('Hash DATA', 'isakmp.hash', at, end));
  } else if ((type === 5 || type === 35 || type === 36) && at + 4 <= end) {
    const idType = b[at];
    rows.push(row('ID type', range(version === V2 ? T.ID_TYPE_V2 : T.ID_TYPE_V1, idType), 'isakmp.id.type', at, at + 1));
    if (version === V1) {
      rows.push(
        row('Protocol ID', b[at + 1] === 17 ? 'UDP (17)' : b[at + 1] === 6 ? 'TCP (6)' : String(b[at + 1]), 'isakmp.id.protoid', at + 1, at + 2),
        row('Port', u16(b, at + 2), 'isakmp.id.port', at + 2, at + 4),
      );
    } else {
      rows.push(bytes('Reserved', 'isakmp.reserved', at + 1, at + 4));
    }
    const data = at + 4;
    const shown = idType === 1 && data + 4 <= end ? formatIpv4Address(b, data)
      : idType === 5 && data + 16 <= end ? formatIpv6Address(b, data)
        : idType === 2 || idType === 3 ? utf8.decode(b.subarray(data, end)) : null;
    if (shown !== null) {
      const child = idType === 1 ? row('ID_IPV4_ADDR', shown, 'isakmp.id.data.ipv4_addr', data, end)
        : idType === 5 ? row('ID_IPV6_ADDR', shown, 'isakmp.id.data.ipv6_addr', data, end)
          : idType === 2 ? row('ID_FQDN', shown, 'isakmp.id.data.fqdn', data, end)
            : row('ID_USER_FQDN', shown, 'isakmp.id.data.user_fqdn', data, end);
      rows.push({ name: `Identification Data:${shown}`, value: '', abbrev: 'isakmp.id.data', rawBytesRange: [data, end - 1], children: [child] });
    } else if (data < end) {
      rows.push(bytes('Identification Data', 'isakmp.id.data', data, end));
    }
  } else if ((type === 11 || type === 41) && at + 4 <= end) {
    // Notify: DOI in IKEv1 only, then protocol, SPI size, type, SPI, data.
    let p = at;
    if (version === V1) {
      rows.push(row('Domain of interpretation', named(T.SA_DOI[u32(b, at)], u32(b, at)), 'isakmp.notify.doi', at, at + 4));
      p += 4;
    }
    if (p + 4 > end) return { rows, suffix };
    const spiSize = b[p + 1];
    const message = u16(b, p + 2);
    const messageName = T.rangeName(version === V2 ? T.NOTIFY_V2 : T.NOTIFY_V1, message);
    fields['isakmp.notify.msgtype'] = message;
    suffix = ` - ${messageName ?? 'Unknown'}`;
    rows.push(
      row('Protocol ID', named((version === V2 ? T.PROTOCOL_V2 : T.PROTOCOL_V1)[b[p]], b[p]), 'isakmp.notify.protoid', p, p + 1),
      row('SPI Size', spiSize, 'isakmp.spisize', p + 1, p + 2),
      row('Notify Message Type', named(messageName, message), 'isakmp.notify.msgtype', p + 2, p + 4),
    );
    p += 4;
    if (spiSize > 0 && p + spiSize <= end) {
      rows.push(bytes('SPI', 'isakmp.spi', p, p + spiSize));
      p += spiSize;
    }
    rows.push(p < end ? bytes('Notification DATA', 'isakmp.notify.data', p, end) : row('Notification DATA', '<MISSING>', 'isakmp.notify.data'));
    if (version === V2 && message === 16431) {
      for (let q = p; q + 2 <= end; q += 2) {
        rows.push(row('Supported Signature Hash Algorithm', named(SIGNATURE_HASHES[u16(b, q)], u16(b, q)),
          'isakmp.notify.data.signature_hash_algorithms', q, q + 2));
      }
    } else if (version === V2 && message === 17 && p + 2 <= end) {
      rows.push(row('Accepted KE method', named(T.KE_METHOD[u16(b, p)], u16(b, p)), 'isakmp.notify.data.accepted_dh_group', p, p + 2));
    }
  } else if ((type === 7 || type === 38) && at < end) {
    rows.push(
      row('Certificate Type', range(version === V2 ? T.CERT_V2 : T.CERT_V1, b[at]), 'isakmp.certreq.type', at, at + 1),
      ...(at + 1 < end ? [bytes('Certificate Authority Data', 'isakmp.ike.certreq.authority', at + 1, end)] : []),
    );
  } else if (type === 46 || type === 53) {
    // Encrypted: an IV whose length only the negotiated cipher knows. The
    // reference, with no keys to consult, takes four bytes and calls the
    // rest encrypted, and so does this.
    if (at + 4 <= end) rows.push(bytes('Initialization Vector', 'isakmp.enc.iv', at, at + 4));
    if (at + 4 < end) rows.push(row('Encrypted Data', '', 'isakmp.enc.data', at + 4, end));
  } else if (at < end) {
    rows.push(bytes('Data Payload', 'isakmp.datapayload', at, end));
  }
  return { rows, suffix };
}

export interface IsakmpResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

export function dissectIsakmp(b: Uint8Array, start: number, end: number): IsakmpResult | null {
  if (start + 28 > end) return null;
  const firstPayload = b[start + 16];
  const version = b[start + 17] >> 4;
  const exchange = b[start + 18];
  const flags = b[start + 19];
  const messageId = u32(b, start + 20);
  const length = u32(b, start + 24);
  const stop = Math.min(end, start + Math.max(28, length));
  const v2 = version === 2;
  const fields: Record<string, string | number> = {
    'isakmp.ispi': hexColons(b, start, start + 8).replace(/:/g, ''),
    'isakmp.rspi': hexColons(b, start + 8, start + 16).replace(/:/g, ''),
    'isakmp.version': version,
    'isakmp.exchangetype': exchange,
    'isakmp.messageid': messageId,
  };
  const exchangeName = T.EXCHANGE_TYPE[exchange] ?? 'Unknown';
  const flagNames = v2
    ? [(flags & 0x08) !== 0 ? 'Initiator' : 'Responder', (flags & 0x10) !== 0 ? 'Higher version' : 'No higher version', (flags & 0x20) !== 0 ? 'Response' : 'Request']
    : [];
  const flagRows: ProtocolField[] = v2
    ? [
      bits('Initiator', flagNames[0], 'isakmp.flag_i', start + 19, 4, 1, 8),
      bits('Version', flagNames[1], 'isakmp.flag_v', start + 19, 3, 1, 8),
      bits('Response', flagNames[2], 'isakmp.flag_r', start + 19, 2, 1, 8),
    ]
    : [
      bits('Encryption', (flags & 0x01) !== 0 ? 'Encrypted' : 'Not encrypted', 'isakmp.flag_e', start + 19, 7, 1, 8),
      bits('Commit', (flags & 0x02) !== 0 ? 'Commit' : 'No commit', 'isakmp.flag_c', start + 19, 6, 1, 8),
      bits('Authentication', (flags & 0x04) !== 0 ? 'Authentication' : 'No authentication', 'isakmp.flag_a', start + 19, 5, 1, 8),
    ];
  const flagHex = `0x${flags.toString(16).padStart(2, '0')}`;
  const rows: ProtocolField[] = [
    row('Initiator SPI', hexColons(b, start, start + 8), 'isakmp.ispi', start, start + 8),
    row('Responder SPI', hexColons(b, start + 8, start + 16), 'isakmp.rspi', start + 8, start + 16),
    row('Next payload', range(T.PAYLOAD, firstPayload), 'isakmp.nextpayload', start + 16, start + 17),
    {
      ...row('Version', `${version}.${b[start + 17] & 0x0f}`, 'isakmp.version', start + 17, start + 18),
      children: [
        bits('MjVer', `0x${version.toString(16)}`, 'isakmp.mjver', start + 17, 0, 4, 8),
        bits('MnVer', `0x${(b[start + 17] & 0x0f).toString(16)}`, 'isakmp.mnver', start + 17, 4, 4, 8),
      ],
    },
    row('Exchange type', named(exchangeName, exchange), 'isakmp.exchangetype', start + 18, start + 19),
    { ...row('Flags', v2 ? `${flagHex} (${flagNames.join(', ')})` : flagHex, 'isakmp.flags', start + 19, start + 20), children: flagRows },
    row('Message ID', `0x${messageId.toString(16).padStart(8, '0')}`, 'isakmp.messageid', start + 20, start + 24),
    row('Length', length, 'isakmp.length', start + 24, start + 28),
  ];

  if (!v2 && (flags & 0x01) !== 0) {
    // IKEv1 encrypts everything after the header; there is nothing to walk.
    rows.push({ name: `Encrypted Data (${stop - start - 28} bytes)`, value: '', abbrev: 'isakmp.enc.data', rawBytesRange: [start + 28, stop - 1] });
  } else {
    let next = firstPayload;
    let p = start + 28;
    for (let i = 0; next !== 0 && p + 4 <= stop && i < 64; i++) {
      const type = next;
      next = b[p];
      const payloadLength = u16(b, p + 2);
      if (payloadLength < 4) break;
      const payloadEnd = Math.min(stop, p + payloadLength);
      const header: ProtocolField[] = v2
        ? [
          row('Next payload', range(T.PAYLOAD, next), 'isakmp.nextpayload', p, p + 1),
          bits('Critical Bit', (b[p + 1] & 0x80) !== 0 ? 'Critical' : 'Not critical', 'isakmp.criticalpayload', p + 1, 0, 1, 8),
          bits('Reserved', `0x${(b[p + 1] & 0x7f).toString(16).padStart(2, '0')}`, 'isakmp.reserved7', p + 1, 1, 7, 8),
          row('Payload length', payloadLength, 'isakmp.payloadlength', p + 2, p + 4),
        ]
        : [
          row('Next payload', range(T.PAYLOAD, next), 'isakmp.nextpayload', p, p + 1),
          row('Reserved', hexColons(b, p + 1, p + 2), 'isakmp.reserved', p + 1, p + 2),
          row('Payload length', payloadLength, 'isakmp.payloadlength', p + 2, p + 4),
        ];
      const body = payloadBody(b, type, p + 4, payloadEnd, v2 ? V2 : V1, fields);
      rows.push({
        name: 'Payload', value: `${range(T.PAYLOAD, type)}${body.suffix}`, abbrev: 'isakmp.typepayload',
        rawBytesRange: [p, payloadEnd - 1], children: [...header, ...body.rows],
      });
      p = payloadEnd;
      // An Encrypted payload's Next Payload names what is inside it.
      if (type === 46 || type === 53) break;
    }
  }

  const info = v2
    ? `${exchangeName} MID=${String(messageId).padStart(2, '0')} ${flagNames[0]} ${flagNames[2]}`
    : exchangeName;
  return {
    protocolLabel: 'ISAKMP',
    info,
    layer: { name: 'Internet Security Association and Key Management Protocol', summary: info, fields: rows, rawBytesRange: [start, stop - 1] },
    fields,
  };
}

export interface EspSequence {
  /** The sequence number this SPI's next packet should have carried. */
  expected: number;
  /** The frame this SPI was last seen in. */
  previousFrame: number;
}

/**
 * ESP (RFC 4303): its SPI and sequence number, and - when a tracker has seen
 * this SPI before and this packet is not the next - what was expected instead,
 * as the reference's sequence analysis reports it.
 */
export function dissectEsp(b: Uint8Array, start: number, end: number, sequence: EspSequence | null): { info: string; layer: ProtocolLayer; fields: Record<string, string | number> } | null {
  if (start + 8 > end) return null;
  const spi = u32(b, start);
  const seq = u32(b, start + 4);
  const spiHex = spi.toString(16).padStart(8, '0');
  const rows: ProtocolField[] = [
    row('ESP SPI', `0x${spiHex} (${spi})`, 'esp.spi', start, start + 4),
    row('ESP Sequence', seq, 'esp.sequence', start + 4, start + 8),
  ];
  if (sequence !== null && seq !== sequence.expected) {
    const { expected } = sequence;
    const message = seq > expected ? `${seq - expected} missing`
      : seq === expected - 1 ? `${seq} repeated` : `${expected - seq} less than expected`;
    const warning = `Wrong Sequence Number for SPI ${spiHex} - ${message}`;
    rows.push(
      {
        name: 'Expected SN', value: seq > expected ? `${expected} (${seq - expected} SNs missing)` : expected,
        abbrev: 'esp.sequence-analysis.expected-sn', generated: true,
        children: [{ name: warning, value: '', abbrev: 'esp.sequence-analysis.wrong-sequence-number', expertInfo: { message: warning, category: 'Loss' } }],
      },
      { name: 'Previous Frame', value: sequence.previousFrame, abbrev: 'esp.sequence-analysis.previous-frame', generated: true, linkToFrame: sequence.previousFrame },
    );
  }
  const info = `ESP (SPI=0x${spiHex})`;
  return {
    info,
    layer: { name: 'Encapsulating Security Payload', summary: info, fields: rows, rawBytesRange: [start, end - 1] },
    fields: { 'esp.spi': spi, 'esp.sequence': seq },
  };
}
