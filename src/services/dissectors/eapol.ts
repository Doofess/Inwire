/**
 * 802.1X: EAPOL (ethertype 0x888E) and the EAP it carries.
 *
 *   Key (Message 1 of 4)
 *   Request, Identity
 *   Request, Protected EAP (EAP-PEAP)
 *
 * The frames a laptop sends every time it joins a protected Wi-Fi network or a
 * port-authenticated wired one. The four-way handshake is what a "connected
 * but no internet" or "keeps dropping" capture is about, and it was reaching
 * the packet list as an ethertype with no Info.
 *
 * **Which message of the handshake a frame is** is not on the wire; the
 * reference works it out from the Key Information bits, and so does this
 * (`keyMessage`): a pairwise key with Key ACK is message 3 when it says
 * Install and message 1 when it does not; without Key ACK it is message 2 when
 * it carries key data, and otherwise message 4 when it is Secure or its nonce
 * is zero. A group key is message 1 of 2 with Key ACK and 2 of 2 without. A
 * frame with Request or Error set is a request, and numbered as none.
 *
 * The key data is drawn as bytes: in message 2 it is the station's RSN element
 * (which the reference decodes as an 802.11 tag), in 3 and the group message it
 * is encrypted. EAP-TLS, -TTLS, -PEAP and -FAST are drawn to their flags and
 * length; the TLS handshake inside them is not dissected here.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import type { LeafResult } from './dispatch';

const EAPOL_VERSIONS: Record<number, string> = { 1: '802.1X-2001', 2: '802.1X-2004', 3: '802.1X-2010' };
const EAPOL_TYPES: Record<number, string> = {
  0: 'EAP Packet', 1: 'Start', 2: 'Logoff', 3: 'Key', 4: 'Encapsulated ASF Alert', 5: 'MKA',
  6: 'Announcement (Generic)', 7: 'Announcement (Specific)', 8: 'Announcement Request',
};
const KEY_DESCRIPTORS: Record<number, string> = { 1: 'RC4 Descriptor', 2: 'EAPOL RSN Key', 254: 'EAPOL WPA Key' };
const KEY_DESCRIPTOR_VERSIONS: Record<number, string> = {
  1: 'RC4 Cipher, HMAC-MD5 MIC', 2: 'AES Cipher, HMAC-SHA1 MIC', 3: 'AES Cipher, AES-128-CMAC MIC',
};

const EAP_CODES: Record<number, string> = {
  1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure', 5: 'Initiate', 6: 'Finish',
};
/** The reference's `eap.type` table, as `tshark -G values` prints it. */
const EAP_TYPES: Record<number, string> = {
  1: 'Identity', 2: 'Notification', 3: 'Legacy Nak (Response Only)', 4: 'MD5-Challenge EAP (EAP-MD5-CHALLENGE)',
  5: 'One-Time Password EAP (EAP-OTP)', 6: 'Generic Token Card EAP (EAP-GTC)', 7: 'Allocated', 8: 'Allocated',
  9: 'RSA Public Key Authentication EAP (EAP-RSA-PKA)', 10: 'DSS Unilateral EAP (EAP-DSS)', 11: 'KEA EAP (EAP-KEA)',
  12: 'KEA Validate EAP (EAP-KEA-VALIDATE)', 13: 'TLS EAP (EAP-TLS)', 14: 'Defender Token EAP (EAP-AXENT)',
  15: 'RSA Security SecurID EAP (EAP-RSA-SECURID)', 16: 'Arcot Systems EAP (EAP-ARCOT-SYSTEMS)',
  17: 'Cisco Wireless EAP / Lightweight EAP (EAP-LEAP)', 18: 'GSM Subscriber Identity Modules EAP (EAP-SIM)',
  19: 'Secure Remote Password SHA1 Part 1 EAP (EAP-SRP-SHA1-PART1)',
  20: 'Secure Remote Password SHA1 Part 2 EAP (EAP-SRP-SHA1-PART2)', 21: 'Tunneled TLS EAP (EAP-TTLS)',
  22: 'Remote Access Service EAP (EAP-RAS)', 23: 'UMTS Authentication and Key Agreement EAP (EAP-AKA)',
  24: '3Com Wireless EAP (EAP-3COM-WIRELESS)', 25: 'Protected EAP (EAP-PEAP)', 26: 'MS-Authentication EAP (EAP-MS-AUTH)',
  27: 'Mutual Authentication w/Key Exchange EAP (EAP-MAKE)', 28: 'CRYPTOCard EAP (EAP-CRYPTOCARD)',
  29: 'MS-CHAP-v2 EAP (EAP-MS-CHAP-V2)', 30: 'DynamID EAP (EAP-DYNAMID)', 31: 'Rob EAP (EAP-ROB)',
  32: 'Protected One-Time Password EAP (EAP-POTP)', 33: 'MS-Authentication TLV EAP (EAP-MS-AUTH-TLV)',
  34: 'SentriNET (EAP-SENTRINET)', 35: 'Actiontec Wireless EAP (EAP-ACTIONTEC-WIRELESS)',
  36: 'Cogent Systems Biometrics Authentication EAP (EAP-COGENT-BIOMETRIC)', 37: 'AirFortress EAP (EAP-AIRFORTRESS)',
  38: 'HTTP Digest EAP (EAP-HTTP-DIGEST)', 39: 'SecureSuite EAP (EAP-SECURESUITE)',
  40: 'DeviceConnect EAP (EAP-DEVICECONNECT)', 41: 'Simple Password Exponential Key Exchange EAP (EAP-SPEKE)',
  42: 'MOBAC EAP (EAP-MOBAC)', 43: 'Flexible Authentication via Secure Tunneling EAP (EAP-FAST)',
  44: 'ZoneLabs EAP (EAP-ZLXEAP)', 45: 'Link EAP (EAP-LINK)', 46: 'Password Authenticated eXchange EAP (EAP-PAX)',
  47: 'Pre-Shared Key EAP (EAP-PSK)', 48: 'Shared-secret Authentication and Key Establishment EAP (EAP-SAKE)',
  49: 'Internet Key Exchange v2 EAP (EAP-IKEv2)', 50: "UMTS Authentication and Key Agreement' EAP (EAP-AKA')",
  51: 'Generalized Pre-Shared Key EAP (EAP-GPSK)', 52: 'Password EAP (EAP-pwd)',
  53: 'Encrypted Key Exchange v1 EAP (EAP-EKEv1)', 55: 'Tunneled EAP protocol', 254: 'Expanded Type', 255: 'Experimental',
};
/** The TLS-tunnelled methods: a flags octet, an optional length, then TLS. */
const TLS_METHODS = new Set([13, 21, 25, 43]);

const named = (table: Record<number, string>, value: number) => `${table[value] ?? 'Unknown'} (${value})`;
const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const utf8 = new TextDecoder('utf-8', { fatal: false });

/** One bit of a 16-bit word, as the reference draws it: `.... 1... = Key ACK: Set`. */
function flagRow(name: string, abbrev: string, word: number, bit: number, at: number, on = 'Set', off = 'Not set'): ProtocolField {
  return {
    name, value: (word & (1 << (15 - bit))) !== 0 ? on : off, abbrev,
    rawBytesRange: [at, at + 1], bitfield: { bitOffset: bit, bitLength: 1, totalBits: 16 },
  };
}

/**
 * Which message of the four-way (or two-way group) handshake this is, or null
 * for a request or error report, which the reference numbers as none.
 */
export function keyMessage(info: number, dataLength: number, nonceIsZero: boolean): { group: boolean; n: number } | null {
  if ((info & 0x0c00) !== 0) return null;
  const ack = (info & 0x0080) !== 0;
  if ((info & 0x0008) === 0) return { group: true, n: ack ? 1 : 2 };
  if (ack) return { group: false, n: (info & 0x0040) !== 0 ? 3 : 1 };
  if (dataLength > 0) return { group: false, n: 2 };
  return { group: false, n: (info & 0x0200) !== 0 || nonceIsZero ? 4 : 2 };
}

/** The RSN / WPA key descriptor (IEEE 802.11-2020 §12.7.2), from its Key Information on. */
function keyDescriptor(
  b: Uint8Array, at: number, end: number, rows: ProtocolField[], fields: Record<string, string | number>,
): string {
  if (at + 94 > end) return 'Key';
  const info = u16(b, at);
  const dataLength = u16(b, at + 92);
  const nonceIsZero = b.subarray(at + 12, at + 44).every((x) => x === 0);
  const message = keyMessage(info, dataLength, nonceIsZero);
  fields['wlan_rsna_eapol.keydes.key_info'] = info;
  if (message !== null) {
    fields['wlan_rsna_eapol.keydes.msgnr'] = message.n;
    rows.push({ name: 'Message number', value: message.n, abbrev: 'wlan_rsna_eapol.keydes.msgnr', generated: true });
  }
  rows.push({
    name: 'Key Information', value: `0x${info.toString(16).padStart(4, '0')}`, abbrev: 'wlan_rsna_eapol.keydes.key_info',
    rawBytesRange: [at, at + 1],
    children: [
      {
        name: 'Key Descriptor Version', value: named(KEY_DESCRIPTOR_VERSIONS, info & 0x07),
        abbrev: 'wlan_rsna_eapol.keydes.key_info.keydes_version',
        rawBytesRange: [at, at + 1], bitfield: { bitOffset: 13, bitLength: 3, totalBits: 16 },
      },
      flagRow('Key Type', 'wlan_rsna_eapol.keydes.key_info.key_type', info, 12, at, 'Pairwise Key', 'Group Key'),
      {
        name: 'Key Index', value: (info >> 4) & 0x03, abbrev: 'wlan_rsna_eapol.keydes.key_info.key_index',
        rawBytesRange: [at, at + 1], bitfield: { bitOffset: 10, bitLength: 2, totalBits: 16 },
      },
      flagRow('Install', 'wlan_rsna_eapol.keydes.key_info.install', info, 9, at),
      flagRow('Key ACK', 'wlan_rsna_eapol.keydes.key_info.key_ack', info, 8, at),
      flagRow('Key MIC', 'wlan_rsna_eapol.keydes.key_info.key_mic', info, 7, at),
      flagRow('Secure', 'wlan_rsna_eapol.keydes.key_info.secure', info, 6, at),
      flagRow('Error', 'wlan_rsna_eapol.keydes.key_info.error', info, 5, at),
      flagRow('Request', 'wlan_rsna_eapol.keydes.key_info.request', info, 4, at),
      flagRow('Encrypted Key Data', 'wlan_rsna_eapol.keydes.key_info.encrypted_key_data', info, 3, at),
      flagRow('SMK Message', 'wlan_rsna_eapol.keydes.key_info.smk_message', info, 2, at),
    ],
  });
  const bytesRow = (name: string, abbrev: string, from: number, length: number): ProtocolField => ({
    name, value: hexColons(b, from, from + length), abbrev, rawBytesRange: [from, from + length - 1],
  });
  const replay = b.subarray(at + 4, at + 12).reduce((n, x) => n * 256n + BigInt(x), 0n);
  rows.push(
    { name: 'Key Length', value: u16(b, at + 2), abbrev: 'eapol.keydes.key_len', rawBytesRange: [at + 2, at + 3] },
    { name: 'Replay Counter', value: replay.toString(), abbrev: 'eapol.keydes.replay_counter', rawBytesRange: [at + 4, at + 11] },
    bytesRow('WPA Key Nonce', 'wlan_rsna_eapol.keydes.nonce', at + 12, 32),
    bytesRow('Key IV', 'eapol.keydes.key_iv', at + 44, 16),
    bytesRow('WPA Key RSC', 'wlan_rsna_eapol.keydes.rsc', at + 60, 8),
    bytesRow('WPA Key ID', 'wlan_rsna_eapol.keydes.id', at + 68, 8),
    bytesRow('WPA Key MIC', 'wlan_rsna_eapol.keydes.mic', at + 76, 16),
    { name: 'WPA Key Data Length', value: dataLength, abbrev: 'wlan_rsna_eapol.keydes.data_len', rawBytesRange: [at + 92, at + 93] },
  );
  const data = Math.min(dataLength, end - (at + 94));
  if (data > 0) rows.push(bytesRow('WPA Key Data', 'wlan_rsna_eapol.keydes.data', at + 94, data));

  if ((info & 0x0c00) !== 0) {
    return `Key (${[(info & 0x0800) !== 0 ? 'Request' : '', (info & 0x0400) !== 0 ? 'Error' : ''].filter(Boolean).join(', ')})`;
  }
  return message === null ? 'Key' : `Key (${message.group ? 'Group ' : ''}Message ${message.n} of ${message.group ? 2 : 4})`;
}

/** An EAP packet (RFC 3748 §4), as its own layer. */
function dissectEap(b: Uint8Array, at: number, end: number): { layer: ProtocolLayer; info: string; fields: Record<string, string | number> } | null {
  if (at + 4 > end) return null;
  const code = b[at];
  const length = u16(b, at + 2);
  const stop = Math.min(end, at + Math.max(4, length));
  const rows: ProtocolField[] = [
    { name: 'Code', value: named(EAP_CODES, code), abbrev: 'eap.code', rawBytesRange: [at, at] },
    { name: 'Id', value: b[at + 1], abbrev: 'eap.id', rawBytesRange: [at + 1, at + 1] },
    { name: 'Length', value: length, abbrev: 'eap.len', rawBytesRange: [at + 2, at + 3] },
  ];
  const fields: Record<string, string | number> = { 'eap.code': code, 'eap.id': b[at + 1], 'eap.len': length };
  let info = EAP_CODES[code] ?? `Unknown code (${code})`;
  if ((code === 1 || code === 2) && at + 4 < stop) {
    const type = b[at + 4];
    fields['eap.type'] = type;
    info += `, ${EAP_TYPES[type] ?? `Unknown type (0x${type.toString(16).padStart(2, '0')})`}`;
    rows.push({ name: 'Type', value: named(EAP_TYPES, type), abbrev: 'eap.type', rawBytesRange: [at + 4, at + 4] });
    const body = at + 5;
    if (type === 1 && body < stop) {
      const identity = utf8.decode(b.subarray(body, stop));
      fields['eap.identity'] = identity;
      rows.push({ name: 'Identity', value: identity, abbrev: 'eap.identity', rawBytesRange: [body, stop - 1] });
    } else if (type === 2 && body < stop) {
      rows.push({ name: 'Notification', value: utf8.decode(b.subarray(body, stop)), abbrev: 'eap.notification', rawBytesRange: [body, stop - 1] });
    } else if (type === 3) {
      for (let p = body; p < stop; p++) {
        rows.push({ name: 'Desired Auth Type', value: named(EAP_TYPES, b[p]), abbrev: 'eap.desired_type', rawBytesRange: [p, p] });
      }
    } else if (type === 4 && body < stop) {
      // The reference's two warnings, as rows: a method an attacker in the
      // middle can answer for the station, and one a captured exchange can
      // be cracked from offline.
      rows.push({
        name: 'Vulnerable to MITM attacks. If possible, change EAP type.', value: '', abbrev: 'eap.mitm_attacks',
        expertInfo: { message: 'Vulnerable to MITM attacks. If possible, change EAP type.', category: 'Security' },
      });
      const size = b[body];
      const valueEnd = Math.min(stop, body + 1 + size);
      rows.push(
        { name: 'EAP-MD5 Value-Size', value: size, abbrev: 'eap.md5.value_size', rawBytesRange: [body, body] },
        { name: 'EAP-MD5 Value', value: hexColons(b, body + 1, valueEnd), abbrev: 'eap.md5.value', rawBytesRange: [body + 1, valueEnd - 1] },
      );
      if (valueEnd < stop) {
        rows.push({ name: 'EAP-MD5 Extra Data', value: hexColons(b, valueEnd, stop), abbrev: 'eap.md5.extra_data', rawBytesRange: [valueEnd, stop - 1] });
      }
    } else if (type === 17 && body + 3 <= stop) {
      const warning = 'Vulnerable to dictionary attacks. If possible, change EAP type. '
        + 'See http://www.cisco.com/warp/public/cc/pd/witc/ao350ap/prodlit/2331_pp.pdf';
      rows.push(
        { name: warning, value: '', abbrev: 'eap.dictionary_attacks', expertInfo: { message: warning, category: 'Security' } },
        { name: 'EAP-LEAP Version', value: b[body], abbrev: 'eap.leap.version', rawBytesRange: [body, body] },
        { name: 'EAP-LEAP Reserved', value: `0x${b[body + 1].toString(16).padStart(2, '0')}`, abbrev: 'eap.leap.reserved', rawBytesRange: [body + 1, body + 1] },
        { name: 'EAP-LEAP Count', value: b[body + 2], abbrev: 'eap.leap.count', rawBytesRange: [body + 2, body + 2] },
      );
      // The access point's challenge in a request, the station's answer in a
      // response, then the user name the exchange is for.
      const proof = Math.min(stop, body + 3 + b[body + 2]);
      if (code === 1 || code === 2) {
        rows.push(code === 1
          ? { name: 'EAP-LEAP Peer Challenge', value: hexColons(b, body + 3, proof), abbrev: 'eap.leap.peer_challenge', rawBytesRange: [body + 3, proof - 1] }
          : { name: 'EAP-LEAP Peer Response', value: hexColons(b, body + 3, proof), abbrev: 'eap.leap.peer_response', rawBytesRange: [body + 3, proof - 1] });
      }
      if (proof < stop) {
        rows.push({ name: 'EAP-LEAP Name', value: utf8.decode(b.subarray(proof, stop)), abbrev: 'eap.leap.name', rawBytesRange: [proof, stop - 1] });
      }
    } else if (TLS_METHODS.has(type) && body < stop) {
      const flags = b[body];
      const bit = (n: number) => (flags & (0x80 >> n)) !== 0 ? 'True' : 'False';
      const flagRows: ProtocolField[] = [
        { name: 'Length Included', value: bit(0), abbrev: 'eap.tls.flags.len_included', rawBytesRange: [body, body], bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 } },
        { name: 'More Fragments', value: bit(1), abbrev: 'eap.tls.flags.more_fragments', rawBytesRange: [body, body], bitfield: { bitOffset: 1, bitLength: 1, totalBits: 8 } },
        { name: 'Start', value: bit(2), abbrev: 'eap.tls.flags.start', rawBytesRange: [body, body], bitfield: { bitOffset: 2, bitLength: 1, totalBits: 8 } },
      ];
      // EAP-TLS itself has no version bits; the tunnelled methods do.
      if (type !== 13) {
        flagRows.push({ name: 'Version', value: flags & 0x07, abbrev: 'eap.tls.flags.version', rawBytesRange: [body, body], bitfield: { bitOffset: 5, bitLength: 3, totalBits: 8 } });
      }
      rows.push({ name: 'EAP-TLS Flags', value: `0x${flags.toString(16).padStart(2, '0')}`, abbrev: 'eap.tls.flags', rawBytesRange: [body, body], children: flagRows });
      if ((flags & 0x80) !== 0 && body + 5 <= stop) {
        const total = ((b[body + 1] << 24) | (b[body + 2] << 16) | (b[body + 3] << 8) | b[body + 4]) >>> 0;
        rows.push({ name: 'EAP-TLS Length', value: total, abbrev: 'eap.tls.len', rawBytesRange: [body + 1, body + 4] });
      }
    } else if (body < stop) {
      // A method with no decoder here - OTP, GTC, MS-CHAPv2 and the rest -
      // is its bytes, as the reference draws one it has none for either.
      rows.push({ name: 'EAP Data', value: hexColons(b, body, stop), abbrev: 'eap.data', rawBytesRange: [body, stop - 1] });
    }
  }
  return {
    layer: { name: 'Extensible Authentication Protocol', summary: info, fields: rows, rawBytesRange: [at, stop - 1] },
    info,
    fields,
  };
}

export function dissectEapol(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start + 4 > end) return null;
  const version = b[start];
  const type = b[start + 1];
  const length = u16(b, start + 2);
  const stop = Math.min(end, start + 4 + length);
  const rows: ProtocolField[] = [
    { name: 'Version', value: named(EAPOL_VERSIONS, version), abbrev: 'eapol.version', rawBytesRange: [start, start] },
    { name: 'Type', value: named(EAPOL_TYPES, type), abbrev: 'eapol.type', rawBytesRange: [start + 1, start + 1] },
    { name: 'Length', value: length, abbrev: 'eapol.len', rawBytesRange: [start + 2, start + 3] },
  ];
  const fields: Record<string, string | number> = { 'eapol.version': version, 'eapol.type': type, 'eapol.len': length };
  let protocolLabel = 'EAPOL';
  let info = EAPOL_TYPES[type] ?? `Unknown Type (0x${type.toString(16).padStart(2, '0')})`;
  const innerLayers: ProtocolLayer[] = [];

  if (type === 0) {
    const eap = dissectEap(b, start + 4, stop);
    if (eap !== null) {
      protocolLabel = 'EAP';
      info = eap.info;
      innerLayers.push(eap.layer);
      Object.assign(fields, eap.fields);
    }
  } else if (type === 3 && start + 4 < stop) {
    const descriptor = b[start + 4];
    fields['eapol.keydes.type'] = descriptor;
    rows.push({ name: 'Key Descriptor Type', value: named(KEY_DESCRIPTORS, descriptor), abbrev: 'eapol.keydes.type', rawBytesRange: [start + 4, start + 4] });
    info = descriptor === 2 || descriptor === 254 ? keyDescriptor(b, start + 5, stop, rows, fields) : 'Key';
  }

  return {
    protocolLabel,
    info,
    layer: { name: '802.1X Authentication', summary: info, fields: rows, rawBytesRange: [start, stop - 1] },
    innerLayers,
    fields,
  };
}
