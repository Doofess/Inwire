/**
 * DTLS (RFC 6347): TLS over datagrams - what every WebRTC call (Meet, Teams,
 * Discord, a browser's video chat) and Cisco AnyConnect key their media with.
 *
 *   Client Hello
 *   Server Hello, Certificate (Fragment)
 *   Certificate (Reassembled), Server Key Exchange (Fragment)
 *
 * Found by content on any UDP port, as the reference finds it: one or more
 * records, each a DTLS content type and version, that fill the datagram
 * exactly. A WebRTC port carries STUN, DTLS and RTP side by side, and the
 * first byte keeps them apart (RFC 7983) - DTLS starts 20 to 63.
 *
 * **The handshake is TLS's**, so the hellos and certificates are drawn by
 * `tls.ts` and renamed `dtls.`, the reference's names for the same rows; what
 * is DTLS's own is drawn here: each record's epoch and sequence number, each
 * handshake message's sequence and fragment, the HelloVerifyRequest cookie,
 * and the **reassembly of a message the datagram size split** - a certificate
 * chain rarely fits one. The fragments are kept per conversation
 * (`DtlsConversationState`) until the message is whole; the frame that
 * completes it draws it, with the list of fragments the reference draws.
 *
 * **The version is the reference's single-pass reading** for the tree: none
 * until a record other than a ClientHello says one, then the ServerHello's.
 * The Protocol column is patched to the settled version on the frames before
 * it, as TLS's is - which is the reference's two-pass reading.
 *
 * Records after Change Cipher Spec (epoch 1 and up) are encrypted and drawn
 * as such: there is no DTLS decryption here.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { TlsConversationState } from '../tcpStreamTracker';
import { hexColons } from '../dissect/hexBytes';
import { certificateFields, helloFields, parseClientHello, parseServerHello, serverHelloFields } from './tls';
import {
  ALERT_DESCRIPTION_NAMES, ALERT_LEVEL_NAMES, HANDSHAKE_TYPE_NAMES, nameCipher, nameGroup, nameSignatureAlgorithm,
  nameSignatureHash, nameSignatureKind, nameVersion,
} from './tlsTables';
import { summarizeCertificate } from './x509';

const RECORD_HEADER = 13;
const HANDSHAKE_HEADER = 12;
const DTLS_VERSIONS = new Set([0xfeff, 0xfefd, 0xfefc, 0x0100]);
const CT_CCS = 20;
const CT_ALERT = 21;
const CT_HANDSHAKE = 22;
const CT_APP_DATA = 23;
/** A handshake message bigger than this is not being reassembled: it is not one. */
const MAX_MESSAGE = 1 << 18;

const SRTP_PROFILES: Record<number, string> = {
  1: 'SRTP_AES128_CM_HMAC_SHA1_80', 2: 'SRTP_AES128_CM_HMAC_SHA1_32', 5: 'SRTP_NULL_HMAC_SHA1_80',
  6: 'SRTP_NULL_HMAC_SHA1_32', 7: 'SRTP_AEAD_AES_128_GCM', 8: 'SRTP_AEAD_AES_256_GCM',
  9: 'DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM', 10: 'DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM',
  11: 'SRTP_ARIA_128_CTR_HMAC_SHA1_80', 12: 'SRTP_ARIA_128_CTR_HMAC_SHA1_32', 13: 'SRTP_ARIA_256_CTR_HMAC_SHA1_80',
  14: 'SRTP_ARIA_256_CTR_HMAC_SHA1_32', 15: 'SRTP_AEAD_ARIA_128_GCM', 16: 'SRTP_AEAD_ARIA_256_GCM',
};
const CURVE_TYPES: Record<number, string> = { 1: 'explicit_prime', 2: 'explicit_char2', 3: 'named_curve' };

const u16 = (b: ArrayLike<number>, at: number) => (b[at] << 8) | b[at + 1];
const u24 = (b: ArrayLike<number>, at: number) => (b[at] << 16) | (b[at + 1] << 8) | b[at + 2];
const hex2 = (n: number) => n.toString(16).padStart(2, '0');
const hex4 = (n: number) => n.toString(16).padStart(4, '0');

/** A handshake message some of whose fragments have arrived. */
interface DtlsPending {
  /** The sender's `address:port`. */
  from: string;
  seq: number;
  type: number;
  length: number;
  /** The message body, `length` bytes, filled as fragments arrive. */
  body: number[];
  /** Each fragment taken: its frame and where it sat in the message. */
  parts: { frame: number; offset: number; length: number }[];
}

export interface DtlsConversationState {
  /** `dtls.stream`: conversations in the order they were first seen. */
  stream: number;
  /** The version as known so far, single-pass. */
  version?: number;
  /** The ServerHello has settled the version. */
  settled: boolean;
  /** Frames before it did, for label patches. */
  unsettled: number[];
  /** The negotiated cipher suite, which says how a key exchange is shaped. */
  cipher?: number;
  /** The ClientHello's server name, for the certificate's name check. */
  sni?: string;
  pending: DtlsPending[];
}

export const freshDtlsConversation = (stream: number): DtlsConversationState => ({ stream, settled: false, unsettled: [], pending: [] });

/**
 * The reference's heuristic: records with a DTLS content type and version
 * whose lengths fill the datagram exactly.
 */
export function looksLikeDtls(b: Uint8Array, start: number, end: number): boolean {
  let p = start;
  let records = 0;
  while (p < end) {
    if (p + RECORD_HEADER > end) return false;
    const type = b[p];
    if (type < CT_CCS || type > 26) return false;
    if (!DTLS_VERSIONS.has(u16(b, p + 1))) return false;
    p += RECORD_HEADER + u16(b, p + 11);
    records++;
  }
  return records > 0 && p === end;
}

/** `tls.` rows renamed `dtls.`, and `Name: value` headings split the way the reference splits them. */
function asDtls(rows: ProtocolField[]): ProtocolField[] {
  return rows.map((row) => {
    const out: ProtocolField = { ...row };
    if (out.abbrev?.startsWith('tls.') && !out.abbrev.startsWith('tls.x509.')) out.abbrev = `d${out.abbrev}`;
    if (out.value === '' && out.name.includes(': ') && out.abbrev !== undefined) {
      const at = out.name.indexOf(': ');
      out.value = out.name.slice(at + 2);
      out.name = out.name.slice(0, at);
    }
    if (out.children) out.children = asDtls(out.children);
    return out;
  });
}

/** The TLS layout of a handshake message: its type and 24-bit length, then the body. */
function tlsShaped(type: number, body: ArrayLike<number>): Uint8Array {
  const out = new Uint8Array(4 + body.length);
  out[0] = type;
  out[1] = (body.length >> 16) & 0xff;
  out[2] = (body.length >> 8) & 0xff;
  out[3] = body.length & 0xff;
  out.set(Array.from(body), 4);
  return out;
}

const row = (name: string, value: string | number, abbrev: string): ProtocolField => ({ name, value, abbrev });
const bytesRow = (name: string, abbrev: string, b: ArrayLike<number>, from: number, to: number): ProtocolField =>
  ({ name, value: hexColons(Uint8Array.from(Array.from(b).slice(from, to)), 0, to - from), abbrev });

function signatureAlgorithm(s: number): ProtocolField {
  return {
    name: 'Signature Algorithm', value: nameSignatureAlgorithm(s), abbrev: 'dtls.handshake.sig_hash_alg',
    children: [
      row('Signature Hash Algorithm Hash', nameSignatureHash((s >> 8) & 0xff), 'dtls.handshake.sig_hash_hash'),
      row('Signature Hash Algorithm Signature', nameSignatureKind(s & 0xff), 'dtls.handshake.sig_hash_sig'),
    ],
  };
}

/** One whole handshake message's body rows, by type. */
function messageBody(type: number, body: Uint8Array, conv: DtlsConversationState, version: number, now: Date): ProtocolField[] {
  if (type === 1 && body.length >= 35) {
    // Drop the cookie to give TLS's parser the layout it reads, then put the
    // cookie's rows back after the session ID, where DTLS has them.
    const sidLength = body[34];
    const cookieAt = 35 + sidLength;
    const cookieLength = body[cookieAt] ?? 0;
    const withoutCookie = new Uint8Array(body.length - 1 - cookieLength);
    withoutCookie.set(body.subarray(0, cookieAt), 0);
    withoutCookie.set(body.subarray(cookieAt + 1 + cookieLength), cookieAt);
    const hello = parseClientHello(tlsShaped(1, withoutCookie), 'd');
    if (hello === null) return [];
    if (hello.sni !== null) conv.sni = hello.sni;
    const rows = asDtls(helloFields(hello));
    const after = rows.findIndex((r) => r.abbrev === 'dtls.handshake.cipher_suites_length');
    const cookie: ProtocolField[] = [row('Cookie Length', cookieLength, 'dtls.handshake.cookie_length')];
    if (cookieLength > 0) cookie.push(bytesRow('Cookie', 'dtls.handshake.cookie', body, cookieAt + 1, cookieAt + 1 + cookieLength));
    rows.splice(after < 0 ? rows.length : after, 0, ...cookie);
    withSrtp(rows, hello.extensions);
    return rows;
  }
  if (type === 2) {
    const hello = parseServerHello(tlsShaped(2, body));
    if (hello === null) return [];
    conv.cipher = hello.cipher;
    const rows = asDtls(serverHelloFields(hello, { negotiatedVersion: version } as TlsConversationState));
    withSrtp(rows, hello.extensions);
    return rows;
  }
  if (type === 3 && body.length >= 3) {
    const cookieLength = body[2];
    return [
      row('Version', `${nameVersion(u16(body, 0)).replace('DTLSv', 'DTLS ')} (0x${hex4(u16(body, 0))})`, 'dtls.handshake.version'),
      row('Cookie Length', cookieLength, 'dtls.handshake.cookie_length'),
      ...(cookieLength > 0 ? [bytesRow('Cookie', 'dtls.handshake.cookie', body, 3, 3 + cookieLength)] : []),
    ];
  }
  if (type === 11 && body.length >= 3) {
    const total = u24(body, 0);
    const certificates: ProtocolField[] = [];
    for (let p = 3; p + 3 <= Math.min(body.length, 3 + total);) {
      const length = u24(body, p);
      if (p + 3 + length > body.length) break;
      const der = body.subarray(p + 3, p + 3 + length);
      const summary = summarizeCertificate(der);
      const detail = summary !== null
        ? asDtls(certificateFields([summary], { sni: conv.sni } as TlsConversationState, now))[0]?.children
        : undefined;
      certificates.push(
        row('Certificate Length', length, 'dtls.handshake.certificate_length'),
        { name: 'Certificate', value: hexColons(der, 0, der.length), abbrev: 'dtls.handshake.certificate', ...(detail ? { children: detail } : {}) },
      );
      p += 3 + length;
    }
    return [
      row('Certificates Length', total, 'dtls.handshake.certificates_length'),
      { name: `Certificates (${total} bytes)`, value: '', abbrev: 'dtls.handshake.certificates', children: certificates },
    ];
  }
  if (type === 12 && body.length >= 4 && body[0] === 3) {
    // ECDHE: a named curve, the server's point, and its signature over them.
    const pointLength = body[3];
    let p = 4 + pointLength;
    const params: ProtocolField[] = [
      row('Curve Type', `${CURVE_TYPES[body[0]] ?? 'Unknown'} (0x${hex2(body[0])})`, 'dtls.handshake.server_curve_type'),
      row('Named Curve', nameGroup(u16(body, 1)), 'dtls.handshake.server_named_curve'),
      row('Pubkey Length', pointLength, 'dtls.handshake.server_point_len'),
      bytesRow('Pubkey', 'dtls.handshake.server_point', body, 4, p),
    ];
    if (version === 0xfefd && p + 2 <= body.length) {
      params.push(signatureAlgorithm(u16(body, p)));
      p += 2;
    }
    if (p + 2 <= body.length) {
      const sigLength = u16(body, p);
      params.push(row('Signature Length', sigLength, 'dtls.handshake.sig_len'), bytesRow('Signature', 'dtls.handshake.sig', body, p + 2, p + 2 + sigLength));
    }
    return [{ name: 'EC Diffie-Hellman Server Params', value: '', children: params }];
  }
  if (type === 16 && body.length >= 1) {
    const suite = conv.cipher === undefined ? '' : nameCipher(conv.cipher);
    if (suite.includes('_ECDHE_') || suite.includes('_ECDH_')) {
      return [{
        name: 'EC Diffie-Hellman Client Params', value: '',
        children: [row('Pubkey Length', body[0], 'dtls.handshake.client_point_len'), bytesRow('Pubkey', 'dtls.handshake.client_point', body, 1, 1 + body[0])],
      }];
    }
    if (suite.startsWith('TLS_RSA_') && body.length >= 2) {
      return [{
        name: 'RSA Encrypted PreMaster Secret', value: '',
        children: [row('Encrypted PreMaster length', u16(body, 0), 'dtls.handshake.epms_len'), bytesRow('Encrypted PreMaster', 'dtls.handshake.epms', body, 2, body.length)],
      }];
    }
    return [];
  }
  if (type === 4 && body.length >= 6) {
    const hint = ((body[0] << 24) | (body[1] << 16) | (body[2] << 8) | body[3]) >>> 0;
    const ticketLength = u16(body, 4);
    return [{
      name: 'TLS Session Ticket', value: '',
      children: [
        row('Session Ticket Lifetime Hint', `${hint} seconds${lifetimeWords(hint)}`, 'dtls.handshake.session_ticket_lifetime_hint'),
        row('Session Ticket Length', ticketLength, 'dtls.handshake.session_ticket_length'),
        bytesRow('Session Ticket', 'dtls.handshake.session_ticket', body, 6, 6 + ticketLength),
      ],
    }];
  }
  return [];
}

/** The reference's gloss on a lifetime: `(2 hours)`, `(1 day)`. */
function lifetimeWords(seconds: number): string {
  if (seconds === 0) return '';
  const units: [number, string][] = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
  const parts: string[] = [];
  let left = seconds;
  for (const [size, name] of units) {
    const n = Math.floor(left / size);
    if (n > 0) parts.push(`${n} ${name}${n === 1 ? '' : 's'}`);
    left -= n * size;
  }
  return ` (${parts.join(', ')})`;
}

/** use_srtp's body, which is DTLS's alone: the reference names it `dtls.use_srtp`. */
function withSrtp(rows: ProtocolField[], extensions: { type: number; body: Uint8Array }[]): void {
  const extensionRows = rows.filter((r) => r.abbrev === 'dtls.handshake.extension');
  extensions.forEach((ext, i) => {
    const target = extensionRows[i];
    if (ext.type !== 14 || target === undefined || ext.body.length < 2) return;
    const b = ext.body;
    const listLength = u16(b, 0);
    // The generic extension's raw data row gives way to the profiles.
    const children = (target.children ?? []).filter((r) => r.abbrev !== 'dtls.handshake.extension.data');
    children.push(row('SRTP Protection Profiles Length', listLength, 'dtls.use_srtp.protection_profiles_length'));
    for (let p = 2; p + 2 <= Math.min(b.length, 2 + listLength); p += 2) {
      const profile = u16(b, p);
      children.push(row('SRTP Protection Profile', `${SRTP_PROFILES[profile] ?? 'Unknown'} (0x${hex4(profile)})`, 'dtls.use_srtp.protection_profile'));
    }
    const mkiAt = 2 + listLength;
    if (mkiAt < b.length) {
      children.push(row('MKI Length', b[mkiAt], 'dtls.use_srtp.mki_length'));
      if (b[mkiAt] > 0) children.push(bytesRow('MKI', 'dtls.use_srtp.mki', b, mkiAt + 1, mkiAt + 1 + b[mkiAt]));
    }
    target.children = children;
  });
}

export interface DtlsResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /** Earlier frames whose Protocol column the settled version rewrites. */
  labelPatches?: { frameId: number; protocolLabel: string }[];
}

/**
 * One datagram of a DTLS conversation, read against the conversation's state.
 * `from` is the sender's `address:port`.
 */
export function dissectDtls(
  b: Uint8Array, start: number, end: number, conv: DtlsConversationState, from: string, frame: number, now: Date,
): DtlsResult | null {
  if (!looksLikeDtls(b, start, end)) return null;
  const records: ProtocolField[] = [];
  const info: string[] = [];
  const fields: Record<string, string | number> = { 'dtls.stream': conv.stream };
  let serverHelloSeen = false;

  for (let p = start; p + RECORD_HEADER <= end;) {
    const type = b[p];
    const recordVersion = u16(b, p + 1);
    const epoch = u16(b, p + 3);
    const sequence = b.subarray(p + 5, p + 11).reduce((n, x) => n * 256 + x, 0);
    const length = u16(b, p + 11);
    const bodyAt = p + RECORD_HEADER;
    const bodyEnd = Math.min(end, bodyAt + length);
    const encrypted = epoch > 0;
    fields['dtls.record.content_type'] ??= type;

    // The reference takes the version from the first record that is not a
    // ClientHello - a ClientHello's record version is a lower bound, not a
    // choice - and from the ServerHello once one is read.
    if (conv.version === undefined && !(type === CT_HANDSHAKE && !encrypted && b[bodyAt] === 1)) conv.version = recordVersion;
    const label = conv.version === undefined ? 'DTLS' : nameVersion(conv.version);

    const header: ProtocolField[] = [
      row('Content Type', `${['Change Cipher Spec', 'Alert', 'Handshake', 'Application Data', 'Heartbeat', 'Connection ID', 'ACK'][type - 20] ?? 'Unknown'} (${type})`, 'dtls.record.content_type'),
      row('Version', `${nameVersion(recordVersion).replace('DTLSv', 'DTLS ')} (0x${hex4(recordVersion)})`, 'dtls.record.version'),
      row('Epoch', epoch, 'dtls.record.epoch'),
      row('Sequence Number', sequence, 'dtls.record.sequence_number'),
      row('Length', length, 'dtls.record.length'),
    ];
    let title = '';
    const content: ProtocolField[] = [];

    if (type === CT_HANDSHAKE && encrypted) {
      title = 'Record Layer';
      content.push({ name: 'Handshake Protocol', value: '', abbrev: 'dtls.handshake' });
      info.push('Encrypted Handshake Message');
    } else if (type === CT_HANDSHAKE) {
      const titles: string[] = [];
      for (let q = bodyAt; q + HANDSHAKE_HEADER <= bodyEnd;) {
        const hsType = b[q];
        const hsLength = u24(b, q + 1);
        const seq = u16(b, q + 4);
        const offset = u24(b, q + 6);
        const fragmentLength = u24(b, q + 9);
        const fragmentEnd = Math.min(bodyEnd, q + HANDSHAKE_HEADER + fragmentLength);
        const name = HANDSHAKE_TYPE_NAMES[hsType] ?? `Unknown (${hsType})`;
        const hs: ProtocolField[] = [
          row('Handshake Type', `${name} (${hsType})`, 'dtls.handshake.type'),
          row('Length', hsLength, 'dtls.handshake.length'),
          row('Message Sequence', seq, 'dtls.handshake.message_seq'),
          row('Fragment Offset', offset, 'dtls.handshake.fragment_offset'),
          row('Fragment Length', fragmentLength, 'dtls.handshake.fragment_length'),
        ];
        fields['dtls.handshake.type'] ??= hsType;
        let suffix = '';
        let whole: Uint8Array | null = null;
        let fragments: ProtocolField | null = null;
        if (offset === 0 && fragmentLength === hsLength) {
          whole = b.subarray(q + HANDSHAKE_HEADER, fragmentEnd);
        } else if (hsLength <= MAX_MESSAGE && offset + fragmentLength <= hsLength) {
          let pending = conv.pending.find((m) => m.from === from && m.seq === seq && m.type === hsType);
          if (pending === undefined) {
            pending = { from, seq, type: hsType, length: hsLength, body: new Array(hsLength).fill(0), parts: [] };
            conv.pending.push(pending);
          }
          if (!pending.parts.some((part) => part.offset === offset && part.length === fragmentLength)) {
            for (let i = 0; i < fragmentEnd - (q + HANDSHAKE_HEADER); i++) pending.body[offset + i] = b[q + HANDSHAKE_HEADER + i];
            pending.parts.push({ frame, offset, length: fragmentLength });
          }
          const covered = new Set<number>();
          for (const part of pending.parts) for (let i = part.offset; i < part.offset + part.length; i++) covered.add(i);
          if (covered.size >= hsLength) {
            suffix = ' (Reassembled)';
            whole = Uint8Array.from(pending.body);
            const parts = [...pending.parts].sort((x, y) => x.offset - y.offset);
            fragments = {
              name: `${parts.length} Message fragments (${hsLength} bytes)`,
              value: parts.map((part) => `#${part.frame}(${part.length})`).join(', '),
              abbrev: 'dtls.fragments',
              children: [
                ...parts.map((part): ProtocolField => ({
                  name: 'Frame', value: `${part.frame}, payload: ${part.offset}-${part.offset + part.length - 1} (${part.length} bytes)`,
                  abbrev: 'dtls.fragment', linkToFrame: part.frame,
                })),
                row('Message fragment count', parts.length, 'dtls.fragment.count'),
                row('Reassembled DTLS length', hsLength, 'dtls.reassembled.length'),
              ],
            };
            conv.pending = conv.pending.filter((m) => m !== pending);
          } else {
            suffix = ' (Fragment)';
          }
        }
        if (whole !== null) {
          hs.push(...messageBody(hsType, whole, conv, conv.version ?? recordVersion, now));
          if (hsType === 2) {
            const serverVersion = u16(whole, 0);
            conv.version = serverVersion;
            serverHelloSeen = true;
          }
        }
        titles.push(`${name}${suffix}`);
        content.push({ name: 'Handshake Protocol', value: `${name}${suffix}`, abbrev: 'dtls.handshake', children: hs });
        if (fragments !== null) content.push(fragments);
        q = fragmentEnd;
      }
      title = `${label} Record Layer: Handshake Protocol: ${titles.join(', ')}`;
      info.push(...titles);
    } else if (type === CT_CCS) {
      title = `${label} Record Layer: Change Cipher Spec Protocol: Change Cipher Spec`;
      content.push({ name: 'Change Cipher Spec Message', value: '', abbrev: 'dtls.change_cipher_spec' });
      info.push('Change Cipher Spec');
    } else if (type === CT_ALERT && (encrypted || length !== 2)) {
      title = `${label} Record Layer: Encrypted Alert`;
      content.push({ name: 'Alert Message', value: 'Encrypted Alert', abbrev: 'dtls.alert_message' });
      info.push('Encrypted Alert');
    } else if (type === CT_ALERT) {
      const level = ALERT_LEVEL_NAMES[b[bodyAt]] ?? 'Unknown';
      const description = ALERT_DESCRIPTION_NAMES[b[bodyAt + 1]] ?? 'Unknown';
      title = `${label} Record Layer: Alert (Level: ${level}, Description: ${description})`;
      content.push({
        name: 'Alert Message', value: '', abbrev: 'dtls.alert_message',
        children: [
          row('Level', `${level} (${b[bodyAt]})`, 'dtls.alert_message.level'),
          row('Description', `${description} (${b[bodyAt + 1]})`, 'dtls.alert_message.desc'),
        ],
      });
      info.push(`Alert (Level: ${level}, Description: ${description})`);
    } else if (type === CT_APP_DATA) {
      title = `${label} Record Layer: Application Data Protocol: Application Data`;
      content.push(bytesRow('Encrypted Application Data', 'dtls.app_data', b, bodyAt, bodyEnd));
      info.push('Application Data');
    } else {
      title = `${label} Record Layer`;
    }
    const at = title.indexOf(': ');
    records.push({
      ...(at >= 0 ? { name: title.slice(0, at), value: title.slice(at + 2) } : { name: title, value: '' }),
      abbrev: 'dtls.record', rawBytesRange: [p, bodyEnd - 1], children: [...header, ...content],
    });
    p = bodyAt + length;
  }

  // The Protocol column is the version as finally settled: the frames before
  // the ServerHello get it now, as the reference's second pass gives it them.
  const protocolLabel = conv.version === undefined ? 'DTLS' : nameVersion(conv.version);
  let labelPatches: DtlsResult['labelPatches'];
  if (serverHelloSeen && !conv.settled) {
    labelPatches = conv.unsettled.map((frameId) => ({ frameId, protocolLabel }));
    conv.unsettled = [];
    conv.settled = true;
  } else if (!conv.settled && conv.unsettled.length < 64) {
    conv.unsettled.push(frame);
  }
  return {
    protocolLabel,
    info: info.join(', '),
    layer: {
      name: 'Datagram Transport Layer Security', summary: 'Datagram Transport Layer Security',
      fields: [{ name: 'Stream index', value: conv.stream, abbrev: 'dtls.stream', generated: true }, ...records],
      rawBytesRange: [start, end - 1],
    },
    fields,
    ...(labelPatches !== undefined && labelPatches.length > 0 ? { labelPatches } : {}),
  };
}
