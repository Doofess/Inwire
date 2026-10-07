/**
 * SSH (RFC 4253) on TCP 22: the banners, the key exchange, and then encrypted
 * packets.
 *
 *   Client: Protocol (SSH-2.0-OpenSSH_9.9)
 *   Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys
 *   Client: Encrypted packet (len=36)
 *
 * Everything after New Keys is ciphertext, so what a capture says is who
 * connected with what software, what each side offered, what they settled
 * on - cipher, MAC, key exchange, host key - and the client and server
 * **hassh** fingerprints, which are to SSH what JA3 is to TLS. Port 22 only,
 * as the reference dispatches it.
 *
 * **Each direction is read as a stream** (`SshDirectionState`): the banner
 * line, then length-prefixed packets numbered from 0, until that side's New
 * Keys. A packet larger than its segment is kept and finished by the next
 * one; the segments before the last read as TCP with `[TCP PDU reassembled
 * in N]`, and the last carries the packet and a reassembled-segments block,
 * as TLS records do here. After New Keys each segment is one encrypted
 * packet, its MAC the negotiated MAC's length.
 *
 * **Negotiation is the client's preference**: the first algorithm in the
 * client's list that the server also lists (RFC 4253 §7.1), for the key
 * exchange and for each direction's cipher, MAC and compression. The key
 * exchange decides what messages 30 to 34 are: plain Diffie-Hellman, group
 * exchange, elliptic curve, or the post-quantum hybrids OpenSSH now defaults
 * to.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import { md5Hex } from '../crypto/md5';
import type { TcpReassembly } from './tls';

export const SSH_PORT = 22;

export interface SshDirectionState {
  /** The banner's protocol version: 2 for 2.0 and 1.99, 1 for 1.x, 0 before it. */
  version: number;
  /** The next packet's sequence number. */
  seq: number;
  /** New Keys was sent: everything after it is encrypted. */
  encrypted: boolean;
  /** A packet begun in an earlier segment: its bytes so far. */
  pending: number[] | null;
  /** The frames those bytes came from, and how many from each. */
  pendingFrames: { frame: number; bytes: number }[];
}

export interface SshConversationState {
  client: SshDirectionState;
  server: SshDirectionState;
  /** Each side's KEXINIT name-lists, in wire order. */
  clientLists?: string[];
  serverLists?: string[];
}

const freshDirection = (): SshDirectionState => ({ version: 0, seq: 0, encrypted: false, pending: null, pendingFrames: [] });
export const freshSshConversation = (): SshConversationState => ({ client: freshDirection(), server: freshDirection() });

/** A packet longer than this (RFC 4253 §6.1 allows 35,000) is not one: the stream is not where it was thought. */
const MAX_PACKET = 35000;

/** KEXINIT's name-lists: label and abbrev of each, the abbrevs whole for the registry's scanner. */
const NAME_LISTS = [
  ['kex_algorithms', 'ssh.kex_algorithms', 'ssh.kex_algorithms_length'],
  ['server_host_key_algorithms', 'ssh.server_host_key_algorithms', 'ssh.server_host_key_algorithms_length'],
  ['encryption_algorithms_client_to_server', 'ssh.encryption_algorithms_client_to_server', 'ssh.encryption_algorithms_client_to_server_length'],
  ['encryption_algorithms_server_to_client', 'ssh.encryption_algorithms_server_to_client', 'ssh.encryption_algorithms_server_to_client_length'],
  ['mac_algorithms_client_to_server', 'ssh.mac_algorithms_client_to_server', 'ssh.mac_algorithms_client_to_server_length'],
  ['mac_algorithms_server_to_client', 'ssh.mac_algorithms_server_to_client', 'ssh.mac_algorithms_server_to_client_length'],
  ['compression_algorithms_client_to_server', 'ssh.compression_algorithms_client_to_server', 'ssh.compression_algorithms_client_to_server_length'],
  ['compression_algorithms_server_to_client', 'ssh.compression_algorithms_server_to_client', 'ssh.compression_algorithms_server_to_client_length'],
  ['languages_client_to_server', 'ssh.languages_client_to_server', 'ssh.languages_client_to_server_length'],
  ['languages_server_to_client', 'ssh.languages_server_to_client', 'ssh.languages_server_to_client_length'],
] as const;
const KEX = 0;
const ENC_C2S = 2;
const MAC_C2S = 4;
const COMP_C2S = 6;

/** Message names outside the key exchange's own range (`ssh.message_code`). */
const MESSAGES: Record<number, string> = {
  1: 'Disconnect', 2: 'Ignore', 3: 'Unimplemented', 4: 'Debug', 5: 'Service Request', 6: 'Service Accept',
  7: 'Extension Information', 8: 'New Compression', 20: 'Key Exchange Init', 21: 'New Keys',
  50: 'User Authentication Request', 51: 'User Authentication Failure', 52: 'User Authentication Success',
  53: 'User Authentication Banner', 60: 'Public Key algorithm accepted', 80: 'Global Request', 81: 'Request Success',
  82: 'Request Failure', 90: 'Channel Open', 91: 'Channel Open Confirmation', 92: 'Channel Open Failure',
  93: 'Window Adjust', 94: 'Channel Data', 95: 'Channel Extended Data', 96: 'Channel EOF', 97: 'Channel Close',
  98: 'Channel Request', 99: 'Channel Success', 100: 'Channel Failure', 192: 'Ping', 193: 'Pong',
};

type KexFamily = 'dh' | 'gex' | 'ecdh' | 'hybrid' | null;
function kexFamily(method: string | undefined): KexFamily {
  if (method === undefined) return null;
  if (method.startsWith('diffie-hellman-group-exchange')) return 'gex';
  if (method.startsWith('diffie-hellman-group')) return 'dh';
  if (method.startsWith('ecdh-sha2-') || method.startsWith('curve25519') || method.startsWith('curve448')) return 'ecdh';
  if (method.startsWith('sntrup761x25519') || method.startsWith('mlkem')) return 'hybrid';
  return null;
}
const KEX_MESSAGES: Record<Exclude<KexFamily, null>, Record<number, string>> = {
  dh: { 30: 'Diffie-Hellman Key Exchange Init', 31: 'Diffie-Hellman Key Exchange Reply' },
  gex: {
    30: 'Diffie-Hellman Group Exchange Request (Old)', 31: 'Diffie-Hellman Group Exchange Group',
    32: 'Diffie-Hellman Group Exchange Init', 33: 'Diffie-Hellman Group Exchange Reply', 34: 'Diffie-Hellman Group Exchange Request',
  },
  ecdh: { 30: 'Elliptic Curve Diffie-Hellman Key Exchange Init', 31: 'Elliptic Curve Diffie-Hellman Key Exchange Reply' },
  hybrid: { 30: 'PQ/T Hybrid Key Exchange Init', 31: 'PQ/T Hybrid Key Exchange Reply' },
};

const AEAD = new Set(['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com']);
/** Each MAC's length on the wire, `-etm@openssh.com` variants alike. */
const MAC_BYTES: Record<string, number> = {
  'hmac-sha1': 20, 'hmac-sha1-96': 12, 'hmac-md5': 16, 'hmac-md5-96': 12, 'hmac-sha2-256': 32, 'hmac-sha2-512': 64,
  'umac-64@openssh.com': 8, 'umac-128@openssh.com': 16, none: 0,
};

const u32 = (b: ArrayLike<number>, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const utf8 = new TextDecoder('utf-8', { fatal: false });

/** RFC 4253 §7.1: the client's first choice the server also offers. */
function negotiate(client: string | undefined, server: string | undefined): string | undefined {
  if (client === undefined || server === undefined) return undefined;
  const offered = new Set(server.split(','));
  return client.split(',').find((name) => offered.has(name));
}

/** What a direction settled on, once both KEXINITs are known. */
function negotiated(conv: SshConversationState, fromClient: boolean) {
  const c = conv.clientLists;
  const s = conv.serverLists;
  if (c === undefined || s === undefined) return null;
  const at = (i: number) => negotiate(c[i + (fromClient ? 0 : 1)], s[i + (fromClient ? 0 : 1)]);
  const encryption = at(ENC_C2S);
  const mac = encryption !== undefined && AEAD.has(encryption) ? '<implicit>' : at(MAC_C2S);
  return { method: negotiate(c[KEX], s[KEX]), encryption, mac, compression: at(COMP_C2S) };
}

function macBytes(mac: string | undefined): number | undefined {
  if (mac === undefined) return undefined;
  if (mac === '<implicit>') return 16;
  return MAC_BYTES[mac.replace('-etm@openssh.com', '').replace(/@openssh\.com$/, '')] ?? MAC_BYTES[mac];
}

/** Reads SSH's length-prefixed fields off one packet's payload. */
class Reader {
  constructor(readonly b: Uint8Array, public at: number, readonly end: number) {}
  get left() { return this.end - this.at; }
  /** A `uint32` length, then that many bytes: the length row and the value's range. */
  sized(): { length: number; from: number; to: number } | null {
    if (this.left < 4) return null;
    const length = u32(this.b, this.at);
    const from = this.at + 4;
    if (from + length > this.end) return null;
    this.at = from + length;
    return { length, from, to: from + length };
  }
}

const row = (name: string, value: string | number, abbrev: string, from?: number, to?: number): ProtocolField =>
  ({ name, value, abbrev, ...(from !== undefined && to !== undefined && to > from ? { rawBytesRange: [from, to - 1] as [number, number] } : {}) });

/** A length row and the bytes after it: `ssh.ecdh.q_c_length`, `ssh.ecdh.q_c`. */
function sizedBytes(r: Reader, lengthName: string, lengthAbbrev: string, name: string, abbrev: string): ProtocolField[] {
  const at = r.at;
  const field = r.sized();
  if (field === null) return [];
  return [
    row(lengthName, field.length, lengthAbbrev, at, at + 4),
    row(name, hexColons(r.b, field.from, field.to), abbrev, field.from, field.to),
  ];
}

/** An mpint: `Multi Precision Integer Length`, then its value as bytes. */
const mpint = (r: Reader, name: string, abbrev: string) =>
  sizedBytes(r, 'Multi Precision Integer Length', 'ssh.mpint_length', name, abbrev);

/** The server's host key blob (RFC 4253 §6.6), its rows by key type. */
function hostKey(r: Reader): ProtocolField | null {
  const at = r.at;
  const blob = r.sized();
  if (blob === null) return null;
  const inner = new Reader(r.b, blob.from, blob.to);
  const typeAt = inner.at;
  const type = inner.sized();
  if (type === null) return null;
  const typeName = utf8.decode(r.b.subarray(type.from, type.to));
  const children: ProtocolField[] = [
    row('Host key length', blob.length, 'ssh.host_key.length', at, at + 4),
    row('Host key type length', type.length, 'ssh.host_key.type_length', typeAt, typeAt + 4),
    row('Host key type', typeName, 'ssh.host_key.type', type.from, type.to),
  ];
  if (typeName === 'ssh-ed25519' || typeName === 'ssh-ed448') {
    children.push(...sizedBytes(inner, 'EdDSA public key length', 'ssh.host_key.eddsa.key_length', 'EdDSA public key', 'ssh.host_key.eddsa.key'));
  } else if (typeName.startsWith('ecdsa-sha2-')) {
    const idAt = inner.at;
    const id = inner.sized();
    if (id !== null) {
      children.push(
        row('ECDSA elliptic curve identifier length', id.length, 'ssh.host_key.ecdsa.id_length', idAt, idAt + 4),
        row('ECDSA elliptic curve identifier', utf8.decode(r.b.subarray(id.from, id.to)), 'ssh.host_key.ecdsa.id', id.from, id.to),
        ...sizedBytes(inner, 'ECDSA public key length', 'ssh.host_key.ecdsa.q_length', 'ECDSA public key (Q)', 'ssh.host_key.ecdsa.q'),
      );
    }
  } else if (typeName === 'ssh-rsa') {
    children.push(...mpint(inner, 'RSA public exponent (e)', 'ssh.host_key.rsa.e'), ...mpint(inner, 'RSA modulus (N)', 'ssh.host_key.rsa.n'));
  } else if (typeName === 'ssh-dss') {
    children.push(
      ...mpint(inner, 'DSA prime modulus (p)', 'ssh.host_key.dsa.p'), ...mpint(inner, 'DSA prime divisor (q)', 'ssh.host_key.dsa.q'),
      ...mpint(inner, 'DSA subgroup generator (g)', 'ssh.host_key.dsa.g'), ...mpint(inner, 'DSA public key (y)', 'ssh.host_key.dsa.y'),
    );
  } else if (inner.left > 0) {
    children.push(row('Host key data', hexColons(r.b, inner.at, blob.to), 'ssh.host_key.data', inner.at, blob.to));
  }
  return { name: `KEX host key (type: ${typeName})`, value: '', rawBytesRange: [at, blob.to - 1], children };
}

/** The exchange hash's signature: its type, then the rest as the reference shows it. */
function hostSignature(r: Reader): ProtocolField | null {
  const at = r.at;
  const blob = r.sized();
  if (blob === null) return null;
  const inner = new Reader(r.b, blob.from, blob.to);
  const typeAt = inner.at;
  const type = inner.sized();
  if (type === null) return null;
  const typeName = utf8.decode(r.b.subarray(type.from, type.to));
  return {
    name: `KEX host signature (type: ${typeName})`, value: '', rawBytesRange: [at, blob.to - 1],
    children: [
      row('Host signature length', blob.length, 'ssh.host_sig.length', at, at + 4),
      row('Host signature type length', type.length, 'ssh.host_sig.type_length', typeAt, typeAt + 4),
      row('Host signature type', typeName, 'ssh.host_sig.type', type.from, type.to),
      row('Host signature data', hexColons(r.b, inner.at, blob.to), 'ssh.host_sig.data', inner.at, blob.to),
    ],
  };
}

/** A hybrid exchange's blob: the classical half is the last 32 bytes, the post-quantum half the rest. */
function hybridBlob(r: Reader, client: boolean): ProtocolField[] {
  const at = r.at;
  const blob = r.sized();
  if (blob === null) return [];
  const split = Math.max(blob.from, blob.to - 32);
  return [
    row(`Hybrid Key Exchange Blob ${client ? 'Client' : 'Server'} Length`, blob.length,
      client ? 'ssh.kex_hybrid_blob_client_len' : 'ssh.kex_hybrid_blob_server_len', at, at + 4),
    {
      name: `Hybrid Key Exchange Blob ${client ? 'Client' : 'Server'}`, value: '', rawBytesRange: [blob.from, blob.to - 1],
      children: client
        ? [row("ECDH client's ephemeral public key (Q_C)", hexColons(r.b, split, blob.to), 'ssh.ecdh.q_c', split, blob.to),
          row('Client PQ KEM Public Key', hexColons(r.b, blob.from, split), 'ssh.kex.pq_kem_client', blob.from, split)]
        : [row("ECDH server's ephemeral public key (Q_S)", hexColons(r.b, split, blob.to), 'ssh.ecdh.q_s', split, blob.to),
          row('Server PQ KEM Response', hexColons(r.b, blob.from, split), 'ssh.kex.pq_kem_server', blob.from, split)],
    },
  ];
}

/** A KEXINIT's body: cookie, the ten name-lists, the flag and the hassh. */
function kexInit(r: Reader, fromClient: boolean, conv: SshConversationState, fields: Record<string, string | number>): ProtocolField[] {
  const rows: ProtocolField[] = [];
  if (r.left < 16) return rows;
  rows.push(row('Cookie', hexColons(r.b, r.at, r.at + 16), 'ssh.cookie', r.at, r.at + 16));
  r.at += 16;
  const lists: string[] = [];
  for (const [label, abbrev, lengthAbbrev] of NAME_LISTS) {
    const at = r.at;
    const list = r.sized();
    if (list === null) return rows;
    const text = utf8.decode(r.b.subarray(list.from, list.to));
    lists.push(text);
    rows.push(row(`${label} length`, list.length, lengthAbbrev, at, at + 4), row(`${label} string`, text, abbrev, list.from, list.to));
  }
  if (r.left >= 5) {
    rows.push(
      row('First KEX Packet Follows', r.b[r.at], 'ssh.first_kex_packet_follows', r.at, r.at + 1),
      row('Reserved', hexColons(r.b, r.at + 1, r.at + 5), 'ssh.kex.reserved', r.at + 1, r.at + 5),
    );
    r.at += 5;
  }
  // hassh: the algorithms this side would send with, as `kex;enc;mac;comp`.
  const own = fromClient ? 0 : 1;
  const algorithms = [lists[KEX], lists[ENC_C2S + own], lists[MAC_C2S + own], lists[COMP_C2S + own]].join(';');
  const hassh = md5Hex(algorithms);
  if (fromClient) {
    conv.clientLists = lists;
    fields['ssh.kex.hassh'] = hassh;
    rows.push(row('hasshAlgorithms', algorithms, 'ssh.kex.hassh_algorithms'), row('hassh', hassh, 'ssh.kex.hassh'));
  } else {
    conv.serverLists = lists;
    fields['ssh.kex.hasshserver'] = hassh;
    rows.push(row('hasshServerAlgorithms', algorithms, 'ssh.kex.hasshserver_algorithms'), row('hasshServer', hassh, 'ssh.kex.hasshserver'));
  }
  return rows;
}

/** One unencrypted packet, as its "SSH Version 2" subtree; its message name for Info. */
function packet(
  b: Uint8Array, at: number, end: number, dir: SshDirectionState, conv: SshConversationState, fromClient: boolean,
  fields: Record<string, string | number>,
): { node: ProtocolField; name: string } {
  const length = u32(b, at);
  const padding = b[at + 4];
  const payloadStart = at + 5;
  const payloadEnd = Math.max(payloadStart, Math.min(end, at + 4 + length - padding));
  const code = b[payloadStart];
  const settled = negotiated(conv, fromClient);
  const family = kexFamily(settled?.method);
  const name = (family !== null && code >= 30 && code <= 49 ? KEX_MESSAGES[family][code] : undefined)
    ?? MESSAGES[code] ?? `Unknown (${code})`;
  fields['ssh.message_code'] = code;

  const r = new Reader(b, payloadStart + 1, payloadEnd);
  const body: ProtocolField[] = [row('Message Code', `${name} (${code})`, 'ssh.message_code', payloadStart, payloadStart + 1)];
  if (code === 20) {
    body.push({ name: 'Algorithms', value: '', rawBytesRange: [r.at, payloadEnd - 1], children: kexInit(r, fromClient, conv, fields) });
  } else if (code >= 30 && code <= 34 && family !== null) {
    if (family === 'ecdh' && code === 30) {
      body.push(...sizedBytes(r, "ECDH client's ephemeral public key length", 'ssh.ecdh.q_c_length', "ECDH client's ephemeral public key (Q_C)", 'ssh.ecdh.q_c'));
    } else if (family === 'hybrid' && code === 30) {
      body.push(...hybridBlob(r, true));
    } else if ((family === 'dh' && code === 30) || (family === 'gex' && code === 32)) {
      body.push(...mpint(r, 'DH client e', 'ssh.dh.e'));
    } else if (family === 'gex' && code === 30 && r.left >= 4) {
      body.push(row('DH GEX Number of Bits', u32(b, r.at), 'ssh.dh_gex.nbits', r.at, r.at + 4));
    } else if (family === 'gex' && code === 34 && r.left >= 12) {
      body.push(
        row('DH GEX Min', u32(b, r.at), 'ssh.dh_gex.min', r.at, r.at + 4),
        row('DH GEX Number of Bits', u32(b, r.at + 4), 'ssh.dh_gex.nbits', r.at + 4, r.at + 8),
        row('DH GEX Max', u32(b, r.at + 8), 'ssh.dh_gex.max', r.at + 8, r.at + 12),
      );
    } else if (family === 'gex' && code === 31) {
      body.push(...mpint(r, 'DH GEX modulus (P)', 'ssh.dh_gex.p'), ...mpint(r, 'DH GEX base (G)', 'ssh.dh_gex.g'));
    } else if ((code === 31 && family !== 'gex') || (family === 'gex' && code === 33)) {
      const key = hostKey(r);
      if (key !== null) body.push(key);
      if (family === 'ecdh') {
        body.push(...sizedBytes(r, "ECDH server's ephemeral public key length", 'ssh.ecdh.q_s_length', "ECDH server's ephemeral public key (Q_S)", 'ssh.ecdh.q_s'));
      } else if (family === 'hybrid') {
        body.push(...hybridBlob(r, false));
      } else {
        body.push(...mpint(r, 'DH server f', 'ssh.dh.f'));
      }
      const signature = hostSignature(r);
      if (signature !== null) body.push(signature);
    }
  } else if (code !== 21 && r.left > 0) {
    body.push(row('Payload', hexColons(b, r.at, payloadEnd), 'ssh.payload', r.at, payloadEnd));
  }

  const method = settled?.method;
  const children: ProtocolField[] = [
    row('Packet Length', length, 'ssh.packet_length', at, at + 4),
    row('Padding Length', padding, 'ssh.padding_length', at + 4, at + 5),
    { name: method === undefined ? 'Key Exchange' : `Key Exchange (method:${method})`, value: '', rawBytesRange: [payloadStart, payloadEnd - 1], children: body },
  ];
  const padEnd = Math.min(end, at + 4 + length);
  if (padEnd > payloadEnd) children.push(row('Padding String', hexColons(b, payloadEnd, padEnd), 'ssh.padding_string', payloadEnd, padEnd));
  children.push(row('Sequence number', dir.seq, 'ssh.seq_num'));
  dir.seq += 1;
  if (code === 21) dir.encrypted = true;
  return { node: { name: versionHeading(conv, fromClient), value: '', rawBytesRange: [at, padEnd - 1], children }, name };
}

function versionHeading(conv: SshConversationState, fromClient: boolean): string {
  const settled = negotiated(conv, fromClient);
  return settled === null || settled.encryption === undefined
    ? 'SSH Version 2'
    : `SSH Version 2 (encryption:${settled.encryption} mac:${settled.mac ?? '<unknown>'} compression:${settled.compression ?? '<unknown>'})`;
}

export interface SshSegmentResult {
  protocolLabel: string;
  /** Empty when the segment only continued a packet that finishes later. */
  info: string;
  /** Null when the segment only continued a packet: it reads as TCP. */
  layer: ProtocolLayer | null;
  fields: Record<string, string | number>;
  /** Packets this segment finished that began in earlier ones. */
  reassemblies?: TcpReassembly[];
  reassembledFrom?: number[];
  /** Bytes at this segment's end kept for a packet that finishes later. */
  pendingBytes: number;
}

/** A banner line: `SSH-protoversion-softwareversion`, up to its line feed. */
function banner(b: Uint8Array, at: number, end: number): { line: string; next: number } | null {
  if (end - at < 4 || b[at] !== 0x53 || b[at + 1] !== 0x53 || b[at + 2] !== 0x48 || b[at + 3] !== 0x2d) return null;
  let p = at;
  while (p < end && b[p] !== 0x0a) p++;
  const line = utf8.decode(b.subarray(at, p)).replace(/\r$/, '');
  return { line, next: Math.min(end, p + 1) };
}

/**
 * One in-order segment of an SSH connection, read against its direction's
 * state. Null when it is not SSH as far as this can tell - a segment before
 * any banner that does not open with one.
 */
export function dissectSshSegment(
  b: Uint8Array, start: number, end: number, conv: SshConversationState, fromClient: boolean, frame: number,
): SshSegmentResult | null {
  const dir = fromClient ? conv.client : conv.server;
  const peer = fromClient ? conv.server : conv.client;
  const fields: Record<string, string | number> = {};
  const rows: ProtocolField[] = [];
  const names: string[] = [];
  const reassemblies: TcpReassembly[] = [];
  const reassembledFrom: number[] = [];
  let pendingBytes = 0;
  let p = start;

  if (dir.version === 0) {
    const line = banner(b, p, end);
    if (line === null) return null;
    dir.version = /^SSH-(2\.0|1\.99)-/.test(line.line) ? 2 : /^SSH-1\./.test(line.line) ? 1 : 2;
    fields['ssh.protocol'] = line.line;
    rows.push(row('Protocol', line.line, 'ssh.protocol', p, line.next));
    names.push(`Protocol (${line.line})`);
    p = line.next;
  }

  while (p < end && dir.version === 2) {
    if (dir.encrypted) {
      const settled = negotiated(conv, fromClient);
      const mac = macBytes(settled?.mac);
      const children: ProtocolField[] = [];
      const length = end - p;
      if (length >= 4) {
        children.push(row('Packet Length (encrypted)', hexColons(b, p, p + 4), 'ssh.packet_length_encrypted', p, p + 4));
        const macStart = mac !== undefined && mac > 0 && length - 4 > mac ? end - mac : end;
        children.push(row('Encrypted Packet', hexColons(b, p + 4, macStart), 'ssh.encrypted_packet', p + 4, macStart));
        if (macStart < end) children.push(row('MAC', hexColons(b, macStart, end), 'ssh.mac', macStart, end));
      }
      rows.push({ name: versionHeading(conv, fromClient), value: '', rawBytesRange: [p, end - 1], children });
      names.push(`Encrypted packet (len=${length})`);
      p = end;
      break;
    }

    // A packet begun earlier: this segment's bytes go on the end of it -
    // first whatever its length field still lacks, then the rest of it.
    if (dir.pending !== null) {
      const pending = dir.pending;
      let took = 0;
      while (pending.length < 4 && p < end) { pending.push(b[p++]); took++; }
      const total = pending.length >= 4 ? 4 + u32(pending, 0) : 0;
      if (total !== 0 && (total < 9 || total > MAX_PACKET + 4)) {
        // Not a length after all: the stream is not where it was thought.
        dir.pending = null;
        dir.pendingFrames = [];
        break;
      }
      while (total !== 0 && pending.length < total && p < end) { pending.push(b[p++]); took++; }
      if (total === 0 || pending.length < total) {
        dir.pendingFrames.push({ frame, bytes: took });
        pendingBytes += took;
        break;
      }
      // Finished here: drawn from the joined bytes, which belong to no one
      // frame, so its rows point at none.
      reassemblies.push({ length: total, contributions: [...dir.pendingFrames, { frame, bytes: took }] });
      reassembledFrom.push(...dir.pendingFrames.map((c) => c.frame).filter((f) => f !== frame));
      dir.pending = null;
      dir.pendingFrames = [];
      const done = packet(Uint8Array.from(pending), 0, total, dir, conv, fromClient, fields);
      stripRanges(done.node);
      rows.push(done.node);
      names.push(done.name);
      continue;
    }

    if (end - p < 4) {
      dir.pending = Array.from(b.subarray(p, end));
      dir.pendingFrames = [{ frame, bytes: end - p }];
      pendingBytes += end - p;
      break;
    }
    const length = u32(b, p);
    if (length < 5 || length > MAX_PACKET) break;
    const total = 4 + length;
    if (p + total > end) {
      dir.pending = Array.from(b.subarray(p, end));
      dir.pendingFrames = [{ frame, bytes: end - p }];
      pendingBytes += end - p;
      break;
    }
    const done = packet(b, p, p + total, dir, conv, fromClient, fields);
    rows.push(done.node);
    names.push(done.name);
    p += total;
  }

  const version = dir.version || peer.version;
  const protocolLabel = version === 2 ? 'SSHv2' : version === 1 ? 'SSHv1' : 'SSH';
  if (names.length === 0) {
    return { protocolLabel: 'TCP', info: '', layer: null, fields: {}, pendingBytes };
  }
  rows.push({ name: 'Direction', value: fromClient ? 'Client to Server' : 'Server to Client', abbrev: 'ssh.direction' });
  const info = `${fromClient ? 'Client' : 'Server'}: ${names.join(', ')}`;
  return {
    protocolLabel,
    info,
    layer: { name: 'SSH Protocol', summary: 'SSH Protocol', fields: rows, rawBytesRange: [start, end - 1] },
    fields,
    ...(reassemblies.length > 0 ? { reassemblies, reassembledFrom } : {}),
    pendingBytes,
  };
}

function stripRanges(field: ProtocolField): void {
  delete field.rawBytesRange;
  for (const child of field.children ?? []) stripRanges(child);
}
