/**
 * WireGuard (wireguard.com/protocol), recognised on any UDP port.
 *
 *   Handshake Initiation, sender=0x01020304
 *   Transport Data, receiver=0x05060708, counter=5, datalen=32
 *
 * The VPN behind a growing share of consumer and corporate clients - Mullvad,
 * NordLynx, Cloudflare WARP, Tailscale - on whatever port it was configured
 * for, which is why it is found by content and not by 51820. Everything after
 * the handshake is encrypted, so what a capture can say is who opened a
 * session, whether it was answered, and how much went through it.
 *
 * **Recognised as the reference recognises it**: the type byte, then a length
 * that is exact for the three handshake messages and at least 32 for data.
 * The reserved bytes must be zero only for a cookie reply and for data -
 * Cloudflare's implementation puts load-balancing bits in them during the
 * handshake, and the reference accepts that.
 *
 * Indices are little-endian, as the protocol writes them, and the reference
 * prints them as 0x%08x of that value. The ephemeral key is base64, which is
 * how WireGuard's own tools print keys.
 *
 * Sessions - `wg.stream`, and the response's `[Response to Frame]` - are the
 * L3 tracker's (`L3Tracker.wireguard`); this module reads one datagram.
 */
import type { ProtocolField } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import type { UdpAppResult } from './udpApps';

const TYPES: Record<number, string> = {
  1: 'Handshake Initiation', 2: 'Handshake Response', 3: 'Cookie Reply', 4: 'Transport Data',
};
const LENGTHS: Record<number, number> = { 1: 148, 2: 92, 3: 64 };

const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const index = (n: number) => `0x${n.toString(16).padStart(8, '0')}`;
/** The Info column's spelling of the same index: the reference upper-cases it there and only there. */
const infoIndex = (n: number) => `0x${n.toString(16).toUpperCase().padStart(8, '0')}`;

/** Base64 without a TextEncoder round trip: the key is 32 raw bytes. */
function base64(b: Uint8Array, from: number, to: number): string {
  let binary = '';
  for (let i = from; i < to; i++) binary += String.fromCharCode(b[i]);
  return btoa(binary);
}

export function looksLikeWireGuard(b: Uint8Array, start: number, end: number): boolean {
  const length = end - start;
  if (length < 4) return false;
  const type = b[start];
  const reservedZero = b[start + 1] === 0 && b[start + 2] === 0 && b[start + 3] === 0;
  if (type === 4) return reservedZero && length >= 32;
  if (type === 3) return reservedZero && length === LENGTHS[3];
  return (type === 1 || type === 2) && length === LENGTHS[type];
}

/** What the session tracker needs of a datagram already recognised. */
export interface WireGuardFacts {
  type: 1 | 2 | 3 | 4;
  sender?: number;
  receiver?: number;
}

export function wireGuardFacts(b: Uint8Array, start: number): WireGuardFacts {
  const type = b[start] as 1 | 2 | 3 | 4;
  if (type === 1) return { type, sender: le32(b, start + 4) };
  if (type === 2) return { type, sender: le32(b, start + 4), receiver: le32(b, start + 8) };
  return { type, receiver: le32(b, start + 4) };
}

export function dissectWireGuard(b: Uint8Array, start: number, end: number): UdpAppResult | null {
  if (!looksLikeWireGuard(b, start, end)) return null;
  const type = b[start];
  const rows: ProtocolField[] = [
    { name: 'Type', value: `${TYPES[type]} (${type})`, abbrev: 'wg.type', rawBytesRange: [start, start] },
    { name: 'Reserved', value: hexColons(b, start + 1, start + 4), abbrev: 'wg.reserved', rawBytesRange: [start + 1, start + 3] },
  ];
  const fields: Record<string, string | number> = { 'wg.type': type };
  const idRow = (name: string, abbrev: 'wg.sender' | 'wg.receiver', at: number): ProtocolField => {
    const value = le32(b, at);
    fields[abbrev] = value;
    return { name, value: index(value), abbrev, rawBytesRange: [at, at + 3] };
  };
  const bytesRow = (name: string, abbrev: string, at: number, length: number): ProtocolField =>
    ({ name, value: hexColons(b, at, at + length), abbrev, rawBytesRange: [at, at + length - 1] });
  const ephemeral = (at: number): ProtocolField => ({
    name: 'Ephemeral', value: base64(b, at, at + 32), abbrev: 'wg.ephemeral', rawBytesRange: [at, at + 31],
    // Whether a key file named this key's private half. None is ever loaded.
    children: [{ name: 'Has Private Key', value: 'False', abbrev: 'wg.ephemeral.known_privkey', generated: true }],
  });
  const opaque = (name: string, abbrev: string, at: number, length: number): ProtocolField =>
    ({ name, value: '', abbrev, rawBytesRange: [at, at + length - 1] });

  let info: string;
  if (type === 1) {
    const sender = idRow('Sender', 'wg.sender', start + 4);
    rows.push(
      sender, ephemeral(start + 8),
      opaque('Encrypted Static', 'wg.encrypted_static', start + 40, 48),
      opaque('Encrypted Timestamp', 'wg.encrypted_timestamp', start + 88, 28),
      bytesRow('mac1', 'wg.mac1', start + 116, 16), bytesRow('mac2', 'wg.mac2', start + 132, 16),
    );
    info = `Handshake Initiation, sender=${infoIndex(fields['wg.sender'] as number)}`;
  } else if (type === 2) {
    const sender = idRow('Sender', 'wg.sender', start + 4);
    const receiver = idRow('Receiver', 'wg.receiver', start + 8);
    rows.push(
      sender, receiver, ephemeral(start + 12),
      opaque('Encrypted Empty', 'wg.encrypted_empty', start + 44, 16),
      bytesRow('mac1', 'wg.mac1', start + 60, 16), bytesRow('mac2', 'wg.mac2', start + 76, 16),
    );
    info = `Handshake Response, sender=${infoIndex(fields['wg.sender'] as number)}, receiver=${infoIndex(fields['wg.receiver'] as number)}`;
  } else if (type === 3) {
    const receiver = idRow('Receiver', 'wg.receiver', start + 4);
    rows.push(
      receiver, bytesRow('Nonce', 'wg.nonce', start + 8, 24),
      bytesRow('Encrypted Cookie', 'wg.encrypted_cookie', start + 32, 32),
    );
    info = `Cookie Reply, receiver=${infoIndex(fields['wg.receiver'] as number)}`;
  } else {
    const receiver = idRow('Receiver', 'wg.receiver', start + 4);
    // A 64-bit little-endian counter; past 2^53 it is not a safe integer, and
    // a session that sent that many packets has been rekeyed long since.
    const counter = le32(b, start + 8) + le32(b, start + 12) * 2 ** 32;
    fields['wg.counter'] = counter;
    rows.push(
      receiver,
      { name: 'Counter', value: counter, abbrev: 'wg.counter', rawBytesRange: [start + 8, start + 15] },
      opaque('Encrypted Packet', 'wg.encrypted_packet', start + 16, end - start - 16),
    );
    // The plaintext is the ciphertext less its 16-byte tag; none is a keepalive.
    const dataLength = end - start - 32;
    if (dataLength === 0) {
      rows.push({ name: 'This is a Keepalive message', value: '', abbrev: 'wg.keepalive', generated: true });
      info = `Keepalive, receiver=${infoIndex(fields['wg.receiver'] as number)}, counter=${counter}`;
    } else {
      info = `Transport Data, receiver=${infoIndex(fields['wg.receiver'] as number)}, counter=${counter}, datalen=${dataLength}`;
    }
  }

  return {
    protocolLabel: 'WireGuard',
    info,
    layer: { name: 'WireGuard Protocol', summary: info, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
    token: 'wg',
  };
}
