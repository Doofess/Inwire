/**
 * OpenVPN on UDP 1194: the packet header, control and data channel alike.
 *
 *   MessageType: P_CONTROL_HARD_RESET_CLIENT_V2
 *   MessageType: P_DATA_V2
 *
 * The other VPN a consumer client runs when it is not WireGuard. Almost all of
 * a session is P_DATA_V2 - a peer ID and ciphertext - so what a capture says
 * is which peer, which key, and whether the handshake (the hard resets, the
 * acknowledgements, the control packets) completed. Port 1194 only, as the
 * reference dispatches it.
 *
 * **tls-auth is detected as the reference detects it**: on a control or ack
 * packet, when the byte after the session ID is not zero and the four bytes
 * there have at most one zero among them, they are taken for the start of a
 * 20-byte HMAC, followed by a replay packet ID and a timestamp. That is a
 * guess - which is why the reference makes it a preference - and it is the
 * same guess, so the rows agree.
 *
 * A control packet's payload is a fragment of the TLS handshake that keys the
 * session. The reference reassembles those fragments and draws the TLS; here
 * the fragment is drawn as its bytes.
 */
import type { ProtocolField } from '../../types/packet';
import { hexColons } from '../dissect/hexBytes';
import { formatArrivalTime } from '../dissect/arrivalTime';
import type { LeafResult } from './dispatch';

export const OPENVPN_PORT = 1194;

const OPCODES: Record<number, string> = {
  1: 'P_CONTROL_HARD_RESET_CLIENT_V1', 2: 'P_CONTROL_HARD_RESET_SERVER_V1', 3: 'P_CONTROL_SOFT_RESET_V1',
  4: 'P_CONTROL_V1', 5: 'P_ACK_V1', 6: 'P_DATA_V1', 7: 'P_CONTROL_HARD_RESET_CLIENT_V2',
  8: 'P_CONTROL_HARD_RESET_SERVER_V2', 9: 'P_DATA_V2', 10: 'P_CONTROL_HARD_RESET_CLIENT_V3', 11: 'P_CONTROL_WKC_V1',
};
const P_ACK = 5;
const P_DATA_V1 = 6;
const P_DATA_V2 = 9;
/** The reference's default HMAC size when it decides tls-auth is on: SHA-1's. */
const HMAC_BYTES = 20;

const u32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const u64 = (b: Uint8Array, at: number) => b.subarray(at, at + 8).reduce((n, x) => n * 256n + BigInt(x), 0n);

/** packet-openvpn.c's `check_for_valid_hmac`: at most one zero byte among four. */
function looksLikeHmac(b: Uint8Array, at: number): boolean {
  let zeros = 0;
  for (let i = 0; i < 4; i++) if (b[at + i] === 0) zeros++;
  return zeros <= 1;
}

export function dissectOpenvpn(b: Uint8Array, start: number, end: number): LeafResult | null {
  if (start >= end) return null;
  const opcode = b[start] >> 3;
  const keyId = b[start] & 0x07;
  const name = OPCODES[opcode];
  if (name === undefined) return null;
  const rows: ProtocolField[] = [{
    name: 'Type', value: `0x${b[start].toString(16).padStart(2, '0')} [opcode/key_id]`, abbrev: 'openvpn.type', rawBytesRange: [start, start],
    children: [
      { name: 'Opcode', value: `${name} (0x${opcode.toString(16).padStart(2, '0')})`, abbrev: 'openvpn.opcode', rawBytesRange: [start, start], bitfield: { bitOffset: 0, bitLength: 5, totalBits: 8 } },
      { name: 'Key ID', value: keyId, abbrev: 'openvpn.keyid', rawBytesRange: [start, start], bitfield: { bitOffset: 5, bitLength: 3, totalBits: 8 } },
    ],
  }];
  const fields: Record<string, string | number> = { 'openvpn.opcode': opcode, 'openvpn.keyid': keyId };
  let p = start + 1;

  if (opcode === P_DATA_V1 || opcode === P_DATA_V2) {
    if (opcode === P_DATA_V2 && p + 3 <= end) {
      const peer = (b[p] << 16) | (b[p + 1] << 8) | b[p + 2];
      fields['openvpn.peerid'] = peer;
      rows.push({ name: 'Peer ID', value: peer, abbrev: 'openvpn.peerid', rawBytesRange: [p, p + 2] });
      p += 3;
    }
  } else {
    if (p + 8 > end) return null;
    const session = u64(b, p).toString();
    fields['openvpn.sessionid'] = session;
    rows.push({ name: 'Session ID', value: session, abbrev: 'openvpn.sessionid', rawBytesRange: [p, p + 7] });
    p += 8;
    if (p + 4 <= end && b[p] > 0 && looksLikeHmac(b, p) && p + HMAC_BYTES + 8 <= end) {
      rows.push(
        { name: 'HMAC', value: hexColons(b, p, p + HMAC_BYTES), abbrev: 'openvpn.hmac', rawBytesRange: [p, p + HMAC_BYTES - 1] },
        { name: 'Replay-Packet-ID', value: u32(b, p + HMAC_BYTES), abbrev: 'openvpn.pid', rawBytesRange: [p + HMAC_BYTES, p + HMAC_BYTES + 3] },
        { name: 'Net Time', value: formatArrivalTime(u32(b, p + HMAC_BYTES + 4) * 1_000_000), abbrev: 'openvpn.net_time', rawBytesRange: [p + HMAC_BYTES + 4, p + HMAC_BYTES + 7] },
      );
      p += HMAC_BYTES + 8;
    }
    if (p >= end) return null;
    const acks = b[p];
    rows.push({ name: 'Message Packet-ID Array Length', value: acks, abbrev: 'openvpn.mpidarraylength', rawBytesRange: [p, p] });
    p += 1;
    if (acks > 0) {
      const array: ProtocolField[] = [];
      for (let i = 0; i < acks && p + 4 <= end; i++, p += 4) {
        array.push({ name: 'Message Packet-ID Array Element', value: u32(b, p), abbrev: 'openvpn.mpidarrayelement', rawBytesRange: [p, p + 3] });
      }
      rows.push({ name: 'Packet-ID Array', value: '', children: array });
      if (p + 8 <= end) {
        rows.push({ name: 'Remote Session ID', value: u64(b, p).toString(), abbrev: 'openvpn.rsessionid', rawBytesRange: [p, p + 7] });
        p += 8;
      }
    }
    if (opcode !== P_ACK && p + 4 <= end) {
      rows.push({ name: 'Message Packet-ID', value: u32(b, p), abbrev: 'openvpn.mpid', rawBytesRange: [p, p + 3] });
      p += 4;
    }
  }
  if (p < end) {
    rows.push({
      name: `Data (${end - p} bytes)`, value: '', rawBytesRange: [p, end - 1],
      children: [{ name: 'Data', value: hexColons(b, p, end), abbrev: 'openvpn.data', rawBytesRange: [p, end - 1] }],
    });
  }
  return {
    protocolLabel: 'OpenVPN',
    info: `MessageType: ${name}`,
    layer: { name: 'OpenVPN Protocol', summary: `OpenVPN Protocol, Opcode: ${name}, Key ID: ${keyId}`, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
  };
}
