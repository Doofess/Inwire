/**
 * NTLMSSP messages and the carriers that hold them, built from MS-NLMP,
 * RFC 4178 (SPNEGO) and RFC 2743 (GSS-API), for `scripts/ntlmssp/dissect.ts`.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';

export const le16 = (n: number) => [n & 255, (n >> 8) & 255];
export const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
export const le64 = (n: bigint) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
export const utf16 = (text: string) => [...text].flatMap((c) => le16(c.charCodeAt(0)));
export const ascii = (text: string) => [...text].map((c) => c.charCodeAt(0));
const SIGNATURE = ascii('NTLMSSP\0');

/** Windows 10's version structure: major, minor, build, three reserved, NTLM revision 15. */
export const VERSION = [10, 0, ...le16(19041), 0, 0, 0, 15];

/** A message: its fixed part with each buffer's (length, max, offset) filled in, then the buffers. */
function message(type: number, fixed: (sb: (i: number) => number[]) => number[], buffers: number[][]): number[] {
  // Two passes: the fixed part's length decides where the payload starts.
  const head = (offsets: number[]) => [...SIGNATURE, ...le32(type),
    ...fixed((i) => [...le16(buffers[i].length), ...le16(buffers[i].length), ...le32(offsets[i])])];
  const fixedLength = head(buffers.map(() => 0)).length;
  const offsets: number[] = [];
  let at = fixedLength;
  for (const b of buffers) { offsets.push(at); at += b.length; }
  return [...head(offsets), ...buffers.flat()];
}

export function negotiate(flags: number, domain = '', workstation = '', version = true): number[] {
  return message(1, (sb) => [...le32(flags), ...sb(0), ...sb(1), ...(version ? VERSION : [])], [ascii(domain), ascii(workstation)]);
}

export interface AvPair { id: number; value: number[] }
export const av = (id: number, value: number[]): AvPair => ({ id, value });
export const avText = (id: number, text: string): AvPair => av(id, utf16(text));
export const avList = (pairs: AvPair[]) => [...pairs.flatMap((p) => [...le16(p.id), ...le16(p.value.length), ...p.value]), 0, 0, 0, 0];

export const FILETIME = 0x01d9a3b4c5d6e7f8n;

export function challenge(flags: number, target: string, info: AvPair[], serverChallenge = [1, 2, 3, 4, 5, 6, 7, 8]): number[] {
  return message(2, (sb) => [...sb(0), ...le32(flags), ...serverChallenge, 0, 0, 0, 0, 0, 0, 0, 0, ...sb(1), ...VERSION],
    [utf16(target), avList(info)]);
}

/** An NTLMv2 response: NTProofStr, then the client's blob. */
export function ntlmv2Response(info: AvPair[]): number[] {
  const proof = Array.from({ length: 16 }, (_, i) => 0xa0 + i);
  return [...proof, 1, 1, 0, 0, 0, 0, 0, 0, ...le64(FILETIME), 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, ...avList(info), 0, 0, 0, 0];
}

export function authenticate(
  flags: number, domain: string, user: string, host: string,
  lm: number[], nt: number[], sessionKey: number[], mic = true, oem = false,
): number[] {
  const text = oem ? ascii : utf16;
  return message(3, (sb) => [...sb(0), ...sb(1), ...sb(2), ...sb(3), ...sb(4), ...sb(5), ...le32(flags), ...VERSION,
    ...(mic ? Array.from({ length: 16 }, (_, i) => 0xc0 + i) : [])],
  [lm, nt, text(domain), text(user), text(host), sessionKey]);
}

// --- ASN.1 DER, for SPNEGO --------------------------------------------------

export function tlv(tag: number, content: number[]): number[] {
  const n = content.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 255];
  return [tag, ...length, ...content];
}
export const SPNEGO_OID = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
export const NTLMSSP_OID = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
export const KRB5_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
export const MSKRB5_OID = [0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/** A GSS-API InitialContextToken holding a SPNEGO negTokenInit. */
export function negTokenInit(mechs: number[][], mechToken?: number[], hints = false): number[] {
  const parts = [
    ...tlv(0xa0, tlv(0x30, mechs.flatMap((m) => tlv(0x06, m)))),
    ...(mechToken !== undefined ? tlv(0xa2, tlv(0x04, mechToken)) : []),
    ...(hints ? tlv(0xa3, tlv(0x30, tlv(0xa0, tlv(0x1b, ascii('not_defined_in_RFC4178@please_ignore'))))) : []),
  ];
  return tlv(0x60, [...tlv(0x06, SPNEGO_OID), ...tlv(0xa0, tlv(0x30, parts))]);
}

/** A SPNEGO negTokenResp. */
export function negTokenResp(opts: { state?: number; mech?: number[]; token?: number[]; mic?: number[] }): number[] {
  const parts = [
    ...(opts.state !== undefined ? tlv(0xa0, tlv(0x0a, [opts.state])) : []),
    ...(opts.mech !== undefined ? tlv(0xa1, tlv(0x06, opts.mech)) : []),
    ...(opts.token !== undefined ? tlv(0xa2, tlv(0x04, opts.token)) : []),
    ...(opts.mic !== undefined ? tlv(0xa3, tlv(0x04, opts.mic)) : []),
  ];
  return tlv(0xa1, tlv(0x30, parts));
}

// --- one TCP connection, for each carrier ------------------------------------

export class Connection {
  private clientSeq = 1000;
  private serverSeq = 5000;
  constructor(readonly client: string, readonly server: string, readonly clientPort: number, readonly serverPort: number) {}
  segment(fromClient: boolean, payload: number[]): Uint8Array {
    const body = Uint8Array.from(payload);
    const seg = fromClient
      ? tcp(this.clientPort, this.serverPort, this.clientSeq, this.serverSeq, body)
      : tcp(this.serverPort, this.clientPort, this.serverSeq, this.clientSeq, body);
    if (fromClient) this.clientSeq += body.length; else this.serverSeq += body.length;
    return Uint8Array.from([...ethernet(0x0800).build(),
      ...ipv4(6, seg, fromClient ? this.client : this.server, fromClient ? this.server : this.client)]);
  }
}

/** The 64-byte SMB2 header. */
export const smb2Header = (command: number, messageId: number, response: boolean, sessionId: bigint, status = 0) => [
  0xfe, 0x53, 0x4d, 0x42, ...le16(64), ...le16(1), ...le32(status), ...le16(command), ...le16(1), ...le32(response ? 1 : 0), ...le32(0),
  ...le64(BigInt(messageId)), ...le32(0xfeff), ...le32(0), ...le64(sessionId), ...new Array(16).fill(0),
];
export const nbss = (message: number[]) => [0, (message.length >> 16) & 255, (message.length >> 8) & 255, message.length & 255, ...message];

export function sessionSetupRequest(messageId: number, sessionId: bigint, blob: number[]): number[] {
  return nbss([...smb2Header(1, messageId, false, sessionId), ...le16(25), 0, 1, ...le32(1), ...le32(0),
    ...le16(88), ...le16(blob.length), ...le64(0n), ...blob]);
}
export function sessionSetupResponse(messageId: number, sessionId: bigint, status: number, blob: number[]): number[] {
  return nbss([...smb2Header(1, messageId, true, sessionId, status), ...le16(9), ...le16(0),
    ...le16(blob.length > 0 ? 72 : 0), ...le16(blob.length), ...blob]);
}
export function negotiateResponse(messageId: number, blob: number[]): number[] {
  return nbss([...smb2Header(0, messageId, true, 0n), ...le16(65), ...le16(1), ...le16(0x0311), ...le16(0),
    ...new Array(16).fill(0x42), ...le32(0x2f), ...le32(0x800000), ...le32(0x800000), ...le32(0x800000),
    ...le64(0n), ...le64(0n), ...le16(128), ...le16(blob.length), ...le32(0), ...blob]);
}

export const base64 = (bytes: number[]) => Buffer.from(bytes).toString('base64');
