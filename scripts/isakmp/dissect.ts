/**
 * IPsec - IKEv1, IKEv2, ESP and NAT-T - against the reference, row for row.
 *
 *   npx tsx scripts/isakmp/dissect.ts
 *
 * How a VPN built into Windows or macOS, or run by a strongSwan, Cisco or
 * Fortinet gateway, comes up - and, when it does not, the only part of the
 * conversation that says why. Built from RFC 2408/2409 and RFC 7296 layouts,
 * since neither fixture holds IPsec:
 * - IKEv1 Main Mode (SA with two transforms and their attributes, the vendor
 *   IDs a Windows client sends, KE/Nonce/NAT-D, then encrypted), Aggressive
 *   Mode with its cleartext identity, Quick Mode and Informational;
 * - IKEv2's IKE_SA_INIT both ways - proposals with their transforms, the key
 *   exchange, the NAT-detection and capability notifies, a certificate
 *   request - an INVALID_KE_PAYLOAD refusal, and the encrypted exchanges after;
 * - ESP's sequence analysis: in order, repeated, a gap, behind, a second SA;
 * - NAT-T on 4500: IKE behind the non-ESP marker, ESP, and the keepalive.
 */
import { Bytes, ipFrame, udpFrame } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const fill = (n: number, v: number) => new Array(n).fill(v);
const hex = (h: string) => h.match(/../g)!.map((x) => parseInt(x, 16));
const u16 = (n: number) => [n >> 8, n & 255];
const u32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
/** A generic payload: next payload, reserved, length, body. */
const payload = (next: number, body: number[]) => [next, 0, ...u16(4 + body.length), ...body];
/** An ISAKMP message: SPIs, first payload, version, exchange, flags, message ID, length. */
const message = (first: number, version: number, exchange: number, flags: number, id: number, body: number[], responderSpi = false) =>
  Uint8Array.from([...fill(8, 0x11), ...(responderSpi ? fill(8, 0x22) : fill(8, 0)), first, version, exchange, flags, ...u32(id), ...u32(28 + body.length), ...body]);
const tv = (type: number, value: number) => [0x80 | (type >> 8), type & 255, ...u16(value)];
const tlv = (type: number, value: number[]) => [type >> 8, type & 255, ...u16(value.length), ...value];

// IKEv1: an SA offering AES-256/SHA2-256/PSK/group 14 and 3DES/SHA1/XAUTH/group 2.
const v1Transform = (last: boolean, n: number, attributes: number[]) => payload(last ? 0 : 3, [n, 1, 0, 0, ...attributes]);
const v1Sa = [...u32(1), ...u32(1), ...payload(0, [1, 1, 0, 2,
  ...v1Transform(false, 1, [...tv(1, 7), ...tv(14, 256), ...tv(2, 4), ...tv(3, 1), ...tv(4, 14), ...tv(11, 1), ...tlv(12, u32(28800))]),
  ...v1Transform(true, 2, [...tv(1, 5), ...tv(2, 2), ...tv(3, 65001), ...tv(4, 2), ...tv(11, 1), ...tv(12, 28800)]),
])];
// IKEv2: AES-CBC-256/SHA2-256/ECP-256, or AES-GCM-128/Curve25519/MODP-2048.
const v2Transform = (last: boolean, type: number, id: number, attributes: number[] = []) => payload(last ? 0 : 3, [type, 0, ...u16(id), ...attributes]);
const v2Proposals = [
  ...payload(2, [1, 1, 0, 4, ...v2Transform(false, 1, 12, tv(14, 256)), ...v2Transform(false, 3, 12), ...v2Transform(false, 2, 5), ...v2Transform(true, 4, 19)]),
  ...payload(0, [2, 1, 0, 4, ...v2Transform(false, 1, 20, tv(14, 128)), ...v2Transform(false, 2, 5), ...v2Transform(false, 4, 31), ...v2Transform(true, 4, 14)]),
];
const v2Payload = (next: number, body: number[], critical = false) => [next, critical ? 0x80 : 0, ...u16(4 + body.length), ...body];
const notify = (next: number, type: number, data: number[]) => v2Payload(next, [0, 0, ...u16(type), ...data]);
const encrypted = (first: number) => v2Payload(0, [...fill(16, 0x49), ...fill(48, 0x45), ...fill(16, 0x16)]).map((x, i) => (i === 0 ? first : x));

const ike = (payloadBytes: Uint8Array) => udpFrame(500, 500, payloadBytes);
const natT = (payloadBytes: number[] | Uint8Array) => udpFrame(4500, 4500, Uint8Array.from(payloadBytes));
const esp = (spi: number, seq: number) => new Bytes().u32(spi).u32(seq).raw(fill(48, 0x99)).build();

const cases: OracleCase[] = [
  { label: 'IKEv1 Main Mode 1: the SA and a Windows client\'s vendor IDs', frame: ike(message(1, 0x10, 2, 0, 0, [
    ...payload(13, v1Sa), ...payload(13, hex('4a131c81070358455c5728f20e95452f')),
    ...payload(13, hex('1e2b516905991c7d7c96fcbfb587e46100000004')), ...payload(13, hex('fb1de3cdf341b7ea16b7e5be0855f120')),
    ...payload(13, hex('4048b7d56ebce88525e7de7f00d6c2d380000000')), ...payload(0, hex('afcad71368a1f1c96b8696fc77570100')),
  ])) },
  { label: 'IKEv1 Main Mode 3: key exchange, nonce, NAT detection', frame: ike(message(4, 0x10, 2, 0, 0, [
    ...payload(10, fill(128, 0x4b)), ...payload(20, fill(32, 0x4e)), ...payload(20, fill(20, 0xd1)), ...payload(0, fill(20, 0xd2)),
  ], true)) },
  { label: 'IKEv1 Main Mode 5: encrypted', frame: ike(message(5, 0x10, 2, 1, 0, fill(64, 0xe5), true)) },
  { label: 'IKEv1 Aggressive Mode with an IPv4 identity', frame: ike(message(1, 0x10, 4, 0, 0, [
    ...payload(4, v1Sa), ...payload(10, fill(128, 0x4b)), ...payload(5, fill(16, 0x4e)),
    ...payload(13, [1, 17, ...u16(500), 192, 0, 2, 1]), ...payload(0, hex('09002689dfd6b712')),
  ])) },
  { label: 'IKEv1 Aggressive Mode with an FQDN identity', frame: ike(message(5, 0x10, 4, 0, 0, [
    ...payload(13, [2, 17, ...u16(500), ...new TextEncoder().encode('vpn.example.com')]), ...payload(0, hex('12f5f28c457168a9702d9fe274cc0100')),
  ])) },
  { label: 'IKEv1 Quick Mode, encrypted', frame: ike(message(8, 0x10, 32, 1, 0x12345678, fill(48, 0xe6), true)) },
  { label: 'IKEv1 Informational, encrypted', frame: ike(message(8, 0x10, 5, 1, 0x0abcdef0, fill(48, 0xe7), true)) },
  { label: 'IKEv2 IKE_SA_INIT request', frame: ike(message(33, 0x20, 34, 0x08, 0, [
    ...v2Payload(34, v2Proposals), ...v2Payload(40, [0, 19, 0, 0, ...fill(64, 0x4b)]), ...v2Payload(41, fill(32, 0x4e)),
    ...notify(41, 16388, fill(20, 0x51)), ...notify(41, 16389, fill(20, 0x52)), ...notify(41, 16430, []),
    ...notify(43, 16431, [0, 2, 0, 3, 0, 4]), ...v2Payload(0, hex('882fe56d6fd20dbc2251613b2ebe5beb')),
  ])) },
  { label: 'IKEv2 IKE_SA_INIT response with a certificate request', frame: ike(message(33, 0x20, 34, 0x20, 0, [
    ...v2Payload(34, v2Proposals.slice(0, 48).map((x, i) => (i === 0 ? 0 : x))), ...v2Payload(40, [0, 19, 0, 0, ...fill(64, 0x4c)]),
    ...v2Payload(41, fill(32, 0x4f)), ...notify(41, 16388, fill(20, 0x53)), ...notify(38, 16404, []),
    ...v2Payload(0, [4, ...fill(20, 0xca)]),
  ], true)) },
  { label: 'IKEv2 refusal: INVALID_KE_PAYLOAD', frame: ike(message(41, 0x20, 34, 0x20, 0, notify(0, 17, u16(14)), true)) },
  { label: 'IKEv2 refusal: NO_PROPOSAL_CHOSEN', frame: ike(message(41, 0x20, 34, 0x20, 0, notify(0, 14, []), true)) },
  { label: 'IKEv2 IKE_AUTH over NAT-T, encrypted', frame: natT([0, 0, 0, 0, ...message(46, 0x20, 35, 0x08, 1, encrypted(35), true)]) },
  { label: 'IKEv2 INFORMATIONAL, encrypted', frame: ike(message(46, 0x20, 37, 0x28, 2, encrypted(0), true)) },
  { label: 'ESP, the first packet of an SA', frame: ipFrame(50, esp(0x1001, 1)) },
  { label: 'ESP, the next in order', frame: ipFrame(50, esp(0x1001, 2)) },
  { label: 'ESP, in order again', frame: ipFrame(50, esp(0x1001, 3)) },
  { label: 'ESP, repeated', frame: ipFrame(50, esp(0x1001, 3)) },
  { label: 'ESP, after a gap', frame: ipFrame(50, esp(0x1001, 10)) },
  { label: 'ESP, a second SA', frame: ipFrame(50, esp(0x2002, 5)) },
  { label: 'ESP, behind', frame: ipFrame(50, esp(0x1001, 9)) },
  { label: 'ESP inside NAT-T', frame: natT(esp(0x3003, 1)) },
  { label: 'a NAT-T keepalive', frame: natT([0xff]) },
  { label: 'ESP inside NAT-T, next in order', frame: natT(esp(0x3003, 2)) },
];

const packets = await compareWithReference(cases, { rows: /^(isakmp|esp|udpencap)\./ });
await checkRevisit(cases);

check('a refusal is filterable by its notify', packets[9]?.fields?.['isakmp.notify.msgtype'] === 17);
check('ESP inside NAT-T is `udpencap` then `esp`', JSON.stringify(packets[20]?.frameProtocols?.slice(-2)) === '["udpencap","esp"]');
check('ESP over IP is the `esp` layer', packets[13]?.frameProtocols?.at(-1) === 'esp');

finish('IPsec');
