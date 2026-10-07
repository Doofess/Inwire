/**
 * NAT-PMP, PCP and Dropbox's LAN discovery, against the reference.
 *
 *   npx tsx scripts/portcontrol/dissect.ts
 *
 * Small, constant chatter on any laptop's network that reached the packet
 * list as anonymous UDP: a Mac or a BitTorrent client asking the gateway for
 * its external address and a port forward (NAT-PMP, RFC 6886, and its
 * successor PCP, RFC 6887, on one port and told apart by the version byte),
 * the gateway announcing a restart, and every Dropbox client broadcasting
 * itself every thirty seconds as JSON.
 *
 * PCP writes IPv4 addresses as IPv4-mapped IPv6, which is how a gap in the
 * shared address formatter showed up: the reference keeps the dotted half
 * only when its top sixteen bits are not zero (`::ffff:10.0.0.0`, but
 * `::ffff:0:1`). Those cases are held at unit level too.
 */
import { Bytes, udpFrame, udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { formatIpv6Address } from '../../src/services/addressFormat';

const ascii = (text: string) => new Bytes().ascii(text).build();
const mapped = (v4: number[]) => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4];
const NONCE = new Array(12).fill(0x77);
const GATEWAY = '192.0.2.2';
const HOST = '192.0.2.1';
const fromGateway = (dst: string, dstPort: number, payload: Uint8Array) => udpFrameTo(GATEWAY, dst, 5351, dstPort, payload);

const cases: OracleCase[] = [
  { label: 'NAT-PMP external address request', frame: udpFrame(50000, 5351, new Bytes().u8(0, 0).build()) },
  { label: 'NAT-PMP external address response', frame: fromGateway(HOST, 50000,
    new Bytes().u8(0, 128).u16(0).u32(3600).u8(203, 0, 113, 7).build()) },
  { label: 'NAT-PMP map TCP request', frame: udpFrame(50000, 5351, new Bytes().u8(0, 2).u16(0).u16(51413, 51413).u32(7200).build()) },
  { label: 'NAT-PMP map TCP response', frame: fromGateway(HOST, 50000,
    new Bytes().u8(0, 130).u16(0).u32(3600).u16(51413, 51413).u32(7200).build()) },
  { label: 'NAT-PMP gateway restart announcement', frame: udpFrameTo(GATEWAY, '224.0.0.1', 5351, 5350,
    new Bytes().u8(0, 128).u16(0).u32(3600).u8(203, 0, 113, 7).build()) },
  { label: 'NAT-PMP map UDP refused', frame: fromGateway(HOST, 50000,
    new Bytes().u8(0, 129).u16(3).u32(3600).u16(8080, 0).u32(0).build()) },
  { label: 'PCP map request with options', frame: udpFrame(50000, 5351, new Bytes()
    .u8(2, 1).u16(0).u32(7200).raw(mapped([192, 0, 2, 1])).raw(NONCE).u8(6, 0, 0, 0).u16(80, 8080).raw(mapped([0, 0, 0, 0]))
    .u8(1, 0).u16(16).raw(mapped([192, 0, 2, 50]))          // Third Party
    .u8(2, 0).u16(0)                                          // Prefer Failure
    .u8(128, 0).u16(5).raw([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0, 0, 0]) // Description, padded
    .build()) },
  { label: 'PCP map response, assigned', frame: fromGateway(HOST, 50000, new Bytes()
    .u8(2, 0x81).u8(0, 0).u32(7200).u32(1234).raw(new Array(12).fill(0)).raw(NONCE).u8(17, 0, 0, 0).u16(51413, 51413)
    .raw(mapped([203, 0, 113, 7])).build()) },
  { label: 'PCP map response, out of resources', frame: fromGateway(HOST, 50000, new Bytes()
    .u8(2, 0x81).u8(0, 8).u32(30).u32(5).raw(new Array(12).fill(0)).raw(NONCE).u8(6, 0, 0, 0).u16(80, 0)
    .raw(mapped([0, 0, 0, 0])).build()) },
  { label: 'PCP peer request', frame: udpFrame(50000, 5351, new Bytes()
    .u8(2, 2).u16(0).u32(600).raw(mapped([192, 0, 2, 1])).raw(NONCE).u8(17, 0, 0, 0).u16(5000, 6000).raw(mapped([0, 0, 0, 0]))
    .u16(443, 0).raw(mapped([198, 51, 100, 9])).build()) },
  { label: 'PCP announce request', frame: udpFrame(50000, 5351, new Bytes().u8(2, 0).u16(0).u32(0).raw(mapped([192, 0, 2, 1])).build()) },
  { label: 'PCP announce from the gateway', frame: udpFrameTo(GATEWAY, '224.0.0.1', 5351, 5350,
    new Bytes().u8(2, 0x80).u8(0, 0).u32(0).u32(99).raw(new Array(12).fill(0)).build()) },
  { label: 'PCP version 1 map request (no nonce)', frame: udpFrame(50000, 5351, new Bytes()
    .u8(1, 1).u16(0).u32(7200).raw(mapped([192, 0, 2, 1])).u8(6, 0, 0, 0).u16(80, 8080).raw(mapped([0, 0, 0, 0])).build()) },
  { label: 'Dropbox LAN sync discovery', frame: udpFrame(17500, 17500, ascii(
    '{"host_int": 123456789, "version": [2, 0], "displayname": "", "port": 17500, "namespaces": [1, 2, 3]}')) },
];

// JSON's rows are not compared: the JSON tree is `dissectors/json.ts`'s own
// layout, which differs from the reference's for every JSON body, not just
// this one - Dropbox is held to its columns and to handing its body on.
const packets = await compareWithReference(cases, { rows: /^(nat-pmp|portcontrol)\./ });
check('Dropbox discovery hands its body to JSON', JSON.stringify(packets[13]?.frameProtocols?.slice(-2)) === '["db-lsp-disc","json"]');
check('NAT-PMP is the `nat-pmp` layer and PCP `portcontrol`',
  packets[0]?.frameProtocols?.at(-1) === 'nat-pmp' && packets[6]?.frameProtocols?.at(-1) === 'portcontrol');
await checkRevisit(cases);

// --- the address formatter, held to the reference's own output -----------------
const v6 = (bytes: number[]) => formatIpv6Address(Uint8Array.from(bytes), 0);
const FORMS: [number[], string][] = [
  [mapped([192, 0, 2, 1]), '::ffff:192.0.2.1'],
  [mapped([0, 0, 0, 1]), '::ffff:0:1'],
  [mapped([10, 0, 0, 0]), '::ffff:10.0.0.0'],
  [mapped([0, 0, 1, 0]), '::ffff:0:100'],
  [mapped([0, 1, 0, 0]), '::ffff:0.1.0.0'],
  [mapped([0, 0, 0, 0]), '::ffff:0:0'],
  [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4], '::1.2.3.4'],
  [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], '::1'],
  [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0], '::100'],
  [[0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4], '64:ff9b::102:304'],
];
for (const [bytes, want] of FORMS) check(`IPv6 ${want} is written as the reference writes it`, v6(bytes) === want, v6(bytes));

finish('NAT-PMP, PCP and DB-LSP-DISC');
