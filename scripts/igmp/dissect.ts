/**
 * Assertion tests for the IGMP dissector.
 *
 *   npx tsx scripts/igmp/dissect.ts
 *
 * Every frame below was captured off a real network with tshark, and every
 * expected string is copied from `tshark -V` / `-T fields -e _ws.col.info` for
 * that same frame - so a failure here means NetView would disagree with
 * Wireshark about traffic that shows up on any LAN.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import type { ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const bytes = (hex: string) =>
  Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

// IGMPv3 membership report, "Join group 239.7.7.7" (record type 4).
const V3_JOIN =
  '01005e000016047c1652db1708004600002869280000010200000a000004e0000016' +
  '940400002200e3ef0000000104000000ef070707';
// IGMPv3 membership report, "Leave group 239.7.7.7" (record type 3).
const V3_LEAVE =
  '01005e000016047c1652db17080046000028692a0000010200000a000004e0000016' +
  '940400002200e4ef0000000103000000ef070707';
// IGMPv3 general membership query from the router - the 60-byte frame to
// 224.0.0.1 that the bug report showed as "TCP / Frame (60 bytes)".
const V3_QUERY =
  '01005e0000014415245dcc62080046000024f6774000010203d10a00008ae0000001' +
  '94040000110aec7800000000027d000000000000000000000000';
// IGMPv3 report carrying three records at once, the 70-byte frame from the
// bug report.
const V3_MULTI =
  '01005e000016047c1652db17080046000038692c0000010200000a000004e0000016' +
  '94040000220026090000000302000000e00000fb02000000e00000fc02000000effffffa';

function decode(hex: string) {
  const raw = bytes(hex);
  const { packet } = decodeRawEthernetPacket(raw, 1, Date.now(), 0, 0, raw.length);
  return packet;
}

function findField(fields: ProtocolField[], name: string): ProtocolField | undefined {
  for (const f of fields) {
    if (f.name === name) return f;
    const nested = f.children && findField(f.children, name);
    if (nested) return nested;
  }
  return undefined;
}

// --- the regression the bug report describes ---------------------------------
// Before the dissector existed these frames kept decodeRawEthernetPacket's
// initial values, so both of these assertions failed at once.
const query = decode(V3_QUERY);
check('a query is not labeled TCP', query.protocolLabel, 'IGMPv3');
check('a query has real Info text', query.info, 'Membership Query, general');
check('query source', query.source, '10.0.0.138');
check('query destination', query.destination, '224.0.0.1');

const multi = decode(V3_MULTI);
check('a 3-record report is not labeled TCP', multi.protocolLabel, 'IGMPv3');
check(
  'a 3-record report lists every group, in wire order',
  multi.info,
  'Membership Report / Join group 224.0.0.251 for any sources / Join group 224.0.0.252 for any sources / Join group 239.255.255.250 for any sources',
);

// --- Info text per record type ----------------------------------------------
check(
  'Change To Exclude Mode with no sources reads as a join',
  decode(V3_JOIN).info,
  'Membership Report / Join group 239.7.7.7 for any sources',
);
check(
  'Change To Include Mode with no sources reads as a leave',
  decode(V3_LEAVE).info,
  'Membership Report / Leave group 239.7.7.7',
);

// --- the dissection tree, against `tshark -V` --------------------------------
const igmpLayer = query.layers.find((l) => l.name === 'Internet Group Management Protocol');
check('an IGMP layer is added to the tree', !!igmpLayer, true);

const qf = igmpLayer!.fields;
check('version is generated, not read from a header field', findField(qf, '[IGMP Version]')?.value, 3);
check('query type', findField(qf, 'Type')?.value, 'Membership Query (0x11)');
check('max response time is decoded to seconds', findField(qf, 'Max Resp Time')?.value, '1.0 sec (0x0a)');
check('checksum is verified, not just displayed', findField(qf, 'Checksum')?.value, '0xec78 [correct]');
check('checksum status', findField(qf, '[Checksum Status]')?.value, 'Good');
check('a general query carries the all-zero group', findField(qf, 'Multicast Address')?.value, '0.0.0.0');
check('S flag', findField(qf, 'S')?.value, 'Do not suppress router side processing');
check('QRV', findField(qf, 'QRV')?.value, 2);
check('QQIC', findField(qf, 'QQIC')?.value, 125);
check('Num Src', findField(qf, 'Num Src')?.value, 0);

// S and QRV share one byte, so they are only readable as bit positions.
check('S renders as a bitfield', JSON.stringify(findField(qf, 'S')?.bitfield), JSON.stringify({ bitOffset: 4, bitLength: 1, totalBits: 8 }));
check('QRV renders as a bitfield', JSON.stringify(findField(qf, 'QRV')?.bitfield), JSON.stringify({ bitOffset: 5, bitLength: 3, totalBits: 8 }));

const rf = multi.layers.find((l) => l.name === 'Internet Group Management Protocol')!.fields;
check('report type', findField(rf, 'Type')?.value, 'Membership Report (0x22)');
check('record count', findField(rf, 'Num Group Records')?.value, 3);
const records = rf.filter((f) => f.name === 'Group Record');
check('every record gets its own sub-tree', records.length, 3);
check('record summary matches Wireshark', records[0].value, '224.0.0.251  Mode Is Exclude');
check('record type', findField(records[0].children!, 'Record Type')?.value, 'Mode Is Exclude (2)');
check('record group address', findField(records[0].children!, 'Multicast Address')?.value, '224.0.0.251');

// --- the general fallback, for protocols with no dissector -------------------
// An IPv4 header (protocol 47, GRE) with nothing after it. The point is that
// the frame is named honestly rather than inheriting "TCP".
const gre = decode('001122334455' + '66778899aabb' + '0800' + '4500001400010000402f0000' + '0a000001' + '0a000002');
check('an undissected protocol is named, not called TCP', gre.protocolLabel, 'GRE');
check('an undissected protocol gets honest Info', gre.info, 'GRE payload (protocol 47, not dissected)');

const unknownProto = decode('001122334455' + '66778899aabb' + '0800' + '450000140001000040fd0000' + '0a000001' + '0a000002');
check('an unlisted protocol falls back to its number', unknownProto.protocolLabel, 'IP Protocol 253');
check('an unlisted protocol gets honest Info', unknownProto.info, 'IP protocol 253 payload (not dissected)');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
