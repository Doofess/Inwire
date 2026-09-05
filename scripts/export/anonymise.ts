/**
 * Assertion tests for anonymise-on-export.
 *
 *   npx tsx scripts/export/anonymise.ts
 *
 * A packet capture is one of the most revealing files a person can hand over,
 * and an anonymiser is the kind of feature that is trusted precisely because
 * nobody checks it. Two failure modes matter and they pull in opposite
 * directions: leaving something identifying in the file, and destroying so much
 * structure that the file is no longer a network.
 *
 * So both halves are asserted. The **prefix-preserving** property is the one
 * that is easy to claim and hard to get right - it is what keeps subnets
 * legible - and it is checked by construction rather than by example: for
 * every pair of addresses, the anonymised pair must agree on exactly as many
 * leading bits as the real pair did.
 */
import { Anonymiser, anonymiseCapture, parseIpv4, parseIpv6 } from '../../src/services/anonymise';
import { FieldBlockWriter } from '../../src/services/dissect/fieldSplit';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { LINKTYPE } from '../../src/services/dissect/types';
import type { Packet, ProtocolType } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** How many leading bits two addresses share. */
function sharedPrefix(a: Uint8Array, b: Uint8Array): number {
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) { bits += 8; continue; }
    const diff = a[i] ^ b[i];
    for (let k = 7; k >= 0; k--) {
      if ((diff >> k) & 1) return bits;
      bits++;
    }
  }
  return bits;
}

// --- the property that makes it useful ------------------------------------------

{
  const a = new Anonymiser();
  // A plausible mix: two /24s inside one /16, a neighbour /16, and a public
  // address a long way from all of them.
  const addresses = [
    '10.1.1.1', '10.1.1.2', '10.1.1.254',
    '10.1.2.1', '10.1.2.2',
    '10.2.1.1',
    '192.0.2.5', '192.0.2.6', '198.51.100.7',
    '203.0.113.1', '203.0.113.128',
  ];
  const mapped = new Map(addresses.map((x) => [x, a.ipv4Address(x)]));

  let prefixesMatch = true;
  let collisions = false;
  const seen = new Set<string>();
  for (const x of addresses) {
    if (seen.has(mapped.get(x)!)) collisions = true;
    seen.add(mapped.get(x)!);
    for (const y of addresses) {
      const before = sharedPrefix(parseIpv4(x)!, parseIpv4(y)!);
      const after = sharedPrefix(parseIpv4(mapped.get(x)!)!, parseIpv4(mapped.get(y)!)!);
      if (before !== after) prefixesMatch = false;
    }
  }
  checkTrue('every pair keeps exactly the prefix it had - subnets survive', prefixesMatch);
  checkTrue('...and no two addresses collide', !collisions);

  // The point of the whole exercise: two hosts on one /24 still look like it.
  check('two hosts in a /24 still share 24 bits',
    sharedPrefix(parseIpv4(mapped.get('10.1.1.1')!)!, parseIpv4(mapped.get('10.1.1.2')!)!) >= 24, true);
  check('...and hosts in different /16s still do not',
    sharedPrefix(parseIpv4(mapped.get('10.1.1.1')!)!, parseIpv4(mapped.get('10.2.1.1')!)!) < 24, true);

  checkTrue('an address is actually changed', mapped.get('10.1.1.1') !== '10.1.1.1');
  check('...and the same address maps the same way twice',
    a.ipv4Address('10.1.1.1'), mapped.get('10.1.1.1'));
}

{
  // The same property over IPv6's 128 bits, where a /64 boundary is the one
  // that carries almost all of the structure.
  const a = new Anonymiser();
  const addresses = [
    '2001:db8:1:1::1', '2001:db8:1:1::2', '2001:db8:1:2::1', '2001:db8:2::1',
    '2001:db8:422c:9100::1', '2001:db8:422c:9100::2',
  ];
  const mapped = new Map(addresses.map((x) => [x, a.ipv6Address(x)]));
  let ok = true;
  for (const x of addresses) for (const y of addresses) {
    if (sharedPrefix(parseIpv6(x)!, parseIpv6(y)!) !== sharedPrefix(parseIpv6(mapped.get(x)!)!, parseIpv6(mapped.get(y)!)!)) ok = false;
  }
  checkTrue('IPv6 prefixes are preserved too', ok);
  check('...so two addresses in one /64 still share it',
    sharedPrefix(parseIpv6(mapped.get('2001:db8:1:1::1')!)!, parseIpv6(mapped.get('2001:db8:1:1::2')!)!) >= 64, true);
  checkTrue('...and the address really changed',
    mapped.get('2001:db8:1:1::1') !== '2001:db8:1:1::1');
}

// --- addresses that are not anybody's --------------------------------------------

{
  const a = new Anonymiser();
  // Rewriting these hides nothing - they are identical on every network on
  // earth - and destroys the file's meaning: mDNS to a rewritten 224.0.0.251
  // is traffic to a host that does not exist.
  for (const address of ['224.0.0.251', '255.255.255.255', '0.0.0.0', '127.0.0.1']) {
    check(`${address} is left alone`, a.ipv4Address(address), address);
  }
  for (const address of ['ff02::fb', '::', '::1']) {
    check(`${address} is left alone`, a.ipv6Address(address), address);
  }
  check('broadcast MAC is left alone', a.mac('ff:ff:ff:ff:ff:ff'), 'ff:ff:ff:ff:ff:ff');
  check('an IPv6 multicast MAC is left alone', a.mac('33:33:00:00:00:fb'), '33:33:00:00:00:fb');
}

// --- MACs keep the half that says who made the device ------------------------------

{
  const a = new Anonymiser();
  const real = ['44:15:24:aa:bb:cc', '44:15:24:aa:bb:cd', '00:11:22:33:44:55'];
  const mapped = real.map((m) => a.mac(m));

  check('the OUI survives - the vendor is what makes a device identifiable as a kind',
    mapped.map((m) => m.slice(0, 8)), real.map((m) => m.slice(0, 8)));
  checkTrue('...and the unit half does not', mapped.every((m, i) => m !== real[i]));
  checkTrue('two devices from one vendor stay distinct', mapped[0] !== mapped[1]);
  check('...and one device maps the same way twice', a.mac(real[0]), mapped[0]);
}

// --- a whole frame ---------------------------------------------------------------

const MAC_DST = [0x44, 0x15, 0x24, 0xaa, 0xbb, 0xcc];
const MAC_SRC = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/** An Ethernet/IPv4/TCP frame with a recognisable payload. */
function frame(payload: number[], opts: { vlan?: boolean } = {}): Uint8Array {
  const tcp = [
    0xc7, 0x38, 0x01, 0xbb,
    0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x18, 0x20, 0x00,
    0xab, 0xcd, 0x00, 0x00,
    ...payload,
  ];
  const total = 20 + tcp.length;
  const ip = [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x01, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,
    10, 1, 1, 5,
    203, 0, 113, 9,
  ];
  return new Uint8Array([
    ...MAC_DST, ...MAC_SRC,
    ...(opts.vlan ? [0x81, 0x00, 0x00, 0x64] : []),
    0x08, 0x00,
    ...ip, ...tcp,
  ]);
}

const SECRET = Array.from(new TextEncoder().encode('password=hunter2 cookie=abc'));

function decode(bytes: Uint8Array, id = 1): Packet {
  return decodeRawEthernetPacket(
    bytes, id, 1_700_000_000_000_000, 0, 0, bytes.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  ).packet;
}

{
  const original = decode(frame(SECRET));
  const { packets, summary } = anonymiseCapture([original]);
  const out = packets[0];

  check('the addresses in the columns are rewritten',
    [out.source === original.source, out.destination === original.destination], [false, false]);
  check('...and so are the ones in the bytes',
    decode(out.rawBytes).source === original.source, false);
  // Compared against the original's own dissection rather than a literal: the
  // property is "the frame still reads the way it did", and hard-coding what
  // that reading is would make this a test of the dissector instead.
  check('the rewritten frame still parses as what it was',
    [decode(out.rawBytes).protocol, decode(out.rawBytes).destPort],
    [original.protocol, original.destPort]);

  // The headers are the analysis; only the payload is the secret.
  const redecoded = decode(out.rawBytes);
  check('ports survive, because they are the protocol not the person',
    [redecoded.sourcePort, redecoded.destPort], [original.sourcePort, original.destPort]);
  check('sequence numbers survive', redecoded.fields?.['tcp.seq_raw'], original.fields?.['tcp.seq_raw']);

  const text = new TextDecoder().decode(out.rawBytes);
  checkTrue('the payload is gone, not scrambled', !text.includes('hunter2'));
  checkTrue('...and specifically zeroed',
    out.rawBytes.slice(out.rawBytes.length - SECRET.length).every((b) => b === 0));
  check('...and the removal is counted', summary.payloadsStripped, 1);
  check('...with the byte count', summary.bytesStripped, SECRET.length);

  // A stale header checksum would paint every frame in the file as damaged and
  // bury whatever the capture was shared to show.
  check('the IPv4 header checksum is recomputed, not left stale',
    redecoded.fields?.['ip.checksum.status'], 'Good');

  checkTrue('nothing the dissection learned is carried over',
    out.layers.length === 0 && out.fields === undefined && out.resolved === undefined);
  check('...and the Info column no longer describes the frame', out.info, '(anonymised)');
}

{
  // An anonymiser that writes twelve bytes at a fixed offset corrupts a
  // VLAN-tagged frame's payload and leaves its addresses intact - the worst of
  // both outcomes. The link layer is read, not assumed.
  const original = decode(frame(SECRET, { vlan: true }));
  const out = anonymiseCapture([original]).packets[0];
  const redecoded = decode(out.rawBytes);
  check('a VLAN tag does not throw the offsets off',
    [redecoded.protocol, redecoded.destPort, redecoded.fields?.['vlan.id']],
    [original.protocol, original.destPort, 100]);
  checkTrue('...the address is still rewritten', redecoded.source !== original.source);
  checkTrue('...and the payload is still gone',
    !new TextDecoder().decode(out.rawBytes).includes('hunter2'));
}

{
  // ARP carries addresses in a layout of its own. An anonymiser that only knew
  // about IP headers would leave the whole local subnet in plain view.
  const arp = new Uint8Array([
    ...MAC_DST, ...MAC_SRC, 0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
    ...MAC_SRC, 10, 1, 1, 5,
    ...MAC_DST, 10, 1, 1, 9,
  ]);
  const out = anonymiseCapture([decode(arp)]).packets[0];
  const redecoded = decode(out.rawBytes);
  check('ARP is still ARP', redecoded.frameProtocols?.includes('arp'), true);
  checkTrue('...but its sender address is not the real one',
    redecoded.fields?.['arp.src.proto_ipv4'] !== '10.1.1.5');
  checkTrue('...nor its target', redecoded.fields?.['arp.dst.proto_ipv4'] !== '10.1.1.9');
  // The two addresses were in one /24, and still are.
  const src = parseIpv4(String(redecoded.fields?.['arp.src.proto_ipv4']))!;
  const dst = parseIpv4(String(redecoded.fields?.['arp.dst.proto_ipv4']))!;
  check('...and they are still on one subnet', sharedPrefix(src, dst) >= 24, true);
}

{
  // Two exports of the same capture must not produce the same addresses, or a
  // recipient holding both could line them up - and anyone holding one could
  // build a dictionary for the next.
  const one = anonymiseCapture([decode(frame([]))]).packets[0];
  const two = anonymiseCapture([decode(frame([]))]).packets[0];
  checkTrue('a second export uses a different key', one.source !== two.source);
}

{
  // The frame is copied, not edited: exporting must not change the buffer the
  // packet list is still rendering from.
  const original = decode(frame(SECRET));
  const before = Array.from(original.rawBytes);
  anonymiseCapture([original]);
  check('the capture in memory is untouched', Array.from(original.rawBytes), before);
}

// --- what the machine knew, and the file must not -------------------------------
//
// Process attribution comes from the operating system of the machine the
// capture was taken on (`services/flowAnnotations.ts`), and "chrome.exe, pid
// 8412, C:/Users/<name>/AppData/..." identifies a person far more precisely
// than the address it sits beside. It is stripped today only because the
// anonymiser drops the whole field bag, which is the right design and exactly
// the kind of property that survives until someone adds one carefully
// preserved field. So it is asserted rather than assumed.
{
  const original = decode(frame(SECRET));
  original.fields = {
    ...original.fields,
    'inwire.process.name': 'chrome.exe',
    'inwire.process.pid': 8412,
    'inwire.process.path': 'C:/Users/someone/AppData/Local/Chrome/chrome.exe',
  };
  const out = anonymiseCapture([original]).packets[0];

  checkTrue('an anonymised frame carries no process name', out.fields === undefined);
  checkTrue('...and nothing anywhere in it mentions the executable',
    !JSON.stringify(out).includes('chrome.exe'));
  checkTrue('...nor the path it ran from',
    !JSON.stringify(out).includes('AppData'));
}


// --- A frame whose dense fields live in a column must lose those too ----------
//
// `fields: undefined` alone is not enough once the split lands: addresses,
// ports and sequence numbers all moved into a shared column block reached
// through `cols`, and leaving that pointer in place would keep every one of
// them readable on a frame this function has just declared anonymous.
{
  const frame = {
    id: 1, tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: '10.0.0.1', destination: '10.0.0.2',
    protocol: 'TCP' as ProtocolType, length: 100, info: '', status: 'ok' as const,
    layers: [], rawBytes: new Uint8Array(0), interfaceName: 'test',
    fields: { 'ip.src': '10.0.0.1', 'tcp.srcport': 51000, 'dns.qry.name': 'secret.invalid' },
  } as unknown as Packet;
  new FieldBlockWriter().absorb([frame]);
  // Proves the split actually happened, so the check below is not vacuous.
  checkTrue('the frame reads its address through a column',
    fieldValue(frame, 'ip.src') === '10.0.0.1' && frame.fields?.['ip.src'] === undefined);

  const { packets: scrubbed } = anonymiseCapture([frame]);
  check('anonymising clears the column values as well as the bag',
    ['ip.src', 'tcp.srcport', 'dns.qry.name'].map((k) => fieldValue(scrubbed[0], k)),
    [undefined, undefined, undefined]);
}
console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All anonymisation checks passed.');
process.exit(0);
